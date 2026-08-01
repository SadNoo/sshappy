package panel

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/stats"
)

type policySet struct {
	users map[int]userPolicy
}

type Runtime struct {
	state         *State
	base          stats.Collector
	policies      atomic.Pointer[policySet]
	resolveIPPort func(context.Context, conn.Addr) (netip.AddrPort, error)
	sessionsMu    sync.Mutex
	sessions      map[int]map[uint64]context.CancelFunc
	nextSessionID uint64
}

func NewRuntime(state *State) *Runtime {
	r := &Runtime{
		state: state,
		base:  stats.NewServerCollector(),
		resolveIPPort: func(ctx context.Context, target conn.Addr) (netip.AddrPort, error) {
			return target.ResolveIPPort(ctx, "ip")
		},
		sessions: make(map[int]map[uint64]context.CancelFunc),
	}
	r.policies.Store(&policySet{users: make(map[int]userPolicy)})
	return r
}

// ReplaceUsers compiles and atomically publishes a new authorization snapshot.
// A malformed policy rejects only its owning user instead of silently widening
// that user's access or invalidating unrelated users.
func (r *Runtime) ReplaceUsers(users []User) []UserPolicyError {
	next := make(map[int]userPolicy, len(users))
	var rejected []UserPolicyError
	for _, user := range users {
		policy, err := compileUserPolicy(user)
		if err != nil {
			policyErr := UserPolicyError{UserID: user.ID, Field: "policy", Err: err}
			if ruleErr, ok := err.(*policyRuleError); ok {
				policyErr.Field = ruleErr.field
				policyErr.RuleIndex = ruleErr.ruleIndex
				policyErr.Err = ruleErr.err
			}
			rejected = append(rejected, policyErr)
			continue
		}
		next[user.ID] = policy
	}
	var cancelSessions []context.CancelFunc
	r.sessionsMu.Lock()
	previous := r.policies.Load()
	r.policies.Store(&policySet{users: next})
	for userID, sessions := range r.sessions {
		previousPolicy, previouslyAuthorized := previous.users[userID]
		nextPolicy, stillAuthorized := next[userID]
		if stillAuthorized && previouslyAuthorized && previousPolicy.revision == nextPolicy.revision {
			continue
		}
		for _, cancel := range sessions {
			cancelSessions = append(cancelSessions, cancel)
		}
		delete(r.sessions, userID)
	}
	r.sessionsMu.Unlock()
	// Cancel outside the registry lock. Cancellation callbacks close network
	// resources and must never be allowed to call back into this mutex.
	for _, cancel := range cancelSessions {
		cancel()
	}
	return rejected
}

func (r *Runtime) Accept(_ string, username string, source netip.AddrPort, target conn.Addr) bool {
	userID, err := strconv.Atoi(username)
	if err != nil {
		return false
	}
	policy, ok := r.policies.Load().users[userID]
	if !ok {
		return false
	}
	return policy.accepts(source.Addr(), target)
}

// ResolveAndAcceptTarget implements service.RuntimeTargetResolver. It resolves
// domain targets once, checks the exact resolved IP against the latest policy,
// and returns a literal address that the relay must use for dialing. This avoids
// a policy-check/dial DNS rebinding window.
func (r *Runtime) ResolveAndAcceptTarget(ctx context.Context, network, username string, source netip.AddrPort, target conn.Addr) (conn.Addr, bool, error) {
	// Reject unknown users, disconnected sources, and forbidden ports before
	// spending time on a DNS lookup.
	if !r.Accept(network, username, source, target) {
		return target, false, nil
	}
	if target.IsIP() {
		return target, true, nil
	}

	resolved, err := r.resolveIPPort(ctx, target)
	if err != nil {
		return conn.Addr{}, false, fmt.Errorf("failed to resolve target %q: %w", target.Host(), err)
	}
	resolvedTarget := conn.AddrFromIPPort(resolved)
	// Reload policy after DNS resolution so a concurrent user removal or policy
	// refresh cannot authorize a target using a stale snapshot.
	if !r.Accept(network, username, source, resolvedTarget) {
		return resolvedTarget, false, nil
	}
	return resolvedTarget, true, nil
}

// BeginSession implements service.RuntimeSessionController. Registration and
// policy publication share sessionsMu, so a session either registers before a
// revocation and is canceled by it, or observes the new policy and is rejected.
func (r *Runtime) BeginSession(parent context.Context, _ string, username string, source netip.AddrPort, target conn.Addr) (context.Context, func(), bool) {
	userID, err := strconv.Atoi(username)
	if err != nil {
		return parent, nil, false
	}

	sessionCtx, cancel := context.WithCancel(parent)
	r.sessionsMu.Lock()
	policy, authorized := r.policies.Load().users[userID]
	if !authorized || !policy.accepts(source.Addr(), target) {
		r.sessionsMu.Unlock()
		cancel()
		return parent, nil, false
	}
	r.nextSessionID++
	sessionID := r.nextSessionID
	userSessions := r.sessions[userID]
	if userSessions == nil {
		userSessions = make(map[uint64]context.CancelFunc)
		r.sessions[userID] = userSessions
	}
	userSessions[sessionID] = cancel
	r.sessionsMu.Unlock()

	var once sync.Once
	end := func() {
		once.Do(func() {
			r.sessionsMu.Lock()
			if sessions := r.sessions[userID]; sessions != nil {
				delete(sessions, sessionID)
				if len(sessions) == 0 {
					delete(r.sessions, userID)
				}
			}
			r.sessionsMu.Unlock()
			cancel()
		})
	}
	return sessionCtx, end, true
}

func (r *Runtime) Observe(_ string, username string, source netip.AddrPort) {
	userID, err := strconv.Atoi(username)
	if err != nil {
		return
	}
	r.state.AddAliveIP(userID, source.Addr().Unmap().String())
}

func (r *Runtime) CollectTCPSession(username string, downlinkBytes, uplinkBytes uint64) {
	r.base.CollectTCPSession(username, downlinkBytes, uplinkBytes)
	r.addTraffic(username, uplinkBytes, downlinkBytes)
}

func (r *Runtime) CollectUDPSessionDownlink(username string, packets, bytes uint64) {
	r.base.CollectUDPSessionDownlink(username, packets, bytes)
	r.addTraffic(username, 0, bytes)
}

func (r *Runtime) CollectUDPSessionUplink(username string, packets, bytes uint64) {
	r.base.CollectUDPSessionUplink(username, packets, bytes)
	r.addTraffic(username, bytes, 0)
}

func (r *Runtime) Snapshot() stats.Server {
	return r.base.Snapshot()
}

func (r *Runtime) SnapshotAndReset() stats.Server {
	return r.base.SnapshotAndReset()
}

func (r *Runtime) addTraffic(username string, upload, download uint64) {
	userID, err := strconv.Atoi(username)
	if err != nil {
		return
	}
	r.state.AddTraffic(userID, int64(upload), int64(download))
}

func (r *Runtime) CollectTCPSessionStart(username string) {
	r.base.CollectTCPSessionStart(username)
}

func (r *Runtime) CollectUDPSessionStart(username string) {
	r.base.CollectUDPSessionStart(username)
}
