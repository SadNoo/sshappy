package flyskynode

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/service"
	"github.com/database64128/shadowsocks-go/stats"
)

const trafficShardCount = 32

type User struct {
	ID                  string
	CredentialVersion   int64
	Key                 []byte
	ValidUntil          time.Time
	Unlimited           bool
	QuotaRemainingBytes int64
	PolicyVersion       int64
}

func credentialLabel(user User) string {
	// The label exists only in the node's credential store. It is not sent on
	// the wire, but it lets the runtime distinguish an old authenticated stream
	// from a new credential or policy for the same user.
	return fmt.Sprintf("flysky:%s:c%d:p%d", user.ID, user.CredentialVersion, user.PolicyVersion)
}

type policySet struct {
	validUntil time.Time
	users      map[string]*runtimePolicy
}

type runtimePolicy struct {
	identity      service.SessionIdentity
	validUntil    time.Time
	quotaDisabled bool
	ledger        *quotaLedger
}

type quotaLedger struct {
	mu        sync.Mutex
	identity  service.SessionIdentity
	active    bool
	unlimited bool
	remaining uint64
	available uint64
	reserved  uint64
}

type trafficKey struct {
	userID            string
	credentialVersion int64
}

type TrafficDelta struct {
	UserID            string
	CredentialVersion int64
	UploadBytes       int64
	DownloadBytes     int64
}

type trafficShard struct {
	mu      sync.Mutex
	traffic map[trafficKey]TrafficDelta
}

type State struct {
	traffic [trafficShardCount]trafficShard
	aliveMu sync.Mutex
	alive   map[string]map[string]time.Time
	seenAt  map[string]time.Time
}

func NewState() *State {
	state := &State{
		alive:  make(map[string]map[string]time.Time),
		seenAt: make(map[string]time.Time),
	}
	for i := range state.traffic {
		state.traffic[i].traffic = make(map[trafficKey]TrafficDelta)
	}
	return state
}

type Runtime struct {
	state    *State
	base     stats.Collector
	policies atomic.Pointer[policySet]
	now      func() time.Time

	mu       sync.Mutex
	ledgers  map[service.SessionIdentity]*quotaLedger
	sessions map[*runtimeSession]struct{}
}

func NewRuntime(state *State) *Runtime {
	runtime := &Runtime{
		state: state, base: stats.NewServerCollector(), now: time.Now,
		ledgers:  make(map[service.SessionIdentity]*quotaLedger),
		sessions: make(map[*runtimeSession]struct{}),
	}
	runtime.policies.Store(&policySet{users: make(map[string]*runtimePolicy)})
	return runtime
}

func (runtime *Runtime) ReplaceUsers(validUntil time.Time, users []User) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()

	activeLedgers := make(map[service.SessionIdentity]struct{}, len(users))
	next := make(map[string]*runtimePolicy, len(users))
	for _, user := range users {
		identity := service.SessionIdentity{
			UserID: user.ID, CredentialVersion: user.CredentialVersion, PolicyVersion: user.PolicyVersion,
		}
		ledger := runtime.ledgers[identity]
		created := ledger == nil
		if ledger == nil {
			ledger = &quotaLedger{identity: identity}
			runtime.ledgers[identity] = ledger
		}
		ledger.mu.Lock()
		wasUnlimited := ledger.unlimited
		ledger.active = true
		ledger.unlimited = user.Unlimited
		if user.Unlimited {
			ledger.available = 0
		} else {
			var snapshotRemaining uint64
			if user.QuotaRemainingBytes > 0 {
				snapshotRemaining = uint64(user.QuotaRemainingBytes)
			}
			if created || wasUnlimited {
				ledger.remaining = snapshotRemaining
			} else if snapshotRemaining < ledger.remaining {
				ledger.remaining = snapshotRemaining
			}
			ledger.available = saturatingSubtract(ledger.remaining, ledger.reserved)
		}
		ledger.mu.Unlock()

		activeLedgers[identity] = struct{}{}
		next[credentialLabel(user)] = &runtimePolicy{
			identity: identity, validUntil: minTime(validUntil, user.ValidUntil),
			quotaDisabled: !user.Unlimited && user.QuotaRemainingBytes <= 0,
			ledger:        ledger,
		}
	}

	for identity, ledger := range runtime.ledgers {
		if _, active := activeLedgers[identity]; active {
			continue
		}
		ledger.mu.Lock()
		ledger.active = false
		ledger.mu.Unlock()
	}

	policies := &policySet{validUntil: validUntil, users: next}
	runtime.policies.Store(policies)
	for session := range runtime.sessions {
		policy, exists := next[session.username]
		if !exists || policy.identity != session.identity {
			session.invalidate()
			continue
		}
		session.updateDeadline(policy.validUntil)
		if policy.quotaDisabled || ledgerConfirmedExhausted(policy.ledger) {
			session.invalidate()
		}
	}
	runtime.gcLedgersLocked()
}

func saturatingSubtract(value, sub uint64) uint64 {
	if sub >= value {
		return 0
	}
	return value - sub
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func ledgerAvailable(ledger *quotaLedger) bool {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	return ledger.active && (ledger.unlimited || ledger.available > 0)
}

func ledgerConfirmedExhausted(ledger *quotaLedger) bool {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	return ledger.active && !ledger.unlimited && ledger.available == 0 && ledger.reserved == 0
}

func (runtime *Runtime) Accept(_ string, username string, _ netip.AddrPort, _ conn.Addr) bool {
	policies := runtime.policies.Load()
	now := runtime.now()
	if policies == nil || !now.Before(policies.validUntil) {
		return false
	}
	policy, exists := policies.users[username]
	return exists && now.Before(policy.validUntil) && ledgerAvailable(policy.ledger)
}

func (runtime *Runtime) Observe(_ string, username string, source netip.AddrPort) {
	policy, exists := runtime.policies.Load().users[username]
	if !exists {
		return
	}
	runtime.state.AddAliveIP(policy.identity.UserID, source.Addr().Unmap().String())
}

func (runtime *Runtime) OpenRuntimeSession(
	network, username string,
	source netip.AddrPort,
	target conn.Addr,
) (service.RuntimeSession, bool) {
	_ = target
	runtime.mu.Lock()
	defer runtime.mu.Unlock()

	policies := runtime.policies.Load()
	now := runtime.now()
	if policies == nil || !now.Before(policies.validUntil) {
		return nil, false
	}
	policy, exists := policies.users[username]
	if !exists || !now.Before(policy.validUntil) || !ledgerAvailable(policy.ledger) {
		return nil, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	session := &runtimeSession{
		runtime: runtime, network: network, username: username, source: source,
		identity: policy.identity, ledger: policy.ledger, ctx: ctx, cancel: cancel,
	}
	runtime.sessions[session] = struct{}{}
	session.updateDeadline(policy.validUntil)
	return session, true
}

type runtimeSession struct {
	runtime  *Runtime
	network  string
	username string
	source   netip.AddrPort
	identity service.SessionIdentity
	ledger   *quotaLedger
	ctx      context.Context
	cancel   context.CancelFunc

	timerMu sync.Mutex
	timer   *time.Timer
	timerID uint64
	closed  bool
}

func (session *runtimeSession) Identity() service.SessionIdentity { return session.identity }
func (session *runtimeSession) Context() context.Context          { return session.ctx }

func (session *runtimeSession) Active() bool {
	select {
	case <-session.ctx.Done():
		return false
	default:
		return ledgerAvailable(session.ledger)
	}
}

func (session *runtimeSession) Observe(source netip.AddrPort) {
	if !session.Active() {
		return
	}
	session.runtime.state.AddAliveIP(session.identity.UserID, source.Addr().Unmap().String())
}

func (session *runtimeSession) ReserveTraffic(
	direction service.RuntimeTrafficDirection,
	packets, bytes uint64,
) service.RuntimeTrafficReservation {
	if bytes == 0 || direction != service.RuntimeTrafficUplink && direction != service.RuntimeTrafficDownlink {
		return nil
	}
	select {
	case <-session.ctx.Done():
		return nil
	default:
	}

	ledger := session.ledger
	ledger.mu.Lock()
	select {
	case <-session.ctx.Done():
		ledger.mu.Unlock()
		return nil
	default:
	}
	if !ledger.active {
		ledger.mu.Unlock()
		return nil
	}
	reserved := bytes
	limited := !ledger.unlimited
	if limited {
		if ledger.available == 0 {
			ledger.mu.Unlock()
			return nil
		}
		reserved = min(reserved, ledger.available)
		ledger.available -= reserved
	}
	ledger.reserved += reserved
	ledger.mu.Unlock()

	return &runtimeReservation{
		session: session, direction: direction, packets: packets, bytes: reserved,
	}
}

func (session *runtimeSession) Close() {
	session.invalidate()
	session.runtime.mu.Lock()
	delete(session.runtime.sessions, session)
	session.runtime.gcLedgersLocked()
	session.runtime.mu.Unlock()
}

func (session *runtimeSession) invalidate() {
	session.timerMu.Lock()
	if session.closed {
		session.timerMu.Unlock()
		return
	}
	session.closed = true
	session.timerID++
	if session.timer != nil {
		session.timer.Stop()
		session.timer = nil
	}
	session.timerMu.Unlock()
	session.cancel()
}

func (session *runtimeSession) updateDeadline(deadline time.Time) {
	session.timerMu.Lock()
	defer session.timerMu.Unlock()
	if session.closed {
		return
	}
	session.timerID++
	timerID := session.timerID
	if session.timer != nil {
		session.timer.Stop()
	}
	delay := deadline.Sub(session.runtime.now())
	if delay <= 0 {
		go session.invalidate()
		return
	}
	session.timer = time.AfterFunc(delay, func() { session.expireDeadline(timerID) })
}

func (session *runtimeSession) expireDeadline(timerID uint64) {
	// Checking the generation and claiming the closed state happen under the
	// same lock. A stale timer can therefore never cancel a deadline refreshed
	// by ReplaceUsers between a check and a later invalidate call.
	session.timerMu.Lock()
	if session.closed || session.timerID != timerID {
		session.timerMu.Unlock()
		return
	}
	session.closed = true
	session.timerID++
	session.timer = nil
	session.timerMu.Unlock()
	session.cancel()
}

type runtimeReservation struct {
	session   *runtimeSession
	direction service.RuntimeTrafficDirection
	packets   uint64
	bytes     uint64
	once      sync.Once
}

func (reservation *runtimeReservation) Bytes() uint64 { return reservation.bytes }

func (reservation *runtimeReservation) Commit(confirmedBytes uint64) {
	reservation.once.Do(func() {
		confirmedBytes = min(confirmedBytes, reservation.bytes)
		reservation.settle(confirmedBytes)
	})
}

func (reservation *runtimeReservation) Refund() {
	reservation.once.Do(func() { reservation.settle(0) })
}

func (reservation *runtimeReservation) settle(confirmedBytes uint64) {
	ledger := reservation.session.ledger
	ledger.mu.Lock()
	ledger.reserved -= reservation.bytes
	if !ledger.unlimited {
		ledger.remaining = saturatingSubtract(ledger.remaining, confirmedBytes)
		ledger.available = saturatingSubtract(ledger.remaining, ledger.reserved)
	}
	exhaustedCandidate := ledger.active && !ledger.unlimited && ledger.available == 0 && ledger.reserved == 0
	inactive := !ledger.active
	ledger.mu.Unlock()

	if confirmedBytes > 0 {
		packets := reservation.packets
		if confirmedBytes < reservation.bytes {
			packets = 0
		}
		reservation.session.runtime.recordTraffic(
			reservation.session.network, reservation.session.username, reservation.session.identity,
			reservation.direction, packets, confirmedBytes,
		)
	}
	if exhaustedCandidate {
		reservation.session.runtime.invalidateIdentityIfExhausted(reservation.session.identity, ledger)
	}
	if inactive {
		reservation.session.runtime.gcLedgers()
	}
}

func (runtime *Runtime) invalidateIdentityIfExhausted(identity service.SessionIdentity, ledger *quotaLedger) {
	runtime.mu.Lock()
	ledger.mu.Lock()
	exhausted := runtime.ledgers[identity] == ledger && ledger.active && !ledger.unlimited &&
		ledger.available == 0 && ledger.reserved == 0
	ledger.mu.Unlock()
	if !exhausted {
		runtime.mu.Unlock()
		return
	}
	for session := range runtime.sessions {
		if session.identity == identity {
			session.invalidate()
		}
	}
	runtime.mu.Unlock()
}

func (runtime *Runtime) gcLedgers() {
	runtime.mu.Lock()
	runtime.gcLedgersLocked()
	runtime.mu.Unlock()
}

func (runtime *Runtime) gcLedgersLocked() {
	identitiesWithSessions := make(map[service.SessionIdentity]struct{}, len(runtime.sessions))
	for session := range runtime.sessions {
		identitiesWithSessions[session.identity] = struct{}{}
	}
	for identity, ledger := range runtime.ledgers {
		if _, exists := identitiesWithSessions[identity]; exists {
			continue
		}
		ledger.mu.Lock()
		removable := !ledger.active && ledger.reserved == 0
		ledger.mu.Unlock()
		if removable {
			delete(runtime.ledgers, identity)
		}
	}
}

func (runtime *Runtime) recordTraffic(
	network, username string,
	identity service.SessionIdentity,
	direction service.RuntimeTrafficDirection,
	packets, bytes uint64,
) {
	switch network {
	case "tcp":
		if direction == service.RuntimeTrafficUplink {
			runtime.base.CollectTCPSession(username, 0, bytes)
			runtime.state.AddTraffic(identity.UserID, identity.CredentialVersion, int64(bytes), 0)
		} else {
			runtime.base.CollectTCPSession(username, bytes, 0)
			runtime.state.AddTraffic(identity.UserID, identity.CredentialVersion, 0, int64(bytes))
		}
	case "udp":
		if direction == service.RuntimeTrafficUplink {
			runtime.base.CollectUDPSessionUplink(username, packets, bytes)
			runtime.state.AddTraffic(identity.UserID, identity.CredentialVersion, int64(bytes), 0)
		} else {
			runtime.base.CollectUDPSessionDownlink(username, packets, bytes)
			runtime.state.AddTraffic(identity.UserID, identity.CredentialVersion, 0, int64(bytes))
		}
	}
}

// Collector methods remain the compatibility path for deployments that do not
// use RuntimeSessionFactory. Flysky relay paths use per-session reservations and
// therefore do not call these methods for the same confirmed bytes.
func (runtime *Runtime) CollectTCPSession(username string, downlinkBytes, uplinkBytes uint64) {
	runtime.base.CollectTCPSession(username, downlinkBytes, uplinkBytes)
	runtime.addTraffic(username, uplinkBytes, downlinkBytes)
}

func (runtime *Runtime) CollectUDPSessionDownlink(username string, packets, bytes uint64) {
	runtime.base.CollectUDPSessionDownlink(username, packets, bytes)
	runtime.addTraffic(username, 0, bytes)
}

func (runtime *Runtime) CollectUDPSessionUplink(username string, packets, bytes uint64) {
	runtime.base.CollectUDPSessionUplink(username, packets, bytes)
	runtime.addTraffic(username, bytes, 0)
}

func (runtime *Runtime) Snapshot() stats.Server { return runtime.base.Snapshot() }

func (runtime *Runtime) SnapshotAndReset() stats.Server { return runtime.base.SnapshotAndReset() }

func (runtime *Runtime) addTraffic(username string, upload, download uint64) {
	policy, exists := runtime.policies.Load().users[username]
	if !exists || upload == 0 && download == 0 {
		return
	}
	runtime.state.AddTraffic(policy.identity.UserID, policy.identity.CredentialVersion, int64(upload), int64(download))
}

func (state *State) AddTraffic(userID string, credentialVersion int64, upload, download int64) {
	if userID == "" || credentialVersion < 1 || upload == 0 && download == 0 {
		return
	}
	shard := &state.traffic[userShard(userID)]
	key := trafficKey{userID: userID, credentialVersion: credentialVersion}
	shard.mu.Lock()
	delta := shard.traffic[key]
	delta.UserID = userID
	delta.CredentialVersion = credentialVersion
	delta.UploadBytes += upload
	delta.DownloadBytes += download
	shard.traffic[key] = delta
	shard.mu.Unlock()
}

func (state *State) SnapshotTraffic() []TrafficDelta {
	var out []TrafficDelta
	for i := range state.traffic {
		shard := &state.traffic[i]
		shard.mu.Lock()
		for _, delta := range shard.traffic {
			out = append(out, delta)
		}
		shard.traffic = make(map[trafficKey]TrafficDelta)
		shard.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UserID == out[j].UserID {
			return out[i].CredentialVersion < out[j].CredentialVersion
		}
		return out[i].UserID < out[j].UserID
	})
	return out
}

func (state *State) MergeTraffic(deltas []TrafficDelta) {
	for _, delta := range deltas {
		state.AddTraffic(delta.UserID, delta.CredentialVersion, delta.UploadBytes, delta.DownloadBytes)
	}
}

func (state *State) AddAliveIP(userID, ip string) {
	if userID == "" || ip == "" {
		return
	}
	state.aliveMu.Lock()
	ips := state.alive[userID]
	if ips == nil {
		ips = make(map[string]time.Time)
		state.alive[userID] = ips
	}
	now := time.Now()
	ips[ip] = now
	state.seenAt[userID] = now
	state.aliveMu.Unlock()
}

func (state *State) OnlineUserCount(window time.Duration) int {
	_, users := state.AliveSummary(window, time.Now())
	return users
}

func (state *State) AliveSummary(window time.Duration, now time.Time) (onlineIPs, activeUsers int) {
	state.aliveMu.Lock()
	defer state.aliveMu.Unlock()
	uniqueIPs := make(map[string]struct{})
	for userID, seenAt := range state.seenAt {
		if now.Sub(seenAt) <= window {
			activeUsers++
		} else {
			delete(state.seenAt, userID)
		}
	}
	for userID, ips := range state.alive {
		for ip, seenAt := range ips {
			if now.Sub(seenAt) <= window {
				uniqueIPs[ip] = struct{}{}
			} else {
				delete(ips, ip)
			}
		}
		if len(ips) == 0 {
			delete(state.alive, userID)
		}
	}
	return len(uniqueIPs), activeUsers
}

func userShard(userID string) uint32 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(userID))
	return hash.Sum32() % trafficShardCount
}
