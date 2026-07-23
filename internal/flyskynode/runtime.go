package flyskynode

import (
	"hash/fnv"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/database64128/shadowsocks-go/conn"
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

type policySet struct {
	validUntil time.Time
	users      map[string]User
}

type TrafficDelta struct {
	UserID            string
	CredentialVersion int64
	UploadBytes       int64
	DownloadBytes     int64
}

type trafficShard struct {
	mu      sync.Mutex
	traffic map[string]TrafficDelta
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
		state.traffic[i].traffic = make(map[string]TrafficDelta)
	}
	return state
}

type Runtime struct {
	state    *State
	base     stats.Collector
	policies atomic.Pointer[policySet]
	now      func() time.Time
}

func NewRuntime(state *State) *Runtime {
	runtime := &Runtime{state: state, base: stats.NewServerCollector(), now: time.Now}
	runtime.policies.Store(&policySet{users: make(map[string]User)})
	return runtime
}

func (runtime *Runtime) ReplaceUsers(validUntil time.Time, users []User) {
	next := make(map[string]User, len(users))
	for _, user := range users {
		user.Key = append([]byte(nil), user.Key...)
		next[user.ID] = user
	}
	runtime.policies.Store(&policySet{validUntil: validUntil, users: next})
}

func (runtime *Runtime) Accept(_ string, username string, _ netip.AddrPort, _ conn.Addr) bool {
	policies := runtime.policies.Load()
	now := runtime.now()
	if policies == nil || !now.Before(policies.validUntil) {
		return false
	}
	user, exists := policies.users[username]
	return exists && now.Before(user.ValidUntil) && (user.Unlimited || user.QuotaRemainingBytes > 0)
}

func (runtime *Runtime) Observe(_ string, username string, source netip.AddrPort) {
	if _, exists := runtime.policies.Load().users[username]; !exists {
		return
	}
	runtime.state.AddAliveIP(username, source.Addr().Unmap().String())
}

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

func (runtime *Runtime) Snapshot() stats.Server {
	return runtime.base.Snapshot()
}

func (runtime *Runtime) SnapshotAndReset() stats.Server {
	return runtime.base.SnapshotAndReset()
}

func (runtime *Runtime) addTraffic(username string, upload, download uint64) {
	user, exists := runtime.policies.Load().users[username]
	if !exists || upload == 0 && download == 0 {
		return
	}
	runtime.state.AddTraffic(user.ID, user.CredentialVersion, int64(upload), int64(download))
}

func (state *State) AddTraffic(userID string, credentialVersion int64, upload, download int64) {
	if userID == "" || credentialVersion < 1 || upload == 0 && download == 0 {
		return
	}
	shard := &state.traffic[userShard(userID)]
	shard.mu.Lock()
	delta := shard.traffic[userID]
	delta.UserID = userID
	delta.CredentialVersion = credentialVersion
	delta.UploadBytes += upload
	delta.DownloadBytes += download
	shard.traffic[userID] = delta
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
		shard.traffic = make(map[string]TrafficDelta)
		shard.mu.Unlock()
	}
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
