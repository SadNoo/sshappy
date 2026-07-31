package panel

import (
	"sync"
	"time"
)

const trafficShardCount = 32

type trafficShard struct {
	mu      sync.Mutex
	traffic map[int]TrafficDelta
}

type State struct {
	traffic  [trafficShardCount]trafficShard
	aliveMu  sync.Mutex
	alive    map[int]map[string]struct{}
	lastSeen map[int]time.Time
}

type pendingStateMetrics struct {
	TrafficUsers         int
	TrafficUploadBytes   int64
	TrafficDownloadBytes int64
	AliveUsers           int
	AliveRecords         int
}

func NewState() *State {
	state := &State{
		alive:    make(map[int]map[string]struct{}),
		lastSeen: make(map[int]time.Time),
	}
	for i := range state.traffic {
		state.traffic[i].traffic = make(map[int]TrafficDelta)
	}
	return state
}

func (s *State) AddTraffic(userID int, upload, download int64) {
	if userID <= 0 || upload == 0 && download == 0 {
		return
	}
	shard := &s.traffic[userID%trafficShardCount]
	shard.mu.Lock()
	delta := shard.traffic[userID]
	delta.UserID = userID
	delta.Upload += upload
	delta.Download += download
	shard.traffic[userID] = delta
	shard.mu.Unlock()
}

func (s *State) SnapshotTraffic() []TrafficDelta {
	var out []TrafficDelta
	for i := range s.traffic {
		shard := &s.traffic[i]
		shard.mu.Lock()
		for _, delta := range shard.traffic {
			out = append(out, delta)
		}
		shard.traffic = make(map[int]TrafficDelta)
		shard.mu.Unlock()
	}
	return out
}

func (s *State) MergeTraffic(deltas []TrafficDelta) {
	for _, delta := range deltas {
		s.AddTraffic(delta.UserID, delta.Upload, delta.Download)
	}
}

func (s *State) AddAliveIP(userID int, ip string) {
	if userID <= 0 || ip == "" {
		return
	}
	s.aliveMu.Lock()
	ips := s.alive[userID]
	if ips == nil {
		ips = make(map[string]struct{})
		s.alive[userID] = ips
	}
	ips[ip] = struct{}{}
	s.lastSeen[userID] = time.Now()
	s.aliveMu.Unlock()
}

func (s *State) SnapshotAliveIPs() map[int]map[string]struct{} {
	s.aliveMu.Lock()
	out := s.alive
	s.alive = make(map[int]map[string]struct{})
	s.aliveMu.Unlock()
	return out
}

func (s *State) MergeAliveIPs(alive map[int]map[string]struct{}) {
	s.aliveMu.Lock()
	defer s.aliveMu.Unlock()
	for userID, ips := range alive {
		if userID <= 0 {
			continue
		}
		current := s.alive[userID]
		if current == nil {
			current = make(map[string]struct{})
			s.alive[userID] = current
		}
		for ip := range ips {
			if ip != "" {
				current[ip] = struct{}{}
			}
		}
	}
}

func (s *State) OnlineUserCount(window time.Duration) int {
	s.aliveMu.Lock()
	defer s.aliveMu.Unlock()
	now := time.Now()
	online := 0
	for userID, seenAt := range s.lastSeen {
		if now.Sub(seenAt) <= window {
			online++
		} else {
			delete(s.lastSeen, userID)
		}
	}
	return online
}

func (s *State) PendingMetrics() pendingStateMetrics {
	var metrics pendingStateMetrics
	for i := range s.traffic {
		shard := &s.traffic[i]
		shard.mu.Lock()
		metrics.TrafficUsers += len(shard.traffic)
		for _, delta := range shard.traffic {
			metrics.TrafficUploadBytes += delta.Upload
			metrics.TrafficDownloadBytes += delta.Download
		}
		shard.mu.Unlock()
	}

	s.aliveMu.Lock()
	metrics.AliveUsers = len(s.alive)
	for _, ips := range s.alive {
		metrics.AliveRecords += len(ips)
	}
	s.aliveMu.Unlock()
	return metrics
}
