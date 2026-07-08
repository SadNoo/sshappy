package sstest

import (
	"sync"
	"time"
)

const trafficShardCount = 32

type trafficShard struct {
	mu      sync.Mutex
	traffic map[int]TrafficDelta
}

type RuntimeState struct {
	traffic  [trafficShardCount]trafficShard
	aliveMu  sync.Mutex
	alive    map[int]map[string]struct{}
	lastSeen map[int]time.Time
}

func NewRuntimeState() *RuntimeState {
	state := &RuntimeState{
		alive:    make(map[int]map[string]struct{}),
		lastSeen: make(map[int]time.Time),
	}
	for i := range state.traffic {
		state.traffic[i].traffic = make(map[int]TrafficDelta)
	}
	return state
}

func (s *RuntimeState) AddTraffic(userID int, upload int64, download int64) {
	if upload == 0 && download == 0 {
		return
	}
	shard := s.trafficShard(userID)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	delta := shard.traffic[userID]
	delta.UserID = userID
	delta.Upload += upload
	delta.Download += download
	shard.traffic[userID] = delta
}

func (s *RuntimeState) SnapshotTraffic() []TrafficDelta {
	out := make([]TrafficDelta, 0)
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

func (s *RuntimeState) MergeTraffic(deltas []TrafficDelta) {
	for _, delta := range deltas {
		s.AddTraffic(delta.UserID, delta.Upload, delta.Download)
	}
}

func (s *RuntimeState) AddAliveIP(userID int, ip string) {
	if ip == "" {
		return
	}
	s.aliveMu.Lock()
	defer s.aliveMu.Unlock()
	ips := s.alive[userID]
	if ips == nil {
		ips = make(map[string]struct{})
		s.alive[userID] = ips
	}
	ips[ip] = struct{}{}
	s.lastSeen[userID] = time.Now()
}

func (s *RuntimeState) SnapshotAliveIPs() map[int]map[string]struct{} {
	s.aliveMu.Lock()
	defer s.aliveMu.Unlock()
	out := s.alive
	s.alive = make(map[int]map[string]struct{})
	return out
}

func (s *RuntimeState) OnlineUserCount(window time.Duration) int {
	s.aliveMu.Lock()
	defer s.aliveMu.Unlock()
	now := time.Now()
	online := 0
	for userID, seenAt := range s.lastSeen {
		if now.Sub(seenAt) <= window {
			online++
			continue
		}
		delete(s.lastSeen, userID)
	}
	return online
}

func (s *RuntimeState) trafficShard(userID int) *trafficShard {
	if userID < 0 {
		userID = -userID
	}
	return &s.traffic[userID%trafficShardCount]
}
