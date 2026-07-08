package sstest

import (
	"sync"
	"time"
)

type RuntimeState struct {
	mu       sync.Mutex
	traffic  map[int]TrafficDelta
	alive    map[int]map[string]struct{}
	lastSeen map[int]time.Time
}

func NewRuntimeState() *RuntimeState {
	return &RuntimeState{
		traffic:  make(map[int]TrafficDelta),
		alive:    make(map[int]map[string]struct{}),
		lastSeen: make(map[int]time.Time),
	}
}

func (s *RuntimeState) AddTraffic(userID int, upload int64, download int64) {
	if upload == 0 && download == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delta := s.traffic[userID]
	delta.UserID = userID
	delta.Upload += upload
	delta.Download += download
	s.traffic[userID] = delta
}

func (s *RuntimeState) SnapshotTraffic() []TrafficDelta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TrafficDelta, 0, len(s.traffic))
	for _, delta := range s.traffic {
		out = append(out, delta)
	}
	s.traffic = make(map[int]TrafficDelta)
	return out
}

func (s *RuntimeState) AddAliveIP(userID int, ip string) {
	if ip == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ips := s.alive[userID]
	if ips == nil {
		ips = make(map[string]struct{})
		s.alive[userID] = ips
	}
	ips[ip] = struct{}{}
	s.lastSeen[userID] = time.Now()
}

func (s *RuntimeState) SnapshotAliveIPs() map[int]map[string]struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.alive
	s.alive = make(map[int]map[string]struct{})
	return out
}

func (s *RuntimeState) OnlineUserCount(window time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
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
