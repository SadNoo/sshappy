package panel

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/database64128/shadowsocks-go/conn"
	"github.com/database64128/shadowsocks-go/stats"
)

type policySet struct {
	users map[int]User
}

type Runtime struct {
	state    *State
	base     stats.Collector
	policies atomic.Pointer[policySet]
}

func NewRuntime(state *State) *Runtime {
	r := &Runtime{
		state: state,
		base:  stats.NewServerCollector(),
	}
	r.policies.Store(&policySet{users: make(map[int]User)})
	return r
}

func (r *Runtime) ReplaceUsers(users []User) {
	next := make(map[int]User, len(users))
	for _, user := range users {
		next[user.ID] = user
	}
	r.policies.Store(&policySet{users: next})
}

func (r *Runtime) Accept(_ string, username string, source netip.AddrPort, target conn.Addr) bool {
	userID, err := strconv.Atoi(username)
	if err != nil {
		return false
	}
	user, ok := r.policies.Load().users[userID]
	if !ok {
		return false
	}
	sourceIP := source.Addr().Unmap().String()
	if isDisconnectIP(user, sourceIP) ||
		isForbiddenPort(user, int(target.Port())) ||
		isForbiddenHost(user, target.Host()) {
		return false
	}
	return true
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

func isForbiddenPort(user User, port int) bool {
	for _, rule := range splitRules(user.ForbiddenPort) {
		var left, right int
		switch {
		case strings.Contains(rule, "-"):
			if _, err := fmt.Sscanf(rule, "%d-%d", &left, &right); err == nil && left <= port && port <= right {
				return true
			}
		case strings.Contains(rule, ":"):
			if _, err := fmt.Sscanf(rule, "%d:%d", &left, &right); err == nil && left <= port && port <= right {
				return true
			}
		default:
			if value, err := strconv.Atoi(rule); err == nil && value == port {
				return true
			}
		}
	}
	return false
}

func isForbiddenHost(user User, host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, rule := range splitRules(user.ForbiddenIP) {
		if strings.Contains(rule, "/") {
			if _, network, err := net.ParseCIDR(rule); err == nil && network.Contains(ip) {
				return true
			}
		} else if other := net.ParseIP(rule); other != nil && other.Equal(ip) {
			return true
		}
	}
	return false
}

func isDisconnectIP(user User, ip string) bool {
	for _, rule := range splitRules(user.DisconnectIP) {
		if rule == ip {
			return true
		}
	}
	return false
}

func splitRules(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
}
