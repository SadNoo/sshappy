package sstest

import (
	"fmt"
	"net"
	"strings"
)

func isForbiddenPort(user *User, port int) bool {
	for _, rule := range splitRules(user.ForbiddenPort) {
		if strings.Contains(rule, "-") || strings.Contains(rule, ":") {
			sep := "-"
			if strings.Contains(rule, ":") {
				sep = ":"
			}
			parts := strings.SplitN(rule, sep, 2)
			left, lerr := parseInt(parts[0])
			right, rerr := parseInt(parts[1])
			if lerr == nil && rerr == nil && left <= port && port <= right {
				return true
			}
		} else if value, err := parseInt(rule); err == nil && value == port {
			return true
		}
	}
	return false
}

func isForbiddenHost(user *User, host string) bool {
	rules := splitRules(user.ForbiddenIP)
	if len(rules) == 0 {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, rule := range rules {
		if strings.Contains(rule, "/") {
			if _, network, err := net.ParseCIDR(rule); err == nil && network.Contains(ip) {
				return true
			}
			continue
		}
		if other := net.ParseIP(rule); other != nil && other.Equal(ip) {
			return true
		}
	}
	return false
}

func isDisconnectIP(user *User, ip string) bool {
	for _, rule := range splitRules(user.DisconnectIP) {
		if rule == ip {
			return true
		}
	}
	return false
}

func splitRules(value string) []string {
	raw := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parseInt(value string) (int, error) {
	var out int
	_, err := fmt.Sscanf(value, "%d", &out)
	return out, err
}
