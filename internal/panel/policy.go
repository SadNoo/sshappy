package panel

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/database64128/shadowsocks-go/conn"
)

type portRange struct {
	from uint16
	to   uint16
}

type userPolicy struct {
	forbiddenIPs   []netip.Prefix
	forbiddenPorts []portRange
	disconnectIPs  map[netip.Addr]struct{}
	revision       [sha256.Size]byte
}

// UserPolicyError identifies one invalid per-user policy without exposing the
// user's email, password, key, or complete policy value.
type UserPolicyError struct {
	UserID    int
	Field     string
	RuleIndex int
	Err       error
}

func (e UserPolicyError) Error() string {
	return fmt.Sprintf("user %d has invalid %s rule %d: %v", e.UserID, e.Field, e.RuleIndex, e.Err)
}

func (e UserPolicyError) Unwrap() error {
	return e.Err
}

type policyRuleError struct {
	field     string
	ruleIndex int
	err       error
}

func (e *policyRuleError) Error() string {
	return e.err.Error()
}

func compileUserPolicy(user User) (userPolicy, error) {
	if user.ID <= 0 {
		return userPolicy{}, &policyRuleError{
			field:     "id",
			ruleIndex: 0,
			err:       errors.New("user ID must be positive"),
		}
	}

	policy := userPolicy{
		disconnectIPs: make(map[netip.Addr]struct{}),
		revision:      userAuthorizationRevision(user),
	}

	for i, rule := range splitPolicyRules(user.ForbiddenIP) {
		prefix, err := parsePolicyPrefix(rule)
		if err != nil {
			return userPolicy{}, &policyRuleError{field: "forbidden_ip", ruleIndex: i + 1, err: err}
		}
		policy.forbiddenIPs = append(policy.forbiddenIPs, prefix)
	}

	for i, rule := range splitPolicyRules(user.ForbiddenPort) {
		rangeRule, err := parsePolicyPortRange(rule)
		if err != nil {
			return userPolicy{}, &policyRuleError{field: "forbidden_port", ruleIndex: i + 1, err: err}
		}
		policy.forbiddenPorts = append(policy.forbiddenPorts, rangeRule)
	}

	for i, rule := range splitPolicyRules(user.DisconnectIP) {
		ip, err := netip.ParseAddr(rule)
		if err != nil || ip.Zone() != "" {
			if err != nil {
				err = errors.New("must be a literal IP address")
			} else {
				err = errors.New("scoped IP addresses are not supported")
			}
			return userPolicy{}, &policyRuleError{field: "disconnect_ip", ruleIndex: i + 1, err: err}
		}
		policy.disconnectIPs[ip.Unmap()] = struct{}{}
	}

	return policy, nil
}

func parsePolicyPrefix(rule string) (netip.Prefix, error) {
	if strings.ContainsRune(rule, '/') {
		prefix, err := netip.ParsePrefix(rule)
		if err != nil {
			return netip.Prefix{}, errors.New("must be a valid IP prefix")
		}
		if prefix.Addr().Zone() != "" {
			return netip.Prefix{}, errors.New("scoped IP prefixes are not supported")
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return netip.Prefix{}, errors.New("IPv4-mapped prefix must be at least /96")
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		return prefix.Masked(), nil
	}

	ip, err := netip.ParseAddr(rule)
	if err != nil {
		return netip.Prefix{}, errors.New("must be a valid IP address")
	}
	if ip.Zone() != "" {
		return netip.Prefix{}, errors.New("scoped IP addresses are not supported")
	}
	ip = ip.Unmap()
	return netip.PrefixFrom(ip, ip.BitLen()), nil
}

func parsePolicyPortRange(rule string) (portRange, error) {
	separator := byte(0)
	for _, candidate := range []byte{'-', ':'} {
		if strings.ContainsRune(rule, rune(candidate)) {
			if separator != 0 || strings.Count(rule, string(candidate)) != 1 {
				return portRange{}, errors.New("port range must contain exactly one '-' or ':' separator")
			}
			separator = candidate
		}
	}

	if separator == 0 {
		port, err := parsePolicyPort(rule)
		return portRange{from: port, to: port}, err
	}

	left, right, ok := strings.Cut(rule, string(separator))
	if !ok || left == "" || right == "" {
		return portRange{}, errors.New("port range is missing an endpoint")
	}
	from, err := parsePolicyPort(left)
	if err != nil {
		return portRange{}, err
	}
	to, err := parsePolicyPort(right)
	if err != nil {
		return portRange{}, err
	}
	if from > to {
		return portRange{}, errors.New("port range start exceeds end")
	}
	return portRange{from: from, to: to}, nil
}

func parsePolicyPort(value string) (uint16, error) {
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, errors.New("port must be a base-10 integer between 1 and 65535")
	}
	if port == 0 {
		return 0, errors.New("port must be between 1 and 65535")
	}
	return uint16(port), nil
}

func userAuthorizationRevision(user User) [sha256.Size]byte {
	h := sha256.New()
	fields := [][]byte{
		[]byte(user.ForbiddenIP),
		[]byte(user.ForbiddenPort),
		[]byte(user.DisconnectIP),
		user.UserKey,
		[]byte(user.UserKeyB64),
		[]byte(user.Passwd),
	}
	var size [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(field)
	}
	var revision [sha256.Size]byte
	copy(revision[:], h.Sum(nil))
	return revision
}

func (p userPolicy) accepts(source netip.Addr, target conn.Addr) bool {
	if _, disconnected := p.disconnectIPs[source.Unmap()]; disconnected {
		return false
	}
	port := target.Port()
	for _, forbidden := range p.forbiddenPorts {
		if forbidden.from <= port && port <= forbidden.to {
			return false
		}
	}
	if target.IsIP() {
		ip := target.IP().Unmap()
		for _, forbidden := range p.forbiddenIPs {
			if forbidden.Contains(ip) {
				return false
			}
		}
	}
	return true
}

func splitPolicyRules(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
}
