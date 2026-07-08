package sstest

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type ClientRequest struct {
	User           *User
	Target         TargetAddress
	InitialPayload []byte
	Decryptor      *aeadStream
	RequestSalt    []byte
}

func readClientRequest(conn net.Conn, usersByIdentity map[[16]byte]*User, serverKey []byte) (*ClientRequest, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return nil, err
	}
	identityHeader := make([]byte, identityHeaderLen)
	if _, err := io.ReadFull(conn, identityHeader); err != nil {
		return nil, err
	}
	identitySubkey := deriveIdentitySubkey(serverKey, salt)
	identityPlain, err := aesECBDecryptBlock(identitySubkey, identityHeader)
	if err != nil {
		return nil, err
	}
	var identity [16]byte
	copy(identity[:], identityPlain[:16])
	user := usersByIdentity[identity]
	if user == nil {
		return nil, fmt.Errorf("unknown SS2022 identity")
	}
	decryptor, err := newAEADStream(deriveSessionSubkey(user.UserKey, salt))
	if err != nil {
		return nil, err
	}
	fixedCipher := make([]byte, 11+tagLen)
	if _, err := io.ReadFull(conn, fixedCipher); err != nil {
		return nil, err
	}
	fixed, err := decryptor.decrypt(fixedCipher)
	if err != nil {
		return nil, err
	}
	if len(fixed) != 11 {
		return nil, fmt.Errorf("invalid fixed header")
	}
	if fixed[0] != 0 {
		return nil, fmt.Errorf("invalid client header type")
	}
	ts := int64(binary.BigEndian.Uint64(fixed[1:9]))
	if abs64(time.Now().Unix()-ts) > 30 {
		return nil, fmt.Errorf("timestamp outside allowed window")
	}
	variableLen := int(binary.BigEndian.Uint16(fixed[9:11]))
	if variableLen <= 0 || variableLen > tcpMaxPayloadSize {
		return nil, fmt.Errorf("invalid variable header length")
	}
	varCipher := make([]byte, variableLen+tagLen)
	if _, err := io.ReadFull(conn, varCipher); err != nil {
		return nil, err
	}
	variable, err := decryptor.decrypt(varCipher)
	if err != nil {
		return nil, err
	}
	target, payload, padding, err := parseClientVariableHeader(variable)
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 && padding == 0 {
		return nil, fmt.Errorf("request header has no payload or padding")
	}
	return &ClientRequest{
		User:           user,
		Target:         target,
		InitialPayload: payload,
		Decryptor:      decryptor,
		RequestSalt:    salt,
	}, nil
}

func parseClientVariableHeader(data []byte) (TargetAddress, []byte, int, error) {
	target, offset, err := parseTargetAddress(data, 0)
	if err != nil {
		return target, nil, 0, err
	}
	if len(data) < offset+2 {
		return target, nil, 0, fmt.Errorf("short padding length")
	}
	paddingLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if len(data) < offset+paddingLen {
		return target, nil, 0, fmt.Errorf("short padding")
	}
	offset += paddingLen
	return target, data[offset:], paddingLen, nil
}

func parseTargetAddress(data []byte, offset int) (TargetAddress, int, error) {
	var target TargetAddress
	if len(data) < offset+1 {
		return target, offset, fmt.Errorf("empty address")
	}
	atyp := data[offset]
	offset++
	switch atyp {
	case 1:
		if len(data) < offset+4 {
			return target, offset, fmt.Errorf("short ipv4")
		}
		target.Host = net.IP(data[offset : offset+4]).String()
		offset += 4
	case 3:
		if len(data) < offset+1 {
			return target, offset, fmt.Errorf("short domain length")
		}
		n := int(data[offset])
		offset++
		if len(data) < offset+n {
			return target, offset, fmt.Errorf("short domain")
		}
		target.Host = string(data[offset : offset+n])
		offset += n
	case 4:
		if len(data) < offset+16 {
			return target, offset, fmt.Errorf("short ipv6")
		}
		target.Host = net.IP(data[offset : offset+16]).String()
		offset += 16
	default:
		return target, offset, fmt.Errorf("unsupported address type")
	}
	if len(data) < offset+2 {
		return target, offset, fmt.Errorf("short port")
	}
	target.Port = int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	return target, offset, nil
}

func readClientPayload(conn net.Conn, decryptor *aeadStream) ([]byte, error) {
	lenCipher := make([]byte, 2+tagLen)
	if _, err := io.ReadFull(conn, lenCipher); err != nil {
		return nil, err
	}
	lenPlain, err := decryptor.decrypt(lenCipher)
	if err != nil {
		return nil, err
	}
	if len(lenPlain) != 2 {
		return nil, fmt.Errorf("invalid payload length")
	}
	size := int(binary.BigEndian.Uint16(lenPlain))
	if size > tcpMaxPayloadSize {
		return nil, fmt.Errorf("payload too large")
	}
	if size == 0 {
		return nil, io.EOF
	}
	payloadCipher := make([]byte, size+tagLen)
	if _, err := io.ReadFull(conn, payloadCipher); err != nil {
		return nil, err
	}
	return decryptor.decrypt(payloadCipher)
}

func writeResponseHeaderAndPayload(conn net.Conn, userKey []byte, requestSalt []byte, payload []byte) (*aeadStream, error) {
	responseSalt := make([]byte, saltLen)
	if _, err := rand.Read(responseSalt); err != nil {
		return nil, err
	}
	encryptor, err := newAEADStream(deriveSessionSubkey(userKey, responseSalt))
	if err != nil {
		return nil, err
	}
	fixed := make([]byte, 0, 1+8+len(requestSalt)+2)
	fixed = append(fixed, 1)
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, uint64(time.Now().Unix()))
	fixed = append(fixed, tmp...)
	fixed = append(fixed, requestSalt...)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(payload)))
	fixed = append(fixed, lenBuf...)
	if err := writeFull(conn, responseSalt); err != nil {
		return nil, err
	}
	if err := writeFull(conn, encryptor.encrypt(fixed)); err != nil {
		return nil, err
	}
	if err := writeFull(conn, encryptor.encrypt(payload)); err != nil {
		return nil, err
	}
	return encryptor, nil
}

func writeResponsePayload(conn net.Conn, encryptor *aeadStream, payload []byte) error {
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(payload)))
	if err := writeFull(conn, encryptor.encrypt(lenBuf)); err != nil {
		return err
	}
	return writeFull(conn, encryptor.encrypt(payload))
}

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
	raw := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' ' })
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

func abs64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}
