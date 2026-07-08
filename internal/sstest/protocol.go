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

type UDPClientPacket struct {
	User            *User
	Target          TargetAddress
	Payload         []byte
	ClientSessionID uint64
	PacketID        uint64
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

func packTargetAddress(target TargetAddress) ([]byte, error) {
	ip := net.ParseIP(target.Host)
	if ip4 := ip.To4(); ip4 != nil {
		out := make([]byte, 1+4+2)
		out[0] = 1
		copy(out[1:5], ip4)
		binary.BigEndian.PutUint16(out[5:7], uint16(target.Port))
		return out, nil
	}
	if ip16 := ip.To16(); ip16 != nil {
		out := make([]byte, 1+16+2)
		out[0] = 4
		copy(out[1:17], ip16)
		binary.BigEndian.PutUint16(out[17:19], uint16(target.Port))
		return out, nil
	}
	if len(target.Host) > 255 {
		return nil, fmt.Errorf("domain name too long")
	}
	out := make([]byte, 1+1+len(target.Host)+2)
	out[0] = 3
	out[1] = byte(len(target.Host))
	copy(out[2:2+len(target.Host)], target.Host)
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(target.Port))
	return out, nil
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

func readClientPayloadBuffered(conn net.Conn, decryptor *aeadStream, lenCipher []byte, payloadCipher []byte) ([]byte, []byte, error) {
	if _, err := io.ReadFull(conn, lenCipher[:2+tagLen]); err != nil {
		return nil, payloadCipher, err
	}
	lenPlain, err := decryptor.decryptInto(lenCipher[:0], lenCipher[:2+tagLen])
	if err != nil {
		return nil, payloadCipher, err
	}
	if len(lenPlain) != 2 {
		return nil, payloadCipher, fmt.Errorf("invalid payload length")
	}
	size := int(binary.BigEndian.Uint16(lenPlain))
	if size > tcpMaxPayloadSize {
		return nil, payloadCipher, fmt.Errorf("payload too large")
	}
	if size == 0 {
		return nil, payloadCipher, io.EOF
	}
	needed := size + tagLen
	if cap(payloadCipher) < needed {
		payloadCipher = make([]byte, needed)
	}
	payloadCipher = payloadCipher[:needed]
	if _, err := io.ReadFull(conn, payloadCipher); err != nil {
		return nil, payloadCipher, err
	}
	payload, err := decryptor.decryptInto(payloadCipher[:0], payloadCipher)
	return payload, payloadCipher, err
}

func writeResponseHeaderAndPayload(conn net.Conn, userKey []byte, requestSalt []byte, payload []byte, writeBuf []byte) (*aeadStream, []byte, error) {
	responseSalt := make([]byte, saltLen)
	if _, err := rand.Read(responseSalt); err != nil {
		return nil, writeBuf, err
	}
	encryptor, err := newAEADStream(deriveSessionSubkey(userKey, responseSalt))
	if err != nil {
		return nil, writeBuf, err
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
	needed := saltLen + len(fixed) + tagLen + len(payload) + tagLen
	if cap(writeBuf) < needed {
		writeBuf = make([]byte, 0, needed)
	}
	writeBuf = writeBuf[:0]
	writeBuf = append(writeBuf, responseSalt...)
	writeBuf = encryptor.encryptInto(writeBuf, fixed)
	writeBuf = encryptor.encryptInto(writeBuf, payload)
	if err := writeFull(conn, writeBuf); err != nil {
		return nil, writeBuf, err
	}
	return encryptor, writeBuf, nil
}

func writeResponsePayload(conn net.Conn, encryptor *aeadStream, payload []byte, writeBuf []byte) ([]byte, error) {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	needed := 2 + tagLen + len(payload) + tagLen
	if cap(writeBuf) < needed {
		writeBuf = make([]byte, 0, needed)
	}
	writeBuf = writeBuf[:0]
	writeBuf = encryptor.encryptInto(writeBuf, lenBuf[:])
	writeBuf = encryptor.encryptInto(writeBuf, payload)
	return writeBuf, writeFull(conn, writeBuf)
}

func decryptUDPClientPacket(packet []byte, usersByIdentity map[[16]byte]*User, serverKey []byte) (*UDPClientPacket, error) {
	minLen := udpHeaderLen + identityHeaderLen + tagLen + 1 + 8 + 2
	if len(packet) < minLen {
		return nil, fmt.Errorf("udp packet too short")
	}
	header, err := aesECBDecryptBlock(serverKey, packet[:udpHeaderLen])
	if err != nil {
		return nil, err
	}
	clientSessionID := binary.BigEndian.Uint64(header[:8])
	packetID := binary.BigEndian.Uint64(header[8:16])
	eihPlain, err := aesECBDecryptBlock(serverKey, packet[udpHeaderLen:udpHeaderLen+identityHeaderLen])
	if err != nil {
		return nil, err
	}
	var identity [16]byte
	for i := range identity {
		identity[i] = eihPlain[i] ^ header[i]
	}
	user := usersByIdentity[identity]
	if user == nil {
		return nil, fmt.Errorf("unknown SS2022 udp identity")
	}
	var sessionIDBytes [8]byte
	binary.BigEndian.PutUint64(sessionIDBytes[:], clientSessionID)
	block, err := newAESGCM(deriveSessionSubkey(user.UserKey, sessionIDBytes[:]))
	if err != nil {
		return nil, err
	}
	plaintext, err := block.Open(nil, header[4:16], packet[udpHeaderLen+identityHeaderLen:], nil)
	if err != nil {
		return nil, err
	}
	if len(plaintext) < 1+8+2 {
		return nil, fmt.Errorf("udp plaintext too short")
	}
	offset := 0
	if plaintext[offset] != udpClientType {
		return nil, fmt.Errorf("invalid udp client packet type")
	}
	offset++
	timestamp := int64(binary.BigEndian.Uint64(plaintext[offset : offset+8]))
	offset += 8
	if abs64(time.Now().Unix()-timestamp) > 30 {
		return nil, fmt.Errorf("udp packet timestamp outside allowed window")
	}
	paddingLen := int(binary.BigEndian.Uint16(plaintext[offset : offset+2]))
	offset += 2
	if len(plaintext) < offset+paddingLen {
		return nil, fmt.Errorf("short udp padding")
	}
	offset += paddingLen
	target, offset, err := parseTargetAddress(plaintext, offset)
	if err != nil {
		return nil, err
	}
	return &UDPClientPacket{
		User:            user,
		Target:          target,
		Payload:         plaintext[offset:],
		ClientSessionID: clientSessionID,
		PacketID:        packetID,
	}, nil
}

func encryptUDPServerPacket(user *User, target TargetAddress, payload []byte, clientSessionID uint64, packetID uint64, serverSessionID uint64) ([]byte, error) {
	header := make([]byte, udpHeaderLen)
	binary.BigEndian.PutUint64(header[:8], serverSessionID)
	binary.BigEndian.PutUint64(header[8:16], packetID)
	packedTarget, err := packTargetAddress(target)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, 0, 1+8+8+2+len(packedTarget)+len(payload))
	plaintext = append(plaintext, udpServerType)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(time.Now().Unix()))
	plaintext = append(plaintext, tmp[:]...)
	binary.BigEndian.PutUint64(tmp[:], clientSessionID)
	plaintext = append(plaintext, tmp[:]...)
	plaintext = append(plaintext, 0, 0)
	plaintext = append(plaintext, packedTarget...)
	plaintext = append(plaintext, payload...)

	var sessionIDBytes [8]byte
	binary.BigEndian.PutUint64(sessionIDBytes[:], serverSessionID)
	block, err := newAESGCM(deriveSessionSubkey(user.UserKey, sessionIDBytes[:]))
	if err != nil {
		return nil, err
	}
	encrypted := block.Seal(nil, header[4:16], plaintext, nil)
	encryptedHeader, err := aesECBEncryptBlock(user.UserKey, header)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(encryptedHeader)+len(encrypted))
	out = append(out, encryptedHeader...)
	out = append(out, encrypted...)
	return out, nil
}

func makeUDPServerSessionID() uint64 {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint64(raw[:])
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
