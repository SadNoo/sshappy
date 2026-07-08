package sstest

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestUDPClientPacketIdentifiesUserAndPayload(t *testing.T) {
	serverKey := make([]byte, 32)
	userKey := make([]byte, 32)
	for i := range serverKey {
		serverKey[i] = byte(i)
		userKey[i] = byte(31 - i)
	}
	user := udpTestUser(userKey)
	target := TargetAddress{Host: "8.8.8.8", Port: 53}
	payload := []byte{0x12, 0x34, 'd', 'n', 's'}
	packet := makeUDPClientTestPacket(t, serverKey, userKey, 0x0102030405060708, 9, target, payload)

	decoded, err := decryptUDPClientPacket(packet, map[[16]byte]*User{user.IdentityHash: user}, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.User.ID != user.ID {
		t.Fatalf("user id = %d", decoded.User.ID)
	}
	if decoded.Target != target {
		t.Fatalf("target = %#v", decoded.Target)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("payload = %x", decoded.Payload)
	}
	if decoded.ClientSessionID != 0x0102030405060708 || decoded.PacketID != 9 {
		t.Fatalf("session/packet = %x/%d", decoded.ClientSessionID, decoded.PacketID)
	}
}

func TestUDPServerPacketRoundTrips(t *testing.T) {
	userKey := make([]byte, 32)
	for i := range userKey {
		userKey[i] = byte(31 - i)
	}
	user := udpTestUser(userKey)
	target := TargetAddress{Host: "1.1.1.1", Port: 53}
	payload := []byte{0xab, 0xcd, 'r', 'e', 'p', 'l', 'y'}

	packet, err := encryptUDPServerPacket(user, target, payload, 3, 4, 5)
	if err != nil {
		t.Fatal(err)
	}
	header, err := aesECBDecryptBlock(userKey, packet[:16])
	if err != nil {
		t.Fatal(err)
	}
	var sessionIDBytes [8]byte
	binary.BigEndian.PutUint64(sessionIDBytes[:], 5)
	block, err := newAESGCM(deriveSessionSubkey(userKey, sessionIDBytes[:]))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := block.Open(nil, header[4:16], packet[16:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext[0] != udpServerType {
		t.Fatalf("type = %d", plaintext[0])
	}
	if binary.BigEndian.Uint64(plaintext[9:17]) != 3 {
		t.Fatalf("client session = %d", binary.BigEndian.Uint64(plaintext[9:17]))
	}
	if plaintext[17] != 0 || plaintext[18] != 0 {
		t.Fatalf("padding length = %x", plaintext[17:19])
	}
	decodedTarget, offset, err := parseTargetAddress(plaintext, 19)
	if err != nil {
		t.Fatal(err)
	}
	if decodedTarget != target {
		t.Fatalf("target = %#v", decodedTarget)
	}
	if !bytes.Equal(plaintext[offset:], payload) {
		t.Fatalf("payload = %x", plaintext[offset:])
	}
}

func udpTestUser(userKey []byte) *User {
	return &User{
		ID:           7,
		Email:        "u@example.test",
		Passwd:       "passwd",
		UserKey:      userKey,
		IdentityHash: identityHash(userKey),
	}
}

func makeUDPClientTestPacket(t *testing.T, serverKey []byte, userKey []byte, sessionID uint64, packetID uint64, target TargetAddress, payload []byte) []byte {
	t.Helper()
	header := make([]byte, 16)
	binary.BigEndian.PutUint64(header[:8], sessionID)
	binary.BigEndian.PutUint64(header[8:16], packetID)
	identity := identityHash(userKey)
	identityPlain := make([]byte, 16)
	for i := range identityPlain {
		identityPlain[i] = identity[i] ^ header[i]
	}
	packedTarget, err := packTargetAddress(target)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := make([]byte, 0, 1+8+2+len(packedTarget)+len(payload))
	plaintext = append(plaintext, udpClientType)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(time.Now().Unix()))
	plaintext = append(plaintext, tmp[:]...)
	plaintext = append(plaintext, 0, 0)
	plaintext = append(plaintext, packedTarget...)
	plaintext = append(plaintext, payload...)

	var sessionIDBytes [8]byte
	binary.BigEndian.PutUint64(sessionIDBytes[:], sessionID)
	block, err := newAESGCM(deriveSessionSubkey(userKey, sessionIDBytes[:]))
	if err != nil {
		t.Fatal(err)
	}
	encrypted := block.Seal(nil, header[4:16], plaintext, nil)
	encryptedHeader, err := aesECBEncryptBlock(serverKey, header)
	if err != nil {
		t.Fatal(err)
	}
	encryptedIdentity, err := aesECBEncryptBlock(serverKey, identityPlain)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 0, len(encryptedHeader)+len(encryptedIdentity)+len(encrypted))
	out = append(out, encryptedHeader...)
	out = append(out, encryptedIdentity...)
	out = append(out, encrypted...)
	return out
}
