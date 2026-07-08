package sstest

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/zeebo/blake3"
)

const (
	identitySubkeyContext = "shadowsocks 2022 identity subkey"
	sessionSubkeyContext  = "shadowsocks 2022 session subkey"
)

func decodePSK(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(raw) != keyLen {
		return nil, fmt.Errorf("2022 key must decode to 32 bytes")
	}
	return raw, nil
}

func deriveUserKeyB64(userID int, passwd string, nodeID int, serverKeyB64 string) string {
	material := strings.Join([]string{fmt.Sprint(userID), passwd, method, fmt.Sprint(nodeID), serverKeyB64}, "|")
	sum := sha256.Sum256([]byte(material))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func identityHash(key []byte) [16]byte {
	sum := blake3.Sum256(key)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

func deriveIdentitySubkey(serverKey []byte, salt []byte) []byte {
	material := make([]byte, 0, len(serverKey)+len(salt))
	material = append(material, serverKey...)
	material = append(material, salt...)
	return deriveKey(identitySubkeyContext, material)
}

func deriveSessionSubkey(psk []byte, salt []byte) []byte {
	material := make([]byte, 0, len(psk)+len(salt))
	material = append(material, psk...)
	material = append(material, salt...)
	return deriveKey(sessionSubkeyContext, material)
}

func deriveKey(context string, material []byte) []byte {
	out := make([]byte, 32)
	blake3.DeriveKey(context, material, out)
	return out
}
