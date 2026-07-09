package panel

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

func decodePSK(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(raw) != KeyLen {
		return nil, fmt.Errorf("2022 key must decode to 32 bytes")
	}
	return raw, nil
}

func deriveUserKey(userID int, passwd string, nodeID int, serverKeyB64 string) ([]byte, string) {
	material := strings.Join([]string{
		strconv.Itoa(userID),
		passwd,
		Method,
		strconv.Itoa(nodeID),
		serverKeyB64,
	}, "|")
	sum := sha256.Sum256([]byte(material))
	return sum[:], base64.StdEncoding.EncodeToString(sum[:])
}
