package ss2022

import (
	"bytes"
	"crypto/rand"
	"strconv"
	"strings"
	"testing"
)

func TestPSKLengthErrorRedactsPSK(t *testing.T) {
	err := (&PSKLengthError{PSK: []byte("secret"), ExpectedLength: 32}).Error()
	if strings.Contains(err, "secret") || strings.Contains(err, "c2VjcmV0") {
		t.Fatalf("PSKLengthError disclosed the PSK: %q", err)
	}
}

func TestCipherConfigsCloneKeyInputsAndSliceOutputs(t *testing.T) {
	psk := bytes.Repeat([]byte{1}, 16)
	iPSK := bytes.Repeat([]byte{2}, 16)
	client, err := NewClientCipherConfig(psk, [][]byte{iPSK}, true)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := NewServerIdentityCipherConfig(iPSK, true)
	if err != nil {
		t.Fatal(err)
	}

	psk[0] = 9
	iPSK[0] = 9
	if client.PSK[0] != 1 || client.iPSKs[0][0] != 2 || identity.IPSK[0] != 2 {
		t.Fatal("mutating constructor inputs changed cipher configuration")
	}

	// The exported fields remain available for source compatibility, but must
	// not alias the immutable key material used by live cipher operations.
	client.PSK[0] = 8
	identity.IPSK[0] = 8
	if client.keyMaterial()[0] != 1 || identity.keyMaterial()[0] != 2 {
		t.Fatal("mutating exported key views changed live cipher key material")
	}
	if _, err = client.AEAD(bytes.Repeat([]byte{3}, 16)); err != nil {
		t.Fatalf("client cipher stopped working after exported PSK mutation: %v", err)
	}
	if _, err = identity.TCP(bytes.Repeat([]byte{4}, 16)); err != nil {
		t.Fatalf("identity cipher stopped working after exported IPSK mutation: %v", err)
	}

	hashes := client.EIHPSKHashes()
	wantHash := hashes[0]
	hashes[0] = [IdentityHeaderLength]byte{}
	if got := client.EIHPSKHashes()[0]; got != wantHash {
		t.Fatal("EIHPSKHashes returned mutable internal storage")
	}
	ciphers := client.UDPIdentityHeaderCiphers()
	ciphers[0] = nil
	if client.UDPIdentityHeaderCiphers()[0] == nil {
		t.Fatal("UDPIdentityHeaderCiphers returned mutable internal storage")
	}
}

var (
	methodCases = [...]string{
		"2022-blake3-aes-128-gcm",
		"2022-blake3-aes-256-gcm",
	}

	cipherCases = [...]struct {
		name            string
		newCipherConfig func(method string, enableUDP bool) (
			clientCipherConfig *ClientCipherConfig,
			userCipherConfig UserCipherConfig,
			identityCipherConfig ServerIdentityCipherConfig,
			userLookupMap UserLookupMap,
			username string,
			err error,
		)
	}{
		{
			name:            "NoEIH",
			newCipherConfig: newRandomCipherConfigTupleNoEIH,
		},
		{
			name:            "WithEIH",
			newCipherConfig: newRandomCipherConfigTupleWithEIH,
		},
	}
)

func newRandomCipherConfigTupleNoEIH(method string, enableUDP bool) (clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, _ ServerIdentityCipherConfig, _ UserLookupMap, _ string, err error) {
	keySize, err := PSKLengthForMethod(method)
	if err != nil {
		return
	}
	psk := make([]byte, keySize)
	rand.Read(psk)
	clientCipherConfig, err = NewClientCipherConfig(psk, nil, enableUDP)
	if err != nil {
		return
	}
	userCipherConfig, err = NewUserCipherConfig(psk, enableUDP)
	return
}

func newRandomCipherConfigTupleWithEIH(method string, enableUDP bool) (clientCipherConfig *ClientCipherConfig, userCipherConfig UserCipherConfig, identityCipherConfig ServerIdentityCipherConfig, userLookupMap UserLookupMap, username string, err error) {
	keySize, err := PSKLengthForMethod(method)
	if err != nil {
		return
	}

	iPSK := make([]byte, keySize)
	rand.Read(iPSK)
	iPSKs := [][]byte{iPSK}

	var uPSK []byte
	userLookupMap = make(UserLookupMap, 7)
	for i := range 7 {
		uPSK = make([]byte, keySize)
		rand.Read(uPSK)
		username = strconv.Itoa(i)

		uPSKHash := PSKHash(uPSK)
		var c ServerUserCipherConfig
		c, err = NewServerUserCipherConfig(username, uPSK, enableUDP)
		if err != nil {
			return
		}

		userLookupMap[uPSKHash] = c
	}

	clientCipherConfig, err = NewClientCipherConfig(uPSK, iPSKs, enableUDP)
	if err != nil {
		return
	}
	identityCipherConfig, err = NewServerIdentityCipherConfig(iPSK, enableUDP)
	return
}
