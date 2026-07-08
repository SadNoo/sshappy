package sstest

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

func aesECBDecryptBlock(key []byte, block []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, aes.BlockSize)
	c.Decrypt(out, block)
	return out, nil
}

type aeadStream struct {
	aead    cipher.AEAD
	counter uint64
}

func newAEADStream(key []byte) (*aeadStream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &aeadStream{aead: aead}, nil
}

func (s *aeadStream) nonce() []byte {
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[:8], s.counter)
	return nonce
}

func (s *aeadStream) decrypt(data []byte) ([]byte, error) {
	out, err := s.aead.Open(nil, s.nonce(), data, nil)
	if err != nil {
		return nil, err
	}
	s.counter++
	return out, nil
}

func (s *aeadStream) encrypt(data []byte) []byte {
	out := s.aead.Seal(nil, s.nonce(), data, nil)
	s.counter++
	return out
}
