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

func aesECBEncryptBlock(key []byte, block []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, aes.BlockSize)
	c.Encrypt(out, block)
	return out, nil
}

type aeadStream struct {
	aead    cipher.AEAD
	counter uint64
}

func newAEADStream(key []byte) (*aeadStream, error) {
	aead, err := newAESGCM(key)
	if err != nil {
		return nil, err
	}
	return &aeadStream{aead: aead}, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

func (s *aeadStream) nonce() [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[:8], s.counter)
	return nonce
}

func (s *aeadStream) decrypt(data []byte) ([]byte, error) {
	return s.decryptInto(nil, data)
}

func (s *aeadStream) decryptInto(dst []byte, data []byte) ([]byte, error) {
	nonce := s.nonce()
	out, err := s.aead.Open(dst, nonce[:], data, nil)
	if err != nil {
		return nil, err
	}
	s.counter++
	return out, nil
}

func (s *aeadStream) encrypt(data []byte) []byte {
	return s.encryptInto(nil, data)
}

func (s *aeadStream) encryptInto(dst []byte, data []byte) []byte {
	nonce := s.nonce()
	out := s.aead.Seal(dst, nonce[:], data, nil)
	s.counter++
	return out
}
