package x3dh

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/curve25519"
)

var (
	ErrInvalidKey = errors.New("invalid-key")
)

// Key X25519 with extra methods
type Key struct {
	Public  [32]byte
	Private [32]byte
}

// GenerateKey generates a new key pair for X25519
func GenerateKey() (*Key, error) {
	var k Key
	if _, err := rand.Read(k.Private[:]); err != nil {
		return nil, err
	}

	curve25519.ScalarBaseMult(&k.Public, &k.Private)
	return &k, nil
}

func (k *Key) Exchange(other *Key) ([]byte, error) {
	if other == nil || k == nil {
		return nil, ErrInvalidKey
	}

	shared, err := curve25519.X25519(k.Private[:], other.Public[:])
	if err != nil {
		return nil, err
	}

	return shared, nil
}
