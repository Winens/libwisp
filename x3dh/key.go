package x3dh

import (
	"crypto/rand"
	"golang.org/x/crypto/curve25519"
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
