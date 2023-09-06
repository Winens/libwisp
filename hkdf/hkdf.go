package hkdf

import (
	"errors"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
	"io"
)

var (
	ErrInvalidInput  = errors.New("invalid-input")
	ErrKeyDerivation = errors.New("key-derivation")
)

func HKDF(keys ...[]byte) ([]byte, error) {
	if len(keys) == 0 {
		return nil, ErrInvalidInput
	}

	combined := make([]byte, 0, 32*len(keys))
	for index := range keys {
		combined = append(combined, keys[index]...)
	}

	hash := make([]byte, 32*len(keys))
	hashReader := hkdf.New(sha3.New512, combined, nil, nil)
	if _, err := io.ReadFull(hashReader, hash); err != nil {
		return nil, ErrKeyDerivation
	}

	return hash, nil
}
