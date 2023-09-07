package doubleratchet

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

type SymmetricRatchet struct {
	State [32]byte
}

func (r *SymmetricRatchet) Next(input []byte) ([]byte, []byte, error) {
	// Turn the ratchet, generating a new key
	output := make([]byte, 64+24)
	hashReader := hkdf.New(sha3.New256, append(r.State[:], input...), nil, nil)
	if _, err := io.ReadFull(hashReader, output); err != nil {
		return nil, nil, ErrKeyDerivation
	}

	// Update the state
	copy(r.State[:], output[:32])
	outKey, nonce := output[32:64], output[64:]
	return outKey, nonce, nil
}
