package hkdf

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"github.com/Winens/libwisp/x3dh"
	"testing"
)

func TestHKDF(t *testing.T) {
	// Generate keys
	alice, err := x3dh.GenerateKey()
	if err != nil {
		t.Error(err)
	}

	bob, err := x3dh.GenerateKey()
	if err != nil {
		t.Error(err)
	}

	// Alice -> Bob
	aliceShared, err := alice.Exchange(bob)
	if err != nil {
		t.Error(err)
	}

	// Bob -> Alice
	bobShared, err := bob.Exchange(alice)
	if err != nil {
		t.Error(err)
	}

	// HKDF
	aliceHKDF, err := HKDF(aliceShared, bobShared[:])
	if err != nil {
		t.Error(err)
	}

	bobHKDF, err := HKDF(bobShared, aliceShared)
	if err != nil {
		t.Error(err)
	}

	// Compare
	if subtle.ConstantTimeCompare(aliceHKDF, bobHKDF) != 1 {
		t.Error("hkdf: key derivation failed")
	}

	fmt.Println("aliceHKDF: ", base64.StdEncoding.EncodeToString(aliceHKDF))
	fmt.Println("bobHKDF: ", base64.StdEncoding.EncodeToString(bobHKDF))
}
