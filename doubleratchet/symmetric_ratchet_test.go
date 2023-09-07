package doubleratchet

import (
	"encoding/base64"
	"fmt"
	"github.com/Winens/libwisp/hkdf"
	"github.com/Winens/libwisp/x3dh"
	"golang.org/x/crypto/chacha20poly1305"
	"testing"
)

func TestSymmetricRatchet_Next(t *testing.T) {
	// Alice generates her keys
	aliceIK, err := x3dh.GenerateKey()
	if err != nil {
		t.Error(err)
	}

	aliceEPK, err := x3dh.GenerateKey()
	if err != nil {
		t.Error(err)
	}

	// Bob generates his keys
	bobIK, err := x3dh.GenerateKey()
	if err != nil {
		t.Error(err)
	}

	bobSPK, err := x3dh.GenerateKey()
	if err != nil {
		t.Error(err)
	}

	bobOPK, _ := x3dh.GenerateKey()

	// Alice X3DH
	var aliceShared []byte
	{
		dh1, err := aliceIK.Exchange(bobSPK.Public)
		if err != nil {
			t.Error(err)
		}

		dh2, err := aliceEPK.Exchange(bobIK.Public)
		if err != nil {
			t.Error(err)
		}

		dh3, err := aliceEPK.Exchange(bobSPK.Public)
		if err != nil {
			t.Error(err)
		}

		dh4, err := aliceEPK.Exchange(bobOPK.Public)
		if err != nil {
			t.Error(err)
		}

		// HKDF
		aliceHKDF, err := hkdf.HKDF(dh1, dh2, dh3, dh4)
		if err != nil {
			t.Error(err)
		}

		aliceShared = aliceHKDF
		fmt.Println("aliceHKDF: ", base64.StdEncoding.EncodeToString(aliceShared))
	}

	// Bob X3DH
	var bobShared []byte
	{
		dh1, err := bobSPK.Exchange(aliceIK.Public)
		if err != nil {
			t.Error(err)
		}

		dh2, err := bobIK.Exchange(aliceEPK.Public)
		if err != nil {
			t.Error(err)
		}

		dh3, err := bobSPK.Exchange(aliceEPK.Public)
		if err != nil {
			t.Error(err)
		}

		dh4, err := bobOPK.Exchange(aliceEPK.Public)
		if err != nil {
			t.Error(err)
		}

		// HKDF
		bobHKDF, err := hkdf.HKDF(dh1, dh2, dh3, dh4)
		if err != nil {
			t.Error(err)
		}
		bobShared = bobHKDF
		fmt.Println("bobHKDF: ", base64.StdEncoding.EncodeToString(bobShared))
	}

	// DH ratchet
	// Alice
	aliceDHRatchet, _ := x3dh.GenerateKey()
	aliceRootRatchet := SymmetricRatchet{}
	copy(aliceRootRatchet.State[:], aliceShared)

	x, _, _ := aliceRootRatchet.Next(nil)
	aliceRecv := SymmetricRatchet{}
	copy(aliceRecv.State[:], x)

	x, _, _ = aliceRootRatchet.Next(nil)
	aliceSend := SymmetricRatchet{}
	copy(aliceSend.State[:], x)

	// Bob
	bobDHRatchet, _ := x3dh.GenerateKey()
	bobRootRatchet := SymmetricRatchet{}
	copy(bobRootRatchet.State[:], bobShared)

	x, _, _ = aliceRootRatchet.Next(nil)
	bobRecv := SymmetricRatchet{}
	copy(bobRecv.State[:], x)

	x, _, _ = aliceRootRatchet.Next(nil)
	bobSend := SymmetricRatchet{}
	copy(bobSend.State[:], x)

	// Alice -> Bob
	var alicesMsgCipher []byte
	var alicesMsgNonce []byte
	{
		aliceMsg := []byte("Hello Bob!")
		aliceDH, err := aliceDHRatchet.Exchange(bobDHRatchet.Public)
		if err != nil {
			t.Error(err)
		}
		aliceKey, aliceNone, err := aliceSend.Next(aliceDH)
		if err != nil {
			t.Error(err)
		}
		ci, err := chacha20poly1305.NewX(aliceKey)
		if err != nil {
			t.Error(err)
		}
		fmt.Println(string(aliceKey))
		aliceCiphertext := ci.Seal(aliceNone, aliceNone, aliceMsg, nil)
		alicesMsgCipher = aliceCiphertext
		alicesMsgNonce = aliceNone
		fmt.Println("aliceCiphertext: ", base64.StdEncoding.EncodeToString(aliceCiphertext))
	}

	// Bob receives
	{
		dhRecv, err := bobDHRatchet.Exchange(aliceDHRatchet.Public)
		if err != nil {
			t.Error(err)
		}
		bobKey, _, err := bobRecv.Next(dhRecv)
		if err != nil {
			t.Error(err)
		}
		ci, err := chacha20poly1305.NewX(bobKey)
		if err != nil {
			t.Error(err)
		}

		fmt.Println(string(bobKey))
		//nonce, ciphertext := alicesMsgCipher[:ci.NonceSize()], alicesMsgCipher[ci.NonceSize():]
		bobsMsg, err := ci.Open(nil, alicesMsgNonce, alicesMsgCipher, nil)
		if err != nil {
			t.Error(err)
		}

		fmt.Println("Bob decrypts: ", string(bobsMsg))
	}

}
