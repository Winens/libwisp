package x3dh

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Public:", base64.StdEncoding.EncodeToString(k.Public[:]))
	fmt.Println("Private:", base64.StdEncoding.EncodeToString(k.Private[:]))
}
