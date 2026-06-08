package mlkem1024_test

import (
	"bytes"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/mlkem1024"
)

// TestDecapsulationKeyZeroize verifies the public Zeroize wrapper clears the
// decapsulation key seed.
func TestDecapsulationKeyZeroize(t *testing.T) {
	dk, err := mlkem1024.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	dk.Zeroize()
	if !bytes.Equal(dk.Bytes(), make([]byte, mlkem1024.SeedSize)) {
		t.Fatal("Zeroize did not clear the decapsulation key seed")
	}
}
