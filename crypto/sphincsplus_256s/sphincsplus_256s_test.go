package sphincsplus_256s

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestSphincsPlus256s_GetHexSeed(t *testing.T) {
	// Create a new instance with a known seed
	var seed [CRYPTO_SEEDBYTES]uint8
	for i := range seed {
		seed[i] = byte(i)
	}

	s, err := NewSphincsPlus256sFromSeed(seed)
	if err != nil {
		t.Fatalf("NewSphincsPlus256sFromSeed failed: %v", err)
	}

	hexSeed := s.GetHexSeed()

	// Verify it starts with 0x
	if !strings.HasPrefix(hexSeed, "0x") {
		t.Errorf("GetHexSeed() should start with '0x', got %s", hexSeed)
	}

	// Verify the hex content matches the original seed
	expectedHex := "0x" + hex.EncodeToString(seed[:])
	if hexSeed != expectedHex {
		t.Errorf("GetHexSeed() = %s, want %s", hexSeed, expectedHex)
	}
}

func TestSphincsPlus256s_GetHexSeedRoundTrip(t *testing.T) {
	// Create instance
	s1, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Get hex seed
	hexSeed := s1.GetHexSeed()

	// Parse hex seed back
	if !strings.HasPrefix(hexSeed, "0x") {
		t.Fatal("GetHexSeed should return 0x-prefixed string")
	}

	seedBytes, err := hex.DecodeString(hexSeed[2:])
	if err != nil {
		t.Fatalf("Failed to decode hex seed: %v", err)
	}

	// Convert slice to fixed array
	var seedArray [CRYPTO_SEEDBYTES]uint8
	copy(seedArray[:], seedBytes)

	// Create new instance from seed
	s2, err := NewSphincsPlus256sFromSeed(seedArray)
	if err != nil {
		t.Fatalf("NewSphincsPlus256sFromSeed failed: %v", err)
	}

	// Verify seeds match
	if s1.GetHexSeed() != s2.GetHexSeed() {
		t.Error("Round-trip through GetHexSeed produced different seeds")
	}

	// Verify public keys match
	pk1 := s1.GetPK()
	pk2 := s2.GetPK()
	if pk1 != pk2 {
		t.Error("Round-trip through GetHexSeed produced different public keys")
	}
}
