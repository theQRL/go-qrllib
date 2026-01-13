package common

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestToSeed_Valid(t *testing.T) {
	seedBytes := make([]byte, SeedSize)
	for i := range seedBytes {
		seedBytes[i] = byte(i)
	}

	seed, err := ToSeed(seedBytes)
	if err != nil {
		t.Fatalf("ToSeed failed: %v", err)
	}

	if !bytes.Equal(seed[:], seedBytes) {
		t.Error("seed bytes mismatch")
	}
}

func TestToSeed_InvalidSize(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"too short", SeedSize - 1},
		{"too long", SeedSize + 1},
		{"empty", 0},
		{"half size", SeedSize / 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seedBytes := make([]byte, tt.size)
			_, err := ToSeed(seedBytes)
			if err == nil {
				t.Errorf("expected error for size %d", tt.size)
			}
		})
	}
}

func TestSeed_ToBytes(t *testing.T) {
	var seed Seed
	for i := range seed {
		seed[i] = byte(i * 3)
	}

	bytes := seed.ToBytes()
	if len(bytes) != SeedSize {
		t.Errorf("ToBytes length: got %d, want %d", len(bytes), SeedSize)
	}

	for i := range seed {
		if bytes[i] != seed[i] {
			t.Errorf("ToBytes mismatch at %d: got %d, want %d", i, bytes[i], seed[i])
		}
	}
}

func TestSeed_HashSHA256(t *testing.T) {
	var seed Seed
	for i := range seed {
		seed[i] = byte(i)
	}

	hash1 := seed.HashSHA256()
	hash2 := seed.HashSHA256()

	// Deterministic
	if hash1 != hash2 {
		t.Error("SHA256 hash should be deterministic")
	}

	// Correct size
	if len(hash1) != 32 {
		t.Errorf("SHA256 hash size: got %d, want 32", len(hash1))
	}

	// Different seed produces different hash
	var seed2 Seed
	seed2[0] = 1
	hash3 := seed2.HashSHA256()
	if hash1 == hash3 {
		t.Error("different seeds should produce different hashes")
	}
}

func TestSeed_HashSHAKE256(t *testing.T) {
	var seed Seed
	for i := range seed {
		seed[i] = byte(i)
	}

	// Test various output sizes
	sizes := []uint32{16, 32, 64, 128}
	for _, size := range sizes {
		hash := seed.HashSHAKE256(size)
		if uint32(len(hash)) != size {
			t.Errorf("SHAKE256(%d) size: got %d, want %d", size, len(hash), size)
		}
	}

	// Deterministic
	hash1 := seed.HashSHAKE256(32)
	hash2 := seed.HashSHAKE256(32)
	if !bytes.Equal(hash1, hash2) {
		t.Error("SHAKE256 hash should be deterministic")
	}

	// Different seed produces different hash
	var seed2 Seed
	seed2[0] = 1
	hash3 := seed2.HashSHAKE256(32)
	if bytes.Equal(hash1, hash3) {
		t.Error("different seeds should produce different hashes")
	}
}

func TestSeed_HashDivergence(t *testing.T) {
	var seed Seed
	for i := range seed {
		seed[i] = byte(i)
	}

	sha256Hash := seed.HashSHA256()
	shake256Hash := seed.HashSHAKE256(32)

	if bytes.Equal(sha256Hash[:], shake256Hash) {
		t.Error("SHA256 and SHAKE256 should produce different hashes")
	}
}

func TestHexStrToSeed_Valid(t *testing.T) {
	var originalSeed Seed
	for i := range originalSeed {
		originalSeed[i] = byte(i)
	}
	hexStr := hex.EncodeToString(originalSeed[:])

	seed, err := HexStrToSeed(hexStr)
	if err != nil {
		t.Fatalf("HexStrToSeed failed: %v", err)
	}

	if seed != originalSeed {
		t.Error("decoded seed mismatch")
	}
}

func TestHexStrToSeed_With0xPrefix(t *testing.T) {
	var originalSeed Seed
	for i := range originalSeed {
		originalSeed[i] = byte(i)
	}
	hexStr := "0x" + hex.EncodeToString(originalSeed[:])

	seed, err := HexStrToSeed(hexStr)
	if err != nil {
		t.Fatalf("HexStrToSeed with 0x prefix failed: %v", err)
	}

	if seed != originalSeed {
		t.Error("decoded seed mismatch")
	}
}

func TestHexStrToSeed_InvalidHex(t *testing.T) {
	invalidHex := strings.Repeat("zz", SeedSize)
	_, err := HexStrToSeed(invalidHex)
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestHexStrToSeed_WrongLength(t *testing.T) {
	tests := []struct {
		name   string
		hexStr string
	}{
		{"too short", strings.Repeat("ab", SeedSize-1)},
		{"too long", strings.Repeat("ab", SeedSize+1)},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := HexStrToSeed(tt.hexStr)
			if err == nil {
				t.Error("expected error for wrong length")
			}
		})
	}
}

func TestHexStrToSeed_UppercaseHex(t *testing.T) {
	var originalSeed Seed
	for i := range originalSeed {
		originalSeed[i] = byte(i)
	}
	hexStr := strings.ToUpper(hex.EncodeToString(originalSeed[:]))

	seed, err := HexStrToSeed(hexStr)
	if err != nil {
		t.Fatalf("HexStrToSeed with uppercase failed: %v", err)
	}

	if seed != originalSeed {
		t.Error("decoded seed mismatch")
	}
}
