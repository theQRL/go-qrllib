package common

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

func TestNewExtendedSeed_Valid(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	desc := descriptor.New(descBytes)

	var seed Seed
	for i := range seed {
		seed[i] = byte(i)
	}

	extSeed, err := NewExtendedSeed(desc, seed)
	if err != nil {
		t.Fatalf("NewExtendedSeed failed: %v", err)
	}

	if len(extSeed) != ExtendedSeedSize {
		t.Errorf("extended seed size: got %d, want %d", len(extSeed), ExtendedSeedSize)
	}
}

func TestNewExtendedSeed_InvalidDescriptor(t *testing.T) {
	invalidDesc := descriptor.Descriptor{255, 0, 0}
	var seed Seed

	_, err := NewExtendedSeed(invalidDesc, seed)
	if err == nil {
		t.Error("expected error for invalid descriptor")
	}
}

func TestNewExtendedSeedFromBytes_Valid(t *testing.T) {
	// Create valid extended seed bytes
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	extSeedBytes := make([]byte, ExtendedSeedSize)
	copy(extSeedBytes[:descriptor.DescriptorSize], descBytes[:])
	for i := descriptor.DescriptorSize; i < ExtendedSeedSize; i++ {
		extSeedBytes[i] = byte(i)
	}

	extSeed, err := NewExtendedSeedFromBytes(extSeedBytes)
	if err != nil {
		t.Fatalf("NewExtendedSeedFromBytes failed: %v", err)
	}

	if !bytes.Equal(extSeed[:], extSeedBytes) {
		t.Error("extended seed bytes mismatch")
	}
}

func TestNewExtendedSeedFromBytes_InvalidLength(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"too short", ExtendedSeedSize - 1},
		{"too long", ExtendedSeedSize + 1},
		{"empty", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extSeedBytes := make([]byte, tt.size)
			_, err := NewExtendedSeedFromBytes(extSeedBytes)
			if err == nil {
				t.Error("expected error for invalid length")
			}
		})
	}
}

func TestNewExtendedSeedFromBytes_InvalidDescriptor(t *testing.T) {
	extSeedBytes := make([]byte, ExtendedSeedSize)
	extSeedBytes[0] = 255 // Invalid wallet type

	_, err := NewExtendedSeedFromBytes(extSeedBytes)
	if err == nil {
		t.Error("expected error for invalid descriptor")
	}
}

func TestNewExtendedSeedFromHexString_Valid(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	extSeedBytes := make([]byte, ExtendedSeedSize)
	copy(extSeedBytes[:descriptor.DescriptorSize], descBytes[:])
	for i := descriptor.DescriptorSize; i < ExtendedSeedSize; i++ {
		extSeedBytes[i] = byte(i)
	}

	hexStr := hex.EncodeToString(extSeedBytes)
	extSeed, err := NewExtendedSeedFromHexString(hexStr)
	if err != nil {
		t.Fatalf("NewExtendedSeedFromHexString failed: %v", err)
	}

	if !bytes.Equal(extSeed[:], extSeedBytes) {
		t.Error("extended seed bytes mismatch")
	}
}

func TestNewExtendedSeedFromHexString_InvalidLength(t *testing.T) {
	tests := []struct {
		name   string
		hexStr string
	}{
		{"too short", strings.Repeat("00", ExtendedSeedSize-1)},
		{"too long", strings.Repeat("00", ExtendedSeedSize+1)},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewExtendedSeedFromHexString(tt.hexStr)
			if err == nil {
				t.Error("expected error for invalid length")
			}
		})
	}
}

func TestNewExtendedSeedFromHexString_InvalidHex(t *testing.T) {
	invalidHex := strings.Repeat("zz", ExtendedSeedSize)
	_, err := NewExtendedSeedFromHexString(invalidHex)
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestExtendedSeed_GetDescriptorBytes(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.SPHINCSPLUS_256S, [2]byte{0x12, 0x34})
	desc := descriptor.New(descBytes)
	var seed Seed

	extSeed, err := NewExtendedSeed(desc, seed)
	if err != nil {
		t.Fatalf("NewExtendedSeed failed: %v", err)
	}

	gotDescBytes := extSeed.GetDescriptorBytes()
	if gotDescBytes != descBytes {
		t.Error("descriptor bytes mismatch")
	}
}

func TestExtendedSeed_GetSeedBytes(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	desc := descriptor.New(descBytes)

	var seed Seed
	for i := range seed {
		seed[i] = byte(i * 5)
	}

	extSeed, err := NewExtendedSeed(desc, seed)
	if err != nil {
		t.Fatalf("NewExtendedSeed failed: %v", err)
	}

	seedBytes := extSeed.GetSeedBytes()
	if !bytes.Equal(seedBytes, seed[:]) {
		t.Error("seed bytes mismatch")
	}
}

func TestExtendedSeed_GetSeed(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	desc := descriptor.New(descBytes)

	var originalSeed Seed
	for i := range originalSeed {
		originalSeed[i] = byte(i * 7)
	}

	extSeed, err := NewExtendedSeed(desc, originalSeed)
	if err != nil {
		t.Fatalf("NewExtendedSeed failed: %v", err)
	}

	seed, err := extSeed.GetSeed()
	if err != nil {
		t.Fatalf("GetSeed failed: %v", err)
	}

	if seed != originalSeed {
		t.Error("seed mismatch")
	}
}

func TestExtendedSeed_ToBytes(t *testing.T) {
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	desc := descriptor.New(descBytes)
	var seed Seed

	extSeed, err := NewExtendedSeed(desc, seed)
	if err != nil {
		t.Fatalf("NewExtendedSeed failed: %v", err)
	}

	toBytes := extSeed.ToBytes()
	if len(toBytes) != ExtendedSeedSize {
		t.Errorf("ToBytes length: got %d, want %d", len(toBytes), ExtendedSeedSize)
	}

	if !bytes.Equal(toBytes, extSeed[:]) {
		t.Error("ToBytes mismatch")
	}
}

func TestExtendedSeed_RoundTrip(t *testing.T) {
	// Create original extended seed
	descBytes := descriptor.GetDescriptorBytes(wallettype.SPHINCSPLUS_256S, [2]byte{0xAB, 0xCD})
	desc := descriptor.New(descBytes)

	var seed Seed
	for i := range seed {
		seed[i] = byte(i * 11)
	}

	original, err := NewExtendedSeed(desc, seed)
	if err != nil {
		t.Fatalf("NewExtendedSeed failed: %v", err)
	}

	// Round-trip through bytes
	fromBytes, err := NewExtendedSeedFromBytes(original.ToBytes())
	if err != nil {
		t.Fatalf("NewExtendedSeedFromBytes failed: %v", err)
	}

	if original != fromBytes {
		t.Error("round-trip through bytes failed")
	}

	// Round-trip through hex
	hexStr := hex.EncodeToString(original[:])
	fromHex, err := NewExtendedSeedFromHexString(hexStr)
	if err != nil {
		t.Fatalf("NewExtendedSeedFromHexString failed: %v", err)
	}

	if original != fromHex {
		t.Error("round-trip through hex failed")
	}
}
