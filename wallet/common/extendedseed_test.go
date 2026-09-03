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

	// Verify descriptor bytes are correctly placed at the start
	if extSeed[0] != byte(wallettype.ML_DSA_87) {
		t.Errorf("descriptor type byte: got %d, want %d", extSeed[0], wallettype.ML_DSA_87)
	}
}

func TestNewExtendedSeed_InvalidDescriptor(t *testing.T) {
	tests := []struct {
		name string
		desc descriptor.Descriptor
	}{
		{"unknown wallet type", descriptor.Descriptor{255, 0, 0}},
		{"ML_DSA_87 with non-zero metadata byte 1", descriptor.Descriptor{byte(wallettype.ML_DSA_87), 0x01, 0x00}},
		{"ML_DSA_87 with non-zero metadata byte 2", descriptor.Descriptor{byte(wallettype.ML_DSA_87), 0x00, 0x01}},
		{"SPHINCSPLUS_256S canonical reserved but not valid today", descriptor.Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0x00, 0x00}},
		{"SPHINCSPLUS_256S with non-canonical metadata", descriptor.Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0x12, 0x34}},
	}

	var seed Seed
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewExtendedSeed(tt.desc, seed); err == nil {
				t.Error("expected error for invalid descriptor")
			}
		})
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

// validExtendedSeedHex returns the unprefixed canonical hex body of a valid
// ML-DSA-87 extended seed, alongside the bytes it encodes.
func validExtendedSeedHex(t *testing.T) (string, []byte) {
	t.Helper()

	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	extSeedBytes := make([]byte, ExtendedSeedSize)
	copy(extSeedBytes[:descriptor.DescriptorSize], descBytes[:])
	for i := descriptor.DescriptorSize; i < ExtendedSeedSize; i++ {
		extSeedBytes[i] = byte(i)
	}
	return hex.EncodeToString(extSeedBytes), extSeedBytes
}

// TestNewExtendedSeedFromHexString_AcceptedForms locks the accepted text
// superset: the canonical "0x"-prefixed form this library emits, the "0X"
// spelling, uppercase hex, and the unprefixed body. The prefix must be
// removed before the length check, otherwise the canonical form fails as a
// length error.
func TestNewExtendedSeedFromHexString_AcceptedForms(t *testing.T) {
	hexBody, extSeedBytes := validExtendedSeedHex(t)

	tests := []struct {
		name   string
		hexStr string
	}{
		{"unprefixed", hexBody},
		{"0x prefix (canonical)", "0x" + hexBody},
		{"0X prefix", "0X" + hexBody},
		{"uppercase hex", strings.ToUpper(hexBody)},
		{"0x prefix with uppercase hex", "0x" + strings.ToUpper(hexBody)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extSeed, err := NewExtendedSeedFromHexString(tt.hexStr)
			if err != nil {
				t.Fatalf("NewExtendedSeedFromHexString failed: %v", err)
			}
			if !bytes.Equal(extSeed[:], extSeedBytes) {
				t.Error("extended seed bytes mismatch")
			}
		})
	}
}

// TestNewExtendedSeedFromHexString_RejectedForms locks the other side of the
// superset: prefix removal is the only normalization, so whitespace and
// separator characters stay rejected.
func TestNewExtendedSeedFromHexString_RejectedForms(t *testing.T) {
	hexBody, _ := validExtendedSeedHex(t)

	tests := []struct {
		name   string
		hexStr string
	}{
		{"leading whitespace", " 0x" + hexBody},
		{"trailing whitespace", "0x" + hexBody + "\n"},
		{"whitespace between prefix and body", "0x " + hexBody},
		{"interior whitespace", "0x" + hexBody[:10] + " " + hexBody[10:]},
		{"interior separator", "0x" + hexBody[:10] + ":" + hexBody[10:]},
		{"prefix only", "0x"},
		// Every doubling, not just the same-case one: chained TrimPrefix
		// calls would strip "0X0x" but not "0x0x", so covering one spelling
		// hides the other. Exactly one prefix is removed, matching the
		// wallet-level constructors.
		{"doubled prefix 0x0x", "0x0x" + hexBody},
		{"doubled prefix 0X0x", "0X0x" + hexBody},
		{"doubled prefix 0x0X", "0x0X" + hexBody},
		{"doubled prefix 0X0X", "0X0X" + hexBody},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewExtendedSeedFromHexString(tt.hexStr); err == nil {
				t.Error("expected error for non-canonical input")
			}
		})
	}
}

// TestExtendedSeed_ToHexRoundTrip is the round-trip lock: whatever ToHex
// emits must parse back through NewExtendedSeedFromHexString unmodified.
func TestExtendedSeed_ToHexRoundTrip(t *testing.T) {
	_, extSeedBytes := validExtendedSeedHex(t)

	original, err := NewExtendedSeedFromBytes(extSeedBytes)
	if err != nil {
		t.Fatalf("NewExtendedSeedFromBytes failed: %v", err)
	}

	hexStr := original.ToHex()
	if want := "0x" + hex.EncodeToString(extSeedBytes); hexStr != want {
		t.Errorf("ToHex() = %s, want %s", hexStr, want)
	}
	if hexStr != strings.ToLower(hexStr) {
		t.Errorf("ToHex() must emit lowercase, got %s", hexStr)
	}
	if len(hexStr) != 2+2*ExtendedSeedSize {
		t.Errorf("ToHex() length = %d, want %d", len(hexStr), 2+2*ExtendedSeedSize)
	}

	parsed, err := NewExtendedSeedFromHexString(hexStr)
	if err != nil {
		t.Fatalf("NewExtendedSeedFromHexString(ToHex()) failed: %v", err)
	}
	if parsed != original {
		t.Error("ToHex/NewExtendedSeedFromHexString round-trip changed the extended seed")
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
		{"too short with 0x prefix", "0x" + strings.Repeat("00", ExtendedSeedSize-1)},
		{"too long with 0x prefix", "0x" + strings.Repeat("00", ExtendedSeedSize+1)},
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
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
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
	descBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
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
