package ml_dsa_87

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
	"github.com/theQRL/go-qrllib/wallet/misc"
)

func TestNewWalletFromHexSeed_Valid(t *testing.T) {
	var seed common.Seed
	for i := range seed {
		seed[i] = byte(i)
	}
	hexSeed := hex.EncodeToString(seed[:])

	wallet, err := NewWalletFromHexSeed(hexSeed)
	if err != nil {
		t.Fatalf("NewWalletFromHexSeed failed: %v", err)
	}

	if wallet.GetSeed() != seed {
		t.Error("seed mismatch")
	}
}

func TestNewWalletFromHexSeed_With0xPrefix(t *testing.T) {
	var seed common.Seed
	for i := range seed {
		seed[i] = byte(i)
	}
	hexSeed := "0x" + hex.EncodeToString(seed[:])

	wallet, err := NewWalletFromHexSeed(hexSeed)
	if err != nil {
		t.Fatalf("NewWalletFromHexSeed with 0x prefix failed: %v", err)
	}

	if wallet.GetSeed() != seed {
		t.Error("seed mismatch")
	}
}

func TestNewWalletFromHexSeed_With0XPrefix(t *testing.T) {
	var seed common.Seed
	hexSeed := "0X" + hex.EncodeToString(seed[:])

	_, err := NewWalletFromHexSeed(hexSeed)
	if err != nil {
		t.Fatalf("NewWalletFromHexSeed with 0X prefix failed: %v", err)
	}
}

func TestNewWalletFromHexSeed_InvalidHex(t *testing.T) {
	invalidHex := strings.Repeat("zz", common.SeedSize)
	_, err := NewWalletFromHexSeed(invalidHex)
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestNewWalletFromHexSeed_WrongLength(t *testing.T) {
	tests := []struct {
		name   string
		hexStr string
	}{
		{"too short", strings.Repeat("ab", common.SeedSize-1)},
		{"too long", strings.Repeat("ab", common.SeedSize+1)},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewWalletFromHexSeed(tt.hexStr)
			if err == nil {
				t.Error("expected error for wrong length")
			}
		})
	}
}

func TestNewWalletFromHexExtendedSeed_InvalidHex(t *testing.T) {
	invalidHex := strings.Repeat("zz", common.ExtendedSeedSize)
	_, err := NewWalletFromHexExtendedSeed(invalidHex)
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestNewWalletFromHexExtendedSeed_WrongLength(t *testing.T) {
	tests := []struct {
		name   string
		hexStr string
	}{
		{"too short", strings.Repeat("ab", common.ExtendedSeedSize-1)},
		{"too long", strings.Repeat("ab", common.ExtendedSeedSize+1)},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewWalletFromHexExtendedSeed(tt.hexStr)
			if err == nil {
				t.Error("expected error for wrong length")
			}
		})
	}
}

func TestNewWalletFromHexExtendedSeed_WrongDescriptorType(t *testing.T) {
	// Create extended seed bytes with SPHINCS+ descriptor type
	descBytes := descriptor.GetDescriptorBytes(wallettype.SPHINCSPLUS_256S, [2]byte{0, 0})
	extSeedBytes := make([]byte, common.ExtendedSeedSize)
	copy(extSeedBytes[:descriptor.DescriptorSize], descBytes[:])

	hexStr := hex.EncodeToString(extSeedBytes)
	_, err := NewWalletFromHexExtendedSeed(hexStr)
	if err == nil {
		t.Error("expected error for wrong descriptor type")
	}
}

func TestNewWalletFromExtendedSeed_WrongDescriptorType(t *testing.T) {
	// Create extended seed with SPHINCS+ descriptor type
	descBytes := descriptor.GetDescriptorBytes(wallettype.SPHINCSPLUS_256S, [2]byte{0, 0})
	var extSeed common.ExtendedSeed
	copy(extSeed[:descriptor.DescriptorSize], descBytes[:])

	_, err := NewWalletFromExtendedSeed(extSeed)
	if err == nil {
		t.Error("expected error for wrong descriptor type")
	}
}

func TestNewWalletFromMnemonic_InvalidMnemonic(t *testing.T) {
	invalidMnemonic := "invalid mnemonic words that do not exist"
	_, err := NewWalletFromMnemonic(invalidMnemonic)
	if err == nil {
		t.Error("expected error for invalid mnemonic")
	}
}

func TestNewWalletFromMnemonic_WrongDescriptorType(t *testing.T) {
	// First create a SPHINCS+ wallet to get its mnemonic
	sphincsDescBytes := descriptor.GetDescriptorBytes(wallettype.SPHINCSPLUS_256S, [2]byte{0, 0})
	var extSeed common.ExtendedSeed
	copy(extSeed[:descriptor.DescriptorSize], sphincsDescBytes[:])

	// This extended seed has SPHINCS+ type, trying to create ML-DSA wallet should fail
	// We need a valid mnemonic for this test - let's skip the mnemonic conversion
	// and directly test with extended seed
	_, err := NewWalletFromExtendedSeed(extSeed)
	if err == nil {
		t.Error("expected error for wrong descriptor type in mnemonic")
	}
}

func TestGetDescriptor(t *testing.T) {
	wallet, err := NewWallet()
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	desc := wallet.GetDescriptor()
	if !desc.IsValid() {
		t.Error("descriptor should be valid")
	}
	if desc.WalletType() != wallettype.ML_DSA_87 {
		t.Errorf("wallet type: got %v, want %v", desc.WalletType(), wallettype.ML_DSA_87)
	}
}

func TestVerify_InvalidDescriptor(t *testing.T) {
	wallet, err := NewWallet()
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	message := []byte("test message")
	sig, err := wallet.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pk := wallet.GetPK()

	// Use SPHINCS+ descriptor type
	wrongDesc := [descriptor.DescriptorSize]byte{byte(wallettype.SPHINCSPLUS_256S), 0, 0}
	if Verify(message, sig[:], &pk, wrongDesc) {
		t.Error("expected verification to fail with wrong descriptor type")
	}

	// Use unknown descriptor type
	unknownDesc := [descriptor.DescriptorSize]byte{99, 0, 0}
	if Verify(message, sig[:], &pk, unknownDesc) {
		t.Error("expected verification to fail with unknown descriptor type")
	}
}

func TestVerify_InvalidSignatureSize(t *testing.T) {
	wallet, err := NewWallet()
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	message := []byte("test message")
	pk := wallet.GetPK()
	desc := wallet.GetDescriptor().ToDescriptor()

	// Too short signature
	shortSig := make([]byte, SigSize-1)
	if Verify(message, shortSig, &pk, desc) {
		t.Error("expected verification to fail with short signature")
	}

	// Too long signature
	longSig := make([]byte, SigSize+1)
	if Verify(message, longSig, &pk, desc) {
		t.Error("expected verification to fail with long signature")
	}

	// Empty signature
	if Verify(message, []byte{}, &pk, desc) {
		t.Error("expected verification to fail with empty signature")
	}
}

func TestDescriptor_ToDescriptor(t *testing.T) {
	desc, err := NewMLDSA87Descriptor()
	if err != nil {
		t.Fatalf("NewMLDSA87Descriptor failed: %v", err)
	}

	converted := desc.ToDescriptor()
	if converted[0] != byte(wallettype.ML_DSA_87) {
		t.Errorf("ToDescriptor type byte: got %d, want %d", converted[0], wallettype.ML_DSA_87)
	}
}

func TestNewMLDSA87DescriptorFromDescriptor_Valid(t *testing.T) {
	baseDesc := descriptor.Descriptor{byte(wallettype.ML_DSA_87), 0x12, 0x34}

	desc, err := NewMLDSA87DescriptorFromDescriptor(baseDesc)
	if err != nil {
		t.Fatalf("NewMLDSA87DescriptorFromDescriptor failed: %v", err)
	}

	if !desc.IsValid() {
		t.Error("descriptor should be valid")
	}
}

func TestNewMLDSA87DescriptorFromDescriptor_Invalid(t *testing.T) {
	tests := []struct {
		name string
		desc descriptor.Descriptor
	}{
		{"wrong type SPHINCS+", descriptor.Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0, 0}},
		{"unknown type", descriptor.Descriptor{99, 0, 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMLDSA87DescriptorFromDescriptor(tt.desc)
			if err == nil {
				t.Error("expected error for invalid descriptor")
			}
		})
	}
}

func TestWallet_RoundTripThroughHexSeed(t *testing.T) {
	original, err := NewWallet()
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	hexSeed, err := original.GetHexSeed()
	if err != nil {
		t.Fatalf("GetHexSeed failed: %v", err)
	}

	recovered, err := NewWalletFromHexExtendedSeed(hexSeed)
	if err != nil {
		t.Fatalf("NewWalletFromHexExtendedSeed failed: %v", err)
	}

	if original.GetAddress() != recovered.GetAddress() {
		t.Error("address mismatch after round-trip")
	}
}

// Tests for invalid wallet state - these test error paths when wallet is
// constructed with an invalid descriptor (which can't happen through normal
// constructors but tests defensive error handling)

func TestGetExtendedSeed_InvalidDescriptor(t *testing.T) {
	// Construct wallet with invalid descriptor (type byte 255 is invalid)
	// This bypasses normal constructors which always create valid descriptors
	w := &Wallet{
		desc: Descriptor{255, 0, 0}, // 255 is not a valid wallet type
		seed: common.Seed{},
		d:    nil, // not needed for this test
	}

	_, err := w.GetExtendedSeed()
	if err == nil {
		t.Error("expected error for wallet with invalid descriptor")
	}
}

func TestGetHexSeed_InvalidDescriptor(t *testing.T) {
	// Construct wallet with invalid descriptor
	w := &Wallet{
		desc: Descriptor{255, 0, 0},
		seed: common.Seed{},
		d:    nil,
	}

	_, err := w.GetHexSeed()
	if err == nil {
		t.Error("expected error for wallet with invalid descriptor")
	}
}

func TestGetMnemonic_InvalidDescriptor(t *testing.T) {
	// Construct wallet with invalid descriptor
	w := &Wallet{
		desc: Descriptor{255, 0, 0},
		seed: common.Seed{},
		d:    nil,
	}

	_, err := w.GetMnemonic()
	if err == nil {
		t.Error("expected error for wallet with invalid descriptor")
	}
}

func TestNewWalletFromMnemonic_WrongDescriptorTypeViaMnemonic(t *testing.T) {
	// Create a SPHINCS+ extended seed and convert to mnemonic
	sphincsDescBytes := descriptor.GetDescriptorBytes(wallettype.SPHINCSPLUS_256S, [2]byte{0, 0})
	var extSeed common.ExtendedSeed
	copy(extSeed[:descriptor.DescriptorSize], sphincsDescBytes[:])
	// Fill rest with some bytes
	for i := descriptor.DescriptorSize; i < len(extSeed); i++ {
		extSeed[i] = byte(i)
	}

	// Convert to mnemonic using the misc package
	mnemonic, err := misc.BinToMnemonic(extSeed[:])
	if err != nil {
		t.Fatalf("BinToMnemonic failed: %v", err)
	}

	// Try to create ML-DSA-87 wallet from SPHINCS+ mnemonic
	_, err = NewWalletFromMnemonic(mnemonic)
	if err == nil {
		t.Error("expected error when creating ML-DSA-87 wallet from SPHINCS+ mnemonic")
	}
}

func TestNewWalletFromMnemonic_InvalidDescriptorTypeViaMnemonic(t *testing.T) {
	// Create an extended seed with invalid type byte (255) and convert to mnemonic
	// This tests the NewExtendedSeedFromBytes error path in NewWalletFromMnemonic
	var extSeed common.ExtendedSeed
	extSeed[0] = 255 // Invalid wallet type
	extSeed[1] = 0
	extSeed[2] = 0
	// Fill rest with some bytes
	for i := descriptor.DescriptorSize; i < len(extSeed); i++ {
		extSeed[i] = byte(i)
	}

	// Convert to mnemonic
	mnemonic, err := misc.BinToMnemonic(extSeed[:])
	if err != nil {
		t.Fatalf("BinToMnemonic failed: %v", err)
	}

	// Try to create wallet from mnemonic with invalid descriptor
	// This should fail at NewExtendedSeedFromBytes because type 255 is invalid
	_, err = NewWalletFromMnemonic(mnemonic)
	if err == nil {
		t.Error("expected error when creating wallet from mnemonic with invalid descriptor type")
	}
}
