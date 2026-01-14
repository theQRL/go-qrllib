package xmss

import (
	"testing"

	"github.com/theQRL/go-qrllib/common"
	xmsscrypto "github.com/theQRL/go-qrllib/crypto/xmss"
)

func TestLegacyQRLDescriptorFromBytes_InvalidHashFunction(t *testing.T) {
	// Byte 0: lower nibble = 0x0F (invalid hash function, valid are 0-2)
	// Byte 0: upper nibble = 0x00 (valid signature type XMSS)
	descriptorBytes := []byte{0x0F, 0x05, 0x00}

	_, err := LegacyQRLDescriptorFromBytes(descriptorBytes)
	if err == nil {
		t.Error("expected error for invalid hash function")
	}
}

func TestLegacyQRLDescriptorFromBytes_InvalidHeight(t *testing.T) {
	// Byte 0: 0x01 = valid (hash=SHAKE_128, sig type=XMSS)
	// Byte 1: lower nibble = 0x00, height = 0 << 1 = 0 (invalid, must be 2-30)
	descriptorBytes := []byte{0x01, 0x00, 0x00}

	_, err := LegacyQRLDescriptorFromBytes(descriptorBytes)
	if err == nil {
		t.Error("expected error for invalid height")
	}
}

func TestLegacyQRLDescriptorFromBytes_InvalidSignatureType(t *testing.T) {
	// Byte 0: lower nibble = 0x01 (valid hash SHAKE_128)
	// Byte 0: upper nibble = 0xF0 (invalid signature type, only 0 is valid)
	// Byte 1: 0x05 = valid height 10
	descriptorBytes := []byte{0xF1, 0x05, 0x00}

	_, err := LegacyQRLDescriptorFromBytes(descriptorBytes)
	if err == nil {
		t.Error("expected error for invalid signature type")
	}
}

func TestLegacyQRLDescriptorFromBytes_AllInvalid(t *testing.T) {
	// 0xFFFFFF - all bytes invalid
	// Will fail on first check (hash function)
	descriptorBytes := []byte{0xFF, 0xFF, 0xFF}

	_, err := LegacyQRLDescriptorFromBytes(descriptorBytes)
	if err == nil {
		t.Error("expected error for invalid descriptor bytes")
	}
}

func TestNewWalletFromSeed_TreeInitError(t *testing.T) {
	// Height 2 fails InitializeTree because WOTSParamK (2) >= height (2)
	var seed [SeedSize]uint8
	_, err := NewWalletFromSeed(seed, 2, xmsscrypto.SHAKE_128, common.SHA256_2X)
	if err == nil {
		t.Error("expected error for tree initialization with height 2")
	}
}

func TestNewWalletFromExtendedSeed_TreeInitError(t *testing.T) {
	// Create extended seed with height 2 (which will fail tree init)
	var extSeed [ExtendedSeedSize]uint8
	// Byte 0: hash=SHAKE_128 (1), sig type=XMSS (0) -> 0x01
	extSeed[0] = 0x01
	// Byte 1: addr format=SHA256_2X (0), height=2 -> (0 << 4) | (2 >> 1) = 0x01
	extSeed[1] = 0x01

	_, err := NewWalletFromExtendedSeed(extSeed)
	if err == nil {
		t.Error("expected error for tree initialization with height 2")
	}
}

func TestVerify_HeightMismatch(t *testing.T) {
	// Create a wallet with height 4
	var seed [SeedSize]uint8
	w, err := NewWalletFromSeed(seed, 4, xmsscrypto.SHAKE_128, common.SHA256_2X)
	if err != nil {
		t.Fatalf("failed to create wallet: %v", err)
	}

	// Sign a message to get a valid signature for height 4
	message := []byte("test message")
	sig, err := w.Sign(message)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Create a PK with a different height (6) but same other params
	var pk [ExtendedPKSize]uint8
	// Byte 0: hash=SHAKE_128 (1), sig type=XMSS (0) -> 0x01
	pk[0] = 0x01
	// Byte 1: addr format=SHA256_2X (0), height=6 -> (0 << 4) | (6 >> 1) = 0x03
	pk[1] = 0x03

	// Verify should return false due to height mismatch
	if Verify(message, sig, pk) {
		t.Error("expected Verify to return false for height mismatch")
	}
}

func TestVerify_InvalidDescriptor(t *testing.T) {
	// Create a PK with invalid descriptor (invalid hash function)
	var pk [ExtendedPKSize]uint8
	pk[0] = 0x0F // Invalid hash function

	message := []byte("test")
	// Need a signature of valid size - for height 4, it's specific size
	// Just use any signature, it should fail at descriptor parsing first
	sig := make([]byte, 2287) // Some size that gives valid height

	if Verify(message, sig, pk) {
		t.Error("expected Verify to return false for invalid descriptor")
	}
}
