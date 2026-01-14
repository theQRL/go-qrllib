package xmss

import (
	"encoding/hex"
	"testing"
)

func TestGetXMSSAddressFromPK_InvalidDescriptor(t *testing.T) {
	var pk [ExtendedPKSize]uint8
	// Set invalid hash function (0x0F is invalid)
	pk[0] = 0x0F

	_, err := GetXMSSAddressFromPK(pk)
	if err == nil {
		t.Error("expected error for invalid descriptor")
	}
}

func TestGetXMSSAddressFromPK_UnsupportedAddressFormat(t *testing.T) {
	var pk [ExtendedPKSize]uint8
	// Byte 0: (signature_type << 4) | hash_function = (0 << 4) | 1 = XMSS with SHAKE_128
	pk[0] = 0x01
	// Byte 1: (addr_format << 4) | (height >> 1) = (1 << 4) | 5 = non-SHA256_2X with height 10
	pk[1] = 0x15 // addr_format = 1 (not SHA256_2X which is 0)

	_, err := GetXMSSAddressFromPK(pk)
	if err != ErrUnsupportedAddressFormat {
		t.Errorf("expected ErrUnsupportedAddressFormat, got %v", err)
	}
}

func TestIsValidXMSSAddress_UnsupportedAddressFormat(t *testing.T) {
	var addr [AddressSize]uint8
	// Byte 0: valid XMSS signature type with SHAKE_128
	addr[0] = 0x01
	// Byte 1: non-SHA256_2X address format (upper nibble = 1)
	addr[1] = 0x15

	if IsValidXMSSAddress(addr) {
		t.Error("expected address with unsupported format to be invalid")
	}
}

func TestGetXMSSAddressFromPK_LegacyPK(t *testing.T) {
	// Legacy extended PK for Q010500b5ed7673fe166d7118cd4d9ea19f216adf4e973209e99b49c6ecf157ba14a0e8454195d4
	pkHex := "01050043559486d0bb65088477848ad81224dca1545fa31ae33d0f49a6a0721e88f972dd9228b48b1ccf4f83adc265e00dc887b791641f7da0c577899d339b126f3d04"
	pkBytes, err := hex.DecodeString(pkHex)
	if err != nil {
		t.Fatalf("failed to decode hex pk: %v", err)
	}

	var pk [ExtendedPKSize]uint8
	copy(pk[:], pkBytes)

	addr, err := GetXMSSAddressFromPK(pk)
	if err != nil {
		t.Fatalf("failed to get address from PK: %v", err)
	}

	// Verify the address is valid
	if !IsValidXMSSAddress(addr) {
		t.Error("expected derived address to be valid")
	}
}
