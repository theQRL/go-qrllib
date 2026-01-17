package xmss

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/theQRL/go-qrllib/common"
	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	xmsscrypto "github.com/theQRL/go-qrllib/crypto/xmss"
	"github.com/theQRL/go-qrllib/legacywallet"
)

const (
	Address = "01020095f03f084bcb29b96b0529c17ce92c54c1e8290193a93803812ead95e8e6902506b67897"
)

func newTestXMSSWallet(t *testing.T, height xmsscrypto.Height) *XMSSWallet {
	t.Helper()
	var seed [SeedSize]uint8
	w, err := NewWalletFromSeed(seed, height, xmsscrypto.SHAKE_128, common.SHA256_2X)
	if err != nil {
		t.Fatalf("NewWalletFromSeed failed: %v", err)
	}
	return w
}

func TestXMSS_GetAddress(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)

	address, _ := xmss.GetAddress()
	if Address != hex.EncodeToString(address[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", Address, hex.EncodeToString(address[:]))
	}
}

func TestXMSS_GetLegacyAddress(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)

	address, _ := xmss.GetAddress()
	if Address != hex.EncodeToString(address[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", Address, hex.EncodeToString(address[:]))
	}
}

func TestIsValidXMSSAddress(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)

	address, _ := xmss.GetAddress()
	if !IsValidXMSSAddress(address) {
		t.Errorf("Invalid Address")
	}
}

func TestIsValidLegacyXMSSAddress(t *testing.T) {
	addr, _ := hex.DecodeString("01060060d974fd1faf2c2b0c91d9e33cae9f1b42208c62169f946373ae64198b97b6479f6c8ce5")
	var address [AddressSize]uint8
	copy(address[:], addr)
	if !IsValidXMSSAddress(address) {
		t.Errorf("Invalid Address")
	}
}

func TestXMSS_GetMnemonic(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)

	expectedMnemonic := "absorb bunny aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback"
	mnemonic, err := xmss.GetMnemonic()
	if err != nil {
		t.Fatalf("GetMnemonic() error: %v", err)
	}
	if expectedMnemonic != mnemonic {
		t.Errorf("Mnemonic Mismatch\nExpected: %s\nFound: %s", expectedMnemonic, mnemonic)
	}
}

func TestXMSS_GetExtendedSeed(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)

	expectedESeed := "010200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	eSeed := xmss.GetExtendedSeed()
	eSeedStr := hex.EncodeToString(eSeed[:])
	if expectedESeed != eSeedStr {
		t.Errorf("Mnemonic Mismatch\nExpected: %s\nFound: %s", expectedESeed, eSeedStr)
	}
}

func TestXMSSCreationHeight4(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)

	expectedPK := "010200c25188b585f731c128e2b457069e" +
		"afd1e3fa3961605af8c58a1aec4d82ac" +
		"316d3191da3442686282b3d5160f25cf" +
		"162a517fd2131f83fbf2698a58f9c46a" +
		"fc5d"

	pk := xmss.GetPK()
	if expectedPK != hex.EncodeToString(pk[:]) {
		t.Errorf("PK Mismatch\nExpected: %s\nFound: %s", expectedPK, hex.EncodeToString(pk[:]))
	}

	address, _ := xmss.GetAddress()
	if Address != hex.EncodeToString(address[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", Address, hex.EncodeToString(address[:]))
	}

	tmpAddr, _ := GetXMSSAddressFromPK(pk)
	if Address != hex.EncodeToString(tmpAddr[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", Address, hex.EncodeToString(tmpAddr[:]))
	}

	desc, _ := NewQRLDescriptorFromExtendedPK(&pk)
	if desc.GetHeight() != 4 {
		t.Errorf("Height Mismatch\nExpected: %d\nFound: %d", 6, desc.GetHeight())
	}

	if desc.GetHashFunction() != xmsscrypto.SHAKE_128 {
		t.Errorf("Descriptor Mismatch\nExpected: %d\nFound: %d", xmsscrypto.SHAKE_128, desc.GetHashFunction())
	}
}

func TestXMSSCreationHeight6(t *testing.T) {
	xmss := newTestXMSSWallet(t, 6)

	expectedAddress := "0103008b0e18dd0bac2c3fdc9a48e10fc466eef899ef074449d12ddf050317b2083527aee74bc3"
	expectedPK := "010300859060f15adc3825adeec85c7483" +
		"d868e898bc5117d0cff04ab1343916d4" +
		"07af3191da3442686282b3d5160f25cf" +
		"162a517fd2131f83fbf2698a58f9c46a" +
		"fc5d"

	pk := xmss.GetPK()
	if expectedPK != hex.EncodeToString(pk[:]) {
		t.Errorf("PK Mismatch\nExpected: %s\nFound: %s", expectedPK, hex.EncodeToString(pk[:]))
	}

	address, _ := xmss.GetAddress()
	if expectedAddress != hex.EncodeToString(address[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", expectedAddress, hex.EncodeToString(address[:]))
	}

	tmpAddr, _ := GetXMSSAddressFromPK(pk)
	if expectedAddress != hex.EncodeToString(tmpAddr[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", expectedAddress, hex.EncodeToString(tmpAddr[:]))
	}

	desc, _ := NewQRLDescriptorFromExtendedPK(&pk)
	if desc.GetHeight() != 6 {
		t.Errorf("Height Mismatch\nExpected: %d\nFound: %d", 6, desc.GetHeight())
	}

	if desc.GetHashFunction() != xmsscrypto.SHAKE_128 {
		t.Errorf("Descriptor Mismatch\nExpected: %d\nFound: %d", xmsscrypto.SHAKE_128, desc.GetHashFunction())
	}
}

func TestXMSS(t *testing.T) {
	height, err := xmsscrypto.ToHeight(4)
	if err != nil {
		t.Fatalf("ToHeight failed: %v", err)
	}
	xmss := newTestXMSSWallet(t, height)

	if xmss == nil {
		t.Errorf("XMSS cannot be nil")
	}

	if xmss.GetHeight() != height {
		t.Errorf("Height Mismatch\nExpected: %d\nFound: %d", height, xmss.GetHeight())
	}

	var message [32]uint8

	signature, err := xmss.Sign(message[:])

	if err != nil {
		t.Errorf("Failed to Sign")
	}

	for i := 0; i < 1000; i++ {
		if !Verify(message[:], signature, xmss.GetPK()) {
			t.Errorf("Expected True")
		}
	}

	signature[100] = signature[100] + 1
	if Verify(message[:], signature, xmss.GetPK()) {
		t.Errorf("Expected False")
	}

	signature[100] = signature[100] - 1
	if !Verify(message[:], signature, xmss.GetPK()) {
		t.Errorf("Expected True")
	}

	message[2] = message[2] + 1
	if Verify(message[:], signature, xmss.GetPK()) {
		t.Errorf("Expected False")
	}

	message[2] = message[2] - 1
	if !Verify(message[:], signature, xmss.GetPK()) {
		t.Errorf("Expected True")
	}
}

func TestXMSSExceptionConstructor(t *testing.T) {
	// Height 7 is invalid (must be even), so ToHeight should return an error
	_, err := xmsscrypto.ToHeight(7)
	if err == nil {
		t.Error("Expected error for odd height 7")
	}
}

func TestIsValidXMSSAddress2Verify(t *testing.T) {
	var message [SeedSize]uint8
	var signature [2287]uint8
	var pk [ExtendedPKSize]uint8

	// Invalid signature size should return false, not panic
	if Verify(message[:], signature[:], pk) {
		t.Error("Expected Verify to return false for invalid signature size")
	}
}

func TestXMSSExceptionVerify2(t *testing.T) {
	var message [SeedSize]uint8
	var signature [2287]uint8
	var pk [ExtendedPKSize]uint8

	pk[0] = uint8(legacywallet.WalletTypeXMSS) << 4
	// Invalid signature size should return false, not panic
	if Verify(message[:], signature[:], pk) {
		t.Error("Expected Verify to return false for invalid signature size")
	}
}

func TestXMSSChangeIndexTooHigh(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)
	err := xmss.SetIndex(20)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, cryptoerrors.ErrOTSIndexTooHigh) {
		t.Errorf("unexpected error: got %q, want ErrOTSIndexTooHigh", err.Error())
	}
}

func TestXMSSChangeIndexHigh(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)
	err := xmss.SetIndex(16)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, cryptoerrors.ErrOTSIndexTooHigh) {
		t.Errorf("unexpected error: got %q, want ErrOTSIndexTooHigh", err.Error())
	}
}

func TestXMSSChangeIndexLimit(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)
	if err := xmss.SetIndex(15); err != nil {
		t.Fatalf("SetIndex failed: %v", err)
	}
	if xmss.GetIndex() != 15 {
		t.Errorf("Index Mismatch\nExpected: %d\nFound: %d", 15, xmss.GetIndex())
	}
}

func TestXMSSChangeIndex(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)
	if err := xmss.SetIndex(0); err != nil {
		t.Fatalf("SetIndex failed: %v", err)
	}
	if xmss.GetIndex() != 0 {
		t.Errorf("Index Mismatch\nExpected: %d\nFound: %d", 0, xmss.GetIndex())
	}
}

func TestNewWalletFromHeight(t *testing.T) {
	wallet, err := NewWalletFromHeight(4, xmsscrypto.SHAKE_128)
	if err != nil {
		t.Fatalf("NewWalletFromHeight failed: %v", err)
	}

	if wallet.GetHeight() != 4 {
		t.Errorf("Height mismatch: got %d, want 4", wallet.GetHeight())
	}

	// Seed should be non-zero (randomly generated)
	seed := wallet.GetSeed()
	allZero := true
	for _, b := range seed {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("seed should be randomly generated, not all zeros")
	}
}

func TestNewWalletFromExtendedSeed(t *testing.T) {
	// Create a wallet first to get a valid extended seed
	original := newTestXMSSWallet(t, 4)
	extSeed := original.GetExtendedSeed()

	// Create new wallet from extended seed
	recovered, err := NewWalletFromExtendedSeed(extSeed)
	if err != nil {
		t.Fatalf("NewWalletFromExtendedSeed failed: %v", err)
	}

	// Should match original
	if original.GetSeed() != recovered.GetSeed() {
		t.Error("seed mismatch")
	}
	if original.GetHeight() != recovered.GetHeight() {
		t.Error("height mismatch")
	}
	if original.GetPK() != recovered.GetPK() {
		t.Error("PK mismatch")
	}
}

func TestNewWalletFromExtendedSeed_InvalidDescriptor(t *testing.T) {
	var extSeed [ExtendedSeedSize]uint8
	extSeed[0] = 0xFF // Invalid signature type

	_, err := NewWalletFromExtendedSeed(extSeed)
	if err == nil {
		t.Error("expected error for invalid descriptor")
	}
}

func TestNewWalletFromSeed_HeightExceedsMax(t *testing.T) {
	var seed [SeedSize]uint8
	_, err := NewWalletFromSeed(seed, 100, xmsscrypto.SHAKE_128, common.SHA256_2X)
	if err == nil {
		t.Error("expected error for height exceeding maximum")
	}
}

func TestXMSS_GetHexSeed(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)
	hexSeed := xmss.GetHexSeed()

	// Should start with 0x
	if hexSeed[:2] != "0x" {
		t.Errorf("hex seed should start with 0x, got %s", hexSeed[:2])
	}

	// Should be 0x + 51 bytes * 2 = 104 chars total
	expectedLen := 2 + ExtendedSeedSize*2
	if len(hexSeed) != expectedLen {
		t.Errorf("hex seed length: got %d, want %d", len(hexSeed), expectedLen)
	}
}

func TestXMSS_GetSK(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)
	sk := xmss.GetSK()

	if len(sk) == 0 {
		t.Error("SK should not be empty")
	}
}

func TestXMSS_GetRoot(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)
	root := xmss.GetRoot()

	if len(root) != 32 {
		t.Errorf("root length: got %d, want 32", len(root))
	}
}

func TestVerify_WrongSignatureType(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)
	message := []byte("test message")
	sig, err := xmss.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pk := xmss.GetPK()
	// Tamper with signature type in PK
	pk[0] = 0x10 // Change signature type to 1 (not XMSS)

	if Verify(message, sig, pk) {
		t.Error("expected verification to fail with wrong signature type")
	}
}

func TestVerify_WrongHeight(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)
	message := []byte("test message")
	sig, err := xmss.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pk := xmss.GetPK()
	// Tamper with height in descriptor
	pk[1] = (pk[1] & 0xF0) | 0x03 // Change height to 6 instead of 4

	if Verify(message, sig, pk) {
		t.Error("expected verification to fail with wrong height in descriptor")
	}
}

func TestIsValidXMSSAddress_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		address [AddressSize]uint8
	}{
		{"all zeros", [AddressSize]uint8{}},
		{"invalid descriptor", func() [AddressSize]uint8 {
			var addr [AddressSize]uint8
			addr[0] = 0xFF // Invalid signature type
			return addr
		}()},
		{"invalid checksum", func() [AddressSize]uint8 {
			var addr [AddressSize]uint8
			addr[0] = 0x01 // Valid XMSS signature type
			addr[1] = 0x02 // SHA256_2X address format
			// Rest is zeros, checksum won't match
			return addr
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if IsValidXMSSAddress(tt.address) {
				t.Error("expected address to be invalid")
			}
		})
	}
}

func TestQRLDescriptor_Getters(t *testing.T) {
	desc := NewQRLDescriptor(4, xmsscrypto.SHAKE_128, legacywallet.WalletTypeXMSS, common.SHA256_2X)

	if desc.GetHeight() != 4 {
		t.Errorf("GetHeight: got %d, want 4", desc.GetHeight())
	}
	if desc.GetHashFunction() != xmsscrypto.SHAKE_128 {
		t.Errorf("GetHashFunction: got %d, want %d", desc.GetHashFunction(), xmsscrypto.SHAKE_128)
	}
	if desc.GetSignatureType() != legacywallet.WalletTypeXMSS {
		t.Errorf("GetSignatureType: got %d, want %d", desc.GetSignatureType(), legacywallet.WalletTypeXMSS)
	}
	if desc.GetAddrFormatType() != common.SHA256_2X {
		t.Errorf("GetAddrFormatType: got %d, want %d", desc.GetAddrFormatType(), common.SHA256_2X)
	}
}

func TestQRLDescriptor_GetBytes_RoundTrip(t *testing.T) {
	original := NewQRLDescriptor(6, xmsscrypto.SHAKE_256, legacywallet.WalletTypeXMSS, common.SHA256_2X)
	bytes := original.GetBytes()

	recovered, err := NewQRLDescriptorFromBytes(bytes[:])
	if err != nil {
		t.Fatalf("NewQRLDescriptorFromBytes failed: %v", err)
	}

	if original.GetHeight() != recovered.GetHeight() {
		t.Error("height mismatch after round-trip")
	}
	if original.GetHashFunction() != recovered.GetHashFunction() {
		t.Error("hash function mismatch after round-trip")
	}
	if original.GetSignatureType() != recovered.GetSignatureType() {
		t.Error("signature type mismatch after round-trip")
	}
	if original.GetAddrFormatType() != recovered.GetAddrFormatType() {
		t.Error("address format type mismatch after round-trip")
	}
}

func TestNewQRLDescriptorFromBytes_InvalidLength(t *testing.T) {
	tests := []struct {
		name  string
		bytes []uint8
	}{
		{"too short", []uint8{0, 1}},
		{"too long", []uint8{0, 1, 2, 3}},
		{"empty", []uint8{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewQRLDescriptorFromBytes(tt.bytes)
			if err == nil {
				t.Error("expected error for invalid length")
			}
		})
	}
}

func TestNewQRLDescriptorFromBytes_InvalidHashFunction(t *testing.T) {
	// Create descriptor bytes with invalid hash function (0x0F)
	bytes := []uint8{0x0F, 0x02, 0x00}
	_, err := NewQRLDescriptorFromBytes(bytes)
	if err == nil {
		t.Error("expected error for invalid hash function")
	}
}

func TestNewQRLDescriptorFromBytes_InvalidHeight(t *testing.T) {
	// Create descriptor bytes with invalid height
	// Height is calculated as (byte[1] & 0x0F) << 1
	// Using 0x00 for byte[1] gives height 0, which is invalid (min is 2)
	bytes := []uint8{0x01, 0x00, 0x00}
	_, err := NewQRLDescriptorFromBytes(bytes)
	if err == nil {
		t.Error("expected error for invalid height")
	}
}

func TestLegacyQRLDescriptorFromBytes_InvalidLength(t *testing.T) {
	_, err := LegacyQRLDescriptorFromBytes([]uint8{0, 1})
	if err == nil {
		t.Error("expected error for invalid length")
	}
}

func TestLegacyQRLDescriptorFromExtendedPK(t *testing.T) {
	xmss := newTestXMSSWallet(t, 4)
	pk := xmss.GetPK()

	desc, err := LegacyQRLDescriptorFromExtendedPK(&pk)
	if err != nil {
		t.Fatalf("LegacyQRLDescriptorFromExtendedPK failed: %v", err)
	}

	if desc.GetHeight() != 4 {
		t.Errorf("height mismatch: got %d, want 4", desc.GetHeight())
	}
}
