package xmss

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/theQRL/go-qrllib/common"
	xmsscrypto "github.com/theQRL/go-qrllib/crypto/xmss"
	"github.com/theQRL/go-qrllib/legacywallet"
	legacywalletcommon "github.com/theQRL/go-qrllib/legacywallet/common"
)

const (
	Address = "01020095f03f084bcb29b96b0529c17ce92c54c1e8290193a93803812ead95e8e6902506b67897"
)

func newTestXMSSWallet(height xmsscrypto.Height) *XMSSWallet {
	var seed [SeedSize]uint8
	return NewWalletFromSeed(seed, height, xmsscrypto.SHAKE_128, common.SHA256_2X)
}

func expectPanicWithMessage(t *testing.T, expected string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			if r != expected {
				t.Errorf("Expected panic: %q, but got: %q", expected, r)
			}
		} else {
			t.Errorf("Expected panic %q but none occurred", expected)
		}
	}()
	fn()
}

func TestXMSS_GetAddress(t *testing.T) {
	xmss := newTestXMSSWallet(4)

	address := xmss.GetAddress()
	if Address != hex.EncodeToString(address[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", Address, hex.EncodeToString(address[:]))
	}
}

func TestXMSS_GetLegacyAddress(t *testing.T) {
	xmss := newTestXMSSWallet(4)

	address := xmss.GetAddress()
	if Address != hex.EncodeToString(address[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", Address, hex.EncodeToString(address[:]))
	}
}

func TestIsValidXMSSAddress(t *testing.T) {
	xmss := newTestXMSSWallet(4)

	address := xmss.GetAddress()
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
	xmss := newTestXMSSWallet(4)

	expectedMnemonic := "absorb bunny aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback"
	mnemonic := xmss.GetMnemonic()
	if expectedMnemonic != mnemonic {
		t.Errorf("Mnemonic Mismatch\nExpected: %s\nFound: %s", expectedMnemonic, mnemonic)
	}
}

func TestXMSS_GetExtendedSeed(t *testing.T) {
	xmss := newTestXMSSWallet(4)

	expectedESeed := "010200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	eSeed := xmss.GetExtendedSeed()
	eSeedStr := hex.EncodeToString(eSeed[:])
	if expectedESeed != eSeedStr {
		t.Errorf("Mnemonic Mismatch\nExpected: %s\nFound: %s", expectedESeed, eSeedStr)
	}
}

func TestXMSSCreationHeight4(t *testing.T) {
	xmss := newTestXMSSWallet(4)

	expectedPK := "010200c25188b585f731c128e2b457069e" +
		"afd1e3fa3961605af8c58a1aec4d82ac" +
		"316d3191da3442686282b3d5160f25cf" +
		"162a517fd2131f83fbf2698a58f9c46a" +
		"fc5d"

	pk := xmss.GetPK()
	if expectedPK != hex.EncodeToString(pk[:]) {
		t.Errorf("PK Mismatch\nExpected: %s\nFound: %s", expectedPK, hex.EncodeToString(pk[:]))
	}

	address := xmss.GetAddress()
	if Address != hex.EncodeToString(address[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", Address, hex.EncodeToString(address[:]))
	}

	tmpAddr := GetXMSSAddressFromPK(pk)
	if Address != hex.EncodeToString(tmpAddr[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", Address, hex.EncodeToString(tmpAddr[:]))
	}

	desc := NewQRLDescriptorFromExtendedPK(&pk)
	if desc.GetHeight() != 4 {
		t.Errorf("Height Mismatch\nExpected: %d\nFound: %d", 6, desc.GetHeight())
	}

	if desc.GetHashFunction() != xmsscrypto.SHAKE_128 {
		t.Errorf("Descriptor Mismatch\nExpected: %d\nFound: %d", xmsscrypto.SHAKE_128, desc.GetHashFunction())
	}
}

func TestXMSSCreationHeight6(t *testing.T) {
	xmss := newTestXMSSWallet(6)

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

	address := xmss.GetAddress()
	if expectedAddress != hex.EncodeToString(address[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", expectedAddress, hex.EncodeToString(address[:]))
	}

	tmpAddr := GetXMSSAddressFromPK(pk)
	if expectedAddress != hex.EncodeToString(tmpAddr[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", expectedAddress, hex.EncodeToString(tmpAddr[:]))
	}

	desc := NewQRLDescriptorFromExtendedPK(&pk)
	if desc.GetHeight() != 6 {
		t.Errorf("Height Mismatch\nExpected: %d\nFound: %d", 6, desc.GetHeight())
	}

	if desc.GetHashFunction() != xmsscrypto.SHAKE_128 {
		t.Errorf("Descriptor Mismatch\nExpected: %d\nFound: %d", xmsscrypto.SHAKE_128, desc.GetHashFunction())
	}
}

func TestXMSS(t *testing.T) {
	height := xmsscrypto.ToHeight(4)
	xmss := newTestXMSSWallet(height)

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
	expectPanicWithMessage(t, "For BDS traversal, H - K must be even, with H > K >= 2!", func() {
		newTestXMSSWallet(7)
	})
}

func TestIsValidXMSSAddress2Verify(t *testing.T) {
	var message [SeedSize]uint8
	var signature [2287]uint8
	var pk [ExtendedPKSize]uint8

	expectPanicWithMessage(t, "Invalid signature size", func() {
		Verify(message[:], signature[:], pk)
	})
}

func TestXMSSExceptionVerify2(t *testing.T) {
	var message [SeedSize]uint8
	var signature [2287]uint8
	var pk [ExtendedPKSize]uint8

	pk[0] = uint8(legacywallet.WalletTypeXMSS) << 4
	expectPanicWithMessage(t, "Invalid signature size", func() {
		Verify(message[:], signature[:], pk)
	})
}

func TestXMSSChangeIndexTooHigh(t *testing.T) {
	xmss := newTestXMSSWallet(4)
	err := xmss.SetIndex(20)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	expectedError := fmt.Errorf(legacywalletcommon.ErrOTSIndexTooHigh, 20, 15).Error()
	if err.Error() != expectedError {
		t.Errorf("unexpected error: got %q, want %q", err.Error(), expectedError)
	}
}

func TestXMSSChangeIndexHigh(t *testing.T) {
	xmss := newTestXMSSWallet(4)
	err := xmss.SetIndex(16)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	expectedError := fmt.Errorf(legacywalletcommon.ErrOTSIndexTooHigh, 16, 15).Error()
	if err.Error() != expectedError {
		t.Errorf("unexpected error: got %q, want %q", err.Error(), expectedError)
	}
}

func TestXMSSChangeIndexLimit(t *testing.T) {
	xmss := newTestXMSSWallet(4)
	if err := xmss.SetIndex(15); err != nil {
		t.Fatalf("SetIndex failed: %v", err)
	}
	if xmss.GetIndex() != 15 {
		t.Errorf("Index Mismatch\nExpected: %d\nFound: %d", 15, xmss.GetIndex())
	}
}

func TestXMSSChangeIndex(t *testing.T) {
	xmss := newTestXMSSWallet(4)
	if err := xmss.SetIndex(0); err != nil {
		t.Fatalf("SetIndex failed: %v", err)
	}
	if xmss.GetIndex() != 0 {
		t.Errorf("Index Mismatch\nExpected: %d\nFound: %d", 0, xmss.GetIndex())
	}
}
