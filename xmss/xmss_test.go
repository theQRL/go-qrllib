package xmss

import (
	"encoding/hex"
	"testing"

	"github.com/theQRL/go-qrllib/common"
)

func TestXMSS_GetAddress(t *testing.T) {
	height := uint8(4)

	var seed [common.SeedSize]uint8 // seed initialized with 0 (default) value
	xmss := NewXMSSFromSeed(seed, height, SHAKE_128, common.SHA256_2X)

	expectedAddress := "0102006f4c94686167e4eb233d3e8e80b14abfa2"
	address := xmss.GetAddress()
	if expectedAddress != hex.EncodeToString(address[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", expectedAddress, hex.EncodeToString(address[:]))
	}
}

func TestXMSS_GetLegacyAddress(t *testing.T) {
	height := uint8(4)

	var seed [common.SeedSize]uint8 // seed initialized with 0 (default) value
	xmss := NewXMSSFromSeed(seed, height, SHAKE_128, common.SHA256_2X)

	expectedAddress := "01020095f03f084bcb29b96b0529c17ce92c54c1e8290193a93803812ead95e8e6902506b67897"
	address := xmss.GetLegacyAddress()
	if expectedAddress != hex.EncodeToString(address[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", expectedAddress, hex.EncodeToString(address[:]))
	}
}

func TestIsValidXMSSAddress(t *testing.T) {
	height := uint8(4)

	var seed [common.SeedSize]uint8 // seed initialized with 0 (default) value
	xmss := NewXMSSFromSeed(seed, height, SHAKE_128, common.SHA256_2X)

	address := xmss.GetAddress()
	if !IsValidXMSSAddress(address) {
		t.Errorf("Invalid Address")
	}
}

func TestIsValidLegacyXMSSAddress(t *testing.T) {
	addr, _ := hex.DecodeString("01060060d974fd1faf2c2b0c91d9e33cae9f1b42208c62169f946373ae64198b97b6479f6c8ce5")
	var address [LegacyAddressSize]uint8
	copy(address[:], addr)
	if !IsValidLegacyXMSSAddress(address) {
		t.Errorf("Invalid Address")
	}
}

func TestIsValidXMSSAddress2(t *testing.T) {
	addr, _ := hex.DecodeString("1001430a5152fcc369c309caf3554bd3528161c8")
	var address [20]uint8
	copy(address[:], addr)
	if IsValidXMSSAddress(address) {
		t.Errorf("Dilithium address passed the validXMSSAddress check")
	}
}

func TestXMSS_GetMnemonic(t *testing.T) {
	height := uint8(4)

	var seed [common.SeedSize]uint8 // seed initialized with 0 (default) value
	xmss := NewXMSSFromSeed(seed, height, SHAKE_128, common.SHA256_2X)

	expectedMnemonic := "absorb bunny aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback"
	mnemonic := xmss.GetMnemonic()
	if expectedMnemonic != mnemonic {
		t.Errorf("Mnemonic Mismatch\nExpected: %s\nFound: %s", expectedMnemonic, mnemonic)
	}
}

func TestXMSS_GetExtendedSeed(t *testing.T) {
	height := uint8(4)

	var seed [common.SeedSize]uint8 // seed initialized with 0 (default) value
	xmss := NewXMSSFromSeed(seed, height, SHAKE_128, common.SHA256_2X)

	expectedESeed := "010200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	eSeed := xmss.GetExtendedSeed()
	eSeedStr := hex.EncodeToString(eSeed[:])
	if expectedESeed != eSeedStr {
		t.Errorf("Mnemonic Mismatch\nExpected: %s\nFound: %s", expectedESeed, eSeedStr)
	}
}

func TestXMSSCreationHeight4(t *testing.T) {
	height := uint8(4)

	var seed [common.SeedSize]uint8 // seed initialized with 0 (default) value
	xmss := NewXMSSFromSeed(seed, height, SHAKE_128, common.SHA256_2X)

	expectedAddress := "0102006f4c94686167e4eb233d3e8e80b14abfa2"
	expectedLegacyAddress := "01020095f03f084bcb29b96b0529c17ce92c54c1e8290193a93803812ead95e8e6902506b67897"
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
	if expectedAddress != hex.EncodeToString(address[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", expectedAddress, hex.EncodeToString(address[:]))
	}

	tmpAddr := GetXMSSAddressFromPK(pk)
	if expectedAddress != hex.EncodeToString(tmpAddr[:]) {
		t.Errorf("Address Mismatch\nExpected: %s\nFound: %s", expectedAddress, hex.EncodeToString(tmpAddr[:]))
	}

	legacyAddress := xmss.GetLegacyAddress()
	if expectedLegacyAddress != hex.EncodeToString(legacyAddress[:]) {
		t.Errorf("Legacy Address Mismatch\nExpected: %s\nFound: %s", expectedLegacyAddress, hex.EncodeToString(legacyAddress[:]))
	}

	tmpLegacyAddr := GetLegacyXMSSAddressFromPK(pk)
	if expectedLegacyAddress != hex.EncodeToString(tmpLegacyAddr[:]) {
		t.Errorf("Legacy Address Mismatch\nExpected: %s\nFound: %s", expectedLegacyAddress, hex.EncodeToString(tmpLegacyAddr[:]))
	}

	desc := NewQRLDescriptorFromExtendedPK(&pk)
	if desc.GetHeight() != 4 {
		t.Errorf("Height Mismatch\nExpected: %d\nFound: %d", 6, desc.GetHeight())
	}

	if desc.GetHashFunction() != SHAKE_128 {
		t.Errorf("Descriptor Mismatch\nExpected: %d\nFound: %d", SHAKE_128, desc.GetHashFunction())
	}
}

func TestXMSSCreationHeight6(t *testing.T) {
	height := uint8(6)

	var seed [common.SeedSize]uint8
	xmss := NewXMSSFromSeed(seed, height, SHAKE_128, common.SHA256_2X)

	expectedAddress := "0103003a7d5125fd1d014f972c05b715cfa2f6cd"
	expectedLegacyAddress := "0103008b0e18dd0bac2c3fdc9a48e10fc466eef899ef074449d12ddf050317b2083527aee74bc3"
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

	legacyAddress := xmss.GetLegacyAddress()
	if expectedLegacyAddress != hex.EncodeToString(legacyAddress[:]) {
		t.Errorf("Legacy Address Mismatch\nExpected: %s\nFound: %s", expectedLegacyAddress, hex.EncodeToString(legacyAddress[:]))
	}

	tmpLegacyAddr := GetLegacyXMSSAddressFromPK(pk)
	if expectedLegacyAddress != hex.EncodeToString(tmpLegacyAddr[:]) {
		t.Errorf("Legacy Address Mismatch\nExpected: %s\nFound: %s", expectedLegacyAddress, hex.EncodeToString(tmpLegacyAddr[:]))
	}

	desc := NewQRLDescriptorFromExtendedPK(&pk)
	if desc.GetHeight() != 6 {
		t.Errorf("Height Mismatch\nExpected: %d\nFound: %d", 6, desc.GetHeight())
	}

	if desc.GetHashFunction() != SHAKE_128 {
		t.Errorf("Descriptor Mismatch\nExpected: %d\nFound: %d", SHAKE_128, desc.GetHashFunction())
	}
}

func TestXMSS(t *testing.T) {
	height := uint8(4)

	var seed [common.SeedSize]uint8
	xmss := NewXMSSFromSeed(seed, height, SHAKE_128, common.SHA256_2X)

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
	height := uint8(7)
	var seed [common.SeedSize]uint8
	//assert.Panic(
	//	t,
	//	func() {
	//		NewXMSSFromSeed(seed, height, SHAKE_128, SHA256_2X)
	//	}, "For BDS traversal, H - K must be even, with H > K >= 2!")

	defer func() {
		if r := recover(); r != nil {
			if r != "For BDS traversal, H - K must be even, with H > K >= 2!" {
				t.Error("expected different panic message")
			}
		} else {
			t.Error("expected panic")
		}
	}()
	NewXMSSFromSeed(seed, height, SHAKE_128, common.SHA256_2X)
}

func TestIsValidXMSSAddress2Verify(t *testing.T) {
	var message [common.SeedSize]uint8
	var signature [2287]uint8
	var pk [ExtendedPKSize]uint8

	defer func() {
		if r := recover(); r != nil {
			if r != "Invalid signature size" {
				t.Error("expected different panic message")
			}
		} else {
			t.Error("expected panic")
		}
	}()
	if Verify(message[:], signature[:], pk) {
		t.Errorf("expected panic")
	}
}

func TestXMSSExceptionVerify2(t *testing.T) {
	var message [common.SeedSize]uint8
	var signature [2287]uint8
	var pk [ExtendedPKSize]uint8

	pk[0] = uint8(common.XMSSSig) << 4
	defer func() {
		if r := recover(); r != nil {
			if r != "Invalid signature size" {
				t.Error("expected different panic message")
			}
		} else {
			t.Error("expected panic")
		}
	}()
	if Verify(message[:], signature[:], pk) {
		t.Errorf("expected panic")
	}
}

func TestXMSSChangeIndexTooHigh(t *testing.T) {
	height := uint8(4)
	var seed [common.SeedSize]uint8

	xmss := NewXMSSFromSeed(seed, height, SHAKE_128, 16)
	defer func() {
		if r := recover(); r != nil {
			if r != "index too high" {
				t.Error("expected different panic message")
			}
		} else {
			t.Error("expected panic")
		}
	}()

	xmss.SetIndex(20)
}

func TestXMSSChangeIndexHigh(t *testing.T) {
	height := uint8(4)
	var seed [common.SeedSize]uint8

	xmss := NewXMSSFromSeed(seed, height, SHAKE_128, 16)
	defer func() {
		if r := recover(); r != nil {
			if r != "index too high" {
				t.Error("expected different panic message")
			}
		} else {
			t.Error("expected panic")
		}
	}()
	xmss.SetIndex(16)
}

func TestXMSSChangeIndexLimit(t *testing.T) {
	height := uint8(4)
	var seed [common.SeedSize]uint8
	xmss := NewXMSSFromSeed(seed, height, SHAKE_128, 16)

	xmss.SetIndex(15)
	if xmss.GetIndex() != 15 {
		t.Errorf("Index Mismatch\nExpected: %d\nFound: %d", 15, xmss.GetIndex())
	}
}

func TestXMSSChangeIndex(t *testing.T) {
	height := uint8(4)
	var seed [common.SeedSize]uint8
	xmss := NewXMSSFromSeed(seed, height, SHAKE_128, 16)

	xmss.SetIndex(0)
	if xmss.GetIndex() != 0 {
		t.Errorf("Index Mismatch\nExpected: %d\nFound: %d", 0, xmss.GetIndex())
	}
}
