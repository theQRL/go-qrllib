package dilithium

import (
	"encoding/hex"
	"reflect"
	"testing"
)

const (
	// HexSeed is a 32-byte seed (SEED_BYTES) for consistent type-safe testing
	HexSeed = "f29f58aff0b00de2844f7e20bd9eeaacc379150043beeb328335817512b29fbb"
)

func PKHStrToBin(pkHStr string) [CRYPTO_PUBLIC_KEY_BYTES]uint8 {
	if len(pkHStr) != 2*CRYPTO_PUBLIC_KEY_BYTES {
		panic("Invalid pkHStr")
	}
	var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
	pkDecode, _ := hex.DecodeString(pkHStr)
	copy(pk[:], pkDecode)
	return pk
}

func SKHStrToBin(skHStr string) [CRYPTO_SECRET_KEY_BYTES]uint8 {
	if len(skHStr) != 2*CRYPTO_SECRET_KEY_BYTES {
		panic("Invalid skHStr")
	}
	var sk [CRYPTO_SECRET_KEY_BYTES]uint8
	skDecode, _ := hex.DecodeString(skHStr)
	copy(sk[:], skDecode)
	return sk
}

func TestNew(t *testing.T) {
	defer func() {
		if err := recover(); err != nil {
			t.Error("Panic while creating dilithium ", err)
		}
	}()
	if _, err := New(); err != nil {
		t.Error("failed to generate new dilithium ", err.Error())
	}
}

func TestNewDilithiumFromSeed(t *testing.T) {
	defer func() {
		if err := recover(); err != nil {
			t.Error("Panic while creating dilithium ", err)
		}
	}()

	binUnsizeSeed, err := hex.DecodeString(HexSeed)
	if err != nil {
		t.Error("failed to decode hexseed ", err.Error())
	}
	var binSeed [SEED_BYTES]uint8
	copy(binSeed[:], binUnsizeSeed)
	d, err := NewDilithiumFromSeed(binSeed)
	if err != nil {
		t.Error("failed to generate new dilithium from seed ", err.Error())
	}

	// Verify determinism - same seed should produce same keys
	d2, err := NewDilithiumFromSeed(binSeed)
	if err != nil {
		t.Error("failed to generate second dilithium from seed ", err.Error())
	}

	pk := d.GetPK()
	pk2 := d2.GetPK()
	if pk != pk2 {
		t.Error("pk mismatch - key generation not deterministic")
	}

	sk := d.GetSK()
	sk2 := d2.GetSK()
	if sk != sk2 {
		t.Error("sk mismatch - key generation not deterministic")
	}

	if "0x"+HexSeed != d.GetHexSeed() {
		t.Errorf("hexseed mismatch\nExpected: %s\nFound: %s", "0x"+HexSeed, d.GetHexSeed())
	}
}

func TestNewDilithiumFromHexSeed(t *testing.T) {
	defer func() {
		if err := recover(); err != nil {
			t.Error("Panic while creating dilithium ", err)
		}
	}()
	d, err := NewDilithiumFromHexSeed(HexSeed)
	if err != nil {
		t.Error("failed to generate new dilithium from hex seed ", err.Error())
	}

	// Verify determinism - same seed should produce same keys
	d2, err := NewDilithiumFromHexSeed(HexSeed)
	if err != nil {
		t.Error("failed to generate second dilithium from hex seed ", err.Error())
	}

	pk := d.GetPK()
	pk2 := d2.GetPK()
	if pk != pk2 {
		t.Error("pk mismatch - key generation not deterministic")
	}

	sk := d.GetSK()
	sk2 := d2.GetSK()
	if sk != sk2 {
		t.Error("sk mismatch - key generation not deterministic")
	}

	if "0x"+HexSeed != d.GetHexSeed() {
		t.Errorf("hexseed mismatch\nExpected: %s\nFound: %s", "0x"+HexSeed, d.GetHexSeed())
	}
}

func TestNewDilithiumFromHexSeed_InvalidHex(t *testing.T) {
	// Test that invalid hex returns an error instead of panicking
	invalidHexSeeds := []string{
		"invalid_hex_string",
		"zzzz",
		"12345g",
	}

	for _, invalidSeed := range invalidHexSeeds {
		_, err := NewDilithiumFromHexSeed(invalidSeed)
		if err == nil {
			t.Errorf("expected error for invalid hex seed %q, got nil", invalidSeed)
		}
	}
}

func TestDilithium_GetPK(t *testing.T) {
	binUnsizeSeed, err := hex.DecodeString(HexSeed)
	if err != nil {
		t.Error("failed to decode hexseed ", err.Error())
	}
	var binSeed [SEED_BYTES]uint8
	copy(binSeed[:], binUnsizeSeed)
	d, err := NewDilithiumFromSeed(binSeed)
	if err != nil {
		t.Error("failed to generate new dilithium from seed ", err.Error())
	}

	pk := d.GetPK()
	// Verify public key is not all zeros (which would indicate an error)
	allZero := true
	for _, b := range pk {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("PK should not be all zeros")
	}
}

func TestDilithium_GetSK(t *testing.T) {
	binUnsizeSeed, err := hex.DecodeString(HexSeed)
	if err != nil {
		t.Error("failed to decode hexseed ", err.Error())
	}
	var binSeed [SEED_BYTES]uint8
	copy(binSeed[:], binUnsizeSeed)
	d, err := NewDilithiumFromSeed(binSeed)
	if err != nil {
		t.Error("failed to generate new dilithium from seed ", err.Error())
	}

	sk := d.GetSK()
	// Verify secret key is not all zeros (which would indicate an error)
	allZero := true
	for _, b := range sk {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("SK should not be all zeros")
	}
}

func TestDilithium_GetSeed(t *testing.T) {
	binUnsizeSeed, err := hex.DecodeString(HexSeed)
	if err != nil {
		t.Error("failed to decode hexseed ", err.Error())
	}
	var binSeed [SEED_BYTES]uint8
	copy(binSeed[:], binUnsizeSeed)
	d, err := NewDilithiumFromSeed(binSeed)
	if err != nil {
		t.Error("failed to generate new dilithium from seed ", err.Error())
	}

	if binSeed != d.GetSeed() {
		t.Error("Seed Mismatch")
	}
}

func TestDilithium_GetHexSeed(t *testing.T) {
	binUnsizeSeed, err := hex.DecodeString(HexSeed)
	if err != nil {
		t.Error("failed to decode hexseed ", err.Error())
	}
	var binSeed [SEED_BYTES]uint8
	copy(binSeed[:], binUnsizeSeed)
	d, err := NewDilithiumFromSeed(binSeed)
	if err != nil {
		t.Error("failed to generate new dilithium from seed ", err.Error())
	}

	if "0x"+HexSeed != d.GetHexSeed() {
		t.Error("HexSeed Mismatch")
	}
}

func TestDilithium_Seal(t *testing.T) {
	msg := []uint8{0, 1, 2, 4, 6, 9, 1}

	binUnsizeSeed, err := hex.DecodeString(HexSeed)
	if err != nil {
		t.Error("failed to decode hexseed ", err.Error())
	}
	var binSeed [SEED_BYTES]uint8
	copy(binSeed[:], binUnsizeSeed)
	d, err := NewDilithiumFromSeed(binSeed)
	if err != nil {
		t.Error("failed to generate new dilithium from seed ", err.Error())
	}

	signatureMessage, err := d.Seal(msg)
	if err != nil {
		t.Error("failed to seal ", err.Error())
	}

	// Verify the sealed message has correct size (signature + message)
	if len(signatureMessage) != CRYPTO_BYTES+len(msg) {
		t.Errorf("sealed message size mismatch: got %d, want %d", len(signatureMessage), CRYPTO_BYTES+len(msg))
	}

	// Verify the sealed message can be opened with the correct public key
	pk := d.GetPK()
	opened := Open(signatureMessage, &pk)
	if !reflect.DeepEqual(opened, msg) {
		t.Error("failed to open sealed message")
	}

	// Verify determinism - same seed, same message should produce same sealed result
	d2, _ := NewDilithiumFromSeed(binSeed)
	signatureMessage2, _ := d2.Seal(msg)
	if hex.EncodeToString(signatureMessage) != hex.EncodeToString(signatureMessage2) {
		t.Error("seal operation is not deterministic")
	}
}

func TestDilithium_Open(t *testing.T) {
	msg := []uint8{0, 1, 2, 4, 6, 9, 1}

	binUnsizeSeed, err := hex.DecodeString(HexSeed)
	if err != nil {
		t.Error("failed to decode hexseed ", err.Error())
	}
	var binSeed [SEED_BYTES]uint8
	copy(binSeed[:], binUnsizeSeed)
	d, err := NewDilithiumFromSeed(binSeed)
	if err != nil {
		t.Error("failed to generate new dilithium from seed ", err.Error())
	}

	signatureMessage, err := d.Seal(msg)
	if err != nil {
		t.Error("failed to seal ", err.Error())
	}

	// Verify Open recovers the original message
	pk := d.GetPK()
	if !reflect.DeepEqual(Open(signatureMessage, &pk), msg) {
		t.Error("SignatureMessage Verification failed")
	}

	// Verify Open fails with wrong public key
	wrongDil, _ := New()
	wrongPK := wrongDil.GetPK()
	if Open(signatureMessage, &wrongPK) != nil {
		t.Error("Open should fail with wrong public key")
	}
}

func TestDilithium_Sign(t *testing.T) {
	msg := []uint8{0, 1, 2, 4, 6, 9, 1}

	binUnsizeSeed, err := hex.DecodeString(HexSeed)
	if err != nil {
		t.Error("failed to decode hexseed ", err.Error())
	}
	var binSeed [SEED_BYTES]uint8
	copy(binSeed[:], binUnsizeSeed)
	d, err := NewDilithiumFromSeed(binSeed)
	if err != nil {
		t.Error("failed to generate new dilithium from seed ", err.Error())
	}

	signature, err := d.Sign(msg)
	if err != nil {
		t.Error("failed to sign ", err.Error())
	}

	// Verify signature has correct size
	if len(signature) != CRYPTO_BYTES {
		t.Errorf("signature size mismatch: got %d, want %d", len(signature), CRYPTO_BYTES)
	}

	// Verify signature verifies with correct public key
	pk := d.GetPK()
	if !Verify(msg, signature, &pk) {
		t.Error("signature verification failed")
	}

	// Verify determinism - same seed, same message should produce same signature
	d2, _ := NewDilithiumFromSeed(binSeed)
	signature2, _ := d2.Sign(msg)
	if signature != signature2 {
		t.Error("Signatures should be identical for deterministic signing with same seed")
	}
}

func TestDilithium_Verify(t *testing.T) {
	msg := []uint8{0, 1, 2, 4, 6, 9, 1}

	binUnsizeSeed, err := hex.DecodeString(HexSeed)
	if err != nil {
		t.Error("failed to decode hexseed ", err.Error())
	}
	var binSeed [SEED_BYTES]uint8
	copy(binSeed[:], binUnsizeSeed)
	d, err := NewDilithiumFromSeed(binSeed)
	if err != nil {
		t.Error("failed to generate new dilithium from seed ", err.Error())
	}

	signature, err := d.Sign(msg)
	if err != nil {
		t.Error("failed to sign ", err.Error())
	}

	// Verify with correct public key
	pk := d.GetPK()
	if !Verify(msg, signature, &pk) {
		t.Error("Signature Verification failed")
	}

	// Verify with wrong public key should fail
	wrongDil, _ := New()
	wrongPK := wrongDil.GetPK()
	if Verify(msg, signature, &wrongPK) {
		t.Error("Signature should not verify with wrong public key")
	}

	// Verify with wrong message should fail
	wrongMsg := []uint8{1, 2, 3, 4, 5, 6, 7}
	if Verify(wrongMsg, signature, &pk) {
		t.Error("Signature should not verify with wrong message")
	}
}

func TestExtractMessage(t *testing.T) {
	msg := []uint8{0, 1, 2, 4, 6, 9, 1}

	binUnsizeSeed, err := hex.DecodeString(HexSeed)
	if err != nil {
		t.Error("failed to decode hexseed ", err.Error())
	}
	var binSeed [SEED_BYTES]uint8
	copy(binSeed[:], binUnsizeSeed)
	d, err := NewDilithiumFromSeed(binSeed)
	if err != nil {
		t.Error("failed to generate new dilithium from seed ", err.Error())
	}

	signatureMessage, err := d.Seal(msg)
	if err != nil {
		t.Error("failed to seal ", err.Error())
	}

	// Verify sealed message has correct size
	if len(signatureMessage) != CRYPTO_BYTES+len(msg) {
		t.Errorf("signatureMessage length: expected %d, got %d", CRYPTO_BYTES+len(msg), len(signatureMessage))
	}

	extractedMessage := ExtractMessage(signatureMessage)

	if !reflect.DeepEqual(msg, extractedMessage) {
		t.Error("ExtractedMessage mismatch")
	}
}

func TestExtractSignature(t *testing.T) {
	msg := []uint8{0, 1, 2, 4, 6, 9, 1}

	binUnsizeSeed, err := hex.DecodeString(HexSeed)
	if err != nil {
		t.Error("failed to decode hexseed ", err.Error())
	}
	var binSeed [SEED_BYTES]uint8
	copy(binSeed[:], binUnsizeSeed)
	d, err := NewDilithiumFromSeed(binSeed)
	if err != nil {
		t.Error("failed to generate new dilithium from seed ", err.Error())
	}

	signatureMessage, err := d.Seal(msg)
	if err != nil {
		t.Error("failed to seal ", err.Error())
	}

	// Verify sealed message has correct size
	if len(signatureMessage) != CRYPTO_BYTES+len(msg) {
		t.Errorf("signatureMessage length: expected %d, got %d", CRYPTO_BYTES+len(msg), len(signatureMessage))
	}

	extractedSignature := ExtractSignature(signatureMessage)

	if len(extractedSignature) != CRYPTO_BYTES {
		t.Errorf("extracted signature length: expected %d, got %d", CRYPTO_BYTES, len(extractedSignature))
	}

	if !reflect.DeepEqual(signatureMessage[:CRYPTO_BYTES], extractedSignature) {
		t.Error("ExtractedSignature mismatch")
	}
}

// test SignWithSecretKey also produces expected output
func TestSignWithSecretKey(t *testing.T) {
	msg := []uint8{0, 1, 2, 4, 6, 9, 1}

	// Create Dilithium instance to get a valid secret key
	binUnsizeSeed, err := hex.DecodeString(HexSeed)
	if err != nil {
		t.Error("failed to decode hexseed ", err.Error())
	}
	var binSeed [SEED_BYTES]uint8
	copy(binSeed[:], binUnsizeSeed)
	d, err := NewDilithiumFromSeed(binSeed)
	if err != nil {
		t.Error("failed to generate new dilithium from seed ", err.Error())
	}

	sk := d.GetSK()
	pk := d.GetPK()

	// Sign using SignWithSecretKey
	signature, err := SignWithSecretKey(msg, &sk)
	if err != nil {
		t.Error("failed to sign with secret key ", err.Error())
	}

	// Verify signature has correct size
	if len(signature) != CRYPTO_BYTES {
		t.Errorf("signature size: expected %d, got %d", CRYPTO_BYTES, len(signature))
	}

	// Verify signature is valid
	if !Verify(msg, signature, &pk) {
		t.Error("signature verification failed")
	}

	// Sign using the instance method and compare (deterministic signing)
	signature2, err := d.Sign(msg)
	if err != nil {
		t.Error("failed to sign with instance method ", err.Error())
	}

	if signature != signature2 {
		t.Error("SignWithSecretKey and Sign() should produce identical signatures")
	}
}
