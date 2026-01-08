package xmss

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

// Test vectors generated with known seed for deterministic testing
var testSeed = make([]uint8, 48)

func newTestXMSS(t *testing.T, height Height) *XMSS {
	t.Helper()
	xmss, err := InitializeTree(height, SHAKE_128, testSeed)
	if err != nil {
		t.Fatalf("InitializeTree failed: %v", err)
	}
	return xmss
}

func TestInitializeTreeHeight4(t *testing.T) {
	xmss := newTestXMSS(t, 4)
	if xmss == nil {
		t.Fatal("InitializeTree returned nil")
	}

	if xmss.GetHeight() != 4 {
		t.Errorf("Height mismatch: expected 4, got %d", xmss.GetHeight())
	}

	if xmss.GetHashFunction() != SHAKE_128 {
		t.Errorf("HashFunction mismatch: expected SHAKE_128, got %d", xmss.GetHashFunction())
	}
}

func TestInitializeTreeHeight6(t *testing.T) {
	xmss := newTestXMSS(t, 6)
	if xmss == nil {
		t.Fatal("InitializeTree returned nil")
	}

	if xmss.GetHeight() != 6 {
		t.Errorf("Height mismatch: expected 6, got %d", xmss.GetHeight())
	}
}

func TestInitializeTreeHeight8(t *testing.T) {
	xmss := newTestXMSS(t, 8)
	if xmss == nil {
		t.Fatal("InitializeTree returned nil")
	}

	if xmss.GetHeight() != 8 {
		t.Errorf("Height mismatch: expected 8, got %d", xmss.GetHeight())
	}
}

func TestInitializeTreeDeterministic(t *testing.T) {
	// Two trees with same seed should produce same keys
	xmss1 := newTestXMSS(t, 4)
	xmss2 := newTestXMSS(t, 4)

	if !bytes.Equal(xmss1.GetSK(), xmss2.GetSK()) {
		t.Error("Secret keys should be equal for same seed")
	}

	if !bytes.Equal(xmss1.GetRoot(), xmss2.GetRoot()) {
		t.Error("Roots should be equal for same seed")
	}

	if !bytes.Equal(xmss1.GetPKSeed(), xmss2.GetPKSeed()) {
		t.Error("PK seeds should be equal for same seed")
	}
}

func TestInitializeTreeDifferentSeeds(t *testing.T) {
	seed1 := make([]uint8, 48)
	seed2 := make([]uint8, 48)
	seed2[0] = 1 // Different seed

	xmss1, err := InitializeTree(4, SHAKE_128, seed1)
	if err != nil {
		t.Fatalf("InitializeTree failed: %v", err)
	}
	xmss2, err := InitializeTree(4, SHAKE_128, seed2)
	if err != nil {
		t.Fatalf("InitializeTree failed: %v", err)
	}

	if bytes.Equal(xmss1.GetSK(), xmss2.GetSK()) {
		t.Error("Secret keys should differ for different seeds")
	}

	if bytes.Equal(xmss1.GetRoot(), xmss2.GetRoot()) {
		t.Error("Roots should differ for different seeds")
	}
}

func TestGetSeed(t *testing.T) {
	xmss := newTestXMSS(t, 4)
	seed := xmss.GetSeed()

	if !bytes.Equal(seed, testSeed) {
		t.Error("GetSeed should return the original seed")
	}
}

func TestGetSK(t *testing.T) {
	xmss := newTestXMSS(t, 4)
	sk := xmss.GetSK()

	if len(sk) != 132 {
		t.Errorf("SK length mismatch: expected 132, got %d", len(sk))
	}
}

func TestGetPKSeed(t *testing.T) {
	xmss := newTestXMSS(t, 4)
	pkSeed := xmss.GetPKSeed()

	if len(pkSeed) != 32 {
		t.Errorf("PKSeed length mismatch: expected 32, got %d", len(pkSeed))
	}
}

func TestGetRoot(t *testing.T) {
	xmss := newTestXMSS(t, 4)
	root := xmss.GetRoot()

	if len(root) != 32 {
		t.Errorf("Root length mismatch: expected 32, got %d", len(root))
	}
}

func TestGetIndex(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	// Initial index should be 0
	if xmss.GetIndex() != 0 {
		t.Errorf("Initial index should be 0, got %d", xmss.GetIndex())
	}
}

func TestSetIndex(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	// Set index to 5
	if err := xmss.SetIndex(5); err != nil {
		t.Fatalf("SetIndex(5) failed: %v", err)
	}

	if xmss.GetIndex() != 5 {
		t.Errorf("Index should be 5, got %d", xmss.GetIndex())
	}
}

func TestSetIndexLimit(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	// Height 4 means 2^4 = 16 signatures, max index is 15
	if err := xmss.SetIndex(15); err != nil {
		t.Fatalf("SetIndex(15) failed: %v", err)
	}

	if xmss.GetIndex() != 15 {
		t.Errorf("Index should be 15, got %d", xmss.GetIndex())
	}
}

func TestSetIndexTooHigh(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	// Height 4 means max index is 15, 16 should fail
	err := xmss.SetIndex(16)
	if err == nil {
		t.Error("SetIndex(16) should fail for height 4")
	}
}

func TestSetIndexWayTooHigh(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	// Way beyond limit
	err := xmss.SetIndex(1000)
	if err == nil {
		t.Error("SetIndex(1000) should fail for height 4")
	}
}

func TestSignAndVerify(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	message := make([]uint8, 32)
	for i := range message {
		message[i] = uint8(i)
	}

	signature, err := xmss.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Build public key from root and PKSeed
	pk := make([]uint8, 64)
	copy(pk[:32], xmss.GetRoot())
	copy(pk[32:], xmss.GetPKSeed())

	if !Verify(SHAKE_128, message, signature, pk) {
		t.Error("Verify should return true for valid signature")
	}
}

func TestSignAndVerifyMultiple(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	message := make([]uint8, 32)

	signature, err := xmss.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pk := make([]uint8, 64)
	copy(pk[:32], xmss.GetRoot())
	copy(pk[32:], xmss.GetPKSeed())

	// Verify multiple times (should always succeed)
	for i := 0; i < 100; i++ {
		if !Verify(SHAKE_128, message, signature, pk) {
			t.Errorf("Verify failed on iteration %d", i)
		}
	}
}

func TestVerifyCorruptedSignature(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	message := make([]uint8, 32)

	signature, err := xmss.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pk := make([]uint8, 64)
	copy(pk[:32], xmss.GetRoot())
	copy(pk[32:], xmss.GetPKSeed())

	// Corrupt signature
	signature[100]++

	if Verify(SHAKE_128, message, signature, pk) {
		t.Error("Verify should return false for corrupted signature")
	}

	// Restore and verify it works again
	signature[100]--
	if !Verify(SHAKE_128, message, signature, pk) {
		t.Error("Verify should return true after restoring signature")
	}
}

func TestVerifyCorruptedMessage(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	message := make([]uint8, 32)

	signature, err := xmss.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pk := make([]uint8, 64)
	copy(pk[:32], xmss.GetRoot())
	copy(pk[32:], xmss.GetPKSeed())

	// Corrupt message
	message[2]++

	if Verify(SHAKE_128, message, signature, pk) {
		t.Error("Verify should return false for corrupted message")
	}

	// Restore and verify it works again
	message[2]--
	if !Verify(SHAKE_128, message, signature, pk) {
		t.Error("Verify should return true after restoring message")
	}
}

func TestVerifyWrongPublicKey(t *testing.T) {
	xmss1 := newTestXMSS(t, 4)

	seed2 := make([]uint8, 48)
	seed2[0] = 1
	xmss2, err := InitializeTree(4, SHAKE_128, seed2)
	if err != nil {
		t.Fatalf("InitializeTree failed: %v", err)
	}

	message := make([]uint8, 32)

	signature, err := xmss1.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Use wrong public key
	pk := make([]uint8, 64)
	copy(pk[:32], xmss2.GetRoot())
	copy(pk[32:], xmss2.GetPKSeed())

	if Verify(SHAKE_128, message, signature, pk) {
		t.Error("Verify should return false for wrong public key")
	}
}

func TestVerifyInvalidSignatureSize(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	message := make([]uint8, 32)
	invalidSig := make([]uint8, 100) // Too short

	pk := make([]uint8, 64)
	copy(pk[:32], xmss.GetRoot())
	copy(pk[32:], xmss.GetPKSeed())

	// Should return false, not panic
	if Verify(SHAKE_128, message, invalidSig, pk) {
		t.Error("Verify should return false for undersized signature")
	}
}

func TestVerifyEmptySignature(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	message := make([]uint8, 32)
	emptySig := make([]uint8, 0)

	pk := make([]uint8, 64)
	copy(pk[:32], xmss.GetRoot())
	copy(pk[32:], xmss.GetPKSeed())

	// Should return false, not panic
	if Verify(SHAKE_128, message, emptySig, pk) {
		t.Error("Verify should return false for empty signature")
	}
}

func TestVerifyMisalignedSignatureSize(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	message := make([]uint8, 32)
	// Signature size that doesn't align to (4 + n*32)
	misalignedSig := make([]uint8, 2500)

	pk := make([]uint8, 64)
	copy(pk[:32], xmss.GetRoot())
	copy(pk[32:], xmss.GetPKSeed())

	// Should return false, not panic
	if Verify(SHAKE_128, message, misalignedSig, pk) {
		t.Error("Verify should return false for misaligned signature size")
	}
}

func TestSignIncrementsIndex(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	initialIndex := xmss.GetIndex()
	if initialIndex != 0 {
		t.Fatalf("Initial index should be 0, got %d", initialIndex)
	}

	message := make([]uint8, 32)

	_, err := xmss.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Index should have incremented
	if xmss.GetIndex() != 1 {
		t.Errorf("Index should be 1 after signing, got %d", xmss.GetIndex())
	}
}

func TestMultipleSignatures(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	pk := make([]uint8, 64)
	copy(pk[:32], xmss.GetRoot())
	copy(pk[32:], xmss.GetPKSeed())

	// Sign multiple messages
	for i := 0; i < 5; i++ {
		message := make([]uint8, 32)
		message[0] = uint8(i)

		signature, err := xmss.Sign(message)
		if err != nil {
			t.Fatalf("Sign failed on iteration %d: %v", i, err)
		}

		if !Verify(SHAKE_128, message, signature, pk) {
			t.Errorf("Verify failed on iteration %d", i)
		}

		// Index should increment
		expectedIndex := uint32(i + 1)
		if xmss.GetIndex() != expectedIndex {
			t.Errorf("Index should be %d after %d signatures, got %d", expectedIndex, i+1, xmss.GetIndex())
		}
	}
}

func TestZeroize(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	// Get copies before zeroize
	sk := make([]uint8, len(xmss.GetSK()))
	copy(sk, xmss.GetSK())

	seed := make([]uint8, len(xmss.GetSeed()))
	copy(seed, xmss.GetSeed())

	// Zeroize
	xmss.Zeroize()

	// Verify SK is zeroed
	for i, b := range xmss.GetSK() {
		if b != 0 {
			t.Errorf("SK byte %d should be 0 after Zeroize, got %d", i, b)
		}
	}

	// Verify seed is zeroed
	for i, b := range xmss.GetSeed() {
		if b != 0 {
			t.Errorf("Seed byte %d should be 0 after Zeroize, got %d", i, b)
		}
	}
}

func TestHeightIsValid(t *testing.T) {
	testCases := []struct {
		height uint8
		valid  bool
	}{
		{0, false},
		{1, false},
		{2, true},
		{3, false},
		{4, true},
		{5, false},
		{6, true},
		{8, true},
		{10, true},
		{12, true},
		{14, true},
		{16, true},
		{18, true},
		{20, true},
		{30, true},
		{31, false},
		{32, false},
	}

	for _, tc := range testCases {
		h := Height(tc.height)
		if h.IsValid() != tc.valid {
			t.Errorf("Height(%d).IsValid() = %v, want %v", tc.height, h.IsValid(), tc.valid)
		}
	}
}

func TestToHeightReturnsErrorOnInvalid(t *testing.T) {
	// Odd number - should return error
	_, err := ToHeight(7)
	if err == nil {
		t.Error("ToHeight(7) should return error for odd height")
	}

	// Height 0 - should return error
	_, err = ToHeight(0)
	if err == nil {
		t.Error("ToHeight(0) should return error")
	}

	// Height > MaxHeight - should return error
	_, err = ToHeight(32)
	if err == nil {
		t.Error("ToHeight(32) should return error for height > MaxHeight")
	}
}

func TestInitializeTreeReturnsErrorOnInvalidHeight(t *testing.T) {
	// Height 3 is invalid (odd) - should fail at ToHeight
	_, err := ToHeight(3)
	if err == nil {
		t.Error("ToHeight(3) should return error for odd height")
	}

	// Height 2 with k=2 fails BDS check (k >= height)
	// WOTSParamK is 2, so height 2 is invalid for BDS traversal
	seed := make([]uint8, 48)
	_, err = InitializeTree(2, SHAKE_128, seed)
	if err == nil {
		t.Error("InitializeTree with height=2 should return error (k >= height)")
	}
}

func TestDifferentHashFunctions(t *testing.T) {
	seed := make([]uint8, 48)

	hashFunctions := []HashFunction{SHA2_256, SHAKE_128, SHAKE_256}

	for _, hf := range hashFunctions {
		t.Run(fmt.Sprintf("HashFunction_%d", hf), func(t *testing.T) {
			xmss, err := InitializeTree(4, hf, seed)
			if err != nil {
				t.Fatalf("InitializeTree failed: %v", err)
			}

			if xmss.GetHashFunction() != hf {
				t.Errorf("HashFunction mismatch: expected %d, got %d", hf, xmss.GetHashFunction())
			}

			message := make([]uint8, 32)
			signature, err := xmss.Sign(message)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			pk := make([]uint8, 64)
			copy(pk[:32], xmss.GetRoot())
			copy(pk[32:], xmss.GetPKSeed())

			if !Verify(hf, message, signature, pk) {
				t.Error("Verify should return true")
			}

			// Verify with wrong hash function should fail
			wrongHF := (hf + 1) % 3
			if Verify(wrongHF, message, signature, pk) {
				t.Error("Verify with wrong hash function should return false")
			}
		})
	}
}

func TestKnownTestVector(t *testing.T) {
	// Test vector from legacy wallet tests (legacy QRL python/cpp/js qrllib)
	// This ensures backward compatibility with existing QRL addresses.
	// Zero seed should produce known root/address.
	seed := make([]uint8, 48)
	xmss, err := InitializeTree(4, SHAKE_128, seed)
	if err != nil {
		t.Fatalf("InitializeTree failed: %v", err)
	}

	root := xmss.GetRoot()
	pkSeed := xmss.GetPKSeed()

	// The expected root from the legacy wallet test (part of the PK)
	// PK format: descriptor(3) + root(32) + pkSeed(32) = 67 bytes
	// From legacy test: expectedPK starting with "010200c25188..."
	// The root is at bytes 3-35 of the extended PK

	// Verify we get consistent results
	rootHex := hex.EncodeToString(root)
	pkSeedHex := hex.EncodeToString(pkSeed)

	t.Logf("Root: %s", rootHex)
	t.Logf("PKSeed: %s", pkSeedHex)

	// From legacy test expectedPK (after 3-byte descriptor):
	// c25188b585f731c128e2b457069eafd1e3fa3961605af8c58a1aec4d82ac316d (root)
	// 3191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5d (pkSeed)
	expectedRoot := "c25188b585f731c128e2b457069eafd1e3fa3961605af8c58a1aec4d82ac316d"
	expectedPKSeed := "3191da3442686282b3d5160f25cf162a517fd2131f83fbf2698a58f9c46afc5d"

	if rootHex != expectedRoot {
		t.Errorf("Root mismatch:\nExpected: %s\nGot:      %s", expectedRoot, rootHex)
	}

	if pkSeedHex != expectedPKSeed {
		t.Errorf("PKSeed mismatch:\nExpected: %s\nGot:      %s", expectedPKSeed, pkSeedHex)
	}
}

func TestEmptyMessage(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	message := make([]uint8, 0) // Empty message

	signature, err := xmss.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pk := make([]uint8, 64)
	copy(pk[:32], xmss.GetRoot())
	copy(pk[32:], xmss.GetPKSeed())

	if !Verify(SHAKE_128, message, signature, pk) {
		t.Error("Verify should return true for empty message")
	}
}

func TestLargeMessage(t *testing.T) {
	xmss := newTestXMSS(t, 4)

	message := make([]uint8, 10000) // Large message
	for i := range message {
		message[i] = uint8(i % 256)
	}

	signature, err := xmss.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pk := make([]uint8, 64)
	copy(pk[:32], xmss.GetRoot())
	copy(pk[32:], xmss.GetPKSeed())

	if !Verify(SHAKE_128, message, signature, pk) {
		t.Error("Verify should return true for large message")
	}
}
