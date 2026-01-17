package xmss

import (
	"crypto/rand"
	"testing"
)

// Canonicality tests for XMSS signature verification.
// XMSS is hash-based, meaning signatures are inherently canonical
// (no alternate encodings for the same signature). These tests verify
// that malformed signatures are rejected.
//
// Signature layout: index (4 bytes) || R (n bytes) || WOTS signature || auth path

// Helper constants for test signature sizes
const (
	wotsKeySize   = 67 * 32 // WOTSParamLen * WOTSParamN = 2144
	sigBaseSize   = 4 + 32 + wotsKeySize // index + R + wots = 2180
)

// getCanonicalityTestSignatureSize calculates expected signature size for a height.
func getCanonicalityTestSignatureSize(height Height) int {
	return sigBaseSize + int(height)*32
}

// TestCanonicalityTruncatedSignatures tests that truncated signatures are rejected.
func TestCanonicalityTruncatedSignatures(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message for canonicality")
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	validSig, err := xmss.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	expectedSize := getCanonicalityTestSignatureSize(4)

	// Test various truncation points
	truncationPoints := []struct {
		name   string
		length int
	}{
		{"empty", 0},
		{"one_byte", 1},
		{"partial_index", 2},
		{"exactly_index", 4},
		{"partial_R", 4 + 16},
		{"exactly_R", 4 + 32},
		{"partial_wots", 4 + 32 + wotsKeySize/2},
		{"exactly_wots", 4 + 32 + wotsKeySize},
		{"partial_auth_path", sigBaseSize + 2*32},
		{"missing_last_node", expectedSize - 32},
		{"missing_last_byte", expectedSize - 1},
	}

	for _, tc := range truncationPoints {
		t.Run(tc.name, func(t *testing.T) {
			if tc.length >= expectedSize {
				t.Skip("Not a truncation test")
			}

			truncated := make([]byte, tc.length)
			copy(truncated, validSig[:tc.length])

			if Verify(xmss.GetHashFunction(), msg, truncated, pk) {
				t.Errorf("Truncated signature at %d bytes should not verify", tc.length)
			}
		})
	}
}

// TestCanonicalityOversizedSignatures tests that oversized signatures are rejected.
func TestCanonicalityOversizedSignatures(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message")
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	expectedSize := getCanonicalityTestSignatureSize(4)

	// Create oversized signatures
	oversizedLengths := []int{
		expectedSize + 1,
		expectedSize + 32,
		expectedSize + 100,
		expectedSize * 2,
	}

	for _, length := range oversizedLengths {
		t.Run("oversized", func(t *testing.T) {
			oversized := make([]byte, length)
			_, _ = rand.Read(oversized)

			if Verify(xmss.GetHashFunction(), msg, oversized, pk) {
				t.Errorf("Oversized signature at %d bytes should not verify", length)
			}
		})
	}
}

// TestCanonicalityIndexCorruption tests corruption of the signature index bytes.
func TestCanonicalityIndexCorruption(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message for index canonicality")
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	validSig, err := xmss.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Test corruption of each index byte
	for i := 0; i < 4; i++ {
		t.Run("index_byte", func(t *testing.T) {
			corruptedSig := make([]byte, len(validSig))
			copy(corruptedSig, validSig)
			corruptedSig[i] ^= 0xFF

			if Verify(xmss.GetHashFunction(), msg, corruptedSig, pk) {
				t.Errorf("Corrupted index byte %d should not verify", i)
			}
		})
	}
}

// TestCanonicalityRCorruption tests corruption of the R (randomizer) bytes.
func TestCanonicalityRCorruption(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message for R canonicality")
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	validSig, err := xmss.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	rStart := 4 // After index
	rEnd := 4 + 32

	// Test corruption at various R positions
	positions := []int{rStart, rStart + 8, rStart + 16, rEnd - 1}

	for _, pos := range positions {
		t.Run("R_corruption", func(t *testing.T) {
			corruptedSig := make([]byte, len(validSig))
			copy(corruptedSig, validSig)
			corruptedSig[pos] ^= 0xFF

			if Verify(xmss.GetHashFunction(), msg, corruptedSig, pk) {
				t.Errorf("Corrupted R at byte %d should not verify", pos)
			}
		})
	}
}

// TestCanonicalityWOTSCorruption tests corruption of WOTS signature components.
func TestCanonicalityWOTSCorruption(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message for WOTS canonicality")
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	validSig, err := xmss.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	wotsStart := 4 + 32 // After index and R
	wotsEnd := wotsStart + wotsKeySize

	// Test corruption at various WOTS chain positions
	// WOTS has 67 chains of 32 bytes each
	for chain := 0; chain < 67; chain += 10 { // Sample every 10th chain
		t.Run("wots_chain", func(t *testing.T) {
			pos := wotsStart + chain*32
			if pos >= wotsEnd {
				return
			}

			corruptedSig := make([]byte, len(validSig))
			copy(corruptedSig, validSig)
			corruptedSig[pos] ^= 0x01

			if Verify(xmss.GetHashFunction(), msg, corruptedSig, pk) {
				t.Errorf("Corrupted WOTS chain %d should not verify", chain)
			}
		})
	}
}

// TestCanonicalityAuthPathCorruption tests corruption of auth path nodes.
func TestCanonicalityAuthPathCorruption(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message for auth path canonicality")
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	validSig, err := xmss.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	authStart := sigBaseSize // After index, R, and WOTS

	// Test corruption at each auth path level
	for level := 0; level < 4; level++ { // Height 4 = 4 auth path nodes
		t.Run("auth_level", func(t *testing.T) {
			pos := authStart + level*32

			corruptedSig := make([]byte, len(validSig))
			copy(corruptedSig, validSig)
			corruptedSig[pos] ^= 0x01

			if Verify(xmss.GetHashFunction(), msg, corruptedSig, pk) {
				t.Errorf("Corrupted auth path level %d should not verify", level)
			}
		})
	}
}

// TestCanonicalityAllZeroSignature tests that an all-zero signature is rejected.
func TestCanonicalityAllZeroSignature(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message")
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	zeroSig := make([]byte, getCanonicalityTestSignatureSize(4))

	if Verify(xmss.GetHashFunction(), msg, zeroSig, pk) {
		t.Error("All-zero signature should not verify")
	}
}

// TestCanonicalityAllOnesSignature tests that an all-ones signature is rejected.
func TestCanonicalityAllOnesSignature(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message")
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	onesSig := make([]byte, getCanonicalityTestSignatureSize(4))
	for i := range onesSig {
		onesSig[i] = 0xFF
	}

	if Verify(xmss.GetHashFunction(), msg, onesSig, pk) {
		t.Error("All-ones signature should not verify")
	}
}

// TestCanonicalityRandomSignatures tests that random signatures don't verify.
func TestCanonicalityRandomSignatures(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message")
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	sigSize := getCanonicalityTestSignatureSize(4)

	// Test multiple random signatures
	for i := 0; i < 50; i++ {
		randomSig := make([]byte, sigSize)
		_, _ = rand.Read(randomSig)

		if Verify(xmss.GetHashFunction(), msg, randomSig, pk) {
			t.Errorf("Random signature %d should not verify", i)
		}
	}
}

// TestCanonicalityMisalignedSignatureSize tests signatures with incorrect alignment.
func TestCanonicalityMisalignedSignatureSize(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message")
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	// Signature size should be (sigSize - 4) % 32 == 0
	// Test various misaligned sizes
	baseSizeMinusIndex := sigBaseSize - 4 // Should be divisible by 32

	misalignedSizes := []int{
		baseSizeMinusIndex + 4 + 1,  // Off by 1
		baseSizeMinusIndex + 4 + 15, // Off by 15
		baseSizeMinusIndex + 4 + 33, // Just over one auth node
	}

	for _, size := range misalignedSizes {
		t.Run("misaligned", func(t *testing.T) {
			misaligned := make([]byte, size)
			_, _ = rand.Read(misaligned)

			if Verify(xmss.GetHashFunction(), msg, misaligned, pk) {
				t.Errorf("Misaligned signature of size %d should not verify", size)
			}
		})
	}
}

// TestCanonicalityInvalidHeightSignature tests signatures with invalid derived height.
func TestCanonicalityInvalidHeightSignature(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message")
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	// Height 0, 1, and 2 fail BDS parameter check
	invalidHeightSizes := []struct {
		name   string
		height Height
	}{
		{"height_0", 0},
		{"height_1", 1},
		{"height_2", 2},
	}

	for _, tc := range invalidHeightSizes {
		t.Run(tc.name, func(t *testing.T) {
			size := getCanonicalityTestSignatureSize(tc.height)
			sig := make([]byte, size)
			_, _ = rand.Read(sig)

			if Verify(xmss.GetHashFunction(), msg, sig, pk) {
				t.Errorf("Signature with invalid height %d should not verify", tc.height)
			}
		})
	}
}

// TestCanonicalityWrongHashFunction tests that signatures don't verify with wrong hash function.
func TestCanonicalityWrongHashFunction(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message")

	validSig, err := xmss.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	// Verify with correct hash function works
	if !Verify(SHAKE_128, msg, validSig, pk) {
		t.Fatal("Valid signature should verify with correct hash function")
	}

	// Verify with wrong hash functions should fail
	wrongHashFuncs := []HashFunction{SHA2_256, SHAKE_256}

	for _, hf := range wrongHashFuncs {
		t.Run(hf.String(), func(t *testing.T) {
			if Verify(hf, msg, validSig, pk) {
				t.Errorf("Signature should not verify with wrong hash function %s", hf.String())
			}
		})
	}
}

// TestCanonicalityValidSignatureVerifies ensures valid signatures still work.
func TestCanonicalityValidSignatureVerifies(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	messages := [][]byte{
		{},
		{0x00},
		[]byte("short"),
		[]byte("a longer message for testing signature verification"),
	}

	for i, msg := range messages {
		sig, err := xmss.Sign(msg)
		if err != nil {
			t.Fatalf("Failed to sign message %d: %v", i, err)
		}

		pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
		if !Verify(xmss.GetHashFunction(), msg, sig, pk) {
			t.Errorf("Valid signature for message %d should verify", i)
		}
	}
}

// TestCanonicalityDifferentHeights tests canonicality across different tree heights.
func TestCanonicalityDifferentHeights(t *testing.T) {
	heights := []Height{4, 6, 8}

	for _, h := range heights {
		t.Run("height", func(t *testing.T) {
			seed := make([]byte, 48)
			xmss, _ := InitializeTree(h, SHAKE_128, seed)

			msg := []byte("test message")
			pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

			validSig, err := xmss.Sign(msg)
			if err != nil {
				t.Fatalf("Failed to sign at height %d: %v", h, err)
			}

			// Valid signature should verify
			if !Verify(xmss.GetHashFunction(), msg, validSig, pk) {
				t.Errorf("Valid signature at height %d should verify", h)
			}

			// Corrupted signature should not verify
			corruptedSig := make([]byte, len(validSig))
			copy(corruptedSig, validSig)
			corruptedSig[len(validSig)/2] ^= 0xFF

			if Verify(xmss.GetHashFunction(), msg, corruptedSig, pk) {
				t.Errorf("Corrupted signature at height %d should not verify", h)
			}
		})
	}
}
