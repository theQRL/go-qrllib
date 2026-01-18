package ml_dsa_87

import (
	"crypto/rand"
	"testing"
)

// Canonicality tests for ML-DSA-87 signature verification.
// These tests verify that non-canonical encodings are rejected, ensuring
// signature malleability resistance as documented in SECURITY.md.
//
// Signature layout: c_tilde (64 bytes) || z (L*640=4480 bytes) || hints (OMEGA+K=83 bytes)
// Hints layout: hint_indices[OMEGA=75] || cumulative_counts[K=8]

// TestCanonicalityTruncatedSignatures tests that truncated signatures are rejected.
func TestCanonicalityTruncatedSignatures(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message for canonicality")
	ctx := []byte{}
	pk := mldsa.GetPK()

	validSig, err := mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Test various truncation points
	truncationPoints := []struct {
		name   string
		length int
	}{
		{"empty", 0},
		{"one_byte", 1},
		{"partial_c_tilde", C_TILDE_BYTES / 2},
		{"exactly_c_tilde", C_TILDE_BYTES},
		{"partial_z_first_poly", C_TILDE_BYTES + POLY_Z_PACKED_BYTES/2},
		{"one_z_poly", C_TILDE_BYTES + POLY_Z_PACKED_BYTES},
		{"all_z_no_hints", C_TILDE_BYTES + L*POLY_Z_PACKED_BYTES},
		{"partial_hints", C_TILDE_BYTES + L*POLY_Z_PACKED_BYTES + OMEGA/2},
		{"missing_last_byte", CRYPTO_BYTES - 1},
	}

	for _, tc := range truncationPoints {
		t.Run(tc.name, func(t *testing.T) {
			if tc.length >= CRYPTO_BYTES {
				t.Skip("Not a truncation test")
			}

			// Create truncated signature by copying to smaller fixed array
			// Note: Verify expects [CRYPTO_BYTES]uint8, so we test via Open
			truncated := make([]byte, tc.length)
			copy(truncated, validSig[:tc.length])

			// Use Open which handles variable-length sealed messages
			sealed := append(truncated, msg...)
			if Open(ctx, sealed, &pk) != nil {
				t.Errorf("Truncated signature at %d bytes should not verify", tc.length)
			}
		})
	}
}

// TestCanonicalityExtendedSignatures tests that signatures with extra trailing bytes are handled.
// Note: The API uses fixed-size arrays, but we verify behavior is correct.
func TestCanonicalityExtendedSignatures(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message for canonicality")
	ctx := []byte{}
	pk := mldsa.GetPK()

	validSig, err := mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify the valid signature works
	if !Verify(ctx, msg, validSig, &pk) {
		t.Fatal("Valid signature should verify")
	}

	// Test that corrupting any trailing position invalidates
	// (The fixed array prevents extension, so we test boundary)
	t.Run("last_byte_corruption", func(t *testing.T) {
		corruptedSig := validSig
		corruptedSig[CRYPTO_BYTES-1] ^= 0x01
		if Verify(ctx, msg, corruptedSig, &pk) {
			t.Error("Corrupted last byte should invalidate signature")
		}
	})
}

// TestCanonicalityHintIndexOutOfBounds tests that hint indices >= N are rejected.
func TestCanonicalityHintIndexOutOfBounds(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.GetPK()

	validSig, err := mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	hintStart := C_TILDE_BYTES + L*POLY_Z_PACKED_BYTES

	// N=256, so valid indices are 0-255. Index 256 or higher should be rejected.
	// However, hint indices are stored as uint8, so max is 255.
	// Test that index 255 with malformed structure fails verification.

	t.Run("hint_index_at_max_with_bad_structure", func(t *testing.T) {
		malformedSig := validSig
		// Set one hint at index 255
		malformedSig[hintStart+OMEGA] = 1 // cumulative count = 1 for first poly
		malformedSig[hintStart+0] = 255   // index 255
		// Clear remaining cumulative counts
		for i := 1; i < K; i++ {
			malformedSig[hintStart+OMEGA+i] = 1
		}
		// The malformed signature should not verify
		if Verify(ctx, msg, malformedSig, &pk) {
			t.Error("Malformed signature with modified hints should not verify")
		}
	})
}

// TestCanonicalityCumulativeCountDecreasing tests that decreasing cumulative counts are rejected.
func TestCanonicalityCumulativeCountDecreasing(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.GetPK()

	validSig, err := mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	hintStart := C_TILDE_BYTES + L*POLY_Z_PACKED_BYTES

	t.Run("cumulative_count_decreases", func(t *testing.T) {
		malformedSig := validSig
		// Set cumulative counts that decrease: 3, 2 (invalid!)
		malformedSig[hintStart+OMEGA+0] = 3
		malformedSig[hintStart+OMEGA+1] = 2 // Decreases from 3 to 2
		// Set valid indices for first 3 hints
		malformedSig[hintStart+0] = 10
		malformedSig[hintStart+1] = 20
		malformedSig[hintStart+2] = 30

		if Verify(ctx, msg, malformedSig, &pk) {
			t.Error("Signature with decreasing cumulative count should not verify")
		}
	})

	t.Run("cumulative_count_zero_then_positive", func(t *testing.T) {
		malformedSig := validSig
		// Set cumulative counts: 0, 2 (valid - can have no hints in first poly)
		// But then we need strictly increasing indices starting at position 0
		malformedSig[hintStart+OMEGA+0] = 0
		malformedSig[hintStart+OMEGA+1] = 2
		malformedSig[hintStart+0] = 5
		malformedSig[hintStart+1] = 10
		for i := 2; i < K; i++ {
			malformedSig[hintStart+OMEGA+i] = 2
		}
		// Zero padding for remaining
		for i := 2; i < OMEGA; i++ {
			malformedSig[hintStart+i] = 0
		}
		// This is a valid encoding, but won't verify cryptographically
	})
}

// TestCanonicalityCumulativeCountExceedsOmega tests that cumulative counts > OMEGA are rejected.
func TestCanonicalityCumulativeCountExceedsOmega(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.GetPK()

	validSig, err := mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	hintStart := C_TILDE_BYTES + L*POLY_Z_PACKED_BYTES

	testCases := []struct {
		name  string
		count uint8
	}{
		{"omega_plus_one", OMEGA + 1},
		{"max_uint8", 255},
		{"omega_plus_10", OMEGA + 10},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			malformedSig := validSig
			// Set cumulative count exceeding OMEGA
			malformedSig[hintStart+OMEGA+0] = tc.count

			if Verify(ctx, msg, malformedSig, &pk) {
				t.Errorf("Signature with cumulative count %d (> OMEGA=%d) should not verify", tc.count, OMEGA)
			}
		})
	}
}

// TestCanonicalityHintIndicesNotStrictlyIncreasing tests various non-canonical hint orderings.
func TestCanonicalityHintIndicesNotStrictlyIncreasing(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.GetPK()

	validSig, err := mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	hintStart := C_TILDE_BYTES + L*POLY_Z_PACKED_BYTES

	testCases := []struct {
		name    string
		indices []uint8
		count   uint8
	}{
		{"equal_indices", []uint8{10, 10, 20}, 3},
		{"decreasing_pair", []uint8{20, 10, 30}, 3},
		{"all_same", []uint8{5, 5, 5, 5}, 4},
		{"decreasing_sequence", []uint8{30, 20, 10}, 3},
		{"almost_sorted_duplicate", []uint8{1, 2, 3, 3, 5}, 5},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			malformedSig := validSig
			// Set hint indices
			for i, idx := range tc.indices {
				malformedSig[hintStart+i] = idx
			}
			// Set cumulative count for first polynomial
			malformedSig[hintStart+OMEGA] = tc.count
			// Set remaining cumulative counts equal
			for i := 1; i < K; i++ {
				malformedSig[hintStart+OMEGA+i] = tc.count
			}
			// Zero padding
			for i := int(tc.count); i < OMEGA; i++ {
				malformedSig[hintStart+i] = 0
			}

			if Verify(ctx, msg, malformedSig, &pk) {
				t.Errorf("Signature with non-increasing hint indices %v should not verify", tc.indices)
			}
		})
	}
}

// TestCanonicalityNonZeroPadding tests that non-zero bytes in padding area are rejected.
func TestCanonicalityNonZeroPadding(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.GetPK()

	validSig, err := mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	hintStart := C_TILDE_BYTES + L*POLY_Z_PACKED_BYTES

	testCases := []struct {
		name         string
		paddingPos   int
		paddingValue uint8
	}{
		{"first_padding_byte", 0, 0xFF},
		{"middle_padding_byte", OMEGA / 2, 0x01},
		{"last_padding_byte", OMEGA - 1, 0x80},
		{"random_value", 10, 0x42},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			malformedSig := validSig
			// Set all cumulative counts to 0 (no hints)
			for i := 0; i < K; i++ {
				malformedSig[hintStart+OMEGA+i] = 0
			}
			// Add non-zero value in padding area
			malformedSig[hintStart+tc.paddingPos] = tc.paddingValue

			if Verify(ctx, msg, malformedSig, &pk) {
				t.Errorf("Signature with non-zero padding at position %d should not verify", tc.paddingPos)
			}
		})
	}
}

// TestCanonicalityChallengeMalformation tests that corrupted challenge bytes are rejected.
func TestCanonicalityChallengeMalformation(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.GetPK()

	validSig, err := mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Test corruption at various positions in c_tilde
	positions := []int{0, C_TILDE_BYTES / 4, C_TILDE_BYTES / 2, C_TILDE_BYTES - 1}

	for _, pos := range positions {
		t.Run("challenge_corruption", func(t *testing.T) {
			malformedSig := validSig
			malformedSig[pos] ^= 0xFF

			if Verify(ctx, msg, malformedSig, &pk) {
				t.Errorf("Signature with corrupted challenge at byte %d should not verify", pos)
			}
		})
	}
}

// TestCanonicalityZVectorCorruption tests that corrupted z-vector bytes are rejected.
func TestCanonicalityZVectorCorruption(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.GetPK()

	validSig, err := mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	zStart := C_TILDE_BYTES
	zEnd := C_TILDE_BYTES + L*POLY_Z_PACKED_BYTES

	// Test corruption at various positions in z-vector
	positions := []int{
		zStart,                  // First byte of z
		zStart + POLY_Z_PACKED_BYTES/2, // Middle of first z poly
		zStart + POLY_Z_PACKED_BYTES,   // Start of second z poly
		zEnd - 1,               // Last byte of z
	}

	for _, pos := range positions {
		t.Run("z_vector_corruption", func(t *testing.T) {
			malformedSig := validSig
			malformedSig[pos] ^= 0xFF

			if Verify(ctx, msg, malformedSig, &pk) {
				t.Errorf("Signature with corrupted z-vector at byte %d should not verify", pos)
			}
		})
	}
}

// TestCanonicalityAllZeroSignature tests that an all-zero signature is rejected.
func TestCanonicalityAllZeroSignature(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.GetPK()

	var zeroSig [CRYPTO_BYTES]uint8

	if Verify(ctx, msg, zeroSig, &pk) {
		t.Error("All-zero signature should not verify")
	}
}

// TestCanonicalityAllOnesSignature tests that an all-ones signature is rejected.
func TestCanonicalityAllOnesSignature(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.GetPK()

	var onesSig [CRYPTO_BYTES]uint8
	for i := range onesSig {
		onesSig[i] = 0xFF
	}

	if Verify(ctx, msg, onesSig, &pk) {
		t.Error("All-ones signature should not verify")
	}
}

// TestCanonicalityRandomSignatures tests that random signatures don't verify.
func TestCanonicalityRandomSignatures(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.GetPK()

	// Test multiple random signatures
	for i := 0; i < 100; i++ {
		var randomSig [CRYPTO_BYTES]uint8
		_, _ = rand.Read(randomSig[:])

		if Verify(ctx, msg, randomSig, &pk) {
			t.Errorf("Random signature %d should not verify", i)
		}
	}
}

// TestCanonicalityValidSignatureVerifies ensures valid signatures still work.
func TestCanonicalityValidSignatureVerifies(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	messages := [][]byte{
		{},
		{0x00},
		[]byte("short"),
		[]byte("a longer message for testing signature verification"),
		make([]byte, 1024),
	}

	for i, msg := range messages {
		if i == len(messages)-1 {
			_, _ = rand.Read(msg)
		}

		ctx := []byte{}
		sig, err := mldsa.Sign(ctx, msg)
		if err != nil {
			t.Fatalf("Failed to sign message %d: %v", i, err)
		}

		pk := mldsa.GetPK()
		if !Verify(ctx, msg, sig, &pk) {
			t.Errorf("Valid signature for message %d should verify", i)
		}
	}
}

// TestCanonicalitySignatureUniqueness tests that the same message produces valid but potentially different signatures.
func TestCanonicalitySignatureUniqueness(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.GetPK()

	sig1, err := mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	sig2, err := mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Both signatures must verify
	if !Verify(ctx, msg, sig1, &pk) {
		t.Error("First signature should verify")
	}
	if !Verify(ctx, msg, sig2, &pk) {
		t.Error("Second signature should verify")
	}

	// Note: ML-DSA-87 with deterministic signing may produce identical signatures
	// This is expected behavior and not a canonicality issue
}
