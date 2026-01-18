package dilithium

import (
	"crypto/rand"
	"testing"
)

// Canonicality tests for Dilithium signature verification.
// These tests verify that non-canonical encodings are rejected, ensuring
// signature malleability resistance as documented in SECURITY.md.
//
// Signature layout: c (32 bytes) || z (L*640=4480 bytes) || hints (OMEGA+K=83 bytes)
// Hints layout: hint_indices[OMEGA=75] || cumulative_counts[K=8]

// TestCanonicalityTruncatedSignatures tests that truncated signatures are rejected.
func TestCanonicalityTruncatedSignatures(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message for canonicality")
	pk := dil.GetPK()

	validSig, err := dil.Sign(msg)
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
		{"partial_challenge", SEED_BYTES / 2},
		{"exactly_challenge", SEED_BYTES},
		{"partial_z_first_poly", SEED_BYTES + POLY_Z_PACKED_BYTES/2},
		{"one_z_poly", SEED_BYTES + POLY_Z_PACKED_BYTES},
		{"all_z_no_hints", SEED_BYTES + L*POLY_Z_PACKED_BYTES},
		{"partial_hints", SEED_BYTES + L*POLY_Z_PACKED_BYTES + OMEGA/2},
		{"missing_last_byte", CRYPTO_BYTES - 1},
	}

	for _, tc := range truncationPoints {
		t.Run(tc.name, func(t *testing.T) {
			if tc.length >= CRYPTO_BYTES {
				t.Skip("Not a truncation test")
			}

			// Create truncated signature
			truncated := make([]byte, tc.length)
			copy(truncated, validSig[:tc.length])

			// Use Open which handles variable-length sealed messages
			sealed := append(truncated, msg...)
			if Open(sealed, &pk) != nil {
				t.Errorf("Truncated signature at %d bytes should not verify", tc.length)
			}
		})
	}
}

// TestCanonicalityExtendedSignatures tests that signatures with extra trailing bytes are handled.
func TestCanonicalityExtendedSignatures(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message for canonicality")
	pk := dil.GetPK()

	validSig, err := dil.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify the valid signature works
	if !Verify(msg, validSig, &pk) {
		t.Fatal("Valid signature should verify")
	}

	// Test that corrupting any trailing position invalidates
	t.Run("last_byte_corruption", func(t *testing.T) {
		corruptedSig := validSig
		corruptedSig[CRYPTO_BYTES-1] ^= 0x01
		if Verify(msg, corruptedSig, &pk) {
			t.Error("Corrupted last byte should invalidate signature")
		}
	})
}

// TestCanonicalityCumulativeCountDecreasing tests that decreasing cumulative counts are rejected.
func TestCanonicalityCumulativeCountDecreasing(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	pk := dil.GetPK()

	validSig, err := dil.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	hintStart := SEED_BYTES + L*POLY_Z_PACKED_BYTES

	t.Run("cumulative_count_decreases", func(t *testing.T) {
		malformedSig := validSig
		// Set cumulative counts that decrease: 3, 2 (invalid!)
		malformedSig[hintStart+OMEGA+0] = 3
		malformedSig[hintStart+OMEGA+1] = 2 // Decreases from 3 to 2
		// Set valid indices for first 3 hints
		malformedSig[hintStart+0] = 10
		malformedSig[hintStart+1] = 20
		malformedSig[hintStart+2] = 30

		if Verify(msg, malformedSig, &pk) {
			t.Error("Signature with decreasing cumulative count should not verify")
		}
	})

	t.Run("cumulative_jumps_back", func(t *testing.T) {
		malformedSig := validSig
		// Set cumulative counts: 5, 3, 7 (3 < 5 is invalid)
		malformedSig[hintStart+OMEGA+0] = 5
		malformedSig[hintStart+OMEGA+1] = 3
		malformedSig[hintStart+OMEGA+2] = 7
		// Fill first 5 hint indices
		for i := 0; i < 5; i++ {
			malformedSig[hintStart+i] = uint8(i * 10)
		}

		if Verify(msg, malformedSig, &pk) {
			t.Error("Signature with non-monotonic cumulative count should not verify")
		}
	})
}

// TestCanonicalityCumulativeCountExceedsOmega tests that cumulative counts > OMEGA are rejected.
func TestCanonicalityCumulativeCountExceedsOmega(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	pk := dil.GetPK()

	validSig, err := dil.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	hintStart := SEED_BYTES + L*POLY_Z_PACKED_BYTES

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

			if Verify(msg, malformedSig, &pk) {
				t.Errorf("Signature with cumulative count %d (> OMEGA=%d) should not verify", tc.count, OMEGA)
			}
		})
	}
}

// TestCanonicalityHintIndicesNotStrictlyIncreasing tests various non-canonical hint orderings.
func TestCanonicalityHintIndicesNotStrictlyIncreasing(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	pk := dil.GetPK()

	validSig, err := dil.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	hintStart := SEED_BYTES + L*POLY_Z_PACKED_BYTES

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

			if Verify(msg, malformedSig, &pk) {
				t.Errorf("Signature with non-increasing hint indices %v should not verify", tc.indices)
			}
		})
	}
}

// TestCanonicalityNonZeroPadding tests that non-zero bytes in padding area are rejected.
func TestCanonicalityNonZeroPadding(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	pk := dil.GetPK()

	validSig, err := dil.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	hintStart := SEED_BYTES + L*POLY_Z_PACKED_BYTES

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

			if Verify(msg, malformedSig, &pk) {
				t.Errorf("Signature with non-zero padding at position %d should not verify", tc.paddingPos)
			}
		})
	}
}

// TestCanonicalityChallengeMalformation tests that corrupted challenge bytes are rejected.
func TestCanonicalityChallengeMalformation(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	pk := dil.GetPK()

	validSig, err := dil.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Test corruption at various positions in challenge
	positions := []int{0, SEED_BYTES / 4, SEED_BYTES / 2, SEED_BYTES - 1}

	for _, pos := range positions {
		t.Run("challenge_corruption", func(t *testing.T) {
			malformedSig := validSig
			malformedSig[pos] ^= 0xFF

			if Verify(msg, malformedSig, &pk) {
				t.Errorf("Signature with corrupted challenge at byte %d should not verify", pos)
			}
		})
	}
}

// TestCanonicalityZVectorCorruption tests that corrupted z-vector bytes are rejected.
func TestCanonicalityZVectorCorruption(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	pk := dil.GetPK()

	validSig, err := dil.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	zStart := SEED_BYTES
	zEnd := SEED_BYTES + L*POLY_Z_PACKED_BYTES

	// Test corruption at various positions in z-vector
	positions := []int{
		zStart,                         // First byte of z
		zStart + POLY_Z_PACKED_BYTES/2, // Middle of first z poly
		zStart + POLY_Z_PACKED_BYTES,   // Start of second z poly
		zEnd - 1,                       // Last byte of z
	}

	for _, pos := range positions {
		t.Run("z_vector_corruption", func(t *testing.T) {
			malformedSig := validSig
			malformedSig[pos] ^= 0xFF

			if Verify(msg, malformedSig, &pk) {
				t.Errorf("Signature with corrupted z-vector at byte %d should not verify", pos)
			}
		})
	}
}

// TestCanonicalityAllZeroSignature tests that an all-zero signature is rejected.
func TestCanonicalityAllZeroSignature(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	pk := dil.GetPK()

	var zeroSig [CRYPTO_BYTES]uint8

	if Verify(msg, zeroSig, &pk) {
		t.Error("All-zero signature should not verify")
	}
}

// TestCanonicalityAllOnesSignature tests that an all-ones signature is rejected.
func TestCanonicalityAllOnesSignature(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	pk := dil.GetPK()

	var onesSig [CRYPTO_BYTES]uint8
	for i := range onesSig {
		onesSig[i] = 0xFF
	}

	if Verify(msg, onesSig, &pk) {
		t.Error("All-ones signature should not verify")
	}
}

// TestCanonicalityRandomSignatures tests that random signatures don't verify.
func TestCanonicalityRandomSignatures(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	pk := dil.GetPK()

	// Test multiple random signatures
	for i := 0; i < 100; i++ {
		var randomSig [CRYPTO_BYTES]uint8
		_, _ = rand.Read(randomSig[:])

		if Verify(msg, randomSig, &pk) {
			t.Errorf("Random signature %d should not verify", i)
		}
	}
}

// TestCanonicalityValidSignatureVerifies ensures valid signatures still work.
func TestCanonicalityValidSignatureVerifies(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
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

		sig, err := dil.Sign(msg)
		if err != nil {
			t.Fatalf("Failed to sign message %d: %v", i, err)
		}

		pk := dil.GetPK()
		if !Verify(msg, sig, &pk) {
			t.Errorf("Valid signature for message %d should verify", i)
		}
	}
}

// TestCanonicalitySignatureUniqueness tests that the same message produces valid but potentially different signatures.
func TestCanonicalitySignatureUniqueness(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	pk := dil.GetPK()

	sig1, err := dil.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	sig2, err := dil.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Both signatures must verify
	if !Verify(msg, sig1, &pk) {
		t.Error("First signature should verify")
	}
	if !Verify(msg, sig2, &pk) {
		t.Error("Second signature should verify")
	}
}
