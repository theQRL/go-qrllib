package dilithium

import (
	"crypto/rand"
	"testing"
)

// Edge case tests for Dilithium (TST-004)
// Tests cover: zero-length messages, maximum-length messages,
// invalid signatures, and boundary conditions.

// TestEdgeCaseZeroLengthMessage tests signing and verifying empty messages
func TestEdgeCaseZeroLengthMessage(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	emptyMsg := []byte{}

	// Sign empty message
	sig, err := dil.Sign(emptyMsg)
	if err != nil {
		t.Fatalf("Failed to sign empty message: %v", err)
	}

	// Verify empty message
	pk := dil.GetPK()
	if !Verify(emptyMsg, sig, &pk) {
		t.Error("Failed to verify signature on empty message")
	}

	// Seal/Open empty message
	sealed, err := dil.Seal(emptyMsg)
	if err != nil {
		t.Fatalf("Failed to seal empty message: %v", err)
	}

	opened := Open(sealed, &pk)
	if opened == nil {
		t.Error("Failed to open sealed empty message")
	}
	if len(opened) != 0 {
		t.Errorf("Opened message should be empty, got %d bytes", len(opened))
	}
}

// TestEdgeCaseNilMessage tests handling of nil messages
func TestEdgeCaseNilMessage(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	var nilMsg []byte = nil

	// Sign nil message (should behave like empty)
	sig, err := dil.Sign(nilMsg)
	if err != nil {
		t.Fatalf("Failed to sign nil message: %v", err)
	}

	// Verify nil message
	pk := dil.GetPK()
	if !Verify(nilMsg, sig, &pk) {
		t.Error("Failed to verify signature on nil message")
	}
}

// TestEdgeCaseLargeMessage tests signing large messages
func TestEdgeCaseLargeMessage(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	// Test various large message sizes
	sizes := []int{
		1024,        // 1 KB
		64 * 1024,   // 64 KB
		1024 * 1024, // 1 MB
	}

	for _, size := range sizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			largeMsg := make([]byte, size)
			if _, err := rand.Read(largeMsg); err != nil {
				t.Fatalf("Failed to generate random message: %v", err)
			}

			sig, err := dil.Sign(largeMsg)
			if err != nil {
				t.Fatalf("Failed to sign %d byte message: %v", size, err)
			}

			pk := dil.GetPK()
			if !Verify(largeMsg, sig, &pk) {
				t.Errorf("Failed to verify signature on %d byte message", size)
			}
		})
	}
}

// TestEdgeCaseInvalidSignature tests various invalid signature scenarios
func TestEdgeCaseInvalidSignature(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	pk := dil.GetPK()

	t.Run("all_zeros_signature", func(t *testing.T) {
		var zeroSig [CRYPTO_BYTES]uint8
		if Verify(msg, zeroSig, &pk) {
			t.Error("All-zeros signature should not verify")
		}
	})

	t.Run("all_ones_signature", func(t *testing.T) {
		var onesSig [CRYPTO_BYTES]uint8
		for i := range onesSig {
			onesSig[i] = 0xFF
		}
		if Verify(msg, onesSig, &pk) {
			t.Error("All-ones signature should not verify")
		}
	})

	t.Run("random_signature", func(t *testing.T) {
		var randomSig [CRYPTO_BYTES]uint8
		_, _ = rand.Read(randomSig[:])
		if Verify(msg, randomSig, &pk) {
			t.Error("Random signature should not verify")
		}
	})

	t.Run("corrupted_valid_signature", func(t *testing.T) {
		sig, err := dil.Sign(msg)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		// Corrupt each byte position
		for i := 0; i < len(sig); i += len(sig) / 10 { // Test every 10%
			corruptedSig := sig
			corruptedSig[i] ^= 0xFF
			if Verify(msg, corruptedSig, &pk) {
				t.Errorf("Corrupted signature at byte %d should not verify", i)
			}
		}
	})
}

// TestEdgeCaseMalformedSignatureHints tests signature hint encoding validation
func TestEdgeCaseMalformedSignatureHints(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	pk := dil.GetPK()

	// Get a valid signature to use as base
	validSig, err := dil.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Signature layout: c (32) || z (L*640=4480) || hints (OMEGA+K=83)
	// Hints layout: hint_indices[OMEGA] || cumulative_counts[K]
	hintStart := SEED_BYTES + L*POLY_Z_PACKED_BYTES // 32 + 4480 = 4512

	t.Run("non_increasing_hint_indices", func(t *testing.T) {
		// Create a signature with non-increasing hint indices
		malformedSig := validSig
		// Set hint indices that are not strictly increasing
		// First, set cumulative count to indicate we have 2 hints in first polynomial
		malformedSig[hintStart+OMEGA] = 2 // cumulative count for poly 0
		// Set hint indices: second should be > first, but we make it equal
		malformedSig[hintStart+0] = 10
		malformedSig[hintStart+1] = 10 // Not strictly increasing!

		if Verify(msg, malformedSig, &pk) {
			t.Error("Signature with non-increasing hint indices should not verify")
		}
	})

	t.Run("decreasing_hint_indices", func(t *testing.T) {
		malformedSig := validSig
		malformedSig[hintStart+OMEGA] = 2
		malformedSig[hintStart+0] = 20
		malformedSig[hintStart+1] = 10 // Decreasing!

		if Verify(msg, malformedSig, &pk) {
			t.Error("Signature with decreasing hint indices should not verify")
		}
	})

	t.Run("non_zero_padding_in_hints", func(t *testing.T) {
		malformedSig := validSig
		// Set all cumulative counts to 0 (no hints)
		for i := 0; i < K; i++ {
			malformedSig[hintStart+OMEGA+i] = 0
		}
		// But put non-zero data in the hint indices area
		malformedSig[hintStart+0] = 0xFF // Should be zero if no hints

		if Verify(msg, malformedSig, &pk) {
			t.Error("Signature with non-zero hint padding should not verify")
		}
	})
}

// TestEdgeCaseInvalidPublicKey tests verification with invalid public keys
func TestEdgeCaseInvalidPublicKey(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	sig, err := dil.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	t.Run("all_zeros_pk", func(t *testing.T) {
		var zeroPK [CRYPTO_PUBLIC_KEY_BYTES]uint8
		if Verify(msg, sig, &zeroPK) {
			t.Error("All-zeros public key should not verify")
		}
	})

	t.Run("random_pk", func(t *testing.T) {
		var randomPK [CRYPTO_PUBLIC_KEY_BYTES]uint8
		_, _ = rand.Read(randomPK[:])
		if Verify(msg, sig, &randomPK) {
			t.Error("Random public key should not verify")
		}
	})
}

// TestEdgeCaseExtractFunctions tests Extract functions with edge cases
func TestEdgeCaseExtractFunctions(t *testing.T) {
	t.Run("nil_input", func(t *testing.T) {
		if ExtractMessage(nil) != nil {
			t.Error("ExtractMessage(nil) should return nil")
		}
		if ExtractSignature(nil) != nil {
			t.Error("ExtractSignature(nil) should return nil")
		}
	})

	t.Run("empty_input", func(t *testing.T) {
		if ExtractMessage([]byte{}) != nil {
			t.Error("ExtractMessage([]) should return nil")
		}
		if ExtractSignature([]byte{}) != nil {
			t.Error("ExtractSignature([]) should return nil")
		}
	})

	t.Run("too_short_input", func(t *testing.T) {
		short := make([]byte, CRYPTO_BYTES-1)
		if ExtractMessage(short) != nil {
			t.Error("ExtractMessage(short) should return nil")
		}
		if ExtractSignature(short) != nil {
			t.Error("ExtractSignature(short) should return nil")
		}
	})

	t.Run("exact_signature_size", func(t *testing.T) {
		exact := make([]byte, CRYPTO_BYTES)
		msg := ExtractMessage(exact)
		if msg == nil || len(msg) != 0 {
			t.Error("ExtractMessage should return empty slice for exact size")
		}
		sig := ExtractSignature(exact)
		if sig == nil || len(sig) != CRYPTO_BYTES {
			t.Error("ExtractSignature should return full signature for exact size")
		}
	})
}

// TestEdgeCaseOpenFunction tests Open function with edge cases
func TestEdgeCaseOpenFunction(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}
	pk := dil.GetPK()

	t.Run("nil_input", func(t *testing.T) {
		if Open(nil, &pk) != nil {
			t.Error("Open(nil) should return nil")
		}
	})

	t.Run("empty_input", func(t *testing.T) {
		if Open([]byte{}, &pk) != nil {
			t.Error("Open([]) should return nil")
		}
	})

	t.Run("too_short_input", func(t *testing.T) {
		short := make([]byte, CRYPTO_BYTES-1)
		if Open(short, &pk) != nil {
			t.Error("Open(short) should return nil")
		}
	})

	t.Run("invalid_signature_in_sealed", func(t *testing.T) {
		// Create a sealed message with invalid signature
		invalidSealed := make([]byte, CRYPTO_BYTES+10)
		_, _ = rand.Read(invalidSealed)
		if Open(invalidSealed, &pk) != nil {
			t.Error("Open with invalid signature should return nil")
		}
	})
}

// TestEdgeCaseSeedBoundaries tests seed handling edge cases
func TestEdgeCaseSeedBoundaries(t *testing.T) {
	t.Run("zero_seed", func(t *testing.T) {
		var zeroSeed [SEED_BYTES]uint8
		dil, err := NewDilithiumFromSeed(zeroSeed)
		if err != nil {
			t.Fatalf("Failed to create from zero seed: %v", err)
		}

		msg := []byte("test")
		sig, err := dil.Sign(msg)
		if err != nil {
			t.Fatalf("Failed to sign with zero seed: %v", err)
		}

		pk := dil.GetPK()
		if !Verify(msg, sig, &pk) {
			t.Error("Failed to verify with zero seed keypair")
		}
	})

	t.Run("max_seed", func(t *testing.T) {
		var maxSeed [SEED_BYTES]uint8
		for i := range maxSeed {
			maxSeed[i] = 0xFF
		}
		dil, err := NewDilithiumFromSeed(maxSeed)
		if err != nil {
			t.Fatalf("Failed to create from max seed: %v", err)
		}

		msg := []byte("test")
		sig, err := dil.Sign(msg)
		if err != nil {
			t.Fatalf("Failed to sign with max seed: %v", err)
		}

		pk := dil.GetPK()
		if !Verify(msg, sig, &pk) {
			t.Error("Failed to verify with max seed keypair")
		}
	})
}

// TestEdgeCaseHexSeedParsing tests hex seed parsing edge cases
func TestEdgeCaseHexSeedParsing(t *testing.T) {
	t.Run("empty_hex", func(t *testing.T) {
		_, err := NewDilithiumFromHexSeed("")
		if err == nil {
			t.Error("Empty hex seed should return error")
		}
	})

	t.Run("short_hex", func(t *testing.T) {
		_, err := NewDilithiumFromHexSeed("0102030405")
		if err == nil {
			t.Error("Short hex seed should return error (security: prevents weak key generation)")
		}
	})

	t.Run("invalid_hex_chars", func(t *testing.T) {
		_, err := NewDilithiumFromHexSeed("xyz123")
		if err == nil {
			t.Error("Invalid hex characters should return error")
		}
	})

	t.Run("odd_length_hex", func(t *testing.T) {
		_, err := NewDilithiumFromHexSeed("123") // Odd length
		if err == nil {
			t.Error("Odd length hex should return error")
		}
	})

	t.Run("valid_hex_with_prefix", func(t *testing.T) {
		validSeed := "0102030405060708091011121314151617181920212223242526272829303132"
		_, err := NewDilithiumFromHexSeed("0x" + validSeed)
		if err != nil {
			t.Fatalf("Valid hex seed with 0x prefix should work: %v", err)
		}
	})
}

// TestSeedLengthValidation (QUA-004) tests comprehensive seed length validation
func TestSeedLengthValidation(t *testing.T) {
	// Valid seed: exactly 32 bytes = 64 hex chars
	validSeed := "0102030405060708091011121314151617181920212223242526272829303132"

	t.Run("valid_32_byte_seed", func(t *testing.T) {
		dil, err := NewDilithiumFromHexSeed(validSeed)
		if err != nil {
			t.Errorf("Valid 32-byte seed should work: %v", err)
		}
		if dil == nil {
			t.Error("Valid seed should return non-nil Dilithium")
		}
	})

	t.Run("1_byte_seed", func(t *testing.T) {
		_, err := NewDilithiumFromHexSeed("01")
		if err == nil {
			t.Error("1-byte seed should be rejected")
		}
	})

	t.Run("31_byte_seed", func(t *testing.T) {
		// 31 bytes = 62 hex chars
		seed31 := "01020304050607080910111213141516171819202122232425262728293031"
		_, err := NewDilithiumFromHexSeed(seed31)
		if err == nil {
			t.Error("31-byte seed should be rejected (off by one)")
		}
	})

	t.Run("33_byte_seed", func(t *testing.T) {
		// 33 bytes = 66 hex chars
		seed33 := "010203040506070809101112131415161718192021222324252627282930313233"
		_, err := NewDilithiumFromHexSeed(seed33)
		if err == nil {
			t.Error("33-byte seed should be rejected (off by one)")
		}
	})

	t.Run("64_byte_seed", func(t *testing.T) {
		// 64 bytes = 128 hex chars (double the required length)
		seed64 := validSeed + validSeed
		_, err := NewDilithiumFromHexSeed(seed64)
		if err == nil {
			t.Error("64-byte seed should be rejected")
		}
	})

	t.Run("error_message_contains_lengths", func(t *testing.T) {
		_, err := NewDilithiumFromHexSeed("0102030405")
		if err == nil {
			t.Fatal("Short seed should return error")
		}
		errMsg := err.Error()
		if errMsg == "" {
			t.Error("Error message should not be empty")
		}
		// Error should mention expected vs actual lengths
		if !contains(errMsg, "32") || !contains(errMsg, "5") {
			t.Errorf("Error message should mention expected (32) and actual (5) lengths: %s", errMsg)
		}
	})
}

// contains checks if s contains substr (helper for test clarity)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestEdgeCaseSignWithSecretKey tests SignWithSecretKey edge cases
func TestEdgeCaseSignWithSecretKey(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	sk := dil.GetSK()
	pk := dil.GetPK()

	t.Run("empty_message", func(t *testing.T) {
		sig, err := SignWithSecretKey([]byte{}, &sk)
		if err != nil {
			t.Fatalf("Failed to sign empty message: %v", err)
		}
		if !Verify([]byte{}, sig, &pk) {
			t.Error("Failed to verify empty message signature")
		}
	})

	t.Run("nil_message", func(t *testing.T) {
		sig, err := SignWithSecretKey(nil, &sk)
		if err != nil {
			t.Fatalf("Failed to sign nil message: %v", err)
		}
		if !Verify(nil, sig, &pk) {
			t.Error("Failed to verify nil message signature")
		}
	})

	t.Run("nil_secret_key", func(t *testing.T) {
		_, err := SignWithSecretKey([]byte("test message"), nil)
		if err == nil {
			t.Error("Expected error when signing with nil secret key")
		}
	})

	t.Run("zero_secret_key", func(t *testing.T) {
		var zeroSK [CRYPTO_SECRET_KEY_BYTES]uint8
		_, err := SignWithSecretKey([]byte("test message"), &zeroSK)
		if err == nil {
			t.Error("Expected error when signing with zero secret key")
		}
	})
}
