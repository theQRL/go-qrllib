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
		// Should work but with zero-length seed
		if err != nil {
			t.Logf("Empty hex seed error (expected): %v", err)
		}
	})

	t.Run("short_hex", func(t *testing.T) {
		_, err := NewDilithiumFromHexSeed("0102030405")
		if err != nil {
			t.Fatalf("Short hex seed should work: %v", err)
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
