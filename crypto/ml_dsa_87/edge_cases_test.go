package ml_dsa_87

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Edge case tests for ML-DSA-87 (TST-004)
// Tests cover: zero-length messages, maximum-length messages,
// invalid signatures, and boundary conditions.

// TestEdgeCaseZeroLengthMessage tests signing and verifying empty messages
func TestEdgeCaseZeroLengthMessage(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	emptyMsg := []byte{}
	ctx := []byte{}

	// Sign empty message
	sig, err := mldsa.Sign(ctx, emptyMsg)
	if err != nil {
		t.Fatalf("Failed to sign empty message: %v", err)
	}

	// Verify empty message
	pk := mldsa.GetPK()
	if !Verify(ctx, emptyMsg, sig, &pk) {
		t.Error("Failed to verify signature on empty message")
	}

	// Seal/Open empty message
	sealed, err := mldsa.Seal(ctx, emptyMsg)
	if err != nil {
		t.Fatalf("Failed to seal empty message: %v", err)
	}

	opened := Open(ctx, sealed, &pk)
	if opened == nil {
		t.Error("Failed to open sealed empty message")
	}
	if len(opened) != 0 {
		t.Errorf("Opened message should be empty, got %d bytes", len(opened))
	}
}

// TestEdgeCaseNilMessage tests handling of nil messages
func TestEdgeCaseNilMessage(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	var nilMsg []byte = nil
	ctx := []byte{}

	// Sign nil message (should behave like empty)
	sig, err := mldsa.Sign(ctx, nilMsg)
	if err != nil {
		t.Fatalf("Failed to sign nil message: %v", err)
	}

	// Verify nil message
	pk := mldsa.GetPK()
	if !Verify(ctx, nilMsg, sig, &pk) {
		t.Error("Failed to verify signature on nil message")
	}
}

// TestEdgeCaseLargeMessage tests signing large messages
func TestEdgeCaseLargeMessage(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
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

			ctx := []byte{}

			sig, err := mldsa.Sign(ctx, largeMsg)
			if err != nil {
				t.Fatalf("Failed to sign %d byte message: %v", size, err)
			}

			pk := mldsa.GetPK()
			if !Verify(ctx, largeMsg, sig, &pk) {
				t.Errorf("Failed to verify signature on %d byte message", size)
			}
		})
	}
}

// TestEdgeCaseInvalidSignature tests various invalid signature scenarios
func TestEdgeCaseInvalidSignature(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	pk := mldsa.GetPK()

	t.Run("all_zeros_signature", func(t *testing.T) {
		var zeroSig [CRYPTO_BYTES]uint8
		if Verify(ctx, msg, zeroSig, &pk) {
			t.Error("All-zeros signature should not verify")
		}
	})

	t.Run("all_ones_signature", func(t *testing.T) {
		var onesSig [CRYPTO_BYTES]uint8
		for i := range onesSig {
			onesSig[i] = 0xFF
		}
		if Verify(ctx, msg, onesSig, &pk) {
			t.Error("All-ones signature should not verify")
		}
	})

	t.Run("random_signature", func(t *testing.T) {
		var randomSig [CRYPTO_BYTES]uint8
		_, _ = rand.Read(randomSig[:])
		if Verify(ctx, msg, randomSig, &pk) {
			t.Error("Random signature should not verify")
		}
	})

	t.Run("corrupted_valid_signature", func(t *testing.T) {
		sig, err := mldsa.Sign(ctx, msg)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		// Corrupt each byte position
		for i := 0; i < len(sig); i += len(sig) / 10 { // Test every 10%
			corruptedSig := sig
			corruptedSig[i] ^= 0xFF
			if Verify(ctx, msg, corruptedSig, &pk) {
				t.Errorf("Corrupted signature at byte %d should not verify", i)
			}
		}
	})
}

// TestEdgeCaseInvalidPublicKey tests verification with invalid public keys
func TestEdgeCaseInvalidPublicKey(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	ctx := []byte{}
	sig, err := mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	t.Run("all_zeros_pk", func(t *testing.T) {
		var zeroPK [CRYPTO_PUBLIC_KEY_BYTES]uint8
		if Verify(ctx, msg, sig, &zeroPK) {
			t.Error("All-zeros public key should not verify")
		}
	})

	t.Run("random_pk", func(t *testing.T) {
		var randomPK [CRYPTO_PUBLIC_KEY_BYTES]uint8
		_, _ = rand.Read(randomPK[:])
		if Verify(ctx, msg, sig, &randomPK) {
			t.Error("Random public key should not verify")
		}
	})
}

// TestEdgeCaseContextVariations tests various context scenarios
func TestEdgeCaseContextVariations(t *testing.T) {
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	msg := []byte("test message")
	pk := mldsa.GetPK()

	contexts := [][]byte{
		nil,
		{},
		{0x00},
		[]byte("short"),
		[]byte("a longer context string for testing"),
		bytes.Repeat([]byte{0x42}, 255), // Max context length per FIPS 204
	}

	for i, ctx := range contexts {
		t.Run(string(rune(i)), func(t *testing.T) {
			sig, err := mldsa.Sign(ctx, msg)
			if err != nil {
				t.Fatalf("Failed to sign with context %d: %v", i, err)
			}

			if !Verify(ctx, msg, sig, &pk) {
				t.Errorf("Failed to verify with context %d", i)
			}

			// Verify with wrong context should fail
			wrongCtx := append(ctx, 0xFF)
			if Verify(wrongCtx, msg, sig, &pk) {
				t.Errorf("Verification should fail with wrong context %d", i)
			}
		})
	}
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
	mldsa, err := New()
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}
	pk := mldsa.GetPK()
	ctx := []byte{}

	t.Run("nil_input", func(t *testing.T) {
		if Open(ctx, nil, &pk) != nil {
			t.Error("Open(nil) should return nil")
		}
	})

	t.Run("empty_input", func(t *testing.T) {
		if Open(ctx, []byte{}, &pk) != nil {
			t.Error("Open([]) should return nil")
		}
	})

	t.Run("too_short_input", func(t *testing.T) {
		short := make([]byte, CRYPTO_BYTES-1)
		if Open(ctx, short, &pk) != nil {
			t.Error("Open(short) should return nil")
		}
	})

	t.Run("invalid_signature_in_sealed", func(t *testing.T) {
		// Create a sealed message with invalid signature
		invalidSealed := make([]byte, CRYPTO_BYTES+10)
		_, _ = rand.Read(invalidSealed)
		if Open(ctx, invalidSealed, &pk) != nil {
			t.Error("Open with invalid signature should return nil")
		}
	})
}

// TestEdgeCaseSeedBoundaries tests seed handling edge cases
func TestEdgeCaseSeedBoundaries(t *testing.T) {
	t.Run("zero_seed", func(t *testing.T) {
		var zeroSeed [SEED_BYTES]uint8
		mldsa, err := NewMLDSA87FromSeed(zeroSeed)
		if err != nil {
			t.Fatalf("Failed to create from zero seed: %v", err)
		}

		msg := []byte("test")
		ctx := []byte{}
		sig, err := mldsa.Sign(ctx, msg)
		if err != nil {
			t.Fatalf("Failed to sign with zero seed: %v", err)
		}

		pk := mldsa.GetPK()
		if !Verify(ctx, msg, sig, &pk) {
			t.Error("Failed to verify with zero seed keypair")
		}
	})

	t.Run("max_seed", func(t *testing.T) {
		var maxSeed [SEED_BYTES]uint8
		for i := range maxSeed {
			maxSeed[i] = 0xFF
		}
		mldsa, err := NewMLDSA87FromSeed(maxSeed)
		if err != nil {
			t.Fatalf("Failed to create from max seed: %v", err)
		}

		msg := []byte("test")
		ctx := []byte{}
		sig, err := mldsa.Sign(ctx, msg)
		if err != nil {
			t.Fatalf("Failed to sign with max seed: %v", err)
		}

		pk := mldsa.GetPK()
		if !Verify(ctx, msg, sig, &pk) {
			t.Error("Failed to verify with max seed keypair")
		}
	})
}

// TestEdgeCaseHexSeedParsing tests hex seed parsing edge cases
func TestEdgeCaseHexSeedParsing(t *testing.T) {
	t.Run("empty_hex", func(t *testing.T) {
		_, err := NewMLDSA87FromHexSeed("")
		if err == nil {
			t.Error("Empty hex seed should return error")
		}
	})

	t.Run("short_hex", func(t *testing.T) {
		_, err := NewMLDSA87FromHexSeed("0102030405")
		if err == nil {
			t.Error("Short hex seed should return error")
		}
	})

	t.Run("invalid_hex_chars", func(t *testing.T) {
		_, err := NewMLDSA87FromHexSeed("xyz123")
		if err == nil {
			t.Error("Invalid hex characters should return error")
		}
	})

	t.Run("odd_length_hex", func(t *testing.T) {
		_, err := NewMLDSA87FromHexSeed("123") // Odd length
		if err == nil {
			t.Error("Odd length hex should return error")
		}
	})

	t.Run("valid_hex_with_prefix", func(t *testing.T) {
		validSeed := "0102030405060708091011121314151617181920212223242526272829303132"
		_, err := NewMLDSA87FromHexSeed("0x" + validSeed)
		if err != nil {
			t.Fatalf("Valid hex seed with 0x prefix should work: %v", err)
		}
	})
}
