package xmss

import (
	"crypto/rand"
	"testing"
)

// Edge case tests for XMSS (TST-004)
// Tests cover: zero-length messages, maximum-length messages,
// invalid signatures, and boundary conditions.

// getTestSignatureSize calculates the expected signature size for a given height
// Formula: signatureBaseSize + height * 32
// where signatureBaseSize = 4 + 32 + keySize
// and keySize = WOTSParamLen * WOTSParamN = 67 * 32 = 2144
func getTestSignatureSize(height Height) uint32 {
	const keySize = 67 * 32      // WOTS key size
	const baseSize = 4 + 32 + keySize // 4 (index) + 32 (R) + keySize
	return baseSize + uint32(height)*32
}

// TestEdgeCaseZeroLengthMessage tests signing and verifying empty messages
func TestEdgeCaseZeroLengthMessage(t *testing.T) {
	seed := make([]byte, 48)
	xmss := InitializeTree(4, SHAKE_128, seed)

	emptyMsg := []byte{}

	// Sign empty message
	sig, err := xmss.Sign(emptyMsg)
	if err != nil {
		t.Fatalf("Failed to sign empty message: %v", err)
	}

	// Verify empty message
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
	if !Verify(xmss.GetHashFunction(), emptyMsg, sig, pk) {
		t.Error("Failed to verify signature on empty message")
	}
}

// TestEdgeCaseNilMessage tests handling of nil messages
func TestEdgeCaseNilMessage(t *testing.T) {
	seed := make([]byte, 48)
	xmss := InitializeTree(4, SHAKE_128, seed)

	var nilMsg []byte = nil

	// Sign nil message (should behave like empty)
	sig, err := xmss.Sign(nilMsg)
	if err != nil {
		t.Fatalf("Failed to sign nil message: %v", err)
	}

	// Verify nil message
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
	if !Verify(xmss.GetHashFunction(), nilMsg, sig, pk) {
		t.Error("Failed to verify signature on nil message")
	}
}

// TestEdgeCaseLargeMessage tests signing large messages
func TestEdgeCaseLargeMessage(t *testing.T) {
	seed := make([]byte, 48)
	xmss := InitializeTree(4, SHAKE_128, seed)

	// Test various message sizes
	sizes := []int{
		1024,      // 1 KB
		64 * 1024, // 64 KB
	}

	for _, size := range sizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			largeMsg := make([]byte, size)
			if _, err := rand.Read(largeMsg); err != nil {
				t.Fatalf("Failed to generate random message: %v", err)
			}

			sig, err := xmss.Sign(largeMsg)
			if err != nil {
				t.Fatalf("Failed to sign %d byte message: %v", size, err)
			}

			pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
			if !Verify(xmss.GetHashFunction(), largeMsg, sig, pk) {
				t.Errorf("Failed to verify signature on %d byte message", size)
			}
		})
	}
}

// TestEdgeCaseInvalidSignature tests various invalid signature scenarios
func TestEdgeCaseInvalidSignature(t *testing.T) {
	seed := make([]byte, 48)
	xmss := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message")
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	t.Run("all_zeros_signature", func(t *testing.T) {
		zeroSig := make([]byte, getTestSignatureSize(4))
		if Verify(xmss.GetHashFunction(), msg, zeroSig, pk) {
			t.Error("All-zeros signature should not verify")
		}
	})

	t.Run("all_ones_signature", func(t *testing.T) {
		onesSig := make([]byte, getTestSignatureSize(4))
		for i := range onesSig {
			onesSig[i] = 0xFF
		}
		if Verify(xmss.GetHashFunction(), msg, onesSig, pk) {
			t.Error("All-ones signature should not verify")
		}
	})

	t.Run("random_signature", func(t *testing.T) {
		randomSig := make([]byte, getTestSignatureSize(4))
		rand.Read(randomSig)
		if Verify(xmss.GetHashFunction(), msg, randomSig, pk) {
			t.Error("Random signature should not verify")
		}
	})

	t.Run("corrupted_valid_signature", func(t *testing.T) {
		sig, err := xmss.Sign(msg)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		// Corrupt key positions
		positions := []int{0, len(sig) / 4, len(sig) / 2, len(sig) - 1}
		for _, i := range positions {
			corruptedSig := make([]byte, len(sig))
			copy(corruptedSig, sig)
			corruptedSig[i] ^= 0xFF
			if Verify(xmss.GetHashFunction(), msg, corruptedSig, pk) {
				t.Errorf("Corrupted signature at byte %d should not verify", i)
			}
		}
	})
}

// TestEdgeCaseInvalidPublicKey tests verification with invalid public keys
func TestEdgeCaseInvalidPublicKey(t *testing.T) {
	seed := make([]byte, 48)
	xmss := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message")
	sig, err := xmss.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	t.Run("all_zeros_pk", func(t *testing.T) {
		zeroPK := make([]byte, 64)
		if Verify(xmss.GetHashFunction(), msg, sig, zeroPK) {
			t.Error("All-zeros public key should not verify")
		}
	})

	t.Run("random_pk", func(t *testing.T) {
		randomPK := make([]byte, 64)
		rand.Read(randomPK)
		if Verify(xmss.GetHashFunction(), msg, sig, randomPK) {
			t.Error("Random public key should not verify")
		}
	})

	t.Run("short_pk", func(t *testing.T) {
		shortPK := make([]byte, 32)
		// Should not panic, just return false
		result := Verify(xmss.GetHashFunction(), msg, sig, shortPK)
		if result {
			t.Error("Short public key should not verify")
		}
	})
}

// TestEdgeCaseSignatureSize tests signature size boundary conditions
func TestEdgeCaseSignatureSize(t *testing.T) {
	seed := make([]byte, 48)
	xmss := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message")
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	t.Run("empty_signature", func(t *testing.T) {
		if Verify(xmss.GetHashFunction(), msg, []byte{}, pk) {
			t.Error("Empty signature should not verify")
		}
	})

	t.Run("nil_signature", func(t *testing.T) {
		if Verify(xmss.GetHashFunction(), msg, nil, pk) {
			t.Error("Nil signature should not verify")
		}
	})

	t.Run("too_short_signature", func(t *testing.T) {
		shortSig := make([]byte, 100)
		if Verify(xmss.GetHashFunction(), msg, shortSig, pk) {
			t.Error("Too short signature should not verify")
		}
	})

	t.Run("misaligned_signature_size", func(t *testing.T) {
		// Signature size should be 4 + n*32 for some n
		misaligned := make([]byte, 1000) // Not aligned to 32-byte boundary
		if Verify(xmss.GetHashFunction(), msg, misaligned, pk) {
			t.Error("Misaligned signature should not verify")
		}
	})

	t.Run("too_large_signature", func(t *testing.T) {
		// Larger than max height signature
		tooLarge := make([]byte, getTestSignatureSize(20)+1000)
		if Verify(xmss.GetHashFunction(), msg, tooLarge, pk) {
			t.Error("Too large signature should not verify")
		}
	})
}

// TestEdgeCaseHashFunctions tests edge cases for different hash functions
func TestEdgeCaseHashFunctions(t *testing.T) {
	seed := make([]byte, 48)
	msg := []byte("test message")

	hashFuncs := []HashFunction{SHA2_256, SHAKE_128, SHAKE_256}

	for _, hf := range hashFuncs {
		t.Run(hf.String(), func(t *testing.T) {
			xmss := InitializeTree(4, hf, seed)

			sig, err := xmss.Sign(msg)
			if err != nil {
				t.Fatalf("Failed to sign with %s: %v", hf.String(), err)
			}

			pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
			if !Verify(hf, msg, sig, pk) {
				t.Errorf("Failed to verify with %s", hf.String())
			}

			// Cross-hash function verification should fail
			for _, otherHf := range hashFuncs {
				if otherHf != hf {
					if Verify(otherHf, msg, sig, pk) {
						t.Errorf("Verification should fail with wrong hash function %s (signed with %s)", otherHf.String(), hf.String())
					}
				}
			}
		})
	}
}

// TestEdgeCaseHeights tests edge cases for different tree heights
func TestEdgeCaseHeights(t *testing.T) {
	seed := make([]byte, 48)
	msg := []byte("test message")

	heights := []Height{4, 6, 8, 10}

	for _, h := range heights {
		t.Run(string(rune(h)), func(t *testing.T) {
			xmss := InitializeTree(h, SHAKE_128, seed)

			sig, err := xmss.Sign(msg)
			if err != nil {
				t.Fatalf("Failed to sign with height %d: %v", h, err)
			}

			pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
			if !Verify(xmss.GetHashFunction(), msg, sig, pk) {
				t.Errorf("Failed to verify with height %d", h)
			}

			// Verify signature size matches expected
			expectedSize := getTestSignatureSize(h)
			if uint32(len(sig)) != expectedSize {
				t.Errorf("Signature size mismatch: expected %d, got %d", expectedSize, len(sig))
			}
		})
	}
}

// TestEdgeCaseIndexBoundary tests index boundary conditions
func TestEdgeCaseIndexBoundary(t *testing.T) {
	seed := make([]byte, 48)

	t.Run("index_zero", func(t *testing.T) {
		xmss := InitializeTree(4, SHAKE_128, seed)

		if xmss.GetIndex() != 0 {
			t.Errorf("Initial index should be 0, got %d", xmss.GetIndex())
		}

		msg := []byte("test")
		_, err := xmss.Sign(msg)
		if err != nil {
			t.Fatalf("Failed to sign at index 0: %v", err)
		}

		if xmss.GetIndex() != 1 {
			t.Errorf("Index should be 1 after signing, got %d", xmss.GetIndex())
		}
	})

	t.Run("set_index_forward", func(t *testing.T) {
		xmss := InitializeTree(4, SHAKE_128, seed)

		// Set index forward (allowed)
		err := xmss.SetIndex(5)
		if err != nil {
			t.Fatalf("Failed to set index forward: %v", err)
		}

		if xmss.GetIndex() != 5 {
			t.Errorf("Index should be 5, got %d", xmss.GetIndex())
		}
	})

	t.Run("set_index_boundary", func(t *testing.T) {
		xmss := InitializeTree(4, SHAKE_128, seed)

		// Height 4 = 2^4 = 16 signatures max (indices 0-15)
		maxIndex := uint32(1<<4 - 1) // 15

		err := xmss.SetIndex(maxIndex)
		if err != nil {
			t.Fatalf("Failed to set index to max: %v", err)
		}

		msg := []byte("test")
		_, err = xmss.Sign(msg)
		if err != nil {
			t.Fatalf("Failed to sign at max index: %v", err)
		}
	})
}

// TestEdgeCaseSeedVariations tests various seed scenarios
func TestEdgeCaseSeedVariations(t *testing.T) {
	msg := []byte("test message")

	t.Run("zero_seed", func(t *testing.T) {
		zeroSeed := make([]byte, 48)
		xmss := InitializeTree(4, SHAKE_128, zeroSeed)

		sig, err := xmss.Sign(msg)
		if err != nil {
			t.Fatalf("Failed to sign with zero seed: %v", err)
		}

		pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
		if !Verify(xmss.GetHashFunction(), msg, sig, pk) {
			t.Error("Failed to verify with zero seed")
		}
	})

	t.Run("max_seed", func(t *testing.T) {
		maxSeed := make([]byte, 48)
		for i := range maxSeed {
			maxSeed[i] = 0xFF
		}
		xmss := InitializeTree(4, SHAKE_128, maxSeed)

		sig, err := xmss.Sign(msg)
		if err != nil {
			t.Fatalf("Failed to sign with max seed: %v", err)
		}

		pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
		if !Verify(xmss.GetHashFunction(), msg, sig, pk) {
			t.Error("Failed to verify with max seed")
		}
	})

	t.Run("short_seed", func(t *testing.T) {
		shortSeed := make([]byte, 16)
		xmss := InitializeTree(4, SHAKE_128, shortSeed)

		sig, err := xmss.Sign(msg)
		if err != nil {
			t.Fatalf("Failed to sign with short seed: %v", err)
		}

		pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
		if !Verify(xmss.GetHashFunction(), msg, sig, pk) {
			t.Error("Failed to verify with short seed")
		}
	})
}

// TestEdgeCaseVerifyCustomWOTSParam tests VerifyWithCustomWOTSParamW edge cases
func TestEdgeCaseVerifyCustomWOTSParam(t *testing.T) {
	seed := make([]byte, 48)
	xmss := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message")
	sig, err := xmss.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)

	// Default WOTS param should work
	if !VerifyWithCustomWOTSParamW(xmss.GetHashFunction(), msg, sig, pk, WOTSParamW) {
		t.Error("Verification with default WOTS param should succeed")
	}

	// Wrong WOTS param should fail
	if VerifyWithCustomWOTSParamW(xmss.GetHashFunction(), msg, sig, pk, WOTSParamW+1) {
		t.Error("Verification with wrong WOTS param should fail")
	}
}
