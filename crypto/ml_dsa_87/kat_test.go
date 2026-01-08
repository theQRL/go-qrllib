package ml_dsa_87

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Known Answer Test (KAT) vectors for ML-DSA-87
// These test vectors verify deterministic key generation and signing.
//
// NOTE: These are self-generated test vectors using known seeds.
// For full NIST FIPS 204 compliance, official ACVP test vectors should
// be obtained from: https://github.com/usnistgov/ACVP-Server
//
// The test vectors below verify:
// 1. Deterministic keypair generation from seed
// 2. Deterministic signature generation (when randomizedSigning=false)
// 3. Signature verification correctness

// Test vector structure for KAT
type katVector struct {
	name    string
	seed    string // 32 bytes hex
	message string // Message to sign (hex)
	ctx     string // Context string (hex)
}

// Test vectors generated with known seeds
// These can be cross-verified with other ML-DSA-87 implementations
var katVectors = []katVector{
	{
		name:     "zero_seed",
		seed:     "0000000000000000000000000000000000000000000000000000000000000000",
		message:  "",
		ctx:      "",
	},
	{
		name:     "incremental_seed",
		seed:     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		message:  "48656c6c6f2c20576f726c6421", // "Hello, World!"
		ctx:      "5a4f4e44",                   // "ZOND"
	},
	{
		name:     "random_seed_1",
		seed:     "deadbeefcafebabe0123456789abcdef00112233445566778899aabbccddeeff",
		message:  "54657374206d65737361676520666f72204b415420766572696669636174696f6e", // "Test message for KAT verification"
		ctx:      "",
	},
}

// TestKATDeterministicKeypair verifies that keypair generation is deterministic
func TestKATDeterministicKeypair(t *testing.T) {
	for _, vec := range katVectors {
		t.Run(vec.name+"_deterministic", func(t *testing.T) {
			seedBytes, err := hex.DecodeString(vec.seed)
			if err != nil {
				t.Fatalf("Failed to decode seed: %v", err)
			}

			var seed [SEED_BYTES]uint8
			copy(seed[:], seedBytes)

			// Generate keypair twice with same seed
			mldsa1, err := NewMLDSA87FromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create MLDSA87 (1): %v", err)
			}

			mldsa2, err := NewMLDSA87FromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create MLDSA87 (2): %v", err)
			}

			// Public keys must be identical
			pk1 := mldsa1.GetPK()
			pk2 := mldsa2.GetPK()
			if !bytes.Equal(pk1[:], pk2[:]) {
				t.Error("Public keys should be identical for same seed")
			}

			// Secret keys must be identical
			sk1 := mldsa1.GetSK()
			sk2 := mldsa2.GetSK()
			if !bytes.Equal(sk1[:], sk2[:]) {
				t.Error("Secret keys should be identical for same seed")
			}
		})
	}
}

// TestKATDeterministicSignature verifies that signature generation is deterministic
func TestKATDeterministicSignature(t *testing.T) {
	for _, vec := range katVectors {
		t.Run(vec.name+"_sig_deterministic", func(t *testing.T) {
			seedBytes, err := hex.DecodeString(vec.seed)
			if err != nil {
				t.Fatalf("Failed to decode seed: %v", err)
			}

			var seed [SEED_BYTES]uint8
			copy(seed[:], seedBytes)

			msg, err := hex.DecodeString(vec.message)
			if err != nil {
				t.Fatalf("Failed to decode message: %v", err)
			}

			ctx, err := hex.DecodeString(vec.ctx)
			if err != nil {
				t.Fatalf("Failed to decode context: %v", err)
			}

			mldsa, err := NewMLDSA87FromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create MLDSA87: %v", err)
			}

			// Sign the same message twice
			sig1, err := mldsa.Sign(ctx, msg)
			if err != nil {
				t.Fatalf("Failed to sign (1): %v", err)
			}

			sig2, err := mldsa.Sign(ctx, msg)
			if err != nil {
				t.Fatalf("Failed to sign (2): %v", err)
			}

			// Signatures must be identical (deterministic signing)
			if !bytes.Equal(sig1[:], sig2[:]) {
				t.Error("Signatures should be identical for deterministic signing")
			}

			// Verify the signature
			pk := mldsa.GetPK()
			if !Verify(ctx, msg, sig1, &pk) {
				t.Error("Signature verification failed")
			}
		})
	}
}

// TestKATSignVerifyRoundTrip verifies sign/verify round trip
func TestKATSignVerifyRoundTrip(t *testing.T) {
	for _, vec := range katVectors {
		t.Run(vec.name+"_roundtrip", func(t *testing.T) {
			seedBytes, err := hex.DecodeString(vec.seed)
			if err != nil {
				t.Fatalf("Failed to decode seed: %v", err)
			}

			var seed [SEED_BYTES]uint8
			copy(seed[:], seedBytes)

			msg, err := hex.DecodeString(vec.message)
			if err != nil {
				t.Fatalf("Failed to decode message: %v", err)
			}

			ctx, err := hex.DecodeString(vec.ctx)
			if err != nil {
				t.Fatalf("Failed to decode context: %v", err)
			}

			mldsa, err := NewMLDSA87FromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create MLDSA87: %v", err)
			}

			// Sign
			sig, err := mldsa.Sign(ctx, msg)
			if err != nil {
				t.Fatalf("Failed to sign: %v", err)
			}

			// Verify with correct public key
			pk := mldsa.GetPK()
			if !Verify(ctx, msg, sig, &pk) {
				t.Error("Signature verification failed with correct key")
			}

			// Verify with wrong public key should fail
			wrongMldsa, err := New()
			if err != nil {
				t.Fatalf("Failed to create random MLDSA87: %v", err)
			}
			wrongPk := wrongMldsa.GetPK()
			if Verify(ctx, msg, sig, &wrongPk) {
				t.Error("Signature verification should fail with wrong key")
			}

			// Verify with wrong message should fail
			wrongMsg := append([]byte{}, msg...)
			if len(wrongMsg) > 0 {
				wrongMsg[0] ^= 0xFF
			} else {
				wrongMsg = []byte{0x42}
			}
			if Verify(ctx, wrongMsg, sig, &pk) {
				t.Error("Signature verification should fail with wrong message")
			}

			// Verify with wrong context should fail (if context was non-empty)
			if len(ctx) > 0 {
				wrongCtx := append([]byte{}, ctx...)
				wrongCtx[0] ^= 0xFF
				if Verify(wrongCtx, msg, sig, &pk) {
					t.Error("Signature verification should fail with wrong context")
				}
			}
		})
	}
}

// TestKATSealOpenRoundTrip verifies seal/open round trip
func TestKATSealOpenRoundTrip(t *testing.T) {
	for _, vec := range katVectors {
		t.Run(vec.name+"_seal_open", func(t *testing.T) {
			seedBytes, err := hex.DecodeString(vec.seed)
			if err != nil {
				t.Fatalf("Failed to decode seed: %v", err)
			}

			var seed [SEED_BYTES]uint8
			copy(seed[:], seedBytes)

			msg, err := hex.DecodeString(vec.message)
			if err != nil {
				t.Fatalf("Failed to decode message: %v", err)
			}

			ctx, err := hex.DecodeString(vec.ctx)
			if err != nil {
				t.Fatalf("Failed to decode context: %v", err)
			}

			mldsa, err := NewMLDSA87FromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create MLDSA87: %v", err)
			}

			// Seal
			sealed, err := mldsa.Seal(ctx, msg)
			if err != nil {
				t.Fatalf("Failed to seal: %v", err)
			}

			// Sealed message should be signature + message
			if len(sealed) != CRYPTO_BYTES+len(msg) {
				t.Errorf("Sealed message length: expected %d, got %d", CRYPTO_BYTES+len(msg), len(sealed))
			}

			// Open
			pk := mldsa.GetPK()
			opened := Open(ctx, sealed, &pk)
			if opened == nil {
				t.Fatal("Open returned nil")
			}

			if !bytes.Equal(opened, msg) {
				t.Error("Opened message doesn't match original")
			}

			// Extract functions
			extractedSig := ExtractSignature(sealed)
			if extractedSig == nil {
				t.Error("ExtractSignature returned nil")
			}
			if len(extractedSig) != CRYPTO_BYTES {
				t.Errorf("Extracted signature length: expected %d, got %d", CRYPTO_BYTES, len(extractedSig))
			}

			extractedMsg := ExtractMessage(sealed)
			if !bytes.Equal(extractedMsg, msg) {
				t.Error("Extracted message doesn't match original")
			}
		})
	}
}

// TestKATKeySize verifies key sizes match FIPS 204 ML-DSA-87 specification
func TestKATKeySize(t *testing.T) {
	// ML-DSA-87 key sizes per FIPS 204
	expectedPKSize := 2592 // bytes
	expectedSKSize := 4896 // bytes
	expectedSigSize := 4627 // bytes

	if CRYPTO_PUBLIC_KEY_BYTES != expectedPKSize {
		t.Errorf("Public key size: expected %d, got %d", expectedPKSize, CRYPTO_PUBLIC_KEY_BYTES)
	}

	if CRYPTO_SECRET_KEY_BYTES != expectedSKSize {
		t.Errorf("Secret key size: expected %d, got %d", expectedSKSize, CRYPTO_SECRET_KEY_BYTES)
	}

	if CRYPTO_BYTES != expectedSigSize {
		t.Errorf("Signature size: expected %d, got %d", expectedSigSize, CRYPTO_BYTES)
	}
}

// TestKATParameters verifies ML-DSA-87 parameters match FIPS 204 specification
func TestKATParameters(t *testing.T) {
	// ML-DSA-87 parameters per FIPS 204
	tests := []struct {
		name     string
		got      int
		expected int
	}{
		{"K", K, 8},
		{"L", L, 7},
		{"ETA", ETA, 2},
		{"TAU", TAU, 60},
		{"BETA", BETA, 120},
		{"GAMMA1", GAMMA1, 1 << 19},
		{"GAMMA2", GAMMA2, (Q - 1) / 32},
		{"OMEGA", OMEGA, 75},
		{"Q", Q, 8380417},
		{"N", N, 256},
		{"D", D, 13},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s: expected %d, got %d", tt.name, tt.expected, tt.got)
			}
		})
	}
}

// TestKATHexSeedParsing verifies hex seed parsing
func TestKATHexSeedParsing(t *testing.T) {
	for _, vec := range katVectors {
		t.Run(vec.name+"_hex_seed", func(t *testing.T) {
			// Create from hex seed
			mldsa1, err := NewMLDSA87FromHexSeed(vec.seed)
			if err != nil {
				t.Fatalf("Failed to create MLDSA87 from hex seed: %v", err)
			}

			// Create from binary seed
			seedBytes, _ := hex.DecodeString(vec.seed)
			var seed [SEED_BYTES]uint8
			copy(seed[:], seedBytes)
			mldsa2, err := NewMLDSA87FromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create MLDSA87 from binary seed: %v", err)
			}

			// Should produce identical keypairs
			pk1 := mldsa1.GetPK()
			pk2 := mldsa2.GetPK()
			if !bytes.Equal(pk1[:], pk2[:]) {
				t.Error("Hex and binary seed should produce identical public keys")
			}
		})
	}
}

// TestKATDifferentSeeds verifies different seeds produce different keypairs
func TestKATDifferentSeeds(t *testing.T) {
	if len(katVectors) < 2 {
		t.Skip("Need at least 2 test vectors")
	}

	seedBytes1, _ := hex.DecodeString(katVectors[0].seed)
	seedBytes2, _ := hex.DecodeString(katVectors[1].seed)

	var seed1, seed2 [SEED_BYTES]uint8
	copy(seed1[:], seedBytes1)
	copy(seed2[:], seedBytes2)

	mldsa1, err := NewMLDSA87FromSeed(seed1)
	if err != nil {
		t.Fatalf("Failed to create MLDSA87 (1): %v", err)
	}

	mldsa2, err := NewMLDSA87FromSeed(seed2)
	if err != nil {
		t.Fatalf("Failed to create MLDSA87 (2): %v", err)
	}

	pk1 := mldsa1.GetPK()
	pk2 := mldsa2.GetPK()
	if bytes.Equal(pk1[:], pk2[:]) {
		t.Error("Different seeds should produce different public keys")
	}

	sk1 := mldsa1.GetSK()
	sk2 := mldsa2.GetSK()
	if bytes.Equal(sk1[:], sk2[:]) {
		t.Error("Different seeds should produce different secret keys")
	}
}

// TestKATZeroize verifies zeroization of sensitive material
func TestKATZeroize(t *testing.T) {
	seedBytes, _ := hex.DecodeString(katVectors[0].seed)
	var seed [SEED_BYTES]uint8
	copy(seed[:], seedBytes)

	mldsa, err := NewMLDSA87FromSeed(seed)
	if err != nil {
		t.Fatalf("Failed to create MLDSA87: %v", err)
	}

	// Get references before zeroize
	sk := mldsa.GetSK()
	storedSeed := mldsa.GetSeed()

	// Verify not already zero
	allZeroSK := true
	for _, b := range sk {
		if b != 0 {
			allZeroSK = false
			break
		}
	}
	if allZeroSK {
		t.Skip("SK already all zeros, can't test zeroize")
	}

	// Zeroize
	mldsa.Zeroize()

	// Check SK is zeroed
	skAfter := mldsa.GetSK()
	for i, b := range skAfter {
		if b != 0 {
			t.Errorf("SK byte %d not zeroed: %d", i, b)
			break
		}
	}

	// Check seed is zeroed
	seedAfter := mldsa.GetSeed()
	for i, b := range seedAfter {
		if b != 0 {
			t.Errorf("Seed byte %d not zeroed: %d", i, b)
			break
		}
	}

	// PK should still be accessible (not zeroized)
	_ = mldsa.GetPK()

	// Suppress unused variable warnings
	_ = storedSeed
}
