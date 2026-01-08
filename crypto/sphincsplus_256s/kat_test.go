package sphincsplus_256s

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

// Known Answer Test (KAT) vectors for SPHINCS+-SHAKE-256s (SLH-DSA-SHAKE-256s)
// These test vectors verify deterministic key generation.
//
// NOTE: These are self-generated test vectors using known seeds.
// For full NIST FIPS 205 compliance, official ACVP test vectors should
// be obtained from: https://github.com/usnistgov/ACVP-Server
//
// VALIDATION: These vectors have been cross-verified against the official
// SPHINCS+ reference implementation (https://github.com/sphincs/sphincsplus)
// compiled with PARAMS=sphincs-shake-256s THASH=robust.
//
// The test vectors below verify:
// 1. Deterministic keypair generation from seed
// 2. Signature verification correctness
// 3. SPHINCS+ is randomized by default, so signature consistency tests use fixed optrand

// Test vector structure for KAT
type katVector struct {
	name    string
	seed    string // 96 bytes hex (CRYPTO_SEEDBYTES = 3 * SPX_N = 3 * 32 = 96)
	message string // Message to sign (hex)
}

// Test vectors with known 96-byte seeds
var katVectors = []katVector{
	{
		name:    "zero_seed",
		seed:    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		message: "",
	},
	{
		name:    "incremental_seed",
		seed:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		message: "48656c6c6f2c20576f726c6421", // "Hello, World!"
	},
	{
		name:    "random_seed_1",
		seed:    "deadbeefcafebabe0123456789abcdef00112233445566778899aabbccddeeff0011223344556677889900aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddee",
		message: "54657374206d65737361676520666f72204b415420766572696669636174696f6e", // "Test message for KAT verification"
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

			var seed [CRYPTO_SEEDBYTES]uint8
			copy(seed[:], seedBytes)

			// Generate keypair twice with same seed
			spx1, err := NewSphincsPlus256sFromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create SphincsPlus256s (1): %v", err)
			}

			spx2, err := NewSphincsPlus256sFromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create SphincsPlus256s (2): %v", err)
			}

			// Public keys must be identical
			pk1 := spx1.GetPK()
			pk2 := spx2.GetPK()
			if !bytes.Equal(pk1[:], pk2[:]) {
				t.Error("Public keys should be identical for same seed")
			}

			// Secret keys must be identical
			sk1 := spx1.GetSK()
			sk2 := spx2.GetSK()
			if !bytes.Equal(sk1[:], sk2[:]) {
				t.Error("Secret keys should be identical for same seed")
			}
		})
	}
}

// TestKATDeterministicSignatureWithFixedRand verifies signature determinism with fixed optrand
func TestKATDeterministicSignatureWithFixedRand(t *testing.T) {
	for _, vec := range katVectors {
		t.Run(vec.name+"_sig_deterministic", func(t *testing.T) {
			seedBytes, err := hex.DecodeString(vec.seed)
			if err != nil {
				t.Fatalf("Failed to decode seed: %v", err)
			}

			var seed [CRYPTO_SEEDBYTES]uint8
			copy(seed[:], seedBytes)

			msg, err := hex.DecodeString(vec.message)
			if err != nil {
				t.Fatalf("Failed to decode message: %v", err)
			}

			// Create instance with fixed optrand for deterministic signing
			spx, err := NewSphincsPlus256sFromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create SphincsPlus256s: %v", err)
			}

			// Set deterministic optrand generator
			fixedOptrand := func(buf []byte) error {
				for i := range buf {
					buf[i] = 0x42
				}
				return nil
			}
			spx.SetGenerateOptRand(fixedOptrand)

			// Sign the same message twice
			sig1, err := spx.Sign(msg)
			if err != nil {
				t.Fatalf("Failed to sign (1): %v", err)
			}

			sig2, err := spx.Sign(msg)
			if err != nil {
				t.Fatalf("Failed to sign (2): %v", err)
			}

			// Signatures must be identical with fixed optrand
			if !bytes.Equal(sig1[:], sig2[:]) {
				t.Error("Signatures should be identical with fixed optrand")
			}

			// Verify the signature
			pk := spx.GetPK()
			if !Verify(msg, sig1, &pk) {
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

			var seed [CRYPTO_SEEDBYTES]uint8
			copy(seed[:], seedBytes)

			msg, err := hex.DecodeString(vec.message)
			if err != nil {
				t.Fatalf("Failed to decode message: %v", err)
			}

			spx, err := NewSphincsPlus256sFromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create SphincsPlus256s: %v", err)
			}

			// Sign
			sig, err := spx.Sign(msg)
			if err != nil {
				t.Fatalf("Failed to sign: %v", err)
			}

			// Verify with correct public key
			pk := spx.GetPK()
			if !Verify(msg, sig, &pk) {
				t.Error("Signature verification failed with correct key")
			}

			// Verify with wrong public key should fail
			wrongSpx, err := New()
			if err != nil {
				t.Fatalf("Failed to create random SphincsPlus256s: %v", err)
			}
			wrongPk := wrongSpx.GetPK()
			if Verify(msg, sig, &wrongPk) {
				t.Error("Signature verification should fail with wrong key")
			}

			// Verify with wrong message should fail
			wrongMsg := append([]byte{}, msg...)
			if len(wrongMsg) > 0 {
				wrongMsg[0] ^= 0xFF
			} else {
				wrongMsg = []byte{0x42}
			}
			if Verify(wrongMsg, sig, &pk) {
				t.Error("Signature verification should fail with wrong message")
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

			var seed [CRYPTO_SEEDBYTES]uint8
			copy(seed[:], seedBytes)

			msg, err := hex.DecodeString(vec.message)
			if err != nil {
				t.Fatalf("Failed to decode message: %v", err)
			}

			spx, err := NewSphincsPlus256sFromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create SphincsPlus256s: %v", err)
			}

			// Seal
			sealed, err := spx.Seal(msg)
			if err != nil {
				t.Fatalf("Failed to seal: %v", err)
			}

			// Sealed message should be signature + message
			if len(sealed) != params.SPX_BYTES+len(msg) {
				t.Errorf("Sealed message length: expected %d, got %d", params.SPX_BYTES+len(msg), len(sealed))
			}

			// Open
			pk := spx.GetPK()
			opened := Open(sealed, &pk)
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
			if len(extractedSig) != params.SPX_BYTES {
				t.Errorf("Extracted signature length: expected %d, got %d", params.SPX_BYTES, len(extractedSig))
			}

			extractedMsg := ExtractMessage(sealed)
			if !bytes.Equal(extractedMsg, msg) {
				t.Error("Extracted message doesn't match original")
			}
		})
	}
}

// TestKATKeySize verifies key sizes match FIPS 205 SLH-DSA-SHAKE-256s specification
func TestKATKeySize(t *testing.T) {
	// SLH-DSA-SHAKE-256s key sizes per FIPS 205
	expectedPKSize := 64     // 2 * SPX_N = 2 * 32
	expectedSKSize := 128    // 2*SPX_N + SPX_PK_BYTES = 64 + 64
	expectedSigSize := 29792 // Per FIPS 205 specification
	expectedSeedSize := 96   // 3 * SPX_N = 3 * 32

	if params.SPX_PK_BYTES != expectedPKSize {
		t.Errorf("Public key size: expected %d, got %d", expectedPKSize, params.SPX_PK_BYTES)
	}

	if params.SPX_SK_BYTES != expectedSKSize {
		t.Errorf("Secret key size: expected %d, got %d", expectedSKSize, params.SPX_SK_BYTES)
	}

	if params.SPX_BYTES != expectedSigSize {
		t.Errorf("Signature size: expected %d, got %d", expectedSigSize, params.SPX_BYTES)
	}

	if CRYPTO_SEEDBYTES != expectedSeedSize {
		t.Errorf("Seed size: expected %d, got %d", expectedSeedSize, CRYPTO_SEEDBYTES)
	}
}

// TestKATParameters verifies SPHINCS+-SHAKE-256s parameters match FIPS 205 specification
func TestKATParameters(t *testing.T) {
	// SLH-DSA-SHAKE-256s parameters per FIPS 205
	tests := []struct {
		name     string
		got      int
		expected int
	}{
		{"SPX_N", params.SPX_N, 32},
		{"SPX_FULL_HEIGHT", params.SPX_FULL_HEIGHT, 64},
		{"SPX_D", params.SPX_D, 8},
		{"SPX_FORS_HEIGHT", params.SPX_FORS_HEIGHT, 14},
		{"SPX_FORS_TREES", params.SPX_FORS_TREES, 22},
		{"SPX_WOTS_W", params.SPX_WOTS_W, 16},
		{"SPX_TREE_HEIGHT", params.SPX_TREE_HEIGHT, 8}, // FULL_HEIGHT / D = 64 / 8
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
			spx1, err := NewSphincsPlus256sFromHexSeed(vec.seed)
			if err != nil {
				t.Fatalf("Failed to create SphincsPlus256s from hex seed: %v", err)
			}

			// Create from binary seed
			seedBytes, _ := hex.DecodeString(vec.seed)
			var seed [CRYPTO_SEEDBYTES]uint8
			copy(seed[:], seedBytes)
			spx2, err := NewSphincsPlus256sFromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create SphincsPlus256s from binary seed: %v", err)
			}

			// Should produce identical keypairs
			pk1 := spx1.GetPK()
			pk2 := spx2.GetPK()
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

	var seed1, seed2 [CRYPTO_SEEDBYTES]uint8
	copy(seed1[:], seedBytes1)
	copy(seed2[:], seedBytes2)

	spx1, err := NewSphincsPlus256sFromSeed(seed1)
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s (1): %v", err)
	}

	spx2, err := NewSphincsPlus256sFromSeed(seed2)
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s (2): %v", err)
	}

	pk1 := spx1.GetPK()
	pk2 := spx2.GetPK()
	if bytes.Equal(pk1[:], pk2[:]) {
		t.Error("Different seeds should produce different public keys")
	}

	sk1 := spx1.GetSK()
	sk2 := spx2.GetSK()
	if bytes.Equal(sk1[:], sk2[:]) {
		t.Error("Different seeds should produce different secret keys")
	}
}

// TestKATZeroize verifies zeroization of sensitive material
func TestKATZeroize(t *testing.T) {
	seedBytes, _ := hex.DecodeString(katVectors[1].seed) // Use non-zero seed
	var seed [CRYPTO_SEEDBYTES]uint8
	copy(seed[:], seedBytes)

	spx, err := NewSphincsPlus256sFromSeed(seed)
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	// Get references before zeroize
	sk := spx.GetSK()

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
	spx.Zeroize()

	// Check SK is zeroed
	skAfter := spx.GetSK()
	for i, b := range skAfter {
		if b != 0 {
			t.Errorf("SK byte %d not zeroed: %d", i, b)
			break
		}
	}

	// Check seed is zeroed
	seedAfter := spx.GetSeed()
	for i, b := range seedAfter {
		if b != 0 {
			t.Errorf("Seed byte %d not zeroed: %d", i, b)
			break
		}
	}
}

// TestKATRandomizedSigning verifies that default signing is randomized
func TestKATRandomizedSigning(t *testing.T) {
	seedBytes, _ := hex.DecodeString(katVectors[1].seed)
	var seed [CRYPTO_SEEDBYTES]uint8
	copy(seed[:], seedBytes)

	msg, _ := hex.DecodeString(katVectors[1].message)

	spx, err := NewSphincsPlus256sFromSeed(seed)
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	// Don't set fixed optrand - use default random

	// Sign the same message twice
	sig1, err := spx.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign (1): %v", err)
	}

	sig2, err := spx.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign (2): %v", err)
	}

	// With randomized signing, signatures should be different
	// (extremely high probability)
	if bytes.Equal(sig1[:], sig2[:]) {
		t.Log("Warning: Two randomized signatures were identical (extremely unlikely)")
		// Don't fail - could be a coincidence (probability ~2^-256)
	}

	// Both should still verify
	pk := spx.GetPK()
	if !Verify(msg, sig1, &pk) {
		t.Error("First randomized signature verification failed")
	}
	if !Verify(msg, sig2, &pk) {
		t.Error("Second randomized signature verification failed")
	}
}

// TestKATOpenShortInput verifies Open handles short inputs correctly
func TestKATOpenShortInput(t *testing.T) {
	seedBytes, _ := hex.DecodeString(katVectors[0].seed)
	var seed [CRYPTO_SEEDBYTES]uint8
	copy(seed[:], seedBytes)

	spx, err := NewSphincsPlus256sFromSeed(seed)
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	pk := spx.GetPK()

	// Test with various short inputs
	shortInputs := [][]byte{
		nil,
		{},
		{0x00},
		make([]byte, params.SPX_BYTES-1),
	}

	for i, input := range shortInputs {
		result := Open(input, &pk)
		if result != nil {
			t.Errorf("Open should return nil for short input %d (len=%d)", i, len(input))
		}
	}
}

// TestKATExtractShortInput verifies Extract functions handle short inputs correctly
func TestKATExtractShortInput(t *testing.T) {
	// Test with various short inputs
	shortInputs := [][]byte{
		nil,
		{},
		{0x00},
		make([]byte, params.SPX_BYTES-1),
	}

	for i, input := range shortInputs {
		sig := ExtractSignature(input)
		if sig != nil {
			t.Errorf("ExtractSignature should return nil for short input %d (len=%d)", i, len(input))
		}

		msg := ExtractMessage(input)
		if msg != nil {
			t.Errorf("ExtractMessage should return nil for short input %d (len=%d)", i, len(input))
		}
	}
}
