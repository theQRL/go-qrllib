package dilithium

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/theQRL/go-qrllib/misc"
)

// Known Answer Test (KAT) vectors for Dilithium
// These test vectors verify deterministic key generation and signing.
//
// NOTE: Dilithium in go-qrllib uses a 32-byte seed (SeedBytes) that gets
// hashed with SHAKE256 before key generation. This matches the standard
// approach used by ML-DSA-87 and ensures type safety.

// Test vector structure for KAT
type katVector struct {
	name    string
	seed    string // 32 bytes hex (SeedBytes)
	message string // Message to sign (hex)
}

// Test vectors with known 32-byte seeds
var katVectors = []katVector{
	{
		name:    "zero_seed",
		seed:    "0000000000000000000000000000000000000000000000000000000000000000",
		message: "",
	},
	{
		name:    "incremental_seed",
		seed:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		message: "48656c6c6f2c20576f726c6421", // "Hello, World!"
	},
	{
		name:    "random_seed_1",
		seed:    "deadbeefcafebabe0123456789abcdef00112233445566778899aabbccddeeff",
		message: "54657374206d65737361676520666f72204b415420766572696669636174696f6e", // "Test message for KAT verification"
	},
}

// TestKATDeterministicKeypair verifies that keypair generation is deterministic
func TestKATDeterministicKeypair(t *testing.T) {
	for _, vec := range katVectors {
		t.Run(vec.name+"_deterministic", func(t *testing.T) {
			seedSlice, err := hex.DecodeString(vec.seed)
			if err != nil {
				t.Fatalf("Failed to decode seed: %v", err)
			}
			var seed [SeedBytes]uint8
			copy(seed[:], seedSlice)

			// Generate keypair twice with same seed
			dil1, err := NewDilithiumFromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create Dilithium (1): %v", err)
			}

			dil2, err := NewDilithiumFromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create Dilithium (2): %v", err)
			}

			// Public keys must be identical
			pk1 := dil1.GetPK()
			pk2 := dil2.GetPK()
			if !bytes.Equal(pk1[:], pk2[:]) {
				t.Error("Public keys should be identical for same seed")
			}

			// Secret keys must be identical
			sk1 := dil1.GetSK()
			sk2 := dil2.GetSK()
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
			seedSlice, err := hex.DecodeString(vec.seed)
			if err != nil {
				t.Fatalf("Failed to decode seed: %v", err)
			}
			var seed [SeedBytes]uint8
			copy(seed[:], seedSlice)

			msg, err := hex.DecodeString(vec.message)
			if err != nil {
				t.Fatalf("Failed to decode message: %v", err)
			}

			dil, err := NewDilithiumFromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create Dilithium: %v", err)
			}

			// Sign the same message twice
			sig1, err := dil.Sign(msg)
			if err != nil {
				t.Fatalf("Failed to sign (1): %v", err)
			}

			sig2, err := dil.Sign(msg)
			if err != nil {
				t.Fatalf("Failed to sign (2): %v", err)
			}

			// Signatures must be identical (deterministic signing)
			if !bytes.Equal(sig1[:], sig2[:]) {
				t.Error("Signatures should be identical for deterministic signing")
			}

			// Verify the signature
			pk := dil.GetPK()
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
			seedSlice, err := hex.DecodeString(vec.seed)
			if err != nil {
				t.Fatalf("Failed to decode seed: %v", err)
			}
			var seed [SeedBytes]uint8
			copy(seed[:], seedSlice)

			msg, err := hex.DecodeString(vec.message)
			if err != nil {
				t.Fatalf("Failed to decode message: %v", err)
			}

			dil, err := NewDilithiumFromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create Dilithium: %v", err)
			}

			// Sign
			sig, err := dil.Sign(msg)
			if err != nil {
				t.Fatalf("Failed to sign: %v", err)
			}

			// Verify with correct public key
			pk := dil.GetPK()
			if !Verify(msg, sig, &pk) {
				t.Error("Signature verification failed with correct key")
			}

			// Verify with wrong public key should fail
			wrongDil, err := New()
			if err != nil {
				t.Fatalf("Failed to create random Dilithium: %v", err)
			}
			wrongPk := wrongDil.GetPK()
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
			seedSlice, err := hex.DecodeString(vec.seed)
			if err != nil {
				t.Fatalf("Failed to decode seed: %v", err)
			}
			var seed [SeedBytes]uint8
			copy(seed[:], seedSlice)

			msg, err := hex.DecodeString(vec.message)
			if err != nil {
				t.Fatalf("Failed to decode message: %v", err)
			}

			dil, err := NewDilithiumFromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create Dilithium: %v", err)
			}

			// Seal
			sealed, err := dil.Seal(msg)
			if err != nil {
				t.Fatalf("Failed to seal: %v", err)
			}

			// Sealed message should be signature + message
			if len(sealed) != CryptoBytes+len(msg) {
				t.Errorf("Sealed message length: expected %d, got %d", CryptoBytes+len(msg), len(sealed))
			}

			// Open
			pk := dil.GetPK()
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
			if len(extractedSig) != CryptoBytes {
				t.Errorf("Extracted signature length: expected %d, got %d", CryptoBytes, len(extractedSig))
			}

			extractedMsg := ExtractMessage(sealed)
			if !bytes.Equal(extractedMsg, msg) {
				t.Error("Extracted message doesn't match original")
			}
		})
	}
}

// TestKATKeySize verifies key sizes match Dilithium5 specification
func TestKATKeySize(t *testing.T) {
	// Dilithium5 key sizes
	expectedPKSize := 2592 // bytes
	expectedSKSize := 4864 // bytes (differs from ML-DSA-87 due to secret key format)
	expectedSigSize := 4595 // bytes (differs from ML-DSA-87 due to c_tilde size)

	if CryptoPublicKeyBytes != expectedPKSize {
		t.Errorf("Public key size: expected %d, got %d", expectedPKSize, CryptoPublicKeyBytes)
	}

	if CryptoSecretKeyBytes != expectedSKSize {
		t.Errorf("Secret key size: expected %d, got %d", expectedSKSize, CryptoSecretKeyBytes)
	}

	if CryptoBytes != expectedSigSize {
		t.Errorf("Signature size: expected %d, got %d", expectedSigSize, CryptoBytes)
	}
}

// TestKATParameters verifies Dilithium5 parameters
func TestKATParameters(t *testing.T) {
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

// TestKATSeedHashing verifies the seed hashing behavior
func TestKATSeedHashing(t *testing.T) {
	// Verify that the 32-byte seed is hashed correctly with SHAKE256
	seedSlice, _ := hex.DecodeString(katVectors[1].seed)
	var seed [SeedBytes]uint8
	copy(seed[:], seedSlice)

	var hashedSeed [32]uint8
	misc.SHAKE256(hashedSeed[:], seed[:])

	// The hashed seed should be non-zero
	allZero := true
	for _, b := range hashedSeed {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Hashed seed should not be all zeros for non-zero input")
	}
}

// TestKATHexSeedParsing verifies hex seed parsing
func TestKATHexSeedParsing(t *testing.T) {
	for _, vec := range katVectors {
		t.Run(vec.name+"_hex_seed", func(t *testing.T) {
			// Create from hex seed
			dil1, err := NewDilithiumFromHexSeed(vec.seed)
			if err != nil {
				t.Fatalf("Failed to create Dilithium from hex seed: %v", err)
			}

			// Create from binary seed
			seedSlice, _ := hex.DecodeString(vec.seed)
			var seed [SeedBytes]uint8
			copy(seed[:], seedSlice)
			dil2, err := NewDilithiumFromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create Dilithium from binary seed: %v", err)
			}

			// Should produce identical keypairs
			pk1 := dil1.GetPK()
			pk2 := dil2.GetPK()
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

	seedSlice1, _ := hex.DecodeString(katVectors[0].seed)
	seedSlice2, _ := hex.DecodeString(katVectors[1].seed)
	var seed1, seed2 [SeedBytes]uint8
	copy(seed1[:], seedSlice1)
	copy(seed2[:], seedSlice2)

	dil1, err := NewDilithiumFromSeed(seed1)
	if err != nil {
		t.Fatalf("Failed to create Dilithium (1): %v", err)
	}

	dil2, err := NewDilithiumFromSeed(seed2)
	if err != nil {
		t.Fatalf("Failed to create Dilithium (2): %v", err)
	}

	pk1 := dil1.GetPK()
	pk2 := dil2.GetPK()
	if bytes.Equal(pk1[:], pk2[:]) {
		t.Error("Different seeds should produce different public keys")
	}

	sk1 := dil1.GetSK()
	sk2 := dil2.GetSK()
	if bytes.Equal(sk1[:], sk2[:]) {
		t.Error("Different seeds should produce different secret keys")
	}
}

// TestKATSignWithSecretKey verifies SignWithSecretKey function
func TestKATSignWithSecretKey(t *testing.T) {
	for _, vec := range katVectors {
		t.Run(vec.name+"_sign_with_sk", func(t *testing.T) {
			seedSlice, err := hex.DecodeString(vec.seed)
			if err != nil {
				t.Fatalf("Failed to decode seed: %v", err)
			}
			var seed [SeedBytes]uint8
			copy(seed[:], seedSlice)

			msg, err := hex.DecodeString(vec.message)
			if err != nil {
				t.Fatalf("Failed to decode message: %v", err)
			}

			dil, err := NewDilithiumFromSeed(seed)
			if err != nil {
				t.Fatalf("Failed to create Dilithium: %v", err)
			}

			// Sign using the struct method
			sig1, err := dil.Sign(msg)
			if err != nil {
				t.Fatalf("Failed to sign with method: %v", err)
			}

			// Sign using SignWithSecretKey function
			sk := dil.GetSK()
			sig2, err := SignWithSecretKey(msg, &sk)
			if err != nil {
				t.Fatalf("Failed to sign with SignWithSecretKey: %v", err)
			}

			// Both signatures should be identical (deterministic)
			if !bytes.Equal(sig1[:], sig2[:]) {
				t.Error("Sign() and SignWithSecretKey() should produce identical signatures")
			}

			// Both should verify
			pk := dil.GetPK()
			if !Verify(msg, sig1, &pk) {
				t.Error("Signature from Sign() failed verification")
			}
			if !Verify(msg, sig2, &pk) {
				t.Error("Signature from SignWithSecretKey() failed verification")
			}
		})
	}
}

// TestKATZeroize verifies zeroization of sensitive material
func TestKATZeroize(t *testing.T) {
	seedSlice, _ := hex.DecodeString(katVectors[0].seed)
	var seed [SeedBytes]uint8
	copy(seed[:], seedSlice)

	dil, err := NewDilithiumFromSeed(seed)
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	// Get references before zeroize
	sk := dil.GetSK()

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
	dil.Zeroize()

	// Check SK is zeroed
	skAfter := dil.GetSK()
	for i, b := range skAfter {
		if b != 0 {
			t.Errorf("SK byte %d not zeroed: %d", i, b)
			break
		}
	}

	// Check seed is zeroed
	seedAfter := dil.GetSeed()
	for i, b := range seedAfter {
		if b != 0 {
			t.Errorf("Seed byte %d not zeroed: %d", i, b)
			break
		}
	}
}
