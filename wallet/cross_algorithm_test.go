package wallet_test

import (
	"bytes"
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
	ml_dsa_wallet "github.com/theQRL/go-qrllib/wallet/ml_dsa_87"
	sphincs_wallet "github.com/theQRL/go-qrllib/wallet/sphincsplus_256s"
)

// TestSeedHashDivergence verifies that the same raw seed produces different
// cryptographic keys for different algorithms due to different hash functions.
// ML-DSA-87 uses SHA-256, SPHINCS+ uses SHAKE-256.
func TestSeedHashDivergence(t *testing.T) {
	// Create identical seed for both algorithms
	var seed common.Seed
	for i := range seed {
		seed[i] = byte(i)
	}

	// Create wallets from same seed
	mlWallet, err := ml_dsa_wallet.NewWalletFromSeed(seed)
	if err != nil {
		t.Fatalf("failed to create ML-DSA-87 wallet: %v", err)
	}

	sphincsWallet, err := sphincs_wallet.NewWalletFromSeed(seed)
	if err != nil {
		t.Fatalf("failed to create SPHINCS+ wallet: %v", err)
	}

	// Verify raw seeds are identical
	if mlWallet.GetSeed() != sphincsWallet.GetSeed() {
		t.Error("raw seeds should be identical")
	}

	// Verify hash divergence produces different derived seeds
	sha256Hash := seed.HashSHA256()
	shake256Hash := seed.HashSHAKE256(32)

	if bytes.Equal(sha256Hash[:], shake256Hash) {
		t.Error("SHA-256 and SHAKE-256 should produce different hashes")
	}

	// Verify public keys are different (different algorithms, different keys)
	// Keys have different sizes, so they must be different
	mlPKLen := len(mlWallet.GetPK())
	sphincsPKLen := len(sphincsWallet.GetPK())
	if mlPKLen == sphincsPKLen {
		t.Errorf("public key sizes should differ: ML-DSA=%d, SPHINCS+=%d",
			mlPKLen, sphincsPKLen)
	}

	// Addresses should be different (different PKs and descriptors)
	if mlWallet.GetAddress() == sphincsWallet.GetAddress() {
		t.Error("addresses from different algorithms should differ")
	}
}

// TestCrossAlgorithmVerificationRejection ensures that signatures from one
// algorithm are rejected when verified with another algorithm's verifier.
func TestCrossAlgorithmVerificationRejection(t *testing.T) {
	message := []byte("cross-algorithm test message")

	// Create wallets
	mlWallet, err := ml_dsa_wallet.NewWallet()
	if err != nil {
		t.Fatalf("failed to create ML-DSA-87 wallet: %v", err)
	}

	sphincsWallet, err := sphincs_wallet.NewWallet()
	if err != nil {
		t.Fatalf("failed to create SPHINCS+ wallet: %v", err)
	}

	// Sign with ML-DSA-87
	mlSig, err := mlWallet.Sign(message)
	if err != nil {
		t.Fatalf("ML-DSA-87 signing failed: %v", err)
	}

	// Sign with SPHINCS+
	sphincsSig, err := sphincsWallet.Sign(message)
	if err != nil {
		t.Fatalf("SPHINCS+ signing failed: %v", err)
	}

	// Verify ML-DSA signature with ML-DSA verifier (should pass)
	mlPK := mlWallet.GetPK()
	mlDesc := mlWallet.GetDescriptor().ToDescriptor()
	if !ml_dsa_wallet.Verify(message, mlSig[:], &mlPK, mlDesc) {
		t.Error("ML-DSA signature should verify with ML-DSA verifier")
	}

	// Verify SPHINCS+ signature with SPHINCS+ verifier (should pass)
	sphincsPK := sphincsWallet.GetPK()
	sphincsDesc := sphincsWallet.GetDescriptor().ToDescriptor()
	if !sphincs_wallet.Verify(message, sphincsSig[:], &sphincsPK, sphincsDesc) {
		t.Error("SPHINCS+ signature should verify with SPHINCS+ verifier")
	}

	// Cross-verify ML-DSA signature with SPHINCS+ verifier (should fail)
	// The descriptor check should reject it first
	if sphincs_wallet.Verify(message, mlSig[:], &sphincsPK, mlDesc) {
		t.Error("ML-DSA signature should NOT verify with SPHINCS+ verifier")
	}

	// Cross-verify SPHINCS+ signature with ML-DSA verifier (should fail)
	if ml_dsa_wallet.Verify(message, sphincsSig[:], &mlPK, sphincsDesc) {
		t.Error("SPHINCS+ signature should NOT verify with ML-DSA verifier")
	}
}

// TestDescriptorIsolation verifies that descriptors correctly identify and
// isolate different algorithm types.
func TestDescriptorIsolation(t *testing.T) {
	mlWallet, _ := ml_dsa_wallet.NewWallet()
	sphincsWallet, _ := sphincs_wallet.NewWallet()

	mlDesc := mlWallet.GetDescriptor().ToDescriptor()
	sphincsDesc := sphincsWallet.GetDescriptor().ToDescriptor()

	// Verify descriptor type bytes differ
	if mlDesc[0] == sphincsDesc[0] {
		t.Error("descriptor type bytes should differ between algorithms")
	}

	// Verify correct wallet types
	if wallettype.WalletType(mlDesc[0]) != wallettype.ML_DSA_87 {
		t.Errorf("ML-DSA descriptor type should be %d, got %d",
			wallettype.ML_DSA_87, mlDesc[0])
	}

	if wallettype.WalletType(sphincsDesc[0]) != wallettype.SPHINCSPLUS_256S {
		t.Errorf("SPHINCS+ descriptor type should be %d, got %d",
			wallettype.SPHINCSPLUS_256S, sphincsDesc[0])
	}

	// Verify descriptor validation
	if !mlDesc.IsValid() {
		t.Error("ML-DSA descriptor should be valid")
	}
	if !sphincsDesc.IsValid() {
		t.Error("SPHINCS+ descriptor should be valid")
	}

	// Verify invalid descriptor type
	invalidDesc := descriptor.Descriptor{255, 0, 0}
	if invalidDesc.IsValid() {
		t.Error("descriptor with type 255 should be invalid")
	}
}

// TestMnemonicRecoveryConsistency verifies that mnemonic recovery produces
// identical wallets for each algorithm independently.
func TestMnemonicRecoveryConsistency(t *testing.T) {
	t.Run("ML-DSA-87", func(t *testing.T) {
		original, err := ml_dsa_wallet.NewWallet()
		if err != nil {
			t.Fatalf("failed to create wallet: %v", err)
		}

		mnemonic, err := original.GetMnemonic()
		if err != nil {
			t.Fatalf("GetMnemonic() error: %v", err)
		}

		recovered, err := ml_dsa_wallet.NewWalletFromMnemonic(mnemonic)
		if err != nil {
			t.Fatalf("failed to recover from mnemonic: %v", err)
		}

		// Verify all wallet components match
		if original.GetSeed() != recovered.GetSeed() {
			t.Error("recovered seed should match original")
		}
		if original.GetPK() != recovered.GetPK() {
			t.Error("recovered public key should match original")
		}
		if original.GetSK() != recovered.GetSK() {
			t.Error("recovered secret key should match original")
		}
		if original.GetAddress() != recovered.GetAddress() {
			t.Error("recovered address should match original")
		}
		if original.GetAddressStr() != recovered.GetAddressStr() {
			t.Error("recovered address string should match original")
		}
	})

	t.Run("SPHINCS+", func(t *testing.T) {
		original, err := sphincs_wallet.NewWallet()
		if err != nil {
			t.Fatalf("failed to create wallet: %v", err)
		}

		mnemonic, err := original.GetMnemonic()
		if err != nil {
			t.Fatalf("GetMnemonic() error: %v", err)
		}

		recovered, err := sphincs_wallet.NewWalletFromMnemonic(mnemonic)
		if err != nil {
			t.Fatalf("failed to recover from mnemonic: %v", err)
		}

		if original.GetSeed() != recovered.GetSeed() {
			t.Error("recovered seed should match original")
		}
		if original.GetPK() != recovered.GetPK() {
			t.Error("recovered public key should match original")
		}
		if original.GetSK() != recovered.GetSK() {
			t.Error("recovered secret key should match original")
		}
		if original.GetAddress() != recovered.GetAddress() {
			t.Error("recovered address should match original")
		}
	})
}

// TestMnemonicCrossAlgorithmIsolation verifies that mnemonics from one algorithm
// cannot be used to create wallets of another algorithm type.
func TestMnemonicCrossAlgorithmIsolation(t *testing.T) {
	// Create ML-DSA wallet and get mnemonic
	mlWallet, err := ml_dsa_wallet.NewWallet()
	if err != nil {
		t.Fatalf("failed to create ML-DSA wallet: %v", err)
	}
	mlMnemonic, err := mlWallet.GetMnemonic()
	if err != nil {
		t.Fatalf("GetMnemonic() error: %v", err)
	}

	// Create SPHINCS+ wallet and get mnemonic
	sphincsWallet, err := sphincs_wallet.NewWallet()
	if err != nil {
		t.Fatalf("failed to create SPHINCS+ wallet: %v", err)
	}
	sphincsMnemonic, err := sphincsWallet.GetMnemonic()
	if err != nil {
		t.Fatalf("GetMnemonic() error: %v", err)
	}

	// Attempting to recover ML-DSA mnemonic as SPHINCS+ should fail
	// (descriptor type mismatch)
	_, err = sphincs_wallet.NewWalletFromMnemonic(mlMnemonic)
	if err == nil {
		t.Error("recovering ML-DSA mnemonic as SPHINCS+ should fail")
	}

	// Attempting to recover SPHINCS+ mnemonic as ML-DSA should fail
	_, err = ml_dsa_wallet.NewWalletFromMnemonic(sphincsMnemonic)
	if err == nil {
		t.Error("recovering SPHINCS+ mnemonic as ML-DSA should fail")
	}
}

// TestKeySizeInvariants verifies that key and signature sizes match expected
// constants for each algorithm.
func TestKeySizeInvariants(t *testing.T) {
	t.Run("ML-DSA-87", func(t *testing.T) {
		wallet, _ := ml_dsa_wallet.NewWallet()

		// Verify actual key sizes match constants
		if pkLen := len(wallet.GetPK()); pkLen != ml_dsa_wallet.PKSize {
			t.Errorf("PK size: got %d, want %d", pkLen, ml_dsa_wallet.PKSize)
		}
		if skLen := len(wallet.GetSK()); skLen != ml_dsa_wallet.SKSize {
			t.Errorf("SK size: got %d, want %d", skLen, ml_dsa_wallet.SKSize)
		}

		// Verify signature is produced and has correct size
		// (sig array type has fixed size, just verify signing succeeds)
		if _, err := wallet.Sign([]byte("test")); err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		// Verify expected FIPS 204 ML-DSA-87 sizes
		const (
			expectedPK  = 2592
			expectedSK  = 4896
			expectedSig = 4627
		)
		if ml_dsa_wallet.PKSize != expectedPK {
			t.Errorf("ML-DSA-87 PKSize constant: got %d, want %d",
				ml_dsa_wallet.PKSize, expectedPK)
		}
		if ml_dsa_wallet.SKSize != expectedSK {
			t.Errorf("ML-DSA-87 SKSize constant: got %d, want %d",
				ml_dsa_wallet.SKSize, expectedSK)
		}
		if ml_dsa_wallet.SigSize != expectedSig {
			t.Errorf("ML-DSA-87 SigSize constant: got %d, want %d",
				ml_dsa_wallet.SigSize, expectedSig)
		}
	})

	t.Run("SPHINCS+", func(t *testing.T) {
		wallet, _ := sphincs_wallet.NewWallet()

		// Verify actual key sizes match constants
		if pkLen := len(wallet.GetPK()); pkLen != sphincs_wallet.PKSize {
			t.Errorf("PK size: got %d, want %d", pkLen, sphincs_wallet.PKSize)
		}
		if skLen := len(wallet.GetSK()); skLen != sphincs_wallet.SKSize {
			t.Errorf("SK size: got %d, want %d", skLen, sphincs_wallet.SKSize)
		}

		// Verify signature is produced and has correct size
		// (sig array type has fixed size, just verify signing succeeds)
		if _, err := wallet.Sign([]byte("test")); err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		// Verify expected FIPS 205 SPHINCS+-256s sizes
		const (
			expectedPK  = 64
			expectedSK  = 128
			expectedSig = 29792
		)
		if sphincs_wallet.PKSize != expectedPK {
			t.Errorf("SPHINCS+ PKSize constant: got %d, want %d",
				sphincs_wallet.PKSize, expectedPK)
		}
		if sphincs_wallet.SKSize != expectedSK {
			t.Errorf("SPHINCS+ SKSize constant: got %d, want %d",
				sphincs_wallet.SKSize, expectedSK)
		}
		if sphincs_wallet.SigSize != expectedSig {
			t.Errorf("SPHINCS+ SigSize constant: got %d, want %d",
				sphincs_wallet.SigSize, expectedSig)
		}
	})
}

// TestAddressFormatConsistency verifies that both algorithms produce addresses
// in the same format (Q + 40 hex chars).
func TestAddressFormatConsistency(t *testing.T) {
	mlWallet, _ := ml_dsa_wallet.NewWallet()
	sphincsWallet, _ := sphincs_wallet.NewWallet()

	mlAddr := mlWallet.GetAddressStr()
	sphincsAddr := sphincsWallet.GetAddressStr()

	// Both should start with 'Q'
	if mlAddr[0] != 'Q' {
		t.Error("ML-DSA address should start with 'Q'")
	}
	if sphincsAddr[0] != 'Q' {
		t.Error("SPHINCS+ address should start with 'Q'")
	}

	// Both should be same length: Q + 40 hex chars = 41
	expectedLen := 1 + common.AddressSize*2 // Q + hex-encoded address
	if len(mlAddr) != expectedLen {
		t.Errorf("ML-DSA address length: got %d, want %d", len(mlAddr), expectedLen)
	}
	if len(sphincsAddr) != expectedLen {
		t.Errorf("SPHINCS+ address length: got %d, want %d", len(sphincsAddr), expectedLen)
	}

	// Address validation should work for both
	if !common.IsValidAddress(mlAddr) {
		t.Error("ML-DSA address should be valid")
	}
	if !common.IsValidAddress(sphincsAddr) {
		t.Error("SPHINCS+ address should be valid")
	}

	// Addresses should differ (different algorithms, different PKs)
	if mlAddr == sphincsAddr {
		t.Error("addresses from different algorithms should differ")
	}
}

// TestExtendedSeedIsolation verifies that extended seeds properly encode
// algorithm type and prevent cross-algorithm usage.
func TestExtendedSeedIsolation(t *testing.T) {
	mlWallet, err := ml_dsa_wallet.NewWallet()
	if err != nil {
		t.Fatalf("failed to create ML-DSA wallet: %v", err)
	}
	sphincsWallet, err := sphincs_wallet.NewWallet()
	if err != nil {
		t.Fatalf("failed to create SPHINCS+ wallet: %v", err)
	}

	mlExtSeed, err := mlWallet.GetExtendedSeed()
	if err != nil {
		t.Fatalf("GetExtendedSeed() error: %v", err)
	}
	sphincsExtSeed, err := sphincsWallet.GetExtendedSeed()
	if err != nil {
		t.Fatalf("GetExtendedSeed() error: %v", err)
	}

	// Verify extended seed size is consistent
	if len(mlExtSeed) != common.ExtendedSeedSize {
		t.Errorf("ML-DSA extended seed size: got %d, want %d",
			len(mlExtSeed), common.ExtendedSeedSize)
	}
	if len(sphincsExtSeed) != common.ExtendedSeedSize {
		t.Errorf("SPHINCS+ extended seed size: got %d, want %d",
			len(sphincsExtSeed), common.ExtendedSeedSize)
	}

	// Verify descriptor bytes differ
	mlDescBytes := mlExtSeed.GetDescriptorBytes()
	sphincsDescBytes := sphincsExtSeed.GetDescriptorBytes()

	if mlDescBytes[0] == sphincsDescBytes[0] {
		t.Error("extended seed descriptor type bytes should differ")
	}

	// Verify cross-algorithm extended seed recovery fails
	_, err = ml_dsa_wallet.NewWalletFromExtendedSeed(sphincsExtSeed)
	if err == nil {
		t.Error("ML-DSA wallet from SPHINCS+ extended seed should fail")
	}

	_, err = sphincs_wallet.NewWalletFromExtendedSeed(mlExtSeed)
	if err == nil {
		t.Error("SPHINCS+ wallet from ML-DSA extended seed should fail")
	}
}

// TestHexSeedRoundTrip verifies hex seed encoding/decoding works for both algorithms.
func TestHexSeedRoundTrip(t *testing.T) {
	t.Run("ML-DSA-87", func(t *testing.T) {
		original, err := ml_dsa_wallet.NewWallet()
		if err != nil {
			t.Fatalf("failed to create wallet: %v", err)
		}
		hexSeed, err := original.GetHexSeed()
		if err != nil {
			t.Fatalf("GetHexSeed() error: %v", err)
		}

		recovered, err := ml_dsa_wallet.NewWalletFromHexExtendedSeed(hexSeed[2:]) // trim 0x
		if err != nil {
			t.Fatalf("failed to recover from hex seed: %v", err)
		}

		if original.GetAddress() != recovered.GetAddress() {
			t.Error("recovered wallet address should match original")
		}
	})

	t.Run("SPHINCS+", func(t *testing.T) {
		original, err := sphincs_wallet.NewWallet()
		if err != nil {
			t.Fatalf("failed to create wallet: %v", err)
		}
		hexSeed, err := original.GetHexSeed()
		if err != nil {
			t.Fatalf("GetHexSeed() error: %v", err)
		}

		recovered, err := sphincs_wallet.NewWalletFromHexExtendedSeed(hexSeed[2:])
		if err != nil {
			t.Fatalf("failed to recover from hex seed: %v", err)
		}

		if original.GetAddress() != recovered.GetAddress() {
			t.Error("recovered wallet address should match original")
		}
	})
}

// TestSignVerifyRoundTrip performs comprehensive sign/verify round-trips
// for both algorithms with various message sizes.
func TestSignVerifyRoundTrip(t *testing.T) {
	messageSizes := []int{0, 1, 32, 256, 1024, 65536}

	t.Run("ML-DSA-87", func(t *testing.T) {
		wallet, _ := ml_dsa_wallet.NewWallet()
		pk := wallet.GetPK()
		desc := wallet.GetDescriptor().ToDescriptor()

		for _, size := range messageSizes {
			msg := make([]byte, size)
			for i := range msg {
				msg[i] = byte(i)
			}

			sig, err := wallet.Sign(msg)
			if err != nil {
				t.Fatalf("sign failed for size %d: %v", size, err)
			}

			if !ml_dsa_wallet.Verify(msg, sig[:], &pk, desc) {
				t.Errorf("verify failed for message size %d", size)
			}

			// Tampered message should fail
			if size > 0 {
				msg[0] ^= 0xFF
				if ml_dsa_wallet.Verify(msg, sig[:], &pk, desc) {
					t.Errorf("tampered message should fail verification (size %d)", size)
				}
			}
		}
	})

	t.Run("SPHINCS+", func(t *testing.T) {
		wallet, _ := sphincs_wallet.NewWallet()
		pk := wallet.GetPK()
		desc := wallet.GetDescriptor().ToDescriptor()

		// Use smaller sizes for SPHINCS+ due to slower signing
		smallSizes := []int{0, 1, 32, 256}

		for _, size := range smallSizes {
			msg := make([]byte, size)
			for i := range msg {
				msg[i] = byte(i)
			}

			sig, err := wallet.Sign(msg)
			if err != nil {
				t.Fatalf("sign failed for size %d: %v", size, err)
			}

			if !sphincs_wallet.Verify(msg, sig[:], &pk, desc) {
				t.Errorf("verify failed for message size %d", size)
			}

			// Tampered message should fail
			if size > 0 {
				msg[0] ^= 0xFF
				if sphincs_wallet.Verify(msg, sig[:], &pk, desc) {
					t.Errorf("tampered message should fail verification (size %d)", size)
				}
			}
		}
	})
}

// TestDeterministicKeyGeneration verifies that the same seed always produces
// the same keys for each algorithm.
func TestDeterministicKeyGeneration(t *testing.T) {
	var seed common.Seed
	for i := range seed {
		seed[i] = byte(i * 7) // deterministic pattern
	}

	t.Run("ML-DSA-87", func(t *testing.T) {
		wallet1, _ := ml_dsa_wallet.NewWalletFromSeed(seed)
		wallet2, _ := ml_dsa_wallet.NewWalletFromSeed(seed)

		if wallet1.GetPK() != wallet2.GetPK() {
			t.Error("same seed should produce same public key")
		}
		if wallet1.GetSK() != wallet2.GetSK() {
			t.Error("same seed should produce same secret key")
		}
		if wallet1.GetAddress() != wallet2.GetAddress() {
			t.Error("same seed should produce same address")
		}
	})

	t.Run("SPHINCS+", func(t *testing.T) {
		wallet1, _ := sphincs_wallet.NewWalletFromSeed(seed)
		wallet2, _ := sphincs_wallet.NewWalletFromSeed(seed)

		if wallet1.GetPK() != wallet2.GetPK() {
			t.Error("same seed should produce same public key")
		}
		if wallet1.GetSK() != wallet2.GetSK() {
			t.Error("same seed should produce same secret key")
		}
		if wallet1.GetAddress() != wallet2.GetAddress() {
			t.Error("same seed should produce same address")
		}
	})
}

// TestWalletTypeConstants verifies wallet type enumeration values.
func TestWalletTypeConstants(t *testing.T) {
	// SPHINCSPLUS_256S should be 0, ML_DSA_87 should be 1
	if wallettype.SPHINCSPLUS_256S != 0 {
		t.Errorf("SPHINCSPLUS_256S should be 0, got %d", wallettype.SPHINCSPLUS_256S)
	}
	if wallettype.ML_DSA_87 != 1 {
		t.Errorf("ML_DSA_87 should be 1, got %d", wallettype.ML_DSA_87)
	}

	// Verify string representations
	if wallettype.SPHINCSPLUS_256S.String() != "SPHINCSPLUS_256S" {
		t.Errorf("unexpected string: %s", wallettype.SPHINCSPLUS_256S.String())
	}
	if wallettype.ML_DSA_87.String() != "ML_DSA_87" {
		t.Errorf("unexpected string: %s", wallettype.ML_DSA_87.String())
	}

	// Verify validity
	if !wallettype.SPHINCSPLUS_256S.IsValid() {
		t.Error("SPHINCSPLUS_256S should be valid")
	}
	if !wallettype.ML_DSA_87.IsValid() {
		t.Error("ML_DSA_87 should be valid")
	}
	if wallettype.InvalidWalletType.IsValid() {
		t.Error("InvalidWalletType should not be valid")
	}
}

// TestSignatureDeterminism documents the determinism properties of each algorithm.
// ML-DSA-87 is deterministic (same message + key = same signature).
// SPHINCS+ uses randomized signing for additional security (hedged signatures).
func TestSignatureDeterminism(t *testing.T) {
	message := []byte("determinism test")

	t.Run("ML-DSA-87_deterministic", func(t *testing.T) {
		var seed common.Seed
		wallet, _ := ml_dsa_wallet.NewWalletFromSeed(seed)

		sig1, _ := wallet.Sign(message)
		sig2, _ := wallet.Sign(message)

		// ML-DSA-87 uses deterministic signing (no randomness)
		if sig1 != sig2 {
			t.Error("ML-DSA-87 signatures should be deterministic")
		}
	})

	t.Run("SPHINCS+_randomized", func(t *testing.T) {
		var seed common.Seed
		wallet, _ := sphincs_wallet.NewWalletFromSeed(seed)
		pk := wallet.GetPK()
		desc := wallet.GetDescriptor().ToDescriptor()

		sig1, _ := wallet.Sign(message)
		sig2, _ := wallet.Sign(message)

		// SPHINCS+ uses randomized signing (hedged signatures) for additional security
		// Signatures should differ but both should verify correctly
		if sig1 == sig2 {
			t.Log("Warning: SPHINCS+ signatures were identical (extremely unlikely)")
		}

		// Both signatures must be valid
		if !sphincs_wallet.Verify(message, sig1[:], &pk, desc) {
			t.Error("first SPHINCS+ signature should verify")
		}
		if !sphincs_wallet.Verify(message, sig2[:], &pk, desc) {
			t.Error("second SPHINCS+ signature should verify")
		}
	})
}

// TestInvalidDescriptorRejection verifies that invalid descriptors are rejected.
func TestInvalidDescriptorRejection(t *testing.T) {
	wallet, _ := ml_dsa_wallet.NewWallet()
	message := []byte("test")
	sig, _ := wallet.Sign(message)
	pk := wallet.GetPK()

	// Valid descriptor should work
	validDesc := wallet.GetDescriptor().ToDescriptor()
	if !ml_dsa_wallet.Verify(message, sig[:], &pk, validDesc) {
		t.Error("valid descriptor should verify")
	}

	// Wrong algorithm type in descriptor should fail
	wrongTypeDesc := descriptor.Descriptor{byte(wallettype.SPHINCSPLUS_256S), 0, 0}
	if ml_dsa_wallet.Verify(message, sig[:], &pk, wrongTypeDesc) {
		t.Error("wrong descriptor type should fail verification")
	}

	// Invalid descriptor type should fail
	invalidDesc := descriptor.Descriptor{255, 0, 0}
	if ml_dsa_wallet.Verify(message, sig[:], &pk, invalidDesc) {
		t.Error("invalid descriptor should fail verification")
	}
}

// TestSignatureSizeRejection verifies that signatures with wrong sizes are rejected.
func TestSignatureSizeRejection(t *testing.T) {
	t.Run("ML-DSA-87", func(t *testing.T) {
		wallet, _ := ml_dsa_wallet.NewWallet()
		pk := wallet.GetPK()
		desc := wallet.GetDescriptor().ToDescriptor()
		message := []byte("test")

		// Too short signature
		shortSig := make([]byte, ml_dsa_wallet.SigSize-1)
		if ml_dsa_wallet.Verify(message, shortSig, &pk, desc) {
			t.Error("short signature should fail")
		}

		// Too long signature
		longSig := make([]byte, ml_dsa_wallet.SigSize+1)
		if ml_dsa_wallet.Verify(message, longSig, &pk, desc) {
			t.Error("long signature should fail")
		}
	})

	t.Run("SPHINCS+", func(t *testing.T) {
		wallet, _ := sphincs_wallet.NewWallet()
		pk := wallet.GetPK()
		desc := wallet.GetDescriptor().ToDescriptor()
		message := []byte("test")

		// Too short signature
		shortSig := make([]byte, sphincs_wallet.SigSize-1)
		if sphincs_wallet.Verify(message, shortSig, &pk, desc) {
			t.Error("short signature should fail")
		}

		// Too long signature
		longSig := make([]byte, sphincs_wallet.SigSize+1)
		if sphincs_wallet.Verify(message, longSig, &pk, desc) {
			t.Error("long signature should fail")
		}
	})
}
