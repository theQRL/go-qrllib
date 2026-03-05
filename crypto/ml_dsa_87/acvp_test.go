//go:build acvp

package ml_dsa_87

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// NIST ACVP test vector verification for ML-DSA-87.
//
// These tests validate key generation and deterministic signature generation
// against official NIST ACVP test vectors. Guarded by the "acvp" build tag
// so they only run in CI or when explicitly requested.
//
// See .github/acvp/README.md for setup, local usage, and vector format details.

func acvpVectorsDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("ACVP_VECTORS_DIR")
	if dir == "" {
		t.Skip("ACVP_VECTORS_DIR not set; skipping ACVP tests. See acvp_test.go for instructions.")
	}
	return dir
}

type acvpKeyGenVector struct {
	TcID int    `json:"tcId"`
	Seed string `json:"seed"`
	PK   string `json:"pk"`
	SK   string `json:"sk"`
}

type acvpSigGenVector struct {
	TcID      int    `json:"tcId"`
	SK        string `json:"sk"`
	Message   string `json:"message"`
	Context   string `json:"context"`
	Signature string `json:"signature"`
}

// TestACVPKeyGen verifies that key generation from seed produces byte-exact
// matches against NIST ACVP expected public and secret keys.
func TestACVPKeyGen(t *testing.T) {
	dir := acvpVectorsDir(t)

	data, err := os.ReadFile(filepath.Join(dir, "keygen.json"))
	if err != nil {
		t.Fatalf("Failed to read keygen.json: %v", err)
	}

	var vectors []acvpKeyGenVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse keygen.json: %v", err)
	}

	if len(vectors) == 0 {
		t.Fatal("No keygen test vectors found")
	}

	t.Logf("Running %d ACVP keygen test vectors", len(vectors))

	for _, vec := range vectors {
		t.Run(fmt.Sprintf("tc%d", vec.TcID), func(t *testing.T) {
			seedBytes, err := hex.DecodeString(vec.Seed)
			if err != nil {
				t.Fatalf("Invalid seed hex: %v", err)
			}
			if len(seedBytes) != SEED_BYTES {
				t.Fatalf("Seed length %d, expected %d", len(seedBytes), SEED_BYTES)
			}

			expectedPK, err := hex.DecodeString(vec.PK)
			if err != nil {
				t.Fatalf("Invalid pk hex: %v", err)
			}
			expectedSK, err := hex.DecodeString(vec.SK)
			if err != nil {
				t.Fatalf("Invalid sk hex: %v", err)
			}

			var seed [SEED_BYTES]uint8
			copy(seed[:], seedBytes)

			var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
			var sk [CRYPTO_SECRET_KEY_BYTES]uint8

			if _, err := cryptoSignKeypair(&seed, &pk, &sk); err != nil {
				t.Fatalf("cryptoSignKeypair failed: %v", err)
			}

			if !bytes.Equal(pk[:], expectedPK) {
				t.Errorf("Public key mismatch\n  got:  %s...\n  want: %s...",
					hex.EncodeToString(pk[:32]), hex.EncodeToString(expectedPK[:32]))
			}

			if !bytes.Equal(sk[:], expectedSK) {
				t.Errorf("Secret key mismatch\n  got:  %s...\n  want: %s...",
					hex.EncodeToString(sk[:32]), hex.EncodeToString(expectedSK[:32]))
			}
		})
	}
}

// TestACVPSigGen verifies that deterministic signature generation produces
// byte-exact matches against NIST ACVP expected signatures.
//
// Only deterministic, external-interface, pure (non-preHash) vectors are tested,
// as go-qrllib implements deterministic pure ML-DSA signing.
func TestACVPSigGen(t *testing.T) {
	dir := acvpVectorsDir(t)

	data, err := os.ReadFile(filepath.Join(dir, "siggen.json"))
	if err != nil {
		t.Fatalf("Failed to read siggen.json: %v", err)
	}

	var vectors []acvpSigGenVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse siggen.json: %v", err)
	}

	if len(vectors) == 0 {
		t.Fatal("No siggen test vectors found")
	}

	t.Logf("Running %d ACVP siggen test vectors", len(vectors))

	for _, vec := range vectors {
		t.Run(fmt.Sprintf("tc%d", vec.TcID), func(t *testing.T) {
			skBytes, err := hex.DecodeString(vec.SK)
			if err != nil {
				t.Fatalf("Invalid sk hex: %v", err)
			}
			if len(skBytes) != CRYPTO_SECRET_KEY_BYTES {
				t.Fatalf("SK length %d, expected %d", len(skBytes), CRYPTO_SECRET_KEY_BYTES)
			}

			msg, err := hex.DecodeString(vec.Message)
			if err != nil {
				t.Fatalf("Invalid message hex: %v", err)
			}

			ctx, err := hex.DecodeString(vec.Context)
			if err != nil {
				t.Fatalf("Invalid context hex: %v", err)
			}

			expectedSig, err := hex.DecodeString(vec.Signature)
			if err != nil {
				t.Fatalf("Invalid signature hex: %v", err)
			}

			var sk [CRYPTO_SECRET_KEY_BYTES]uint8
			copy(sk[:], skBytes)

			// Deterministic signing: rnd is all zeros, context encoded as
			// FIPS 204 domain separation prefix [0x00, len(ctx), ctx...]
			sig := make([]uint8, CRYPTO_BYTES)
			if err := cryptoSignSignature(sig, msg, ctx, &sk, false); err != nil {
				t.Fatalf("cryptoSignSignature failed: %v", err)
			}

			if !bytes.Equal(sig, expectedSig) {
				t.Errorf("Signature mismatch\n  got:  %s...\n  want: %s...",
					hex.EncodeToString(sig[:32]), hex.EncodeToString(expectedSig[:32]))
			}

			// Also verify the signature we produced is valid
			// Extract pk from the sk (first 32 bytes of sk is rho, which is
			// also the first 32 bytes of pk, but we need the full pk).
			// Regenerate pk from sk by re-deriving from the components.
			// Simpler: just verify using the sign-then-verify path.
			var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
			var rho [SEED_BYTES]uint8
			var tr [TR_BYTES]uint8
			var key [SEED_BYTES]uint8
			var t0 polyVecK
			var s1 polyVecL
			var s2 polyVecK

			unpackSk(&rho, &tr, &key, &t0, &s1, &s2, &sk)

			// Reconstruct pk from rho and t1 (t1 = power2round(A*s1+s2).high)
			var s1hat polyVecL
			var mat [K]polyVecL
			var t1 polyVecK

			s1hat = s1
			polyVecLNTT(&s1hat)
			_ = polyVecMatrixExpand(&mat, &rho)
			polyVecMatrixPointWiseMontgomery(&t1, &mat, &s1hat)
			polyVecKReduce(&t1)
			polyVecKInvNTTToMont(&t1)
			polyVecKAdd(&t1, &t1, &s2)
			polyVecKCAddQ(&t1)

			var t0Discard polyVecK
			polyVecKPower2Round(&t1, &t0Discard, &t1)
			packPk(&pk, rho, &t1)

			var sigArr [CRYPTO_BYTES]uint8
			copy(sigArr[:], sig)
			if !Verify(ctx, msg, sigArr, &pk) {
				t.Error("Generated signature failed verification")
			}
		})
	}
}
