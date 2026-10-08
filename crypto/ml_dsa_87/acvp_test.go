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
// These tests validate key generation, signature generation and signature
// verification against official NIST ACVP test vectors. Guarded by the
// "acvp" build tag so they only run in CI or when explicitly requested.
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

func acvpLoad[T any](t *testing.T, dir, name string) []T {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("Failed to read %s: %v", name, err)
	}
	var vectors []T
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse %s: %v", name, err)
	}
	if len(vectors) == 0 {
		t.Fatalf("No test vectors found in %s", name)
	}
	return vectors
}

func acvpHex(t *testing.T, field, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("Invalid %s hex: %v", field, err)
	}
	return b
}

type acvpKeyGenVector struct {
	TcID int    `json:"tcId"`
	Seed string `json:"seed"`
	PK   string `json:"pk"`
	SK   string `json:"sk"`
}

type acvpSigGenVector struct {
	TcID          int    `json:"tcId"`
	Deterministic bool   `json:"deterministic"`
	Interface     string `json:"signatureInterface"`
	SK            string `json:"sk"`
	Message       string `json:"message"`
	Context       string `json:"context"`
	Rnd           string `json:"rnd"`
	Signature     string `json:"signature"`
}

type acvpSigVerVector struct {
	TcID       int    `json:"tcId"`
	Interface  string `json:"signatureInterface"`
	PK         string `json:"pk"`
	Message    string `json:"message"`
	Context    string `json:"context"`
	Signature  string `json:"signature"`
	TestPassed bool   `json:"testPassed"`
}

// TestACVPKeyGen verifies that key generation from seed produces byte-exact
// matches against NIST ACVP expected public and secret keys.
func TestACVPKeyGen(t *testing.T) {
	vectors := acvpLoad[acvpKeyGenVector](t, acvpVectorsDir(t), "keygen.json")
	t.Logf("Running %d ACVP keygen test vectors", len(vectors))

	for _, vec := range vectors {
		t.Run(fmt.Sprintf("tc%d", vec.TcID), func(t *testing.T) {
			seedBytes := acvpHex(t, "seed", vec.Seed)
			if len(seedBytes) != SEED_BYTES {
				t.Fatalf("Seed length %d, expected %d", len(seedBytes), SEED_BYTES)
			}
			expectedPK := acvpHex(t, "pk", vec.PK)
			expectedSK := acvpHex(t, "sk", vec.SK)

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

// acvpPublicKeyFromSecretKey rebuilds the public key a secret key belongs
// to: t1 is the high part of A*s1 + s2, as in key generation.
func acvpPublicKeyFromSecretKey(sk *[CRYPTO_SECRET_KEY_BYTES]uint8) [CRYPTO_PUBLIC_KEY_BYTES]uint8 {
	var rho [SEED_BYTES]uint8
	var tr [TR_BYTES]uint8
	var key [SEED_BYTES]uint8
	var t0 polyVecK
	var s1 polyVecL
	var s2 polyVecK
	unpackSk(&rho, &tr, &key, &t0, &s1, &s2, sk)

	var mat [K]polyVecL
	var t1 polyVecK
	s1hat := s1
	polyVecLNTT(&s1hat)
	_ = polyVecMatrixExpand(&mat, &rho)
	polyVecMatrixPointWiseMontgomery(&t1, &mat, &s1hat)
	polyVecKReduce(&t1)
	polyVecKInvNTTToMont(&t1)
	polyVecKAdd(&t1, &t1, &s2)
	polyVecKCAddQ(&t1)

	var t0Discard polyVecK
	polyVecKPower2Round(&t1, &t0Discard, &t1)

	var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
	packPk(&pk, rho, &t1)
	return pk
}

// TestACVPSigGen verifies that signature generation produces byte-exact
// matches against NIST ACVP expected signatures, for the deterministic
// variant (rnd = zero) and the hedged variant with the rnd NIST supplies,
// through both the external interface (M' = 0x00 || |ctx| || ctx || M) and
// the internal interface (M' as given). The pre-hash and external-mu groups
// are not part of the vectors, as the implementation does not offer them.
//
// Public signing is hedged with crypto/rand, so the vectors are reproduced
// through the unexported entry points that take an explicit rnd.
func TestACVPSigGen(t *testing.T) {
	vectors := acvpLoad[acvpSigGenVector](t, acvpVectorsDir(t), "siggen.json")
	t.Logf("Running %d ACVP siggen test vectors", len(vectors))

	for _, vec := range vectors {
		t.Run(fmt.Sprintf("tc%d", vec.TcID), func(t *testing.T) {
			skBytes := acvpHex(t, "sk", vec.SK)
			if len(skBytes) != CRYPTO_SECRET_KEY_BYTES {
				t.Fatalf("SK length %d, expected %d", len(skBytes), CRYPTO_SECRET_KEY_BYTES)
			}
			msg := acvpHex(t, "message", vec.Message)
			ctx := acvpHex(t, "context", vec.Context)
			expectedSig := acvpHex(t, "signature", vec.Signature)

			var sk [CRYPTO_SECRET_KEY_BYTES]uint8
			copy(sk[:], skBytes)

			var rnd [RND_BYTES]uint8 // zero: the FIPS 204 deterministic variant
			if !vec.Deterministic {
				rndBytes := acvpHex(t, "rnd", vec.Rnd)
				if len(rndBytes) != RND_BYTES {
					t.Fatalf("rnd length %d, expected %d", len(rndBytes), RND_BYTES)
				}
				copy(rnd[:], rndBytes)
			}

			sig := make([]uint8, CRYPTO_BYTES)
			var err error
			switch vec.Interface {
			case "external":
				err = cryptoSignSignatureWithRnd(sig, msg, ctx, &sk, rnd)
			case "internal":
				err = cryptoSignSignatureInternal(sig, msg, nil, rnd, &sk)
			default:
				t.Fatalf("unsupported signature interface %q", vec.Interface)
			}
			if err != nil {
				t.Fatalf("signing failed: %v", err)
			}

			if !bytes.Equal(sig, expectedSig) {
				t.Errorf("Signature mismatch\n  got:  %s...\n  want: %s...",
					hex.EncodeToString(sig[:32]), hex.EncodeToString(expectedSig[:32]))
			}

			// The signature must also verify under the key's public key.
			pk := acvpPublicKeyFromSecretKey(&sk)
			if err := ValidatePublicKey(&pk); err != nil {
				t.Errorf("NIST key rejected by ValidatePublicKey: %v", err)
			}
			var sigArr [CRYPTO_BYTES]uint8
			copy(sigArr[:], sig)
			var ok bool
			if vec.Interface == "external" {
				ok = Verify(ctx, msg, sigArr, &pk)
			} else {
				ok, err = cryptoSignVerifyInternal(sigArr, msg, nil, &pk)
				if err != nil {
					t.Fatalf("verification failed: %v", err)
				}
			}
			if !ok {
				t.Error("Generated signature failed verification")
			}
		})
	}
}

// TestACVPSigVer verifies that signature verification reaches NIST's verdict
// on every ACVP sigVer vector, valid and invalid alike, through the external
// and the internal interface.
func TestACVPSigVer(t *testing.T) {
	vectors := acvpLoad[acvpSigVerVector](t, acvpVectorsDir(t), "sigver.json")
	t.Logf("Running %d ACVP sigver test vectors", len(vectors))

	for _, vec := range vectors {
		t.Run(fmt.Sprintf("tc%d", vec.TcID), func(t *testing.T) {
			pkBytes := acvpHex(t, "pk", vec.PK)
			if len(pkBytes) != CRYPTO_PUBLIC_KEY_BYTES {
				t.Fatalf("PK length %d, expected %d", len(pkBytes), CRYPTO_PUBLIC_KEY_BYTES)
			}
			msg := acvpHex(t, "message", vec.Message)
			ctx := acvpHex(t, "context", vec.Context)
			sigBytes := acvpHex(t, "signature", vec.Signature)

			var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
			copy(pk[:], pkBytes)

			// A signature of the wrong length is invalid (FIPS 204 §3.6.2);
			// the fixed-size signature type enforces this for callers.
			got := false
			if len(sigBytes) == CRYPTO_BYTES {
				var sig [CRYPTO_BYTES]uint8
				copy(sig[:], sigBytes)
				switch vec.Interface {
				case "external":
					got = Verify(ctx, msg, sig, &pk)
				case "internal":
					ok, err := cryptoSignVerifyInternal(sig, msg, nil, &pk)
					got = err == nil && ok
				default:
					t.Fatalf("unsupported signature interface %q", vec.Interface)
				}
			}

			if got != vec.TestPassed {
				t.Errorf("Verification = %v, NIST expects %v", got, vec.TestPassed)
			}
		})
	}
}
