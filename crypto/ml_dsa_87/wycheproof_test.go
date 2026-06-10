//go:build wycheproof

package ml_dsa_87

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Wycheproof ML-DSA-87 test vector verification.
//
// These tests exercise the ML-DSA-87 verifier against the C2SP/wycheproof
// project's edge-case test vectors — covering signature malleability,
// truncated/extended signatures, public-key edge cases, and similar
// boundary conditions that complement NIST ACVP's correctness coverage.
//
// Guarded by the "wycheproof" build tag so they only run in CI or when
// explicitly requested. See .github/wycheproof/README.md for setup,
// local usage, and vector source.

func wycheproofVectorsDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("WYCHEPROOF_VECTORS_DIR")
	if dir == "" {
		t.Skip("WYCHEPROOF_VECTORS_DIR not set; skipping Wycheproof tests. See wycheproof_test.go for instructions.")
	}
	return dir
}

// wycheproofVerifyTestFile mirrors the schema at
// schemas/mldsa_verify_schema.json in the wycheproof repo. Only the
// fields we consume are modelled; unknown fields are ignored.
type wycheproofVerifyTestFile struct {
	Algorithm     string `json:"algorithm"`
	NumberOfTests int    `json:"numberOfTests"`
	TestGroups    []struct {
		Type      string `json:"type"`
		PublicKey string `json:"publicKey"`
		Tests     []struct {
			TcID    int      `json:"tcId"`
			Comment string   `json:"comment"`
			Msg     string   `json:"msg"`
			Ctx     string   `json:"ctx"` // optional; "" when absent
			Sig     string   `json:"sig"`
			Result  string   `json:"result"` // "valid" | "invalid" | "acceptable"
			Flags   []string `json:"flags"`
		} `json:"tests"`
	} `json:"testGroups"`
}

// TestWycheproofVerify runs the ML-DSA-87 Verify path against every
// vector in mldsa_87_verify_test.json. Each test specifies an expected
// outcome; we assert that go-qrllib's Verify matches:
//
//   - "valid":      Verify must return true.
//   - "invalid":    Verify must return false (or the caller-side
//     length checks must reject the input).
//   - "acceptable": Either outcome is allowed by the spec; we record
//     what we observed but do not fail.
func TestWycheproofVerify(t *testing.T) {
	dir := wycheproofVectorsDir(t)

	path := filepath.Join(dir, "mldsa_87_verify_test.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var file wycheproofVerifyTestFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	if file.Algorithm != "ML-DSA-87" {
		t.Fatalf("unexpected algorithm %q (want ML-DSA-87)", file.Algorithm)
	}
	if len(file.TestGroups) == 0 {
		t.Fatal("no test groups in verify file")
	}

	t.Logf("Running Wycheproof ML-DSA-87 Verify: %d groups, %d total tests",
		len(file.TestGroups), file.NumberOfTests)

	var totalPass, totalFail, totalSkip, totalAcceptable int

	for gi, group := range file.TestGroups {
		if group.Type != "MlDsaVerify" {
			t.Logf("group %d: skipping unrecognised type %q", gi, group.Type)
			continue
		}

		pkBytes, err := hex.DecodeString(group.PublicKey)
		if err != nil {
			t.Errorf("group %d: invalid publicKey hex: %v", gi, err)
			continue
		}

		// Wycheproof groups occasionally include malformed-pk groups
		// to test that verifiers reject them. If the pk length doesn't
		// match the ML-DSA-87 expectation, every test in the group
		// should be "invalid" — we assert that and continue.
		var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
		pkLengthOK := len(pkBytes) == CRYPTO_PUBLIC_KEY_BYTES
		if pkLengthOK {
			copy(pk[:], pkBytes)
		}

		for _, tc := range group.Tests {
			name := fmt.Sprintf("g%d_tc%d_%s", gi, tc.TcID, sanitize(tc.Comment))
			t.Run(name, func(t *testing.T) {
				msg, err := hex.DecodeString(tc.Msg)
				if err != nil {
					t.Fatalf("invalid msg hex: %v", err)
				}
				sig, err := hex.DecodeString(tc.Sig)
				if err != nil {
					t.Fatalf("invalid sig hex: %v", err)
				}
				ctx, err := hex.DecodeString(tc.Ctx)
				if err != nil {
					t.Fatalf("invalid ctx hex: %v", err)
				}

				var ok bool
				switch {
				case !pkLengthOK:
					// Group-wide bad pk; Verify can't be called with a
					// fixed-size array, so the API-level rejection is
					// "we'd never accept this". Treat as not-verified.
					ok = false
				case len(sig) != CRYPTO_BYTES:
					// Wycheproof exercises wrong-length signatures.
					// go-qrllib's Verify requires a fixed-size array,
					// so a wrong-length sig is rejected at the API
					// boundary. Mirror that here.
					ok = false
				default:
					var sigArr [CRYPTO_BYTES]uint8
					copy(sigArr[:], sig)
					ok = Verify(ctx, msg, sigArr, &pk)
				}

				switch tc.Result {
				case "valid":
					if !ok {
						totalFail++
						t.Errorf("expected valid; Verify returned false. comment=%q flags=%v",
							tc.Comment, tc.Flags)
					} else {
						totalPass++
					}
				case "invalid":
					if ok {
						totalFail++
						t.Errorf("expected invalid; Verify returned true. comment=%q flags=%v",
							tc.Comment, tc.Flags)
					} else {
						totalPass++
					}
				case "acceptable":
					// Spec allows either outcome — record but don't fail.
					totalAcceptable++
					t.Logf("acceptable (observed=%v): comment=%q flags=%v", ok, tc.Comment, tc.Flags)
				default:
					totalSkip++
					t.Skipf("unknown result %q", tc.Result)
				}
			})
		}
	}

	t.Logf("Wycheproof ML-DSA-87 Verify summary: pass=%d fail=%d acceptable=%d skip=%d",
		totalPass, totalFail, totalAcceptable, totalSkip)
}

// sanitize replaces characters that aren't friendly in Go subtest names
// with underscores, keeping the comment readable but valid.
func sanitize(s string) string {
	if s == "" {
		return "case"
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s) && i < 40; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}
