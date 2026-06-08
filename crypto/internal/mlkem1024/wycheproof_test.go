//go:build wycheproof

package mlkem1024

// Wycheproof / CCTV ML-KEM-1024 vector verification.
//
// This mirrors the ML-DSA-87 harness in crypto/ml_dsa_87/wycheproof_test.go.
// Vectors are consumed directly from upstream at CI time (never vendored):
//
//   - C2SP/wycheproof  testvectors_v1/mlkem_1024_{keygen_seed,encaps,test}_test.json
//     via WYCHEPROOF_VECTORS_DIR
//   - C2SP/CCTV         ML-KEM/modulus/ML-KEM-1024.txt.gz
//     via CCTV_VECTORS_DIR
//
// Guarded by the "wycheproof" build tag so they don't run during normal
// `go test ./...`. See .github/wycheproof/README.md for setup and provenance.
//
// The tests live in the internal package because the wycheproof encapsulation
// vectors are derandomized (they fix the message m), which requires the
// test-only EncapsulateInternal entry point.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func wycheproofDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("WYCHEPROOF_VECTORS_DIR")
	if dir == "" {
		t.Skip("WYCHEPROOF_VECTORS_DIR not set; skipping ML-KEM Wycheproof tests. See .github/wycheproof/README.md.")
	}
	return dir
}

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}

func hasFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

// TestWycheproofMLKEMKeyGen checks seed -> encapsulation-key derivation against
// mlkem_1024_keygen_seed_test.json.
func TestWycheproofMLKEMKeyGen(t *testing.T) {
	dir := wycheproofDir(t)
	var f struct {
		Algorithm  string `json:"algorithm"`
		TestGroups []struct {
			ParameterSet string `json:"parameterSet"`
			Tests        []struct {
				TcID   int    `json:"tcId"`
				Seed   string `json:"seed"`
				EK     string `json:"ek"`
				Result string `json:"result"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	loadJSON(t, filepath.Join(dir, "mlkem_1024_keygen_seed_test.json"), &f)
	if f.Algorithm != "ML-KEM" {
		t.Fatalf("unexpected algorithm %q (want ML-KEM)", f.Algorithm)
	}

	var pass, fail, n int
	for _, g := range f.TestGroups {
		if g.ParameterSet != "ML-KEM-1024" {
			continue
		}
		for _, tc := range g.Tests {
			n++
			dk, err := NewDecapsulationKey(mustHex(t, tc.Seed))
			switch tc.Result {
			case "valid":
				if err != nil {
					t.Errorf("tc%d: NewDecapsulationKey: %v", tc.TcID, err)
					fail++
					continue
				}
				if !bytes.Equal(dk.EncapsulationKey().Bytes(), mustHex(t, tc.EK)) {
					t.Errorf("tc%d: encapsulation-key mismatch", tc.TcID)
					fail++
				} else {
					pass++
				}
			case "invalid":
				if err == nil {
					t.Errorf("tc%d: expected rejection, got nil error", tc.TcID)
					fail++
				} else {
					pass++
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no ML-KEM-1024 keyGen vectors processed")
	}
	t.Logf("Wycheproof ML-KEM-1024 KeyGen: pass=%d fail=%d", pass, fail)
}

// TestWycheproofMLKEMEncaps checks derandomized encapsulation (ek, m -> c, K)
// and encapsulation-key validation against mlkem_1024_encaps_test.json.
func TestWycheproofMLKEMEncaps(t *testing.T) {
	dir := wycheproofDir(t)
	var f struct {
		Algorithm  string `json:"algorithm"`
		TestGroups []struct {
			ParameterSet string `json:"parameterSet"`
			Tests        []struct {
				TcID   int      `json:"tcId"`
				EK     string   `json:"ek"`
				M      string   `json:"m"`
				C      string   `json:"c"`
				K      string   `json:"K"`
				Result string   `json:"result"`
				Flags  []string `json:"flags"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	loadJSON(t, filepath.Join(dir, "mlkem_1024_encaps_test.json"), &f)
	if f.Algorithm != "ML-KEM" {
		t.Fatalf("unexpected algorithm %q (want ML-KEM)", f.Algorithm)
	}

	var pass, fail, n, modulus int
	for _, g := range f.TestGroups {
		if g.ParameterSet != "ML-KEM-1024" {
			continue
		}
		for _, tc := range g.Tests {
			n++
			ek, err := NewEncapsulationKey(mustHex(t, tc.EK))
			switch tc.Result {
			case "valid":
				if err != nil {
					t.Errorf("tc%d: NewEncapsulationKey: %v", tc.TcID, err)
					fail++
					continue
				}
				mb := mustHex(t, tc.M)
				if len(mb) != 32 {
					t.Errorf("tc%d: message length %d (want 32)", tc.TcID, len(mb))
					fail++
					continue
				}
				var m [32]byte
				copy(m[:], mb)
				gotK, gotC := EncapsulateInternal(ek, &m)
				if !bytes.Equal(gotC, mustHex(t, tc.C)) || !bytes.Equal(gotK, mustHex(t, tc.K)) {
					t.Errorf("tc%d: encapsulation mismatch (flags=%v)", tc.TcID, tc.Flags)
					fail++
				} else {
					pass++
				}
			case "invalid":
				if err == nil {
					t.Errorf("tc%d: expected encapsulation-key rejection (flags=%v)", tc.TcID, tc.Flags)
					fail++
				} else {
					pass++
					if hasFlag(tc.Flags, "ModulusOverflow") {
						modulus++
					}
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no ML-KEM-1024 encaps vectors processed")
	}
	t.Logf("Wycheproof ML-KEM-1024 Encaps: pass=%d fail=%d (incl. %d ModulusOverflow rejections)", pass, fail, modulus)
}

// TestWycheproofMLKEMDecaps checks decapsulation (seed, c -> K), including the
// implicit-rejection and Strcmp edge cases, against mlkem_1024_test.json.
func TestWycheproofMLKEMDecaps(t *testing.T) {
	dir := wycheproofDir(t)
	var f struct {
		Algorithm  string `json:"algorithm"`
		TestGroups []struct {
			ParameterSet string `json:"parameterSet"`
			Tests        []struct {
				TcID    int      `json:"tcId"`
				Comment string   `json:"comment"`
				Seed    string   `json:"seed"`
				C       string   `json:"c"`
				K       string   `json:"K"`
				Result  string   `json:"result"`
				Flags   []string `json:"flags"`
			} `json:"tests"`
		} `json:"testGroups"`
	}
	loadJSON(t, filepath.Join(dir, "mlkem_1024_test.json"), &f)
	if f.Algorithm != "ML-KEM" {
		t.Fatalf("unexpected algorithm %q (want ML-KEM)", f.Algorithm)
	}

	var pass, fail, n, strcmp int
	for _, g := range f.TestGroups {
		if g.ParameterSet != "ML-KEM-1024" {
			continue
		}
		for _, tc := range g.Tests {
			n++
			dk, err := NewDecapsulationKey(mustHex(t, tc.Seed))
			ct := mustHex(t, tc.C)
			switch tc.Result {
			case "valid":
				// Includes implicit-rejection cases: a malformed-but-right-length
				// ciphertext must yield the pseudorandom rejection key, never an
				// error. Strcmp-flagged vectors fail if the implicit-rejection
				// comparison is not constant-time / byte-exact.
				if err != nil {
					t.Errorf("tc%d: NewDecapsulationKey: %v", tc.TcID, err)
					fail++
					continue
				}
				gotK, derr := dk.Decapsulate(ct)
				if derr != nil {
					t.Errorf("tc%d: Decapsulate: %v", tc.TcID, derr)
					fail++
					continue
				}
				if !bytes.Equal(gotK, mustHex(t, tc.K)) {
					t.Errorf("tc%d: shared-secret mismatch (comment=%q flags=%v)", tc.TcID, tc.Comment, tc.Flags)
					fail++
				} else {
					pass++
					if hasFlag(tc.Flags, "Strcmp") {
						strcmp++
					}
				}
			case "invalid":
				// Structural rejection (e.g. wrong-length seed or ciphertext)
				// must surface as an error at the API boundary.
				rejected := err != nil
				if !rejected {
					if _, derr := dk.Decapsulate(ct); derr != nil {
						rejected = true
					}
				}
				if rejected {
					pass++
				} else {
					t.Errorf("tc%d: expected rejection (comment=%q)", tc.TcID, tc.Comment)
					fail++
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no ML-KEM-1024 decaps vectors processed")
	}
	t.Logf("Wycheproof ML-KEM-1024 Decaps: pass=%d fail=%d (incl. %d Strcmp implicit-rejection vectors)", pass, fail, strcmp)
}

// TestCCTVMLKEMModulus exhaustively checks that every invalid encapsulation key
// in the C2SP/CCTV modulus vectors (one coefficient forced into [q, 2^12-1] at
// every position) is rejected by NewEncapsulationKey's modulus check.
func TestCCTVMLKEMModulus(t *testing.T) {
	dir := os.Getenv("CCTV_VECTORS_DIR")
	if dir == "" {
		t.Skip("CCTV_VECTORS_DIR not set; skipping CCTV ML-KEM modulus tests. See .github/wycheproof/README.md.")
	}
	path := filepath.Join(dir, "modulus", "ML-KEM-1024.txt.gz")
	fr, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer fr.Close()
	gz, err := gzip.NewReader(fr)
	if err != nil {
		t.Fatalf("gzip %s: %v", path, err)
	}
	defer gz.Close()

	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	var n, rejected int
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		n++
		if _, err := NewEncapsulationKey(mustHex(t, line)); err != nil {
			rejected++
		} else {
			t.Errorf("line %d: invalid (out-of-range coefficient) encapsulation key was ACCEPTED", n)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	if n == 0 {
		t.Fatal("no CCTV ML-KEM-1024 modulus vectors found")
	}
	t.Logf("CCTV ML-KEM-1024 modulus: %d/%d invalid encapsulation keys rejected", rejected, n)
}
