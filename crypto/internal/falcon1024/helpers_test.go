package falcon1024

import (
	"encoding/hex"
	"slices"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/internal/testutil"
)

func requireEqualWords(t *testing.T, name string, got, want []uint32) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustDecodeSmallPolynomialHex(t *testing.T, s string) smallPolynomial {
	t.Helper()
	b := mustDecodeHex(t, s)
	if len(b) != n {
		t.Fatalf("decoded polynomial length = %d, want %d", len(b), n)
	}
	var p smallPolynomial
	for i, v := range b {
		p[i] = int32(int8(v))
	}
	return p
}

type signTreeRound3KATVector struct {
	Count            int    `json:"count"`
	CompressedLength int    `json:"compressedLength"`
	CompressedSHA256 string `json:"compressedSHA256"`
}

func readSignTreeRound3KATVectors(t *testing.T) []signTreeRound3KATVector {
	t.Helper()

	vectors := testutil.ReadJSON[[]signTreeRound3KATVector](t, "testdata", "sign_tree_round3_kat.json.gz")
	if len(vectors) != 100 {
		t.Fatalf("sign tree Round 3 KAT vector count = %d, want 100", len(vectors))
	}

	return vectors
}

type verifyRawKATFixture struct {
	PublicKeyHex string               `json:"publicKeyHex"`
	Tests        []verifyRawKATVector `json:"tests"`
}

type verifyRawKATVector struct {
	NonceHex     string `json:"nonceHex"`
	Message      string `json:"message"`
	SignatureHex string `json:"signatureHex"`
}

func readVerifyRawKATFixture(t *testing.T) verifyRawKATFixture {
	t.Helper()

	vectors := testutil.ReadJSON[verifyRawKATFixture](t, "testdata", "verify_raw_kat.json.gz")
	if vectors.PublicKeyHex == "" {
		t.Fatal("verify_raw KAT public key is empty")
	}
	if len(vectors.Tests) != 10 {
		t.Fatalf("verify_raw KAT vector count = %d, want 10", len(vectors.Tests))
	}

	return vectors
}

func referencePublicKeyBytes(t *testing.T) []byte {
	t.Helper()
	return mustDecodeHex(t, readVerifyRawKATFixture(t).PublicKeyHex)
}

func decodeVerifyRawKATS2(t *testing.T, sig []byte) smallPolynomial {
	t.Helper()
	if len(sig) != 1+2*n {
		t.Fatalf("bad KAT signature length: got %d", len(sig))
	}
	if sig[0] != logN {
		t.Fatalf("bad KAT signature header: got %#x", sig[0])
	}

	var s2 smallPolynomial
	for i := range s2 {
		j := 1 + 2*i
		s2[i] = int32(int16(uint16(sig[j])<<8 | uint16(sig[j+1])))
	}
	return s2
}
