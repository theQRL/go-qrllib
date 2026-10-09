package falcon1024_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	. "github.com/theQRL/go-qrllib/crypto/falcon1024"
	"github.com/theQRL/go-qrllib/crypto/internal/testutil"
)

// paddedSignatureSize is the fixed length of the falcon-padded-1024 format,
// which other verifiers also accept for compressed signatures.
const paddedSignatureSize = 1280

// signatureEncodingVectors is the shared Falcon signature acceptance-set file.
type signatureEncodingVectors struct {
	PublicKey string `json:"publicKey"`
	Message   string `json:"message"`
	Vectors   []struct {
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		Bytes    string `json:"bytes"`
		Expected string `json:"expected"`
	} `json:"vectors"`
}

// mustHex decodes a hex string or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSignatureEncodingVectors checks the acceptance set the shared vectors
// freeze: exactly one encoding per signature, so the zero-padded forms other
// implementations accept are refused here, through the public API.
func TestSignatureEncodingVectors(t *testing.T) {
	file := testutil.ReadJSON[signatureEncodingVectors](t, filepath.Join("..", "internal", "falcon1024", "testdata"), "signature_encoding_vectors.json")
	pub, err := NewPublicKey(mustHex(t, file.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	message := mustHex(t, file.Message)
	seen := map[string]int{}
	for _, v := range file.Vectors {
		input := mustHex(t, v.Bytes)
		valid := v.Expected == "valid"
		seen[v.Kind+"/"+v.Expected]++
		switch v.Kind {
		case "detached":
			if Verify(pub, message, input) != valid {
				t.Errorf("%s: Verify = %v; vector says %s", v.Name, !valid, v.Expected)
			}
		case "signedMessage":
			opened, openErr := Open(pub, input)
			if accepted := openErr == nil && bytes.Equal(opened, message); accepted != valid {
				t.Errorf("%s: Open = (%x, %v); vector says %s", v.Name, opened, openErr, v.Expected)
			}
			if !valid && !errors.Is(openErr, cryptoerrors.ErrInvalidSignature) {
				t.Errorf("%s: Open error = %v; want ErrInvalidSignature", v.Name, openErr)
			}
		default:
			t.Fatalf("%s: unknown kind %q", v.Name, v.Kind)
		}
	}
	for _, kind := range []string{"detached/valid", "detached/invalid", "signedMessage/valid", "signedMessage/invalid"} {
		if seen[kind] == 0 {
			t.Errorf("the vector file carries no %s vector", kind)
		}
	}
}

// TestZeroPaddedSignaturesAreRejected checks, on a fresh key, that a
// signature zero-padded to the falcon-padded-1024 length is refused in both
// the detached and the signed-message form. Compressed signatures vary in
// length (about 1,261 bytes on average, up to MaxSignatureSize), so the
// test resigns until both forms have room for padding; a signature that is
// already 1,280 bytes long would be its own padded form.
func TestZeroPaddedSignaturesAreRejected(t *testing.T) {
	pub, priv, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("padding")
	var sig, sm []byte
	for attempt := 0; ; attempt++ {
		if attempt == 32 {
			t.Fatal("no signature shorter than the padded length in 32 attempts")
		}
		if sig, err = SignDetached(nil, priv, message); err != nil {
			t.Fatal(err)
		}
		if sm, err = Sign(nil, priv, message); err != nil {
			t.Fatal(err)
		}
		smSigLen := int(sm[0])<<8 | int(sm[1])
		if len(sig) < paddedSignatureSize && smSigLen+40 < paddedSignatureSize {
			break
		}
	}
	if !Verify(pub, message, sig) {
		t.Fatal("compact signature does not verify")
	}
	padded := make([]byte, paddedSignatureSize)
	copy(padded, sig)
	if Verify(pub, message, padded) {
		t.Error("zero-padded detached signature verifies")
	}

	// The signed message's signature field (1 + compressed body) says how
	// much zero padding brings its body to the padded length.
	sigLen := int(sm[0])<<8 | int(sm[1])
	pad := paddedSignatureSize - 40 - sigLen
	smPadded := append(bytes.Clone(sm), make([]byte, pad)...)
	smPadded[0], smPadded[1] = byte((sigLen+pad)>>8), byte(sigLen+pad)
	if _, openErr := Open(pub, smPadded); !errors.Is(openErr, cryptoerrors.ErrInvalidSignature) {
		t.Errorf("zero-padded signed message: Open error = %v; want ErrInvalidSignature", openErr)
	}
}
