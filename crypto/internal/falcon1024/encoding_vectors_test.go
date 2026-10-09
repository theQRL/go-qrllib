package falcon1024

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	"github.com/theQRL/go-qrllib/crypto/internal/testutil"
)

const (
	signatureEncodingVectorsFile = "signature_encoding_vectors.json"

	// paddedSignatureSize is the fixed length of the falcon-padded-1024
	// signature format (PQClean's PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES).
	// PQClean's falcon-1024 verifier and liboqs accept a compressed signature
	// zero-padded to this length as well as the compact form; this package
	// accepts exactly one encoding per signature.
	paddedSignatureSize = 1280
)

// signatureEncodingVector is one input to Verify (kind "detached") or Open
// (kind "signedMessage") together with the verdict every QRL client must
// reach.
type signatureEncodingVector struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Bytes    string `json:"bytes"`
	Expected string `json:"expected"`
	Note     string `json:"note,omitempty"`
}

// signatureEncodingVectorFile is the shared vector file for the signature
// acceptance set.
type signatureEncodingVectorFile struct {
	Description string                    `json:"description"`
	PublicKey   string                    `json:"publicKey"`
	Message     string                    `json:"message"`
	Vectors     []signatureEncodingVector `json:"vectors"`
}

// buildSignatureEncodingVectors signs one message deterministically and
// derives the padded and extended encodings from the result. Regenerate the
// file with
// FALCON_WRITE_SIGNATURE_VECTORS=1 go test -run TestSignatureEncodingVectors ./crypto/internal/falcon1024/
func buildSignatureEncodingVectors(t *testing.T) signatureEncodingVectorFile {
	t.Helper()
	priv := testPrivateKey(t)
	message := []byte("falcon-1024 signature encoding vectors")
	stream := func() *sha3.SHAKE {
		s := sha3.NewSHAKE256()
		_, _ = s.Write([]byte("signature encoding vectors"))
		return s
	}
	sm, err := Sign(stream(), priv, message)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignDetached(stream(), priv, message)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) >= paddedSignatureSize {
		t.Fatalf("detached signature is %d bytes, no room for padding", len(sig))
	}

	zeroPadded := make([]byte, paddedSignatureSize)
	copy(zeroPadded, sig)
	nonZeroPadded := bytes.Clone(zeroPadded)
	nonZeroPadded[paddedSignatureSize-1] = 0x01

	// The signed message carries the signature length in its first two bytes;
	// raising it over appended zeros gives the form PQClean's crypto_sign_open
	// accepts (a 1239-byte compressed body, as in the padded format).
	sigLen := int(sm[0])<<8 | int(sm[1])
	smPad := paddedSignatureSize - nonceSize - sigLen
	if smPad <= 0 {
		t.Fatalf("signed message body is %d bytes, no room for padding", sigLen-1)
	}
	smPadded := append(bytes.Clone(sm), make([]byte, smPad)...)
	smPadded[0], smPadded[1] = byte((sigLen+smPad)>>8), byte(sigLen+smPad)

	return signatureEncodingVectorFile{
		Description: "Falcon-1024 signature acceptance set. Each vector is an input to Verify (kind detached, with the message below) or Open " +
			"(kind signedMessage) under the public key below, with the verdict expected: valid when the signature verifies (and Open returns " +
			"the message), invalid otherwise. A signature has exactly one accepted encoding: the compressed polynomial must consume every " +
			"byte after the nonce. The zero-padded forms are the falcon-padded-1024 length that PQClean's falcon-1024 verifier and liboqs " +
			"also accept; every QRL client must reject them so that the accepted set is the same everywhere.",
		PublicKey: hex.EncodeToString(priv.PublicKey().Bytes()),
		Message:   hex.EncodeToString(message),
		Vectors: []signatureEncodingVector{
			{"detached, compact", "detached", hex.EncodeToString(sig), "valid", "the one accepted encoding"},
			{"detached, one trailing zero byte", "detached", hex.EncodeToString(append(bytes.Clone(sig), 0)), "invalid", ""},
			{"detached, zero-padded to 1280 bytes", "detached", hex.EncodeToString(zeroPadded), "invalid", "falcon-padded-1024 length; PQClean falcon-1024 (pqclean.c, do_verify) and liboqs accept this form"},
			{"detached, padded to 1280 bytes ending in a non-zero byte", "detached", hex.EncodeToString(nonZeroPadded), "invalid", "rejected by every implementation"},
			{"signed message, compact", "signedMessage", hex.EncodeToString(sm), "valid", ""},
			{"signed message, signature field raised over zero padding to a 1239-byte body", "signedMessage", hex.EncodeToString(smPadded), "invalid", "PQClean crypto_sign_open accepts this form"},
			{"signed message, one trailing byte beyond the declared length", "signedMessage", hex.EncodeToString(append(bytes.Clone(sm), 0)), "invalid", "shifts the signature field; rejected by every implementation"},
		},
	}
}

// TestSignatureEncodingVectors rebuilds the shared signature vectors, checks
// that the stored file matches, and re-derives every verdict from the stored
// bytes alone. With FALCON_WRITE_SIGNATURE_VECTORS=1 it rewrites the file.
func TestSignatureEncodingVectors(t *testing.T) {
	built := buildSignatureEncodingVectors(t)
	path := filepath.Join("testdata", signatureEncodingVectorsFile)
	if os.Getenv("FALCON_WRITE_SIGNATURE_VECTORS") == "1" {
		data, err := json.MarshalIndent(built, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
	}

	stored := testutil.ReadJSON[signatureEncodingVectorFile](t, "testdata", signatureEncodingVectorsFile)
	if stored.PublicKey != built.PublicKey || stored.Message != built.Message || len(stored.Vectors) != len(built.Vectors) {
		t.Fatalf("vector file does not match the construction; regenerate with FALCON_WRITE_SIGNATURE_VECTORS=1")
	}
	pk, err := hex.DecodeString(stored.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := NewPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	message, err := hex.DecodeString(stored.Message)
	if err != nil {
		t.Fatal(err)
	}

	for i, v := range stored.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v != built.Vectors[i] {
				t.Fatalf("stored vector differs from the construction; regenerate with FALCON_WRITE_SIGNATURE_VECTORS=1")
			}
			input, err := hex.DecodeString(v.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			valid := v.Expected == "valid"
			var verdict bool
			var verifyErr error
			switch v.Kind {
			case "detached":
				verifyErr = Verify(pub, message, input)
				verdict = verifyErr == nil
			case "signedMessage":
				var opened []byte
				opened, verifyErr = Open(pub, input)
				verdict = verifyErr == nil && bytes.Equal(opened, message)
			default:
				t.Fatalf("unknown kind %q", v.Kind)
			}
			if verdict != valid {
				t.Fatalf("accepted = %v (%v), vector says %s", verdict, verifyErr, v.Expected)
			}
			if !valid && !errors.Is(verifyErr, cryptoerrors.ErrInvalidSignature) {
				t.Fatalf("error = %v; want ErrInvalidSignature", verifyErr)
			}
		})
	}
}
