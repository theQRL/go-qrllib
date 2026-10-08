package falcon1024_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"testing/iotest"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	. "github.com/theQRL/go-qrllib/crypto/falcon1024"
	"github.com/theQRL/go-qrllib/crypto/internal/testutil"
)

func TestZeroize(t *testing.T) {
	pub, priv, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("zeroize")
	signature, err := SignDetached(nil, priv, message)
	if err != nil {
		t.Fatal(err)
	}
	same, err := NewPrivateKey(priv.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(same) {
		t.Fatal("re-imported key is not Equal to the original")
	}
	heldPublic := priv.Public().(*PublicKey)

	priv.Zeroize()

	if priv.Bytes() != nil {
		t.Error("Bytes after Zeroize is not nil")
	}
	if _, err := Sign(nil, priv, message); !errors.Is(err, cryptoerrors.ErrSecretKeyZeroized) {
		t.Errorf("Sign after Zeroize error = %v; want ErrSecretKeyZeroized", err)
	}
	if _, err := priv.SignDetached(nil, message); !errors.Is(err, cryptoerrors.ErrSecretKeyZeroized) {
		t.Errorf("SignDetached after Zeroize error = %v; want ErrSecretKeyZeroized", err)
	}
	if priv.Equal(same) || same.Equal(priv) {
		t.Error("a zeroized key compared Equal")
	}

	// The public key stays available: the copy taken earlier, a fresh one,
	// and the one GenerateKey returned all still verify.
	for name, pk := range map[string]*PublicKey{
		"held copy": heldPublic, "fresh": priv.Public().(*PublicKey), "generated": pub,
	} {
		if !Verify(pk, message, signature) {
			t.Errorf("%s public key no longer verifies after Zeroize", name)
		}
	}
	if !pub.Equal(priv.Public()) {
		t.Error("public key changed after Zeroize")
	}

	// Zeroize is idempotent and does not touch other keys.
	priv.Zeroize()
	if _, err := Sign(nil, same, message); err != nil {
		t.Errorf("unrelated key cannot sign: %v", err)
	}
}

// NewPrivateKey applies the key-generation bounds and the reference's own
// consistency checks to imported encodings.
func TestNewPrivateKeyRejectsOutOfBoundEncodings(t *testing.T) {
	priv, err := NewPrivateKeyFromSeed(testSeed())
	if err != nil {
		t.Fatal(err)
	}
	valid := priv.Bytes()
	if _, err := NewPrivateKey(valid); err != nil {
		t.Fatalf("valid encoding rejected: %v", err)
	}

	// f, g: 1024 five-bit fields each (bytes 1..640 and 641..1280), then F
	// at eight bits (bytes 1281..2304). The constant polynomial 15 packs the
	// bit pattern 01111 repeated, five bytes per eight coefficients.
	fifteen := bytes.Repeat([]byte{0x7B, 0xDE, 0xF7, 0xBD, 0xEF}, 128)

	for name, tc := range map[string]struct {
		mutate func(sk []byte)
		want   error
	}{
		"f = 1, g = 0, F = 0 (derives the weak key h = 0)": {func(sk []byte) {
			clear(sk[1:])
			sk[1] = 0x08
		}, cryptoerrors.ErrWeakPublicKey},
		"f = 15 everywhere, g = 0, F = 0 (derives h = 0)": {func(sk []byte) {
			clear(sk[1:])
			copy(sk[1:], fifteen)
		}, cryptoerrors.ErrWeakPublicKey},
		"f coefficient encoded as -16":  {func(sk []byte) { sk[1] = sk[1]&0x07 | 0x80 }, cryptoerrors.ErrInvalidSecretKey},
		"g coefficient encoded as -16":  {func(sk []byte) { sk[641] = sk[641]&0x07 | 0x80 }, cryptoerrors.ErrInvalidSecretKey},
		"F coefficient encoded as -128": {func(sk []byte) { sk[1281] = 0x80 }, cryptoerrors.ErrInvalidSecretKey},
		"F inconsistent with f and g":   {func(sk []byte) { sk[1281] ^= 0x01 }, cryptoerrors.ErrInvalidSecretKey},
	} {
		sk := bytes.Clone(valid)
		tc.mutate(sk)
		if _, err := NewPrivateKey(sk); !errors.Is(err, tc.want) {
			t.Errorf("%s: error = %v; want %v", name, err, tc.want)
		}
	}

	// The key-generation bounds, with a public half the weak-key rule
	// accepts, come from the shared vector file.
	for _, v := range weakKeyVectorFile(t).PrivateKeys {
		sk, err := hex.DecodeString(v.SK)
		if err != nil {
			t.Fatal(err)
		}
		_, err = NewPrivateKey(sk)
		switch v.Expected {
		case "valid":
			if err != nil {
				t.Errorf("%s: %v", v.Name, err)
			}
		case "weak":
			if !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
				t.Errorf("%s: error = %v; want ErrWeakPublicKey", v.Name, err)
			}
		case "invalid":
			if !errors.Is(err, cryptoerrors.ErrInvalidSecretKey) || errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
				t.Errorf("%s: error = %v; want ErrInvalidSecretKey only", v.Name, err)
			}
		default:
			t.Fatalf("%s: unknown expectation %q", v.Name, v.Expected)
		}
	}
}

type weakKeyVectors struct {
	PublicKeys []struct {
		Name     string `json:"name"`
		PK       string `json:"pk"`
		Expected string `json:"expected"`
	} `json:"publicKeys"`
	PrivateKeys []struct {
		Name     string `json:"name"`
		SK       string `json:"sk"`
		Expected string `json:"expected"`
	} `json:"privateKeys"`
}

func weakKeyVectorFile(t *testing.T) weakKeyVectors {
	t.Helper()
	v := testutil.ReadJSON[weakKeyVectors](t, filepath.Join("..", "internal", "falcon1024", "testdata"), "weak_public_key_vectors.json")
	if len(v.PublicKeys) == 0 || len(v.PrivateKeys) == 0 {
		t.Fatal("weak-key vector file is empty")
	}
	return v
}

// ValidatePublicKey and NewPublicKey reach the shared vectors' verdicts, and
// ValidatePublicKey reports a malformed encoding as such.
func TestValidatePublicKeyVectors(t *testing.T) {
	for _, v := range weakKeyVectorFile(t).PublicKeys {
		pk, err := hex.DecodeString(v.PK)
		if err != nil {
			t.Fatal(err)
		}
		err = ValidatePublicKey(pk)
		_, errNew := NewPublicKey(pk)
		switch v.Expected {
		case "weak":
			if !errors.Is(err, cryptoerrors.ErrWeakPublicKey) || !errors.Is(errNew, cryptoerrors.ErrWeakPublicKey) {
				t.Errorf("%s: ValidatePublicKey = %v, NewPublicKey = %v; want ErrWeakPublicKey", v.Name, err, errNew)
			}
		case "strong":
			if err != nil || errNew != nil {
				t.Errorf("%s: ValidatePublicKey = %v, NewPublicKey = %v; want nil", v.Name, err, errNew)
			}
		default:
			t.Fatalf("%s: unknown expectation %q", v.Name, v.Expected)
		}
	}
	for name, bad := range map[string][]byte{"nil": nil, "short": make([]byte, PublicKeySize-1), "header": make([]byte, PublicKeySize)} {
		if err := ValidatePublicKey(bad); !errors.Is(err, cryptoerrors.ErrInvalidPublicKey) {
			t.Errorf("ValidatePublicKey(%s) = %v; want ErrInvalidPublicKey", name, err)
		}
	}
}

// A signature or signed message shorter than its fixed prefix is a size
// error; anything else malformed is an invalid signature.
func TestShortSignaturesAreSizeErrors(t *testing.T) {
	pub, priv, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("sizes")
	sm, err := Sign(nil, priv, message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(pub, sm[:41]); !errors.Is(err, cryptoerrors.ErrInvalidSignatureSize) {
		t.Errorf("Open of a 41-byte signed message: error = %v; want ErrInvalidSignatureSize", err)
	}
	if _, err := Open(pub, sm[:len(sm)-1]); !errors.Is(err, cryptoerrors.ErrInvalidSignature) || errors.Is(err, cryptoerrors.ErrInvalidSignatureSize) {
		t.Errorf("Open of a truncated signed message: error = %v; want ErrInvalidSignature only", err)
	}
	if _, err := Open(pub, sm); err != nil {
		t.Errorf("Open of the valid signed message: %v", err)
	}
}

func TestNewPublicKeyRejectsCoefficientAtQ(t *testing.T) {
	pub, _, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pk := pub.Bytes()
	// The first coefficient is the top 14 bits of bytes 1 and 2, big-endian.
	// q = 0x3001 is one past the largest valid value.
	pk[1] = 0xC0
	pk[2] = pk[2]&0x03 | 0x04
	if _, err := NewPublicKey(pk); !errors.Is(err, cryptoerrors.ErrInvalidPublicKey) {
		t.Errorf("coefficient q: error = %v; want ErrInvalidPublicKey", err)
	}
	// q - 1 in the same position is a valid coefficient.
	pk[2] &= 0x03
	if _, err := NewPublicKey(pk); err != nil {
		t.Errorf("coefficient q-1 rejected: %v", err)
	}
	for name, bad := range map[string][]byte{
		"short": pk[:PublicKeySize-1], "long": append(bytes.Clone(pk), 0),
	} {
		if _, err := NewPublicKey(bad); !errors.Is(err, cryptoerrors.ErrInvalidPublicKey) {
			t.Errorf("%s encoding: error = %v; want ErrInvalidPublicKey", name, err)
		}
	}
}

// The io.Reader contract: a failing reader fails the operation, a reader that
// returns its bytes in small pieces changes nothing, and nil means crypto/rand.
func TestRandomnessReaders(t *testing.T) {
	boom := errors.New("boom")
	if _, _, err := GenerateKey(iotest.ErrReader(boom)); !errors.Is(err, boom) || !errors.Is(err, cryptoerrors.ErrSeedGeneration) {
		t.Errorf("GenerateKey with a failing reader: error = %v; want boom wrapped in ErrSeedGeneration", err)
	}

	seed := testSeed()
	fromSeed, err := NewPrivateKeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	_, pieces, err := GenerateKey(iotest.HalfReader(bytes.NewReader(seed)))
	if err != nil {
		t.Fatal(err)
	}
	if !pieces.Equal(fromSeed) {
		t.Error("GenerateKey over a partial-read reader derived a different key")
	}

	message := []byte("readers")
	randomness := make([]byte, 40+SeedSize)
	for i := range randomness {
		randomness[i] = byte(i * 7)
	}
	whole, err := SignDetached(bytes.NewReader(randomness), fromSeed, message)
	if err != nil {
		t.Fatal(err)
	}
	byteAtATime, err := SignDetached(iotest.OneByteReader(bytes.NewReader(randomness)), fromSeed, message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(whole, byteAtATime) {
		t.Error("SignDetached over a one-byte reader produced a different signature")
	}
	if _, signErr := Sign(iotest.ErrReader(boom), fromSeed, message); !errors.Is(signErr, boom) || !errors.Is(signErr, cryptoerrors.ErrSeedGeneration) {
		t.Errorf("Sign with a failing reader: error = %v; want boom wrapped in ErrSeedGeneration", signErr)
	}
	// A reader that runs dry inside the sampler seed fails that read.
	if _, shortErr := SignDetached(bytes.NewReader(make([]byte, 41)), fromSeed, message); !errors.Is(shortErr, io.ErrUnexpectedEOF) || !errors.Is(shortErr, cryptoerrors.ErrSeedGeneration) {
		t.Errorf("SignDetached with a short reader: error = %v; want ErrUnexpectedEOF wrapped in ErrSeedGeneration", shortErr)
	}

	pub := fromSeed.Public().(*PublicKey)
	sig, err := SignDetached(nil, fromSeed, message)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, message, sig) {
		t.Error("SignDetached with nil randomness did not verify")
	}
}
