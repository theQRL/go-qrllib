// Regression tests for TOB-QRLLIB-14 (extended to dilithium for
// consistency): Open returns ([]byte, error) so callers can
// distinguish between failure modes via errors.Is.

package dilithium

import (
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

func openFixture(t *testing.T) (dil *Dilithium, sealed []byte) {
	t.Helper()
	d, err := New()
	if err != nil {
		t.Fatalf("setup: New: %v", err)
	}
	signed, err := d.SignAttached([]byte("test message"))
	if err != nil {
		t.Fatalf("setup: SignAttached: %v", err)
	}
	return d, signed
}

func TestOpen_NilPublicKey_ReturnsErrPublicKeyNil(t *testing.T) {
	_, sealed := openFixture(t)

	msg, err := Open(sealed, nil)
	if msg != nil {
		t.Errorf("Open(nil pk) msg = %v; want nil", msg)
	}
	if !errors.Is(err, cryptoerrors.ErrPublicKeyNil) {
		t.Errorf("Open(nil pk) err = %v; want ErrPublicKeyNil", err)
	}
}

func TestOpen_ShortInput_ReturnsErrInvalidSignatureSize(t *testing.T) {
	d, _ := openFixture(t)
	pk := d.GetPK()

	cases := [][]byte{
		nil,
		{},
		make([]byte, CRYPTO_BYTES-1),
	}

	for _, sm := range cases {
		msg, err := Open(sm, &pk)
		if msg != nil {
			t.Errorf("Open(short sm len=%d) msg = %v; want nil", len(sm), msg)
		}
		if !errors.Is(err, cryptoerrors.ErrInvalidSignatureSize) {
			t.Errorf("Open(short sm len=%d) err = %v; want ErrInvalidSignatureSize", len(sm), err)
		}
	}
}

func TestOpen_InvalidSignature_ReturnsErrInvalidSignature(t *testing.T) {
	d, sealed := openFixture(t)
	pk := d.GetPK()

	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[10] ^= 0xFF

	msg, err := Open(tampered, &pk)
	if msg != nil {
		t.Errorf("Open(tampered) msg = %v; want nil", msg)
	}
	if !errors.Is(err, cryptoerrors.ErrInvalidSignature) {
		t.Errorf("Open(tampered) err = %v; want ErrInvalidSignature", err)
	}
}

func TestOpen_HappyPath_ReturnsMessageAndNilError(t *testing.T) {
	d, sealed := openFixture(t)
	pk := d.GetPK()

	msg, err := Open(sealed, &pk)
	if err != nil {
		t.Fatalf("Open(valid) returned err = %v; want nil", err)
	}
	if msg == nil {
		t.Fatal("Open(valid) returned nil msg; want recovered message")
	}
	if string(msg) != "test message" {
		t.Errorf("Open(valid) recovered %q; want %q", string(msg), "test message")
	}
}
