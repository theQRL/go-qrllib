// Regression tests for TOB-QRLLIB-14 (extended to sphincsplus_256s for
// consistency): Open returns ([]byte, error) so callers can
// distinguish between failure modes via errors.Is.

package sphincsplus_256s

import (
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

func openFixture(t *testing.T) (spx *SphincsPlus256s, sealed []byte) {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatalf("setup: New: %v", err)
	}
	signed, err := s.SignAttached([]byte("test message"))
	if err != nil {
		t.Fatalf("setup: SignAttached: %v", err)
	}
	return s, signed
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
	spx, _ := openFixture(t)
	pk := spx.GetPK()

	cases := [][]byte{
		nil,
		{},
		make([]byte, params.SPX_BYTES-1),
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
	spx, sealed := openFixture(t)
	pk := spx.GetPK()

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
	spx, sealed := openFixture(t)
	pk := spx.GetPK()

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
