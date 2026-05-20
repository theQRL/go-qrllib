// Regression tests for TOB-QRLLIB-14: ML-DSA Open API collapsed distinct
// failure modes into a nil result.
//
// Open's signature has been redesigned from `(...) []byte` to
// `(...) ([]byte, error)` so that callers can distinguish:
//
//   - public key not provided           → ErrPublicKeyNil
//   - context exceeds 255 bytes         → ErrInvalidContext
//   - signatureMessage too short for sig → ErrInvalidSignatureSize
//   - cryptographic verification failed → ErrInvalidSignature
//
// These tests exercise each path and assert the typed sentinel via
// errors.Is. Without distinct sentinels each of these would have
// silently returned nil under the old API, leaving the caller unable
// to log meaningfully or route on specific failure types.

package ml_dsa_87

import (
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

func openFixture(t *testing.T) (mldsa *MLDSA87, ctx []byte, sealed []byte) {
	t.Helper()
	m, err := New()
	if err != nil {
		t.Fatalf("setup: New: %v", err)
	}
	ctx = []byte("open-errors-test")
	signed, err := m.SignAttached(ctx, []byte("test message"))
	if err != nil {
		t.Fatalf("setup: SignAttached: %v", err)
	}
	return m, ctx, signed
}

func TestOpen_NilPublicKey_ReturnsErrPublicKeyNil(t *testing.T) {
	_, ctx, sealed := openFixture(t)

	msg, err := Open(ctx, sealed, nil)
	if msg != nil {
		t.Errorf("Open(nil pk) msg = %v; want nil", msg)
	}
	if !errors.Is(err, cryptoerrors.ErrPublicKeyNil) {
		t.Errorf("Open(nil pk) err = %v; want ErrPublicKeyNil", err)
	}
}

func TestOpen_OversizedContext_ReturnsErrInvalidContext(t *testing.T) {
	m, _, sealed := openFixture(t)
	pk := m.GetPK()

	// FIPS 204 caps ctx at 255 bytes.
	oversized := make([]byte, 256)

	msg, err := Open(oversized, sealed, &pk)
	if msg != nil {
		t.Errorf("Open(oversized ctx) msg = %v; want nil", msg)
	}
	if !errors.Is(err, cryptoerrors.ErrInvalidContext) {
		t.Errorf("Open(oversized ctx) err = %v; want ErrInvalidContext", err)
	}
}

func TestOpen_ShortInput_ReturnsErrInvalidSignatureSize(t *testing.T) {
	m, ctx, _ := openFixture(t)
	pk := m.GetPK()

	cases := [][]byte{
		nil,
		{},
		make([]byte, CRYPTO_BYTES-1),
	}

	for _, sm := range cases {
		msg, err := Open(ctx, sm, &pk)
		if msg != nil {
			t.Errorf("Open(short sm len=%d) msg = %v; want nil", len(sm), msg)
		}
		if !errors.Is(err, cryptoerrors.ErrInvalidSignatureSize) {
			t.Errorf("Open(short sm len=%d) err = %v; want ErrInvalidSignatureSize", len(sm), err)
		}
	}
}

func TestOpen_InvalidSignature_ReturnsErrInvalidSignature(t *testing.T) {
	m, ctx, sealed := openFixture(t)
	pk := m.GetPK()

	// Flip a bit inside the signature portion. The attached-signature message is
	// `signature || message`; tampering anywhere up to CRYPTO_BYTES
	// invalidates the signature.
	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[10] ^= 0xFF

	msg, err := Open(ctx, tampered, &pk)
	if msg != nil {
		t.Errorf("Open(tampered) msg = %v; want nil", msg)
	}
	if !errors.Is(err, cryptoerrors.ErrInvalidSignature) {
		t.Errorf("Open(tampered) err = %v; want ErrInvalidSignature", err)
	}
}

func TestOpen_HappyPath_ReturnsMessageAndNilError(t *testing.T) {
	m, ctx, sealed := openFixture(t)
	pk := m.GetPK()

	msg, err := Open(ctx, sealed, &pk)
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
