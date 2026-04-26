// Regression tests for TOB-QRLLIB-11: ML-DSA Open and Verify panic on a
// nil public key.
//
// The audit's proof-of-concept (figure 11.4) deferred a recover() and
// asserted that recover() != nil — i.e. a panic occurred. These tests
// invert that assertion: with the nil-check guards now in place, the
// public surface MUST return a clean refusal (false from Verify, nil
// from Open) and MUST NOT panic. A regression that removes the guard
// would re-introduce the panic, which these tests would catch.

package ml_dsa_87

import (
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// fixtureSign produces a real signature so tests have well-formed
// material to feed into Verify/Open. Using real material rules out
// "Verify returned false because the signature was malformed" as an
// alternative explanation when asserting the nil-pk refusal path.
func fixtureSign(t *testing.T) (msg []byte, ctx []byte, sig [CRYPTO_BYTES]uint8, sealed []byte) {
	t.Helper()
	mldsa, err := New()
	if err != nil {
		t.Fatalf("setup: New failed: %v", err)
	}
	msg = []byte("nil-pk regression test message")
	ctx = []byte("test-ctx")
	sig, err = mldsa.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("setup: Sign failed: %v", err)
	}
	sealed, err = mldsa.Seal(ctx, msg)
	if err != nil {
		t.Fatalf("setup: Seal failed: %v", err)
	}
	return msg, ctx, sig, sealed
}

func TestVerify_NilPublicKey_ReturnsFalseNoPanic(t *testing.T) {
	msg, ctx, sig, _ := fixtureSign(t)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Verify panicked on nil public key: %v", r)
		}
	}()

	if Verify(ctx, msg, sig, nil) {
		t.Fatal("Verify(nil pk) returned true; want false")
	}
}

func TestOpen_NilPublicKey_ReturnsNilNoPanic(t *testing.T) {
	_, ctx, _, sealed := fixtureSign(t)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Open panicked on nil public key: %v", r)
		}
	}()

	if got := Open(ctx, sealed, nil); got != nil {
		t.Fatalf("Open(nil pk) returned %v; want nil", got)
	}
}

func TestCryptoSignVerify_NilPublicKey_ReturnsErrPublicKeyNil(t *testing.T) {
	msg, ctx, sig, _ := fixtureSign(t)

	ok, err := cryptoSignVerify(sig, msg, ctx, nil)
	if ok {
		t.Error("cryptoSignVerify(nil pk) returned ok=true; want false")
	}
	if !errors.Is(err, cryptoerrors.ErrPublicKeyNil) {
		t.Errorf("cryptoSignVerify(nil pk) err = %v; want ErrPublicKeyNil", err)
	}
}

func TestCryptoSignOpen_NilPublicKey_ReturnsErrPublicKeyNil(t *testing.T) {
	_, ctx, _, sealed := fixtureSign(t)

	msg, err := cryptoSignOpen(sealed, ctx, nil)
	if msg != nil {
		t.Errorf("cryptoSignOpen(nil pk) returned msg=%v; want nil", msg)
	}
	if !errors.Is(err, cryptoerrors.ErrPublicKeyNil) {
		t.Errorf("cryptoSignOpen(nil pk) err = %v; want ErrPublicKeyNil", err)
	}
}
