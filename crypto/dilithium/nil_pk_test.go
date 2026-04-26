// Regression tests for TOB-QRLLIB-11 (variant for Dilithium): public
// Verify and Open must not panic when the public key pointer is nil;
// they must return false / nil respectively.

package dilithium

import (
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

func fixtureSign(t *testing.T) (msg []byte, sig [CRYPTO_BYTES]uint8, sealed []byte) {
	t.Helper()
	d, err := New()
	if err != nil {
		t.Fatalf("setup: New failed: %v", err)
	}
	msg = []byte("nil-pk regression test message (dilithium)")
	sig, err = d.Sign(msg)
	if err != nil {
		t.Fatalf("setup: Sign failed: %v", err)
	}
	sealed, err = d.Seal(msg)
	if err != nil {
		t.Fatalf("setup: Seal failed: %v", err)
	}
	return msg, sig, sealed
}

func TestVerify_NilPublicKey_ReturnsFalseNoPanic(t *testing.T) {
	msg, sig, _ := fixtureSign(t)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Verify panicked on nil public key: %v", r)
		}
	}()

	if Verify(msg, sig, nil) {
		t.Fatal("Verify(nil pk) returned true; want false")
	}
}

func TestOpen_NilPublicKey_ReturnsNilNoPanic(t *testing.T) {
	_, _, sealed := fixtureSign(t)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Open panicked on nil public key: %v", r)
		}
	}()

	if got := Open(sealed, nil); got != nil {
		t.Fatalf("Open(nil pk) returned %v; want nil", got)
	}
}

func TestCryptoSignVerify_NilPublicKey_ReturnsErrPublicKeyNil(t *testing.T) {
	msg, sig, _ := fixtureSign(t)

	ok, err := cryptoSignVerify(sig, msg, nil)
	if ok {
		t.Error("cryptoSignVerify(nil pk) returned ok=true; want false")
	}
	if !errors.Is(err, cryptoerrors.ErrPublicKeyNil) {
		t.Errorf("cryptoSignVerify(nil pk) err = %v; want ErrPublicKeyNil", err)
	}
}

func TestCryptoSignOpen_NilPublicKey_ReturnsErrPublicKeyNil(t *testing.T) {
	_, _, sealed := fixtureSign(t)

	msg, err := cryptoSignOpen(sealed, nil)
	if msg != nil {
		t.Errorf("cryptoSignOpen(nil pk) returned msg=%v; want nil", msg)
	}
	if !errors.Is(err, cryptoerrors.ErrPublicKeyNil) {
		t.Errorf("cryptoSignOpen(nil pk) err = %v; want ErrPublicKeyNil", err)
	}
}
