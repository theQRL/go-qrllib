// Regression tests for TOB-QRLLIB-11 (variant for SPHINCS+-256s):
// public Verify and Open must not panic when the public key pointer is
// nil; they must return false / nil respectively.

package sphincsplus_256s

import (
	"testing"

	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

func fixtureSign(t *testing.T) (msg []byte, sig [params.SPX_BYTES]uint8, sealed []byte) {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatalf("setup: New failed: %v", err)
	}
	msg = []byte("nil-pk regression test message (sphincs)")
	sig, err = s.Sign(msg)
	if err != nil {
		t.Fatalf("setup: Sign failed: %v", err)
	}
	sealed, err = s.SignAttached(msg)
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
