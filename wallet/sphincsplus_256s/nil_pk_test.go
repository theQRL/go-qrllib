// Regression test for TOB-QRLLIB-11 (wallet variant for SPHINCS+-256s):
// wallet-level Verify must not panic when the public key pointer is nil.
//
// SPHINCSPLUS_256S is gated off in production (see TOB-QRLLIB-4); the
// package-wide TestMain shim flips the experimental flag on for the
// duration of the test binary so the underlying Verify path is reachable.

package sphincsplus_256s

import (
	"testing"
)

func TestVerify_NilPublicKey_ReturnsFalseNoPanic(t *testing.T) {
	w, err := NewWallet()
	if err != nil {
		t.Fatalf("setup: NewWallet failed: %v", err)
	}
	msg := []byte("nil-pk regression test message (wallet/sphincsplus_256s)")
	sig, err := w.Sign(msg)
	if err != nil {
		t.Fatalf("setup: Sign failed: %v", err)
	}
	desc := w.GetDescriptor().ToDescriptor()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Verify panicked on nil public key: %v", r)
		}
	}()

	if Verify(msg, sig[:], nil, desc) {
		t.Fatal("Verify(nil pk) returned true; want false")
	}
}
