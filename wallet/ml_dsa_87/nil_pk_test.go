// Regression test for TOB-QRLLIB-11 (wallet variant): wallet-level
// Verify must not panic when the public key pointer is nil.

package ml_dsa_87

import (
	"testing"
)

func TestVerify_NilPublicKey_ReturnsFalseNoPanic(t *testing.T) {
	w, err := NewWallet()
	if err != nil {
		t.Fatalf("setup: NewWallet failed: %v", err)
	}
	msg := []byte("nil-pk regression test message (wallet/ml_dsa_87)")
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
