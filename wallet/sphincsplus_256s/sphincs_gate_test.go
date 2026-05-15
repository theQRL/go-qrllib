// Regression tests for TOB-QRLLIB-4: the wallet allows SPHINCS+ as a valid
// signature scheme.
//
// Our position is that SPHINCSPLUS_256S is a forward placeholder for the
// eventual SLH-DSA (FIPS 205) adoption rather than a legacy type to remove.
// The library therefore keeps the descriptor parseable but gates wallet
// construction and verification behind the IsIssuable/IsVerifiable
// switches in wallettype, so that no SPHINCS+ wallet can be issued and no
// SPHINCS+ signature can be verified through the public API today.
//
// These tests assert the gate's behaviour by explicitly flipping the
// in-package experimental flag off, exercising the public API, and
// restoring the flag on cleanup. The package-wide TestMain shim
// (main_test.go) keeps experimental enabled for the rest of the test
// suite so the implementation stays continuously exercised.

package sphincsplus_256s

import (
	"errors"
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common"
)

// withGateClosed runs fn with the experimental flag set to false (the
// production default), restoring whatever value the package-wide TestMain
// shim left in place when the test exits.
func withGateClosed(t *testing.T, fn func()) {
	t.Helper()
	prev := EnableExperimentalForTesting(false)
	t.Cleanup(func() { EnableExperimentalForTesting(prev) })
	fn()
}

func TestNewWallet_GatedWhenNotIssuable(t *testing.T) {
	withGateClosed(t, func() {
		w, err := NewWallet()
		if err == nil {
			t.Fatal("NewWallet expected ErrWalletTypeNotIssuable, got nil")
		}
		if !errors.Is(err, common.ErrWalletTypeNotIssuable) {
			t.Errorf("NewWallet returned %v, want ErrWalletTypeNotIssuable", err)
		}
		if w != nil {
			t.Errorf("NewWallet returned non-nil wallet on error")
		}
	})
}

func TestNewWalletFromSeed_GatedWhenNotIssuable(t *testing.T) {
	withGateClosed(t, func() {
		var seed common.Seed
		w, err := NewWalletFromSeed(seed)
		if err == nil {
			t.Fatal("NewWalletFromSeed expected ErrWalletTypeNotIssuable, got nil")
		}
		if !errors.Is(err, common.ErrWalletTypeNotIssuable) {
			t.Errorf("NewWalletFromSeed returned %v, want ErrWalletTypeNotIssuable", err)
		}
		if w != nil {
			t.Errorf("NewWalletFromSeed returned non-nil wallet on error")
		}
	})
}

func TestNewWalletFromHexSeed_GatedWhenNotIssuable(t *testing.T) {
	withGateClosed(t, func() {
		// 48-byte zero seed in hex (96 chars).
		hexSeed := "0x" + "00"
		// Pad to 96 hex chars (48 bytes) so we exercise the gate after the
		// hex-decode step rather than before it.
		for len(hexSeed) < 2+96 {
			hexSeed += "00"
		}
		w, err := NewWalletFromHexSeed(hexSeed)
		if err == nil {
			t.Fatal("NewWalletFromHexSeed expected ErrWalletTypeNotIssuable, got nil")
		}
		if !errors.Is(err, common.ErrWalletTypeNotIssuable) {
			t.Errorf("NewWalletFromHexSeed returned %v, want ErrWalletTypeNotIssuable", err)
		}
		if w != nil {
			t.Errorf("NewWalletFromHexSeed returned non-nil wallet on error")
		}
	})
}

func TestNewWalletFromExtendedSeed_GatedWhenNotIssuable(t *testing.T) {
	withGateClosed(t, func() {
		// First build a valid extended seed via the unexported impl while
		// the gate is open, so we have a real one to feed back through the
		// gated public constructor.
		EnableExperimentalForTesting(true)
		w, err := NewWallet()
		if err != nil {
			t.Fatalf("setup: NewWallet failed: %v", err)
		}
		ext, err := w.GetExtendedSeed()
		if err != nil {
			t.Fatalf("setup: GetExtendedSeed failed: %v", err)
		}
		EnableExperimentalForTesting(false)

		w2, err := NewWalletFromExtendedSeed(ext)
		if err == nil {
			t.Fatal("NewWalletFromExtendedSeed expected ErrWalletTypeNotIssuable, got nil")
		}
		if !errors.Is(err, common.ErrWalletTypeNotIssuable) {
			t.Errorf("NewWalletFromExtendedSeed returned %v, want ErrWalletTypeNotIssuable", err)
		}
		if w2 != nil {
			t.Errorf("NewWalletFromExtendedSeed returned non-nil wallet on error")
		}
	})
}

func TestVerify_GatedWhenNotVerifiable(t *testing.T) {
	// Build a real signature with the gate open so we have valid material
	// to feed Verify with. Then flip the gate closed and assert Verify
	// refuses to even consider it.
	w, err := NewWallet()
	if err != nil {
		t.Fatalf("setup: NewWallet failed: %v", err)
	}
	msg := []byte("verify-gate test message")
	sig, err := w.Sign(msg)
	if err != nil {
		t.Fatalf("setup: Sign failed: %v", err)
	}
	pk := w.GetPK()
	desc := w.GetDescriptor().ToDescriptor()

	// Sanity check: with the gate open Verify accepts the signature.
	if !Verify(msg, sig[:], &pk, desc) {
		t.Fatal("setup: Verify rejected a signature it should accept (gate open)")
	}

	withGateClosed(t, func() {
		if Verify(msg, sig[:], &pk, desc) {
			t.Fatal("Verify accepted a signature with the gate closed; expected false")
		}
	})
}
