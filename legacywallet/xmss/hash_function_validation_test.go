// Regression tests for TOB-QRLLIB-13 (wallet variant): the legacywallet
// XMSS constructor must reject invalid HashFunction values at the API
// boundary, even though the underlying crypto/xmss.InitializeTree also
// rejects them. The wallet-layer guard surfaces a wallet-typed error
// to the caller and avoids constructing a QRLDescriptor that would
// never produce a usable key.

package xmss

import (
	"errors"
	"testing"

	"github.com/theQRL/go-qrllib/common"
	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	"github.com/theQRL/go-qrllib/crypto/xmss"
)

func TestNewWalletFromSeed_RejectsInvalidHashFunction(t *testing.T) {
	var seed [SeedSize]uint8

	cases := []xmss.HashFunction{
		xmss.HashFunction(3),
		xmss.HashFunction(99),
		xmss.HashFunction(255),
	}

	height, err := xmss.ToHeight(10)
	if err != nil {
		t.Fatalf("ToHeight(10): %v", err)
	}

	for _, hf := range cases {
		t.Run(hf.String(), func(t *testing.T) {
			w, err := NewWalletFromSeed(seed, height, hf, common.SHA256_2X)
			if err == nil {
				t.Fatalf("NewWalletFromSeed(HashFunction(%d)) expected error, got nil", hf)
			}
			if !errors.Is(err, cryptoerrors.ErrInvalidHashFunction) {
				t.Errorf("NewWalletFromSeed(HashFunction(%d)) returned %v, want wrapped ErrInvalidHashFunction", hf, err)
			}
			if w != nil {
				t.Errorf("NewWalletFromSeed(HashFunction(%d)) returned non-nil wallet on error", hf)
			}
		})
	}
}

func TestNewWalletFromHeight_RejectsInvalidHashFunction(t *testing.T) {
	height, _ := xmss.ToHeight(10)
	w, err := NewWalletFromHeight(height, xmss.HashFunction(99))
	if err == nil {
		t.Fatal("NewWalletFromHeight(HashFunction(99)) expected error, got nil")
	}
	if !errors.Is(err, cryptoerrors.ErrInvalidHashFunction) {
		t.Errorf("NewWalletFromHeight(HashFunction(99)) returned %v, want wrapped ErrInvalidHashFunction", err)
	}
	if w != nil {
		t.Error("NewWalletFromHeight returned non-nil wallet on error")
	}
}
