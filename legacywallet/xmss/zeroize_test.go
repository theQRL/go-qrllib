package xmss

import (
	"testing"

	"github.com/theQRL/go-qrllib/common"
	"github.com/theQRL/go-qrllib/crypto/xmss"
)

// Regression test for the wallet-level Zeroize method: the legacy XMSS
// wallet retains the 48-byte seed and wraps the stateful XMSS tree, so
// it must offer the same wipe surface as the v2 wallet types.
func TestXMSSWalletZeroize(t *testing.T) {
	var seed [SeedSize]uint8
	for i := range seed {
		seed[i] = uint8(i + 1)
	}
	h, err := xmss.ToHeight(4)
	if err != nil {
		t.Fatalf("ToHeight: %v", err)
	}
	w, err := NewWalletFromSeed(seed, h, xmss.SHAKE_256, common.SHA256_2X)
	if err != nil {
		t.Fatalf("NewWalletFromSeed: %v", err)
	}

	w.Zeroize()

	gotSeed := w.GetSeed()
	for i, b := range gotSeed {
		if b != 0 {
			t.Fatalf("seed byte %d not wiped: %#x", i, b)
		}
	}
	for i, b := range w.GetSK() {
		if b != 0 {
			t.Fatalf("sk byte %d not wiped: %#x", i, b)
		}
	}
}
