package xmss

import (
	"bytes"
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// Regression tests for the seed-length boundary check: every public
// constructor that accepts a raw QRL seed must reject lengths other
// than SeedSize (48) with ErrInvalidSeed instead of silently
// SHAKE256-expanding an entropy-starved input.

func TestInitializeTreeSeedLengthValidation(t *testing.T) {
	h, err := ToHeight(4)
	if err != nil {
		t.Fatalf("ToHeight(4): %v", err)
	}

	for _, tc := range []struct {
		name string
		seed []uint8
	}{
		{"nil", nil},
		{"empty", []uint8{}},
		{"one_short", make([]uint8, SeedSize-1)},
		{"one_long", make([]uint8, SeedSize+1)},
		{"expanded_length", make([]uint8, 96)}, // 96 bytes belongs to the FromExpandedSeed path
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := InitializeTree(h, SHAKE_256, tc.seed)
			if !errors.Is(err, cryptoerrors.ErrInvalidSeed) {
				t.Fatalf("InitializeTree(%d-byte seed) returned %v, want ErrInvalidSeed", len(tc.seed), err)
			}
			if tree != nil {
				t.Error("InitializeTree returned non-nil XMSS on error")
			}
		})
	}

	t.Run("exact_48_accepted", func(t *testing.T) {
		tree, err := InitializeTree(h, SHAKE_256, make([]uint8, SeedSize))
		if err != nil {
			t.Fatalf("InitializeTree(48-byte seed): %v", err)
		}
		if tree == nil {
			t.Fatal("InitializeTree(48-byte seed) returned nil tree without error")
		}
	})
}

func TestXMSSFastGenKeyPairSeedLengthValidation(t *testing.T) {
	params := NewXMSSParams(WOTSParamN, 4, WOTSParamW, WOTSParamK)
	bds := NewBDSState(4, WOTSParamN, WOTSParamK)
	pk := make([]uint8, 64)
	sk := make([]uint8, 132)

	if err := XMSSFastGenKeyPair(SHAKE_256, params, pk, sk, bds, make([]uint8, 32)); !errors.Is(err, cryptoerrors.ErrInvalidSeed) {
		t.Fatalf("XMSSFastGenKeyPair(32-byte seed) returned %v, want ErrInvalidSeed", err)
	}
	allZero := true
	for _, b := range pk {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("XMSSFastGenKeyPair wrote to pk on the invalid-seed error path")
	}
}

// The constructor must retain a private copy of the seed rather than
// aliasing the caller's slice: mutating the caller's buffer after
// construction must not change what GetSeed reports, and Zeroize must
// wipe the tree's copy, not the caller's.
func TestInitializeTreeDoesNotAliasCallerSeed(t *testing.T) {
	h, _ := ToHeight(4)
	seed := bytes.Repeat([]byte{0x42}, SeedSize)

	tree, err := InitializeTree(h, SHAKE_256, seed)
	if err != nil {
		t.Fatalf("InitializeTree: %v", err)
	}

	seed[0] = 0xFF // caller mutates its buffer after construction
	got := tree.GetSeed()
	if got[0] != 0x42 {
		t.Error("tree seed aliases the caller's slice; mutation leaked into the XMSS instance")
	}

	tree.Zeroize()
	if seed[1] != 0x42 {
		t.Error("Zeroize wiped the caller's buffer; it must only wipe the private copy")
	}
}
