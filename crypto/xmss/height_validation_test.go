// Regression tests for TOB-QRLLIB-2: XMSS InitializeTree accepts invalid
// typed Height values above MaxHeight.
//
// The underlying defect was that Height had an IsValid() contract (even
// values between 2 and MaxHeight) but InitializeTree never enforced it.
// A caller that constructed a Height via a raw cast (e.g. xmss.Height(32))
// could reach treeHashSetup where lastNode := index + (1 << h) overflows
// uint32 for h >= 32, producing a zero-rooted XMSS that would only fail
// later at signing time.
//
// These tests assert that every public constructor in the xmss package
// rejects invalid Height values with ErrInvalidHeight at the API boundary,
// before any key derivation runs.

package xmss

import (
	"bytes"
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// invalidHeightCases covers the specific values called out in the ToB audit
// (Height(31), Height(32), Height(34), Height(98)) plus a few adjacent
// values that exercise the odd-height, below-minimum, and far-above-maximum
// paths through Height.IsValid().
var invalidHeightCases = []struct {
	name string
	h    Height
}{
	{"odd_below_max (31)", Height(31)},
	{"one_above_max (32)", Height(32)},
	{"even_above_max (34)", Height(34)},
	{"far_above_max (98)", Height(98)},
	{"odd_minimum_boundary (1)", Height(1)},
	{"zero (0)", Height(0)},
	{"odd (3)", Height(3)},
	{"uint8_max (255)", Height(255)},
}

// TestInitializeTree_RejectsInvalidHeight asserts that InitializeTree returns
// ErrInvalidHeight for every invalid Height at the public API boundary,
// rather than proceeding into key derivation and returning a zero-rooted
// XMSS or panicking on uint32 overflow.
func TestInitializeTree_RejectsInvalidHeight(t *testing.T) {
	seed := make([]uint8, 48)

	for _, tc := range invalidHeightCases {
		t.Run(tc.name, func(t *testing.T) {
			xmss, err := InitializeTree(tc.h, SHAKE_256, seed)
			if err == nil {
				t.Fatalf("InitializeTree(Height(%d)) expected error, got nil", tc.h)
			}
			if !errors.Is(err, cryptoerrors.ErrInvalidHeight) {
				t.Errorf("InitializeTree(Height(%d)) returned %v, want ErrInvalidHeight", tc.h, err)
			}
			if xmss != nil {
				t.Errorf("InitializeTree(Height(%d)) returned non-nil XMSS on error", tc.h)
			}
		})
	}
}

// TestInitializeTree_AcceptsValidHeight is the positive round-trip control
// asserting that a valid Height constructed via the validating helper
// succeeds, produces a non-zero Merkle root, and can sign and verify a
// message. Without this, a bug that makes InitializeTree reject everything
// would make TestInitializeTree_RejectsInvalidHeight pass trivially.
func TestInitializeTree_AcceptsValidHeight(t *testing.T) {
	seed := make([]uint8, 48)

	h, err := ToHeight(10)
	if err != nil {
		t.Fatalf("ToHeight(10) unexpectedly failed: %v", err)
	}

	xmss, err := InitializeTree(h, SHAKE_256, seed)
	if err != nil {
		t.Fatalf("InitializeTree(Height(10)) failed: %v", err)
	}
	if xmss == nil {
		t.Fatal("InitializeTree(Height(10)) returned nil XMSS without error")
	}

	root := xmss.GetRoot()
	if bytes.Equal(root, make([]byte, len(root))) {
		t.Fatal("InitializeTree(Height(10)) produced a zero-byte Merkle root; " +
			"this is the exact degenerate state TOB-QRLLIB-2 describes and " +
			"means key derivation did not execute")
	}

	sig, err := xmss.Sign([]byte("regression: round-trip control"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
	if !Verify(xmss.GetHashFunction(), []byte("regression: round-trip control"), sig, pk) {
		t.Fatal("Verify rejected a signature produced by the same key")
	}
}

// TestXMSSFastGenKeyPair_RejectsInvalidHeight asserts that the exported
// XMSSFastGenKeyPair also rejects out-of-range heights, so that a direct
// caller of that lower-level entry point is protected as well.
//
// The test passes a BDSState that was constructed with a *valid* height
// (so that NewBDSState itself does not misbehave on the h<k underflow
// path, which is a separate latent issue worth its own fix) and an
// XMSSParams with an invalid h. The guard under test reads xmssParams.h
// and returns before touching bdsState, so this isolates the guard.
func TestXMSSFastGenKeyPair_RejectsInvalidHeight(t *testing.T) {
	seed := make([]uint8, 48)
	validBDS := NewBDSState(4, WOTSParamN, WOTSParamK) // any valid height will do

	for _, tc := range invalidHeightCases {
		t.Run(tc.name, func(t *testing.T) {
			params := NewXMSSParams(WOTSParamN, uint32(tc.h), WOTSParamW, WOTSParamK)
			sk := make([]uint8, 132)
			pk := make([]uint8, 64)

			err := XMSSFastGenKeyPair(SHAKE_256, params, pk, sk, validBDS, seed)
			if err == nil {
				t.Fatalf("XMSSFastGenKeyPair(h=%d) expected error, got nil", tc.h)
			}
			if !errors.Is(err, cryptoerrors.ErrInvalidHeight) {
				t.Errorf("XMSSFastGenKeyPair(h=%d) returned %v, want ErrInvalidHeight", tc.h, err)
			}
			if !bytes.Equal(pk, make([]byte, len(pk))) {
				t.Errorf("XMSSFastGenKeyPair(h=%d) wrote to pk on error path", tc.h)
			}
		})
	}
}

// TestInitializeTree_RejectsHeight2BDS asserts that Height(2) — which passes
// Height.IsValid() per the documented even-heights-in-[2,MaxHeight] contract
// but cannot form a valid BDS state with WOTSParamK=2 — is rejected at
// InitializeTree with ErrInvalidBDSParams rather than ErrInvalidHeight. This
// pins the boundary between the two validators so a future refactor that
// collapses them doesn't change observable error semantics.
func TestInitializeTree_RejectsHeight2BDS(t *testing.T) {
	seed := make([]uint8, 48)

	h, err := ToHeight(2)
	if err != nil {
		t.Fatalf("ToHeight(2) unexpectedly failed: %v", err)
	}
	if !h.IsValid() {
		t.Fatal("Height(2) should satisfy IsValid per the even-heights-in-[2,MaxHeight] contract")
	}

	xmss, err := InitializeTree(h, SHAKE_256, seed)
	if err == nil {
		t.Fatalf("InitializeTree(Height(2)) expected error, got nil")
	}
	if !errors.Is(err, cryptoerrors.ErrInvalidBDSParams) {
		t.Errorf("InitializeTree(Height(2)) returned %v, want ErrInvalidBDSParams", err)
	}
	if xmss != nil {
		t.Errorf("InitializeTree(Height(2)) returned non-nil XMSS on error")
	}
}

// TestNewBDSState_NilOnHeightUnderflow asserts the nil-guard added to
// NewBDSState while remediating TOB-QRLLIB-2. Without it, NewBDSState with
// height <= k underflowed uint32 in the treeHash allocation loop and hung
// the process attempting to allocate ~4 billion TreeHashInst structures.
// Discovered while writing the TOB-QRLLIB-2 XMSSFastGenKeyPair tests.
func TestNewBDSState_NilOnHeightUnderflow(t *testing.T) {
	cases := []struct {
		name   string
		height uint32
		k      uint32
	}{
		{"height_less_than_k", 1, 2},
		{"height_equals_k", 2, 2},
		{"height_zero", 0, 2},
		{"height_zero_k_zero", 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NewBDSState(tc.height, WOTSParamN, tc.k)
			if got != nil {
				t.Errorf("NewBDSState(height=%d, k=%d) returned non-nil, want nil", tc.height, tc.k)
			}
		})
	}
}

// TestNewBDSState_NonNilOnValidHeight is the positive control for the
// nil-guard: any height strictly greater than k must produce a usable
// BDSState.
func TestNewBDSState_NonNilOnValidHeight(t *testing.T) {
	for _, h := range []uint32{3, 4, 10, 30} {
		got := NewBDSState(h, WOTSParamN, WOTSParamK)
		if got == nil {
			t.Errorf("NewBDSState(height=%d, k=%d) returned nil, want non-nil", h, WOTSParamK)
		}
	}
}

// TestInitializeTree_RejectsEveryInvalidHeightUint8 asserts the complementary
// rejection property: for every uint8 value h where Height.IsValid() reports
// invalid, InitializeTree rejects the cast Height(h) with ErrInvalidHeight.
// This gives exhaustive coverage of the rejection side and prevents a future
// edit from loosening the constructor guard without also loosening IsValid().
//
// We only exercise the rejection side here. Constructing InitializeTree with
// every *valid* height (2, 4, ..., 30) would be prohibitively slow for the
// larger heights (height 30 constructs a full 2^30-leaf Merkle tree at setup
// time). Positive coverage is provided by TestInitializeTree_AcceptsValidHeight
// and by the existing height-4/6/8/10 tests elsewhere in the package.
func TestInitializeTree_RejectsEveryInvalidHeightUint8(t *testing.T) {
	seed := make([]uint8, 48)

	for v := 0; v <= 255; v++ {
		h := Height(v)
		if h.IsValid() {
			continue
		}

		xmss, err := InitializeTree(h, SHAKE_256, seed)
		if err == nil {
			t.Errorf("InitializeTree(Height(%d)) accepted, but IsValid() reports invalid", v)
			continue
		}
		if !errors.Is(err, cryptoerrors.ErrInvalidHeight) {
			t.Errorf("InitializeTree(Height(%d)) returned %v, want ErrInvalidHeight", v, err)
		}
		if xmss != nil {
			t.Errorf("InitializeTree(Height(%d)) returned non-nil XMSS on error", v)
		}
	}
}
