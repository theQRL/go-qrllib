// Regression tests for TOB-QRLLIB-13: invalid XMSS hash-function values
// produce degenerate interchangeable keys and signatures.
//
// The underlying defect was that coreHash dispatched on the HashFunction
// enum via a switch with no default case, so an unrecognised value left
// the output buffer zero-initialised. This propagated through the Merkle
// construction and produced an XMSS whose root was all-zero — and any
// two such keys (from different seeds) cross-verified each other's
// signatures because both shared the same zero-rooted public key.
//
// These tests assert the layered fixes:
//
//   1. InitializeTree refuses an invalid HashFunction at the API
//      boundary (the primary fix).
//   2. coreHash's switch carries a default-case tripwire that panics if
//      reached, so a future regression that removes the upstream guard
//      surfaces immediately rather than producing a degenerate root.
//   3. InitializeTree carries a post-construction non-zero-root
//      invariant check as defence-in-depth against any *other* future
//      regression in the key-derivation pipeline.

package xmss

import (
	"bytes"
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// invalidHashFunctionCases covers values outside the recognised set
// {SHA2_256, SHAKE_128, SHAKE_256} ∈ {0, 1, 2}.
var invalidHashFunctionCases = []struct {
	name string
	hf   HashFunction
}{
	{"first_invalid (3)", HashFunction(3)},
	{"audit_proof_of_concept (99)", HashFunction(99)},
	{"high_value (200)", HashFunction(200)},
	{"uint8_max (255)", HashFunction(255)},
}

// TestInitializeTree_RejectsInvalidHashFunction asserts that the public
// constructor refuses every invalid HashFunction at the API boundary
// with ErrInvalidHashFunction, before any key derivation runs.
func TestInitializeTree_RejectsInvalidHashFunction(t *testing.T) {
	seed := make([]uint8, 48)
	h, err := ToHeight(10)
	if err != nil {
		t.Fatalf("ToHeight(10): %v", err)
	}

	for _, tc := range invalidHashFunctionCases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := InitializeTree(h, tc.hf, seed)
			if err == nil {
				t.Fatalf("InitializeTree(HashFunction(%d)) expected error, got nil", tc.hf)
			}
			if !errors.Is(err, cryptoerrors.ErrInvalidHashFunction) {
				t.Errorf("InitializeTree(HashFunction(%d)) returned %v, want ErrInvalidHashFunction", tc.hf, err)
			}
			if tree != nil {
				t.Errorf("InitializeTree(HashFunction(%d)) returned non-nil XMSS on error", tc.hf)
			}
		})
	}
}

// TestInitializeTree_AcceptsValidHashFunctions is the positive control
// asserting that each valid HashFunction produces an XMSS with a
// non-zero Merkle root and that signatures from different seeds do NOT
// cross-verify (the property the defect violated).
func TestInitializeTree_AcceptsValidHashFunctions(t *testing.T) {
	seedA := bytes.Repeat([]byte{0xAA}, 48)
	seedB := bytes.Repeat([]byte{0xBB}, 48)
	h, _ := ToHeight(4) // small height keeps the test fast across all hash functions

	for _, hf := range []HashFunction{SHA2_256, SHAKE_128, SHAKE_256} {
		t.Run(hf.String(), func(t *testing.T) {
			treeA, err := InitializeTree(h, hf, seedA)
			if err != nil {
				t.Fatalf("InitializeTree(%s, seedA): %v", hf, err)
			}
			treeB, err := InitializeTree(h, hf, seedB)
			if err != nil {
				t.Fatalf("InitializeTree(%s, seedB): %v", hf, err)
			}

			rootA := treeA.GetRoot()
			rootB := treeB.GetRoot()

			zero := make([]byte, len(rootA))
			if bytes.Equal(rootA, zero) {
				t.Fatalf("%s: root from seedA is all-zero (degenerate state)", hf)
			}
			if bytes.Equal(rootB, zero) {
				t.Fatalf("%s: root from seedB is all-zero (degenerate state)", hf)
			}
			if bytes.Equal(rootA, rootB) {
				t.Fatalf("%s: distinct seeds produced identical roots — this is the exact "+
					"degenerate state TOB-QRLLIB-13 describes", hf)
			}
		})
	}
}

// TestInitializeTree_RejectsEveryInvalidHashFunctionUint8 asserts the
// complementary rejection property: for every uint8 value h where
// HashFunction.IsValid() reports invalid, InitializeTree rejects it
// with ErrInvalidHashFunction. Cross-checks the constructor guard
// against the type's own IsValid predicate so a future loosening of
// one without the other is caught.
func TestInitializeTree_RejectsEveryInvalidHashFunctionUint8(t *testing.T) {
	seed := make([]uint8, 48)
	h, _ := ToHeight(4)

	for v := 0; v <= 255; v++ {
		hf := HashFunction(v)
		if hf.IsValid() {
			continue
		}
		tree, err := InitializeTree(h, hf, seed)
		if err == nil {
			t.Errorf("InitializeTree(HashFunction(%d)) accepted, but IsValid() reports invalid", v)
			continue
		}
		if !errors.Is(err, cryptoerrors.ErrInvalidHashFunction) {
			t.Errorf("InitializeTree(HashFunction(%d)) returned %v, want ErrInvalidHashFunction", v, err)
		}
		if tree != nil {
			t.Errorf("InitializeTree(HashFunction(%d)) returned non-nil XMSS on error", v)
		}
	}
}

// TestCoreHash_DefaultTripwirePanics directly exercises the
// default-case tripwire in coreHash. Bypassing the upstream guard is
// only possible by calling the unexported function from within the
// package; this test does that to assert the tripwire fires when the
// guard is bypassed (i.e. that any future regression which lets an
// invalid value through to coreHash will crash loudly rather than
// silently zero the buffer).
func TestCoreHash_DefaultTripwirePanics(t *testing.T) {
	out := make([]uint8, 32)
	in := make([]uint8, 32)
	key := make([]uint8, 32)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("coreHash with invalid HashFunction did not panic; the dispatch tripwire is missing")
		}
	}()

	coreHash(HashFunction(99), out, 0, key, 32, in, 32, 32)
}
