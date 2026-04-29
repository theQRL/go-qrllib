// Regression tests for TOB-QRLLIB-1: XMSS implementation is not fully
// compliant with RFC 8391.
//
// XMSSFastGenKeyPair takes a parametric *XMSSParams but its internal
// buffer arithmetic (`rnd = 96`, `pks = 32`, `4+2*n` / `4+3*n` slice
// offsets) is correct only for n=32, w=16, k=2. Calling it with any
// other tuple silently produced malformed keys whose pub_seed region
// was uninitialised and whose root was truncated.
//
// The function now rejects unsupported tuples with
// ErrUnsupportedParameterSet at the API boundary. These tests exercise
// each rejection path and a positive control demonstrating the
// supported tuple still produces a non-zero Merkle root.

package xmss

import (
	"bytes"
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// allocBuffers returns sk/pk slices and a BDSState sized for the
// supported n=32 layout, regardless of the params under test. We pass
// these into XMSSFastGenKeyPair to assert it rejects unsupported
// tuples at the boundary *before* it would reach into the buffers
// with the wrong arithmetic.
func allocBuffers(t *testing.T) (sk, pk []uint8, bds *BDSState) {
	t.Helper()
	sk = make([]uint8, 132) // 4 + 4*n for n=32
	pk = make([]uint8, 64)  // 2*n for n=32
	bds = NewBDSState(uint32(10), WOTSParamN, WOTSParamK)
	return
}

func TestXMSSFastGenKeyPair_RejectsUnsupportedN(t *testing.T) {
	seed := make([]uint8, 48)
	sk, pk, bds := allocBuffers(t)

	for _, n := range []uint32{16, 64, 128, 31, 33} {
		t.Run("n="+itoa(n), func(t *testing.T) {
			params := NewXMSSParams(n, 10, WOTSParamW, WOTSParamK)
			err := XMSSFastGenKeyPair(SHAKE_256, params, pk, sk, bds, seed)
			if err == nil {
				t.Fatalf("XMSSFastGenKeyPair(n=%d) accepted; want ErrUnsupportedParameterSet", n)
			}
			if !errors.Is(err, cryptoerrors.ErrUnsupportedParameterSet) {
				t.Errorf("XMSSFastGenKeyPair(n=%d) returned %v; want ErrUnsupportedParameterSet", n, err)
			}
		})
	}
}

func TestXMSSFastGenKeyPair_RejectsUnsupportedW(t *testing.T) {
	seed := make([]uint8, 48)
	sk, pk, bds := allocBuffers(t)

	// NewWOTSParams panics for log2(w) ∉ {2, 4, 8}, so the only other
	// constructible RFC 8391 w values are w=4 and w=256. Both should be
	// rejected by XMSSFastGenKeyPair since QRL only supports w=16.
	for _, w := range []uint32{4, 256} {
		t.Run("w="+itoa(w), func(t *testing.T) {
			params := NewXMSSParams(WOTSParamN, 10, w, WOTSParamK)
			err := XMSSFastGenKeyPair(SHAKE_256, params, pk, sk, bds, seed)
			if err == nil {
				t.Fatalf("XMSSFastGenKeyPair(w=%d) accepted; want ErrUnsupportedParameterSet", w)
			}
			if !errors.Is(err, cryptoerrors.ErrUnsupportedParameterSet) {
				t.Errorf("XMSSFastGenKeyPair(w=%d) returned %v; want ErrUnsupportedParameterSet", w, err)
			}
		})
	}
}

func TestXMSSFastGenKeyPair_RejectsUnsupportedK(t *testing.T) {
	seed := make([]uint8, 48)
	sk, pk, bds := allocBuffers(t)

	for _, k := range []uint32{0, 1, 4, 6} {
		t.Run("k="+itoa(k), func(t *testing.T) {
			params := NewXMSSParams(WOTSParamN, 10, WOTSParamW, k)
			err := XMSSFastGenKeyPair(SHAKE_256, params, pk, sk, bds, seed)
			if err == nil {
				t.Fatalf("XMSSFastGenKeyPair(k=%d) accepted; want ErrUnsupportedParameterSet", k)
			}
			if !errors.Is(err, cryptoerrors.ErrUnsupportedParameterSet) {
				t.Errorf("XMSSFastGenKeyPair(k=%d) returned %v; want ErrUnsupportedParameterSet", k, err)
			}
		})
	}
}

// TestXMSSFastGenKeyPairFromExpandedSeed_RejectsUnsupported asserts
// that the RFC 8391 direct-seed entry point shares the same parameter
// validation as XMSSFastGenKeyPair (TOB-QRLLIB-1). Both must reject
// any tuple outside the supported family with
// ErrUnsupportedParameterSet, regardless of which seed-derivation
// path the caller is on.
func TestXMSSFastGenKeyPairFromExpandedSeed_RejectsUnsupported(t *testing.T) {
	var expanded [96]uint8
	sk, pk, bds := allocBuffers(t)

	params := NewXMSSParams(64, 10, WOTSParamW, WOTSParamK)
	err := XMSSFastGenKeyPairFromExpandedSeed(SHAKE_256, params, pk, sk, bds, &expanded)
	if err == nil {
		t.Fatal("XMSSFastGenKeyPairFromExpandedSeed(n=64) accepted; want ErrUnsupportedParameterSet")
	}
	if !errors.Is(err, cryptoerrors.ErrUnsupportedParameterSet) {
		t.Errorf("XMSSFastGenKeyPairFromExpandedSeed(n=64) returned %v; want ErrUnsupportedParameterSet", err)
	}
}

// TestXMSSFastGenKeyPairFromExpandedSeed_AcceptsSupported is the
// positive control: the RFC 8391 direct-seed path should produce a
// well-formed keypair (non-zero pub_seed, non-zero root) given valid
// inputs.
func TestXMSSFastGenKeyPairFromExpandedSeed_AcceptsSupported(t *testing.T) {
	var expanded [96]uint8
	for i := range expanded {
		expanded[i] = byte(i)
	}
	sk := make([]uint8, 132)
	pk := make([]uint8, 64)
	bds := NewBDSState(10, WOTSParamN, WOTSParamK)

	params := NewXMSSParams(WOTSParamN, 10, WOTSParamW, WOTSParamK)
	if err := XMSSFastGenKeyPairFromExpandedSeed(SHAKE_256, params, pk, sk, bds, &expanded); err != nil {
		t.Fatalf("XMSSFastGenKeyPairFromExpandedSeed: %v", err)
	}
	if bytes.Equal(pk[:32], make([]byte, 32)) {
		t.Fatal("root region of pk is zero; key is degenerate")
	}
	if bytes.Equal(pk[32:], make([]byte, 32)) {
		t.Fatal("pub_seed region of pk is zero; key is degenerate")
	}
}

// TestInitializeTreeFromExpandedSeed_HappyPath exercises the
// public direct-seed entry point. The rfc8391 sub-package wraps
// this; cross-package test coverage isn't attributed by `go test
// -coverprofile`, so this in-package test covers it.
func TestInitializeTreeFromExpandedSeed_HappyPath(t *testing.T) {
	var expanded [96]uint8
	for i := range expanded {
		expanded[i] = byte(i)
	}
	h, _ := ToHeight(10)
	tree, err := InitializeTreeFromExpandedSeed(h, SHAKE_256, &expanded)
	if err != nil {
		t.Fatalf("InitializeTreeFromExpandedSeed: %v", err)
	}
	if tree == nil {
		t.Fatal("InitializeTreeFromExpandedSeed returned nil tree without error")
	}
	if bytes.Equal(tree.GetRoot(), make([]byte, 32)) {
		t.Fatal("root is zero; key is degenerate")
	}
	// Round-trip sign/verify proves the tree is functional.
	msg := []byte("InitializeTreeFromExpandedSeed round-trip")
	sig, err := tree.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pk := append(tree.GetRoot(), tree.GetPKSeed()...)
	if !Verify(SHAKE_256, msg, sig, pk) {
		t.Fatal("Verify rejected a signature produced by the same key")
	}
}

func TestInitializeTreeFromExpandedSeed_RejectsInvalidInputs(t *testing.T) {
	var expanded [96]uint8
	h, _ := ToHeight(10)

	t.Run("nil_seed", func(t *testing.T) {
		if _, err := InitializeTreeFromExpandedSeed(h, SHAKE_256, nil); err == nil {
			t.Fatal("InitializeTreeFromExpandedSeed(nil) accepted; want error")
		} else if !errors.Is(err, cryptoerrors.ErrInvalidSeed) {
			t.Errorf("err = %v; want ErrInvalidSeed", err)
		}
	})

	t.Run("invalid_hash_function", func(t *testing.T) {
		_, err := InitializeTreeFromExpandedSeed(h, HashFunction(99), &expanded)
		if !errors.Is(err, cryptoerrors.ErrInvalidHashFunction) {
			t.Errorf("err = %v; want ErrInvalidHashFunction", err)
		}
	})

	t.Run("invalid_height", func(t *testing.T) {
		_, err := InitializeTreeFromExpandedSeed(Height(99), SHAKE_256, &expanded)
		if !errors.Is(err, cryptoerrors.ErrInvalidHeight) {
			t.Errorf("err = %v; want ErrInvalidHeight", err)
		}
	})

	t.Run("invalid_bds_h2", func(t *testing.T) {
		// h=2 is IsValid but k>=h fails the BDS check
		_, err := InitializeTreeFromExpandedSeed(Height(2), SHAKE_256, &expanded)
		if !errors.Is(err, cryptoerrors.ErrInvalidBDSParams) {
			t.Errorf("err = %v; want ErrInvalidBDSParams", err)
		}
	})
}

// TestXMSSFastGenKeyPair_AcceptsSupportedTuple is the positive control
// — for the documented supported tuple (n=32, w=16, k=2, h=10) the
// function must succeed AND produce a non-zero pub_seed and Merkle
// root. Without this, a regression that makes the function reject
// everything (e.g. by inverting the guard) would make the negative
// tests above pass trivially.
func TestXMSSFastGenKeyPair_AcceptsSupportedTuple(t *testing.T) {
	seed := bytes.Repeat([]byte{0xAA}, 48)
	sk := make([]uint8, 132)
	pk := make([]uint8, 64)
	bds := NewBDSState(10, WOTSParamN, WOTSParamK)

	params := NewXMSSParams(WOTSParamN, 10, WOTSParamW, WOTSParamK)
	if err := XMSSFastGenKeyPair(SHAKE_256, params, pk, sk, bds, seed); err != nil {
		t.Fatalf("XMSSFastGenKeyPair(supported tuple): %v", err)
	}

	// Root is the first 32 bytes of pk.
	if bytes.Equal(pk[:32], make([]byte, 32)) {
		t.Fatal("pub_seed region of pk is zero; key is degenerate")
	}
	// pub_seed is the second 32 bytes of pk.
	if bytes.Equal(pk[32:], make([]byte, 32)) {
		t.Fatal("root region of pk is zero; key is degenerate")
	}
}

// itoa is a tiny dependency-free integer-to-string helper for the
// subtest names; the standard strconv would also do but keeps the
// test file's imports tighter.
func itoa(u uint32) string {
	if u == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	return string(buf[i:])
}
