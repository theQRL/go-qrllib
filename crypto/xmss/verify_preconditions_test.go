package xmss

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// Regression tests for the public-API preconditions of the raw XMSS tier
// (2026-10 review): Verify must refuse — never panic on — an invalid
// HashFunction or a non-canonical public-key length, and the exported
// key-generation entry points must refuse bad output buffers and BDS state
// the same way InitializeTree does.

// newVerifyFixture returns a verified message/signature/public-key triple
// from a fixed-seed height-4 SHAKE_256 tree.
func newVerifyFixture(t *testing.T) (msg, sig, pk []uint8) {
	t.Helper()
	seed := bytes.Repeat([]byte{0x42}, SeedSize)
	h, err := ToHeight(4)
	if err != nil {
		t.Fatalf("ToHeight: %v", err)
	}
	tree, err := InitializeTree(h, SHAKE_256, seed)
	if err != nil {
		t.Fatalf("InitializeTree: %v", err)
	}
	msg = []byte("precondition fixture")
	sig, err = tree.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pk = append(tree.GetRoot(), tree.GetPKSeed()...)
	if !Verify(SHAKE_256, msg, sig, pk) {
		t.Fatal("control: valid signature did not verify")
	}
	return msg, sig, pk
}

// noPanicBool runs f, failing the test if it panics.
func noPanicBool(t *testing.T, name string, f func() bool) (result bool) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", name, r)
		}
	}()
	return f()
}

// noPanicErr runs f, failing the test if it panics.
func noPanicErr(t *testing.T, name string, f func() error) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", name, r)
		}
	}()
	return f()
}

// Every HashFunction value outside {SHA2_256, SHAKE_128, SHAKE_256} must make
// Verify and VerifyWithCustomWOTSParamW return false. Before the boundary
// guard, an invalid value flowed to coreHash's invariant tripwire and panicked.
func TestVerify_RejectsInvalidHashFunction(t *testing.T) {
	msg, sig, pk := newVerifyFixture(t)
	invalid := 0
	for v := 0; v <= 255; v++ {
		hf := HashFunction(uint8(v))
		if hf.IsValid() {
			continue
		}
		invalid++
		if noPanicBool(t, fmt.Sprintf("Verify(HashFunction(%d))", v), func() bool {
			return Verify(hf, msg, sig, pk)
		}) {
			t.Errorf("Verify(HashFunction(%d)) = true, want false", v)
		}
		if noPanicBool(t, fmt.Sprintf("VerifyWithCustomWOTSParamW(HashFunction(%d))", v), func() bool {
			return VerifyWithCustomWOTSParamW(hf, msg, sig, pk, WOTSParamW)
		}) {
			t.Errorf("VerifyWithCustomWOTSParamW(HashFunction(%d)) = true, want false", v)
		}
	}
	if invalid != 253 {
		t.Fatalf("expected 253 invalid HashFunction values, iterated %d", invalid)
	}
}

// The public key is exactly root || pub_seed (64 bytes); trailing bytes used
// to be silently ignored, letting two byte strings name one key.
func TestVerify_RequiresExactPublicKeyLength(t *testing.T) {
	msg, sig, pk := newVerifyFixture(t)
	for _, extra := range []int{1, 36} {
		long := append(append([]uint8{}, pk...), make([]uint8, extra)...)
		if Verify(SHAKE_256, msg, sig, long) {
			t.Errorf("pk with %d trailing bytes (len %d) verified; want false", extra, len(long))
		}
	}
	if Verify(SHAKE_256, msg, sig, pk[:63]) {
		t.Error("63-byte pk verified; want false")
	}
	if Verify(SHAKE_256, msg, sig, nil) {
		t.Error("nil pk verified; want false")
	}
}

// The exported key-generation functions must refuse the inputs that would
// otherwise panic inside xmssFastGenKeyPairCore — short output buffers, a nil
// BDS state, and a height that cannot form a BDS state (h <= k) — using the
// same errors InitializeTree uses, and without touching pk on the error path.
func TestXMSSFastGenKeyPair_RejectsBadOutputs(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, SeedSize)
	var expanded [96]uint8
	params4 := NewXMSSParams(WOTSParamN, 4, WOTSParamW, WOTSParamK)

	cases := []struct {
		name   string
		params *XMSSParams
		pkLen  int
		skLen  int
		bds    *BDSState
		want   error
	}{
		{"short_pk", params4, 10, 132, NewBDSState(4, WOTSParamN, WOTSParamK), cryptoerrors.ErrBufferTooSmall},
		{"short_sk", params4, 64, 0, NewBDSState(4, WOTSParamN, WOTSParamK), cryptoerrors.ErrBufferTooSmall},
		{"nil_bds", params4, 64, 132, nil, cryptoerrors.ErrInvalidBDSParams},
		// h=2 passes the [2, MaxHeight] range but NewBDSState(2, 32, 2) is nil
		// because h <= k; the params validator must reject it before anything
		// dereferences that nil, exactly as InitializeTree does.
		{"height_2_not_bds_capable", NewXMSSParams(WOTSParamN, 2, WOTSParamW, WOTSParamK), 64, 132, NewBDSState(2, WOTSParamN, WOTSParamK), cryptoerrors.ErrInvalidBDSParams},
		{"nil_params", nil, 64, 132, NewBDSState(4, WOTSParamN, WOTSParamK), cryptoerrors.ErrUnsupportedParameterSet},
		// A BDS state built for another tree passes a nil check but not a
		// dimension check: n = 1 makes every buffer too short (slice bounds
		// panic in the core before this check); height 6 makes them too long
		// and desynchronises the traversal state from the tree.
		{"bds_built_for_n_1", params4, 64, 132, NewBDSState(4, 1, WOTSParamK), cryptoerrors.ErrInvalidBDSParams},
		{"bds_built_for_height_6", params4, 64, 132, NewBDSState(6, WOTSParamN, WOTSParamK), cryptoerrors.ErrInvalidBDSParams},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pk := make([]uint8, tc.pkLen)
			sk := make([]uint8, tc.skLen)
			err := noPanicErr(t, "XMSSFastGenKeyPair", func() error {
				return XMSSFastGenKeyPair(SHAKE_256, tc.params, pk, sk, tc.bds, seed)
			})
			if !errors.Is(err, tc.want) {
				t.Errorf("XMSSFastGenKeyPair = %v, want %v", err, tc.want)
			}
			err = noPanicErr(t, "XMSSFastGenKeyPairFromExpandedSeed", func() error {
				return XMSSFastGenKeyPairFromExpandedSeed(SHAKE_256, tc.params, pk, sk, tc.bds, &expanded)
			})
			if !errors.Is(err, tc.want) {
				t.Errorf("XMSSFastGenKeyPairFromExpandedSeed = %v, want %v", err, tc.want)
			}
			if !bytes.Equal(pk, make([]uint8, tc.pkLen)) {
				t.Error("pk was written on the error path")
			}
		})
	}

	// Positive control: correctly sized inputs still succeed.
	pk := make([]uint8, 64)
	sk := make([]uint8, 132)
	if err := XMSSFastGenKeyPair(SHAKE_256, params4, pk, sk, NewBDSState(4, WOTSParamN, WOTSParamK), seed); err != nil {
		t.Fatalf("control XMSSFastGenKeyPair: %v", err)
	}
	if bytes.Equal(pk, make([]uint8, 64)) {
		t.Fatal("control produced an all-zero pk")
	}
}

// A nil expanded seed is refused before the index bytes of sk are written.
func TestXMSSFastGenKeyPairFromExpandedSeed_RejectsNilSeed(t *testing.T) {
	params4 := NewXMSSParams(WOTSParamN, 4, WOTSParamW, WOTSParamK)
	pk := make([]uint8, 64)
	sk := bytes.Repeat([]uint8{0xAA}, 132)
	err := noPanicErr(t, "XMSSFastGenKeyPairFromExpandedSeed", func() error {
		return XMSSFastGenKeyPairFromExpandedSeed(SHAKE_256, params4, pk, sk, NewBDSState(4, WOTSParamN, WOTSParamK), nil)
	})
	if !errors.Is(err, cryptoerrors.ErrInvalidSeed) {
		t.Errorf("nil expanded seed: error = %v, want ErrInvalidSeed", err)
	}
	if !bytes.Equal(sk, bytes.Repeat([]uint8{0xAA}, 132)) {
		t.Error("sk was written on the error path")
	}
}

// fits must also notice a tree-hash instance that is missing or sized for
// another n, which no constructor produces but a hand-built state could.
func TestBDSStateFits_TreeHashInstances(t *testing.T) {
	params4 := NewXMSSParams(WOTSParamN, 4, WOTSParamW, WOTSParamK)
	good := NewBDSState(4, WOTSParamN, WOTSParamK)
	if !good.fits(params4) {
		t.Fatal("freshly built state does not fit its own parameters")
	}
	missing := NewBDSState(4, WOTSParamN, WOTSParamK)
	missing.treeHash[0] = nil
	if missing.fits(params4) {
		t.Error("state with a nil tree-hash instance fits")
	}
	short := NewBDSState(4, WOTSParamN, WOTSParamK)
	short.treeHash[1].node = make([]uint8, WOTSParamN-1)
	if short.fits(params4) {
		t.Error("state with a short tree-hash node fits")
	}
	var none *BDSState
	if none.fits(params4) || good.fits(nil) {
		t.Error("nil state or nil params fit")
	}
}
