package rfc8391

import (
	"bytes"
	"errors"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/xmss"
)

// fixedSeed96 returns a deterministic 96-byte seed for round-trip
// testing. Using a fixed value makes failures reproducible.
func fixedSeed96(b byte) [ExpandedSeedSize]uint8 {
	var s [ExpandedSeedSize]uint8
	for i := range s {
		s[i] = b
	}
	return s
}

func TestParameterSet_IsSupported(t *testing.T) {
	supported := []ParameterSet{
		XMSS_SHA2_10_256, XMSS_SHA2_16_256, XMSS_SHA2_20_256,
		XMSS_SHAKE_10_256, XMSS_SHAKE_16_256, XMSS_SHAKE_20_256,
	}
	for _, p := range supported {
		t.Run(p.String(), func(t *testing.T) {
			if !p.IsSupported() {
				t.Errorf("ParameterSet(0x%08x).IsSupported() = false; want true", uint32(p))
			}
		})
	}

	// n=64 family from RFC 8391 §5.3
	unsupported := []ParameterSet{
		0x00000004, // XMSS-SHA2_10_512
		0x00000005, // XMSS-SHA2_16_512
		0x00000006, // XMSS-SHA2_20_512
		0x0000000a, // XMSS-SHAKE_10_512
		0x0000000b, // XMSS-SHAKE_16_512
		0x0000000c, // XMSS-SHAKE_20_512
		0x00000000, // not assigned
		0xdeadbeef, // arbitrary garbage
	}
	for _, p := range unsupported {
		t.Run(p.String(), func(t *testing.T) {
			if p.IsSupported() {
				t.Errorf("ParameterSet(0x%08x).IsSupported() = true; want false", uint32(p))
			}
		})
	}
}

func TestParameterSet_HeightAndHashFunction(t *testing.T) {
	cases := []struct {
		p    ParameterSet
		h    uint8
		hash xmss.HashFunction
	}{
		{XMSS_SHA2_10_256, 10, xmss.SHA2_256},
		{XMSS_SHA2_16_256, 16, xmss.SHA2_256},
		{XMSS_SHA2_20_256, 20, xmss.SHA2_256},
		{XMSS_SHAKE_10_256, 10, xmss.SHAKE_256},
		{XMSS_SHAKE_16_256, 16, xmss.SHAKE_256},
		{XMSS_SHAKE_20_256, 20, xmss.SHAKE_256},
	}
	for _, c := range cases {
		t.Run(c.p.String(), func(t *testing.T) {
			h, err := c.p.Height()
			if err != nil {
				t.Fatalf("Height: %v", err)
			}
			if uint8(h) != c.h {
				t.Errorf("Height = %d; want %d", h, c.h)
			}
			hf, err := c.p.HashFunction()
			if err != nil {
				t.Fatalf("HashFunction: %v", err)
			}
			if hf != c.hash {
				t.Errorf("HashFunction = %s; want %s", hf, c.hash)
			}
		})
	}

	t.Run("unsupported_OID_returns_error", func(t *testing.T) {
		var p ParameterSet = 0x00000004 // XMSS-SHA2_10_512
		if _, err := p.Height(); !errors.Is(err, ErrUnsupportedParameterSet) {
			t.Errorf("Height(unsupported) = %v; want ErrUnsupportedParameterSet", err)
		}
		if _, err := p.HashFunction(); !errors.Is(err, ErrUnsupportedParameterSet) {
			t.Errorf("HashFunction(unsupported) = %v; want ErrUnsupportedParameterSet", err)
		}
	})
}

// TestInferParameterSet_AllSupportedCombinations exercises the
// HashFunction × Height → ParameterSet mapping for every supported
// pair without paying the cost of full keypair generation. The mapping
// itself is the point of inferParameterSet; we pin every branch.
func TestInferParameterSet_AllSupportedCombinations(t *testing.T) {
	cases := []struct {
		hf   xmss.HashFunction
		h    uint8
		want ParameterSet
	}{
		{xmss.SHA2_256, 10, XMSS_SHA2_10_256},
		{xmss.SHA2_256, 16, XMSS_SHA2_16_256},
		{xmss.SHA2_256, 20, XMSS_SHA2_20_256},
		{xmss.SHAKE_256, 10, XMSS_SHAKE_10_256},
		{xmss.SHAKE_256, 16, XMSS_SHAKE_16_256},
		{xmss.SHAKE_256, 20, XMSS_SHAKE_20_256},
	}
	for _, c := range cases {
		t.Run(c.want.String(), func(t *testing.T) {
			got, err := inferParameterSet(c.hf, xmss.Height(c.h))
			if err != nil {
				t.Fatalf("inferParameterSet(%s, %d): %v", c.hf, c.h, err)
			}
			if got != c.want {
				t.Errorf("inferParameterSet = 0x%08x; want 0x%08x", uint32(got), uint32(c.want))
			}
		})
	}
}

func TestInferParameterSet_RejectsUnsupportedCombinations(t *testing.T) {
	cases := []struct {
		name string
		hf   xmss.HashFunction
		h    uint8
	}{
		{"SHAKE_128_h10", xmss.SHAKE_128, 10},
		{"SHA2_256_h12", xmss.SHA2_256, 12}, // valid h but no RFC OID
		{"SHA2_256_h8", xmss.SHA2_256, 8},
		{"SHAKE_256_h14", xmss.SHAKE_256, 14},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := inferParameterSet(c.hf, xmss.Height(c.h))
			if !errors.Is(err, ErrUnsupportedParameterSet) {
				t.Errorf("inferParameterSet(%s, %d) = %v; want ErrUnsupportedParameterSet", c.hf, c.h, err)
			}
		})
	}
}

func TestNewKeyPair_RejectsUnsupportedParameterSet(t *testing.T) {
	seed := fixedSeed96(0x42)
	_, err := NewKeyPair(0x00000004, &seed) // XMSS-SHA2_10_512
	if !errors.Is(err, ErrUnsupportedParameterSet) {
		t.Errorf("NewKeyPair(unsupported) = %v; want ErrUnsupportedParameterSet", err)
	}
}

// TestNewKeyPair_DeterministicRoot pins the property that the derived
// root depends ONLY on the 96 bytes of expanded seed (and the
// parameter set), not on any QRL-specific intermediate state. Two
// independent calls with the same seed must produce the same root.
// This is the property RFC 8391 reference impls rely on for
// reproducible test vectors.
func TestNewKeyPair_DeterministicRoot(t *testing.T) {
	seed := fixedSeed96(0x42)

	x1, err := NewKeyPair(XMSS_SHA2_10_256, &seed)
	if err != nil {
		t.Fatalf("NewKeyPair #1: %v", err)
	}
	x2, err := NewKeyPair(XMSS_SHA2_10_256, &seed)
	if err != nil {
		t.Fatalf("NewKeyPair #2: %v", err)
	}
	if !bytes.Equal(x1.GetRoot(), x2.GetRoot()) {
		t.Errorf("NewKeyPair: same seed produced different roots\n  #1=%x\n  #2=%x",
			x1.GetRoot(), x2.GetRoot())
	}
	if !bytes.Equal(x1.GetPKSeed(), x2.GetPKSeed()) {
		t.Errorf("NewKeyPair: same seed produced different pub_seeds")
	}
}

func TestNewKeyPair_DistinctSeedsProduceDistinctRoots(t *testing.T) {
	seedA := fixedSeed96(0xAA)
	seedB := fixedSeed96(0xBB)

	xa, err := NewKeyPair(XMSS_SHA2_10_256, &seedA)
	if err != nil {
		t.Fatalf("NewKeyPair seedA: %v", err)
	}
	xb, err := NewKeyPair(XMSS_SHA2_10_256, &seedB)
	if err != nil {
		t.Fatalf("NewKeyPair seedB: %v", err)
	}
	if bytes.Equal(xa.GetRoot(), xb.GetRoot()) {
		t.Fatal("Different seeds produced identical roots; this is the degenerate state TOB-QRLLIB-13 describes")
	}
}

// TestNewKeyPair_DiffersFromInitializeTree pins the contract that the
// rfc8391 entry point and the QRL [xmss.InitializeTree] entry point
// produce DIFFERENT keypairs even when given seed material that
// looks similar. This is by design: the QRL path SHAKE256-expands a
// 48-byte seed, the RFC path takes 96 bytes directly. A future edit
// that accidentally collapsed the two paths would re-introduce
// confusion about which derivation is in use.
func TestNewKeyPair_DiffersFromInitializeTree(t *testing.T) {
	// 48-byte seed for the QRL path, 96-byte seed for the RFC path.
	// They have the same first 48 bytes but the QRL path expands
	// those into a different 96 bytes than the RFC path's literal 96.
	qrlSeed := bytes.Repeat([]byte{0x42}, 48)
	var rfcSeed [ExpandedSeedSize]uint8
	for i := range rfcSeed {
		rfcSeed[i] = 0x42
	}

	h, _ := xmss.ToHeight(10)
	qrlTree, err := xmss.InitializeTree(h, xmss.SHA2_256, qrlSeed)
	if err != nil {
		t.Fatalf("InitializeTree: %v", err)
	}
	rfcTree, err := NewKeyPair(XMSS_SHA2_10_256, &rfcSeed)
	if err != nil {
		t.Fatalf("NewKeyPair: %v", err)
	}
	if bytes.Equal(qrlTree.GetRoot(), rfcTree.GetRoot()) {
		t.Fatal("QRL and RFC paths produced the same root for matching-byte seeds; " +
			"the SHAKE256 expansion step has collapsed and the two derivations are no longer distinguishable")
	}
}

// TestRoundTrip_SignViaRFC8391_VerifyViaXMSS demonstrates the
// bidirectional interop scenario: keypair generated via the RFC 8391
// path, signature produced, then verified via the QRL xmss.Verify
// entry point. Both directions must succeed for cross-verify to be
// meaningful.
func TestRoundTrip_SignViaRFC8391_VerifyViaXMSS(t *testing.T) {
	for _, p := range []ParameterSet{
		XMSS_SHA2_10_256,
		XMSS_SHAKE_10_256,
	} {
		t.Run(p.String(), func(t *testing.T) {
			seed := fixedSeed96(0x77)
			tree, err := NewKeyPair(p, &seed)
			if err != nil {
				t.Fatalf("NewKeyPair: %v", err)
			}

			msg := []byte("rfc8391 round-trip test message")
			sig, err := tree.Sign(msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			// Construct the xmss.Verify-style pk: root || pub_seed.
			rootPubSeed := append(tree.GetRoot(), tree.GetPKSeed()...)
			hf, _ := p.HashFunction()
			if !xmss.Verify(hf, msg, sig, rootPubSeed) {
				t.Fatal("xmss.Verify rejected a signature produced by the rfc8391 keypair")
			}

			// Same signature, but verify through the rfc8391 wrapper
			// (which takes an RFC-format public key).
			rfcPK, err := MarshalPublicKey(tree)
			if err != nil {
				t.Fatalf("MarshalPublicKey: %v", err)
			}
			ok, err := Verify(msg, sig, rfcPK)
			if err != nil {
				t.Fatalf("rfc8391.Verify: %v", err)
			}
			if !ok {
				t.Fatal("rfc8391.Verify rejected a signature it should accept")
			}
		})
	}
}

// TestMarshalUnmarshalPublicKey_RoundTrip exercises the marshal/
// unmarshal round-trip via real keypair generation. Restricted to
// h=10 so the test is fast; the marshal/unmarshal logic itself is
// height-agnostic and is exhaustively exercised by the byte-level
// test below for every supported OID.
func TestMarshalUnmarshalPublicKey_RoundTrip(t *testing.T) {
	for _, p := range []ParameterSet{XMSS_SHA2_10_256, XMSS_SHAKE_10_256} {
		t.Run(p.String(), func(t *testing.T) {
			seed := fixedSeed96(0x11)
			tree, err := NewKeyPair(p, &seed)
			if err != nil {
				t.Fatalf("NewKeyPair: %v", err)
			}

			marshalled, err := MarshalPublicKey(tree)
			if err != nil {
				t.Fatalf("MarshalPublicKey: %v", err)
			}
			if len(marshalled) != PublicKeySize {
				t.Errorf("MarshalPublicKey returned %d bytes; want %d", len(marshalled), PublicKeySize)
			}

			gotP, root, pubSeed, err := UnmarshalPublicKey(marshalled)
			if err != nil {
				t.Fatalf("UnmarshalPublicKey: %v", err)
			}
			if gotP != p {
				t.Errorf("Unmarshalled OID = 0x%08x; want 0x%08x", uint32(gotP), uint32(p))
			}
			if !bytes.Equal(root[:], tree.GetRoot()) {
				t.Errorf("Unmarshalled root != tree root")
			}
			if !bytes.Equal(pubSeed[:], tree.GetPKSeed()) {
				t.Errorf("Unmarshalled pub_seed != tree pub_seed")
			}
		})
	}
}

// TestUnmarshalPublicKey_AllSupportedOIDs covers the
// `UnmarshalPublicKey` path for every supported OID without paying
// the cost of full keypair generation. The unmarshal logic only
// inspects the 4-byte OID prefix, so synthetic byte-level inputs are
// sufficient and let us test all six OIDs cheaply.
func TestUnmarshalPublicKey_AllSupportedOIDs(t *testing.T) {
	for _, p := range []ParameterSet{
		XMSS_SHA2_10_256, XMSS_SHA2_16_256, XMSS_SHA2_20_256,
		XMSS_SHAKE_10_256, XMSS_SHAKE_16_256, XMSS_SHAKE_20_256,
	} {
		t.Run(p.String(), func(t *testing.T) {
			pk := make([]byte, PublicKeySize)
			pk[0] = byte(uint32(p) >> 24)
			pk[1] = byte(uint32(p) >> 16)
			pk[2] = byte(uint32(p) >> 8)
			pk[3] = byte(uint32(p))
			// Fill root and pub_seed with distinguishable patterns so
			// we can verify the slice boundaries are correct.
			for i := 4; i < 36; i++ {
				pk[i] = 0xAA
			}
			for i := 36; i < 68; i++ {
				pk[i] = 0xBB
			}

			gotP, root, pubSeed, err := UnmarshalPublicKey(pk)
			if err != nil {
				t.Fatalf("UnmarshalPublicKey: %v", err)
			}
			if gotP != p {
				t.Errorf("OID = 0x%08x; want 0x%08x", uint32(gotP), uint32(p))
			}
			expectedRoot := bytes.Repeat([]byte{0xAA}, 32)
			expectedPubSeed := bytes.Repeat([]byte{0xBB}, 32)
			if !bytes.Equal(root[:], expectedRoot) {
				t.Errorf("root = %x; want all-AA", root[:])
			}
			if !bytes.Equal(pubSeed[:], expectedPubSeed) {
				t.Errorf("pub_seed = %x; want all-BB", pubSeed[:])
			}
		})
	}
}

func TestUnmarshalPublicKey_RejectsWrongLength(t *testing.T) {
	cases := []int{0, 1, 67, 69, 100}
	for _, n := range cases {
		t.Run("len="+itoa(n), func(t *testing.T) {
			_, _, _, err := UnmarshalPublicKey(make([]byte, n))
			if !errors.Is(err, ErrInvalidPublicKeyLength) {
				t.Errorf("UnmarshalPublicKey(len=%d) = %v; want ErrInvalidPublicKeyLength", n, err)
			}
		})
	}
}

func TestUnmarshalPublicKey_RejectsUnsupportedOID(t *testing.T) {
	pk := make([]byte, PublicKeySize)
	pk[3] = 0x04 // XMSS-SHA2_10_512 — n=64, unsupported

	_, _, _, err := UnmarshalPublicKey(pk)
	if !errors.Is(err, ErrUnsupportedParameterSet) {
		t.Errorf("UnmarshalPublicKey(unsupported OID) = %v; want ErrUnsupportedParameterSet", err)
	}
}

// TestMarshalPublicKey_RejectsNonRFCParameterSet asserts that a tree
// constructed with the legacy QRL-only SHAKE_128 hash function (which
// has no RFC 8391 OID) cannot be marshalled to RFC format. This is
// the contract that prevents callers from accidentally using
// SHAKE_128 keys in cross-implementation contexts.
func TestMarshalPublicKey_RejectsNonRFCParameterSet(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 48)
	h, _ := xmss.ToHeight(10)
	tree, err := xmss.InitializeTree(h, xmss.SHAKE_128, seed)
	if err != nil {
		t.Fatalf("InitializeTree(SHAKE_128): %v", err)
	}
	if _, err := MarshalPublicKey(tree); !errors.Is(err, ErrUnsupportedParameterSet) {
		t.Errorf("MarshalPublicKey(SHAKE_128 tree) = %v; want ErrUnsupportedParameterSet", err)
	}
}

func TestVerify_PropagatesUnmarshalError(t *testing.T) {
	// rfcPK is too short → UnmarshalPublicKey returns ErrInvalidPublicKeyLength;
	// Verify should propagate it rather than panicking on the slice access.
	ok, err := Verify([]byte("msg"), []byte("sig"), []byte{0, 0, 0, 1})
	if ok {
		t.Error("Verify(short pk) returned ok=true; want false")
	}
	if !errors.Is(err, ErrInvalidPublicKeyLength) {
		t.Errorf("Verify(short pk) err = %v; want ErrInvalidPublicKeyLength", err)
	}
}

func TestVerify_RejectsTamperedSignature(t *testing.T) {
	seed := fixedSeed96(0x33)
	tree, err := NewKeyPair(XMSS_SHA2_10_256, &seed)
	if err != nil {
		t.Fatalf("NewKeyPair: %v", err)
	}
	msg := []byte("verify test message")
	sig, err := tree.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	rfcPK, err := MarshalPublicKey(tree)
	if err != nil {
		t.Fatalf("MarshalPublicKey: %v", err)
	}

	// Sanity: untampered signature verifies.
	ok, err := Verify(msg, sig, rfcPK)
	if err != nil || !ok {
		t.Fatalf("Verify(valid) = (%v, %v); want (true, nil)", ok, err)
	}

	// Tamper with the signature byte.
	sig[100] ^= 0xFF
	ok, err = Verify(msg, sig, rfcPK)
	if err != nil {
		t.Fatalf("Verify(tampered) returned unexpected error: %v", err)
	}
	if ok {
		t.Fatal("Verify(tampered) accepted a tampered signature; want false")
	}
}

// itoa is a tiny dependency-free integer-to-string helper for subtest
// names; saves importing strconv.
func itoa(u int) string {
	if u == 0 {
		return "0"
	}
	neg := u < 0
	if neg {
		u = -u
	}
	var buf [20]byte
	i := len(buf)
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
