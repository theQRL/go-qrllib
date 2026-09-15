// Security regression tests for finding H1: the all-zero-t1 ML-DSA-87
// public key is universally forgeable.
//
// With t1 = 0 the verifier reconstructs
//
//	w1' = UseHint(h, A·z - c·2^d·t1)
//
// A forger picks z = 0 and h = 0, so the argument collapses to 0 and
// UseHint(0, 0) = 0 regardless of the challenge c. The challenge no
// longer constrains the signature, so the forger sets
//
//	c~ = SHAKE256(mu || w1Encode(0))
//
// which is exactly the value the verifier recomputes. This needs only
// public data (the public-key bytes, the context and the message); no
// secret key is involved. It is the ML-DSA analogue of the BLS
// infinity-public-key forgery that BLS libraries reject at key import.
//
// SECURE EXPECTATION (what these tests assert): Verify / Open MUST
// reject any public key whose t1 region (bytes SEED_BYTES..end) is all
// zero. Until that guard is added these security assertions FAIL,
// demonstrating the live forgery; once the guard lands they pass and
// guard against regression.
//
// The helper-sanity and control tests below hold both before and after
// the fix, so a failure in TestVerify_RejectsZeroT1Forgery is
// unambiguously the missing key check, not malformed test input.

package ml_dsa_87

import (
	"crypto/sha3"
	"testing"
)

// forgeZeroT1Sig builds a signature that a t1 = 0 public key accepts,
// using only public inputs (pk bytes, ctx, msg). z = 0, h = 0, and the
// challenge is the hash the verifier will recompute for w1 = 0.
func forgeZeroT1Sig(t *testing.T, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8, ctx, msg []uint8) [CRYPTO_BYTES]uint8 {
	t.Helper()

	// pre = 0x00 || len(ctx) || ctx   (see cryptoSignVerify)
	pre := make([]uint8, len(ctx)+2)
	pre[0] = 0
	pre[1] = uint8(len(ctx))
	copy(pre[2:], ctx)

	// tr = SHAKE256(pk)[:TR_BYTES]
	var tr [TR_BYTES]uint8
	copy(tr[:], sha3.SumSHAKE256(pk[:], TR_BYTES))

	// mu = SHAKE256(tr || pre || msg)[:CRH_BYTES]
	var mu [CRH_BYTES]uint8
	st := sha3.NewSHAKE256()
	_, _ = st.Write(tr[:])
	_, _ = st.Write(pre)
	_, _ = st.Write(msg)
	_, _ = st.Read(mu[:])

	// For z = h = t1 = 0 the verifier reconstructs w1 = 0, so
	// w1Encode(w1) is K*POLY_W1_PACKED_BYTES zero bytes.
	var w1enc [K * POLY_W1_PACKED_BYTES]uint8
	var cTilde [C_TILDE_BYTES]uint8
	st.Reset()
	_, _ = st.Write(mu[:])
	_, _ = st.Write(w1enc[:])
	_, _ = st.Read(cTilde[:])

	var z polyVecL // zero
	var h polyVecK // zero
	var sig [CRYPTO_BYTES]uint8
	if err := packSig(sig[:], cTilde, &z, &h); err != nil {
		t.Fatalf("packSig: %v", err)
	}
	return sig
}

// zeroT1PK returns a public key with the given rho bytes and an all-zero
// t1 region. rho == nil yields an all-zero public key.
func zeroT1PK(rho []uint8) *[CRYPTO_PUBLIC_KEY_BYTES]uint8 {
	var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
	copy(pk[:SEED_BYTES], rho)
	return &pk
}

// TestVerify_RejectsZeroT1Forgery is the security assertion. It FAILS
// against the current (unpatched) code, demonstrating the forgery, and
// PASSES once Verify rejects all-zero-t1 public keys.
func TestVerify_RejectsZeroT1Forgery(t *testing.T) {
	zondCtx := []uint8{'Z', 'O', 'N', 'D'}

	cases := []struct {
		name string
		rho  []uint8
		ctx  []uint8
		msg  []uint8
	}{
		{"all-zero pk, ZOND ctx", nil, zondCtx, []uint8("attacker chosen message #1")},
		{"all-zero pk, second message", nil, zondCtx, []uint8("a completely different message #2")},
		{"all-zero pk, empty ctx", nil, []uint8{}, []uint8("empty-ctx forgery")},
		{"non-zero rho, zero t1", []uint8{1, 2, 3, 4, 5, 6, 7, 8}, zondCtx, []uint8("rho does not save you")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pk := zeroT1PK(tc.rho)
			sig := forgeZeroT1Sig(t, pk, tc.ctx, tc.msg)

			if Verify(tc.ctx, tc.msg, sig, pk) {
				t.Fatal("SECURITY (finding H1): a forged signature verified under an " +
					"all-zero-t1 public key; Verify must reject public keys whose t1 " +
					"region is all zero")
			}

			// Open (attached form) must reject it too.
			sealed := make([]uint8, CRYPTO_BYTES+len(tc.msg))
			copy(sealed[:CRYPTO_BYTES], sig[:])
			copy(sealed[CRYPTO_BYTES:], tc.msg)
			if _, err := Open(tc.ctx, sealed, pk); err == nil {
				t.Fatal("SECURITY (finding H1): Open accepted a forged attached " +
					"signature under an all-zero-t1 public key")
			}
		})
	}
}

// TestZeroT1Forgery_HelperProducesWellFormedSig proves the forged
// signature is structurally valid input (correct length, decodes, z in
// range). This holds regardless of the fix, so a rejection in the
// security test above cannot be blamed on malformed test material.
func TestZeroT1Forgery_HelperProducesWellFormedSig(t *testing.T) {
	pk := zeroT1PK(nil)
	sig := forgeZeroT1Sig(t, pk, []uint8{'Z', 'O', 'N', 'D'}, []uint8("well-formedness check"))

	var c [C_TILDE_BYTES]uint8
	var z polyVecL
	var h polyVecK
	if unpackSig(&c, &z, &h, sig) != 0 {
		t.Fatal("forged signature failed structural unpacking; it must be a " +
			"well-formed signature so that rejection is attributable to the key check")
	}
	if polyVecLChkNorm(&z, GAMMA1-BETA) != 0 {
		t.Fatal("forged z failed the norm bound; it must pass so rejection is " +
			"attributable to the key check, not the norm check")
	}
}

// TestZeroT1Forgery_ControlRealKey guards against a wrong fix (e.g. one
// that makes Verify always return false). A genuine key must still
// accept its genuine signature, and must reject the zero-t1 forgery
// recipe applied to it. Both assertions hold before and after the fix.
func TestZeroT1Forgery_ControlRealKey(t *testing.T) {
	ctx := []uint8{'Z', 'O', 'N', 'D'}
	msg := []uint8("control message")

	d, err := New()
	if err != nil {
		t.Fatalf("setup: New failed: %v", err)
	}
	realPK := d.GetPK()

	genuine, err := d.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("setup: Sign failed: %v", err)
	}
	if !Verify(ctx, msg, genuine, &realPK) {
		t.Fatal("control: a genuine signature must verify under its real key")
	}

	forged := forgeZeroT1Sig(t, &realPK, ctx, msg)
	if Verify(ctx, msg, forged, &realPK) {
		t.Fatal("control: the zero-t1 forgery recipe must NOT verify under a real " +
			"(non-zero-t1) key")
	}
}
