// Tests for ValidatePublicKey and for the deliberate FIPS 204 behaviour of
// Verify / Open under an all-zero-t1 public key.
//
// With t1 = 0 the verifier reconstructs
//
//	w1' = UseHint(h, A·z − c·2^d·t1)
//
// which collapses to UseHint(0, 0) = 0 for z = h = 0 regardless of the
// challenge c. A forger therefore sets c~ = SHAKE256(mu || w1Encode(0)) and
// the verifier recomputes exactly that value. Only public data is needed.
//
// FIPS 204 Algorithm 8 has no key-validity precondition, and the
// C2SP/wycheproof ZeroPublicKey vectors (tcId 66, 174) require such a
// signature to verify. Verify and Open therefore ACCEPT the forgery; that is
// pinned here so it is not "fixed" by accident. The rejection is a separate
// key-validation step, ValidatePublicKey, applied by the wallet layer and by
// any consumer that hands untrusted key bytes to the primitive.

package ml_dsa_87

import (
	"crypto/sha3"
	"errors"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// forgeZeroT1Sig builds a signature that any t1 = 0 public key accepts,
// from public inputs only (pk bytes, ctx, msg).
func forgeZeroT1Sig(t *testing.T, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8, ctx, msg []uint8) [CRYPTO_BYTES]uint8 {
	t.Helper()

	// pre = 0x00 || len(ctx) || ctx   (see cryptoSignVerify)
	pre := make([]uint8, len(ctx)+2)
	pre[0] = 0
	pre[1] = uint8(len(ctx))
	copy(pre[2:], ctx)

	var tr [TR_BYTES]uint8
	copy(tr[:], sha3.SumSHAKE256(pk[:], TR_BYTES))

	var mu [CRH_BYTES]uint8
	st := sha3.NewSHAKE256()
	_, _ = st.Write(tr[:])
	_, _ = st.Write(pre)
	_, _ = st.Write(msg)
	_, _ = st.Read(mu[:])

	// For z = h = t1 = 0 the verifier reconstructs w1 = 0.
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

// zeroT1PK returns a public key with rho filled with the given byte and an
// all-zero t1 region.
func zeroT1PK(rho uint8) *[CRYPTO_PUBLIC_KEY_BYTES]uint8 {
	var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
	for i := 0; i < SEED_BYTES; i++ {
		pk[i] = rho
	}
	return &pk
}

// TestValidatePublicKey_RejectsZeroT1 checks that an all-zero t1 region is
// rejected regardless of the rho bytes.
func TestValidatePublicKey_RejectsZeroT1(t *testing.T) {
	for _, rho := range []uint8{0x00, 0xab, 0xff} {
		err := ValidatePublicKey(zeroT1PK(rho))
		if !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
			t.Fatalf("rho=%#x: err = %v, want ErrWeakPublicKey", rho, err)
		}
	}
}

// TestValidatePublicKey_NilPK checks that a nil key returns ErrPublicKeyNil
// rather than panicking.
func TestValidatePublicKey_NilPK(t *testing.T) {
	if err := ValidatePublicKey(nil); !errors.Is(err, cryptoerrors.ErrPublicKeyNil) {
		t.Fatalf("nil pk: err = %v, want ErrPublicKeyNil", err)
	}
}

// TestValidatePublicKey_AcceptsRealKey is the control: a freshly generated
// key passes validation.
func TestValidatePublicKey_AcceptsRealKey(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("setup: New: %v", err)
	}
	pk := d.GetPK()
	if err := ValidatePublicKey(&pk); err != nil {
		t.Fatalf("real key rejected: %v", err)
	}
}

// TestValidatePublicKey_CountsEveryPosition places the minimum number of
// large coefficients at the extreme positions of t1, so a key passes only
// if the count covers the first and last coefficient of every polynomial;
// one fewer fails, and a non-zero rho with a zero t1 fails.
func TestValidatePublicKey_CountsEveryPosition(t *testing.T) {
	build := func(n int) *[CRYPTO_PUBLIC_KEY_BYTES]uint8 {
		var rho [SEED_BYTES]uint8
		var t1 polyVecK
		positions := [][2]int{{0, 0}, {K - 1, N - 1}, {0, N - 1}, {K - 1, 0}}
		for i := 0; i < n; i++ {
			if i < len(positions) {
				t1.vec[positions[i][0]].coeffs[positions[i][1]] = t1LargeLow
			} else {
				t1.vec[i%K].coeffs[1+(i/K)%(N-2)] = t1LargeHigh
			}
		}
		var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
		packPk(&pk, rho, &t1)
		return &pk
	}
	if err := ValidatePublicKey(build(t1MinLarge)); err != nil {
		t.Fatalf("%d large coefficients at the extremes rejected: %v", t1MinLarge, err)
	}
	if err := ValidatePublicKey(build(t1MinLarge - 1)); !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
		t.Fatalf("%d large coefficients: err = %v, want ErrWeakPublicKey", t1MinLarge-1, err)
	}
	pk := zeroT1PK(0)
	pk[SEED_BYTES-1] = 1
	if err := ValidatePublicKey(pk); !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
		t.Fatalf("rho byte must not count as t1: err = %v", err)
	}
}

// TestValidatePublicKey_Constants pins the derived rule constants to the
// values shared with rust-qrllib, qrypto.js and wallet.js.
func TestValidatePublicKey_Constants(t *testing.T) {
	if t1LargeLow != 96 || t1LargeHighBelowHalf != 415 || t1LargeLowAboveHalf != 608 || t1LargeHigh != 927 || t1MinLarge != 76 {
		t.Fatalf("rule constants = %d %d %d %d %d, want 96 415 608 927 76",
			t1LargeLow, t1LargeHighBelowHalf, t1LargeLowAboveHalf, t1LargeHigh, t1MinLarge)
	}
}

// TestVerify_AcceptsZeroT1ForgeryByDesign pins the FIPS 204 behaviour of
// the primitive: the forgery DOES verify. This is intentional; see the file
// comment. It also shows, side by side, that ValidatePublicKey rejects the
// same key — the two halves of the design.
func TestVerify_AcceptsZeroT1ForgeryByDesign(t *testing.T) {
	cases := []struct {
		name string
		rho  uint8
		ctx  []uint8
		msg  []uint8
	}{
		{"all-zero pk, ctx", 0x00, []uint8("ZOND"), []uint8("attacker chosen message #1")},
		{"all-zero pk, empty ctx", 0x00, []uint8{}, []uint8("empty-ctx forgery")},
		{"non-zero rho, zero t1", 0xab, []uint8("ZOND"), []uint8("rho does not save you")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pk := zeroT1PK(tc.rho)
			sig := forgeZeroT1Sig(t, pk, tc.ctx, tc.msg)

			// FIPS 204 Algorithm 8: the forgery verifies. Do not "fix" this
			// here; it would fail wycheproof tcId 66 / 174.
			if !Verify(tc.ctx, tc.msg, sig, rawPK(*pk)) {
				t.Fatal("Verify rejected a zero-t1 forgery; the primitive is no longer " +
					"FIPS 204 conformant and will fail the wycheproof ZeroPublicKey vectors")
			}
			sealed := append(append([]uint8{}, sig[:]...), tc.msg...)
			if got, err := Open(tc.ctx, sealed, rawPK(*pk)); err != nil || string(got) != string(tc.msg) {
				t.Fatalf("Open rejected a zero-t1 forgery (err=%v); see Verify note", err)
			}

			// The key-validation step is where the rejection lives.
			if err := ValidatePublicKey(pk); !errors.Is(err, cryptoerrors.ErrWeakPublicKey) {
				t.Fatalf("ValidatePublicKey err = %v, want ErrWeakPublicKey", err)
			}
		})
	}
}

// TestVerify_ZeroT1ForgeryControl guards the forgery recipe itself: it must
// NOT verify under a real key, and a genuine signature must.
func TestVerify_ZeroT1ForgeryControl(t *testing.T) {
	d, err := New()
	if err != nil {
		t.Fatalf("setup: New: %v", err)
	}
	pk := d.GetPK()
	ctx := []uint8("ZOND")
	msg := []uint8("control message")

	if Verify(ctx, msg, forgeZeroT1Sig(t, &pk, ctx, msg), rawPK(pk)) {
		t.Fatal("control: zero-t1 forgery recipe verified under a real key")
	}
	genuine, err := d.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("setup: Sign: %v", err)
	}
	if !Verify(ctx, msg, genuine, rawPK(pk)) {
		t.Fatal("control: genuine signature must verify")
	}
}
