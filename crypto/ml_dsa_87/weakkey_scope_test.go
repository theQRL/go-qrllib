package ml_dsa_87

import (
	"crypto/rand"
	"testing"
)

// TestValidatePublicKey_KnownGap_SmallT1NotRejected documents a KNOWN
// LIMITATION of the current key-validation rule, so that the gap is visible
// in the test suite rather than only in prose, and so that strengthening the
// rule is a deliberate change (this test will then fail and must be updated).
//
// ValidatePublicKey rejects only t1 == 0. But the forgery
// (z = 0, h = 0, c~ = H(mu || w1Encode(0))) succeeds whenever
// HighBits(−c·2^d·t1) = 0 for the message's challenge c, and HighBits
// discards everything below GAMMA2 = 2^13·31.97. So keys whose t1 is small —
// a single coefficient ≤ 31, a handful of unit coefficients, even every
// coefficient equal to 1 — are forgeable for essentially every message and
// currently pass validation. Honestly generated keys are never in this
// class (t1 is essentially uniform in [0, 2^10) per coefficient); it is
// reachable only with attacker-supplied key bytes. A stronger, jointly
// agreed rule across the QRL implementations is a tracked follow-up.
func TestValidatePublicKey_KnownGap_SmallT1NotRejected(t *testing.T) {
	var rho [SEED_BYTES]uint8
	if _, err := rand.Read(rho[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ctx := []uint8("ZOND")

	cases := []struct {
		name  string
		build func(t1 *polyVecK)
	}{
		{"single coefficient = 31", func(t1 *polyVecK) { t1.vec[0].coeffs[0] = 31 }},
		{"eight unit coefficients", func(t1 *polyVecK) {
			for i := 0; i < 8; i++ {
				t1.vec[i].coeffs[i*7] = 1
			}
		}},
		{"every coefficient = 1", func(t1 *polyVecK) {
			for i := 0; i < K; i++ {
				for j := 0; j < N; j++ {
					t1.vec[i].coeffs[j] = 1
				}
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var t1 polyVecK
			tc.build(&t1)
			var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
			packPk(&pk, rho, &t1)

			// Current scope: accepted by validation.
			if err := ValidatePublicKey(&pk); err != nil {
				t.Fatalf("rule has been strengthened (ValidatePublicKey err = %v); update this test and its doc references", err)
			}
			// ...yet forgeable at the primitive for a fresh random message.
			msg := make([]uint8, 32)
			if _, err := rand.Read(msg); err != nil {
				t.Fatalf("rand: %v", err)
			}
			if !Verify(ctx, msg, forgeZeroT1Sig(t, &pk, ctx, msg), rawPK(pk)) {
				t.Fatal("forgery no longer verifies for this small-t1 key; the documented gap has changed — re-analyse")
			}
		})
	}
}
