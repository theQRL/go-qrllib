package ml_dsa_87

import (
	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// Weak-key rule constants, derived from the parameter set. A t1 coefficient
// v is large when t1LargeLow <= v <= t1LargeHighBelowHalf or
// t1LargeLowAboveHalf <= v <= t1LargeHigh; a key is weak unless at least
// t1MinLarge of its K*N coefficients are large. See [ValidatePublicKey].
//
//	t1LargeLow           = floor(3*GAMMA2 / 2^D) + 1        = 96
//	t1LargeHighBelowHalf = floor((Q - 6*GAMMA2) / 2^(D+1))  = 415
//	t1LargeLowAboveHalf  = ceil((Q + 6*GAMMA2) / 2^(D+1))   = 608
//	t1LargeHigh          = ceil((Q - 3*GAMMA2) / 2^D) - 1   = 927
//	t1MinLarge           = OMEGA + 1                        = 76
const (
	t1LargeLow           = 3*GAMMA2/(1<<D) + 1
	t1LargeHighBelowHalf = (Q - 6*GAMMA2) / (1 << (D + 1))
	t1LargeLowAboveHalf  = (Q + 6*GAMMA2 + (1 << (D + 1)) - 1) / (1 << (D + 1))
	t1LargeHigh          = (Q-3*GAMMA2+(1<<D)-1)/(1<<D) - 1
	t1MinLarge           = OMEGA + 1
)

// ValidatePublicKey checks a packed public key before it is used for
// verification. It returns [cryptoerrors.ErrPublicKeyNil] for a nil key and
// [cryptoerrors.ErrWeakPublicKey] for a weak key, defined below. Any other
// well-formed key passes.
//
// A weak key is one under which the verifier accepts a signature that
// anyone can compute from the key alone. With z = 0 and up to OMEGA hints
// the verifier reconstructs w1' = UseHint(h, −c·2^D·t1), so if every
// coefficient of c·2^D·t1 can be brought to HighBits 0 then
// (z = 0, h, c~ = H(mu || w1Encode(0))) verifies for any message. That
// happens when the coefficients of t1 are small, either near 0 or near
// 2^10 (2^13·1023 = q − 1), and also when they sit near 512: then
// 2^13·v ≡ 2^-1·s (mod q) for a small odd s, and c·(1 + x + … + x^255)
// always has even coefficients, so the 2^-1 cancels.
//
// The rule: a coefficient v of t1 is large when 96 ≤ v ≤ 415 or
// 608 ≤ v ≤ 927; a key is weak unless at least 76 of its 2048 coefficients
// are large. A large coefficient contributes more than 3·GAMMA2 per
// challenge tap under either mechanism, which is two HighBits bands from
// zero and beyond hint correction, and 76 = OMEGA + 1 is more such
// contributions than the verifier can correct. The bounds derive from the
// parameter set (see the constants above). Key generation never produces
// a weak key: an honest t1 has about 1280 large coefficients, and the
// chance of fewer than 76 is below 2^-800.
//
// The check is separate from [Verify] and [Open] on purpose. FIPS 204
// Algorithm 8 has no key-validity step, and the C2SP/wycheproof vectors
// require a conformant verifier to accept the all-zero key (tcId 66 and
// 174) and the all-1023 key (tcId 240), so the primitive stays as the
// standard specifies and validation
// runs once, in [ParsePublicKey] and in key generation, the only ways to
// obtain a [PublicKey]. It is exported for callers holding raw bytes.
//
// rust-qrllib, qrypto.js and wallet.js apply the same rule and are tested
// against the same vectors, testdata/weak_public_key_vectors.json, so a
// key is accepted or rejected identically across QRL clients.
func ValidatePublicKey(pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) error {
	if pk == nil {
		return cryptoerrors.ErrPublicKeyNil
	}
	var rho [SEED_BYTES]uint8
	var t1 polyVecK
	unpackPk(&rho, &t1, pk)
	if countLargeT1(&t1) < t1MinLarge {
		return cryptoerrors.ErrWeakPublicKey
	}
	return nil
}

// countLargeT1 returns how many coefficients of t1 are large. Every
// coefficient is in [0, 2^10) after polyT1Unpack. The accumulation is
// branch-free: each range test folds to 0 or -1 via the sign bit.
func countLargeT1(t1 *polyVecK) int {
	n := 0
	for k := 0; k < K; k++ {
		for i := 0; i < N; i++ {
			v := t1.vec[k].coeffs[i]
			inLow := ((v - t1LargeLow) | (t1LargeHighBelowHalf - v)) >> 31 // 0 in range, -1 outside
			inHigh := ((v - t1LargeLowAboveHalf) | (t1LargeHigh - v)) >> 31
			n += int((1 + inLow) | (1 + inHigh))
		}
	}
	return n
}
