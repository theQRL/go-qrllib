package ml_dsa_87

import (
	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// ValidateSecretKey checks a packed secret key before it is used for
// signing. It returns [cryptoerrors.ErrSecretKeyNil] for a nil key and
// [cryptoerrors.ErrInvalidSecretKey] when any coefficient of s1 or s2 is
// outside [-ETA, ETA]. Any other key of the right length passes.
//
// A packed secret key is rho || K || tr || s1 || s2 || t0. The s1 and s2
// coefficients are stored as 3-bit fields holding ETA - v, so 0..2*ETA are
// the only valid encodings; 5, 6 and 7 decode to -3, -4 and -5 and never
// come from key generation. t0 has no invalid encoding (every 13-bit field
// decodes into the Power2Round range), and rho, K and tr are opaque bytes,
// so this is the whole of what can be checked without recomputing the
// public key. Out-of-range s1 or s2 would break the ‖z‖∞ < GAMMA1 − BETA
// bound the rejection loop relies on, and with it the zero-knowledge
// property of the signature.
//
// Every signing path applies this check. Keys made by this package always
// pass; it is exported for callers holding raw secret-key bytes.
func ValidateSecretKey(sk *[CRYPTO_SECRET_KEY_BYTES]uint8) error {
	if sk == nil {
		return cryptoerrors.ErrSecretKeyNil
	}
	var rho, key [SEED_BYTES]uint8
	var tr [TR_BYTES]uint8
	var t0 polyVecK
	var s1 polyVecL
	var s2 polyVecK
	unpackSk(&rho, &tr, &key, &t0, &s1, &s2, sk)
	err := validateSecretKeyVecs(&s1, &s2)
	zeroBytes(key[:])
	zeroPolyVecL(&s1)
	zeroPolyVecK(&s2)
	zeroPolyVecK(&t0)
	return err
}

// validateSecretKeyVecs reports whether every coefficient of s1 and s2 lies
// in [-ETA, ETA]. The accumulation is branch-free: (v + ETA) | (ETA - v) is
// negative exactly when v is out of range, and the sign bits are OR-ed so
// the loop never stops early.
func validateSecretKeyVecs(s1 *polyVecL, s2 *polyVecK) error {
	var bad int32
	for i := 0; i < L; i++ {
		for j := 0; j < N; j++ {
			v := s1.vec[i].coeffs[j]
			bad |= (v + ETA) | (ETA - v)
		}
	}
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			v := s2.vec[i].coeffs[j]
			bad |= (v + ETA) | (ETA - v)
		}
	}
	if bad < 0 {
		return cryptoerrors.ErrInvalidSecretKey
	}
	return nil
}
