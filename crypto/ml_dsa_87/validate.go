package ml_dsa_87

import (
	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// ValidatePublicKey reports whether pk is safe to use as a verification key.
//
// This is NOT part of FIPS 204. Algorithm 8 (ML-DSA.Verify) has no
// key-validity precondition, and [Verify] / [Open] deliberately do not call
// this function, so that they remain conformant implementations and keep
// passing the C2SP/wycheproof ZeroPublicKey vectors (mldsa_87_verify_test.json
// tcId 66 and 174), which require a valid signature under an all-zero-t1 key
// to verify. See .github/wycheproof/README.md.
//
// ValidatePublicKey implements the separate "assurance of public key
// validity" step (NIST SP 800-89). Any caller that accepts a public key from
// an untrusted source — a wallet import, a consensus precompile, a deposit —
// MUST call this before [Verify] or [Open]. The wallet layer
// ([github.com/theQRL/go-qrllib/wallet/ml_dsa_87]) does so on every
// import and every verification.
//
// It currently rejects exactly one class of key: t1 == 0. With t1 = 0 the
// verifier's reconstructed commitment
//
//	w1' = UseHint(h, A·z − c·2^d·t1)
//
// no longer depends on the challenge c, so the triple
// (z = 0, h = 0, c~ = H(mu || w1Encode(0))) is a valid signature for any
// message under any such key, computable from public data alone. This is
// the ML-DSA analogue of the BLS infinity public key. Because q is prime
// and 2^d·t1 < q for every packed coefficient, 2^d·t1 ≡ 0 (mod q) only
// when t1 = 0, so exact zero is the only key with this property.
//
// Returns [cryptoerrors.ErrPublicKeyNil] if pk is nil and
// [cryptoerrors.ErrZeroT1PublicKey] if the t1 region is all zero.
func ValidatePublicKey(pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) error {
	if pk == nil {
		return cryptoerrors.ErrPublicKeyNil
	}
	// CRYPTO_PUBLIC_KEY_BYTES = SEED_BYTES + K*POLY_T1_PACKED_BYTES, so
	// pk[SEED_BYTES:] is exactly the packed t1. polyT1Pack is a plain
	// 10-bit field packing with no offset, so the bytes are all zero iff
	// every coefficient is zero. The OR-accumulate is branchless so the
	// cost does not depend on where the first non-zero byte falls.
	var acc uint8
	for _, b := range pk[SEED_BYTES:] {
		acc |= b
	}
	if acc == 0 {
		return cryptoerrors.ErrZeroT1PublicKey
	}
	return nil
}
