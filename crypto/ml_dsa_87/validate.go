package ml_dsa_87

import (
	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// ValidatePublicKey checks a packed public key before it is used for
// verification. It returns [cryptoerrors.ErrPublicKeyNil] for a nil key and
// [cryptoerrors.ErrZeroT1PublicKey] when the t1 region (every byte after
// rho) is all zero. Any other well-formed key passes.
//
// Key generation never produces an all-zero t1, so this only ever rejects a
// crafted key. It is rejected because, with t1 = 0, the value the verifier
// reconstructs no longer depends on the challenge, and a signature that
// anyone can compute from the key alone verifies for every message. This is
// the key the C2SP/wycheproof ZeroPublicKey vectors are built on.
//
// The check is separate from [Verify] and [Open] on purpose. FIPS 204
// Algorithm 8 has no key-validity step, and Wycheproof requires a
// conformant verifier to accept those vectors (tcId 66 and 174), so the
// primitive stays as the standard specifies and validation runs once, in
// [ParsePublicKey] and in key generation, the only ways to obtain a
// [PublicKey]. It is exported for callers that want the same check on raw
// bytes, as the wallet layer's BytesToPK does.
//
// The rule is a minimum, not a full description of which crafted keys are
// weak. A key whose t1 is small enough that HighBits(c·2^d·t1) is zero for
// the message's challenge also verifies such a signature and passes this
// check. Honest keys are nowhere near that region. Tightening the rule is a
// tracked follow-up across the QRL implementations; see
// TestValidatePublicKey_KnownGap_SmallT1NotRejected.

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
