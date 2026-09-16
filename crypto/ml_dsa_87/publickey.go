package ml_dsa_87

import (
	"crypto"
	"crypto/subtle"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// PublicKey is a validated ML-DSA-87 public key.
//
// Outside this package a *PublicKey can only be obtained from
// [ParsePublicKey] or [MLDSA87.PublicKey], both of which apply
// [ValidatePublicKey]. Every *PublicKey a caller can hold has therefore
// passed key validation, and [Verify] / [Open] need no further check.
//
// The FIPS 204 Algorithm 8 primitive underneath performs no key
// validation, as the standard specifies. In-package tests construct a
// PublicKey directly to exercise it on arbitrary inputs — the
// C2SP/wycheproof ZeroPublicKey vectors require an all-zero-t1 key to
// verify. That path is intentionally unreachable from other packages.
//
// The zero value PublicKey{} is NOT a usable key. Go always allows a zero
// value to be declared, and its zero bytes are exactly the forgeable
// all-zero-t1 key, so the type carries an unexported validity marker that
// only the validating constructors set; [Verify] and [Open] reject a key
// without it.
//
// PublicKey follows the [crypto.PublicKey] Equal convention and is what
// [CryptoSigner.Public] returns.
type PublicKey struct {
	packed [CRYPTO_PUBLIC_KEY_BYTES]uint8
	// valid is set only by ParsePublicKey, MLDSA87.PublicKey, and the
	// in-package test constructor. It is what makes the zero value inert.
	valid bool
}

// ParsePublicKey decodes a packed public key (rho || t1) and validates it.
// It returns [cryptoerrors.ErrInvalidPublicKey] for a wrong-length input
// and [cryptoerrors.ErrZeroT1PublicKey] for the universally forgeable
// all-zero-t1 key.
func ParsePublicKey(b []byte) (*PublicKey, error) {
	if len(b) != CRYPTO_PUBLIC_KEY_BYTES {
		return nil, cryptoerrors.ErrInvalidPublicKey
	}
	pk := new(PublicKey)
	copy(pk.packed[:], b)
	if err := ValidatePublicKey(&pk.packed); err != nil {
		return nil, err
	}
	pk.valid = true
	return pk, nil
}

// PublicKey returns the keypair's validated public key. Key generation
// upholds the validation invariant, so this cannot fail.
func (d *MLDSA87) PublicKey() *PublicKey {
	return &PublicKey{packed: d.pk, valid: true}
}

// Bytes returns a copy of the packed encoding (rho || t1).
func (pk *PublicKey) Bytes() [CRYPTO_PUBLIC_KEY_BYTES]uint8 {
	return pk.packed
}

// Equal reports whether x is a *PublicKey with the same packed bytes,
// compared in constant time. It satisfies the [crypto.PublicKey] Equal
// convention used by [crypto.Signer] implementations. A nil receiver, a
// nil or differently typed x, or a zero-value (unvalidated) key on either
// side compares unequal.
func (pk *PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PublicKey)
	if !ok || other == nil || pk == nil || !pk.valid || !other.valid {
		return false
	}
	return subtle.ConstantTimeCompare(pk.packed[:], other.packed[:]) == 1
}
