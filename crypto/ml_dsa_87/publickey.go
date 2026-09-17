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
// PublicKey directly to exercise it on arbitrary inputs, including the
// all-zero-t1 keys the C2SP/wycheproof ZeroPublicKey vectors require it to
// accept. That path is unreachable from other packages.
//
// The zero value PublicKey{} is not a usable key. Go always allows a zero
// value to be declared, and its bytes are the weakest key there is, so the
// type carries an unexported validity marker that only the validating
// constructors set; [Verify] and [Open] reject a key without it.
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
// and [cryptoerrors.ErrWeakPublicKey] for a weak key (see
// [ValidatePublicKey]).
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

// PublicKey returns the keypair's validated public key, or nil for a
// zero-value MLDSA87{} that never went through a constructor. It works
// after [MLDSA87.Zeroize], since the public key is not secret.
//
// The key is re-checked with [ValidatePublicKey] rather than trusted, so
// every *PublicKey handed out by this package has passed validation on
// the way out, whatever path produced the bytes.
func (d *MLDSA87) PublicKey() *PublicKey {
	if d == nil || d.state == keyStateUninitialised || ValidatePublicKey(&d.pk) != nil {
		return nil
	}
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
