package falcon1024

import (
	"fmt"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// Weak-key rule constants. See [ValidatePublicKey].
const (
	// weakKeyMultiplierBound is the largest integer multiplier c the rule
	// scans. A key h = a/c whose lattice basis is short enough to forge with
	// needs c <= 907 (see below); 1024 covers that with margin.
	weakKeyMultiplierBound = 1024

	// weakKeySquaredNormBound is the bound on ||c*h||^2 + c^2 at or below
	// which the key is weak. Forgery by rounding against the basis a weak key
	// hands out works up to about 823,237; honest keys have ||c*h||^2 about
	// 1.29 * 10^10 for every c and fall below 2^30 with probability under
	// 2^-1562 even after the union over all multipliers.
	weakKeySquaredNormBound = 1 << 30
)

// ValidatePublicKey checks an encoded public key before it is used for
// verification. It returns an error wrapping [cryptoerrors.ErrInvalidPublicKey]
// for a malformed encoding and one wrapping [cryptoerrors.ErrWeakPublicKey]
// for a weak key, defined below. Any other well-formed key passes.
//
// A weak key is one under which the verifier accepts a signature that anyone
// can compute from the key alone. Verification accepts (s1, s2) whenever
// s1 + s2*h = H(nonce || message) and ||(s1, s2)||^2 <= 70,265,242, so a
// forger needs a short basis of the lattice {(s1, s2): s1 + s2*h = 0 mod q}.
// An honest key hides that basis (f, g, F, G); a key of the form h = a/c
// with a small polynomial a and a small integer c publishes one: the
// rotations of (-a, c) have squared norm N = ||a||^2 + c^2, the rest of the
// basis has Gram-Schmidt norm about q/sqrt(N), and rounding a target against
// that basis gives a signature of squared norm about n*(N + q^2/N)/12, which
// is inside the bound for 184 <= N <= 823,237. Constants and monomials are
// the simplest members: for any k, some c <= 111 brings k*c mod q below 111,
// so 98.6% of the constant keys k in [1, q) forge end to end (the rest have
// an even shorter lattice vector). The rule catches all of them at c = 1
// already, since a single centred coefficient has squared norm under 2^30;
// the multiplier scan is for keys a/c whose coefficients look large.
//
// The rule: with h centred in (-q/2, q/2], the key is weak if for some
// integer c in [1, 1024] the squared norm of the centred coefficients of
// c*h, plus c^2, is at most 2^30. The scan is integer-only and the same on
// every platform. Key generation never produces a weak key: h = g/f is
// uniform, so each ||c*h||^2 is about 1.29 * 10^10, and the chance that any of
// the 1024 multiples falls below 2^30 is under 2^-1562.
//
// The rule covers integer multipliers, which is where cheap forgeries come
// from; it is sufficient, not complete. A key built as a/b for a sparse
// polynomial b (for example 1 + x^512) is not caught, and finding such b for
// a given key is the attacker's problem as much as the validator's. Keys with
// that structure never arise from key generation either.
//
// The check runs once, in [NewPublicKey], in [NewPrivateKey] on the public
// half an imported key derives, and in key generation. The primitive
// verifier itself stays as the Falcon specification defines it. Other QRL
// clients must apply the same rule and the vectors in
// testdata/weak_public_key_vectors.json so that a key is accepted or
// rejected identically everywhere.
func ValidatePublicKey(pubBytes []byte) error {
	h, err := pkDecode(pubBytes)
	if err != nil {
		return err
	}
	return validatePublicPolynomial(h)
}

// validatePublicPolynomial applies the weak-key rule to a decoded h.
func validatePublicPolynomial(h ringElement) error {
	if c, norm := weakPublicKeyMultiplier(h); c != 0 {
		return fmt.Errorf("falcon-1024: %w: %d*h has squared norm %d, at most %d allowed",
			cryptoerrors.ErrWeakPublicKey, c, norm, weakKeySquaredNormBound-c*c)
	}
	return nil
}

// weakPublicKeyMultiplier returns the smallest integer c in
// [1, weakKeyMultiplierBound] for which ||centred(c*h)||^2 + c^2 is at most
// weakKeySquaredNormBound, together with that squared norm, or (0, 0) when
// the key is not weak. h holds coefficients in [0, q).
func weakPublicKeyMultiplier(h ringElement) (c int, norm uint64) {
	// Each coefficient of c*h is reduced on demand, and a multiplier is
	// abandoned as soon as its partial norm passes the bound, after a few
	// dozen coefficients for an honest key. The data is public, so the early
	// exit leaks nothing.
	for c = 1; c <= weakKeyMultiplierBound; c++ {
		norm = uint64(c * c)
		for i := 0; i < n && norm <= weakKeySquaredNormBound; i++ {
			v := int64((uint32(c) * uint32(h[i])) % q)
			if v > q/2 {
				v -= q
			}
			norm += uint64(v * v)
		}
		if norm <= weakKeySquaredNormBound {
			return c, norm - uint64(c*c)
		}
	}
	return 0, 0
}
