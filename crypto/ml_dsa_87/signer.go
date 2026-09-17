package ml_dsa_87

import (
	"crypto"
	"errors"
	"io"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

var errUnsupportedSignerOpts = errors.New("ml_dsa_87: opts must be *SignerOpts or nil")

// SignerOpts carries the FIPS 204 context for use with crypto.Signer.
type SignerOpts struct {
	Context []byte
}

func (o *SignerOpts) HashFunc() crypto.Hash { return 0 }

// CryptoSigner wraps an MLDSA87 instance to implement crypto.Signer.
type CryptoSigner struct {
	d *MLDSA87
}

// NewCryptoSigner returns a crypto.Signer backed by d. A nil d yields a
// signer whose Public returns nil and whose Sign returns
// [cryptoerrors.ErrSecretKeyNil], rather than one that panics.
func NewCryptoSigner(d *MLDSA87) *CryptoSigner {
	return &CryptoSigner{d: d}
}

// Public implements crypto.Signer. The returned value is a *[PublicKey].
// It is an untyped nil (not an interface wrapping a nil pointer) when the
// signer has no usable keypair, so `Public() == nil` is a valid check.
func (s *CryptoSigner) Public() crypto.PublicKey {
	if s == nil || s.d == nil {
		return nil
	}
	pk := s.d.PublicKey()
	if pk == nil {
		return nil
	}
	return pk
}

// Sign implements crypto.Signer. The opts parameter must be *SignerOpts
// (to provide the FIPS 204 context) or nil (empty context). Passing
// any other SignerOpts type returns an error.
//
// The rand parameter, when non-nil, is honoured as the source of the
// per-signature RND_BYTES (FIPS 204 §3.5 hedged signing); when nil,
// crypto/rand is used. Either way signing is hedged — the deterministic
// path was removed in TOB-QRLLIB-6 alongside the rand-discarding bug.
func (s *CryptoSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s == nil || s.d == nil {
		return nil, cryptoerrors.ErrSecretKeyNil
	}
	if err := s.d.signable(); err != nil {
		return nil, err
	}
	var ctx []byte
	switch o := opts.(type) {
	case *SignerOpts:
		if o != nil {
			ctx = o.Context
		}
	case nil:
		// empty context
	default:
		return nil, errUnsupportedSignerOpts
	}

	// nil rand → standard hedged path (crypto/rand under the hood).
	if rand == nil {
		sig, err := s.d.Sign(ctx, digest)
		if err != nil {
			return nil, err
		}
		return sig[:], nil
	}

	// Non-nil rand → caller-supplied entropy. Read RND_BYTES from it
	// and route through cryptoSignSignatureWithRnd so the caller's
	// io.Reader is what feeds the per-signature randomness.
	var rnd [RND_BYTES]uint8
	if _, err := io.ReadFull(rand, rnd[:]); err != nil {
		return nil, err
	}
	var sigBuf [CRYPTO_BYTES]uint8
	if err := cryptoSignSignatureWithRnd(sigBuf[:], digest, ctx, &s.d.sk, rnd); err != nil {
		return nil, err
	}
	return sigBuf[:], nil
}
