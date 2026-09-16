package ml_dsa_87

import (
	"crypto"
	"errors"
	"io"
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

// NewCryptoSigner returns a crypto.Signer backed by the given MLDSA87 instance.
func NewCryptoSigner(d *MLDSA87) *CryptoSigner {
	return &CryptoSigner{d: d}
}

// Public implements crypto.Signer. The returned value is a *[PublicKey].
func (s *CryptoSigner) Public() crypto.PublicKey {
	return s.d.PublicKey()
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
