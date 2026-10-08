// Package falcon1024 provides Falcon-1024 digital signatures with the API and
// the byte formats of the NIST submission's reference implementation
// (nist.c): keys use the CRYPTO_SECRETKEYBYTES and CRYPTO_PUBLICKEYBYTES
// encodings, and signing produces the crypto_sign signed message, which
// carries the message together with its signature and is opened, rather than
// verified against a separate message, with [Open].
//
// For signatures kept apart from their message, [SignDetached] and [Verify]
// use the compressed signature format of the reference library API (falcon.h,
// FALCON_SIG_COMPRESSED), which PQClean and liboqs also use for Falcon-1024.
// A detached signature carries the same nonce and compressed polynomial as
// the signed message, under the header byte 0x3A instead of 0x2A.
//
// # Which Falcon
//
// This is Falcon as submitted to round 3 of the NIST post-quantum
// competition (specification v1.2), bit for bit: keys and signatures equal
// the reference implementation's on every target, and CI checks that against
// PQClean. NIST's standard for Falcon, FIPS 206 (FN-DSA), is still a draft
// and is announced to differ from the submission in details, so formats may
// change when it is final.
//
// # Randomness
//
// [GenerateKey], [Sign] and [SignDetached] draw their randomness from the
// io.Reader they are given: 48 bytes for a key, and a 40-byte nonce followed
// by a 48-byte sampler seed for each signature. The reader must be a
// cryptographically secure source; pass nil to use crypto/rand. The sampler
// seed is as sensitive as the private key for the signature it produces, so a
// reader that repeats bytes belongs in tests only.
//
// # Public keys
//
// [NewPublicKey] checks the encoding: the header byte, the length and that
// every coefficient is below q. It does not check the shape of the
// polynomial. A public key whose polynomial is a small constant or monomial
// lets anyone produce signatures the verifier accepts, so a signature proves
// nothing about who generated the key it verifies under. Keys from
// [GenerateKey] never have that shape. Callers that accept keys from other
// parties should treat key generation as part of the trust decision; see
// SECURITY.md.
//
// # Private keys, zeroization and timing
//
// [NewPrivateKey] rejects an encoding whose (f, g) fails the bounds key
// generation enforces, in addition to the reference's own checks; every key
// the reference or this package generates passes. [PrivateKey.Zeroize]
// overwrites the secret material; signing afterwards returns an error
// wrapping cryptoerrors.ErrSecretKeyZeroized while the public key stays
// available. A *PrivateKey may be used by concurrent Sign calls; Zeroize must
// not run concurrently with them. Verification uses integer arithmetic only.
// Key generation and signing use native float64 arithmetic that rounds as
// the reference does; like the reference, they are not constant-time.
//
// Every function and method treats a nil or zero-value key as a refusal
// rather than a panic, with the same sentinels as the other schemes in the
// library: [Verify] returns false; [Open] returns an error wrapping
// cryptoerrors.ErrPublicKeyNil for a nil key and cryptoerrors.ErrInvalidPublicKey
// for a zero value; [Sign] and [SignDetached] return cryptoerrors.ErrSecretKeyNil
// for a nil key and cryptoerrors.ErrKeyUninitialised for a zero value that
// never went through a constructor; Equal returns false; Bytes and Public
// return nil. Every other error wraps a sentinel too: a signature shorter
// than its fixed prefix is cryptoerrors.ErrInvalidSignatureSize, any other
// malformed or invalid signature is cryptoerrors.ErrInvalidSignature, a
// failing randomness reader is cryptoerrors.ErrSeedGeneration with the
// reader's own error kept in the chain, and a signature that does not fit
// its encoding is cryptoerrors.ErrSigningFailed.
package falcon1024

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	"github.com/theQRL/go-qrllib/crypto/internal/falcon1024"
)

var (
	errUninitialisedPublicKey  = fmt.Errorf("falcon-1024: public key holds no key: %w", cryptoerrors.ErrInvalidPublicKey)
	errUninitialisedPrivateKey = fmt.Errorf("falcon-1024: %w", cryptoerrors.ErrKeyUninitialised)
)

const (
	// PublicKeySize is the size in bytes of an encoded Falcon-1024 public key
	// (CRYPTO_PUBLICKEYBYTES).
	PublicKeySize = 1793

	// PrivateKeySize is the size in bytes of an encoded Falcon-1024 private
	// key (CRYPTO_SECRETKEYBYTES).
	PrivateKeySize = 2305

	// MaxSignedMessageOverhead is the most a signed message exceeds the
	// message it carries, in bytes (CRYPTO_BYTES).
	MaxSignedMessageOverhead = 1330

	// MaxSignatureSize is the maximum size in bytes of a detached signature
	// (FALCON_SIG_COMPRESSED_MAXSIZE of the reference library API for degree
	// 1024). Signatures are about 1261 bytes on average.
	MaxSignatureSize = 1462

	// SeedSize is the size in bytes of the random input key generation
	// consumes, and of the seed [NewPrivateKeyFromSeed] expands.
	SeedSize = 48
)

// PublicKey is the type of Falcon-1024 public keys. The zero value holds no
// key and is refused by every function that takes one.
type PublicKey struct {
	key *falcon1024.PublicKey
}

// NewPublicKey constructs a public key from its PublicKeySize-byte encoded
// form. See the package documentation for what is and is not checked.
func NewPublicKey(publicKey []byte) (*PublicKey, error) {
	key, err := falcon1024.NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &PublicKey{key}, nil
}

// Bytes returns the PublicKeySize-byte encoded form of pub, or nil when pub
// holds no key.
func (pub *PublicKey) Bytes() []byte {
	if pub == nil {
		return nil
	}
	return pub.key.Bytes()
}

// Equal reports whether pub and x have the same value. A key-less PublicKey
// equals nothing.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok || pub == nil || xx == nil {
		return false
	}
	return pub.key.Equal(xx.key)
}

// PrivateKey is the type of Falcon-1024 private keys. The zero value holds no
// key and is refused by every function that takes one.
type PrivateKey struct {
	key *falcon1024.PrivateKey
}

// NewPrivateKey constructs a private key from its PrivateKeySize-byte encoded
// form. The encoding carries f, g and F; G is recomputed from them, and
// encodings for which that fails are rejected, as in the reference. An
// encoding whose (f, g) is outside the key-generation bounds is rejected as
// well; see the package documentation.
func NewPrivateKey(privateKey []byte) (*PrivateKey, error) {
	key, err := falcon1024.NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{key}, nil
}

// NewPrivateKeyFromSeed returns the private key deterministically generated
// from seed, which must be a SeedSize-byte value. It expands the seed exactly
// as the reference key generation expands the random bytes it draws, so the
// key equals the one [GenerateKey] produces when its reader yields seed.
func NewPrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	key, err := falcon1024.NewPrivateKeyFromSeed(seed)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{key}, nil
}

// Bytes returns the PrivateKeySize-byte encoded form of priv, or nil when
// priv holds no key or has been zeroized.
func (priv *PrivateKey) Bytes() []byte {
	if priv == nil {
		return nil
	}
	return priv.key.Bytes()
}

// Public returns the [PublicKey] corresponding to priv, or nil when priv
// holds no key. The returned key is a copy and stays usable after
// [PrivateKey.Zeroize].
func (priv *PrivateKey) Public() crypto.PublicKey {
	if priv == nil || priv.key == nil {
		return nil
	}
	return &PublicKey{priv.key.PublicKey()}
}

// Equal reports whether priv and x have the same value. A key-less or
// zeroized PrivateKey equals nothing.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok || priv == nil || xx == nil {
		return false
	}
	return priv.key.Equal(xx.key)
}

// Zeroize overwrites the secret material of priv: the encoded key and the
// precomputed signing data derived from it. The public key stays available;
// [Sign] and [SignDetached] afterwards return an error wrapping
// cryptoerrors.ErrSecretKeyZeroized. Zeroization is best effort under Go's
// memory model; see SECURITY.md "Key Zeroization". Calling it on a key-less
// PrivateKey or more than once is harmless.
func (priv *PrivateKey) Zeroize() {
	if priv == nil {
		return
	}
	priv.key.Zeroize()
}

// Sign signs the message with priv and returns the signed message.
// If random is nil, Sign uses crypto/rand.Reader.
func (priv *PrivateKey) Sign(random io.Reader, message []byte) (signedMessage []byte, err error) {
	return Sign(random, priv, message)
}

// SignDetached signs the message with priv and returns a detached signature.
// If random is nil, SignDetached uses crypto/rand.Reader.
func (priv *PrivateKey) SignDetached(random io.Reader, message []byte) (signature []byte, err error) {
	return SignDetached(random, priv, message)
}

// GenerateKey generates a public/private key pair using SeedSize bytes of
// entropy from random, as the reference crypto_sign_keypair does. If random
// is nil, GenerateKey uses crypto/rand.Reader.
func GenerateKey(random io.Reader) (*PublicKey, *PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}

	key, err := falcon1024.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}

	priv := &PrivateKey{key}
	return &PublicKey{key.PublicKey()}, priv, nil
}

// Sign signs the message with privateKey and returns the signed message in
// the format of the reference crypto_sign: a two-byte big-endian signature
// length, a 40-byte nonce, the message, and the signature. The signed message
// is at most MaxSignedMessageOverhead bytes longer than the message. random
// supplies the nonce and the sampler seed and must be a cryptographically
// secure source; if it is nil, Sign uses crypto/rand.Reader.
//
// It returns an error if privateKey holds no key or is zeroized, if random
// fails, or if signature generation fails.
func Sign(random io.Reader, privateKey *PrivateKey, message []byte) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	if privateKey != nil && privateKey.key == nil {
		return nil, errUninitialisedPrivateKey
	}

	return falcon1024.Sign(random, innerPrivateKey(privateKey), message)
}

// SignDetached signs the message with privateKey and returns a detached
// signature in the compressed format of the reference library API: the
// header byte 0x3A, a 40-byte nonce and the compressed polynomial, at most
// MaxSignatureSize bytes. It consumes randomness exactly as Sign does, so the
// same random bytes yield the signature Sign embeds in its signed message.
// random must be a cryptographically secure source; if it is nil,
// SignDetached uses crypto/rand.Reader.
//
// It returns an error if privateKey holds no key or is zeroized, if random
// fails, or if signature generation fails.
func SignDetached(random io.Reader, privateKey *PrivateKey, message []byte) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	if privateKey != nil && privateKey.key == nil {
		return nil, errUninitialisedPrivateKey
	}

	return falcon1024.SignDetached(random, innerPrivateKey(privateKey), message)
}

// Verify reports whether signature is a valid detached signature of message
// by publicKey. It returns false for a nil or key-less publicKey.
func Verify(publicKey *PublicKey, message, signature []byte) bool {
	return falcon1024.Verify(innerPublicKey(publicKey), message, signature) == nil
}

// Open verifies signedMessage with publicKey and returns the message it
// carries, as the reference crypto_sign_open does. It returns an error
// wrapping cryptoerrors.ErrPublicKeyNil for a nil publicKey,
// cryptoerrors.ErrInvalidPublicKey for a zero-value one,
// cryptoerrors.ErrInvalidSignatureSize for a signed message shorter than its
// 42-byte prefix, and cryptoerrors.ErrInvalidSignature if the signed message
// is otherwise malformed or the signature is invalid.
func Open(publicKey *PublicKey, signedMessage []byte) ([]byte, error) {
	if publicKey != nil && publicKey.key == nil {
		return nil, errUninitialisedPublicKey
	}
	return falcon1024.Open(innerPublicKey(publicKey), signedMessage)
}

// innerPublicKey unwraps pub for the internal package, which refuses a nil
// key with an error wrapping cryptoerrors.ErrPublicKeyNil.
func innerPublicKey(pub *PublicKey) *falcon1024.PublicKey {
	if pub == nil {
		return nil
	}
	return pub.key
}

// innerPrivateKey unwraps priv for the internal package, which refuses a nil
// key with an error wrapping cryptoerrors.ErrSecretKeyNil.
func innerPrivateKey(priv *PrivateKey) *falcon1024.PrivateKey {
	if priv == nil {
		return nil
	}
	return priv.key
}
