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
package falcon1024

import (
	"crypto"
	"crypto/rand"
	"io"

	"github.com/theQRL/go-qrllib/crypto/internal/falcon1024"
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

// PublicKey is the type of Falcon-1024 public keys.
type PublicKey struct {
	key *falcon1024.PublicKey
}

// NewPublicKey constructs a public key from its PublicKeySize-byte encoded
// form.
func NewPublicKey(publicKey []byte) (*PublicKey, error) {
	key, err := falcon1024.NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &PublicKey{key}, nil
}

// Bytes returns the PublicKeySize-byte encoded form of pub.
func (pub *PublicKey) Bytes() []byte {
	return pub.key.Bytes()
}

// Equal reports whether pub and x have the same value.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*PublicKey)
	if !ok {
		return false
	}
	return pub.key.Equal(xx.key)
}

// PrivateKey is the type of Falcon-1024 private keys.
type PrivateKey struct {
	key *falcon1024.PrivateKey
}

// NewPrivateKey constructs a private key from its PrivateKeySize-byte encoded
// form. The encoding carries f, g and F; G is recomputed from them, and
// encodings for which that fails are rejected, as in the reference.
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

// Bytes returns the PrivateKeySize-byte encoded form of priv.
func (priv *PrivateKey) Bytes() []byte {
	return priv.key.Bytes()
}

// Public returns the [PublicKey] corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &PublicKey{priv.key.PublicKey()}
}

// Equal reports whether priv and x have the same value.
func (priv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return priv.key.Equal(xx.key)
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
// supplies the nonce and the sampler seed; if it is nil, Sign uses
// crypto/rand.Reader.
//
// It returns an error if random fails or signature generation fails.
func Sign(random io.Reader, privateKey *PrivateKey, message []byte) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}

	return falcon1024.Sign(random, privateKey.key, message)
}

// SignDetached signs the message with privateKey and returns a detached
// signature in the compressed format of the reference library API: the
// header byte 0x3A, a 40-byte nonce and the compressed polynomial, at most
// MaxSignatureSize bytes. It consumes randomness exactly as Sign does, so the
// same random bytes yield the signature Sign embeds in its signed message.
// If random is nil, SignDetached uses crypto/rand.Reader.
//
// It returns an error if random fails or signature generation fails.
func SignDetached(random io.Reader, privateKey *PrivateKey, message []byte) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}

	return falcon1024.SignDetached(random, privateKey.key, message)
}

// Verify reports whether signature is a valid detached signature of message
// by publicKey.
func Verify(publicKey *PublicKey, message, signature []byte) bool {
	return falcon1024.Verify(publicKey.key, message, signature) == nil
}

// Open verifies signedMessage with publicKey and returns the message it
// carries, as the reference crypto_sign_open does. It returns an error if
// the signed message is malformed or the signature is invalid.
func Open(publicKey *PublicKey, signedMessage []byte) ([]byte, error) {
	return falcon1024.Open(publicKey.key, signedMessage)
}
