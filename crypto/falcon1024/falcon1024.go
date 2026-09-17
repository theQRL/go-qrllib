// Package falcon1024 provides Falcon-1024 digital signature primitives.
//
// The package currently only supports padded Falcon signatures, which are
// fixed-size signatures containing a compressed payload padded with zeros.
package falcon1024

import (
	"crypto"
	"crypto/rand"
	"io"

	"github.com/theQRL/go-qrllib/crypto/internal/falcon1024"
)

const (
	// PublicKeySize is the size in bytes of an encoded Falcon-1024 public key.
	PublicKeySize = 1793

	// SignatureSize is the size in bytes of a padded Falcon-1024 signature.
	SignatureSize = 1280

	// SeedSize is the size in bytes of the seed used to deterministically
	// generate a Falcon-1024 private key.
	SeedSize = 48

	// PrivateKeySize is the size in bytes of a Falcon-1024 private key in seed
	// form.
	PrivateKeySize = SeedSize
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

// NewPrivateKey returns the private key deterministically generated from seed,
// which must be a SeedSize-byte value.
func NewPrivateKey(seed []byte) (*PrivateKey, error) {
	key, err := falcon1024.NewPrivateKey(seed)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{key}, nil
}

// Bytes returns the SeedSize-byte private key seed.
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

// Sign signs the message with priv and returns a signature.
// If random is nil, Sign uses crypto/rand.Reader.
func (priv *PrivateKey) Sign(random io.Reader, message []byte) (signature []byte, err error) {
	return Sign(random, priv, message)
}

// GenerateKey generates a public/private key pair using entropy from random.
// If random is nil, GenerateKey uses crypto/rand.Reader.
func GenerateKey(random io.Reader) (*PublicKey, *PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}

	var seed [SeedSize]byte
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return nil, nil, err
	}

	priv, err := NewPrivateKey(seed[:])
	if err != nil {
		return nil, nil, err
	}

	return &PublicKey{priv.key.PublicKey()}, priv, nil
}

// Sign signs the message with privateKey and returns a signature.
// If random is nil, Sign uses crypto/rand.Reader.
//
// It returns an error if random fails or signature generation fails.
func Sign(random io.Reader, privateKey *PrivateKey, message []byte) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}

	return falcon1024.Sign(random, privateKey.key, message)
}

// Verify reports whether sig is a valid signature of message by publicKey.
func Verify(publicKey *PublicKey, message, sig []byte) bool {
	return falcon1024.Verify(publicKey.key, message, sig) == nil
}
