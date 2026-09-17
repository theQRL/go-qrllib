// Package errors provides sanitized sentinel errors for cryptographic operations.
// These errors intentionally omit sensitive details like key sizes, seed lengths,
// and internal state to prevent information leakage in production environments.
package errors

import "errors"

// Seed errors
var (
	ErrInvalidSeed    = errors.New("invalid seed")
	ErrSeedGeneration = errors.New("seed generation failed")
	ErrInvalidHexSeed = errors.New("invalid hex seed")
)

// Key errors
var (
	ErrInvalidPublicKey = errors.New("invalid public key")
	// ErrInvalidSecretKey is returned when a packed ML-DSA-87 secret key has
	// an s1 or s2 coefficient outside [-ETA, ETA]; see
	// ml_dsa_87.ValidateSecretKey. Key generation never produces one.
	ErrInvalidSecretKey  = errors.New("invalid secret key")
	ErrPublicKeyNil      = errors.New("public key is nil")
	ErrSecretKeyNil      = errors.New("secret key is nil")
	ErrSecretKeyZeroized = errors.New("secret key is zeroized")
	// ErrKeyUninitialised is returned when a zero-value keypair, one that
	// never went through a constructor, is asked to sign.
	ErrKeyUninitialised = errors.New("keypair is uninitialised")
	ErrKeyGeneration    = errors.New("key generation failed")
	// ErrWeakPublicKey is returned by key validation when an ML-DSA-87
	// public key is weak: fewer than 76 of its 2048 t1 coefficients are
	// large, so the verifier would accept a signature anyone can compute.
	// Key generation never produces such a key; see
	// ml_dsa_87.ValidatePublicKey for the rule.
	ErrWeakPublicKey = errors.New("public key is weak: fewer than 76 of 2048 t1 coefficients are large")
)

// Signature errors
var (
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrInvalidSignatureSize = errors.New("invalid signature size")
	// ErrSigningFailed is returned when the ML-DSA-87 rejection loop exceeds
	// its attempt bound. That is a sub-2^-440 event for a valid key; it
	// happens only for a secret key crafted to be rejected on most attempts.
	ErrSigningFailed = errors.New("signing failed")
)

// Context errors (ML-DSA)
var (
	ErrInvalidContext = errors.New("invalid context")
)

// XMSS-specific errors
var (
	ErrInvalidHeight           = errors.New("invalid height")
	ErrInvalidBDSParams        = errors.New("invalid BDS parameters")
	ErrOTSIndexTooHigh         = errors.New("OTS index exceeds maximum")
	ErrOTSIndexRewind          = errors.New("cannot rewind OTS index")
	ErrXMSSInternal            = errors.New("internal XMSS error")
	ErrUnsupportedParameterSet = errors.New("unsupported XMSS parameter set")
)

// Hash function errors
var (
	ErrInvalidHashFunction = errors.New("invalid hash function")
)

// Buffer errors
var (
	ErrBufferTooSmall = errors.New("buffer too small")
	ErrInvalidLength  = errors.New("invalid length")
)
