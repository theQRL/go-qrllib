// Package errors provides sanitized sentinel errors for cryptographic operations.
// These errors intentionally omit sensitive details like key sizes, seed lengths,
// and internal state to prevent information leakage in production environments.
package errors

import "errors"

// Seed errors
var (
	ErrInvalidSeed       = errors.New("invalid seed")
	ErrSeedGeneration    = errors.New("seed generation failed")
	ErrInvalidHexSeed    = errors.New("invalid hex seed")
)

// Key errors
var (
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrInvalidSecretKey  = errors.New("invalid secret key")
	ErrSecretKeyNil      = errors.New("secret key is nil")
	ErrSecretKeyZeroized = errors.New("secret key is zeroized")
	ErrKeyGeneration     = errors.New("key generation failed")
)

// Signature errors
var (
	ErrInvalidSignature     = errors.New("invalid signature")
	ErrInvalidSignatureSize = errors.New("invalid signature size")
	ErrSigningFailed        = errors.New("signing failed")
)

// Context errors (ML-DSA)
var (
	ErrInvalidContext = errors.New("invalid context")
)

// XMSS-specific errors
var (
	ErrInvalidHeight    = errors.New("invalid height")
	ErrInvalidBDSParams = errors.New("invalid BDS parameters")
	ErrOTSIndexTooHigh  = errors.New("OTS index exceeds maximum")
	ErrOTSIndexRewind   = errors.New("cannot rewind OTS index")
	ErrXMSSInternal     = errors.New("internal XMSS error")
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
