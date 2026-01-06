package ml_dsa_87

import (
	"testing"
)

// FuzzMLDSA87Verify tests that Verify handles arbitrary input without panicking
func FuzzMLDSA87Verify(f *testing.F) {
	// Add seed corpus with various sizes
	f.Add(make([]byte, 0), make([]byte, 0), make([]byte, CRYPTO_BYTES), make([]byte, CRYPTO_PUBLIC_KEY_BYTES))
	f.Add(make([]byte, 10), make([]byte, 32), make([]byte, CRYPTO_BYTES), make([]byte, CRYPTO_PUBLIC_KEY_BYTES))
	f.Add(make([]byte, 255), make([]byte, 1000), make([]byte, CRYPTO_BYTES), make([]byte, CRYPTO_PUBLIC_KEY_BYTES))

	f.Fuzz(func(t *testing.T, ctx, message, sigBytes, pkBytes []byte) {
		// Convert to fixed-size arrays, padding or truncating as needed
		var sig [CRYPTO_BYTES]uint8
		var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8

		copy(sig[:], sigBytes)
		copy(pk[:], pkBytes)

		// This should never panic, regardless of input
		_ = Verify(ctx, message, sig, &pk)
	})
}

// FuzzMLDSA87Open tests that Open handles arbitrary input without panicking
func FuzzMLDSA87Open(f *testing.F) {
	// Add seed corpus
	f.Add(make([]byte, 0), make([]byte, 0), make([]byte, CRYPTO_PUBLIC_KEY_BYTES))
	f.Add(make([]byte, 10), make([]byte, CRYPTO_BYTES), make([]byte, CRYPTO_PUBLIC_KEY_BYTES))
	f.Add(make([]byte, 255), make([]byte, CRYPTO_BYTES+100), make([]byte, CRYPTO_PUBLIC_KEY_BYTES))

	f.Fuzz(func(t *testing.T, ctx, signatureMessage, pkBytes []byte) {
		var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
		copy(pk[:], pkBytes)

		// This should never panic
		_ = Open(ctx, signatureMessage, &pk)
	})
}

// FuzzMLDSA87ExtractMessage tests ExtractMessage with arbitrary input
func FuzzMLDSA87ExtractMessage(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, CRYPTO_BYTES-1))
	f.Add(make([]byte, CRYPTO_BYTES))
	f.Add(make([]byte, CRYPTO_BYTES+100))

	f.Fuzz(func(t *testing.T, signatureMessage []byte) {
		// This should never panic
		_ = ExtractMessage(signatureMessage)
	})
}

// FuzzMLDSA87ExtractSignature tests ExtractSignature with arbitrary input
func FuzzMLDSA87ExtractSignature(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, CRYPTO_BYTES-1))
	f.Add(make([]byte, CRYPTO_BYTES))
	f.Add(make([]byte, CRYPTO_BYTES+100))

	f.Fuzz(func(t *testing.T, signatureMessage []byte) {
		// This should never panic
		_ = ExtractSignature(signatureMessage)
	})
}
