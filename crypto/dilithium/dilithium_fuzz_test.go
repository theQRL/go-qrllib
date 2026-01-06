package dilithium

import (
	"testing"
)

// FuzzDilithiumVerify tests that Verify handles arbitrary input without panicking
func FuzzDilithiumVerify(f *testing.F) {
	// Add seed corpus with various sizes
	f.Add(make([]byte, 0), make([]byte, CryptoBytes), make([]byte, CryptoPublicKeyBytes))
	f.Add(make([]byte, 32), make([]byte, CryptoBytes), make([]byte, CryptoPublicKeyBytes))
	f.Add(make([]byte, 1000), make([]byte, CryptoBytes), make([]byte, CryptoPublicKeyBytes))

	f.Fuzz(func(t *testing.T, message, sigBytes, pkBytes []byte) {
		// Convert to fixed-size arrays, padding or truncating as needed
		var sig [CryptoBytes]uint8
		var pk [CryptoPublicKeyBytes]uint8

		copy(sig[:], sigBytes)
		copy(pk[:], pkBytes)

		// This should never panic, regardless of input
		_ = Verify(message, sig, &pk)
	})
}

// FuzzDilithiumOpen tests that Open handles arbitrary input without panicking
func FuzzDilithiumOpen(f *testing.F) {
	// Add seed corpus
	f.Add(make([]byte, 0), make([]byte, CryptoPublicKeyBytes))
	f.Add(make([]byte, CryptoBytes), make([]byte, CryptoPublicKeyBytes))
	f.Add(make([]byte, CryptoBytes+100), make([]byte, CryptoPublicKeyBytes))

	f.Fuzz(func(t *testing.T, signatureMessage, pkBytes []byte) {
		var pk [CryptoPublicKeyBytes]uint8
		copy(pk[:], pkBytes)

		// This should never panic
		_ = Open(signatureMessage, &pk)
	})
}

// FuzzDilithiumExtractMessage tests ExtractMessage with arbitrary input
func FuzzDilithiumExtractMessage(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, CryptoBytes-1))
	f.Add(make([]byte, CryptoBytes))
	f.Add(make([]byte, CryptoBytes+100))

	f.Fuzz(func(t *testing.T, signatureMessage []byte) {
		// This should never panic
		_ = ExtractMessage(signatureMessage)
	})
}

// FuzzDilithiumExtractSignature tests ExtractSignature with arbitrary input
func FuzzDilithiumExtractSignature(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, CryptoBytes-1))
	f.Add(make([]byte, CryptoBytes))
	f.Add(make([]byte, CryptoBytes+100))

	f.Fuzz(func(t *testing.T, signatureMessage []byte) {
		// This should never panic
		_ = ExtractSignature(signatureMessage)
	})
}
