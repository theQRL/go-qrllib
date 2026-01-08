package sphincsplus_256s

import (
	"testing"

	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

// FuzzSphincsPlus256sVerify tests that Verify handles arbitrary input without panicking
func FuzzSphincsPlus256sVerify(f *testing.F) {
	// Add seed corpus with various sizes
	f.Add(make([]byte, 0), make([]byte, params.SPX_BYTES), make([]byte, params.SPX_PK_BYTES))
	f.Add(make([]byte, 32), make([]byte, params.SPX_BYTES), make([]byte, params.SPX_PK_BYTES))
	f.Add(make([]byte, 1000), make([]byte, params.SPX_BYTES), make([]byte, params.SPX_PK_BYTES))

	f.Fuzz(func(t *testing.T, message, sigBytes, pkBytes []byte) {
		// Convert to fixed-size arrays, padding or truncating as needed
		var sig [params.SPX_BYTES]uint8
		var pk [params.SPX_PK_BYTES]uint8

		copy(sig[:], sigBytes)
		copy(pk[:], pkBytes)

		// This should never panic, regardless of input
		_ = Verify(message, sig, &pk)
	})
}

// FuzzSphincsPlus256sOpen tests that Open handles arbitrary input without panicking
func FuzzSphincsPlus256sOpen(f *testing.F) {
	// Add seed corpus
	f.Add(make([]byte, 0), make([]byte, params.SPX_PK_BYTES))
	f.Add(make([]byte, params.SPX_BYTES), make([]byte, params.SPX_PK_BYTES))
	f.Add(make([]byte, params.SPX_BYTES+100), make([]byte, params.SPX_PK_BYTES))

	f.Fuzz(func(t *testing.T, signatureMessage, pkBytes []byte) {
		var pk [params.SPX_PK_BYTES]uint8
		copy(pk[:], pkBytes)

		// This should never panic
		_ = Open(signatureMessage, &pk)
	})
}

// FuzzSphincsPlus256sExtractMessage tests ExtractMessage with arbitrary input
func FuzzSphincsPlus256sExtractMessage(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, params.SPX_BYTES-1))
	f.Add(make([]byte, params.SPX_BYTES))
	f.Add(make([]byte, params.SPX_BYTES+100))

	f.Fuzz(func(t *testing.T, signatureMessage []byte) {
		// This should never panic
		_ = ExtractMessage(signatureMessage)
	})
}

// FuzzSphincsPlus256sExtractSignature tests ExtractSignature with arbitrary input
func FuzzSphincsPlus256sExtractSignature(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, params.SPX_BYTES-1))
	f.Add(make([]byte, params.SPX_BYTES))
	f.Add(make([]byte, params.SPX_BYTES+100))

	f.Fuzz(func(t *testing.T, signatureMessage []byte) {
		// This should never panic
		_ = ExtractSignature(signatureMessage)
	})
}
