package xmss

import (
	"testing"
)

// FuzzXMSSVerify tests that Verify handles arbitrary input without panicking
func FuzzXMSSVerify(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{}, []byte{}, []byte{}, uint8(0))
	f.Add(make([]byte, 32), make([]byte, 2287), make([]byte, 64), uint8(1))
	f.Add(make([]byte, 100), make([]byte, 100), make([]byte, 100), uint8(2))

	f.Fuzz(func(t *testing.T, message, signature, pk []byte, hashFuncByte uint8) {
		// Deliberately unmasked: Verify must return false, never panic, for
		// every HashFunction value including the 253 invalid ones.
		hashFunc := HashFunction(hashFuncByte)

		// This should never panic, regardless of input
		_ = Verify(hashFunc, message, signature, pk)
	})
}

// FuzzXMSSVerifyWithCustomWOTSParamW tests VerifyWithCustomWOTSParamW with arbitrary input
func FuzzXMSSVerifyWithCustomWOTSParamW(f *testing.F) {
	f.Add([]byte{}, []byte{}, []byte{}, uint8(0), uint32(16))
	f.Add(make([]byte, 32), make([]byte, 2287), make([]byte, 64), uint8(1), uint32(16))

	f.Fuzz(func(t *testing.T, message, signature, pk []byte, hashFuncByte uint8, wotsParamW uint32) {
		// Deliberately unmasked on both selectors: VerifyWithCustomWOTSParamW
		// validates hashFunction and wotsParamW itself and must return false,
		// never panic, for every value of each.
		hashFunc := HashFunction(hashFuncByte)

		// This should never panic
		_ = VerifyWithCustomWOTSParamW(hashFunc, message, signature, pk, wotsParamW)
	})
}
