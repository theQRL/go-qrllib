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
		// Map hashFuncByte to valid hash function
		hashFunc := HashFunction(hashFuncByte % 3)

		// This should never panic, regardless of input
		_ = Verify(hashFunc, message, signature, pk)
	})
}

// FuzzXMSSVerifyWithCustomWOTSParamW tests VerifyWithCustomWOTSParamW with arbitrary input
func FuzzXMSSVerifyWithCustomWOTSParamW(f *testing.F) {
	f.Add([]byte{}, []byte{}, []byte{}, uint8(0), uint32(16))
	f.Add(make([]byte, 32), make([]byte, 2287), make([]byte, 64), uint8(1), uint32(16))

	f.Fuzz(func(t *testing.T, message, signature, pk []byte, hashFuncByte uint8, wotsParamW uint32) {
		hashFunc := HashFunction(hashFuncByte % 3)

		// Constrain wotsParamW to valid values to avoid panic in NewWOTSParams
		// Valid values are powers of 2 where logW is 2, 4, or 8 (i.e., w = 4, 16, 256)
		validW := []uint32{4, 16, 256}
		w := validW[int(wotsParamW)%len(validW)]

		// This should never panic
		_ = VerifyWithCustomWOTSParamW(hashFunc, message, signature, pk, w)
	})
}
