package sphincsplus_256s

import (
	"golang.org/x/crypto/sha3"
)

// SHAKE256Rate is the byte rate for SHAKE256 (168 for 1344-bit capacity)
const SHAKE256Rate = 136

// Shake256 implements a non-incremental SHAKE256 XOF
// output: destination buffer to fill (length determines output size)
// input: input data to absorb
func Shake256(output, input []byte) {
	shake := sha3.NewShake256()
	_, err := shake.Write(input)
	if err != nil {
		//coverage:ignore - sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		panic("shake256: write failed: " + err.Error())
	}
	_, err = shake.Read(output)
	if err != nil {
		//coverage:ignore - sha3.ShakeHash.Read never returns an error for XOF
		panic("shake256: read failed: " + err.Error())
	}
}

// Shake256XOF returns a SHAKE256 XOF reader (incremental interface)
func Shake256XOF(input []byte) sha3.ShakeHash {
	shake := sha3.NewShake256()
	_, err := shake.Write(input)
	if err != nil {
		//coverage:ignore - sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		panic("shake256 XOF: write failed: " + err.Error())
	}
	return shake
}

// Shake256Simple is a convenience wrapper that creates a buffer and returns the output
func Shake256Simple(input []byte, outputLen int) []byte {
	out := make([]byte, outputLen)
	Shake256(out, input)
	return out
}
