package xmss

import (
	"fmt"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

type HashFunction uint8

const (
	SHA2_256 HashFunction = iota
	SHAKE_128
	SHAKE_256
)

// ToHashFunction converts a uint8 to a HashFunction, returning an error if invalid.
// Valid hash functions are SHA2_256 (0), SHAKE_128 (1), and SHAKE_256 (2).
func ToHashFunction(val uint8) (HashFunction, error) {
	h := HashFunction(val)
	if !h.IsValid() {
		return 0, cryptoerrors.ErrInvalidHashFunction
	}
	return h, nil
}

// HashFunctionFromDescriptorByte extracts a HashFunction from a descriptor byte.
// Returns an error if the extracted hash function is invalid.
func HashFunctionFromDescriptorByte(val uint8) (HashFunction, error) {
	return ToHashFunction((val >> 4) & 0x0f)
}

func (hf HashFunction) ToDescriptorByte() byte {
	return uint8((hf << 4) & 0xf0)
}

func (hf HashFunction) IsValid() bool {
	switch hf {
	case SHA2_256, SHAKE_128, SHAKE_256:
		return true
	default:
		return false
	}
}

func (hf HashFunction) String() string {
	switch hf {
	case SHA2_256:
		return "SHA2_256"
	case SHAKE_128:
		return "SHAKE_128"
	case SHAKE_256:
		return "SHAKE_256"
	default:
		return fmt.Sprintf("UnknownHashFunction(%d)", hf)
	}
}
