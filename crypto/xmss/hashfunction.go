package xmss

import "fmt"

type HashFunction uint8

const (
	SHA2_256 HashFunction = iota
	SHAKE_128
	SHAKE_256
)

func ToHashFunction(val uint8) HashFunction {
	h := HashFunction(val)
	if !h.IsValid() {
		panic(fmt.Errorf("unknown XMSS Hash Function: %d", val))
	}
	return h
}

func HashFunctionFromDescriptorByte(val uint8) HashFunction {
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
