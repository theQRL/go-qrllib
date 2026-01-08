package xmss

import (
	"errors"
	"fmt"
)

// ErrInvalidHeight is returned when an invalid XMSS tree height is provided.
// Valid heights are even numbers from 2 to MaxHeight (30).
var ErrInvalidHeight = errors.New("invalid XMSS height")

// ErrInvalidSignatureSize is returned when a signature has an invalid size.
var ErrInvalidSignatureSize = errors.New("invalid signature size")

type Height uint8

// ToHeight converts a uint8 to a Height, returning an error if invalid.
// Valid heights are even numbers from 2 to MaxHeight (30).
func ToHeight(val uint8) (Height, error) {
	h := Height(val)
	if !h.IsValid() {
		return 0, fmt.Errorf("%w: %d (must be even, 2-%d)", ErrInvalidHeight, val, MaxHeight)
	}
	return h, nil
}

// UInt32ToHeight converts a uint32 to a Height, returning an error if invalid.
func UInt32ToHeight(val uint32) (Height, error) {
	if val > MaxHeight {
		return 0, fmt.Errorf("%w: %d exceeds maximum %d", ErrInvalidHeight, val, MaxHeight)
	}
	return ToHeight(uint8(val))
}

// HeightFromDescriptorByte extracts a Height from a descriptor byte.
// Returns an error if the extracted height is invalid.
func HeightFromDescriptorByte(val uint8) (Height, error) {
	return ToHeight((val & 0x0f) << 1)
}

// ToDescriptorByte converts the height to its descriptor byte representation.
// Returns an error if the height is invalid.
func (h Height) ToDescriptorByte() (byte, error) {
	if !h.IsValid() {
		return 0, fmt.Errorf("%w: %d", ErrInvalidHeight, h)
	}
	return uint8((h >> 1) & 0x0f), nil
}

func (h Height) ToUInt32() uint32 {
	return uint32(h)
}

func (h Height) IsValid() bool {
	if h > MaxHeight || h < 2 || h%2 != 0 {
		return false
	}
	return true
}

// GetHeightFromSigSize calculates the tree height from a signature size.
// Returns an error if the signature size is invalid.
func GetHeightFromSigSize(sigSize, wotsParamW uint32) (Height, error) {
	wotsParam := NewWOTSParams(WOTSParamN, wotsParamW)
	signatureBaseSize := calculateSignatureBaseSize(wotsParam.keySize)
	if sigSize < signatureBaseSize {
		return 0, fmt.Errorf("%w: size %d is smaller than base size %d", ErrInvalidSignatureSize, sigSize, signatureBaseSize)
	}

	if (sigSize-4)%32 != 0 {
		return 0, fmt.Errorf("%w: size %d is not properly aligned", ErrInvalidSignatureSize, sigSize)
	}

	return UInt32ToHeight((sigSize - signatureBaseSize) / 32)
}
