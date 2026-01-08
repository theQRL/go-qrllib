package common

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
)

type ExtendedSeed [ExtendedSeedSize]byte

func NewExtendedSeed(desc descriptor.Descriptor, seed Seed) (ExtendedSeed, error) {
	if !desc.IsValid() {
		return ExtendedSeed{}, fmt.Errorf("invalid descriptor")
	}

	// Check in case the value of ExtendedSeedSize changes to some inappropriate value in future
	if len(desc)+len(seed) != ExtendedSeedSize {
		return ExtendedSeed{}, fmt.Errorf("len(extended seed) != len(desc)+len(seed) | %d != %d", len(desc)+len(seed), ExtendedSeedSize)
	}

	var e ExtendedSeed
	copy(e[:descriptor.DescriptorSize], desc[:])
	copy(e[descriptor.DescriptorSize:], seed[:])

	return e, nil
}

func NewExtendedSeedFromBytes(extendedSeedBytes []byte) (ExtendedSeed, error) {
	if len(extendedSeedBytes) != ExtendedSeedSize {
		return ExtendedSeed{}, fmt.Errorf("invalid length of extendedSeedBytes")
	}

	var d [descriptor.DescriptorSize]byte
	copy(d[:], extendedSeedBytes[:descriptor.DescriptorSize])
	desc := descriptor.New(d)
	seed, err := ToSeed(extendedSeedBytes[descriptor.DescriptorSize:])
	if err != nil {
		return ExtendedSeed{}, err
	}
	return NewExtendedSeed(desc, seed)
}

func NewExtendedSeedFromHexString(extendedSeedStr string) (ExtendedSeed, error) {
	if len(extendedSeedStr) != 2*ExtendedSeedSize {
		return ExtendedSeed{}, errors.New("invalid length of extendedSeedStr")
	}

	extendedSeedBytes, err := hex.DecodeString(extendedSeedStr)
	if err != nil {
		return ExtendedSeed{}, fmt.Errorf("hex.DecodeString failed: %v", err)
	}

	return NewExtendedSeedFromBytes(extendedSeedBytes)
}

func (e ExtendedSeed) GetDescriptorBytes() [descriptor.DescriptorSize]byte {
	var d [descriptor.DescriptorSize]byte
	copy(d[:], e[:descriptor.DescriptorSize])
	return d
}

func (e ExtendedSeed) GetSeedBytes() []byte {
	return e[descriptor.DescriptorSize:]
}

func (e ExtendedSeed) GetSeed() (Seed, error) {
	return ToSeed(e.GetSeedBytes())
}

func (e ExtendedSeed) ToBytes() []byte {
	return e[:]
}
