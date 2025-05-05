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

	if len(desc)+len(seed) != ExtendedSeedSize {
		return ExtendedSeed{}, fmt.Errorf("invalid length of descriptor bytes and seed")
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

	desc := descriptor.NewDescriptor(extendedSeedBytes[:descriptor.DescriptorSize])
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

func (e ExtendedSeed) GetDescriptorBytes() []byte {
	return e[:descriptor.DescriptorSize]
}

func (e ExtendedSeed) GetSeedBytes() []byte {
	return e[descriptor.DescriptorSize:]
}

func (e ExtendedSeed) GetSeed() Seed {
	seed, err := ToSeed(e.GetSeedBytes())
	if err != nil {
		panic(err)
	}
	return seed
}

func (e ExtendedSeed) ToBytes() []byte {
	return e[:]
}
