package common

import (
	"encoding/hex"
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
		//coverage:ignore
		//rationale: compile-time constant check, len(desc)+len(seed) always equals ExtendedSeedSize
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
		//coverage:ignore
		//rationale: slice is always exactly SeedSize bytes after ExtendedSeedSize validation
		return ExtendedSeed{}, err
	}
	return NewExtendedSeed(desc, seed)
}

// NewExtendedSeedFromHexString parses the hex text form of an extended seed.
//
// An optional "0x"/"0X" prefix is removed before the length check, so the
// canonical form emitted by [ExtendedSeed.ToHex] (and by the wallet packages'
// GetHexSeed) parses back through this constructor to the identical bytes.
// Stripping before the length check rather than after is the whole point:
// checking first rejects the canonical form as a length error. Exactly one
// prefix is removed, so a doubled "0X0x" is rejected here just as it is by the
// wallet-level constructors. Uppercase hex is accepted; whitespace and
// separator characters are not.
func NewExtendedSeedFromHexString(extendedSeedStr string) (ExtendedSeed, error) {
	extendedSeedStr = trimHexPrefix(extendedSeedStr)

	if len(extendedSeedStr) != 2*ExtendedSeedSize {
		return ExtendedSeed{}, fmt.Errorf("invalid length of extendedSeedStr %d, expected %d", len(extendedSeedStr), 2*ExtendedSeedSize)
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

// ToHex returns the canonical text form of the extended seed: lowercase "0x"
// followed by 2*ExtendedSeedSize lowercase hex characters. This is the only
// form the library emits, and [NewExtendedSeedFromHexString] accepts it.
func (e ExtendedSeed) ToHex() string {
	return "0x" + hex.EncodeToString(e[:])
}
