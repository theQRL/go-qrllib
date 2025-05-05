package common

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type Seed [SeedSize]byte

func ToSeed(seedBytes []byte) (Seed, error) {
	var seed Seed

	if len(seedBytes) != SeedSize {
		return seed, fmt.Errorf("invalid seed size %d, expected %d", len(seedBytes), SeedSize)
	}

	copy(seed[:], seedBytes)
	return seed, nil
}

func HexStrToSeed(hexStr string) (Seed, error) {
	if strings.HasPrefix(hexStr, "0x") {
		hexStr = hexStr[2:]
	}

	seedBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return Seed{}, err
	}
	return ToSeed(seedBytes)
}

func (s Seed) ToBytes() []byte {
	return s[:]
}
