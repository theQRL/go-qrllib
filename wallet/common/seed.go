package common

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/sha3"
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

func (s Seed) ToBytes() []byte {
	return s[:]
}

func (s Seed) HashSHA256() [32]byte {
	return sha256.Sum256(s[:])
}

func (s Seed) HashSHAKE256(size uint32) []byte {
	output := make([]byte, size)
	sha3.ShakeSum256(output, s[:])
	return output
}

func HexStrToSeed(hexStr string) (Seed, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")

	seedBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return Seed{}, err
	}
	return ToSeed(seedBytes)
}
