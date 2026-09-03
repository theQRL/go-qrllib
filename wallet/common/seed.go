package common

import (
	"crypto/sha256"
	"crypto/sha3"
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

func (s Seed) ToBytes() []byte {
	return s[:]
}

func (s Seed) HashSHA256() [32]byte {
	return sha256.Sum256(s[:])
}

func (s Seed) HashSHAKE256(size uint32) []byte {
	return sha3.SumSHAKE256(s[:], int(size))
}

// trimHexPrefix removes at most one leading "0x"/"0X".
//
// At most one is the point. Chaining TrimPrefix("0X") into TrimPrefix("0x")
// strips a doubled prefix, so "0X0x" + a valid body would parse here while the
// wallet-level constructors — which strip exactly one — reject it. A doubled
// prefix is not a valid text form for any field in this library, and the two
// layers disagreeing about it is the entry-point divergence this package
// exists to prevent.
func trimHexPrefix(s string) string {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return s[2:]
	}
	return s
}

func HexStrToSeed(hexStr string) (Seed, error) {
	hexStr = trimHexPrefix(hexStr)

	seedBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return Seed{}, err
	}
	return ToSeed(seedBytes)
}
