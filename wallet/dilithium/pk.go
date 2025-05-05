package dilithium

import (
	"encoding/hex"
	"fmt"
	"github.com/theQRL/go-qrllib/crypto/dilithium"
)

type PK [dilithium.CryptoPublicKeyBytes]byte

func BytesToPK(pkBytes []byte) (PK, error) {
	var pk PK

	if len(pkBytes) != PKSize {
		return pk, fmt.Errorf("invalid pkBytes size %d, expected %d", len(pkBytes), PKSize)
	}

	copy(pk[:], pkBytes)
	return pk, nil
}

func HexStrToPK(hexStr string) (PK, error) {
	pkBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return PK{}, err
	}
	return BytesToPK(pkBytes)
}
