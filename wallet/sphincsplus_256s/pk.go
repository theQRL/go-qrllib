package sphincsplus_256s

import (
	"encoding/hex"
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

type PK [PKSize]byte

func BytesToPK(pkBytes []byte) (PK, error) {
	var pk PK

	if len(pkBytes) != PKSize {
		return pk, fmt.Errorf(common.ErrInvalidPKSize, wallettype.SPHINCSPLUS_256S, len(pkBytes), PKSize)
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
