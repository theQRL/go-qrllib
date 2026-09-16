package ml_dsa_87

import (
	"encoding/hex"
	"fmt"

	"github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

// PK is a packed ML-DSA-87 public key (rho || t1).
//
// PK is a plain array type, so a value can be constructed without going
// through [BytesToPK]. Key validation is therefore enforced at [Verify] as
// well as at construction; [BytesToPK] only adds fail-fast rejection on
// import.
type PK [PKSize]byte

// BytesToPK parses a packed ML-DSA-87 public key. It rejects a key of the
// wrong length and a key whose t1 region is all zero (see
// [ml_dsa_87.ValidatePublicKey]); the latter is universally forgeable.
func BytesToPK(pkBytes []byte) (PK, error) {
	var pk PK

	if len(pkBytes) != PKSize {
		return pk, fmt.Errorf(common.ErrInvalidPKSize, wallettype.ML_DSA_87, len(pkBytes), PKSize)
	}

	copy(pk[:], pkBytes)

	// Fail fast on import for keys that ValidatePublicKey rejects (today,
	// the universally-forgeable all-zero-t1 key). This is defense in depth:
	// PK is a plain array type, so [Verify] re-runs the same validation on
	// every call for keys built without this constructor.
	if err := ml_dsa_87.ValidatePublicKey((*[ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES]uint8)(&pk)); err != nil {
		return PK{}, fmt.Errorf(common.ErrZeroT1PublicKey, wallettype.ML_DSA_87, err)
	}
	return pk, nil
}

func HexStrToPK(hexStr string) (PK, error) {
	pkBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return PK{}, err
	}
	return BytesToPK(pkBytes)
}
