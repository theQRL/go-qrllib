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

	// Reject the universally-forgeable all-zero-t1 public key at
	// construction (finding H1). This is fail-fast defense in depth; the
	// authoritative guard is in crypto/ml_dsa_87's verify path, since a PK
	// can also be built without going through this constructor.
	if hasZeroT1(pkBytes) {
		return pk, fmt.Errorf(common.ErrZeroT1PublicKey, wallettype.ML_DSA_87)
	}

	copy(pk[:], pkBytes)

	if err := ml_dsa_87.ValidatePublicKey((*[ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES]uint8)(&pk)); err != nil {
		return PK{}, fmt.Errorf(common.ErrZeroT1PublicKey, wallettype.ML_DSA_87, err)
	}
	return pk, nil
}

// hasZeroT1 reports whether the t1 region of a packed ML-DSA-87 public key
// (every byte after the rho prefix) is all zero. Callers must ensure
// pkBytes is at least PKSize bytes long. The branchless OR-accumulate keeps
// the check independent of where the first non-zero byte falls.
func hasZeroT1(pkBytes []byte) bool {
	var acc byte
	for _, b := range pkBytes[ml_dsa_87.SEED_BYTES:] {
		acc |= b
	}
	return acc == 0
}

func HexStrToPK(hexStr string) (PK, error) {
	pkBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return PK{}, err
	}
	return BytesToPK(pkBytes)
}
