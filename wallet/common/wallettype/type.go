package wallettype

import "fmt"

type WalletType uint8

const (
	SPHINCSPLUS_256S WalletType = iota
	ML_DSA_87

	// InvalidWalletType is returned when wallet type validation fails.
	// Always check IsValid() before using a WalletType value.
	InvalidWalletType WalletType = 255
)

// ToWalletType converts a uint8 to a WalletType.
// Returns InvalidWalletType and an error if the value is not a valid wallet type.
func ToWalletType(val uint8) (WalletType, error) {
	w := WalletType(val)
	if !w.IsValid() {
		return InvalidWalletType, fmt.Errorf("unknown wallet type: %d", val)
	}
	return w, nil
}

// ToWalletTypeOf converts a uint8 to a WalletType and validates it matches the expected type.
// Returns InvalidWalletType and an error if the value is invalid or doesn't match the expected wallet type.
func ToWalletTypeOf(val uint8, walletType WalletType) (WalletType, error) {
	w, err := ToWalletType(val)
	if err != nil {
		return InvalidWalletType, err
	}
	if w != walletType {
		return InvalidWalletType, fmt.Errorf("wallet type mismatch. expected: %s, found: %s", walletType, w)
	}
	return w, nil
}

func (w WalletType) IsValid() bool {
	switch w {
	case SPHINCSPLUS_256S, ML_DSA_87:
		return true
	default:
		return false
	}
}

func (w WalletType) String() string {
	switch w {
	case SPHINCSPLUS_256S:
		return "SPHINCSPLUS_256S"
	case ML_DSA_87:
		return "ML_DSA_87"
	case InvalidWalletType:
		return "InvalidWalletType"
	default:
		return fmt.Sprintf("UnknownWalletType(%d)", uint8(w))
	}
}
