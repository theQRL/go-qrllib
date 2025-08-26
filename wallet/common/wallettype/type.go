package wallettype

import "fmt"

type WalletType uint8

const (
	SPHINCSPLUS_256S WalletType = iota
	ML_DSA_87
)

func ToWalletType(val uint8) WalletType {
	w := WalletType(val)
	if !w.IsValid() {
		panic(fmt.Errorf("unknown wallet type: %d", val))
	}
	return w
}

func ToWalletTypeOf(val uint8, walletType WalletType) WalletType {
	w := ToWalletType(val)
	if w != walletType {
		panic(fmt.Errorf("wallet type mismatch. expected: %s, found: %s", walletType, w))
	}
	return w
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
	default:
		return fmt.Sprintf("UnknownWalletType(%d)", uint8(w))
	}
}
