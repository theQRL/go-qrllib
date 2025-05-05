package legacywallet

import "fmt"

/*
WalletType
This is the legacy XMSS code, thus have a customized WalletType
to ensure in case of any future updates on the original wallet type
doesn't affect this legacy XMSS code.
*/
type WalletType uint8

const (
	WalletTypeXMSS WalletType = iota
)

func ToWalletType(val uint8) WalletType {
	w := WalletType(val)
	if !w.IsValid() {
		panic(fmt.Errorf("unknown wallet type: %d", val))
	}
	return w
}

func (w WalletType) IsValid() bool {
	switch w {
	case WalletTypeXMSS:
		return true
	default:
		return false
	}
}
