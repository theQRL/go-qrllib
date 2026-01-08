package legacywallet

import (
	"errors"
	"fmt"
)

// ErrInvalidWalletType is returned when an unknown wallet type is specified.
var ErrInvalidWalletType = errors.New("invalid wallet type")

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

// ToWalletType converts a uint8 to a WalletType, returning an error if invalid.
func ToWalletType(val uint8) (WalletType, error) {
	w := WalletType(val)
	if !w.IsValid() {
		return 0, fmt.Errorf("%w: %d", ErrInvalidWalletType, val)
	}
	return w, nil
}

func (w WalletType) IsValid() bool {
	switch w {
	case WalletTypeXMSS:
		return true
	default:
		return false
	}
}
