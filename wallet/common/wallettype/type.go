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

// IsValid reports whether the wallet type is valid in the production common
// wallet API today. SPHINCSPLUS_256S remains a reserved constant, but is not a
// valid wallet type until QRL activates a reviewed SLH-DSA wallet path.
func (w WalletType) IsValid() bool {
	switch w {
	case ML_DSA_87:
		return true
	default:
		return false
	}
}

// IsIssuable reports whether the library will construct *new* wallets of
// this type. Use this in wallet constructors before deriving key material,
// returning [github.com/theQRL/go-qrllib/wallet/common.ErrWalletTypeNotIssuable]
// on a false result.
//
// SPHINCSPLUS_256S is reserved as a forward placeholder for QRL's eventual
// adoption of the SLH-DSA family (FIPS 205) and is not currently issuable.
func (w WalletType) IsIssuable() bool {
	switch w {
	case ML_DSA_87:
		return true
	default:
		return false
	}
}

// IsVerifiable reports whether the library has an active verification path
// for signatures produced under this wallet type. Use this in wallet-level
// Verify before dispatching to the underlying primitive, returning false
// (or [github.com/theQRL/go-qrllib/wallet/common.ErrWalletTypeNotVerifiable]
// where the API surface allows it) on a false result.
//
// SPHINCSPLUS_256S is reserved as a forward placeholder (see IsIssuable).
// No signatures will ever have been produced under it on QRL networks
// until SLH-DSA activation, so refusing verification today is consistent
// with the on-chain reality.
func (w WalletType) IsVerifiable() bool {
	switch w {
	case ML_DSA_87:
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
