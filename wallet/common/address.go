package common

import (
	"encoding/hex"
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
	"golang.org/x/crypto/sha3"
)

/*
UnsafeGetAddress builds the address bytes from a validated descriptor and public key.

Rationale: this is a fast-path used by wallet implementations that already validate
the descriptor type and public key length during construction. Skipping checks avoids
repeat validation on every call, but it is unsafe for untrusted inputs.

Callers MUST ensure:
  - desc.IsValid() is true for the intended wallet type
  - pk is the correct length for that wallet type
*/
func UnsafeGetAddress(pk []byte, desc descriptor.Descriptor) [AddressSize]byte {
	// noinspection GoBoolExpressions
	if AddressSize > 32 {
		panic("AddressSize must be <= 32")
	}

	sh := sha3.NewShake256()
	_, _ = sh.Write(desc.ToBytes())
	_, _ = sh.Write(pk)

	var addr [AddressSize]byte
	_, _ = sh.Read(addr[:]) // take the first N bytes
	return addr
}

// GetAddress validates the descriptor and public key length, then derives the address.
// It is the safe wrapper around UnsafeGetAddress for untrusted inputs.
func GetAddress(pk []byte, desc descriptor.Descriptor) ([AddressSize]byte, error) {
	var addr [AddressSize]byte
	if !desc.IsValid() {
		return addr, fmt.Errorf(ErrInvalidDescriptor, wallettype.WalletType(desc.Type()))
	}
	expectedSize, err := expectedPKSize(desc)
	if err != nil {
		return addr, err
	}
	if len(pk) != expectedSize {
		return addr, fmt.Errorf(ErrInvalidPKSize, wallettype.WalletType(desc.Type()), len(pk), expectedSize)
	}
	return UnsafeGetAddress(pk, desc), nil
}

func expectedPKSize(desc descriptor.Descriptor) (int, error) {
	switch wallettype.WalletType(desc.Type()) {
	case wallettype.ML_DSA_87:
		return MLDSA87PKSize, nil
	case wallettype.SPHINCSPLUS_256S:
		return SPHINCSPlus256sPKSize, nil
	default:
		return 0, fmt.Errorf(ErrInvalidDescriptor, wallettype.WalletType(desc.Type()))
	}
}

// IsValidAddress validates a QRL address string.
// A valid address has the format "Q" followed by AddressSize*2 hex characters.
func IsValidAddress(addr string) bool {
	// Check length: "Q" prefix + hex-encoded address (2 chars per byte)
	expectedLen := 1 + AddressSize*2
	if len(addr) != expectedLen {
		return false
	}

	// Check Q prefix
	if addr[0] != 'Q' {
		return false
	}

	// Check that the rest is valid hex
	_, err := hex.DecodeString(addr[1:])
	return err == nil
}
