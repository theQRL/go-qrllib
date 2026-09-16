package ml_dsa_87

import (
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

// Descriptor is the ML-DSA-87 wallet descriptor: a 3-byte value whose first
// byte encodes the wallet type and whose remaining bytes are reserved and
// must be zero. It is bound into the signing context and the address
// derivation, so a signature and an address are both tied to it.
type Descriptor descriptor.Descriptor

// NewMLDSA87Descriptor returns the default ML-DSA-87 descriptor: wallet
// type ML_DSA_87 with the reserved bytes zero.
func NewMLDSA87Descriptor() (Descriptor, error) {
	descriptorBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	return NewMLDSA87DescriptorFromDescriptorBytes(descriptorBytes)
}

// NewMLDSA87DescriptorFromDescriptor converts a generic descriptor,
// rejecting it unless [Descriptor.IsValid] holds.
func NewMLDSA87DescriptorFromDescriptor(descriptor descriptor.Descriptor) (Descriptor, error) {
	d := Descriptor(descriptor)
	if !d.IsValid() {
		return Descriptor{}, fmt.Errorf(common.ErrInvalidDescriptor, wallettype.ML_DSA_87)
	}
	return d, nil
}

// NewMLDSA87DescriptorFromDescriptorBytes builds a descriptor from its raw
// bytes, rejecting it unless [Descriptor.IsValid] holds.
func NewMLDSA87DescriptorFromDescriptorBytes(descriptorBytes [descriptor.DescriptorSize]uint8) (Descriptor, error) {
	d := descriptor.New(descriptorBytes)
	return NewMLDSA87DescriptorFromDescriptor(d)
}

// WalletType returns the wallet type encoded in the descriptor, or
// wallettype.InvalidWalletType if the first byte does not denote ML-DSA-87.
func (d Descriptor) WalletType() wallettype.WalletType {
	wt, err := wallettype.ToWalletTypeOf(d[0], wallettype.ML_DSA_87)
	if err != nil {
		return wallettype.InvalidWalletType
	}
	return wt
}

// IsValid reports whether the descriptor is a well-formed ML-DSA-87
// descriptor. Bytes 1 and 2 carry no defined semantics today and must
// be zero; see descriptor.Descriptor.IsValid for rationale.
func (d Descriptor) IsValid() bool {
	if _, err := wallettype.ToWalletTypeOf(d[0], wallettype.ML_DSA_87); err != nil {
		return false
	}
	return d[1] == 0 && d[2] == 0
}

// ToDescriptor returns the descriptor as the generic
// [github.com/theQRL/go-qrllib/wallet/common/descriptor.Descriptor] type.
func (d Descriptor) ToDescriptor() descriptor.Descriptor {
	return descriptor.Descriptor(d)
}
