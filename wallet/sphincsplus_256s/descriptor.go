package sphincsplus_256s

import (
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

type Descriptor descriptor.Descriptor

func NewSphincsPlus256sDescriptor() (Descriptor, error) {
	descriptorBytes := descriptor.GetDescriptorBytes(wallettype.SPHINCSPLUS_256S, [2]byte{0x00, 0x00})
	return NewSphincsPlus256sDescriptorFromDescriptorBytes(descriptorBytes)
}

func NewSphincsPlus256sDescriptorFromDescriptor(descriptor descriptor.Descriptor) (Descriptor, error) {
	d := Descriptor(descriptor)
	if !d.IsValid() {
		return Descriptor{}, fmt.Errorf(common.ErrInvalidDescriptor, wallettype.SPHINCSPLUS_256S)
	}
	return d, nil
}

func NewSphincsPlus256sDescriptorFromDescriptorBytes(descriptorBytes [descriptor.DescriptorSize]uint8) (Descriptor, error) {
	d := descriptor.New(descriptorBytes)
	return NewSphincsPlus256sDescriptorFromDescriptor(d)
}

func (d Descriptor) WalletType() wallettype.WalletType {
	wt, err := wallettype.ToWalletTypeOf(d[0], wallettype.SPHINCSPLUS_256S)
	if err != nil {
		return wallettype.InvalidWalletType
	}
	return wt
}

// IsValid reports whether the descriptor is a well-formed SPHINCS+-256s
// descriptor. Bytes 1 and 2 carry no defined semantics today and must
// be zero; see descriptor.Descriptor.IsValid for rationale.
func (d Descriptor) IsValid() bool {
	if _, err := wallettype.ToWalletTypeOf(d[0], wallettype.SPHINCSPLUS_256S); err != nil {
		return false
	}
	return d[1] == 0 && d[2] == 0
}

func (d Descriptor) ToDescriptor() descriptor.Descriptor {
	return descriptor.Descriptor(d)
}
