package sphincsplus_256s

import (
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

type Descriptor descriptor.Descriptor

func NewSphincsPlus256sDescriptor() Descriptor {
	descriptorBytes := descriptor.GetDescriptorBytes(wallettype.SPHINCSPLUS_256S, [2]byte{0x00, 0x00})
	d, err := NewSphincsPlus256sDescriptorFromDescriptorBytes(descriptorBytes)
	if err != nil {
		panic(err)
	}
	return d
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
	return wallettype.ToWalletTypeOf(d[0], wallettype.SPHINCSPLUS_256S)
}

func (d Descriptor) IsValid() bool {
	return d.WalletType() == wallettype.SPHINCSPLUS_256S
}

func (d Descriptor) ToDescriptor() descriptor.Descriptor {
	return descriptor.Descriptor(d)
}
