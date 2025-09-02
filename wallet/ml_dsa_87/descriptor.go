package ml_dsa_87

import (
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

type Descriptor descriptor.Descriptor

func NewMLDSA87Descriptor() Descriptor {
	descriptorBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	d, err := NewMLDSA87DescriptorFromDescriptorBytes(descriptorBytes)
	if err != nil {
		panic(err)
	}
	return d
}

func NewMLDSA87DescriptorFromDescriptor(descriptor descriptor.Descriptor) (Descriptor, error) {
	d := Descriptor(descriptor)
	if !d.IsValid() {
		return Descriptor{}, fmt.Errorf(common.ErrInvalidDescriptor, wallettype.ML_DSA_87)
	}
	return d, nil
}

func NewMLDSA87DescriptorFromDescriptorBytes(descriptorBytes [descriptor.DescriptorSize]uint8) (Descriptor, error) {
	d := descriptor.New(descriptorBytes)
	return NewMLDSA87DescriptorFromDescriptor(d)
}

func (d Descriptor) WalletType() wallettype.WalletType {
	return wallettype.ToWalletTypeOf(d[0], wallettype.ML_DSA_87)
}

func (d Descriptor) IsValid() bool {
	return d.WalletType() == wallettype.ML_DSA_87
}

func (d Descriptor) ToDescriptor() descriptor.Descriptor {
	return descriptor.Descriptor(d)
}
