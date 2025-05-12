package ml_dsa_87

import (
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

type Descriptor descriptor.Descriptor

func NewMLDSA87Descriptor() Descriptor {
	descriptorBytes := []byte{uint8(wallettype.ML_DSA_87), 0x00, 0x00}
	d, err := NewMLDSA87DescriptorFromDescriptorBytes(descriptorBytes)
	if err != nil {
		panic(err)
	}
	return d
}

func NewMLDSA87DescriptorFromDescriptor(descriptor descriptor.Descriptor) (Descriptor, error) {
	x := Descriptor(descriptor)
	if !x.IsValid() {
		return Descriptor{}, fmt.Errorf("invalid ML-DSA-87 descriptor")
	}
	return x, nil
}

func NewMLDSA87DescriptorFromDescriptorBytes(descriptorBytes []uint8) (Descriptor, error) {
	d := descriptor.NewDescriptor(descriptorBytes)
	return NewMLDSA87DescriptorFromDescriptor(d)
}

func (x Descriptor) WalletType() wallettype.WalletType {
	return wallettype.ToWalletTypeOf(x[0], wallettype.ML_DSA_87)
}

func (x Descriptor) IsValid() bool {
	return x.WalletType() == wallettype.ML_DSA_87
}

func (x Descriptor) ToDescriptor() descriptor.Descriptor {
	return descriptor.Descriptor(x)
}
