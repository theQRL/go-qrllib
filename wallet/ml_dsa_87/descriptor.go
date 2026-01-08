package ml_dsa_87

import (
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

type Descriptor descriptor.Descriptor

func NewMLDSA87Descriptor() (Descriptor, error) {
	descriptorBytes := descriptor.GetDescriptorBytes(wallettype.ML_DSA_87, [2]byte{0x00, 0x00})
	return NewMLDSA87DescriptorFromDescriptorBytes(descriptorBytes)
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
	wt, err := wallettype.ToWalletTypeOf(d[0], wallettype.ML_DSA_87)
	if err != nil {
		return wallettype.InvalidWalletType
	}
	return wt
}

func (d Descriptor) IsValid() bool {
	_, err := wallettype.ToWalletTypeOf(d[0], wallettype.ML_DSA_87)
	return err == nil
}

func (d Descriptor) ToDescriptor() descriptor.Descriptor {
	return descriptor.Descriptor(d)
}
