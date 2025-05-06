package dilithium

import (
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

type Descriptor descriptor.Descriptor

func NewDilithiumDescriptor() Descriptor {
	descriptorBytes := []byte{uint8(wallettype.Dilithium), 0x00, 0x00}
	d, err := NewDilithiumDescriptorFromDescriptorBytes(descriptorBytes)
	if err != nil {
		panic(err)
	}
	return d
}

func NewDilithiumDescriptorFromDescriptor(descriptor descriptor.Descriptor) (Descriptor, error) {
	x := Descriptor(descriptor)
	if !x.IsValid() {
		return Descriptor{}, fmt.Errorf("invalid Dilithium descriptor")
	}
	return x, nil
}

func NewDilithiumDescriptorFromDescriptorBytes(descriptorBytes []uint8) (Descriptor, error) {
	d := descriptor.NewDescriptor(descriptorBytes)
	return NewDilithiumDescriptorFromDescriptor(d)
}

func (x Descriptor) WalletType() wallettype.WalletType {
	return wallettype.ToWalletTypeOf(x[0], wallettype.Dilithium)
}

func (x Descriptor) IsValid() bool {
	return x.WalletType() == wallettype.Dilithium
}

func (x Descriptor) ToDescriptor() descriptor.Descriptor {
	return descriptor.Descriptor(x)
}
