package xmss

import (
	"fmt"

	"github.com/theQRL/go-qrllib/crypto/xmss"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

type Descriptor descriptor.Descriptor

func NewXMSSDescriptor(hashFunction xmss.HashFunction, height xmss.Height) (Descriptor, error) {
	descBytes := []byte{uint8(wallettype.XMSS), HashFunctionAndHeightToDescriptorByte(hashFunction, height), 0x00}
	d := descriptor.NewDescriptor(descBytes)
	return NewXMSSDescriptorFromDescriptorBytes(d.ToBytes())
}

func NewXMSSDescriptorFromDescriptor(descriptor descriptor.Descriptor) (Descriptor, error) {
	x := Descriptor(descriptor)
	if !x.IsValid() {
		return Descriptor{}, fmt.Errorf("invalid XMSS descriptor")
	}
	return x, nil
}

func NewXMSSDescriptorFromDescriptorBytes(descriptorBytes []uint8) (Descriptor, error) {
	d := descriptor.NewDescriptor(descriptorBytes)
	return NewXMSSDescriptorFromDescriptor(d)
}

func (x Descriptor) WalletType() wallettype.WalletType {
	return wallettype.ToWalletTypeOf(x[0], wallettype.XMSS)
}

func (x Descriptor) GetHashFunction() xmss.HashFunction {
	return xmss.HashFunctionFromDescriptorByte(x[1])
}

func (x Descriptor) GetHeight() xmss.Height {
	return xmss.HeightFromDescriptorByte(x[1])
}

func (x Descriptor) IsValid() bool {
	return x.WalletType() == wallettype.XMSS && x.GetHashFunction().IsValid() && x.GetHeight().IsValid()
}

func (x Descriptor) ToDescriptor() descriptor.Descriptor {
	return descriptor.Descriptor(x)
}

func HashFunctionAndHeightToDescriptorByte(hashFunction xmss.HashFunction, height xmss.Height) byte {
	return hashFunction.ToDescriptorByte() | height.ToDescriptorByte()
}
