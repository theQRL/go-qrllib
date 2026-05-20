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
	if d[0] == byte(wallettype.SPHINCSPLUS_256S) {
		return wallettype.SPHINCSPLUS_256S
	}
	return wallettype.InvalidWalletType
}

// IsValid reports whether the descriptor is a well-formed SPHINCS+-256s
// descriptor. Bytes 1 and 2 carry no defined semantics today and must
// be zero. This package-local check exists only for the experimental
// SPHINCS+ implementation; descriptor.Descriptor.IsValid intentionally
// rejects SPHINCSPLUS_256S in the production common wallet API.
func (d Descriptor) IsValid() bool {
	if d[0] != byte(wallettype.SPHINCSPLUS_256S) {
		return false
	}
	return d[1] == 0 && d[2] == 0
}

func (d Descriptor) ToDescriptor() descriptor.Descriptor {
	return descriptor.Descriptor(d)
}
