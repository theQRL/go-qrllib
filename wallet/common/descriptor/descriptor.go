package descriptor

import (
	"errors"

	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

const (
	DescriptorSize = 3
)

type CryptoDescriptor interface {
	Type() byte
	FromDescriptor(d Descriptor) error
	ToDescriptor() Descriptor
	IsValid() bool
}

// Descriptor represents a compact, variable-size identifier
// containing cryptographic metadata.
//
// The descriptor is a byte array where:
//   - Byte 0 (index 0): Indicates the cryptographic type.
//   - Rest of the bytes if exist are the metadata for the respective wallet type
//	   or is 0 in case of no data

type Descriptor [DescriptorSize]byte

func New(descriptorBytes [DescriptorSize]byte) Descriptor {
	var d Descriptor
	copy(d[:], descriptorBytes[:])
	return d
}

func FromBytes(descriptorBytes []byte) (Descriptor, error) {
	var d Descriptor
	if len(descriptorBytes) != DescriptorSize {
		return d, errors.New("invalid descriptor size")
	}
	copy(d[:], descriptorBytes[:])
	return d, nil
}

func (d Descriptor) Type() byte {
	return d[0]
}

func (d Descriptor) IsValid() bool {
	// TODO (cyyber): Add checks for WalletType
	return true
}

func (d Descriptor) ToBytes() []byte {
	return d[:]
}

func GetDescriptorBytes(walletType wallettype.WalletType, metadata [2]byte) [DescriptorSize]byte {
	return [DescriptorSize]byte{byte(walletType), metadata[0], metadata[1]}
}
