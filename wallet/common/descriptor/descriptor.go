package descriptor

import (
	"fmt"
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

func NewDescriptor(descriptorBytes []byte) Descriptor {
	if len(descriptorBytes) != DescriptorSize {
		panic(fmt.Sprintf("Descriptor size should be %v byte", DescriptorSize))
	}
	var d Descriptor
	copy(d[:], descriptorBytes)
	return d
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
