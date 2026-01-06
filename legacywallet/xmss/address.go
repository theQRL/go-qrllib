package xmss

import (
	"reflect"

	"github.com/theQRL/go-qrllib/common"
	"github.com/theQRL/go-qrllib/misc"
)

func GetXMSSAddressFromPK(ePK [ExtendedPKSize]uint8) [AddressSize]uint8 {
	desc := LegacyQRLDescriptorFromExtendedPK(&ePK)

	if desc.GetAddrFormatType() != common.SHA256_2X {
		panic("Address format type not supported")
	}

	var address [AddressSize]uint8
	addressOffset := 0
	descBytes := desc.GetBytes()

	copy(address[:], descBytes[:])
	addressOffset += len(descBytes)

	var hashedKey [32]uint8
	misc.SHA256(hashedKey[:], ePK[:])
	copy(address[addressOffset:], hashedKey[:])
	addressOffset += len(hashedKey)

	var hashedKey2 [32]uint8
	misc.SHA256(hashedKey2[:], address[:addressOffset])
	hashedKey2Offset := len(hashedKey2) - 4

	copy(address[addressOffset:], hashedKey2[hashedKey2Offset:])

	return address
}

func IsValidXMSSAddress(address [AddressSize]uint8) bool {
	d := NewQRLDescriptorFromBytes(address[:DescriptorSize])
	if d.GetAddrFormatType() != common.SHA256_2X {
		return false
	}

	var hashedKey [32]uint8
	misc.SHA256(hashedKey[:], address[:DescriptorSize+32])

	return reflect.DeepEqual(address[DescriptorSize+32:], hashedKey[28:])
}
