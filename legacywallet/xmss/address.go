package xmss

import (
	"errors"
	"reflect"

	"github.com/theQRL/go-qrllib/common"
	"github.com/theQRL/go-qrllib/misc"
)

// ErrUnsupportedAddressFormat is returned when the address format is not SHA256_2X.
var ErrUnsupportedAddressFormat = errors.New("unsupported address format type")

func GetXMSSAddressFromPK(ePK [ExtendedPKSize]uint8) ([AddressSize]uint8, error) {
	desc, err := LegacyQRLDescriptorFromExtendedPK(&ePK)
	if err != nil {
		return [AddressSize]uint8{}, err
	}

	if desc.GetAddrFormatType() != common.SHA256_2X {
		return [AddressSize]uint8{}, ErrUnsupportedAddressFormat
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

	return address, nil
}

func IsValidXMSSAddress(address [AddressSize]uint8) bool {
	d, err := NewQRLDescriptorFromBytes(address[:DescriptorSize])
	if err != nil {
		return false
	}
	if d.GetAddrFormatType() != common.SHA256_2X {
		return false
	}

	var hashedKey [32]uint8
	misc.SHA256(hashedKey[:], address[:DescriptorSize+32])

	return reflect.DeepEqual(address[DescriptorSize+32:], hashedKey[28:])
}
