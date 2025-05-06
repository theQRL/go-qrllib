package common

import (
	"github.com/theQRL/go-qrllib/misc"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
)

/*
UnsafeGetAddress - It is unsafe as it doesn't validate the pk and descriptor. This function
should only be called after validating the pk and descriptor. If it's being called by the method of XMSS or Dilithium,
in that case no validation is required as the objects of those classes are made after the validation.
*/
func UnsafeGetAddress(pk []uint8, descriptor descriptor.Descriptor) [AddressSize]uint8 {
	var hashedKey [32]uint8

	// noinspection GoBoolExpressions
	if len(hashedKey) < AddressSize {
		panic("Address size is not sufficient")
	}

	hashInput := make([]byte, len(descriptor)+len(pk))
	hashInput = append(hashInput, descriptor.ToBytes()...)
	hashInput = append(hashInput, pk[:]...)
	misc.SHAKE256(hashedKey[:], hashInput)

	var address [AddressSize]uint8
	copy(address[:], hashedKey[len(hashedKey)-AddressSize:])
	return address
}
