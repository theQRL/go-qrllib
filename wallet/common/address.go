package common

import (
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"golang.org/x/crypto/sha3"
)

/*
UnsafeGetAddress - It is unsafe as it doesn't validate the pk and descriptor. This function
should only be called after validating the pk and descriptor. If it's being called by the method of SPHINCS+-256s
or ML-DSA-87, in that case no validation is required as the objects of those classes are made after the validation.
*/
func UnsafeGetAddress(pk []byte, desc descriptor.Descriptor) [AddressSize]byte {
	// noinspection GoBoolExpressions
	if AddressSize > 32 {
		panic("AddressSize must be <= 32")
	}

	sh := sha3.NewShake256()
	_, _ = sh.Write(desc.ToBytes())
	_, _ = sh.Write(pk)

	var addr [AddressSize]byte
	_, _ = sh.Read(addr[:]) // take the first N bytes
	return addr
}
