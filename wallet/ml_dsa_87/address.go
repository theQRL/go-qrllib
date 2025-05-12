package ml_dsa_87

import (
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
)

func GetMLDSA87Address(pk PK, descriptor Descriptor) ([common.AddressSize]uint8, error) {
	var address [common.AddressSize]uint8
	if !descriptor.IsValid() {
		return address, fmt.Errorf("invalid ML-DSA-87 descriptor")
	}
	return common.UnsafeGetAddress(pk[:], descriptor.ToDescriptor()), nil
}
