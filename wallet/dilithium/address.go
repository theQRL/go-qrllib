package dilithium

import (
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
)

func GetDilithiumAddress(pk PK, descriptor Descriptor) ([common.AddressSize]uint8, error) {
	var address [common.AddressSize]uint8
	if !descriptor.IsValid() {
		return address, fmt.Errorf("invalid Dilithium descriptor")
	}
	return common.UnsafeGetAddress(pk[:], descriptor.ToDescriptor()), nil
}
