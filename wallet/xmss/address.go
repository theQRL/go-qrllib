package xmss

import (
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
)

func GetXMSSAddress(pk PK, descriptor Descriptor) ([common.AddressSize]uint8, error) {
	var address [common.AddressSize]uint8
	if !descriptor.IsValid() {
		return address, fmt.Errorf("invalid XMSS descriptor")
	}
	return common.UnsafeGetAddress(pk[:], descriptor.ToDescriptor()), nil
}
