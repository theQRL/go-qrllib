package sphincsplus_256s

import (
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

func GetSphincsPlus256sAddress(pk PK, descriptor Descriptor) ([common.AddressSize]uint8, error) {
	var address [common.AddressSize]uint8
	if !descriptor.IsValid() {
		return address, fmt.Errorf(common.ErrInvalidDescriptor, wallettype.SPHINCSPLUS_256S)
	}
	return common.UnsafeGetAddress(pk[:], descriptor.ToDescriptor()), nil
}
