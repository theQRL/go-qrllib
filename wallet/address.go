package wallet

import (
	"errors"
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
	"github.com/theQRL/go-qrllib/wallet/ml_dsa_87"
	"github.com/theQRL/go-qrllib/wallet/sphincsplus_256s"
)

func validatePKAndDescriptor(pk []uint8, descriptor descriptor.Descriptor) error {
	if !descriptor.IsValid() {
		return errors.New("invalid descriptor")
	}
	switch wallettype.WalletType(descriptor[0]) {
	case wallettype.SPHINCSPLUS_256S:
		_, err := sphincsplus_256s.BytesToPK(pk)
		if err != nil {
			return err
		}
		_, err = sphincsplus_256s.NewSphincsPlus256sDescriptorFromDescriptor(descriptor)
		if err != nil {
			return err
		}
	case wallettype.ML_DSA_87:
		_, err := ml_dsa_87.BytesToPK(pk)
		if err != nil {
			return err
		}
		_, err = ml_dsa_87.NewMLDSA87DescriptorFromDescriptor(descriptor)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown wallet type: %d", descriptor[0])
	}
	return nil
}

func GetAddressFromPKAndDescriptor(pk []uint8, descriptor descriptor.Descriptor) ([common.AddressSize]uint8, error) {
	if err := validatePKAndDescriptor(pk, descriptor); err != nil {
		return [common.AddressSize]uint8{}, fmt.Errorf("invalid pk or descriptor: %v", err)
	}
	return common.UnsafeGetAddress(pk, descriptor), nil
}

func IsValidAddress(address [common.AddressSize]uint8) bool {
	return true
}
