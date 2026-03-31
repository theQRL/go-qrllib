package common

import (
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
)

const (
	AddressSize           = 48
	SeedSize              = 48
	ExtendedSeedSize      = descriptor.DescriptorSize + SeedSize
	MLDSA87PKSize         = 2592
	SPHINCSPlus256sPKSize = 64
)
