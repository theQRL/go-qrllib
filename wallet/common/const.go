package common

import (
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
)

const (
	AddressSize      = 24
	SeedSize         = 48
	ExtendedSeedSize = descriptor.DescriptorSize + SeedSize
)
