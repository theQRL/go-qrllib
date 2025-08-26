package common

const (
	ErrSeedGenerationFailure             = "failed to generate random seed for %s address: %v"
	ErrInvalidDescriptor                 = "invalid %s descriptor"
	ErrDescriptorFromExtendedSeed        = "failed to generate %s descriptor from extended seed: %v"
	ErrExtendedSeedToSeed                = "failed to convert %s extended seed to seed: %v"
	ErrMnemonicToBin                     = "failed to convert %s mnemonic to bin: %v"
	ErrExtendedSeedFromMnemonic          = "failed to create %s extended seed from mnemonic: %v"
	ErrExtendedSeedFromDescriptorAndSeed = "failed to create %s extended seed from descriptor and seed: %v"
	ErrInvalidSignatureSize              = "%s unexpected signature size %d, expected signature size %d"
	ErrDecodeHexSeed                     = "failed to decode hex seed for %s: %v"
	ErrInvalidPKSize                     = "%s invalid pkBytes size %d, expected %d"
)
