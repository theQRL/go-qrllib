package common

import "errors"

// fmt.Errorf format strings used for wrapping errors with wallet-type
// context. These are not sentinel errors; for errors.Is comparisons see
// the sentinel block below.
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
	ErrInvalidSeedLength                 = "%s invalid seed length %d, expected %d"
	ErrInvalidExtendedSeedLength         = "%s invalid extended seed length %d, expected %d"
)

// Sentinel errors for wallet-type gating. Compare with errors.Is.
//
// ErrWalletTypeNotIssuable is returned by wallet constructors when the
// requested wallet type is recognised by the descriptor format but is
// not currently enabled for new wallet construction. Today this means
// SPHINCSPLUS_256S, which is reserved as a forward placeholder for QRL's
// eventual SLH-DSA (FIPS 205) adoption. See
// [github.com/theQRL/go-qrllib/wallet/common/wallettype.WalletType.IsIssuable].
//
// ErrWalletTypeNotVerifiable is the equivalent for wallet-level Verify
// dispatch. Today wallet-level Verify functions return false rather than
// surfacing this error directly (Verify's signature is a bool), but the
// sentinel is exposed for callers that need to distinguish "signature
// invalid" from "wallet type not currently supported".
var (
	ErrWalletTypeNotIssuable   = errors.New("wallet type is not currently issuable")
	ErrWalletTypeNotVerifiable = errors.New("wallet type is not currently verifiable")
)
