package sphincsplus_256s

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s"
	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
	"github.com/theQRL/go-qrllib/wallet/misc"
)

// experimental controls whether the SPHINCS+ wallet path is enabled.
//
// SPHINCSPLUS_256S is reserved in the QRL descriptor format as a forward
// placeholder for QRL's eventual SLH-DSA (FIPS 205) adoption (see
// [github.com/theQRL/go-qrllib/wallet/common/wallettype.WalletType.IsIssuable]).
// Until SLH-DSA activation, public wallet constructors return
// [common.ErrWalletTypeNotIssuable] and Verify returns false, regardless
// of the underlying primitive being functional.
//
// Tests in this package (and other QRL test code that needs to exercise
// the SPHINCS+ implementation end-to-end) enable the path via
// EnableExperimentalForTesting in a TestMain shim so the implementation
// stays continuously exercised. Activation in production is a one-line
// change to the IsIssuable / IsVerifiable switches in the wallettype
// package; toggling this variable is not the supported activation path.
var experimental = false

// EnableExperimentalForTesting flips the package-internal experimental
// flag and returns the previous value, allowing test code to opt in to
// SPHINCS+ wallet construction and verification while the type is gated
// in production. Returns the previous value so callers can restore it.
//
// Production code MUST NOT call this. The supported activation path for
// SLH-DSA (FIPS 205) goes through the IsIssuable / IsVerifiable switches
// in [github.com/theQRL/go-qrllib/wallet/common/wallettype], not through
// this helper. Ignoring this warning and calling this in a non-test context
// will result in wallets and signatures that are not part of QRL's supported
// production surface and may not be compatible with future activation
// (which may carry parameter-set or layout differences).
func EnableExperimentalForTesting(enabled bool) bool {
	prev := experimental
	experimental = enabled
	return prev
}

// issuable reports whether wallet construction should proceed for
// SPHINCSPLUS_256S today, combining the static type-level switch with
// the in-package experimental flag.
func issuable() bool {
	return experimental || wallettype.SPHINCSPLUS_256S.IsIssuable()
}

// verifiable reports whether Verify should accept signatures under a
// SPHINCSPLUS_256S descriptor today. Mirrors issuable for the
// verification side.
func verifiable() bool {
	return experimental || wallettype.SPHINCSPLUS_256S.IsVerifiable()
}

type Wallet struct {
	desc Descriptor
	s    *sphincsplus_256s.SphincsPlus256s
	seed common.Seed
}

func NewWallet() (*Wallet, error) {
	var seed common.Seed
	_, err := rand.Read(seed[:])
	if err != nil {
		//coverage:ignore
		//rationale: crypto/rand.Read only fails if system entropy source is broken
		return nil, fmt.Errorf(common.ErrSeedGenerationFailure, wallettype.SPHINCSPLUS_256S, err)
	}
	return NewWalletFromSeed(seed)
}

func toSphincsPlus256sSeed(seed []byte) [sphincsplus_256s.CRYPTO_SEEDBYTES]uint8 {
	var sphincsPlus256sSeed [sphincsplus_256s.CRYPTO_SEEDBYTES]uint8
	copy(sphincsPlus256sSeed[:], seed)
	return sphincsPlus256sSeed
}

func NewWalletFromSeed(seed common.Seed) (*Wallet, error) {
	if !issuable() {
		return nil, fmt.Errorf("%w: %s", common.ErrWalletTypeNotIssuable, wallettype.SPHINCSPLUS_256S)
	}
	desc, err := NewSphincsPlus256sDescriptor()
	if err != nil {
		//coverage:ignore
		//rationale: descriptor uses hardcoded valid wallet type, cannot fail
		return nil, fmt.Errorf("failed to create descriptor: %w", err)
	}
	d, err := sphincsplus_256s.NewSphincsPlus256sFromSeed(toSphincsPlus256sSeed(seed.HashSHAKE256(sphincsplus_256s.CRYPTO_SEEDBYTES)))
	if err != nil {
		//coverage:ignore
		//rationale: keypair generation only fails if buffer sizes wrong, Go's type system guarantees correct sizes
		return nil, err
	}

	return &Wallet{
		desc,
		d,
		seed,
	}, nil
}

func NewWalletFromHexSeed(hexSeed string) (*Wallet, error) {
	if strings.HasPrefix(hexSeed, "0x") || strings.HasPrefix(hexSeed, "0X") {
		hexSeed = hexSeed[2:]
	}
	binSeed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf(common.ErrDecodeHexSeed, wallettype.SPHINCSPLUS_256S, err.Error())
	}
	if len(binSeed) != common.SeedSize {
		return nil, fmt.Errorf(common.ErrInvalidSeedLength, wallettype.SPHINCSPLUS_256S, len(binSeed), common.SeedSize)
	}
	var seed common.Seed
	copy(seed[:], binSeed[:])
	return NewWalletFromSeed(seed)
}

func NewWalletFromExtendedSeed(extendedSeed common.ExtendedSeed) (*Wallet, error) {
	if !issuable() {
		return nil, fmt.Errorf("%w: %s", common.ErrWalletTypeNotIssuable, wallettype.SPHINCSPLUS_256S)
	}
	desc, err := NewSphincsPlus256sDescriptorFromDescriptorBytes(extendedSeed.GetDescriptorBytes())
	if err != nil {
		return nil, fmt.Errorf(common.ErrDescriptorFromExtendedSeed, wallettype.SPHINCSPLUS_256S, err)
	}

	seed, err := common.ToSeed(extendedSeed.GetSeedBytes())
	if err != nil {
		//coverage:ignore
		return nil, fmt.Errorf(common.ErrExtendedSeedToSeed, wallettype.SPHINCSPLUS_256S, err)
	}

	d, err := sphincsplus_256s.NewSphincsPlus256sFromSeed(toSphincsPlus256sSeed(seed.HashSHAKE256(sphincsplus_256s.CRYPTO_SEEDBYTES)))
	if err != nil {
		//coverage:ignore
		return nil, err
	}

	return &Wallet{
		desc,
		d,
		seed,
	}, nil
}

func NewWalletFromHexExtendedSeed(hexExtendedSeed string) (*Wallet, error) {
	if strings.HasPrefix(hexExtendedSeed, "0x") || strings.HasPrefix(hexExtendedSeed, "0X") {
		hexExtendedSeed = hexExtendedSeed[2:]
	}
	binExtendedSeed, err := hex.DecodeString(hexExtendedSeed)
	if err != nil {
		return nil, fmt.Errorf(common.ErrDecodeHexSeed, wallettype.SPHINCSPLUS_256S, err.Error())
	}
	if len(binExtendedSeed) != common.ExtendedSeedSize {
		return nil, fmt.Errorf(common.ErrInvalidExtendedSeedLength, wallettype.SPHINCSPLUS_256S, len(binExtendedSeed), common.ExtendedSeedSize)
	}
	var extendedSeed common.ExtendedSeed
	copy(extendedSeed[:], binExtendedSeed[:])
	return NewWalletFromExtendedSeed(extendedSeed)
}

func NewWalletFromMnemonic(mnemonic string) (*Wallet, error) {
	bin, err := misc.MnemonicToBin(mnemonic)
	if err != nil {
		return nil, fmt.Errorf(common.ErrMnemonicToBin, wallettype.SPHINCSPLUS_256S, err)
	}

	extendedSeed, err := common.NewExtendedSeedFromBytes(bin)
	if err != nil {
		return nil, fmt.Errorf(common.ErrExtendedSeedFromMnemonic, wallettype.SPHINCSPLUS_256S, err)
	}

	return NewWalletFromExtendedSeed(extendedSeed)
}

func (w *Wallet) GetSeed() common.Seed {
	return w.seed
}

func (w *Wallet) GetExtendedSeed() (common.ExtendedSeed, error) {
	extendedSeed, err := common.NewExtendedSeed(w.desc.ToDescriptor(), w.GetSeed())
	if err != nil {
		return common.ExtendedSeed{}, fmt.Errorf(common.ErrExtendedSeedFromDescriptorAndSeed, wallettype.SPHINCSPLUS_256S, err)
	}
	return extendedSeed, nil
}

func (w *Wallet) GetHexSeed() (string, error) {
	eSeed, err := w.GetExtendedSeed()
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(eSeed[:]), nil
}

func (w *Wallet) GetMnemonic() (string, error) {
	eSeed, err := w.GetExtendedSeed()
	if err != nil {
		return "", err
	}
	mnemonic, err := misc.BinToMnemonic(eSeed[:])
	if err != nil {
		//coverage:ignore
		return "", err
	}
	return mnemonic, nil
}

func (w *Wallet) GetPK() PK {
	return w.s.GetPK()
}

func (w *Wallet) GetSK() [SKSize]uint8 {
	return w.s.GetSK()
}

func (w *Wallet) GetDescriptor() Descriptor {
	return w.desc
}

func (w *Wallet) GetAddress() [common.AddressSize]uint8 {
	pk := w.GetPK()
	return common.UnsafeGetAddress(pk[:], w.desc.ToDescriptor())
}

func (w *Wallet) GetAddressStr() string {
	addr := w.GetAddress()
	return fmt.Sprintf("Q%x", addr[:])
}

// domainSeparatedMessage prepends the fixed-length signing context to the
// message, so SPHINCS+ (which has no native ctx parameter) still commits
// to the descriptor in its signed bytes. The prefix is a compile-time
// constant length (common.SigningContextSize), so concatenation is
// canonically parseable and cannot collide with a shifted-boundary
// forgery.
func domainSeparatedMessage(desc descriptor.Descriptor, message []uint8) []uint8 {
	ctx := common.SigningContext(desc)
	out := make([]uint8, 0, len(ctx)+len(message))
	out = append(out, ctx...)
	out = append(out, message...)
	return out
}

func (w *Wallet) Sign(message []uint8) ([SigSize]uint8, error) {
	return w.s.Sign(domainSeparatedMessage(w.desc.ToDescriptor(), message))
}

// Zeroize clears sensitive key material from memory.
// This should be called when the Wallet is no longer needed.
func (w *Wallet) Zeroize() {
	for i := range w.seed {
		w.seed[i] = 0
	}
	w.s.Zeroize()
}

func Verify(message, signature []uint8, pk *PK, desc [descriptor.DescriptorSize]byte) (result bool) {
	if !verifiable() {
		return false
	}
	d, err := NewSphincsPlus256sDescriptorFromDescriptorBytes(desc)
	if err != nil {
		return false
	}

	if len(signature) != SigSize {
		// Invalid signature size - return false instead of panicking
		return false
	}

	var sig [SigSize]uint8
	copy(sig[:], signature)

	var pk2 [PKSize]uint8
	copy(pk2[:], pk[:])

	return sphincsplus_256s.Verify(domainSeparatedMessage(d.ToDescriptor(), message), sig, &pk2)
}
