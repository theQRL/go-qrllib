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

func (w *Wallet) Sign(message []uint8) ([SigSize]uint8, error) {
	return w.s.Sign(message)
}

func Verify(message, signature []uint8, pk *PK, desc [descriptor.DescriptorSize]byte) (result bool) {
	_, err := NewSphincsPlus256sDescriptorFromDescriptorBytes(desc)
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

	return sphincsplus_256s.Verify(message, sig, &pk2)
}
