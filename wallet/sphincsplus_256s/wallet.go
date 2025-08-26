package sphincsplus_256s

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

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
		panic(fmt.Errorf(common.ErrSeedGenerationFailure, wallettype.SPHINCSPLUS_256S, err))
	}
	return newWalletFromSeed(seed)
}

func toSphincsPlus256sSeed(seed []byte) [sphincsplus_256s.CRYPTO_SEEDBYTES]uint8 {
	var sphincsPlus256sSeed [sphincsplus_256s.CRYPTO_SEEDBYTES]uint8
	copy(sphincsPlus256sSeed[:], seed)
	return sphincsPlus256sSeed
}

func newWalletFromSeed(seed common.Seed) (*Wallet, error) {
	desc := NewSphincsPlus256sDescriptor()
	d, err := sphincsplus_256s.NewSphincsPlus256sFromSeed(toSphincsPlus256sSeed(seed.HashSHAKE256(sphincsplus_256s.CRYPTO_SEEDBYTES)))
	if err != nil {
		return nil, err
	}

	return &Wallet{
		desc,
		d,
		seed,
	}, nil
}

func NewWalletFromExtendedSeed(extendedSeed common.ExtendedSeed) (*Wallet, error) {
	desc, err := NewSphincsPlus256sDescriptorFromDescriptorBytes(extendedSeed.GetDescriptorBytes())
	if err != nil {
		return nil, fmt.Errorf(common.ErrDescriptorFromExtendedSeed, wallettype.SPHINCSPLUS_256S, err)
	}

	seed, err := common.ToSeed(extendedSeed.GetSeedBytes())
	if err != nil {
		return nil, fmt.Errorf(common.ErrExtendedSeedToSeed, wallettype.SPHINCSPLUS_256S, err)
	}

	d, err := sphincsplus_256s.NewSphincsPlus256sFromSeed(toSphincsPlus256sSeed(seed.HashSHAKE256(sphincsplus_256s.CRYPTO_SEEDBYTES)))
	if err != nil {
		return nil, err
	}

	return &Wallet{
		desc,
		d,
		seed,
	}, nil
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

func (w *Wallet) GetExtendedSeed() common.ExtendedSeed {
	extendedSeed, err := common.NewExtendedSeed(w.desc.ToDescriptor(), w.GetSeed())
	if err != nil {
		panic(fmt.Errorf(common.ErrExtendedSeedFromDescriptorAndSeed, wallettype.SPHINCSPLUS_256S, err))
	}
	return extendedSeed
}

func (w *Wallet) GetHexSeed() string {
	eSeed := w.GetExtendedSeed()
	return "0x" + hex.EncodeToString(eSeed[:])
}

func (w *Wallet) GetMnemonic() string {
	eSeed := w.GetExtendedSeed()
	mnemonic, err := misc.BinToMnemonic(eSeed[:])
	if err != nil {
		panic(err)
	}
	return mnemonic
}

func (w *Wallet) GetPK() PK {
	return w.s.GetPK()
}

func (w *Wallet) GetSK() [SKSize]uint8 {
	return w.s.GetSK()
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
		panic(fmt.Errorf(common.ErrInvalidSignatureSize, wallettype.SPHINCSPLUS_256S, len(signature), SigSize))
	}

	var sig [SigSize]uint8
	copy(sig[:], signature)

	var pk2 [PKSize]uint8
	copy(pk2[:], pk[:])

	return sphincsplus_256s.Verify(message, sig, &pk2)
}
