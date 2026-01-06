package ml_dsa_87

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
	"github.com/theQRL/go-qrllib/wallet/misc"
)

var ctx = []uint8{'Z', 'O', 'N', 'D'}

type Wallet struct {
	desc Descriptor
	d    *ml_dsa_87.MLDSA87
	seed common.Seed
}

func NewWallet() (*Wallet, error) {
	var seed common.Seed
	_, err := rand.Read(seed[:])
	if err != nil {
		return nil, fmt.Errorf(common.ErrSeedGenerationFailure, wallettype.ML_DSA_87, err)
	}
	return NewWalletFromSeed(seed)
}

func NewWalletFromSeed(seed common.Seed) (*Wallet, error) {
	desc := NewMLDSA87Descriptor()
	d, err := ml_dsa_87.NewMLDSA87FromSeed(seed.HashSHA256())
	if err != nil {
		return nil, err
	}

	return &Wallet{
		desc,
		d,
		seed,
	}, nil
}

func NewWalletFromHexSeed(hexSeed string) (*Wallet, error) {
	binSeed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf(common.ErrDecodeHexSeed, wallettype.ML_DSA_87, err.Error())
	}
	if len(binSeed) != common.SeedSize {
		return nil, fmt.Errorf(common.ErrInvalidSeedLength, wallettype.ML_DSA_87, len(binSeed), common.SeedSize)
	}
	var seed common.Seed
	copy(seed[:], binSeed[:])
	return NewWalletFromSeed(seed)
}

func NewWalletFromExtendedSeed(extendedSeed common.ExtendedSeed) (*Wallet, error) {
	desc, err := NewMLDSA87DescriptorFromDescriptorBytes(extendedSeed.GetDescriptorBytes())
	if err != nil {
		return nil, fmt.Errorf(common.ErrDescriptorFromExtendedSeed, wallettype.ML_DSA_87, err)
	}

	seed, err := common.ToSeed(extendedSeed.GetSeedBytes())
	if err != nil {
		return nil, fmt.Errorf(common.ErrExtendedSeedToSeed, wallettype.ML_DSA_87, err)
	}

	d, err := ml_dsa_87.NewMLDSA87FromSeed(seed.HashSHA256())
	if err != nil {
		return nil, err
	}

	return &Wallet{
		desc,
		d,
		seed,
	}, nil
}

func NewWalletFromHexExtendedSeed(hexExtendedSeed string) (*Wallet, error) {
	binExtendedSeed, err := hex.DecodeString(hexExtendedSeed)
	if err != nil {
		return nil, fmt.Errorf(common.ErrDecodeHexSeed, wallettype.ML_DSA_87, err.Error())
	}
	if len(binExtendedSeed) != common.ExtendedSeedSize {
		return nil, fmt.Errorf(common.ErrInvalidExtendedSeedLength, wallettype.ML_DSA_87, len(binExtendedSeed), common.ExtendedSeedSize)
	}
	var extendedSeed common.ExtendedSeed
	copy(extendedSeed[:], binExtendedSeed[:])
	return NewWalletFromExtendedSeed(extendedSeed)
}

func NewWalletFromMnemonic(mnemonic string) (*Wallet, error) {
	bin, err := misc.MnemonicToBin(mnemonic)
	if err != nil {
		return nil, fmt.Errorf(common.ErrMnemonicToBin, wallettype.ML_DSA_87, err)
	}

	extendedSeed, err := common.NewExtendedSeedFromBytes(bin)
	if err != nil {
		return nil, fmt.Errorf(common.ErrExtendedSeedFromMnemonic, wallettype.ML_DSA_87, err)
	}

	return NewWalletFromExtendedSeed(extendedSeed)
}

func (w *Wallet) GetSeed() common.Seed {
	return w.seed
}

func (w *Wallet) GetExtendedSeed() common.ExtendedSeed {
	extendedSeed, err := common.NewExtendedSeed(w.desc.ToDescriptor(), w.GetSeed())
	if err != nil {
		panic(fmt.Errorf(common.ErrExtendedSeedFromDescriptorAndSeed, wallettype.ML_DSA_87, err))
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
	return w.d.GetPK()
}

func (w *Wallet) GetSK() [SKSize]uint8 {
	return w.d.GetSK()
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
	return w.d.Sign(ctx, message)
}

func Verify(message, signature []uint8, pk *PK, desc [descriptor.DescriptorSize]byte) (result bool) {
	_, err := NewMLDSA87DescriptorFromDescriptorBytes(desc)
	if err != nil {
		return false
	}

	if len(signature) != SigSize {
		// Invalid signature size - return false instead of panicking
		return false
	}

	var sig [SigSize]uint8
	copy(sig[:], signature)

	var pk2 [ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES]uint8
	copy(pk2[:], pk[:])

	return ml_dsa_87.Verify(ctx, message, sig, &pk2)
}
