package ml_dsa_87

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

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
	if err != nil { //coverage:ignore - crypto/rand.Read only fails if system entropy source is broken
		return nil, fmt.Errorf(common.ErrSeedGenerationFailure, wallettype.ML_DSA_87, err)
	}
	return NewWalletFromSeed(seed)
}

func NewWalletFromSeed(seed common.Seed) (*Wallet, error) {
	desc, err := NewMLDSA87Descriptor()
	if err != nil { //coverage:ignore - descriptor uses hardcoded valid wallet type, cannot fail
		return nil, fmt.Errorf("failed to create descriptor: %w", err)
	}
	d, err := ml_dsa_87.NewMLDSA87FromSeed(seed.HashSHA256())
	if err != nil { //coverage:ignore - keypair generation is deterministic mathematics, only fails if seed is nil
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
	if err != nil { //coverage:ignore - ExtendedSeed.GetSeedBytes() always returns exactly SeedSize bytes
		return nil, fmt.Errorf(common.ErrExtendedSeedToSeed, wallettype.ML_DSA_87, err)
	}

	d, err := ml_dsa_87.NewMLDSA87FromSeed(seed.HashSHA256())
	if err != nil { //coverage:ignore - keypair generation is deterministic mathematics, only fails if seed is nil
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

func (w *Wallet) GetExtendedSeed() (common.ExtendedSeed, error) {
	extendedSeed, err := common.NewExtendedSeed(w.desc.ToDescriptor(), w.GetSeed())
	if err != nil {
		return common.ExtendedSeed{}, fmt.Errorf(common.ErrExtendedSeedFromDescriptorAndSeed, wallettype.ML_DSA_87, err)
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
	if err != nil { //coverage:ignore - ExtendedSeed is always 51 bytes (divisible by 3) and buffer writes never error
		return "", err
	}
	return mnemonic, nil
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
