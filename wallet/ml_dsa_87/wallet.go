package ml_dsa_87

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
	"github.com/theQRL/go-qrllib/wallet/common"
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
		panic("Failed to generate random seed for XMSS address")
	}
	return newWalletFromSeed(seed)
}

func newWalletFromSeed(seed common.Seed) (*Wallet, error) {
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

func NewWalletFromExtendedSeed(extendedSeed common.ExtendedSeed) (*Wallet, error) {
	desc, err := NewMLDSA87DescriptorFromDescriptorBytes(extendedSeed.GetDescriptorBytes())
	if err != nil {
		return nil, fmt.Errorf("failed to generate MLDSA87 descriptor from extended seed: %v", err)
	}

	seed, err := common.ToSeed(extendedSeed.GetSeedBytes())
	if err != nil {
		return nil, fmt.Errorf("failed to convert extended seed from extended seed to seed: %v", err)
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

func NewWalletFromMnemonic(mnemonic string) (*Wallet, error) {
	bin, err := misc.MnemonicToBin(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to convert mnemonic to bin: %v", err)
	}

	extendedSeed, err := common.NewExtendedSeedFromBytes(bin)
	if err != nil {
		return nil, fmt.Errorf("failed to create extended seed from mnemonic: %v", err)
	}

	return NewWalletFromExtendedSeed(extendedSeed)
}

func (w *Wallet) GetSeed() common.Seed {
	return w.seed
}

func (w *Wallet) GetExtendedSeed() common.ExtendedSeed {
	var extendedSeed common.ExtendedSeed
	extendedSeed, err := common.NewExtendedSeed(w.desc.ToDescriptor(), w.GetSeed())
	if err != nil {
		panic(fmt.Errorf("failed to create extended seed. Reason: %v", err))
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

func (w *Wallet) GetAddress() [common.AddressSize]uint8 {
	pk := w.GetPK()
	return common.UnsafeGetAddress(pk[:], w.desc.ToDescriptor())
}

func (w *Wallet) GetAddressStr() string {
	addr := w.GetAddress()
	return fmt.Sprintf("Z%x", addr[:])
}

func (w *Wallet) Sign(message []uint8) ([SigSize]uint8, error) {
	return w.d.Sign(ctx, message)
}

func Verify(message, signature []uint8, pk *PK, descriptor []byte) (result bool) {
	_, err := NewMLDSA87DescriptorFromDescriptorBytes(descriptor)
	if err != nil {
		return false
	}

	if len(signature) != SigSize {
		panic(fmt.Errorf("unexpected: signature size %d, expected signature size %d", len(signature), SigSize))
	}

	var sig [SigSize]uint8
	copy(sig[:], signature)

	var pk2 [ml_dsa_87.CryptoPublicKeyBytes]uint8
	copy(pk2[:], pk[:])

	return ml_dsa_87.Verify(ctx, message, sig, &pk2)
}
