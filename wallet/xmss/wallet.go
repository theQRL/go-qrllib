package xmss

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/theQRL/go-qrllib/crypto/xmss"
	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/misc"
)

type Wallet struct {
	seed common.Seed
	desc Descriptor
	xmss *xmss.XMSS
}

func NewWallet(height xmss.Height, hashFunction xmss.HashFunction) (*Wallet, error) {
	var seed common.Seed
	_, err := rand.Read(seed[:])
	if err != nil {
		panic("Failed to generate random seed for XMSS address")
	}
	return newWalletFromSeed(seed, height, hashFunction)
}

func newWalletFromSeed(seed common.Seed, height xmss.Height, hashFunction xmss.HashFunction) (*Wallet, error) {
	desc, err := NewXMSSDescriptor(hashFunction, height)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		seed,
		desc,
		xmss.InitializeTree(desc.GetHeight(), desc.GetHashFunction(), seed.ToBytes()),
	}, nil
}

func NewWalletFromExtendedSeed(extendedSeed common.ExtendedSeed) (*Wallet, error) {
	desc, err := NewXMSSDescriptorFromDescriptorBytes(extendedSeed.GetDescriptorBytes())
	if err != nil {
		return nil, fmt.Errorf("failed to generate XMSS descriptor from extended seed: %v", err)
	}

	seed, err := common.ToSeed(extendedSeed.GetSeedBytes())
	if err != nil {
		return nil, fmt.Errorf("failed to convert extended seed from extended seed to seed: %v", err)
	}

	return &Wallet{
		seed,
		desc,
		xmss.InitializeTree(desc.GetHeight(), desc.GetHashFunction(), seed.ToBytes()),
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

func (w *Wallet) GetHashFunction() xmss.HashFunction {
	return w.xmss.GetHashFunction()
}

func (w *Wallet) GetHeight() xmss.Height {
	return w.xmss.GetHeight()
}

func (w *Wallet) GetSeed() common.Seed {
	seed, err := common.ToSeed(w.xmss.GetSeed())
	if err != nil {
		panic(fmt.Errorf("failed to GetSeed: %v", err))
	}
	return seed
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

func (w *Wallet) GetRoot() []uint8 {
	return w.xmss.GetRoot()
}

func (w *Wallet) GetPK() PK {
	//    PK format
	//    32 bytes root address
	//    32 bytes pub_seed

	root := w.xmss.GetRoot()
	pubSeed := w.xmss.GetPKSeed()

	var output PK
	if len(root)+len(pubSeed) != PKSize {
		panic("Unexpected: len(root)+len(pubSeed) != ExtendedPKSize")
	}

	copy(output[:], root)
	copy(output[len(root):], pubSeed)
	return output
}

func (w *Wallet) GetSK() []uint8 {
	return w.xmss.GetSK()
}

func (w *Wallet) GetAddress() [common.AddressSize]uint8 {
	pk := w.GetPK()
	return common.UnsafeGetAddress(pk[:], w.desc.ToDescriptor())
}

func (w *Wallet) GetAddressStr() string {
	addr := w.GetAddress()
	return fmt.Sprintf("Z%x", addr[:])
}

func (w *Wallet) GetIndex() uint32 {
	return w.xmss.GetIndex()
}

func (w *Wallet) SetIndex(index uint32) error {
	return w.xmss.SetIndex(index)
}

func (w *Wallet) Sign(message []uint8) ([]uint8, error) {
	return w.xmss.Sign(message)
}

func Verify(message, signature []uint8, pk *PK, descriptor []byte) (result bool) {
	height := xmss.GetHeightFromSigSize(uint32(len(signature)), xmss.WOTSParamW)
	if !height.IsValid() {
		return false
	}

	desc, err := NewXMSSDescriptorFromDescriptorBytes(descriptor)
	if err != nil || !desc.IsValid() {
		return false
	}

	if desc.GetHeight() != height {
		return false
	}

	return xmss.Verify(desc.GetHashFunction(), message, signature, pk[:])
}
