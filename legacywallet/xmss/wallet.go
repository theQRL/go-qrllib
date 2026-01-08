package xmss

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	misc2 "github.com/theQRL/go-qrllib/wallet/misc"

	"github.com/theQRL/go-qrllib/common"
	"github.com/theQRL/go-qrllib/crypto/xmss"
	"github.com/theQRL/go-qrllib/legacywallet"
)

type XMSSWallet struct {
	seed [SeedSize]uint8
	desc *QRLDescriptor
	xmss *xmss.XMSS
}

func NewWalletFromSeed(seed [SeedSize]uint8, height xmss.Height, hashFunction xmss.HashFunction, addrFormatType common.AddrFormatType) (*XMSSWallet, error) {
	signatureType := legacywallet.WalletTypeXMSS // Signature Type hard coded for now
	if height > xmss.MaxHeight {
		return nil, fmt.Errorf("height %d exceeds maximum %d", height, xmss.MaxHeight)
	}
	desc := NewQRLDescriptor(height, hashFunction, signatureType, addrFormatType)

	tree, err := xmss.InitializeTree(desc.height, desc.hashFunction, seed[:])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize XMSS tree: %w", err)
	}

	return &XMSSWallet{
		seed: seed,
		desc: desc,
		xmss: tree,
	}, nil
}

func NewWalletFromExtendedSeed(extendedSeed [ExtendedSeedSize]uint8) (*XMSSWallet, error) {
	desc, err := NewQRLDescriptorFromExtendedSeed(extendedSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to parse descriptor: %w", err)
	}

	var seed [SeedSize]uint8
	copy(seed[:], extendedSeed[DescriptorSize:])

	tree, err := xmss.InitializeTree(desc.height, desc.hashFunction, seed[:])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize XMSS tree: %w", err)
	}

	return &XMSSWallet{
		seed: seed,
		desc: desc,
		xmss: tree,
	}, nil
}

func NewWalletFromHeight(height xmss.Height, hashFunction xmss.HashFunction) (*XMSSWallet, error) {
	var seed [SeedSize]uint8
	_, err := rand.Read(seed[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}
	return NewWalletFromSeed(seed, height, hashFunction, common.SHA256_2X)
}

func (w *XMSSWallet) SetIndex(newIndex uint32) error {
	return w.xmss.SetIndex(newIndex)
}

func (w *XMSSWallet) GetHeight() xmss.Height {
	return w.xmss.GetHeight()
}

func (w *XMSSWallet) GetSeed() [SeedSize]uint8 {
	return w.seed
}

func (w *XMSSWallet) GetExtendedSeed() [ExtendedSeedSize]uint8 {
	var extendedSeed [ExtendedSeedSize]uint8
	descBytes := w.desc.GetBytes()
	seed := w.GetSeed()
	copy(extendedSeed[:3], descBytes[:])
	copy(extendedSeed[3:], seed[:])
	return extendedSeed
}

func (w *XMSSWallet) GetHexSeed() string {
	eSeed := w.GetExtendedSeed()
	return "0x" + hex.EncodeToString(eSeed[:])
}

func (w *XMSSWallet) GetMnemonic() (string, error) {
	extendedSeed := w.GetExtendedSeed()
	return misc2.BinToMnemonic(extendedSeed[:])
}

func (w *XMSSWallet) GetRoot() []uint8 {
	return w.xmss.GetRoot()
}

func (w *XMSSWallet) GetPK() [ExtendedPKSize]uint8 {
	//    PK format
	//     3 QRL_DESCRIPTOR
	//    32 root address
	//    32 pub_seed

	desc := w.desc.GetBytes()
	root := w.GetRoot()
	pubSeed := w.xmss.GetPKSeed()

	var output [ExtendedPKSize]uint8
	offset := 0
	copy(output[:], desc[:])
	offset += len(desc)
	copy(output[offset:], root[:])
	offset += len(root)
	copy(output[offset:], pubSeed[:])
	return output
}

func (w *XMSSWallet) GetSK() []uint8 {
	return w.xmss.GetSK()
}

func (w *XMSSWallet) GetAddress() ([AddressSize]uint8, error) {
	return GetXMSSAddressFromPK(w.GetPK())
}

func (w *XMSSWallet) GetIndex() uint32 {
	return w.xmss.GetIndex()
}

func (w *XMSSWallet) Sign(message []uint8) ([]uint8, error) {
	return w.xmss.Sign(message)
}

func Verify(message, signature []uint8, extendedPK [ExtendedPKSize]uint8) (result bool) {
	height, err := xmss.GetHeightFromSigSize(uint32(len(signature)), xmss.WOTSParamW)
	if err != nil {
		return false
	}

	desc, err := NewQRLDescriptorFromExtendedPK(&extendedPK)
	if err != nil {
		return false
	}

	if desc.GetSignatureType() != legacywallet.WalletTypeXMSS {
		return false
	}

	if desc.GetHeight() != height {
		return false
	}

	pk := extendedPK[DescriptorSize:]

	return xmss.Verify(desc.hashFunction, message, signature, pk)
}
