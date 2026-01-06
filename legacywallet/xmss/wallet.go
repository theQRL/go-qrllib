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

func NewWalletFromSeed(seed [SeedSize]uint8, height xmss.Height, hashFunction xmss.HashFunction, addrFormatType common.AddrFormatType) *XMSSWallet {
	signatureType := legacywallet.WalletTypeXMSS // Signature Type hard coded for now
	if height > xmss.MaxHeight {
		panic(fmt.Sprintf("Height should be <= %d", xmss.MaxHeight))
	}
	desc := NewQRLDescriptor(height, hashFunction, signatureType, addrFormatType)

	return &XMSSWallet{
		seed: seed,
		desc: desc,
		xmss: xmss.InitializeTree(desc.height, desc.hashFunction, seed[:]),
	}
}

func NewWalletFromExtendedSeed(extendedSeed [ExtendedSeedSize]uint8) *XMSSWallet {
	desc := NewQRLDescriptorFromExtendedSeed(extendedSeed)

	var seed [SeedSize]uint8
	copy(seed[:], extendedSeed[DescriptorSize:])

	return &XMSSWallet{
		seed: seed,
		desc: desc,
		xmss: xmss.InitializeTree(desc.height, desc.hashFunction, seed[:]),
	}
}

func NewWalletFromHeight(height xmss.Height, hashFunction xmss.HashFunction) *XMSSWallet {
	var seed [SeedSize]uint8
	_, err := rand.Read(seed[:])
	if err != nil {
		panic("Failed to generate random seed for XMSS address")
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

func (w *XMSSWallet) GetMnemonic() string {
	extendedSeed := w.GetExtendedSeed()
	mnemonic, err := misc2.BinToMnemonic(extendedSeed[:])
	if err != nil {
		panic(err)
	}
	return mnemonic
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

func (w *XMSSWallet) GetAddress() [AddressSize]uint8 {
	return GetXMSSAddressFromPK(w.GetPK())
}

func (w *XMSSWallet) GetIndex() uint32 {
	return w.xmss.GetIndex()
}

func (w *XMSSWallet) Sign(message []uint8) ([]uint8, error) {
	return w.xmss.Sign(message)
}

func Verify(message, signature []uint8, extendedPK [ExtendedPKSize]uint8) (result bool) {
	height := xmss.GetHeightFromSigSize(uint32(len(signature)), xmss.WOTSParamW)
	if !height.IsValid() {
		return false
	}

	desc := NewQRLDescriptorFromExtendedPK(&extendedPK)
	if desc.GetSignatureType() != legacywallet.WalletTypeXMSS {
		panic("invalid signature type")
	}

	if desc.GetHeight() != height {
		return false
	}

	pk := extendedPK[DescriptorSize:]

	return xmss.Verify(desc.hashFunction, message, signature, pk)
}
