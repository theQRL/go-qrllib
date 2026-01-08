package xmss

import (
	"errors"
	"fmt"

	"github.com/theQRL/go-qrllib/common"
	"github.com/theQRL/go-qrllib/crypto/xmss"
	"github.com/theQRL/go-qrllib/legacywallet"
)

// ErrInvalidDescriptorSize is returned when descriptor bytes have wrong length.
var ErrInvalidDescriptorSize = errors.New("invalid descriptor size: expected 3 bytes")

type QRLDescriptor struct {
	hashFunction   xmss.HashFunction
	signatureType  legacywallet.WalletType // Signature Type = XMSS = 0
	height         xmss.Height
	addrFormatType common.AddrFormatType
}

func NewQRLDescriptor(height xmss.Height, hashFunction xmss.HashFunction, signatureType legacywallet.WalletType, addrFormatType common.AddrFormatType) *QRLDescriptor {
	return &QRLDescriptor{
		hashFunction:   hashFunction,
		signatureType:  signatureType,
		height:         height,
		addrFormatType: addrFormatType,
	}
}

func NewQRLDescriptorFromExtendedSeed(extendedSeed [ExtendedSeedSize]uint8) (*QRLDescriptor, error) {
	return NewQRLDescriptorFromBytes(extendedSeed[:DescriptorSize])
}

func NewQRLDescriptorFromExtendedPK(extendedPK *[ExtendedPKSize]uint8) (*QRLDescriptor, error) {
	return NewQRLDescriptorFromBytes(extendedPK[:DescriptorSize])
}

func LegacyQRLDescriptorFromExtendedPK(extendedPK *[ExtendedPKSize]uint8) (*QRLDescriptor, error) {
	return LegacyQRLDescriptorFromBytes(extendedPK[:DescriptorSize])
}

func NewQRLDescriptorFromBytes(descriptorBytes []uint8) (*QRLDescriptor, error) {
	if len(descriptorBytes) != 3 {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidDescriptorSize, len(descriptorBytes))
	}

	hashFunction, err := xmss.ToHashFunction(descriptorBytes[0] & 0x0f)
	if err != nil {
		return nil, fmt.Errorf("invalid hash function in descriptor: %w", err)
	}

	height, err := xmss.ToHeight((descriptorBytes[1] & 0x0f) << 1)
	if err != nil {
		return nil, fmt.Errorf("invalid height in descriptor: %w", err)
	}

	signatureType, err := legacywallet.ToWalletType((descriptorBytes[0] >> 4) & 0x0F)
	if err != nil {
		return nil, fmt.Errorf("invalid signature type in descriptor: %w", err)
	}

	return &QRLDescriptor{
		hashFunction:   hashFunction,
		signatureType:  signatureType,
		height:         height,
		addrFormatType: common.AddrFormatType((descriptorBytes[1] & 0xF0) >> 4),
	}, nil
}

func LegacyQRLDescriptorFromBytes(descriptorBytes []uint8) (*QRLDescriptor, error) {
	if len(descriptorBytes) != 3 {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidDescriptorSize, len(descriptorBytes))
	}

	hashFunction, err := xmss.ToHashFunction(descriptorBytes[0] & 0x0f)
	if err != nil {
		return nil, fmt.Errorf("invalid hash function in descriptor: %w", err)
	}

	height, err := xmss.ToHeight((descriptorBytes[1] & 0x0f) << 1)
	if err != nil {
		return nil, fmt.Errorf("invalid height in descriptor: %w", err)
	}

	signatureType, err := legacywallet.ToWalletType((descriptorBytes[0] >> 4) & 0x0F)
	if err != nil {
		return nil, fmt.Errorf("invalid signature type in descriptor: %w", err)
	}

	return &QRLDescriptor{
		hashFunction:   hashFunction,
		signatureType:  signatureType,
		height:         height,
		addrFormatType: common.AddrFormatType((descriptorBytes[1] & 0xF0) >> 4),
	}, nil
}

func (d *QRLDescriptor) GetHeight() xmss.Height {
	return d.height
}

func (d *QRLDescriptor) GetHashFunction() xmss.HashFunction {
	return d.hashFunction
}

func (d *QRLDescriptor) GetSignatureType() legacywallet.WalletType {
	return d.signatureType
}

func (d *QRLDescriptor) GetAddrFormatType() common.AddrFormatType {
	return d.addrFormatType
}

func (d *QRLDescriptor) GetBytes() [DescriptorSize]uint8 {
	var output [DescriptorSize]uint8
	output[0] = (uint8(d.signatureType) << 4) | (uint8(d.hashFunction) & 0x0F)
	output[1] = (uint8(d.addrFormatType) << 4) | (uint8(d.height>>1) & 0x0F)

	return output
}
