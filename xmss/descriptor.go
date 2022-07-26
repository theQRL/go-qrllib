package xmss

import "github.com/theQRL/go-qrllib/common"

type QRLDescriptor struct {
	hashFunction   HashFunction
	signatureType  common.SignatureType // Signature Type = XMSS = 0
	height         uint8
	addrFormatType common.AddrFormatType
}

func NewQRLDescriptor(height uint8, hashFunction HashFunction, signatureType common.SignatureType, addrFormatType common.AddrFormatType) *QRLDescriptor {
	return &QRLDescriptor{
		hashFunction:   hashFunction,
		signatureType:  signatureType,
		height:         height,
		addrFormatType: addrFormatType,
	}
}

func NewQRLDescriptorFromExtendedSeed(extendedSeed [common.ExtendedSeedSize]uint8) *QRLDescriptor {
	return NewQRLDescriptorFromBytes(extendedSeed[:common.DescriptorSize])
}

func NewQRLDescriptorFromExtendedPK(extendedPK *[ExtendedPKSize]uint8) *QRLDescriptor {
	return NewQRLDescriptorFromBytes(extendedPK[:common.DescriptorSize])
}

func NewQRLDescriptorFromBytes(descriptorBytes []uint8) *QRLDescriptor {
	if len(descriptorBytes) != 3 {
		panic("Descriptor size should be 3 bytes")
	}

	return &QRLDescriptor{
		hashFunction:   HashFunction(descriptorBytes[0] & 0x0f),
		signatureType:  common.SignatureType((descriptorBytes[0] >> 4) & 0x0f),
		height:         (descriptorBytes[1] & 0x0f) << 1,
		addrFormatType: common.AddrFormatType((descriptorBytes[1] & 0xF0) >> 4),
	}
}

func (d *QRLDescriptor) GetHeight() uint8 {
	return d.height
}

func (d *QRLDescriptor) GetHashFunction() HashFunction {
	return d.hashFunction
}

func (d *QRLDescriptor) GetSignatureType() common.SignatureType {
	return d.signatureType
}

func (d *QRLDescriptor) GetAddrFormatType() common.AddrFormatType {
	return d.addrFormatType
}

func (d *QRLDescriptor) GetBytes() [common.DescriptorSize]uint8 {
	var output [common.DescriptorSize]uint8
	output[0] = (uint8(d.signatureType) << 4) | (uint8(d.hashFunction) & 0x0F)
	output[1] = (uint8(d.addrFormatType) << 4) | ((d.height >> 1) & 0x0F)

	return output
}
