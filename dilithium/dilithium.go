package dilithium

import (
	"github.com/theQRL/go-qrllib/common"
	"github.com/theQRL/go-qrllib/misc"
)

type Dilithium struct {
	pk [PKSizePacked]uint8
	sk [SKSizePacked]uint8
}

func New() *Dilithium {
	var sk [SKSizePacked]uint8
	var pk [PKSizePacked]uint8
	cryptoSignKeypair(nil, &pk, &sk)
	return &Dilithium{pk, sk}
}

func NewFromKeys(pk *[PKSizePacked]uint8, sk *[SKSizePacked]uint8) *Dilithium {
	return &Dilithium{*pk, *sk}
}

func (d *Dilithium) GetPK() [PKSizePacked]uint8 {
	return d.pk
}

func (d *Dilithium) GetSK() [SKSizePacked]uint8 {
	return d.sk
}

// Seal the message, returns signature attached with message.
func (d *Dilithium) Seal(message []uint8) []uint8 {
	return cryptoSign(message, &d.sk)
}

// Sign the message, and return a detached signature. Detached signatures are
// variable sized, but never larger than SIG_SIZE_PACKED.
func (d *Dilithium) Sign(message []uint8) []uint8 {
	var sig [SigSizePacked]byte
	return cryptoSignDetached(&sig, message, &d.sk)
}

// Open the sealed message m. Returns the original message sealed with signature.
// In case the signature is invalid, nil is returned.
func Open(signatureMessage []uint8, pk *[PKSizePacked]uint8) []uint8 {
	return cryptoSignOpen(signatureMessage, pk)
}

func Verify(message []uint8, signature []uint8, pk *[PKSizePacked]uint8) bool {
	return cryptoVerifyDetached(signature, message, pk)
}

// ExtractMessage extracts message from Signature attached with message.
func ExtractMessage(signatureMessage []uint8) []uint8 {
	return signatureMessage[SigSizePacked:]
}

// ExtractSignature extracts signature from Signature attached with message.
func ExtractSignature(signatureMessage []uint8) []uint8 {
	return signatureMessage[:SigSizePacked]
}

func GetDilithiumDescriptor() [common.DescriptorSize]uint8 {
	/*
		In case of Dilithium address, it doesn't have any choice of hashFunction,
		height. Thus keeping all those values to 0 and assigning only signatureType
		in the descriptor and the addrFormatType as we are using SHA256_2X to hash
		the pk for the address computation.
	*/
	var desc [common.DescriptorSize]uint8
	desc[0] = uint8(common.DilithiumSig) << 4
	desc[1] = uint8(common.SHA256_2X) << 4
	return desc
}

func GetDilithiumAddressFromPK(pk [PKSizePacked]uint8) [common.AddressSize]uint8 {
	var address [common.AddressSize]uint8
	descBytes := GetDilithiumDescriptor()
	copy(address[:common.DescriptorSize], descBytes[:common.DescriptorSize])

	var hashedKey [32]uint8
	misc.SHAKE256(hashedKey[:], pk[:])

	copy(address[common.DescriptorSize:], hashedKey[len(hashedKey)-common.AddressSize+common.DescriptorSize:])

	return address
}
