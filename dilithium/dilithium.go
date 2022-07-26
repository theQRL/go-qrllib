package dilithium

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/theQRL/go-qrllib/common"
	"github.com/theQRL/go-qrllib/misc"
)

type Dilithium struct {
	pk   [PKSizePacked]uint8
	sk   [SKSizePacked]uint8
	seed [common.SeedSize]uint8
}

func New() *Dilithium {
	var sk [SKSizePacked]uint8
	var pk [PKSizePacked]uint8
	var seed [common.SeedSize]uint8

	_, err := rand.Read(seed[:])
	if err != nil {
		panic("Failed to generate random seed for Dilithium address")
	}

	var hashedSeed [32]uint8
	misc.SHAKE256(hashedSeed[:], seed[:])
	cryptoSignKeypair(hashedSeed[:], &pk, &sk)

	return &Dilithium{pk, sk, seed}
}

func NewDilithiumFromSeed(seed [common.SeedSize]uint8) *Dilithium {
	var sk [SKSizePacked]uint8
	var pk [PKSizePacked]uint8

	var hashedSeed [32]uint8
	misc.SHAKE256(hashedSeed[:], seed[:])
	cryptoSignKeypair(hashedSeed[:], &pk, &sk)
	return &Dilithium{pk, sk, seed}
}

//func NewFromKeys(pk *[PKSizePacked]uint8, sk *[SKSizePacked]uint8) *Dilithium {
//	return &Dilithium{*pk, *sk}
//}

func (d *Dilithium) GetPK() [PKSizePacked]uint8 {
	return d.pk
}

func (d *Dilithium) GetSK() [SKSizePacked]uint8 {
	return d.sk
}

func (d *Dilithium) GetSeed() [common.SeedSize]uint8 {
	return d.seed
}

func (d *Dilithium) GetHexSeed() string {
	seed := d.GetSeed()
	return hex.EncodeToString(seed[:])
}

func (d *Dilithium) GetMnemonic() string {
	return misc.SeedBinToMnemonic(d.GetSeed())
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

func (d *Dilithium) GetAddress() [common.AddressSize]uint8 {
	return GetDilithiumAddressFromPK(d.GetPK())
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

func GetDilithiumDescriptor() uint8 {
	/*
		In case of Dilithium address, it doesn't have any choice of hashFunction,
		height, addrFormatType. Thus keeping all those values to 0 and assigning
		only signatureType in the descriptor.
	*/
	return uint8(common.DilithiumSig) << 4
}

func GetDilithiumAddressFromPK(pk [PKSizePacked]uint8) [common.AddressSize]uint8 {
	var address [common.AddressSize]uint8
	descBytes := GetDilithiumDescriptor()
	address[0] = descBytes

	var hashedKey [32]uint8
	misc.SHAKE256(hashedKey[:], pk[:])

	copy(address[1:], hashedKey[len(hashedKey)-common.AddressSize+1:])

	return address
}

func IsValidDilithiumAddress(address [common.AddressSize]uint8) bool {
	d := GetDilithiumDescriptor()
	if address[0] != d {
		return false
	}

	// TODO: Add checksum
	return true
}
