package dilithium

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/theQRL/go-qrllib/common"
	"github.com/theQRL/go-qrllib/misc"
)

type Dilithium struct {
	pk                [CryptoPublicKeyBytes]uint8
	sk                [CryptoSecretKeyBytes]uint8
	seed              [common.SeedSize]uint8
	randomizedSigning bool
}

func New() *Dilithium {
	var sk [CryptoSecretKeyBytes]uint8
	var pk [CryptoPublicKeyBytes]uint8
	var seed [common.SeedSize]uint8

	_, err := rand.Read(seed[:])
	if err != nil {
		panic("Failed to generate random seed for Dilithium address")
	}

	var hashedSeed [32]uint8
	misc.SHAKE256(hashedSeed[:], seed[:])
	cryptoSignKeypair(hashedSeed[:], &pk, &sk)

	return &Dilithium{pk, sk, seed, false}
}

func NewDilithiumFromSeed(seed [common.SeedSize]uint8) *Dilithium {
	var sk [CryptoSecretKeyBytes]uint8
	var pk [CryptoPublicKeyBytes]uint8

	var hashedSeed [32]uint8
	misc.SHAKE256(hashedSeed[:], seed[:])
	cryptoSignKeypair(hashedSeed[:], &pk, &sk)

	return &Dilithium{pk, sk, seed, false}
}

//func NewFromKeys(pk *[CryptoPublicKeyBytes]uint8, sk *[CryptoSecretKeyBytes]uint8) *Dilithium {
//	return &Dilithium{*pk, *sk}
//}

func (d *Dilithium) GetPK() [CryptoPublicKeyBytes]uint8 {
	return d.pk
}

func (d *Dilithium) GetSK() [CryptoSecretKeyBytes]uint8 {
	return d.sk
}

func (d *Dilithium) GetSeed() [common.SeedSize]uint8 {
	return d.seed
}

func (d *Dilithium) GetHexSeed() string {
	seed := d.GetSeed()
	return "0x" + hex.EncodeToString(seed[:])
}

func (d *Dilithium) GetMnemonic() string {
	return misc.SeedBinToMnemonic(d.GetSeed())
}

// Seal the message, returns signature attached with message.
func (d *Dilithium) Seal(message []uint8) []uint8 {
	return cryptoSign(message, &d.sk, d.randomizedSigning)
}

// Sign the message, and return a detached signature. Detached signatures are
// variable sized, but never larger than SIG_SIZE_PACKED.
func (d *Dilithium) Sign(message []uint8) [CryptoBytes]uint8 {
	sm := cryptoSign(message, &d.sk, d.randomizedSigning)
	var signature [CryptoBytes]uint8
	copy(signature[:CryptoBytes], sm[:CryptoBytes])
	return signature
}

func (d *Dilithium) GetAddress() [common.AddressSize]uint8 {
	return GetDilithiumAddressFromPK(d.GetPK())
}

// Open the sealed message m. Returns the original message sealed with signature.
// In case the signature is invalid, nil is returned.
func Open(signatureMessage []uint8, pk *[CryptoPublicKeyBytes]uint8) []uint8 {
	return cryptoSignOpen(signatureMessage, pk)
}

func Verify(message []uint8, signature [CryptoBytes]uint8, pk *[CryptoPublicKeyBytes]uint8) bool {
	return cryptoSignVerify(signature, message, pk)
}

// ExtractMessage extracts message from Signature attached with message.
func ExtractMessage(signatureMessage []uint8) []uint8 {
	return signatureMessage[CryptoBytes:]
}

// ExtractSignature extracts signature from Signature attached with message.
func ExtractSignature(signatureMessage []uint8) []uint8 {
	return signatureMessage[:CryptoBytes]
}

func GetDilithiumDescriptor() uint8 {
	/*
		In case of Dilithium address, it doesn't have any choice of hashFunction,
		height, addrFormatType. Thus keeping all those values to 0 and assigning
		only signatureType in the descriptor.
	*/
	return uint8(common.DilithiumSig) << 4
}

func GetDilithiumAddressFromPK(pk [CryptoPublicKeyBytes]uint8) [common.AddressSize]uint8 {
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
