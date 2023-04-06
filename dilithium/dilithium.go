package dilithium

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/theQRL/go-qrllib/common"
	"github.com/theQRL/go-qrllib/misc"
)

type Dilithium struct {
	pk                [CryptoPublicKeyBytes]uint8
	sk                [CryptoSecretKeyBytes]uint8
	seed              [common.SeedSize]uint8
	randomizedSigning bool
}

func New() (*Dilithium, error) {
	var sk [CryptoSecretKeyBytes]uint8
	var pk [CryptoPublicKeyBytes]uint8
	var seed [common.SeedSize]uint8

	_, err := rand.Read(seed[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate random seed for Dilithium address: %v", err)
	}

	var hashedSeed [32]uint8
	misc.SHAKE256(hashedSeed[:], seed[:])
	if _, err := cryptoSignKeypair(hashedSeed[:], &pk, &sk); err != nil {
		return nil, err
	}

	return &Dilithium{pk, sk, seed, false}, nil
}

func NewDilithiumFromSeed(seed [common.SeedSize]uint8) (*Dilithium, error) {
	var sk [CryptoSecretKeyBytes]uint8
	var pk [CryptoPublicKeyBytes]uint8

	var hashedSeed [32]uint8
	misc.SHAKE256(hashedSeed[:], seed[:])
	if _, err := cryptoSignKeypair(hashedSeed[:], &pk, &sk); err != nil {
		return nil, err
	}

	return &Dilithium{pk, sk, seed, false}, nil
}

func NewDilithiumFromMnemonic(mnemonic string) (*Dilithium, error) {
	seed := misc.MnemonicToSeedBin(mnemonic)
	return NewDilithiumFromSeed(seed)
}

func NewDilithiumFromHexSeed(hexSeed string) (*Dilithium, error) {
	seed, err := hex.DecodeString(hexSeed)
	if err != nil {
		panic("Failed to decode hexseed to bin")
	}
	if len(seed) != common.SeedSize {
		panic("Seed is not equal to SeedSize")
	}
	var binSeed [common.SeedSize]uint8
	copy(binSeed[:], seed[:common.SeedSize])
	return NewDilithiumFromSeed(binSeed)
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
func (d *Dilithium) Seal(message []uint8) ([]uint8, error) {
	return cryptoSign(message, &d.sk, d.randomizedSigning)
}

// Sign the message, and return a detached signature. Detached signatures are
// variable sized, but never larger than SIG_SIZE_PACKED.
func (d *Dilithium) Sign(message []uint8) ([CryptoBytes]uint8, error) {
	var signature [CryptoBytes]uint8

	sm, err := cryptoSign(message, &d.sk, d.randomizedSigning)
	if err == nil {
		copy(signature[:CryptoBytes], sm[:CryptoBytes])
	}
	return signature, err
}

func (d *Dilithium) GetAddress() [common.AddressSize]uint8 {
	return GetDilithiumAddressFromPK(d.GetPK())
}

// Open the sealed message m. Returns the original message sealed with signature.
// In case the signature is invalid, nil is returned.
func Open(signatureMessage []uint8, pk *[CryptoPublicKeyBytes]uint8) []uint8 {
	msg, _ := cryptoSignOpen(signatureMessage, pk)
	return msg
}

func Verify(message []uint8, signature [CryptoBytes]uint8, pk *[CryptoPublicKeyBytes]uint8) bool {
	result, err := cryptoSignVerify(signature, message, pk)
	if err != nil {
		return false
	}
	return result
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
