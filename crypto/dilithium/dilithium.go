package dilithium

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

type Dilithium struct {
	pk                [CryptoPublicKeyBytes]uint8
	sk                [CryptoSecretKeyBytes]uint8
	seed              [SeedBytes]uint8
	randomizedSigning bool
}

func New() (*Dilithium, error) {
	var sk [CryptoSecretKeyBytes]uint8
	var pk [CryptoPublicKeyBytes]uint8
	var seed [SeedBytes]uint8

	_, err := rand.Read(seed[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate random seed for Dilithium address: %v", err)
	}

	if _, err := cryptoSignKeypair(&seed, &pk, &sk); err != nil {
		return nil, err
	}

	return &Dilithium{pk, sk, seed, false}, nil
}

func NewDilithiumFromSeed(seed [SeedBytes]uint8) (*Dilithium, error) {
	var sk [CryptoSecretKeyBytes]uint8
	var pk [CryptoPublicKeyBytes]uint8

	if _, err := cryptoSignKeypair(&seed, &pk, &sk); err != nil {
		return nil, err
	}

	return &Dilithium{pk, sk, seed, false}, nil
}

func NewDilithiumFromHexSeed(hexSeed string) (*Dilithium, error) {
	unsizedSeed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hexseed to bin %v", err.Error())
	}
	var seed [SeedBytes]uint8
	copy(seed[:], unsizedSeed)
	return NewDilithiumFromSeed(seed)
}

func (d *Dilithium) GetPK() [CryptoPublicKeyBytes]uint8 {
	return d.pk
}

func (d *Dilithium) GetSK() [CryptoSecretKeyBytes]uint8 {
	return d.sk
}

func (d *Dilithium) GetSeed() [SeedBytes]uint8 {
	return d.seed
}

func (d *Dilithium) GetHexSeed() string {
	seed := d.GetSeed()
	return "0x" + hex.EncodeToString(seed[:])
}

// Seal the message, returns signature attached with message.
func (d *Dilithium) Seal(ctx, message []uint8) ([]uint8, error) {
	return cryptoSign(message, ctx, &d.sk, d.randomizedSigning)
}

// Sign the message, and return a detached signature. Detached signatures are
// variable sized, but never larger than SIG_SIZE_PACKED.
func (d *Dilithium) Sign(ctx, message []uint8) ([CryptoBytes]uint8, error) {
	var signature [CryptoBytes]uint8

	sm, err := cryptoSign(message, ctx, &d.sk, d.randomizedSigning)
	if err == nil {
		copy(signature[:CryptoBytes], sm[:CryptoBytes])
	}
	return signature, err
}

// Open the sealed message m. Returns the original message sealed with signature.
// In case the signature is invalid, nil is returned.
func Open(ctx, signatureMessage []uint8, pk *[CryptoPublicKeyBytes]uint8) []uint8 {
	msg, _ := cryptoSignOpen(signatureMessage, ctx, pk)
	return msg
}

func Verify(ctx, message []uint8, signature [CryptoBytes]uint8, pk *[CryptoPublicKeyBytes]uint8) bool {
	result, err := cryptoSignVerify(signature, message, ctx, pk)
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
