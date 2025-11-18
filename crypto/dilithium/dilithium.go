package dilithium

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/theQRL/go-qrllib/misc"
)

type Dilithium struct {
	pk                [CryptoPublicKeyBytes]uint8
	sk                [CryptoSecretKeyBytes]uint8
	seed              []uint8
	randomizedSigning bool
}

func New() (*Dilithium, error) {
	var sk [CryptoSecretKeyBytes]uint8
	var pk [CryptoPublicKeyBytes]uint8
	var seed []uint8

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

func NewDilithiumFromSeed(seed []uint8) (*Dilithium, error) {
	var sk [CryptoSecretKeyBytes]uint8
	var pk [CryptoPublicKeyBytes]uint8

	var hashedSeed [32]uint8
	misc.SHAKE256(hashedSeed[:], seed[:])
	if _, err := cryptoSignKeypair(hashedSeed[:], &pk, &sk); err != nil {
		return nil, err
	}

	return &Dilithium{pk, sk, seed, false}, nil
}

func NewDilithiumFromHexSeed(hexSeed string) (*Dilithium, error) {
	seed, err := hex.DecodeString(hexSeed)
	if err != nil {
		panic("Failed to decode hexseed to bin")
	}
	return NewDilithiumFromSeed(seed)
}

func (d *Dilithium) GetPK() [CryptoPublicKeyBytes]uint8 {
	return d.pk
}

func (d *Dilithium) GetSK() [CryptoSecretKeyBytes]uint8 {
	return d.sk
}

func (d *Dilithium) GetSeed() []uint8 {
	return d.seed
}

func (d *Dilithium) GetHexSeed() string {
	seed := d.GetSeed()
	return "0x" + hex.EncodeToString(seed[:])
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

// SignWithSecretKey signs a message using a secret key directly.
// This is a package-level function similar to Verify, allowing signing
// without needing a Dilithium instance.
func SignWithSecretKey(message []uint8, sk *[CryptoSecretKeyBytes]uint8) ([CryptoBytes]uint8, error) {
	var signature [CryptoBytes]uint8

	// Use cryptoSignSignature directly with the provided secret key
	// randomizedSigning is set to false (deterministic signing)
	err := cryptoSignSignature(signature[:], message, sk, false)
	if err != nil {
		return signature, err
	}

	return signature, nil
}
