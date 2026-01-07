package dilithium

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/theQRL/go-qrllib/misc"
)

type Dilithium struct {
	pk                [CRYPTO_PUBLIC_KEY_BYTES]uint8
	sk                [CRYPTO_SECRET_KEY_BYTES]uint8
	seed              [SEED_BYTES]uint8
	randomizedSigning bool
}

func New() (*Dilithium, error) {
	var sk [CRYPTO_SECRET_KEY_BYTES]uint8
	var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
	var seed [SEED_BYTES]uint8

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

func NewDilithiumFromSeed(seed [SEED_BYTES]uint8) (*Dilithium, error) {
	var sk [CRYPTO_SECRET_KEY_BYTES]uint8
	var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8

	var hashedSeed [32]uint8
	misc.SHAKE256(hashedSeed[:], seed[:])
	if _, err := cryptoSignKeypair(hashedSeed[:], &pk, &sk); err != nil {
		return nil, err
	}

	return &Dilithium{pk, sk, seed, false}, nil
}

func NewDilithiumFromHexSeed(hexSeed string) (*Dilithium, error) {
	unsizedSeed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex seed: %w", err)
	}
	if len(unsizedSeed) != SEED_BYTES {
		return nil, fmt.Errorf("invalid seed length: expected %d bytes, got %d", SEED_BYTES, len(unsizedSeed))
	}
	var seed [SEED_BYTES]uint8
	copy(seed[:], unsizedSeed)
	return NewDilithiumFromSeed(seed)
}

func (d *Dilithium) GetPK() [CRYPTO_PUBLIC_KEY_BYTES]uint8 {
	return d.pk
}

func (d *Dilithium) GetSK() [CRYPTO_SECRET_KEY_BYTES]uint8 {
	return d.sk
}

func (d *Dilithium) GetSeed() [SEED_BYTES]uint8 {
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
func (d *Dilithium) Sign(message []uint8) ([CRYPTO_BYTES]uint8, error) {
	var signature [CRYPTO_BYTES]uint8

	sm, err := cryptoSign(message, &d.sk, d.randomizedSigning)
	if err == nil {
		copy(signature[:CRYPTO_BYTES], sm[:CRYPTO_BYTES])
	}
	return signature, err
}

// Open the sealed message m. Returns the original message sealed with signature.
// In case the signature is invalid, nil is returned.
func Open(signatureMessage []uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) []uint8 {
	msg, _ := cryptoSignOpen(signatureMessage, pk)
	return msg
}

func Verify(message []uint8, signature [CRYPTO_BYTES]uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) bool {
	result, err := cryptoSignVerify(signature, message, pk)
	if err != nil {
		return false
	}
	return result
}

// ExtractMessage extracts message from Signature attached with message.
// Returns nil if the input is too short to contain a valid signature.
func ExtractMessage(signatureMessage []uint8) []uint8 {
	if len(signatureMessage) < CRYPTO_BYTES {
		return nil
	}
	return signatureMessage[CRYPTO_BYTES:]
}

// ExtractSignature extracts signature from Signature attached with message.
// Returns nil if the input is too short to contain a valid signature.
func ExtractSignature(signatureMessage []uint8) []uint8 {
	if len(signatureMessage) < CRYPTO_BYTES {
		return nil
	}
	return signatureMessage[:CRYPTO_BYTES]
}

// Zeroize clears sensitive key material from memory.
// This should be called when the Dilithium instance is no longer needed.
func (d *Dilithium) Zeroize() {
	for i := range d.sk {
		d.sk[i] = 0
	}
	for i := range d.seed {
		d.seed[i] = 0
	}
}

// SignWithSecretKey signs a message using a secret key directly.
// This is a package-level function similar to Verify, allowing signing
// without needing a Dilithium instance.
//
// Security considerations:
//   - Uses deterministic signing (not randomized). The same message and key
//     will always produce the same signature.
//   - The caller is responsible for ensuring the secret key was properly
//     derived using NewDilithiumFromSeed or similar secure key generation.
//   - No validation is performed on the secret key structure; an invalid
//     key will produce invalid signatures that fail verification.
//   - This function is safe to call concurrently from multiple goroutines
//     with the same or different keys.
//
// Returns an error if sk is nil.
func SignWithSecretKey(message []uint8, sk *[CRYPTO_SECRET_KEY_BYTES]uint8) ([CRYPTO_BYTES]uint8, error) {
	var signature [CRYPTO_BYTES]uint8

	if sk == nil {
		return signature, fmt.Errorf("secret key cannot be nil")
	}

	// Check for zeroized or uninitialized key
	isZero := true
	for _, b := range sk {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		return signature, fmt.Errorf("secret key is zero (uninitialized or zeroized)")
	}

	// Use cryptoSignSignature directly with the provided secret key
	// randomizedSigning is set to false (deterministic signing)
	err := cryptoSignSignature(signature[:], message, sk, false)
	if err != nil {
		return signature, err
	}

	return signature, nil
}
