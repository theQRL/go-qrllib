package dilithium

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
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
		//coverage:ignore
		//rationale: crypto/rand.Read only fails if system entropy source is broken
		return nil, cryptoerrors.ErrSeedGeneration
	}

	var hashedSeed [32]uint8
	misc.SHAKE256(hashedSeed[:], seed[:])
	if _, err := cryptoSignKeypair(hashedSeed[:], &pk, &sk); err != nil {
		//coverage:ignore
		//rationale: cryptoSignKeypair only fails if sha3 operations fail, which never happens
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
		//coverage:ignore
		//rationale: cryptoSignKeypair only fails if sha3 operations fail, which never happens
		return nil, err
	}

	return &Dilithium{pk, sk, seed, false}, nil
}

func NewDilithiumFromHexSeed(hexSeed string) (*Dilithium, error) {
	if strings.HasPrefix(hexSeed, "0x") || strings.HasPrefix(hexSeed, "0X") {
		hexSeed = hexSeed[2:]
	}
	unsizedSeed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, cryptoerrors.ErrInvalidHexSeed
	}
	if len(unsizedSeed) != SEED_BYTES {
		return nil, cryptoerrors.ErrInvalidSeed
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

// SignAttached signs message and returns `signature || message` as a
// single attached-signature byte string.
//
// Use [Dilithium.Sign] (and [Verify]) for the *detached* form;
// SignAttached (and [Open]) is the attached-signature variant.
//
// SignAttached has no confidentiality property; the message bytes are
// embedded in the result in the clear. Renamed during
// TOB-QRLLIB-12 to remove the misleading AEAD-style connotation.
func (d *Dilithium) SignAttached(message []uint8) ([]uint8, error) {
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

// Open verifies an attached-signature byte string produced by
// [Dilithium.SignAttached] (i.e. `signature || message`) under pk and
// returns the recovered plaintext message on success.
//
// The returned message is the same bytes that were originally signed —
// it is *not* decrypted; this scheme has no confidentiality property,
// the message bytes were already in plaintext inside signatureMessage.
//
// Returns a typed error distinguishing each failure mode (TOB-QRLLIB-14):
//
//   - [cryptoerrors.ErrPublicKeyNil] if pk is nil
//   - [cryptoerrors.ErrInvalidSignatureSize] if signatureMessage is shorter than CRYPTO_BYTES
//   - [cryptoerrors.ErrInvalidSignature] if the signature does not verify under pk
//
// On any error the returned message slice is nil.
func Open(signatureMessage []uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) ([]uint8, error) {
	if pk == nil {
		return nil, cryptoerrors.ErrPublicKeyNil
	}
	return cryptoSignOpen(signatureMessage, pk)
}

// Verify reports whether signature is a valid Dilithium signature over
// message under pk. Returns false if pk is nil rather than panicking.
// (TOB-QRLLIB-11)
func Verify(message []uint8, signature [CRYPTO_BYTES]uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) bool {
	if pk == nil {
		return false
	}
	result, err := cryptoSignVerify(signature, message, pk)
	if err != nil {
		//coverage:ignore
		//rationale: cryptoSignVerify only returns error from sha3 operations, which never fail
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
		return signature, cryptoerrors.ErrSecretKeyNil
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
		return signature, cryptoerrors.ErrSecretKeyZeroized
	}

	// Use cryptoSignSignature directly with the provided secret key
	// randomizedSigning is set to false (deterministic signing)
	err := cryptoSignSignature(signature[:], message, sk, false)
	if err != nil {
		//coverage:ignore
		//rationale: cryptoSignSignature only fails if sha3 operations fail, which never happens
		return signature, err
	}

	return signature, nil
}
