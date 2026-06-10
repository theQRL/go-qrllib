package sphincsplus_256s

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

type SphincsPlus256s struct {
	pk              [params.SPX_PK_BYTES]uint8
	sk              [params.SPX_SK_BYTES]uint8
	seed            [CRYPTO_SEEDBYTES]uint8
	generateOptRand func([]byte) error
}

func New() (*SphincsPlus256s, error) {
	var sk [params.SPX_SK_BYTES]uint8
	var pk [params.SPX_PK_BYTES]uint8
	var seed [CRYPTO_SEEDBYTES]uint8

	_, err := rand.Read(seed[:])
	if err != nil {
		//coverage:ignore
		//rationale: crypto/rand.Read only fails if system entropy source is broken
		return nil, cryptoerrors.ErrSeedGeneration
	}

	if err := cryptoSignKeypair(pk[:], sk[:], seed); err != nil {
		//coverage:ignore
		//rationale: cryptoSignKeypair only fails if buffers are wrong size, but we use fixed-size arrays
		return nil, err
	}

	return &SphincsPlus256s{pk, sk, seed, generateOptrand}, nil
}

func NewSphincsPlus256sFromSeed(seed [CRYPTO_SEEDBYTES]uint8) (*SphincsPlus256s, error) {
	var sk [params.SPX_SK_BYTES]uint8
	var pk [params.SPX_PK_BYTES]uint8

	if err := cryptoSignKeypair(pk[:], sk[:], seed); err != nil {
		//coverage:ignore
		//rationale: cryptoSignKeypair only fails if buffers are wrong size, but we use fixed-size arrays
		return nil, err
	}

	return &SphincsPlus256s{pk, sk, seed, generateOptrand}, nil
}

func NewSphincsPlus256sFromHexSeed(hexSeed string) (*SphincsPlus256s, error) {
	if strings.HasPrefix(hexSeed, "0x") || strings.HasPrefix(hexSeed, "0X") {
		hexSeed = hexSeed[2:]
	}
	unsizedSeed, err := hex.DecodeString(hexSeed)
	if err != nil {
		// hex.DecodeString's error echoes input characters; return the
		// sanitized sentinel instead.
		return nil, cryptoerrors.ErrInvalidHexSeed
	}
	if len(unsizedSeed) != CRYPTO_SEEDBYTES {
		return nil, cryptoerrors.ErrInvalidSeed
	}
	var seed [CRYPTO_SEEDBYTES]uint8
	copy(seed[:], unsizedSeed)
	return NewSphincsPlus256sFromSeed(seed)
}

// SetGenerateOptRand replaces the randomness generator used during signing.
// This is intended for testing only. Injecting a weak or constant generator
// removes fault-attack protection from SPHINCS+ signatures.
//
// Calling this outside a `go test` binary panics.
//
// WARNING: This method is NOT safe for concurrent use with Sign.
// The caller must ensure no signing operations are in progress.
func (s *SphincsPlus256s) SetGenerateOptRand(generateOptRand func([]byte) error) {
	if !testing.Testing() {
		//coverage:ignore
		//rationale: testing.Testing() is true in every go test binary, so this
		//branch is unreachable under test; it exists to panic on production misuse
		panic("sphincsplus_256s: SetGenerateOptRand is test-only and must not be called from production code")
	}
	s.generateOptRand = generateOptRand
}

func (s *SphincsPlus256s) GetPK() [params.SPX_PK_BYTES]uint8 {
	return s.pk
}

func (s *SphincsPlus256s) GetSK() [params.SPX_SK_BYTES]uint8 {
	return s.sk
}

func (s *SphincsPlus256s) GetSeed() [CRYPTO_SEEDBYTES]uint8 {
	return s.seed
}

func (s *SphincsPlus256s) GetHexSeed() string {
	seed := s.GetSeed()
	return "0x" + hex.EncodeToString(seed[:])
}

// SignAttached signs message and returns `signature || message` as a
// single attached-signature byte string.
//
// Use [SphincsPlus256s.Sign] (and [Verify]) for the *detached* form;
// SignAttached (and [Open]) is the attached-signature variant.
//
// SignAttached has no confidentiality property; the message bytes are
// embedded in the result in the clear. Renamed during
// TOB-QRLLIB-12 to remove the misleading AEAD-style connotation.
func (s *SphincsPlus256s) SignAttached(message []uint8) ([]uint8, error) {
	return cryptoSign(message, s.sk[:], s.generateOptRand)
}

// Sign the message, and return a detached signature. SPHINCS+-256s
// detached signatures are fixed-size: exactly params.SPX_BYTES (29,792) bytes.
func (s *SphincsPlus256s) Sign(message []uint8) ([params.SPX_BYTES]uint8, error) {
	var signature [params.SPX_BYTES]uint8

	sm, err := cryptoSign(message, s.sk[:], s.generateOptRand)
	if err == nil {
		copy(signature[:params.SPX_BYTES], sm[:params.SPX_BYTES])
	}
	return signature, err
}

// Open verifies an attached-signature byte string produced by
// [SphincsPlus256s.SignAttached] (i.e. `signature || message`) under
// pk and returns the recovered plaintext message on success.
//
// The returned message is the same bytes that were originally signed —
// it is *not* decrypted; this scheme has no confidentiality property,
// the message bytes were already in plaintext inside signatureMessage.
//
// Returns a typed error distinguishing each failure mode (TOB-QRLLIB-14):
//
//   - [cryptoerrors.ErrPublicKeyNil] if pk is nil
//   - [cryptoerrors.ErrInvalidSignatureSize] if signatureMessage is shorter than params.SPX_BYTES
//   - [cryptoerrors.ErrInvalidSignature] if the signature does not verify under pk
//
// On any error the returned message slice is nil.
func Open(signatureMessage []uint8, pk *[params.SPX_PK_BYTES]uint8) ([]uint8, error) {
	if pk == nil {
		return nil, cryptoerrors.ErrPublicKeyNil
	}
	if len(signatureMessage) < params.SPX_BYTES {
		return nil, cryptoerrors.ErrInvalidSignatureSize
	}
	m := make([]uint8, len(signatureMessage)-params.SPX_BYTES)
	if !cryptoSignOpen(m, signatureMessage, pk[:]) {
		return nil, cryptoerrors.ErrInvalidSignature
	}
	return m, nil
}

// Verify reports whether signature is a valid SPHINCS+ signature over
// message under pk. Returns false if pk is nil rather than panicking.
// (TOB-QRLLIB-11)
func Verify(message []uint8, signature [params.SPX_BYTES]uint8, pk *[params.SPX_PK_BYTES]uint8) bool {
	if pk == nil {
		return false
	}
	return cryptoSignVerify(signature[:], message, pk[:])
}

// ExtractMessage extracts message from Signature attached with message.
// Returns nil if the input is too short to contain a valid signature.
func ExtractMessage(signatureMessage []uint8) []uint8 {
	if len(signatureMessage) < params.SPX_BYTES {
		return nil
	}
	return signatureMessage[params.SPX_BYTES:]
}

// ExtractSignature extracts signature from Signature attached with message.
// Returns nil if the input is too short to contain a valid signature.
func ExtractSignature(signatureMessage []uint8) []uint8 {
	if len(signatureMessage) < params.SPX_BYTES {
		return nil
	}
	return signatureMessage[:params.SPX_BYTES]
}

// Zeroize clears sensitive key material from memory.
// This should be called when the SphincsPlus256s instance is no longer needed.
func (s *SphincsPlus256s) Zeroize() {
	for i := range s.sk {
		s.sk[i] = 0
	}
	for i := range s.seed {
		s.seed[i] = 0
	}
	s.generateOptRand = nil
}
