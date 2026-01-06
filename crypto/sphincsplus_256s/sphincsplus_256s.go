package sphincsplus_256s

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
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
		return nil, fmt.Errorf(common.ErrSeedGenerationFailure, wallettype.SPHINCSPLUS_256S, err)
	}

	if err := cryptoSignKeypair(pk[:], sk[:], seed); err != nil {
		return nil, err
	}

	return &SphincsPlus256s{pk, sk, seed, generateOptrand}, nil
}

func NewSphincsPlus256sFromSeed(seed [CRYPTO_SEEDBYTES]uint8) (*SphincsPlus256s, error) {
	var sk [params.SPX_SK_BYTES]uint8
	var pk [params.SPX_PK_BYTES]uint8

	if err := cryptoSignKeypair(pk[:], sk[:], seed); err != nil {
		return nil, err
	}

	return &SphincsPlus256s{pk, sk, seed, generateOptrand}, nil
}

func NewSphincsPlus256sFromHexSeed(hexSeed string) (*SphincsPlus256s, error) {
	unsizedSeed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf(common.ErrDecodeHexSeed, wallettype.SPHINCSPLUS_256S, err.Error())
	}
	var seed [CRYPTO_SEEDBYTES]uint8
	copy(seed[:], unsizedSeed)
	return NewSphincsPlus256sFromSeed(seed)
}

// SetGenerateOptRand This function added to set generate opt rand to some mocked function for test
func (s *SphincsPlus256s) SetGenerateOptRand(generateOptRand func([]byte) error) {
	// Set mocked generateOptRand function
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

// Seal the message, returns signature attached with message.
func (s *SphincsPlus256s) Seal(message []uint8) ([]uint8, error) {
	return cryptoSign(message, s.sk[:], s.generateOptRand)
}

// Sign the message, and return a detached signature. Detached signatures are
// variable sized, but never larger than SIG_SIZE_PACKED.
func (s *SphincsPlus256s) Sign(message []uint8) ([params.SPX_BYTES]uint8, error) {
	var signature [params.SPX_BYTES]uint8

	sm, err := cryptoSign(message, s.sk[:], s.generateOptRand)
	if err == nil {
		copy(signature[:params.SPX_BYTES], sm[:params.SPX_BYTES])
	}
	return signature, err
}

// Open the sealed message m. Returns the original message sealed with signature.
// In case the signature is invalid, nil is returned.
func Open(signatureMessage []uint8, pk *[params.SPX_PK_BYTES]uint8) []uint8 {
	// Check for undersized input
	if len(signatureMessage) < params.SPX_BYTES {
		return nil
	}
	m := make([]uint8, len(signatureMessage)-params.SPX_BYTES)
	result := cryptoSignOpen(m, signatureMessage, pk[:])
	if !result {
		return nil
	}
	return m
}

func Verify(message []uint8, signature [params.SPX_BYTES]uint8, pk *[params.SPX_PK_BYTES]uint8) bool {
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
}
