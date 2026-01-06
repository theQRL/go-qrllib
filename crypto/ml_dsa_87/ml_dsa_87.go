package ml_dsa_87

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

type MLDSA87 struct {
	pk                [CRYPTO_PUBLIC_KEY_BYTES]uint8
	sk                [CRYPTO_SECRET_KEY_BYTES]uint8
	seed              [SEED_BYTES]uint8
	randomizedSigning bool
}

func New() (*MLDSA87, error) {
	var sk [CRYPTO_SECRET_KEY_BYTES]uint8
	var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8
	var seed [SEED_BYTES]uint8

	_, err := rand.Read(seed[:])
	if err != nil {
		return nil, fmt.Errorf(common.ErrSeedGenerationFailure, wallettype.ML_DSA_87, err)
	}

	if _, err := cryptoSignKeypair(&seed, &pk, &sk); err != nil {
		return nil, err
	}

	return &MLDSA87{pk, sk, seed, false}, nil
}

func NewMLDSA87FromSeed(seed [SEED_BYTES]uint8) (*MLDSA87, error) {
	var sk [CRYPTO_SECRET_KEY_BYTES]uint8
	var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8

	if _, err := cryptoSignKeypair(&seed, &pk, &sk); err != nil {
		return nil, err
	}

	return &MLDSA87{pk, sk, seed, false}, nil
}

func NewMLDSA87FromHexSeed(hexSeed string) (*MLDSA87, error) {
	unsizedSeed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf(common.ErrDecodeHexSeed, wallettype.ML_DSA_87, err.Error())
	}
	var seed [SEED_BYTES]uint8
	copy(seed[:], unsizedSeed)
	return NewMLDSA87FromSeed(seed)
}

func (d *MLDSA87) GetPK() [CRYPTO_PUBLIC_KEY_BYTES]uint8 {
	return d.pk
}

func (d *MLDSA87) GetSK() [CRYPTO_SECRET_KEY_BYTES]uint8 {
	return d.sk
}

func (d *MLDSA87) GetSeed() [SEED_BYTES]uint8 {
	return d.seed
}

func (d *MLDSA87) GetHexSeed() string {
	seed := d.GetSeed()
	return "0x" + hex.EncodeToString(seed[:])
}

// Seal the message, returns signature attached with message.
func (d *MLDSA87) Seal(ctx, message []uint8) ([]uint8, error) {
	return cryptoSign(message, ctx, &d.sk, d.randomizedSigning)
}

// Sign the message, and return a detached signature. Detached signatures are
// variable sized, but never larger than SIG_SIZE_PACKED.
func (d *MLDSA87) Sign(ctx, message []uint8) ([CRYPTO_BYTES]uint8, error) {
	var signature [CRYPTO_BYTES]uint8

	sm, err := cryptoSign(message, ctx, &d.sk, d.randomizedSigning)
	if err == nil {
		copy(signature[:CRYPTO_BYTES], sm[:CRYPTO_BYTES])
	}
	return signature, err
}

// Open the sealed message m. Returns the original message sealed with signature.
// In case the signature is invalid, nil is returned.
func Open(ctx, signatureMessage []uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) []uint8 {
	msg, _ := cryptoSignOpen(signatureMessage, ctx, pk)
	return msg
}

func Verify(ctx, message []uint8, signature [CRYPTO_BYTES]uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) bool {
	result, err := cryptoSignVerify(signature, message, ctx, pk)
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
// This should be called when the MLDSA87 instance is no longer needed.
func (d *MLDSA87) Zeroize() {
	for i := range d.sk {
		d.sk[i] = 0
	}
	for i := range d.seed {
		d.seed[i] = 0
	}
}
