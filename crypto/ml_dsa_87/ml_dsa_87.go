// Package ml_dsa_87 implements the ML-DSA-87 digital signature algorithm
// as specified in FIPS 204 (Module-Lattice-Based Digital Signature Standard).
//
// # API Difference: Context Parameter
//
// Unlike other signature packages in go-qrllib (Dilithium, SPHINCS+, XMSS),
// ML-DSA-87 requires a context parameter (ctx) in Sign, Verify, Seal, and Open
// functions. This is mandated by FIPS 204 for domain separation.
//
// The context parameter:
//   - Is a byte slice of 0-255 bytes
//   - Is prepended to the message hash as [0x00, len(ctx), ...ctx]
//   - Enables domain separation between different applications
//   - QRL wallet uses ctx = ['Z', 'O', 'N', 'D'] for blockchain transactions
//
// Why other packages don't have context:
//   - Dilithium: Pre-FIPS version of the algorithm (no context in original spec)
//   - SPHINCS+: FIPS 205 hash-based signature (context not part of spec)
//   - XMSS: RFC 8391 hash-based signature (uses hash function selector instead)
//
// The wallet layer (wallet/ml_dsa_87) abstracts this by hardcoding the context,
// providing a consistent Sign(message) API to callers.
//
// # Thread Safety
//
// An MLDSA87 instance is safe for concurrent reads (GetPK, GetSK, GetSeed),
// but Sign and Seal should not be called concurrently on the same instance.
// The package-level Verify and Open functions are safe for concurrent use.
package ml_dsa_87

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
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
		//coverage:ignore
		//rationale: crypto/rand.Read only fails if system entropy source is broken
		return nil, fmt.Errorf(common.ErrSeedGenerationFailure, wallettype.ML_DSA_87, err)
	}

	if _, err := cryptoSignKeypair(&seed, &pk, &sk); err != nil {
		//coverage:ignore
		//rationale: cryptoSignKeypair only fails if sha3 operations fail, which never happens
		return nil, err
	}

	return &MLDSA87{pk, sk, seed, false}, nil
}

func NewMLDSA87FromSeed(seed [SEED_BYTES]uint8) (*MLDSA87, error) {
	var sk [CRYPTO_SECRET_KEY_BYTES]uint8
	var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8

	if _, err := cryptoSignKeypair(&seed, &pk, &sk); err != nil {
		//coverage:ignore
		//rationale: cryptoSignKeypair only fails if sha3 operations fail, which never happens
		return nil, err
	}

	return &MLDSA87{pk, sk, seed, false}, nil
}

func NewMLDSA87FromHexSeed(hexSeed string) (*MLDSA87, error) {
	if strings.HasPrefix(hexSeed, "0x") || strings.HasPrefix(hexSeed, "0X") {
		hexSeed = hexSeed[2:]
	}
	unsizedSeed, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf(common.ErrDecodeHexSeed, wallettype.ML_DSA_87, err.Error())
	}
	// The decoded seed is secret material; wipe the heap-allocated
	// intermediate buffer once we no longer need it. The fixed-size
	// stack array `seed` is also wiped after key derivation completes —
	// NewMLDSA87FromSeed copies it into the returned struct, so the
	// local copy is no longer needed after that call. Best-effort under
	// Go's memory model (see SECURITY.md and MLDSA87.Zeroize).
	// (TOB-QRLLIB-10)
	defer zeroBytes(unsizedSeed)

	if len(unsizedSeed) != SEED_BYTES {
		return nil, cryptoerrors.ErrInvalidSeed
	}
	var seed [SEED_BYTES]uint8
	defer zeroBytes(seed[:])

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

// Sign the message with the given context, and return a detached signature.
// The ctx parameter is required by FIPS 204 for domain separation (max 255 bytes).
// Detached signatures are variable sized, but never larger than SIG_SIZE_PACKED.
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

// Verify checks the signature against the message and public key with the given context.
// The ctx parameter must match the context used during signing (FIPS 204 requirement).
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

// Zeroize clears the secret-key and seed fields of the MLDSA87 instance.
// Call this when the instance is no longer needed.
//
// # Guarantee boundary (best-effort under Go's memory model)
//
// Zeroisation in this library is **best-effort**, not absolute. Go's
// runtime is free to copy values during garbage collection, escape
// analysis, slice growth, or interface boxing; any such copy that
// occurred before Zeroize executes is outside the library's control
// and remains in memory until that copy is itself overwritten or
// reclaimed. The package's [zeroBytes] helper uses [runtime.KeepAlive]
// to defeat dead-store elimination for the explicit overwrite, which
// addresses compiler-side erasure but not runtime-side duplication.
//
// What this means in practice:
//
//   - Calling Zeroize closes the obvious window where d.sk and d.seed
//     sit in process memory after the keypair has finished being used.
//     This is a useful defence-in-depth measure for short-lived signers
//     and against memory-disclosure bugs in the host process.
//   - It does NOT guarantee that no copy of the secret survives anywhere
//     in the address space. Workloads with adversaries that have
//     physical or kernel-level memory access (cold-boot, /proc/<pid>/mem,
//     hibernation images, swap files) need a hardware security module
//     for hard guarantees.
//
// See SECURITY.md ("Key Zeroization") for the full discussion.
func (d *MLDSA87) Zeroize() {
	zeroBytes(d.sk[:])
	zeroBytes(d.seed[:])
}
