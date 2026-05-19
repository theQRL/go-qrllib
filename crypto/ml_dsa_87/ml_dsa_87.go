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
// # Signing Mode (Hedged by Default)
//
// Public ML-DSA-87 signing — [MLDSA87.Sign], [MLDSA87.SignAttached],
// the `wallet/ml_dsa_87` Sign wrapper, and the [crypto.Signer]-style
// [CryptoSigner.Sign] — is **always hedged** per FIPS 204 §3.4 (the
// recommended mode). Each call mixes fresh `crypto/rand` randomness
// into the per-signature `RND_BYTES` value, so two calls with the
// same `(key, ctx, message)` produce **distinct** signatures, both of
// which verify under the same public key. Verification is unchanged
// and existing verifiers — on-chain or off — are unaffected.
//
// FIPS-204-deterministic signing is available for callers that need
// it (RANDAO-style verifiable beacon contributions, test-vector
// reproduction) via two equivalent paths:
//
//   - [MLDSA87.SignDeterministic] — thin convenience helper that
//     signs with `rnd = 32 zero bytes`. Recommended entry point when
//     the deterministic property is itself a protocol requirement.
//   - [CryptoSigner.Sign] with an `io.Reader` that returns
//     deterministic bytes (e.g. `bytes.NewReader(make([]byte, 32))`).
//     Useful when integrating with code that already uses Go's
//     `crypto.Signer` interface and expects to drive randomness via
//     the `rand` parameter.
//
// Both paths route into the same internal entry point and produce
// byte-identical signatures for byte-identical input. Default-hedged
// signing remains the recommended mode for general-purpose use; the
// deterministic helpers exist as documented opt-in escape hatches
// rather than as alternatives to be picked casually. See SECURITY.md
// for the full discussion (TOB-QRLLIB-6).
//
// [crypto.Signer.Sign] also honours its `rand io.Reader` parameter:
// when non-nil, its bytes drive `RND_BYTES`; when nil, `crypto/rand`
// is used.
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

// MLDSA87 holds an ML-DSA-87 keypair. Signing is **always hedged**
// (per FIPS 204 §3.4 — the recommended mode); the previous
// `randomizedSigning bool` field was removed in TOB-QRLLIB-6 alongside
// the dead deterministic-default path. Callers needing
// FIPS-204-deterministic signing for test-vector reproduction
// (ACVP / KAT) call the unexported [cryptoSignSignatureWithRnd] with
// rnd=zero directly.
type MLDSA87 struct {
	pk   [CRYPTO_PUBLIC_KEY_BYTES]uint8
	sk   [CRYPTO_SECRET_KEY_BYTES]uint8
	seed [SEED_BYTES]uint8
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

	return &MLDSA87{pk, sk, seed}, nil
}

func NewMLDSA87FromSeed(seed [SEED_BYTES]uint8) (*MLDSA87, error) {
	var sk [CRYPTO_SECRET_KEY_BYTES]uint8
	var pk [CRYPTO_PUBLIC_KEY_BYTES]uint8

	if _, err := cryptoSignKeypair(&seed, &pk, &sk); err != nil {
		//coverage:ignore
		//rationale: cryptoSignKeypair only fails if sha3 operations fail, which never happens
		return nil, err
	}

	return &MLDSA87{pk, sk, seed}, nil
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

// SignAttached signs message with the FIPS 204 context ctx and returns
// `signature || message` as a single attached-signature byte string.
//
// Use [MLDSA87.Sign] (and [Verify]) for the *detached* form, where the
// signature and message are kept as separate values; use SignAttached
// (and [Open]) when a single self-contained byte string is convenient
// — for example when storing or transmitting a signed message over a
// channel that does not have a place for a side-channel signature.
//
// SignAttached has no confidentiality property; the message bytes are
// embedded in the result in the clear. Renamed from Seal in
// TOB-QRLLIB-12 to remove the misleading AEAD-style connotation.
//
// Signing is hedged (FIPS 204 §3.4): the per-signature RND_BYTES are
// drawn from crypto/rand, so two SignAttached calls with the same
// (ctx, message) under the same key produce distinct signatures, both
// of which verify under the same public key. (TOB-QRLLIB-6.)
func (d *MLDSA87) SignAttached(ctx, message []uint8) ([]uint8, error) {
	return cryptoSign(message, ctx, &d.sk)
}

// Sign the message with the given context, and return a detached signature.
// The ctx parameter is required by FIPS 204 for domain separation (max 255 bytes).
// Detached signatures are variable sized, but never larger than SIG_SIZE_PACKED.
//
// Signing is hedged (FIPS 204 §3.4): the per-signature RND_BYTES are
// drawn from crypto/rand, so two Sign calls with the same
// (ctx, message) under the same key produce distinct signatures, both
// of which verify under the same public key. (TOB-QRLLIB-6.)
func (d *MLDSA87) Sign(ctx, message []uint8) ([CRYPTO_BYTES]uint8, error) {
	var signature [CRYPTO_BYTES]uint8

	sm, err := cryptoSign(message, ctx, &d.sk)
	if err == nil {
		copy(signature[:CRYPTO_BYTES], sm[:CRYPTO_BYTES])
	}
	return signature, err
}

// SignDeterministic produces an ML-DSA-87 signature using the FIPS 204
// §3.5 deterministic mode (per-signature RND_BYTES = 32 zero bytes).
// Two SignDeterministic calls with the same (key, ctx, message) produce
// byte-identical signatures.
//
// **Use this only when the deterministic property is itself a security
// or protocol requirement** — for example, RANDAO-style verifiable
// beacon contributions where each validator must produce the same
// signature for the same input, or test-vector reproduction. For all
// other use cases (general-purpose signing, blockchain transactions,
// signed messages, document signing) prefer [MLDSA87.Sign], which is
// hedged by default per FIPS 204 §3.4 and provides additional
// resistance to side-channel and fault-injection attacks (TOB-QRLLIB-6).
//
// Verification does not depend on signing mode: a signature produced
// by SignDeterministic verifies under [Verify] / [Open] with the same
// public key, just as a hedged signature does.
//
// Equivalent to calling [crypto.Signer.Sign] (via [NewCryptoSigner])
// with an [io.Reader] that returns 32 zero bytes; this method is the
// thin convenience wrapper for callers that don't need the
// crypto.Signer plumbing.
func (d *MLDSA87) SignDeterministic(ctx, message []uint8) ([CRYPTO_BYTES]uint8, error) {
	var signature [CRYPTO_BYTES]uint8
	var rnd [RND_BYTES]uint8 // zero — FIPS 204 §3.5 deterministic mode
	if err := cryptoSignSignatureWithRnd(signature[:], message, ctx, &d.sk, rnd); err != nil {
		return signature, err
	}
	return signature, nil
}

// Open verifies an attached-signature byte string produced by
// [MLDSA87.SignAttached] (i.e. `signature || message`) under pk and the
// FIPS 204 context ctx, and returns the recovered plaintext message on
// success.
//
// The returned message is the same bytes that were originally signed —
// it is *not* decrypted; this scheme has no confidentiality property,
// the message bytes were already in plaintext inside signatureMessage.
//
// Returns a typed error distinguishing each failure mode (TOB-QRLLIB-14):
//
//   - [cryptoerrors.ErrPublicKeyNil] if pk is nil
//   - [cryptoerrors.ErrInvalidContext] if len(ctx) > 255
//   - [cryptoerrors.ErrInvalidSignatureSize] if signatureMessage is shorter than CRYPTO_BYTES
//   - [cryptoerrors.ErrInvalidSignature] if the signature does not verify under pk
//
// On any error the returned message slice is nil. Callers that don't
// need to distinguish failure modes can use `msg, _ := Open(...)` and
// check `msg != nil`.
func Open(ctx, signatureMessage []uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) ([]uint8, error) {
	if pk == nil {
		return nil, cryptoerrors.ErrPublicKeyNil
	}
	return cryptoSignOpen(signatureMessage, ctx, pk)
}

// Verify checks the signature against the message and public key with the given context.
// The ctx parameter must match the context used during signing (FIPS 204 requirement).
// Returns false if pk is nil rather than panicking. (TOB-QRLLIB-11)
func Verify(ctx, message []uint8, signature [CRYPTO_BYTES]uint8, pk *[CRYPTO_PUBLIC_KEY_BYTES]uint8) bool {
	if pk == nil {
		return false
	}
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
