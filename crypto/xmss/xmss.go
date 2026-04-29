package xmss

import (
	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

type XMSS struct {
	xmssParams   *XMSSParams
	hashFunction HashFunction
	height       uint8
	seed         []uint8
	sk           []uint8

	bdsState *BDSState
}

// InitializeTree creates a new XMSS tree with the specified parameters,
// using QRL's pre-standardisation seed-derivation convention: the
// 48-byte caller-supplied seed is expanded via SHAKE256 into the 96
// bytes of randomness (SK_SEED || SK_PRF || PUB_SEED) the construction
// requires. This is the only path that produces QRL v1-mainnet
// addresses.
//
// Returns an error if the hashFunction is not one of the recognised
// values, if the height is outside the valid range (even values between
// 2 and MaxHeight), or if the height/k parameters are invalid for BDS
// traversal.
//
// Callers that need RFC 8391 reference-implementation interop —
// where the 96 bytes are supplied directly without QRL's SHAKE256
// expansion step — should use [InitializeTreeFromExpandedSeed] or the
// [github.com/theQRL/go-qrllib/crypto/xmss/rfc8391] sub-package.
//
// XMSS is a stateful scheme: each call to Sign increments an internal index
// that MUST be persisted to durable storage before the signature is used.
// Reusing an index completely breaks the security of the scheme. See the
// package documentation for safe usage patterns and recovery procedures.
func InitializeTree(h Height, hashFunction HashFunction, seed []uint8) (*XMSS, error) {
	// Validate the caller's HashFunction at the API boundary. A caller
	// may construct an out-of-range HashFunction via a raw cast (e.g.
	// xmss.HashFunction(99)) which bypasses ToHashFunction's validation;
	// without this guard the coreHash switch falls through and leaves
	// the output buffer zero-initialised, producing a degenerate
	// zero-rooted XMSS whose signatures would cross-verify with any
	// other invalid-hash-function key derived from a different seed.
	// This is the primary fix for TOB-QRLLIB-13.
	if !hashFunction.IsValid() {
		return nil, cryptoerrors.ErrInvalidHashFunction
	}

	// Validate the caller's Height at the API boundary. A caller may
	// construct an out-of-range Height via a raw cast (e.g. xmss.Height(32))
	// which bypasses the ToHeight/UInt32ToHeight validators; catching it
	// here ensures we never attempt to derive a key from an invalid height
	// and surfaces a deterministic error instead of silently producing a
	// zero-rooted XMSS at signing time. (TOB-QRLLIB-2)
	if !h.IsValid() {
		return nil, cryptoerrors.ErrInvalidHeight
	}

	height := uint32(h)
	sk := make([]uint8, 132)
	pk := make([]uint8, 64)

	k := WOTSParamK
	w := WOTSParamW
	n := WOTSParamN

	// BDS traversal requires height > k. Height.IsValid() accepts h=2 in line
	// with the documented even-heights-in-[2,MaxHeight] contract, but the
	// current WOTS parameters (k=2) mean h=2 cannot form a valid BDS state.
	// The (height-k)%2 branch is unreachable under IsValid (even h minus
	// even k is always even) but is retained as defense-in-depth against a
	// future WOTS-parameter change.
	if k >= height || (height-k)%2 == 1 {
		return nil, cryptoerrors.ErrInvalidBDSParams
	}

	xmssParams := NewXMSSParams(n, height, w, k)
	bdsState := NewBDSState(height, n, k)

	if err := XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed); err != nil {
		//coverage:ignore
		//rationale: XMSSFastGenKeyPair only fails for odd heights, but BDS check above ensures heights are even
		return nil, cryptoerrors.ErrKeyGeneration
	}

	// Post-construction invariant (TOB-QRLLIB-13): the Merkle root must
	// be non-zero for any well-formed key. A zero root is the signature
	// of the degenerate state described in the audit (invalid hash
	// dispatch left buffers zeroed). The hashFunction.IsValid() guard
	// above already prevents that path, but this defence-in-depth check
	// catches any *other* future regression in the key-derivation
	// pipeline that produces an unconstructed root.
	rootStart := offsetRoot
	rootEnd := rootStart + 32
	allZero := true
	for i := rootStart; i < rootEnd; i++ {
		if sk[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		//coverage:ignore
		//rationale: tripwire only — upstream HashFunction.IsValid() and Height.IsValid()
		//guards prevent the degenerate-root path; this would only fire if a future
		//edit silently re-introduced the bug.
		return nil, cryptoerrors.ErrKeyGeneration
	}

	return &XMSS{
		xmssParams,
		hashFunction,
		uint8(height),
		seed,
		sk,
		bdsState,
	}, nil
}

// InitializeTreeFromExpandedSeed creates a new XMSS tree from 96 bytes
// of pre-expanded seed material, in the layout RFC 8391's reference
// implementation consumes directly: SK_SEED || SK_PRF || PUB_SEED.
//
// This is the entry point used by the
// [github.com/theQRL/go-qrllib/crypto/xmss/rfc8391] sub-package to
// achieve bit-for-bit cross-implementation interop with the reference
// XMSS implementation. It bypasses the QRL-specific 48-byte
// SHAKE256-expansion step that [InitializeTree] performs; everything
// downstream (Merkle tree construction, signing, verification) is
// identical between the two paths.
//
// For QRL wallet code, use [InitializeTree] instead — the QRL
// SHAKE256 expansion is the only path that produces v1-mainnet
// addresses, so any wallet recovery code MUST use that.
//
// Validation and post-construction invariants mirror [InitializeTree]
// exactly (HashFunction.IsValid, Height.IsValid, BDS-params check,
// non-zero-root invariant).
func InitializeTreeFromExpandedSeed(h Height, hashFunction HashFunction, expandedSeed *[96]uint8) (*XMSS, error) {
	if expandedSeed == nil {
		return nil, cryptoerrors.ErrInvalidSeed
	}
	if !hashFunction.IsValid() {
		return nil, cryptoerrors.ErrInvalidHashFunction
	}
	if !h.IsValid() {
		return nil, cryptoerrors.ErrInvalidHeight
	}

	height := uint32(h)
	sk := make([]uint8, 132)
	pk := make([]uint8, 64)

	k := WOTSParamK
	w := WOTSParamW
	n := WOTSParamN

	if k >= height || (height-k)%2 == 1 {
		return nil, cryptoerrors.ErrInvalidBDSParams
	}

	xmssParams := NewXMSSParams(n, height, w, k)
	bdsState := NewBDSState(height, n, k)

	if err := XMSSFastGenKeyPairFromExpandedSeed(hashFunction, xmssParams, pk, sk, bdsState, expandedSeed); err != nil {
		//coverage:ignore
		//rationale: validation above already covers every error path the
		//inner function returns; this would only fire if a future edit
		//introduced a new error case.
		return nil, cryptoerrors.ErrKeyGeneration
	}

	rootStart := offsetRoot
	rootEnd := rootStart + 32
	allZero := true
	for i := rootStart; i < rootEnd; i++ {
		if sk[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		//coverage:ignore
		//rationale: same tripwire as InitializeTree's; upstream guards
		//prevent the degenerate-root path.
		return nil, cryptoerrors.ErrKeyGeneration
	}

	// We retain the 96 bytes the caller passed in so that GetSeed()
	// returns something meaningful for diagnostic / logging use. The
	// value is not used as input to any subsequent crypto operation
	// (the relevant material has already been packed into sk).
	storedSeed := make([]uint8, 96)
	copy(storedSeed, expandedSeed[:])

	return &XMSS{
		xmssParams,
		hashFunction,
		uint8(height),
		storedSeed,
		sk,
		bdsState,
	}, nil
}

func (x *XMSS) GetSeed() []uint8 {
	result := make([]uint8, len(x.seed))
	copy(result, x.seed)
	return result
}

func (x *XMSS) GetSK() []uint8 {
	result := make([]uint8, len(x.sk))
	copy(result, x.sk)
	return result
}

func (x *XMSS) GetPKSeed() []uint8 {
	result := make([]uint8, 32)
	copy(result, x.sk[offsetPubSeed:offsetPubSeed+32])
	return result
}

func (x *XMSS) GetRoot() []uint8 {
	result := make([]uint8, 32)
	copy(result, x.sk[offsetRoot:offsetRoot+32])
	return result
}

func (x *XMSS) GetHashFunction() HashFunction {
	return x.hashFunction
}

func (x *XMSS) GetHeight() Height {
	// Height is validated at construction time, so this should never fail.
	// We use the value directly since it was stored from a valid Height.
	return Height(x.height)
}

func (x *XMSS) GetIndex() uint32 {
	return (uint32(x.sk[0]) << 24) + (uint32(x.sk[1]) << 16) + (uint32(x.sk[2]) << 8) + uint32(x.sk[3])
}

func (x *XMSS) SetIndex(newIndex uint32) error {
	return xmssFastUpdate(x.hashFunction, x.xmssParams, x.sk, x.bdsState, newIndex)
}

// Sign generates a signature for message and advances the one-time index.
// The caller MUST persist the updated index (via GetIndex) to durable storage
// before using the returned signature. See the package documentation for details.
func (x *XMSS) Sign(message []uint8) ([]uint8, error) {
	index := x.GetIndex()
	if err := x.SetIndex(index); err != nil {
		return nil, cryptoerrors.ErrSigningFailed
	}

	return xmssFastSignMessage(x.hashFunction, x.xmssParams, x.sk, x.bdsState, message)
}

// Zeroize clears sensitive key material from memory.
// This should be called when the XMSS instance is no longer needed.
func (x *XMSS) Zeroize() {
	for i := range x.sk {
		x.sk[i] = 0
	}
	for i := range x.seed {
		x.seed[i] = 0
	}
	if x.bdsState != nil {
		for i := range x.bdsState.stack {
			x.bdsState.stack[i] = 0
		}
		for i := range x.bdsState.auth {
			x.bdsState.auth[i] = 0
		}
		for i := range x.bdsState.keep {
			x.bdsState.keep[i] = 0
		}
		for i := range x.bdsState.retain {
			x.bdsState.retain[i] = 0
		}
		for _, th := range x.bdsState.treeHash {
			for i := range th.node {
				th.node[i] = 0
			}
		}
	}
}

func Verify(hashFunction HashFunction, message, signature []uint8, pk []uint8) (result bool) {
	return VerifyWithCustomWOTSParamW(hashFunction, message, signature, pk, WOTSParamW)
}

func VerifyWithCustomWOTSParamW(hashFunction HashFunction, message, signature []uint8, pk []uint8, wotsParamW uint32) (result bool) {
	// Validate wotsParamW before calling NewWOTSParams to avoid panic on unsupported values.
	// Valid WOTS w values are powers of 2 where log2(w) ∈ {2, 4, 8}.
	switch wotsParamW {
	case 4, 16, 256:
		// valid
	default:
		return false
	}
	wotsParam := NewWOTSParams(WOTSParamN, wotsParamW)
	signatureBaseSize := calculateSignatureBaseSize(wotsParam.keySize)

	sigSize := uint32(len(signature))

	// Check for undersized signatures
	if sigSize < signatureBaseSize {
		return false
	}

	// Check signature size alignment (must be 4 + n*32 for some n)
	if (sigSize-4)%32 != 0 {
		return false
	}

	// Check for oversized signatures
	if sigSize > signatureBaseSize+uint32(MaxHeight)*32 {
		return false
	}

	// Get height from signature size - returns error for invalid sizes
	height, err := GetHeightFromSigSize(sigSize, wotsParamW)
	if err != nil {
		return false
	}

	k := WOTSParamK
	w := wotsParamW
	n := WOTSParamN

	if k >= height.ToUInt32() || (height.ToUInt32()-k)%2 == 1 {
		// Invalid BDS traversal parameters - return false instead of panicking
		return false
	}

	params := NewXMSSParams(n, height.ToUInt32(), w, k)

	return verifySig(hashFunction,
		params.wotsParams,
		message,
		signature,
		pk,
		height.ToUInt32())
}
