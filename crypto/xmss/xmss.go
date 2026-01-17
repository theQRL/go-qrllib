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

// InitializeTree creates a new XMSS tree with the specified parameters.
// Returns an error if the height/k parameters are invalid for BDS traversal.
func InitializeTree(h Height, hashFunction HashFunction, seed []uint8) (*XMSS, error) {
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

	if err := XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed); err != nil {
		//coverage:ignore
		//rationale: XMSSFastGenKeyPair only fails for odd heights, but BDS check above ensures heights are even
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

func (x *XMSS) GetSeed() []uint8 {
	result := make([]uint8, len(x.seed))
	copy(result, x.seed)
	return result
}

func (x *XMSS) GetSK() []uint8 {
	return x.sk
}

func (x *XMSS) GetPKSeed() []uint8 {
	return x.sk[offsetPubSeed : offsetPubSeed+32]
}

func (x *XMSS) GetRoot() []uint8 {
	return x.sk[offsetRoot : offsetRoot+32]
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
}

func Verify(hashFunction HashFunction, message, signature []uint8, pk []uint8) (result bool) {
	return VerifyWithCustomWOTSParamW(hashFunction, message, signature, pk, WOTSParamW)
}

func VerifyWithCustomWOTSParamW(hashFunction HashFunction, message, signature []uint8, pk []uint8, wotsParamW uint32) (result bool) {
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
