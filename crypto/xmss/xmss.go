package xmss

import "fmt"

type XMSS struct {
	xmssParams   *XMSSParams
	hashFunction HashFunction
	height       uint8
	seed         []uint8
	sk           []uint8

	bdsState *BDSState
}

func InitializeTree(h Height, hashFunction HashFunction, seed []uint8) *XMSS {
	height := uint32(h)
	sk := make([]uint8, 132)
	pk := make([]uint8, 64)

	k := WOTSParamK
	w := WOTSParamW
	n := WOTSParamN

	if k >= height || (height-k)%2 == 1 {
		panic("For BDS traversal, H - K must be even, with H > K >= 2!")
	}

	xmssParams := NewXMSSParams(n, height, w, k)
	bdsState := NewBDSState(height, n, k)

	XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed)
	return &XMSS{
		xmssParams,
		hashFunction,
		uint8(height),
		seed,
		sk,
		bdsState,
	}
}

func (x *XMSS) GetSeed() []uint8 {
	return x.seed
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
	return ToHeight(x.height)
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
		return nil, fmt.Errorf("XMSS Sign: cannot set index %v err: %v", index, err)
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

	// Pre-validate the computed height before calling GetHeightFromSigSize
	// Height must be valid: even, >= 2, <= MaxHeight
	computedHeight := (sigSize - signatureBaseSize) / 32
	if computedHeight < 2 || computedHeight > MaxHeight || computedHeight%2 != 0 {
		return false
	}

	height := GetHeightFromSigSize(sigSize, wotsParamW)
	if !height.IsValid() {
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
