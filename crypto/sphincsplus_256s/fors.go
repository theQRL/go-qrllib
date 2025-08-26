package sphincsplus_256s

import (
	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

func forsGenSK(sk []byte, ctx *SPXCtx, forsLeafAddr *[8]uint32) {
	prfAddr(sk, ctx, forsLeafAddr)
}

func forsSKToLeaf(leaf []byte, sk []byte, ctx *SPXCtx, forsLeafAddr *[8]uint32) {
	tHash(leaf, sk, 1, ctx, forsLeafAddr)
}

type forsGenLeafInfo struct {
	LeafAddrX [8]uint32
}

func forsGenLeafX1(leaf []byte, ctx *SPXCtx, addrIdx uint32, info any) {
	forsInfo := info.(*forsGenLeafInfo)
	forsLeafAddr := &forsInfo.LeafAddrX

	// Only set parts the caller doesn't set
	setTreeIndex(forsLeafAddr, addrIdx)
	setType(forsLeafAddr, SPX_ADDR_TYPE_FORSPRF)

	forsGenSK(leaf, ctx, forsLeafAddr)

	setType(forsLeafAddr, SPX_ADDR_TYPE_FORSTREE)
	forsSKToLeaf(leaf, leaf, ctx, forsLeafAddr)
}

func messageToIndices(indices []uint32, m []byte) {
	offset := 0

	for i := 0; i < params.SPX_FORS_TREES; i++ {
		indices[i] = 0
		for j := 0; j < params.SPX_FORS_HEIGHT; j++ {
			bit := (m[offset>>3] >> (7 - (offset & 0x7))) & 1
			indices[i] ^= uint32(bit) << (params.SPX_FORS_HEIGHT - 1 - j)
			offset++
		}
	}
}

func forsSign(sig []byte, pk []byte, m []byte, ctx *SPXCtx, forsAddr *[8]uint32) {
	var indices [params.SPX_FORS_TREES]uint32
	roots := make([]byte, params.SPX_FORS_TREES*params.SPX_N)

	var forsTreeAddr [8]uint32
	var forsLeafInfo forsGenLeafInfo
	forsLeafAddr := &forsLeafInfo.LeafAddrX
	var forsPkAddr [8]uint32

	copyKeypairAddr(&forsTreeAddr, forsAddr)
	copyKeypairAddr(forsLeafAddr, forsAddr)

	copyKeypairAddr(&forsPkAddr, forsAddr)
	setType(&forsPkAddr, SPX_ADDR_TYPE_FORSPK)

	messageToIndices(indices[:], m)

	sigOffset := 0
	for i := 0; i < params.SPX_FORS_TREES; i++ {
		idxOffset := uint32(i) * (1 << params.SPX_FORS_HEIGHT)

		setTreeHeight(&forsTreeAddr, 0)
		setTreeIndex(&forsTreeAddr, indices[i]+idxOffset)
		setType(&forsTreeAddr, SPX_ADDR_TYPE_FORSPRF)

		// Generate secret key for this leaf
		forsGenSK(sig[sigOffset:], ctx, &forsTreeAddr)
		sigOffset += params.SPX_N

		// Compute auth path and root
		setType(&forsTreeAddr, SPX_ADDR_TYPE_FORSTREE)
		treeHashX1(
			roots[i*params.SPX_N:(i+1)*params.SPX_N],
			sig[sigOffset:],
			ctx,
			indices[i],
			idxOffset,
			params.SPX_FORS_HEIGHT,
			forsGenLeafX1,
			&forsTreeAddr,
			&forsLeafInfo,
		)

		sigOffset += params.SPX_N * params.SPX_FORS_HEIGHT
	}

	// Compute public key from all FORS roots
	tHash(pk, roots, params.SPX_FORS_TREES, ctx, &forsPkAddr)
}

func forsPKFromSig(
	pk []byte,
	sig []byte,
	m []byte,
	ctx *SPXCtx,
	forsAddr *[8]uint32,
) {
	var indices [params.SPX_FORS_TREES]uint32
	roots := make([]byte, params.SPX_FORS_TREES*params.SPX_N)
	leaf := make([]byte, params.SPX_N)

	var forsTreeAddr [8]uint32
	var forsPkAddr [8]uint32

	copyKeypairAddr(&forsTreeAddr, forsAddr)
	copyKeypairAddr(&forsPkAddr, forsAddr)

	setType(&forsTreeAddr, SPX_ADDR_TYPE_FORSTREE)
	setType(&forsPkAddr, SPX_ADDR_TYPE_FORSPK)

	messageToIndices(indices[:], m)

	sigOffset := 0
	for i := 0; i < params.SPX_FORS_TREES; i++ {
		idxOffset := uint32(i) * (1 << params.SPX_FORS_HEIGHT)

		setTreeHeight(&forsTreeAddr, 0)
		setTreeIndex(&forsTreeAddr, indices[i]+idxOffset)

		// Derive the leaf from the included secret key part
		forsSKToLeaf(leaf, sig[sigOffset:], ctx, &forsTreeAddr)
		sigOffset += params.SPX_N

		// Derive the root of this FORS tree
		computeRoot(
			roots[i*params.SPX_N:(i+1)*params.SPX_N],
			leaf,
			indices[i],
			idxOffset,
			sig[sigOffset:],
			params.SPX_FORS_HEIGHT,
			ctx,
			&forsTreeAddr,
		)
		sigOffset += params.SPX_N * params.SPX_FORS_HEIGHT
	}

	// Hash horizontally across all tree roots to derive the FORS public key
	tHash(pk, roots, params.SPX_FORS_TREES, ctx, &forsPkAddr)
}
