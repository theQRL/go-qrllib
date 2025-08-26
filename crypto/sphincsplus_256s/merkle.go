package sphincsplus_256s

import (
	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

func MerkleSign(sig []byte, root []byte, ctx *SPXCtx, wotsAddr, treeAddr *[8]uint32, idxLeaf uint32) {
	authPath := sig[params.SPX_WOTS_BYTES:]

	var info LeafInfoX1
	var steps [params.SPX_WOTS_LEN]uint8

	info.WotsSig = sig
	chainLengths(steps[:], root)
	info.WotsSteps = steps[:]

	setType(treeAddr, SPX_ADDR_TYPE_HASHTREE)
	setType(&info.PkAddr, SPX_ADDR_TYPE_WOTSPK)
	copySubtreeAddr(&info.LeafAddr, wotsAddr)
	copySubtreeAddr(&info.PkAddr, wotsAddr)

	info.WotsSignLeaf = idxLeaf
	treeHashX1(root, authPath, ctx,
		idxLeaf, 0,
		params.SPX_TREE_HEIGHT,
		WotsGenLeafX1,
		treeAddr, &info)
}

func MerkleGenRoot(root []byte, ctx *SPXCtx) {
	authPath := make([]byte, params.SPX_TREE_HEIGHT*params.SPX_N+params.SPX_WOTS_BYTES)
	var topTreeAddr [8]uint32
	var wotsAddr [8]uint32

	setLayerAddr(&topTreeAddr, params.SPX_D-1)
	setLayerAddr(&wotsAddr, params.SPX_D-1)

	MerkleSign(authPath, root, ctx,
		&wotsAddr, &topTreeAddr,
		^uint32(0)) // ~0 in C is 0xFFFFFFFF
}
