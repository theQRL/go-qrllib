package sphincsplus_256s

import (
	"crypto/subtle"

	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

func cryptoSignVerify(sig, m, pk []byte) bool {
	if len(sig) != params.SPX_BYTES {
		return false
	}
	pubRoot := pk[params.SPX_N:]
	var mHash [params.SPX_FORS_MSG_BYTES]byte
	var wotsPK [params.SPX_WOTS_BYTES]byte
	var root [params.SPX_N]byte
	var leaf [params.SPX_N]byte

	var tree uint64
	var idxLeaf uint32
	var wotsAddr [8]uint32
	var treeAddr [8]uint32
	var wotsPKAddr [8]uint32
	ctx := &SPXCtx{}
	copy(ctx.PubSeed[:params.SPX_N], pk[:params.SPX_N])

	initializeHashFunction(ctx)

	setType(&wotsAddr, SPX_ADDR_TYPE_WOTS)
	setType(&treeAddr, SPX_ADDR_TYPE_HASHTREE)
	setType(&wotsPKAddr, SPX_ADDR_TYPE_WOTSPK)

	hashMessage(mHash[:], &tree, &idxLeaf, sig, pk, m, ctx)
	sig = sig[params.SPX_N:]

	setTreeAddr(&wotsAddr, tree)
	setKeypairAddr(&wotsAddr, idxLeaf)

	forsPKFromSig(root[:], sig, mHash[:], ctx, &wotsAddr)
	sig = sig[params.SPX_FORS_BYTES:]

	for i := uint32(0); i < SPX_D; i++ {
		setLayerAddr(&treeAddr, i)
		setTreeAddr(&treeAddr, tree)

		copySubtreeAddr(&wotsAddr, &treeAddr)
		setKeypairAddr(&wotsAddr, idxLeaf)

		copyKeypairAddr(&wotsPKAddr, &wotsAddr)

		WotsPKFromSig(wotsPK[:], sig, root[:], ctx, &wotsAddr)
		sig = sig[params.SPX_WOTS_BYTES:]

		tHash(leaf[:], wotsPK[:], params.SPX_WOTS_LEN, ctx, &wotsPKAddr)

		computeRoot(root[:], leaf[:], idxLeaf, 0, sig, params.SPX_TREE_HEIGHT, ctx, &treeAddr)
		sig = sig[params.SPX_TREE_HEIGHT*params.SPX_N:]

		idxLeaf = uint32(tree & ((1 << params.SPX_TREE_HEIGHT) - 1))
		tree = tree >> params.SPX_TREE_HEIGHT
	}

	return subtle.ConstantTimeCompare(root[:params.SPX_N], pubRoot[:params.SPX_N]) == 1
}

func cryptoSignOpen(m, sm, pk []byte) bool {
	if len(sm) < params.SPX_BYTES {
		return false
	}

	if !cryptoSignVerify(sm[:params.SPX_BYTES], sm[params.SPX_BYTES:], pk) {
		return false
	}

	copy(m, sm[params.SPX_BYTES:])

	return true
}
