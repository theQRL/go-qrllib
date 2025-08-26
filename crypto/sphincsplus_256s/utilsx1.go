package sphincsplus_256s

import (
	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

func treeHashX1(
	root []byte,
	authPath []byte,
	ctx *SPXCtx,
	leafIdx uint32,
	idxOffset uint32,
	treeHeight uint32,
	genLeaf func(dest []byte, ctx *SPXCtx, idx uint32, info any),
	treeAddr *[8]uint32,
	info any,
) {
	stack := make([]byte, treeHeight*params.SPX_N)
	maxIdx := (uint32(1) << treeHeight) - 1

	for idx := uint32(0); ; idx++ {
		current := make([]byte, 2*params.SPX_N)

		// Generate leaf
		genLeaf(current[params.SPX_N:], ctx, idx+idxOffset, info)

		internalIdxOffset := idxOffset
		internalIdx := idx
		internalLeaf := leafIdx
		var h uint32

		for {
			if h == treeHeight {
				copy(root, current[params.SPX_N:])
				return
			}

			if (internalIdx ^ internalLeaf) == 1 {
				copy(authPath[h*params.SPX_N:], current[params.SPX_N:])
			}

			if (internalIdx&1) == 0 && idx < maxIdx {
				break
			}

			internalIdxOffset >>= 1
			setTreeHeight(treeAddr, h+1)
			setTreeIndex(treeAddr, internalIdx/2+internalIdxOffset)

			left := stack[h*params.SPX_N : (h+1)*params.SPX_N]
			copy(current[0:], left)

			tHash(current[params.SPX_N:], current, 2, ctx, treeAddr)

			h++
			internalIdx >>= 1
			internalLeaf >>= 1
		}
		copy(stack[h*params.SPX_N:], current[params.SPX_N:])
	}
}
