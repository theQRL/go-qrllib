package sphincsplus_256s

import "github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"

func UllToBytes(out []byte, outLen int, in uint64) {
	for i := outLen - 1; i >= 0; i-- {
		out[i] = byte(in & 0xff)
		in >>= 8
	}
}

func U32ToBytes(out []byte, in uint32) {
	out[0] = byte(in >> 24)
	out[1] = byte(in >> 16)
	out[2] = byte(in >> 8)
	out[3] = byte(in)
}

func BytesToUll(in []byte, inLen int) uint64 {
	var out uint64
	for i := 0; i < inLen; i++ {
		out |= uint64(in[i]) << (8 * (inLen - 1 - i))
	}
	return out
}

func Uint32SliceToBytes(in []uint32) []byte {
	out := make([]byte, 4*len(in))
	for i, val := range in {
		outIdx := i * 4
		out[outIdx] = byte(val >> 24)
		out[outIdx+1] = byte(val >> 16)
		out[outIdx+2] = byte(val >> 8)
		out[outIdx+3] = byte(val)
	}
	return out
}

func computeRoot(root, leaf []byte, leafIdx, idxOffset uint32,
	authPath []byte, treeHeight uint32,
	ctx *SPXCtx, addr *[8]uint32) {

	buffer := make([]byte, 2*params.SPX_N)

	if leafIdx&1 == 1 {
		copy(buffer[params.SPX_N:], leaf)
		copy(buffer, authPath[:params.SPX_N])
	} else {
		copy(buffer, leaf)
		copy(buffer[params.SPX_N:], authPath[:params.SPX_N])
	}
	authPath = authPath[params.SPX_N:]

	for i := uint32(0); i < treeHeight-1; i++ {
		leafIdx >>= 1
		idxOffset >>= 1

		setTreeHeight(addr, i+1)
		setTreeIndex(addr, leafIdx+idxOffset)

		if leafIdx&1 == 1 {
			tHash(buffer[params.SPX_N:], buffer, 2, ctx, addr)
			copy(buffer, authPath[:params.SPX_N])
		} else {
			tHash(buffer, buffer, 2, ctx, addr)
			copy(buffer[params.SPX_N:], authPath[:params.SPX_N])
		}
		authPath = authPath[params.SPX_N:]
	}

	leafIdx >>= 1
	idxOffset >>= 1
	setTreeHeight(addr, treeHeight)
	setTreeIndex(addr, leafIdx+idxOffset)

	tHash(root, buffer, 2, ctx, addr)
}

