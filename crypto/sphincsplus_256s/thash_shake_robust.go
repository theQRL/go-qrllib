package sphincsplus_256s

import (
	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

func tHash(out, in []byte, inBlocks uint, ctx *SPXCtx, addr *[8]uint32) {
	bufLen := params.SPX_N + params.SPX_ADDR_BYTES + int(inBlocks)*params.SPX_N
	buf := make([]byte, bufLen)
	bitmask := make([]byte, int(inBlocks)*params.SPX_N)

	// Copy pub_seed to buf
	copy(buf[:params.SPX_N], ctx.PubSeed[:])

	// Copy addr as bytes into buf[SPX_N:SPX_N+SPX_ADDR_BYTES]
	memcpy(buf[params.SPX_N:params.SPX_N+params.SPX_ADDR_BYTES], addr)

	// Compute bitmask using SHAKE256(pub_seed || addr)
	Shake256(bitmask, buf[:params.SPX_N+params.SPX_ADDR_BYTES])

	// XOR input with bitmask and place it into buf
	for i := 0; i < len(bitmask); i++ {
		buf[params.SPX_N+params.SPX_ADDR_BYTES+i] = in[i] ^ bitmask[i]
	}

	// Final SHAKE256 to get output
	Shake256(out, buf)
}
