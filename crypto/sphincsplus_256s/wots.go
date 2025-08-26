package sphincsplus_256s

import (
	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

// genChain performs the hash chain operation as in WOTS+
func GenChain(out, in []byte, start, steps uint, ctx *SPXCtx, addr *[8]uint32) {
	copy(out, in[:params.SPX_N])
	for i := start; i < start+steps && i < params.SPX_WOTS_W; i++ {
		setHashAddr(addr, uint32(i))
		tHash(out, out, 1, ctx, addr)
	}
}

// baseW interprets a byte array as integers in base w
func BaseW(output []uint8, outLen int, input []byte) {
	in := 0
	out := 0
	var total byte
	bits := 0

	for consumed := 0; consumed < outLen; consumed++ {
		if bits == 0 {
			total = input[in]
			in++
			bits += 8
		}
		bits -= params.SPX_WOTS_LOGW
		output[out] = uint8((total >> bits) & (params.SPX_WOTS_W - 1))
		out++
	}
}

// WotsChecksum computes the WOTS+ checksum over a base_w message
func WotsChecksum(csumBaseW []uint8, msgBaseW []uint8) {
	csum := uint(0)
	csumBytes := make([]byte, (params.SPX_WOTS_LEN2*params.SPX_WOTS_LOGW+7)/8)

	for i := 0; i < params.SPX_WOTS_LEN1; i++ {
		csum += params.SPX_WOTS_W - 1 - uint(msgBaseW[i])
	}
	csum = csum << ((8 - ((params.SPX_WOTS_LEN2 * params.SPX_WOTS_LOGW) % 8)) % 8)
	UllToBytes(csumBytes, len(csumBytes), uint64(csum))
	BaseW(csumBaseW, params.SPX_WOTS_LEN2, csumBytes)
}

// chainLengths derives WOTS+ chain lengths from a message
func chainLengths(lengths []uint8, msg []byte) {
	BaseW(lengths[:params.SPX_WOTS_LEN1], params.SPX_WOTS_LEN1, msg)
	WotsChecksum(lengths[params.SPX_WOTS_LEN1:], lengths[:params.SPX_WOTS_LEN1])
}

// WotsPKFromSig computes the WOTS public key from a signature and message
func WotsPKFromSig(pk, sig, msg []byte, ctx *SPXCtx, addr *[8]uint32) {
	var lengths [params.SPX_WOTS_LEN]uint8
	chainLengths(lengths[:], msg)

	for i := 0; i < params.SPX_WOTS_LEN; i++ {
		setChainAddr(addr, uint32(i))
		GenChain(pk[i*params.SPX_N:], sig[i*params.SPX_N:], uint(lengths[i]), uint(params.SPX_WOTS_W-1-lengths[i]), ctx, addr)
	}
}
