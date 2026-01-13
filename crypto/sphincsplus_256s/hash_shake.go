package sphincsplus_256s

import (
	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
	"golang.org/x/crypto/sha3"
)

var (
	SPX_TREE_BITS  = params.SPX_TREE_HEIGHT * (params.SPX_D - 1)
	SPX_TREE_BYTES = (SPX_TREE_BITS + 7) / 8
	SPX_LEAF_BITS  = params.SPX_TREE_HEIGHT
	SPX_LEAF_BYTES = (SPX_LEAF_BITS + 7) / 8
	SPX_DGST_BYTES = params.SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES
)

// initializeHashFunction is a no-op for SHAKE256
//coverage:ignore
//rationale: empty function body has no statements to test
func initializeHashFunction(ctx *SPXCtx) {
	//coverage:ignore
	//rationale: empty function body, no-op as in C reference
}

// prfAddr computes PRF(pub_seed, addr, sk_seed) using SHAKE256
func prfAddr(out []byte, ctx *SPXCtx, addr *[8]uint32) {
	buf := make([]byte, 2*params.SPX_N+params.SPX_ADDR_BYTES)
	copy(buf[:params.SPX_N], ctx.PubSeed[:])
	addrBytes := addrToBytes(addr)
	copy(buf[params.SPX_N:], addrBytes[:])
	copy(buf[params.SPX_N+params.SPX_ADDR_BYTES:], ctx.SkSeed[:])

	shake := sha3.NewShake256()
	if _, err := shake.Write(buf); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		panic("shake write failed: " + err.Error())
	}

	if _, err := shake.Read(out[:params.SPX_N]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		panic("shake read failed: " + err.Error())
	}
}

// genMessageRandom computes R = SHAKE256(skPrf || optRand || message)
func genMessageRandom(R, skPrf, optRand, m []byte, ctx *SPXCtx) {
	shake := sha3.NewShake256()
	if _, err := shake.Write(skPrf[:params.SPX_N]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		panic("shake.Write(skPrf) failed: " + err.Error())
	}
	if _, err := shake.Write(optRand[:params.SPX_N]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		panic("shake.Write(optRand) failed: " + err.Error())
	}
	if _, err := shake.Write(m); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		panic("shake.Write(m) failed: " + err.Error())
	}
	if _, err := shake.Read(R[:params.SPX_N]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		panic("shake.Read(R) failed: " + err.Error())
	}
}

// hashMessage produces the message digest and parses tree and leaf indices
func hashMessage(digest []byte, tree *uint64, leafIdx *uint32,
	R, pk, m []byte, ctx *SPXCtx) {

	buf := make([]byte, SPX_DGST_BYTES)
	shake := sha3.NewShake256()
	if _, err := shake.Write(R[:params.SPX_N]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		panic("SHAKE256 write error on R: " + err.Error())
	}
	if _, err := shake.Write(pk[:params.SPX_PK_BYTES]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		panic("SHAKE256 write error on pk: " + err.Error())
	}
	if _, err := shake.Write(m); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		panic("SHAKE256 write error on message: " + err.Error())
	}
	if _, err := shake.Read(buf); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		panic("SHAKE256 read error: " + err.Error())
	}

	offset := 0
	copy(digest, buf[offset:offset+params.SPX_FORS_MSG_BYTES])
	offset += params.SPX_FORS_MSG_BYTES

	//noinspection GoBoolExpressions
	if SPX_D == 1 {
		*tree = 0
	} else {
		*tree = bytesToULL(buf[offset : offset+SPX_TREE_BYTES])
		*tree &= ^uint64(0) >> (64 - SPX_TREE_BITS)
	}
	offset += SPX_TREE_BYTES

	*leafIdx = uint32(bytesToULL(buf[offset : offset+SPX_LEAF_BYTES]))
	*leafIdx &= ^uint32(0) >> (32 - SPX_LEAF_BITS)
}

// bytesToULL converts a big-endian byte slice to a uint64
func bytesToULL(b []byte) uint64 {
	var val uint64
	for i := 0; i < len(b); i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val
}
