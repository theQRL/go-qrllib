package sphincsplus_256s

import (
	"encoding/binary"
	"unsafe"

	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

const (
	SPX_ADDR_TYPE_WOTS     = 0
	SPX_ADDR_TYPE_WOTSPK   = 1
	SPX_ADDR_TYPE_HASHTREE = 2
	SPX_ADDR_TYPE_FORSTREE = 3
	SPX_ADDR_TYPE_FORSPK   = 4
	SPX_ADDR_TYPE_WOTSPRF  = 5
	SPX_ADDR_TYPE_FORSPRF  = 6
)

func init() {
	//noinspection GoBoolExpressions
	if (params.SPX_TREE_HEIGHT * (params.SPX_D - 1)) > 64 {
		panic("Subtree addressing is limited to at most 2^64 trees")
	}
}

func setLayerAddr(addr *[8]uint32, layer uint32) {
	byteAddr := (*[32]byte)(unsafe.Pointer(addr))[:]
	byteAddr[params.SPX_OFFSET_LAYER] = byte(layer)
}

func setTreeAddr(addr *[8]uint32, tree uint64) {
	byteAddr := (*[32]byte)(unsafe.Pointer(addr))[:]

	// Write tree in big-endian format at offset SPX_OFFSET_TREE
	binary.BigEndian.PutUint64(byteAddr[params.SPX_OFFSET_TREE:], tree)
}

func setType(addr *[8]uint32, typ uint32) {
	byteAddr := (*[32]byte)(unsafe.Pointer(addr))[:]
	byteAddr[params.SPX_OFFSET_TYPE] = byte(typ)
}

func copySubtreeAddr(out, in *[8]uint32) {
	inBytes := (*[32]byte)(unsafe.Pointer(in))[:]
	outBytes := (*[32]byte)(unsafe.Pointer(out))[:]
	copy(outBytes[:params.SPX_OFFSET_TREE+8], inBytes[:params.SPX_OFFSET_TREE+8])
}

func setKeypairAddr(addr *[8]uint32, keypair uint32) {
	byteAddr := (*[32]byte)(unsafe.Pointer(addr))[:]
	binary.BigEndian.PutUint32(byteAddr[params.SPX_OFFSET_KP_ADDR:], keypair)
}

func memcpy(out []byte, in *[8]uint32) {
	inBytes := (*[32]byte)(unsafe.Pointer(in))[:]
	copy(out, inBytes[:])
}

func copyKeypairAddr(out, in *[8]uint32) {
	// Reinterpret addr as a 32-byte array
	inBytes := (*[32]byte)(unsafe.Pointer(in))[:]
	outBytes := (*[32]byte)(unsafe.Pointer(out))[:]

	// Copy first (SPX_OFFSET_TREE + 8) bytes
	copy(outBytes[:params.SPX_OFFSET_TREE+8], inBytes[:params.SPX_OFFSET_TREE+8])

	// Copy 4 bytes at SPX_OFFSET_KP_ADDR (typically offset 28)
	copy(outBytes[params.SPX_OFFSET_KP_ADDR:params.SPX_OFFSET_KP_ADDR+4], inBytes[params.SPX_OFFSET_KP_ADDR:params.SPX_OFFSET_KP_ADDR+4])
}

func setChainAddr(addr *[8]uint32, chain uint32) {
	byteAddr := (*[32]byte)(unsafe.Pointer(addr))[:]
	byteAddr[params.SPX_OFFSET_CHAIN_ADDR] = byte(chain)
}

func setHashAddr(addr *[8]uint32, hash uint32) {
	byteAddr := (*[32]byte)(unsafe.Pointer(addr))[:]
	byteAddr[params.SPX_OFFSET_HASH_ADDR] = byte(hash)
}

func setTreeHeight(addr *[8]uint32, treeHeight uint32) {
	byteAddr := (*[32]byte)(unsafe.Pointer(addr))[:]
	byteAddr[params.SPX_OFFSET_TREE_HGT] = byte(treeHeight)
}

func setTreeIndex(addr *[8]uint32, treeIndex uint32) {
	byteAddr := (*[32]byte)(unsafe.Pointer(addr))[:]
	binary.BigEndian.PutUint32(byteAddr[params.SPX_OFFSET_TREE_INDEX:], treeIndex)
}

func setByteAtOffset(addr *[8]uint32, offset int, value byte) {
	byteAddr := (*[32]byte)(unsafe.Pointer(addr))[:]
	byteAddr[offset] = value
}

func getByteAtOffset(addr *[8]uint32, offset int) byte {
	byteAddr := (*[32]byte)(unsafe.Pointer(addr))[:]
	return byteAddr[offset]
}
