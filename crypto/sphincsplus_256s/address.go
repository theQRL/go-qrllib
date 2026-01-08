package sphincsplus_256s

import (
	"encoding/binary"

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

// addrToBytes converts [8]uint32 to [32]byte using big-endian encoding.
// SPHINCS+ addresses are defined as 32-byte big-endian structures.
func addrToBytes(addr *[8]uint32) [32]byte {
	var out [32]byte
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(out[i*4:], addr[i])
	}
	return out
}

// bytesToAddr converts [32]byte to [8]uint32 using big-endian encoding.
func bytesToAddr(b []byte) [8]uint32 {
	var addr [8]uint32
	for i := 0; i < 8; i++ {
		addr[i] = binary.BigEndian.Uint32(b[i*4:])
	}
	return addr
}

// updateAddrByte sets a single byte at the given offset in the address.
// This is done by converting to bytes, modifying, and converting back.
func updateAddrByte(addr *[8]uint32, offset int, value byte) {
	bytes := addrToBytes(addr)
	bytes[offset] = value
	*addr = bytesToAddr(bytes[:])
}

func setLayerAddr(addr *[8]uint32, layer uint32) {
	updateAddrByte(addr, params.SPX_OFFSET_LAYER, byte(layer))
}

func setTreeAddr(addr *[8]uint32, tree uint64) {
	bytes := addrToBytes(addr)
	binary.BigEndian.PutUint64(bytes[params.SPX_OFFSET_TREE:], tree)
	*addr = bytesToAddr(bytes[:])
}

func setType(addr *[8]uint32, typ uint32) {
	updateAddrByte(addr, params.SPX_OFFSET_TYPE, byte(typ))
}

func copySubtreeAddr(out, in *[8]uint32) {
	inBytes := addrToBytes(in)
	outBytes := addrToBytes(out)
	copy(outBytes[:params.SPX_OFFSET_TREE+8], inBytes[:params.SPX_OFFSET_TREE+8])
	*out = bytesToAddr(outBytes[:])
}

func setKeypairAddr(addr *[8]uint32, keypair uint32) {
	bytes := addrToBytes(addr)
	binary.BigEndian.PutUint32(bytes[params.SPX_OFFSET_KP_ADDR:], keypair)
	*addr = bytesToAddr(bytes[:])
}

func memcpy(out []byte, in *[8]uint32) {
	inBytes := addrToBytes(in)
	copy(out, inBytes[:])
}

func copyKeypairAddr(out, in *[8]uint32) {
	inBytes := addrToBytes(in)
	outBytes := addrToBytes(out)

	// Copy first (SPX_OFFSET_TREE + 8) bytes
	copy(outBytes[:params.SPX_OFFSET_TREE+8], inBytes[:params.SPX_OFFSET_TREE+8])

	// Copy 4 bytes at SPX_OFFSET_KP_ADDR (typically offset 28)
	copy(outBytes[params.SPX_OFFSET_KP_ADDR:params.SPX_OFFSET_KP_ADDR+4], inBytes[params.SPX_OFFSET_KP_ADDR:params.SPX_OFFSET_KP_ADDR+4])

	*out = bytesToAddr(outBytes[:])
}

func setChainAddr(addr *[8]uint32, chain uint32) {
	updateAddrByte(addr, params.SPX_OFFSET_CHAIN_ADDR, byte(chain))
}

func setHashAddr(addr *[8]uint32, hash uint32) {
	updateAddrByte(addr, params.SPX_OFFSET_HASH_ADDR, byte(hash))
}

func setTreeHeight(addr *[8]uint32, treeHeight uint32) {
	updateAddrByte(addr, params.SPX_OFFSET_TREE_HGT, byte(treeHeight))
}

func setTreeIndex(addr *[8]uint32, treeIndex uint32) {
	bytes := addrToBytes(addr)
	binary.BigEndian.PutUint32(bytes[params.SPX_OFFSET_TREE_INDEX:], treeIndex)
	*addr = bytesToAddr(bytes[:])
}
