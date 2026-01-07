package misc

import (
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

const (
	littleEndian = iota
	bigEndian
)

// nativeEndian is determined once at package init time using binary.NativeEndian (Go 1.21+)
var nativeEndian uint8

func init() {
	// Use binary.NativeEndian to safely detect byte order without unsafe
	buf := [2]byte{}
	binary.NativeEndian.PutUint16(buf[:], 0xABCD)
	if buf[0] == 0xCD {
		nativeEndian = littleEndian
	} else {
		nativeEndian = bigEndian
	}
}

// GetEndian returns the native byte order of the system.
// Deprecated: This function is kept for API compatibility but now uses
// binary.NativeEndian internally instead of unsafe pointer manipulation.
func GetEndian() uint8 {
	return nativeEndian
}

func SHAKE128(out, msg []byte) []byte {
	hasher := sha3.NewShake128()
	_, _ = hasher.Write(msg)
	_, _ = hasher.Read(out) // ShakeHash.Read never returns an error
	return out
}

func SHAKE256(out, msg []byte) []byte {
	hasher := sha3.NewShake256()
	_, _ = hasher.Write(msg)
	_, _ = hasher.Read(out) // ShakeHash.Read never returns an error
	return out
}

func SHA256(out, msg []byte) []byte {
	hasher := sha256.New()
	hasher.Write(msg)
	hashOut := hasher.Sum(nil)
	copy(out, hashOut)
	return out
}

func SetType(addr *[8]uint32, typeValue uint32) {
	addr[3] = typeValue
	for i := 4; i < 8; i++ {
		addr[i] = 0
	}
}

func SetOTSAddr(addr *[8]uint32, ots uint32) {
	addr[4] = ots
}

func SetChainAddr(addr *[8]uint32, chain uint32) {
	addr[5] = chain
}

func SetHashAddr(addr *[8]uint32, hash uint32) {
	addr[6] = hash
}

func SetLTreeAddr(addr *[8]uint32, lTree uint32) {
	addr[4] = lTree
}

func SetTreeHeight(addr *[8]uint32, treeHeight uint32) {
	addr[5] = treeHeight
}

func SetTreeIndex(addr *[8]uint32, treeIndex uint32) {
	addr[6] = treeIndex
}

func SetKeyAndMask(addr *[8]uint32, keyAndMask uint32) {
	addr[7] = keyAndMask
}

// AddrToByte serializes an 8-element uint32 address to a 32-byte array.
// Always uses Big Endian (network byte order) for cryptographic interoperability.
func AddrToByte(out *[32]uint8, addr *[8]uint32) {
	for i := 0; i < 8; i++ {
		ToByteBigEndian(out[i*4:i*4+4], addr[i], 4)
	}
}

// ToByteLittleEndian converts a uint32 to bytes in little-endian order.
// Little endian: LSB at lowest address (index 0).
// Example: 0x12345678 → [0x78, 0x56, 0x34, 0x12]
func ToByteLittleEndian(out []uint8, in uint32, bytes uint32) {
	for i := uint32(0); i < bytes; i++ {
		out[i] = uint8(in & 0xff)
		in = in >> 8
	}
}

// ToByteBigEndian converts a uint32 to bytes in big-endian order (network byte order).
// Big endian: MSB at lowest address (index 0).
// Example: 0x12345678 → [0x12, 0x34, 0x56, 0x78]
func ToByteBigEndian(out []uint8, in uint32, bytes uint32) {
	for i := int32(bytes - 1); i >= 0; i-- {
		out[i] = uint8(in & 0xff)
		in = in >> 8
	}
}
