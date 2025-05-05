package misc

import (
	"crypto/sha256"
	"golang.org/x/crypto/sha3"
	"unsafe"
)

const (
	littleEndian = iota
	bigEndian
)

func GetEndian() uint8 {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		return littleEndian
	case [2]byte{0xAB, 0xCD}:
		return bigEndian
	default:
		panic("Could not determine native endian.")
	}
}

func SHAKE128(out, msg []byte) []byte {
	hasher := sha3.NewShake128()
	hasher.Write(msg)
	hasher.Read(out)
	return out
}

func SHAKE256(out, msg []byte) []byte {
	hasher := sha3.NewShake256()
	hasher.Write(msg)
	hasher.Read(out)
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

func AddrToByte(out *[32]uint8, addr *[8]uint32) {
	switch GetEndian() {
	case littleEndian:
		for i := 0; i < 8; i++ {
			ToByteLittleEndian(out[i*4:i*4+4], addr[i], 4)
		}
	case bigEndian:
		for i := 0; i < 8; i++ {
			ToByteBigEndian(out[i*4:i*4+4], addr[i], 4)
		}
	default:
		panic("Invalid Endian")
	}

}

func ToByteLittleEndian(out []uint8, in uint32, bytes uint32) {
	for i := int32(bytes - 1); i >= 0; i-- {
		out[i] = uint8(in & 0xff)
		in = in >> 8
	}
}

func ToByteBigEndian(out []uint8, in uint32, bytes uint32) {
	for i := uint32(0); i < bytes; i++ {
		out[i] = uint8(in & 0xff)
		in = in >> 8
	}
}
