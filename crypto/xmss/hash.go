package xmss

import "github.com/theQRL/go-qrllib/misc"

func hashH(hashFunction HashFunction,
	out []uint8, in []uint8, pubSeed []uint8, addr *[8]uint32, n uint32) {
	buf := make([]uint8, 2*n)
	key := make([]uint8, n)
	bitMask := make([]uint8, 2*n)
	var byteAddr [32]uint8

	misc.SetKeyAndMask(addr, 0)
	misc.AddrToByte(&byteAddr, addr)
	prf(hashFunction, key, &byteAddr, pubSeed, n)

	// Use MSB order
	misc.SetKeyAndMask(addr, 1)
	misc.AddrToByte(&byteAddr, addr)
	prf(hashFunction, bitMask[:n], &byteAddr, pubSeed, n)
	misc.SetKeyAndMask(addr, 2)
	misc.AddrToByte(&byteAddr, addr)
	prf(hashFunction, bitMask[n:n+n], &byteAddr, pubSeed, n)
	for i := uint32(0); i < 2*n; i++ {
		buf[i] = in[i] ^ bitMask[i]
	}
	coreHash(hashFunction, out, 1, key, n, buf, 2*n, n)
}

// prf computes the RFC 8391 pseudo-random function over a fixed 32-byte
// input. The in parameter is typed as *[32]uint8 rather than []uint8 to
// pin the input length at compile time: every call site already passes a
// 32-byte stack-allocated array, and the underlying coreHash dispatch
// reads exactly 32 bytes regardless of slice length, so a shorter slice
// would index out of bounds. (TOB-QRLLIB-5)
//
// The key parameter remains a slice because its length (keyLen, equal to
// the parameter set's n) is variable across the supported hash functions.
func prf(hashFunction HashFunction, out []uint8, in *[32]uint8, key []uint8, keyLen uint32) {
	coreHash(hashFunction, out, 3, key, keyLen, in[:], 32, keyLen)
}

func coreHash(hashFunction HashFunction, out []uint8, typeValue uint32, key []uint8, keyLen uint32, in []uint8, inLen uint32, n uint32) {
	buf := make([]uint8, inLen+n+keyLen)
	misc.ToByteBigEndian(buf, typeValue, n) // RFC 8391 requires big-endian encoding

	for i := uint32(0); i < keyLen; i++ {
		buf[i+n] = key[i]
	}

	for i := uint32(0); i < inLen; i++ {
		buf[keyLen+n+i] = in[i]
	}

	switch hashFunction {
	case SHAKE_128:
		misc.SHAKE128(out, buf)
	case SHAKE_256:
		misc.SHAKE256(out, buf)
	case SHA2_256:
		misc.SHA256(out, buf)
	}
}
