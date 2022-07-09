package misc

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/theQRL/go-qrllib/qrl"
	"golang.org/x/crypto/sha3"
	"strings"
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

func BinToMnemonic(input [51]uint8) string {
	if len(input)%3 != 0 {
		panic("byte count needs to be a multiple of 3")
	}
	buf := bytes.NewBuffer(nil)
	separator := ""
	for nibble := 0; nibble < len(input)*2; nibble += 3 {
		p := nibble >> 1
		b1 := uint32(input[p])
		b2 := uint32(0)
		if p+1 < len(input) {
			b2 = uint32(input[p+1])
		}
		idx := uint32(0)
		if nibble%2 == 0 {
			idx = (b1 << 4) + (b2 >> 4)
		} else {
			idx = ((b1 & 0x0F) << 8) + b2
		}
		_, err := fmt.Fprint(buf, separator, qrl.WordList[idx])
		if err != nil {
			panic(fmt.Sprintf("BinToMnemonic error %s", err))
		}
		separator = " "
	}

	return buf.String()
}

func MnemonicToBin(mnemonic string) [51]uint8 {
	mnemonicWords := strings.Split(mnemonic, " ")
	wordCount := len(mnemonicWords)
	if wordCount%2 != 0 {
		panic(fmt.Sprintf("word count = %d must be even", wordCount))
	}

	// Prepare lookup
	// FIXME: Create the look up in advance
	wordLookup := make(map[string]int)

	for i, word := range qrl.WordList {
		wordLookup[word] = i
	}

	var result [51]uint8

	current := 0
	buffering := 0
	resultIndex := 0
	for _, w := range mnemonicWords {
		value, found := wordLookup[w]
		if !found {
			panic("invalid word in mnemonic")
		}

		buffering += 3
		current = (current << 12) + value

		for buffering > 2 {
			shift := 4 * (buffering - 2)
			mask := (1 << shift) - 1
			tmp := current >> shift
			buffering -= 2
			current &= mask
			result[resultIndex] = uint8(tmp)
			resultIndex++
		}
	}

	if buffering > 0 {
		result[resultIndex] = uint8(current & 0xFF)
		resultIndex++
	}

	return result
}
