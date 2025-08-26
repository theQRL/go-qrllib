package sphincsplus_256s

import (
	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

type LeafInfoX1 struct {
	WotsSig      []byte    // Corresponds to unsigned char*
	WotsSignLeaf uint32    // Index of the WOTS used to sign
	WotsSteps    []uint8   // Corresponds to uint32_t*
	LeafAddr     [8]uint32 // Fixed-size array of 8 uint32 values
	PkAddr       [8]uint32 // Fixed-size array of 8 uint32 values
}

func InitializeLeafInfoX1(info *LeafInfoX1, addr *[8]uint32, stepBuffer []uint8) {
	info.WotsSig = nil
	info.WotsSignLeaf = ^uint32(0) // Equivalent to ~0u in C
	info.WotsSteps = stepBuffer

	copy(info.LeafAddr[:], addr[:])
	copy(info.PkAddr[:], addr[:])
}

func WotsGenLeafX1(dest []byte, ctx *SPXCtx, leafIdx uint32, vInfo any) {
	info := vInfo.(*LeafInfoX1)
	leafAddr := &info.LeafAddr
	pkAddr := &info.PkAddr

	var pkBuffer [params.SPX_WOTS_BYTES]byte
	buffer := pkBuffer[:]

	var wotsKMask uint8
	if leafIdx == info.WotsSignLeaf {
		wotsKMask = 0
	} else {
		wotsKMask = ^uint8(0)
	}

	setKeypairAddr(leafAddr, leafIdx)
	setKeypairAddr(pkAddr, leafIdx)

	for i := 0; i < params.SPX_WOTS_LEN; i++ {
		offset := i * params.SPX_N
		buf := buffer[offset : offset+params.SPX_N]

		wotsK := info.WotsSteps[i] | wotsKMask

		// Generate seed
		setChainAddr(leafAddr, uint32(i))
		setHashAddr(leafAddr, 0)
		setType(leafAddr, SPX_ADDR_TYPE_WOTSPRF)

		prfAddr(buf, ctx, leafAddr)

		setType(leafAddr, SPX_ADDR_TYPE_WOTS)

		for k := uint8(0); ; k++ {
			if k == wotsK {
				copy(info.WotsSig[offset:], buf)
			}
			if k == params.SPX_WOTS_W-1 {
				break
			}

			setHashAddr(leafAddr, uint32(k))
			tHash(buf, buf, 1, ctx, leafAddr)
		}
	}

	tHash(dest, pkBuffer[:], params.SPX_WOTS_LEN, ctx, pkAddr)
}
