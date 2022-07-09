package xmss

import (
	"github.com/theQRL/go-qrllib/misc"
)

func XMSSFastGenKeyPair(hashFunction HashFunction, xmssParams *XMSSParams,
	pk, sk []uint8, bdsState *BDSState, seed [48]uint8) {

	if xmssParams.h&1 == 1 {
		panic("Not a valid h, only even numbers supported! Try again with an even number")
	}

	n := xmssParams.n

	// Set idx = 0
	sk[0] = 0
	sk[1] = 0
	sk[2] = 0
	sk[3] = 0

	// Copy PUB_SEED to public key
	randombits := make([]uint8, 3*n)

	misc.SHAKE256(randombits, seed[:])
	//shake256(randombits, 3 * n, seed, 48);  // FIXME: seed size has been hardcoded to 48

	rnd := 96
	pks := uint32(32)
	copy(sk[4:], randombits[:rnd])
	copy(pk[n:], sk[4+2*n:4+2*n+pks])

	addr := make([]uint32, 8)
	treeHashSetup(hashFunction, pk, 0, bdsState, sk[4:4+n], xmssParams, sk[4+2*n:4+2*n+n], addr)
	copy(sk[4+3*n:], pk[:pks])
}

func treeHashSetup(hashFunction HashFunction, node []uint8, index uint32, bdsState *BDSState, skSeed []uint8, xmssParams *XMSSParams, pubSeed []uint8, addr []uint32) {
	n := xmssParams.n
	h := xmssParams.h
	k := xmssParams.k

	var otsAddr [8]uint32
	var lTreeAddr [8]uint32
	var nodeAddr [8]uint32

	copy(otsAddr[:3], addr[:3])
	misc.SetType(&otsAddr, 0)

	copy(lTreeAddr[:3], addr[:3])
	misc.SetType(&lTreeAddr, 1)

	copy(nodeAddr[:3], addr[:3])
	misc.SetType(&nodeAddr, 2)

	lastNode := index + (1 << h)

	bound := h - k
	stack := make([]uint8, (h+1)*n)
	stackLevels := make([]uint32, h+1)
	stackOffset := uint32(0)
	nodeH := uint32(0)

	for i := uint32(0); i < bound; i++ {
		bdsState.treeHash[i].h = i
		bdsState.treeHash[i].completed = 1
		bdsState.treeHash[i].stackUsage = 0
	}

	i := uint32(0)
	for ; index < lastNode; index++ {
		misc.SetLTreeAddr(&lTreeAddr, index)
		misc.SetOTSAddr(&otsAddr, index)

		genLeafWOTS(hashFunction, stack[stackOffset*n:stackOffset*n+n], skSeed, xmssParams, pubSeed, &lTreeAddr, &otsAddr)
		stackLevels[stackOffset] = 0
		stackOffset++
		if h-k > 0 && i == 3 {
			copy(bdsState.treeHash[0].node, stack[stackOffset*n:stackOffset*n+n])
		}
		for stackOffset > 1 && stackLevels[stackOffset-1] == stackLevels[stackOffset-2] {
			nodeH = stackLevels[stackOffset-1]
			if (i >> nodeH) == 1 {
				authStart := nodeH * n
				stackStart := (stackOffset - 1) * n
				copy(bdsState.auth[authStart:authStart+n], stack[stackStart:stackStart+n])
			} else {
				if (nodeH < h-k) && ((i >> nodeH) == 3) {
					stackStart := (stackOffset - 1) * n
					copy(bdsState.treeHash[nodeH].node, stack[stackStart:stackStart+n])
				} else if nodeH >= h-k {
					//memcpy(state->retain + ((1 << (h - 1 - nodeh)) + nodeh - h + (((i >> nodeh) - 3) >> 1)) * n,
					//	stack + (stackoffset - 1) * n, n);
					retainStart := ((1 << (h - 1 - nodeH)) + nodeH - h + (((i >> nodeH) - 3) >> 1)) * n
					stackStart := (stackOffset - 1) * n
					copy(bdsState.retain[retainStart:retainStart+n], stack[stackStart:stackStart+n])
				}
			}
			misc.SetTreeHeight(&nodeAddr, stackLevels[stackOffset-1])
			misc.SetTreeIndex(&nodeAddr, index>>(stackLevels[stackOffset-1]+1))
			stackStart := (stackOffset - 2) * n
			hashH(hashFunction, stack[stackStart:stackStart+n], stack[stackStart:stackStart+2*n], pubSeed,
				&nodeAddr, n)
			stackLevels[stackOffset-2]++
			stackOffset--
		}
		i++
	}

	copy(node[:n], stack[:n])
}

func genLeafWOTS(hashFunction HashFunction, leaf, skSeed []uint8, xmssParams *XMSSParams, pubSeed []uint8, lTreeAddr, otsAddr *[8]uint32) {
	seed := make([]uint8, xmssParams.n)
	pk := make([]uint8, xmssParams.wotsParams.keySize)

	getSeed(hashFunction, seed, skSeed, xmssParams.n, otsAddr)
	wOTSPKGen(hashFunction, pk, seed, xmssParams.wotsParams, pubSeed, otsAddr)

	lTree(hashFunction, xmssParams.wotsParams, leaf, pk, pubSeed, lTreeAddr)

}

func getSeed(hashFunction HashFunction, seed, skSeed []uint8, n uint32, addr *[8]uint32) {
	var bytes [32]uint8

	misc.SetChainAddr(addr, 0)
	misc.SetHashAddr(addr, 0)
	misc.SetKeyAndMask(addr, 0)

	// Generate pseudorandom value
	misc.AddrToByte(&bytes, addr)
	prf(hashFunction, seed, bytes[:], skSeed, n)
}

func wOTSPKGen(hashFunction HashFunction, pk, sk []uint8, wOTSParams *WOTSParams, pubSeed []uint8, addr *[8]uint32) {
	expandSeed(hashFunction, pk, sk, wOTSParams.n, wOTSParams.len)
	for i := uint32(0); i < wOTSParams.len; i++ {
		misc.SetChainAddr(addr, i)
		pkStartOffset := i * wOTSParams.n
		genChain(hashFunction,
			pk[pkStartOffset:pkStartOffset+wOTSParams.n],
			pk[pkStartOffset:pkStartOffset+wOTSParams.n],
			0,
			wOTSParams.w-1,
			wOTSParams,
			pubSeed,
			addr)
	}
}

func expandSeed(hashFunction HashFunction, outSeeds, inSeeds []uint8, n, len uint32) {
	var ctr [32]uint8
	for i := uint32(0); i < len; i++ {
		misc.ToByteLittleEndian(ctr[:], i, 32)
		prf(hashFunction, outSeeds[i*n:i*n+n], ctr[:], inSeeds, n)
	}
}

func genChain(hashFunction HashFunction, out, in []uint8, start, steps uint32, params *WOTSParams, pubSeed []uint8, addr *[8]uint32) {
	for j := uint32(0); j < params.n; j++ {
		out[j] = in[j]
	}

	for i := start; i < (start+steps) && i < params.w; i++ {
		misc.SetHashAddr(addr, i)
		hashF(hashFunction, out, out, pubSeed, addr, params.n)
	}
}

func hashF(hashFunction HashFunction, out, in, pubSeed []uint8, addr *[8]uint32, n uint32) {
	buf := make([]uint8, n)
	key := make([]uint8, n)
	bitMask := make([]uint8, n)
	var byteAddr [32]uint8

	misc.SetKeyAndMask(addr, 0)
	misc.AddrToByte(&byteAddr, addr)
	prf(hashFunction, key, byteAddr[:], pubSeed, n)

	misc.SetKeyAndMask(addr, 1)
	misc.AddrToByte(&byteAddr, addr)
	prf(hashFunction, bitMask, byteAddr[:], pubSeed, n)

	for i := uint32(0); i < n; i++ {
		buf[i] = in[i] ^ bitMask[i]
	}
	coreHash(hashFunction, out, 0, key, n, buf, n, n)
}

func lTree(hashFunction HashFunction, params *WOTSParams, leaf, wotsPK, pubSeed []uint8, addr *[8]uint32) {
	l := params.len
	n := params.n

	height := uint32(0)
	bound := uint32(0)

	misc.SetTreeHeight(addr, height)
	for l > 1 {
		bound = l >> 1
		for i := uint32(0); i < bound; i++ {
			misc.SetTreeIndex(addr, i)
			outStartOffset := i * n
			inStartOffset := i * 2 * n
			hashH(hashFunction, wotsPK[outStartOffset:outStartOffset+n], wotsPK[inStartOffset:inStartOffset+2*n], pubSeed, addr, n)
		}
		if l&1 == 1 {
			destStartOffset := (l >> 1) * n
			srcStartOffset := (l - 1) * n
			copy(wotsPK[destStartOffset:destStartOffset+n], wotsPK[srcStartOffset:srcStartOffset+n])
			l = (l >> 1) + 1
		} else {
			l = l >> 1
		}
		height++
		misc.SetTreeHeight(addr, height)
	}
	copy(leaf[:n], wotsPK[:n])
}

func xmssFastUpdate(hashFunction HashFunction, params *XMSSParams, sk []uint8, bdsState *BDSState, newIdx uint32) int32 {
	numElems := uint32(1 << params.h)

	currentIdx := uint32(sk[0])<<24 | uint32(sk[1])<<16 | uint32(sk[2])<<8 | uint32(sk[3])

	if newIdx >= numElems {
		panic("index too high")
	}

	if newIdx < currentIdx {
		panic("cannot rewind")
	}

	skSeed := make([]uint8, params.n)
	copy(skSeed, sk[4:4+params.n])

	startOffset := 4 + 2*32
	pubSeed := make([]uint8, params.n)
	copy(pubSeed[:32], sk[startOffset:startOffset+32])

	var otsAddr [8]uint32

	for j := currentIdx; j < newIdx; j++ {
		if j >= numElems {
			return -1
		}

		bdsRound(hashFunction, bdsState, j, skSeed, params, pubSeed, &otsAddr)
		bdsTreeHashUpdate(hashFunction, bdsState, (params.h-params.k)>>1, skSeed, params, pubSeed, &otsAddr)
	}

	sk[0] = uint8(newIdx >> 24 & 0xff)
	sk[1] = uint8(newIdx >> 16 & 0xff)
	sk[2] = uint8(newIdx >> 8 & 0xff)
	sk[3] = uint8(newIdx & 0xff)

	return 0
}

func bdsRound(hashFunction HashFunction, bdsState *BDSState, leafIdx uint32, skSeed []uint8, params *XMSSParams, pubSeed []uint8, addr *[8]uint32) {
	n := params.n
	h := params.h
	k := params.k

	tau := h
	buf := make([]uint8, 2*n)

	var otsAddr [8]uint32
	var lTreeAddr [8]uint32
	var nodeAddr [8]uint32

	copy(otsAddr[:3], addr[:3])
	misc.SetType(&otsAddr, 0)

	copy(lTreeAddr[:3], addr[:3])
	misc.SetType(&lTreeAddr, 1)

	copy(nodeAddr[:3], addr[:3])
	misc.SetType(&nodeAddr, 2)

	for i := uint32(0); i < h; i++ {
		if (leafIdx>>i)&1 == 0 {
			tau = i
			break
		}
	}

	if tau > 0 {
		srcOffset := (tau - 1) * n
		copy(buf[:n], bdsState.auth[srcOffset:srcOffset+n])

		srcOffset = ((tau - 1) >> 1) * n
		copy(buf[n:2*n], bdsState.keep[srcOffset:srcOffset+n])
	}
	if ((leafIdx>>(tau+1))&1) == 0 && (tau < h-1) {
		destOffset := (tau >> 1) * n
		srcOffset := tau * n
		copy(bdsState.keep[destOffset:destOffset+n], bdsState.auth[srcOffset:srcOffset+n])
	}
	if tau == 0 {
		misc.SetLTreeAddr(&lTreeAddr, leafIdx)
		misc.SetOTSAddr(&otsAddr, leafIdx)
		genLeafWOTS(hashFunction, bdsState.auth[:n], skSeed[:], params, pubSeed[:], &lTreeAddr, &otsAddr)
	} else {
		misc.SetTreeHeight(&nodeAddr, tau-1)
		misc.SetTreeIndex(&nodeAddr, leafIdx>>tau)
		hashH(hashFunction, bdsState.auth[tau*n:tau*n+n], buf, pubSeed[:], &nodeAddr, n)
		for i := uint32(0); i < tau; i++ {
			if i < h-k {
				copy(bdsState.auth[i*n:i*n+n], bdsState.treeHash[i].node[:n])
			} else {
				offset := (1 << (h - 1 - i)) + i - h
				rowIdx := ((leafIdx >> i) - 1) >> 1
				srcOffset := (offset + rowIdx) * n
				copy(bdsState.auth[i*n:i*n+n], bdsState.retain[srcOffset:srcOffset+n])
			}
		}

		compareValue := h - k
		if tau < h-k {
			compareValue = tau
		}
		for i := uint32(0); i < compareValue; i++ {
			startIdx := leafIdx + 1 + 3*(1<<i)
			if startIdx < (1 << h) {
				bdsState.treeHash[i].h = i
				bdsState.treeHash[i].nextIdx = startIdx
				bdsState.treeHash[i].completed = 0
				bdsState.treeHash[i].stackUsage = 0
			}
		}
	}
}

func bdsTreeHashUpdate(hashFunction HashFunction, bdsState *BDSState, updates uint32, skSeed []uint8, params *XMSSParams, pubSeed []uint8, addr *[8]uint32) uint32 {
	h := params.h
	k := params.k
	used := uint32(0)
	lMin := uint32(0)
	level := uint32(0)
	low := uint32(0)

	for j := uint32(0); j < updates; j++ {
		lMin = h
		level = h - k
		for i := uint32(0); i < h-k; i++ {
			if bdsState.treeHash[i].completed == 1 {
				low = h
			} else if bdsState.treeHash[i].stackUsage == 0 {
				low = i
			} else {
				low = treeHashMinHeightOnStack(bdsState, params, bdsState.treeHash[i])
			}
			if low < lMin {
				level = i
				lMin = low
			}
		}
		if level == h-k {
			break
		}
		treeHashUpdate(hashFunction, bdsState.treeHash[level], bdsState, skSeed, params, pubSeed, addr)
		used++
	}
	return updates - used
}

func treeHashMinHeightOnStack(state *BDSState, params *XMSSParams, treeHash *TreeHashInst) uint32 {
	r := params.h
	for i := uint32(0); i < treeHash.stackUsage; i++ {
		if uint32(state.stackLevels[state.stackOffset-i-1]) < r {
			r = uint32(state.stackLevels[state.stackOffset-i-1])
		}
	}
	return r
}

func treeHashUpdate(hashFunction HashFunction, treeHash *TreeHashInst, bdsState *BDSState, skSeed []uint8, params *XMSSParams, pubSeed []uint8, addr *[8]uint32) {
	n := params.n

	var otsAddr [8]uint32
	var lTreeAddr [8]uint32
	var nodeAddr [8]uint32

	copy(otsAddr[:3], addr[:3])
	misc.SetType(&otsAddr, 0)

	copy(lTreeAddr[:3], addr[:3])
	misc.SetType(&lTreeAddr, 1)

	copy(nodeAddr[:3], addr[:3])
	misc.SetType(&nodeAddr, 2)

	misc.SetLTreeAddr(&lTreeAddr, treeHash.nextIdx)
	misc.SetOTSAddr(&otsAddr, treeHash.nextIdx)

	nodeBuffer := make([]uint8, 2*n)
	nodeHeight := uint32(0)

	genLeafWOTS(hashFunction, nodeBuffer, skSeed, params, pubSeed, &lTreeAddr, &otsAddr)

	for treeHash.stackUsage > 0 && uint32(bdsState.stackLevels[bdsState.stackOffset-1]) == nodeHeight {
		copy(nodeBuffer[n:n+n], nodeBuffer[:n])
		srcOffset := (bdsState.stackOffset - 1) * n
		copy(nodeBuffer[:n], bdsState.stack[srcOffset:srcOffset+n])
		misc.SetTreeHeight(&nodeAddr, nodeHeight)
		misc.SetTreeIndex(&nodeAddr, treeHash.nextIdx>>(nodeHeight+1))
		hashH(hashFunction, nodeBuffer[:n], nodeBuffer, pubSeed, &nodeAddr, n)
		nodeHeight++
		treeHash.stackUsage--
		bdsState.stackOffset--
	}
	if nodeHeight == treeHash.h { // this also implies stackusage == 0
		copy(treeHash.node[:n], nodeBuffer[:n])
		treeHash.completed = 1
	} else {
		destOffset := bdsState.stackOffset * n
		copy(bdsState.stack[destOffset:destOffset+n], nodeBuffer[:n])
		treeHash.stackUsage++
		bdsState.stackLevels[bdsState.stackOffset] = uint8(nodeHeight)
		bdsState.stackOffset++
		treeHash.nextIdx++
	}
}
