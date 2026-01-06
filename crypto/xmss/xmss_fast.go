package xmss

import (
	"fmt"

	"github.com/theQRL/go-qrllib/legacywallet/common"
	"github.com/theQRL/go-qrllib/misc"
)

func XMSSFastGenKeyPair(hashFunction HashFunction, xmssParams *XMSSParams,
	pk, sk []uint8, bdsState *BDSState, seed []uint8) {

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

	misc.SHAKE256(randombits, seed)
	//shake256(randombits, 3 * n, seed, 48);  // FIXME: seed size has been hardcoded to 48

	rnd := 96
	pks := uint32(32)
	copy(sk[4:], randombits[:rnd])
	copy(pk[n:], sk[4+2*n:4+2*n+pks])

	addr := make([]uint32, 8)
	treeHashSetup(hashFunction, pk, 0, bdsState, sk[4:4+n], xmssParams, sk[4+2*n:4+2*n+n], addr)
	copy(sk[4+3*n:], pk[:pks])
}

func xmssFastSignMessage(hashFunction HashFunction, params *XMSSParams, sk []uint8, bdsState *BDSState, message []uint8) ([]uint8, error) {
	n := params.n

	idx := (uint32(sk[0]) << 24) | (uint32(sk[1]) << 16) | (uint32(sk[2]) << 8) | uint32(sk[3])

	skSeed := make([]uint8, n)
	copy(skSeed, sk[4:4+n])
	skPRF := make([]uint8, n)
	copy(skPRF, sk[4+n:4+n+n])
	pubSeed := make([]uint8, n)
	copy(pubSeed, sk[4+2*n:4+2*n+n])

	var idxBytes32 [32]uint8
	misc.ToByteLittleEndian(idxBytes32[:], idx, 32)

	hashKey := make([]uint8, 3*n)

	sk[0] = uint8((idx + 1) >> 24 & 0xff)
	sk[1] = uint8((idx + 1) >> 16 & 0xff)
	sk[2] = uint8((idx + 1) >> 8 & 0xff)
	sk[3] = uint8((idx + 1) & 0xff)

	R := make([]uint8, n)
	var otsAddr [8]uint32

	prf(hashFunction, R, idxBytes32[:], skPRF, n)
	copy(hashKey[:n], R)
	copy(hashKey[n:n+n], sk[4+3*n:4+3*n+n])
	misc.ToByteLittleEndian(hashKey[2*n:2*n+n], idx, n)
	msgHash := make([]uint8, n)
	err := hMsg(hashFunction, msgHash, message, hashKey, n)
	if err != nil {
		return nil, err
	}
	sigMsgLen := uint32(0)
	sigMsg := make([]uint8, getSignatureSize(params))
	sigMsg[0] = uint8((idx >> 24) & 0xff)
	sigMsg[1] = uint8((idx >> 16) & 0xff)
	sigMsg[2] = uint8((idx >> 8) & 0xff)
	sigMsg[3] = uint8(idx & 0xff)

	sigMsgLen += 4
	for i := uint32(0); i < n; i++ {
		sigMsg[sigMsgLen+i] = R[i]
	}

	sigMsgLen += n

	misc.SetType(&otsAddr, 0)
	misc.SetOTSAddr(&otsAddr, idx)

	otsSeed := make([]uint8, n)
	getSeed(hashFunction, otsSeed, skSeed, n, &otsAddr)

	wotsSign(hashFunction, sigMsg[sigMsgLen:], msgHash, otsSeed, params.wotsParams, pubSeed, &otsAddr)

	sigMsgLen += params.wotsParams.keySize

	copy(sigMsg[sigMsgLen:sigMsgLen+params.h*params.n], bdsState.auth[:params.h*params.n])

	if idx < (uint32(1)<<params.h)-1 {
		bdsRound(hashFunction, bdsState, idx, skSeed, params, pubSeed, &otsAddr)
		bdsTreeHashUpdate(hashFunction, bdsState, (params.h-params.k)>>1, skSeed, params, pubSeed, &otsAddr)
	}

	return sigMsg, nil
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

func xmssFastUpdate(hashFunction HashFunction, params *XMSSParams, sk []uint8, bdsState *BDSState, newIdx uint32) error {
	numElems := uint32(1 << params.h)

	currentIdx := uint32(sk[0])<<24 | uint32(sk[1])<<16 | uint32(sk[2])<<8 | uint32(sk[3])

	if newIdx >= numElems {
		return fmt.Errorf(common.ErrOTSIndexTooHigh, newIdx, numElems-1)
	}

	if newIdx < currentIdx {
		return fmt.Errorf(common.ErrCannotRewindOTSIndex, currentIdx, newIdx)
	}

	skSeed := make([]uint8, params.n)
	copy(skSeed, sk[4:4+params.n])

	startOffset := 4 + 2*32
	pubSeed := make([]uint8, params.n)
	copy(pubSeed[:32], sk[startOffset:startOffset+32])

	var otsAddr [8]uint32

	for j := currentIdx; j < newIdx; j++ {
		if j >= numElems {
			panic(fmt.Sprintf("index out of bounds: j=%d >= numElems=%d", j, numElems))
		}

		bdsRound(hashFunction, bdsState, j, skSeed, params, pubSeed, &otsAddr)
		bdsTreeHashUpdate(hashFunction, bdsState, (params.h-params.k)>>1, skSeed, params, pubSeed, &otsAddr)
	}

	sk[0] = uint8(newIdx >> 24 & 0xff)
	sk[1] = uint8(newIdx >> 16 & 0xff)
	sk[2] = uint8(newIdx >> 8 & 0xff)
	sk[3] = uint8(newIdx & 0xff)

	return nil
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

func wotsSign(hashFunction HashFunction, sig, msg, sk []uint8, params *WOTSParams, pubSeed []uint8, addr *[8]uint32) {
	baseW := make([]uint8, params.len)
	csum := uint32(0)

	calcBaseW(baseW, params.len1, msg, params)

	for i := uint32(0); i < params.len1; i++ {
		csum += params.w - 1 - uint32(baseW[i])
	}

	csum = csum << (8 - ((params.len2 * params.logW) % 8))

	len2Bytes := ((params.len2 * params.logW) + 7) / 8

	cSumBytes := make([]uint8, len2Bytes)
	misc.ToByteLittleEndian(cSumBytes, csum, len2Bytes)

	cSumBaseW := make([]uint8, params.len2)

	calcBaseW(cSumBaseW, params.len2, cSumBytes, params)

	for i := uint32(0); i < params.len2; i++ {
		baseW[params.len1+i] = cSumBaseW[i]
	}

	expandSeed(hashFunction, sig, sk, params.n, params.len)

	for i := uint32(0); i < params.len; i++ {
		misc.SetChainAddr(addr, i)
		offset := i * params.n
		genChain(hashFunction, sig[offset:offset+params.n], sig[offset:offset+params.n], 0, uint32(baseW[i]), params, pubSeed, addr)
	}
}

func verifySig(hashFunction HashFunction, wotsParams *WOTSParams, msg, sigMsg, pk []uint8, h uint32) bool {

	sigMsgOffset := uint32(0)

	n := wotsParams.n

	// Validate public key length (must be at least 2*n bytes: root + pubSeed)
	if uint32(len(pk)) < 2*n {
		return false
	}

	wotsPK := make([]uint8, wotsParams.keySize)
	pkHash := make([]uint8, n)
	root := make([]uint8, n)
	hashKey := make([]uint8, 3*n)

	pubSeed := make([]uint8, n)
	copy(pubSeed, pk[n:n+n])

	// Init addresses
	var otsAddr [8]uint32
	var lTreeAddr [8]uint32
	var nodeAddr [8]uint32

	misc.SetType(&otsAddr, 0)
	misc.SetType(&lTreeAddr, 1)
	misc.SetType(&nodeAddr, 2)

	// Extract index
	idx := (uint32(sigMsg[0]) << 24) |
		(uint32(sigMsg[1]) << 16) |
		(uint32(sigMsg[2]) << 8) |
		uint32(sigMsg[3])

	// printf("verify:: idx = %lu\n", idx);

	// Generate hash key (R || root || idx)
	copy(hashKey[:n], sigMsg[4:4+n])
	copy(hashKey[n:n+n], pk[:n])
	misc.ToByteLittleEndian(hashKey[2*n:2*n+n], idx, n)

	sigMsgOffset += n + 4

	// hash message
	msgHash := make([]uint8, n)
	err := hMsg(hashFunction, msgHash, msg, hashKey, n)
	if err != nil {
		return false
	}
	//-----------------------
	// Verify signature
	//-----------------------

	// Prepare Address
	misc.SetOTSAddr(&otsAddr, idx)
	// Check WOTS signature
	wotsPKFromSig(hashFunction, wotsPK, sigMsg[sigMsgOffset:], msgHash, wotsParams, pubSeed, &otsAddr)

	sigMsgOffset += wotsParams.keySize

	// Compute Ltree
	misc.SetLTreeAddr(&lTreeAddr, idx)
	lTree(hashFunction, wotsParams, pkHash, wotsPK, pubSeed, &lTreeAddr)

	// Compute root
	validateAuthPath(hashFunction, root, pkHash, idx, sigMsg[sigMsgOffset:], n, h, pubSeed, &nodeAddr)

	for i := uint32(0); i < n; i++ {
		if root[i] != pk[i] {
			return false
		}
	}

	return true
}

func validateAuthPath(hashFunc HashFunction, root, leaf []uint8, leafIdx uint32, authpath []uint8, n, h uint32, pub_seed []uint8, addr *[8]uint32) {

	buffer := make([]uint8, 2*n)

	// If leafidx is odd (last bit = 1), current path element is a right child and authpath has to go to the left.
	// Otherwise, it is the other way around
	if leafIdx&1 == 1 {
		for j := uint32(0); j < n; j++ {
			buffer[n+j] = leaf[j]
		}
		for j := uint32(0); j < n; j++ {
			buffer[j] = authpath[j]
		}
	} else {
		for j := uint32(0); j < n; j++ {
			buffer[j] = leaf[j]
		}
		for j := uint32(0); j < n; j++ {
			buffer[n+j] = authpath[j]
		}
	}
	authPathOffset := n

	for i := uint32(0); i < h-1; i++ {
		misc.SetTreeHeight(addr, i)
		leafIdx >>= 1
		misc.SetTreeIndex(addr, leafIdx)
		if leafIdx&1 == 1 {
			hashH(hashFunc, buffer[n:n+n], buffer, pub_seed, addr, n)
			for j := uint32(0); j < n; j++ {
				buffer[j] = authpath[authPathOffset+j]
			}
		} else {
			hashH(hashFunc, buffer[:n], buffer, pub_seed, addr, n)
			for j := uint32(0); j < n; j++ {
				buffer[j+n] = authpath[authPathOffset+j]
			}
		}
		authPathOffset += n
	}
	misc.SetTreeHeight(addr, h-1)
	leafIdx >>= 1
	misc.SetTreeIndex(addr, leafIdx)
	hashH(hashFunc, root[:n], buffer, pub_seed, addr, n)
}

func wotsPKFromSig(hashfunction HashFunction, pk, sig, msg []uint8, wotsParams *WOTSParams, pubSeed []uint8, addr *[8]uint32) {
	XMSSWOTSLEN := wotsParams.len
	XMSSWOTSLEN1 := wotsParams.len1
	XMSSWOTSLEN2 := wotsParams.len2
	XMSSWOTSLOGW := wotsParams.logW
	XMSSWOTSW := wotsParams.w
	XMSSN := wotsParams.n

	baseW := make([]uint8, XMSSWOTSLEN)
	cSum := uint32(0)
	cSumBytes := make([]uint8, ((XMSSWOTSLEN2*XMSSWOTSLOGW)+7)/8)
	cSumBaseW := make([]uint8, XMSSWOTSLEN2)

	calcBaseW(baseW, XMSSWOTSLEN1, msg, wotsParams)

	for i := uint32(0); i < XMSSWOTSLEN1; i++ {
		cSum += XMSSWOTSW - 1 - uint32(baseW[i])
	}

	cSum = cSum << (8 - ((XMSSWOTSLEN2 * XMSSWOTSLOGW) % 8))

	misc.ToByteLittleEndian(cSumBytes, cSum, ((XMSSWOTSLEN2*XMSSWOTSLOGW)+7)/8)
	calcBaseW(cSumBaseW, XMSSWOTSLEN2, cSumBytes, wotsParams)

	for i := uint32(0); i < XMSSWOTSLEN2; i++ {
		baseW[XMSSWOTSLEN1+i] = cSumBaseW[i]
	}
	for i := uint32(0); i < XMSSWOTSLEN; i++ {
		misc.SetChainAddr(addr, i)
		offset := i * XMSSN
		genChain(hashfunction, pk[offset:offset+XMSSN], sig[offset:offset+XMSSN], uint32(baseW[i]), XMSSWOTSW-1-uint32(baseW[i]), wotsParams, pubSeed, addr)
	}
}

func calcBaseW(output []uint8, outputLen uint32, input []uint8, params *WOTSParams) {
	in := 0
	out := 0
	total := uint32(0)
	bits := uint32(0)

	for consumed := uint32(0); consumed < outputLen; consumed++ {
		if bits == 0 {
			total = uint32(input[in])
			in++
			bits += 8
		}
		bits -= params.logW
		output[out] = uint8((total >> bits) & (params.w - 1))
		out++
	}
}

func calculateSignatureBaseSize(keySize uint32) uint32 {
	return 4 + 32 + keySize
}

func getSignatureSize(params *XMSSParams) uint32 {
	signatureBaseSize := calculateSignatureBaseSize(params.wotsParams.keySize)
	return signatureBaseSize + params.h*32
}

func hMsg(hashFunction HashFunction, out, in, key []uint8, n uint32) error {
	if uint32(len(key)) != 3*n {
		return fmt.Errorf("H_msg takes 3n-bit keys, we got n=%d but a keylength of %d.\n", n, len(key))
	}
	coreHash(hashFunction, out, 2, key, uint32(len(key)), in, uint32(len(in)), n)
	return nil
}
