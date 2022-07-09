package xmss

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/theQRL/go-qrllib/misc"
	"math/rand"
)

type HashFunction uint

const (
	SHA2_256 HashFunction = iota
	SHAKE_128
	SHAKE_256
)

const (
	offsetIDX     = 0
	offsetSKSeed  = offsetIDX + 4
	offsetSKPRF   = offsetSKSeed + 32
	offsetPubSeed = offsetSKPRF + 32
	offsetRoot    = offsetPubSeed + 32
)

const (
	XMSSMaxHeight = 254
)

const (
	XMSSAddressSize = 39
)

type XMSS struct {
	xmssParams   *XMSSParams
	hashFunction HashFunction
	//addrFormatType eAddrFormatType  // not needed as there is only 1 type
	height uint8
	sk     []uint8
	seed   [48]uint8

	/*
		bds_state _state;
		    unsigned int _stackoffset = 0;
		    std::vector<unsigned char> _stack;
		    std::vector<unsigned char> _stacklevels;
		    std::vector<unsigned char> _auth;

		    std::vector<unsigned char> _keep;
		    std::vector<treehash_inst> _treehash;
		    std::vector<unsigned char> _th_nodes;
		    std::vector<unsigned char> _retain;
	*/

	bdsState *BDSState
	desc     *QRLDescriptor
	//stackOffset uint32
	//stack       []uint8
	//stackLevels []uint8
	//auth        []uint8
	//
	//keep     []uint8
	//treeHash []*TreeHashInst
	//thNodes  []uint8
	//retain   []uint8
}

func NewXMSSFromSeed(seed [48]uint8, height uint8, hashFunction HashFunction, addrFormatType AddrFormatType) *XMSS {
	signatureType := XMSSSig // Signature Type hard coded for now
	if height > XMSSMaxHeight {
		panic("Height should be <= 254")
	}
	desc := NewQRLDescriptor(height, hashFunction, signatureType, addrFormatType)

	return initializeTree(desc, seed)
}

func NewXMSSFromExtendedSeed(extendedSeed [51]uint8) *XMSS {
	desc := NewQRLDescriptorFromExtendedSeed(extendedSeed)

	var seed [48]uint8
	copy(seed[:], extendedSeed[DescriptorSize:])

	return initializeTree(desc, seed)
}

func NewXMSSFromHeight(height uint8, hashFunction HashFunction) *XMSS {
	var seed [48]uint8
	rand.Read(seed[:])
	return NewXMSSFromSeed(seed, height, hashFunction, SHA256_2X)
}

func initializeTree(desc *QRLDescriptor, seed [48]uint8) *XMSS {
	height := uint32(desc.GetHeight())
	hashFunction := desc.GetHashFunction()
	sk := make([]uint8, 132)
	pk := make([]uint8, 64)

	k := WOTSParamK
	w := WOTSParamW
	n := WOTSParamN

	if k >= height || (height-k)%2 == 1 {
		panic("For BDS traversal, H - K must be even, with H > K >= 2!")
	}

	xmssParams := NewXMSSParams(n, height, w, k)

	bdsState := NewBDSState(height, n, k)

	XMSSFastGenKeyPair(hashFunction, xmssParams, pk, sk, bdsState, seed)
	return &XMSS{
		xmssParams,
		hashFunction,
		uint8(height),
		sk,
		seed,

		bdsState,
		desc,
	}
}

func (x *XMSS) SetIndex(newIndex uint32) {
	xmssFastUpdate(x.hashFunction, x.xmssParams, x.sk, x.bdsState, newIndex)
}

func (x *XMSS) GetHeight() uint8 {
	return x.height
}

func (x *XMSS) GetPKSeed() []uint8 {
	return x.sk[offsetPubSeed : offsetPubSeed+32]
}

func (x *XMSS) GetSeed() [48]uint8 {
	return x.seed
}

func (x *XMSS) GetExtendedSeed() [51]uint8 {
	var extendedSeed [51]uint8
	descBytes := x.desc.GetBytes()
	seed := x.GetSeed()
	copy(extendedSeed[:3], descBytes[:])
	copy(extendedSeed[3:], seed[:])
	return extendedSeed
}

func (x *XMSS) GetHexSeed() string {
	eSeed := x.GetExtendedSeed()
	return hex.EncodeToString(eSeed[:])
}

func (x *XMSS) GetMnemonic() string {
	return misc.BinToMnemonic(x.GetExtendedSeed())
}

func (x *XMSS) GetRoot() []uint8 {
	return x.sk[offsetRoot : offsetRoot+32]
}

func (x *XMSS) GetPK() [67]uint8 {
	//    PK format
	//     3 QRL_DESCRIPTOR
	//    32 root address
	//    32 pub_seed

	desc := x.desc.GetBytes()
	root := x.GetRoot()
	pubSeed := x.GetPKSeed()

	var output [67]uint8
	offset := 0
	for i := 0; i < len(desc); i++ {
		output[i] = desc[i]
	}
	offset += len(desc)
	for i := 0; i < len(root); i++ {
		output[offset+i] = root[i]
	}
	offset += len(root)
	for i := 0; i < len(pubSeed); i++ {
		output[offset+i] = pubSeed[i]
	}
	return output
}

func (x *XMSS) GetSK() []uint8 {
	return x.sk
}

func (x *XMSS) GetAddress() [XMSSAddressSize]uint8 {
	return GetXMSSAddressFromPK(x.GetPK())
}

func (x *XMSS) GetIndex() uint32 {
	return (uint32(x.sk[0]) << 24) + (uint32(x.sk[1]) << 16) + (uint32(x.sk[2]) << 8) + uint32(x.sk[3])
}

func (x *XMSS) Sign(message []uint8) ([]uint8, error) {
	index := x.GetIndex()
	x.SetIndex(index)

	return xmssFastSignMessage(x.hashFunction, x.xmssParams, x.sk, x.bdsState, message)
}

func Verify(message, signature []uint8, extendedPK [67]uint8, wotsParamW uint32) (result bool) {
	wotsParam := NewWOTSParams(WOTSParamN, wotsParamW)
	signatureBaseSize := calculateSignatureBaseSize(wotsParam.keySize)
	if uint32(len(signature)) > signatureBaseSize+uint32(XMSSMaxHeight)*32 {
		panic("invalid signature size. Height<=254")
	}

	desc := NewQRLDescriptorFromExtendedPK(&extendedPK)

	if desc.GetSignatureType() != XMSSSig {
		return false
	}

	height := getHeightFromSigSize(uint32(len(signature)), wotsParamW)

	if height == 0 || uint32(desc.GetHeight()) != height {
		return false
	}

	hashFunction := desc.GetHashFunction()

	k := WOTSParamK
	w := wotsParamW
	n := WOTSParamN

	if k >= height || (height-k)%2 == 1 {
		panic("For BDS traversal, H - K must be even, with H > K >= 2!")
	}

	params := NewXMSSParams(n, height, w, k)

	tmp := signature

	return xmssVerifySig(hashFunction,
		params.wotsParams,
		message,
		tmp,
		extendedPK[DescriptorSize:],
		height)
}

func xmssVerifySig(hashFunction HashFunction, wotsParams *WOTSParams, msg, sigMsg, pk []uint8, h uint32) bool {

	sigMsgOffset := uint32(0)

	n := wotsParams.n

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

	CalcBaseW(baseW, XMSSWOTSLEN1, msg, wotsParams)

	for i := uint32(0); i < XMSSWOTSLEN1; i++ {
		cSum += XMSSWOTSW - 1 - uint32(baseW[i])
	}

	cSum = cSum << (8 - ((XMSSWOTSLEN2 * XMSSWOTSLOGW) % 8))

	misc.ToByteLittleEndian(cSumBytes, cSum, ((XMSSWOTSLEN2*XMSSWOTSLOGW)+7)/8)
	CalcBaseW(cSumBaseW, XMSSWOTSLEN2, cSumBytes, wotsParams)

	for i := uint32(0); i < XMSSWOTSLEN2; i++ {
		baseW[XMSSWOTSLEN1+i] = cSumBaseW[i]
	}
	for i := uint32(0); i < XMSSWOTSLEN; i++ {
		misc.SetChainAddr(addr, i)
		offset := i * XMSSN
		genChain(hashfunction, pk[offset:offset+XMSSN], sig[offset:offset+XMSSN], uint32(baseW[i]), XMSSWOTSW-1-uint32(baseW[i]), wotsParams, pubSeed, addr)
	}
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

func wotsSign(hashFunction HashFunction, sig, msg, sk []uint8, params *WOTSParams, pubSeed []uint8, addr *[8]uint32) {
	baseW := make([]uint8, params.len)
	csum := uint32(0)

	CalcBaseW(baseW, params.len1, msg, params)

	for i := uint32(0); i < params.len1; i++ {
		csum += params.w - 1 - uint32(baseW[i])
	}

	csum = csum << (8 - ((params.len2 * params.logW) % 8))

	len2Bytes := ((params.len2 * params.logW) + 7) / 8

	cSumBytes := make([]uint8, len2Bytes)
	misc.ToByteLittleEndian(cSumBytes, csum, len2Bytes)

	cSumBaseW := make([]uint8, params.len2)

	CalcBaseW(cSumBaseW, params.len2, cSumBytes, params)

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

func CalcBaseW(output []uint8, outputLen uint32, input []uint8, params *WOTSParams) {
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

func getHeightFromSigSize(sigSize, wotsParamW uint32) uint32 {
	wotsParam := NewWOTSParams(WOTSParamN, wotsParamW)
	signatureBaseSize := calculateSignatureBaseSize(wotsParam.keySize)
	if sigSize < signatureBaseSize {
		panic("Invalid signature size")
	}

	if (sigSize-4)%32 != 0 {
		panic("Invalid signature size")
	}

	return (sigSize - signatureBaseSize) / 32
}

func hMsg(hashFunction HashFunction, out, in, key []uint8, n uint32) error {
	if uint32(len(key)) != 3*n {
		return errors.New(fmt.Sprintf("H_msg takes 3n-bit keys, we got n=%d but a keylength of %d.\n", n, len(key)))
	}
	coreHash(hashFunction, out, 2, key, uint32(len(key)), in, uint32(len(in)), n)
	return nil
}

func GetXMSSAddressFromPK(ePK [67]uint8) [XMSSAddressSize]uint8 {
	desc := NewQRLDescriptorFromExtendedPK(&ePK)

	if desc.GetAddrFormatType() != SHA256_2X {
		panic("Address format type not supported")
	}

	var address [XMSSAddressSize]uint8
	addressOffset := 0
	descBytes := desc.GetBytes()

	for i := 0; i < len(descBytes); i++ {
		address[i] = descBytes[i]
	}
	addressOffset += len(descBytes)

	var hashedKey [32]uint8
	misc.SHA256(hashedKey[:], ePK[:])
	for i := 0; i < len(hashedKey); i++ {
		address[addressOffset+i] = hashedKey[i]
	}
	addressOffset += len(hashedKey)

	var hashedKey2 [32]uint8
	misc.SHA256(hashedKey2[:], address[:addressOffset])
	hashedKey2Offset := len(hashedKey2) - 4

	for i := 0; i < 4; i++ {
		address[addressOffset+i] = hashedKey2[hashedKey2Offset+i]
	}

	return address
}
