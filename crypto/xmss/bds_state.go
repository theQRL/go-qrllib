package xmss

type TreeHashInst struct {
	h          uint32
	nextIdx    uint32
	stackUsage uint32
	completed  uint8
	node       []uint8
}

type BDSState struct {
	stack       []uint8
	stackOffset uint32
	stackLevels []uint8
	auth        []uint8
	keep        []uint8
	treeHash    []*TreeHashInst
	retain      []uint8
	nextLeaf    uint32
}

// NewBDSState constructs the BDS traversal state for an XMSS tree of the
// given height.
//
// Returns nil if height <= k. The callers inside this package already
// validate height before reaching here (see InitializeTree and
// XMSSFastGenKeyPair, both of which reject heights outside [2, MaxHeight]
// for WOTSParamK=2). This nil-guard is defense-in-depth for any direct
// caller of the exported constructor: without it, the treeHash allocation
// loop below underflows uint32 when height < k and attempts to allocate
// roughly 4 billion TreeHashInst values, which in practice hangs the
// process. Noted and fixed while remediating TOB-QRLLIB-2.
func NewBDSState(height, n, k uint32) *BDSState {
	if height <= k {
		return nil
	}

	stackOffset := uint32(0)
	stack := make([]uint8, (height+1)*n)
	stackLevels := make([]uint8, height+1)
	auth := make([]uint8, height*n)
	keep := make([]uint8, (height>>1)*n)
	treeHash := make([]*TreeHashInst, 0)
	//thNodes := make([]uint8, (height-k)*n)
	retain := make([]uint8, ((1<<k)-k-1)*n)

	for i := uint32(0); i < height-k; i++ {
		treeHash = append(treeHash, &TreeHashInst{
			h:          0,
			nextIdx:    0,
			stackUsage: 0,
			completed:  0,
			node:       make([]uint8, n),
		})
	}

	return &BDSState{
		stack:       stack,
		stackOffset: stackOffset,
		stackLevels: stackLevels,
		auth:        auth,
		keep:        keep,
		treeHash:    treeHash,
		retain:      retain,
		nextLeaf:    0,
	}
}
