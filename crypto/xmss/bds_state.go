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

func NewBDSState(height, n, k uint32) *BDSState {
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
