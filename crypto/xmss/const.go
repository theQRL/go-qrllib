package xmss

const (
	offsetIDX     = 0
	offsetSKSeed  = offsetIDX + 4
	offsetSKPRF   = offsetSKSeed + 32
	offsetPubSeed = offsetSKPRF + 32
	offsetRoot    = offsetPubSeed + 32
)

const (
	MaxHeight = 30 // MaxHeight set to 30, as lastNode datatype is uint32 anything more than height 30 will result into overflow
)
