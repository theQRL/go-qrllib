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

// SeedSize is the required length in bytes of the caller-supplied seed
// for the QRL pre-standardisation derivation convention: exactly 48
// bytes, SHAKE256-expanded into the 96 bytes of randomness
// (SK_SEED || SK_PRF || PUB_SEED) the construction consumes. Other
// lengths are rejected at the API boundary rather than silently
// expanded with less entropy than the caller believes.
const SeedSize = 48
