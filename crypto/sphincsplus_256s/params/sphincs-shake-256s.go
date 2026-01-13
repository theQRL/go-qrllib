package params

const (
	SPX_N              = 32
	SPX_FULL_HEIGHT    = 64
	SPX_D              = 8
	SPX_FORS_HEIGHT    = 14
	SPX_FORS_TREES     = 22
	SPX_WOTS_W         = 16
	SPX_ADDR_BYTES     = 32
	SPX_WOTS_LOGW      = 4
	SPX_WOTS_LEN1      = 8 * SPX_N / SPX_WOTS_LOGW
	SPX_WOTS_LEN2      = 3
	SPX_WOTS_LEN       = SPX_WOTS_LEN1 + SPX_WOTS_LEN2
	SPX_WOTS_BYTES     = SPX_WOTS_LEN * SPX_N
	SPX_WOTS_PK_BYTES  = SPX_WOTS_BYTES
	SPX_TREE_HEIGHT    = SPX_FULL_HEIGHT / SPX_D
	SPX_FORS_MSG_BYTES = (SPX_FORS_HEIGHT*SPX_FORS_TREES + 7) / 8
	SPX_FORS_BYTES     = (SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N
	SPX_FORS_PK_BYTES  = SPX_N
	SPX_BYTES          = SPX_N + SPX_FORS_BYTES + SPX_D*SPX_WOTS_BYTES + SPX_FULL_HEIGHT*SPX_N
	SPX_PK_BYTES       = 2 * SPX_N
	SPX_SK_BYTES       = 2*SPX_N + SPX_PK_BYTES
)

// shake offset
const (
	SPX_OFFSET_LAYER      = 3
	SPX_OFFSET_TREE       = 8
	SPX_OFFSET_TYPE       = 19
	SPX_OFFSET_KP_ADDR    = 20
	SPX_OFFSET_CHAIN_ADDR = 27
	SPX_OFFSET_HASH_ADDR  = 31
	SPX_OFFSET_TREE_HGT   = 27
	SPX_OFFSET_TREE_INDEX = 28
	SPX_SHAKE             = 1
)

// ValidateParams checks that SPHINCS+ parameters are consistent.
// Returns an error describing the first invalid parameter found, or nil if all valid.
func ValidateParams(wotsW, n, treeHeight, d, fullHeight int) error {
	if wotsW != 16 {
		return &ParamError{"SPX_WOTS_W", wotsW, 16}
	}
	if n != 32 {
		return &ParamError{"SPX_N", n, 32}
	}
	if treeHeight*d != fullHeight {
		return &ParamError{"SPX_TREE_HEIGHT*SPX_D", treeHeight * d, fullHeight}
	}
	return nil
}

// ParamError represents an invalid parameter configuration.
type ParamError struct {
	Param    string
	Got      int
	Expected int
}

func (e *ParamError) Error() string {
	return e.Param + " must be " + string(rune('0'+e.Expected))
}

func init() {
	//coverage:ignore
	if err := ValidateParams(SPX_WOTS_W, SPX_N, SPX_TREE_HEIGHT, SPX_D, SPX_FULL_HEIGHT); err != nil {
		//coverage:ignore
		panic(err.Error())
	}
}
