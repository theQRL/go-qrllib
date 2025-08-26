package sphincsplus_256s

import "github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"

type SPXCtx struct {
	PubSeed [params.SPX_N]byte
	SkSeed  [params.SPX_N]byte
}
