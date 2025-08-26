package sphincsplus_256s

import "github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"

type Context struct {
	PubSeed [params.SPX_N]byte
	SkSeed  [params.SPX_N]byte
	// Add more fields as needed for hash state, etc.
}
