package sphincsplus_256s

import "github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"

const (
	SPX_D                 = 8
	CRYPTO_SECRETKEYBYTES = params.SPX_SK_BYTES
	CRYPTO_PUBLICKEYBYTES = params.SPX_PK_BYTES
	CRYPTO_BYTES          = params.SPX_BYTES
	CRYPTO_SEEDBYTES      = 3 * params.SPX_N
)
