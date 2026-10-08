package ml_dsa_87

import "github.com/theQRL/go-qrllib/crypto/ml_dsa_87"

// Sizes in bytes of the packed public key, packed secret key, and detached
// signature. They equal the corresponding crypto/ml_dsa_87 constants.
const (
	PKSize  = ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES
	SKSize  = ml_dsa_87.CRYPTO_SECRET_KEY_BYTES
	SigSize = ml_dsa_87.CRYPTO_BYTES
)
