package ml_dsa_87

import (
	"crypto/sha3"
	"sync"
)

// shake256Pool provides pooled SHAKE256 hashers to reduce allocations
// in high-frequency signing and verification operations.
var shake256Pool = sync.Pool{
	New: func() interface{} {
		return sha3.NewSHAKE256()
	},
}

// getShake256 returns a clean, reset SHAKE256 hasher from the pool.
func getShake256() *sha3.SHAKE {
	h := shake256Pool.Get().(*sha3.SHAKE)
	h.Reset()
	return h
}

// putShake256 resets a SHAKE256 hasher and returns it to the pool.
//
// The Reset is a security measure: the signing path absorbs secret key
// material through pooled states, and without a wipe-on-put that
// secret-derived sponge state would linger in the pool indefinitely.
// getShake256's Reset-on-Get is kept as defence-in-depth.
func putShake256(h *sha3.SHAKE) {
	h.Reset()
	shake256Pool.Put(h)
}
