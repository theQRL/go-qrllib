package dilithium

import (
	"sync"

	"golang.org/x/crypto/sha3"
)

// shake256Pool provides pooled SHAKE256 hashers to reduce allocations
// in high-frequency signing and verification operations.
var shake256Pool = sync.Pool{
	New: func() interface{} {
		return sha3.NewShake256()
	},
}

// getShake256 returns a clean, reset SHAKE256 hasher from the pool.
func getShake256() sha3.ShakeHash {
	h := shake256Pool.Get().(sha3.ShakeHash)
	h.Reset()
	return h
}

// putShake256 returns a SHAKE256 hasher to the pool.
func putShake256(h sha3.ShakeHash) {
	shake256Pool.Put(h)
}
