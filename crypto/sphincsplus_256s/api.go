package sphincsplus_256s

import (
	"crypto/rand"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

func cryptoSignSeedKeypair(pk, sk []byte, seed []byte) error {
	if len(seed) != CRYPTO_SEEDBYTES {
		//coverage:ignore
		//rationale: All callers use fixed-size [CRYPTO_SEEDBYTES] arrays converted to slices
		return cryptoerrors.ErrInvalidSeed
	}
	copy(sk[:CRYPTO_SEEDBYTES], seed)

	copy(pk, sk[2*params.SPX_N:3*params.SPX_N]) // PUB_SEED

	ctx := &SPXCtx{}
	copy(ctx.PubSeed[:], pk[:params.SPX_N])
	copy(ctx.SkSeed[:], sk[:params.SPX_N])

	MerkleGenRoot(sk[3*params.SPX_N:], ctx)
	copy(pk[params.SPX_N:], sk[3*params.SPX_N:])

	return nil
}

func cryptoSignKeypair(pk, sk []byte, seed [CRYPTO_SEEDBYTES]byte) error {
	if len(pk) != CRYPTO_PUBLICKEYBYTES || len(sk) != CRYPTO_SECRETKEYBYTES {
		//coverage:ignore
		//rationale: All callers use fixed-size arrays with correct sizes
		return cryptoerrors.ErrBufferTooSmall
	}
	return cryptoSignSeedKeypair(pk, sk, seed[:])
}

func generateOptrand(optRand []byte) error {
	if _, err := rand.Read(optRand); err != nil {
		//coverage:ignore
		//rationale: crypto/rand.Read only fails if system entropy source is broken
		return err
	}
	return nil
}

func cryptoSignSignature(sig []byte, m []byte, sk []byte, generateOptRand func([]byte) error) error {
	var ctx SPXCtx

	skPrf := sk[params.SPX_N : 2*params.SPX_N]
	pk := sk[2*params.SPX_N : 4*params.SPX_N]

	optRand := make([]byte, params.SPX_N)
	mHash := make([]byte, params.SPX_FORS_MSG_BYTES)
	root := make([]byte, params.SPX_N)
	var tree uint64
	var idxLeaf uint32
	var wotsAddr [8]uint32
	var treeAddr [8]uint32

	copy(ctx.SkSeed[:], sk[:params.SPX_N])
	copy(ctx.PubSeed[:], pk[:params.SPX_N])

	initializeHashFunction(&ctx)

	setType(&wotsAddr, SPX_ADDR_TYPE_WOTS)
	setType(&treeAddr, SPX_ADDR_TYPE_HASHTREE)

	if err := generateOptRand(optRand); err != nil {
		//coverage:ignore
		//rationale: generateOptRand uses crypto/rand.Read which only fails if system entropy is broken
		return err
	}
	genMessageRandom(sig[:params.SPX_N], skPrf, optRand, m, &ctx)

	// Derive the message digest and tree/leaf index
	hashMessage(mHash, &tree, &idxLeaf, sig[:params.SPX_N], pk, m, &ctx)
	sigOffset := params.SPX_N
	setTreeAddr(&wotsAddr, tree)
	setKeypairAddr(&wotsAddr, idxLeaf)

	forsSign(sig[sigOffset:], root, mHash, &ctx, &wotsAddr)
	sigOffset += params.SPX_FORS_BYTES

	for i := uint32(0); i < SPX_D; i++ {
		setLayerAddr(&treeAddr, i)
		setTreeAddr(&treeAddr, tree)

		copySubtreeAddr(&wotsAddr, &treeAddr)
		setKeypairAddr(&wotsAddr, idxLeaf)
		MerkleSign(sig[sigOffset:], root, &ctx, &wotsAddr, &treeAddr, idxLeaf)
		sigOffset += params.SPX_WOTS_BYTES + params.SPX_TREE_HEIGHT*params.SPX_N

		idxLeaf = uint32(tree & ((1 << params.SPX_TREE_HEIGHT) - 1))
		tree >>= params.SPX_TREE_HEIGHT
	}

	return nil
}

func cryptoSign(m []byte, sk []byte, generateOptRand func([]byte) error) ([]byte, error) {
	sm := make([]byte, params.SPX_BYTES+len(m))
	// Assumes sm is preallocated with at least len(m) + SPX_BYTES bytes
	err := cryptoSignSignature(sm, m, sk, generateOptRand)
	if err != nil {
		//coverage:ignore
		//rationale: cryptoSignSignature only fails if generateOptRand fails (system entropy broken)
		return nil, err
	}

	copy(sm[params.SPX_BYTES:], m)
	return sm, nil
}
