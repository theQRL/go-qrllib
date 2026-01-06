package ml_dsa_87

import "github.com/theQRL/go-qrllib/crypto/internal/lattice"

func ntt(a *[N]int32) {
	lattice.NTT(a)
}

func invNTTToMont(a *[N]int32) {
	lattice.InvNTTToMont(a)
}
