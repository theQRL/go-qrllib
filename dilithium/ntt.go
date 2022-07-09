package dilithium

func ntt(p *[N]uint32) {
	var count, start, j, k uint
	var zeta, t uint32

	k = 1
	for count = 128; count > 0; count >>= 1 {
		for start = 0; start < N; start = j + count {
			zeta = zetas[k]
			k++
			for j = start; j < start+count; j++ {
				t = montgomeryReduce(uint64(zeta) * uint64(p[j+count]))
				p[j+count] = p[j] + 2*Q - t
				p[j] = p[j] + t
			}
		}
	}
}

func invNTTFromInvMont(p *[N]uint32) {
	var count, start, j, k uint
	var zeta, t uint32
	f := uint32(((uint64(MONT) * MONT % Q) * (Q - 1) % Q) * ((Q - 1) >> 8) % Q)

	k = 0
	for count = 1; count < N; count <<= 1 {
		for start = 0; start < N; start = j + count {
			zeta = zetasInv[k]
			k++
			for j = start; j < start+count; j++ {
				t = p[j]
				p[j] = t + p[j+count]
				p[j+count] = t + 256*Q - p[j+count]
				p[j+count] = montgomeryReduce(uint64(zeta) * uint64(p[j+count]))
			}
		}
	}

	for j = 0; j < N; j++ {
		p[j] = montgomeryReduce(uint64(f) * uint64(p[j]))
	}
}
