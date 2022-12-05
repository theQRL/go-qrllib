package dilithium

func ntt(a *[N]int32) {
	var count, start, j, k uint
	var zeta, t int32

	k = 0
	for count = 128; count > 0; count >>= 1 {
		for start = 0; start < N; start = j + count {
			k++
			zeta = zetas[k]
			for j = start; j < start+count; j++ {
				t = montgomeryReduce(int64(zeta) * int64(a[j+count]))
				a[j+count] = a[j] - t
				a[j] = a[j] + t
			}
		}
	}
}

func invNTTToMont(a *[N]int32) {
	var count, start, j, k uint
	var zeta, t int32
	f := int32(41978)

	k = 256
	for count = 1; count < N; count <<= 1 {
		for start = 0; start < N; start = j + count {
			k--
			zeta = -zetas[k]
			for j = start; j < start+count; j++ {
				t = a[j]
				a[j] = t + a[j+count]
				a[j+count] = t - a[j+count]
				a[j+count] = montgomeryReduce(int64(zeta) * int64(a[j+count]))
			}
		}
	}

	for j = 0; j < N; j++ {
		a[j] = montgomeryReduce(int64(f) * int64(a[j]))
	}
}
