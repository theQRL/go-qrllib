package falcon1024

// modP helpers implement arithmetic over Falcon's auxiliary 31-bit primes used
// by the NTRU/CRT solver. They are intentionally separate from the q-modular
// helpers, which operate modulo Falcon's fixed modulus q = 12289.

func modPSet(x int32, p uint32) uint32 {
	w := uint32(x)
	w += p & -(w >> 31)
	return w
}

func modPNorm(x, p uint32) int32 {
	w := x - (p & -(((p >> 1) - x) >> 31))
	return int32(w)
}

func modPNInv31(p uint32) uint32 {
	y := uint32(2 - p)
	y *= 2 - p*y
	y *= 2 - p*y
	y *= 2 - p*y
	y *= 2 - p*y
	return mask31 & -y
}

func modPR(p uint32) uint32 {
	return (uint32(1) << 31) - p
}

func modPAdd(a, b, p uint32) uint32 {
	d := a + b - p
	d += p & -(d >> 31)
	return d
}

func modPSub(a, b, p uint32) uint32 {
	d := a - b
	d += p & -(d >> 31)
	return d
}

func modPMontyMul(a, b, p, p0i uint32) uint32 {
	z := uint64(a) * uint64(b)
	w := (uint32(z) * p0i) & mask31
	z = (z + uint64(w)*uint64(p)) >> 31
	d := uint32(z) - p
	d += p & -(d >> 31)
	return d
}

func modPR2(p, p0i uint32) uint32 {
	z := modPR(p)
	z = modPAdd(z, z, p)
	z = modPMontyMul(z, z, p, p0i)
	z = modPMontyMul(z, z, p, p0i)
	z = modPMontyMul(z, z, p, p0i)
	z = modPMontyMul(z, z, p, p0i)
	z = modPMontyMul(z, z, p, p0i)
	return (z + (p & -(z & 1))) >> 1
}

func modPRx(x int, p, p0i, r2 uint32) uint32 {
	x--
	r := r2
	z := modPR(p)
	for i := 0; (1 << i) <= x; i++ {
		if x&(1<<i) != 0 {
			z = modPMontyMul(z, r, p, p0i)
		}
		r = modPMontyMul(r, r, p, p0i)
	}
	return z
}

func modPDiv(a, b, p, p0i, r uint32) uint32 {
	e := p - 2
	z := r
	for i := 30; i >= 0; i-- {
		z = modPMontyMul(z, z, p, p0i)
		z2 := modPMontyMul(z, b, p, p0i)
		z ^= (z ^ z2) & -((e >> i) & 1)
	}
	z = modPMontyMul(z, 1, p, p0i)
	return modPMontyMul(a, z, p, p0i)
}

func modPMkgm2(gm, igm []uint32, logn int, primitiveRoot, p, p0i uint32) {
	degree := 1 << logn
	r2 := modPR2(p, p0i)
	g := modPMontyMul(primitiveRoot, r2, p, p0i)
	for k := logn; k < 10; k++ {
		g = modPMontyMul(g, g, p, p0i)
	}

	r := modPR(p)
	ig := modPDiv(r2, g, p, p0i, r)
	x1 := r
	x2 := r
	k := 10 - logn
	for i := range degree {
		j := int(rev10[i]) >> k
		gm[j] = x1
		igm[j] = x2
		x1 = modPMontyMul(x1, g, p, p0i)
		x2 = modPMontyMul(x2, ig, p, p0i)
	}
}

func modPNTT2Ext(a []uint32, stride int, gm []uint32, logn int, p, p0i uint32) {
	if logn == 0 {
		return
	}

	degree := 1 << logn
	t := degree
	for m := 1; m < degree; m <<= 1 {
		ht := t >> 1
		for i, v1 := 0, 0; i < m; i, v1 = i+1, v1+t {
			s := gm[m+i]
			r1 := v1 * stride
			r2 := r1 + ht*stride
			for range ht {
				x := a[r1]
				y := modPMontyMul(a[r2], s, p, p0i)
				a[r1] = modPAdd(x, y, p)
				a[r2] = modPSub(x, y, p)
				r1 += stride
				r2 += stride
			}
		}
		t = ht
	}
}

func modPINTT2Ext(a []uint32, stride int, igm []uint32, logn int, p, p0i uint32) {
	if logn == 0 {
		return
	}

	degree := 1 << logn
	t := 1
	for m := degree; m > 1; m >>= 1 {
		hm := m >> 1
		dt := t << 1
		for i, v1 := 0, 0; i < hm; i, v1 = i+1, v1+dt {
			s := igm[hm+i]
			r1 := v1 * stride
			r2 := r1 + t*stride
			for range t {
				x := a[r1]
				y := a[r2]
				a[r1] = modPAdd(x, y, p)
				a[r2] = modPMontyMul(modPSub(x, y, p), s, p, p0i)
				r1 += stride
				r2 += stride
			}
		}
		t = dt
	}

	ni := uint32(1) << (31 - logn)
	for k, r := 0, 0; k < degree; k, r = k+1, r+stride {
		a[r] = modPMontyMul(a[r], ni, p, p0i)
	}
}

func modPNTT2(a, gm []uint32, logn int, p, p0i uint32) {
	modPNTT2Ext(a, 1, gm, logn, p, p0i)
}

func modPINTT2(a, igm []uint32, logn int, p, p0i uint32) {
	modPINTT2Ext(a, 1, igm, logn, p, p0i)
}

func modPPolyRecRes(f []uint32, logn int, p, p0i, r2 uint32) {
	hn := 1 << (logn - 1)
	for i := range hn {
		f[i] = modPMontyMul(modPMontyMul(f[i<<1], f[(i<<1)+1], p, p0i), r2, p, p0i)
	}
}
