package falcon1024

// zint values are little-endian arrays of 31-bit limbs. Callers own scratch
// allocation and length invariants; these helpers assume correctly sized
// buffers and keep limbs reduced under mask31.
const (
	mask31    = 0x7FFFFFFF
	signBit31 = 1 << 30 // sign bit of a 31-bit two's-complement limb
)

func zintSub(a, b []uint32, ctl uint32) uint32 {
	var cc uint32
	m := -ctl
	for i := range a {
		aw := a[i]
		w := aw - b[i] - cc
		cc = w >> 31
		a[i] = aw ^ (((w & mask31) ^ aw) & m)
	}
	return cc
}

func zintMulSmall(m []uint32, x uint32) uint32 {
	var cc uint32
	for i := range m {
		z := uint64(m[i])*uint64(x) + uint64(cc)
		m[i] = uint32(z) & mask31
		cc = uint32(z >> 31)
	}
	return cc
}

func zintModSmallUnsigned(d []uint32, p, p0i, r2 uint32) uint32 {
	var x uint32
	for i := len(d); i > 0; {
		i--
		x = modPMontyMul(x, r2, p, p0i)
		w := d[i] - p
		w += p & -(w >> 31)
		x = modPAdd(x, w, p)
	}
	return x
}

func zintModSmallSigned(d []uint32, p, p0i, r2, rx uint32) uint32 {
	if len(d) == 0 {
		return 0
	}
	z := zintModSmallUnsigned(d, p, p0i, r2)
	return modPSub(z, rx&-(d[len(d)-1]>>30), p)
}

func zintAddMulSmall(x, y []uint32, s uint32) {
	var cc uint32
	for i := range y {
		z := uint64(y[i])*uint64(s) + uint64(x[i]) + uint64(cc)
		x[i] = uint32(z) & mask31
		cc = uint32(z >> 31)
	}
	x[len(y)] = cc
}

func zintNormZero(x, p []uint32) {
	var r, bb uint32
	for i := len(x); i > 0; {
		i--
		wx := x[i]
		wp := (p[i] >> 1) | (bb << 30)
		bb = p[i] & 1
		cc := wp - wx
		cc = ((-cc) >> 31) | -(cc >> 31)
		r |= cc & ((r & 1) - 1)
	}
	zintSub(x, p, r>>31)
}

func zintRebuildCRT(xx []uint32, xlen, xstride, count int, primes []smallPrime, normalizeSigned bool, tmp []uint32) {
	tmp[0] = primes[0].p

	for u := 1; u < xlen; u++ {
		p := primes[u].p
		s := primes[u].s
		p0i := smallPrimeDerivedValues[u].p0i
		r2 := smallPrimeDerivedValues[u].r2

		for v := range count {
			x := xx[v*xstride : v*xstride+xlen]
			xp := x[u]
			xq := zintModSmallUnsigned(x[:u], p, p0i, r2)
			xr := modPMontyMul(s, modPSub(xp, xq, p), p, p0i)
			zintAddMulSmall(x[:u+1], tmp[:u], xr)
		}

		tmp[u] = zintMulSmall(tmp[:u], p)
	}

	if normalizeSigned {
		for u := range count {
			x := xx[u*xstride : u*xstride+xlen]
			zintNormZero(x, tmp[:xlen])
		}
	}
}

func zintNegate(a []uint32, ctl uint32) {
	cc := ctl
	m := -ctl >> 1
	for i := range a {
		aw := (a[i] ^ m) + cc
		a[i] = aw & mask31
		cc = aw >> 31
	}
}

func zintCoReduce(a, b []uint32, xa, xb, ya, yb int64) uint32 {
	var cca, ccb int64
	for i := range a {
		wa := a[i]
		wb := b[i]
		za := uint64(wa)*uint64(xa) + uint64(wb)*uint64(xb) + uint64(cca)
		zb := uint64(wa)*uint64(ya) + uint64(wb)*uint64(yb) + uint64(ccb)
		if i > 0 {
			a[i-1] = uint32(za) & mask31
			b[i-1] = uint32(zb) & mask31
		}
		cca = int64(za) >> 31
		ccb = int64(zb) >> 31
	}
	a[len(a)-1] = uint32(cca)
	b[len(b)-1] = uint32(ccb)

	nega := uint32(uint64(cca) >> 63)
	negb := uint32(uint64(ccb) >> 63)
	zintNegate(a, nega)
	zintNegate(b, negb)
	return nega | (negb << 1)
}

func zintFinishMod(a, m []uint32, neg uint32) {
	var cc uint32
	for i := range a {
		cc = (a[i] - m[i] - cc) >> 31
	}

	xm := -neg >> 1
	ym := -(neg | (1 - cc))
	cc = neg
	for i := range a {
		mw := (m[i] ^ xm) & ym
		aw := a[i] - mw - cc
		a[i] = aw & mask31
		cc = aw >> 31
	}
}

func zintCoReduceMod(a, b, m []uint32, m0i uint32, xa, xb, ya, yb int64) {
	var cca, ccb int64
	fa := ((a[0]*uint32(xa) + b[0]*uint32(xb)) * m0i) & mask31
	fb := ((a[0]*uint32(ya) + b[0]*uint32(yb)) * m0i) & mask31
	for i := range a {
		wa := a[i]
		wb := b[i]
		za := uint64(wa)*uint64(xa) + uint64(wb)*uint64(xb) + uint64(m[i])*uint64(fa) + uint64(cca)
		zb := uint64(wa)*uint64(ya) + uint64(wb)*uint64(yb) + uint64(m[i])*uint64(fb) + uint64(ccb)
		if i > 0 {
			a[i-1] = uint32(za) & mask31
			b[i-1] = uint32(zb) & mask31
		}
		cca = int64(za) >> 31
		ccb = int64(zb) >> 31
	}
	a[len(a)-1] = uint32(cca)
	b[len(b)-1] = uint32(ccb)

	zintFinishMod(a, m, uint32(uint64(cca)>>63))
	zintFinishMod(b, m, uint32(uint64(ccb)>>63))
}

func zintBezout(u, v, x, y []uint32, tmp []uint32) bool {
	length := len(x)
	if length == 0 {
		return false
	}

	u0 := u
	v0 := v
	u1 := tmp[:length]
	v1 := tmp[length : 2*length]
	a := tmp[2*length : 3*length]
	b := tmp[3*length : 4*length]

	x0i := modPNInv31(x[0])
	y0i := modPNInv31(y[0])

	copy(a, x)
	copy(b, y)
	u0[0] = 1
	clear(u0[1:length])
	clear(v0)
	copy(u1, y)
	copy(v1, x)
	v1[0]--

	for num := uint32(62*length + 30); num >= 30; num -= 30 {
		c0 := ^uint32(0)
		c1 := ^uint32(0)
		var a0, a1, b0, b1 uint32
		for j := length; j > 0; {
			j--
			aw := a[j]
			bw := b[j]
			a0 ^= (a0 ^ aw) & c0
			a1 ^= (a1 ^ aw) & c1
			b0 ^= (b0 ^ bw) & c0
			b1 ^= (b1 ^ bw) & c1
			c1 = c0
			c0 &= (((aw | bw) + mask31) >> 31) - 1
		}

		a1 |= a0 & c1
		a0 &^= c1
		b1 |= b0 & c1
		b0 &^= c1
		aHi := (uint64(a0) << 31) + uint64(a1)
		bHi := (uint64(b0) << 31) + uint64(b1)
		aLo := a[0]
		bLo := b[0]

		pa, pb, qa, qb := int64(1), int64(0), int64(0), int64(1)
		for i := range 31 {
			rz := bHi - aHi
			rt := uint32((rz ^ ((aHi ^ bHi) & (aHi ^ rz))) >> 63)

			oa := (aLo >> i) & 1
			ob := (bLo >> i) & 1
			cAB := oa & ob & rt
			cBA := oa & ob &^ rt
			cA := cAB | (oa ^ 1)

			aLo -= bLo & -cAB
			aHi -= bHi & -uint64(cAB)
			pa -= qa & -int64(cAB)
			pb -= qb & -int64(cAB)
			bLo -= aLo & -cBA
			bHi -= aHi & -uint64(cBA)
			qa -= pa & -int64(cBA)
			qb -= pb & -int64(cBA)

			aLo += aLo & (cA - 1)
			pa += pa & (int64(cA) - 1)
			pb += pb & (int64(cA) - 1)
			aHi ^= (aHi ^ (aHi >> 1)) & -uint64(cA)
			bLo += bLo & -cA
			qa += qa & -int64(cA)
			qb += qb & -int64(cA)
			bHi ^= (bHi ^ (bHi >> 1)) & (uint64(cA) - 1)
		}

		r := zintCoReduce(a, b, pa, pb, qa, qb)
		pa -= (pa + pa) & -int64(r&1)
		pb -= (pb + pb) & -int64(r&1)
		qa -= (qa + qa) & -int64(r>>1)
		qb -= (qb + qb) & -int64(r>>1)
		zintCoReduceMod(u0, u1, y, y0i, pa, pb, qa, qb)
		zintCoReduceMod(v0, v1, x, x0i, pa, pb, qa, qb)
	}

	rc := a[0] ^ 1
	for i := 1; i < length; i++ {
		rc |= a[i]
	}
	return ((1 - ((rc | -rc) >> 31)) & x[0] & y[0]) != 0
}

func zintAddScaledMulSmall(x, y []uint32, k int32, sch, scl uint32) {
	if len(y) == 0 {
		return
	}

	ysign := -(y[len(y)-1] >> 30) >> 1
	var tw uint32
	var cc int32
	for u := int(sch); u < len(x); u++ {
		v := u - int(sch)
		wy := ysign
		if v < len(y) {
			wy = y[v]
		}
		wys := ((wy << scl) & mask31) | tw
		tw = wy >> (31 - scl)

		z := uint64(int64(wys)*int64(k) + int64(x[u]) + int64(cc))
		x[u] = uint32(z) & mask31
		cc = int32(uint32(z >> 31))
	}
}

func zintSubScaled(x, y []uint32, sch, scl uint32) {
	if len(y) == 0 {
		return
	}

	ysign := -(y[len(y)-1] >> 30) >> 1
	var tw, cc uint32
	for u := int(sch); u < len(x); u++ {
		v := u - int(sch)
		wy := ysign
		if v < len(y) {
			wy = y[v]
		}
		wys := ((wy << scl) & mask31) | tw
		tw = wy >> (31 - scl)

		w := x[u] - wys - cc
		x[u] = w & mask31
		cc = w >> 31
	}
}

func zintOneToPlain(x uint32) int32 {
	w := x | ((x & signBit31) << 1)
	return int32(w)
}
