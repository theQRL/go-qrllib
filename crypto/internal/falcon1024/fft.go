package falcon1024

import (
	"math"
	"math/bits"
)

type fprTree [(logN + 1) * n]fpr

// FFT values store N/2 complex coefficients as split real/imaginary halves:
// f[0:N/2] are real parts and f[N/2:N] are imaginary parts.
type fftPolynomial [n]fpr

// fftFromSmall converts a small polynomial to floating-point in place at dst,
// then runs an in-place forward FFT. dst must hold n elements.
func fftFromSmall(dst []fpr, src smallPolynomial) {
	for i := range src {
		dst[i] = fpr(src[i])
	}
	fft(dst, logN)
}

type uint72 struct {
	hi byte
	lo uint64
}

var (
	fftGMRe, fftGMIm = initFFTGM()
	invSigma         = [...]fpr{
		0,
		0.00690547932959408896,
		0.00681022677671779767,
		0.00671881019107227126,
		0.00658833543700736678,
		0.00646517812076029003,
		0.00634867888280789966,
		0.00623825865290843738,
		0.00613340650209302611,
		0.00603366966815772378,
		0.00593864530953311636,
	}
	// 72-bit CDT bounds for Falcon's half-Gaussian sampler.
	gaussian0CDF = [...]uint72{
		{hi: 0x00, lo: 0x0000000000000000},
		{hi: 0x00, lo: 0x00000000000000c5},
		{hi: 0x00, lo: 0x0000000000007097},
		{hi: 0x00, lo: 0x00000000002f5d7d},
		{hi: 0x00, lo: 0x000000000ebf6eba},
		{hi: 0x00, lo: 0x00000003665da997},
		{hi: 0x00, lo: 0x000000949f8b091e},
		{hi: 0x00, lo: 0x000012cf24d031fa},
		{hi: 0x00, lo: 0x0001c3fdb2040c68},
		{hi: 0x00, lo: 0x001f80d88a7b6427},
		{hi: 0x00, lo: 0x01a1ffdc65ad63d9},
		{hi: 0x00, lo: 0x1024dd542b776ae3},
		{hi: 0x00, lo: 0x774ac754ed74bd5e},
		{hi: 0x02, lo: 0x95846caef33f1f6e},
		{hi: 0x0a, lo: 0xd1754377c7994ae3},
		{hi: 0x22, lo: 0x7dcdd0934829c1fe},
		{hi: 0x54, lo: 0xd32b181f3f7ddb81},
		{hi: 0xa3, lo: 0xf7f42ed3ac391801},
		{hi: 0xff, lo: 0xffffffffffffffff},
	}
)

func initFFTGM() ([n]fpr, [n]fpr) {
	var re, im [n]fpr
	for j := range n {
		re[j] = fpr(math.Float64frombits(fprGMTabBits[j<<1]))
		im[j] = fpr(math.Float64frombits(fprGMTabBits[(j<<1)+1]))
	}
	return re, im
}

// gaussian0Sample implements the Falcon reference gaussian0_sampler over the
// 72-bit half-Gaussian CDT.
func gaussian0Sample(prng *samplerPRNG) int {
	lo := prng.readUint64()
	hi := uint64(prng.readByte())

	var z int
	for _, bound := range gaussian0CDF {
		// bound - sample borrows iff bound < sample. We want the count of
		// entries where bound >= sample, i.e. where there is no borrow.
		_, borrow := bits.Sub64(bound.lo, lo, 0)
		_, borrow = bits.Sub64(uint64(bound.hi), hi, borrow)
		z += int(1 - borrow)
	}
	return z - 1
}

// berExp implements the Falcon reference BerExp rejection step.
func berExp(prng *samplerPRNG, x, ccs fpr) bool {
	s := int(fprTrunc(x * invLog2))
	r := x - fpr(s)*log2

	sw := uint32(s)
	sw ^= (sw ^ 63) & -((63 - sw) >> 31)
	s = int(sw)

	z := ((fprExpmP63(r, ccs) << 1) - 1) >> uint(s)

	i := 64
	var w uint32
	for {
		i -= 8
		w = uint32(prng.readByte()) - (uint32(z>>uint(i)) & 0xFF)
		if w != 0 || i == 0 {
			break
		}
	}
	return w>>31 != 0
}

// sampleFFTPoint samples one Falcon FFT coordinate using the discrete Gaussian
// sampler.
func sampleFFTPoint(prng *samplerPRNG, mu, isigma fpr) fpr {
	s := math.Floor(float64(mu))
	r := mu - fpr(s)
	dss := 0.5 * isigma * isigma
	ccs := sigmaMin1024 * isigma

	for {
		z0 := gaussian0Sample(prng)
		b := int(prng.readByte()) & 1
		z := b + ((b<<1)-1)*z0

		x := fpr(z) - r
		x = x*x*dss - fpr(z0*z0)*inv2SqrSigma0
		if berExp(prng, x, ccs) {
			return fpr(s + float64(z))
		}
	}
}

func ffLDLTreeSize(logn int) int {
	return (logn + 1) << logn
}

func ffLDLFFT(tree, g00, g01, g11 []fpr, logn int, tmp []fpr) {
	degree := 1 << logn
	if degree == 1 {
		tree[0] = g00[0]
		return
	}
	if len(tmp) < 3*degree {
		panic("falcon1024: short ffLDLFFT scratch")
	}

	hn := degree >> 1
	d00 := tmp[:degree]
	d11 := tmp[degree : 2*degree]
	t := tmp[2*degree : 3*degree]

	copy(d00, g00[:degree])
	fftLDLMV(d11, tree[:degree], g00[:degree], g01[:degree], g11[:degree], logn)

	splitFFT(t[:hn], t[hn:degree], d00, logn)
	splitFFT(d00[:hn], d00[hn:degree], d11, logn)
	copy(d11, t)

	ffLDLFFTInner(tree[degree:], d11[:hn], d11[hn:degree], logn-1, t)
	ffLDLFFTInner(tree[degree+ffLDLTreeSize(logn-1):], d00[:hn], d00[hn:degree], logn-1, t)
}

func ffLDLFFTInner(tree, g0, g1 []fpr, logn int, tmp []fpr) {
	degree := 1 << logn
	if degree == 1 {
		tree[0] = g0[0]
		return
	}

	hn := degree >> 1
	fftLDLMV(tmp[:degree], tree[:degree], g0[:degree], g1[:degree], g0[:degree], logn)

	splitFFT(g1[:hn], g1[hn:degree], g0[:degree], logn)
	splitFFT(g0[:hn], g0[hn:degree], tmp[:degree], logn)

	ffLDLFFTInner(tree[degree:], g1[:hn], g1[hn:degree], logn-1, tmp)
	ffLDLFFTInner(tree[degree+ffLDLTreeSize(logn-1):], g0[:hn], g0[hn:degree], logn-1, tmp)
}

func fftLDLMV(d11, l10, g00, g01, g11 []fpr, logn int) {
	hn := 1 << (logn - 1)
	for i := range hn {
		g00Re := g00[i]
		g00Im := g00[i+hn]
		g01Re := g01[i]
		g01Im := g01[i+hn]
		g11Re := g11[i]
		g11Im := g11[i+hn]

		den := g00Re*g00Re + g00Im*g00Im
		muRe := (g01Re*g00Re + g01Im*g00Im) / den
		muIm := (g01Im*g00Re - g01Re*g00Im) / den

		xiRe := muRe*g01Re + muIm*g01Im
		xiIm := muIm*g01Re - muRe*g01Im

		d11[i] = g11Re - xiRe
		d11[i+hn] = g11Im - xiIm
		l10[i] = muRe
		l10[i+hn] = -muIm
	}
}

func ffLDLBinaryNormalize(tree []fpr, origLogn, logn int) {
	degree := 1 << logn
	if degree == 1 {
		tree[0] = fpr(math.Sqrt(float64(tree[0]))) * invSigma[origLogn]
		return
	}

	ffLDLBinaryNormalize(tree[degree:], origLogn, logn-1)
	ffLDLBinaryNormalize(tree[degree+ffLDLTreeSize(logn-1):], origLogn, logn-1)
}

func splitFFT(f0, f1, f []fpr, logn int) {
	degree := 1 << logn
	hn := degree >> 1
	qn := hn >> 1

	f0[0] = f[0]
	f1[0] = f[hn]
	for u := range qn {
		j := u << 1
		aRe := f[j]
		aIm := f[j+hn]
		bRe := f[j+1]
		bIm := f[j+1+hn]

		tRe := aRe + bRe
		tIm := aIm + bIm
		f0[u] = 0.5 * tRe
		f0[u+qn] = 0.5 * tIm

		tRe = aRe - bRe
		tIm = aIm - bIm
		gmRe := fftGMRe[u+hn]
		gmIm := -fftGMIm[u+hn]
		f1[u] = 0.5 * (tRe*gmRe - tIm*gmIm)
		f1[u+qn] = 0.5 * (tRe*gmIm + tIm*gmRe)
	}
}

func mergeFFT(f, f0, f1 []fpr, logn int) {
	degree := 1 << logn
	hn := degree >> 1
	qn := hn >> 1

	f[0] = f0[0]
	f[hn] = f1[0]
	for u := range qn {
		aRe := f0[u]
		aIm := f0[u+qn]
		bRe := f1[u]
		bIm := f1[u+qn]
		gmRe := fftGMRe[u+hn]
		gmIm := fftGMIm[u+hn]
		cRe := bRe*gmRe - bIm*gmIm
		cIm := bRe*gmIm + bIm*gmRe

		j := u << 1
		f[j] = aRe + cRe
		f[j+hn] = aIm + cIm
		f[j+1] = aRe - cRe
		f[j+1+hn] = aIm - cIm
	}
}

// ffSamplingFFTRecursive mirrors the Falcon reference base cases; the
// hand-unrolled logn == 2 path avoids another split/merge recursion.
func ffSamplingFFTRecursive(prng *samplerPRNG, z0, z1, tree, t0, t1, tmp []fpr, logn int) {
	if logn == 2 {
		tree0 := tree[4:]
		tree1 := tree[8:]

		aRe := t1[0]
		aIm := t1[2]
		bRe := t1[1]
		bIm := t1[3]

		cRe := aRe + bRe
		cIm := aIm + bIm
		w0 := 0.5 * cRe
		w1 := 0.5 * cIm

		cRe = aRe - bRe
		cIm = aIm - bIm
		w2 := (cRe + cIm) * invSqrt8
		w3 := (cIm - cRe) * invSqrt8

		x0 := w2
		x1 := w3
		w2 = sampleFFTPoint(prng, x0, tree1[3])
		w3 = sampleFFTPoint(prng, x1, tree1[3])

		aRe = x0 - w2
		aIm = x1 - w3
		bRe = tree1[0]
		bIm = tree1[1]
		cRe = aRe*bRe - aIm*bIm
		cIm = aRe*bIm + aIm*bRe
		x0 = cRe + w0
		x1 = cIm + w1

		w0 = sampleFFTPoint(prng, x0, tree1[2])
		w1 = sampleFFTPoint(prng, x1, tree1[2])

		aRe = w0
		aIm = w1
		bRe = w2
		bIm = w3
		cRe = (bRe - bIm) * invSqrt2
		cIm = (bRe + bIm) * invSqrt2
		z1[0] = aRe + cRe
		z1[2] = aIm + cIm
		z1[1] = aRe - cRe
		z1[3] = aIm - cIm

		w0 = t1[0] - z1[0]
		w1 = t1[1] - z1[1]
		w2 = t1[2] - z1[2]
		w3 = t1[3] - z1[3]

		aRe = w0
		aIm = w2
		bRe = tree[0]
		bIm = tree[2]
		w0 = aRe*bRe - aIm*bIm
		w2 = aRe*bIm + aIm*bRe

		aRe = w1
		aIm = w3
		bRe = tree[1]
		bIm = tree[3]
		w1 = aRe*bRe - aIm*bIm
		w3 = aRe*bIm + aIm*bRe

		w0 += t0[0]
		w1 += t0[1]
		w2 += t0[2]
		w3 += t0[3]

		aRe = w0
		aIm = w2
		bRe = w1
		bIm = w3

		cRe = aRe + bRe
		cIm = aIm + bIm
		w0 = 0.5 * cRe
		w1 = 0.5 * cIm

		cRe = aRe - bRe
		cIm = aIm - bIm
		w2 = (cRe + cIm) * invSqrt8
		w3 = (cIm - cRe) * invSqrt8

		x0 = w2
		x1 = w3
		w2 = sampleFFTPoint(prng, x0, tree0[3])
		w3 = sampleFFTPoint(prng, x1, tree0[3])

		aRe = x0 - w2
		aIm = x1 - w3
		bRe = tree0[0]
		bIm = tree0[1]
		cRe = aRe*bRe - aIm*bIm
		cIm = aRe*bIm + aIm*bRe
		x0 = cRe + w0
		x1 = cIm + w1

		w0 = sampleFFTPoint(prng, x0, tree0[2])
		w1 = sampleFFTPoint(prng, x1, tree0[2])

		aRe = w0
		aIm = w1
		bRe = w2
		bIm = w3
		cRe = (bRe - bIm) * invSqrt2
		cIm = (bRe + bIm) * invSqrt2
		z0[0] = aRe + cRe
		z0[2] = aIm + cIm
		z0[1] = aRe - cRe
		z0[3] = aIm - cIm
		return
	}

	if logn == 1 {
		x0 := t1[0]
		x1 := t1[1]
		z1[0] = sampleFFTPoint(prng, x0, tree[3])
		z1[1] = sampleFFTPoint(prng, x1, tree[3])

		aRe := x0 - z1[0]
		aIm := x1 - z1[1]
		bRe := tree[0]
		bIm := tree[1]
		cRe := aRe*bRe - aIm*bIm
		cIm := aRe*bIm + aIm*bRe

		z0[0] = sampleFFTPoint(prng, cRe+t0[0], tree[2])
		z0[1] = sampleFFTPoint(prng, cIm+t0[1], tree[2])
		return
	}

	if logn == 0 {
		isigma := tree[0]
		z0[0] = sampleFFTPoint(prng, t0[0], isigma)
		z1[0] = sampleFFTPoint(prng, t1[0], isigma)
		return
	}

	degree := 1 << logn
	hn := degree >> 1
	tree0 := tree[degree:]
	tree1 := tree[degree+ffLDLTreeSize(logn-1):]

	splitFFT(z1[:hn], z1[hn:degree], t1[:degree], logn)
	ffSamplingFFTRecursive(prng, tmp[:hn], tmp[hn:degree], tree1, z1[:hn], z1[hn:degree], tmp[degree:], logn-1)
	mergeFFT(z1[:degree], tmp[:hn], tmp[hn:degree], logn)

	copy(tmp[:degree], t1[:degree])
	for i := range degree {
		tmp[i] -= z1[i]
	}
	fftMul(tmp[:degree], tree[:degree], logn)
	for i := range degree {
		tmp[i] += t0[i]
	}

	splitFFT(z0[:hn], z0[hn:degree], tmp[:degree], logn)
	ffSamplingFFTRecursive(prng, tmp[:hn], tmp[hn:degree], tree0, z0[:hn], z0[hn:degree], tmp[degree:], logn-1)
	mergeFFT(z0[:degree], tmp[:hn], tmp[hn:degree], logn)
}

func fft(f []fpr, logn int) {
	if logn == 0 {
		return
	}
	hn := 1 << (logn - 1)
	t := hn
	for u, m := 1, 2; u < logn; u, m = u+1, m<<1 {
		ht := t >> 1
		hm := m >> 1
		for i1, j1 := 0, 0; i1 < hm; i1, j1 = i1+1, j1+t {
			j2 := j1 + ht
			sRe := fftGMRe[m+i1]
			sIm := fftGMIm[m+i1]
			for j := j1; j < j2; j++ {
				xRe := f[j]
				xIm := f[j+hn]
				yRe := f[j+ht]
				yIm := f[j+ht+hn]
				yRe, yIm = yRe*sRe-yIm*sIm, yRe*sIm+yIm*sRe
				f[j] = xRe + yRe
				f[j+hn] = xIm + yIm
				f[j+ht] = xRe - yRe
				f[j+ht+hn] = xIm - yIm
			}
		}
		t = ht
	}
}

func inverseFFT(f []fpr, logn int) {
	if logn == 0 {
		return
	}
	hn := 1 << (logn - 1)
	t := 1
	m := 1 << logn
	for u := logn; u > 1; u-- {
		hm := m >> 1
		dt := t << 1
		for i1, j1 := 0, 0; j1 < hn; i1, j1 = i1+1, j1+dt {
			j2 := j1 + t
			sRe := fftGMRe[hm+i1]
			sIm := -fftGMIm[hm+i1]
			for j := j1; j < j2; j++ {
				xRe := f[j]
				xIm := f[j+hn]
				yRe := f[j+t]
				yIm := f[j+t+hn]
				f[j] = xRe + yRe
				f[j+hn] = xIm + yIm
				xRe, xIm = xRe-yRe, xIm-yIm
				f[j+t] = xRe*sRe - xIm*sIm
				f[j+t+hn] = xRe*sIm + xIm*sRe
			}
		}
		t = dt
		m = hm
	}

	scale := fprP2Tab[logn]
	for i := range 1 << logn {
		f[i] *= scale
	}
}

func fftInvNorm2(dst, a, b []fpr, logn int) {
	hn := 1 << (logn - 1)
	for i := range hn {
		aRe := a[i]
		aIm := a[i+hn]
		bRe := b[i]
		bIm := b[i+hn]
		dst[i] = 1 / (aRe*aRe + aIm*aIm + bRe*bRe + bIm*bIm)
	}
}

func fftAdj(a []fpr, logn int) {
	degree := 1 << logn
	hn := degree >> 1
	for i := hn; i < degree; i++ {
		a[i] = -a[i]
	}
}

func fftMul(a, b []fpr, logn int) {
	hn := 1 << (logn - 1)
	for i := range hn {
		aRe := a[i]
		aIm := a[i+hn]
		bRe := b[i]
		bIm := b[i+hn]
		a[i] = aRe*bRe - aIm*bIm
		a[i+hn] = aRe*bIm + aIm*bRe
	}
}

func fftMulConst(a []fpr, x fpr, logn int) {
	for i := range 1 << logn {
		a[i] *= x
	}
}

// fftSelfAdj writes dst = src * adj(src) in FFT representation. The
// result is real-valued so the imaginary half is explicitly zeroed; callers
// (notably expandPrivateKey's fftAdd composition) rely on that.
func fftSelfAdj(dst, src []fpr, logn int) {
	hn := 1 << (logn - 1)
	for i := range hn {
		aRe := src[i]
		aIm := src[i+hn]
		dst[i] = aRe*aRe + aIm*aIm
		dst[i+hn] = 0
	}
}

func fftNeg(a []fpr, logn int) {
	for i := range 1 << logn {
		a[i] = -a[i]
	}
}

func fftMulAdj(dst, a, b []fpr, logn int) {
	hn := 1 << (logn - 1)
	for i := range hn {
		aRe := a[i]
		aIm := a[i+hn]
		bRe := b[i]
		bIm := -b[i+hn]
		dst[i] = aRe*bRe - aIm*bIm
		dst[i+hn] = aRe*bIm + aIm*bRe
	}
}

func fftMulAutoAdj(a, b []fpr, logn int) {
	hn := 1 << (logn - 1)
	for i := range hn {
		a[i] *= b[i]
		a[i+hn] *= b[i]
	}
}

func fftAdd(a, b []fpr, logn int) {
	for i := range 1 << logn {
		a[i] += b[i]
	}
}

func fftSub(a, b []fpr, logn int) {
	for i := range 1 << logn {
		a[i] -= b[i]
	}
}

func fftAddMulAdj(dst, F, G, f, g []fpr, logn int) {
	hn := 1 << (logn - 1)
	for i := range hn {
		FRe := F[i]
		FIm := F[i+hn]
		GRe := G[i]
		GIm := G[i+hn]
		fRe := f[i]
		fIm := -f[i+hn]
		gRe := g[i]
		gIm := -g[i+hn]
		dst[i] = FRe*fRe - FIm*fIm + GRe*gRe - GIm*gIm
		dst[i+hn] = FRe*fIm + FIm*fRe + GRe*gIm + GIm*gRe
	}
}

func fftDivAutoAdj(a, b []fpr, logn int) {
	hn := 1 << (logn - 1)
	for i := range hn {
		a[i] /= b[i]
		a[i+hn] /= b[i]
	}
}

func ffSamplingFFT(prng *samplerPRNG, z0, z1, t0, t1, tree []fpr, logn int) {
	var tmp [2 * n]fpr
	degree := 1 << logn
	ffSamplingFFTRecursive(prng, z0[:degree], z1[:degree], tree, t0[:degree], t1[:degree], tmp[:degree<<1], logn)
}
