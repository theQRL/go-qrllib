package falcon1024

import "math"

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
	// gaussian0Dist is the reference gaussian0_sampler table: the 72-bit
	// cumulative distribution of the half-Gaussian, 18 rows of three 24-bit
	// limbs, most significant first.
	gaussian0Dist = [...]uint32{
		10745844, 3068844, 3741698,
		5559083, 1580863, 8248194,
		2260429, 13669192, 2736639,
		708981, 4421575, 10046180,
		169348, 7122675, 4136815,
		30538, 13063405, 7650655,
		4132, 14505003, 7826148,
		417, 16768101, 11363290,
		31, 8444042, 8086568,
		1, 12844466, 265321,
		0, 1232676, 13644283,
		0, 38047, 9111839,
		0, 870, 6138264,
		0, 14, 12545723,
		0, 0, 3104126,
		0, 0, 28824,
		0, 0, 198,
		0, 0, 1,
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

// gaussian0Sample is the reference gaussian0_sampler: it draws 72 random
// bits as three 24-bit limbs and counts, with a constant-time borrow chain,
// the table rows the value falls below.
func gaussian0Sample(prng *samplerPRNG) int {
	lo := prng.readUint64()
	hi := uint32(prng.readByte())
	v0 := uint32(lo) & 0xFFFFFF
	v1 := uint32(lo>>24) & 0xFFFFFF
	v2 := uint32(lo>>48) | (hi << 16)

	z := 0
	for u := 0; u < len(gaussian0Dist); u += 3 {
		w0 := gaussian0Dist[u+2]
		w1 := gaussian0Dist[u+1]
		w2 := gaussian0Dist[u]
		cc := (v0 - w0) >> 31
		cc = (v1 - w1 - cc) >> 31
		cc = (v2 - w2 - cc) >> 31
		z += int(cc)
	}
	return z
}

// berExp implements the Falcon reference BerExp rejection step.
func berExp(prng *samplerPRNG, x, ccs fpr) bool {
	s := int(fprTrunc(x * invLog2))
	r := x - fpr(fpr(s)*log2)

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
	dss := fpr(isigma*isigma) * 0.5
	ccs := isigma * sigmaMin1024

	for {
		z0 := gaussian0Sample(prng)
		b := int(prng.readByte()) & 1
		z := b + ((b<<1)-1)*z0

		x := fpr(z) - r
		x = fpr(fpr(x*x)*dss) - fpr(fpr(z0*z0)*inv2SqrSigma0)
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

		// mu = g01 / g00, evaluated exactly as the reference FPC_DIV macro:
		// invert |g00|^2 once, scale conj(g00) by it, then multiply.
		m := fpr(g00Re*g00Re) + fpr(g00Im*g00Im)
		m = 1 / m
		bRe := g00Re * m
		bIm := (-g00Im) * m
		muRe := fpr(g01Re*bRe) - fpr(g01Im*bIm)
		muIm := fpr(g01Re*bIm) + fpr(g01Im*bRe)

		// xi = mu * conj(g01), as the reference FPC_MUL with negated g01Im.
		ng01Im := -g01Im
		xiRe := fpr(muRe*g01Re) - fpr(muIm*ng01Im)
		xiIm := fpr(muRe*ng01Im) + fpr(muIm*g01Re)

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
		f1[u] = 0.5 * (fpr(tRe*gmRe) - fpr(tIm*gmIm))
		f1[u+qn] = 0.5 * (fpr(tRe*gmIm) + fpr(tIm*gmRe))
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
		cRe := fpr(bRe*gmRe) - fpr(bIm*gmIm)
		cIm := fpr(bRe*gmIm) + fpr(bIm*gmRe)

		j := u << 1
		f[j] = aRe + cRe
		f[j+hn] = aIm + cIm
		f[j+1] = aRe - cRe
		f[j+1+hn] = aIm - cIm
	}
}

// ffSamplingFFTRecursive mirrors the Falcon reference ffSampling_fft_dyntree
// recursion used by sign_dyn, the signer behind the reference NIST API: every
// level down to the degree-1 leaves goes through the generic split and merge
// routines. (The reference's expanded-key signer ffSampling_fft instead
// inlines the two lowest levels with a different operation order, which
// rounds differently in the last bit.) The LDL values come from the
// precomputed tree, which holds exactly what the dynamic version recomputes.
func ffSamplingFFTRecursive(samp samplerZ, prng *samplerPRNG, z0, z1, tree, t0, t1, tmp []fpr, logn int) {
	if logn == 0 {
		isigma := tree[0]
		z0[0] = samp(prng, t0[0], isigma)
		z1[0] = samp(prng, t1[0], isigma)
		return
	}

	degree := 1 << logn
	hn := degree >> 1
	tree0 := tree[degree:]
	tree1 := tree[degree+ffLDLTreeSize(logn-1):]

	splitFFT(z1[:hn], z1[hn:degree], t1[:degree], logn)
	ffSamplingFFTRecursive(samp, prng, tmp[:hn], tmp[hn:degree], tree1, z1[:hn], z1[hn:degree], tmp[degree:], logn-1)
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
	ffSamplingFFTRecursive(samp, prng, tmp[:hn], tmp[hn:degree], tree0, z0[:hn], z0[hn:degree], tmp[degree:], logn-1)
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
				yRe, yIm = fpr(yRe*sRe)-fpr(yIm*sIm), fpr(yRe*sIm)+fpr(yIm*sRe)
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
				f[j+t] = fpr(xRe*sRe) - fpr(xIm*sIm)
				f[j+t+hn] = fpr(xRe*sIm) + fpr(xIm*sRe)
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
		// Associate as the reference poly_invnorm2_fft: (|a|^2) + (|b|^2).
		dst[i] = 1 / ((fpr(aRe*aRe) + fpr(aIm*aIm)) + (fpr(bRe*bRe) + fpr(bIm*bIm)))
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
		a[i] = fpr(aRe*bRe) - fpr(aIm*bIm)
		a[i+hn] = fpr(aRe*bIm) + fpr(aIm*bRe)
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
		dst[i] = fpr(aRe*aRe) + fpr(aIm*aIm)
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
		dst[i] = fpr(aRe*bRe) - fpr(aIm*bIm)
		dst[i+hn] = fpr(aRe*bIm) + fpr(aIm*bRe)
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
		// Form F*adj(f) and G*adj(g) separately, then add, as the reference
		// poly_add_muladj_fft does.
		aRe := fpr(FRe*fRe) - fpr(FIm*fIm)
		aIm := fpr(FRe*fIm) + fpr(FIm*fRe)
		bRe := fpr(GRe*gRe) - fpr(GIm*gIm)
		bIm := fpr(GRe*gIm) + fpr(GIm*gRe)
		dst[i] = aRe + bRe
		dst[i+hn] = aIm + bIm
	}
}

func fftDivAutoAdj(a, b []fpr, logn int) {
	hn := 1 << (logn - 1)
	for i := range hn {
		// Invert once and multiply, as the reference poly_div_autoadj_fft
		// does; a/b and a*(1/b) differ in the last bit.
		ib := 1 / b[i]
		a[i] *= ib
		a[i+hn] *= ib
	}
}

// samplerZ is the integer sampler the Fast Fourier sampling recursion calls at
// its leaves, with the signature of the reference samplerZ callback: it
// returns an integer sampled around center mu with standard deviation
// 1/isigma. sampleFFTPoint is the real sampler; tests substitute recorders.
type samplerZ func(prng *samplerPRNG, mu, isigma fpr) fpr

func ffSamplingFFT(samp samplerZ, prng *samplerPRNG, z0, z1, t0, t1, tree []fpr, logn int) {
	var tmp [2 * n]fpr
	defer zeroFPRs(tmp[:])
	degree := 1 << logn
	ffSamplingFFTRecursive(samp, prng, z0[:degree], z1[:degree], tree, t0[:degree], t1[:degree], tmp[:degree<<1], logn)
}
