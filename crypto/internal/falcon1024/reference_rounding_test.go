package falcon1024

// These tests pin the floating-point behaviour of the FFT, LDL, Gaussian
// sampling and key-generation helpers to the Falcon reference implementation's
// exact operation order (fft.c, sign.c and keygen.c in
// https://falcon-sign.info/falcon-round3.zip). The reference rounds every
// product and sum to binary64 individually. The oracles below are literal
// transliterations of the reference routines in which every operation passes
// through an explicit floating-point conversion, which the Go specification
// defines as a rounding point that no fused operation may skip, so they round
// exactly as the C code does on every Go target.
//
// A production routine that reorders an operation, or a build in which the
// compiler fuses a multiply-add (arm64, ppc64, s390x, riscv64, or amd64 with
// GOAMD64=v3), produces different low bits and fails these tests. Before the
// explicit-rounding fix in fft.go and field.go the LDL, inverse-norm,
// add-mul-adjoint, div-auto-adjoint, key-expansion and key-generation-norm
// tests failed on every target, and all of the tests failed on
// fused-multiply-add targets. The round-3 KAT suite alone did not catch the
// fusion reliably: with GOAMD64=v3 key generation for KAT seed 65 produced a
// different key than the reference, while the arm64 build, which fuses a
// different set of operations, happened to reproduce all 100 vectors.

import (
	"crypto/sha3"
	"encoding/binary"
	"math"
	"testing"
)

// Explicitly rounded reference arithmetic (fpr_add, fpr_sub, fpr_mul, ...).
func refAdd(a, b fpr) fpr { return fpr(float64(a) + float64(b)) }
func refSub(a, b fpr) fpr { return fpr(float64(a) - float64(b)) }
func refMul(a, b fpr) fpr { return fpr(float64(a) * float64(b)) }
func refSqr(a fpr) fpr    { return refMul(a, a) }
func refInv(a fpr) fpr    { return fpr(1 / float64(a)) }
func refHalf(a fpr) fpr   { return refMul(a, 0.5) }
func refSqrt(a fpr) fpr   { return fpr(math.Sqrt(float64(a))) }

// refFPCMul is the reference FPC_MUL macro.
func refFPCMul(aRe, aIm, bRe, bIm fpr) (fpr, fpr) {
	return refSub(refMul(aRe, bRe), refMul(aIm, bIm)),
		refAdd(refMul(aRe, bIm), refMul(aIm, bRe))
}

// refFPCDiv is the reference FPC_DIV macro.
func refFPCDiv(aRe, aIm, bRe, bIm fpr) (fpr, fpr) {
	m := refInv(refAdd(refSqr(bRe), refSqr(bIm)))
	bRe = refMul(bRe, m)
	bIm = refMul(-bIm, m)
	return refSub(refMul(aRe, bRe), refMul(aIm, bIm)),
		refAdd(refMul(aRe, bIm), refMul(aIm, bRe))
}

// refFFT is the reference FFT.
func refFFT(f []fpr, logn int) {
	hn := 1 << (logn - 1)
	t := hn
	for u, m := 1, 2; u < logn; u, m = u+1, m<<1 {
		ht := t >> 1
		hm := m >> 1
		for i1, j1 := 0, 0; i1 < hm; i1, j1 = i1+1, j1+t {
			j2 := j1 + ht
			sRe, sIm := fftGMRe[m+i1], fftGMIm[m+i1]
			for j := j1; j < j2; j++ {
				xRe, xIm := f[j], f[j+hn]
				yRe, yIm := refFPCMul(f[j+ht], f[j+ht+hn], sRe, sIm)
				f[j], f[j+hn] = refAdd(xRe, yRe), refAdd(xIm, yIm)
				f[j+ht], f[j+ht+hn] = refSub(xRe, yRe), refSub(xIm, yIm)
			}
		}
		t = ht
	}
}

// refIFFT is the reference iFFT.
func refIFFT(f []fpr, logn int) {
	degree := 1 << logn
	hn := degree >> 1
	t := 1
	m := degree
	for u := logn; u > 1; u-- {
		hm := m >> 1
		dt := t << 1
		for i1, j1 := 0, 0; j1 < hn; i1, j1 = i1+1, j1+dt {
			j2 := j1 + t
			sRe, sIm := fftGMRe[hm+i1], -fftGMIm[hm+i1]
			for j := j1; j < j2; j++ {
				xRe, xIm := f[j], f[j+hn]
				yRe, yIm := f[j+t], f[j+t+hn]
				f[j], f[j+hn] = refAdd(xRe, yRe), refAdd(xIm, yIm)
				xRe, xIm = refSub(xRe, yRe), refSub(xIm, yIm)
				f[j+t], f[j+t+hn] = refFPCMul(xRe, xIm, sRe, sIm)
			}
		}
		t = dt
		m = hm
	}
	ni := fprP2Tab[logn]
	for u := range degree {
		f[u] = refMul(f[u], ni)
	}
}

// refPolySplitFFT is the reference poly_split_fft.
func refPolySplitFFT(f0, f1, f []fpr, logn int) {
	hn := 1 << (logn - 1)
	qn := hn >> 1
	f0[0] = f[0]
	f1[0] = f[hn]
	for u := range qn {
		aRe, aIm := f[u<<1], f[(u<<1)+hn]
		bRe, bIm := f[(u<<1)+1], f[(u<<1)+1+hn]
		tRe, tIm := refAdd(aRe, bRe), refAdd(aIm, bIm)
		f0[u], f0[u+qn] = refHalf(tRe), refHalf(tIm)
		tRe, tIm = refSub(aRe, bRe), refSub(aIm, bIm)
		tRe, tIm = refFPCMul(tRe, tIm, fftGMRe[u+hn], -fftGMIm[u+hn])
		f1[u], f1[u+qn] = refHalf(tRe), refHalf(tIm)
	}
}

// refPolyMergeFFT is the reference poly_merge_fft.
func refPolyMergeFFT(f, f0, f1 []fpr, logn int) {
	hn := 1 << (logn - 1)
	qn := hn >> 1
	f[0] = f0[0]
	f[hn] = f1[0]
	for u := range qn {
		aRe, aIm := f0[u], f0[u+qn]
		bRe, bIm := refFPCMul(f1[u], f1[u+qn], fftGMRe[u+hn], fftGMIm[u+hn])
		f[u<<1], f[(u<<1)+hn] = refAdd(aRe, bRe), refAdd(aIm, bIm)
		f[(u<<1)+1], f[(u<<1)+1+hn] = refSub(aRe, bRe), refSub(aIm, bIm)
	}
}

// refPolyMulFFT is the reference poly_mul_fft.
func refPolyMulFFT(a, b []fpr, logn int) {
	hn := 1 << (logn - 1)
	for u := range hn {
		a[u], a[u+hn] = refFPCMul(a[u], a[u+hn], b[u], b[u+hn])
	}
}

// refPolyMulAdjFFT is the reference poly_muladj_fft.
func refPolyMulAdjFFT(a, b []fpr, logn int) {
	hn := 1 << (logn - 1)
	for u := range hn {
		a[u], a[u+hn] = refFPCMul(a[u], a[u+hn], b[u], -b[u+hn])
	}
}

// refPolyMulSelfAdjFFT is the reference poly_mulselfadj_fft.
func refPolyMulSelfAdjFFT(a []fpr, logn int) {
	hn := 1 << (logn - 1)
	for u := range hn {
		a[u] = refAdd(refSqr(a[u]), refSqr(a[u+hn]))
		a[u+hn] = 0
	}
}

// refPolyMulConst is the reference poly_mulconst.
func refPolyMulConst(a []fpr, x fpr, logn int) {
	for u := range 1 << logn {
		a[u] = refMul(a[u], x)
	}
}

// refPolyInvNorm2FFT is the reference poly_invnorm2_fft.
func refPolyInvNorm2FFT(d, a, b []fpr, logn int) {
	hn := 1 << (logn - 1)
	for u := range hn {
		d[u] = refInv(refAdd(
			refAdd(refSqr(a[u]), refSqr(a[u+hn])),
			refAdd(refSqr(b[u]), refSqr(b[u+hn]))))
	}
}

// refPolyAddMulAdjFFT is the reference poly_add_muladj_fft.
func refPolyAddMulAdjFFT(d, F, G, f, g []fpr, logn int) {
	hn := 1 << (logn - 1)
	for u := range hn {
		aRe, aIm := refFPCMul(F[u], F[u+hn], f[u], -f[u+hn])
		bRe, bIm := refFPCMul(G[u], G[u+hn], g[u], -g[u+hn])
		d[u], d[u+hn] = refAdd(aRe, bRe), refAdd(aIm, bIm)
	}
}

// refPolyMulAutoAdjFFT is the reference poly_mul_autoadj_fft.
func refPolyMulAutoAdjFFT(a, b []fpr, logn int) {
	hn := 1 << (logn - 1)
	for u := range hn {
		a[u] = refMul(a[u], b[u])
		a[u+hn] = refMul(a[u+hn], b[u])
	}
}

// refPolyDivAutoAdjFFT is the reference poly_div_autoadj_fft.
func refPolyDivAutoAdjFFT(a, b []fpr, logn int) {
	hn := 1 << (logn - 1)
	for u := range hn {
		ib := refInv(b[u])
		a[u] = refMul(a[u], ib)
		a[u+hn] = refMul(a[u+hn], ib)
	}
}

// refPolyLDLmvFFT is the reference poly_LDLmv_fft.
func refPolyLDLmvFFT(d11, l10, g00, g01, g11 []fpr, logn int) {
	hn := 1 << (logn - 1)
	for u := range hn {
		g00Re, g00Im := g00[u], g00[u+hn]
		g01Re, g01Im := g01[u], g01[u+hn]
		g11Re, g11Im := g11[u], g11[u+hn]
		muRe, muIm := refFPCDiv(g01Re, g01Im, g00Re, g00Im)
		g01Re, g01Im = refFPCMul(muRe, muIm, g01Re, -g01Im)
		d11[u], d11[u+hn] = refSub(g11Re, g01Re), refSub(g11Im, g01Im)
		l10[u], l10[u+hn] = muRe, -muIm
	}
}

// refPolyAdd is the reference poly_add.
func refPolyAdd(a, b []fpr, logn int) {
	for u := range 1 << logn {
		a[u] = refAdd(a[u], b[u])
	}
}

// refPolyNeg is the reference poly_neg.
func refPolyNeg(a []fpr, logn int) {
	for u := range 1 << logn {
		a[u] = -a[u]
	}
}

// refPolyAdjFFT is the reference poly_adj_fft.
func refPolyAdjFFT(a []fpr, logn int) {
	degree := 1 << logn
	for u := degree >> 1; u < degree; u++ {
		a[u] = -a[u]
	}
}

// refFFLDLFFTInner is the reference ffLDL_fft_inner.
func refFFLDLFFTInner(tree, g0, g1 []fpr, logn int, tmp []fpr) {
	degree := 1 << logn
	if degree == 1 {
		tree[0] = g0[0]
		return
	}
	hn := degree >> 1
	refPolyLDLmvFFT(tmp, tree, g0, g1, g0, logn)
	refPolySplitFFT(g1, g1[hn:], g0, logn)
	refPolySplitFFT(g0, g0[hn:], tmp, logn)
	refFFLDLFFTInner(tree[degree:], g1, g1[hn:], logn-1, tmp)
	refFFLDLFFTInner(tree[degree+ffLDLTreeSize(logn-1):], g0, g0[hn:], logn-1, tmp)
}

// refFFLDLFFT is the reference ffLDL_fft; tmp needs 3 * 2^logn entries.
func refFFLDLFFT(tree, g00, g01, g11 []fpr, logn int, tmp []fpr) {
	degree := 1 << logn
	if degree == 1 {
		tree[0] = g00[0]
		return
	}
	hn := degree >> 1
	d00 := tmp[:degree]
	d11 := tmp[degree : 2*degree]
	tmp = tmp[2*degree:]
	copy(d00, g00[:degree])
	refPolyLDLmvFFT(d11, tree, g00, g01, g11, logn)
	refPolySplitFFT(tmp, tmp[hn:], d00, logn)
	refPolySplitFFT(d00, d00[hn:], d11, logn)
	copy(d11, tmp[:degree])
	refFFLDLFFTInner(tree[degree:], d11, d11[hn:], logn-1, tmp)
	refFFLDLFFTInner(tree[degree+ffLDLTreeSize(logn-1):], d00, d00[hn:], logn-1, tmp)
}

// refFFLDLBinaryNormalize is the reference ffLDL_binary_normalize.
func refFFLDLBinaryNormalize(tree []fpr, origLogn, logn int) {
	degree := 1 << logn
	if degree == 1 {
		tree[0] = refMul(refSqrt(tree[0]), invSigma[origLogn])
		return
	}
	refFFLDLBinaryNormalize(tree[degree:], origLogn, logn-1)
	refFFLDLBinaryNormalize(tree[degree+ffLDLTreeSize(logn-1):], origLogn, logn-1)
}

// refExpandPrivateKey is the reference expand_privkey.
func refExpandPrivateKey(f, g, F, G smallPolynomial) (b00, b01, b10, b11 fftPolynomial, tree fprTree) {
	for u := range n {
		b01[u] = fpr(f[u])
		b00[u] = fpr(g[u])
		b11[u] = fpr(F[u])
		b10[u] = fpr(G[u])
	}
	refFFT(b01[:], logN)
	refFFT(b00[:], logN)
	refFFT(b11[:], logN)
	refFFT(b10[:], logN)
	refPolyNeg(b01[:], logN)
	refPolyNeg(b11[:], logN)

	var g00, g01, g11, gxx fftPolynomial
	g00 = b00
	refPolyMulSelfAdjFFT(g00[:], logN)
	gxx = b01
	refPolyMulSelfAdjFFT(gxx[:], logN)
	refPolyAdd(g00[:], gxx[:], logN)

	g01 = b00
	refPolyMulAdjFFT(g01[:], b10[:], logN)
	gxx = b01
	refPolyMulAdjFFT(gxx[:], b11[:], logN)
	refPolyAdd(g01[:], gxx[:], logN)

	g11 = b10
	refPolyMulSelfAdjFFT(g11[:], logN)
	gxx = b11
	refPolyMulSelfAdjFFT(gxx[:], logN)
	refPolyAdd(g11[:], gxx[:], logN)

	var scratch [3 * n]fpr
	refFFLDLFFT(tree[:], g00[:], g01[:], g11[:], logN, scratch[:])
	refFFLDLBinaryNormalize(tree[:], logN, logN)
	return b00, b01, b10, b11, tree
}

// refKeygenOrthogonalizedNorm is the orthogonalized-norm computation of the
// reference keygen, up to and including the bnorm accumulation loop.
func refKeygenOrthogonalizedNorm(f, g smallPolynomial) fpr {
	var rt1, rt2, rt3 fftPolynomial
	for u := range n {
		rt1[u] = fpr(f[u])
		rt2[u] = fpr(g[u])
	}
	refFFT(rt1[:], logN)
	refFFT(rt2[:], logN)
	refPolyInvNorm2FFT(rt3[:], rt1[:], rt2[:], logN)
	refPolyAdjFFT(rt1[:], logN)
	refPolyAdjFFT(rt2[:], logN)
	refPolyMulConst(rt1[:], q, logN)
	refPolyMulConst(rt2[:], q, logN)
	refPolyMulAutoAdjFFT(rt1[:], rt3[:], logN)
	refPolyMulAutoAdjFFT(rt2[:], rt3[:], logN)
	refIFFT(rt1[:], logN)
	refIFFT(rt2[:], logN)
	var bnorm fpr
	for u := range n {
		bnorm = refAdd(bnorm, refSqr(rt1[u]))
		bnorm = refAdd(bnorm, refSqr(rt2[u]))
	}
	return bnorm
}

// refGaussian0Dist is the reference gaussian0_sampler table: 18 rows of
// three 24-bit limbs, most significant first.
var refGaussian0Dist = [...]uint32{
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

// refGaussian0Sampler is the reference gaussian0_sampler.
func refGaussian0Sampler(p *samplerPRNG) int {
	lo := p.readUint64()
	hi := uint32(p.readByte())
	v0 := uint32(lo) & 0xFFFFFF
	v1 := uint32(lo>>24) & 0xFFFFFF
	v2 := uint32(lo>>48) | (hi << 16)
	z := 0
	for u := 0; u < len(refGaussian0Dist); u += 3 {
		w0 := refGaussian0Dist[u+2]
		w1 := refGaussian0Dist[u+1]
		w2 := refGaussian0Dist[u]
		cc := (v0 - w0) >> 31
		cc = (v1 - w1 - cc) >> 31
		cc = (v2 - w2 - cc) >> 31
		z += int(cc)
	}
	return z
}

// refBerExpZ is the value BerExp compares against the PRNG bytes, for the
// reduced argument r and the unsaturated shift count s.
func refBerExpZ(r, ccs fpr, s int) uint64 {
	sw := uint32(s)
	sw ^= (sw ^ 63) & -((63 - sw) >> 31)
	return ((fprExpmP63(r, ccs) << 1) - 1) >> uint(sw)
}

// refBerExp is the reference BerExp.
func refBerExp(p *samplerPRNG, x, ccs fpr) bool {
	s := int(fprTrunc(refMul(x, invLog2)))
	r := refSub(x, refMul(fpr(s), log2))
	z := refBerExpZ(r, ccs, s)
	i := 64
	var w uint32
	for {
		i -= 8
		w = uint32(p.readByte()) - (uint32(z>>uint(i)) & 0xFF)
		if w != 0 || i == 0 {
			break
		}
	}
	return w>>31 != 0
}

// refSampler is the reference sampler (sign.c), returning the sampled integer.
func refSampler(p *samplerPRNG, mu, isigma fpr) int {
	s := int(math.Floor(float64(mu)))
	r := refSub(mu, fpr(s))
	dss := refHalf(refSqr(isigma))
	ccs := refMul(isigma, sigmaMin1024)
	for {
		z0 := refGaussian0Sampler(p)
		b := int(p.readByte()) & 1
		z := b + ((b<<1)-1)*z0
		x := refMul(refSqr(refSub(fpr(z), r)), dss)
		x = refSub(x, refMul(fpr(z0*z0), inv2SqrSigma0))
		if refBerExp(p, x, ccs) {
			return s + z
		}
	}
}

// refRand is a deterministic source of test inputs.
type refRand struct {
	shake *sha3.SHAKE
}

func newRefRand(label string) *refRand {
	shake := sha3.NewSHAKE256()
	_, _ = shake.Write([]byte(label))
	return &refRand{shake: shake}
}

func (r *refRand) bytes(b []byte) {
	_, _ = r.shake.Read(b)
}

func (r *refRand) uint64() uint64 {
	var b [8]byte
	r.bytes(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

// unit returns a value in [0, 1).
func (r *refRand) unit() fpr {
	return fpr(float64(r.uint64()>>11) / (1 << 53))
}

// fprWithExponent returns a value with a random sign and 52-bit mantissa and
// an exponent uniform in [minExp, maxExp].
func (r *refRand) fprWithExponent(minExp, maxExp int) fpr {
	v := r.uint64()
	mant := 1 + float64(v>>12)/(1<<52)
	exp := minExp + int((v>>1)%uint64(maxExp-minExp+1))
	if v&1 != 0 {
		mant = -mant
	}
	return fpr(math.Ldexp(mant, exp))
}

func (r *refRand) smallPolynomial(bound int32) smallPolynomial {
	var p smallPolynomial
	for i := range p {
		p[i] = int32(r.uint64()%uint64(2*bound+1)) - bound
	}
	return p
}

// fftImage returns the reference FFT of a random small polynomial, which has
// the magnitudes the production helpers see in practice.
func (r *refRand) fftImage() fftPolynomial {
	p := r.smallPolynomial(20)
	var out fftPolynomial
	for i := range p {
		out[i] = fpr(p[i])
	}
	refFFT(out[:], logN)
	return out
}

// mixed returns values with random exponents, to exercise rounding at many
// scales.
func (r *refRand) mixed() fftPolynomial {
	var out fftPolynomial
	for i := range out {
		out[i] = r.fprWithExponent(-8, 24)
	}
	return out
}

func requireSameBits(t *testing.T, name string, got, want []fpr) {
	t.Helper()
	for i := range want {
		if math.Float64bits(float64(got[i])) != math.Float64bits(float64(want[i])) {
			t.Fatalf("%s: index %d: got %x, want %x", name, i, float64(got[i]), float64(want[i]))
		}
	}
}

// gramInputs builds Gram-matrix entries g00 = |a|^2 + |b|^2,
// g01 = a adj(c) + b adj(d), g11 = |c|^2 + |d|^2 with the reference arithmetic.
func gramInputs(a, b, c, d fftPolynomial) (g00, g01, g11 fftPolynomial) {
	g00, gxx := a, b
	refPolyMulSelfAdjFFT(g00[:], logN)
	refPolyMulSelfAdjFFT(gxx[:], logN)
	refPolyAdd(g00[:], gxx[:], logN)

	g01, gxx = a, b
	refPolyMulAdjFFT(g01[:], c[:], logN)
	refPolyMulAdjFFT(gxx[:], d[:], logN)
	refPolyAdd(g01[:], gxx[:], logN)

	g11, gxx = c, d
	refPolyMulSelfAdjFFT(g11[:], logN)
	refPolyMulSelfAdjFFT(gxx[:], logN)
	refPolyAdd(g11[:], gxx[:], logN)
	return g00, g01, g11
}

func TestFFTLayerMatchesReferenceRounding(t *testing.T) {
	rnd := newRefRand("falcon1024 fft layer reference rounding")

	for round := range 6 {
		var a, b, c, d fftPolynomial
		if round%2 == 0 {
			a, b, c, d = rnd.fftImage(), rnd.fftImage(), rnd.fftImage(), rnd.fftImage()
		} else {
			a, b, c, d = rnd.mixed(), rnd.mixed(), rnd.mixed(), rnd.mixed()
		}
		g00, g01, g11 := gramInputs(a, b, c, d)

		t.Run("FFT", func(t *testing.T) {
			got, want := a, a
			fft(got[:], logN)
			refFFT(want[:], logN)
			requireSameBits(t, "fft", got[:], want[:])
		})

		t.Run("iFFT", func(t *testing.T) {
			got, want := a, a
			inverseFFT(got[:], logN)
			refIFFT(want[:], logN)
			requireSameBits(t, "inverseFFT", got[:], want[:])
		})

		t.Run("poly_split_fft", func(t *testing.T) {
			var got0, got1, want0, want1 [n / 2]fpr
			splitFFT(got0[:], got1[:], a[:], logN)
			refPolySplitFFT(want0[:], want1[:], a[:], logN)
			requireSameBits(t, "splitFFT even", got0[:], want0[:])
			requireSameBits(t, "splitFFT odd", got1[:], want1[:])
		})

		t.Run("poly_merge_fft", func(t *testing.T) {
			var got, want fftPolynomial
			mergeFFT(got[:], a[:n/2], b[:n/2], logN)
			refPolyMergeFFT(want[:], a[:n/2], b[:n/2], logN)
			requireSameBits(t, "mergeFFT", got[:], want[:])
		})

		t.Run("poly_mul_fft", func(t *testing.T) {
			got, want := a, a
			fftMul(got[:], b[:], logN)
			refPolyMulFFT(want[:], b[:], logN)
			requireSameBits(t, "fftMul", got[:], want[:])

			// The inputs must be able to expose a fused multiply-add: at
			// least one output has to change when either product of the
			// complex multiplication is fused into the subtraction.
			fusable := 0
			for i := range n / 2 {
				aRe, aIm, bRe, bIm := a[i], a[i+n/2], b[i], b[i+n/2]
				fusedA := fpr(math.FMA(float64(aRe), float64(bRe), -float64(refMul(aIm, bIm))))
				fusedB := fpr(math.FMA(-float64(aIm), float64(bIm), float64(refMul(aRe, bRe))))
				if fusedA != want[i] && fusedB != want[i] {
					fusable++
				}
			}
			if fusable == 0 {
				t.Fatal("test inputs cannot expose fused multiply-adds")
			}
		})

		t.Run("poly_muladj_fft", func(t *testing.T) {
			var got, want fftPolynomial
			fftMulAdj(got[:], a[:], b[:], logN)
			want = a
			refPolyMulAdjFFT(want[:], b[:], logN)
			requireSameBits(t, "fftMulAdj", got[:], want[:])
		})

		t.Run("poly_mulselfadj_fft", func(t *testing.T) {
			var got, want fftPolynomial
			fftSelfAdj(got[:], a[:], logN)
			want = a
			refPolyMulSelfAdjFFT(want[:], logN)
			requireSameBits(t, "fftSelfAdj", got[:], want[:])
		})

		t.Run("poly_mulconst", func(t *testing.T) {
			got, want := a, a
			fftMulConst(got[:], -fprInverseOfQ, logN)
			refPolyMulConst(want[:], -fprInverseOfQ, logN)
			requireSameBits(t, "fftMulConst", got[:], want[:])
		})

		t.Run("poly_invnorm2_fft", func(t *testing.T) {
			var got, want fftPolynomial
			fftInvNorm2(got[:], a[:], b[:], logN)
			refPolyInvNorm2FFT(want[:], a[:], b[:], logN)
			requireSameBits(t, "fftInvNorm2", got[:n/2], want[:n/2])
		})

		t.Run("poly_add_muladj_fft", func(t *testing.T) {
			var got, want fftPolynomial
			fftAddMulAdj(got[:], a[:], b[:], c[:], d[:], logN)
			refPolyAddMulAdjFFT(want[:], a[:], b[:], c[:], d[:], logN)
			requireSameBits(t, "fftAddMulAdj", got[:], want[:])
		})

		t.Run("poly_mul_autoadj_fft", func(t *testing.T) {
			got, want := a, a
			fftMulAutoAdj(got[:], g00[:], logN)
			refPolyMulAutoAdjFFT(want[:], g00[:], logN)
			requireSameBits(t, "fftMulAutoAdj", got[:], want[:])
		})

		t.Run("poly_div_autoadj_fft", func(t *testing.T) {
			got, want := a, a
			fftDivAutoAdj(got[:], g00[:], logN)
			refPolyDivAutoAdjFFT(want[:], g00[:], logN)
			requireSameBits(t, "fftDivAutoAdj", got[:], want[:])
		})

		t.Run("poly_LDLmv_fft", func(t *testing.T) {
			var gotD, gotL, wantD, wantL fftPolynomial
			fftLDLMV(gotD[:], gotL[:], g00[:], g01[:], g11[:], logN)
			refPolyLDLmvFFT(wantD[:], wantL[:], g00[:], g01[:], g11[:], logN)
			requireSameBits(t, "fftLDLMV d11", gotD[:], wantD[:])
			requireSameBits(t, "fftLDLMV l10", gotL[:], wantL[:])
		})

		t.Run("ffLDL_fft", func(t *testing.T) {
			var got, want fprTree
			var gotTmp, wantTmp [3 * n]fpr
			ffLDLFFT(got[:], g00[:], g01[:], g11[:], logN, gotTmp[:])
			refFFLDLFFT(want[:], g00[:], g01[:], g11[:], logN, wantTmp[:])
			requireSameBits(t, "ffLDLFFT", got[:], want[:])

			ffLDLBinaryNormalize(got[:], logN, logN)
			refFFLDLBinaryNormalize(want[:], logN, logN)
			requireSameBits(t, "ffLDLBinaryNormalize", got[:], want[:])
		})
	}
}

func TestExpandPrivateKeyMatchesReferenceRounding(t *testing.T) {
	for i := range 2 {
		rng := sha3.NewSHAKE256()
		_, _ = rng.Write([]byte{byte(i), 'e', 'x', 'p', 'a', 'n', 'd'})
		f, g, F, G, _ := generateKeyComponents(rng)

		var priv PrivateKey
		expandPrivateKey(&priv, f, g, F, G)
		b00, b01, b10, b11, tree := refExpandPrivateKey(f, g, F, G)

		requireSameBits(t, "b00", priv.b00[:], b00[:])
		requireSameBits(t, "b01", priv.b01[:], b01[:])
		requireSameBits(t, "b10", priv.b10[:], b10[:])
		requireSameBits(t, "b11", priv.b11[:], b11[:])
		requireSameBits(t, "tree", priv.tree[:], tree[:])
	}
}

func TestKeygenOrthogonalizedNormMatchesReference(t *testing.T) {
	// orthogonalizedNormExceedsBound rejects iff the norm is not below the
	// bound, so a bound equal to the reference norm must be reported as
	// exceeded and the next representable value must not: together they pin
	// the norm to the reference value bit for bit.
	rng := sha3.NewSHAKE256()
	_, _ = rng.Write([]byte("falcon1024 keygen norm reference rounding"))
	for i := range 24 {
		f := sampleGaussianPolynomial(rng)
		g := sampleGaussianPolynomial(rng)
		want := float64(refKeygenOrthogonalizedNorm(f, g))
		if !orthogonalizedNormExceedsBound(f, g, want) {
			t.Fatalf("pair %d: norm is below the reference norm %x", i, want)
		}
		if orthogonalizedNormExceedsBound(f, g, math.Nextafter(want, math.Inf(1))) {
			t.Fatalf("pair %d: norm is above the reference norm %x", i, want)
		}
	}
}

func TestSampleFFTPointMatchesReference(t *testing.T) {
	rnd := newRefRand("falcon1024 sampler reference rounding")
	for i := range 2048 {
		var stream [512]byte
		rnd.bytes(stream[:])
		prng := newSamplerPRNGFromBytes(stream[:])
		refPRNG := newSamplerPRNGFromBytes(stream[:])

		mu := fpr(int64(rnd.uint64()%200)-100) + rnd.unit()
		// Falcon-1024 leaf values of 1/sigma lie in [1/1.8205, 1/1.2983].
		isigma := fpr(0.549) + fpr(0.221)*rnd.unit()

		got := sampleFFTPoint(prng, mu, isigma)
		want := refSampler(refPRNG, mu, isigma)
		if got != fpr(want) {
			t.Fatalf("case %d: sampleFFTPoint(%x, %x) = %v, want %d", i, float64(mu), float64(isigma), got, want)
		}
		if prng.ptr != refPRNG.ptr || prng.counter != refPRNG.counter {
			t.Fatalf("case %d: consumed %d bytes (counter %d), reference consumed %d (counter %d)",
				i, prng.ptr, prng.counter, refPRNG.ptr, refPRNG.counter)
		}
	}
}

// berExpWord is the eight PRNG bytes BerExp compares against z, as the
// big-endian word W: BerExp accepts iff W < z.
func berExpWord(stream []byte) uint64 {
	return binary.BigEndian.Uint64(stream[:8])
}

func TestBerExpMatchesReferenceAtFusionBoundary(t *testing.T) {
	// berExp reduces x to r = x - s*log2 and accepts iff the next eight PRNG
	// bytes, read as a big-endian word W, satisfy W < z(r, ccs). A build that
	// fuses s*log2 into the subtraction rounds r differently and moves z by
	// a few hundred units out of 2^63, which random inputs practically never
	// expose. This test searches for (x, ccs) pairs for which the fused and
	// the reference roundings of r decide differently, and checks that
	// berExp decides like the reference. It uses s = 3: for s = 1 and s = 2
	// the product s*log2 is exact, so fusion cannot change r.
	rnd := newRefRand("falcon1024 BerExp fusion boundary")
	var stream [512]byte
	rnd.bytes(stream[:])
	// Keep W below 2^59 so that z = (2*expm - 1) >> 3 can reach it with ccs < 1.
	stream[0] &= 0x07
	w := berExpWord(stream[:])

	const wantCases = 8
	found := 0
	for attempt := 0; attempt < 1<<14 && found < wantCases; attempt++ {
		x := refMul(fpr(3)+rnd.unit(), log2)
		s := int(fprTrunc(refMul(x, invLog2)))
		if s < 3 {
			continue
		}
		rWant := refSub(x, refMul(fpr(s), log2))
		rFused := fpr(math.FMA(-float64(s), float64(log2), float64(x)))
		if rWant == rFused || rWant < 0 {
			continue
		}
		// z ~ 2^64 * ccs * exp(-r) / 2^s and fprExpmP63(r, 1/2) ~ 2^62 * exp(-r),
		// so z = W needs ccs ~ W * 2^s / (4 * fprExpmP63(r, 1/2)).
		ccs0 := float64(w) * math.Ldexp(1, s) / (4 * float64(fprExpmP63(rWant, 0.5)))
		if ccs0 <= 0 || ccs0 >= 0.99 {
			continue
		}
		for k := int64(-2048); k <= 2048; k++ {
			ccs := fpr(math.Float64frombits(uint64(int64(math.Float64bits(ccs0)) + k)))
			zWant := refBerExpZ(rWant, ccs, s)
			zFused := refBerExpZ(rFused, ccs, s)
			if (w < zWant) == (w < zFused) {
				continue
			}

			want := refBerExp(newSamplerPRNGFromBytes(stream[:]), x, ccs)
			if want != (w < zWant) {
				t.Fatalf("reference BerExp disagrees with its own z for x=%x ccs=%x", float64(x), float64(ccs))
			}
			if got := berExp(newSamplerPRNGFromBytes(stream[:]), x, ccs); got != want {
				t.Fatalf("berExp(x=%x, ccs=%x) = %v, want %v (fused multiply-add rounding)", float64(x), float64(ccs), got, want)
			}
			found++
			break
		}
	}
	if found < wantCases {
		t.Fatalf("found only %d of %d boundary cases", found, wantCases)
	}
}

func TestSampleFFTPointMatchesReferenceAtFusionBoundary(t *testing.T) {
	// The sampler computes x = (z - r)^2 * dss - z0^2 * c, two products
	// feeding one subtraction; a fused build rounds whichever product it
	// fuses differently. With x < log(2) the BerExp reduction is exact
	// (s = 0), so x alone decides. For each of the two possible fusions this
	// test searches for a center mu at which that fusion and the reference
	// rounding decide the first candidate differently, and checks that
	// sampleFFTPoint follows the reference, both in its result and in how
	// many PRNG bytes it consumes.
	rnd := newRefRand("falcon1024 sampler fusion boundary")
	for variant := range 2 {
		found := false
		for label := 0; label < 4096 && !found; label++ {
			var stream [512]byte
			rnd.bytes(stream[:])
			probe := newSamplerPRNGFromBytes(stream[:])
			z0 := refGaussian0Sampler(probe)
			b := int(probe.readByte()) & 1
			// The fused product must be inexact: for z0 = 0 the subtracted
			// term is zero, and z0^2 * c is exact when z0^2 is a power of two.
			if z0 < 1 || (variant == 1 && z0&(z0-1) == 0) {
				continue
			}
			z := b + ((b<<1)-1)*z0
			w := berExpWord(stream[10:])
			zc := refMul(fpr(z0*z0), inv2SqrSigma0)

			// With s = 0, BerExp compares W against z(x) ~ 2^64 * ccs * exp(-x),
			// which crosses W at x0 = log(2^64 * ccs / W). Scan 1/sigma over
			// the Falcon-1024 leaf range for a crossing that puts the center
			// r in [0, 1).
			for step := 0; step < 64 && !found; step++ {
				isigma := fpr(0.549 + 0.221*float64(step)/64)
				ccs := refMul(isigma, sigmaMin1024)
				dss := refHalf(refSqr(isigma))
				x0 := math.Log(math.Ldexp(float64(ccs), 64) / float64(w))
				if x0 <= 0 || x0 >= 0.6 {
					continue
				}
				// Solve (z - r)^2 * dss - z0^2 * c = x0 for r.
				dist := math.Sqrt((x0 + float64(zc)) / float64(dss))
				r0 := dist - float64(z0)
				if b == 1 {
					r0 = float64(1+z0) - dist
				}
				if r0 <= 0 || r0 >= 1 {
					continue
				}

				for k := int64(-2048); k <= 2048 && !found; k++ {
					r := fpr(math.Float64frombits(uint64(int64(math.Float64bits(r0)) + k)))
					if r <= 0 || r >= 1 {
						continue
					}
					sq := refSqr(refSub(fpr(z), r))
					xWant := refSub(refMul(sq, dss), zc)
					var xFused fpr
					if variant == 0 {
						xFused = fpr(math.FMA(float64(sq), float64(dss), -float64(zc)))
					} else {
						xFused = fpr(math.FMA(-float64(z0*z0), float64(inv2SqrSigma0), float64(refMul(sq, dss))))
					}
					if xWant == xFused || xWant < 0 {
						continue
					}
					if fprTrunc(refMul(xWant, invLog2)) != 0 || fprTrunc(refMul(xFused, invLog2)) != 0 {
						continue
					}
					if (w < refBerExpZ(xWant, ccs, 0)) == (w < refBerExpZ(xFused, ccs, 0)) {
						continue
					}

					prng := newSamplerPRNGFromBytes(stream[:])
					refPRNG := newSamplerPRNGFromBytes(stream[:])
					got := sampleFFTPoint(prng, r, isigma)
					want := refSampler(refPRNG, r, isigma)
					if got != fpr(want) {
						t.Fatalf("variant %d: sampleFFTPoint(%x, %x) = %v, want %d (fused multiply-add rounding)",
							variant, float64(r), float64(isigma), got, want)
					}
					if prng.ptr != refPRNG.ptr || prng.counter != refPRNG.counter {
						t.Fatalf("variant %d: consumed %d bytes, reference consumed %d (fused multiply-add rounding)",
							variant, prng.ptr, refPRNG.ptr)
					}
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("variant %d: no boundary case found", variant)
		}
	}
}

// refPolyLDLFFT is the reference poly_LDL_fft (in place: l10 into g01, d11
// into g11).
func refPolyLDLFFT(g00, g01, g11 []fpr, logn int) {
	hn := 1 << (logn - 1)
	for u := range hn {
		g00Re, g00Im := g00[u], g00[u+hn]
		g01Re, g01Im := g01[u], g01[u+hn]
		g11Re, g11Im := g11[u], g11[u+hn]
		muRe, muIm := refFPCDiv(g01Re, g01Im, g00Re, g00Im)
		g01Re, g01Im = refFPCMul(muRe, muIm, g01Re, -g01Im)
		g11[u], g11[u+hn] = refSub(g11Re, g01Re), refSub(g11Im, g01Im)
		g01[u], g01[u+hn] = muRe, -muIm
	}
}

// refPolySub is the reference poly_sub.
func refPolySub(a, b []fpr, logn int) {
	for u := range 1 << logn {
		a[u] = refSub(a[u], b[u])
	}
}

// refFFSamplingFFTDyntree is the reference ffSampling_fft_dyntree, the
// sampler behind sign_dyn and therefore behind the NIST API. tmp needs at
// least 4 * 2^logn entries.
func refFFSamplingFFTDyntree(samp samplerZ, p *samplerPRNG, t0, t1, g00, g01, g11 []fpr, origLogn, logn int, tmp []fpr) {
	if logn == 0 {
		leaf := refMul(refSqrt(g00[0]), invSigma[origLogn])
		t0[0] = samp(p, t0[0], leaf)
		t1[0] = samp(p, t1[0], leaf)
		return
	}

	degree := 1 << logn
	hn := degree >> 1

	refPolyLDLFFT(g00, g01, g11, logn)

	refPolySplitFFT(tmp, tmp[hn:], g00, logn)
	copy(g00[:degree], tmp[:degree])
	refPolySplitFFT(tmp, tmp[hn:], g11, logn)
	copy(g11[:degree], tmp[:degree])
	copy(tmp[:degree], g01[:degree])
	copy(g01[:hn], g00[:hn])
	copy(g01[hn:degree], g11[:hn])

	z1 := tmp[degree:]
	refPolySplitFFT(z1, z1[hn:], t1, logn)
	refFFSamplingFFTDyntree(samp, p, z1, z1[hn:], g11, g11[hn:], g01[hn:], origLogn, logn-1, z1[degree:])
	merged := tmp[2*degree:]
	refPolyMergeFFT(merged, z1, z1[hn:], logn)

	copy(z1[:degree], t1[:degree])
	refPolySub(z1, merged, logn)
	copy(t1[:degree], merged[:degree])
	refPolyMulFFT(tmp, z1, logn)
	refPolyAdd(t0, tmp, logn)

	z0 := tmp
	refPolySplitFFT(z0, z0[hn:], t0, logn)
	refFFSamplingFFTDyntree(samp, p, z0, z0[hn:], g00, g00[hn:], g01, origLogn, logn-1, z0[degree:])
	refPolyMergeFFT(t0, z0, z0[hn:], logn)
}

// refIsShortHalf is the reference is_short_half.
func refIsShortHalf(sqn uint32, s2 [n]int16) bool {
	ng := -(sqn >> 31)
	for u := range n {
		z := int32(s2[u])
		sqn += uint32(z * z)
		ng |= sqn
	}
	sqn |= -(ng >> 31)
	return uint64(sqn) <= signatureNormBound
}

// refSignDynAttempt is the reference do_sign_dyn: one signing attempt from
// the compact key, with the Gram matrix and the LDL tree computed on the fly.
// refSamplerZ adapts the reference sampler transliteration to the samplerZ
// callback signature.
func refSamplerZ(p *samplerPRNG, mu, isigma fpr) fpr {
	return fpr(refSampler(p, mu, isigma))
}

func refSignDynAttempt(samp samplerZ, p *samplerPRNG, f, g, F, G smallPolynomial, hm ringElement) (smallPolynomial, bool) {
	var b00, b01, b10, b11 fftPolynomial
	for u := range n {
		b01[u] = fpr(f[u])
		b00[u] = fpr(g[u])
		b11[u] = fpr(F[u])
		b10[u] = fpr(G[u])
	}
	refFFT(b01[:], logN)
	refFFT(b00[:], logN)
	refFFT(b11[:], logN)
	refFFT(b10[:], logN)
	refPolyNeg(b01[:], logN)
	refPolyNeg(b11[:], logN)

	t0 := b01
	refPolyMulSelfAdjFFT(t0[:], logN)
	t1 := b00
	refPolyMulAdjFFT(t1[:], b10[:], logN)
	g00 := b00
	refPolyMulSelfAdjFFT(g00[:], logN)
	refPolyAdd(g00[:], t0[:], logN)
	g01 := b01
	refPolyMulAdjFFT(g01[:], b11[:], logN)
	refPolyAdd(g01[:], t1[:], logN)
	g11 := b10
	refPolyMulSelfAdjFFT(g11[:], logN)
	t1 = b11
	refPolyMulSelfAdjFFT(t1[:], logN)
	refPolyAdd(g11[:], t1[:], logN)

	for u := range n {
		t0[u] = fpr(hm[u])
	}
	refFFT(t0[:], logN)
	t1 = t0
	refPolyMulFFT(t1[:], b01[:], logN)
	refPolyMulConst(t1[:], -fprInverseOfQ, logN)
	refPolyMulFFT(t0[:], b11[:], logN)
	refPolyMulConst(t0[:], fprInverseOfQ, logN)

	var tmp [8 * n]fpr
	refFFSamplingFFTDyntree(samp, p, t0[:], t1[:], g00[:], g01[:], g11[:], logN, logN, tmp[:])

	tx := t0
	refPolyMulFFT(tx[:], b00[:], logN)
	ty := t1
	refPolyMulFFT(ty[:], b10[:], logN)
	refPolyAdd(tx[:], ty[:], logN)
	ty = t0
	refPolyMulFFT(ty[:], b01[:], logN)
	t0 = tx
	refPolyMulFFT(t1[:], b11[:], logN)
	refPolyAdd(t1[:], ty[:], logN)
	refIFFT(t0[:], logN)
	refIFFT(t1[:], logN)

	var sqn, ng uint32
	for u := range n {
		z := int32(hm[u]) - int32(fprRint(t0[u]))
		sqn += uint32(z * z)
		ng |= sqn
	}
	sqn |= -(ng >> 31)
	var s2tmp [n]int16
	for u := range n {
		s2tmp[u] = int16(-fprRint(t1[u]))
	}
	if !refIsShortHalf(sqn, s2tmp) {
		return smallPolynomial{}, false
	}
	var s2 smallPolynomial
	for u := range n {
		s2[u] = int32(s2tmp[u])
	}
	return s2, true
}

func TestSignAttemptMatchesReferenceSignDyn(t *testing.T) {
	// The NIST API signs with sign_dyn, whose sampler recurses with the
	// generic split and merge down to the leaves. The reference's other
	// signer, sign_tree, inlines the two lowest levels with a different
	// operation order, so the two round differently in the last bit and
	// only one of them can be matched. This pins signAttempt to sign_dyn,
	// result and PRNG consumption alike, on every attempt including rejected
	// ones.
	for key := range 2 {
		rng := sha3.NewSHAKE256()
		_, _ = rng.Write([]byte{byte(key), 's', 'i', 'g', 'n', 'd', 'y', 'n'})
		f, g, F, G, h := generateKeyComponents(rng)
		priv, err := initPrivateKey(&PrivateKey{}, f, g, F, G, h)
		if err != nil {
			t.Fatal(err)
		}

		for msg := range 6 {
			hash := sha3.NewSHAKE256()
			_, _ = hash.Write([]byte{byte(key), byte(msg), 'm', 's', 'g'})
			hm := hashToPoint(hash)

			seed := sha3.NewSHAKE256()
			_, _ = seed.Write([]byte{byte(key), byte(msg), 'p', 'r', 'n', 'g'})
			var prng samplerPRNG
			initSamplerPRNG(&prng, seed)
			ref := prng

			gotS2, gotOK := signAttempt(&prng, priv, hm)
			wantS2, wantOK := refSignDynAttempt(refSamplerZ, &ref, f, g, F, G, hm)
			if gotOK != wantOK {
				t.Fatalf("key %d message %d: accepted = %v, reference accepted = %v", key, msg, gotOK, wantOK)
			}
			if gotS2 != wantS2 {
				t.Fatalf("key %d message %d: signAttempt differs from the reference sign_dyn", key, msg)
			}
			if prng.ptr != ref.ptr || prng.counter != ref.counter {
				t.Fatalf("key %d message %d: consumed %d PRNG bytes (counter %d), reference consumed %d (counter %d)",
					key, msg, prng.ptr, prng.counter, ref.ptr, ref.counter)
			}
		}
	}
}

func TestFFSamplingFFTMatchesReferenceDyntree(t *testing.T) {
	// Pins the whole Fast Fourier sampling recursion, including every split,
	// merge and LDL value it hands to the integer sampler, to the reference
	// ffSampling_fft_dyntree bit for bit. The integer sampler is replaced on
	// both sides by a deterministic recorder, so the comparison covers the
	// centers and standard deviations passed down, which the sampled
	// integers alone would reveal only with negligible probability.
	type sample struct{ mu, isigma fpr }
	recorder := func(log *[]sample) samplerZ {
		return func(_ *samplerPRNG, mu, isigma fpr) fpr {
			*log = append(*log, sample{mu, isigma})
			// A deterministic stand-in for the Gaussian sample: the rounded
			// center, nudged by a value that varies with the position.
			return fpr(math.Round(float64(mu))) + fpr(len(*log)%3-1)
		}
	}

	for key := range 2 {
		rng := sha3.NewSHAKE256()
		_, _ = rng.Write([]byte{byte(key), 'd', 'y', 'n', 't', 'r', 'e', 'e'})
		f, g, F, G, h := generateKeyComponents(rng)
		priv, err := initPrivateKey(&PrivateKey{}, f, g, F, G, h)
		if err != nil {
			t.Fatal(err)
		}
		b00, b01, b10, b11, _ := refExpandPrivateKey(f, g, F, G)
		g00, g01, g11 := gramInputs(b00, b01, b10, b11)

		for msg := range 3 {
			hash := sha3.NewSHAKE256()
			_, _ = hash.Write([]byte{byte(key), byte(msg), 't', 'a', 'r', 'g', 'e', 't'})
			hm := hashToPoint(hash)

			// The target vector, computed with the reference arithmetic and
			// shared by both sides.
			var t0 fftPolynomial
			for u := range n {
				t0[u] = fpr(hm[u])
			}
			refFFT(t0[:], logN)
			t1 := t0
			refPolyMulFFT(t1[:], b01[:], logN)
			refPolyMulConst(t1[:], -fprInverseOfQ, logN)
			refPolyMulFFT(t0[:], b11[:], logN)
			refPolyMulConst(t0[:], fprInverseOfQ, logN)

			var gotLog []sample
			var z0, z1 fftPolynomial
			ffSamplingFFT(recorder(&gotLog), nil, z0[:], z1[:], t0[:], t1[:], priv.tree[:], logN)

			var wantLog []sample
			wantT0, wantT1 := t0, t1
			wantG00, wantG01, wantG11 := g00, g01, g11
			var tmp [8 * n]fpr
			refFFSamplingFFTDyntree(recorder(&wantLog), nil, wantT0[:], wantT1[:],
				wantG00[:], wantG01[:], wantG11[:], logN, logN, tmp[:])

			if len(gotLog) != len(wantLog) {
				t.Fatalf("key %d message %d: %d sampler calls, reference made %d", key, msg, len(gotLog), len(wantLog))
			}
			for i := range wantLog {
				if math.Float64bits(float64(gotLog[i].mu)) != math.Float64bits(float64(wantLog[i].mu)) ||
					math.Float64bits(float64(gotLog[i].isigma)) != math.Float64bits(float64(wantLog[i].isigma)) {
					t.Fatalf("key %d message %d: sampler call %d: got (%x, %x), want (%x, %x)",
						key, msg, i, float64(gotLog[i].mu), float64(gotLog[i].isigma),
						float64(wantLog[i].mu), float64(wantLog[i].isigma))
				}
			}
			requireSameBits(t, "z0", z0[:], wantT0[:])
			requireSameBits(t, "z1", z1[:], wantT1[:])
		}
	}
}

// refIsShort is the reference is_short.
func refIsShort(s1, s2 [n]int16) bool {
	var s, ng uint32
	for u := range n {
		z := int32(s1[u])
		s += uint32(z * z)
		ng |= s
		z = int32(s2[u])
		s += uint32(z * z)
		ng |= s
	}
	s |= -(ng >> 31)
	return uint64(s) <= signatureNormBound
}

// refPolySmallSqnorm is the reference poly_small_sqnorm over the int8 range.
func refPolySmallSqnorm(f [n]int8) uint32 {
	var s, ng uint32
	for u := range n {
		z := int32(f[u])
		s += uint32(z * z)
		ng |= s
	}
	return s | -(ng >> 31)
}

func TestNormChecksMatchReference(t *testing.T) {
	// The norm checks must decide exactly as the reference's saturating
	// 32-bit accumulators, including on sums that overflow 32 bits, which
	// honest keys and signatures never produce.
	rnd := newRefRand("falcon1024 norm checks reference")
	for round := range 256 {
		var s1, s2 [n]int16
		var p1, p2 smallPolynomial
		var f [n]int8
		var pf smallPolynomial
		scale := []int{4, 64, 2048, 8192, 32768}[round%5]
		for u := range n {
			v := rnd.uint64()
			s1[u] = int16(int(v&0xFFFF) % scale)
			s2[u] = int16(int((v>>16)&0xFFFF) % scale)
			if v>>32&1 != 0 {
				s1[u] = -s1[u]
			}
			if v>>33&1 != 0 {
				s2[u] = -s2[u]
			}
			p1[u], p2[u] = int32(s1[u]), int32(s2[u])
			f[u] = int8(v >> 40)
			pf[u] = int32(f[u])
		}
		if got, want := signatureNormWithinBound(p1, p2), refIsShort(s1, s2); got != want {
			t.Fatalf("round %d: signatureNormWithinBound = %v, reference is_short = %v", round, got, want)
		}
		sqn := uint32(rnd.uint64())
		if round%4 == 0 {
			sqn = uint32(rnd.uint64()) >> 8
		}
		if got, want := signatureNormExceedsPartialBound(sqn, p2), !refIsShortHalf(sqn, s2); got != want {
			t.Fatalf("round %d: signatureNormExceedsPartialBound = %v, reference is_short_half = %v", round, got, !want)
		}
		if got, want := pf.squaredNorm(), refPolySmallSqnorm(f); got != want {
			t.Fatalf("round %d: squaredNorm = %d, reference poly_small_sqnorm = %d", round, got, want)
		}
	}

	// Saturation: a sum that wraps past 32 bits must still count as too large.
	var big smallPolynomial
	for u := range big {
		big[u] = 32767
	}
	if signatureNormWithinBound(big, big) {
		t.Fatal("signatureNormWithinBound accepted an overflowing norm")
	}
	if !signatureNormExceedsPartialBound(0, big) {
		t.Fatal("signatureNormExceedsPartialBound accepted an overflowing norm")
	}
	if big.squaredNorm() != 0xFFFFFFFF {
		t.Fatalf("squaredNorm of an overflowing polynomial = %#x, want saturated", big.squaredNorm())
	}
}

func TestGaussian0SampleMatchesReference(t *testing.T) {
	rnd := newRefRand("falcon1024 gaussian0 reference")
	for i := range 64 {
		var stream [512]byte
		rnd.bytes(stream[:])
		prng := newSamplerPRNGFromBytes(stream[:])
		ref := newSamplerPRNGFromBytes(stream[:])
		for j := range 56 {
			got, want := gaussian0Sample(prng), refGaussian0Sampler(ref)
			if got != want {
				t.Fatalf("stream %d sample %d: gaussian0Sample = %d, reference = %d", i, j, got, want)
			}
		}
		if prng.ptr != ref.ptr || prng.counter != ref.counter {
			t.Fatalf("stream %d: consumed %d bytes, reference consumed %d", i, prng.ptr, ref.ptr)
		}
	}
}

func TestCompletePrivateCenterMatchesReference(t *testing.T) {
	// complete_private subtracts q from every residue of q/2 and above:
	// w -= Q & ~-((w - (Q >> 1)) >> 31).
	for w := uint32(0); w < q; w++ {
		want := int32(w)
		if w >= q/2 {
			want -= q
		}
		if got := completePrivateCenter(w); got != want {
			t.Fatalf("completePrivateCenter(%d) = %d, want %d", w, got, want)
		}
	}
	for _, tc := range []struct {
		w    uint32
		want int32
	}{
		{0, 0}, {6143, 6143}, {6144, -6145}, {6145, -6144}, {12288, -1},
	} {
		if got := completePrivateCenter(tc.w); got != tc.want {
			t.Fatalf("completePrivateCenter(%d) = %d, want %d", tc.w, got, tc.want)
		}
	}
}
