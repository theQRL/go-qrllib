package falcon1024

import "math"

const ntruCoeffBound = 127

var (
	maxBlSmall = [...]int{1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209}
	maxBlLarge = [...]int{2, 2, 5, 7, 12, 21, 40, 78, 157, 308}
)

func solveNTRU(f, g smallPolynomial) (ntruF, ntruG smallPolynomial, ok bool) {
	wk := newNTRUWorkspace()

	if !solveNTRUDeepest(f, g, wk.solution) {
		return smallPolynomial{}, smallPolynomial{}, false
	}

	for depth := logN; depth > 2; {
		depth--
		if !solveNTRUIntermediate(f, g, depth, wk) {
			return smallPolynomial{}, smallPolynomial{}, false
		}
	}
	if !solveNTRUBinaryDepth1(f, g, wk) {
		return smallPolynomial{}, smallPolynomial{}, false
	}
	solveNTRUBinaryDepth0(f, g, wk)

	ntruF, ok = polyBigToSmall(wk.solution[:n], ntruCoeffBound)
	if !ok {
		return smallPolynomial{}, smallPolynomial{}, false
	}
	ntruG, ok = polyBigToSmall(wk.solution[n:2*n], ntruCoeffBound)
	if !ok {
		return smallPolynomial{}, smallPolynomial{}, false
	}
	if !checkNTRUEquation(f, g, ntruF, ntruG, wk.scratch.u32) {
		return smallPolynomial{}, smallPolynomial{}, false
	}
	return ntruF, ntruG, true
}

const (
	// ntruScratchLen is the rounded uint32 capacity for the persistent NTRU
	// solution buffer and the deepest-stage workspace carved from it.
	ntruScratchLen = 7 * n

	// makeFGScratchLen is the rounded uint32 capacity for makeFG; the largest
	// layout is the first makeFGStep at full Falcon degree.
	makeFGScratchLen = 6 * n

	// polySubScaledNTTScratchLen is the maximum uint32 workspace needed by
	// polySubScaledNTT across the depths where the NTT path is used.
	polySubScaledNTTScratchLen = 1536

	// ntruU32ScratchLen is the rounded uint32 scratch capacity; binary depth 0
	// saturates the current layout.
	ntruU32ScratchLen = 11 * n

	// ntruFPRScratchLen is the rounded fpr scratch capacity; binary depth 1 is
	// the largest current user.
	ntruFPRScratchLen = 8 * n

	// Intermediate buffers below are exact maxima for solveNTRUIntermediate
	// across the depths where it runs (2..logN-1).
	ntruInterFdGdMax = 256  // max(dlen*hn) at depth 2 and 3 (tied)
	ntruInterFtGtMax = 1280 // max(n*llen)  at depth 2
	ntruInterNMax    = 256  // max n         at depth 2
)

// ntruWorkspace mirrors the Falcon reference tmp scratch model, but keeps
// uint32 and fpr scratch storage separate for Go type safety. All buffers are
// owned by the workspace so per-keygen helpers can borrow slices without
// allocating.
type ntruWorkspace struct {
	// solution carries serialized F || G across recursive depths. During the
	// deepest stage it also acts as temporary scratch before the result is
	// written into its leading words.
	solution []uint32

	scratch         ntruScratchWorkspace
	makeFGWorkspace ntruMakeFGWorkspace
	intermediate    ntruIntermediateWorkspace
}

type ntruScratchWorkspace struct {
	u32 []uint32 // generic uint32 scratch (newUint32Scratch consumers)
	fpr []fpr    // generic fpr scratch    (newFPRScratch consumers)
}

type ntruMakeFGWorkspace struct {
	data []uint32 // 6*N, used by makeFG and the ft/gt slices it leaves behind
}

type ntruIntermediateWorkspace struct {
	Fd, Gd []uint32 // dlen*hn snapshot of wk.solution from previous depth
	Ft, Gt []uint32 // n*llen lifted solution

	k []int32
}

func newNTRUWorkspace() *ntruWorkspace {
	return &ntruWorkspace{
		solution: make([]uint32, ntruScratchLen),
		scratch: ntruScratchWorkspace{
			u32: make([]uint32, ntruU32ScratchLen),
			fpr: make([]fpr, ntruFPRScratchLen),
		},
		makeFGWorkspace: ntruMakeFGWorkspace{
			data: make([]uint32, makeFGScratchLen),
		},
		intermediate: ntruIntermediateWorkspace{
			Fd: make([]uint32, ntruInterFdGdMax),
			Gd: make([]uint32, ntruInterFdGdMax),
			Ft: make([]uint32, ntruInterFtGtMax),
			Gt: make([]uint32, ntruInterFtGtMax),
			k:  make([]int32, ntruInterNMax),
		},
	}
}

type uint32Scratch struct {
	buf []uint32
	off int
}

func newUint32Scratch(buf []uint32) uint32Scratch {
	return uint32Scratch{buf: buf}
}

func (s *uint32Scratch) take(size int) []uint32 {
	if size < 0 || size > len(s.buf)-s.off {
		panic("falcon1024: NTRU scratch exhausted")
	}
	out := s.buf[s.off : s.off+size]
	s.off += size
	return out
}

func (s *uint32Scratch) takeCopy(src []uint32) []uint32 {
	out := s.take(len(src))
	copy(out, src)
	return out
}

type fprScratch struct {
	buf []fpr
	off int
}

func newFPRScratch(buf []fpr) fprScratch {
	return fprScratch{buf: buf}
}

func (s *fprScratch) take(size int) []fpr {
	if size < 0 || size > len(s.buf)-s.off {
		panic("falcon1024: NTRU scratch exhausted")
	}
	out := s.buf[s.off : s.off+size]
	s.off += size
	return out
}

type ntruLiftScratch struct {
	gm, igm    []uint32
	fx, gx     []uint32
	Fp, Gp     []uint32
	crtScratch []uint32
}

func (wk *ntruWorkspace) liftScratch(degree, hn, llen, slen int) ntruLiftScratch {
	u32s := newUint32Scratch(wk.scratch.u32)
	return ntruLiftScratch{
		gm:         u32s.take(degree),
		igm:        u32s.take(degree),
		fx:         u32s.take(degree),
		gx:         u32s.take(degree),
		Fp:         u32s.take(hn),
		Gp:         u32s.take(hn),
		crtScratch: u32s.take(max(llen, slen)),
	}
}

type ntruReduceScratch struct {
	scaledNTT []uint32

	rt1, rt2 []fpr
	rt3, rt4 []fpr
	rt5      []fpr
}

func (wk *ntruWorkspace) reduceScratch(degree int) ntruReduceScratch {
	fprs := newFPRScratch(wk.scratch.fpr)
	u32s := newUint32Scratch(wk.scratch.u32)
	return ntruReduceScratch{
		rt1:       fprs.take(degree),
		rt2:       fprs.take(degree),
		rt3:       fprs.take(degree),
		rt4:       fprs.take(degree),
		rt5:       fprs.take(degree >> 1),
		scaledNTT: u32s.take(polySubScaledNTTScratchLen),
	}
}

type ntruDepth0Scratch struct {
	prevF, prevG []uint32
	Fp, Gp       []uint32
	ft, gt       []uint32
	gm, igm      []uint32
	t2, t3       []uint32
	t4, t5       []uint32

	num, den []fpr
	work     []fpr
}

func (wk *ntruWorkspace) depth0Scratch(degree, hn int) ntruDepth0Scratch {
	u32s := newUint32Scratch(wk.scratch.u32)
	fprs := newFPRScratch(wk.scratch.fpr)
	return ntruDepth0Scratch{
		prevF: u32s.takeCopy(wk.solution[:hn]),
		prevG: u32s.takeCopy(wk.solution[hn:degree]),
		Fp:    u32s.take(degree),
		Gp:    u32s.take(degree),
		ft:    u32s.take(degree),
		gt:    u32s.take(degree),
		gm:    u32s.take(degree),
		igm:   u32s.take(degree),
		t2:    u32s.take(degree),
		t3:    u32s.take(degree),
		t4:    u32s.take(degree),
		t5:    u32s.take(degree),
		num:   fprs.take(degree),
		den:   fprs.take(hn),
		work:  fprs.take(degree),
	}
}

type ntruDepth1Scratch struct {
	Fd, Gd     []uint32
	Ft, Gt     []uint32
	ft, gt     []uint32
	gmFull     []uint32
	igmFull    []uint32
	fx, gx     []uint32
	Fp, Gp     []uint32
	crtScratch []uint32

	rt1, rt2 []fpr
	rt3, rt4 []fpr
	rt5, rt6 []fpr
	kf, kg   []fpr
}

func (wk *ntruWorkspace) depth1Scratch(degree, hn, slen, dlen, llen int) ntruDepth1Scratch {
	u32s := newUint32Scratch(wk.scratch.u32)
	fprs := newFPRScratch(wk.scratch.fpr)
	return ntruDepth1Scratch{
		Fd:         u32s.takeCopy(wk.solution[:dlen*hn]),
		Gd:         u32s.takeCopy(wk.solution[dlen*hn : 2*dlen*hn]),
		Ft:         u32s.take(degree * llen),
		Gt:         u32s.take(degree * llen),
		ft:         u32s.take(degree * slen),
		gt:         u32s.take(degree * slen),
		gmFull:     u32s.take(n),
		igmFull:    u32s.take(n),
		fx:         u32s.take(n),
		gx:         u32s.take(n),
		Fp:         u32s.take(hn),
		Gp:         u32s.take(hn),
		crtScratch: u32s.take(max(llen, slen)),
		rt1:        fprs.take(degree),
		rt2:        fprs.take(degree),
		rt3:        fprs.take(degree),
		rt4:        fprs.take(degree),
		rt5:        fprs.take(degree),
		rt6:        fprs.take(degree >> 1),
		kf:         fprs.take(degree),
		kg:         fprs.take(degree),
	}
}

func checkNTRUEquation(f, g, ntruF, ntruG smallPolynomial, scratch []uint32) bool {
	p := smallPrimes[0].p
	p0i := smallPrimeDerivedValues[0].p0i
	gm := scratch[:n]
	igm := scratch[n : 2*n]
	modPMkgm2(gm, igm, logN, smallPrimes[0].g, p, p0i)

	ft := scratch[2*n : 3*n]
	gt := scratch[3*n : 4*n]
	Ft := scratch[4*n : 5*n]
	Gt := scratch[5*n : 6*n]
	for i := range n {
		ft[i] = modPSet(f[i], p)
		gt[i] = modPSet(g[i], p)
		Ft[i] = modPSet(ntruF[i], p)
		Gt[i] = modPSet(ntruG[i], p)
	}

	modPNTT2(ft, gm, logN, p, p0i)
	modPNTT2(gt, gm, logN, p, p0i)
	modPNTT2(Ft, gm, logN, p, p0i)
	modPNTT2(Gt, gm, logN, p, p0i)

	target := modPMontyMul(q, 1, p, p0i)
	for i := range n {
		z := modPSub(
			modPMontyMul(ft[i], Gt[i], p, p0i),
			modPMontyMul(gt[i], Ft[i], p, p0i),
			p,
		)
		if z != target {
			return false
		}
	}

	return true
}

func makeFG(data []uint32, f, g smallPolynomial, depth int, outNTT bool) {
	ft := data[:n]
	gt := data[n : 2*n]
	p0 := smallPrimes[0].p
	for i := range n {
		ft[i] = modPSet(f[i], p0)
		gt[i] = modPSet(g[i], p0)
	}

	if depth == 0 && outNTT {
		p := smallPrimes[0].p
		p0i := smallPrimeDerivedValues[0].p0i
		gm := data[2*n : 3*n]
		igm := data[3*n : 4*n]
		modPMkgm2(gm, igm, logN, smallPrimes[0].g, p, p0i)
		modPNTT2(ft, gm, logN, p, p0i)
		modPNTT2(gt, gm, logN, p, p0i)
		return
	}
	for d := range depth {
		makeFGStep(data, logN-d, d, d != 0, (d+1) < depth || outNTT)
	}
}

func (wk *ntruWorkspace) makeFGIntermediate(f, g smallPolynomial, depth, degree, slen int) (ft, gt []uint32) {
	data := wk.makeFGWorkspace.data[:makeFGScratchLen]
	makeFG(data, f, g, depth, true)
	return data[:degree*slen], data[degree*slen : 2*degree*slen]
}

type makeFGStepLayout struct {
	fd, gd []uint32
	fs, gs []uint32
	gm     []uint32
	igm    []uint32
	t1     []uint32

	crtScratch []uint32
	fsOff      int
	gmOff      int
}

func makeFGStepLayoutOf(data []uint32, degree, hn, slen, tlen int) makeFGStepLayout {
	fsOff := 2 * hn * tlen
	gmOff := fsOff + 2*degree*slen
	t1Off := gmOff + 2*degree

	t1 := data[t1Off : t1Off+degree]
	crtScratch := t1
	if len(crtScratch) < slen {
		scratchOff := t1Off + degree
		crtScratch = data[scratchOff : scratchOff+slen]
	}

	return makeFGStepLayout{
		fd:         data[:hn*tlen],
		gd:         data[hn*tlen : fsOff],
		fs:         data[fsOff : fsOff+degree*slen],
		gs:         data[fsOff+degree*slen : gmOff],
		gm:         data[gmOff : gmOff+degree],
		igm:        data[gmOff+degree : t1Off],
		t1:         t1,
		crtScratch: crtScratch[:slen],
		fsOff:      fsOff,
		gmOff:      gmOff,
	}
}

func makeFGStep(data []uint32, logn, depth int, inNTT, outNTT bool) {
	degree := 1 << logn
	hn := degree >> 1
	slen := maxBlSmall[depth]
	tlen := maxBlSmall[depth+1]

	layout := makeFGStepLayoutOf(data, degree, hn, slen, tlen)
	fd, gd := layout.fd, layout.gd
	fs, gs := layout.fs, layout.gs
	gm, igm, t1 := layout.gm, layout.igm, layout.t1

	// Move the source f/g limbs out of the output fd/gd area before writing
	// the next-depth values. The source and destination may overlap, matching
	// the Falcon reference tmp-buffer memmove.
	copy(data[layout.fsOff:layout.gmOff], data[:2*degree*slen])
	for u := range slen {
		prime := smallPrimes[u]
		derived := smallPrimeDerivedValues[u]
		p := prime.p
		p0i := derived.p0i
		r2 := derived.r2
		modPMkgm2(gm, igm, logn, prime.g, p, p0i)

		for v, x := 0, u; v < degree; v, x = v+1, x+slen {
			t1[v] = fs[x]
		}
		if !inNTT {
			modPNTT2(t1, gm, logn, p, p0i)
		}
		for v, x := 0, u; v < hn; v, x = v+1, x+tlen {
			w0 := t1[v<<1]
			w1 := t1[(v<<1)+1]
			fd[x] = modPMontyMul(modPMontyMul(w0, w1, p, p0i), r2, p, p0i)
		}
		if inNTT {
			modPINTT2Ext(fs[u:], slen, igm, logn, p, p0i)
		}

		for v, x := 0, u; v < degree; v, x = v+1, x+slen {
			t1[v] = gs[x]
		}
		if !inNTT {
			modPNTT2(t1, gm, logn, p, p0i)
		}
		for v, x := 0, u; v < hn; v, x = v+1, x+tlen {
			w0 := t1[v<<1]
			w1 := t1[(v<<1)+1]
			gd[x] = modPMontyMul(modPMontyMul(w0, w1, p, p0i), r2, p, p0i)
		}
		if inNTT {
			modPINTT2Ext(gs[u:], slen, igm, logn, p, p0i)
		}

		if !outNTT {
			modPINTT2Ext(fd[u:], tlen, igm, logn-1, p, p0i)
			modPINTT2Ext(gd[u:], tlen, igm, logn-1, p, p0i)
		}
	}

	zintRebuildCRT(fs, slen, slen, degree, smallPrimes[:], true, layout.crtScratch)
	zintRebuildCRT(gs, slen, slen, degree, smallPrimes[:], true, layout.crtScratch)

	for u := slen; u < tlen; u++ {
		prime := smallPrimes[u]
		derived := smallPrimeDerivedValues[u]
		p := prime.p
		p0i := derived.p0i
		r2 := derived.r2
		rx := modPRx(slen, p, p0i, r2)
		modPMkgm2(gm, igm, logn, prime.g, p, p0i)

		for v, x := 0, 0; v < degree; v, x = v+1, x+slen {
			t1[v] = zintModSmallSigned(fs[x:x+slen], p, p0i, r2, rx)
		}
		modPNTT2(t1, gm, logn, p, p0i)
		for v, x := 0, u; v < hn; v, x = v+1, x+tlen {
			w0 := t1[v<<1]
			w1 := t1[(v<<1)+1]
			fd[x] = modPMontyMul(modPMontyMul(w0, w1, p, p0i), r2, p, p0i)
		}

		for v, x := 0, 0; v < degree; v, x = v+1, x+slen {
			t1[v] = zintModSmallSigned(gs[x:x+slen], p, p0i, r2, rx)
		}
		modPNTT2(t1, gm, logn, p, p0i)
		for v, x := 0, u; v < hn; v, x = v+1, x+tlen {
			w0 := t1[v<<1]
			w1 := t1[(v<<1)+1]
			gd[x] = modPMontyMul(modPMontyMul(w0, w1, p, p0i), r2, p, p0i)
		}

		if !outNTT {
			modPINTT2Ext(fd[u:], tlen, igm, logn-1, p, p0i)
			modPINTT2Ext(gd[u:], tlen, igm, logn-1, p, p0i)
		}
	}
}

type ntruDeepestLayout struct {
	Fp, Gp     []uint32
	resultants []uint32
	fp, gp     []uint32
	scratch    []uint32
}

func ntruDeepestLayoutOf(tmp []uint32, wordLen int) ntruDeepestLayout {
	resultants := tmp[2*wordLen:]
	return ntruDeepestLayout{
		Fp:         tmp[:wordLen],
		Gp:         tmp[wordLen : 2*wordLen],
		resultants: resultants,
		fp:         resultants[:wordLen],
		gp:         resultants[wordLen : 2*wordLen],
		scratch:    tmp[4*wordLen:],
	}
}

func solveNTRUDeepest(f, g smallPolynomial, tmp []uint32) bool {
	wordLen := maxBlSmall[logN]
	layout := ntruDeepestLayoutOf(tmp, wordLen)

	makeFG(layout.resultants, f, g, logN, false)
	zintRebuildCRT(layout.resultants, wordLen, wordLen, 2, smallPrimes[:], false, layout.scratch)

	if !zintBezout(layout.Gp, layout.Fp, layout.fp, layout.gp, layout.scratch) {
		return false
	}

	if zintMulSmall(layout.Fp, q) != 0 || zintMulSmall(layout.Gp, q) != 0 {
		return false
	}

	return true
}

func polyBigToFP(dst []fpr, src []uint32, wordLen, stride, logn int) {
	degree := 1 << logn
	if wordLen == 0 {
		clear(dst[:degree])
		return
	}
	for i := range degree {
		x := src[i*stride:]
		neg := -(x[wordLen-1] >> 30)
		xm := neg >> 1
		cc := neg & 1
		var y fpr
		scale := fpr(1)
		for j := range wordLen {
			w := (x[j] ^ xm) + cc
			cc = w >> 31
			w &= mask31
			w -= (w << 1) & neg
			y += fpr(int32(w)) * scale
			scale *= twoTo31
		}
		dst[i] = y
	}
}

func polyBigToSmall(src []uint32, bound int) (smallPolynomial, bool) {
	var dst smallPolynomial
	for i := range dst {
		x := zintOneToPlain(src[i])
		if x < int32(-bound) || x > int32(bound) {
			return smallPolynomial{}, false
		}
		dst[i] = x
	}
	return dst, true
}

func polySubScaled(F []uint32, Flen, Fstride int, f []uint32, flen, fstride int, k []int32, sch, scl uint32, logn int) {
	degree := 1 << logn
	for u := range degree {
		kf := -k[u]
		x := u * Fstride
		for v := range degree {
			zintAddScaledMulSmall(F[x:x+Flen], f[v*fstride:v*fstride+flen], kf, sch, scl)
			if u+v == degree-1 {
				x = 0
				kf = -kf
			} else {
				x += Fstride
			}
		}
	}
}

type polySubScaledNTTLayout struct {
	gm, igm []uint32
	fk      []uint32
	t1      []uint32
}

func polySubScaledNTTLayoutOf(tmp []uint32, degree, tlen int) polySubScaledNTTLayout {
	return polySubScaledNTTLayout{
		gm:  tmp[:degree],
		igm: tmp[degree : 2*degree],
		fk:  tmp[2*degree : 2*degree+degree*tlen],
		t1:  tmp[2*degree+degree*tlen : 3*degree+degree*tlen],
	}
}

func polySubScaledNTT(F []uint32, Flen, Fstride int, f []uint32, flen, fstride int, k []int32, sch, scl uint32, logn int, tmp []uint32) {
	degree := 1 << logn
	tlen := flen + 1
	layout := polySubScaledNTTLayoutOf(tmp, degree, tlen)
	gm, igm := layout.gm, layout.igm
	fk, t1 := layout.fk, layout.t1
	for u := range tlen {
		prime := smallPrimes[u]
		derived := smallPrimeDerivedValues[u]
		p := prime.p
		p0i := derived.p0i
		r2 := derived.r2
		rx := modPRx(flen, p, p0i, r2)
		modPMkgm2(gm, igm, logn, prime.g, p, p0i)
		for v := range degree {
			t1[v] = modPSet(k[v], p)
		}
		modPNTT2(t1, gm, logn, p, p0i)

		for v, x := 0, u; v < degree; v, x = v+1, x+tlen {
			fk[x] = zintModSmallSigned(f[v*fstride:v*fstride+flen], p, p0i, r2, rx)
		}
		modPNTT2Ext(fk[u:], tlen, gm, logn, p, p0i)

		for v, x := 0, u; v < degree; v, x = v+1, x+tlen {
			fk[x] = modPMontyMul(modPMontyMul(t1[v], fk[x], p, p0i), r2, p, p0i)
		}
		modPINTT2Ext(fk[u:], tlen, igm, logn, p, p0i)
	}

	zintRebuildCRT(fk, tlen, tlen, degree, smallPrimes[:], true, t1)
	for u := range degree {
		zintSubScaled(F[u*Fstride:u*Fstride+Flen], fk[u*tlen:u*tlen+tlen], sch, scl)
	}
}

func solveNTRUIntermediate(f, g smallPolynomial, depth int, wk *ntruWorkspace) bool {
	logn := logN - depth
	degree := 1 << logn
	hn := degree >> 1

	slen := maxBlSmall[depth]
	dlen := maxBlSmall[depth+1]
	llen := maxBlLarge[depth]

	// Snapshot the previous depth's solution out of wk.solution before lift /
	// reduce overwrites it.
	Fd := wk.intermediate.Fd[:dlen*hn]
	Gd := wk.intermediate.Gd[:dlen*hn]
	copy(Fd, wk.solution[:dlen*hn])
	copy(Gd, wk.solution[dlen*hn:2*dlen*hn])

	// makeFG leaves ft/gt in wk.makeFGWorkspace.data; they remain valid until the
	// scratch buffer is reused by the next intermediate-depth step.
	ft, gt := wk.makeFGIntermediate(f, g, depth, degree, slen)

	Ft := wk.intermediate.Ft[:degree*llen]
	Gt := wk.intermediate.Gt[:degree*llen]

	liftNTRUSolution(wk, Ft, Gt, Fd, Gd, ft, gt, logn, slen, dlen, llen)

	if !reduceNTRUSolution(wk, Ft, Gt, ft, gt, depth, logn, slen, llen) {
		return false
	}
	writeReducedNTRUSolution(wk.solution, Ft, Gt, degree, slen, llen)
	return true
}

func liftNTRUSolution(wk *ntruWorkspace, Ft, Gt, Fd, Gd, ft, gt []uint32, logn, slen, dlen, llen int) {
	degree := 1 << logn
	hn := degree >> 1

	scratch := wk.liftScratch(degree, hn, llen, slen)

	// First reduce the previous-depth F/G modulo all primes needed for the lift.
	for u := range llen {
		derived := smallPrimeDerivedValues[u]
		p := smallPrimes[u].p
		p0i := derived.p0i
		r2 := derived.r2
		rx := modPRx(dlen, p, p0i, r2)
		for v := range hn {
			Ft[v*llen+u] = zintModSmallSigned(Fd[v*dlen:v*dlen+dlen], p, p0i, r2, rx)
			Gt[v*llen+u] = zintModSmallSigned(Gd[v*dlen:v*dlen+dlen], p, p0i, r2, rx)
		}
	}

	for u := range llen {
		prime := smallPrimes[u]
		derived := smallPrimeDerivedValues[u]
		p := prime.p
		p0i := derived.p0i
		r2 := derived.r2

		if u == slen {
			zintRebuildCRT(ft, slen, slen, degree, smallPrimes[:], true, scratch.crtScratch[:slen])
			zintRebuildCRT(gt, slen, slen, degree, smallPrimes[:], true, scratch.crtScratch[:slen])
		}

		modPMkgm2(scratch.gm, scratch.igm, logn, prime.g, p, p0i)

		if u < slen {
			for v := range degree {
				scratch.fx[v] = ft[v*slen+u]
				scratch.gx[v] = gt[v*slen+u]
			}
			modPINTT2Ext(ft[u:], slen, scratch.igm, logn, p, p0i)
			modPINTT2Ext(gt[u:], slen, scratch.igm, logn, p, p0i)
		} else {
			rx := modPRx(slen, p, p0i, r2)
			for v := range degree {
				scratch.fx[v] = zintModSmallSigned(ft[v*slen:v*slen+slen], p, p0i, r2, rx)
				scratch.gx[v] = zintModSmallSigned(gt[v*slen:v*slen+slen], p, p0i, r2, rx)
			}
			modPNTT2(scratch.fx, scratch.gm, logn, p, p0i)
			modPNTT2(scratch.gx, scratch.gm, logn, p, p0i)
		}

		for v := range hn {
			scratch.Fp[v] = Ft[v*llen+u]
			scratch.Gp[v] = Gt[v*llen+u]
		}
		modPNTT2(scratch.Fp, scratch.gm, logn-1, p, p0i)
		modPNTT2(scratch.Gp, scratch.gm, logn-1, p, p0i)
		for v := range hn {
			ftA := scratch.fx[v<<1]
			ftB := scratch.fx[(v<<1)+1]
			gtA := scratch.gx[v<<1]
			gtB := scratch.gx[(v<<1)+1]
			mFp := modPMontyMul(scratch.Fp[v], r2, p, p0i)
			mGp := modPMontyMul(scratch.Gp[v], r2, p, p0i)
			Ft[(v<<1)*llen+u] = modPMontyMul(gtB, mFp, p, p0i)
			Ft[((v<<1)+1)*llen+u] = modPMontyMul(gtA, mFp, p, p0i)
			Gt[(v<<1)*llen+u] = modPMontyMul(ftB, mGp, p, p0i)
			Gt[((v<<1)+1)*llen+u] = modPMontyMul(ftA, mGp, p, p0i)
		}
		modPINTT2Ext(Ft[u:], llen, scratch.igm, logn, p, p0i)
		modPINTT2Ext(Gt[u:], llen, scratch.igm, logn, p, p0i)
	}

	zintRebuildCRT(Ft, llen, llen, degree, smallPrimes[:], true, scratch.crtScratch[:llen])
	zintRebuildCRT(Gt, llen, llen, degree, smallPrimes[:], true, scratch.crtScratch[:llen])
}

const depthIntFG = 4

var bitLength = [...]struct{ avg, std int }{
	{4, 0},
	{11, 1},
	{24, 1},
	{50, 1},
	{102, 1},
	{202, 2},
	{401, 4},
	{794, 5},
	{1577, 8},
	{3138, 13},
	{6308, 25},
}

func reduceNTRUSolution(wk *ntruWorkspace, Ft, Gt, ft, gt []uint32, depth, logn, slen, llen int) bool {
	degree := 1 << logn

	scratch := wk.reduceScratch(degree)

	k := wk.intermediate.k[:degree]

	rlen := min(slen, 10)
	polyBigToFP(scratch.rt3, ft[slen-rlen:], rlen, slen, logn)
	polyBigToFP(scratch.rt4, gt[slen-rlen:], rlen, slen, logn)
	scaleFGBase := 31 * (slen - rlen)

	minBitsFG := bitLength[depth].avg - 6*bitLength[depth].std
	maxBitsFG := bitLength[depth].avg + 6*bitLength[depth].std

	fft(scratch.rt3, logn)
	fft(scratch.rt4, logn)
	fftInvNorm2(scratch.rt5, scratch.rt3, scratch.rt4, logn)
	fftAdj(scratch.rt3, logn)
	fftAdj(scratch.rt4, logn)

	FGlen := llen
	maxBitsFGSolution := 31 * llen
	scaleK := maxBitsFGSolution - minBitsFG

	for {
		rlen = min(FGlen, 10)
		scaleFGSolution := 31 * (FGlen - rlen)
		polyBigToFP(scratch.rt1, Ft[FGlen-rlen:], rlen, llen, logn)
		polyBigToFP(scratch.rt2, Gt[FGlen-rlen:], rlen, llen, logn)

		fft(scratch.rt1, logn)
		fft(scratch.rt2, logn)
		fftMul(scratch.rt1, scratch.rt3, logn)
		fftMul(scratch.rt2, scratch.rt4, logn)
		fftAdd(scratch.rt2, scratch.rt1, logn)
		fftMulAutoAdj(scratch.rt2, scratch.rt5, logn)
		inverseFFT(scratch.rt2, logn)

		scaleCorrection := scaleK - scaleFGSolution + scaleFGBase
		pdc := fpr(math.Ldexp(1, -scaleCorrection))
		for i := range degree {
			x := scratch.rt2[i] * pdc
			// Bounds written with !(<) on both sides to also reject NaN
			// (NaN comparisons all return false; the negation captures them).
			if !(negTwoTo31Minus1 < x) || !(x < twoTo31Minus1) {
				return false
			}
			k[i] = int32(fprRint(x))
		}

		sch := uint32(scaleK / 31)
		scl := uint32(scaleK % 31)
		if depth <= depthIntFG {
			polySubScaledNTT(Ft, FGlen, llen, ft, slen, slen, k, sch, scl, logn, scratch.scaledNTT)
			polySubScaledNTT(Gt, FGlen, llen, gt, slen, slen, k, sch, scl, logn, scratch.scaledNTT)
		} else {
			polySubScaled(Ft, FGlen, llen, ft, slen, slen, k, sch, scl, logn)
			polySubScaled(Gt, FGlen, llen, gt, slen, slen, k, sch, scl, logn)
		}

		newMaxBitsFGSolution := scaleK + maxBitsFG + 10
		if newMaxBitsFGSolution < maxBitsFGSolution {
			maxBitsFGSolution = newMaxBitsFGSolution
			if FGlen*31 >= maxBitsFGSolution+31 {
				FGlen--
			}
		}

		if scaleK <= 0 {
			break
		}
		scaleK -= 25
		if scaleK < 0 {
			scaleK = 0
		}
	}

	if FGlen < slen {
		for i := range degree {
			Fw := -(Ft[i*llen+FGlen-1] >> 30) >> 1
			Gw := -(Gt[i*llen+FGlen-1] >> 30) >> 1
			for j := FGlen; j < slen; j++ {
				Ft[i*llen+j] = Fw
				Gt[i*llen+j] = Gw
			}
		}
	}
	return true
}

func writeReducedNTRUSolution(tmp, Ft, Gt []uint32, degree, slen, llen int) {
	for i := range degree {
		copy(tmp[i*slen:(i+1)*slen], Ft[i*llen:i*llen+slen])
		copy(tmp[(degree+i)*slen:(degree+i+1)*slen], Gt[i*llen:i*llen+slen])
	}
}

func solveNTRUBinaryDepth0(f, g smallPolynomial, wk *ntruWorkspace) {
	hn := n >> 1

	p := smallPrimes[0].p
	p0i := smallPrimeDerivedValues[0].p0i
	r2 := smallPrimeDerivedValues[0].r2

	tmp := wk.solution
	s := wk.depth0Scratch(n, hn)
	prevF, prevG := s.prevF, s.prevG
	Fp, Gp := s.Fp, s.Gp
	ft, gt := s.ft, s.gt
	gm, igm := s.gm, s.igm
	t2, t3 := s.t2, s.t3
	t4, t5 := s.t4, s.t5
	num, den, work := s.num, s.den, s.work

	modPMkgm2(gm, igm, logN, smallPrimes[0].g, p, p0i)

	for i := range hn {
		prevF[i] = modPSet(zintOneToPlain(prevF[i]), p)
		prevG[i] = modPSet(zintOneToPlain(prevG[i]), p)
	}
	modPNTT2(prevF, gm, logN-1, p, p0i)
	modPNTT2(prevG, gm, logN-1, p, p0i)

	for i := range n {
		ft[i] = modPSet(f[i], p)
		gt[i] = modPSet(g[i], p)
	}
	modPNTT2(ft, gm, logN, p, p0i)
	modPNTT2(gt, gm, logN, p, p0i)

	for i := 0; i < n; i += 2 {
		ftA := ft[i]
		ftB := ft[i+1]
		gtA := gt[i]
		gtB := gt[i+1]
		mFp := modPMontyMul(prevF[i>>1], r2, p, p0i)
		mGp := modPMontyMul(prevG[i>>1], r2, p, p0i)
		Fp[i] = modPMontyMul(gtB, mFp, p, p0i)
		Fp[i+1] = modPMontyMul(gtA, mFp, p, p0i)
		Gp[i] = modPMontyMul(ftB, mGp, p, p0i)
		Gp[i+1] = modPMontyMul(ftA, mGp, p, p0i)
	}
	modPINTT2(Fp, igm, logN, p, p0i)
	modPINTT2(Gp, igm, logN, p, p0i)

	modPNTT2(Fp, gm, logN, p, p0i)
	modPNTT2(Gp, gm, logN, p, p0i)

	t4[0] = modPSet(f[0], p)
	t5[0] = t4[0]
	for i := 1; i < n; i++ {
		t4[i] = modPSet(f[i], p)
		t5[n-i] = modPSet(-f[i], p)
	}
	modPNTT2(t4, gm, logN, p, p0i)
	modPNTT2(t5, gm, logN, p, p0i)

	for i := range n {
		w := modPMontyMul(t5[i], r2, p, p0i)
		t2[i] = modPMontyMul(w, Fp[i], p, p0i)
		t3[i] = modPMontyMul(w, t4[i], p, p0i)
	}

	t4[0] = modPSet(g[0], p)
	t5[0] = t4[0]
	for i := 1; i < n; i++ {
		t4[i] = modPSet(g[i], p)
		t5[n-i] = modPSet(-g[i], p)
	}
	modPNTT2(t4, gm, logN, p, p0i)
	modPNTT2(t5, gm, logN, p, p0i)

	for i := range n {
		w := modPMontyMul(t5[i], r2, p, p0i)
		t2[i] = modPAdd(t2[i], modPMontyMul(w, Gp[i], p, p0i), p)
		t3[i] = modPAdd(t3[i], modPMontyMul(w, t4[i], p, p0i), p)
	}

	modPINTT2(t2, igm, logN, p, p0i)
	modPINTT2(t3, igm, logN, p, p0i)

	for i := range n {
		work[i] = fpr(modPNorm(t3[i], p))
	}
	fft(work, logN)
	copy(den, work[:hn])
	for i := range n {
		num[i] = fpr(modPNorm(t2[i], p))
	}
	fft(num, logN)
	fftDivAutoAdj(num, den, logN)
	inverseFFT(num, logN)
	for i := range n {
		t2[i] = modPSet(int32(fprRint(num[i])), p)
	}

	for i := range n {
		t4[i] = modPSet(f[i], p)
		t5[i] = modPSet(g[i], p)
	}
	modPNTT2(t2, gm, logN, p, p0i)
	modPNTT2(t4, gm, logN, p, p0i)
	modPNTT2(t5, gm, logN, p, p0i)
	for i := range n {
		kw := modPMontyMul(t2[i], r2, p, p0i)
		Fp[i] = modPSub(Fp[i], modPMontyMul(kw, t4[i], p, p0i), p)
		Gp[i] = modPSub(Gp[i], modPMontyMul(kw, t5[i], p, p0i), p)
	}
	modPINTT2(Fp, igm, logN, p, p0i)
	modPINTT2(Gp, igm, logN, p, p0i)
	for i := range n {
		tmp[i] = uint32(modPNorm(Fp[i], p))
		tmp[n+i] = uint32(modPNorm(Gp[i], p))
	}
}

func solveNTRUBinaryDepth1(f, g smallPolynomial, wk *ntruWorkspace) bool {
	depth := 1
	logn := logN - depth
	degree := 1 << logn
	hn := degree >> 1
	slen := maxBlSmall[depth]
	dlen := maxBlSmall[depth+1]
	llen := maxBlLarge[depth]

	tmp := wk.solution
	s := wk.depth1Scratch(degree, hn, slen, dlen, llen)
	Fd, Gd := s.Fd, s.Gd
	Ft, Gt := s.Ft, s.Gt
	ft, gt := s.ft, s.gt
	gmFull, igmFull := s.gmFull, s.igmFull
	fx, gx := s.fx, s.gx
	Fp, Gp := s.Fp, s.Gp
	crtScratch := s.crtScratch
	rt1, rt2 := s.rt1, s.rt2
	rt3, rt4 := s.rt3, s.rt4
	rt5, rt6 := s.rt5, s.rt6
	kf, kg := s.kf, s.kg

	for u := range llen {
		derived := smallPrimeDerivedValues[u]
		p := smallPrimes[u].p
		p0i := derived.p0i
		r2 := derived.r2
		rx := modPRx(dlen, p, p0i, r2)
		for v := range hn {
			Ft[v*llen+u] = zintModSmallSigned(Fd[v*dlen:v*dlen+dlen], p, p0i, r2, rx)
			Gt[v*llen+u] = zintModSmallSigned(Gd[v*dlen:v*dlen+dlen], p, p0i, r2, rx)
		}
	}

	for u := range llen {
		prime := smallPrimes[u]
		derived := smallPrimeDerivedValues[u]
		p := prime.p
		p0i := derived.p0i
		r2 := derived.r2

		modPMkgm2(gmFull, igmFull, logN, prime.g, p, p0i)

		for v := range n {
			fx[v] = modPSet(f[v], p)
			gx[v] = modPSet(g[v], p)
		}

		modPNTT2(fx, gmFull, logN, p, p0i)
		modPNTT2(gx, gmFull, logN, p, p0i)
		for e := logN; e > logn; e-- {
			modPPolyRecRes(fx, e, p, p0i, r2)
			modPPolyRecRes(gx, e, p, p0i, r2)
		}

		gm := gmFull[:degree]
		igm := igmFull[:degree]

		for v := range hn {
			Fp[v] = Ft[v*llen+u]
			Gp[v] = Gt[v*llen+u]
		}
		modPNTT2(Fp, gm, logn-1, p, p0i)
		modPNTT2(Gp, gm, logn-1, p, p0i)

		for v := range hn {
			ftA := fx[v<<1]
			ftB := fx[(v<<1)+1]
			gtA := gx[v<<1]
			gtB := gx[(v<<1)+1]
			mFp := modPMontyMul(Fp[v], r2, p, p0i)
			mGp := modPMontyMul(Gp[v], r2, p, p0i)
			Ft[(v<<1)*llen+u] = modPMontyMul(gtB, mFp, p, p0i)
			Ft[((v<<1)+1)*llen+u] = modPMontyMul(gtA, mFp, p, p0i)
			Gt[(v<<1)*llen+u] = modPMontyMul(ftB, mGp, p, p0i)
			Gt[((v<<1)+1)*llen+u] = modPMontyMul(ftA, mGp, p, p0i)
		}
		modPINTT2Ext(Ft[u:], llen, igm, logn, p, p0i)
		modPINTT2Ext(Gt[u:], llen, igm, logn, p, p0i)

		if u < slen {
			modPINTT2(fx[:degree], igm, logn, p, p0i)
			modPINTT2(gx[:degree], igm, logn, p, p0i)
			for v := range degree {
				ft[v*slen+u] = fx[v]
				gt[v*slen+u] = gx[v]
			}
		}
	}

	zintRebuildCRT(Ft, llen, llen, degree, smallPrimes[:], true, crtScratch[:llen])
	zintRebuildCRT(Gt, llen, llen, degree, smallPrimes[:], true, crtScratch[:llen])
	zintRebuildCRT(ft, slen, slen, degree, smallPrimes[:], true, crtScratch[:slen])
	zintRebuildCRT(gt, slen, slen, degree, smallPrimes[:], true, crtScratch[:slen])

	polyBigToFP(rt1, Ft, llen, llen, logn)
	polyBigToFP(rt2, Gt, llen, llen, logn)
	polyBigToFP(rt3, ft, slen, slen, logn)
	polyBigToFP(rt4, gt, slen, slen, logn)

	fft(rt1, logn)
	fft(rt2, logn)
	fft(rt3, logn)
	fft(rt4, logn)

	fftAddMulAdj(rt5, rt1, rt2, rt3, rt4, logn)
	fftInvNorm2(rt6, rt3, rt4, logn)
	fftMulAutoAdj(rt5, rt6, logn)

	inverseFFT(rt5, logn)
	for i := range degree {
		z := rt5[i]
		// Bounds written with !(<) on both sides to also reject NaN
		// (NaN comparisons all return false; the negation captures them).
		if !(z < twoTo63Minus1) || !(negTwoTo63Minus1 < z) {
			return false
		}
		rt5[i] = fpr(fprRint(z))
	}
	fft(rt5, logn)

	copy(kf, rt3)
	copy(kg, rt4)
	fftMul(kf, rt5, logn)
	fftMul(kg, rt5, logn)
	fftSub(rt1, kf, logn)
	fftSub(rt2, kg, logn)
	inverseFFT(rt1, logn)
	inverseFFT(rt2, logn)

	for i := range degree {
		tmp[i] = uint32(fprRint(rt1[i]))
		tmp[degree+i] = uint32(fprRint(rt2[i]))
	}

	return true
}
