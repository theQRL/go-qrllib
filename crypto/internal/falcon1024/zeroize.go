package falcon1024

import "runtime"

// The helpers below overwrite secret material in place. runtime.KeepAlive
// keeps the compiler from treating the overwrite of a value that is never
// read again as a dead store. The guarantee is best effort under Go's memory
// model: copies the runtime made earlier are out of reach. See SECURITY.md
// "Key Zeroization".

func zeroBytes(b []byte) {
	clear(b)
	runtime.KeepAlive(&b)
}

func zeroFPRs(s []fpr) {
	clear(s)
	runtime.KeepAlive(&s)
}

func zeroUint32s(s []uint32) {
	clear(s)
	runtime.KeepAlive(&s)
}

func zeroInt32s(s []int32) {
	clear(s)
	runtime.KeepAlive(&s)
}

func zeroSmallPolynomials(ps ...*smallPolynomial) {
	for _, p := range ps {
		zeroInt32s(p[:])
	}
}

func zeroRingElements(rs ...*ringElement) {
	for _, r := range rs {
		clear(r[:])
		runtime.KeepAlive(r)
	}
}

func zeroFFTPolynomials(ps ...*fftPolynomial) {
	for _, p := range ps {
		zeroFPRs(p[:])
	}
}

// zeroize wipes the ChaCha20 state and the output buffer. The sampler stream
// is as sensitive as the private key for the signature it produced.
func (p *samplerPRNG) zeroize() {
	zeroBytes(p.buf[:])
	clear(p.state[:])
	p.counter = 0
	p.ptr = 0
	runtime.KeepAlive(p)
}

// zeroize wipes every buffer of the NTRU solver workspace, which holds f, g
// and the partial solutions for F and G in several representations.
func (wk *ntruWorkspace) zeroize() {
	zeroUint32s(wk.solution)
	zeroUint32s(wk.scratch.u32)
	zeroFPRs(wk.scratch.fpr)
	zeroUint32s(wk.makeFGWorkspace.data)
	zeroUint32s(wk.intermediate.Fd)
	zeroUint32s(wk.intermediate.Gd)
	zeroUint32s(wk.intermediate.Ft)
	zeroUint32s(wk.intermediate.Gt)
	zeroInt32s(wk.intermediate.k)
}
