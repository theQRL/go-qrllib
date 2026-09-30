package falcon1024

import (
	"crypto/sha3"
	"strconv"
	"testing"
)

// fillRandomPoly fills f with random integer coefficients in the -512..+511
// range.
func fillRandomPoly(p *samplerPRNG, f []fpr) {
	for i := range f {
		x := int32(p.readByte())
		x = (x << 8) + int32(p.readByte())
		x &= 0x3FF
		f[i] = fpr(x - 512)
	}
}

func TestPolyRandomized(t *testing.T) {
	// For every degree 2^logn up to 1024, random polynomials are pushed
	// through FFT/iFFT, FFT multiplication (against schoolbook multiplication
	// modulo X^n+1) and split/merge. The inputs have integer coefficients, so
	// results are compared after rounding to the nearest integer.
	for logn := 1; logn <= logN; logn++ {
		t.Run("logn-"+strconv.Itoa(logn), func(t *testing.T) {
			degree := 1 << logn
			hn := degree >> 1

			rng := sha3.NewSHAKE256()
			_, _ = rng.Write([]byte{byte(logn)})
			p := newSamplerPRNG(rng)

			f := make([]fpr, degree)
			g := make([]fpr, degree)
			h := make([]fpr, degree)
			f0 := make([]fpr, hn)
			f1 := make([]fpr, hn)
			g0 := make([]fpr, hn)
			g1 := make([]fpr, hn)

			for ctr := range 131072 >> logn {
				fillRandomPoly(p, f)
				copy(g, f)
				fft(g, logn)
				inverseFFT(g, logn)
				for u := range f {
					if fprRint(f[u]) != fprRint(g[u]) {
						t.Fatalf("round %d: FFT/iFFT mismatch at %d: got %v, want %v", ctr, u, g[u], f[u])
					}
				}

				fillRandomPoly(p, g)
				clear(h)
				for u := range degree {
					for v := range degree {
						s := f[u] * g[v]
						k := u + v
						if k >= degree {
							k -= degree
							s = -s
						}
						h[k] += s
					}
				}
				fft(f, logn)
				fft(g, logn)
				fftMul(f, g, logn)
				inverseFFT(f, logn)
				for u := range f {
					if fprRint(f[u]) != fprRint(h[u]) {
						t.Fatalf("round %d: FFT multiplication mismatch at %d: got %v, want %v", ctr, u, f[u], h[u])
					}
				}

				fillRandomPoly(p, f)
				copy(h, f)
				fft(f, logn)
				splitFFT(f0, f1, f, logn)

				copy(g0, f0)
				copy(g1, f1)
				inverseFFT(g0, logn-1)
				inverseFFT(g1, logn-1)
				for u := range hn {
					if fprRint(g0[u]) != fprRint(h[u<<1]) || fprRint(g1[u]) != fprRint(h[(u<<1)+1]) {
						t.Fatalf("round %d: split mismatch at %d: got (%v, %v), want (%v, %v)",
							ctr, u, g0[u], g1[u], h[u<<1], h[(u<<1)+1])
					}
				}

				mergeFFT(g, f0, f1, logn)
				inverseFFT(g, logn)
				for u := range g {
					if fprRint(g[u]) != fprRint(h[u]) {
						t.Fatalf("round %d: split/merge mismatch at %d: got %v, want %v", ctr, u, g[u], h[u])
					}
				}
			}
		})
	}
}
