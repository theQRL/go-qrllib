package falcon1024

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
)

const (
	n    = 1024  // polynomial degree
	logN = 10    // log2(n)
	q    = 12289 // field modulus
)

type fieldElement uint32

func fieldFromSmall(x int32) fieldElement {
	y := uint32(x)
	y += q & -(y >> 31)
	return fieldElement(y)
}

func fieldReduceOnce(a uint32) fieldElement {
	x := a - q
	x += q & -(x >> 31)
	return fieldElement(x)
}

func fieldAdd(a, b fieldElement) fieldElement {
	x := uint32(a + b)
	return fieldReduceOnce(x)
}

func fieldSub(a, b fieldElement) fieldElement {
	x := uint32(a - b + q)
	return fieldReduceOnce(x)
}

const r2 = 10952

// fieldInvMontgomery returns 1/x in Montgomery representation.
func fieldInvMontgomery(x fieldElement) fieldElement {
	y0 := fieldMontgomeryMul(x, r2)
	y1 := fieldMontgomerySqr(y0)
	y2 := fieldMontgomeryMul(y1, y0)
	y3 := fieldMontgomeryMul(y2, y1)
	y4 := fieldMontgomerySqr(y3)
	y5 := fieldMontgomerySqr(y4)
	y6 := fieldMontgomerySqr(y5)
	y7 := fieldMontgomerySqr(y6)
	y8 := fieldMontgomerySqr(y7)
	y9 := fieldMontgomeryMul(y8, y2)
	y10 := fieldMontgomeryMul(y9, y8)
	y11 := fieldMontgomerySqr(y10)
	y12 := fieldMontgomerySqr(y11)
	y13 := fieldMontgomeryMul(y12, y9)
	y14 := fieldMontgomerySqr(y13)
	y15 := fieldMontgomerySqr(y14)
	y16 := fieldMontgomeryMul(y15, y10)
	y17 := fieldMontgomerySqr(y16)
	return fieldMontgomeryMul(y17, y0)
}

func fieldMontgomerySqr(x fieldElement) fieldElement {
	return fieldMontgomeryMul(x, x)
}

func fieldMontgomeryMul(a, b fieldElement) fieldElement {
	x := uint32(a) * uint32(b)
	return fieldMontgomeryReduce(x)
}

const qNegInv = 12287
const mask16 = 0xFFFF

func fieldMontgomeryReduce(x uint32) fieldElement {
	w := ((x * qNegInv) & mask16) * q
	x = (x + w) >> 16
	x -= q
	x += q & -(x >> 31)
	return fieldElement(x)
}

func fieldCenteredMod(x fieldElement) int32 {
	v := int32(x)
	if v > int32(q/2) {
		v -= int32(q)
	}
	return v
}

type ringElement [n]fieldElement // modulo-q polynomial

func polyByteEncode(dst []byte, p ringElement) {
	for i := 0; i < n; i += 4 {
		x := uint64(p[i])<<42 |
			uint64(p[i+1])<<28 |
			uint64(p[i+2])<<14 |
			uint64(p[i+3])

		dst[0] = byte(x >> 48)
		dst[1] = byte(x >> 40)
		dst[2] = byte(x >> 32)
		dst[3] = byte(x >> 24)
		dst[4] = byte(x >> 16)
		dst[5] = byte(x >> 8)
		dst[6] = byte(x)

		dst = dst[7:]
	}
}

// encodingSize14 is the byte size of a ringElement encoded with 14-bit coefficients.
const encodingSize14 = 1792

func polyByteDecode(b []byte) (ringElement, error) {
	if len(b) != encodingSize14 {
		return ringElement{}, errors.New("falcon-1024: invalid encoding length")
	}

	var p ringElement
	for i := 0; i < n; i += 4 {
		x := uint64(b[0])<<48 |
			uint64(b[1])<<40 |
			uint64(b[2])<<32 |
			uint64(b[3])<<24 |
			uint64(b[4])<<16 |
			uint64(b[5])<<8 |
			uint64(b[6])

		p[i] = fieldElement((x >> 42) & 0x3FFF)
		p[i+1] = fieldElement((x >> 28) & 0x3FFF)
		p[i+2] = fieldElement((x >> 14) & 0x3FFF)
		p[i+3] = fieldElement(x & 0x3FFF)

		if p[i] >= q || p[i+1] >= q || p[i+2] >= q || p[i+3] >= q {
			return ringElement{}, errors.New("falcon-1024: invalid polynomial encoding")
		}

		b = b[7:]
	}

	return p, nil
}

const hashToPointRejectionThreshold = 5 * q // 61445

// hashToPoint maps a SHAKE stream to a uniform ringElement, matching the Falcon
// reference hash_to_point_vartime.
func hashToPoint(h *sha3.SHAKE) ringElement {
	var p ringElement
	var buf [2]byte

	for i := 0; i < n; {
		_, _ = h.Read(buf[:])

		w := uint32(buf[0])<<8 | uint32(buf[1])
		if w >= hashToPointRejectionThreshold {
			continue
		}

		p[i] = fieldElement(w % q)
		i++
	}

	return p
}

func ntt(f []fieldElement) {
	t := n
	for m := 1; m < n; m <<= 1 {
		ht := t >> 1
		for i, j1 := 0, 0; i < m; i, j1 = i+1, j1+t {
			s := gmb[m+i]
			j2 := j1 + ht
			for j := j1; j < j2; j++ {
				u := f[j]
				v := fieldMontgomeryMul(f[j+ht], s)
				f[j] = fieldAdd(u, v)
				f[j+ht] = fieldSub(u, v)
			}
		}
		t = ht
	}
}

const nInverseMontgomery = 64

func inverseNTT(f []fieldElement) {
	t := 1
	m := n
	for m > 1 {
		hm := m >> 1
		dt := t << 1
		for i, j1 := 0, 0; i < hm; i, j1 = i+1, j1+dt {
			j2 := j1 + t
			s := igmb[hm+i]
			for j := j1; j < j2; j++ {
				u := f[j]
				v := f[j+t]
				f[j] = fieldAdd(u, v)
				w := fieldSub(u, v)
				f[j+t] = fieldMontgomeryMul(w, s)
			}
		}
		t = dt
		m = hm
	}

	for i := range f {
		f[i] = fieldMontgomeryMul(f[i], nInverseMontgomery)
	}
}

func nttMul(a, b []fieldElement) {
	for i := range a {
		a[i] = fieldMontgomeryMul(a[i], b[i])
	}
}

func toNTTMonty(f []fieldElement) {
	ntt(f)
	for i := range f {
		f[i] = fieldMontgomeryMul(f[i], r2)
	}
}

// divideNTTByBatchedInverse computes hNTT[i] /= fNTT[i] for each i via a
// single Fermat inversion of the prefix product (Montgomery's trick) followed
// by back-substitution. Returns false if any fNTT[i] is zero.
func divideNTTByBatchedInverse(hNTT, fNTT []fieldElement) bool {
	var fMont, pMont [n]fieldElement
	for i := range fNTT {
		if fNTT[i] == 0 {
			return false
		}
		fMont[i] = fieldMontgomeryMul(fNTT[i], r2)
	}
	pMont[0] = fMont[0]
	for i := 1; i < n; i++ {
		pMont[i] = fieldMontgomeryMul(pMont[i-1], fMont[i])
	}

	invRunMont := fieldMontgomeryMul(fieldInvMontgomery(pMont[n-1]), r2)

	for i := n - 1; i >= 1; i-- {
		invMont := fieldMontgomeryMul(invRunMont, pMont[i-1])
		hNTT[i] = fieldMontgomeryMul(hNTT[i], invMont)
		invRunMont = fieldMontgomeryMul(invRunMont, fMont[i])
	}
	hNTT[0] = fieldMontgomeryMul(hNTT[0], invRunMont)
	return true
}

type smallPolynomial [n]int32

func sampleGaussianPolynomial(rng *sha3.SHAKE) smallPolynomial {
	var p smallPolynomial
	var parity int32

	for i := 0; i < n; {
		x := sampleKeygenGaussian(rng)
		if x < -ntruCoeffBound || x > ntruCoeffBound {
			continue
		}

		if i == n-1 {
			if (parity ^ (x & 1)) == 0 {
				continue
			}
		} else {
			parity ^= x & 1
		}

		p[i] = x
		i++
	}

	return p
}

var gauss1024Q12289 = [...]uint64{
	1283868770400643928, 6416574995475331444, 4078260278032692663,
	2353523259288686585, 1227179971273316331, 575931623374121527,
	242543240509105209, 91437049221049666, 30799446349977173,
	9255276791179340, 2478152334826140, 590642893610164,
	125206034929641, 23590435911403, 3948334035941,
	586753615614, 77391054539, 9056793210,
	940121950, 86539696, 7062824,
	510971, 32764, 1862,
	94, 4, 0,
}

func sampleKeygenGaussian(rng *sha3.SHAKE) int32 {
	r := readShakeUint64(rng)
	neg := uint32(r >> 63)
	r &^= uint64(1) << 63
	f := uint32((r - gauss1024Q12289[0]) >> 63)

	r = readShakeUint64(rng)
	r &^= uint64(1) << 63

	var v uint32
	for k := uint32(1); k < uint32(len(gauss1024Q12289)); k++ {
		t := uint32(((r - gauss1024Q12289[k]) >> 63) ^ 1)
		v |= k & -(t & (f ^ 1))
		f |= t
	}

	v = (v ^ -neg) + neg
	return int32(v)
}

func readShakeUint64(rng *sha3.SHAKE) uint64 {
	var buf [8]byte
	_, _ = rng.Read(buf[:])
	return binary.LittleEndian.Uint64(buf[:])
}

func coefficientsExceedBound(p smallPolynomial, bound int32) bool {
	for _, x := range p {
		if x < -bound || x > bound {
			return true
		}
	}
	return false
}

func squaredNormExceedsBound(f, g smallPolynomial, bound uint32) bool {
	return f.squaredNorm()+g.squaredNorm() >= bound
}

func orthogonalizedNormExceedsBound(f, g smallPolynomial, bound float64) bool {
	var rf, rg fftPolynomial
	fftFromSmall(rf[:], f)
	fftFromSmall(rg[:], g)

	var invNorm fftPolynomial
	fftInvNorm2(invNorm[:], rf[:], rg[:], logN)

	fftAdj(rf[:], logN)
	fftAdj(rg[:], logN)

	for i := range rf {
		rf[i] *= q
		rg[i] *= q
	}

	fftMulAutoAdj(rf[:], invNorm[:], logN)
	fftMulAutoAdj(rg[:], invNorm[:], logN)

	inverseFFT(rf[:], logN)
	inverseFFT(rg[:], logN)

	var norm float64
	for i := range rf {
		norm += float64(rf[i]*rf[i] + rg[i]*rg[i])
	}

	return norm >= bound
}

const signatureNormBound uint64 = 70_265_242

func signatureNormExceedsPartialBound(sqn uint32, s2 smallPolynomial) bool {
	norm := uint64(sqn)

	for _, x := range s2 {
		y := int64(x)
		norm += uint64(y * y)
	}

	return norm > signatureNormBound
}

func (p smallPolynomial) squaredNorm() uint32 {
	var sum uint32
	for _, x := range p {
		sum += uint32(x * x)
	}
	return sum
}

func signatureNormWithinBound(s1, s2 smallPolynomial) bool {
	var norm uint64

	for i := range s1 {
		x := int64(s1[i])
		norm += uint64(x * x)

		y := int64(s2[i])
		norm += uint64(y * y)
	}

	return norm <= signatureNormBound
}
