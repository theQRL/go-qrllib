package mlkem1024

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
)

type fieldElement uint16

func fieldReduceOnce(a uint16) fieldElement {
	x := a - q
	x += q & -(x >> 15)
	return fieldElement(x)
}

func fieldAdd(a, b fieldElement) fieldElement {
	x := uint16(a + b)
	return fieldReduceOnce(x)
}

func fieldSub(a, b fieldElement) fieldElement {
	x := uint16(a - b + q)
	return fieldReduceOnce(x)
}

const (
	barrettMultiplier = 5039
	barrettShift      = 24

	barrettWideMultiplier = 1290167
	barrettWideShift      = 32
)

func fieldReduce(a uint32) fieldElement {
	quotient := uint32((uint64(a) * barrettMultiplier) >> barrettShift)
	return fieldReduceOnce(uint16(a - quotient*q))
}

// fieldReduceWide reduces lazy products and accumulators that do not fit the
// 24-bit Barrett reducer. Current callers stay below about 8*q*q: the lazy NTT
// can multiply zetas by coefficients below 8q, and nttMulAdd4 accumulates
// several coefficient products before reducing.
func fieldReduceWide(a uint32) fieldElement {
	quotient := uint32((uint64(a) * barrettWideMultiplier) >> barrettWideShift)
	return fieldReduceOnce(uint16(a - quotient*q))
}

func fieldMul(a, b fieldElement) fieldElement {
	x := uint32(a) * uint32(b)
	return fieldReduce(x)
}

func fieldMulWide(a, b fieldElement) fieldElement {
	x := uint32(a) * uint32(b)
	return fieldReduceWide(x)
}

func fieldMulSub(a, b, c fieldElement) fieldElement {
	x := uint32(a) * uint32(b-c+q)
	return fieldReduce(x)
}

const (
	compress1Lower = (q + 3) / 4 // ceil(q/4)
	compress1Upper = (3 * q) / 4 // floor(3q/4)
)

func compress1(x fieldElement) byte {
	ux := uint32(x)
	geLower := ((ux - compress1Lower) >> 31) ^ 1
	leUpper := ((compress1Upper - ux) >> 31) ^ 1
	return byte(geLower & leUpper)
}

func compress5(x fieldElement) uint16 {
	dividend := uint32(x) << d5
	quotient := uint32(uint64(dividend) * barrettMultiplier >> barrettShift)
	remainder := dividend - quotient*q
	quotient += (q/2 - remainder) >> 31 & 1
	quotient += (q + q/2 - remainder) >> 31 & 1
	return uint16(quotient & 0x1f)
}

func compress11(x fieldElement) uint16 {
	dividend := uint32(x) << d11
	quotient := uint32(uint64(dividend) * barrettMultiplier >> barrettShift)
	remainder := dividend - quotient*q
	quotient += (q/2 - remainder) >> 31 & 1
	quotient += (q + q/2 - remainder) >> 31 & 1
	return uint16(quotient & 0x7ff)
}

func decompress(y uint16, d uint8) fieldElement {
	dividend := uint32(y) * q
	quotient := dividend >> d
	quotient += dividend >> (d - 1) & 1
	return fieldElement(quotient)
}

type ringElement [n]fieldElement // modulo-q polynomial

const (
	d1  = 1
	d5  = 5
	d11 = 11

	halfQRoundedUp = (q + 1) / 2
	shake128Rate   = 168
)

func ringDecodeAndDecompress1(dst *ringElement, src *[encodingSize1]byte) {
	for i := range dst {
		// Decode one message bit, so the result is either 0 or 1; since
		// q is odd, Decompress_1 maps 1 to (q+1)/2, rounding q/2 up.
		b := src[i/8] >> (i % 8) & 1
		dst[i] = fieldElement(b) * halfQRoundedUp
	}
}

func ringDecodeAndDecompress5(dst *ringElement, src *[encodingSize5]byte) {
	for i, off := 0, 0; i < n; i, off = i+8, off+5 {
		b0 := uint16(src[off])
		b1 := uint16(src[off+1])
		b2 := uint16(src[off+2])
		b3 := uint16(src[off+3])
		b4 := uint16(src[off+4])

		dst[i] = decompress(b0&0x1f, d5)
		dst[i+1] = decompress((b0>>5|b1<<3)&0x1f, d5)
		dst[i+2] = decompress((b1>>2)&0x1f, d5)
		dst[i+3] = decompress((b1>>7|b2<<1)&0x1f, d5)
		dst[i+4] = decompress((b2>>4|b3<<4)&0x1f, d5)
		dst[i+5] = decompress((b3>>1)&0x1f, d5)
		dst[i+6] = decompress((b3>>6|b4<<2)&0x1f, d5)
		dst[i+7] = decompress((b4>>3)&0x1f, d5)
	}
}

func ringDecodeAndDecompress11(dst *ringElement, src *[encodingSize11]byte) {
	for i, off := 0, 0; i < n; i, off = i+8, off+11 {
		b0 := uint32(src[off])
		b1 := uint32(src[off+1])
		b2 := uint32(src[off+2])
		b3 := uint32(src[off+3])
		b4 := uint32(src[off+4])
		b5 := uint32(src[off+5])
		b6 := uint32(src[off+6])
		b7 := uint32(src[off+7])
		b8 := uint32(src[off+8])
		b9 := uint32(src[off+9])
		b10 := uint32(src[off+10])

		dst[i] = decompress(uint16((b0|b1<<8)&0x7ff), d11)
		dst[i+1] = decompress(uint16((b1>>3|b2<<5)&0x7ff), d11)
		dst[i+2] = decompress(uint16((b2>>6|b3<<2|b4<<10)&0x7ff), d11)
		dst[i+3] = decompress(uint16((b4>>1|b5<<7)&0x7ff), d11)
		dst[i+4] = decompress(uint16((b5>>4|b6<<4)&0x7ff), d11)
		dst[i+5] = decompress(uint16((b6>>7|b7<<1|b8<<9)&0x7ff), d11)
		dst[i+6] = decompress(uint16((b8>>2|b9<<6)&0x7ff), d11)
		dst[i+7] = decompress(uint16((b9>>5|b10<<3)&0x7ff), d11)
	}
}

func ringCompressAndEncode1(dst *[encodingSize1]byte, src *ringElement) {
	for i, off := 0, 0; i < n; i, off = i+8, off+1 {
		c0 := compress1(src[i])
		c1 := compress1(src[i+1])
		c2 := compress1(src[i+2])
		c3 := compress1(src[i+3])
		c4 := compress1(src[i+4])
		c5 := compress1(src[i+5])
		c6 := compress1(src[i+6])
		c7 := compress1(src[i+7])

		dst[off] = c0 | c1<<1 | c2<<2 | c3<<3 | c4<<4 | c5<<5 | c6<<6 | c7<<7
	}
}

func ringCompressAndEncode5(dst *[encodingSize5]byte, src *ringElement) {
	for i, off := 0, 0; i < n; i, off = i+8, off+5 {
		c0 := compress5(src[i])
		c1 := compress5(src[i+1])
		c2 := compress5(src[i+2])
		c3 := compress5(src[i+3])
		c4 := compress5(src[i+4])
		c5 := compress5(src[i+5])
		c6 := compress5(src[i+6])
		c7 := compress5(src[i+7])

		dst[off] = byte(c0 | c1<<5)
		dst[off+1] = byte(c1>>3 | c2<<2 | c3<<7)
		dst[off+2] = byte(c3>>1 | c4<<4)
		dst[off+3] = byte(c4>>4 | c5<<1 | c6<<6)
		dst[off+4] = byte(c6>>2 | c7<<3)
	}
}

func ringCompressAndEncode11(dst *[encodingSize11]byte, src *ringElement) {
	for i, off := 0, 0; i < n; i, off = i+8, off+11 {
		c0 := uint32(compress11(src[i]))
		c1 := uint32(compress11(src[i+1]))
		c2 := uint32(compress11(src[i+2]))
		c3 := uint32(compress11(src[i+3]))
		c4 := uint32(compress11(src[i+4]))
		c5 := uint32(compress11(src[i+5]))
		c6 := uint32(compress11(src[i+6]))
		c7 := uint32(compress11(src[i+7]))

		dst[off] = byte(c0)
		dst[off+1] = byte(c0>>8 | c1<<3)
		dst[off+2] = byte(c1>>5 | c2<<6)
		dst[off+3] = byte(c2 >> 2)
		dst[off+4] = byte(c2>>10 | c3<<1)
		dst[off+5] = byte(c3>>7 | c4<<4)
		dst[off+6] = byte(c4>>4 | c5<<7)
		dst[off+7] = byte(c5 >> 1)
		dst[off+8] = byte(c5>>9 | c6<<2)
		dst[off+9] = byte(c6>>6 | c7<<5)
		dst[off+10] = byte(c7 >> 3)
	}
}

// sampleNTT samples the NTT-domain matrix entry A[i,j] from SHAKE128(rho || j || i).
func sampleNTT(dst *ringElement, rho *[32]byte, jIndex, iIndex byte) {
	ctx := sha3.NewSHAKE128()
	_, _ = ctx.Write(rho[:])
	_, _ = ctx.Write([]byte{jIndex, iIndex})

	var j int
	var buf [shake128Rate]byte
	off := len(buf)

	for {
		if off >= len(buf) {
			_, _ = ctx.Read(buf[:])
			off = 0
		}

		x0 := uint16(buf[off]) | (uint16(buf[off+1]&0x0f) << 8)
		x1 := uint16(buf[off+1]>>4) | (uint16(buf[off+2]) << 4)
		off += 3

		if x0 < q {
			dst[j] = fieldElement(x0)
			j++
		}
		if j >= len(dst) {
			break
		}
		if x1 < q {
			dst[j] = fieldElement(x1)
			j++
		}
		if j >= len(dst) {
			break
		}
	}
}

// samplePolyCBD samples a noise polynomial with CBD_2 from SHAKE256(sigma || counter).
func samplePolyCBD(dst *ringElement, sigma *[32]byte, counter byte) {
	prf := sha3.NewSHAKE256()
	_, _ = prf.Write(sigma[:])
	_, _ = prf.Write([]byte{counter})
	var buf [128]byte
	_, _ = prf.Read(buf[:])

	for i, j := 0, 0; i < len(buf); i, j = i+4, j+8 {
		t := binary.LittleEndian.Uint32(buf[i:])
		// Each two-bit field in d is the Hamming weight of one input bit
		// pair; CBD_2 maps adjacent weights to one coefficient as a-b mod q.
		d := (t & 0x55555555) + ((t >> 1) & 0x55555555)

		dst[j] = cbd2(d, d>>2)
		dst[j+1] = cbd2(d>>4, d>>6)
		dst[j+2] = cbd2(d>>8, d>>10)
		dst[j+3] = cbd2(d>>12, d>>14)
		dst[j+4] = cbd2(d>>16, d>>18)
		dst[j+5] = cbd2(d>>20, d>>22)
		dst[j+6] = cbd2(d>>24, d>>26)
		dst[j+7] = cbd2(d>>28, d>>30)
	}
}

func cbd2(a, b uint32) fieldElement {
	return fieldReduceOnce(q + uint16(a&0x3) - uint16(b&0x3))
}

var zetas = [128]fieldElement{1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154}

func ntt(f *ringElement) {
	i := 1
	for length := 128; length >= 2; length /= 2 {
		for start := 0; start < 256; start += 2 * length {
			zeta := zetas[i]
			i++
			for j := start; j < start+length; j++ {
				// Keep butterfly outputs unreduced between layers. Each layer
				// can grow coefficients by at most q, so across the seven NTT
				// layers they stay below 8q and are canonicalized at the end.
				t := fieldMulWide(zeta, f[j+length])
				a := uint16(f[j])
				f[j] = fieldElement(a + uint16(t))
				f[j+length] = fieldElement(a + q - uint16(t))
			}
		}
	}
	for i := range f {
		f[i] = fieldReduce(uint32(f[i]))
	}
}

const inverseNTTScale = 3303

// The final inverse NTT layer multiplies lower-half outputs by inverseNTTScale
// directly and folds the upper-half scaling into its zeta.
const inverseNTTFinalZeta = 1652 // zetas[1] * inverseNTTScale mod q

func inverseNTT(f *ringElement) {
	i := 127
	for length := 2; length < 128; length *= 2 {
		for start := 0; start < 256; start += 2 * length {
			zeta := zetas[i]
			i--
			for j := start; j < start+length; j++ {
				t := f[j]
				f[j] = fieldAdd(t, f[j+length])
				f[j+length] = fieldMulSub(zeta, f[j+length], t)
			}
		}
	}

	for j := range 128 {
		t := f[j]
		f[j] = fieldMul(fieldAdd(t, f[j+128]), inverseNTTScale)
		f[j+128] = fieldMulSub(inverseNTTFinalZeta, f[j+128], t)
	}
}

var gammas = [128]fieldElement{17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735, 2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175}

// nttMulAdd4 fuses the four multiplication terms in an ML-KEM-1024 NTT dot product.
// The repeated lane blocks are intentionally unrolled so each coefficient pair
// loads acc and gamma once, accumulates all four products lazily, and reduces
// only once per output coefficient.
func nttMulAdd4(acc, a0, b0, a1, b1, a2, b2, a3, b3 *ringElement) {
	for i := 0; i < n; i += 2 {
		gamma := gammas[i/2]

		a00, a01 := a0[i], a0[i+1]
		b00, b01 := b0[i], b0[i+1]
		acc0 := uint32(acc[i])
		acc0 += uint32(a00)*uint32(b00) + uint32(fieldMul(a01, b01))*uint32(gamma)
		acc1 := uint32(acc[i+1])
		acc1 += uint32(a00)*uint32(b01) + uint32(a01)*uint32(b00)

		a10, a11 := a1[i], a1[i+1]
		b10, b11 := b1[i], b1[i+1]
		acc0 += uint32(a10)*uint32(b10) + uint32(fieldMul(a11, b11))*uint32(gamma)
		acc1 += uint32(a10)*uint32(b11) + uint32(a11)*uint32(b10)

		a20, a21 := a2[i], a2[i+1]
		b20, b21 := b2[i], b2[i+1]
		acc0 += uint32(a20)*uint32(b20) + uint32(fieldMul(a21, b21))*uint32(gamma)
		acc1 += uint32(a20)*uint32(b21) + uint32(a21)*uint32(b20)

		a30, a31 := a3[i], a3[i+1]
		b30, b31 := b3[i], b3[i+1]
		acc0 += uint32(a30)*uint32(b30) + uint32(fieldMul(a31, b31))*uint32(gamma)
		acc1 += uint32(a30)*uint32(b31) + uint32(a31)*uint32(b30)

		acc[i], acc[i+1] = fieldReduceWide(acc0), fieldReduceWide(acc1)
	}
}

func polyAddAssign(a, b *ringElement) {
	for i := range a {
		a[i] = fieldAdd(a[i], b[i])
	}
}

func polySubAssign(a, b *ringElement) {
	for i := range a {
		a[i] = fieldSub(a[i], b[i])
	}
}

func byteEncode12(dst *[encodingSize12]byte, p *ringElement) {
	for i, off := 0, 0; i < n; i, off = i+2, off+3 {
		x := uint32(p[i]) | uint32(p[i+1])<<12
		dst[off] = byte(x)
		dst[off+1] = byte(x >> 8)
		dst[off+2] = byte(x >> 16)
	}
}

func byteDecode12(dst *ringElement, src *[encodingSize12]byte) error {
	for i, off := 0, 0; i < n; i, off = i+2, off+3 {
		x := uint32(src[off]) | uint32(src[off+1])<<8 | uint32(src[off+2])<<16
		c0 := uint16(x & 0x0fff)
		c1 := uint16(x >> 12)
		if c0 >= q || c1 >= q {
			return errors.New("ml-kem-1024: invalid polynomial encoding")
		}
		dst[i] = fieldElement(c0)
		dst[i+1] = fieldElement(c1)
	}
	return nil
}
