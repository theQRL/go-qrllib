package dilithium

import "golang.org/x/crypto/sha3"

type poly struct {
	coeffs [N]uint32
}

func polyFreeze(a *poly) {
	for i := 0; i < N; i++ {
		a.coeffs[i] = freeze(a.coeffs[i])
	}
}

func polyAdd(c, a, b *poly) {
	for i := 0; i < N; i++ {
		c.coeffs[i] = a.coeffs[i] + b.coeffs[i]
	}
}

func polySub(c, a, b *poly) {
	for i := 0; i < N; i++ {
		c.coeffs[i] = a.coeffs[i] + 2*Q - b.coeffs[i]
	}
}

func polyNeg(a *poly) {
	for i := 0; i < N; i++ {
		a.coeffs[i] = 2*Q - a.coeffs[i]
	}
}

func polyShiftL(a *poly, k uint) {
	for i := 0; i < N; i++ {
		a.coeffs[i] <<= k
	}
}

func polyNTT(a *poly) {
	ntt(&a.coeffs)
}

func polyInvNTTMontgomery(a *poly) {
	invNTTFromInvMont(&a.coeffs)
}

func polyPointWiseInvMontgomery(c, a, b *poly) {
	for i := 0; i < N; i++ {
		c.coeffs[i] = montgomeryReduce(uint64(a.coeffs[i]) * uint64(b.coeffs[i]))
	}
}

func polyChkNorm(a *poly, B uint32) int {
	var t int32

	/* It is ok to leak which coefficient violates the bound since
	   the probability for each coefficient is independent of secret
	   data but we must not leak the sign of the centralized representative. */
	for i := 0; i < N; i++ {
		/* Absolute value of centralized representative */
		t = int32((Q-1)/2 - a.coeffs[i])
		t ^= (t >> 31)
		t = (Q-1)/2 - t

		if uint32(t) >= B {
			return 1
		}
	}

	return 0
}

func rejEta(a []uint32, buf []byte) int {
	if ETA > 7 {
		panic("rejEta() assumes ETA <= 7")
	}

	ctr, buflen, alen := 0, len(buf), len(a)
	for pos := 0; pos < buflen && ctr < alen; pos++ {
		var t0, t1 byte
		if ETA <= 3 {
			t0 = buf[pos] & 0x07
			t1 = buf[pos] >> 5
		} else {
			t0 = buf[pos] & 0x0F
			t1 = buf[pos] >> 4
		}

		if t0 <= 2*ETA {
			a[ctr] = Q + ETA - uint32(t0)
			ctr++
		}
		if t1 <= 2*ETA && ctr < alen {
			a[ctr] = Q + ETA - uint32(t1)
			ctr++
		}
	}
	return ctr
}

func polyUniformEta(a *poly, seed *[SeedBytes]byte, nonce byte) {
	var outbuf [Shake256Rate * 2]byte

	state := sha3.NewShake256()
	state.Write(seed[:])
	state.Write([]byte{nonce})
	state.Read(outbuf[:])

	ctr := rejEta(a.coeffs[:], outbuf[:])
	if ctr < N {
		sub := outbuf[:Shake256Rate]
		state.Read(sub)
		rejEta(a.coeffs[ctr:], sub)
	}
}

func rejGamma1m1(a []uint32, buf []byte) int {
	if GAMMA1 > (1 << 19) {
		panic("rejGamma1m1() assumes GAMMA1 - 1 fits in 19 bits")
	}

	ctr, buflen, alen := 0, len(buf), len(a)
	for pos := 0; pos < buflen && ctr < alen; pos += 5 {
		var t0, t1 uint32
		t0 = uint32(buf[pos])
		t0 |= uint32(buf[pos+1]) << 8
		t0 |= uint32(buf[pos+2]) << 16
		t0 &= 0xFFFFF
		t1 = uint32(buf[pos+2]) >> 4
		t1 |= uint32(buf[pos+3]) << 4
		t1 |= uint32(buf[pos+4]) << 12

		if t0 <= 2*GAMMA1-2 {
			a[ctr] = Q + GAMMA1 - 1 - t0
			ctr++
		}
		if t1 <= 2*GAMMA1-2 && ctr < alen {
			a[ctr] = Q + GAMMA1 - 1 - t1
			ctr++
		}
	}
	return ctr
}

func polyUniformGamma1m1(a *poly, seed *[SeedBytes]byte, crh *[CrhBytes]byte, nonce uint16) {
	var outbuf [Shake256Rate * 5]byte

	state := sha3.NewShake256()
	state.Write(seed[:])
	state.Write(crh[:])
	state.Write([]byte{byte(nonce), byte(nonce >> 8)})
	state.Read(outbuf[:])

	ctr := rejGamma1m1(a.coeffs[:], outbuf[:])
	if ctr < N {
		sub := outbuf[:Shake256Rate]
		state.Read(sub)
		rejGamma1m1(a.coeffs[ctr:], sub)
	}
}

func polyEtaPack(r []byte, a *poly) {
	if ETA > 7 {
		panic("polyEtaPack() assumes ETA <= 7")
	}
	var t [8]byte

	if ETA <= 3 {
		for i := 0; i < N/8; i++ {
			t[0] = byte(Q + ETA - a.coeffs[8*i+0])
			t[1] = byte(Q + ETA - a.coeffs[8*i+1])
			t[2] = byte(Q + ETA - a.coeffs[8*i+2])
			t[3] = byte(Q + ETA - a.coeffs[8*i+3])
			t[4] = byte(Q + ETA - a.coeffs[8*i+4])
			t[5] = byte(Q + ETA - a.coeffs[8*i+5])
			t[6] = byte(Q + ETA - a.coeffs[8*i+6])
			t[7] = byte(Q + ETA - a.coeffs[8*i+7])

			r[3*i+0] = t[0]
			r[3*i+0] |= t[1] << 3
			r[3*i+0] |= t[2] << 6
			r[3*i+1] = t[2] >> 2
			r[3*i+1] |= t[3] << 1
			r[3*i+1] |= t[4] << 4
			r[3*i+1] |= t[5] << 7
			r[3*i+2] = t[5] >> 1
			r[3*i+2] |= t[6] << 2
			r[3*i+2] |= t[7] << 5
		}
	} else {
		for i := 0; i < N/2; i++ {
			t[0] = byte(Q + ETA - a.coeffs[2*i+0])
			t[1] = byte(Q + ETA - a.coeffs[2*i+1])
			r[i] = t[0] | (t[1] << 4)
		}
	}
}

func polyEtaUnpack(r *poly, a []byte) {
	if ETA <= 3 {
		for i := 0; i < N/8; i++ {
			r.coeffs[8*i+0] = uint32((a[3*i+0] & 0x07))
			r.coeffs[8*i+1] = uint32((a[3*i+0] >> 3) & 0x07)
			r.coeffs[8*i+2] = uint32((a[3*i+0] >> 6) | ((a[3*i+1] & 0x01) << 2))
			r.coeffs[8*i+3] = uint32((a[3*i+1] >> 1) & 0x07)
			r.coeffs[8*i+4] = uint32((a[3*i+1] >> 4) & 0x07)
			r.coeffs[8*i+5] = uint32((a[3*i+1] >> 7) | ((a[3*i+2] & 0x03) << 1))
			r.coeffs[8*i+6] = uint32((a[3*i+2] >> 2) & 0x07)
			r.coeffs[8*i+7] = uint32((a[3*i+2] >> 5))

			r.coeffs[8*i+0] = Q + ETA - r.coeffs[8*i+0]
			r.coeffs[8*i+1] = Q + ETA - r.coeffs[8*i+1]
			r.coeffs[8*i+2] = Q + ETA - r.coeffs[8*i+2]
			r.coeffs[8*i+3] = Q + ETA - r.coeffs[8*i+3]
			r.coeffs[8*i+4] = Q + ETA - r.coeffs[8*i+4]
			r.coeffs[8*i+5] = Q + ETA - r.coeffs[8*i+5]
			r.coeffs[8*i+6] = Q + ETA - r.coeffs[8*i+6]
			r.coeffs[8*i+7] = Q + ETA - r.coeffs[8*i+7]
		}
	} else {
		for i := 0; i < N/2; i++ {
			r.coeffs[2*i+0] = uint32(a[i] & 0x0F)
			r.coeffs[2*i+1] = uint32(a[i] >> 4)
			r.coeffs[2*i+0] = Q + ETA - r.coeffs[2*i+0]
			r.coeffs[2*i+1] = Q + ETA - r.coeffs[2*i+1]
		}
	}
}

func polyT1Pack(r []byte, a *poly) {
	if D != 14 {
		panic("polyT1Pack() assumes D == 14")
	}

	for i := 0; i < N/8; i++ {
		r[9*i+0] = byte(a.coeffs[8*i+0] & 0xFF)
		r[9*i+1] = byte((a.coeffs[8*i+0] >> 8) | ((a.coeffs[8*i+1] & 0x7F) << 1))
		r[9*i+2] = byte((a.coeffs[8*i+1] >> 7) | ((a.coeffs[8*i+2] & 0x3F) << 2))
		r[9*i+3] = byte((a.coeffs[8*i+2] >> 6) | ((a.coeffs[8*i+3] & 0x1F) << 3))
		r[9*i+4] = byte((a.coeffs[8*i+3] >> 5) | ((a.coeffs[8*i+4] & 0x0F) << 4))
		r[9*i+5] = byte((a.coeffs[8*i+4] >> 4) | ((a.coeffs[8*i+5] & 0x07) << 5))
		r[9*i+6] = byte((a.coeffs[8*i+5] >> 3) | ((a.coeffs[8*i+6] & 0x03) << 6))
		r[9*i+7] = byte((a.coeffs[8*i+6] >> 2) | ((a.coeffs[8*i+7] & 0x01) << 7))
		r[9*i+8] = byte(a.coeffs[8*i+7] >> 1)
	}
}

func polyT1Unpack(r *poly, a []byte) {
	for i := 0; i < N/8; i++ {
		r.coeffs[8*i+0] = uint32(a[9*i+0]) | (uint32(a[9*i+1]&0x01) << 8)
		r.coeffs[8*i+1] = uint32(a[9*i+1]>>1) | (uint32(a[9*i+2]&0x03) << 7)
		r.coeffs[8*i+2] = uint32(a[9*i+2]>>2) | (uint32(a[9*i+3]&0x07) << 6)
		r.coeffs[8*i+3] = uint32(a[9*i+3]>>3) | (uint32(a[9*i+4]&0x0F) << 5)
		r.coeffs[8*i+4] = uint32(a[9*i+4]>>4) | (uint32(a[9*i+5]&0x1F) << 4)
		r.coeffs[8*i+5] = uint32(a[9*i+5]>>5) | (uint32(a[9*i+6]&0x3F) << 3)
		r.coeffs[8*i+6] = uint32(a[9*i+6]>>6) | (uint32(a[9*i+7]&0x7F) << 2)
		r.coeffs[8*i+7] = uint32(a[9*i+7]>>7) | (uint32(a[9*i+8]&0xFF) << 1)
	}
}

func polyT0Pack(r []byte, a *poly) {
	var t [4]uint32

	for i := 0; i < N/4; i++ {
		t[0] = Q + (1 << (D - 1)) - a.coeffs[4*i+0]
		t[1] = Q + (1 << (D - 1)) - a.coeffs[4*i+1]
		t[2] = Q + (1 << (D - 1)) - a.coeffs[4*i+2]
		t[3] = Q + (1 << (D - 1)) - a.coeffs[4*i+3]

		r[7*i+0] = byte(t[0])
		r[7*i+1] = byte(t[0] >> 8)
		r[7*i+1] |= byte(t[1] << 6)
		r[7*i+2] = byte(t[1] >> 2)
		r[7*i+3] = byte(t[1] >> 10)
		r[7*i+3] |= byte(t[2] << 4)
		r[7*i+4] = byte(t[2] >> 4)
		r[7*i+5] = byte(t[2] >> 12)
		r[7*i+5] |= byte(t[3] << 2)
		r[7*i+6] = byte(t[3] >> 6)
	}
}

func polyT0Unpack(r *poly, a []byte) {
	for i := 0; i < N/4; i++ {
		r.coeffs[4*i+0] = uint32(a[7*i+0])
		r.coeffs[4*i+0] |= uint32(a[7*i+1]&0x3F) << 8

		r.coeffs[4*i+1] = uint32(a[7*i+1]) >> 6
		r.coeffs[4*i+1] |= uint32(a[7*i+2]) << 2
		r.coeffs[4*i+1] |= uint32(a[7*i+3]&0x0F) << 10

		r.coeffs[4*i+2] = uint32(a[7*i+3]) >> 4
		r.coeffs[4*i+2] |= uint32(a[7*i+4]) << 4
		r.coeffs[4*i+2] |= uint32(a[7*i+5]&0x03) << 12

		r.coeffs[4*i+3] = uint32(a[7*i+5]) >> 2
		r.coeffs[4*i+3] |= uint32(a[7*i+6]) << 6

		r.coeffs[4*i+0] = Q + (1 << (D - 1)) - r.coeffs[4*i+0]
		r.coeffs[4*i+1] = Q + (1 << (D - 1)) - r.coeffs[4*i+1]
		r.coeffs[4*i+2] = Q + (1 << (D - 1)) - r.coeffs[4*i+2]
		r.coeffs[4*i+3] = Q + (1 << (D - 1)) - r.coeffs[4*i+3]
	}
}

func polyZPack(r []byte, a *poly) {
	if GAMMA1 > (1 << 19) {
		panic("polyZPack() assumes GAMMA1 <= 2^{19}")
	}
	var t [2]uint32

	for i := 0; i < N/2; i++ {
		/* Map to {0,...,2*GAMMA1 - 2} */
		t[0] = GAMMA1 - 1 - a.coeffs[2*i+0]
		t[0] += uint32((int32(t[0]) >> 31) & Q)
		t[1] = GAMMA1 - 1 - a.coeffs[2*i+1]
		t[1] += uint32((int32(t[1]) >> 31) & Q)

		r[5*i+0] = byte(t[0])
		r[5*i+1] = byte(t[0] >> 8)
		r[5*i+2] = byte(t[0] >> 16)
		r[5*i+2] |= byte(t[1] << 4)
		r[5*i+3] = byte(t[1] >> 4)
		r[5*i+4] = byte(t[1] >> 12)
	}
}

func polyZUnpack(r *poly, a []byte) {
	for i := 0; i < N/2; i++ {
		r.coeffs[2*i+0] = uint32(a[5*i+0])
		r.coeffs[2*i+0] |= uint32(a[5*i+1]) << 8
		r.coeffs[2*i+0] |= uint32(a[5*i+2]&0x0F) << 16

		r.coeffs[2*i+1] = uint32(a[5*i+2] >> 4)
		r.coeffs[2*i+1] |= uint32(a[5*i+3]) << 4
		r.coeffs[2*i+1] |= uint32(a[5*i+4]) << 12

		r.coeffs[2*i+0] = GAMMA1 - 1 - r.coeffs[2*i+0]
		r.coeffs[2*i+0] += uint32((int32(r.coeffs[2*i+0]) >> 31) & Q)
		r.coeffs[2*i+1] = GAMMA1 - 1 - r.coeffs[2*i+1]
		r.coeffs[2*i+1] += uint32((int32(r.coeffs[2*i+1]) >> 31) & Q)
	}
}

func polyW1Pack(r []byte, a *poly) {
	for i := 0; i < N/2; i++ {
		r[i] = byte(a.coeffs[2*i+0] | (a.coeffs[2*i+1] << 4))
	}
}
