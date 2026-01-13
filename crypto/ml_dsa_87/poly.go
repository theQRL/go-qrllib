package ml_dsa_87

import (
	"errors"
	"golang.org/x/crypto/sha3"
)

type poly struct {
	coeffs [N]int32
}

func polyCAddQ(a *poly) {
	for i := 0; i < N; i++ {
		a.coeffs[i] = cAddQ(a.coeffs[i])
	}
}

func polyReduce(a *poly) {
	for i := 0; i < N; i++ {
		a.coeffs[i] = reduce32(a.coeffs[i])
	}
}

func polyAdd(c, a, b *poly) {
	for i := 0; i < N; i++ {
		c.coeffs[i] = a.coeffs[i] + b.coeffs[i]
	}
}

func polySub(c, a, b *poly) {
	for i := 0; i < N; i++ {
		c.coeffs[i] = a.coeffs[i] - b.coeffs[i]
	}
}

func polyShiftL(a *poly) {
	for i := 0; i < N; i++ {
		a.coeffs[i] <<= D
	}
}

func polyNTT(a *poly) {
	ntt(&a.coeffs)
}

func polyInvNTTToMont(a *poly) {
	invNTTToMont(&a.coeffs)
}

func polyPointWiseMontgomery(c, a, b *poly) {
	for i := 0; i < N; i++ {
		c.coeffs[i] = montgomeryReduce(int64(a.coeffs[i]) * int64(b.coeffs[i]))
	}
}

func polyPower2Round(a1, a0, a *poly) {
	for i := 0; i < N; i++ {
		a1.coeffs[i] = power2Round(&a0.coeffs[i], a.coeffs[i])
	}
}

func polyDecompose(a1, a0, a *poly) {
	for i := 0; i < N; i++ {
		a1.coeffs[i] = decompose(&a0.coeffs[i], a.coeffs[i])
	}
}

func polyMakeHint(h, a0, a1 *poly) uint {
	var s uint
	for i := 0; i < N; i++ {
		h.coeffs[i] = int32(makeHint(a0.coeffs[i], a1.coeffs[i]))
		s += uint(h.coeffs[i])
	}

	return s
}

func polyUseHint(b, a, h *poly) {
	for i := 0; i < N; i++ {
		b.coeffs[i] = useHint(a.coeffs[i], int(h.coeffs[i]))
	}

}

func polyChkNorm(a *poly, B int32) int {
	var t int32

	if B > (Q-1)/8 {
		return 1
	}

	/* It is ok to leak which coefficient violates the bound since
	   the probability for each coefficient is independent of secret
	   data but we must not leak the sign of the centralized representative. */
	for i := 0; i < N; i++ {
		/* Absolute value of centralized representative */
		t = a.coeffs[i] >> 31
		t = a.coeffs[i] - (t & 2 * a.coeffs[i])

		if t >= B {
			return 1
		}
	}

	return 0
}

func polyUniform(a *poly, seed *[SEED_BYTES]uint8, nonce uint16) error {
	bufLen := POLY_UNIFORM_N_BLOCKS * STREAM128_BLOCK_BYTES
	var buf [POLY_UNIFORM_N_BLOCKS*STREAM128_BLOCK_BYTES + 2]uint8

	state := sha3.NewShake128()
	if _, err := state.Write(seed[:]); err != nil {
		//coverage:ignore - sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Write([]uint8{uint8(nonce), uint8(nonce >> 8)}); err != nil {
		//coverage:ignore - sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Read(buf[:]); err != nil {
		//coverage:ignore - sha3.ShakeHash.Read never returns an error for XOF
		return err
	}

	ctr := rejUniform(a.coeffs[:], buf[:])

	//coverage:ignore - rejection sampling loop rarely executes; initial buffer is sized to
	// contain enough valid samples with overwhelming probability (rejection rate ~0.02%)
	for ctr < N {
		off := bufLen % 3
		for i := 0; i < off; i++ {
			buf[i] = buf[bufLen-off+i]
		}

		if _, err := state.Read(buf[off : STREAM128_BLOCK_BYTES+off]); err != nil {
			//coverage:ignore - sha3.ShakeHash.Read never returns an error for XOF
			return err
		}
		bufLen = STREAM128_BLOCK_BYTES + off
		ctr += rejUniform(a.coeffs[ctr:], buf[:bufLen])
	}
	return nil
}

func rejUniform(a []int32, buf []uint8) uint32 {
	var ctr, pos, t uint32
	aLen := uint32(len(a))
	bufLen := uint32(len(buf))

	for ctr < aLen && pos+3 <= bufLen {
		t = uint32(buf[pos])
		t |= uint32(buf[pos+1]) << 8
		t |= uint32(buf[pos+2]) << 16
		t &= 0x7fffff

		pos += 3

		if t < Q {
			a[ctr] = int32(t)
			ctr++
		}
	}
	return ctr
}

func rejEta(a []int32, buf []uint8) uint32 {
	var ctr, pos, t0, t1 uint32
	bufLen, aLen := uint32(len(buf)), uint32(len(a))
	for ctr < aLen && pos < bufLen {
		t0 = uint32(buf[pos] & 0x0F)
		t1 = uint32(buf[pos] >> 4)
		pos++

		if t0 < 15 {
			t0 = t0 - (205*t0>>10)*5
			a[ctr] = int32(2 - t0)
			ctr++
		}
		if t1 < 15 && ctr < aLen {
			t1 = t1 - (205*t1>>10)*5
			a[ctr] = int32(2 - t1)
			ctr++
		}
	}
	return ctr
}

func polyUniformEta(a *poly, seed *[CRH_BYTES]uint8, nonce uint16) error {
	var buf [POLY_UNIFORM_ETA_N_BLOCKS * STREAM256_BLOCK_BYTES]uint8
	state := sha3.NewShake256()

	if _, err := state.Write(seed[:]); err != nil {
		//coverage:ignore - sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Write([]uint8{uint8(nonce), uint8(nonce >> 8)}); err != nil {
		//coverage:ignore - sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Read(buf[:]); err != nil {
		//coverage:ignore - sha3.ShakeHash.Read never returns an error for XOF
		return err
	}

	ctr := rejEta(a.coeffs[:], buf[:])
	//coverage:ignore - rejection sampling loop rarely executes; buffer is sized for high success probability
	for ctr < N {
		if _, err := state.Read(buf[:STREAM256_BLOCK_BYTES]); err != nil {
			//coverage:ignore - sha3.ShakeHash.Read never returns an error for XOF
			return err
		}
		ctr += rejEta(a.coeffs[ctr:], buf[:STREAM256_BLOCK_BYTES])
	}
	return nil
}

func polyUniformGamma1(a *poly, seed [CRH_BYTES]uint8, nonce uint16) {
	var buf [POLY_UNIFORM_GAMMA1_N_BLOCKS * STREAM256_BLOCK_BYTES]uint8
	state := sha3.NewShake256()

	_, _ = state.Write(seed[:])
	_, _ = state.Write([]uint8{uint8(nonce), uint8(nonce >> 8)})
	_, _ = state.Read(buf[:]) // ShakeHash.Read never returns an error

	polyZUnpack(a, buf[:])
}

func polyChallenge(c *poly, seed []uint8) error {
	var pos, b uint
	if len(seed) != C_TILDE_BYTES {
		return errors.New("invalid seed length")
	}
	var buf [SHAKE256_RATE]uint8
	state := sha3.NewShake256()
	if _, err := state.Write(seed); err != nil {
		//coverage:ignore - sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Read(buf[:]); err != nil {
		//coverage:ignore - sha3.ShakeHash.Read never returns an error for XOF
		return err
	}

	signs := uint64(0)
	for i := uint64(0); i < 8; i++ {
		signs |= uint64(buf[i]) << (8 * i)
	}
	pos = 8

	for i := 0; i < N; i++ {
		c.coeffs[i] = 0
	}
	for i := N - TAU; i < N; i++ {
		for {
			//coverage:ignore - inner rejection loop for Fisher-Yates shuffle rarely needs extra blocks
			if pos >= SHAKE256_RATE {
				if _, err := state.Read(buf[:]); err != nil {
					//coverage:ignore - sha3.ShakeHash.Read never returns an error for XOF
					return err
				}
				pos = 0
			}

			b = uint(buf[pos])
			pos++
			if b <= uint(i) {
				break
			}
		}

		c.coeffs[i] = c.coeffs[b]
		c.coeffs[b] = int32(1 - 2*(signs&1))
		signs >>= 1
	}
	return nil
}

func polyEtaPack(r []uint8, a *poly) {
	var t [8]uint8

	for i := 0; i < N/8; i++ {
		t[0] = uint8(ETA - a.coeffs[8*i+0])
		t[1] = uint8(ETA - a.coeffs[8*i+1])
		t[2] = uint8(ETA - a.coeffs[8*i+2])
		t[3] = uint8(ETA - a.coeffs[8*i+3])
		t[4] = uint8(ETA - a.coeffs[8*i+4])
		t[5] = uint8(ETA - a.coeffs[8*i+5])
		t[6] = uint8(ETA - a.coeffs[8*i+6])
		t[7] = uint8(ETA - a.coeffs[8*i+7])

		r[3*i+0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6)
		r[3*i+1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)
		r[3*i+2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5)
	}
}

func polyEtaUnpack(r *poly, a []uint8) {
	for i := 0; i < N/8; i++ {
		r.coeffs[8*i+0] = int32((a[3*i+0] >> 0) & 7)
		r.coeffs[8*i+1] = int32((a[3*i+0] >> 3) & 7)
		r.coeffs[8*i+2] = int32(((a[3*i+0] >> 6) | (a[3*i+1] << 2)) & 7)
		r.coeffs[8*i+3] = int32((a[3*i+1] >> 1) & 7)
		r.coeffs[8*i+4] = int32((a[3*i+1] >> 4) & 7)
		r.coeffs[8*i+5] = int32(((a[3*i+1] >> 7) | (a[3*i+2] << 1)) & 7)
		r.coeffs[8*i+6] = int32((a[3*i+2] >> 2) & 7)
		r.coeffs[8*i+7] = int32((a[3*i+2] >> 5) & 7)

		r.coeffs[8*i+0] = ETA - r.coeffs[8*i+0]
		r.coeffs[8*i+1] = ETA - r.coeffs[8*i+1]
		r.coeffs[8*i+2] = ETA - r.coeffs[8*i+2]
		r.coeffs[8*i+3] = ETA - r.coeffs[8*i+3]
		r.coeffs[8*i+4] = ETA - r.coeffs[8*i+4]
		r.coeffs[8*i+5] = ETA - r.coeffs[8*i+5]
		r.coeffs[8*i+6] = ETA - r.coeffs[8*i+6]
		r.coeffs[8*i+7] = ETA - r.coeffs[8*i+7]
	}

}

func polyT1Pack(r []uint8, a *poly) {
	for i := 0; i < N/4; i++ {
		r[5*i+0] = uint8(a.coeffs[4*i+0] >> 0)
		r[5*i+1] = uint8((a.coeffs[4*i+0] >> 8) | (a.coeffs[4*i+1] << 2))
		r[5*i+2] = uint8((a.coeffs[4*i+1] >> 6) | (a.coeffs[4*i+2] << 4))
		r[5*i+3] = uint8((a.coeffs[4*i+2] >> 4) | (a.coeffs[4*i+3] << 6))
		r[5*i+4] = uint8(a.coeffs[4*i+3] >> 2)
	}
}

func polyT1Unpack(r *poly, a []uint8) {
	for i := 0; i < N/4; i++ {
		r.coeffs[4*i+0] = int32((uint32(a[5*i+0]>>0) | (uint32(a[5*i+1]) << 8)) & 0x3FF)
		r.coeffs[4*i+1] = int32((uint32(a[5*i+1]>>2) | (uint32(a[5*i+2]) << 6)) & 0x3FF)
		r.coeffs[4*i+2] = int32((uint32(a[5*i+2]>>4) | (uint32(a[5*i+3]) << 4)) & 0x3FF)
		r.coeffs[4*i+3] = int32((uint32(a[5*i+3]>>6) | (uint32(a[5*i+4]) << 2)) & 0x3FF)
	}
}

func polyT0Pack(r []uint8, a *poly) {
	var t [8]uint32

	for i := 0; i < N/8; i++ {
		t[0] = uint32((1 << (D - 1)) - a.coeffs[8*i+0])
		t[1] = uint32((1 << (D - 1)) - a.coeffs[8*i+1])
		t[2] = uint32((1 << (D - 1)) - a.coeffs[8*i+2])
		t[3] = uint32((1 << (D - 1)) - a.coeffs[8*i+3])
		t[4] = uint32((1 << (D - 1)) - a.coeffs[8*i+4])
		t[5] = uint32((1 << (D - 1)) - a.coeffs[8*i+5])
		t[6] = uint32((1 << (D - 1)) - a.coeffs[8*i+6])
		t[7] = uint32((1 << (D - 1)) - a.coeffs[8*i+7])

		r[13*i+0] = uint8(t[0])
		r[13*i+1] = uint8(t[0] >> 8)
		r[13*i+1] |= uint8(t[1] << 5)
		r[13*i+2] = uint8(t[1] >> 3)
		r[13*i+3] = uint8(t[1] >> 11)
		r[13*i+3] |= uint8(t[2] << 2)
		r[13*i+4] = uint8(t[2] >> 6)
		r[13*i+4] |= uint8(t[3] << 7)
		r[13*i+5] = uint8(t[3] >> 1)
		r[13*i+6] = uint8(t[3] >> 9)
		r[13*i+6] |= uint8(t[4] << 4)
		r[13*i+7] = uint8(t[4] >> 4)
		r[13*i+8] = uint8(t[4] >> 12)
		r[13*i+8] |= uint8(t[5] << 1)
		r[13*i+9] = uint8(t[5] >> 7)
		r[13*i+9] |= uint8(t[6] << 6)
		r[13*i+10] = uint8(t[6] >> 2)
		r[13*i+11] = uint8(t[6] >> 10)
		r[13*i+11] |= uint8(t[7] << 3)
		r[13*i+12] = uint8(t[7] >> 5)
	}
}

func polyT0Unpack(r *poly, a []uint8) {
	for i := 0; i < N/8; i++ {
		r.coeffs[8*i+0] = int32(a[13*i+0])
		r.coeffs[8*i+0] |= int32(uint32(a[13*i+1]) << 8)
		r.coeffs[8*i+0] &= 0x1FFF

		r.coeffs[8*i+1] = int32(a[13*i+1] >> 5)
		r.coeffs[8*i+1] |= int32(uint32(a[13*i+2]) << 3)
		r.coeffs[8*i+1] |= int32(uint32(a[13*i+3]) << 11)
		r.coeffs[8*i+1] &= 0x1FFF

		r.coeffs[8*i+2] = int32(a[13*i+3] >> 2)
		r.coeffs[8*i+2] |= int32(uint32(a[13*i+4]) << 6)
		r.coeffs[8*i+2] &= 0x1FFF

		r.coeffs[8*i+3] = int32(a[13*i+4] >> 7)
		r.coeffs[8*i+3] |= int32(uint32(a[13*i+5]) << 1)
		r.coeffs[8*i+3] |= int32(uint32(a[13*i+6]) << 9)
		r.coeffs[8*i+3] &= 0x1FFF

		r.coeffs[8*i+4] = int32(a[13*i+6] >> 4)
		r.coeffs[8*i+4] |= int32(uint32(a[13*i+7]) << 4)
		r.coeffs[8*i+4] |= int32(uint32(a[13*i+8]) << 12)
		r.coeffs[8*i+4] &= 0x1FFF

		r.coeffs[8*i+5] = int32(a[13*i+8] >> 1)
		r.coeffs[8*i+5] |= int32(uint32(a[13*i+9]) << 7)
		r.coeffs[8*i+5] &= 0x1FFF

		r.coeffs[8*i+6] = int32(a[13*i+9] >> 6)
		r.coeffs[8*i+6] |= int32(uint32(a[13*i+10]) << 2)
		r.coeffs[8*i+6] |= int32(uint32(a[13*i+11]) << 10)
		r.coeffs[8*i+6] &= 0x1FFF

		r.coeffs[8*i+7] = int32(a[13*i+11] >> 3)
		r.coeffs[8*i+7] |= int32(uint32(a[13*i+12]) << 5)
		r.coeffs[8*i+7] &= 0x1FFF

		r.coeffs[8*i+0] = (1 << (D - 1)) - r.coeffs[8*i+0]
		r.coeffs[8*i+1] = (1 << (D - 1)) - r.coeffs[8*i+1]
		r.coeffs[8*i+2] = (1 << (D - 1)) - r.coeffs[8*i+2]
		r.coeffs[8*i+3] = (1 << (D - 1)) - r.coeffs[8*i+3]
		r.coeffs[8*i+4] = (1 << (D - 1)) - r.coeffs[8*i+4]
		r.coeffs[8*i+5] = (1 << (D - 1)) - r.coeffs[8*i+5]
		r.coeffs[8*i+6] = (1 << (D - 1)) - r.coeffs[8*i+6]
		r.coeffs[8*i+7] = (1 << (D - 1)) - r.coeffs[8*i+7]
	}
}

func polyZPack(r []uint8, a *poly) {
	var t [4]uint32

	for i := 0; i < N/2; i++ {
		t[0] = uint32(GAMMA1 - a.coeffs[2*i+0])
		t[1] = uint32(GAMMA1 - a.coeffs[2*i+1])

		r[5*i+0] = uint8(t[0])
		r[5*i+1] = uint8(t[0] >> 8)
		r[5*i+2] = uint8(t[0] >> 16)
		r[5*i+2] |= uint8(t[1] << 4)
		r[5*i+3] = uint8(t[1] >> 4)
		r[5*i+4] = uint8(t[1] >> 12)
	}
}

func polyZUnpack(r *poly, a []uint8) {
	for i := 0; i < N/2; i++ {
		r.coeffs[2*i+0] = int32(a[5*i+0])
		r.coeffs[2*i+0] |= int32(uint32(a[5*i+1]) << 8)
		r.coeffs[2*i+0] |= int32(uint32(a[5*i+2]) << 16)
		r.coeffs[2*i+0] &= 0xFFFFF

		r.coeffs[2*i+1] = int32(a[5*i+2] >> 4)
		r.coeffs[2*i+1] |= int32(uint32(a[5*i+3]) << 4)
		r.coeffs[2*i+1] |= int32(uint32(a[5*i+4]) << 12)
		r.coeffs[2*i+0] &= 0xFFFFF // TODO (cyyber): This line has no use, might be removed

		r.coeffs[2*i+0] = GAMMA1 - r.coeffs[2*i+0]
		r.coeffs[2*i+1] = GAMMA1 - r.coeffs[2*i+1]
	}
}

func polyW1Pack(r []uint8, a *poly) {
	for i := 0; i < N/2; i++ {
		r[i] = uint8(a.coeffs[2*i+0] | (a.coeffs[2*i+1] << 4))
	}
}
