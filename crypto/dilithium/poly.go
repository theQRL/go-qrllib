package dilithium

import (
	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
	"golang.org/x/crypto/sha3"
)

// poly represents a polynomial in Z_q[X]/(X^N + 1) with N=256 coefficients.
// Coefficients are stored as signed 32-bit integers in the range (-Q, Q).
type poly struct {
	coeffs [N]int32
}

// polyCAddQ conditionally adds Q to each coefficient to ensure non-negative representation.
// Used to normalize coefficients before packing operations.
func polyCAddQ(a *poly) {
	for i := 0; i < N; i++ {
		a.coeffs[i] = cAddQ(a.coeffs[i])
	}
}

// polyReduce reduces all coefficients modulo Q to the range (-Q, Q).
func polyReduce(a *poly) {
	for i := 0; i < N; i++ {
		a.coeffs[i] = reduce32(a.coeffs[i])
	}
}

// polyAdd computes c = a + b coefficient-wise.
func polyAdd(c, a, b *poly) {
	for i := 0; i < N; i++ {
		c.coeffs[i] = a.coeffs[i] + b.coeffs[i]
	}
}

// polySub computes c = a - b coefficient-wise.
func polySub(c, a, b *poly) {
	for i := 0; i < N; i++ {
		c.coeffs[i] = a.coeffs[i] - b.coeffs[i]
	}
}

// polyShiftL multiplies each coefficient by 2^D (left shift by D bits).
// Used to recover t from t1 in verification: t = t1 * 2^D + t0.
func polyShiftL(a *poly) {
	for i := 0; i < N; i++ {
		a.coeffs[i] <<= D
	}
}

// polyNTT applies the Number Theoretic Transform in-place.
// After NTT, the polynomial is in "NTT domain" for fast multiplication.
func polyNTT(a *poly) {
	ntt(&a.coeffs)
}

// polyInvNTTToMont applies inverse NTT and converts to Montgomery representation.
// Takes a polynomial from NTT domain back to coefficient domain.
func polyInvNTTToMont(a *poly) {
	invNTTToMont(&a.coeffs)
}

// polyPointWiseMontgomery computes c = a * b coefficient-wise in Montgomery form.
// Both inputs should be in NTT domain; result is also in NTT domain.
func polyPointWiseMontgomery(c, a, b *poly) {
	for i := 0; i < N; i++ {
		c.coeffs[i] = montgomeryReduce(int64(a.coeffs[i]) * int64(b.coeffs[i]))
	}
}

// polyPower2Round splits a into (a1, a0) where a = a1*2^D + a0.
// Used in key generation to create the compressed public key.
func polyPower2Round(a1, a0, a *poly) {
	for i := 0; i < N; i++ {
		a1.coeffs[i] = power2Round(&a0.coeffs[i], a.coeffs[i])
	}
}

// polyDecompose splits a into high bits a1 and low bits a0.
// This is the core operation for the Dilithium hint system.
func polyDecompose(a1, a0, a *poly) {
	for i := 0; i < N; i++ {
		a1.coeffs[i] = decompose(&a0.coeffs[i], a.coeffs[i])
	}
}

// polyMakeHint creates hints for recovering high bits of a1 from a0+a1.
// Returns the total number of hints (non-zero coefficients in h).
// The hint h[i]=1 indicates the high bits would differ without correction.
func polyMakeHint(h, a0, a1 *poly) uint {
	var s uint
	for i := 0; i < N; i++ {
		h.coeffs[i] = int32(makeHint(a0.coeffs[i], a1.coeffs[i]))
		s += uint(h.coeffs[i])
	}

	return s
}

// polyUseHint uses hints to correct high bits of a.
// Given the hint h and value a, computes the corrected high bits.
func polyUseHint(b, a, h *poly) {
	for i := 0; i < N; i++ {
		b.coeffs[i] = useHint(a.coeffs[i], int(h.coeffs[i]))
	}

}

// polyChkNorm checks if the infinity norm of a is strictly less than B.
// Returns 0 if all |a[i]| < B, otherwise returns 1.
//
// Security note: It is safe to leak which coefficient violates the bound
// since the probability is independent of secret data. However, we must
// not leak the sign of the centralized representative.
func polyChkNorm(a *poly, B int32) int {
	var t int32

	if B > (Q-1)/8 {
		//coverage:ignore
		//rationale: defensive check - Dilithium parameters ensure B is always within valid range
		return 1
	}

	for i := 0; i < N; i++ {
		// Compute absolute value without branching on sign
		t = a.coeffs[i] >> 31
		t = a.coeffs[i] - (t & 2 * a.coeffs[i])

		if t >= B {
			return 1
		}
	}

	return 0
}

// polyUniform samples a polynomial with uniformly random coefficients in [0, Q-1].
// Uses SHAKE128 with rejection sampling to ensure uniform distribution.
// The seed and nonce provide domain separation for different polynomials.
func polyUniform(a *poly, seed *[SEED_BYTES]uint8, nonce uint16) error {
	bufLen := POLY_UNIFORM_N_BLOCKS * STREAM128_BLOCK_BYTES
	var buf [POLY_UNIFORM_N_BLOCKS*STREAM128_BLOCK_BYTES + 2]uint8

	state := sha3.NewShake128()
	if _, err := state.Write(seed[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Write([]uint8{uint8(nonce), uint8(nonce >> 8)}); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Read(buf[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return err
	}

	ctr := rejUniform(a.coeffs[:], buf[:])

	for ctr < N {
		//coverage:ignore
		//rationale: rejection sampling loop rarely executes; initial buffer is sized to
		//           contain enough valid samples with overwhelming probability (rejection rate ~0.02%)
		off := bufLen % 3
		//coverage:ignore
		for i := 0; i < off; i++ {
			//coverage:ignore
			buf[i] = buf[bufLen-off+i]
		}

		//coverage:ignore
		if _, err := state.Read(buf[off : STREAM128_BLOCK_BYTES+off]); err != nil {
			//coverage:ignore
			//rationale: sha3.ShakeHash.Read never returns an error for XOF
			return err
		}
		//coverage:ignore
		bufLen = STREAM128_BLOCK_BYTES + off
		ctr += rejUniform(a.coeffs[ctr:], buf[:bufLen])
	}
	return nil
}

// rejUniform performs rejection sampling to produce uniform values in [0, Q-1].
// Reads 3 bytes at a time (23 bits) and accepts values < Q.
// Returns the number of coefficients successfully sampled.
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

// rejEta performs rejection sampling to produce values in [-ETA, ETA].
// Each byte produces two candidate values (4 bits each).
// Values >= 15 are rejected; others are mapped to [-2, 2] for ETA=2.
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

// polyUniformEta samples a polynomial with coefficients uniformly in [-ETA, ETA].
// Used to generate the secret vectors s1 and s2 during key generation.
func polyUniformEta(a *poly, seed *[CRH_BYTES]uint8, nonce uint16) error {
	var buf [POLY_UNIFORM_ETA_N_BLOCKS * STREAM256_BLOCK_BYTES]uint8
	state := sha3.NewShake256()

	if _, err := state.Write(seed[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Write([]uint8{uint8(nonce), uint8(nonce >> 8)}); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Read(buf[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
		return err
	}

	ctr := rejEta(a.coeffs[:], buf[:])
	for ctr < N {
		//coverage:ignore
		//rationale: rejection sampling loop rarely executes; buffer is sized for high success probability
		if _, err := state.Read(buf[:STREAM256_BLOCK_BYTES]); err != nil {
			//coverage:ignore
			//rationale: sha3.ShakeHash.Read never returns an error for XOF
			return err
		}
		ctr += rejEta(a.coeffs[ctr:], buf[:STREAM256_BLOCK_BYTES])
	}
	return nil
}

// polyUniformGamma1 samples a polynomial with coefficients in [-GAMMA1+1, GAMMA1].
// Used to generate the masking vector y during signing.
func polyUniformGamma1(a *poly, seed [CRH_BYTES]uint8, nonce uint16) {
	var buf [POLY_UNIFORM_GAMMA1_N_BLOCKS * STREAM256_BLOCK_BYTES]uint8
	state := sha3.NewShake256()

	_, _ = state.Write(seed[:])
	_, _ = state.Write([]uint8{uint8(nonce), uint8(nonce >> 8)})
	_, _ = state.Read(buf[:]) // ShakeHash.Read never returns an error

	polyZUnpack(a, buf[:])
}

// polyChallenge generates the challenge polynomial c from a seed.
// The challenge has exactly TAU coefficients equal to +/-1, rest are 0.
// This is the "random oracle" output H(mu || w1) used in Fiat-Shamir.
func polyChallenge(c *poly, seed []uint8) error {
	var pos, b uint
	if len(seed) != SEED_BYTES {
		//coverage:ignore
		//rationale: callers always pass SEED_BYTES-length slices
		return cryptoerrors.ErrInvalidSeed
	}
	var buf [SHAKE256_RATE]uint8
	state := sha3.NewShake256()
	if _, err := state.Write(seed); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Write never returns an error per Go's hash.Hash contract
		return err
	}
	if _, err := state.Read(buf[:]); err != nil {
		//coverage:ignore
		//rationale: sha3.ShakeHash.Read never returns an error for XOF
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
			//coverage:ignore
			//rationale: inner rejection loop for Fisher-Yates shuffle rarely needs extra blocks
			if pos >= SHAKE256_RATE {
				//coverage:ignore
				if _, err := state.Read(buf[:]); err != nil {
					//coverage:ignore
					//rationale: sha3.ShakeHash.Read never returns an error for XOF
					return err
				}
				//coverage:ignore
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

// polyEtaPack packs a polynomial with coefficients in [-ETA, ETA] into bytes.
// Uses 3 bits per coefficient (8 coefficients per 3 bytes).
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

// polyEtaUnpack unpacks bytes into a polynomial with coefficients in [-ETA, ETA].
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

// polyT1Pack packs the high bits of t (t1) using 10 bits per coefficient.
// Used for the public key, which contains only t1 (not t0).
func polyT1Pack(r []uint8, a *poly) {
	for i := 0; i < N/4; i++ {
		r[5*i+0] = uint8(a.coeffs[4*i+0] >> 0)
		r[5*i+1] = uint8((a.coeffs[4*i+0] >> 8) | (a.coeffs[4*i+1] << 2))
		r[5*i+2] = uint8((a.coeffs[4*i+1] >> 6) | (a.coeffs[4*i+2] << 4))
		r[5*i+3] = uint8((a.coeffs[4*i+2] >> 4) | (a.coeffs[4*i+3] << 6))
		r[5*i+4] = uint8(a.coeffs[4*i+3] >> 2)
	}
}

// polyT1Unpack unpacks bytes into t1 coefficients (10 bits each).
func polyT1Unpack(r *poly, a []uint8) {
	for i := 0; i < N/4; i++ {
		r.coeffs[4*i+0] = int32((uint32(a[5*i+0]>>0) | (uint32(a[5*i+1]) << 8)) & 0x3FF)
		r.coeffs[4*i+1] = int32((uint32(a[5*i+1]>>2) | (uint32(a[5*i+2]) << 6)) & 0x3FF)
		r.coeffs[4*i+2] = int32((uint32(a[5*i+2]>>4) | (uint32(a[5*i+3]) << 4)) & 0x3FF)
		r.coeffs[4*i+3] = int32((uint32(a[5*i+3]>>6) | (uint32(a[5*i+4]) << 2)) & 0x3FF)
	}
}

// polyT0Pack packs the low bits of t (t0) using 13 bits per coefficient.
// Used in the secret key for computing hints during signing.
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

// polyT0Unpack unpacks bytes into t0 coefficients (13 bits each).
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

// polyZPack packs the response vector z using 20 bits per coefficient.
// z coefficients are in [-GAMMA1+1, GAMMA1], stored as GAMMA1 - z[i].
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

// polyZUnpack unpacks bytes into z coefficients (20 bits each).
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

// polyW1Pack packs w1 coefficients using 4 bits each (2 per byte).
// w1 contains the high bits from Decompose, with values in [0, 15].
func polyW1Pack(r []uint8, a *poly) {
	for i := 0; i < N/2; i++ {
		r[i] = uint8(a.coeffs[2*i+0] | (a.coeffs[2*i+1] << 4))
	}
}
