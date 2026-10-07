package falcon1024

import (
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"math"
	"testing"
)

// fprBlockHash accumulates results into a single SHAKE256 context: every
// value is absorbed as 8 little-endian bytes.
type fprBlockHash struct {
	sc  *sha3.SHAKE
	buf [8]byte
}

func (h *fprBlockHash) uint64(x uint64) {
	binary.LittleEndian.PutUint64(h.buf[:], x)
	_, _ = h.sc.Write(h.buf[:])
}

func (h *fprBlockHash) fpr(x fpr) {
	h.uint64(math.Float64bits(float64(x)))
}

func (h *fprBlockHash) bool(b bool) {
	if b {
		h.uint64(1)
		return
	}
	h.uint64(0)
}

// fprScaled returns i * 2^sc.
func fprScaled(i int64, sc int) fpr {
	return fpr(math.Ldexp(float64(i), sc))
}

// fprLdexp returns x * 2^e.
func fprLdexp(x fpr, e int) fpr {
	return fpr(math.Ldexp(float64(x), e))
}

// fprFloor rounds toward negative infinity; production code uses math.Floor
// in the sampler.
func fprFloor(x fpr) int64 {
	return int64(math.Floor(float64(x)))
}

// randFP returns a value with a random sign and mantissa, and the exponent
// forced into the 1023..1150 range.
func randFP(p *samplerPRNG) fpr {
	m := p.readUint64()
	e := ((m >> 52) & 0x7F) + 1023
	return fpr(math.Float64frombits((m &^ (uint64(0x7FF) << 52)) | (e << 52)))
}

func TestFPRBlock(t *testing.T) {
	// Hashes the bit patterns of close to ten million floating-point results
	// and compares the digest with a pinned value. The expected digest only
	// depends on IEEE-754 binary64 semantics with round-to-nearest-even, so
	// matching it shows that float64 conversions, arithmetic, square roots,
	// scaling and rounding behave bit for bit as Falcon requires on this
	// platform and compiler.
	const wantDigest = "77cea0ea343b8c1c578af7c9fa3267b6"

	h := &fprBlockHash{sc: sha3.NewSHAKE256()}

	zero := fpr(0)
	nzero := fpr(math.Copysign(0, -1))
	if !math.Signbit(float64(nzero)) || !math.Signbit(float64(-zero)) {
		t.Fatal("negative zero was not produced")
	}

	h.fpr(fpr(float64(int64(0))))
	h.fpr(-zero)
	h.fpr(zero * 0.5)
	h.fpr(zero * 2)

	// nzero+zero is hashed twice in a row (and nzero+nzero never is); the
	// pinned digest depends on that exact sequence.
	for range 2 {
		h.fpr(zero + zero)
		h.fpr(zero + nzero)
		h.fpr(nzero + zero)
		h.fpr(nzero + zero)
	}

	// Additions around the 2^53 mantissa boundary, at every relative scale.
	for e := -60; e <= 60; e++ {
		for i := int64(-5); i <= 5; i++ {
			a := fpr(float64((int64(1) << 53) + i))
			h.fpr(a)
			for j := int64(-5); j <= 5; j++ {
				b := fprScaled((int64(1)<<53)+j, e)
				h.fpr(b)
				h.fpr(a + b)
				a = -a
				h.fpr(a + b)
				b = -b
				h.fpr(a + b)
				a = -a
				h.fpr(a + b)
			}
		}
	}

	rng := sha3.NewSHAKE256()
	_, _ = rng.Write([]byte("fpemu"))
	p := newSamplerPRNG(rng)

	for ctr := 1; ctr <= 65536; ctr++ {
		j := int64(p.readUint64())
		j >>= uint(ctr & 63)
		h.fpr(fpr(float64(j)))

		e := int(p.readByte()) - 128
		h.fpr(fprScaled(j, e))

		j = int64(p.readUint64())
		a := fprScaled(j, -8)
		h.fpr(a)
		h.uint64(uint64(fprRint(a)))
		a = fprScaled(j, -52)
		h.fpr(a)
		h.uint64(uint64(fprFloor(a)))

		a = randFP(p)
		b := randFP(p)

		for e := -60; e <= 60; e++ {
			h.fpr(fprLdexp(a, e))
		}

		// a < a and, below, a - a are deliberate: the pinned digest includes
		// them.
		h.bool(a < b)
		h.bool(a < a)

		h.fpr(a + b)
		h.fpr(b + a)
		h.fpr(a + zero)
		h.fpr(zero + a)
		h.fpr(a + (-a))
		h.fpr((-a) + a)

		h.fpr(a - b)
		h.fpr(b - a)
		h.fpr(a - zero)
		h.fpr(zero - a)
		h.fpr(a - a)

		h.fpr(-a)
		h.fpr(a * 0.5)
		h.fpr(a * 2)

		h.fpr(a * b)
		h.fpr(b * a)
		h.fpr(a * zero)
		h.fpr(zero * a)

		if b < zero || zero < b {
			h.fpr(a / b)
		}
		if a < zero {
			a = -a
		}
		h.fpr(fpr(math.Sqrt(float64(a))))
	}

	var got [16]byte
	_, _ = h.sc.Read(got[:])
	if hex.EncodeToString(got[:]) != wantDigest {
		t.Fatalf("floating-point block digest = %x, want %s", got, wantDigest)
	}
}
