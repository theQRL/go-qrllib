package ml_dsa_87

import (
	"bytes"
	"crypto/sha3"
	"io"
	"testing"
)

// refRejNTTPoly is FIPS 204 Algorithm 30 (RejNTTPoly) over a byte stream: it
// takes three bytes at a time from one continuous stream and keeps the 23-bit
// value when it is below q (Algorithm 14, CoeffFromThreeBytes). The reference
// poly_uniform computes the same thing block by block.
func refRejNTTPoly(t *testing.T, xof io.Reader) [N]int32 {
	t.Helper()
	var a [N]int32
	var b [3]byte
	for j := 0; j < N; {
		if _, err := io.ReadFull(xof, b[:]); err != nil {
			t.Fatal(err)
		}
		z := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2]&0x7F)<<16
		if z < Q {
			a[j] = int32(z)
			j++
		}
	}
	return a
}

func requireSameCoefficients(t *testing.T, got, want [N]int32) {
	t.Helper()
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("coefficient %d: got %d, want %d", i, got[i], want[i])
		}
	}
}

func TestPolyUniformRefillMatchesRejNTTPoly(t *testing.T) {
	// The first pass consumes POLY_UNIFORM_N_BLOCKS blocks, 280 candidate
	// triples. A refill happens only if fewer than 256 of them are accepted,
	// which needs at least 25 rejections where fewer than one is expected,
	// so no real seed exercises it. Drive it with a crafted stream whose
	// first 40 triples are 0xFF 0xFF 0x7F, the largest 23-bit value, which
	// is rejected, and check that sampling continues from the right offset
	// of the stream: the reference squeezes exactly five blocks before the
	// refill, and the two spare buffer bytes must not be taken from the
	// stream on the first pass.
	xof := sha3.NewSHAKE256()
	_, _ = xof.Write([]byte("poly_uniform refill"))
	stream := make([]byte, POLY_UNIFORM_N_BLOCKS*STREAM128_BLOCK_BYTES+4*STREAM128_BLOCK_BYTES)
	_, _ = xof.Read(stream)
	for i := range 40 {
		stream[3*i], stream[3*i+1], stream[3*i+2] = 0xFF, 0xFF, 0x7F
	}

	var got poly
	if err := polyUniformFromXOF(&got, bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	requireSameCoefficients(t, got.coeffs, refRejNTTPoly(t, bytes.NewReader(stream)))

	// The refill must have been reached: the accepted coefficients of the
	// first pass cannot fill the polynomial.
	accepted := 0
	for i := 0; i+3 <= POLY_UNIFORM_N_BLOCKS*STREAM128_BLOCK_BYTES; i += 3 {
		z := uint32(stream[i]) | uint32(stream[i+1])<<8 | uint32(stream[i+2]&0x7F)<<16
		if z < Q {
			accepted++
		}
	}
	if accepted >= N {
		t.Fatalf("first pass accepted %d candidates, the refill was not exercised", accepted)
	}
}

func TestPolyUniformMatchesRejNTTPoly(t *testing.T) {
	// On the common path, polyUniform over SHAKE128(seed || nonce) must equal
	// Algorithm 30 over the same stream, for several seeds and nonces.
	rnd := sha3.NewSHAKE256()
	_, _ = rnd.Write([]byte("poly_uniform seeds"))
	for i := range 16 {
		var seed [SEED_BYTES]uint8
		_, _ = rnd.Read(seed[:])
		nonce := uint16(i<<8 | (i * 7 % 8))

		var got poly
		if err := polyUniform(&got, &seed, nonce); err != nil {
			t.Fatal(err)
		}

		xof := sha3.NewSHAKE128()
		_, _ = xof.Write(seed[:])
		_, _ = xof.Write([]byte{uint8(nonce), uint8(nonce >> 8)})
		requireSameCoefficients(t, got.coeffs, refRejNTTPoly(t, xof))
	}
}
