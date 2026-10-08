package falcon1024

import (
	"crypto/sha3"
	"encoding/binary"
	"math/bits"
)

// samplerPRNG is the Falcon reference ChaCha-based sampler PRNG.
type samplerPRNG struct {
	buf     [512]byte
	ptr     int
	state   [12]uint32
	counter uint64
}

func newSamplerPRNG(rng *sha3.SHAKE) *samplerPRNG {
	p := &samplerPRNG{}
	initSamplerPRNG(p, rng)
	return p
}

func initSamplerPRNG(p *samplerPRNG, rng *sha3.SHAKE) {
	// Falcon expands 56 bytes into 48 bytes of ChaCha state and an 8-byte counter.
	var seed [56]byte
	_, _ = rng.Read(seed[:])

	for i := range p.state {
		p.state[i] = binary.LittleEndian.Uint32(seed[4*i:])
	}
	p.counter = binary.LittleEndian.Uint64(seed[48:])

	p.refill()
}

func (p *samplerPRNG) readByte() byte {
	v := p.buf[p.ptr]
	p.ptr++
	if p.ptr == len(p.buf) {
		p.refill()
	}
	return v
}

func (p *samplerPRNG) readUint64() uint64 {
	// Match Falcon's prng_get_u64 cutoff: it may discard tail bytes, but keeps
	// extraction simple and avoids leaving an empty buffer.
	if p.ptr >= len(p.buf)-9 {
		p.refill()
	}
	v := binary.LittleEndian.Uint64(p.buf[p.ptr : p.ptr+8])
	p.ptr += 8
	return v
}

const (
	chachaConst0 uint32 = 0x61707865
	chachaConst1 uint32 = 0x3320646e
	chachaConst2 uint32 = 0x79622d32
	chachaConst3 uint32 = 0x6b206574
)

func (p *samplerPRNG) refill() {
	counter := p.counter
	for block := range 8 {
		state := [16]uint32{
			chachaConst0, chachaConst1, chachaConst2, chachaConst3,
			p.state[0], p.state[1], p.state[2], p.state[3],
			p.state[4], p.state[5], p.state[6], p.state[7],
			p.state[8], p.state[9],
			p.state[10] ^ uint32(counter),
			p.state[11] ^ uint32(counter>>32),
		}

		for range 10 {
			chachaQuarterRound(&state, 0, 4, 8, 12)
			chachaQuarterRound(&state, 1, 5, 9, 13)
			chachaQuarterRound(&state, 2, 6, 10, 14)
			chachaQuarterRound(&state, 3, 7, 11, 15)
			chachaQuarterRound(&state, 0, 5, 10, 15)
			chachaQuarterRound(&state, 1, 6, 11, 12)
			chachaQuarterRound(&state, 2, 7, 8, 13)
			chachaQuarterRound(&state, 3, 4, 9, 14)
		}

		state[0] += chachaConst0
		state[1] += chachaConst1
		state[2] += chachaConst2
		state[3] += chachaConst3
		for v := 4; v < 14; v++ {
			state[v] += p.state[v-4]
		}
		state[14] += p.state[10] ^ uint32(counter)
		state[15] += p.state[11] ^ uint32(counter>>32)
		counter++

		// Store eight ChaCha blocks interleaved by word, matching the Falcon
		// reference buffer layout.
		for word := range state {
			binary.LittleEndian.PutUint32(p.buf[(block<<2)+(word<<5):], state[word])
		}
	}

	p.counter = counter
	p.ptr = 0
}

func chachaQuarterRound(state *[16]uint32, a, b, c, d int) {
	state[a] += state[b]
	state[d] = bits.RotateLeft32(state[d]^state[a], 16)
	state[c] += state[d]
	state[b] = bits.RotateLeft32(state[b]^state[c], 12)
	state[a] += state[b]
	state[d] = bits.RotateLeft32(state[d]^state[a], 8)
	state[c] += state[d]
	state[b] = bits.RotateLeft32(state[b]^state[c], 7)
}
