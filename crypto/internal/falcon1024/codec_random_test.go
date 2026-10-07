package falcon1024

import (
	"crypto/sha3"
	"encoding/binary"
	"testing"
)

func TestCodecRandomRoundTrip(t *testing.T) {
	// Random polynomials, drawn from SHAKE256("codec" || logN), must survive
	// an encode/decode round trip and produce the expected lengths.
	//
	// Signed inputs are generated at every width from 4 to 12 bits for the
	// compressed codec and from 4 to 8 bits for trimI8. Only the two trimI8
	// widths used by Falcon-1024 private keys are implemented, so the other
	// widths are skipped. Their input is still drawn, so that the inputs of
	// the tested widths do not depend on which widths are implemented.
	sc := sha3.NewSHAKE256()
	_, _ = sc.Write([]byte("codec"))
	_, _ = sc.Write([]byte{logN})

	if want := (n*14 + 7) >> 3; encodingSize14 != want {
		t.Fatalf("encodingSize14 = %d, want %d", encodingSize14, want)
	}

	// signedFromBits builds a signed value from the low bits of w: the top bit
	// of the width selects the sign and the lower bits are the magnitude.
	signedFromBits := func(w uint32, bits int) int32 {
		signMask := uint32(1) << (bits - 1)
		magnitude := int32(w & (signMask - 1))
		if w&signMask != 0 {
			return -magnitude
		}
		return magnitude
	}

	encoded := make([]byte, 4*n)

	for iteration := range 10 {
		var m1 ringElement
		for u := range m1 {
			var tt [4]byte
			_, _ = sc.Read(tt[:])
			m1[u] = fieldElement(binary.LittleEndian.Uint32(tt[:]) % q)
		}
		polyByteEncode(encoded[:encodingSize14], m1)
		m2, err := polyByteDecode(encoded[:encodingSize14])
		if err != nil {
			t.Fatalf("iteration %d: polyByteDecode: %v", iteration, err)
		}
		if m1 != m2 {
			t.Fatalf("iteration %d: polyByteEncode/polyByteDecode mismatch", iteration)
		}

		for bits := 4; bits <= 12; bits++ {
			var s1 smallPolynomial
			for u := range s1 {
				var tt [2]byte
				_, _ = sc.Read(tt[:])
				s1[u] = signedFromBits(uint32(binary.LittleEndian.Uint16(tt[:])), bits)
			}

			written, err := compressedEncode(encoded, s1)
			if err != nil {
				t.Fatalf("iteration %d, %d bits: compressedEncode: %v", iteration, bits, err)
			}
			if written == 0 {
				t.Fatalf("iteration %d, %d bits: compressedEncode wrote nothing", iteration, bits)
			}
			s2, consumed, err := compressedDecode(encoded[:written])
			if err != nil {
				t.Fatalf("iteration %d, %d bits: compressedDecode: %v", iteration, bits, err)
			}
			if consumed != written {
				t.Fatalf("iteration %d, %d bits: compressedDecode consumed %d bytes, want %d", iteration, bits, consumed, written)
			}
			if s1 != s2 {
				t.Fatalf("iteration %d, %d bits: compressedEncode/compressedDecode mismatch", iteration, bits)
			}
		}

		for bits := 4; bits <= 8; bits++ {
			var b1 smallPolynomial
			for u := range b1 {
				var tt [1]byte
				_, _ = sc.Read(tt[:])
				b1[u] = signedFromBits(uint32(tt[0]), bits)
			}
			if bits != fgBits && bits != ntruFBits {
				continue
			}

			wantLen := (n*bits + 7) >> 3
			written, err := trimI8Encode(encoded, b1, bits)
			if err != nil {
				t.Fatalf("iteration %d, %d bits: trimI8Encode: %v", iteration, bits, err)
			}
			if written != wantLen {
				t.Fatalf("iteration %d, %d bits: trimI8Encode wrote %d bytes, want %d", iteration, bits, written, wantLen)
			}
			b2, consumed, err := trimI8Decode(encoded[:written], bits)
			if err != nil {
				t.Fatalf("iteration %d, %d bits: trimI8Decode: %v", iteration, bits, err)
			}
			if consumed != written {
				t.Fatalf("iteration %d, %d bits: trimI8Decode consumed %d bytes, want %d", iteration, bits, consumed, written)
			}
			if b1 != b2 {
				t.Fatalf("iteration %d, %d bits: trimI8Encode/trimI8Decode mismatch", iteration, bits)
			}
		}
	}
}
