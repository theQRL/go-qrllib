package ml_dsa_87

import "testing"

// These tests pin the byte->coefficient mapping of polyZUnpack, the routine
// that decodes the signing mask y and the response vector z (20-bit
// coefficients, 5 bytes per coefficient pair, FIPS 204 BitUnpack with
// GAMMA1=2^19).
//
// They guard against the mask-coefficient-duplication bug class (the
// "AABBCC" / "A0B0C0" / "ABABCDCD" re-indexing errors) described in
// D. J. Bernstein, "Exploiting ML-DSA bugs" (2026-06-01): if polyZUnpack
// is mis-indexed so that neighbouring coefficients share input bytes, the
// mask becomes structurally degenerate and the secret key is recoverable
// from signatures. Each correct coefficient must be assembled from its own
// non-overlapping byte range, with only the middle byte (a[5i+2])
// nibble-split between the pair.

// TestPolyZUnpackKnownAnswer isolates every input byte (and both nibbles of
// the shared middle byte) so any re-indexing changes at least one expected
// value. Expected coefficients are written as GAMMA1-(byte<<shift) to mirror
// the spec mapping rather than as opaque constants.
func TestPolyZUnpackKnownAnswer(t *testing.T) {
	cases := []struct {
		name         string
		in           [5]uint8
		want0, want1 int32
	}{
		// coeff0 is built from a[0] | a[1]<<8 | (a[2]&0x0F)<<16.
		{"a0_to_coeff0_bits0_7", [5]uint8{0x05, 0, 0, 0, 0}, GAMMA1 - 0x05, GAMMA1},
		{"a1_to_coeff0_bits8_15", [5]uint8{0, 0x05, 0, 0, 0}, GAMMA1 - (0x05 << 8), GAMMA1},
		{"a2lo_to_coeff0_bits16_19", [5]uint8{0, 0, 0x07, 0, 0}, GAMMA1 - (0x07 << 16), GAMMA1},

		// coeff1 is built from (a[2]>>4) | a[3]<<4 | a[4]<<12.
		// a[2]'s high nibble must feed coeff1 ONLY (the 0xFFFFF mask must
		// keep it out of coeff0) — this case fails if the mask is dropped
		// or the nibble split is wrong.
		{"a2hi_to_coeff1_bits0_3", [5]uint8{0, 0, 0x70, 0, 0}, GAMMA1, GAMMA1 - (0x70 >> 4)},
		{"a3_to_coeff1_bits4_11", [5]uint8{0, 0, 0, 0x05, 0}, GAMMA1, GAMMA1 - (0x05 << 4)},
		{"a4_to_coeff1_bits12_19", [5]uint8{0, 0, 0, 0, 0x05}, GAMMA1, GAMMA1 - (0x05 << 12)},

		// Anti-duplication anchor: distinct concrete coefficients from a
		// fully-populated block. A duplication bug would make want0==want1.
		// in = {0xFF,0xFF,0xE7,0xFF,0x7F} -> raw0=0x7FFFF, raw1=0x7FFFE.
		{"distinct_pair", [5]uint8{0xFF, 0xFF, 0xE7, 0xFF, 0x7F}, 1, 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf [POLY_Z_PACKED_BYTES]uint8
			copy(buf[:5], tc.in[:])

			var p poly
			polyZUnpack(&p, buf[:])

			if p.coeffs[0] != tc.want0 || p.coeffs[1] != tc.want1 {
				t.Fatalf("polyZUnpack(%#v) coeffs = (%d, %d); want (%d, %d)",
					tc.in, p.coeffs[0], p.coeffs[1], tc.want0, tc.want1)
			}
			if p.coeffs[0] == p.coeffs[1] && tc.want0 != tc.want1 {
				t.Fatalf("coefficients duplicated (%d == %d) — possible AABBCC mask-unpacking regression",
					p.coeffs[0], p.coeffs[1])
			}
		})
	}
}

// TestPolyZPackUnpackRoundTrip exercises all N coefficients with distinct,
// in-range values (polyZPack supports coeffs in [-(GAMMA1-1), GAMMA1]). A
// mis-indexing that reused bytes across coefficients would fail to recover
// the distinct neighbours.
func TestPolyZPackUnpackRoundTrip(t *testing.T) {
	var in poly
	for i := 0; i < N; i++ {
		// raw = GAMMA1 - coeff must land in [0, 2^20). Step by a prime so
		// adjacent coefficients are always distinct.
		raw := int32((i*4099 + 7) & 0xFFFFF)
		in.coeffs[i] = GAMMA1 - raw
	}

	var buf [POLY_Z_PACKED_BYTES]uint8
	polyZPack(buf[:], &in)

	var out poly
	polyZUnpack(&out, buf[:])

	for i := 0; i < N; i++ {
		if in.coeffs[i] != out.coeffs[i] {
			t.Fatalf("round-trip mismatch at coeff %d: in=%d out=%d", i, in.coeffs[i], out.coeffs[i])
		}
	}
}
