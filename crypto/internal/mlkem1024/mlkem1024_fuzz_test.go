package mlkem1024

// Fuzz targets for ML-KEM-1024, matching the entry-point + metamorphic style of
// the ML-DSA-87 fuzz suite (crypto/ml_dsa_87/*_fuzz_test.go). A KEM's attacker
// surface differs from a signature's: the ciphertext (and the encapsulation
// key) are attacker-controlled, so these targets exercise:
//
//   - parsing of untrusted encapsulation keys and seeds (never panic; anything
//     accepted must round-trip),
//   - decapsulation of arbitrary ciphertext against a fixed key (never panic;
//     wrong lengths rejected; correct length always yields a 32-byte key via
//     implicit rejection; deterministic), and
//   - a structured round-trip plus single-bit ciphertext maul: the real
//     ciphertext recovers the shared secret, while a mauled ciphertext must
//     decapsulate to a *different* key (implicit rejection) without error.
//
// These run in the normal `go test` fuzzing flow (no build tag), like the
// other suites.

import (
	"bytes"
	"testing"
)

// fuzzMaulBit returns a copy of src with a single bit flipped, selected by
// bitIndex. For a non-empty fixed-length input it always changes exactly one
// bit, so the result differs from src.
func fuzzMaulBit(src []byte, bitIndex uint32) []byte {
	out := append([]byte(nil), src...)
	if len(out) == 0 {
		return []byte{1}
	}
	bit := int(bitIndex) % (len(out) * 8)
	out[bit/8] ^= 1 << (bit % 8)
	return out
}

// FuzzMLKEM1024NewEncapsulationKey feeds arbitrary bytes to the encapsulation-key
// parser: it must never panic, and any key it accepts must round-trip exactly.
func FuzzMLKEM1024NewEncapsulationKey(f *testing.F) {
	valid, err := GenerateKey()
	if err != nil {
		f.Fatalf("GenerateKey setup: %v", err)
	}
	f.Add(valid.EncapsulationKey().Bytes())
	f.Add([]byte{})
	f.Add(make([]byte, EncapsulationKeySize-1))
	f.Add(bytes.Repeat([]byte{0xff}, EncapsulationKeySize)) // out-of-range coefficients

	f.Fuzz(func(t *testing.T, data []byte) {
		ek, err := NewEncapsulationKey(data)
		if err != nil {
			return // rejection is acceptable; we only require no panic
		}
		if len(data) != EncapsulationKeySize {
			t.Fatalf("accepted encapsulation key of length %d (want %d)", len(data), EncapsulationKeySize)
		}
		if !bytes.Equal(ek.Bytes(), data) {
			t.Fatal("accepted encapsulation key did not round-trip through Bytes")
		}
	})
}

// FuzzMLKEM1024NewDecapsulationKey feeds arbitrary bytes to the seed-based
// decapsulation-key constructor: never panic; accepted seeds round-trip.
func FuzzMLKEM1024NewDecapsulationKey(f *testing.F) {
	f.Add(make([]byte, SeedSize))
	f.Add([]byte{})
	f.Add(make([]byte, SeedSize-1))
	f.Add(make([]byte, SeedSize+1))

	f.Fuzz(func(t *testing.T, seed []byte) {
		dk, err := NewDecapsulationKey(seed)
		if err != nil {
			return
		}
		if len(seed) != SeedSize {
			t.Fatalf("accepted seed of length %d (want %d)", len(seed), SeedSize)
		}
		if !bytes.Equal(dk.Bytes(), seed) {
			t.Fatal("accepted seed did not round-trip through Bytes")
		}
	})
}

// FuzzMLKEM1024Decapsulate models the core attacker capability: the ciphertext
// is fully attacker-controlled. Against a fixed key, decapsulating arbitrary
// input must never panic, must reject wrong-length ciphertexts, must always
// return a 32-byte shared secret for correct-length input (implicit rejection),
// and must be deterministic.
func FuzzMLKEM1024Decapsulate(f *testing.F) {
	var seed [SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	dk, err := NewDecapsulationKey(seed[:])
	if err != nil {
		f.Fatalf("NewDecapsulationKey setup: %v", err)
	}
	var m [32]byte
	_, realCT := EncapsulateInternal(dk.EncapsulationKey(), &m)
	f.Add(realCT)
	f.Add([]byte{})
	f.Add(make([]byte, CiphertextSize-1))
	f.Add(make([]byte, CiphertextSize))
	f.Add(bytes.Repeat([]byte{0xff}, CiphertextSize))

	f.Fuzz(func(t *testing.T, ct []byte) {
		k, err := dk.Decapsulate(ct)
		if len(ct) != CiphertextSize {
			if err == nil {
				t.Fatalf("accepted ciphertext of length %d (want %d)", len(ct), CiphertextSize)
			}
			return
		}
		if err != nil {
			t.Fatalf("Decapsulate rejected a correct-length ciphertext: %v", err)
		}
		if len(k) != SharedKeySize {
			t.Fatalf("shared key length %d (want %d)", len(k), SharedKeySize)
		}
		// Implicit rejection must be deterministic for a fixed key + ciphertext.
		k2, err := dk.Decapsulate(ct)
		if err != nil || !bytes.Equal(k, k2) {
			t.Fatal("Decapsulate is not deterministic for a fixed key + ciphertext")
		}
	})
}

// FuzzMLKEM1024RoundTripMutate derives a key from fuzzed (d, z), encapsulates a
// fuzzed message, and checks two properties: (1) decapsulating the real
// ciphertext recovers the encapsulated shared secret; (2) a single-bit-mauled
// ciphertext decapsulates to a *different* key via implicit rejection — never
// the real secret, never an error, never a panic.
func FuzzMLKEM1024RoundTripMutate(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x02}, 32), bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x03}, 32), uint32(0))
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 32), uint32(12345))

	f.Fuzz(func(t *testing.T, dBytes, zBytes, mBytes []byte, bitIndex uint32) {
		var d, z, m [32]byte
		copy(d[:], dBytes)
		copy(z[:], zBytes)
		copy(m[:], mBytes)

		dk := GenerateKeyInternal(&d, &z)
		ss, ct := EncapsulateInternal(dk.EncapsulationKey(), &m)
		if len(ss) != SharedKeySize {
			t.Fatalf("EncapsulateInternal shared key length %d (want %d)", len(ss), SharedKeySize)
		}

		// (1) Round-trip correctness.
		got, err := dk.Decapsulate(ct)
		if err != nil {
			t.Fatalf("Decapsulate(valid ciphertext): %v", err)
		}
		if !bytes.Equal(got, ss) {
			t.Fatal("round-trip failed: decapsulated key != encapsulated shared secret")
		}

		// (2) Mauled ciphertext → implicit rejection (different key, no error).
		mauled := fuzzMaulBit(ct, bitIndex)
		if bytes.Equal(mauled, ct) {
			return // no-op maul; nothing to assert
		}
		rej, err := dk.Decapsulate(mauled)
		if err != nil {
			t.Fatalf("Decapsulate(mauled ciphertext) errored; implicit rejection must not error: %v", err)
		}
		if len(rej) != SharedKeySize {
			t.Fatalf("rejection key length %d (want %d)", len(rej), SharedKeySize)
		}
		if bytes.Equal(rej, ss) {
			t.Fatal("mauled ciphertext decapsulated to the real shared secret — implicit rejection broken")
		}
	})
}
