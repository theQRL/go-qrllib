package mlkem1024

// Metamorphic fuzz targets for ML-KEM-1024, complementing FuzzMLKEM1024RoundTripMutate
// in mlkem1024_fuzz_test.go (which covers round-trip + single-bit ciphertext maul).
// These run in the normal fuzzing flow (no build tag) and are picked up by the
// CI fuzz loop alongside the entry-point fuzzers.

import (
	"bytes"
	"testing"
)

// FuzzMLKEM1024MetamorphicWrongKey: a ciphertext encapsulated to key A must not
// decapsulate to A's shared secret under a key B with a different encapsulation
// key (no cross-key leakage). The skip-guard compares encapsulation keys, not
// the full d||z seed: ML-KEM's decapsulation key is (d, z) where d derives the
// whole keypair and z is only the implicit-rejection secret used on the FAILURE
// path. Two keys that share d but differ in z therefore have distinct Bytes()
// yet the same encapsulation key, and B legitimately recovers A's shared secret
// from a valid ciphertext — that is the FO transform working as designed, not
// leakage. The third f.Add seed below pins exactly that same-d/different-z case.
func FuzzMLKEM1024MetamorphicWrongKey(f *testing.F) {
	f.Add(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32),
		bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32), make([]byte, 32))
	// same d, different z: distinct Bytes() but identical encapsulation key —
	// B must legitimately recover A's secret, and the guard must skip it.
	f.Add(bytes.Repeat([]byte{6}, 32), bytes.Repeat([]byte{7}, 32),
		bytes.Repeat([]byte{6}, 32), bytes.Repeat([]byte{8}, 32), bytes.Repeat([]byte{9}, 32))

	f.Fuzz(func(t *testing.T, dA, zA, dB, zB, msg []byte) {
		var da, za, db, zb, m [32]byte
		copy(da[:], dA)
		copy(za[:], zA)
		copy(db[:], dB)
		copy(zb[:], zB)
		copy(m[:], msg)

		keyA := GenerateKeyInternal(&da, &za)
		keyB := GenerateKeyInternal(&db, &zb)
		ss, ct := EncapsulateInternal(keyA.EncapsulationKey(), &m)

		wrong, err := keyB.Decapsulate(ct)
		if err != nil {
			t.Fatalf("wrong-key Decapsulate errored: %v", err)
		}
		// Skip when the encapsulation keys match (same d): B then shares A's
		// decryption key, so recovering A's shared secret is correct, not leakage.
		if bytes.Equal(keyA.EncapsulationKey().Bytes(), keyB.EncapsulationKey().Bytes()) {
			return
		}
		if bytes.Equal(wrong, ss) {
			t.Fatal("ciphertext decapsulated to A's shared secret under a key B with a different encapsulation key")
		}
	})
}

// FuzzMLKEM1024MetamorphicDecapsDeterminism: decapsulating the same ciphertext
// under the same key twice must yield identical results (value and error-ness).
func FuzzMLKEM1024MetamorphicDecapsDeterminism(f *testing.F) {
	f.Add(bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32), bytes.Repeat([]byte{9}, CiphertextSize))
	f.Add(make([]byte, 32), make([]byte, 32), make([]byte, 0))

	f.Fuzz(func(t *testing.T, d, z, ct []byte) {
		var dd, zz [32]byte
		copy(dd[:], d)
		copy(zz[:], z)
		dk := GenerateKeyInternal(&dd, &zz)

		k1, err1 := dk.Decapsulate(ct)
		k2, err2 := dk.Decapsulate(ct)
		if (err1 == nil) != (err2 == nil) {
			t.Fatal("Decapsulate error-ness is non-deterministic")
		}
		if err1 == nil && !bytes.Equal(k1, k2) {
			t.Fatal("Decapsulate is non-deterministic for a fixed key and ciphertext")
		}
	})
}
