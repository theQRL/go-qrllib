//go:build metamorphic

// Exhaustive / structured metamorphic tests for ML-KEM-1024, mirroring the
// ML-DSA-87 metamorphic suite (crypto/ml_dsa_87/metamorphic_test.go). A KEM has
// no signature to maul, so the analogous invariants are:
//
//   - a mauled ciphertext must decapsulate to the pseudorandom implicit-
//     rejection key — never the real shared secret, never an error — swept
//     bit-by-bit across the entire ciphertext;
//   - decapsulation is deterministic for a fixed (key, ciphertext);
//   - decapsulating a ciphertext under the wrong key is isolated from the real
//     secret and deterministic;
//   - derandomised encapsulation and seed -> key derivation are deterministic
//     and change whenever their input changes.
//
// Guarded by the `metamorphic` build tag (deep, slow); run with:
//
//	go test -tags metamorphic -run TestMetamorphic -timeout 5m ./crypto/internal/mlkem1024/

package mlkem1024

import (
	"bytes"
	"testing"
)

func metamorphicKey(fill byte) *DecapsulationKey {
	var d, z [32]byte
	for i := range d {
		d[i] = fill ^ byte(i)
		z[i] = fill ^ byte(255-i)
	}
	return GenerateKeyInternal(&d, &z)
}

// TestMetamorphicCiphertextMaulImplicitRejection flips every bit of a valid
// ciphertext and asserts decapsulation never errors, never recovers the real
// shared secret, and is deterministic — i.e. the FO implicit-rejection path is
// taken byte-exactly and constant-shape for every single-bit perturbation.
func TestMetamorphicCiphertextMaulImplicitRejection(t *testing.T) {
	dk := metamorphicKey(0xA5)
	var m [32]byte
	for i := range m {
		m[i] = byte(i)
	}
	ss, ct := EncapsulateInternal(dk.EncapsulationKey(), &m)

	if got, err := dk.Decapsulate(ct); err != nil || !bytes.Equal(got, ss) {
		t.Fatalf("baseline decapsulation failed (err=%v)", err)
	}

	for bit := 0; bit < CiphertextSize*8; bit++ {
		mauled := append([]byte(nil), ct...)
		mauled[bit/8] ^= 1 << (bit % 8)

		k, err := dk.Decapsulate(mauled)
		if err != nil {
			t.Fatalf("bit %d: Decapsulate errored; implicit rejection must not error: %v", bit, err)
		}
		if len(k) != SharedKeySize {
			t.Fatalf("bit %d: shared-key length %d (want %d)", bit, len(k), SharedKeySize)
		}
		if bytes.Equal(k, ss) {
			t.Fatalf("bit %d: mauled ciphertext recovered the real shared secret", bit)
		}
		if k2, _ := dk.Decapsulate(mauled); !bytes.Equal(k, k2) {
			t.Fatalf("bit %d: implicit-rejection key is non-deterministic", bit)
		}
	}
}

// TestMetamorphicWrongKeyIsolation decapsulates a valid ciphertext under a
// different key: the result must not be the real secret and must be
// deterministic (no cross-key leakage).
func TestMetamorphicWrongKeyIsolation(t *testing.T) {
	dk := metamorphicKey(0x11)
	wrong := metamorphicKey(0x22)

	var m [32]byte
	m[0] = 0x33
	ss, ct := EncapsulateInternal(dk.EncapsulationKey(), &m)

	k, err := wrong.Decapsulate(ct)
	if err != nil {
		t.Fatalf("wrong-key Decapsulate errored: %v", err)
	}
	if bytes.Equal(k, ss) {
		t.Fatal("decapsulating under the wrong key recovered the real shared secret")
	}
	if k2, _ := wrong.Decapsulate(ct); !bytes.Equal(k, k2) {
		t.Fatal("wrong-key decapsulation is non-deterministic")
	}
}

// TestMetamorphicEncapsAndSeedDeterminism asserts that derandomised
// encapsulation and seed -> key derivation are deterministic and change
// whenever their input changes.
func TestMetamorphicEncapsAndSeedDeterminism(t *testing.T) {
	dk := metamorphicKey(0x5A)
	ek := dk.EncapsulationKey()

	var m [32]byte
	for i := range m {
		m[i] = byte(2 * i)
	}
	ss1, ct1 := EncapsulateInternal(ek, &m)
	ss2, ct2 := EncapsulateInternal(ek, &m)
	if !bytes.Equal(ss1, ss2) || !bytes.Equal(ct1, ct2) {
		t.Fatal("derandomised encapsulation is non-deterministic")
	}

	for bit := 0; bit < 32*8; bit++ {
		mm := m
		mm[bit/8] ^= 1 << (bit % 8)
		ssX, ctX := EncapsulateInternal(ek, &mm)
		if bytes.Equal(ctX, ct1) || bytes.Equal(ssX, ss1) {
			t.Fatalf("message bit %d did not change the encapsulation output", bit)
		}
	}

	var d, z [32]byte
	for i := range d {
		d[i] = byte(i)
		z[i] = byte(255 - i)
	}
	a := GenerateKeyInternal(&d, &z)
	b := GenerateKeyInternal(&d, &z)
	if !bytes.Equal(a.EncapsulationKey().Bytes(), b.EncapsulationKey().Bytes()) {
		t.Fatal("identical seed produced different keys")
	}
	d[0] ^= 1
	c := GenerateKeyInternal(&d, &z)
	if bytes.Equal(a.EncapsulationKey().Bytes(), c.EncapsulationKey().Bytes()) {
		t.Fatal("flipping a seed bit did not change the derived key")
	}
}
