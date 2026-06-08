package mlkem1024

import (
	"bytes"
	"testing"
)

// TestExportedAPIRoundTrip exercises the package's exported entry points and a
// full encapsulate/decapsulate round-trip. These functions are otherwise
// reached only through the public crypto/mlkem1024 wrapper, so without this
// test the per-package coverage profile does not credit them.
func TestExportedAPIRoundTrip(t *testing.T) {
	dk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	seed := dk.Bytes()

	ek := dk.EncapsulationKey()

	// Random encapsulation round-trips back to the same shared secret.
	ss1, ct, err := ek.Encapsulate()
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	ss2, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("shared secrets differ across encapsulate/decapsulate")
	}

	// Bytes() round-trips through the constructors.
	dk2, err := NewDecapsulationKey(seed)
	if err != nil {
		t.Fatalf("NewDecapsulationKey(seed): %v", err)
	}
	if !bytes.Equal(dk2.EncapsulationKey().Bytes(), ek.Bytes()) {
		t.Fatal("decapsulation key did not round-trip through Bytes")
	}
	ek2, err := NewEncapsulationKey(ek.Bytes())
	if err != nil {
		t.Fatalf("NewEncapsulationKey(ek.Bytes()): %v", err)
	}
	if !bytes.Equal(ek2.Bytes(), ek.Bytes()) {
		t.Fatal("encapsulation key did not round-trip through Bytes")
	}

	// The derandomized test-only helpers agree with the seeded path.
	d := (*[32]byte)(seed[:32])
	z := (*[32]byte)(seed[32:])
	if !bytes.Equal(GenerateKeyInternal(d, z).Bytes(), seed) {
		t.Fatal("GenerateKeyInternal disagreed with the GenerateKey seed")
	}

	var m [32]byte
	for i := range m {
		m[i] = byte(i)
	}
	ssA, ctA := EncapsulateInternal(ek, &m)
	ssB, ctB := EncapsulateInternal(ek, &m)
	if !bytes.Equal(ssA, ssB) || !bytes.Equal(ctA, ctB) {
		t.Fatal("EncapsulateInternal is not deterministic")
	}
	ssDec, err := dk.Decapsulate(ctA)
	if err != nil {
		t.Fatalf("Decapsulate(derandomized ct): %v", err)
	}
	if !bytes.Equal(ssDec, ssA) {
		t.Fatal("decapsulation of derandomized ciphertext mismatch")
	}

	// Zeroize clears the secret seeds.
	dk.Zeroize()
	if !bytes.Equal(dk.Bytes(), make([]byte, SeedSize)) {
		t.Fatal("Zeroize did not clear the decapsulation key seeds")
	}
}

// TestExportedAPIErrorPaths covers the length checks and the byteDecode12
// modulus check (rejection of an encapsulation key whose coefficients are >= q).
func TestExportedAPIErrorPaths(t *testing.T) {
	if _, err := NewDecapsulationKey(make([]byte, SeedSize-1)); err == nil {
		t.Fatal("NewDecapsulationKey accepted a short seed")
	}
	if _, err := NewEncapsulationKey(make([]byte, EncapsulationKeySize-1)); err == nil {
		t.Fatal("NewEncapsulationKey accepted a short key")
	}

	dk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := dk.Decapsulate(make([]byte, CiphertextSize-1)); err == nil {
		t.Fatal("Decapsulate accepted a short ciphertext")
	}

	// An all-0xff encapsulation key encodes coefficients of 0xfff (4095) >= q,
	// which byteDecode12 must reject.
	bad := bytes.Repeat([]byte{0xff}, EncapsulationKeySize)
	if _, err := NewEncapsulationKey(bad); err == nil {
		t.Fatal("NewEncapsulationKey accepted out-of-range coefficients")
	}
}
