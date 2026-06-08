package mlkem1024_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha3"
	"encoding/hex"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/internal/mlkem1024"
	. "github.com/theQRL/go-qrllib/crypto/mlkem1024"
)

func TestRoundTrip(t *testing.T) {
	dk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()
	Ke, c, err := ek.Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	if len(Ke) != SharedKeySize {
		t.Fatalf("shared key length = %d, want %d", len(Ke), SharedKeySize)
	}
	if len(c) != CiphertextSize {
		t.Fatalf("ciphertext length = %d, want %d", len(c), CiphertextSize)
	}
	Kd, err := dk.Decapsulate(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke, Kd) {
		t.Fail()
	}

	ek1, err := NewEncapsulationKey(ek.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ek.Bytes(), ek1.Bytes()) {
		t.Fail()
	}

	dk1, err := NewDecapsulationKey(dk.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dk.Bytes(), dk1.Bytes()) {
		t.Fail()
	}

	Ke1, c1, err := ek1.Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	Kd1, err := dk1.Decapsulate(c1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke1, Kd1) {
		t.Fail()
	}

	dk2, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dk.EncapsulationKey().Bytes(), dk2.EncapsulationKey().Bytes()) {
		t.Fail()
	}
	if bytes.Equal(dk.Bytes(), dk2.Bytes()) {
		t.Fail()
	}

	Ke2, c2, err := dk.EncapsulationKey().Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c, c2) {
		t.Fail()
	}
	if bytes.Equal(Ke, Ke2) {
		t.Fail()
	}
}

func testSeed() []byte {
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

func TestInvalidInputLengths(t *testing.T) {
	if _, err := NewDecapsulationKey(make([]byte, SeedSize-1)); err == nil {
		t.Fatal("NewDecapsulationKey accepted a short seed")
	}
	if _, err := NewDecapsulationKey(make([]byte, SeedSize+1)); err == nil {
		t.Fatal("NewDecapsulationKey accepted a long seed")
	}
	if _, err := NewEncapsulationKey(make([]byte, EncapsulationKeySize-1)); err == nil {
		t.Fatal("NewEncapsulationKey accepted a short encapsulation key")
	}
	if _, err := NewEncapsulationKey(make([]byte, EncapsulationKeySize+1)); err == nil {
		t.Fatal("NewEncapsulationKey accepted a long encapsulation key")
	}

	dk, err := NewDecapsulationKey(testSeed())
	if err != nil {
		t.Fatalf("NewDecapsulationKey returned error: %v", err)
	}
	if _, err := dk.Decapsulate(make([]byte, CiphertextSize-1)); err == nil {
		t.Fatal("Decapsulate accepted a short ciphertext")
	}
	if _, err := dk.Decapsulate(make([]byte, CiphertextSize+1)); err == nil {
		t.Fatal("Decapsulate accepted a long ciphertext")
	}
}

// TestAccumulated accumulates deterministic operations and checks the hash of
// the result instead of checking in large vector files.
func TestAccumulated(t *testing.T) {
	const expected = "f1a3925c9cf8538bb104c56efb2f5ecb74cc3df25087460b73f6c873e96bcb6a"

	s := sha3.NewSHAKE128()
	o := sha3.NewSHAKE128()
	seed := make([]byte, SeedSize)
	var m [32]byte
	ct1 := make([]byte, CiphertextSize)

	for range 10000 {
		_, _ = s.Read(seed)
		dk, err := NewDecapsulationKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		ek := dk.EncapsulationKey()
		ekBytes := ek.Bytes()
		_, _ = o.Write(ekBytes)

		_, _ = s.Read(m[:])
		internalEK, err := mlkem1024.NewEncapsulationKey(ekBytes)
		if err != nil {
			t.Fatal(err)
		}
		k, ct := mlkem1024.EncapsulateInternal(internalEK, &m)
		_, _ = o.Write(ct)
		_, _ = o.Write(k)

		kk, err := dk.Decapsulate(ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(kk, k) {
			t.Fatalf("shared key = %x, want %x", kk, k)
		}

		_, _ = s.Read(ct1)
		k1, err := dk.Decapsulate(ct1)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = o.Write(k1)
	}

	var digest [32]byte
	_, _ = o.Read(digest[:])
	got := hex.EncodeToString(digest[:])
	if got != expected {
		t.Errorf("got %s, expected %s", got, expected)
	}
}

// sink keeps benchmark results observable so the compiler cannot eliminate the
// work being measured.
var sink byte

func BenchmarkGenerateKey(b *testing.B) {
	var d, z [32]byte
	_, _ = rand.Read(d[:])
	_, _ = rand.Read(z[:])
	for b.Loop() {
		dk := mlkem1024.GenerateKeyInternal(&d, &z)
		sink ^= dk.EncapsulationKey().Bytes()[0]
	}
}

func BenchmarkEncapsulate(b *testing.B) {
	seed := make([]byte, SeedSize)
	_, _ = rand.Read(seed[:])

	dk, err := NewDecapsulationKey(seed)
	if err != nil {
		b.Fatal(err)
	}
	ekBytes := dk.EncapsulationKey().Bytes()

	for b.Loop() {
		ek, err := NewEncapsulationKey(ekBytes)
		if err != nil {
			b.Fatal(err)
		}
		sharedKey, ciphertext, err := ek.Encapsulate()
		if err != nil {
			b.Fatal(err)
		}
		sink ^= ciphertext[0] ^ sharedKey[0]
	}

}

func BenchmarkDecapsulate(b *testing.B) {
	dk, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	_, ciphertext, err := ek.Encapsulate()
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		sharedKey, _ := dk.Decapsulate(ciphertext)
		sink ^= sharedKey[0]
	}
}

func TestConstantSizes(t *testing.T) {
	if SharedKeySize != mlkem1024.SharedKeySize {
		t.Errorf("SharedKeySize mismatch: got %d, want %d", SharedKeySize, mlkem1024.SharedKeySize)
	}

	if SeedSize != mlkem1024.SeedSize {
		t.Errorf("SeedSize mismatch: got %d, want %d", SeedSize, mlkem1024.SeedSize)
	}

	if CiphertextSize != mlkem1024.CiphertextSize {
		t.Errorf("CiphertextSize mismatch: got %d, want %d", CiphertextSize, mlkem1024.CiphertextSize)
	}

	if EncapsulationKeySize != mlkem1024.EncapsulationKeySize {
		t.Errorf("EncapsulationKeySize mismatch: got %d, want %d", EncapsulationKeySize, mlkem1024.EncapsulationKeySize)
	}
}
