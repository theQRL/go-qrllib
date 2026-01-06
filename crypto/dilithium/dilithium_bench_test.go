package dilithium

import (
	"testing"
)

// Benchmark key generation
func BenchmarkKeyGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark signing
func BenchmarkSign(b *testing.B) {
	dil, err := New()
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("benchmark message for signing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dil.Sign(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark verification
func BenchmarkVerify(b *testing.B) {
	dil, err := New()
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("benchmark message for verification")
	sig, err := dil.Sign(msg)
	if err != nil {
		b.Fatal(err)
	}
	pk := dil.GetPK()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(msg, sig, &pk) {
			b.Fatal("verification failed")
		}
	}
}

// Benchmark seal (sign + attach message)
func BenchmarkSeal(b *testing.B) {
	dil, err := New()
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("benchmark message for sealing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := dil.Seal(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark open (verify + extract message)
func BenchmarkOpen(b *testing.B) {
	dil, err := New()
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("benchmark message for opening")
	sealed, err := dil.Seal(msg)
	if err != nil {
		b.Fatal(err)
	}
	pk := dil.GetPK()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opened := Open(sealed, &pk)
		if opened == nil {
			b.Fatal("open failed")
		}
	}
}

// Benchmark with various message sizes
func BenchmarkSignMessageSizes(b *testing.B) {
	dil, err := New()
	if err != nil {
		b.Fatal(err)
	}

	sizes := []struct {
		name string
		size int
	}{
		{"32B", 32},
		{"256B", 256},
		{"1KB", 1024},
		{"64KB", 64 * 1024},
	}

	for _, size := range sizes {
		msg := make([]byte, size.size)
		b.Run(size.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := dil.Sign(msg)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
