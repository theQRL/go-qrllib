package ml_dsa_87

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
	mldsa, err := New()
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("benchmark message for signing")
	ctx := []byte{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mldsa.Sign(ctx, msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark signing with context
func BenchmarkSignWithContext(b *testing.B) {
	mldsa, err := New()
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("benchmark message for signing")
	ctx := []byte("ZOND")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mldsa.Sign(ctx, msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark verification
func BenchmarkVerify(b *testing.B) {
	mldsa, err := New()
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("benchmark message for verification")
	ctx := []byte{}
	sig, err := mldsa.Sign(ctx, msg)
	if err != nil {
		b.Fatal(err)
	}
	pk := mldsa.GetPK()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(ctx, msg, sig, &pk) {
			b.Fatal("verification failed")
		}
	}
}

// Benchmark seal (sign + attach message)
func BenchmarkSeal(b *testing.B) {
	mldsa, err := New()
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("benchmark message for sealing")
	ctx := []byte{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := mldsa.Seal(ctx, msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark open (verify + extract message)
func BenchmarkOpen(b *testing.B) {
	mldsa, err := New()
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("benchmark message for opening")
	ctx := []byte{}
	sealed, err := mldsa.Seal(ctx, msg)
	if err != nil {
		b.Fatal(err)
	}
	pk := mldsa.GetPK()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		opened := Open(ctx, sealed, &pk)
		if opened == nil {
			b.Fatal("open failed")
		}
	}
}

// Benchmark with various message sizes
func BenchmarkSignMessageSizes(b *testing.B) {
	mldsa, err := New()
	if err != nil {
		b.Fatal(err)
	}

	ctx := []byte{}

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
				_, err := mldsa.Sign(ctx, msg)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Benchmark with various context sizes
func BenchmarkSignContextSizes(b *testing.B) {
	mldsa, err := New()
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("benchmark message")

	sizes := []struct {
		name string
		size int
	}{
		{"NoCtx", 0},
		{"4B", 4},
		{"32B", 32},
		{"255B", 255}, // Max context size per FIPS 204
	}

	for _, size := range sizes {
		ctx := make([]byte, size.size)
		b.Run(size.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := mldsa.Sign(ctx, msg)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
