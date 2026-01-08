package sphincsplus_256s

import "testing"

func BenchmarkKeyGeneration(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := New()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign(b *testing.B) {
	spx, err := New()
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("benchmark message for signing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := spx.Sign(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	spx, err := New()
	if err != nil {
		b.Fatal(err)
	}

	msg := []byte("benchmark message for verification")
	sig, err := spx.Sign(msg)
	if err != nil {
		b.Fatal(err)
	}
	pk := spx.GetPK()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !Verify(msg, sig, &pk) {
			b.Fatal("verification failed")
		}
	}
}
