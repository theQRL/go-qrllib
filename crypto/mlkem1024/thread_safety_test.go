package mlkem1024_test

import (
	"bytes"
	"sync"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/mlkem1024"
)

// TestConcurrentEncapsulateDecapsulate exercises a single shared key pair from
// many goroutines. ML-KEM keys are immutable after construction, so concurrent
// Encapsulate/Decapsulate must be correct and free of data races. Run under the
// race detector (the CI `-race -short` step) to catch shared-state mutation.
func TestConcurrentEncapsulateDecapsulate(t *testing.T) {
	dk, err := mlkem1024.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ek := dk.EncapsulationKey()

	const goroutines, iters = 16, 64
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				ss, ct, err := ek.Encapsulate()
				if err != nil {
					t.Errorf("Encapsulate: %v", err)
					return
				}
				got, err := dk.Decapsulate(ct)
				if err != nil {
					t.Errorf("Decapsulate: %v", err)
					return
				}
				if !bytes.Equal(ss, got) {
					t.Errorf("shared-secret mismatch under concurrent use")
					return
				}
			}
		}()
	}
	wg.Wait()
}
