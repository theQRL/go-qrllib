package dilithium

import (
	"sync"
	"testing"
)

// Thread safety tests for Dilithium (TST-006)
// Run with: go test -race ./crypto/dilithium/...
//
// These tests verify that concurrent operations don't cause data races.

// TestThreadSafetyConcurrentVerify tests parallel verification with shared public key
func TestThreadSafetyConcurrentVerify(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message for concurrent verification")

	sig, err := dil.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	pk := dil.GetPK()

	// Run many concurrent verifications
	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			if !Verify(msg, sig, &pk) {
				errors <- nil // Use nil to indicate verification failure
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		if err == nil {
			t.Error("Concurrent verification failed")
		}
	}
}

// TestThreadSafetyConcurrentSign tests parallel signing with different instances
func TestThreadSafetyConcurrentSign(t *testing.T) {
	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan string, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			// Each goroutine creates its own instance
			dil, err := New()
			if err != nil {
				errors <- "Failed to create instance"
				return
			}

			msg := []byte("test message")

			sig, err := dil.Sign(msg)
			if err != nil {
				errors <- "Failed to sign"
				return
			}

			pk := dil.GetPK()
			if !Verify(msg, sig, &pk) {
				errors <- "Verification failed"
				return
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for errMsg := range errors {
		t.Error(errMsg)
	}
}

// TestThreadSafetyConcurrentKeyGeneration tests parallel key generation
func TestThreadSafetyConcurrentKeyGeneration(t *testing.T) {
	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	results := make(chan *Dilithium, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			dil, err := New()
			if err != nil {
				t.Errorf("Failed to create Dilithium: %v", err)
				return
			}
			results <- dil
		}()
	}

	wg.Wait()
	close(results)

	// Verify all instances are unique
	pks := make(map[string]bool)
	for dil := range results {
		if dil == nil {
			continue
		}
		pk := dil.GetPK()
		pkStr := string(pk[:])
		if pks[pkStr] {
			t.Error("Duplicate public key generated")
		}
		pks[pkStr] = true
	}
}

// TestThreadSafetyConcurrentSealOpen tests parallel seal/open operations
func TestThreadSafetyConcurrentSealOpen(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	pk := dil.GetPK()

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2) // Half seal, half open

	// Pre-create some sealed messages
	sealedMsgs := make([][]byte, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		msg := []byte("message " + string(rune(i)))
		sealed, err := dil.Seal(msg)
		if err != nil {
			t.Fatalf("Failed to seal: %v", err)
		}
		sealedMsgs[i] = sealed
	}

	// Concurrent sealing
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			msg := []byte("concurrent message")
			_, err := dil.Seal(msg)
			if err != nil {
				t.Errorf("Concurrent seal failed: %v", err)
			}
		}(i)
	}

	// Concurrent opening
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			opened := Open(sealedMsgs[idx], &pk)
			if opened == nil {
				t.Error("Concurrent open failed")
			}
		}(i)
	}

	wg.Wait()
}

// TestThreadSafetyConcurrentExtract tests parallel extract operations
func TestThreadSafetyConcurrentExtract(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	msg := []byte("test message")
	sealed, err := dil.Seal(msg)
	if err != nil {
		t.Fatalf("Failed to seal: %v", err)
	}

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			sig := ExtractSignature(sealed)
			if sig == nil || len(sig) != CRYPTO_BYTES {
				t.Error("ExtractSignature failed")
			}
		}()

		go func() {
			defer wg.Done()
			extractedMsg := ExtractMessage(sealed)
			if extractedMsg == nil {
				t.Error("ExtractMessage failed")
			}
		}()
	}

	wg.Wait()
}

// TestThreadSafetySameInstanceSign tests signing from same instance
func TestThreadSafetySameInstanceSign(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	pk := dil.GetPK()

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			msg := []byte("message")

			sig, err := dil.Sign(msg)
			if err != nil {
				t.Errorf("Sign failed: %v", err)
				return
			}

			if !Verify(msg, sig, &pk) {
				t.Error("Verification failed")
			}
		}(i)
	}

	wg.Wait()
}

// TestThreadSafetyConcurrentSignWithSecretKey tests SignWithSecretKey in parallel
func TestThreadSafetyConcurrentSignWithSecretKey(t *testing.T) {
	dil, err := New()
	if err != nil {
		t.Fatalf("Failed to create Dilithium: %v", err)
	}

	sk := dil.GetSK()
	pk := dil.GetPK()

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			msg := []byte("message")

			sig, err := SignWithSecretKey(msg, &sk)
			if err != nil {
				t.Errorf("SignWithSecretKey failed: %v", err)
				return
			}

			if !Verify(msg, sig, &pk) {
				t.Error("Verification failed")
			}
		}(i)
	}

	wg.Wait()
}
