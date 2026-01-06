package sphincsplus_256s

import (
	"sync"
	"testing"

	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

// Thread safety tests for SPHINCS+ (TST-006)
// Run with: go test -race ./crypto/sphincsplus_256s/...
//
// These tests verify that concurrent operations don't cause data races.
// Note: SPHINCS+ tests are slower due to the algorithm's complexity.

// TestThreadSafetyConcurrentVerify tests parallel verification with shared public key
func TestThreadSafetyConcurrentVerify(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	msg := []byte("test message for concurrent verification")

	sig, err := spx.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	pk := spx.GetPK()

	// Run concurrent verifications (fewer than other algorithms due to SPHINCS+ performance)
	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			if !Verify(msg, sig, &pk) {
				errors <- nil
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

// TestThreadSafetySeparateInstances tests parallel signing with separate instances
func TestThreadSafetySeparateInstances(t *testing.T) {
	const numGoroutines = 3 // Very few due to SPHINCS+ performance
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan string, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			// Each goroutine creates its own instance
			spx, err := New()
			if err != nil {
				errors <- "Failed to create instance"
				return
			}

			msg := []byte("test message")

			sig, err := spx.Sign(msg)
			if err != nil {
				errors <- "Failed to sign"
				return
			}

			pk := spx.GetPK()
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

// TestThreadSafetyConcurrentSealOpen tests parallel seal/open operations
func TestThreadSafetyConcurrentSealOpen(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	pk := spx.GetPK()

	// Pre-create some sealed messages
	const numSealed = 3
	sealedMsgs := make([][]byte, numSealed)
	for i := 0; i < numSealed; i++ {
		msg := []byte("message " + string(rune(i)))
		sealed, err := spx.Seal(msg)
		if err != nil {
			t.Fatalf("Failed to seal: %v", err)
		}
		sealedMsgs[i] = sealed
	}

	// Concurrent opening
	var wg sync.WaitGroup
	wg.Add(numSealed * 3) // Open each sealed message 3 times concurrently

	for i := 0; i < numSealed; i++ {
		for j := 0; j < 3; j++ {
			go func(idx int) {
				defer wg.Done()
				opened := Open(sealedMsgs[idx], &pk)
				if opened == nil {
					t.Error("Concurrent open failed")
				}
			}(i)
		}
	}

	wg.Wait()
}

// TestThreadSafetyConcurrentExtract tests parallel extract operations
func TestThreadSafetyConcurrentExtract(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	msg := []byte("test message")
	sealed, err := spx.Seal(msg)
	if err != nil {
		t.Fatalf("Failed to seal: %v", err)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			sig := ExtractSignature(sealed)
			if sig == nil || len(sig) != params.SPX_BYTES {
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

// TestThreadSafetyConcurrentKeyGenFromSeed tests parallel key generation from same seed
func TestThreadSafetyConcurrentKeyGenFromSeed(t *testing.T) {
	var seed [CRYPTO_SEEDBYTES]uint8
	for i := range seed {
		seed[i] = byte(i)
	}

	const numGoroutines = 5
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	results := make(chan [params.SPX_PK_BYTES]uint8, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			spx, err := NewSphincsPlus256sFromSeed(seed)
			if err != nil {
				t.Errorf("Failed to create from seed: %v", err)
				return
			}
			results <- spx.GetPK()
		}()
	}

	wg.Wait()
	close(results)

	// All should produce same public key (deterministic)
	var firstPK [params.SPX_PK_BYTES]uint8
	first := true
	for pk := range results {
		if first {
			firstPK = pk
			first = false
		} else {
			if pk != firstPK {
				t.Error("Deterministic key generation produced different keys")
			}
		}
	}
}

// TestThreadSafetySameInstanceSign tests signing from same instance (stateless, should be safe)
func TestThreadSafetySameInstanceSign(t *testing.T) {
	spx, err := New()
	if err != nil {
		t.Fatalf("Failed to create SphincsPlus256s: %v", err)
	}

	pk := spx.GetPK()

	// SPHINCS+ is stateless, so concurrent signing should be safe
	// However, it uses randomized signing by default which requires random generation
	const numGoroutines = 3 // Few due to performance
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			msg := []byte("message")

			sig, err := spx.Sign(msg)
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
