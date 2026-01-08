package xmss

import (
	"sync"
	"testing"
)

// Thread safety tests for XMSS (TST-006)
// Run with: go test -race ./crypto/xmss/...
//
// IMPORTANT: XMSS is a STATEFUL signature scheme. The index is incremented
// on each signature. Concurrent signing from the same instance is NOT safe
// and will cause index reuse (security vulnerability) or data races.
//
// These tests verify:
// 1. Concurrent verification is safe (read-only operations)
// 2. Concurrent signing with SEPARATE instances is safe
// 3. Single-threaded signing with shared instance works correctly
// 4. The dangers of concurrent access to a shared instance

// TestThreadSafetyConcurrentVerify tests parallel verification with shared public key
func TestThreadSafetyConcurrentVerify(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	msg := []byte("test message for concurrent verification")

	sig, err := xmss.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
	hashFunc := xmss.GetHashFunction()

	// Run many concurrent verifications (should be safe - read-only)
	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			if !Verify(hashFunc, msg, sig, pk) {
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
	const numGoroutines = 10 // Fewer due to XMSS key generation cost
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errors := make(chan string, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()

			// Each goroutine creates its own instance - this is safe
			seed := make([]byte, 48)
			seed[0] = byte(idx) // Different seed for each
			xmss, _ := InitializeTree(4, SHAKE_128, seed)

			msg := []byte("test message")

			sig, err := xmss.Sign(msg)
			if err != nil {
				errors <- "Failed to sign"
				return
			}

			pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
			if !Verify(xmss.GetHashFunction(), msg, sig, pk) {
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

// TestThreadSafetySequentialSigning tests that sequential signing works correctly
func TestThreadSafetySequentialSigning(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
	hashFunc := xmss.GetHashFunction()

	// Sign multiple messages sequentially - this is the safe way
	const numSignatures = 10
	signatures := make([][]byte, numSignatures)
	messages := make([][]byte, numSignatures)

	for i := 0; i < numSignatures; i++ {
		messages[i] = []byte("message " + string(rune(i)))
		sig, err := xmss.Sign(messages[i])
		if err != nil {
			t.Fatalf("Failed to sign message %d: %v", i, err)
		}
		signatures[i] = sig

		// Verify index incremented
		expectedIndex := uint32(i + 1)
		if xmss.GetIndex() != expectedIndex {
			t.Errorf("Index mismatch: expected %d, got %d", expectedIndex, xmss.GetIndex())
		}
	}

	// Verify all signatures
	for i := 0; i < numSignatures; i++ {
		if !Verify(hashFunc, messages[i], signatures[i], pk) {
			t.Errorf("Verification failed for message %d", i)
		}
	}
}

// TestThreadSafetyConcurrentVerifyDifferentSignatures tests verifying different signatures concurrently
func TestThreadSafetyConcurrentVerifyDifferentSignatures(t *testing.T) {
	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
	hashFunc := xmss.GetHashFunction()

	// Create multiple signatures sequentially
	const numSignatures = 10
	type sigPair struct {
		msg []byte
		sig []byte
	}
	pairs := make([]sigPair, numSignatures)

	for i := 0; i < numSignatures; i++ {
		msg := []byte("message " + string(rune(i)))
		sig, err := xmss.Sign(msg)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}
		pairs[i] = sigPair{msg, sig}
	}

	// Verify all signatures concurrently
	var wg sync.WaitGroup
	wg.Add(numSignatures * 10) // Verify each signature 10 times concurrently

	for i := 0; i < numSignatures; i++ {
		for j := 0; j < 10; j++ {
			go func(idx int) {
				defer wg.Done()
				if !Verify(hashFunc, pairs[idx].msg, pairs[idx].sig, pk) {
					t.Errorf("Concurrent verification failed for signature %d", idx)
				}
			}(i)
		}
	}

	wg.Wait()
}

// TestThreadSafetyConcurrentTreeInit tests parallel tree initialization
func TestThreadSafetyConcurrentTreeInit(t *testing.T) {
	const numGoroutines = 5 // Few due to cost
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	results := make(chan *XMSS, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			seed := make([]byte, 48)
			seed[0] = byte(idx)
			xmss, _ := InitializeTree(4, SHAKE_128, seed)
			results <- xmss
		}(i)
	}

	wg.Wait()
	close(results)

	// Verify all instances are unique
	roots := make(map[string]bool)
	for xmss := range results {
		if xmss == nil {
			continue
		}
		root := string(xmss.GetRoot())
		if roots[root] {
			t.Error("Duplicate root generated")
		}
		roots[root] = true
	}
}

// TestThreadSafetyVerifyWithDifferentHashFuncs tests concurrent verify with different hash functions
func TestThreadSafetyVerifyWithDifferentHashFuncs(t *testing.T) {
	hashFuncs := []HashFunction{SHA2_256, SHAKE_128, SHAKE_256}

	var wg sync.WaitGroup
	wg.Add(len(hashFuncs))

	for _, hf := range hashFuncs {
		go func(hashFunc HashFunction) {
			defer wg.Done()

			seed := make([]byte, 48)
			xmss, _ := InitializeTree(4, hashFunc, seed)

			msg := []byte("test message")
			sig, err := xmss.Sign(msg)
			if err != nil {
				t.Errorf("Failed to sign with %s: %v", hashFunc.String(), err)
				return
			}

			pk := append(xmss.GetRoot(), xmss.GetPKSeed()...)
			if !Verify(hashFunc, msg, sig, pk) {
				t.Errorf("Verification failed with %s", hashFunc.String())
			}
		}(hf)
	}

	wg.Wait()
}

// TestXMSSConcurrentSigningWarning documents that concurrent signing is UNSAFE
// This test is commented out because it would cause a data race, which is expected.
// Uncomment to demonstrate the race condition.
/*
func TestXMSSConcurrentSigningUNSAFE(t *testing.T) {
	t.Skip("This test demonstrates UNSAFE concurrent signing - do not use in production")

	seed := make([]byte, 48)
	xmss, _ := InitializeTree(4, SHAKE_128, seed)

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// WARNING: This is UNSAFE and will cause index reuse!
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			msg := []byte("message")
			_, _ = xmss.Sign(msg) // RACE CONDITION HERE
		}()
	}

	wg.Wait()

	// The index will be unpredictable due to race condition
	t.Logf("Final index: %d (expected: %d)", xmss.GetIndex(), numGoroutines)
}
*/
