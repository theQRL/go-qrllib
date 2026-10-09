package falcon1024_test

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	. "github.com/theQRL/go-qrllib/crypto/falcon1024"
)

// TestConcurrentSigningOneKey exercises the documented promise that one
// *PrivateKey may serve concurrent Sign and SignDetached calls: several
// goroutines sign distinct messages with the same key and every result must
// verify. The CI race run covers the data-race half of the promise.
func TestConcurrentSigningOneKey(t *testing.T) {
	pub, priv, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Zeroize()

	const workers, perWorker = 8, 4
	var wg sync.WaitGroup
	problems := make(chan error, workers*perWorker*2)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWorker {
				message := []byte(fmt.Sprintf("worker %d message %d", w, i))
				sig, err := SignDetached(nil, priv, message)
				if err != nil {
					problems <- fmt.Errorf("worker %d: SignDetached: %w", w, err)
				} else if !Verify(pub, message, sig) {
					problems <- fmt.Errorf("worker %d: detached signature %d does not verify", w, i)
				}
				signed, err := Sign(nil, priv, message)
				if err != nil {
					problems <- fmt.Errorf("worker %d: Sign: %w", w, err)
					continue
				}
				if opened, err := Open(pub, signed); err != nil || !bytes.Equal(opened, message) {
					problems <- fmt.Errorf("worker %d: Open of signed message %d: %v", w, i, err)
				}
			}
		}()
	}
	wg.Wait()
	close(problems)
	for err := range problems {
		t.Error(err)
	}
}
