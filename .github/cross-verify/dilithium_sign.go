// dilithium_sign.go - Generate Dilithium signature for cross-verification
package main

import (
	"fmt"
	"os"

	"github.com/theQRL/go-qrllib/crypto/dilithium"
)

func main() {
	// Deterministic seed for reproducibility
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}

	d, err := dilithium.NewDilithiumFromSeed(seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	pk := d.GetPK()
	msg := []byte("Dilithium cross-implementation verification")

	sig, err := d.Sign(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign error: %v\n", err)
		os.Exit(1)
	}

	// Self-verify
	if !dilithium.Verify(msg, sig, &pk) {
		fmt.Fprintln(os.Stderr, "Self-verification failed!")
		os.Exit(1)
	}

	// Write files
	os.WriteFile("/tmp/dilithium_pk.bin", pk[:], 0644)
	os.WriteFile("/tmp/dilithium_sig.bin", sig[:], 0644)
	os.WriteFile("/tmp/dilithium_msg.bin", msg, 0644)

	fmt.Printf("go-qrllib Dilithium5:\n")
	fmt.Printf("  PK size:  %d bytes\n", len(pk))
	fmt.Printf("  Sig size: %d bytes\n", len(sig))
	fmt.Printf("  Self-verify: PASSED\n")
}
