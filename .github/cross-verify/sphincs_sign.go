// sphincs_sign.go - Generate SPHINCS+ signature for cross-verification
package main

import (
	"fmt"
	"os"

	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s"
)

func main() {
	// Deterministic seed for reproducibility (96 bytes = 3 * SPX_N)
	var seed [sphincsplus_256s.CRYPTO_SEEDBYTES]byte
	for i := range seed {
		seed[i] = byte(i)
	}

	s, err := sphincsplus_256s.NewSphincsPlus256sFromSeed(seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	pk := s.GetPK()
	msg := []byte("SPHINCS+ cross-implementation verification")

	sig, err := s.Sign(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign error: %v\n", err)
		os.Exit(1)
	}

	// Self-verify
	if !sphincsplus_256s.Verify(msg, sig, &pk) {
		fmt.Fprintln(os.Stderr, "Self-verification failed!")
		os.Exit(1)
	}

	// Write files
	os.WriteFile("/tmp/sphincs_pk.bin", pk[:], 0644)
	os.WriteFile("/tmp/sphincs_sig.bin", sig[:], 0644)
	os.WriteFile("/tmp/sphincs_msg.bin", msg, 0644)
	os.WriteFile("/tmp/sphincs_seed.bin", seed[:], 0644)

	fmt.Printf("go-qrllib SPHINCS+ SHAKE-256s-robust:\n")
	fmt.Printf("  PK size:   %d bytes\n", len(pk))
	fmt.Printf("  SK size:   %d bytes\n", sphincsplus_256s.CRYPTO_SECRETKEYBYTES)
	fmt.Printf("  Sig size:  %d bytes\n", len(sig))
	fmt.Printf("  Seed size: %d bytes\n", len(seed))
	fmt.Printf("  Self-verify: PASSED\n")
}
