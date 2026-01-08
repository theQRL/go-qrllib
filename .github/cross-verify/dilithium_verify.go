// dilithium_verify.go - Verify pq-crystals signature with go-qrllib
package main

import (
	"fmt"
	"os"

	"github.com/theQRL/go-qrllib/crypto/dilithium"
)

func main() {
	pkBytes, _ := os.ReadFile("/tmp/ref_dilithium_pk.bin")
	sigBytes, _ := os.ReadFile("/tmp/ref_dilithium_sig.bin")
	msgBytes, _ := os.ReadFile("/tmp/ref_dilithium_msg.bin")

	if len(pkBytes) != dilithium.CRYPTO_PUBLIC_KEY_BYTES {
		fmt.Fprintf(os.Stderr, "PK size mismatch: got %d, expected %d\n",
			len(pkBytes), dilithium.CRYPTO_PUBLIC_KEY_BYTES)
		os.Exit(1)
	}
	if len(sigBytes) != dilithium.CRYPTO_BYTES {
		fmt.Fprintf(os.Stderr, "Sig size mismatch: got %d, expected %d\n",
			len(sigBytes), dilithium.CRYPTO_BYTES)
		os.Exit(1)
	}

	var pk [dilithium.CRYPTO_PUBLIC_KEY_BYTES]uint8
	var sig [dilithium.CRYPTO_BYTES]uint8
	copy(pk[:], pkBytes)
	copy(sig[:], sigBytes)

	valid := dilithium.Verify(msgBytes, sig, &pk)

	fmt.Printf("go-qrllib Dilithium5 verifier:\n")
	fmt.Printf("  PK size:  %d bytes\n", len(pkBytes))
	fmt.Printf("  Sig size: %d bytes\n", len(sigBytes))
	fmt.Printf("  Verification: %s\n", map[bool]string{true: "PASSED", false: "FAILED"}[valid])

	if !valid {
		os.Exit(1)
	}
}
