// mldsa87_verify.go - Verify pq-crystals ML-DSA-87 signature with go-qrllib
package main

import (
	"fmt"
	"os"

	"github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
)

func main() {
	pkBytes, _ := os.ReadFile("/tmp/ref_mldsa_pk.bin")
	sigBytes, _ := os.ReadFile("/tmp/ref_mldsa_sig.bin")
	msgBytes, _ := os.ReadFile("/tmp/ref_mldsa_msg.bin")
	ctxBytes, _ := os.ReadFile("/tmp/ref_mldsa_ctx.bin")

	if len(pkBytes) != ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES {
		fmt.Fprintf(os.Stderr, "PK size mismatch: got %d, expected %d\n",
			len(pkBytes), ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES)
		os.Exit(1)
	}
	if len(sigBytes) != ml_dsa_87.CRYPTO_BYTES {
		fmt.Fprintf(os.Stderr, "Sig size mismatch: got %d, expected %d\n",
			len(sigBytes), ml_dsa_87.CRYPTO_BYTES)
		os.Exit(1)
	}

	var pk [ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES]uint8
	var sig [ml_dsa_87.CRYPTO_BYTES]uint8
	copy(pk[:], pkBytes)
	copy(sig[:], sigBytes)

	valid := ml_dsa_87.Verify(ctxBytes, msgBytes, sig, &pk)

	fmt.Printf("go-qrllib ML-DSA-87 verifier:\n")
	fmt.Printf("  PK size:  %d bytes\n", len(pkBytes))
	fmt.Printf("  Sig size: %d bytes\n", len(sigBytes))
	fmt.Printf("  Context:  %s\n", string(ctxBytes))
	fmt.Printf("  Verification: %s\n", map[bool]string{true: "PASSED", false: "FAILED"}[valid])

	if !valid {
		os.Exit(1)
	}
}
