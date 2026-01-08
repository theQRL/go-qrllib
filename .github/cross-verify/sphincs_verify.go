// sphincs_verify.go - Verify reference SPHINCS+ signature with go-qrllib
package main

import (
	"fmt"
	"os"

	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s"
	"github.com/theQRL/go-qrllib/crypto/sphincsplus_256s/params"
)

func main() {
	pkBytes, _ := os.ReadFile("/tmp/ref_sphincs_pk.bin")
	sigBytes, _ := os.ReadFile("/tmp/ref_sphincs_sig.bin")
	msgBytes, _ := os.ReadFile("/tmp/ref_sphincs_msg.bin")

	if len(pkBytes) != sphincsplus_256s.CRYPTO_PUBLICKEYBYTES {
		fmt.Fprintf(os.Stderr, "PK size mismatch: got %d, expected %d\n",
			len(pkBytes), sphincsplus_256s.CRYPTO_PUBLICKEYBYTES)
		os.Exit(1)
	}
	if len(sigBytes) != sphincsplus_256s.CRYPTO_BYTES {
		fmt.Fprintf(os.Stderr, "Sig size mismatch: got %d, expected %d\n",
			len(sigBytes), sphincsplus_256s.CRYPTO_BYTES)
		os.Exit(1)
	}

	var pk [params.SPX_PK_BYTES]uint8
	var sig [params.SPX_BYTES]uint8
	copy(pk[:], pkBytes)
	copy(sig[:], sigBytes)

	valid := sphincsplus_256s.Verify(msgBytes, sig, &pk)

	fmt.Printf("go-qrllib SPHINCS+ SHAKE-256s-robust verifier:\n")
	fmt.Printf("  PK size:  %d bytes\n", len(pkBytes))
	fmt.Printf("  Sig size: %d bytes\n", len(sigBytes))
	fmt.Printf("  Verification: %s\n", map[bool]string{true: "PASSED", false: "FAILED"}[valid])

	if !valid {
		os.Exit(1)
	}
}
