// mlkem1024_crossverify.go - Cross-verify go-qrllib ML-KEM-1024 against the Go
// standard library's FIPS-validated crypto/mlkem implementation.
//
// Unlike the signature cross-verify programs (which interoperate with the
// pq-crystals C reference), ML-KEM-1024's reference here is Go's stdlib
// crypto/mlkem — an independent, FIPS 203-validated implementation. The check
// is pure Go and runs in-process, so there is no reference clone/compile step.
//
// It verifies three interop properties over many fresh keys:
//  1. the same seed yields an identical encapsulation key in both impls;
//  2. a stdlib-produced ciphertext decapsulates to the same shared secret
//     under go-qrllib; and
//  3. a go-qrllib-produced ciphertext decapsulates to the same shared secret
//     under the stdlib.
package main

import (
	"bytes"
	"crypto/mlkem"
	"fmt"
	"os"

	qrlmlkem "github.com/theQRL/go-qrllib/crypto/mlkem1024"
)

const iterations = 1000

func main() {
	for i := 0; i < iterations; i++ {
		if err := crossVerifyOnce(); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL (iteration %d): %v\n", i, err)
			os.Exit(1)
		}
	}
	fmt.Printf("go-qrllib ML-KEM-1024 <-> Go stdlib crypto/mlkem: %d iterations PASSED\n", iterations)
	fmt.Println("  - identical seed -> identical encapsulation key")
	fmt.Println("  - stdlib encapsulate -> go-qrllib decapsulate (shared secrets agree)")
	fmt.Println("  - go-qrllib encapsulate -> stdlib decapsulate (shared secrets agree)")
}

func crossVerifyOnce() error {
	// go-qrllib generates a key; the stdlib must derive the same encapsulation
	// key from its 64-byte seed (d || z).
	qdk, err := qrlmlkem.GenerateKey()
	if err != nil {
		return fmt.Errorf("go-qrllib GenerateKey: %w", err)
	}
	sdk, err := mlkem.NewDecapsulationKey1024(qdk.Bytes())
	if err != nil {
		return fmt.Errorf("stdlib NewDecapsulationKey1024(seed): %w", err)
	}
	if !bytes.Equal(qdk.EncapsulationKey().Bytes(), sdk.EncapsulationKey().Bytes()) {
		return fmt.Errorf("encapsulation-key mismatch for identical seed")
	}

	// stdlib encapsulates; go-qrllib must recover the same shared secret.
	ssStd, ctStd := sdk.EncapsulationKey().Encapsulate()
	ssQrl, err := qdk.Decapsulate(ctStd)
	if err != nil {
		return fmt.Errorf("go-qrllib Decapsulate(stdlib ciphertext): %w", err)
	}
	if !bytes.Equal(ssStd, ssQrl) {
		return fmt.Errorf("stdlib->go-qrllib shared-secret mismatch")
	}

	// go-qrllib encapsulates; the stdlib must recover the same shared secret.
	ssQrl2, ctQrl, err := qdk.EncapsulationKey().Encapsulate()
	if err != nil {
		return fmt.Errorf("go-qrllib Encapsulate: %w", err)
	}
	ssStd2, err := sdk.Decapsulate(ctQrl)
	if err != nil {
		return fmt.Errorf("stdlib Decapsulate(go-qrllib ciphertext): %w", err)
	}
	if !bytes.Equal(ssQrl2, ssStd2) {
		return fmt.Errorf("go-qrllib->stdlib shared-secret mismatch")
	}

	return nil
}
