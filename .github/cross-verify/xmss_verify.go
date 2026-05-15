// xmss_verify.go - Verify a reference-XMSS signature using go-qrllib's
// crypto/xmss/rfc8391 sub-package.
//
// This file is original go-qrllib code. It pairs with xmss_sign_ref.c
// in this directory, which calls into the xmss-reference library
// (https://github.com/XMSS/xmss-reference, CC0 1.0 Universal).
//
// This is the reverse-direction cross-verify counterpart to
// xmss_verify_ref.c: instead of the reference verifying a go-qrllib
// signature, here go-qrllib (via rfc8391.NewKeyPair and
// rfc8391.Verify) verifies a signature produced by the reference.
//
// The signature alone is not enough — the keypairs must also match
// at the public-key bytes level. So this verifier reads the same
// 96-byte expanded seed the reference used, reconstructs the keypair
// via rfc8391.NewKeyPair, and asserts the resulting root || pub_seed
// matches the reference's pk byte-for-byte BEFORE proceeding to
// signature verification. That establishes the keypair-derivation
// equivalence that was the previous cross-verify gap.

package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/theQRL/go-qrllib/crypto/xmss/rfc8391"
)

const expandedSeedSize = 96

func main() {
	pk, err := os.ReadFile("/tmp/xmss_ref_pk.bin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read xmss_ref_pk.bin: %v\n", err)
		os.Exit(1)
	}
	rfcPK, err := os.ReadFile("/tmp/xmss_ref_pk_rfc.bin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read xmss_ref_pk_rfc.bin: %v\n", err)
		os.Exit(1)
	}
	sig, err := os.ReadFile("/tmp/xmss_ref_sig.bin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read xmss_ref_sig.bin: %v\n", err)
		os.Exit(1)
	}
	msg, err := os.ReadFile("/tmp/xmss_ref_msg.bin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read xmss_ref_msg.bin: %v\n", err)
		os.Exit(1)
	}
	expandedSeedBytes, err := os.ReadFile("/tmp/xmss_ref_expanded_seed.bin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read xmss_ref_expanded_seed.bin: %v\n", err)
		os.Exit(1)
	}
	if len(expandedSeedBytes) != expandedSeedSize {
		fmt.Fprintf(os.Stderr, "expanded seed has %d bytes, want %d\n",
			len(expandedSeedBytes), expandedSeedSize)
		os.Exit(1)
	}
	var expandedSeed [expandedSeedSize]uint8
	copy(expandedSeed[:], expandedSeedBytes)

	// Reconstruct the keypair from the same 96 bytes the reference
	// used. If the keypair-derivation equivalence holds, this go-qrllib
	// tree's pk should match the reference's pk byte-for-byte.
	tree, err := rfc8391.NewKeyPair(rfc8391.XMSS_SHA2_10_256, &expandedSeed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rfc8391.NewKeyPair: %v\n", err)
		os.Exit(1)
	}

	ourPK := append(tree.GetRoot(), tree.GetPKSeed()...)
	if !bytes.Equal(ourPK, pk) {
		fmt.Fprintln(os.Stderr, "Keypair-derivation mismatch:")
		fmt.Fprintf(os.Stderr, "  reference pk: %x\n", pk)
		fmt.Fprintf(os.Stderr, "  go-qrllib pk: %x\n", ourPK)
		os.Exit(1)
	}

	// Verify the reference's signature against the keypair we just
	// reconstructed (via the rfc8391-format public key, exercising
	// the full sub-package surface).
	ok, err := rfc8391.Verify(msg, sig, rfcPK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rfc8391.Verify error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("go-qrllib XMSS-SHA2_10_256 verifier:\n")
	fmt.Printf("  Reference PK (root||pub_seed): %d bytes\n", len(pk))
	fmt.Printf("  Reference PK (RFC layout):     %d bytes\n", len(rfcPK))
	fmt.Printf("  Signature:                     %d bytes\n", len(sig))
	fmt.Printf("  Message:                       %d bytes\n", len(msg))
	fmt.Printf("  Keypair-derivation match:      PASSED\n")
	if ok {
		fmt.Printf("  Signature verification:        PASSED\n")
	} else {
		fmt.Printf("  Signature verification:        FAILED\n")
		os.Exit(1)
	}
}
