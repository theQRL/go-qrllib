// xmss_sign.go - Generate XMSS signature for cross-verification
package main

import (
	"fmt"
	"os"

	"github.com/theQRL/go-qrllib/crypto/xmss"
)

func main() {
	// Deterministic seed for reproducibility (48 bytes)
	seed := make([]byte, 48)
	for i := range seed {
		seed[i] = byte(i)
	}

	// Use SHA2_256 and height 10 to match XMSS-SHA2_10_256 OID
	tree, err := xmss.InitializeTree(10, xmss.SHA2_256, seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer tree.Zeroize()

	msg := []byte("XMSS cross-implementation verification")

	sig, err := tree.Sign(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign error: %v\n", err)
		os.Exit(1)
	}

	// Public key is root || pub_seed (64 bytes total)
	pk := append(tree.GetRoot(), tree.GetPKSeed()...)

	// Self-verify
	if !xmss.Verify(xmss.SHA2_256, msg, sig, pk) {
		fmt.Fprintln(os.Stderr, "Self-verification failed!")
		os.Exit(1)
	}

	// Get SK components for reference to reconstruct
	sk := tree.GetSK()
	// SK format: [idx(4) | SK_SEED(32) | SK_PRF(32) | PUB_SEED(32) | root(32)] = 132 bytes
	skSeed := sk[4:36]
	skPrf := sk[36:68]
	pubSeed := sk[68:100]

	// Write files
	os.WriteFile("/tmp/xmss_pk.bin", pk, 0644)
	os.WriteFile("/tmp/xmss_sig.bin", sig, 0644)
	os.WriteFile("/tmp/xmss_msg.bin", msg, 0644)
	os.WriteFile("/tmp/xmss_seed.bin", seed, 0644)
	// Write expanded seed components for reference implementation
	os.WriteFile("/tmp/xmss_sk_seed.bin", skSeed, 0644)
	os.WriteFile("/tmp/xmss_sk_prf.bin", skPrf, 0644)
	os.WriteFile("/tmp/xmss_pub_seed.bin", pubSeed, 0644)

	fmt.Printf("go-qrllib XMSS-SHA2_10_256:\n")
	fmt.Printf("  PK size:   %d bytes\n", len(pk))
	fmt.Printf("  Sig size:  %d bytes\n", len(sig))
	fmt.Printf("  Seed size: %d bytes\n", len(seed))
	fmt.Printf("  Height:    %d\n", tree.GetHeight())
	fmt.Printf("  Index:     %d\n", tree.GetIndex())
	fmt.Printf("  Self-verify: PASSED\n")
}
