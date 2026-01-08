package xmss_test

import (
	"fmt"

	"github.com/theQRL/go-qrllib/crypto/xmss"
)

// Example demonstrates basic XMSS signature operations.
//
// CRITICAL: XMSS is a stateful signature scheme. Each signature uses a unique
// index that MUST NEVER be reused. See the package documentation for safe usage.
func Example() {
	// Create a 48-byte seed
	seed := make([]byte, 48)
	copy(seed, []byte("example-seed-for-xmss-demo-purposes!"))

	// Initialize tree with height 4 (allows 2^4 = 16 signatures)
	tree, _ := xmss.InitializeTree(4, xmss.SHAKE_256, seed)
	defer tree.Zeroize() // Clear sensitive data when done

	fmt.Println("Initial index:", tree.GetIndex())
	fmt.Println("Max signatures:", 1<<tree.GetHeight())

	// Sign a message
	message := []byte("Hello, XMSS!")
	signature, err := tree.Sign(message)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// CRITICAL: Persist index BEFORE using the signature
	// if err := saveIndex(tree.GetIndex()); err != nil {
	//     // DO NOT use the signature!
	// }

	fmt.Println("Index after signing:", tree.GetIndex())

	// Verify - construct pk from root and pkSeed
	pk := append(tree.GetRoot(), tree.GetPKSeed()...)
	valid := xmss.Verify(xmss.SHAKE_256, message, signature, pk)
	fmt.Println("Signature valid:", valid)
	// Output:
	// Initial index: 0
	// Max signatures: 16
	// Index after signing: 1
	// Signature valid: true
}

// ExampleInitializeTree demonstrates tree creation with different heights.
func ExampleInitializeTree() {
	seed := make([]byte, 48)

	// Height determines the number of available signatures
	// Height 4: 16 signatures (fast generation, for testing)
	// Height 10: 1,024 signatures
	// Height 16: 65,536 signatures
	// Height 20: 1,048,576 signatures

	tree, _ := xmss.InitializeTree(4, xmss.SHAKE_256, seed)
	defer tree.Zeroize()

	fmt.Println("Height:", tree.GetHeight())
	fmt.Println("Uses SHAKE-256:", tree.GetHashFunction() == xmss.SHAKE_256)
	// Output:
	// Height: 4
	// Uses SHAKE-256: true
}

// ExampleXMSS_GetIndex demonstrates index management.
func ExampleXMSS_GetIndex() {
	seed := make([]byte, 48)
	tree, _ := xmss.InitializeTree(4, xmss.SHAKE_256, seed)
	defer tree.Zeroize()

	fmt.Println("Starting index:", tree.GetIndex())

	// Each signature increments the index
	_, _ = tree.Sign([]byte("message 1"))
	fmt.Println("After 1st sign:", tree.GetIndex())

	_, _ = tree.Sign([]byte("message 2"))
	fmt.Println("After 2nd sign:", tree.GetIndex())

	// WARNING: Index exhaustion means no more signatures possible
	// Always monitor remaining signatures: (1 << height) - index
	remaining := (1 << tree.GetHeight()) - int(tree.GetIndex())
	fmt.Println("Remaining signatures:", remaining)
	// Output:
	// Starting index: 0
	// After 1st sign: 1
	// After 2nd sign: 2
	// Remaining signatures: 14
}

// ExampleXMSS_SetIndex demonstrates index recovery (use with caution).
func ExampleXMSS_SetIndex() {
	seed := make([]byte, 48)
	tree, _ := xmss.InitializeTree(4, xmss.SHAKE_256, seed)
	defer tree.Zeroize()

	// Simulate recovering from persisted state
	// WARNING: SetIndex should ONLY be used for recovery
	// NEVER set index to a previously used value!
	persistedIndex := uint32(5)
	err := tree.SetIndex(persistedIndex)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Recovered index:", tree.GetIndex())
	// Output: Recovered index: 5
}

// ExampleVerify demonstrates signature verification.
func ExampleVerify() {
	seed := make([]byte, 48)
	tree, _ := xmss.InitializeTree(4, xmss.SHAKE_256, seed)
	defer tree.Zeroize()

	message := []byte("verify this")
	signature, _ := tree.Sign(message)

	// Construct public key from root and pkSeed
	pk := append(tree.GetRoot(), tree.GetPKSeed()...)

	// Verify is stateless and safe
	valid := xmss.Verify(xmss.SHAKE_256, message, signature, pk)
	fmt.Println("Valid:", valid)

	// Tampered message fails
	message[0] ^= 0xFF
	valid = xmss.Verify(xmss.SHAKE_256, message, signature, pk)
	fmt.Println("Tampered:", valid)
	// Output:
	// Valid: true
	// Tampered: false
}

// ExampleXMSS_Zeroize demonstrates secure cleanup.
func ExampleXMSS_Zeroize() {
	seed := make([]byte, 48)
	tree, _ := xmss.InitializeTree(4, xmss.SHAKE_256, seed)

	// Always zeroize when done to clear secret key from memory
	tree.Zeroize()

	fmt.Println("Zeroized successfully")
	// Output: Zeroized successfully
}
