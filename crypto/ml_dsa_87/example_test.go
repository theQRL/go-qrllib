package ml_dsa_87_test

import (
	"fmt"

	"github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
)

// Example demonstrates basic ML-DSA-87 signature operations.
func Example() {
	// Create a new ML-DSA-87 instance with random seed
	m, err := ml_dsa_87.New()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer m.Zeroize() // Clear sensitive key material when done

	// Sign a message with context (FIPS 204 requirement)
	ctx := []byte("my-application")
	message := []byte("Hello, FIPS 204!")
	signature, err := m.Sign(ctx, message)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Verify the signature
	pk := m.GetPK()
	valid := ml_dsa_87.Verify(ctx, message, signature, &pk)
	fmt.Println("Signature valid:", valid)
	// Output: Signature valid: true
}

// ExampleNew demonstrates creating an ML-DSA-87 instance.
func ExampleNew() {
	// Create with random seed
	m, err := ml_dsa_87.New()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer m.Zeroize()

	fmt.Println("Public key size:", len(m.GetPK()))
	// Output: Public key size: 2592
}

// ExampleNewMLDSA87FromSeed demonstrates deterministic key generation.
func ExampleNewMLDSA87FromSeed() {
	// Create from a specific seed for reproducible keys
	var seed [ml_dsa_87.SEED_BYTES]uint8
	copy(seed[:], []byte("my-32-byte-seed-for-testing!"))

	m, err := ml_dsa_87.NewMLDSA87FromSeed(seed)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer m.Zeroize()

	// Same seed always produces same keys
	pk := m.GetPK()
	fmt.Println("Public key generated:", len(pk) == ml_dsa_87.CRYPTO_PUBLIC_KEY_BYTES)
	// Output: Public key generated: true
}

// ExampleMLDSA87_Sign demonstrates signing with context.
func ExampleMLDSA87_Sign() {
	m, _ := ml_dsa_87.New()
	defer m.Zeroize()

	// FIPS 204 requires a context parameter for domain separation
	// Use empty context if not needed, but consider using application-specific context
	ctx := []byte("ZOND") // QRL blockchain uses "ZOND" as context
	message := []byte("transaction data")

	signature, err := m.Sign(ctx, message)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Signature size:", len(signature))
	// Output: Signature size: 4627
}

// ExampleVerify demonstrates signature verification with context.
func ExampleVerify() {
	m, _ := ml_dsa_87.New()
	defer m.Zeroize()

	ctx := []byte("test-context")
	message := []byte("verify me")
	signature, _ := m.Sign(ctx, message)

	pk := m.GetPK()

	// Verify requires the same context used during signing
	valid := ml_dsa_87.Verify(ctx, message, signature, &pk)
	fmt.Println("Valid signature:", valid)

	// Wrong context fails verification
	wrongCtx := []byte("wrong-context")
	valid = ml_dsa_87.Verify(wrongCtx, message, signature, &pk)
	fmt.Println("Wrong context:", valid)
	// Output:
	// Valid signature: true
	// Wrong context: false
}

// ExampleMLDSA87_Seal demonstrates the Seal operation.
func ExampleMLDSA87_Seal() {
	m, _ := ml_dsa_87.New()
	defer m.Zeroize()

	ctx := []byte("seal-context")
	message := []byte("confidential data")

	// Seal prepends the signature to the message
	sealed, err := m.Seal(ctx, message)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Sealed message is signature || message
	fmt.Printf("Sealed length: %d (signature: %d + message: %d)\n",
		len(sealed), ml_dsa_87.CRYPTO_BYTES, len(message))
	// Output: Sealed length: 4644 (signature: 4627 + message: 17)
}

// ExampleOpen demonstrates verifying and extracting a sealed message.
func ExampleOpen() {
	m, _ := ml_dsa_87.New()
	defer m.Zeroize()

	ctx := []byte("open-context")
	original := []byte("secret message")
	sealed, _ := m.Seal(ctx, original)

	// Open verifies and extracts the message
	pk := m.GetPK()
	message := ml_dsa_87.Open(ctx, sealed, &pk)
	if message == nil {
		fmt.Println("Verification failed")
		return
	}

	fmt.Println("Recovered:", string(message))
	// Output: Recovered: secret message
}
