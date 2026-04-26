package dilithium_test

import (
	"fmt"

	"github.com/theQRL/go-qrllib/crypto/dilithium"
)

// Example demonstrates basic Dilithium signature operations.
func Example() {
	// Create a new Dilithium instance with random seed
	d, err := dilithium.New()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer d.Zeroize() // Clear sensitive key material when done

	// Sign a message
	message := []byte("Hello, post-quantum world!")
	signature, err := d.Sign(message)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Verify the signature
	pk := d.GetPK()
	valid := dilithium.Verify(message, signature, &pk)
	fmt.Println("Signature valid:", valid)
	// Output: Signature valid: true
}

// ExampleNew demonstrates creating a Dilithium instance.
func ExampleNew() {
	// Create with random seed
	d, err := dilithium.New()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer d.Zeroize()

	fmt.Println("Public key size:", len(d.GetPK()))
	// Output: Public key size: 2592
}

// ExampleNewDilithiumFromSeed demonstrates deterministic key generation.
func ExampleNewDilithiumFromSeed() {
	// Create from a specific seed for reproducible keys
	var seed [dilithium.SEED_BYTES]uint8
	copy(seed[:], []byte("my-32-byte-seed-for-testing!"))

	d, err := dilithium.NewDilithiumFromSeed(seed)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer d.Zeroize()

	// Same seed always produces same keys
	pk := d.GetPK()
	fmt.Println("Public key generated:", len(pk) == dilithium.CRYPTO_PUBLIC_KEY_BYTES)
	// Output: Public key generated: true
}

// ExampleDilithium_SignAttached demonstrates the attached-signature
// variant: the returned byte string is `signature || message`. There is
// no confidentiality — the message bytes are embedded in the result in
// the clear.
func ExampleDilithium_SignAttached() {
	d, _ := dilithium.New()
	defer d.Zeroize()

	message := []byte("example transaction payload")

	// SignAttached returns signature || message in a single buffer.
	signed, err := d.SignAttached(message)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Printf("Signed length: %d (signature: %d + message: %d)\n",
		len(signed), dilithium.CRYPTO_BYTES, len(message))
	// Output: Signed length: 4622 (signature: 4595 + message: 27)
}

// ExampleOpen demonstrates verifying an attached-signature byte string
// and recovering the plaintext message.
func ExampleOpen() {
	d, _ := dilithium.New()
	defer d.Zeroize()

	original := []byte("example transaction payload")
	signed, _ := d.SignAttached(original)

	// Open verifies and returns the recovered message
	pk := d.GetPK()
	message := dilithium.Open(signed, &pk)
	if message == nil {
		fmt.Println("Verification failed")
		return
	}

	fmt.Println("Recovered:", string(message))
	// Output: Recovered: example transaction payload
}

// ExampleVerify demonstrates signature verification.
func ExampleVerify() {
	d, _ := dilithium.New()
	defer d.Zeroize()

	message := []byte("verify me")
	signature, _ := d.Sign(message)

	pk := d.GetPK()

	// Verify returns true if signature is valid
	valid := dilithium.Verify(message, signature, &pk)
	fmt.Println("Valid signature:", valid)

	// Tampered message fails verification
	message[0] ^= 0xFF
	valid = dilithium.Verify(message, signature, &pk)
	fmt.Println("After tampering:", valid)
	// Output:
	// Valid signature: true
	// After tampering: false
}
