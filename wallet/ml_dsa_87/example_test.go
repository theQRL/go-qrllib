package ml_dsa_87_test

import (
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/ml_dsa_87"
)

// Example demonstrates basic ML-DSA-87 wallet operations.
func Example() {
	// Create a new wallet with random seed
	wallet, err := ml_dsa_87.NewWallet()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Get the QRL address as string
	address := wallet.GetAddressStr()
	fmt.Println("Address starts with Q:", address[0] == 'Q')

	// Sign a message (context is derived from the wallet's descriptor)
	message := []byte("transaction data")
	signature, err := wallet.Sign(message)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Verify the signature
	pk := wallet.GetPK()
	desc := wallet.GetDescriptor().ToDescriptor()
	valid := ml_dsa_87.Verify(message, signature[:], &pk, desc)
	fmt.Println("Signature valid:", valid)
	// Output:
	// Address starts with Q: true
	// Signature valid: true
}

// ExampleNewWallet demonstrates creating a new wallet.
func ExampleNewWallet() {
	wallet, err := ml_dsa_87.NewWallet()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Get the QRL address ("Q" prefix + hex-encoded 64-byte address)
	address := wallet.GetAddressStr()
	fmt.Println("Address length:", len(address))
	// Output: Address length: 129
}

// ExampleNewWalletFromMnemonic demonstrates wallet recovery from mnemonic.
func ExampleNewWalletFromMnemonic() {
	// First create a wallet to get a mnemonic
	wallet, _ := ml_dsa_87.NewWallet()
	mnemonic, _ := wallet.GetMnemonic()

	// Recover wallet from mnemonic
	recovered, err := ml_dsa_87.NewWalletFromMnemonic(mnemonic)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Addresses match
	fmt.Println("Addresses match:", wallet.GetAddressStr() == recovered.GetAddressStr())
	// Output: Addresses match: true
}

// ExampleWallet_GetMnemonic demonstrates mnemonic backup.
func ExampleWallet_GetMnemonic() {
	wallet, _ := ml_dsa_87.NewWallet()

	// Get the mnemonic phrase for backup
	mnemonic, _ := wallet.GetMnemonic()

	// Mnemonic is a space-separated string of words
	fmt.Println("Mnemonic is a string:", len(mnemonic) > 0)
	// Output: Mnemonic is a string: true
}

// ExampleVerify demonstrates signature verification.
func ExampleVerify() {
	wallet, _ := ml_dsa_87.NewWallet()

	message := []byte("test message")
	signature, _ := wallet.Sign(message)

	pk := wallet.GetPK()
	desc := wallet.GetDescriptor().ToDescriptor()

	// Verify requires public key and descriptor
	valid := ml_dsa_87.Verify(message, signature[:], &pk, desc)
	fmt.Println("Valid:", valid)

	// Tampered message fails
	message[0] ^= 0xFF
	valid = ml_dsa_87.Verify(message, signature[:], &pk, desc)
	fmt.Println("After tampering:", valid)
	// Output:
	// Valid: true
	// After tampering: false
}

// ExampleWallet_SignDeterministic shows that deterministic signing is
// reproducible and verifies like a hedged signature.
func ExampleWallet_SignDeterministic() {
	// Deterministic signing: same wallet + same message → identical bytes.
	// Restoring from a fixed extended seed makes this example reproducible.
	wallet, _ := ml_dsa_87.NewWalletFromHexExtendedSeed(
		"010000f29f58aff0b00de2844f7e20bd9eeaacc379150043beeb328335817512b29fbb7184da84a092f842b2a06d72a24a5d28")

	message := []byte("ML-DSA-87 test message for signing")
	sig1, _ := wallet.SignDeterministic(message)
	sig2, _ := wallet.SignDeterministic(message)
	fmt.Println("Identical:", sig1 == sig2)

	// Deterministic signatures verify exactly like hedged ones.
	pk := wallet.GetPK()
	desc := wallet.GetDescriptor().ToDescriptor()
	fmt.Println("Valid:", ml_dsa_87.Verify(message, sig1[:], &pk, desc))

	// The bytes are a stable function of (seed, descriptor, message).
	fmt.Printf("Prefix: %x\n", sig1[:8])
	// Output:
	// Identical: true
	// Valid: true
	// Prefix: c9b6a7ff67fe8017
}
