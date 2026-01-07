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

	// Sign a message (uses hardcoded "ZOND" context)
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

	// Get the QRL address (Q + hex-encoded descriptor + checksum)
	address := wallet.GetAddressStr()
	fmt.Println("Address length:", len(address))
	// Output: Address length: 41
}

// ExampleNewWalletFromMnemonic demonstrates wallet recovery from mnemonic.
func ExampleNewWalletFromMnemonic() {
	// First create a wallet to get a mnemonic
	wallet, _ := ml_dsa_87.NewWallet()
	mnemonic := wallet.GetMnemonic()

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
	mnemonic := wallet.GetMnemonic()

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
