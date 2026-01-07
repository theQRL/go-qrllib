// Package ml_dsa_87 provides a wallet implementation for ML-DSA-87 signatures
// on the QRL blockchain.
//
// This package wraps the low-level [github.com/theQRL/go-qrllib/crypto/ml_dsa_87]
// package and provides:
//
//   - QRL address generation with proper descriptor formatting
//   - Hardcoded "ZOND" context for QRL blockchain domain separation
//   - Seed management and mnemonic conversion
//   - Signature verification with address validation
//
// # Context Handling
//
// The underlying ML-DSA-87 algorithm requires a context parameter for FIPS 204
// compliance. This wallet package hardcodes the context as "ZOND" (the QRL
// blockchain identifier), so callers don't need to specify it:
//
//	// Wallet layer - no context needed
//	wallet, _ := ml_dsa_87.NewWallet()
//	signature, _ := wallet.Sign(message)  // Uses "ZOND" context internally
//
//	// Crypto layer - context required
//	signer, _ := crypto_ml_dsa_87.New()
//	signature, _ := signer.Sign([]byte("ZOND"), message)
//
// # Seed Derivation
//
// The wallet uses a 48-byte common seed that is hashed with SHA-256 to produce
// the 32-byte seed for ML-DSA-87 key generation:
//
//	Common Seed (48 bytes) → SHA-256 → ML-DSA-87 Seed (32 bytes) → Keypair
//
// # Address Format
//
// QRL addresses are generated from the public key with a descriptor prefix:
//
//	Address = "Q" + hex(Descriptor + SHA256(SHA256(Descriptor + PK)))
//
// # Example Usage
//
//	// Create a new wallet
//	wallet, err := ml_dsa_87.NewWallet()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Get the QRL address
//	address := wallet.GetAddress()
//	fmt.Println("Address:", address)
//
//	// Sign a message
//	message := []byte("transaction data")
//	signature, err := wallet.Sign(message)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify a signature
//	pk := wallet.GetPK()
//	desc := wallet.GetDescriptorBytes()
//	valid := ml_dsa_87.Verify(message, signature[:], &pk, desc)
//
// # Thread Safety
//
// A Wallet instance has the same thread safety characteristics as the underlying
// MLDSA87 type: safe for concurrent reads, but Sign should not be called
// concurrently on the same instance.
package ml_dsa_87
