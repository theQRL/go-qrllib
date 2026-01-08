// Package sphincsplus_256s provides a wallet implementation for SPHINCS+-256s
// signatures on the QRL blockchain.
//
// This package wraps the low-level [github.com/theQRL/go-qrllib/crypto/sphincsplus_256s]
// package and provides:
//
//   - QRL address generation with proper descriptor formatting
//   - Seed management and mnemonic conversion
//   - Signature verification with address descriptor validation
//
// # Seed Derivation
//
// The wallet uses a 48-byte common seed that is expanded with SHAKE-256 to
// produce the 96-byte seed for SPHINCS+ key generation:
//
//	Common Seed (48 bytes) → SHAKE-256 → SPHINCS+ Seed (96 bytes) → Keypair
//
// This differs from ML-DSA-87 which uses SHA-256 for seed derivation.
//
// # Address Format
//
// QRL addresses are generated from the public key with a descriptor prefix using SHAKE256:
//
//	Address = "Q" + hex(SHAKE256(Descriptor || PK)[:20])
//
// This produces a standard 20-byte address (plus 'Q' prefix).
//
// # Signature Size
//
// SPHINCS+-256s has large signatures (29,792 bytes) compared to lattice-based
// schemes. This is the trade-off for hash-based security assumptions.
//
// # Example Usage
//
//	// Create a new wallet
//	wallet, err := sphincsplus_256s.NewWallet()
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
//	valid := sphincsplus_256s.Verify(message, signature[:], &pk, desc)
//
// # Thread Safety
//
// A Wallet instance has the same thread safety characteristics as the underlying
// SphincsPlus256s type: safe for concurrent reads, but Sign should not be called
// concurrently on the same instance.
package sphincsplus_256s
