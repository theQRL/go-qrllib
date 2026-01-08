// Package dilithium implements the CRYSTALS-Dilithium digital signature algorithm.
//
// Dilithium is a lattice-based signature scheme that was a finalist in the
// NIST Post-Quantum Cryptography standardization process. This implementation
// corresponds to the pre-FIPS version of the algorithm.
//
// # Recommendation
//
// For new applications, prefer [github.com/theQRL/go-qrllib/crypto/ml_dsa_87]
// which implements the standardized FIPS 204 version (ML-DSA-87).
//
// # Security Level
//
// This implementation provides NIST Level 5 security (equivalent to AES-256),
// based on the hardness of the Module Learning With Errors (MLWE) problem.
//
// # Key Sizes
//
//   - Public Key:  2,592 bytes (CRYPTO_PUBLIC_KEY_BYTES)
//   - Secret Key:  4,896 bytes (CRYPTO_SECRET_KEY_BYTES)
//   - Signature:   4,595 bytes (CRYPTO_BYTES)
//   - Seed:        32 bytes (SEED_BYTES)
//
// # Thread Safety
//
// A Dilithium instance is safe for concurrent reads (GetPK, GetSK, GetSeed),
// but Sign and Seal should not be called concurrently on the same instance.
// The package-level Verify function is safe for concurrent use.
// The SignWithSecretKey function is safe for concurrent use with different keys.
//
// # Example Usage
//
//	// Generate a new keypair
//	d, err := dilithium.New()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer d.Zeroize() // Clear sensitive data when done
//
//	// Sign a message
//	message := []byte("Hello, World!")
//	signature, err := d.Sign(message)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify the signature
//	pk := d.GetPK()
//	valid := dilithium.Verify(message, signature, &pk)
//
// # Differences from ML-DSA-87
//
// Unlike ML-DSA-87, Dilithium does not have a context parameter for domain
// separation. The API is simpler but provides less flexibility for application-
// specific customization. ML-DSA-87 follows FIPS 204 which mandates context
// support.
package dilithium
