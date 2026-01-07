// Package sphincsplus_256s implements the SPHINCS+-256s digital signature algorithm
// as specified in FIPS 205 (Stateless Hash-Based Digital Signature Standard).
//
// SPHINCS+ is a stateless hash-based signature scheme that provides conservative
// post-quantum security based solely on the security of hash functions, without
// relying on lattice assumptions.
//
// # Security Properties
//
//   - Post-quantum secure based on hash function security
//   - Stateless: no state management required (unlike XMSS)
//   - Conservative security assumptions
//   - NIST Level 5 security (equivalent to AES-256)
//
// # Trade-offs
//
// SPHINCS+-256s has larger signatures than lattice-based schemes but provides
// security based on more conservative assumptions:
//
//   - Public Key:  64 bytes (SPX_PK_BYTES)
//   - Secret Key:  128 bytes (SPX_SK_BYTES)
//   - Signature:   29,792 bytes (SPX_BYTES)
//   - Seed:        96 bytes (SPX_SEED_BYTES)
//
// # When to Use SPHINCS+
//
// Choose SPHINCS+ when:
//   - You want maximum confidence in post-quantum security
//   - You don't fully trust lattice-based assumptions
//   - Signature size is not a critical constraint
//   - You need a stateless scheme (no index management)
//
// # Thread Safety
//
// A SphincsPlus256s instance is safe for concurrent reads (GetPK, GetSK, GetSeed),
// but Sign and Seal should not be called concurrently on the same instance.
// The package-level Verify and Open functions are safe for concurrent use.
//
// # Randomized vs Deterministic Signing
//
// By default, SPHINCS+ uses randomized signing which provides additional
// protection against fault attacks. Deterministic signing can be enabled
// for reproducibility requirements.
//
// # Example Usage
//
//	// Generate a new keypair
//	s, err := sphincsplus_256s.New()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer s.Zeroize() // Clear sensitive data when done
//
//	// Sign a message
//	message := []byte("Hello, World!")
//	signature, err := s.Sign(message)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify the signature
//	pk := s.GetPK()
//	valid := sphincsplus_256s.Verify(message, signature, &pk)
package sphincsplus_256s
