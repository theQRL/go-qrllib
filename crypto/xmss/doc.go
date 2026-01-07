// Package xmss implements the XMSS (eXtended Merkle Signature Scheme) as
// specified in RFC 8391.
//
// # CRITICAL WARNING: STATEFUL SIGNATURE SCHEME
//
// XMSS is a STATEFUL signature scheme. Each signature uses a unique index
// that MUST NEVER be reused. Reusing an index allows an attacker to forge
// signatures for ANY message.
//
// # Security Requirements
//
// To use XMSS safely, you MUST:
//
//  1. NEVER sign with the same index twice
//  2. Persist the index to durable storage BEFORE using any signature
//  3. NEVER sign concurrently from the same XMSS instance
//  4. NEVER restore from backup without ensuring index continuity
//  5. Plan for key rotation before index exhaustion (2^height signatures)
//
// # Recommendation
//
// For new applications, strongly prefer stateless alternatives:
//   - [github.com/theQRL/go-qrllib/crypto/ml_dsa_87] (FIPS 204, lattice-based)
//   - [github.com/theQRL/go-qrllib/crypto/sphincsplus_256s] (FIPS 205, hash-based)
//
// XMSS should only be used for:
//   - Legacy QRL address compatibility
//   - Specific compliance requirements mandating RFC 8391
//
// # Security Level
//
// Security level depends on the tree height and hash function:
//   - Height 10: 2^10 = 1,024 signatures
//   - Height 16: 2^16 = 65,536 signatures
//   - Height 20: 2^20 = 1,048,576 signatures
//
// Supported hash functions:
//   - SHA2_256: SHA-256 based
//   - SHAKE_128: SHAKE128 based
//   - SHAKE_256: SHAKE256 based
//
// # Thread Safety
//
// XMSS is NOT thread-safe. Never call Sign from multiple goroutines on the
// same instance. The index management is not protected by locks, and concurrent
// signing will corrupt the state and may lead to index reuse.
//
// # Safe Usage Pattern
//
//	tree := xmss.InitializeTree(xmss.Height10, xmss.SHAKE_256, seed)
//	defer tree.Zeroize()
//
//	// Sign a message
//	signature, err := tree.Sign(message)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// CRITICAL: Persist state BEFORE using the signature
//	if err := persistState(tree.GetIndex()); err != nil {
//	    // DO NOT use the signature if persistence fails!
//	    log.Fatal("state persistence failed, signature unsafe to use")
//	}
//
//	// Only now safe to use
//	broadcast(signature)
//
// # Index Management
//
// The current index can be retrieved and set:
//
//	currentIndex := tree.GetIndex()
//	err := tree.SetIndex(newIndex)
//
// SetIndex should only be used for state recovery, never to "rewind" the index.
//
// # Verification
//
// Signature verification is stateless and safe:
//
//	pk := tree.GetRoot() // combined with tree.GetPKSeed()
//	valid := xmss.Verify(hashFunc, message, signature, pk)
package xmss
