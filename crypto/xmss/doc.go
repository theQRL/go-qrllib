// Package xmss implements the XMSS (eXtended Merkle Signature Scheme)
// hash-based signature primitive used by QRL v1 mainnet addresses.
// The implementation predates RFC 8391 and is retained as a v1 → v2
// migration shim — it is not intended as a general standards-tracking
// XMSS implementation. Where parameter-set choices overlap with
// RFC 8391 (XMSS-SHA2_10_256, XMSS-SHAKE_256_10_256), signatures
// produced by this package are wire-compatible with the RFC 8391
// reference implementation, and bidirectional cross-verify against
// the reference is exercised in CI via the [rfc8391] sub-package.
// See SECURITY.md for the full provenance discussion.
//
// [rfc8391]: https://pkg.go.dev/github.com/theQRL/go-qrllib/crypto/xmss/rfc8391
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
//  2. Persist the UPDATED index to durable storage AFTER signing and BEFORE using any signature
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
// XMSS in this library should only be used for:
//   - Legacy QRL address compatibility (the primary purpose)
//   - Interop testing against an RFC 8391 reference implementation
//     where v1-compatible XMSS signatures are needed (via the
//     [rfc8391] sub-package)
//
// # Security Level
//
// Security level depends on the tree height and hash function:
//   - Height 10: 2^10 = 1,024 signatures
//   - Height 16: 2^16 = 65,536 signatures
//   - Height 20: 2^20 = 1,048,576 signatures
//
// # Supported parameter sets
//
// This implementation only supports the parameter set family that QRL
// has actually deployed. The exported [XMSSFastGenKeyPair] entry point
// rejects any other tuple with [github.com/theQRL/go-qrllib/crypto/errors.ErrUnsupportedParameterSet].
// The supported family is:
//
//   - n = 32 (output length)
//   - w = 16 (Winternitz parameter)
//   - k = 2 (BDS traversal parameter)
//   - h ∈ {2, 4, 6, …, [MaxHeight]} (even tree heights)
//
// Combined with the supported [HashFunction] values, this gives the
// following concrete parameter sets:
//
//   - XMSS-SHA2_h_256 — RFC 8391 (Aug 2018) signature format
//   - XMSS-SHAKE_256_h_256 — RFC 8391 (Aug 2018) signature format
//   - XMSS-SHAKE_128_h_256 — QRL pre-standardisation extension, retained
//     for legacy v1 address compatibility (see [SHAKE_128]). Not part of
//     RFC 8391 or NIST SP 800-208. Not recommended for new wallets.
//
// Note: this implementation follows the original RFC 8391 (Aug 2018)
// `expand_seed` construction, not the NIST SP 800-208 (Oct 2020)
// refinement that adds `pub_seed || ADRS` inputs. See SECURITY.md
// "Standards alignment" for the rationale.
//
// Wider RFC 8391 coverage (`n=64` parameter sets, e.g. XMSS-SHA2_h_512)
// is not implemented and is not on the roadmap; new XMSS-style issuance
// on QRL is moving to ML-DSA-87 (FIPS 204), which sidesteps this concern
// entirely. Bidirectional reference-implementation interop for the
// supported sets is available via the [github.com/theQRL/go-qrllib/crypto/xmss/rfc8391]
// sub-package.
//
// Supported hash functions:
//   - SHA2_256: SHA-256 based
//   - SHAKE_128: SHAKE128 based (legacy QRL extension)
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
// Always construct Height via xmss.ToHeight (or xmss.UInt32ToHeight) rather
// than a raw cast such as xmss.Height(10). The helpers validate the value
// against the allowed range (even integers in [2, MaxHeight]) and return a
// typed error for invalid input; a raw cast bypasses that validation and
// will be rejected at InitializeTree with ErrInvalidHeight.
//
//	height, err := xmss.ToHeight(10)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	tree, err := xmss.InitializeTree(height, xmss.SHAKE_256, seed)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer tree.Zeroize()
//
//	// Sign a message
//	signature, err := tree.Sign(message)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// CRITICAL: Persist the UPDATED index BEFORE using the signature
//	if err := persistIndex(tree.GetIndex()); err != nil {
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
// # Recovery and BDS State
//
// XMSS uses BDS state to speed up signing. This state is not persisted or
// serialized by the library. Recovery requires:
//  1. Securely storing the seed (or extended seed) once, and
//  2. Persisting the last used index after each signature.
// To recover, rebuild the tree from the seed and call SetIndex(persistedIndex)
// to advance the BDS state to the last used index. This can be O(Δ) in the
// number of skipped indices, so persist frequently and avoid large gaps.
//
// # Verification
//
// Signature verification is stateless and safe:
//
//	pk := tree.GetRoot() // combined with tree.GetPKSeed()
//	valid := xmss.Verify(hashFunc, message, signature, pk)
package xmss
