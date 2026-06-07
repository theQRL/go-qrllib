// Package xmss is the legacy XMSS wallet for QRL v1 mainnet
// addresses. New issuance on QRL v2 uses ML-DSA-87
// ([github.com/theQRL/go-qrllib/wallet/ml_dsa_87]); this package exists
// to recover, verify, and sign for v1-era addresses during and after the
// v1 → v2 migration.
//
// # Hash function selection (SHAKE_128 caveat)
//
// The wallet constructors accept any [github.com/theQRL/go-qrllib/crypto/xmss.HashFunction]
// — SHA2_256, SHAKE_128, or SHAKE_256 — to preserve the layout of v1
// addresses that were minted under each. SHAKE_128 in particular is a
// QRL-specific extension retained for legacy address compatibility from
// QRL's pre-standardisation XMSS implementation; it is not one of the
// parameter sets approved by NIST SP 800-208 and is not recommended for
// new wallets. Recovery, verification and signing for existing SHAKE_128
// addresses remains supported and unchanged. See
// [github.com/theQRL/go-qrllib/crypto/xmss.SHAKE_128] for the per-enum
// note and SECURITY.md for the parameter-set provenance summary.
//
// # CRITICAL WARNING — STATEFUL SIGNATURE SCHEME
//
// XMSS is a STATEFUL signature scheme. Each call to [XMSSWallet.Sign]
// consumes a unique one-time-signature (OTS) index. Reusing an index —
// even for a different message — exposes enough of the secret key to
// allow an attacker to forge signatures for ANY message.
//
// To use XMSSWallet safely you MUST:
//
//  1. NEVER sign with the same index twice.
//  2. Persist the UPDATED index — obtained via [XMSSWallet.GetIndex] —
//     to durable storage AFTER each [XMSSWallet.Sign] call and BEFORE
//     the returned signature is used or broadcast. If the persistence
//     step fails, the signature MUST NOT be used.
//  3. NEVER call Sign concurrently on the same XMSSWallet instance. The
//     index is not protected by locks; concurrent signing corrupts the
//     internal BDS state and may lead to index reuse.
//  4. NEVER restore from a backup whose persisted index is behind the
//     true last-used index — doing so would re-use indices.
//  5. Plan for key rotation before index exhaustion (2^height signatures).
//
// # Recovery and BDS state
//
// XMSS uses BDS state to speed up signing. This state is not persisted
// or serialised by the library. Recovery requires:
//
//  1. Securely storing the seed (or extended seed) once, and
//  2. Persisting the last-used index after each signature.
//
// To recover, rebuild the wallet from the seed via NewWalletFromSeed
// (or NewWalletFromExtendedSeed) and call [XMSSWallet.SetIndex] with
// the persisted index to advance the BDS state. SetIndex is O(Δ) in
// the number of skipped indices, so persist frequently and avoid large
// gaps. SetIndex must NEVER be used to "rewind" the index below the
// last-used value.
//
// # Recommendation
//
// For new applications strongly prefer the stateless alternative:
//
//   - [github.com/theQRL/go-qrllib/wallet/ml_dsa_87] (FIPS 204, lattice-based).
//
// XMSS should only be used for legacy QRL v1 address compatibility.
//
// See [github.com/theQRL/go-qrllib/crypto/xmss] for the full safe-usage
// pattern at the lower-level API.
package xmss
