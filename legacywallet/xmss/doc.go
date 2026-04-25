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
// # Stateful signing
//
// XMSS is a stateful signature scheme: the OTS index returned by GetIndex
// MUST be persisted to durable storage AFTER signing and BEFORE using the
// returned signature. Reusing an index allows an attacker to forge
// signatures for any message. See [github.com/theQRL/go-qrllib/crypto/xmss]
// for the full safe-usage pattern.
package xmss
