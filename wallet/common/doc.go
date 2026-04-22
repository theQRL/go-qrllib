// Package common provides shared types and utilities for QRL wallet implementations.
//
// This package contains:
//
//   - Address validation and generation utilities
//   - Common seed handling for different wallet types
//   - Domain-separated signing-context construction ([SigningContext])
//   - Shared error messages and constants
//
// # Signing Context
//
// [SigningContext] returns the fixed-length byte string
//
//	"ZOND" || SigningContextVersion || descriptor   (8 bytes)
//
// used by wallet packages to bind a signature cryptographically to its
// descriptor. ML-DSA-87 uses it as the FIPS 204 ctx parameter; SPHINCS+-256s
// prepends it to the message. Wallet-type-specific packages call this helper
// internally and callers should not usually need to construct it themselves.
// Bumping SigningContextVersion breaks signature compatibility and requires a
// coordinated consensus activation.
//
// # Address Format
//
// QRL address bytes are generated from public keys with a descriptor prefix.
// The string form used by modern wallet packages prepends "Q" and hex-encodes
// the address bytes. The exact byte format depends on the wallet type:
//
//   - Legacy XMSS (byte form):
//     Descriptor + SHA256(PK) + Checksum (39 bytes total)
//
//   - ML-DSA-87 and SPHINCS+-256s (byte form):
//     SHAKE256(Descriptor || PK)[:48] (48 bytes total)
//
// Addresses are validated using [IsValidAddress]. For address generation:
//   - Use [GetAddress] for untrusted inputs (validates descriptor and pk length)
//   - Use [UnsafeGetAddress] only when the descriptor and public key have already
//     been validated by the caller (wallet implementations rely on this fast-path).
//
//	if !common.IsValidAddress(addr) {
//	    return errors.New("invalid QRL address")
//	}
//
// # Seed Derivation
//
// QRL wallets use a common 48-byte seed that is derived differently for each
// signature algorithm:
//
//   - ML-DSA-87:    SHA-256(seed) → 32 bytes
//   - SPHINCS+-256s: SHAKE-256(seed) → 96 bytes
//   - XMSS:         Direct use of seed bytes
//
// This allows the same mnemonic to generate different wallet types.
package common
