// Package common provides shared types and utilities for QRL wallet implementations.
//
// This package contains:
//
//   - Address validation and generation utilities
//   - Common seed handling for different wallet types
//   - Shared error messages and constants
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
//     SHAKE256(Descriptor || PK)[:20] (20 bytes total)
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
