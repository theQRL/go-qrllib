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
// QRL addresses follow the format:
//
//	"Q" + hex(Descriptor + Checksum)
//
// Where:
//   - Descriptor: Wallet type and parameters (variable size)
//   - Checksum: SHA256(SHA256(Descriptor + PublicKey))
//
// Addresses are validated using [IsValidAddress]:
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
