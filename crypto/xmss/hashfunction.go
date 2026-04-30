package xmss

import (
	"fmt"

	cryptoerrors "github.com/theQRL/go-qrllib/crypto/errors"
)

// HashFunction selects the underlying hash primitive used by the XMSS
// construction. The supported values reflect QRL's pre-standardisation
// XMSS implementation rather than the parameter sets formalised later
// in NIST SP 800-208 — see the SHAKE_128 note below for the specific
// non-standard case that is retained for legacy compatibility.
type HashFunction uint8

const (
	// SHA2_256 — XMSS-SHA2_*_256 family. Signature format matches
	// RFC 8391 (Aug 2018); see the package doc and SECURITY.md
	// "Standards alignment" for the relationship to NIST SP 800-208.
	SHA2_256 HashFunction = iota

	// SHAKE_128 is a QRL-specific extension retained for legacy address
	// compatibility from QRL's pre-standardisation XMSS implementation.
	// It is NOT one of the parameter sets approved by NIST SP 800-208
	// (which standardises only SHA2 and SHAKE_256 for XMSS) and is NOT
	// recommended for new wallets: with a 32-byte output, SHAKE_128
	// offers approximately 64-bit quantum security under a Grover-style
	// attack, which is theoretically reduced relative to SHAKE_256 /
	// SHA2_256 (~128-bit quantum), although the gap remains difficult
	// to exploit in practice today.
	//
	// New issuance on QRL is moving to ML-DSA-87 (FIPS 204), which is
	// unaffected by this consideration. Existing v1 mainnet addresses
	// minted under SHAKE_128 must continue to be parseable, verifiable
	// and signable; that is the only reason this enum entry survives.
	// See SECURITY.md for the parameter-set provenance summary.
	SHAKE_128

	// SHAKE_256 — XMSS-SHAKE_*_256 family. Signature format matches
	// RFC 8391 (Aug 2018); see the package doc and SECURITY.md
	// "Standards alignment" for the relationship to NIST SP 800-208.
	SHAKE_256
)

// ToHashFunction converts a uint8 to a HashFunction, returning an error if invalid.
// Valid hash functions are SHA2_256 (0), SHAKE_128 (1), and SHAKE_256 (2).
func ToHashFunction(val uint8) (HashFunction, error) {
	h := HashFunction(val)
	if !h.IsValid() {
		return 0, cryptoerrors.ErrInvalidHashFunction
	}
	return h, nil
}

// HashFunctionFromDescriptorByte extracts a HashFunction from a descriptor byte.
// Returns an error if the extracted hash function is invalid.
func HashFunctionFromDescriptorByte(val uint8) (HashFunction, error) {
	return ToHashFunction((val >> 4) & 0x0f)
}

func (hf HashFunction) ToDescriptorByte() byte {
	return uint8((hf << 4) & 0xf0)
}

func (hf HashFunction) IsValid() bool {
	switch hf {
	case SHA2_256, SHAKE_128, SHAKE_256:
		return true
	default:
		return false
	}
}

func (hf HashFunction) String() string {
	switch hf {
	case SHA2_256:
		return "SHA2_256"
	case SHAKE_128:
		return "SHAKE_128"
	case SHAKE_256:
		return "SHAKE_256"
	default:
		return fmt.Sprintf("UnknownHashFunction(%d)", hf)
	}
}
