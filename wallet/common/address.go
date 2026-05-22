package common

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
	"golang.org/x/crypto/sha3"
)

/*
UnsafeGetAddress builds the address bytes from a validated descriptor and public key.

Rationale: this is a fast-path used by wallet implementations that already validate
the descriptor type and public key length during construction. Skipping checks avoids
repeat validation on every call, but it is unsafe for untrusted inputs.

Callers MUST ensure:
  - desc.IsValid() is true for the intended wallet type
  - pk is the correct length for that wallet type
*/
func UnsafeGetAddress(pk []byte, desc descriptor.Descriptor) [AddressSize]byte {
	sh := sha3.NewShake256()
	_, _ = sh.Write(desc.ToBytes())
	_, _ = sh.Write(pk)

	var addr [AddressSize]byte
	_, _ = sh.Read(addr[:]) // take the first N bytes
	return addr
}

// GetAddress validates the descriptor and public key length, then derives the address.
// It is the safe wrapper around UnsafeGetAddress for untrusted inputs.
func GetAddress(pk []byte, desc descriptor.Descriptor) ([AddressSize]byte, error) {
	var addr [AddressSize]byte
	if !desc.IsValid() {
		return addr, fmt.Errorf(ErrInvalidDescriptor, wallettype.WalletType(desc.Type()))
	}
	expectedSize, err := expectedPKSize(desc)
	if err != nil {
		//coverage:ignore
		//rationale: desc.IsValid() above already validates the wallet type
		return addr, err
	}
	if len(pk) != expectedSize {
		return addr, fmt.Errorf(ErrInvalidPKSize, wallettype.WalletType(desc.Type()), len(pk), expectedSize)
	}
	return UnsafeGetAddress(pk, desc), nil
}

func expectedPKSize(desc descriptor.Descriptor) (int, error) {
	switch wallettype.WalletType(desc.Type()) {
	case wallettype.ML_DSA_87:
		return MLDSA87PKSize, nil
	default:
		//coverage:ignore
		//rationale: only called from GetAddress after desc.IsValid() check
		return 0, fmt.Errorf(ErrInvalidDescriptor, wallettype.WalletType(desc.Type()))
	}
}

/*
EIP-55-style mixed-case checksum (QRL variant).

Identical algorithm across @theqrl/wallet.js, go-qrllib, and rust-qrllib so the
same address bytes produce the same checksummed string in every implementation:

  - Hash:  SHAKE-256 of the UTF-8 bytes of the 128-character lowercase hex
           (no "Q" prefix), with dkLen = AddressSize, giving exactly one nibble
           per hex character.
  - Rule:  for each hex character, if it is a letter ('a'-'f') and the
           corresponding nibble of the hash is >= 8, uppercase it; otherwise
           leave it lowercase.
  - "Q":   always uppercase on output; not part of the checksum input. Input
           parsing accepts uppercase "Q" only on the strict check
           (IsValidChecksumAddress) and continues to require "Q" on
           IsValidAddress (matching the prior Go convention).

IsValidAddress accepts all-lowercase, all-uppercase, and correctly-checksummed
mixed-case hex bodies. Mixed-case bodies whose checksum does not validate are
rejected, mirroring how Ethereum tooling treats EIP-55 addresses.
*/

const hexLen = AddressSize * 2

// checksummedHex computes the canonical mixed-case form of a 128-character
// lowercase hex body. Internal helper; assumes lowerHex is exactly hexLen
// lowercase hex characters.
func checksummedHex(lowerHex string) string {
	sh := sha3.NewShake256()
	_, _ = sh.Write([]byte(lowerHex))
	var hash [AddressSize]byte
	_, _ = sh.Read(hash[:])

	out := make([]byte, len(lowerHex))
	for i := 0; i < len(lowerHex); i++ {
		c := lowerHex[i]
		if c >= 'a' && c <= 'f' {
			var nibble byte
			if i&1 == 0 {
				nibble = hash[i>>1] >> 4
			} else {
				nibble = hash[i>>1] & 0x0f
			}
			if nibble >= 8 {
				out[i] = c - ('a' - 'A')
				continue
			}
		}
		out[i] = c
	}
	return string(out)
}

// ToChecksumAddress returns the EIP-55-style mixed-case checksummed string
// form of an address. The returned string always uses uppercase "Q".
func ToChecksumAddress(addr [AddressSize]byte) string {
	return "Q" + checksummedHex(hex.EncodeToString(addr[:]))
}

// IsValidAddress validates a QRL address string.
//
// A valid address has the format "Q" followed by AddressSize*2 hex characters.
// The hex body must be one of:
//   - all lowercase (case-uniform), or
//   - all uppercase (case-uniform), or
//   - mixed-case matching the EIP-55-style checksum (see checksummedHex).
//
// Mixed-case strings that do not match the checksum are rejected. This is the
// permissive check; use IsValidChecksumAddress to require a properly
// checksummed string.
func IsValidAddress(addr string) bool {
	// Check length: "Q" prefix + hex-encoded address (2 chars per byte)
	expectedLen := 1 + hexLen
	if len(addr) != expectedLen {
		return false
	}

	// Check Q prefix
	if addr[0] != 'Q' {
		return false
	}

	body := addr[1:]
	if _, err := hex.DecodeString(body); err != nil {
		return false
	}

	lower := strings.ToLower(body)
	if body == lower || body == strings.ToUpper(body) {
		return true
	}
	// Mixed case — must satisfy the EIP-55-style checksum.
	return body == checksummedHex(lower)
}

// IsValidChecksumAddress is the strict check: it returns true only when
// addr exactly matches the canonical checksummed form produced by
// ToChecksumAddress. The "Q" prefix must be uppercase and the hex body
// must match character-for-character. All-lowercase and all-uppercase
// addresses that contain letters return false; digit-only hex bodies have
// no checksum information and return true when the rest of the format is
// valid.
func IsValidChecksumAddress(addr string) bool {
	if len(addr) != 1+hexLen {
		return false
	}
	if addr[0] != 'Q' {
		return false
	}
	body := addr[1:]
	if _, err := hex.DecodeString(body); err != nil {
		return false
	}
	return body == checksummedHex(strings.ToLower(body))
}
