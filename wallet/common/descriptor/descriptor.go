package descriptor

import (
	"errors"

	"github.com/theQRL/go-qrllib/wallet/common/wallettype"
)

const (
	DescriptorSize = 3
)

type CryptoDescriptor interface {
	Type() byte
	FromDescriptor(d Descriptor) error
	ToDescriptor() Descriptor
	IsValid() bool
}

// Descriptor represents a compact, variable-size identifier
// containing cryptographic metadata.
//
// The descriptor is a byte array where:
//   - Byte 0 (index 0): Indicates the cryptographic type.
//   - Rest of the bytes if exist are the metadata for the respective wallet type
//	   or is 0 in case of no data

type Descriptor [DescriptorSize]byte

func New(descriptorBytes [DescriptorSize]byte) Descriptor {
	var d Descriptor
	copy(d[:], descriptorBytes[:])
	return d
}

func FromBytes(descriptorBytes []byte) (Descriptor, error) {
	var d Descriptor
	if len(descriptorBytes) != DescriptorSize {
		return d, errors.New("invalid descriptor size")
	}
	copy(d[:], descriptorBytes[:])
	return d, nil
}

func (d Descriptor) Type() byte {
	return d[0]
}

// IsValid reports whether the descriptor is well-formed.
//
// For ML_DSA_87 and SPHINCSPLUS_256S, bytes 1 and 2 carry no defined
// semantics and must be zero. The 3-byte shape is preserved for
// backward compatibility with the legacy XMSS address format and is
// reserved for a future metadata schema, which must be introduced via
// a coordinated consensus/library change.
//
// Rejecting non-zero metadata bytes collapses the set of valid
// descriptors to one canonical value per wallet type, so a single
// keypair cannot be used to derive sibling addresses through the
// public API.
//
// IsValid is the right check for descriptor parsing and address
// derivation. It does NOT report whether the library will currently
// issue new wallets of this type or accept signatures under it; for
// those see IsIssuable and IsVerifiable.
func (d Descriptor) IsValid() bool {
	switch wallettype.WalletType(d[0]) {
	case wallettype.SPHINCSPLUS_256S, wallettype.ML_DSA_87:
		return d[1] == 0 && d[2] == 0
	default:
		return false
	}
}

// IsIssuable reports whether the descriptor is well-formed AND the library
// will currently construct *new* wallets of this type. SPHINCSPLUS_256S
// is parseable (IsValid) but not currently issuable; it is reserved as a
// forward placeholder for QRL's eventual SLH-DSA (FIPS 205) adoption.
// See wallettype.WalletType.IsIssuable for the per-type rationale.
func (d Descriptor) IsIssuable() bool {
	return d.IsValid() && wallettype.WalletType(d[0]).IsIssuable()
}

// IsVerifiable reports whether the descriptor is well-formed AND the
// library has an active verification path for signatures produced under
// this wallet type. SPHINCSPLUS_256S is parseable but not currently
// verifiable; see wallettype.WalletType.IsVerifiable.
func (d Descriptor) IsVerifiable() bool {
	return d.IsValid() && wallettype.WalletType(d[0]).IsVerifiable()
}

func (d Descriptor) ToBytes() []byte {
	return d[:]
}

func GetDescriptorBytes(walletType wallettype.WalletType, metadata [2]byte) [DescriptorSize]byte {
	return [DescriptorSize]byte{byte(walletType), metadata[0], metadata[1]}
}
