package rfc8391

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/theQRL/go-qrllib/crypto/xmss"
)

// ParameterSet identifies one of the RFC 8391 / NIST SP 800-208
// parameter sets by its 32-bit OID. The numeric values are defined in
// RFC 8391 §5.3.
type ParameterSet uint32

const (
	XMSS_SHA2_10_256  ParameterSet = 0x00000001
	XMSS_SHA2_16_256  ParameterSet = 0x00000002
	XMSS_SHA2_20_256  ParameterSet = 0x00000003
	XMSS_SHAKE_10_256 ParameterSet = 0x00000007
	XMSS_SHAKE_16_256 ParameterSet = 0x00000008
	XMSS_SHAKE_20_256 ParameterSet = 0x00000009
)

// PublicKeySize is the byte length of a marshalled RFC 8391 public
// key for any of the supported parameter sets:
// 4 (OID) + 32 (root) + 32 (pub_seed) = 68 bytes.
const PublicKeySize = 4 + 32 + 32

// ExpandedSeedSize is the size of the seed material an RFC 8391
// reference implementation consumes directly: 96 bytes
// (SK_SEED || SK_PRF || PUB_SEED, each n=32 bytes).
const ExpandedSeedSize = 96

// ErrUnsupportedParameterSet is returned for OIDs that QRL does not
// implement (the n=64 family from RFC 8391 §5.3).
var ErrUnsupportedParameterSet = errors.New("rfc8391: unsupported parameter set OID")

// ErrInvalidPublicKeyLength is returned when [UnmarshalPublicKey] is
// passed a slice that is not exactly [PublicKeySize] bytes.
var ErrInvalidPublicKeyLength = errors.New("rfc8391: public key must be exactly 68 bytes")

// IsSupported reports whether p corresponds to one of the parameter
// sets this package can produce or consume.
func (p ParameterSet) IsSupported() bool {
	switch p {
	case XMSS_SHA2_10_256, XMSS_SHA2_16_256, XMSS_SHA2_20_256,
		XMSS_SHAKE_10_256, XMSS_SHAKE_16_256, XMSS_SHAKE_20_256:
		return true
	default:
		return false
	}
}

// Height returns the tree height for parameter set p.
func (p ParameterSet) Height() (xmss.Height, error) {
	switch p {
	case XMSS_SHA2_10_256, XMSS_SHAKE_10_256:
		return xmss.ToHeight(10)
	case XMSS_SHA2_16_256, XMSS_SHAKE_16_256:
		return xmss.ToHeight(16)
	case XMSS_SHA2_20_256, XMSS_SHAKE_20_256:
		return xmss.ToHeight(20)
	default:
		return 0, fmt.Errorf("%w: 0x%08x", ErrUnsupportedParameterSet, uint32(p))
	}
}

// HashFunction returns the underlying hash function for parameter set p.
func (p ParameterSet) HashFunction() (xmss.HashFunction, error) {
	switch p {
	case XMSS_SHA2_10_256, XMSS_SHA2_16_256, XMSS_SHA2_20_256:
		return xmss.SHA2_256, nil
	case XMSS_SHAKE_10_256, XMSS_SHAKE_16_256, XMSS_SHAKE_20_256:
		return xmss.SHAKE_256, nil
	default:
		return 0, fmt.Errorf("%w: 0x%08x", ErrUnsupportedParameterSet, uint32(p))
	}
}

// String returns the canonical RFC 8391 parameter-set name.
func (p ParameterSet) String() string {
	switch p {
	case XMSS_SHA2_10_256:
		return "XMSS-SHA2_10_256"
	case XMSS_SHA2_16_256:
		return "XMSS-SHA2_16_256"
	case XMSS_SHA2_20_256:
		return "XMSS-SHA2_20_256"
	case XMSS_SHAKE_10_256:
		return "XMSS-SHAKE_10_256"
	case XMSS_SHAKE_16_256:
		return "XMSS-SHAKE_16_256"
	case XMSS_SHAKE_20_256:
		return "XMSS-SHAKE_20_256"
	default:
		return fmt.Sprintf("UnsupportedParameterSet(0x%08x)", uint32(p))
	}
}

// inferParameterSet reverses HashFunction × Height → ParameterSet.
// Used by [MarshalPublicKey] to derive the OID from the constructed
// XMSS tree.
func inferParameterSet(hf xmss.HashFunction, h xmss.Height) (ParameterSet, error) {
	switch hf {
	case xmss.SHA2_256:
		switch h {
		case 10:
			return XMSS_SHA2_10_256, nil
		case 16:
			return XMSS_SHA2_16_256, nil
		case 20:
			return XMSS_SHA2_20_256, nil
		}
	case xmss.SHAKE_256:
		switch h {
		case 10:
			return XMSS_SHAKE_10_256, nil
		case 16:
			return XMSS_SHAKE_16_256, nil
		case 20:
			return XMSS_SHAKE_20_256, nil
		}
	}
	return 0, fmt.Errorf("%w: hashFunction=%s height=%d has no RFC 8391 OID",
		ErrUnsupportedParameterSet, hf, uint8(h))
}

// NewKeyPair generates an XMSS keypair for parameter set p from 96
// bytes of pre-expanded seed material (SK_SEED || SK_PRF || PUB_SEED),
// matching RFC 8391's keypair derivation.
//
// To construct an XMSS that round-trips with the reference
// implementation: take the same 96-byte seed material both sides
// consume, pass it here, and compare the resulting root + pub_seed
// against the reference's output.
//
// The QRL [xmss.InitializeTree] entry point is the wrong choice for
// this use case — it expands a 48-byte seed via SHAKE256 first, which
// the RFC reference implementation does not.
func NewKeyPair(p ParameterSet, expandedSeed *[ExpandedSeedSize]uint8) (*xmss.XMSS, error) {
	if !p.IsSupported() {
		return nil, fmt.Errorf("%w: 0x%08x", ErrUnsupportedParameterSet, uint32(p))
	}
	h, err := p.Height()
	if err != nil {
		//coverage:ignore
		//rationale: IsSupported above filters out every value Height would reject
		return nil, err
	}
	hf, err := p.HashFunction()
	if err != nil {
		//coverage:ignore
		//rationale: IsSupported above filters out every value HashFunction would reject
		return nil, err
	}
	return xmss.InitializeTreeFromExpandedSeed(h, hf, expandedSeed)
}

// MarshalPublicKey emits the RFC 8391 public-key byte string for an
// XMSS tree:
//
//	OID(4 bytes, big-endian) || root(32) || pub_seed(32) = 68 bytes
//
// The tree's hash function and height are mapped to the corresponding
// RFC 8391 OID; trees that don't fit one of the supported
// parameter sets (e.g. SHAKE_128 trees, or odd-numbered heights) get
// rejected with [ErrUnsupportedParameterSet].
func MarshalPublicKey(x *xmss.XMSS) ([]byte, error) {
	p, err := inferParameterSet(x.GetHashFunction(), x.GetHeight())
	if err != nil {
		return nil, err
	}
	root := x.GetRoot()
	pubSeed := x.GetPKSeed()

	out := make([]byte, PublicKeySize)
	binary.BigEndian.PutUint32(out[0:4], uint32(p))
	copy(out[4:36], root)
	copy(out[36:68], pubSeed)
	return out, nil
}

// UnmarshalPublicKey parses an RFC 8391 public-key byte string and
// returns the parameter set OID along with the 32-byte root and
// 32-byte pub_seed. Returns [ErrInvalidPublicKeyLength] if the input
// is the wrong size, or [ErrUnsupportedParameterSet] if the OID is
// outside the supported family.
func UnmarshalPublicKey(rfcPK []byte) (p ParameterSet, root, pubSeed [32]byte, err error) {
	if len(rfcPK) != PublicKeySize {
		err = fmt.Errorf("%w: got %d bytes", ErrInvalidPublicKeyLength, len(rfcPK))
		return
	}
	p = ParameterSet(binary.BigEndian.Uint32(rfcPK[0:4]))
	if !p.IsSupported() {
		err = fmt.Errorf("%w: 0x%08x", ErrUnsupportedParameterSet, uint32(p))
		return
	}
	copy(root[:], rfcPK[4:36])
	copy(pubSeed[:], rfcPK[36:68])
	return
}

// Verify checks an RFC-format signature against a message and an
// RFC-format public key. It is a thin wrapper over [xmss.Verify] that
// extracts the root and pub_seed from the RFC public-key bytes and
// looks up the hash function from the OID.
//
// The signature byte layout is identical between RFC 8391 and QRL's
// xmss package, so signatures produced by this package's [NewKeyPair]
// or by an RFC reference implementation can be passed in unchanged.
func Verify(message, signature, rfcPK []byte) (bool, error) {
	p, root, pubSeed, err := UnmarshalPublicKey(rfcPK)
	if err != nil {
		return false, err
	}
	hf, err := p.HashFunction()
	if err != nil {
		//coverage:ignore
		//rationale: UnmarshalPublicKey returns ErrUnsupportedParameterSet
		//for any p that HashFunction would reject, so this branch is unreachable.
		return false, err
	}

	// xmss.Verify expects the root || pub_seed concatenation as its pk argument.
	xmssPK := make([]byte, 64)
	copy(xmssPK[:32], root[:])
	copy(xmssPK[32:], pubSeed[:])

	return xmss.Verify(hf, message, signature, xmssPK), nil
}
