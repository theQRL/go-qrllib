package common

import "github.com/theQRL/go-qrllib/wallet/common/descriptor"

// SigningContextVersion is the current signing-context format version.
//
// Bumping this value is a hard break of the signature wire format: all
// signatures produced under a new version will fail to verify under the
// old version and vice-versa. A version bump must coincide with a
// coordinated consensus/library activation.
const SigningContextVersion byte = 0x01

// SigningContextPrefix is the application-domain tag embedded in every
// signature's context.
var SigningContextPrefix = [...]byte{'Z', 'O', 'N', 'D'}

// SigningContextSize is the fixed on-wire length of a signing context
// constructed by SigningContext.
const SigningContextSize = len(SigningContextPrefix) + 1 + descriptor.DescriptorSize

// SigningContext builds the domain-separated bytes that bind a
// signature to its descriptor:
//
//	"ZOND" || SigningContextVersion || descriptor  (fixed 8 bytes)
//
// The descriptor is embedded verbatim (type byte + reserved metadata
// bytes), so any change to wallet type or future metadata produces a
// distinct context. The version byte allows a later redesign of the
// context layout without colliding with the current scheme.
//
// The layout is fixed-length, so the downstream consumers (ML-DSA-87's
// length-prefixed pre-string, or the SPHINCS+-256s message prefix)
// receive an unambiguous, canonically-encoded byte string.
func SigningContext(d descriptor.Descriptor) []byte {
	ctx := make([]byte, 0, SigningContextSize)
	ctx = append(ctx, SigningContextPrefix[:]...)
	ctx = append(ctx, SigningContextVersion)
	ctx = append(ctx, d[:]...)
	return ctx
}
