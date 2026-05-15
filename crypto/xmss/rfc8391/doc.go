// Package rfc8391 provides RFC 8391 reference-implementation interop
// for the XMSS parameter sets QRL supports.
//
// # What this package is for
//
// QRL's [github.com/theQRL/go-qrllib/crypto/xmss] implementation is
// signature-format compliant with RFC 8391 for the XMSS-SHA2_h_256 and
// XMSS-SHAKE_256_h_256 parameter sets — signatures it produces verify
// correctly under the reference implementation at
// [github.com/XMSS/xmss-reference]. The cross-implementation
// verification CI in `.github/cross-verify/` confirms this.
//
// Two QRL-specific conventions, however, prevent the *opposite*
// direction (reference → go-qrllib) from working out of the box:
//
//  1. **Seed derivation.** [xmss.InitializeTree] expands a 48-byte
//     seed via SHAKE256 into the 96 bytes (SK_SEED || SK_PRF ||
//     PUB_SEED) the construction needs. The RFC 8391 reference takes
//     those 96 bytes directly with no expansion step. So a 48-byte
//     seed handed to both implementations does NOT produce the same
//     keypair; only a 96-byte expanded-seed handed to both does.
//  2. **Public-key prefix.** QRL's extended-PK format prefixes the
//     32-byte root and 32-byte pub_seed with a 3-byte QRL descriptor.
//     RFC 8391 prefixes them with a 4-byte parameter-set OID.
//
// This package addresses both:
//
//   - [NewKeyPair] takes 96 bytes directly, matching the reference
//     implementation's keypair-derivation.
//   - [MarshalPublicKey] / [UnmarshalPublicKey] convert between
//     `*xmss.XMSS` and the RFC 8391 byte layout.
//
// Together they make cross-implementation interop bidirectional for
// the supported parameter sets. Signature byte layouts already match
// at the wire level — no conversion is needed for signatures.
//
// # Supported parameter sets
//
// RFC 8391 defines twelve parameter sets, identified by 32-bit OIDs.
// QRL's implementation supports `n=32, w=16, k=2`, so the OIDs that
// can round-trip through this package are:
//
//   - XMSS-SHA2_10_256  (OID 0x00000001)
//   - XMSS-SHA2_16_256  (OID 0x00000002)
//   - XMSS-SHA2_20_256  (OID 0x00000003)
//   - XMSS-SHAKE_10_256 (OID 0x00000007)
//   - XMSS-SHAKE_16_256 (OID 0x00000008)
//   - XMSS-SHAKE_20_256 (OID 0x00000009)
//
// The remaining six OIDs from RFC 8391 are `n=64` parameter sets
// (XMSS-{SHA2,SHAKE}_h_512); they are out of scope for QRL and not
// implemented. Calling [NewKeyPair] / [UnmarshalPublicKey] with one
// of those OIDs returns [ErrUnsupportedParameterSet].
//
// QRL's pre-standardisation SHAKE_128 hash variant is not part of
// RFC 8391 and has no OID; this package will not produce or consume
// SHAKE_128 keys. Use the parent [xmss] package directly for those.
//
// # Bidirectional cross-verify
//
// See `.github/cross-verify/` for the working bidirectional CI that
// exercises this package.
package rfc8391
