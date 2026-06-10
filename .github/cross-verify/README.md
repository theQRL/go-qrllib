# Cross-Implementation Verification

This directory contains helper files for cross-implementation verification tests run by GitHub Actions.

## Overview

These tests verify that go-qrllib's signature implementations are interoperable with the authoritative reference implementations. The ML-KEM-1024 KEM is additionally cross-verified against the Go standard library's FIPS 203-validated `crypto/mlkem`.

## Tests

### ML-DSA-87 (FIPS 204)
- Reference: https://github.com/pq-crystals/dilithium (current master)
- Tests bidirectional signature verification with context parameter
- Key sizes: PK=2592, SK=4896, Sig=4627 bytes

### SPHINCS+ (SHAKE-256s-robust)
- Reference: https://github.com/sphincs/sphincsplus @ branch `consistent-basew`
- Parameters: PARAMS=sphincs-shake-256s THASH=robust
- Tests bidirectional signature verification
- Key sizes: PK=64, SK=128, Seed=96, Sig=29792 bytes
- Note: Uses `consistent-basew` branch which has the corrected FORS index decoding (see [NIST PQC Forum discussion](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/88tuvtb7nN4/m/DA1QCoJWBAAJ))

### XMSS (SHA2_10_256) - Bidirectional via the rfc8391 sub-package
- Reference: https://github.com/XMSS/xmss-reference @ commit `7793c40`
- Parameters: XMSS-SHA2_10_256 (OID 0x00000001), height=10, n=32, w=16
- Tests **bidirectional** verification using the
  [`crypto/xmss/rfc8391`](../../crypto/xmss/rfc8391/) sub-package on the
  go-qrllib side.
- Key sizes: PK=64 (root||pub_seed) or 68 (RFC layout with OID),
  SK=132, Seed=48 (QRL convention) or 96 (RFC convention), Sig=2500 bytes
- **Pin rationale**: QRL's XMSS implementation predates RFC 8391
  (the spec was published in August 2018, after QRL v1 launched) and
  is retained here primarily as a v1 → v2 migration shim, not as a
  standards-tracking XMSS implementation. Commit `7793c40` (2020-04-14)
  is the last `xmss-reference` revision that uses the original
  RFC 8391 `expand_seed` construction `sk_i = PRF(SK_SEED,
  toByte(i, 32))`. NIST commit `3e28db2` (2020-04-28) "Improved key
  generation" later refined this to `sk_i = PRF_keygen(SK_SEED,
  PUB_SEED || ADRS)` for SP 800-208. QRL keeps the original
  construction because changing it would alter every v1 mainnet
  keypair; pinning the cross-verify reference here matches the
  construction QRL targets. See SECURITY.md "Parameter-set
  provenance" for the full provenance discussion.

#### Why a sub-package was needed for the reverse direction

go-qrllib's primary `xmss.InitializeTree` entry point produces signatures whose **wire format matches RFC 8391** (the forward direction `xmss_sign.go → xmss_verify_ref.c` has always worked), but a 48-byte seed handed to it does NOT produce the same keypair the reference would derive from a literal 96-byte seed. Two QRL-specific conventions caused this:

1. **Seed expansion**: `xmss.InitializeTree` SHAKE256-expands a 48-byte seed into the 96 bytes (SK_SEED || SK_PRF || PUB_SEED) the construction needs. The RFC 8391 reference implementation takes those 96 bytes directly with no expansion step.

2. **Public-key prefix**: QRL's extended-PK format prefixes the 32-byte root and 32-byte pub_seed with a 3-byte QRL descriptor. RFC 8391 prefixes them with a 4-byte parameter-set OID.

The [`crypto/xmss/rfc8391`](../../crypto/xmss/rfc8391/) sub-package
addresses both. `rfc8391.NewKeyPair(p, expandedSeed *[96]uint8)` takes
the 96 bytes directly, matching the reference's keypair derivation
exactly; `rfc8391.MarshalPublicKey` / `UnmarshalPublicKey` convert
between go-qrllib's internal representation and the RFC byte layout.

#### Forward direction: go-qrllib → reference

* `xmss_sign.go` (Go) generates a keypair via the QRL `xmss.InitializeTree`
  entry point, signs, writes pk + sig + msg to `/tmp/`.
* `xmss_verify_ref.c` (C) reads the artefacts, prepends an RFC 8391
  OID to the pk, calls `xmss_sign_open()`. **Already worked before this
  PR; signature byte layout matches at the wire level.**

#### Reverse direction: reference → go-qrllib (new)

- `xmss_sign_ref.c` (C) at the pinned commit `7793c40` the
  reference does not yet expose a public seeded-keypair API
  (`xmssmt_core_seed_keypair` was added in a later commit). To get a
  deterministic keypair from a fixed 96-byte expanded seed, this file
  provides its own `randombytes()` that consumes the seed buffer in
  order, then calls the public `xmss_keypair()` API. The reference's
  internal `xmssmt_core_keypair` makes two calls
  (`randombytes(sk + index_bytes, 64)` for SK_SEED || SK_PRF, then
  `randombytes(sk + index_bytes + 96, 32)` for PUB_SEED), which
  reproduces the 96-byte expanded-seed convention QRL's
  `rfc8391.NewKeyPair` uses. The link command therefore *omits* the
  upstream `randombytes.c`. Output: pk (in both QRL and RFC layouts) +
  sig + msg + expanded seed under `/tmp/`.
- `xmss_verify.go` (Go) reads the same 96-byte expanded seed,
  reconstructs the keypair via `rfc8391.NewKeyPair`, asserts the
  resulting root || pub_seed matches the reference's pk byte-for-byte,
  then verifies the signature via `rfc8391.Verify`. The pk-bytes-match
  check is the actual bidirectional-equivalence proof; signature
  verification is then a straightforward consequence.

**Note**: XMSS in this library is a legacy algorithm: QRL's XMSS implementation predates RFC 8391 (Aug 2018), and the package is maintained as a v1 → v2 migration shim so QRL v1 mainnet addresses remain parseable, verifiable, and signable. For new applications, use ML-DSA-87 (FIPS 204). SLH-DSA (FIPS 205, formerly SPHINCS+) is reserved as a wallet type in the QRL descriptor format but is not currently issuable. The implementation here remains the pre-FIPS-205 SPHINCS+ submission, and finalized parameter set under FIPS 205 remains to be determined.  Committing to a specific SLH-DSA parameter set under FIPS 205, and so activating the wallet path now, would commit users to a parameter set that may change.

### ML-KEM-1024 (FIPS 203) — vs Go stdlib `crypto/mlkem`

ML-KEM-1024 is a key-encapsulation mechanism, not a signature, so cross-verification checks **shared-secret agreement** rather than signature interoperability. The reference is an independent Go implementation — the standard library's FIPS 203-validated `crypto/mlkem` — so no C reference is cloned or compiled; the check runs in-process.

- Reference: Go standard library [`crypto/mlkem`](https://pkg.go.dev/crypto/mlkem) (FIPS 203)
- `mlkem1024_crossverify.go` runs 1000 fresh keys and asserts:
  1. the same 64-byte seed (`d || z`) derives an identical encapsulation key in both implementations;
  2. a stdlib-produced ciphertext decapsulates to the same shared secret under go-qrllib; and
  3. a go-qrllib-produced ciphertext decapsulates to the same shared secret under the stdlib.
- Key sizes: EK=1568, seed=64, ciphertext=1568, shared secret=32 bytes

## Files

| File | Description |
|------|-------------|
| `mldsa87_sign.go` | Generate go-qrllib ML-DSA-87 signature |
| `mldsa87_verify.go` | Verify reference ML-DSA-87 signature with go-qrllib |
| `mldsa87_sign_ref.c` | Generate pq-crystals ML-DSA-87 signature |
| `mldsa87_verify_ref.c` | Verify go-qrllib ML-DSA-87 signature with pq-crystals |
| `sphincs_sign.go` | Generate go-qrllib SPHINCS+ signature |
| `sphincs_verify.go` | Verify reference SPHINCS+ signature with go-qrllib |
| `sphincs_sign_ref.c` | Generate reference SPHINCS+ signature |
| `sphincs_verify_ref.c` | Verify go-qrllib SPHINCS+ signature with reference |
| `xmss_sign.go` | Generate go-qrllib XMSS signature (forward direction) |
| `xmss_verify_ref.c` | Verify go-qrllib XMSS signature with reference (forward direction) |
| `xmss_sign_ref.c` | Generate reference XMSS signature with seeded keypair (reverse direction) |
| `xmss_verify.go` | Verify reference XMSS signature with go-qrllib via the rfc8391 sub-package (reverse direction) |
| `mlkem1024_crossverify.go` | Cross-verify go-qrllib ML-KEM-1024 against Go stdlib `crypto/mlkem` (in-process, both directions) |

## Running Locally

```bash
# ML-DSA-87
git clone https://github.com/pq-crystals/dilithium.git /tmp/mldsa-ref
cd /path/to/go-qrllib
go run .github/cross-verify/mldsa87_sign.go
cd /tmp/mldsa-ref/ref
gcc -DDILITHIUM_MODE=5 -I. -O2 -o /tmp/verify \
    /path/to/go-qrllib/.github/cross-verify/mldsa87_verify_ref.c \
    sign.c packing.c polyvec.c poly.c ntt.c reduce.c \
    rounding.c symmetric-shake.c fips202.c randombytes.c
/tmp/verify

# SPHINCS+ (SHAKE-256s-robust)
git clone --branch consistent-basew https://github.com/sphincs/sphincsplus.git /tmp/sphincs-ref
cd /path/to/go-qrllib
go run .github/cross-verify/sphincs_sign.go
cd /tmp/sphincs-ref/ref
gcc -DPARAMS=sphincs-shake-256s -DTHASH=robust -I. -O2 -o /tmp/verify \
    /path/to/go-qrllib/.github/cross-verify/sphincs_verify_ref.c \
    address.c merkle.c wots.c wotsx1.c utils.c utilsx1.c \
    fors.c sign.c hash_shake.c thash_shake_robust.c fips202.c randombytes.c
/tmp/verify

# XMSS (SHA2_10_256) - bidirectional, pinned to pre-SP-800-208 RFC 8391
git clone https://github.com/XMSS/xmss-reference.git /tmp/xmss-ref
cd /tmp/xmss-ref && git checkout 7793c40   # see "Pin rationale" above

# Forward direction: go-qrllib signs, reference verifies.
cd /path/to/go-qrllib
go run .github/cross-verify/xmss_sign.go
cd /tmp/xmss-ref
gcc -Wall -O2 -I. -o /tmp/verify \
    /path/to/go-qrllib/.github/cross-verify/xmss_verify_ref.c \
    params.c hash.c fips202.c hash_address.c randombytes.c wots.c \
    xmss.c xmss_core.c xmss_commons.c utils.c -lcrypto
/tmp/verify

# Reverse direction: reference signs (with deterministic seed), go-qrllib
# (via rfc8391) verifies. Note: randombytes.c is OMITTED from the link:
# xmss_sign_ref.c provides its own deterministic randombytes() to seed
# the reference's xmssmt_core_keypair, which has no public seeded-keypair
# API at this commit pin.
cd /tmp/xmss-ref
gcc -Wall -O2 -I. -o /tmp/sign_ref \
    /path/to/go-qrllib/.github/cross-verify/xmss_sign_ref.c \
    params.c hash.c fips202.c hash_address.c wots.c \
    xmss.c xmss_core.c xmss_commons.c utils.c -lcrypto
/tmp/sign_ref
cd /path/to/go-qrllib
go run .github/cross-verify/xmss_verify.go
```
