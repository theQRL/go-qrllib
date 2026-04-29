# Cross-Implementation Verification

This directory contains helper files for cross-implementation verification tests run by GitHub Actions.

## Overview

These tests verify that go-qrllib's signature implementations are interoperable with the authoritative reference implementations.

## Tests

### Dilithium (Round 3)
- Reference: https://github.com/pq-crystals/dilithium @ commit `ac743d5`
- Tests bidirectional signature verification
- Key sizes: PK=2592, SK=4896, Sig=4595 bytes

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
- Reference: https://github.com/XMSS/xmss-reference (RFC 8391)
- Parameters: XMSS-SHA2_10_256 (OID 0x00000001), height=10, n=32, w=16
- Tests **bidirectional** verification using the
  [`crypto/xmss/rfc8391`](../../crypto/xmss/rfc8391/) sub-package on the
  go-qrllib side.
- Key sizes: PK=64 (root||pub_seed) or 68 (RFC layout with OID),
  SK=132, Seed=48 (QRL convention) or 96 (RFC convention), Sig=2500 bytes

#### Why a sub-package was needed for the reverse direction

go-qrllib's primary `xmss.InitializeTree` entry point produces **RFC 8391 compliant signatures** (the forward direction `xmss_sign.go → xmss_verify_ref.c` has always worked), but a 48-byte seed handed to it does NOT produce the same keypair the reference would derive from a literal 96-byte seed. Two QRL-specific conventions caused this:

1. **Seed expansion**: `xmss.InitializeTree` SHAKE256-expands a 48-byte seed into the 96 bytes (SK_SEED || SK_PRF || PUB_SEED) the construction needs. The RFC 8391 reference implementation takes those 96 bytes directly with no expansion step.

2. **Public-key prefix**: QRL's extended-PK format prefixes the 32-byte root and 32-byte pub_seed with a 3-byte QRL descriptor. RFC 8391 prefixes them with a 4-byte parameter-set OID.

The [`crypto/xmss/rfc8391`](../../crypto/xmss/rfc8391/) sub-package
addresses both. `rfc8391.NewKeyPair(p, expandedSeed *[96]uint8)` takes
the 96 bytes directly, matching the reference's keypair derivation
exactly; `rfc8391.MarshalPublicKey` / `UnmarshalPublicKey` convert
between go-qrllib's internal representation and the RFC byte layout.

#### Forward direction: go-qrllib → reference

* `xmss_sign.go` (Go) — generates a keypair via the QRL `xmss.InitializeTree`
  entry point, signs, writes pk + sig + msg to `/tmp/`.
* `xmss_verify_ref.c` (C) — reads the artefacts, prepends an RFC 8391
  OID to the pk, calls `xmss_sign_open()`. **Already worked before this
  PR; signature byte layout matches at the wire level.**

#### Reverse direction: reference → go-qrllib (new)

* `xmss_sign_ref.c` (C) — calls the reference's
  `xmss_core_seed_keypair()` with a fixed 96-byte expanded seed,
  signs, writes pk (in both QRL and RFC layouts) + sig + msg +
  expanded seed to `/tmp/`.
* `xmss_verify.go` (Go) — reads the same 96-byte expanded seed,
  reconstructs the keypair via `rfc8391.NewKeyPair`, asserts the
  resulting root || pub_seed matches the reference's pk byte-for-byte,
  then verifies the signature via `rfc8391.Verify`. The pk-bytes-match
  check is the actual bidirectional-equivalence proof; signature
  verification is then a straightforward consequence.

**Note**: XMSS is a legacy algorithm in go-qrllib, maintained for QRL v1 address compatibility. For new applications, use ML-DSA-87 (FIPS 204). SLH-DSA (FIPS 205, formerly SPHINCS+) is reserved for future use in the QRL descriptor format but is not currently issuable.

## Files

| File | Description |
|------|-------------|
| `dilithium_sign.go` | Generate go-qrllib Dilithium signature |
| `dilithium_verify.go` | Verify reference Dilithium signature with go-qrllib |
| `dilithium_sign_ref.c` | Generate pq-crystals Dilithium signature |
| `dilithium_verify_ref.c` | Verify go-qrllib Dilithium signature with pq-crystals |
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

## Running Locally

```bash
# Dilithium
git clone https://github.com/pq-crystals/dilithium.git /tmp/dilithium-ref
cd /tmp/dilithium-ref && git checkout ac743d5
cd /path/to/go-qrllib
go run .github/cross-verify/dilithium_sign.go
cd /tmp/dilithium-ref/ref
gcc -DDILITHIUM_MODE=5 -I. -O2 -o /tmp/verify \
    /path/to/go-qrllib/.github/cross-verify/dilithium_verify_ref.c \
    sign.c packing.c polyvec.c poly.c ntt.c reduce.c \
    rounding.c symmetric-shake.c fips202.c randombytes.c
/tmp/verify

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

# XMSS (SHA2_10_256) - bidirectional
git clone https://github.com/XMSS/xmss-reference.git /tmp/xmss-ref

# Forward direction: go-qrllib signs, reference verifies.
cd /path/to/go-qrllib
go run .github/cross-verify/xmss_sign.go
cd /tmp/xmss-ref
gcc -Wall -O2 -I. -o /tmp/verify \
    /path/to/go-qrllib/.github/cross-verify/xmss_verify_ref.c \
    params.c hash.c fips202.c hash_address.c randombytes.c wots.c \
    xmss.c xmss_core.c xmss_commons.c utils.c -lcrypto
/tmp/verify

# Reverse direction: reference signs, go-qrllib (via rfc8391) verifies.
cd /tmp/xmss-ref
gcc -Wall -O2 -I. -o /tmp/sign_ref \
    /path/to/go-qrllib/.github/cross-verify/xmss_sign_ref.c \
    params.c hash.c fips202.c hash_address.c randombytes.c wots.c \
    xmss.c xmss_core.c xmss_commons.c utils.c -lcrypto
/tmp/sign_ref
cd /path/to/go-qrllib
go run .github/cross-verify/xmss_verify.go
```
