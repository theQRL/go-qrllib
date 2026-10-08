# Cross-Implementation Verification

This directory contains helper files for cross-implementation verification tests
run by GitHub Actions.

## Overview

These tests verify that go-qrllib's signature implementations are interoperable
with the authoritative reference implementations. The ML-KEM-1024 KEM is
additionally cross-verified against the Go standard library's FIPS 203-validated
`crypto/mlkem`.

## Tests

### ML-DSA-87 (FIPS 204)

- Reference: <https://github.com/pq-crystals/dilithium> (current master)
- Tests bidirectional signature verification with context parameter
- Key sizes: PK=2592, SK=4896, Sig=4627 bytes

### SPHINCS+ (SHAKE-256s-robust)

- Reference: <https://github.com/sphincs/sphincsplus> @ branch
  `consistent-basew`
- Parameters: PARAMS=sphincs-shake-256s THASH=robust
- Tests bidirectional signature verification
- Key sizes: PK=64, SK=128, Seed=96, Sig=29792 bytes
- Note: Uses `consistent-basew` branch which has the corrected FORS index
  decoding (see [NIST PQC Forum
  discussion](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/88tuvtb7nN4/m/DA1QCoJWBAAJ))

### XMSS (SHA2_10_256) - Bidirectional via the rfc8391 sub-package

- Reference: <https://github.com/XMSS/xmss-reference> @ commit `7793c40`
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

go-qrllib's primary `xmss.InitializeTree` entry point produces signatures whose
**wire format matches RFC 8391** (the forward direction `xmss_sign.go →
xmss_verify_ref.c` has always worked), but a 48-byte seed handed to it does NOT
produce the same keypair the reference would derive from a literal 96-byte seed.
Two QRL-specific conventions caused this:

1. **Seed expansion**: `xmss.InitializeTree` SHAKE256-expands a 48-byte seed
   into the 96 bytes (SK_SEED || SK_PRF || PUB_SEED) the construction needs. The
   RFC 8391 reference implementation takes those 96 bytes directly with no
   expansion step.

2. **Public-key prefix**: QRL's extended-PK format prefixes the 32-byte root and
   32-byte pub_seed with a 3-byte QRL descriptor. RFC 8391 prefixes them with a
   4-byte parameter-set OID.

The [`crypto/xmss/rfc8391`](../../crypto/xmss/rfc8391/) sub-package
addresses both. `rfc8391.NewKeyPair(p, expandedSeed *[96]uint8)` takes
the 96 bytes directly, matching the reference's keypair derivation
exactly; `rfc8391.MarshalPublicKey` / `UnmarshalPublicKey` convert
between go-qrllib's internal representation and the RFC byte layout.

#### Forward direction: go-qrllib → reference

- `xmss_sign.go` (Go) generates a keypair via the QRL `xmss.InitializeTree`
  entry point, signs, writes pk + sig + msg to `/tmp/`.
- `xmss_verify_ref.c` (C) reads the artefacts, prepends an RFC 8391
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

**Note**: XMSS in this library is a legacy algorithm: QRL's XMSS implementation
predates RFC 8391 (Aug 2018), and the package is maintained as a v1 → v2
migration shim so QRL v1 mainnet addresses remain parseable, verifiable, and
signable. For new applications, use ML-DSA-87 (FIPS 204). SLH-DSA (FIPS 205,
formerly SPHINCS+) is reserved as a wallet type in the QRL descriptor format but
is not currently issuable.

FIPS 205 itself is settled: NIST finalized it in August 2024, and it specifies
twelve parameter sets (SHA2 and SHAKE, at 128/192/256 bits, each in a fast `f`
and small `s` variant). What is undetermined is QRL's choice among them, not
the standard. The implementation cross-verified here is the pre-FIPS-205
SPHINCS+ submission at `SHAKE-256s-robust`, and FIPS 205 standardizes only the
simple instantiation — so this parameter set is not one of the twelve.
Activating the wallet path therefore means first selecting a standardized
parameter set and updating the implementation to match; doing it now would
commit users to a choice QRL has not made.

### Falcon-1024 (round-3 reference, via PQClean)

- Reference: <https://github.com/PQClean/PQClean> `crypto_sign/falcon-1024/clean`
  at commit `0586a824fc0d49df0b6b6e9179d8d15d06d0974f` (pinned in the
  workflow; bump it deliberately). This is the Falcon round-3 reference code
  behind the NIST API: integer-emulated floating point and the `sign_dyn`
  signer, which go-qrllib reproduces bit for bit.
- The job also runs the Falcon test suite on each matrix target before the
  comparison. amd64 fuses only `x*y+z`; arm64 also fuses the subtract forms,
  so the fusion-boundary tests and the KAT must run on both.
- Both sides draw every random byte from the same SHAKE256 stream (the C
  harness defines `randombytes()` over PQClean's SHAKE256), so the check is
  stronger than mutual verification: for 8 entries it requires byte-identical
  public keys, private keys, signed messages (the NIST `crypto_sign` form) and
  detached signatures (the compressed form) from both implementations, in
  both directions, and then opens and verifies each side's output with the
  other.
- Runs on amd64 (`GOAMD64=v1`, which never fuses multiply-adds), on amd64
  with `GOAMD64=v3` and on an arm64 runner. The last two targets would fuse
  multiply-adds unless the code prevents it, which the Go sampler does with
  explicit conversions; running there checks that the guards hold.
- Key sizes: PK=1793, SK=2305 bytes; signed message overhead at most 1462,
  detached signature at most 1462 bytes. At the pinned commit PQClean's
  `crypto_sign_signature` allows a 1,421-byte compressed body (1,462 bytes in
  total), the same maximum as go-qrllib's `SignDetached`.

### ML-KEM-1024 (FIPS 203) — vs Go stdlib `crypto/mlkem`

ML-KEM-1024 is a key-encapsulation mechanism, not a signature, so
cross-verification checks **shared-secret agreement** rather than signature
interoperability. The reference is an independent Go implementation — the
standard library's FIPS 203-validated `crypto/mlkem` — so no C reference is
cloned or compiled; the check runs in-process.

- Reference: Go standard library
  [`crypto/mlkem`](https://pkg.go.dev/crypto/mlkem) (FIPS 203)
- `mlkem1024_crossverify.go` runs 1000 fresh keys and asserts:
  1. the same 64-byte seed (`d || z`) derives an identical encapsulation key in
     both implementations;
  2. a stdlib-produced ciphertext decapsulates to the same shared secret under
     go-qrllib; and
  3. a go-qrllib-produced ciphertext decapsulates to the same shared secret
     under the stdlib.
- Key sizes: EK=1568, seed=64, ciphertext=1568, shared secret=32 bytes

## Files

| File | Description |
| --- | --- |
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
| `falcon1024_crossverify.go` | Generate go-qrllib Falcon-1024 keys and signatures from a shared stream, and regenerate/compare/verify PQClean's |
| `falcon1024_crossverify_ref.c` | Regenerate/compare/verify go-qrllib's Falcon-1024 output with PQClean, and generate PQClean's own |

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

# Falcon-1024 (bidirectional, byte-identical from a shared stream)
# Pinned to the same PQClean commit as CI.
git init /tmp/pqclean
cd /tmp/pqclean && git remote add origin https://github.com/PQClean/PQClean.git
git sparse-checkout init --cone && \
    git sparse-checkout set crypto_sign/falcon-1024/clean common
git fetch --depth 1 --filter=blob:none origin 0586a824fc0d49df0b6b6e9179d8d15d06d0974f
git checkout FETCH_HEAD
cd /path/to/go-qrllib
go run .github/cross-verify/falcon1024_crossverify.go generate /tmp/falcon1024_go.bin
cd /tmp/pqclean
# common/randombytes.c is OMITTED: the harness defines its own randombytes().
gcc -std=c99 -O2 -Icrypto_sign/falcon-1024/clean -Icommon -o /tmp/falcon1024_ref \
    /path/to/go-qrllib/.github/cross-verify/falcon1024_crossverify_ref.c \
    crypto_sign/falcon-1024/clean/codec.c crypto_sign/falcon-1024/clean/common.c \
    crypto_sign/falcon-1024/clean/fft.c crypto_sign/falcon-1024/clean/fpr.c \
    crypto_sign/falcon-1024/clean/keygen.c crypto_sign/falcon-1024/clean/pqclean.c \
    crypto_sign/falcon-1024/clean/rng.c crypto_sign/falcon-1024/clean/sign.c \
    crypto_sign/falcon-1024/clean/vrfy.c common/fips202.c
/tmp/falcon1024_ref /tmp/falcon1024_go.bin /tmp/falcon1024_ref.bin
cd /path/to/go-qrllib
go run .github/cross-verify/falcon1024_crossverify.go check /tmp/falcon1024_ref.bin

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
