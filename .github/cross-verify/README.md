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

### XMSS (SHA2_10_256) - One-Directional
- Reference: https://github.com/XMSS/xmss-reference (RFC 8391)
- Parameters: XMSS-SHA2_10_256 (OID 0x00000001), height=10, n=32, w=16
- Tests **one-directional** verification only (go-qrllib → reference)
- Key sizes: PK=64, SK=132, Seed=48, Sig=2500 bytes

#### Why XMSS is One-Directional Only

go-qrllib produces **RFC 8391 compliant signatures** that are successfully verified by the reference implementation. However, round-trip verification (reference → go-qrllib) is not possible due to differences in key derivation:

1. **Seed Expansion**: go-qrllib uses a 48-byte seed expanded via SHAKE256 to derive SK_SEED, SK_PRF, and PUB_SEED (3×32 bytes). The reference implementation expects these 96 bytes of seed material directly, with no standardized expansion method.

2. **No Seeded Keypair API**: The reference implementation lacks a deterministic seeded keypair function, making it impossible to reconstruct identical keys from go-qrllib's seed components.

3. **Internal State Differences**: Even with matching seed material, the BDS tree traversal state used for efficient signing differs between implementations.

**What This Means**: External systems using the RFC 8391 reference implementation can verify signatures produced by go-qrllib. This is the critical interoperability path for a signature scheme - recipients must be able to verify signatures using standard tools.

**Note**: XMSS is a legacy algorithm in go-qrllib, maintained for QRL address compatibility. For new applications, use ML-DSA-87 (FIPS 204) or SPHINCS+ (FIPS 205).

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
| `xmss_sign.go` | Generate go-qrllib XMSS signature |
| `xmss_verify_ref.c` | Verify go-qrllib XMSS signature with reference |

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

# XMSS (SHA2_10_256) - One-directional only
git clone https://github.com/XMSS/xmss-reference.git /tmp/xmss-ref
cd /path/to/go-qrllib
go run .github/cross-verify/xmss_sign.go
cd /tmp/xmss-ref
gcc -Wall -O2 -I. -o /tmp/verify \
    /path/to/go-qrllib/.github/cross-verify/xmss_verify_ref.c \
    params.c hash.c fips202.c hash_address.c randombytes.c wots.c \
    xmss.c xmss_core.c xmss_commons.c utils.c -lcrypto
/tmp/verify
```
