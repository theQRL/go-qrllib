# Wycheproof Test Vector Verification

This directory documents the CI integration of the
[C2SP/wycheproof](https://github.com/C2SP/wycheproof) and
[C2SP/CCTV](https://github.com/C2SP/CCTV) test vectors (ML-DSA-87 and
ML-KEM-1024) into go-qrllib. There is no tooling in this directory — the
test vectors are consumed directly from the upstream files at
CI time. This page exists so reviewers can see at a glance what is
covered and how.

## How It Works

The GitHub Action (`.github/workflows/wycheproof.yml`) clones the
C2SP/wycheproof repository at its latest commit and runs go-qrllib's
ML-DSA-87 verifier against the upstream vectors. Vectors are never
vendored — they always come directly from the upstream repository.

1. **Clone**: Sparse checkout of `github.com/C2SP/wycheproof` (only
   `testvectors_v1/`).
2. **Test**: `crypto/ml_dsa_87/wycheproof_test.go` walks
   `mldsa_87_verify_test.json`, calls go-qrllib's `Verify` for each
   test vector, and asserts the result matches the expected
   `result` field.

The workflow tracks upstream `master`. If a future legitimate-failure
case appears (e.g., upstream adds a new vector class our verifier
doesn't yet handle), pin to a specific commit and bump deliberately.

## What's Tested

| Vector file | Source | Description |
|-------------|--------|-------------|
| `mldsa_87_verify_test.json` | upstream `testvectors_v1/` | ~175 ML-DSA-87 verification edge cases across ~25 keypairs: malleability, truncated/extended signatures, wrong-length public keys, context-string variants, and similar boundary conditions. |

`mldsa_87_sign_seed_test.json` and `mldsa_87_sign_noseed_test.json`
are not currently exercised — NIST ACVP already covers
seed-to-keypair and signature-determinism in CI, and the
sign-noseed path uses sk formats not currently consumed by
go-qrllib. They could be added later if a coverage gap appears.

## ML-KEM-1024

ML-KEM-1024 (`crypto/internal/mlkem1024`) is verified against two upstreams,
both consumed directly at CI time by the `mlkem1024-wycheproof` job. The harness
lives in `crypto/internal/mlkem1024/wycheproof_test.go`; it is an in-package
test because the derandomised encapsulation vectors need the test-only
`EncapsulateInternal` entry point.

1. **C2SP/wycheproof** `testvectors_v1/mlkem_1024_*.json` (via
   `WYCHEPROOF_VECTORS_DIR`):

   | Vector file | What it exercises |
   |-------------|-------------------|
   | `mlkem_1024_keygen_seed_test.json` | seed (`d‖z`) → encapsulation-key derivation (100 vectors) |
   | `mlkem_1024_encaps_test.json` | derandomised encapsulation (`ek`,`m` → `c`,`K`) and encapsulation-key validation, incl. `ModulusOverflow` rejections (~270 vectors) |
   | `mlkem_1024_test.json` | decapsulation (`seed`,`c` → `K`), incl. implicit-rejection and `Strcmp` constant-time-comparison edge cases, plus structural rejections (~190 vectors) |

   `mlkem_1024_semi_expanded_decaps_test.json` is **not** consumed — it uses the
   3168-byte expanded decapsulation-key format, while go-qrllib loads the
   64-byte seed form.

2. **C2SP/CCTV** `ML-KEM/modulus/ML-KEM-1024.txt.gz` (via `CCTV_VECTORS_DIR`):
   1040 invalid encapsulation keys, each with one coefficient forced into
   `[q, 2¹²-1]` at every position — all must be rejected by the `byteDecode12`
   modulus check. This is the exhaustive counterpart to wycheproof's
   `ModulusOverflow` cases.

NIST ACVP functional vectors (KeyGen / Encaps / Decaps / key-checks) and the
CCTV accumulated 10,000-iteration hash already run in the normal test suite
(`crypto/internal/mlkem1024/acvp_test.go`, `crypto/mlkem1024/mlkem1024_test.go`),
so they are not duplicated here.

Run locally:

```bash
git clone --depth 1 https://github.com/C2SP/wycheproof.git /tmp/wycheproof
git clone --depth 1 https://github.com/C2SP/CCTV.git /tmp/cctv
WYCHEPROOF_VECTORS_DIR=/tmp/wycheproof/testvectors_v1 \
  CCTV_VECTORS_DIR=/tmp/cctv/ML-KEM \
  go test -v -tags wycheproof -run 'TestWycheproofMLKEM|TestCCTVMLKEM' ./crypto/internal/mlkem1024/
```

## Result-Field Semantics

Wycheproof's `result` field has three values:

| Value | go-qrllib expectation |
|-------|----------------------|
| `valid` | `Verify` must return `true`. Test fails if it doesn't. |
| `invalid` | `Verify` must return `false`. Test fails if it returns `true`. |
| `acceptable` | Either outcome is permitted by the spec — typically used for malleability cases where the standard allows either reading. We log the observed outcome but do not fail. |

Wrong-length signatures and wrong-length public keys are rejected at
the API boundary (go-qrllib's `Verify` takes fixed-size arrays); the
test runner mirrors that and treats them as `Verify`-returns-false.

## Running Locally

```bash
# Clone the wycheproof repo (full or sparse)
git clone --depth 1 https://github.com/C2SP/wycheproof.git /tmp/wycheproof

# Run the tests
WYCHEPROOF_VECTORS_DIR=/tmp/wycheproof/testvectors_v1 \
  go test -v -tags wycheproof -run TestWycheproof ./crypto/ml_dsa_87/
```

## Build Tag

The wycheproof tests are gated behind a `wycheproof` build tag so
they don't run during normal `go test ./...`. This keeps day-to-day
iteration fast (the verify file is ~25 MB and 175 verifications take
a few seconds) and avoids requiring the upstream repo to be present.
