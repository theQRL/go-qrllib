# Wycheproof Test Vector Verification

This directory documents the CI integration of the
[C2SP/wycheproof](https://github.com/C2SP/wycheproof) ML-DSA-87 test
vectors into go-qrllib. There is no tooling in this directory — the
test vectors are consumed directly from the upstream JSON files at
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
