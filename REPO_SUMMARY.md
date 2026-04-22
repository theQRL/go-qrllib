# Repository Summary

## Overview

`go-qrllib` is a Go 1.24+ implementation of the Quantum Resistant Ledger cryptographic library. Its main scope is post-quantum signatures plus QRL-specific wallet and address handling.

Primary areas:

- `crypto/`: core signature implementations
- `wallet/`: wallet/address/descriptor support for current algorithms
- `legacywallet/`: legacy XMSS compatibility
- `common/`, `misc/`, `qrl/`: shared helpers and supporting types

Supported algorithms, as described in [`README.md`](./README.md):

- ML-DSA-87: recommended primary algorithm
- Dilithium: legacy pre-FIPS compatibility
- SPHINCS+-256s: stateless conservative option
- XMSS: legacy QRL compatibility, with strong statefulness caveats

The main integrity and QA checks are implemented in GitHub Actions under [`.github/workflows/`](./.github/workflows/).

## Test Suite

The repository currently contains:

- 20 Go packages
- 65 `_test.go` files
- about 511 `Test*` cases
- 18 fuzz targets
- 17 benchmarks

Coverage areas include:

- core crypto behaviour for Dilithium, ML-DSA-87, SPHINCS+, and XMSS
- wallet generation, signing, verification, address formatting, and descriptor handling
- legacy XMSS wallet compatibility
- mnemonic and seed conversion helpers
- negative-path and malformed-input handling
- canonicality tests for rejecting invalid signatures
- edge-case tests
- thread-safety and race-oriented tests
- known-answer tests
- microbenchmarks for performance-sensitive crypto paths

The largest test concentration is in:

- `crypto/sphincsplus_256s`
- `crypto/ml_dsa_87`
- `crypto/xmss`
- `crypto/dilithium`
- `wallet/ml_dsa_87`
- `wallet/sphincsplus_256s`

Useful local targets are defined in [`Makefile`](./Makefile):

- `make test`
- `make test-race`
- `make test-coverage`
- `make test-kat`
- `make test-edge`
- `make test-thread`
- `make fuzz` / `make fuzz-quick`
- `make bench`

## Integrity And QA Checks

### 1. Main Test Workflow

[`test.yml`](./.github/workflows/test.yml) runs on every push and pull request.

It performs:

- Go matrix testing on `1.24.x` and `1.25.x`
- `go mod verify`
- dependency fetch via `go get -v ./...`
- full build via `go build -v ./...`
- full test run via `go test -v ./...`
- atomic coverage generation
- coverage exclusion post-processing with `go-ignore-cov` on Go `1.25.x`
- race-detector execution via `go test -race -short -v ./...`
- per-target fuzz execution for 10 seconds on Go `1.25.x`
- Codecov upload on pushes from the main repository

### 2. Lint And Static Analysis

[`lint.yml`](./.github/workflows/lint.yml) runs on push and pull request and defines three separate jobs:

- `golangci-lint`
- `shadow`
- `ineffassign`

The `golangci-lint` configuration in [`.golangci.yml`](./.golangci.yml) enables:

- `errcheck`
- `govet`
- `ineffassign`
- `staticcheck`

This gives the repo a layered static analysis setup rather than relying on a single lint pass.

### 3. Security Checks

[`security.yml`](./.github/workflows/security.yml) runs on push and pull request.

Always-run jobs:

- `govulncheck` for Go vulnerability scanning
- `gosec` for source-level security analysis

Conditional job:

- `nancy` for dependency vulnerability scanning, only on `main` pushes when `ENABLE_NANCY == true`

The `gosec` invocation intentionally excludes some known crypto-code false positives (`G602`, `G115`) and excludes test files.

### 4. GitHub Actions Integrity

[`actionlint.yml`](./.github/workflows/actionlint.yml) validates workflow files themselves.

It runs:

- on pushes to `main`/`master` that touch `.github/workflows/**`
- on pull requests to `main`/`master` that touch `.github/workflows/**`
- on manual dispatch

### 5. Cryptographic Cross-Verification

[`cross-verify.yml`](./.github/workflows/cross-verify.yml) adds a stronger integrity layer than normal unit tests by checking interoperability with external reference implementations.

It covers:

- Dilithium against `pq-crystals/dilithium` Round 3 reference
- ML-DSA-87 against the current `pq-crystals/dilithium` FIPS 204 path
- SPHINCS+ against the `sphincsplus` `consistent-basew` branch
- XMSS against the `xmss-reference` implementation

Directionality:

- Dilithium, ML-DSA-87, and SPHINCS+ are bidirectional
- XMSS is one-directional only: `go-qrllib -> reference`

### 6. NIST ACVP Validation

[`acvp.yml`](./.github/workflows/acvp.yml) runs ML-DSA-87 against official NIST ACVP vector data.

The workflow:

- sparsely clones the latest `usnistgov/ACVP-Server`
- extracts ML-DSA keygen and siggen vectors
- merges prompt and expected-result JSON through `.github/acvp/merge_vectors.py`
- runs `go test -tags acvp -run TestACVP ./crypto/ml_dsa_87/`

### 7. Release And Supply-Chain Integrity

[`release.yml`](./.github/workflows/release.yml) is triggered from the successful completion of the `Test`, `Lint`, and `Security` workflows on `main`.

It provides:

- semantic-release driven versioning
- SHA-256 and SHA-512 checksum generation
- SPDX and CycloneDX SBOM generation
- GitHub/Sigstore-backed attestations
- direct attestations for `go.mod` and `go.sum`
- SLSA provenance generation and upload

### 8. Dependency Hygiene

[`.github/dependabot.yml`](./.github/dependabot.yml) enables weekly updates for:

- Go modules
- GitHub Actions
