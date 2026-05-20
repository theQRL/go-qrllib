# go-qrllib

Go implementation of the Quantum Resistant Ledger (QRL) cryptographic library.

[![Go Reference](https://pkg.go.dev/badge/github.com/theQRL/go-qrllib.svg)](https://pkg.go.dev/github.com/theQRL/go-qrllib)
[![Go Report Card](https://goreportcard.com/badge/github.com/theQRL/go-qrllib)](https://goreportcard.com/report/github.com/theQRL/go-qrllib)
[![codecov](https://codecov.io/gh/theQRL/go-qrllib/branch/main/graph/badge.svg)](https://codecov.io/gh/theQRL/go-qrllib)

## Overview

go-qrllib provides post-quantum cryptographic signature schemes for the QRL blockchain and general-purpose applications requiring quantum-resistant security.

### Supported Algorithms

| Algorithm | Type | Standard | Use Case |
|-----------|------|----------|----------|
| **ML-DSA-87** | Lattice-based | FIPS 204 | Primary recommended algorithm |
| **Dilithium** | Lattice-based | Pre-FIPS | Legacy compatibility |
| **SPHINCS+-256s** | Hash-based | SPHINCS+ submission (pre-FIPS 205) — see SPHINCS+ notes | Stateless primitive; wallet path gated pending QRL's SLH-DSA parameter-set choice |
| **XMSS** | Hash-based | Pre-standardisation; see XMSS notes | QRL v1 → v2 migration |

---

## CRITICAL: XMSS Statefulness Warning

> **XMSS is a STATEFUL signature scheme. Improper use can lead to COMPLETE LOSS OF SECURITY.**

### The Risk

XMSS maintains an internal index that **MUST** be incremented after each signature. If the same index is ever used twice (even for different messages), an attacker can forge signatures for ANY message.

### Requirements for Safe XMSS Usage

1. **Never reuse an index** - Each signature MUST use a unique, never-before-used index
2. **Persist state before use** - To prevent OTS key reuse, the updated index MUST be persisted to durable storage immediately after signing and BEFORE the signature is used or broadcast
3. **No concurrent signing** - Never sign from the same XMSS instance concurrently
4. **No state rollback** - Never restore an XMSS wallet from backup without extreme care
5. **Index exhaustion** - An XMSS tree has limited signatures (2^height); plan for key rotation

### Safe Pattern

```go
// CORRECT: Sign, then persist updated index before using the signature
height, err := xmss.ToHeight(10)
if err != nil {
    return err
}

tree, err := xmss.InitializeTree(height, xmss.SHAKE_128, seed)
if err != nil {
    return err
}

signature, err := tree.Sign(message)
if err != nil {
    return err
}

// CRITICAL: Persist the UPDATED index NOW. If this fails, the signature MUST NOT be used.
err = persistIndex(tree.GetIndex()) // Save to database/file
if err != nil {
    return fmt.Errorf("failed to persist state (signature unsafe to use): %w", err)
}

// Only now is it safe to broadcast/use the signature
broadcast(signature)
```

### Unsafe Patterns to Avoid

```go
// DANGEROUS: Concurrent signing from same instance
go wallet.Sign(msg1)  // Race condition - index corruption
go wallet.Sign(msg2)

// DANGEROUS: Restoring from backup
backup := loadBackup()  // May have old index
wallet := restoreFromBackup(backup)
wallet.Sign(msg)  // May reuse an index!

// DANGEROUS: Ignoring persistence failures
sig, _ := wallet.Sign(msg)
_ = persistState(wallet)  // Ignoring error!
broadcast(sig)  // Index may not be persisted
```

**For new applications, prefer the stateless ML-DSA-87.** SPHINCS+-256s remains available
as a primitive but the QRL wallet path for SPHINCS+/SLH-DSA is intentionally gated until
NIST and QRL settle on a final SLH-DSA parameter set; see the SPHINCS+ notes below.

### Same requirements at every API level

The persistence requirement applies identically whether you call:

- `crypto/xmss.XMSS.Sign` — the lower-level primitive shown in the example above, or
- `legacywallet/xmss.XMSSWallet.Sign` — the wallet-level wrapper used to sign for legacy QRL v1 addresses.

Both must persist the updated index (`tree.GetIndex()` or `wallet.GetIndex()` respectively) **AFTER** the call returns and **BEFORE** the signature is used or broadcast. The wallet wrapper is a thin delegate over the primitive — it carries the same statefulness invariants. See the godoc on each `Sign` method and the package documentation for [`legacywallet/xmss`](legacywallet/xmss/doc.go) for the full safe-usage pattern.

---

## Installation

```bash
go get github.com/theQRL/go-qrllib
```

Requires Go 1.25 or later.

## Quick Start

### ML-DSA-87 (Recommended)

```go
import "github.com/theQRL/go-qrllib/crypto/ml_dsa_87"

// Generate keypair
signer, err := ml_dsa_87.New()
if err != nil {
    log.Fatal(err)
}
defer signer.Zeroize() // Clear sensitive data when done

// Sign with context (required by FIPS 204)
ctx := []byte("my-application")
message := []byte("The sleeper must awaken")
signature, err := signer.Sign(ctx, message)
if err != nil {
    log.Fatal(err)
}

// Verify
pk := signer.GetPK()
valid := ml_dsa_87.Verify(ctx, message, signature, &pk)
```

### SPHINCS+-256s (primitive; wallet path gated)

The example below uses the raw SPHINCS+-256s primitive directly. The QRL
wallet layer for SPHINCS+/SLH-DSA is intentionally not currently issuable:
the implementation here is the SPHINCS+ submission (pre-FIPS 205), and QRL
has not yet committed to a specific SLH-DSA parameter set under FIPS 205,
so activating the wallet path now would commit users to a parameter set
that may change. See the SPHINCS+ notes in [Standards Compliance](#standards-compliance).

```go
import "github.com/theQRL/go-qrllib/crypto/sphincsplus_256s"

signer, err := sphincsplus_256s.New()
if err != nil {
    log.Fatal(err)
}
defer signer.Zeroize()

message := []byte("The sleeper must awaken")
signature, err := signer.Sign(message)
if err != nil {
    log.Fatal(err)
}

pk := signer.GetPK()
valid := sphincsplus_256s.Verify(message, signature, &pk)
```

### Wallet Layer (QRL V2.0)

The wallet packages wrap the crypto primitives with QRL-specific address derivation, a canonical descriptor, and a domain-separated signing context that cryptographically binds every signature to its wallet descriptor (see package docs for details).

```go
import "github.com/theQRL/go-qrllib/wallet/ml_dsa_87"

// Create a fresh wallet, or restore from a mnemonic / extended seed.
w, err := ml_dsa_87.NewWallet()
// w, err := ml_dsa_87.NewWalletFromMnemonic(phrase)
// w, err := ml_dsa_87.NewWalletFromHexExtendedSeed(hexSeed)
if err != nil {
    log.Fatal(err)
}
defer w.Zeroize()

address := w.GetAddressStr()              // "Q" + hex(64 bytes)
pk      := w.GetPK()
desc    := w.GetDescriptor().ToDescriptor()

sig, err := w.Sign(message)
if err != nil {
    log.Fatal(err)
}

ok := ml_dsa_87.Verify(message, sig[:], &pk, desc)
```

The same API shape is available at `github.com/theQRL/go-qrllib/wallet/sphincsplus_256s`,
but note that the QRL wallet layer currently treats SPHINCS+/SLH-DSA as **non-issuable**
(it remains verifiable, so existing addresses keep working): wallet creation under that
type is gated until the QRL-adopted SLH-DSA parameter set is finalised. See the SPHINCS+
notes below and `wallet/common/wallettype/type.go` for the `IsIssuable` / `IsVerifiable`
split.

### `crypto.Signer` Interface (ML-DSA-87)

ML-DSA-87 implements Go's `crypto.Signer` interface for interoperability with `crypto/tls`, `crypto/x509`, and other standard library consumers:

```go
import "github.com/theQRL/go-qrllib/crypto/ml_dsa_87"

d, err := ml_dsa_87.New()
if err != nil {
    log.Fatal(err)
}
defer d.Zeroize()

signer := ml_dsa_87.NewCryptoSigner(d)
// signer satisfies crypto.Signer

// Sign with FIPS 204 context via SignerOpts
sig, err := signer.Sign(nil, message, &ml_dsa_87.SignerOpts{
    Context: []byte("my-application"),
})
```

The `opts` parameter must be `*ml_dsa_87.SignerOpts` or `nil` (empty context). Passing other `crypto.SignerOpts` types (e.g., `crypto.SHA256`) returns an error.

### Address String Format

QRL addresses are commonly displayed with a leading "Q" prefix followed by the hex
encoded address bytes. This is a convention across legacy and modern tooling,
but not every API in this library emits the "Q" prefix directly.

---

## Thread Safety

| Type | Thread-Safe? | Notes |
|------|--------------|-------|
| `ml_dsa_87.MLDSA87` | Read: Yes, Write: No | Safe to call `GetPK()`, `Verify()` concurrently. Do not call `Sign()` concurrently on same instance. |
| `dilithium.Dilithium` | Read: Yes, Write: No | Same as ML-DSA-87 |
| `sphincsplus_256s.SphincsPlus256s` | Read: Yes, Write: No | Same as ML-DSA-87 |
| `xmss.XMSS` | **No** | NEVER use concurrently. Index management is not thread-safe. |
| Package-level `Verify()` | Yes | Stateless, safe to call concurrently |
| `dilithium.SignWithSecretKey()` | Yes | Stateless function, safe with different keys |

### Safe Concurrent Pattern

```go
// Create separate instances for concurrent signing
func signConcurrently(messages [][]byte, seed [32]byte) {
    var wg sync.WaitGroup
    for _, msg := range messages {
        wg.Add(1)
        go func(m []byte) {
            defer wg.Done()
            // Create NEW instance for each goroutine
            signer, _ := ml_dsa_87.NewMLDSA87FromSeed(seed)
            defer signer.Zeroize()
            signer.Sign(ctx, m)
        }(msg)
    }
    wg.Wait()
}
```

---

## Algorithm Selection Guide

| Requirement | Recommended Algorithm |
|-------------|----------------------|
| General purpose, best performance | ML-DSA-87 |
| Maximum security, don't trust lattice assumptions | SPHINCS+-256s primitive (wallet path gated, see notes) |
| QRL blockchain transactions | ML-DSA-87 (via wallet layer) |
| Legacy QRL address compatibility | XMSS (with extreme care) |
| Signatures must be deterministic (e.g. RANDAO-style verifiable beacon contributions) | ML-DSA-87 via the `SignDeterministic(ctx, msg)` opt-in helper (FIPS 204 deterministic mode) — `Sign` itself is hedged by default as per FIPS 204. Dilithium also remains deterministic. |

### Key Sizes

| Algorithm | Public Key | Secret Key | Signature |
|-----------|------------|------------|-----------|
| ML-DSA-87 | 2,592 bytes | 4,896 bytes | 4,627 bytes |
| Dilithium | 2,592 bytes | 4,896 bytes | 4,595 bytes |
| SPHINCS+-256s | 64 bytes | 128 bytes | 29,792 bytes |
| XMSS (h=10) | 64 bytes | ~2,500 bytes | ~2,500 bytes |

---

## NIST ACVP Verification

ML-DSA-87 key generation and signing are verified against official [NIST ACVP test vectors](https://github.com/usnistgov/ACVP-Server). These tests run automatically in CI and are guarded by a build tag so they don't run during normal `go test ./...`.

To run them locally, see [`.github/acvp/README.md`](.github/acvp/README.md).

---

## Standards Compliance

- **ML-DSA-87**: FIPS 204 (Module-Lattice-Based Digital Signature Standard)
- **SPHINCS+-256s** (notes): The implementation in this library is the **SPHINCS+
  submission** (pre-FIPS 205), specifically `SHAKE-256s-robust`. NIST published
  [SLH-DSA (FIPS 205)](https://csrc.nist.gov/pubs/fips/205/final) in August 2024 as
  the standardised successor; FIPS 205 differs from the SPHINCS+ submission in
  parameter-set details. The QRL wallet layer **does not currently issue new
  SPHINCS+/SLH-DSA wallets**: the wallet type is retained as a reserved constant,
  but common wallet descriptor/type validation rejects it until QRL settles on a
  specific SLH-DSA parameter set and the implementation is updated to match it. Existing
  SPHINCS+-256s primitive use (the `crypto/sphincsplus_256s` package, outside the
  wallet layer) remains supported with the caveat that the parameter set may
  change once SLH-DSA finalises for QRL. **For new wallets, use ML-DSA-87.**
- **XMSS**: This library's XMSS implementation **predates RFC 8391**
  (published August 2018) and was built to support the QRL v1 blockchain at
  launch. It is **not intended as a general RFC-compliant XMSS implementation**;
  its role here is to keep v1 mainnet addresses parseable, verifiable, and
  signable during the v1 → v2 migration. Where parameter-set choices happen to
  overlap with RFC 8391 (XMSS-SHA2_10_256 and XMSS-SHAKE_256_10_256), signatures
  produced by go-qrllib verify under the RFC 8391 reference implementation, and
  reference signatures verify under go-qrllib via the
  [`crypto/xmss/rfc8391`](crypto/xmss/rfc8391/) sub-package. This is exercised
  bidirectionally in CI by [`.github/cross-verify/`](.github/cross-verify/README.md),
  pinned to the original RFC 8391 reference. The library does not track later
  standards updates such as NIST SP 800-208 (October 2020), which refined
  `expand_seed` to take additional inputs. Adopting that refinement would
  change the keypair derived from any given seed and break compatibility with
  existing v1 mainnet addresses, so it is intentionally not applied here. New
  signature issuance on QRL uses **ML-DSA-87 (FIPS 204)**.
  **`SHAKE_128`** is a pre-standardisation QRL-specific hash variant, retained
  for v1 mainnet address compatibility only. See
  [SECURITY.md](SECURITY.md#parameter-set-provenance) for the full provenance
  discussion.
- **Dilithium**: CRYSTALS-Dilithium (pre-FIPS version)

---

## Security Considerations

1. **Zeroize sensitive data** - Always call `Zeroize()` when done with a signer
2. **Use crypto/rand** - Never use weak random sources for key generation
3. **Context separation** - Use unique contexts for different applications (ML-DSA-87)
4. **XMSS state** - See critical warning above
5. **Side channels** - Signing and verification use branchless arithmetic and constant-time comparisons; see [SECURITY.md](SECURITY.md) for precise boundaries

See [SECURITY.md](SECURITY.md) for detailed security information and threat model.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`make test` or `go test ./...`)
- Note: SPHINCS+ wallet tests are slow (~3-4 minutes); use `make test-fast` for quicker iteration.
- Code is linted (`make lint`)
- No new security vulnerabilities (`make vulncheck`)

To install development tools (golangci-lint, govulncheck):
```bash
make tools
```
