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
| **SPHINCS+-256s** | Hash-based | FIPS 205 | Stateless, conservative security |
| **XMSS** | Hash-based | RFC 8391 | Legacy QRL addresses |

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

**For new applications, prefer ML-DSA-87 or SPHINCS+ which are stateless.**

---

## Installation

```bash
go get github.com/theQRL/go-qrllib
```

Requires Go 1.21 or later.

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
message := []byte("Hello, quantum-safe world!")
signature, err := signer.Sign(ctx, message)
if err != nil {
    log.Fatal(err)
}

// Verify
pk := signer.GetPK()
valid := ml_dsa_87.Verify(ctx, message, signature, &pk)
```

### SPHINCS+-256s (Stateless, Conservative)

```go
import "github.com/theQRL/go-qrllib/crypto/sphincsplus_256s"

signer, err := sphincsplus_256s.New()
if err != nil {
    log.Fatal(err)
}
defer signer.Zeroize()

message := []byte("Hello, quantum-safe world!")
signature, err := signer.Sign(message)
if err != nil {
    log.Fatal(err)
}

pk := signer.GetPK()
valid := sphincsplus_256s.Verify(message, signature, &pk)
```

### Wallet Layer (QRL Blockchain)

For QRL blockchain applications, use the wallet packages which handle address generation and descriptor formatting:

```go
import "github.com/theQRL/go-qrllib/wallet/ml_dsa_87"

wallet, err := ml_dsa_87.NewWallet()
if err != nil {
    log.Fatal(err)
}

address := wallet.GetAddress()
signature, err := wallet.Sign(message)
```

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
| Maximum security, don't trust lattice assumptions | SPHINCS+-256s |
| QRL blockchain transactions | ML-DSA-87 (via wallet layer) |
| Legacy QRL address compatibility | XMSS (with extreme care) |
| Signatures must be deterministic | ML-DSA-87 (default), Dilithium |

### Key Sizes

| Algorithm | Public Key | Secret Key | Signature |
|-----------|------------|------------|-----------|
| ML-DSA-87 | 2,592 bytes | 4,896 bytes | 4,627 bytes |
| Dilithium | 2,592 bytes | 4,896 bytes | 4,595 bytes |
| SPHINCS+-256s | 64 bytes | 128 bytes | 29,792 bytes |
| XMSS (h=10) | 64 bytes | ~2,500 bytes | ~2,500 bytes |

---

## Standards Compliance

- **ML-DSA-87**: FIPS 204 (Module-Lattice-Based Digital Signature Standard)
- **SPHINCS+-256s**: FIPS 205 (Stateless Hash-Based Digital Signature Standard)
- **XMSS**: RFC 8391 (XMSS: eXtended Merkle Signature Scheme)
- **Dilithium**: CRYSTALS-Dilithium (pre-FIPS version)

---

## Security Considerations

1. **Zeroize sensitive data** - Always call `Zeroize()` when done with a signer
2. **Use crypto/rand** - Never use weak random sources for key generation
3. **Context separation** - Use unique contexts for different applications (ML-DSA-87)
4. **XMSS state** - See critical warning above
5. **Side channels** - This library uses constant-time operations where applicable

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
