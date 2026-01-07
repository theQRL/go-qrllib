# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in go-qrllib, please report it responsibly:

1. **Do NOT open a public issue**
2. Email security concerns to [security@theqrl.org](mailto:security@theqrl.org)
3. Or report via [https://www.theqrl.org/security-report/](https://www.theqrl.org/security-report/)
4. Include detailed steps to reproduce
5. Allow reasonable time for a fix before public disclosure

---

## Threat Model

### Assumptions

This library assumes:

1. **Trusted execution environment** - The code runs on a system not compromised by malware
2. **Secure random source** - `crypto/rand` provides cryptographically secure randomness
3. **No physical access attacks** - Attacker cannot probe hardware or extract memory
4. **Correct usage** - Caller follows documented usage patterns (especially for XMSS)

### What This Library Protects Against

| Threat | Protection |
|--------|------------|
| Quantum computer attacks on signatures | Post-quantum algorithms (ML-DSA, SPHINCS+, XMSS) |
| Signature forgery | Cryptographic hardness assumptions |
| Timing side-channels in verification | Constant-time comparisons |
| Key material in memory after use | `Zeroize()` methods |
| Non-canonical signature acceptance | Strict signature validation |

### What This Library Does NOT Protect Against

| Threat | Mitigation |
|--------|------------|
| Compromised system/malware | Use hardware security modules |
| Side-channel attacks on signing | Out of scope for pure Go |
| XMSS index reuse | Caller must manage state correctly |
| Weak random number generation | Ensure `crypto/rand` works correctly |
| Memory not being zeroed by GC | Go limitation; use with HSM for high security |

---

## Security Properties by Algorithm

### ML-DSA-87 (FIPS 204)

| Property | Status |
|----------|--------|
| Post-quantum secure | Yes (Module-LWE assumption) |
| EUF-CMA secure | Yes |
| Deterministic signing | Default (optional randomized) |
| Stateless | Yes |
| Side-channel resistant | Constant-time where applicable |
| Signature malleability | No (canonical encoding enforced) |

**Security Level**: NIST Level 5 (equivalent to AES-256)

### SPHINCS+-256s (FIPS 205)

| Property | Status |
|----------|--------|
| Post-quantum secure | Yes (hash function security) |
| EUF-CMA secure | Yes |
| Deterministic signing | Optional (randomized by default) |
| Stateless | Yes |
| Side-channel resistant | Hash-based, inherently resistant |
| Signature malleability | No (hash-based, canonical) |

**Security Level**: NIST Level 5

### XMSS (RFC 8391)

| Property | Status |
|----------|--------|
| Post-quantum secure | Yes (hash function security) |
| EUF-CMA secure | Yes, IF index never reused |
| Deterministic signing | Yes |
| Stateless | **NO - STATEFUL** |
| Side-channel resistant | Hash-based, inherently resistant |
| Signature malleability | No (hash-based, canonical) |

**Security Level**: Configurable based on parameters

**CRITICAL**: XMSS security is COMPLETELY BROKEN if the same index is used twice.

### Dilithium (Pre-FIPS)

| Property | Status |
|----------|--------|
| Post-quantum secure | Yes (Module-LWE assumption) |
| EUF-CMA secure | Yes |
| Deterministic signing | Default |
| Stateless | Yes |
| Side-channel resistant | Constant-time where applicable |
| Signature malleability | No (canonical encoding enforced) |

**Note**: Dilithium is the pre-FIPS version. Prefer ML-DSA-87 for new applications.

---

## Cryptographic Implementation Details

### Constant-Time Operations

The following operations are implemented in constant-time to prevent timing attacks:

- **Signature verification comparison** (`subtle.ConstantTimeCompare`)
- **NTT operations** (fixed loop bounds, no data-dependent branches)
- **Polynomial rounding** (`MakeHint`, `UseHint` use arithmetic masking)
- **Coefficient norm checks** (fixed iteration count)

### Signature Canonicality

All signature schemes enforce canonical encoding:

**ML-DSA-87 / Dilithium**:
- Hint indices stored in strictly increasing order
- z coefficients bounded by `GAMMA1 - BETA`
- Zero padding enforced in hint section

**SPHINCS+ / XMSS**:
- Hash-based signatures are inherently canonical

### Key Zeroization

All crypto types implement `Zeroize()` to clear sensitive material:

```go
func (d *MLDSA87) Zeroize() {
    for i := range d.sk {
        d.sk[i] = 0
    }
    for i := range d.seed {
        d.seed[i] = 0
    }
}
```

**Limitation**: Go's garbage collector may copy memory before zeroization. For highest security, use hardware security modules.

---

## XMSS State Management Security

### Index Persistence Requirements

The XMSS index MUST be persisted to durable storage before using any signature:

```
1. Generate signature (index auto-increments)
2. Persist new index to durable storage
3. Verify persistence succeeded
4. Only then use/broadcast the signature
```

### Failure Modes

| Scenario | Risk | Mitigation |
|----------|------|------------|
| Power loss during signing | Index may not persist | Persist before using signature |
| Concurrent signing | Race condition on index | Never sign concurrently |
| Backup restoration | May reuse old index | Track "high water mark" separately |
| Database rollback | May reuse indices | Use append-only index storage |

### Recommended Architecture

For production XMSS usage:

1. **Use append-only storage** for index tracking
2. **Implement "high water mark"** that can never decrease
3. **Log all signing operations** for audit
4. **Monitor remaining signatures** (2^height limit)
5. **Plan key rotation** before exhaustion

---

## Dependency Security

### Direct Dependencies

| Dependency | Purpose | Security Notes |
|------------|---------|----------------|
| `golang.org/x/crypto` | SHA-3, SHAKE | Well-audited, maintained by Go team |

### Supply Chain Security

- `go mod verify` runs in CI to detect tampering
- Dependabot monitors for vulnerable dependencies
- Minimal dependency footprint

---

## Secure Development Practices

### Code Quality

- **golangci-lint** enforces code quality
- **go test -race** detects race conditions
- **govulncheck** scans for known vulnerabilities
- **Fuzz testing** for parsing robustness

### Review Requirements

All changes to cryptographic code require:
1. Code review by maintainers
2. Passing CI (lint, test, vulncheck)
3. No new security warnings

---

## Version Support

| Version | Supported |
|---------|-----------|
| Latest | Yes |
| Previous minor | Security fixes only |
| Older | No |

---

## Security Audit History

| Date | Auditor | Scope | Findings |
|------|---------|-------|----------|
| 2026-01 | Internal | Full codebase | 57 items identified and resolved |

---

## Contact

For security concerns, contact [security@theqrl.org](mailto:security@theqrl.org).
