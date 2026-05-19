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
| Timing side-channels in verification | All verification uses constant-time comparison (`subtle.ConstantTimeCompare`) |
| Key material in memory after use | `Zeroize()` methods |
| Non-canonical signature acceptance | Strict signature validation |

### What This Library Does NOT Protect Against

| Threat | Mitigation |
|--------|------------|
| Compromised system/malware | Use hardware security modules |
| Side-channel attacks via Go runtime | GC, compiler optimisations, and goroutine scheduling may introduce timing variation outside this library's control |
| XMSS index reuse | Caller must manage state correctly |
| Weak random number generation | Ensure `crypto/rand` works correctly |
| Memory not being zeroed by GC | Go limitation; use with HSM for high security |
| Brute-force verification attempts | Implement rate limiting at application layer |

---

## Security Properties by Algorithm

### ML-DSA-87 (FIPS 204)

| Property | Status |
|----------|--------|
| Post-quantum secure | Yes (Module-LWE assumption) |
| EUF-CMA secure | Yes |
| Deterministic signing | **Hedged by default** as per FIPS 204: each call mixes fresh `crypto/rand` randomness into the per-signature `RND_BYTES`, so two calls with the same `(key, ctx, message)` produce distinct signatures (both verify under the same public key). FIPS 204 deterministic mode (`rnd = 32 zero bytes`) is available as an explicit opt-in via `MLDSA87.SignDeterministic(ctx, msg)` for protocols where determinism is itself a requirement (RANDAO-style verifiable beacon contributions, test-vector reproduction). Equivalent at the wire level to `crypto.Signer.Sign(zeroReader, ...)` — both paths route into the same internal entry point. |
| `crypto.Signer.Sign` rand handling | The caller-supplied `io.Reader` is honoured: non-nil → its bytes drive `RND_BYTES`; nil → `crypto/rand` is used. |
| Stateless | Yes |
| Side-channel resistant | Branchless arithmetic in signing path; see [details below](#constant-time-operations) |
| Signature malleability | No (canonical encoding enforced) |

**Security Level**: NIST Level 5 (equivalent to AES-256)

### SPHINCS+-256s (SPHINCS+ submission, pre-FIPS)

| Property | Status |
|----------|--------|
| Post-quantum secure | Yes (hash function security) |
| EUF-CMA secure | Yes |
| Deterministic signing | Optional (randomized by default) |
| Stateless | Yes |
| Side-channel resistant | Hash-based, inherently resistant |
| Signature malleability | No (hash-based, canonical) |

**Security Level**: NIST Level 5

### XMSS (legacy, v1 → v2 migration)

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

#### Scope: XMSS in this library is a v1 → v2 migration vehicle

The XMSS implementation in `go-qrllib` exists for one purpose: to
keep QRL v1 mainnet addresses parseable, verifiable, and (for their
owners) signable during the ongoing migration to **ML-DSA-87
(FIPS 204)**. New signature issuance on QRL uses ML-DSA-87. XMSS in
this library is not intended as a standards-tracking implementation
and is not recommended for new wallets.

#### Parameter-set provenance

The library exposes three hash-function options:

| HashFunction | Status                                                      |
|--------------|-------------------------------------------------------------|
| `SHA2_256`   | XMSS-SHA2_*_256 family — RFC 8391 (Aug 2018) signature format. See "Standards alignment" below for the relationship to SP 800-208. |
| `SHAKE_256`  | XMSS-SHAKE_*_256 family — RFC 8391 (Aug 2018) signature format. See "Standards alignment" below for the relationship to SP 800-208. |
| `SHAKE_128`  | **QRL-specific extension, retained for legacy compatibility from QRL's pre-standardisation XMSS implementation.** Not part of NIST SP 800-208. With a 32-byte output it offers approximately 64-bit quantum security under a Grover-style attack — theoretically reduced relative to SHAKE_256 / SHA2_256 (~128-bit quantum). **Not recommended for new wallets.** Existing v1 mainnet addresses minted under SHAKE_128 must continue to be parseable, verifiable and signable, which is the only reason this option survives. |

Signatures produced by go-qrllib for the **XMSS-SHA2_10_256** parameter
set match the RFC 8391 (August 2018) signature format and verify under
the reference implementation (see `.github/cross-verify/README.md`).
The keypair-derivation surface diverges from the reference in two
distinct ways:

1. **Layout conventions**: the 48-byte QRL seed is SHAKE-256-expanded
   into the 96 bytes (SK_SEED || SK_PRF || PUB_SEED) the reference
   takes directly, and the QRL public key is prefixed with a 3-byte
   QRL descriptor rather than a 4-byte RFC 8391 OID. The
   [`crypto/xmss/rfc8391`](../crypto/xmss/rfc8391/) sub-package
   exposes a 96-byte direct-seed entry point and OID-form public-key
   marshalling that bridge both conventions, and is what the
   bidirectional cross-verify CI uses on the go-qrllib side.

2. **`expand_seed` construction**: the WOTS+ secret-key derivation
   follows the original RFC 8391 (Aug 2018), not the NIST SP 800-208
   (Oct 2020) refinement. This is because QRL's XMSS implementation
   predates both standards and the v1 mainnet keypair derivation
   depends on the original construction; adopting the SP 800-208
   refinement would alter the keypair derived from any given v1 seed
   and is therefore not appropriate for a deployed scheme. This is
   an algorithmic difference and is *not* something the `rfc8391`
   sub-package can bridge and the sub-package addresses layout
   conventions only. The cross-verify CI accommodates the difference
   by pinning `xmss-reference` to commit `7793c40` (the last revision
   on the original construction) so the bidirectional check aligns
   with the construction this library targets. See "Standards
   alignment" below for the deeper discussion.

#### Standards alignment

The implementation predates RFC 8391 (August 2018) and follows the
original RFC 8391 `expand_seed` construction. It does not track later
refinements such as NIST SP 800-208 (October 2020), which adjusted
`expand_seed` to take additional inputs. Applying that refinement
would alter the keypair derived from any given v1 seed and is
therefore not appropriate here. The cross-implementation verification
CI in `.github/cross-verify/` pins `xmss-reference` to commit
`7793c40` (the last revision on the original spec) so the
bidirectional cross-verify aligns with the construction this library
targets.

### Dilithium (Pre-FIPS)

| Property | Status |
|----------|--------|
| Post-quantum secure | Yes (Module-LWE assumption) |
| EUF-CMA secure | Yes |
| Deterministic signing | Default |
| Stateless | Yes |
| Side-channel resistant | Branchless arithmetic in signing path; see [details below](#constant-time-operations) |
| Signature malleability | No (canonical encoding enforced) |

**Note**: Dilithium is the pre-FIPS version. Prefer ML-DSA-87 for new applications.

---

## Address Security

### Address Derivation

QRL v2.0 addresses are 48 bytes, derived as:

```
Address = SHAKE256(Descriptor || PK)[:48]
```

The 48-byte (384-bit) address provides **NIST Category 5** post-quantum collision resistance. A shorter address (e.g. 20 bytes / 160 bits) would reduce collision resistance below the security level of the underlying signature schemes (ML-DSA-87 and SPHINCS+-256s both target NIST Level 5). The 48-byte size ensures the address does not become the weakest link in the security chain.

String form: `"Q" + hex(address)` = 97 characters.

---

## Cryptographic Implementation Details

### Constant-Time Operations

**Constant-time (no data-dependent branches):**

- **Signature verification**: challenge comparison via `subtle.ConstantTimeCompare` (ML-DSA-87, Dilithium, SPHINCS+)
- **NTT/inverse NTT**: fixed loop bounds, no data-dependent branches
- **Polynomial norm checks**: branchless violation-flag accumulator: iterates all N coefficients regardless of outcome, sign extraction via arithmetic shift (`polyChkNorm` in ML-DSA-87 and Dilithium)
- **Field decomposition**: `Power2Round`, `Decompose`, `MakeHint`, `UseHint` all use mask-based conditional selection with no branches on coefficient values (see `crypto/internal/lattice/rounding.go`)
- **Public key equality**: `CryptoPublicKey.Equal` uses `subtle.ConstantTimeCompare`

**Inherently variable-time (not secret-dependent):**

- **Rejection sampling loop** in signing: the number of iterations before a valid signature is found varies per attempt. FIPS 204 Appendix C acknowledges this is not a side-channel concern: the rejection probability depends on public parameters and random nonces, not on the secret key
- **SHAKE-256 / SHA-3 operations**: assumed constant-time for a given input length (provided by `golang.org/x/crypto/sha3`)

**Go runtime caveats:**

The above properties describe the library's own code. The Go runtime may introduce timing variation through garbage collection pauses, goroutine scheduling, and compiler optimisations (e.g., bounds-check elimination may alter branch patterns). These are outside this library's control. For environments where hardware-level constant-time guarantees are required, use a hardware security module.

### Signature Canonicality

All signature schemes enforce canonical encoding, verified by comprehensive negative tests:

**ML-DSA-87 / Dilithium**:
- Hint indices stored in strictly increasing order
- z coefficients bounded by `GAMMA1 - BETA`
- Zero padding enforced in hint section
- Cumulative counts must be non-decreasing and ≤ OMEGA

**SPHINCS+ / XMSS**:
- Hash-based signatures are inherently canonical
- Fixed signature sizes enforced

#### Canonicality Test Coverage

Non-canonical encodings are rejected by the verification functions. This is verified by:

| Test File | Coverage |
|-----------|----------|
| [`crypto/ml_dsa_87/canonicality_test.go`](crypto/ml_dsa_87/canonicality_test.go) | Truncation, hint ordering, padding, cumulative counts |
| [`crypto/dilithium/canonicality_test.go`](crypto/dilithium/canonicality_test.go) | Truncation, hint ordering, padding, cumulative counts |
| [`crypto/sphincsplus_256s/canonicality_test.go`](crypto/sphincsplus_256s/canonicality_test.go) | Truncation, FORS/WOTS/auth path corruption |
| [`crypto/xmss/canonicality_test.go`](crypto/xmss/canonicality_test.go) | Truncation, index/R/WOTS/auth path corruption, height validation |

Run canonicality tests:
```bash
go test -v -run TestCanonicality ./crypto/...
```

### Key Zeroization

All crypto types implement `Zeroize()` to clear the secret-key and seed
fields of the instance. Internally these route through the package's
shared `zeroBytes` helper so the wipe behaviour is defined in one place:

```go
func (d *MLDSA87) Zeroize() {
    zeroBytes(d.sk[:])
    zeroBytes(d.seed[:])
}
```

`zeroBytes` overwrites the slice in place and uses `runtime.KeepAlive`
to prevent the compiler from eliding the writes as a dead store.

In addition to instance-level `Zeroize()`, both **signing AND key-generation** paths
automatically zeroise their secret temporaries via deferred cleanup
when they return. This reduces the window for secret intermediates
persisting in freed memory:

- **ML-DSA-87 / Dilithium signing** (`cryptoSignSignatureInternal`): `key`, `rhoPrime`, `s1`, `s2`, `t0`
- **ML-DSA-87 key generation** (`cryptoSignKeypair`): `key`, `rhoPrime`, `s1`, `s1hat`, `s2`, `t0`
- **ML-DSA-87 hex-seed parsing** (`NewMLDSA87FromHexSeed`): the heap-allocated `unsizedSeed` byte slice and the temporary fixed-size seed array
- **SPHINCS+**: `ctx.SkSeed`

#### Guarantee boundary (best-effort under Go's memory model)

Zeroisation in this library is **best-effort**, not absolute. Go's
runtime may copy values during garbage collection, escape analysis,
slice growth, or interface boxing; any such copy that occurred
*before* the zeroisation executes is outside the library's control
and remains in memory until that copy is itself overwritten or
reclaimed. The `runtime.KeepAlive` calls in `zeroBytes` and the
`zeroPoly` family defeat **dead-store elimination by the compiler**
for the explicit overwrite, but they do **not** address
**runtime-side duplication** of the underlying data.

What this means in practice:

- Calling `Zeroize` (or letting a signing-path defer fire) closes the
  obvious window where secret material sits in process memory after
  it has finished being used. This is a useful defence-in-depth
  measure for short-lived signers and against memory-disclosure bugs
  in the host process.
- It does **NOT** guarantee that no copy of the secret survives
  anywhere in the address space. Workloads with adversaries that
  have physical or kernel-level memory access (cold-boot attacks,
  `/proc/<pid>/mem`, hibernation images, swap files) need a
  hardware security module for hard guarantees.

For highest security, combine in-library zeroisation with HSM-backed
key storage, locked memory pages (`mlock`/`VirtualLock`), and
swap-disabled hosts.

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

## API Precondition Guarantees

Every public verification and "open" function in the library treats malformed inputs as a refusal, **never as a panic**. The following preconditions are checked at the API boundary:

### Panic policy

The library distinguishes two failure classes:

- **Malformed user input**: nil pointers, wrong-size buffers, unsupported parameter values supplied through the public API. Always surfaces as a typed error or a `false` / `nil` return; **never panics**. The tables below enumerate the specific cases.
- **Invariant violations**: internal preconditions that should never fail if the rest of the library is correct (e.g. an unrecognised `HashFunction` reaching the dispatch switch *after* the public constructor's validation guard, or `xmss/params.go`'s `logW` switch reaching its impossible default). These **panic with a clear message**; they exist as crash-early tripwires so that any future regression which bypasses an upstream guard fails loudly in tests rather than silently corrupting key material in production.

Existing invariant-panic sites include `crypto/xmss/params.go` (WOTS parameter values), `crypto/xmss/hash.go:coreHash` (HashFunction dispatch), `crypto/xmss/xmss_fast.go:treeHashSetup` (Height bounds), and several SHAKE I/O sites in `crypto/sphincsplus_256s/hash_shake.go` (cryptographic-primitive errors that the SHA-3 contract guarantees do not occur). All carry comments explaining what upstream invariant is being enforced.

| Function | Nil public key | Wrong-size signature | Oversized context | Verification failure |
|----------|----------------|----------------------|-------------------|----------------------|
| `crypto/ml_dsa_87.Verify` | returns `false` | returns `false` | returns `false` | returns `false` |
| `crypto/ml_dsa_87.Open` | `(nil, ErrPublicKeyNil)` | `(nil, ErrInvalidSignatureSize)` | `(nil, ErrInvalidContext)` | `(nil, ErrInvalidSignature)` |
| `crypto/dilithium.Verify` | returns `false` | returns `false` | n/a | returns `false` |
| `crypto/dilithium.Open` | `(nil, ErrPublicKeyNil)` | `(nil, ErrInvalidSignatureSize)` | n/a | `(nil, ErrInvalidSignature)` |
| `crypto/sphincsplus_256s.Verify` | returns `false` | returns `false` | n/a | returns `false` |
| `crypto/sphincsplus_256s.Open` | `(nil, ErrPublicKeyNil)` | `(nil, ErrInvalidSignatureSize)` | n/a | `(nil, ErrInvalidSignature)` |
| `crypto/xmss.Verify` | n/a (slice; len-checked) | returns `false` | n/a | returns `false` |
| `legacywallet/xmss.Verify` | n/a (value type) | returns `false` | n/a | returns `false` |
| `wallet/ml_dsa_87.Verify` | returns `false` | returns `false` | n/a | returns `false` |
| `wallet/sphincsplus_256s.Verify` | returns `false` | returns `false` | n/a | returns `false` |

The crypto-level `Open` functions return `([]byte, error)`. Each failure mode surfaces a distinct typed sentinel from `cryptoerrors`, so callers that need to log or route on specific failure types can use `errors.Is(err, cryptoerrors.ErrPublicKeyNil)` etc. Callers that don't care which failure occurred can write `msg, _ := Open(...)` and treat `msg == nil` as "did not verify".

Internal entry points (`cryptoSignVerify`, `cryptoSignOpen`) carry the same nil-PK guard as defense-in-depth and surface the same typed sentinels.

Regression tests in each affected package (`nil_pk_test.go`) exercise the nil-pk path with a recover-and-fail-on-panic harness so a future edit that removes the guard fails CI immediately.

#### Information-leakage considerations

The typed errors returned by `Open` describe (a) the caller's own input shape — nil pointer, oversized context, undersized signature buffer — or (b) the boolean verification outcome. **None is computed from secret material**, so no error path constitutes a verification oracle that could help an attacker forge signatures: the underlying ML-DSA / Dilithium / SPHINCS+ schemes are EUF-CMA secure, and an attacker with unlimited Verify queries learns nothing useful from a "valid input shape, invalid signature" error that they would not learn from `Verify` returning `false`.

The fast-fail vs slow-fail timing distinction (early input-shape errors vs full verification then `ErrInvalidSignature`) reveals only input-shape information that the attacker supplied themselves. Within the slow-fail path the constant-time-comparison properties documented above ensure no further timing leak based on secret state.

Callers forwarding these errors to untrusted clients should follow standard Go server-side practice of mapping internal errors to coarser external messages.

### Constructor preconditions (XMSS parameter validation)

XMSS constructors additionally validate parameter-set identifiers at the API boundary. The contract is: every exported XMSS constructor MUST call `HashFunction.IsValid()` and `Height.IsValid()` on its caller-supplied values *before* deriving any key material; an invalid value MUST surface as a typed error (`cryptoerrors.ErrInvalidHashFunction` or `cryptoerrors.ErrInvalidHeight`) rather than producing a degenerate zero-rooted XMSS at signing time.

| Constructor | HashFunction validated | Height validated |
|-------------|------------------------|------------------|
| `crypto/xmss.InitializeTree` | yes | yes |
| `crypto/xmss.XMSSFastGenKeyPair` | yes (via internal dispatch tripwire, see below) | yes |
| `legacywallet/xmss.NewWalletFromSeed` | yes (defence-in-depth) | yes (existing `height > MaxHeight` check) |
| `legacywallet/xmss.NewWalletFromExtendedSeed` | yes (via descriptor parser → `xmss.ToHashFunction`) | yes (same path) |
| `legacywallet/xmss.NewWalletFromHeight` | yes (delegates to `NewWalletFromSeed`) | yes (same) |

Two internal defence-in-depth tripwires back the contract:

1. **`crypto/xmss.coreHash`** dispatch `switch` carries a `default:` panic that fires immediately if any future regression lets an invalid `HashFunction` reach the hash function with no upstream guard. Without this default case the buffer would be left zero-initialised (the original audit defect).
2. **`crypto/xmss.InitializeTree`** post-construction non-zero-root check, which asserts the constructed Merkle root is not all-zero before returning the XMSS. Catches any *other* future regression in the key-derivation pipeline that produces an unconstructed root.

Regression tests live in `crypto/xmss/hash_function_validation_test.go` and `legacywallet/xmss/hash_function_validation_test.go`; together they cover every invalid `uint8` value cast to `HashFunction`, the `coreHash` tripwire, and a positive cross-seed-distinct-roots invariant for each valid hash function.

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
- **Sigstore attestations** for all release artifacts
- **SLSA Level 3 provenance** for build verification
- **SBOM** published in SPDX and CycloneDX formats

---

## Release Verification

All releases include cryptographic attestations and checksums for verification.

### Verifying with GitHub CLI

```bash
# Verify attestations for go.mod and go.sum
gh attestation verify go.mod --owner theQRL
gh attestation verify go.sum --owner theQRL

# Verify SBOM attestation
gh attestation verify sbom-spdx.json --owner theQRL
```

### Verifying Checksums

Download and verify checksums from the release:

```bash
# Download checksums file
curl -LO https://github.com/theQRL/go-qrllib/releases/download/vX.Y.Z/checksums-sha256.txt

# Verify go.mod and go.sum
sha256sum -c checksums-sha256.txt
```

### Verifying SLSA Provenance

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Download provenance
curl -LO https://github.com/theQRL/go-qrllib/releases/download/vX.Y.Z/provenance.intoto.jsonl

# Verify provenance
slsa-verifier verify-artifact go.mod \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/theQRL/go-qrllib
```

### Software Bill of Materials (SBOM)

Each release includes SBOMs in two formats:
- **SPDX**: `sbom-spdx.json`
- **CycloneDX**: `sbom-cyclonedx.json`

These can be analyzed with tools like:
```bash
# Using grype for vulnerability scanning
grype sbom:sbom-spdx.json

# Using syft for inspection
syft convert sbom-cyclonedx.json -o table
```

### What Gets Attested

| Artifact | Attestation Type | Purpose |
|----------|-----------------|---------|
| `go.mod`, `go.sum` | Build provenance | Verify module dependencies |
| `checksums-sha256.txt` | Build provenance | Integrity verification |
| `sbom-spdx.json` | SBOM | Software composition |
| `sbom-cyclonedx.json` | SBOM | Software composition |
| Source code | SLSA provenance | Build reproducibility |

### Trust Model

Attestations are signed using GitHub's Sigstore integration:
- **Identity**: GitHub Actions OIDC token
- **Transparency**: Logged in Sigstore's Rekor transparency log
- **Verification**: Proves release came from official CI workflow

This provides equivalent (or stronger) guarantees than GPG-signed tags:
- No key management or distribution required
- Tied to repository's GitHub Actions identity
- Publicly auditable via transparency logs

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

## Contact

For security concerns, contact [security@theqrl.org](mailto:security@theqrl.org).
