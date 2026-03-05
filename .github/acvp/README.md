# NIST ACVP Test Vector Verification

This directory contains tooling for testing go-qrllib's ML-DSA-87 implementation against official NIST ACVP (Automated Cryptographic Validation Protocol) test vectors.

## How It Works

The GitHub Action (`.github/workflows/acvp.yml`) clones the NIST ACVP-Server repository at its latest commit and extracts the ML-DSA test vectors at runtime. Vectors are never vendored — they always come directly from NIST's repository.

1. **Clone**: Sparse checkout of `github.com/usnistgov/ACVP-Server` (only the ML-DSA JSON files)
2. **Merge**: `merge_vectors.py` combines the ACVP `prompt.json` (inputs) and `expectedResults.json` (expected outputs) into simplified test vector files, filtered to ML-DSA-87
3. **Test**: `acvp_test.go` runs the vectors through go-qrllib's internal key generation and signing functions, comparing byte-exact output

## What's Tested

| Test | Vectors | Description |
|------|---------|-------------|
| `TestACVPKeyGen` | 25 | Seed -> (pk, sk) matches NIST expected output |
| `TestACVPSigGen` | 15 | sk + message + context -> signature matches NIST expected output |

Only **deterministic, external-interface, pure** (non-preHash) signature vectors are tested, as go-qrllib implements deterministic pure ML-DSA signing.

## Running Locally

```bash
# Clone the ACVP-Server repo
git clone --depth 1 https://github.com/usnistgov/ACVP-Server.git /tmp/acvp-server

# Extract and merge ML-DSA-87 vectors
python3 .github/acvp/merge_vectors.py \
  --keygen-prompt /tmp/acvp-server/gen-val/json-files/ML-DSA-keyGen-FIPS204/prompt.json \
  --keygen-results /tmp/acvp-server/gen-val/json-files/ML-DSA-keyGen-FIPS204/expectedResults.json \
  --siggen-prompt /tmp/acvp-server/gen-val/json-files/ML-DSA-sigGen-FIPS204/prompt.json \
  --siggen-results /tmp/acvp-server/gen-val/json-files/ML-DSA-sigGen-FIPS204/expectedResults.json \
  --parameter-set ML-DSA-87 \
  --output-dir /tmp/acvp-vectors

# Run the tests
ACVP_VECTORS_DIR=/tmp/acvp-vectors go test -v -tags acvp -run TestACVP ./crypto/ml_dsa_87/
```

## Why Not the Other Algorithms?

| Algorithm | ACVP Vectors Available? | Compatible? | Reason |
|-----------|------------------------|-------------|--------|
| **ML-DSA-87** | Yes (ML-DSA FIPS 204) | Yes | Direct match |
| **Dilithium** | No | N/A | Pre-FIPS algorithm; ACVP only covers FIPS 204 (ML-DSA). Cross-verified against pq-crystals reference C implementation instead. |
| **SPHINCS+** | No (SLH-DSA FIPS 205 only) | No | go-qrllib implements SPHINCS+ SHAKE-256s-**robust** (pre-FIPS submission). FIPS 205 (SLH-DSA) dropped the robust variant and only standardized the simple variant. Different thash construction means different outputs. Cross-verified against sphincsplus reference (consistent-basew branch) instead. |
| **XMSS** | No | N/A | XMSS (RFC 8391) is not an ACVP-validated algorithm. One-directional cross-verification against xmss-reference instead. |

## ACVP Vector Format

The NIST ACVP-Server stores vectors in two files per algorithm:

- `prompt.json` — Test inputs (seed, message, sk, context)
- `expectedResults.json` — Expected outputs (pk, sk, signature)

These are linked by `tcId` within test groups. `merge_vectors.py` joins them and filters to the requested parameter set.
