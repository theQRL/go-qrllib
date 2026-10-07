# NIST ACVP Test Vector Verification

This directory contains tooling for testing go-qrllib's ML-DSA-87 implementation
against official NIST ACVP (Automated Cryptographic Validation Protocol) test
vectors.

## How It Works

The GitHub Action (`.github/workflows/acvp.yml`) clones the NIST ACVP-Server
repository at its latest commit and extracts the ML-DSA test vectors at runtime.
Vectors are never vendored — they always come directly from NIST's repository.

1. **Clone**: Sparse checkout of `github.com/usnistgov/ACVP-Server` (only the
   ML-DSA JSON files)
2. **Merge**: `merge_vectors.py` combines the ACVP `prompt.json` (inputs) and
   `expectedResults.json` (expected outputs) into simplified test vector files,
   filtered to ML-DSA-87
3. **Test**: `acvp_test.go` runs the vectors through go-qrllib's internal key
   generation, signing and verification functions, comparing byte-exact
   output and accept/reject verdicts

## What's Tested

| Test | Vectors | Description |
| --- | --- | --- |
| `TestACVPKeyGen` | 25 | Seed -> (pk, sk) matches NIST expected output |
| `TestACVPSigGen` | 60 | sk + message (+ context) (+ rnd) -> signature matches NIST expected output |
| `TestACVPSigVer` | 30 | pk + message (+ context) + signature -> accept/reject matches NIST's verdict |

Signature vectors cover every group the implementation can serve: both
the **deterministic** variant (`rnd` = 32 zero bytes) and the **hedged**
variant with the `rnd` value NIST supplies, through both the **external**
interface (`M' = 0x00 || |ctx| || ctx || M`) and the **internal** interface
(`M'` as given). The **pre-hash** (HashML-DSA) and **external-mu** groups
are skipped: the package implements pure ML-DSA and computes mu itself,
like the pq-crystals reference.

go-qrllib's public ML-DSA-87 API is **hedged by default** per FIPS 204
§3.4 (see SECURITY.md and TOB-QRLLIB-6); a public Sign call mixes fresh
`crypto/rand` into the per-signature `RND_BYTES` and therefore cannot
reproduce a fixed ACVP vector byte-for-byte. The ACVP test runner uses
the unexported `cryptoSignSignatureWithRnd` and
`cryptoSignSignatureInternal` entry points — the same internal functions
the public paths call into — with the explicit `rnd` the vector
prescribes (zero for the deterministic variant).

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
  --sigver-prompt /tmp/acvp-server/gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json \
  --sigver-results /tmp/acvp-server/gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json \
  --parameter-set ML-DSA-87 \
  --output-dir /tmp/acvp-vectors

# Run the tests
ACVP_VECTORS_DIR=/tmp/acvp-vectors go test -v -tags acvp -run TestACVP ./crypto/ml_dsa_87/
```

## Why Not the Other Algorithms?

| Algorithm | ACVP Vectors Available? | Compatible? | Reason |
| --- | --- | --- | --- |
| **ML-DSA-87** | Yes (ML-DSA FIPS 204) | Yes | Direct match |
| **SPHINCS+** | No (SLH-DSA FIPS 205 only) | No | go-qrllib implements SPHINCS+ SHAKE-256s-**robust** (pre-FIPS submission). FIPS 205 (SLH-DSA) dropped the robust variant and only standardized the simple variant. Different thash construction means different outputs. Cross-verified against sphincsplus reference (consistent-basew branch) instead. |
| **XMSS** | No | N/A | XMSS (RFC 8391) is not an ACVP-validated algorithm. One-directional cross-verification against xmss-reference instead. |

## ACVP Vector Format

The NIST ACVP-Server stores vectors in two files per algorithm:

- `prompt.json` — Test inputs (seed, message, sk, pk, context, rnd, signature)
- `expectedResults.json` — Expected outputs (pk, sk, signature, testPassed)

These are linked by `tcId` within test groups. `merge_vectors.py` joins them and
filters to the requested parameter set.
