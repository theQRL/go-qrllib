#!/usr/bin/env python3
"""
Merge NIST ACVP-Server prompt and expectedResults JSON files into
simplified test vector files for go-qrllib ML-DSA-87 testing.

The ACVP-Server separates test inputs (prompt.json) from expected
outputs (expectedResults.json). This script merges them by tcId and
filters to the requested parameter set.

Input format (ACVP-Server):
  prompt.json:          { testGroups: [{ parameterSet, tests: [{ tcId, seed, ... }] }] }
  expectedResults.json: { testGroups: [{ tests: [{ tcId, pk, sk }] }] }

Output format (simplified):
  keygen.json: [{ tcId, seed, pk, sk }]
  siggen.json: [{ tcId, sk, message, context, signature }]
"""

import argparse
import json
import sys


def merge_keygen(prompt_path, results_path, param_set):
    with open(prompt_path) as f:
        prompt = json.load(f)
    with open(results_path) as f:
        results = json.load(f)

    # Build tcId -> expected result lookup
    expected = {}
    for tg in results["testGroups"]:
        for tc in tg["tests"]:
            expected[tc["tcId"]] = tc

    merged = []
    for tg in prompt["testGroups"]:
        if tg["parameterSet"] != param_set:
            continue
        for tc in tg["tests"]:
            tcid = tc["tcId"]
            if tcid not in expected:
                print(f"WARNING: tcId {tcid} missing from expectedResults", file=sys.stderr)
                continue
            exp = expected[tcid]
            merged.append({
                "tcId": tcid,
                "seed": tc["seed"],
                "pk": exp["pk"],
                "sk": exp["sk"],
            })

    return merged


def merge_siggen(prompt_path, results_path, param_set):
    with open(prompt_path) as f:
        prompt = json.load(f)
    with open(results_path) as f:
        results = json.load(f)

    # Build tcId -> expected result lookup
    expected = {}
    for tg in results["testGroups"]:
        for tc in tg["tests"]:
            expected[tc["tcId"]] = tc

    merged = []
    for tg in prompt["testGroups"]:
        if tg["parameterSet"] != param_set:
            continue

        # Only test deterministic, external, pure (non-preHash) vectors.
        # - deterministic: go-qrllib uses deterministic signing (rnd=zeros)
        # - external: tests the full Sign() API including context encoding
        # - pure: go-qrllib implements pure ML-DSA, not pre-hash variant
        deterministic = tg.get("deterministic", False)
        interface = tg.get("signatureInterface", "")
        pre_hash = tg.get("preHash", "")

        if not deterministic:
            continue
        if interface != "external":
            continue
        if pre_hash != "pure":
            continue

        for tc in tg["tests"]:
            tcid = tc["tcId"]
            if tcid not in expected:
                print(f"WARNING: tcId {tcid} missing from expectedResults", file=sys.stderr)
                continue
            exp = expected[tcid]
            merged.append({
                "tcId": tcid,
                "sk": tc["sk"],
                "message": tc.get("message", ""),
                "context": tc.get("context", ""),
                "signature": exp["signature"],
            })

    return merged


def main():
    parser = argparse.ArgumentParser(description="Merge ACVP test vectors")
    parser.add_argument("--keygen-prompt", required=True)
    parser.add_argument("--keygen-results", required=True)
    parser.add_argument("--siggen-prompt", required=True)
    parser.add_argument("--siggen-results", required=True)
    parser.add_argument("--parameter-set", required=True,
                        help="e.g. ML-DSA-87")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    import os
    os.makedirs(args.output_dir, exist_ok=True)

    keygen = merge_keygen(args.keygen_prompt, args.keygen_results,
                          args.parameter_set)
    siggen = merge_siggen(args.siggen_prompt, args.siggen_results,
                          args.parameter_set)

    keygen_path = os.path.join(args.output_dir, "keygen.json")
    siggen_path = os.path.join(args.output_dir, "siggen.json")

    with open(keygen_path, "w") as f:
        json.dump(keygen, f, indent=2)
    with open(siggen_path, "w") as f:
        json.dump(siggen, f, indent=2)

    print(f"Wrote {len(keygen)} keygen vectors to {keygen_path}")
    print(f"Wrote {len(siggen)} siggen vectors to {siggen_path}")

    if len(keygen) == 0:
        print(f"ERROR: No keygen vectors found for {args.parameter_set}",
              file=sys.stderr)
        sys.exit(1)
    if len(siggen) == 0:
        print(f"ERROR: No siggen vectors found for {args.parameter_set}",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
