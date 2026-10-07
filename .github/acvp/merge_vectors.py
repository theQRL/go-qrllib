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
  siggen.json: [{ tcId, deterministic, signatureInterface, sk, message, context, rnd, signature }]
  sigver.json: [{ tcId, signatureInterface, pk, message, context, signature, testPassed }]

Signature groups are kept when the implementation can serve them: the
pure (non-preHash) external interface and the internal interface without
externalMu, in both the deterministic and the hedged variant (the hedged
vectors carry the rnd value NIST used). HashML-DSA (preHash) and
ExternalMu-ML-DSA groups are skipped.
"""

import argparse
import json
import os
import sys


def load_pair(prompt_path, results_path):
    with open(prompt_path) as f:
        prompt = json.load(f)
    with open(results_path) as f:
        results = json.load(f)

    # Build tcId -> expected result lookup
    expected = {}
    for tg in results["testGroups"]:
        for tc in tg["tests"]:
            expected[tc["tcId"]] = tc

    return prompt, expected


def supported_signature_group(tg):
    """Reports whether go-qrllib can serve a sigGen/sigVer test group."""
    interface = tg.get("signatureInterface", "")
    if interface == "external":
        return tg.get("preHash", "") == "pure"
    if interface == "internal":
        return not tg.get("externalMu", False)
    return False


def merge_keygen(prompt_path, results_path, param_set):
    prompt, expected = load_pair(prompt_path, results_path)

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
    prompt, expected = load_pair(prompt_path, results_path)

    merged = []
    for tg in prompt["testGroups"]:
        if tg["parameterSet"] != param_set:
            continue
        if not supported_signature_group(tg):
            continue

        deterministic = tg.get("deterministic", False)
        for tc in tg["tests"]:
            tcid = tc["tcId"]
            if tcid not in expected:
                print(f"WARNING: tcId {tcid} missing from expectedResults", file=sys.stderr)
                continue
            exp = expected[tcid]
            merged.append({
                "tcId": tcid,
                "deterministic": deterministic,
                "signatureInterface": tg["signatureInterface"],
                "sk": tc["sk"],
                "message": tc.get("message", ""),
                "context": tc.get("context", ""),
                "rnd": "" if deterministic else tc["rnd"],
                "signature": exp["signature"],
            })

    return merged


def merge_sigver(prompt_path, results_path, param_set):
    prompt, expected = load_pair(prompt_path, results_path)

    merged = []
    for tg in prompt["testGroups"]:
        if tg["parameterSet"] != param_set:
            continue
        if not supported_signature_group(tg):
            continue

        for tc in tg["tests"]:
            tcid = tc["tcId"]
            if tcid not in expected:
                print(f"WARNING: tcId {tcid} missing from expectedResults", file=sys.stderr)
                continue
            exp = expected[tcid]
            merged.append({
                "tcId": tcid,
                "signatureInterface": tg["signatureInterface"],
                "pk": tc["pk"],
                "message": tc.get("message", ""),
                "context": tc.get("context", ""),
                "signature": tc["signature"],
                "testPassed": exp["testPassed"],
            })

    return merged


def main():
    parser = argparse.ArgumentParser(description="Merge ACVP test vectors")
    parser.add_argument("--keygen-prompt", required=True)
    parser.add_argument("--keygen-results", required=True)
    parser.add_argument("--siggen-prompt", required=True)
    parser.add_argument("--siggen-results", required=True)
    parser.add_argument("--sigver-prompt", required=True)
    parser.add_argument("--sigver-results", required=True)
    parser.add_argument("--parameter-set", required=True,
                        help="e.g. ML-DSA-87")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    outputs = {
        "keygen.json": merge_keygen(args.keygen_prompt, args.keygen_results,
                                    args.parameter_set),
        "siggen.json": merge_siggen(args.siggen_prompt, args.siggen_results,
                                    args.parameter_set),
        "sigver.json": merge_sigver(args.sigver_prompt, args.sigver_results,
                                    args.parameter_set),
    }

    for name, vectors in outputs.items():
        path = os.path.join(args.output_dir, name)
        with open(path, "w") as f:
            json.dump(vectors, f, indent=2)
        print(f"Wrote {len(vectors)} vectors to {path}")
        if len(vectors) == 0:
            print(f"ERROR: No {name} vectors found for {args.parameter_set}",
                  file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
