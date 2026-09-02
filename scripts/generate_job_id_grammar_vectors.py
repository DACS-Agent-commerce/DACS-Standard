#!/usr/bin/env python3
"""Generate deterministic conformance vectors for the canonical DACS jobId."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security" / "job-id-grammar-v0.1.json"
)

JOB = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
OTHER_JOB = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
TEST_RELEASE_PIN = "0000000000000000000000000000000000000001"
CORRECTIVE_TUPLE = {
    "core": "0.3",
    "dacs1": "0.7",
    "dacs2": "0.5",
    "dacs3": "0.4",
    "dacs4": "0.7",
    "dacs5": "0.5",
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def bundle_address(job_id: str, role: str) -> str:
    preimage = job_id.encode("ascii") + b"-bundle-" + role.encode("ascii")
    return "stor-" + hashlib.sha256(preimage).hexdigest()


def vector(
    name: str,
    operation: str,
    expected: str,
    job_id: object,
    note: str,
    *,
    other_job_id: object | None = None,
    role: str | None = None,
    template: str | None = None,
    want: dict | None = None,
) -> dict:
    item = {
        "name": name,
        "operation": operation,
        "expected": expected,
        "jobId": job_id,
        "note": note,
    }
    if other_job_id is not None:
        item["otherJobId"] = other_job_id
    if role is not None:
        item["role"] = role
    if template is not None:
        item["template"] = template
    if want is not None:
        item["want"] = want
    return item


def build() -> dict:
    invalid_no_effects = {"failureStage": "job-id-validation", "hashCalls": 0,
                          "lookupCalls": 0}
    vectors = [
        vector(
            "canonical-ulid",
            "validate",
            "pass",
            JOB,
            "A canonical 26-character upper-case Crockford ULID is accepted byte-exact.",
            want={"canonicalJobId": JOB},
        ),
        vector(
            "lowest-syntactic-value",
            "validate",
            "pass",
            "0" * 26,
            "The lower syntactic boundary is valid; producer uniqueness is a separate obligation.",
            want={"canonicalJobId": "0" * 26},
        ),
        vector(
            "highest-syntactic-value",
            "validate",
            "pass",
            "7" + "Z" * 25,
            "The first-character 0-7 bound admits the largest 128-bit ULID encoding.",
            want={"canonicalJobId": "7" + "Z" * 25},
        ),
        vector(
            "lowercase-is-not-canonical",
            "lookup-bundle",
            "error",
            JOB.lower(),
            "Case-insensitive ULID decoding cannot authorize case-folding before lookup.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "mixed-case-is-not-canonical",
            "lookup-bundle",
            "error",
            JOB[:8] + JOB[8].lower() + JOB[9:],
            "A mixed-case spelling is malformed even when a lenient decoder accepts it.",
            role="seller",
            want=invalid_no_effects,
        ),
        vector(
            "crockford-i-alias-rejected",
            "lookup-bundle",
            "error",
            JOB[:10] + "I" + JOB[11:],
            "The Crockford I-to-1 decode alias is forbidden on the wire.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "crockford-l-alias-rejected",
            "lookup-bundle",
            "error",
            JOB[:10] + "L" + JOB[11:],
            "The Crockford L-to-1 decode alias is forbidden on the wire.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "crockford-o-alias-rejected",
            "lookup-bundle",
            "error",
            JOB[:10] + "O" + JOB[11:],
            "The Crockford O-to-0 decode alias is forbidden on the wire.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "crockford-u-character-rejected",
            "lookup-bundle",
            "error",
            JOB[:10] + "U" + JOB[11:],
            "U is excluded from the canonical Crockford alphabet.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "overflow-first-character-eight",
            "lookup-bundle",
            "error",
            "8" + JOB[1:],
            "A first character above 7 would encode more than 128 bits.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "overflow-first-character-nine",
            "lookup-bundle",
            "error",
            "9" + JOB[1:],
            "The upper first-character overflow spelling is also rejected.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "short-job-id",
            "lookup-bundle",
            "error",
            JOB[:-1],
            "A jobId must contain exactly 26 ASCII characters.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "long-job-id",
            "lookup-bundle",
            "error",
            JOB + "0",
            "A 27-character value is not a canonical ULID.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "hyphenated-job-id",
            "lookup-bundle",
            "error",
            JOB[:13] + "-" + JOB[14:],
            "Separators are not members of the canonical jobId grammar.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "leading-whitespace",
            "lookup-bundle",
            "error",
            " " + JOB,
            "Consumers do not trim a jobId before validation or derivation.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "trailing-newline",
            "lookup-bundle",
            "error",
            JOB + "\n",
            "Trailing whitespace is data, not a permitted transport variation.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "precomposed-unicode-rejected",
            "lookup-bundle",
            "error",
            "0" + "A" * 22 + "ÅA",
            "NFC does not make a non-ASCII jobId conformant.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "decomposed-unicode-rejected",
            "lookup-bundle",
            "error",
            "0" + "A" * 22 + "A\u030aA",
            "A canonically equivalent Unicode spelling is likewise rejected, not normalized.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "percent-encoding-rejected",
            "lookup-bundle",
            "error",
            JOB[:10] + "%" + JOB[11:],
            "CF-4 percent decoding is never applied to a jobId segment.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "null-is-not-a-job-id",
            "lookup-bundle",
            "error",
            None,
            "A missing/null value fails before address work.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "integer-is-not-a-job-id",
            "lookup-bundle",
            "error",
            1,
            "Numeric coercion is forbidden.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "boolean-is-not-a-job-id",
            "lookup-bundle",
            "error",
            True,
            "Boolean-to-integer or Boolean-to-string coercion is forbidden.",
            role="buyer",
            want=invalid_no_effects,
        ),
        vector(
            "buyer-bundle-known-answer",
            "derive-bundle",
            "pass",
            JOB,
            "Bundle addressing hashes the exact validated ASCII jobId and buyer role.",
            role="buyer",
            want={"logicalAddress": bundle_address(JOB, "buyer"), "hashCalls": 1,
                  "lookupCalls": 0},
        ),
        vector(
            "seller-bundle-known-answer",
            "derive-bundle",
            "pass",
            JOB,
            "The seller role has a distinct deterministic logical address.",
            role="seller",
            want={"logicalAddress": bundle_address(JOB, "seller"), "hashCalls": 1,
                  "lookupCalls": 0},
        ),
        vector(
            "orchestrator-bundle-known-answer",
            "derive-bundle",
            "pass",
            JOB,
            "The orchestrator role uses the same byte-exact derivation.",
            role="orchestrator",
            want={"logicalAddress": bundle_address(JOB, "orchestrator"), "hashCalls": 1,
                  "lookupCalls": 0},
        ),
        vector(
            "lookup-after-validation",
            "lookup-bundle",
            "pass",
            JOB,
            "A resolver may run only after canonical grammar validation and derivation.",
            role="buyer",
            want={"logicalAddress": bundle_address(JOB, "buyer"), "hashCalls": 1,
                  "lookupCalls": 1},
        ),
        vector(
            "commit-address-preserves-job-id-bytes",
            "derive-logical",
            "pass",
            JOB,
            "Every non-hash logical-address template inserts the same validated bytes.",
            template="dacs3:commit:{jobId}",
            want={"logicalAddress": "dacs3:commit:" + JOB, "hashCalls": 0,
                  "lookupCalls": 0},
        ),
        vector(
            "payment-address-preserves-job-id-bytes",
            "derive-logical",
            "pass",
            JOB,
            "CF-4 encodes railId, not the canonical ASCII jobId segment.",
            template="dacs4:payment:{jobId}:evm-erc20%3A1%3AUSDC:3",
            want={"logicalAddress": "dacs4:payment:" + JOB + ":evm-erc20%3A1%3AUSDC:3",
                  "hashCalls": 0, "lookupCalls": 0},
        ),
        vector(
            "exact-job-id-comparison",
            "compare",
            "pass",
            JOB,
            "Two independently parsed canonical copies compare byte-exact.",
            other_job_id=JOB,
            want={"equal": True, "hashCalls": 0, "lookupCalls": 0},
        ),
        vector(
            "different-canonical-job-ids",
            "compare",
            "fail",
            JOB,
            "Two different valid ULIDs are a well-formed identity mismatch.",
            other_job_id=OTHER_JOB,
            want={"equal": False, "hashCalls": 0, "lookupCalls": 0},
        ),
        vector(
            "comparison-does-not-case-fold",
            "compare",
            "error",
            JOB,
            "A malformed comparison operand errors instead of being uppercased into equality.",
            other_job_id=JOB.lower(),
            want=invalid_no_effects,
        ),
        {
            "name": "matching-corrective-profile-admitted",
            "operation": "profile-admit",
            "expected": "pass",
            "localProfile": {"releasePin": TEST_RELEASE_PIN,
                             "moduleVersions": CORRECTIVE_TUPLE},
            "peerProfile": {"releasePin": TEST_RELEASE_PIN,
                            "moduleVersions": CORRECTIVE_TUPLE},
            "note": "Exact authenticated release and complete module tuple admit the corrective profile.",
            "want": {"profileAdmitted": True, "hashCalls": 0, "lookupCalls": 0},
        },
        {
            "name": "missing-peer-profile-refuses",
            "operation": "profile-admit",
            "expected": "error",
            "localProfile": {"releasePin": TEST_RELEASE_PIN,
                             "moduleVersions": CORRECTIVE_TUPLE},
            "peerProfile": None,
            "note": "Missing authenticated peer profile refuses before job-specific action.",
            "want": {"failureStage": "profile-admission", "hashCalls": 0,
                     "lookupCalls": 0},
        },
        {
            "name": "different-release-pin-refuses",
            "operation": "profile-admit",
            "expected": "error",
            "localProfile": {"releasePin": TEST_RELEASE_PIN,
                             "moduleVersions": CORRECTIVE_TUPLE},
            "peerProfile": {"releasePin": "f" * 40,
                            "moduleVersions": CORRECTIVE_TUPLE},
            "note": "The same module tuple under a different immutable release is not inferred compatible.",
            "want": {"failureStage": "profile-admission", "hashCalls": 0,
                     "lookupCalls": 0},
        },
        {
            "name": "different-module-tuple-refuses",
            "operation": "profile-admit",
            "expected": "error",
            "localProfile": {"releasePin": TEST_RELEASE_PIN,
                             "moduleVersions": CORRECTIVE_TUPLE},
            "peerProfile": {"releasePin": TEST_RELEASE_PIN,
                            "moduleVersions": {**CORRECTIVE_TUPLE, "core": "0.2"}},
            "note": "A pre-JID-1 CORE tuple refuses even when a caller reuses the release field.",
            "want": {"failureStage": "profile-admission", "hashCalls": 0,
                     "lookupCalls": 0},
        },
        {
            "name": "major-only-discriminator-refuses",
            "operation": "profile-admit",
            "expected": "error",
            "localProfile": {"releasePin": TEST_RELEASE_PIN,
                             "moduleVersions": CORRECTIVE_TUPLE},
            "peerProfile": {"dacsVersion": "1"},
            "note": "A major-only artifact discriminator cannot establish corrective-profile compatibility.",
            "want": {"failureStage": "profile-admission", "hashCalls": 0,
                     "lookupCalls": 0},
        },
    ]
    return {
        "set": "job-id-grammar-v0.1",
        "spec": "CORE §B.1 JID-1..JID-4; DACS-5 §10.3 and §10.4.2",
        "grammar": "^[0-7][0-9A-HJKMNP-TV-Z]{25}$",
        "correctiveProfile": {
            "testOnlyReleasePin": TEST_RELEASE_PIN,
            "moduleVersions": CORRECTIVE_TUPLE,
        },
        "hashRecipe": "sha256(compact sorted-key UTF-8 JSON of vectors)",
        "count": len(vectors),
        "hash": hashlib.sha256(canonical_bytes(vectors)).hexdigest(),
        "vectors": vectors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    generated = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != generated:
            print("jobId grammar vectors are stale; regenerate without --check")
            return 1
        print("jobId grammar vectors are deterministic")
        return 0
    OUTPUT.write_text(generated, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
