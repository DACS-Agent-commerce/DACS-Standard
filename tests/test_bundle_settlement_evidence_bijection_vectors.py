"""Executable assertions for DACS-5 v0.4 SEB-1..SEB-6 candidate vectors."""

import base64
import hashlib
import json
import unittest
from pathlib import Path

import dacs5_reference as R


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance/vectors/security/bundle-settlement-evidence-bijection-v0.4.json"
SPEC = ROOT / "spec/DACS-5-VERIFY.md"
CORE = ROOT / "spec/CORE.md"


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def derive_phase_keys(authority, pubkeys):
    ok, _, phase_keys = R.validate_ebfab(
        authority.get("bundle"),
        authority.get("listing"),
        pubkeys,
        authority.get("referenceValidationByCanonicalRef"),
        authority.get("bundleLifecycle"),
    )
    return phase_keys if ok else None


def evaluate(vector_data, authorities, pubkeys):
    authority = authorities.get(vector_data.get("executionAuthorityRef"))
    expected = derive_phase_keys(authority or {}, pubkeys)
    if expected is None:
        return "rejected", "execution-authority"

    refs = vector_data["topLevelRefs"]
    records = vector_data["authenticatedRecordByRef"]
    pointers = vector_data["pointerMap"]
    st8_reason_by_phase = {
        "pay-cross-chain-htlc": "dest-revealed-source-unclaimed",
        "pay-cross-chain-liquidity-tank": "tank-locked-unreleased",
    }

    if len(refs) != len(set(refs)):
        return "rejected", "raw-multiplicity"

    for successor in refs:
        record = records.get(successor, {})
        interim = record.get("supersedesEvidenceRef")
        if interim is not None:
            interim_record = records.get(interim, {})
            phase_key = record.get("phaseKey")
            phase = phase_key.split(":", 1)[-1] if isinstance(phase_key, str) else None
            expected_reason = st8_reason_by_phase.get(phase)
            if (
                interim in refs
                or record.get("outcome") != "success"
                or interim_record.get("jobId") != record.get("jobId")
                or interim_record.get("phaseKey") != record.get("phaseKey")
                or interim_record.get("outcome") != "failure"
                or interim_record.get("reason") != expected_reason
            ):
                return "rejected", "st8-raw-admissibility"

    authority = authorities[vector_data["executionAuthorityRef"]]
    expected_outcome_by_key = {
        f"{entry['index']}:{entry['kind']}": "success" if entry["outcome"] == "ok" else "failure"
        for entry in authority["bundle"]["phaseSummary"]
        if entry["kind"] in R.EVIDENCE_PHASES
    }
    expected_error_by_key = {
        f"{entry['index']}:{entry['kind']}": entry.get("errorClass")
        for entry in authority["bundle"]["phaseSummary"]
        if entry["kind"] in R.EVIDENCE_PHASES
    }
    if any(
        ref not in records
        or records[ref].get("jobId") != authority["bundle"]["jobId"]
        or records[ref].get("phaseKey") not in expected
        for ref in refs
    ):
        return "rejected", "exact-phase-mapping"
    if any(
        records[ref].get("outcome") != expected_outcome_by_key[records[ref]["phaseKey"]]
        for ref in refs
    ):
        return "rejected", "st8-raw-admissibility"
    for ref in refs:
        record = records[ref]
        phase_key = record["phaseKey"]
        phase = phase_key.split(":", 1)[-1]
        expected_reason = st8_reason_by_phase.get(phase)
        expired_st8 = expected_error_by_key.get(phase_key) == "settlement-atomicity" or (
            phase == "pay-cross-chain-liquidity-tank"
            and expected_error_by_key.get(phase_key) == "substrate"
            and record.get("reason") == expected_reason
        )
        if expired_st8:
            if record.get("reason") != expected_reason:
                return "rejected", "st8-raw-admissibility"
        elif record.get("reason") in set(st8_reason_by_phase.values()):
            return "rejected", "st8-raw-admissibility"

    lifecycle_overrides = vector_data.get("referenceLifecycleByRef", {})
    default_lifecycle = authority["defaultReferenceLifecycle"]
    for ref in refs:
        lifecycle = lifecycle_overrides.get(ref, default_lifecycle)
        if authority["bundle"]["outcome"] == "completed":
            if (
                lifecycle.get("state") != "finalized"
                or lifecycle.get("independentlyResolvable") is not True
            ):
                return "rejected", "lifecycle-gate"
        elif lifecycle.get("state") not in {"included", "finalized"}:
            return "rejected", "lifecycle-gate"

    if len(refs) != len(expected):
        return "rejected", "exact-cardinality"

    mapped = [records[ref]["phaseKey"] for ref in refs]
    if len(set(mapped)) != len(mapped) or set(mapped) != set(expected):
        return "rejected", "exact-bijection"

    if len(set(pointers.values())) != len(pointers):
        return "rejected", "pointer-agreement"
    for phase_key, ref in pointers.items():
        if ref not in refs or records.get(ref, {}).get("phaseKey") != phase_key:
            return "rejected", "pointer-agreement"

    if vector_data["unrelatedAuthorityDisposition"] == "indeterminate":
        return "indeterminate", "unrelated-authority-indeterminate"
    return "verified", "ok"


class BundleSettlementEvidenceBijectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.pubkeys = {
            claim: decode(value)
            for claim, value in cls.data["publicKeys"].items()
        }

    def test_vector_hash_count_and_names(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(self.data["hash"], hashlib.sha256(canonical_json(vectors)).hexdigest())
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_all_expected_dispositions_and_reason_codes(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    evaluate(vector["input"], self.data["executionAuthorities"], self.pubkeys),
                    (vector["want"]["disposition"], vector["want"]["reasonCode"]),
                )

    def test_phase_authority_is_derived_not_caller_supplied(self):
        for vector in self.data["vectors"]:
            self.assertNotIn("expectedPhaseKeys", vector["input"])
            self.assertNotIn("recordClassByRef", vector["input"])
            self.assertNotIn("supersedesEdges", vector["input"])
            self.assertNotIn("resolvedReferencePhaseKeys", vector["input"])
        for definition in self.data["executionAuthorityDefinitions"].values():
            self.assertNotIn("listingSignatureVerified", definition)
            self.assertNotIn("bundleSignaturesVerified", definition)

        repeated = self.data["executionAuthorities"]["repeated-pay-completed"]
        self.assertEqual(
            derive_phase_keys(repeated, self.pubkeys),
            ["0:pay-dem", "1:pay-dem", "2:deliver-entitlement"],
        )
        failed = self.data["executionAuthorities"]["failed-delivery"]
        self.assertEqual(derive_phase_keys(failed, self.pubkeys), ["0:deliver-storage-program"])
        transient = self.data["executionAuthorities"]["transient-retry-exhausted"]
        self.assertEqual(
            derive_phase_keys(transient, self.pubkeys),
            ["0:deliver-storage-program"],
        )
        failed_resolution = next(iter(failed["referenceValidationByCanonicalRef"].values()))
        self.assertFalse(failed_resolution["lifecycle"]["independentlyResolvable"])
        aborted = self.data["executionAuthorities"]["aborted-before-result"]
        self.assertEqual(derive_phase_keys(aborted, self.pubkeys), [])
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-completed-incomplete-summary"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-failed-gapped-summary"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-aborted-result-summary"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-failed-outcome-error-class"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-st8-expired-wrong-reason"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-transient-not-exhausted"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(self.data["executionAuthorities"]["invalid-listing-signature"], self.pubkeys)
        )
        self.assertIsNone(
            derive_phase_keys(self.data["executionAuthorities"]["invalid-bundle-signature"], self.pubkeys)
        )
        self.assertIsNone(
            derive_phase_keys(self.data["executionAuthorities"]["mismatched-listing-signer"], self.pubkeys)
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-completed-bundle-lifecycle"],
                self.pubkeys,
            )
        )

    def test_minor_safe_type_boundary_and_domains(self):
        spec = SPEC.read_text(encoding="utf-8")
        core = CORE.read_text(encoding="utf-8")
        self.assertEqual(self.data["artifactType"], "EvidenceBoundFaultAttestationBundle")
        self.assertIn('evidenceBoundFaultBundleVersion: "1"', spec)
        self.assertIn("MUST NOT claim SEB validation", spec)
        self.assertIn('"dacs-evidence-bound-fault-bundle:v1:"', core)
        self.assertIn('"dacs-evidence-bound-fault-bundle-pointer:v1:"', core)


if __name__ == "__main__":
    unittest.main()
