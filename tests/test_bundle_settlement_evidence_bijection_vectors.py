"""Executable assertions for DACS-5 v0.4 SEB-1..SEB-6 candidate vectors."""

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance/vectors/security/bundle-settlement-evidence-bijection-v0.4.json"
SPEC = ROOT / "spec/DACS-5-VERIFY.md"
CORE = ROOT / "spec/CORE.md"


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def evaluate(data):
    expected = data["expectedPhaseKeys"]
    refs = data["topLevelRefs"]
    resolved = data["resolvedReferencePhaseKeys"]
    pointers = data["pointerMap"]
    supersedes = data.get("supersedesEdges", {})

    if len(refs) != len(set(refs)):
        return "rejected", "raw-multiplicity"

    for successor, interim in supersedes.items():
        if interim in refs or successor not in refs:
            return "rejected", "st8-raw-admissibility"

    if any(ref not in resolved or resolved[ref] not in expected for ref in refs):
        return "rejected", "exact-phase-mapping"

    if len(refs) != len(expected):
        return "rejected", "exact-cardinality"

    mapped = [resolved[ref] for ref in refs]
    if len(set(mapped)) != len(mapped) or set(mapped) != set(expected):
        return "rejected", "exact-bijection"

    if len(set(pointers.values())) != len(pointers):
        return "rejected", "pointer-agreement"
    for phase_key, ref in pointers.items():
        if ref not in refs or resolved.get(ref) != phase_key:
            return "rejected", "pointer-agreement"

    if data["unrelatedAuthorityDisposition"] == "indeterminate":
        return "indeterminate", "unrelated-authority-indeterminate"
    return "verified", "ok"


class BundleSettlementEvidenceBijectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_vector_hash_count_and_names(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(self.data["hash"], hashlib.sha256(canonical_json(vectors)).hexdigest())
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_all_expected_dispositions_and_reason_codes(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(evaluate(vector["input"]), (vector["want"]["disposition"], vector["want"]["reasonCode"]))

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
