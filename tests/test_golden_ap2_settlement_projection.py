"""Recomputation-based consistency regression for the golden AP2 settlement projection.

The public blocking row: `conformance/vectors/golden.json`
`settlement.ap2EvidenceHash` disagreed with the linked
`conformance/fixtures/settlement/settlement-ap2-reference.json`. This suite does
NOT copy a constant: it derives the golden projection from the linked fixture's
signature-excluded canonical evidence (the same JCS scope `test_ap2_reference_
fixture.py` proves the fixture's own `evidenceHash` and signature over), then
requires every dimension of the linkage to hold — and that independent mutation
of the golden hash, the linked evidence, or the linkage itself fails at the
corresponding check. Signature verification stays a separate concern: content
identity here is the signature-excluded canonical hash, and the fixture test
independently verifies the Ed25519 signature over that same hash.
"""
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import jcs  # noqa: E402

GOLDEN = ROOT / "conformance" / "vectors" / "golden.json"
FIXTURE = ROOT / "conformance" / "fixtures" / "settlement" / "settlement-ap2-reference.json"


def signature_excluded_evidence_hash(fixture: dict) -> str:
    """SHA-256 over the JCS canonical form of the fixture evidence, signature excluded.

    This is the §7.2 signed-scope exclusion: the signature member is outside the
    canonical content, so content identity never depends on (or verifies) the
    signature itself.
    """
    unsigned = copy.deepcopy(fixture["evidence"])
    unsigned.pop("signature", None)
    return hashlib.sha256(jcs.canonicalize(unsigned).encode("utf-8")).hexdigest()


class GoldenAp2SettlementProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
        cls.settlement = cls.golden["settlement"]
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def _assert_consistent(self, settlement: dict, fixture: dict) -> None:
        """Every check the golden projection must satisfy, recomputed from inputs."""
        # 1. linkage: the golden row names exactly this fixture, and it exists
        self.assertEqual(
            settlement["ap2Fixture"],
            "conformance/fixtures/settlement/settlement-ap2-reference.json",
        )
        self.assertEqual(
            (ROOT / settlement["ap2Fixture"]).resolve(), FIXTURE.resolve()
        )
        # 2. job identity: the golden job pin matches the linked evidence
        self.assertEqual(settlement["ap2JobId"], fixture["evidence"]["jobId"])
        # 3. content identity: the golden hash equals the recomputed
        #    signature-excluded canonical evidence hash of the linked fixture
        self.assertEqual(
            settlement["ap2EvidenceHash"], signature_excluded_evidence_hash(fixture)
        )
        # 4. the linked fixture's own pinned hash agrees with the recomputation
        self.assertEqual(fixture["evidenceHash"], signature_excluded_evidence_hash(fixture))
        # 5. the decision row is a pass expectation over that fixture
        self.assertEqual(settlement["decisions"]["ap2ReferencePass"], "pass")

    def test_correct_projection_passes(self):
        self._assert_consistent(self.settlement, self.fixture)

    def test_mutated_golden_hash_fails(self):
        for mutate in (
            lambda s: s.__setitem__("ap2EvidenceHash", "00" * 32),
            lambda s: s.__setitem__("ap2EvidenceHash", self.fixture["evidenceHash"][:-1] + "0"),
            lambda s: s.__setitem__(
                "ap2EvidenceHash",
                # a different but well-formed evidence's hash would drift here
                hashlib.sha256(b"other evidence").hexdigest(),
            ),
        ):
            with self.subTest(mutate=mutate.__name__ if hasattr(mutate, "__name__") else mutate):
                settlement = copy.deepcopy(self.settlement)
                mutate(settlement)
                with self.assertRaises(AssertionError):
                    self._assert_consistent(settlement, self.fixture)

    def test_mutated_linked_evidence_fails(self):
        for mutate in (
            lambda e: e.__setitem__("observedAt", e["observedAt"] + 1),
            lambda e: e["paymentAmount"].__setitem__("amount", "0.6"),
            lambda e: e["paymentTxRefs"][0].__setitem__("providerRef", "pi_other"),
            lambda e: e["paymentTxRefs"][0]["receiptAttestation"].__setitem__(
                "contentHash", "00" * 32
            ),
            lambda e: e.__setitem__("outcome", "failure"),
        ):
            with self.subTest(mutate=mutate):
                fixture = copy.deepcopy(self.fixture)
                mutate(fixture["evidence"])
                # the fixture's internal self-hash check (check 4) must also
                # fail for a payload mutation that the fixture pins
                with self.assertRaises(AssertionError):
                    self._assert_consistent(self.settlement, fixture)

    def test_mutated_linkage_fails(self):
        for mutate in (
            # golden row points at a different path
            lambda s: s.__setitem__(
                "ap2Fixture", "conformance/fixtures/settlement/other.json"
            ),
            # golden row pins a different job than the linked evidence carries
            lambda s: s.__setitem__(
                "ap2JobId", "01K4AP2PAY0000000000000005"
            ),
            # decision no longer expects the reference pass
            lambda s: s["decisions"].__setitem__("ap2ReferencePass", "fail"),
        ):
            with self.subTest(mutate=mutate):
                settlement = copy.deepcopy(self.settlement)
                mutate(settlement)
                with self.assertRaises(AssertionError):
                    self._assert_consistent(settlement, self.fixture)

    def test_hash_is_signature_excluded_not_signed_scope(self):
        """Content identity is the signature-excluded canonical form: hashing the
        evidence WITH its signature member must produce a different digest, so the
        projection cannot be a signed-scope hash in disguise."""
        with_sig = copy.deepcopy(self.fixture["evidence"])
        digest_with_sig = hashlib.sha256(
            jcs.canonicalize(with_sig).encode("utf-8")
        ).hexdigest()
        self.assertNotEqual(self.settlement["ap2EvidenceHash"], digest_with_sig)
        # and a different signature value must not change the content identity
        resigned = copy.deepcopy(self.fixture)
        resigned["evidence"]["signature"]["value"] = (
            "A" * 86
        )
        self.assertEqual(
            signature_excluded_evidence_hash(resigned),
            self.settlement["ap2EvidenceHash"],
        )


if __name__ == "__main__":
    unittest.main()
