import json
import copy
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tests.test_sealed_auction_completeness_vectors import Evaluator, VECTORS, fixture_record_receipt_matches
from scripts.generate_sealed_auction_completeness_vectors import base_material, binding_definition, signed_receipt, signed_agreement, make_vector, resign_agreement

class SelectionRoleControls(unittest.TestCase):
    def test_existing_success_vectors_preserved(self):
        vectors = json.loads(VECTORS.read_text())["vectors"]
        for vector in vectors:
            if vector["expected"] == "pass":
                with self.subTest(name=vector["name"]):
                    self.assertEqual(Evaluator(vector).evaluate(), "pass")

    def test_both_ordinary_role_directions(self):
        for phase in ("negotiate-sealed-envelope-complete", "negotiate-sealed-envelope-procurement-complete"):
            with self.subTest(phase=phase):
                entries, records = base_material()
                receipt = signed_receipt(entries, records, phase_kind=phase)
                agreement = signed_agreement(receipt)
                vector = make_vector("ordinary-role-control", "pass", "ordinary role direction", entries, records, receipt, agreement)
                self.assertEqual(Evaluator(vector).evaluate(), "pass")
                self.assertEqual(resign_agreement(agreement), agreement)

    def test_optional_reference_signer_can_be_absent(self):
        entries, records = base_material()
        entry = entries[0]
        ref = copy.deepcopy(entry["recordRef"])
        ref.pop("signer", None)
        bidder = records[ref["contentHash"]]["bidderClaim"]
        self.assertTrue(
            fixture_record_receipt_matches(
                entry["anchorReceipt"], ref, bidder, binding_definition()
            )
        )
