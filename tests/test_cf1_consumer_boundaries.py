"""Pin existing CF-1 consumer outcomes without changing their result contracts."""

import copy
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import jcs  # noqa: E402
import listing_admission  # noqa: E402
import listing_artifact  # noqa: E402
import sr2_resolution_reference as sr2  # noqa: E402
from test_dacs_adapter import request, run_adapter  # noqa: E402
from test_listing_admission_bridge import _legacy_listing  # noqa: E402


class CF1ConsumerBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        security = ROOT / "conformance" / "vectors" / "security"
        cls.vectors = {
            vector["name"]: vector["input"]
            for filename in (
                "sr2-logical-native-resolution-v0.1.json",
                "registry-bootstrap-v0.1.json",
            )
            for vector in json.loads((security / filename).read_text())["vectors"]
        }

    def test_listing_refusal_precedes_signature_and_length_checks(self):
        listing = _legacy_listing()
        inclusion_key = listing["signature"]["signer"].removeprefix("key:")

        def admit(value):
            return listing_admission.admit_listing(
                value,
                inclusion_key=inclusion_key,
                session_boundary="past-authenticated-agreement-commitment",
            )

        self.assertTrue(listing_artifact.validate_listing_shape(listing)[0])
        with (
            mock.patch.object(
                listing_admission, "_verify_listing_signature",
                wraps=listing_admission._verify_listing_signature,
            ) as signature,
            mock.patch.object(
                listing_artifact, "_chars", wraps=listing_artifact._chars,
            ) as length,
        ):
            self.assertEqual(admit(listing), (
                "indeterminate", "authenticated committed-session admission is unavailable", None,
            ))
            self.assertEqual(signature.call_count, 1)
            self.assertGreater(length.call_count, 0)

        for placement in ("unknown-member", "offering.title"):
            with self.subTest(placement=placement):
                refused = copy.deepcopy(listing)
                if placement == "unknown-member":
                    refused["futurePolicyHint"] = chr(0x105C9)
                else:
                    refused["offering"]["title"] = chr(0x105C9)
                self.assertEqual(
                    listing_artifact.validate_listing_shape(refused)[1],
                    "listing is not canonicalizable under CORE profile",
                )
                with (
                    mock.patch.object(
                        listing_admission, "_verify_listing_signature",
                        wraps=listing_admission._verify_listing_signature,
                    ) as signature,
                    mock.patch.object(
                        listing_artifact, "_chars", wraps=listing_artifact._chars,
                    ) as length,
                ):
                    self.assertEqual(admit(refused), (
                        "rejected", "listing shape is invalid", None,
                    ))
                    self.assertEqual(signature.call_count, 0)
                    self.assertEqual(length.call_count, 0)

    def _refused_direct(self):
        case = copy.deepcopy(self.vectors["direct-finalized-receipt-resolves"])
        self.assertEqual(sr2.evaluate_resolution(case), "pass")
        self.assertEqual(len(case["carriers"]), 1)
        receipt = case["carriers"][0]["receipt"]
        receipt["futurePolicyHint"] = "ascii"
        self.assertTrue(sr2._valid_receipt_shape(receipt))
        receipt["futurePolicyHint"] = chr(0x105C9)
        self.assertFalse(sr2._valid_receipt_shape(receipt))
        with self.assertRaises(jcs.UnicodeRepertoireError):
            jcs.canonicalize(receipt)
        return case

    def test_direct_refusal_discards_only_the_bad_carrier(self):
        refused = self._refused_direct()
        self.assertEqual(sr2.evaluate_resolution(refused), "indeterminate")
        valid = self.vectors["direct-finalized-receipt-resolves"]["carriers"][0]
        for position in (0, 1):
            with self.subTest(valid_position=position):
                mixed = copy.deepcopy(refused)
                mixed["carriers"].insert(position, copy.deepcopy(valid))
                self.assertEqual(sr2.evaluate_resolution(mixed), "pass")

    def test_authenticated_reference_survives_a_refused_receipt(self):
        refused = self._refused_direct()["carriers"][0]
        control = self.vectors["finalized-bundle-reference-dereferences"]
        self.assertEqual(sr2.evaluate_resolution(control), "pass")
        for position in (0, 1):
            with self.subTest(refused_position=position):
                case = copy.deepcopy(control)
                case["carriers"].insert(position, copy.deepcopy(refused))
                self.assertEqual(sr2.evaluate_resolution(case), "pass")

    def test_authenticated_absence_survives_a_sole_refused_receipt(self):
        case = self._refused_direct()
        case.update(
            claimsAbsent=True,
            absencePolicy={"declared": True, "satisfied": True},
        )
        self.assertEqual(sr2.evaluate_resolution(case), "pass")
        for field in ("declared", "satisfied"):
            with self.subTest(missing_policy_condition=field):
                incomplete = copy.deepcopy(case)
                incomplete["absencePolicy"][field] = False
                self.assertEqual(sr2.evaluate_resolution(incomplete), "indeterminate")
        case["claimsAbsent"] = False
        self.assertEqual(sr2.evaluate_resolution(case), "indeterminate")

    def test_bootstrap_snapshot_refuses_uncanonicalizable_receipt(self):
        case = copy.deepcopy(self.vectors["valid-recipe-registry-root"])
        descriptor = case["descriptors"][0]
        self.assertEqual(sr2._verify_snapshot(descriptor, case), "pass")
        receipt = descriptor["indexAnchorReceipt"]
        receipt["futurePolicyHint"] = "ascii"
        self.assertTrue(sr2._valid_receipt_shape(receipt))
        receipt["futurePolicyHint"] = chr(0x105C9)
        self.assertFalse(sr2._valid_receipt_shape(receipt))
        with self.assertRaises(jcs.UnicodeRepertoireError):
            jcs.canonicalize(receipt)
        self.assertEqual(sr2._verify_snapshot(descriptor, case), "fail")

    def test_adapter_jsonl_keeps_generic_code_and_specific_diagnostic(self):
        completed, responses = run_adapter([
            request("before", "execute", operation="canonicalize", params=[{"label": "ascii"}]),
            request("refused", "execute", operation="canonicalize", params=[{"label": chr(0x105C9)}]),
            request("after", "execute", operation="canonicalize", params=[{"label": "ascii"}]),
        ])
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual([item["id"] for item in responses], ["before", "refused", "after"])
        self.assertTrue(responses[0]["ok"])
        self.assertFalse(responses[1]["ok"])
        self.assertEqual(responses[1]["error"]["code"], "OPERATION_FAILED")
        self.assertIn("UNASSIGNED-CODE-POINT", responses[1]["error"]["message"])
        self.assertTrue(responses[2]["ok"])

    def test_release_proposal_selects_the_pinned_repertoire_case(self):
        descriptor = json.loads((
            ROOT / "conformance" / "interop" / "dacs-adapter-release-proposal-v1.json"
        ).read_text())
        family = next(item for item in descriptor["families"] if item["id"] == "canonicalization")
        selected = [item for item in family["cases"] if item["caseId"] == "unassigned-in-unicode-15-0"]
        self.assertEqual(selected, [{
            "caseId": "unassigned-in-unicode-15-0",
            "sourceExpected": "fail",
            "sourceExpectedErrorCode": "UNASSIGNED-CODE-POINT",
            "expectedErrorCode": "OPERATION_FAILED",
        }])
        source = json.loads((ROOT / descriptor["sources"][family["source"]]["path"]).read_text())
        vector = next(item for item in source["vectors"] if item["name"] == selected[0]["caseId"])
        self.assertEqual(vector["input"], {"label": chr(0x105C9)})
