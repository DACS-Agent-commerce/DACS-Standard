import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import sr2_resolution_reference as sr2  # noqa: E402


def definition(kind, identifier, version, family="self-signed"):
    """Unsigned selector-unit projection; not an admitted Recipe/RailDefinition."""
    if kind == "recipe":
        return {
            "recipeVersion": version,
            "scheme": identifier,
            "defaultMethod": {"kind": family},
            "availability": "live",
        }
    return {"railVersion": version, "railId": identifier, "availability": "live"}


def entry(kind, identifier, version, document, suffix):
    locator = f"memory:{kind}:{suffix}"
    return {
        "id": identifier,
        "version": version,
        "anchor": {"kind": "storage-program", "locator": locator},
        "contentHash": sr2.hash_hex(document),
    }, locator


def selection_case(kind, entries, documents, query, checks=None):
    native = f"memory:{kind}:index"
    return {"registryKind": kind, "nativeIndexAddress": native}, {
        "indexStorage": {
            native: {
                "registryIndexVersion": "1",
                "registryKind": kind,
                "revision": 1,
                "entries": entries,
            }
        },
        "definitionStorage": documents,
        "definitionQuery": query,
        "definitionChecks": checks
        or {"signatureVerified": True, "semanticRulesVerified": True},
    }


class RegistryIndexSelectionTests(unittest.TestCase):
    def test_index_versions_are_positive_safe_integers_without_coercion(self):
        document = definition("recipe", "sample", 1)
        item, _ = entry("recipe", "sample", 1, document, "one")
        snapshot = {
            "registryIndexVersion": "1",
            "registryKind": "recipe",
            "revision": 1,
            "entries": [item],
        }
        descriptor = {"registryKind": "recipe", "sequence": 1}
        self.assertTrue(sr2._valid_index_snapshot(snapshot, descriptor))
        for value in ("1", 1.0, True, 0, 9007199254740992):
            candidate = copy.deepcopy(snapshot)
            candidate["entries"][0]["version"] = value
            with self.subTest(version=value):
                self.assertFalse(sr2._valid_index_snapshot(candidate, descriptor))

    def test_nfc_equivalent_index_identities_are_duplicates(self):
        composed = definition("recipe", "café", 1)
        decomposed = definition("recipe", "cafe\u0301", 1)
        first, _ = entry("recipe", "café", 1, composed, "composed")
        second, _ = entry("recipe", "cafe\u0301", 1, decomposed, "decomposed")
        snapshot = {
            "registryIndexVersion": "1",
            "registryKind": "recipe",
            "revision": 1,
            "entries": [first, second],
        }
        self.assertFalse(
            sr2._valid_index_snapshot(
                snapshot, {"registryKind": "recipe", "sequence": 1}
            )
        )

    def test_nfc_lookup_and_definition_identity_do_not_rewrite_input(self):
        document = definition("recipe", "café", 1)
        item, locator = entry("recipe", "cafe\u0301", 1, document, "one")
        head, case = selection_case(
            "recipe",
            [item],
            {locator: document},
            {"id": "café", "family": "self-signed", "version": 1},
        )
        original_head = copy.deepcopy(head)
        original_case = copy.deepcopy(case)
        self.assertEqual(sr2._definition_result(head, case), "pass")
        self.assertEqual(head, original_head)
        self.assertEqual(case, original_case)

    def test_exact_pin_and_fetched_definition_versions_are_numeric_and_equal(self):
        document = definition("recipe", "sample", 1)
        item, locator = entry("recipe", "sample", 1, document, "one")
        head, case = selection_case(
            "recipe",
            [item],
            {locator: document},
            {"id": "sample", "family": "self-signed", "version": "1"},
        )
        self.assertEqual(sr2._definition_result(head, case), "fail")

        wrong_definition = definition("recipe", "sample", 2)
        wrong_item, wrong_locator = entry(
            "recipe", "sample", 1, wrong_definition, "wrong-version"
        )
        head, case = selection_case(
            "recipe",
            [wrong_item],
            {wrong_locator: wrong_definition},
            {"id": "sample", "family": "self-signed", "version": 1},
        )
        self.assertEqual(sr2._definition_result(head, case), "fail")

    def test_latest_recipe_is_numeric_greatest_in_exact_family(self):
        documents = {}
        entries = []
        for version, family in (
            (2, "self-signed"),
            (11, "domain-tls-control"),
            (10, "self-signed"),
        ):
            document = definition("recipe", "sample", version, family)
            item, locator = entry(
                "recipe", "sample", version, document, str(version)
            )
            entries.append(item)
            documents[locator] = document
        head, case = selection_case(
            "recipe",
            entries,
            documents,
            {"id": "sample", "family": "self-signed"},
        )
        status, selected = sr2._select_definition(head, case)
        self.assertEqual(status, "pass")
        self.assertEqual(selected["recipeVersion"], 10)
        self.assertEqual(sr2._definition_result(head, case), "pass")

    def test_unclassifiable_or_unavailable_higher_recipe_never_falls_back(self):
        older = definition("recipe", "sample", 2)
        older_entry, older_locator = entry(
            "recipe", "sample", 2, older, "older"
        )
        malformed = {"recipeVersion": 3, "scheme": "sample"}
        malformed_entry, malformed_locator = entry(
            "recipe", "sample", 3, malformed, "malformed"
        )
        head, case = selection_case(
            "recipe",
            [older_entry, malformed_entry],
            {older_locator: older, malformed_locator: malformed},
            {"id": "sample", "family": "self-signed"},
        )
        self.assertEqual(sr2._definition_result(head, case), "fail")

        case["definitionStorage"].pop(malformed_locator)
        self.assertEqual(sr2._definition_result(head, case), "indeterminate")

        unknown = definition("recipe", "sample", 3, "future-unknown")
        unknown_entry, unknown_locator = entry(
            "recipe", "sample", 3, unknown, "unknown"
        )
        head, case = selection_case(
            "recipe",
            [older_entry, unknown_entry],
            {older_locator: older, unknown_locator: unknown},
            {"id": "sample", "family": "self-signed"},
        )
        self.assertEqual(sr2._definition_result(head, case), "fail")

    def test_latest_rail_is_numeric_greatest_for_nfc_id(self):
        documents = {}
        entries = []
        for identifier, version in (
            ("rail-é", 2),
            ("rail-e\u0301", 10),
            ("other", 20),
        ):
            document = definition("rail", identifier, version)
            item, locator = entry(
                "rail", identifier, version, document, f"{identifier}-{version}"
            )
            entries.append(item)
            documents[locator] = document
        head, case = selection_case(
            "rail", entries, documents, {"id": "rail-é"}
        )
        status, selected = sr2._select_definition(head, case)
        self.assertEqual(status, "pass")
        self.assertEqual(selected["railVersion"], 10)


class ModeledHistoricalTraversalTests(unittest.TestCase):
    KEY_ID = "key:" + "11" * 32

    def chain_case(self, mode, target_sequence=None, target_hash=None):
        root = {"sequence": 1, "authorityKeyId": self.KEY_ID, "label": "root"}
        root_hash = sr2.descriptor_hash(root)
        target = {
            "sequence": 2,
            "supersedesDescriptorHash": root_hash,
            "label": "target",
        }
        target_descriptor_hash = sr2.descriptor_hash(target)
        left = {
            "sequence": 3,
            "supersedesDescriptorHash": target_descriptor_hash,
            "label": "left",
        }
        right = {
            "sequence": 3,
            "supersedesDescriptorHash": target_descriptor_hash,
            "label": "right",
        }
        case = {
            "expectedRegistryTuple": {
                "registryKind": "recipe",
                "registryLogicalAddress": "dacs2:registry:v0.1",
                "substrate": "modeled:test",
                "registryBootstrapVersion": "1",
            },
            "trustPin": {"authorityKeyId": self.KEY_ID},
            "verifiedReceiptEvidence": [],
            "indexStorage": {},
            "mode": mode,
            "descriptors": [root, target, left, right],
        }
        if mode == "historical":
            case["targetSequence"] = target_sequence or 2
            case["targetDescriptorHash"] = target_hash or target_descriptor_hash
        return case

    def test_historical_stops_after_authenticating_exact_target(self):
        case = self.chain_case("historical")
        with (
            patch.object(sr2, "_validate_root", return_value="pass"),
            patch.object(sr2, "_validate_successor", return_value="pass") as successor,
            patch.object(sr2, "_definition_result", return_value="pass"),
        ):
            self.assertEqual(
                sr2.evaluate_vector({"family": "bootstrap", "input": case}),
                "pass",
            )
        self.assertEqual(successor.call_count, 1)

    def test_fork_at_target_is_indeterminate_and_latest_keeps_ambiguity(self):
        historical = self.chain_case("historical")
        root, first = historical["descriptors"][:2]
        competing = {
            "sequence": 2,
            "supersedesDescriptorHash": sr2.descriptor_hash(root),
            "label": "competing-target",
        }
        historical["descriptors"] = [root, first, competing]
        latest = copy.deepcopy(historical)
        latest["mode"] = "latest"
        latest.pop("targetSequence")
        latest.pop("targetDescriptorHash")
        with (
            patch.object(sr2, "_validate_root", return_value="pass"),
            patch.object(sr2, "_validate_successor", return_value="pass"),
            patch.object(sr2, "_definition_result", return_value="pass"),
        ):
            self.assertEqual(
                sr2.evaluate_vector({"family": "bootstrap", "input": historical}),
                "indeterminate",
            )
            self.assertEqual(
                sr2.evaluate_vector({"family": "bootstrap", "input": latest}),
                "indeterminate",
            )

    def test_fork_before_target_is_indeterminate(self):
        historical = self.chain_case("historical")
        root, first, _, later = historical["descriptors"]
        competing = {
            "sequence": 2,
            "supersedesDescriptorHash": sr2.descriptor_hash(root),
            "label": "competing-before-target",
        }
        historical["descriptors"] = [root, first, competing, later]
        historical["targetSequence"] = 3
        historical["targetDescriptorHash"] = sr2.descriptor_hash(later)
        with (
            patch.object(sr2, "_validate_root", return_value="pass"),
            patch.object(sr2, "_validate_successor", return_value="pass"),
            patch.object(sr2, "_definition_result", return_value="pass"),
        ):
            self.assertEqual(
                sr2.evaluate_vector({"family": "bootstrap", "input": historical}),
                "indeterminate",
            )


if __name__ == "__main__":
    unittest.main()
