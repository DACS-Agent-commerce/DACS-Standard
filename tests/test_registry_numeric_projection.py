"""Benign numeric-selection controls for already-authenticated fixture projections.

These projections do not establish native receipt or signature authority.
"""

import unittest

import test_claim_requirement_qualification_vectors as recipes
import test_listing_rail_registry_resolution_vectors as rails
import test_sr2_registry_selection as fixtures
import sr2_resolution_reference as sr2


class RegistryNumericProjectionTests(unittest.TestCase):
    def test_rail_uses_complete_numeric_inventory(self):
        data = {
            "trustPhase": "PA-2",
            "payPhases": [{"kind": "pay-new", "rail": "rail-a"}],
            "acceptedRails": [{"railId": "rail-a"}],
            "registry": {
                "state": "verified-finalized",
                "entries": [{"railId": "rail-a", "versions": [2, 10], "latestVersion": 2}],
                "definitions": [
                    {"railId": "rail-a", "railVersion": 2, "phaseHandler": "pay-old", "state": "verified-finalized"},
                    {"railId": "rail-a", "railVersion": 10, "phaseHandler": "pay-new", "state": "verified-finalized"},
                ],
            },
        }
        self.assertEqual(rails.evaluate(data), ("pass", "verified"))

    def test_recipe_uses_numeric_family_inventory(self):
        requirement = {"scheme": "email", "parameters": {"verificationMethod": "dns-txt"}}
        registry = {
            "versionsByFamily": {"email": {"dns-txt": {"2": "live", "10": "live"}}},
            "latestByFamily": {"email": {"dns-txt": 2}},
        }
        _, selected = recipes.qualification_context({"resolvedResults": []}, requirement, registry)
        self.assertEqual(selected, {"dns-txt": 10})
        requirement["recipeVersion"] = 2
        _, selected = recipes.qualification_context({"resolvedResults": []}, requirement, registry)
        self.assertEqual(selected, {"dns-txt": 2})

    def test_recipe_applies_eligibility_after_selection(self):
        requirement = {"scheme": "email", "parameters": {"verificationMethod": "dns-txt"}}
        registry = {"versionsByFamily": {"email": {"dns-txt": {"2": "live", "10": "disabled"}}}}
        with self.assertRaisesRegex(recipes.QualificationError, "not live"):
            recipes.qualification_context({"resolvedResults": []}, requirement, registry)

    def test_invalid_explicit_pin_is_checked_without_results(self):
        for value in (None, True, 0, -1, 9007199254740992):
            with self.subTest(value=value), self.assertRaises(recipes.QualificationError):
                recipes.qualification_context(
                    {"resolvedResults": []}, {"scheme": "domain", "recipeVersion": value},
                    {"versionsByFamily": {}},
                )

    def test_pa1_uses_exact_numeric_pins(self):
        data = {
            "trustPhase": "PA-1", "trustPolicyAcceptsPA1": True,
            "payPhases": [{"kind": "pay", "rail": "rail-a"}],
            "acceptedRails": [{"railId": "rail-a", "railVersion": None}],
            "inCodeDefinitions": [{"railId": "rail-a", "railVersion": 1,
                                   "phaseHandler": "pay", "governanceAnchoring": "in-code",
                                   "signatureValid": True}],
        }
        self.assertEqual(rails.evaluate(data)[0], "fail")
        data["acceptedRails"][0].pop("railVersion")
        self.assertEqual(rails.evaluate(data), ("pass", "verified-pa1"))

    def test_selected_alternative_resolves_owning_family(self):
        document = fixtures.definition("recipe", "domain", 2, family="tlsnotary")
        document["alternatives"] = [{"kind": "zktls"}]
        item, locator = fixtures.entry("recipe", "domain", 2, document, "alternative")
        head, case = fixtures.selection_case(
            "recipe", [item], {locator: document}, {"id": "domain", "method": "zktls"},
        )
        self.assertEqual(sr2._definition_result(head, case), "pass")
        registry = {
            "versionsByFamily": {"domain": {"tlsnotary": {"2": "live"}}},
            "recipeDefinitions": [document],
        }
        _, selected = recipes.qualification_context(
            {"resolvedResults": []},
            {"scheme": "domain", "parameters": {"verificationMethod": "zktls"}}, registry,
        )
        self.assertEqual(selected, {"zktls": 2})


if __name__ == "__main__":
    unittest.main()
