"""Benign numeric-selection controls for already-authenticated fixture projections.

These projections do not establish native receipt or signature authority.
"""

import unittest

import test_claim_requirement_qualification_vectors as recipes
import test_listing_rail_registry_resolution_vectors as rails


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


if __name__ == "__main__":
    unittest.main()
