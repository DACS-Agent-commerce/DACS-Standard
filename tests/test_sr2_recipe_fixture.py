"""Ordinary Recipe fixture checks; no adversarial corpus generation."""
import base64
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import generate_sr2_resolution_vectors as fixtures
from sr2_resolution_reference import hash_hex


class RecipeFixtureTests(unittest.TestCase):
    def verify_steward_signature(self, recipe):
        signature = recipe["signature"]
        self.assertEqual(signature["keyId"], fixtures.OLD_KEY)
        self.assertEqual(signature["algorithm"], "ed25519")
        unsigned = {key: value for key, value in recipe.items() if key != "signature"}
        encoded = signature["value"]
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        public_key = bytes.fromhex(fixtures.OLD_KEY.removeprefix("key:"))
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            raw, b"dacs-recipe:v1:" + hash_hex(unsigned).encode("ascii")
        )

    def test_registered_recipe_has_required_schema_and_steward_signature(self):
        recipe = fixtures.sample_definition("recipe")
        self.assertEqual(recipe["scheme"], "key")
        self.assertEqual(recipe["defaultMethod"], {"kind": "self-signed"})
        self.assertEqual(type(recipe["recipeVersion"]), int)
        self.assertGreater(recipe["defaultMaxAgeSec"], 0)
        self.assertEqual(recipe["retryClass"], "permanent")
        self.assertEqual(recipe["availability"], "live")
        self.assertEqual(recipe["governance"]["proposedBy"], fixtures.OLD_KEY)
        self.assertEqual(type(recipe["governance"]["acceptedAt"]), int)
        self.assertEqual(recipe["governance"]["anchoring"], "single-signer")
        self.verify_steward_signature(recipe)

    def test_ordinary_signed_extension_and_revision_remain_complete(self):
        recipe = fixtures.sign_recipe_definition({
            **fixtures.sample_definition("recipe", 2), "futureMetric": 1.5,
        })
        self.assertEqual(recipe["governance"]["supersedes"], 1)
        self.verify_steward_signature(recipe)

    def test_ordinary_index_and_query_join_the_complete_recipe(self):
        case = fixtures.base_bootstrap("recipe", True)
        descriptor = case["descriptors"][0]
        entry = case["indexStorage"][descriptor["nativeIndexAddress"]]["entries"][0]
        recipe = case["definitionStorage"][entry["anchor"]["locator"]]
        self.assertEqual(entry["id"], recipe["scheme"])
        self.assertEqual(case["definitionQuery"]["id"], recipe["scheme"])
        self.assertEqual(entry["version"], recipe["recipeVersion"])
        self.assertEqual(entry["contentHash"], hash_hex(recipe))
        self.verify_steward_signature(recipe)
