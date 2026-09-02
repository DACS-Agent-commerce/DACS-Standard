import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAPPING = ROOT / "spec" / "DEMOS-MAPPING.md"
DACS5 = ROOT / "spec" / "DACS-5-VERIFY.md"


class DemosMappingBundleCosigningTests(unittest.TestCase):
    def test_mapping_does_not_gate_dacs_on_native_transaction_cosigning(self):
        mapping = MAPPING.read_text(encoding="utf-8")
        self.assertIn(
            "Optional native multi-party Storage Program transaction-signature helper",
            mapping,
        )
        self.assertIn("not a DACS v0.1 dependency", mapping)
        self.assertIn(
            "A future one-transaction multi-party helper is an optimization only",
            mapping,
        )
        self.assertNotIn(
            "🟡 Native multi-party Storage Program signature helper", mapping
        )

    def test_normative_bundle_contract_keeps_both_signature_layers_separate(self):
        dacs5 = DACS5.read_text(encoding="utf-8")
        self.assertIn("Required signers: buyer + seller", dacs5)
        self.assertIn(
            "Each signing party (buyer, seller, and orchestrator if distinct) anchors its own bundle",
            dacs5,
        )
        self.assertIn(
            "Each anchored copy MUST set `anchoredByRole` to the role of the anchoring party",
            dacs5,
        )


if __name__ == "__main__":
    unittest.main()
