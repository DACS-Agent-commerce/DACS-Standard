import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "cci-xm-rail-chain-applicability-v0.5.json"
)
MANIFEST = ROOT / "conformance" / "MANIFEST.json"
DACS1 = ROOT / "spec" / "DACS-1-IDENTIFY.md"
DACS4 = ROOT / "spec" / "DACS-4-SETTLE.md"

CHAIN_ID_RE = re.compile(r"[1-9][0-9]*\Z")


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def claim_eip155_chain(claim):
    if not isinstance(claim, str):
        return None
    parts = claim.split(":", 3)
    if len(parts) != 4 or parts[0].lower() != "cci-xm" or parts[1] != "evm":
        return None
    subchain = parts[2]
    if CHAIN_ID_RE.fullmatch(subchain) is None:
        return None
    address = parts[3].split("?", 1)[0]
    if not address:
        return None
    return f"eip155:{subchain}"


def rail_eip155_chain(rail):
    # This focused PB-2 predicate assumes the other RD-5 railType/asset/network
    # kind-coherence checks have already passed.
    network = rail.get("network")
    asset = rail.get("asset")
    if not isinstance(network, dict) or not isinstance(asset, dict):
        raise ValueError("malformed rail")
    if network.get("kind") != "evm":
        return None

    chain_id = network.get("chainId")
    if type(chain_id) is not int or chain_id <= 0:
        raise ValueError("invalid network chainId")
    if asset.get("kind") in {"erc20", "native-evm"}:
        asset_chain_id = asset.get("chainId")
        if type(asset_chain_id) is not int or asset_chain_id != chain_id:
            raise ValueError("RD-5 asset/network chainId mismatch")
    return f"eip155:{chain_id}"


def evaluate(vector):
    claim_chain = claim_eip155_chain(vector["claim"])
    try:
        rail_chain = rail_eip155_chain(vector["railDefinition"])
    except ValueError:
        return {
            "expected": "error",
            "railChain": None,
            "claimChain": claim_chain,
            "tier2Applicable": False,
            "bindingTier": None,
            "maySubmitPayment": False,
            "failedAt": "RD-5",
        }

    applicable = rail_chain is not None and claim_chain == rail_chain
    common = {
        "railChain": rail_chain,
        "claimChain": claim_chain,
        "tier2Applicable": applicable,
    }
    if not applicable:
        if vector["tier3AgreementAssertionPresent"]:
            return {
                "expected": "pass",
                **common,
                "bindingTier": 3,
                "maySubmitPayment": True,
            }
        return {
            "expected": "fail",
            **common,
            "bindingTier": None,
            "maySubmitPayment": False,
        }

    linkage = vector.get("linkageDecision")
    if linkage == "pass":
        return {
            "expected": "pass",
            **common,
            "bindingTier": 2,
            "maySubmitPayment": True,
        }
    if linkage == "indeterminate":
        return {
            "expected": "indeterminate",
            **common,
            "bindingTier": None,
            "maySubmitPayment": False,
            "sessionTransition": "paused",
            "mustNotUseTier3": True,
        }
    if linkage == "error":
        return {
            "expected": "error",
            **common,
            "bindingTier": None,
            "maySubmitPayment": False,
            "mustNotUseTier3": True,
        }
    raise ValueError("applicable tier-2 vector requires a linkageDecision")


class CciXmRailChainApplicabilityVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.by_name = {vector["name"]: vector for vector in cls.data["vectors"]}

    def test_vector_hash_and_count_are_byte_exact(self):
        self.assertEqual(self.data["count"], len(self.data["vectors"]))
        self.assertEqual(
            self.data["hash"],
            hashlib.sha256(canonical_json(self.data["vectors"])).hexdigest(),
        )

    def test_every_vector_executes_to_its_pinned_result(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                got = evaluate(vector)
                self.assertEqual(got.pop("expected"), vector["expected"])
                self.assertEqual(got, vector["want"])

    def test_named_network_labels_never_establish_tier2(self):
        names = [
            "mainnet-label-is-not-base-chain-id",
            "testnet-label-is-not-ethereum-sepolia",
            "sepolia-label-is-not-ethereum-sepolia",
            "base-label-is-not-base-chain-id",
        ]
        for name in names:
            with self.subTest(vector=name):
                result = evaluate(self.by_name[name])
                self.assertIsNone(result["claimChain"])
                self.assertFalse(result["tier2Applicable"])
                self.assertEqual(result["bindingTier"], 3)
                self.assertTrue(result["maySubmitPayment"])

    def test_mainnet_and_testnet_examples_are_distinguished_by_chain_id(self):
        expected = {
            "ethereum-mainnet-exact-chain-id-tier2": "eip155:1",
            "base-mainnet-exact-chain-id-tier2": "eip155:8453",
            "ethereum-sepolia-exact-chain-id-tier2": "eip155:11155111",
            "base-sepolia-exact-chain-id-tier2": "eip155:84532",
        }
        for name, chain in expected.items():
            with self.subTest(vector=name):
                result = evaluate(self.by_name[name])
                self.assertEqual(result["claimChain"], chain)
                self.assertEqual(result["railChain"], chain)
                self.assertTrue(result["tier2Applicable"])

    def test_exact_match_prevents_linkage_failure_downgrade(self):
        for name in [
            "exact-chain-match-unresolvable-linkage-pauses",
            "exact-chain-match-linkage-error-does-not-downgrade",
        ]:
            with self.subTest(vector=name):
                result = evaluate(self.by_name[name])
                self.assertTrue(result["tier2Applicable"])
                self.assertFalse(result["maySubmitPayment"])
                self.assertTrue(result["mustNotUseTier3"])

    def test_address_is_nonempty_but_otherwise_opaque_for_chain_applicability(self):
        for name in [
            "nonempty-opaque-address-establishes-tier2",
            "claim-parameters-do-not-change-tier2-chain",
        ]:
            with self.subTest(vector=name):
                result = evaluate(self.by_name[name])
                self.assertEqual(result["claimChain"], "eip155:8453")
                self.assertTrue(result["tier2Applicable"])
                self.assertEqual(result["bindingTier"], 2)

        for name in [
            "empty-address-does-not-establish-tier2",
            "parameter-only-address-does-not-establish-tier2",
            "uppercase-family-does-not-establish-tier2",
        ]:
            with self.subTest(vector=name):
                result = evaluate(self.by_name[name])
                self.assertIsNone(result["claimChain"])
                self.assertFalse(result["tier2Applicable"])
                self.assertEqual(result["bindingTier"], 3)

    def test_later_x402_receipt_chain_cannot_retroactively_create_tier2(self):
        result = evaluate(self.by_name["x402-resource-without-pinned-chain-uses-tier3"])
        self.assertIsNone(result["railChain"])
        self.assertFalse(result["tier2Applicable"])
        self.assertEqual(result["bindingTier"], 3)

    def test_rd5_rejects_two_chain_ids_for_one_evm_rail(self):
        result = evaluate(self.by_name["asset-and-network-chain-id-mismatch-rejects-rail"])
        self.assertEqual(result["expected"], "error")
        self.assertEqual(result["failedAt"], "RD-5")
        self.assertFalse(result["maySubmitPayment"])

    def test_rd5_requires_equal_positive_integer_chain_ids(self):
        admitted = evaluate(self.by_name["asset-and-network-chain-id-match-admits-rail"])
        self.assertEqual(admitted["expected"], "pass")
        self.assertTrue(admitted["maySubmitPayment"])

        for name in [
            "zero-asset-chain-id-rejects-rail",
            "both-zero-chain-ids-reject-rail",
            "zero-network-chain-id-rejects-rail",
            "string-asset-chain-id-rejects-rail",
            "string-network-chain-id-rejects-rail",
        ]:
            with self.subTest(vector=name):
                result = evaluate(self.by_name[name])
                self.assertEqual(result["expected"], "error")
                self.assertEqual(result["failedAt"], "RD-5")
                self.assertFalse(result["maySubmitPayment"])

    def test_manifest_no_longer_promotes_the_contradictory_golden(self):
        cases = {
            case["id"]: case
            for case in json.loads(MANIFEST.read_text(encoding="utf-8"))["cases"]
        }
        self.assertNotIn("settlement-cross-chainid-matching-kind-pass", cases)
        corrected = cases["settlement-cross-chainid-mismatch-fail"]
        self.assertEqual(corrected["want"], "fail")
        self.assertEqual(corrected["status"], "candidate")

    def test_normative_text_pins_the_same_predicate_and_empty_alias_table(self):
        dacs1 = DACS1.read_text(encoding="utf-8")
        dacs4 = DACS4.read_text(encoding="utf-8")
        self.assertIn("`cci-xm:evm:<chainId>:<address>`", dacs1)
        self.assertIn("lowercase ASCII literal `evm`", dacs1)
        self.assertIn("address component MUST be non-empty", dacs1)
        self.assertIn("address component is otherwise", dacs4)
        self.assertIn("registers no legacy name-to-chain-ID", dacs1)
        self.assertIn("`eip155:<chainId>`", dacs1)
        self.assertIn("byte-for-byte equal", dacs4)
        self.assertIn("`mainnet`, `testnet`, or `sepolia`", dacs4)
        self.assertIn("tier 3 remains", dacs4)
        self.assertIn("MUST NOT retroactively change", dacs4)


if __name__ == "__main__":
    unittest.main()
