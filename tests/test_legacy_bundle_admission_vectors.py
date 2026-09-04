"""Independent executable adapter for DACS-5 LAB-1..LAB-7 vectors."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import sys
import unittest
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import jcs  # noqa: E402


VECTOR_PATH = (
    ROOT / "conformance" / "vectors" / "security"
    / "legacy-bundle-admission-v0.6.json"
)
SPEC = ROOT / "spec" / "DACS-5-VERIFY.md"
MAPPING = ROOT / "spec" / "DEMOS-MAPPING.md"
CHECKPOINT_DOMAIN = b"dacs-legacy-bundle-checkpoint:v1:"
BINDING_DOMAIN = b"dacs-legacy-bundle-checkpoint-binding:v1:"


def canonical_vectors(vectors: list[dict]) -> bytes:
    return json.dumps(
        vectors, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def result(verdict: str) -> dict:
    disposition = {
        "pass": "eligible",
        "fail": "ineligible",
        "indeterminate": "indeterminate",
    }[verdict]
    return {
        "expected": verdict,
        "want": {
            "admissionDisposition": disposition,
            "reputationEffect": "include" if verdict == "pass" else "exclude",
            "auditInspectable": True,
            "authoritativeAbsence": False,
            "partyFaultCreatedByGate": False,
        },
    }


def artifact_hash(value: dict) -> str:
    unsigned = {key: item for key, item in value.items() if key != "signature"}
    return hashlib.sha256(jcs.canonicalize(unsigned).encode("utf-8")).hexdigest()


def signature_valid(value: dict, domain: bytes) -> bool:
    signature = value.get("signature")
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm", "signer", "value"
    }:
        return False
    signer = signature.get("signer")
    encoded = signature.get("value")
    if (
        signature.get("algorithm") != "ed25519"
        or not isinstance(signer, str)
        or not signer.startswith("key:")
        or not isinstance(encoded, str)
    ):
        return False
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer[4:]))
        raw_signature = base64.urlsafe_b64decode(
            encoded + "=" * ((4 - len(encoded) % 4) % 4)
        )
        public.verify(
            raw_signature,
            domain + artifact_hash(value).encode("ascii"),
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_checkpoint(value: dict) -> tuple[str, tuple[int, int] | None, str | None]:
    checkpoint = value.get("checkpoint")
    if not isinstance(checkpoint, dict) or checkpoint.get("state") != "finalized":
        return "indeterminate", None, None

    discovery = checkpoint.get("discovery")
    if not isinstance(discovery, dict):
        return "indeterminate", None, None
    requested_substrate = value.get("bundleAnchorSubstrate")
    if not isinstance(requested_substrate, str):
        return "fail", None, None
    expected_logical = (
        "dacs5:legacy-bundle-checkpoint:v1:"
        + quote(requested_substrate, safe="-._~")
    )
    if (
        discovery.get("mechanism") != "steward-well-known-or-dacs-catalog"
        or discovery.get("requestedLogicalAddress") != expected_logical
    ):
        return "fail", None, None
    candidates = discovery.get("candidateBindings")
    if not isinstance(candidates, list) or not candidates:
        return "indeterminate", None, None
    if len(candidates) != 1:
        return "indeterminate", None, None
    binding = candidates[0]
    if not isinstance(binding, dict) or set(binding) != {
        "checkpointBindingVersion",
        "substrate",
        "logicalAddress",
        "nativeAddress",
        "checkpointContentHash",
        "anchorTx",
        "signer",
        "signature",
    }:
        return "fail", None, None
    authorized = checkpoint.get("authorizedStewards")
    if not isinstance(authorized, list):
        return "indeterminate", None, None
    binding_signature = binding.get("signature")
    if (
        binding.get("checkpointBindingVersion") != "1"
        or binding.get("substrate") != requested_substrate
        or binding.get("logicalAddress") != expected_logical
        or binding.get("signer") not in authorized
        or not isinstance(binding_signature, dict)
        or binding_signature.get("signer") != binding.get("signer")
        or not signature_valid(binding, BINDING_DOMAIN)
    ):
        return "fail", None, None

    anchored = checkpoint.get("anchoredRecords")
    resolved = (
        anchored.get(binding.get("nativeAddress"))
        if isinstance(anchored, dict)
        else None
    )
    if not isinstance(resolved, dict):
        return "indeterminate", None, None
    artifact = resolved.get("artifact")
    receipt = resolved.get("receipt")
    if not isinstance(artifact, dict) or not isinstance(receipt, dict):
        return "fail", None, None
    if set(artifact) != {
        "legacyBundleCheckpointVersion",
        "substrate",
        "policy",
        "createdAt",
        "signature",
    }:
        return "fail", None, None
    checkpoint_hash = artifact_hash(artifact)
    artifact_signature = artifact.get("signature")
    if (
        artifact.get("legacyBundleCheckpointVersion") != "1"
        or artifact.get("substrate") != requested_substrate
        or artifact.get("policy") != "legacy-attestation-pre-checkpoint-only"
        or not isinstance(artifact_signature, dict)
        or artifact_signature.get("signer") != binding.get("signer")
        or artifact_signature.get("signer") not in authorized
        or not signature_valid(artifact, CHECKPOINT_DOMAIN)
        or binding.get("checkpointContentHash") != checkpoint_hash
    ):
        return "fail", None, None

    if (
        receipt.get("receiptVersion") != "1"
        or receipt.get("substrate") != requested_substrate
        or receipt.get("finalityProfile") != "demos-bft-final"
        or receipt.get("logicalAddress") != expected_logical
        or receipt.get("nativeAddress") != binding.get("nativeAddress")
        or receipt.get("contentHash") != checkpoint_hash
        or receipt.get("transactionRef")
        != {"kind": "demos-transaction", "value": binding.get("anchorTx")}
        or receipt.get("writer")
        != str(binding.get("signer", "")).removeprefix("key:")
        or receipt.get("state") != "finalized"
        or receipt.get("observationDisposition") != "established"
    ):
        return "fail", None, None
    block = receipt.get("blockRef")
    evidence = receipt.get("evidence")
    if (
        not isinstance(block, dict)
        or not isinstance(evidence, dict)
        or evidence.get("kind") != "demos-bft-final"
    ):
        return "fail", None, None
    try:
        proof = json.loads(evidence["value"])
        height = int(block["height"])
        if proof.get("blockHeight") != block["height"]:
            return "fail", None, None
        if proof.get("transactionHash") != binding.get("anchorTx"):
            return "fail", None, None
        transaction_index = proof["transactionIndex"]
        if not isinstance(transaction_index, int) or transaction_index < 0:
            return "fail", None, None
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return "indeterminate", None, None
    return "pass", (height, transaction_index), requested_substrate


def evaluate(vector: dict) -> dict:
    value = vector["input"]
    bundle = value["bundle"]
    if bundle["type"] != "legacy":
        return result("pass")

    checkpoint_verdict, checkpoint_order, checkpoint_substrate = verify_checkpoint(value)
    if checkpoint_verdict != "pass":
        return result(checkpoint_verdict)

    history = value.get("historicalAnchor")
    if not history or history.get("state") != "finalized":
        return result("indeterminate")
    if not history.get("ordered", False):
        return result("indeterminate")
    if checkpoint_substrate != history.get("substrate"):
        return result("fail")
    if history.get("role") != value.get("resolvedRole"):
        return result("fail")
    if history.get("contentHash") != bundle.get("contentHash"):
        return result("fail")
    history_order = (history.get("order"), history.get("transactionIndex", 0))
    if not isinstance(history_order[0], int) or history_order >= checkpoint_order:
        return result("fail")
    return result("pass")


class LegacyBundleAdmissionVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        cls.vectors = cls.data["vectors"]
        cls.by_name = {item["name"]: item for item in cls.vectors}

    def test_metadata_and_hash(self):
        self.assertEqual(self.data["set"], VECTOR_PATH.stem)
        self.assertEqual(self.data["count"], len(self.vectors))
        self.assertEqual(len(self.by_name), len(self.vectors))
        self.assertEqual(
            self.data["hash"],
            hashlib.sha256(canonical_vectors(self.vectors)).hexdigest(),
        )

    def test_independent_adapter_matches_every_vector(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["name"]):
                actual = evaluate(vector)
                self.assertEqual(actual["expected"], vector["expected"])
                self.assertEqual(actual["want"], vector["want"])

    def test_adversarial_acceptance_criteria_are_present(self):
        required = {
            "lab-cross-role-rebind-rejected",
            "lab-fresh-legacy-post-checkpoint",
            "lab-backdated-fresh-legacy",
            "lab-historical-replay-after-checkpoint",
            "lab-anchor-history-missing",
        }
        self.assertTrue(required.issubset(self.by_name))

    def test_timestamps_do_not_override_receipt_order(self):
        vector = self.by_name["lab-backdated-fresh-legacy"]
        self.assertLess(vector["input"]["bundle"]["finalisedAt"], 100)
        self.assertGreater(vector["input"]["historicalAnchor"]["order"], 100)
        self.assertEqual(evaluate(vector)["expected"], "fail")

    def test_role_history_is_not_transferable(self):
        vector = self.by_name["lab-cross-role-rebind-rejected"]
        self.assertNotEqual(
            vector["input"]["resolvedRole"],
            vector["input"]["historicalAnchor"]["role"],
        )
        self.assertFalse(vector["want"]["authoritativeAbsence"])

    def test_spec_defines_complete_lab_family_and_replay_context(self):
        text = SPEC.read_text(encoding="utf-8")
        for number in range(1, 8):
            self.assertIn(f"(LAB-{number})", text)
        self.assertIn("LegacyBundleActivationCheckpoint", text)
        self.assertIn("dacs-legacy-bundle-checkpoint:v1:", text)
        self.assertIn("LegacyBundleEraEvidence", text)
        self.assertIn("strictly before the checkpoint", text)
        self.assertIn("LegacyBundleCheckpointBinding", text)
        self.assertIn("dacs-legacy-bundle-checkpoint-binding:v1:", text)
        mapping = MAPPING.read_text(encoding="utf-8")
        self.assertIn("LegacyBundleCheckpointBinding", mapping)
        self.assertIn("steward's well-known index", mapping)

    def test_checkpoint_is_resolved_and_cryptographically_verified(self):
        vector = self.by_name["lab-authentic-historical-buyer"]
        checkpoint = vector["input"]["checkpoint"]
        binding = checkpoint["discovery"]["candidateBindings"][0]
        resolved = checkpoint["anchoredRecords"][binding["nativeAddress"]]
        self.assertTrue(signature_valid(binding, BINDING_DOMAIN))
        self.assertTrue(signature_valid(resolved["artifact"], CHECKPOINT_DOMAIN))
        self.assertEqual(
            resolved["receipt"]["contentHash"], artifact_hash(resolved["artifact"])
        )
        self.assertEqual(verify_checkpoint(vector["input"])[0], "pass")


if __name__ == "__main__":
    unittest.main()
