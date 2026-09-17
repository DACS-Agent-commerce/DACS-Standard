import copy
import importlib.util
import hashlib
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_artifact_shapes.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_artifact_shapes", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _types(d):
    """Fill in the per-type keys check_file expects (ftypes optional)."""
    for t in d.values():
        t.setdefault("ftypes", {})
    return d


class ArtifactShapeTests(unittest.TestCase):
    def test_repository_vectors_pass(self):
        with mock.patch.object(sys, "argv", ["validate_artifact_shapes.py"]):
            self.assertEqual(load_validator().main(), 0)

    def test_parser_captures_fields_types_and_ignores_nesting(self):
        v = load_validator()
        block = (
            "type Sample = {\n"
            '  ver: "1"\n'
            "  jobId: string\n"
            "  note?: string                 // optional comment\n"
            "  owner: ClaimReference\n"
            "  cosigners?: ClaimReference[]\n"
            "  terms: {\n"
            "    price: PriceTerm            // nested — must be ignored\n"
            "  }\n"
            "}\n"
        )
        fields = v.parse_type_fields(block)["Sample"]
        self.assertEqual(fields["required"], {"ver", "jobId", "owner", "terms"})
        self.assertEqual(fields["optional"], {"note", "cosigners"})
        self.assertEqual(fields["ftypes"]["owner"], "ClaimReference")
        self.assertEqual(fields["ftypes"]["cosigners"], "ClaimReference[]")
        self.assertNotIn("price", fields["required"] | fields["optional"])  # nested ignored

    def test_catches_missing_and_unknown_fields(self):
        v = load_validator()
        types = _types({"Foo": {"required": {"a", "b"}, "optional": {"c"}}})
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "vec.json"
            p.write_text(json.dumps({"artifacts": [{"kind": "Foo", "artifact": {"a": 1, "x": 2}}]}))
            errs, _ = v.check_file(p, types)
        joined = "\n".join(errs)
        self.assertIn("missing required field(s): ['b']", joined)
        self.assertIn("'x'", joined)

    def test_conformant_artifact_passes(self):
        v = load_validator()
        types = _types({"Foo": {"required": {"a", "b"}, "optional": {"c"}}})
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "vec.json"
            p.write_text(json.dumps({"artifacts": [{"kind": "Foo", "artifact": {"a": 1, "b": 2, "c": 3}}]}))
            errs, n = v.check_file(p, types)
            self.assertEqual(errs, [])
            self.assertEqual(n, 1)

    def test_claimref_must_be_string_with_nested_descent(self):
        # Mirrors the AttestationBundle/BundleParty/BundleSignature shape (#145):
        # primaryClaim/party are ClaimReference, reached via nested object arrays;
        # `parties`/`sigs` themselves are object arrays and MUST NOT be flagged.
        v = load_validator()
        types = {
            "Bundle": {"required": {"parties", "sigs"}, "optional": set(),
                       "ftypes": {"parties": "Party[]", "sigs": "Sig[]"}},
            "Party": {"required": {"primaryClaim"}, "optional": set(),
                      "ftypes": {"primaryClaim": "ClaimReference"}},
            "Sig": {"required": {"party"}, "optional": set(),
                    "ftypes": {"party": "ClaimReference"}},
        }
        # object-form ClaimReference (the #145 divergence) → flagged
        bad = {"parties": [{"primaryClaim": {"scheme": "cci", "identifier": "x"}}],
               "sigs": [{"party": {"scheme": "cci", "identifier": "y"}}]}
        errs = []
        v.check_claimrefs(bad, "Bundle", types, "ctx", errs)
        joined = "\n".join(errs)
        self.assertIn("parties[0].primaryClaim", joined)
        self.assertIn("sigs[0].party", joined)
        self.assertNotIn("`parties`", joined)   # the object array itself is NOT a ClaimReference
        # string-form ClaimReference → clean
        good = {"parties": [{"primaryClaim": "cci:x"}], "sigs": [{"party": "cci:y"}]}
        errs2 = []
        v.check_claimrefs(good, "Bundle", types, "ctx", errs2)
        self.assertEqual(errs2, [])

    def test_no_global_field_name_collision(self):
        # `parties` is ClaimReference[] in one type but an object array in another;
        # per-type resolution must not cross-contaminate.
        v = load_validator()
        types = {
            "Commit": {"required": {"parties"}, "optional": set(),
                       "ftypes": {"parties": "ClaimReference[]"}},
            "Bundle": {"required": {"parties"}, "optional": set(),
                       "ftypes": {"parties": "Party[]"}},
            "Party": {"required": {"primaryClaim"}, "optional": set(),
                      "ftypes": {"primaryClaim": "ClaimReference"}},
        }
        # a Bundle with object-array parties must NOT be flagged on `parties`
        errs = []
        v.check_claimrefs({"parties": [{"primaryClaim": "cci:x"}]}, "Bundle", types, "ctx", errs)
        self.assertEqual(errs, [])
        # a Commit with object parties (should be string array) IS flagged
        errs2 = []
        v.check_claimrefs({"parties": [{"scheme": "cci"}]}, "Commit", types, "ctx", errs2)
        self.assertTrue(any("ClaimReference[]" in e for e in errs2))

    def test_scans_examples_dir(self):
        v = load_validator()
        self.assertTrue((v.VECTOR_DIR / "examples").is_dir())

    def test_lifecycle_vectors_no_longer_quarantined(self):
        # #133: the lifecycle vectors were regenerated to current v0.1 spec shapes,
        # so the quarantine is lifted — they are now shape-checked, not skipped.
        v = load_validator()
        self.assertNotIn("dacs-v0.1-happy-path.json", v.QUARANTINE)
        self.assertNotIn("dacs-v0.1-negative-paths.json", v.QUARANTINE)

    def test_attestationref_legacy_shape_is_rejected_at_nested_positions(self):
        v = load_validator()
        types = {
            "Bundle": {
                "required": {"agreementRef", "phases"},
                "optional": set(),
                "ftypes": {
                    "agreementRef": "AttestationRef",
                    "phases": "Phase[]",
                },
            },
            "Phase": {
                "required": {"attestationRef", "txRefs"},
                "optional": set(),
                "ftypes": {
                    "attestationRef": "AttestationRef",
                    "txRefs": "ChainTxRef[]",
                },
            },
            "AttestationRef": {
                "required": {"anchor", "contentHash"},
                "optional": {"signer"},
                "ftypes": {"signer": "ClaimReference"},
            },
        }
        legacy = {
            "kind": "dacs-4-evidence",
            "id": "legacy-1",
            "contentHash": "aa" * 32,
        }
        body = {
            "agreementRef": legacy,
            "phases": [{
                "attestationRef": legacy,
                "txRefs": [{
                    "kind": "payment",
                    "rail": "old-rail",
                    "txHash": "old-tx",
                }],
            }],
        }
        errors = []
        v.check_nested_shapes(body, "Bundle", types, "ctx", errors)
        joined = "\n".join(errors)
        self.assertIn("agreementRef", joined)
        self.assertIn("phases[0].attestationRef", joined)
        self.assertIn("not a registered ChainTxRef discriminator", joined)

    def test_ap2_receipt_attestation_is_checked_recursively(self):
        v = load_validator()
        errors = []
        v.check_chain_tx_ref(
            {
                "kind": "ap2",
                "mandateId": "m-1",
                "providerRef": "p-1",
                "protocolVersion": "1",
                "receiptAttestation": {
                    "kind": "dacs-4-evidence",
                    "id": "legacy",
                    "contentHash": "bb" * 32,
                },
            },
            "ctx",
            errors,
            "txRef",
        )
        self.assertTrue(any("receiptAttestation" in error for error in errors))

    def test_legacy_ap2_arm_rejects_receipt_transaction_ref(self):
        v = load_validator()
        errors = []
        v.check_chain_tx_ref(
            {
                "kind": "ap2",
                "mandateId": "m-1",
                "providerRef": "p-1",
                "protocolVersion": "1",
                "receiptTransactionRef": {
                    "kind": "demos-web2-request",
                    "value": "tx-1",
                    "locator": "not-allowed",
                },
            },
            "ctx",
            errors,
            "txRef",
        )
        self.assertTrue(any("receiptTransactionRef" in error for error in errors))

    def test_ap2_sr3_requires_exact_receipt_references(self):
        v = load_validator()
        valid = {
            "kind": "ap2-sr3",
            "mandateId": "m-1",
            "providerRef": "p-1",
            "protocolVersion": "1",
            "receiptAttestation": {
                "anchor": {
                    "kind": "https",
                    "locator": "https://provider.test/receipts/p-1",
                },
                "contentHash": "aa" * 32,
            },
            "receiptTransactionRef": {
                "kind": "demos-web2-request",
                "value": "tx-1",
            },
        }
        errors = []
        v.check_chain_tx_ref(valid, "ctx", errors, "txRef")
        self.assertEqual(errors, [])

        for missing in ("receiptAttestation", "receiptTransactionRef"):
            malformed = copy.deepcopy(valid)
            malformed.pop(missing)
            errors = []
            v.check_chain_tx_ref(malformed, "ctx", errors, "txRef")
            self.assertTrue(any(missing in error for error in errors))

    def test_reference_shape_set_is_complete_and_hash_pinned(self):
        v = load_validator()
        data = json.loads(v.REFERENCE_SHAPE_VECTOR.read_text(encoding="utf-8"))
        cases = data["vectors"]
        self.assertEqual(data["count"], len(cases))
        encoded = json.dumps(
            cases, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        self.assertEqual(data["hash"], hashlib.sha256(encoded).hexdigest())

        passing_tx_kinds = {
            case["value"]["kind"]
            for case in cases
            if case["type"] == "ChainTxRef" and case["expected"] == "pass"
        }
        self.assertEqual(passing_tx_kinds, set(v._CHAIN_TX_REF_ARMS))
        passing_anchor_kinds = {
            case["value"]["anchor"]["kind"]
            for case in cases
            if case["type"] == "AttestationRef" and case["expected"] == "pass"
        }
        self.assertEqual(passing_anchor_kinds, v._ATTESTATION_ANCHOR_KINDS)


if __name__ == "__main__":
    unittest.main()
