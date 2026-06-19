import importlib.util
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

    def test_known_stale_vectors_are_quarantined(self):
        v = load_validator()
        self.assertIn("dacs-v0.1-happy-path.json", v.QUARANTINE)
        self.assertIn("dacs-v0.1-negative-paths.json", v.QUARANTINE)


if __name__ == "__main__":
    unittest.main()
