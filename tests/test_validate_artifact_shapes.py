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


class ArtifactShapeTests(unittest.TestCase):
    def test_repository_vectors_pass(self):
        with mock.patch.object(sys, "argv", ["validate_artifact_shapes.py"]):
            self.assertEqual(load_validator().main(), 0)

    def test_parser_handles_optional_nested_and_comments(self):
        v = load_validator()
        block = (
            "type Sample = {\n"
            "  ver: \"1\"\n"
            "  jobId: string\n"
            "  note?: string                 // optional comment\n"
            "  terms: {\n"
            "    price: PriceTerm            // nested — must be ignored\n"
            "    rail: PaymentRailRef\n"
            "  }\n"
            "  amount?: { value: string }    // inline nested, optional\n"
            "}\n"
        )
        fields = v.parse_type_fields(block)["Sample"]
        self.assertEqual(fields["required"], {"ver", "jobId", "terms"})
        self.assertEqual(fields["optional"], {"note", "amount"})
        # nested fields must NOT leak to the top level
        self.assertNotIn("price", fields["required"] | fields["optional"])
        self.assertNotIn("rail", fields["required"] | fields["optional"])
        self.assertNotIn("value", fields["required"] | fields["optional"])

    def test_catches_missing_and_unknown_fields(self):
        v = load_validator()
        types = {"Foo": {"required": {"a", "b"}, "optional": {"c"}}}
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "vec.json"
            p.write_text(json.dumps({
                "artifacts": [
                    {"kind": "Foo", "artifact": {"a": 1, "x": 2}},  # missing b, unknown x
                ]
            }))
            errs = v.check_vector(p, types)
        joined = "\n".join(errs)
        self.assertIn("missing required field(s): ['b']", joined)
        self.assertIn("unknown field(s)", joined)
        self.assertIn("'x'", joined)

    def test_conformant_artifact_passes(self):
        v = load_validator()
        types = {"Foo": {"required": {"a", "b"}, "optional": {"c"}}}
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "vec.json"
            p.write_text(json.dumps({
                "artifacts": [{"kind": "Foo", "artifact": {"a": 1, "b": 2, "c": 3}}]
            }))
            self.assertEqual(v.check_vector(p, types), [])

    def test_known_stale_vectors_are_quarantined(self):
        v = load_validator()
        self.assertIn("dacs-v0.1-happy-path.json", v.QUARANTINE)
        self.assertIn("dacs-v0.1-negative-paths.json", v.QUARANTINE)


if __name__ == "__main__":
    unittest.main()
