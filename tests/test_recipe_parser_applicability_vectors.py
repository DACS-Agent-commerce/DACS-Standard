import hashlib
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "recipe-parser-applicability-v0.5.json"
)
GENERATOR = ROOT / "scripts" / "generate_recipe_parser_applicability_vectors.py"
SPEC = ROOT / "spec" / "DACS-2-VET.md"

PARSER_METHODS = {
    "verifiable-credential",
    "tlsnotary",
    "zktls",
    "consensus-backed-proxy",
    "evm-rpc",
}
NATIVE_METHODS = {
    "oauth-attested",
    "domain-tls-control",
    "self-signed",
    "demos-gcr-domain",
}


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def valid_parser_spec(value):
    if not isinstance(value, dict):
        return False
    formats = {
        "json": "successJsonPath",
        "html": "successSelector",
        "xml": "successXPath",
        "raw": "matcher",
    }
    required = formats.get(value.get("format"))
    return required is not None and isinstance(value.get(required), str)


def evaluate(vector):
    result = {
        "verdict": "error",
        "parserApplied": False,
        "methodInvoked": False,
    }
    recipe = vector.get("recipe")
    if not isinstance(recipe, dict) or not isinstance(recipe.get("defaultMethod"), dict):
        return result
    alternatives = recipe.get("alternatives", [])
    if not isinstance(alternatives, list) or any(
        not isinstance(item, dict) for item in alternatives
    ):
        return result
    methods = [recipe["defaultMethod"], *alternatives]
    kinds = [method.get("kind") for method in methods]
    known = PARSER_METHODS | NATIVE_METHODS
    if any(kind not in known for kind in kinds):
        return result

    has_parser = "parserRules" in recipe
    needs_parser = any(kind in PARSER_METHODS for kind in kinds)
    if needs_parser and (
        not has_parser or not valid_parser_spec(recipe.get("parserRules"))
    ):
        return result
    selected = vector.get("selectedMethod")
    if selected not in kinds:
        return result
    result["verdict"] = "pass"
    result["methodInvoked"] = True
    result["parserApplied"] = selected in PARSER_METHODS
    if selected in NATIVE_METHODS and "methodNativeResult" in vector:
        result.update(vector["methodNativeResult"])
    return result


class RecipeParserApplicabilityVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_generator_is_deterministic(self):
        subprocess.run(
            ["python3", str(GENERATOR), "--check"],
            cwd=ROOT,
            check=True,
        )

    def test_header_count_hash_and_unique_names(self):
        vectors = self.document["vectors"]
        self.assertEqual(self.document["count"], len(vectors))
        self.assertEqual(self.document["hash"], hashlib.sha256(canonical_bytes(vectors)).hexdigest())
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_all_vectors_execute(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                result = evaluate(vector)
                self.assertEqual(result["verdict"], vector["expected"])
                self.assertEqual(result["parserApplied"], vector["want"]["parserApplied"])
                self.assertEqual(result["methodInvoked"], vector["want"]["methodInvoked"])
                for field in ("decision", "data"):
                    if field in vector["want"]:
                        self.assertEqual(result[field], vector["want"][field])

    def test_closed_classification_covers_all_registered_methods_once(self):
        self.assertFalse(PARSER_METHODS & NATIVE_METHODS)
        self.assertEqual(
            PARSER_METHODS | NATIVE_METHODS,
            {
                "verifiable-credential",
                "tlsnotary",
                "zktls",
                "consensus-backed-proxy",
                "oauth-attested",
                "evm-rpc",
                "domain-tls-control",
                "self-signed",
                "demos-gcr-domain",
            },
        )

    def test_native_mixed_selection_never_applies_parser(self):
        vector = next(
            item for item in self.document["vectors"]
            if item["name"] == "mixed-recipe-native-selection-skips-parser"
        )
        self.assertIn("parserRules", vector["recipe"])
        result = evaluate(vector)
        self.assertEqual(result["verdict"], "pass")
        self.assertFalse(result["parserApplied"])

    def test_native_only_parser_values_are_readable_but_inert(self):
        for name in (
            "native-only-inert-parser-is-ignored",
            "native-only-divergent-parser-output-is-inert",
            "native-only-null-parser-is-inert",
        ):
            with self.subTest(vector=name):
                vector = next(
                    item for item in self.document["vectors"]
                    if item["name"] == name
                )
                self.assertIn("parserRules", vector["recipe"])
                result = evaluate(vector)
                self.assertEqual(result["verdict"], "pass")
                self.assertTrue(result["methodInvoked"])
                self.assertFalse(result["parserApplied"])

    def test_divergent_parser_output_cannot_override_native_result(self):
        vector = next(
            item for item in self.document["vectors"]
            if item["name"] == "native-only-divergent-parser-output-is-inert"
        )
        self.assertNotEqual(vector["methodNativeResult"], vector["parserWouldProduce"])
        result = evaluate(vector)
        self.assertEqual(result["decision"], vector["methodNativeResult"]["decision"])
        self.assertEqual(result["data"], vector["methodNativeResult"]["data"])

    def test_invalid_recipe_fails_before_method_invocation(self):
        for vector in self.document["vectors"]:
            if vector["expected"] != "error":
                continue
            with self.subTest(vector=vector["name"]):
                result = evaluate(vector)
                self.assertFalse(result["methodInvoked"])

    def test_spec_pins_presence_selection_and_native_authority(self):
        text = SPEC.read_text(encoding="utf-8")
        for required in (
            "**(PRA-1) Closed method classification.**",
            "**(PRA-2) Recipe-shape validity and compatibility.**",
            "**(PRA-3) Selected-method execution.**",
            "**(PRA-4) Method-native authority.**",
            "**(PRA-5) Fail before invocation.**",
            "parserRules?: ParserSpec",
            "parser-consuming methods are `verifiable-credential`, `tlsnotary`, `zktls`,",
            "`consensus-backed-proxy`, and `evm-rpc`",
            "method-native methods are",
            "`oauth-attested`, `domain-tls-control`, `self-signed`, and",
            "`demos-gcr-domain`",
        ):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
