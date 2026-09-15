import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "scripts" / "dacs_adapter.py"
VALIDATOR = ROOT / "scripts" / "validate_dacs_adapter_release.py"
DESCRIPTOR = ROOT / "conformance" / "interop" / "dacs-adapter-release-proposal-v1.json"


def request(request_id, request_type, **values):
    return {
        "protocol": "dacs-adapter/1",
        "id": request_id,
        "type": request_type,
        **values,
    }


def run_adapter(requests):
    encoded = b"".join(
        json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        for item in requests
    )
    completed = subprocess.run(
        [sys.executable, str(ADAPTER)],
        cwd=ROOT,
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
    )
    responses = [json.loads(line) for line in completed.stdout.splitlines()]
    return completed, responses


class DacsAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.descriptor = json.loads(DESCRIPTOR.read_text(encoding="utf-8"))
        cls.sources = {}
        for name, source in cls.descriptor["sources"].items():
            cls.sources[name] = json.loads((ROOT / source["path"]).read_text(encoding="utf-8"))

    def test_release_descriptor_and_actual_domain_primitive_pin(self):
        completed = subprocess.run(
            [sys.executable, str(VALIDATOR)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("14 executable cases, 2 unsupported mappings", completed.stdout)

    def test_metadata_separates_adapter_and_wrapped_standard_identity(self):
        completed, responses = run_adapter([request("metadata", "metadata")])
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(len(responses), 1)
        metadata = responses[0]["result"]
        self.assertEqual(metadata["repository"], self.descriptor["adapter"]["repository"])
        self.assertEqual(
            metadata["revision"],
            "sha256:" + self.descriptor["adapter"]["source"]["sha256"],
        )
        self.assertEqual(
            metadata["wrappedStandard"]["revision"],
            self.descriptor["adapter"]["wrappedStandard"]["revision"],
        )
        self.assertIn(
            metadata["observedOrigin"],
            {
                "https://github.com/DACS-Agent-commerce/DACS-Standard.git",
                "https://github.com/DACS-Agent-commerce/DACS-Standard",
            },
        )
        self.assertEqual(
            metadata["operations"],
            ["canonicalize", "signedScopeHash", "signatureValueVerdict"],
        )
        self.assertNotIn("domainSepSign", metadata["operations"])

    def test_selected_canonicalization_cases_execute(self):
        family = next(item for item in self.descriptor["families"] if item["id"] == "canonicalization")
        raw = self.sources[family["source"]]["vectors"]
        by_name = {item["name"]: item for item in raw}
        requests = [
            request(
                selected["caseId"],
                "execute",
                operation="canonicalize",
                params=[by_name[selected["caseId"]]["input"]],
            )
            for selected in family["cases"]
        ]
        completed, responses = run_adapter(requests)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(len(responses), len(requests))
        selected_by_id = {item["caseId"]: item for item in family["cases"]}
        for response in responses:
            selected = selected_by_id[response["id"]]
            with self.subTest(case=response["id"]):
                if "expected" in selected:
                    self.assertTrue(response["ok"], response)
                    self.assertEqual(response["result"], selected["expected"])
                else:
                    self.assertFalse(response["ok"], response)
                    self.assertEqual(response["error"]["code"], selected["expectedErrorCode"])

    def test_bigint_host_type_is_explicitly_unsupported_and_not_executable(self):
        family = next(item for item in self.descriptor["families"] if item["id"] == "canonicalization")
        self.assertNotIn("bigint-native-type", {item["caseId"] for item in family["cases"]})
        unsupported = family["unsupportedSourceCases"]
        self.assertEqual([item["caseId"] for item in unsupported], ["bigint-native-type"])
        completed, responses = run_adapter(
            [
                request(
                    "bigint-native-type",
                    "execute",
                    operation="canonicalize",
                    params=[{"$dacsType": "bigint", "decimal": "1"}],
                )
            ]
        )
        self.assertEqual(completed.returncode, 0)
        self.assertFalse(responses[0]["ok"])
        self.assertEqual(responses[0]["error"]["code"], "UNSUPPORTED_CASE")
        self.assertNotEqual(responses[0]["error"]["code"], "OPERATION_FAILED")

    def test_selected_signed_scope_cases_execute_actual_dispatch(self):
        family = next(item for item in self.descriptor["families"] if item["id"] == "signed-scope")
        artifacts = self.sources[family["source"]]["artifacts"]
        by_id = {item["id"]: item for item in artifacts}
        requests = [
            request(
                selected["caseId"],
                "execute",
                operation="signedScopeHash",
                params=[by_id[selected["caseId"]]["artifact"]],
            )
            for selected in family["cases"]
        ]
        completed, responses = run_adapter(requests)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(
            [response["result"] for response in responses],
            [selected["expected"] for selected in family["cases"]],
        )

    def test_selected_sig6_wire_cases_execute_without_algorithm_length_check(self):
        family = next(item for item in self.descriptor["families"] if item["id"] == "sig6-wire")
        vectors = self.sources[family["source"]]["vectors"]
        by_name = {item["name"]: item for item in vectors}
        selected = family["cases"]
        wrong_length = by_name["canonical-wire-wrong-ed25519-length-rejected"]
        requests = [
            request(
                item["caseId"],
                "execute",
                operation="signatureValueVerdict",
                params=[by_name[item["caseId"]]["value"]],
            )
            for item in selected
        ]
        requests.append(
            request(
                "wire-only-wrong-length",
                "execute",
                operation="signatureValueVerdict",
                params=[wrong_length["value"]],
            )
        )
        completed, responses = run_adapter(requests)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(
            [response["result"] for response in responses[:-1]],
            [item["expected"] for item in selected],
        )
        self.assertEqual(responses[-1]["result"], "ACCEPT")

    def test_unknown_and_ambiguous_operations_abstain_with_controlled_errors(self):
        completed, responses = run_adapter(
            [
                request("domain", "execute", operation="domainSepSign", params=[]),
                request(
                    "artifact",
                    "execute",
                    operation="signedScopeHash",
                    params=[{"listingVersion": 1}],
                ),
                request(
                    "mixed-artifact",
                    "execute",
                    operation="signedScopeHash",
                    params=[
                        {
                            "evidenceVersion": "1",
                            "bundleVersion": "1",
                            "jobId": "mixed",
                            "phase": "pay-test",
                            "outcome": "success",
                            "phaseSummary": [],
                            "signature": {},
                            "signatures": [],
                        }
                    ],
                ),
                request(
                    "future-artifact",
                    "execute",
                    operation="signedScopeHash",
                    params=[
                        {
                            "evidenceVersion": "2",
                            "jobId": "future",
                            "phase": "pay-test",
                            "outcome": "success",
                            "signature": {},
                        }
                    ],
                ),
                request("unknown", "execute", operation="madeUp", params=[]),
            ]
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(
            [response["error"]["code"] for response in responses],
            [
                "UNSUPPORTED_OPERATION",
                "UNSUPPORTED_ARTIFACT",
                "UNSUPPORTED_ARTIFACT",
                "UNSUPPORTED_ARTIFACT",
                "UNSUPPORTED_OPERATION",
            ],
        )
        stderr = completed.stderr.decode("utf-8")
        self.assertNotIn("Traceback", stderr)
        self.assertNotIn("{\"protocol\"", stderr)

    def test_jsonl_request_size_is_bounded_and_recovers_at_next_line(self):
        oversized = b"{" + b"x" * 1_048_576 + b"}\n"
        valid = json.dumps(request("after", "metadata"), separators=(",", ":")).encode() + b"\n"
        completed = subprocess.run(
            [sys.executable, str(ADAPTER)],
            cwd=ROOT,
            input=oversized + valid,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(responses[0]["error"]["code"], "REQUEST_TOO_LARGE")
        self.assertEqual(responses[1]["id"], "after")
        self.assertTrue(responses[1]["ok"])
        self.assertLess(len(completed.stderr), 1024)

    def test_invalid_unicode_and_control_request_ids_are_controlled_and_recoverable(self):
        invalid_surrogate = (
            b'{"protocol":"dacs-adapter/1","id":"\\ud800","type":"metadata"}\n'
        )
        invalid_control = (
            b'{"protocol":"dacs-adapter/1","id":"\\u0001","type":"metadata"}\n'
        )
        valid = json.dumps(request("after-invalid-id", "metadata"), separators=(",", ":")).encode() + b"\n"
        completed = subprocess.run(
            [sys.executable, str(ADAPTER)],
            cwd=ROOT,
            input=invalid_surrogate + invalid_control + valid,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual([item["id"] for item in responses], [None, None, "after-invalid-id"])
        self.assertEqual(
            [item["error"]["code"] for item in responses[:2]],
            ["INVALID_REQUEST", "INVALID_REQUEST"],
        )
        self.assertTrue(responses[2]["ok"])
        self.assertNotIn(b"Traceback", completed.stderr)
        self.assertNotIn(b"\x01", completed.stderr)


if __name__ == "__main__":
    unittest.main()
