import copy
import importlib.util
import json
import os
import py_compile
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "scripts" / "dacs_adapter.py"
VALIDATOR = ROOT / "scripts" / "validate_dacs_adapter_release.py"
DESCRIPTOR = ROOT / "conformance" / "interop" / "dacs-adapter-release-proposal-v1.json"
DESCRIPTOR_RELATIVE = "conformance/interop/dacs-adapter-release-proposal-v1.json"
EXPECTED_ORIGIN = "https://github.com/DACS-Agent-commerce/DACS-Standard.git"


def request(request_id, request_type, **values):
    return {
        "protocol": "dacs-adapter/1",
        "id": request_id,
        "type": request_type,
        **values,
    }


def run_adapter(requests, *, root=ROOT, env=None):
    encoded = b"".join(
        json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        for item in requests
    )
    return run_adapter_bytes(encoded, root=root, env=env)


def run_adapter_bytes(encoded, *, root=ROOT, env=None):
    completed = subprocess.run(
        [sys.executable, str(root / "scripts" / "dacs_adapter.py")],
        cwd=root,
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=60,
        env=env,
    )
    responses = [json.loads(line) for line in completed.stdout.splitlines()]
    return completed, responses


def execute(request_id, operation, params):
    return request(request_id, "execute", operation=operation, params=params)


def byte_tag(hex_value):
    return {"$dacsType": "bytes", "hex": hex_value}


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    ).stdout.strip()


def committed_clone(test, *, origin=EXPECTED_ORIGIN):
    """A disposable checkout of the committed HEAD with the given origin."""

    directory = tempfile.TemporaryDirectory()
    test.addCleanup(directory.cleanup)
    clone = Path(directory.name) / "checkout"
    git(ROOT, "clone", "--quiet", "--shared", "--no-checkout", str(ROOT), str(clone))
    git(clone, "checkout", "--quiet", "--detach", git(ROOT, "rev-parse", "HEAD"))
    git(clone, "remote", "set-url", "origin", origin)
    return clone


def commit_descriptor(clone, mutate):
    path = clone / DESCRIPTOR_RELATIVE
    descriptor = json.loads(path.read_text(encoding="utf-8"))
    mutate(descriptor)
    path.write_text(json.dumps(descriptor, indent=2) + "\n", encoding="utf-8")
    git(clone, "-c", "user.name=test", "-c", "user.email=test@invalid", "commit", "--quiet", "-am", "mutate")


def unavailable(completed):
    return (
        completed.returncode == 1
        and completed.stdout == b""
        and completed.stderr.startswith(b"dacs-adapter: unavailable: ")
        and completed.stderr.count(b"\n") == 1
        and b"Traceback" not in completed.stderr
    )


METADATA = {"protocol": "dacs-adapter/1", "id": "metadata", "type": "metadata"}


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
        self.assertIn(
            "14 advertised-family cases, 4 bounded F5 cases, 2 unsupported mappings",
            completed.stdout,
        )

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
            [
                "canonicalize",
                "signedScopeHash",
                "signatureValueVerdict",
                "domainSepSign",
                "domainSepVerify",
            ],
        )
        self.assertNotIn("domain-sep-sign", metadata["supportedFamilies"])
        # One revision-free codebase identity for every Standard wrapper.
        self.assertEqual(
            metadata["provenanceCodebase"], "github.com/DACS-Agent-commerce/DACS-Standard"
        )
        self.assertEqual(
            metadata["provenanceCodebase"], self.descriptor["adapter"]["provenanceCodebase"]
        )
        self.assertEqual(
            metadata["boundedOperationProfiles"]["domainSepSign"],
            "listing-single-hash-golden-v1",
        )

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

    def test_bounded_f5_cases_execute_exact_bytes(self):
        family = next(
            item for item in self.descriptor["families"] if item["id"] == "domain-separated-signing"
        )
        self.assertEqual(family["status"], "bounded-operation-profile")
        self.assertFalse(family["advertisedFamily"])
        requests = []
        for case in family["cases"]:
            if case["operation"] == "domainSepSign":
                params = [
                    {"$dacsType": "bytes", "hex": case["messageBytesHex"]},
                    case["separator"],
                    {"$dacsType": "bytes", "hex": case["privateKeyBytesHex"]},
                ]
            else:
                params = [
                    {"$dacsType": "bytes", "hex": case["messageBytesHex"]},
                    case["separator"],
                    {"$dacsType": "bytes", "hex": case["signatureBytesHex"]},
                    {"$dacsType": "bytes", "hex": case["publicKeyHex"]},
                ]
            requests.append(
                request(case["caseId"], "execute", operation=case["operation"], params=params)
            )
        completed, responses = run_adapter(requests)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(
            [response["result"] for response in responses],
            [case["expected"] for case in family["cases"]],
        )

    def test_bounded_f5_refuses_out_of_profile_emission_and_dacs_separator(self):
        family = next(
            item for item in self.descriptor["families"] if item["id"] == "domain-separated-signing"
        )
        sign_case = family["cases"][0]
        message = {"$dacsType": "bytes", "hex": sign_case["messageBytesHex"]}
        seed = {"$dacsType": "bytes", "hex": sign_case["privateKeyBytesHex"]}
        signature = {"$dacsType": "bytes", "hex": sign_case["expected"]["hex"]}
        public_key = {"$dacsType": "bytes", "hex": family["cases"][1]["publicKeyHex"]}
        raw_verify_case = family["unsupportedCases"][0]
        requests = [
            request(
                "raw-digest-sign",
                "execute",
                operation="domainSepSign",
                params=[
                    {"$dacsType": "bytes", "hex": sign_case["artifactHashHex"]},
                    sign_case["separator"],
                    seed,
                ],
            ),
            request(
                "valid-raw-digest-verify",
                "execute",
                operation="domainSepVerify",
                params=[
                    {"$dacsType": "bytes", "hex": raw_verify_case["messageBytesHex"]},
                    raw_verify_case["separator"],
                    {"$dacsType": "bytes", "hex": raw_verify_case["signatureBytesHex"]},
                    {"$dacsType": "bytes", "hex": raw_verify_case["publicKeyHex"]},
                ],
            ),
            request(
                "other-domain-sign",
                "execute",
                operation="domainSepSign",
                params=[message, "dacs-bundle:v1:", seed],
            ),
            request(
                "intermediate-sign",
                "execute",
                operation="domainSepSign",
                params=[
                    message,
                    sign_case["separator"],
                    seed,
                    {"$dacsType": "bytes", "hex": "00" * 32},
                ],
            ),
            request(
                "other-domain-verify",
                "execute",
                operation="domainSepVerify",
                params=[message, "dacs-bundle:v1:", signature, public_key],
            ),
        ]
        completed, responses = run_adapter(requests)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(
            [response["error"]["code"] for response in responses],
            ["UNSUPPORTED_CASE"] * 5,
        )

    def test_unknown_and_ambiguous_operations_abstain_with_controlled_errors(self):
        completed, responses = run_adapter(
            [
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


class DacsAdapterIntegrityTests(unittest.TestCase):
    """The adapter executes exactly the verified committed bytes and nothing else."""

    def test_planted_bytecode_cannot_replace_verified_source(self):
        clone = committed_clone(self)
        source = clone / "scripts" / "jcs.py"
        original = source.read_bytes()
        tampered = original + b"\n\ndef canonicalize(value):\n    return '\"TAMPERED\"'\n"
        tampered_path = clone / "tampered_jcs.py"
        tampered_path.write_bytes(tampered)
        cache = Path(importlib.util.cache_from_source(str(source)))
        cache.parent.mkdir(exist_ok=True)
        py_compile.compile(
            str(tampered_path),
            cfile=str(cache),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
        )
        # Make the planted bytecode look current for the verified source file.
        stat = source.stat()
        data = bytearray(cache.read_bytes())
        data[8:16] = struct.pack("<II", int(stat.st_mtime) & 0xFFFFFFFF, stat.st_size & 0xFFFFFFFF)
        cache.write_bytes(bytes(data))
        completed, responses = run_adapter(
            [execute("jcs", "canonicalize", [{"b": 1, "a": 2}])],
            root=clone,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(responses[0]["result"], {"hex": b'{"a":2,"b":1}'.hex()})

    def test_descriptor_must_pin_exactly_the_modules_the_adapter_executes(self):
        def drop_walkthrough(descriptor):
            wrapped = descriptor["adapter"]["wrappedStandard"]
            wrapped["primitives"] = [
                item for item in wrapped["primitives"]
                if item["path"] != "scripts/run_lifecycle_walkthrough.py"
            ]

        def duplicate_jcs(descriptor):
            primitives = descriptor["adapter"]["wrappedStandard"]["primitives"]
            jcs = next(item for item in primitives if item["path"] == "scripts/jcs.py")
            walkthrough = next(
                item for item in primitives if item["path"] == "scripts/run_lifecycle_walkthrough.py"
            )
            walkthrough.update(jcs)

        def pin_other_file_as_adapter_source(descriptor):
            jcs = next(
                item for item in descriptor["adapter"]["wrappedStandard"]["primitives"]
                if item["path"] == "scripts/jcs.py"
            )
            descriptor["adapter"]["source"] = dict(jcs)

        for mutate in (drop_walkthrough, duplicate_jcs, pin_other_file_as_adapter_source):
            with self.subTest(mutation=mutate.__name__):
                clone = committed_clone(self)
                commit_descriptor(clone, mutate)
                completed, _ = run_adapter([METADATA], root=clone)
                self.assertTrue(unavailable(completed), completed)
                validator = subprocess.run(
                    [sys.executable, str(clone / "scripts" / "validate_dacs_adapter_release.py")],
                    cwd=clone,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    timeout=120,
                )
                self.assertEqual(validator.returncode, 1, validator.stdout)
                self.assertIn("adapter release proposal: FAIL", validator.stderr)

    def test_third_party_modules_never_execute_in_the_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "cryptography"
            package.mkdir()
            marker = Path(directory) / "imported"
            (package / "__init__.py").write_text(
                "import pathlib, sys\n"
                f"pathlib.Path({str(marker)!r}).write_text('imported')\n"
                "sys.stdout.write('POLLUTED\\n')\n",
                encoding="utf-8",
            )
            env = {**os.environ, "PYTHONPATH": directory}
            completed, responses = run_adapter([METADATA, execute("c", "canonicalize", [[1]])], env=env)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertFalse(marker.exists())
        self.assertEqual([item["id"] for item in responses], ["metadata", "c"])
        self.assertEqual(responses[1]["result"], {"hex": b"[1]".hex()})

    def test_git_environment_cannot_redirect_provenance(self):
        env = {**os.environ, "GIT_DIR": "/nonexistent-dacs-git-dir", "GIT_WORK_TREE": "/nonexistent"}
        completed, responses = run_adapter([METADATA], env=env)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertTrue(responses[0]["ok"])

        # A checkout with another origin cannot borrow the pinned origin from the environment.
        fork = committed_clone(self, origin="https://github.com/example-fork/DACS-Standard.git")
        spoof = {
            **os.environ,
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "remote.origin.url",
            "GIT_CONFIG_VALUE_0": EXPECTED_ORIGIN,
        }
        completed, _ = run_adapter([METADATA], root=fork, env=spoof)
        self.assertTrue(unavailable(completed), completed)
        self.assertIn(b"origin", completed.stderr)


class DacsAdapterBoundaryTests(unittest.TestCase):
    """Verdicts, abstentions, and request errors stay distinct."""

    @classmethod
    def setUpClass(cls):
        cls.descriptor = json.loads(DESCRIPTOR.read_text(encoding="utf-8"))
        cls.family = next(
            item for item in cls.descriptor["families"] if item["id"] == "domain-separated-signing"
        )
        cls.cases = {case["caseId"]: case for case in cls.family["cases"]}
        happy = json.loads(
            (ROOT / "conformance" / "vectors" / "dacs-v0.1-happy-path.json").read_text(encoding="utf-8")
        )
        cls.artifacts = {item["id"]: item["artifact"] for item in happy["artifacts"]}

    def test_signed_scope_refuses_every_foreign_type_discriminator(self):
        core = (ROOT / "spec" / "CORE.md").read_text(encoding="utf-8")
        paragraph = next(
            line for line in core.splitlines() if line.startswith("**Version-signalling scope.**")
        )
        discriminators = set(re.findall(r"`([A-Za-z]+Version)`", paragraph))
        spec = importlib.util.spec_from_file_location(
            "dacs_adapter_test_vcv", ROOT / "scripts" / "validate_conformance_vectors.py"
        )
        vcv = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vcv)
        discriminators.update(vcv.BODY_DISCRIMINATORS.values())
        discriminators.add("legacyTransitionEvidenceVersion")  # DACS-4 §9.7 exclusive discriminator
        self.assertGreaterEqual(len(discriminators), 24)

        evidence = self.artifacts["settlement-htlc-release"]
        bundle = self.artifacts["attestation-bundle-happy"]
        requests = [
            execute("control-evidence", "signedScopeHash", [evidence]),
            execute("control-bundle", "signedScopeHash", [bundle]),
        ]
        for own, artifact in (("evidenceVersion", evidence), ("bundleVersion", bundle)):
            for name in sorted(discriminators - {own}):
                requests.append(execute(f"{own}+{name}", "signedScopeHash", [{**artifact, name: "1"}]))
        completed, responses = run_adapter(requests)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        signed_scope = next(item for item in self.descriptor["families"] if item["id"] == "signed-scope")
        self.assertEqual(
            [response["result"] for response in responses[:2]],
            [case["expected"] for case in signed_scope["cases"]],
        )
        for response in responses[2:]:
            with self.subTest(case=response["id"]):
                self.assertFalse(response["ok"], response)
                self.assertEqual(response["error"]["code"], "UNSUPPORTED_ARTIFACT")

    def test_trailing_null_intermediate_hash_is_absent(self):
        """The shared runner encodes an omitted optional argument as JSON null."""

        sign = self.cases["signing::sign-ascii-hex-hash"]
        verify = self.cases["signing::verify-ascii-hex-hash"]
        mismatch = self.cases["signing::reject-mismatched-ascii-hex-hash"]
        unknown = self.cases["signing::unknown-separator-false"]
        raw = self.family["unsupportedCases"][0]

        def verify_params(case, intermediate):
            return [
                byte_tag(case["messageBytesHex"]),
                case["separator"],
                byte_tag(case["signatureBytesHex"]),
                byte_tag(case["publicKeyHex"]),
                intermediate,
            ]

        sign_params = [
            byte_tag(sign["messageBytesHex"]),
            sign["separator"],
            byte_tag(sign["privateKeyBytesHex"]),
        ]
        completed, responses = run_adapter(
            [
                execute("sign-null", "domainSepSign", [*sign_params, None]),
                execute("verify-null", "domainSepVerify", verify_params(verify, None)),
                execute("mismatch-null", "domainSepVerify", verify_params(mismatch, None)),
                execute("unknown-null", "domainSepVerify", verify_params(unknown, None)),
                execute("raw-null", "domainSepVerify", verify_params(raw, None)),
                execute("sign-empty-intermediate", "domainSepSign", [*sign_params, byte_tag("")]),
                execute(
                    "verify-intermediate", "domainSepVerify", verify_params(verify, byte_tag("00" * 32))
                ),
            ]
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(responses[0]["result"], sign["expected"])
        self.assertEqual([item["result"] for item in responses[1:4]], [True, False, False])
        self.assertEqual(
            [item["error"]["code"] for item in responses[4:]],
            ["UNSUPPORTED_CASE"] * 3,
        )

    def test_malformed_requests_are_errors_not_abstentions_or_verdicts(self):
        verify = self.cases["signing::verify-ascii-hex-hash"]
        sign = self.cases["signing::sign-ascii-hex-hash"]
        message = byte_tag(verify["messageBytesHex"])
        signature = byte_tag(verify["signatureBytesHex"])
        public_key = byte_tag(verify["publicKeyHex"])
        seed = byte_tag(sign["privateKeyBytesHex"])
        bigint = {"$dacsType": "bigint", "decimal": "1"}
        listing = "dacs-listing:v1:"
        unknown = "not-a-dacs-separator:v1:"
        cases = [
            ("bigint-before-malformed-tag", "canonicalize", [[bigint, byte_tag("ZZ")]], "MALFORMED_TAG"),
            ("sign-text-message", "domainSepSign", [verify["messageBytesHex"], listing, seed], "INVALID_PARAMS"),
            ("sign-numeric-separator", "domainSepSign", [message, 7, seed], "INVALID_PARAMS"),
            (
                "sign-short-key-with-intermediate",
                "domainSepSign",
                [message, listing, byte_tag("11"), byte_tag("00")],
                "INVALID_PARAMS",
            ),
            ("sign-text-intermediate", "domainSepSign", [message, listing, seed, "00"], "INVALID_PARAMS"),
            ("verify-untyped-intermediate", "domainSepVerify", [1, 2, 3, 4, byte_tag("00")], "INVALID_PARAMS"),
            ("verify-unknown-untyped", "domainSepVerify", [1, unknown, None, []], "INVALID_PARAMS"),
            ("verify-text-signature", "domainSepVerify", [message, listing, "sig", public_key], "INVALID_PARAMS"),
            ("unknown-operation-with-bigint", "madeUp", [bigint], "UNSUPPORTED_OPERATION"),
        ]
        completed, responses = run_adapter(
            [execute(name, operation, params) for name, operation, params, _ in cases]
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        for (name, _, _, code), response in zip(cases, responses, strict=True):
            with self.subTest(case=name):
                self.assertFalse(response["ok"], response)
                self.assertEqual(response["error"]["code"], code)
        # A well-formed unknown non-DACS separator still yields the pinned false verdict.
        completed, responses = run_adapter(
            [execute("well-formed-unknown", "domainSepVerify", [message, unknown, signature, public_key])]
        )
        self.assertIs(responses[0]["result"], False)

    def test_non_json_constants_and_decode_limits_are_invalid_json(self):
        prefix = (
            b'{"protocol":"dacs-adapter/1","id":"x","type":"execute",'
            b'"operation":"signatureValueVerdict","params":['
        )
        lines = [
            prefix + b"NaN]}",
            prefix + b"Infinity]}",
            prefix + b"-Infinity]}",
            prefix + b"9" * 5000 + b"]}",
            b"\xef\xbb\xbf" + json.dumps(METADATA).encode(),
            b'{"protocol":"dacs-adapter/1","id":"\xff","type":"metadata"}',
        ]
        encoded = b"".join(line + b"\n" for line in lines) + json.dumps(METADATA).encode() + b"\n"
        completed, responses = run_adapter_bytes(encoded)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(
            [item.get("error", {}).get("code") for item in responses[:-1]],
            ["INVALID_JSON"] * len(lines),
        )
        self.assertTrue(all(item["id"] is None for item in responses[:-1]))
        self.assertTrue(responses[-1]["ok"])

    def test_stderr_diagnostics_are_single_printable_ascii_lines(self):
        request_id = "a\u202eb\u2028c\u00e9"
        completed, responses = run_adapter(
            [
                execute(request_id, "madeUp", []),
                execute("second", "canonicalize", [{"$dacsType": "x"}]),
            ]
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(responses[0]["id"], request_id)
        lines = completed.stderr.split(b"\n")
        self.assertEqual(lines[-1], b"")
        self.assertEqual(len(lines[:-1]), 2)
        for line in lines[:-1]:
            self.assertTrue(all(0x20 <= byte <= 0x7E for byte in line), line)
        self.assertIn(b"a\\u202eb\\u2028c\\xe9", lines[0])


class DacsAdapterReleaseValidatorTests(unittest.TestCase):
    """The release validator rejects descriptor drift that the adapter cannot see."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("dacs_adapter_release_validator", VALIDATOR)
        cls.validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.validator)
        cls.descriptor = json.loads(DESCRIPTOR.read_text(encoding="utf-8"))

    def mutated(self, mutate):
        descriptor = copy.deepcopy(self.descriptor)
        mutate(descriptor)
        return descriptor

    def family(self, descriptor, family_id):
        return next(item for item in descriptor["families"] if item["id"] == family_id)

    def test_committed_descriptor_passes(self):
        self.assertEqual(
            self.validator.validate_release(copy.deepcopy(self.descriptor)),
            {"families": 4, "executableCases": 14, "boundedCases": 4, "unsupportedCases": 2},
        )

    def test_descriptor_drift_is_rejected(self):
        def stale_control_lines(descriptor):
            self.family(descriptor, "domain-separated-signing")["controlSource"]["lines"] = "38-42"

        def renamed_control_test(descriptor):
            self.family(descriptor, "domain-separated-signing")["controlSource"]["test"] = (
                "test_golden_signature_verifies_over_core_b7_preimage"
            )

        def registered_unknown_separator(descriptor):
            case = next(
                item for item in self.family(descriptor, "domain-separated-signing")["cases"]
                if item["caseId"] == "signing::unknown-separator-false"
            )
            case["separator"] = "dacs-bundle:v1:"

        def unknown_separator_other_message(descriptor):
            case = next(
                item for item in self.family(descriptor, "domain-separated-signing")["cases"]
                if item["caseId"] == "signing::unknown-separator-false"
            )
            case["messageBytesHex"] = "30" * 64

        def unaccounted_source_case(descriptor):
            self.family(descriptor, "canonicalization")["excludedSourceCases"].pop()

        def tagged_case_without_tag(descriptor):
            excluded = self.family(descriptor, "canonicalization")["excludedSourceCases"]
            next(item for item in excluded if item["caseId"] == "negative-zero").pop("sourceTag")

        def expressible_case_claimed_inexpressible(descriptor):
            excluded = self.family(descriptor, "canonicalization")["excludedSourceCases"]
            next(item for item in excluded if item["caseId"] == "fraction-one-tenth")["sourceTag"] = "binary64"

        def revision_qualified_codebase(descriptor):
            descriptor["adapter"]["provenanceCodebase"] = (
                "https://github.com/DACS-Agent-commerce/DACS-Standard@"
                + descriptor["adapter"]["wrappedStandard"]["revision"]
                + "#scripts/jcs.py"
            )

        def dropped_primitive(descriptor):
            descriptor["adapter"]["wrappedStandard"]["primitives"].pop()

        def other_adapter_source(descriptor):
            descriptor["adapter"]["source"]["path"] = "scripts/jcs.py"

        for mutate in (
            stale_control_lines,
            renamed_control_test,
            registered_unknown_separator,
            unknown_separator_other_message,
            unaccounted_source_case,
            tagged_case_without_tag,
            expressible_case_claimed_inexpressible,
            revision_qualified_codebase,
            dropped_primitive,
            other_adapter_source,
        ):
            with self.subTest(mutation=mutate.__name__):
                with self.assertRaises(ValueError):
                    self.validator.validate_release(self.mutated(mutate))


if __name__ == "__main__":
    unittest.main()
