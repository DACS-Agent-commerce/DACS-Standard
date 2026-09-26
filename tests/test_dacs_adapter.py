import atexit
import copy
import functools
import hashlib
import importlib.util
import json
import os
import py_compile
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
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


def run_adapter(requests, *, root=None, env=None):
    encoded = b"".join(
        json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        for item in requests
    )
    return run_adapter_bytes(encoded, root=root, env=env)


def run_adapter_bytes(encoded, *, root=None, env=None):
    root = root or pinned_checkout()
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


def git_bytes(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    ).stdout


@functools.lru_cache(maxsize=None)
def pinned_checkout():
    """This commit, checked out with the pinned origin.

    The adapter only runs from a checkout whose origin is the pinned DACS-Standard
    URL, so the suite exercises it there rather than depending on how the
    developer's own clone (a fork, an SSH remote) is configured.
    """

    directory = tempfile.mkdtemp(prefix="dacs-adapter-tests-")
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    checkout = Path(directory) / "checkout"
    git(ROOT, "clone", "--quiet", "--shared", "--no-checkout", str(ROOT), str(checkout))
    git(checkout, "checkout", "--quiet", "--detach", git(ROOT, "rev-parse", "HEAD"))
    git(checkout, "remote", "set-url", "origin", EXPECTED_ORIGIN)
    return checkout


def pinned_adapter():
    return pinned_checkout() / "scripts" / "dacs_adapter.py"


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


def commit_all(clone, message="mutate"):
    git(clone, "-c", "user.name=test", "-c", "user.email=test@invalid", "commit", "--quiet", "-am", message)
    return git(clone, "rev-parse", "HEAD")


def pin_of(clone, relative, revision="HEAD"):
    data = git_bytes(clone, "show", f"{revision}:{relative}")
    return {
        "path": relative,
        "sha256": hashlib.sha256(data).hexdigest(),
        "gitBlob": git(clone, "rev-parse", f"{revision}:{relative}"),
    }


def unavailable(completed):
    return (
        completed.returncode == 1
        and completed.stdout == b""
        and completed.stderr.startswith(b"dacs-adapter: unavailable: ")
        and completed.stderr.count(b"\n") == 1
        and b"Traceback" not in completed.stderr
    )


METADATA = {"protocol": "dacs-adapter/1", "id": "metadata", "type": "metadata"}


WRAPPED_REVISION = json.loads(DESCRIPTOR.read_text(encoding="utf-8"))["adapter"]["wrappedStandard"]["revision"]


def release_bytes(relative):
    """A file exactly as the wrapped release carries it, whatever the working tree says."""

    return git_bytes(ROOT, "show", f"{WRAPPED_REVISION}:{relative}")


def pinned_text(relative):
    return release_bytes(relative).decode("utf-8")


class DacsAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.descriptor = json.loads(DESCRIPTOR.read_text(encoding="utf-8"))
        cls.sources = {}
        for name, source in cls.descriptor["sources"].items():
            cls.sources[name] = json.loads(pinned_text(source["path"]))

    def test_release_descriptor_and_actual_domain_primitive_pin(self):
        completed = subprocess.run(
            [sys.executable, str(pinned_checkout() / "scripts" / "validate_dacs_adapter_release.py")],
            cwd=pinned_checkout(),
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
        f5 = next(item for item in self.descriptor["families"] if item["id"] == "domain-separated-signing")
        self.assertEqual(
            metadata["boundedOperationProfiles"],
            {"domainSepSign": f5["profile"], "domainSepVerify": f5["profile"]},
        )
        self.assertEqual(metadata["limitations"], self.descriptor["adapter"]["limitations"])
        self.assertEqual(metadata["releaseDescriptorSha256"], hashlib.sha256(DESCRIPTOR.read_bytes()).hexdigest())

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
                "UNSUPPORTED_CASE",
                "UNSUPPORTED_CASE",
                "UNSUPPORTED_CASE",
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
            [sys.executable, str(pinned_adapter())],
            cwd=pinned_checkout(),
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
            [sys.executable, str(pinned_adapter())],
            cwd=pinned_checkout(),
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
        original = release_bytes("scripts/jcs.py")
        source.write_bytes(original)
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

        def misname_adapter_source(descriptor):
            # Correct adapter digests under another path: only the path binding can object.
            descriptor["adapter"]["source"]["path"] = "scripts/jcs.py"

        def misreported_primitive_digest(descriptor):
            # The executed bytes still match the adapter; only the reported digest is false.
            descriptor["adapter"]["wrappedStandard"]["primitives"][0]["sha256"] = "0" * 64

        def misreported_wrapped_revision(descriptor):
            # HEAD carries byte-identical primitives, so only the release binding can object.
            head = git(ROOT, "rev-parse", "HEAD")
            descriptor["adapter"]["wrappedStandard"]["revision"] = head
            descriptor["adapter"]["wrappedStandard"]["tree"] = git(ROOT, "rev-parse", "HEAD^{tree}")

        def add_unexecuted_primitive(descriptor):
            revision = descriptor["adapter"]["wrappedStandard"]["revision"]
            descriptor["adapter"]["wrappedStandard"]["primitives"].append(
                pin_of(ROOT, "scripts/raw_json_profile.py", revision)
            )

        for mutate in (
            drop_walkthrough,
            duplicate_jcs,
            pin_other_file_as_adapter_source,
            misname_adapter_source,
            misreported_primitive_digest,
            misreported_wrapped_revision,
            add_unexecuted_primitive,
        ):
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


    def test_tampered_wrapped_module_cannot_be_repinned_by_the_descriptor(self):
        """The adapter's own sha256, reported as its revision, covers the wrapped code."""

        for variant in ("descriptor-pins", "descriptor-revision", "adapter-constants"):
            with self.subTest(variant=variant):
                clone = committed_clone(self)
                jcs = clone / "scripts" / "jcs.py"
                release = release_bytes("scripts/jcs.py")
                genuine = hashlib.sha256(release).hexdigest()
                jcs.write_bytes(release + b"\n\ndef canonicalize(value):\n    return '\"TAMPERED\"'\n")
                tampered_commit = commit_all(clone, "tamper jcs")
                if variant == "adapter-constants":
                    # Even a re-pinned adapter (whose revision then changes) must not run
                    # bytes that are absent from the wrapped Standard revision.
                    adapter = clone / "scripts" / "dacs_adapter.py"
                    text = adapter.read_text(encoding="utf-8")
                    self.assertEqual(text.count(genuine), 1)
                    adapter.write_text(text.replace(genuine, pin_of(clone, "scripts/jcs.py")["sha256"]), encoding="utf-8")
                    commit_all(clone, "repin adapter constant")

                def repin(descriptor):
                    wrapped = descriptor["adapter"]["wrappedStandard"]
                    if variant == "descriptor-revision":
                        wrapped["revision"] = tampered_commit
                        wrapped["tree"] = git(clone, "rev-parse", f"{tampered_commit}^{{tree}}")
                    for index, item in enumerate(wrapped["primitives"]):
                        if item["path"] == "scripts/jcs.py":
                            wrapped["primitives"][index] = pin_of(clone, "scripts/jcs.py")
                    if variant == "adapter-constants":
                        descriptor["adapter"]["source"] = pin_of(clone, "scripts/dacs_adapter.py")

                commit_descriptor(clone, repin)
                completed, responses = run_adapter(
                    [execute("jcs", "canonicalize", [{"b": 1, "a": 2}])], root=clone
                )
                self.assertTrue(unavailable(completed), (completed, responses))

    def test_every_provenance_check_is_individually_required(self):
        """Each mutation below defeats exactly one check; the adapter must still refuse."""

        def uncommitted_descriptor(clone):
            # Only the committed-at-HEAD check can see an edited limitation string.
            path = clone / DESCRIPTOR_RELATIVE
            text = path.read_text(encoding="utf-8")
            self.assertIn("are not exposed by this release", text)
            path.write_text(text.replace("are not exposed by this release", "are not exposed"), encoding="utf-8")
            return clone

        def nested_plain_copy(clone):
            nested = clone / "nested-copy"
            nested.mkdir()
            archive = subprocess.run(
                ["git", "-C", str(clone), "archive", "HEAD"], check=True, stdout=subprocess.PIPE
            ).stdout
            subprocess.run(["tar", "-x", "-C", str(nested)], input=archive, check=True)
            return nested

        def second_origin_value(clone):
            git(clone, "config", "--add", "remote.origin.url", "https://github.com/example-fork/DACS-Standard.git")
            return clone

        def fork_with_added_pinned_origin(clone):
            git(clone, "remote", "set-url", "origin", "https://github.com/example-fork/DACS-Standard.git")
            git(clone, "config", "--add", "remote.origin.url", EXPECTED_ORIGIN)
            return clone

        def descriptor_is_a_fifo(clone):
            path = clone / DESCRIPTOR_RELATIVE
            path.unlink()
            os.mkfifo(path)
            return clone

        for mutate in (
            uncommitted_descriptor,
            nested_plain_copy,
            second_origin_value,
            fork_with_added_pinned_origin,
            descriptor_is_a_fifo,
        ):
            with self.subTest(mutation=mutate.__name__):
                root = mutate(committed_clone(self))
                completed, _ = run_adapter([METADATA], root=root)
                self.assertTrue(unavailable(completed), completed)

    def test_the_adapter_runs_only_as_its_pinned_committed_source(self):
        """An edited adapter runs only once it is committed and re-pinned, under a new revision."""

        descriptor = json.loads(DESCRIPTOR.read_text(encoding="utf-8"))
        family = next(item for item in descriptor["families"] if item["id"] == "domain-separated-signing")
        mismatch = next(
            case for case in family["cases"] if case["caseId"] == "signing::reject-mismatched-ascii-hex-hash"
        )
        probe = execute(
            "mismatch",
            "domainSepVerify",
            [
                byte_tag(mismatch["messageBytesHex"]),
                mismatch["separator"],
                byte_tag(mismatch["signatureBytesHex"]),
                byte_tag(mismatch["publicKeyHex"]),
            ],
        )
        genuine = "        return _verify_ed25519(public_key, signature, payload)\n"
        for variant in ("uncommitted", "committed-not-repinned", "pinned-bytes-not-at-head", "repinned"):
            with self.subTest(variant=variant):
                clone = committed_clone(self)
                adapter = clone / "scripts" / "dacs_adapter.py"
                original = adapter.read_bytes()
                self.assertEqual(original.decode("utf-8").count(genuine), 1)
                adapter.write_text(
                    original.decode("utf-8").replace(genuine, "        return True\n"), encoding="utf-8"
                )
                if variant != "uncommitted":
                    commit_all(clone, "edit the adapter")
                if variant == "pinned-bytes-not-at-head":
                    # The working file is the pinned one again, but HEAD carries the edit.
                    adapter.write_bytes(original)
                if variant == "repinned":
                    edited = pin_of(clone, "scripts/dacs_adapter.py")
                    commit_descriptor(clone, lambda descriptor: descriptor["adapter"].update(source=edited))
                completed, responses = run_adapter([METADATA, probe], root=clone)
                if variant == "repinned":
                    # The control: the edit is visible, and only under another revision.
                    self.assertEqual(completed.returncode, 0, completed.stderr.decode())
                    self.assertEqual(responses[0]["result"]["revision"], "sha256:" + edited["sha256"])
                    self.assertNotEqual(edited["sha256"], hashlib.sha256(original).hexdigest())
                    self.assertIs(responses[1]["result"], True)
                else:
                    self.assertTrue(unavailable(completed), (completed, responses))

    def test_a_descriptor_with_a_repeated_member_is_refused(self):
        """Its raw text could claim one thing while its parsed value says another."""

        clone = committed_clone(self)
        path = clone / DESCRIPTOR_RELATIVE
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count('"adapter": {'), 1)
        path.write_text(
            text.replace('"adapter": {', '"adapter": {\n    "limitations": ["normative and complete"],', 1),
            encoding="utf-8",
        )
        commit_all(clone, "repeat a member")
        completed, _ = run_adapter([METADATA], root=clone)
        self.assertTrue(unavailable(completed), completed)
        self.assertIn(b"duplicate member name", completed.stderr)
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
        self.assertIn("duplicate member name", validator.stderr)

    def test_later_edits_to_wrapped_files_change_neither_what_runs_nor_whether_it_runs(self):
        """The release is read from Git objects, so ordinary repository work cannot break it."""

        clone = committed_clone(self)
        jcs = clone / "scripts" / "jcs.py"
        jcs.write_bytes(release_bytes("scripts/jcs.py") + b"\n\ndef canonicalize(value):\n    return '\"TAMPERED\"'\n")
        for relative in (
            "scripts/validate_conformance_vectors.py",
            "scripts/run_lifecycle_walkthrough.py",
            "tests/test_flow_trace_signing.py",
        ):
            path = clone / relative
            path.write_bytes((path.read_bytes() if path.exists() else b"") + b"\n# a later, unrelated edit\n")
        golden = clone / "conformance" / "vectors" / "golden.json"
        golden.write_bytes((golden.read_bytes() if golden.exists() else b"") + b"\n")
        git(clone, "add", "--all")
        commit_all(clone, "later work on next")
        (clone / "scripts" / "specsource.py").write_bytes(b"raise SystemExit('uncommitted edit')\n")
        completed, responses = run_adapter(
            [METADATA, execute("jcs", "canonicalize", [{"b": 1, "a": 2}])], root=clone
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(responses[1]["result"], {"hex": b'{"a":2,"b":1}'.hex()})
        validator = subprocess.run(
            [sys.executable, str(clone / "scripts" / "validate_dacs_adapter_release.py")],
            cwd=clone,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=120,
        )
        self.assertEqual(validator.returncode, 0, validator.stderr)

    def test_no_git_transport_runs_during_the_checks(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        clone = Path(directory.name) / "shallow"
        marker = Path(directory.name) / "helper-ran"
        # A depth-1 clone lacks the wrapped revision object, which invites a lazy fetch.
        git(ROOT, "clone", "--quiet", "--depth", "1", f"file://{ROOT}", str(clone))
        git(clone, "remote", "set-url", "origin", EXPECTED_ORIGIN)
        git(clone, "config", "extensions.partialClone", "helper")
        git(clone, "config", "remote.helper.url", f"ext::sh -c touch% {marker}")
        git(clone, "config", "remote.helper.promisor", "true")
        git(clone, "config", "protocol.ext.allow", "always")
        completed, _ = run_adapter([METADATA], root=clone)
        self.assertTrue(unavailable(completed), completed)
        self.assertFalse(marker.exists())

    def test_untracked_and_environment_modules_cannot_shadow_the_standard_library(self):
        clone = committed_clone(self)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        markers = Path(directory.name)
        planted = {
            clone / "scripts" / "json.py": markers / "scripts-json",
            clone / "untracked" / "json.py": markers / "checkout-pythonpath-json",
            markers / "base64.py": markers / "pythonpath-base64",
        }
        for path, marker in planted.items():
            path.parent.mkdir(exist_ok=True)
            path.write_text(f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n", encoding="utf-8")
        env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(clone / "untracked"), str(markers)])}
        completed, responses = run_adapter(
            [METADATA, execute("sig", "signatureValueVerdict", ["YQ"])], root=clone, env=env
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(responses[1]["result"], "ACCEPT")
        for marker in planted.values():
            self.assertFalse(marker.exists(), marker.name)

    def test_closed_streams_never_produce_tracebacks_or_stdout_diagnostics(self):
        bad = json.dumps(execute("bad", "madeUp", [])).encode() + b"\n"
        good = json.dumps(METADATA).encode() + b"\n"
        # stderr closed: diagnostics are dropped and stdout still has one line per request.
        completed = subprocess.run(
            ["sh", "-c", 'exec "$0" "$1" 2>&-', sys.executable, str(pinned_adapter())],
            cwd=pinned_checkout(),
            input=bad * 3 + good,
            stdout=subprocess.PIPE,
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0)
        lines = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual([item["id"] for item in lines], ["bad", "bad", "bad", "metadata"])
        # stdout closed by its reader: exit without a traceback.
        process = subprocess.Popen(
            [sys.executable, str(pinned_adapter())],
            cwd=pinned_checkout(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        process.stdout.close()
        _, stderr = process.communicate(good * 200, timeout=60)
        self.assertEqual(process.returncode, 1)
        self.assertNotIn(b"Traceback", stderr)
        self.assertNotIn(b"BrokenPipeError", stderr)


    def test_nothing_in_the_checkout_runs_before_or_after_the_isolated_reexec(self):
        clone = committed_clone(self)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        markers = Path(directory.name)
        planted = {
            clone / "scripts" / "__future__.py": "annotations = None\n",
            clone / "scripts" / "cryptography" / "__init__.py": "",
            clone / "scripts" / "os.py": "",
        }
        for path, body in planted.items():
            path.parent.mkdir(exist_ok=True)
            marker = markers / path.relative_to(clone).as_posix().replace("/", "_")
            path.write_text(
                f"import sys\nsys.stdout.write('POLLUTED\\n')\nopen({str(marker)!r}, 'w').close()\n{body}",
                encoding="utf-8",
            )
        completed, responses = run_adapter(
            [METADATA, execute("sig", "signatureValueVerdict", ["YQ"])], root=clone
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual([item["id"] for item in responses], ["metadata", "sig"])
        validator = subprocess.run(
            [sys.executable, str(clone / "scripts" / "validate_dacs_adapter_release.py")],
            cwd=clone,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=120,
        )
        self.assertEqual(validator.returncode, 0, validator.stderr)
        self.assertNotIn("POLLUTED", validator.stdout)
        self.assertEqual(sorted(item.name for item in markers.iterdir()), [])

    def test_isolated_reexec_skips_site_initialization(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        venv = Path(directory.name) / "venv"
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True, timeout=120)
        marker = Path(directory.name) / "site-ran-in-isolated-adapter"
        site_packages = next(venv.glob("lib/python3*/site-packages"))
        (site_packages / "zz_probe.pth").write_text(
            f"import sys, pathlib; sys.flags.isolated and pathlib.Path({str(marker)!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        completed = subprocess.run(
            [str(venv / "bin" / "python"), str(pinned_adapter())],
            cwd=pinned_checkout(),
            input=json.dumps(METADATA).encode() + b"\n",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertFalse(marker.exists())

    def test_git_checks_are_scoped_to_the_checkout_and_its_effective_origin(self):
        # Launched from outside the repository, the adapter still checks its own checkout.
        with tempfile.TemporaryDirectory() as elsewhere:
            completed = subprocess.run(
                [sys.executable, str(pinned_adapter())],
                cwd=elsewhere,
                input=json.dumps(METADATA).encode() + b"\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=60,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())

        def origin_only_from_environment(clone):
            git(clone, "remote", "remove", "origin")
            env = {
                **os.environ,
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "remote.origin.url",
                "GIT_CONFIG_VALUE_0": EXPECTED_ORIGIN,
            }
            return env

        def fetch_url_rewritten_by_include(clone):
            include = clone / ".git" / "fork.inc"
            include.write_text(
                '[url "https://github.com/example-fork/"]\n'
                "\tinsteadOf = https://github.com/DACS-Agent-commerce/\n",
                encoding="utf-8",
            )
            git(clone, "config", "include.path", "fork.inc")
            return None

        def second_url_in_worktree_config(clone):
            git(clone, "config", "extensions.worktreeConfig", "true")
            git(clone, "config", "--worktree", "--add", "remote.origin.url", "https://github.com/example-fork/x.git")
            return None

        def fork_with_added_pinned_origin(clone):
            git(clone, "remote", "set-url", "origin", "https://github.com/example-fork/DACS-Standard.git")
            git(clone, "config", "--add", "remote.origin.url", EXPECTED_ORIGIN)
            return None

        # A developer's rewrite of the same repository to SSH is still that repository.
        clone = committed_clone(self)
        (clone / ".git" / "ssh.inc").write_text(
            '[url "git@github.com:"]\n\tinsteadOf = https://github.com/\n', encoding="utf-8"
        )
        git(clone, "config", "include.path", "ssh.inc")
        completed, responses = run_adapter([METADATA], root=clone)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(responses[0]["result"]["observedOrigin"], EXPECTED_ORIGIN)
        validator = subprocess.run(
            [sys.executable, str(clone / "scripts" / "validate_dacs_adapter_release.py")],
            cwd=clone,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=120,
        )
        self.assertEqual(validator.returncode, 0, validator.stderr)

        for mutate in (
            origin_only_from_environment,
            fetch_url_rewritten_by_include,
            second_url_in_worktree_config,
            fork_with_added_pinned_origin,
        ):
            with self.subTest(mutation=mutate.__name__):
                clone = committed_clone(self)
                env = mutate(clone)
                completed, _ = run_adapter([METADATA], root=clone, env=env)
                self.assertTrue(unavailable(completed), completed)
                validator = subprocess.run(
                    [sys.executable, str(clone / "scripts" / "validate_dacs_adapter_release.py")],
                    cwd=clone,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    timeout=120,
                )
                self.assertEqual(validator.returncode, 1, validator.stdout)
                self.assertIn("adapter release proposal: FAIL", validator.stderr)

    def test_wrapped_release_constants_must_name_a_consistent_commit_and_tree(self):
        descriptor = json.loads(DESCRIPTOR.read_text(encoding="utf-8"))
        wrapped_revision = descriptor["adapter"]["wrappedStandard"]["revision"]
        wrapped_tree = descriptor["adapter"]["wrappedStandard"]["tree"]
        for label, new_revision, new_tree in (
            ("tree-of-another-commit", wrapped_revision, git(ROOT, "rev-parse", "HEAD^{tree}")),
            ("tree-object-as-revision", wrapped_tree, wrapped_tree),
        ):
            with self.subTest(variant=label):
                clone = committed_clone(self)
                adapter = clone / "scripts" / "dacs_adapter.py"
                text = adapter.read_text(encoding="utf-8")
                text = text.replace(f'WRAPPED_REVISION = "{wrapped_revision}"', f'WRAPPED_REVISION = "{new_revision}"')
                text = text.replace(f'WRAPPED_TREE = "{wrapped_tree}"', f'WRAPPED_TREE = "{new_tree}"')
                adapter.write_text(text, encoding="utf-8")
                commit_all(clone, "retarget constants")

                def retarget(descriptor):
                    descriptor["adapter"]["wrappedStandard"]["revision"] = new_revision
                    descriptor["adapter"]["wrappedStandard"]["tree"] = new_tree
                    descriptor["adapter"]["source"] = pin_of(clone, "scripts/dacs_adapter.py")

                commit_descriptor(clone, retarget)
                completed, _ = run_adapter([METADATA], root=clone)
                self.assertTrue(unavailable(completed), completed)

    def test_request_and_diagnostic_bounds(self):
        completed, responses = run_adapter(
            [
                request("i" * 256, "metadata"),
                request("i" * 257, "metadata"),
                execute("six", "canonicalize", [1, 2, 3, 4, 5, 6]),
                execute("\u202e" * 256, "madeUp", []),
            ]
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertTrue(responses[0]["ok"])
        self.assertEqual(
            [item["error"]["code"] for item in responses[1:]],
            ["INVALID_REQUEST", "INVALID_REQUEST", "UNSUPPORTED_OPERATION"],
        )
        self.assertTrue(all(len(line) <= 1024 for line in completed.stderr.splitlines()))
        self.assertGreater(max(len(line) for line in completed.stderr.splitlines()), 1000)

        def sized(total):
            head = b'{"protocol":"dacs-adapter/1","id":"s","type":"execute","operation":"canonicalize","params":["'
            tail = b'"]}'
            return head + b"a" * (total - len(head) - len(tail)) + tail

        exact, over = sized(1_048_576), sized(1_048_577)
        completed, responses = run_adapter_bytes(exact + b"\n" + over + b"\n" + over)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertTrue(responses[0]["ok"], responses[0].get("error"))
        self.assertEqual(
            [item["error"]["code"] for item in responses[1:]], ["REQUEST_TOO_LARGE", "REQUEST_TOO_LARGE"]
        )

        clone = committed_clone(self)
        (clone / DESCRIPTOR_RELATIVE).write_bytes(b" " * (9 * 1_048_576))
        completed, _ = run_adapter([METADATA], root=clone)
        self.assertTrue(unavailable(completed), completed)
        self.assertIn(b"too large", completed.stderr)

    def test_a_kept_alive_process_answers_each_request_in_bounded_memory(self):
        """The protocol lets a runner keep one process alive for several requests."""

        process = subprocess.Popen(
            [sys.executable, str(pinned_adapter())],
            cwd=pinned_checkout(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(process.stderr.close)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.kill)
        pending = bytearray()

        def next_line():
            deadline = time.monotonic() + 60
            while b"\n" not in pending:
                remaining = deadline - time.monotonic()
                ready = select.select([process.stdout], [], [], max(remaining, 0))[0] if remaining > 0 else []
                if not ready:
                    self.fail("no response line before the deadline")
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    self.fail("the adapter closed its output")
                pending.extend(chunk)
            line, _, rest = bytes(pending).partition(b"\n")
            pending[:] = rest
            return json.loads(line)

        process.stdin.write(json.dumps(METADATA).encode() + b"\n")
        process.stdin.flush()
        # Each response is flushed as it is written, not when the process exits.
        self.assertTrue(next_line()["ok"])

        # Startup, including every Git call, is over.  Where the host can limit a
        # running process (Linux), the adapter may now use only 64 MiB more address
        # space, far less than the oversized line below; elsewhere this checks recovery.
        import resource

        status = Path(f"/proc/{process.pid}/status")
        if hasattr(resource, "prlimit") and status.exists():
            size = int(re.search(r"^VmSize:\s+(\d+) kB", status.read_text(), re.MULTILINE).group(1)) * 1024
            limit = size + 64 * 1_048_576
            resource.prlimit(process.pid, resource.RLIMIT_AS, (limit, limit))

        def feed():
            chunk = b"a" * 1_048_576
            try:
                for _ in range(192):
                    process.stdin.write(chunk)
                process.stdin.write(b"\n" + json.dumps(execute("after", "canonicalize", [{"b": 1, "a": 2}])).encode() + b"\n")
                process.stdin.flush()
            except BrokenPipeError:
                pass

        writer = threading.Thread(target=feed, daemon=True)
        writer.start()
        oversized = next_line()
        self.assertEqual(oversized["error"]["code"], "REQUEST_TOO_LARGE")
        self.assertEqual(next_line()["result"], {"hex": b'{"a":2,"b":1}'.hex()})
        writer.join(timeout=60)
        process.stdin.close()
        self.assertEqual(process.wait(timeout=60), 0)
        self.assertNotIn(b"Traceback", process.stderr.read())

    def test_failing_standard_streams_fail_closed_with_one_line(self):
        good = json.dumps(METADATA).encode() + b"\n"
        with tempfile.TemporaryDirectory() as directory:
            requests = Path(directory) / "requests.jsonl"
            requests.write_bytes(good)
            for label, redirect in (
                ("stdout-full", f"< {requests} > /dev/full"),
                ("stdout-read-only", f"< {requests} 1< /dev/null"),
                ("stdin-write-only", f"0> {Path(directory) / 'sink'}"),
            ):
                with self.subTest(stream=label):
                    completed = subprocess.run(
                        ["sh", "-c", f'exec "$0" "$1" {redirect}', sys.executable, str(pinned_adapter())],
                        cwd=pinned_checkout(),
                        stdout=subprocess.PIPE if label == "stdin-write-only" else None,
                        stderr=subprocess.PIPE,
                        check=False,
                        timeout=60,
                    )
                    self.assertEqual(completed.returncode, 1)
                    self.assertEqual(completed.stderr.count(b"\n"), 1, completed.stderr)
                    self.assertIn(b"dacs-adapter: unavailable: standard stream failed", completed.stderr)
                    self.assertNotIn(b"Traceback", completed.stderr)


class DacsAdapterBoundaryTests(unittest.TestCase):
    """Verdicts, abstentions, and request errors stay distinct."""

    @classmethod
    def setUpClass(cls):
        cls.descriptor = json.loads(DESCRIPTOR.read_text(encoding="utf-8"))
        cls.family = next(
            item for item in cls.descriptor["families"] if item["id"] == "domain-separated-signing"
        )
        cls.cases = {case["caseId"]: case for case in cls.family["cases"]}
        happy = json.loads(pinned_text("conformance/vectors/dacs-v0.1-happy-path.json"))
        cls.artifacts = {item["id"]: item["artifact"] for item in happy["artifacts"]}

    def test_signed_scope_abstains_on_every_other_version_member(self):
        spec_files = git(ROOT, "ls-tree", "--name-only", WRAPPED_REVISION, "spec/").splitlines()
        spec_text = "\n".join(pinned_text(path) for path in spec_files if path.endswith(".md"))
        # Every *Version name the spec declares or discusses, plus an unknown future one.
        names = set(re.findall(r"\b([a-z][A-Za-z]*Version)\b", spec_text)) | {"futureOptionalVersion"}
        for required in ("payloadAttestationVersion", "finalityCommitmentVersion", "amendmentVersion",
                         "legacyTransitionEvidenceVersion", "finalityBoundEvidenceVersion", "recordVersion"):
            self.assertIn(required, names)

        evidence = self.artifacts["settlement-htlc-release"]
        bundle = self.artifacts["attestation-bundle-happy"]
        allowed = {
            "evidence": {"evidenceVersion"},
            "bundle": {"bundleVersion", "recipeRegistryVersion", "railRegistryVersion"},
        }
        requests = [
            execute("control-evidence", "signedScopeHash", [evidence]),
            execute("control-bundle", "signedScopeHash", [bundle]),
        ]
        for label, artifact in (("evidence", evidence), ("bundle", bundle)):
            for name in sorted(names - allowed[label]):
                requests.append(execute(f"{label}+{name}", "signedScopeHash", [{**artifact, name: "1"}]))
        without_phase = {key: value for key, value in evidence.items() if key != "phase"}
        requests += [
            execute("evidence-without-phase", "signedScopeHash", [without_phase]),
            execute("not-an-object", "signedScopeHash", [[evidence]]),
        ]
        completed, responses = run_adapter(requests)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        signed_scope = next(item for item in self.descriptor["families"] if item["id"] == "signed-scope")
        self.assertEqual(
            [response["result"] for response in responses[:2]],
            [case["expected"] for case in signed_scope["cases"]],
        )
        self.assertGreater(len(responses), 90)
        for response in responses[2:-1]:
            with self.subTest(case=response["id"]):
                self.assertFalse(response["ok"], response)
                self.assertEqual(response["error"]["code"], "UNSUPPORTED_CASE")
        self.assertEqual(responses[-1]["error"]["code"], "INVALID_PARAMS")

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
            ("sign-bigint-message", "domainSepSign", [bigint, listing, seed], "INVALID_PARAMS"),
            ("sign-bigint-arity", "domainSepSign", [message, listing, seed, None, bigint], "INVALID_PARAMS"),
            ("verify-bigint-key", "domainSepVerify", [message, listing, signature, bigint], "INVALID_PARAMS"),
            ("canonicalize-bigint-arity", "canonicalize", [1, bigint], "INVALID_PARAMS"),
            ("signed-scope-bigint-not-object", "signedScopeHash", [bigint], "INVALID_PARAMS"),
            ("sig6-bigint-value", "signatureValueVerdict", [bigint], "UNSUPPORTED_CASE"),
            ("signed-scope-nested-bigint", "signedScopeHash", [{"evidenceVersion": bigint}], "UNSUPPORTED_CASE"),
        ]
        completed, responses = run_adapter(
            [execute(name, operation, params) for name, operation, params, _ in cases]
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        for (name, _, _, code), response in zip(cases, responses, strict=True):
            with self.subTest(case=name):
                self.assertFalse(response["ok"], response)
                self.assertEqual(response["error"]["code"], code)
        # Well-formed requests keep their verdicts: an unknown non-DACS separator and a
        # wrong-length signature or public key are failed verifications, not errors.
        upper = byte_tag(bytes.fromhex(verify["messageBytesHex"]).upper().hex())
        completed, responses = run_adapter(
            [
                execute("well-formed-unknown", "domainSepVerify", [message, unknown, signature, public_key]),
                execute("short-signature", "domainSepVerify", [message, listing, byte_tag("00" * 63), public_key]),
                execute("short-public-key", "domainSepVerify", [message, listing, signature, byte_tag("00" * 31)]),
                execute("uppercase-verify", "domainSepVerify", [upper, listing, signature, public_key]),
                execute("uppercase-sign", "domainSepSign", [upper, listing, seed]),
                execute("negative-zero-bigint", "canonicalize", [{"$dacsType": "bigint", "decimal": "-0"}]),
            ]
        )
        self.assertEqual([item.get("result") for item in responses[:3]], [False, False, False])
        self.assertEqual(
            [item["error"]["code"] for item in responses[3:]],
            ["UNSUPPORTED_CASE", "UNSUPPORTED_CASE", "MALFORMED_TAG"],
        )

    def test_every_request_guard_is_exercised(self):
        evidence = self.artifacts["settlement-htlc-release"]
        bundle = self.artifacts["attestation-bundle-happy"]
        verify = self.cases["signing::verify-ascii-hex-hash"]
        sign = self.cases["signing::sign-ascii-hex-hash"]
        message = byte_tag(verify["messageBytesHex"])
        signature = byte_tag(verify["signatureBytesHex"])
        public_key = byte_tag(verify["publicKeyHex"])
        seed = byte_tag(sign["privateKeyBytesHex"])
        raw_digest = byte_tag(self.family["unsupportedCases"][0]["messageBytesHex"])

        def without(artifact, member):
            return {key: value for key, value in artifact.items() if key != member}

        cases = [
            ("bundle-version-2", "signedScopeHash", [{**bundle, "bundleVersion": "2"}], "UNSUPPORTED_CASE"),
            ("evidence-version-2", "signedScopeHash", [{**evidence, "evidenceVersion": "2"}], "UNSUPPORTED_CASE"),
            *[
                (f"evidence-without-{member}", "signedScopeHash", [without(evidence, member)], "UNSUPPORTED_CASE")
                for member in ("jobId", "phase", "outcome", "signature")
            ],
            *[
                (f"bundle-without-{member}", "signedScopeHash", [without(bundle, member)], "UNSUPPORTED_CASE")
                for member in ("jobId", "outcome", "phaseSummary", "signatures")
            ],
            ("signed-scope-arity", "signedScopeHash", [evidence, evidence], "INVALID_PARAMS"),
            ("sig6-arity", "signatureValueVerdict", [], "INVALID_PARAMS"),
            ("canonicalize-arity", "canonicalize", [], "INVALID_PARAMS"),
            ("verify-arity", "domainSepVerify", [message, "dacs-listing:v1:", signature], "INVALID_PARAMS"),
            ("sign-arity", "domainSepSign", [message, "dacs-listing:v1:"], "INVALID_PARAMS"),
            ("verify-numeric-separator", "domainSepVerify", [message, 7, signature, public_key], "INVALID_PARAMS"),
            # 32 characters, so only the byte-tag type check can object.
            ("sign-text-seed", "domainSepSign", [message, "dacs-listing:v1:", "s" * 32], "INVALID_PARAMS"),
            ("unknown-op-before-tags", "madeUp", [{"$dacsType": "bytes", "hex": "ZZ"}], "UNSUPPORTED_OPERATION"),
            ("uppercase-bytes-tag", "canonicalize", [{"$dacsType": "bytes", "hex": "AB"}], "MALFORMED_TAG"),
            ("odd-bytes-tag", "canonicalize", [{"$dacsType": "bytes", "hex": "abc"}], "MALFORMED_TAG"),
            ("bytes-tag-extra-member", "canonicalize", [{"$dacsType": "bytes", "hex": "ab", "x": 1}], "MALFORMED_TAG"),
            ("unknown-tag", "canonicalize", [{"$dacsType": "binary64", "hex": "00" * 8}], "MALFORMED_TAG"),
            ("bigint-extra-member", "canonicalize", [{"$dacsType": "bigint", "decimal": "1", "x": 1}], "MALFORMED_TAG"),
            ("bigint-leading-zero", "canonicalize", [{"$dacsType": "bigint", "decimal": "01"}], "MALFORMED_TAG"),
            # Two digits, so only the string type check can object.
            ("bytes-tag-number", "canonicalize", [{"$dacsType": "bytes", "hex": 55}], "MALFORMED_TAG"),
            ("bigint-number", "canonicalize", [{"$dacsType": "bigint", "decimal": 5}], "MALFORMED_TAG"),
            ("verify-dacs5-separator", "domainSepVerify", [message, "dacs5-bundle:v1:", signature, public_key], "UNSUPPORTED_CASE"),
            ("verify-sig4-uppercase-kind", "domainSepVerify", [message, "dacs-x-Foo:v1:", signature, public_key], "UNSUPPORTED_CASE"),
            ("verify-sig4-underscore-kind", "domainSepVerify", [message, "dacs-x-foo_bar:v1:", signature, public_key], "UNSUPPORTED_CASE"),
            ("sign-sig4-kind", "domainSepSign", [message, "dacs-x-Foo:v1:", seed], "UNSUPPORTED_CASE"),
        ]
        envelopes = [
            ({"id": "p", "type": "metadata"}, "PROTOCOL_MISMATCH"),
            ({"protocol": "dacs-adapter/0", "id": "p", "type": "metadata"}, "PROTOCOL_MISMATCH"),
            ({"protocol": "dacs-adapter/1", "id": "p", "type": "other"}, "INVALID_REQUEST"),
            ({"protocol": "dacs-adapter/1", "id": "p", "type": "metadata", "x": 1}, "INVALID_REQUEST"),
            ({**execute("p", "canonicalize", [1]), "x": 1}, "INVALID_REQUEST"),
            (execute("p", "", [1]), "INVALID_REQUEST"),
            ({**execute("p", "canonicalize", [1]), "params": {"0": 1}}, "INVALID_REQUEST"),
            ({"protocol": "dacs-adapter/1", "id": 7, "type": "metadata"}, "INVALID_REQUEST"),
            ({**execute("p", "canonicalize", [1]), "operation": 5}, "INVALID_REQUEST"),
            ([METADATA], "INVALID_REQUEST"),
        ]
        requests = [execute(name, operation, params) for name, operation, params, _ in cases]
        requests += [envelope for envelope, _ in envelopes]
        # Verification decides the separator before the message grammar.
        requests.append(
            execute("raw-digest-unknown-separator", "domainSepVerify",
                    [raw_digest, "not-a-dacs-separator:v1:", signature, public_key])
        )
        completed, responses = run_adapter(requests)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        expected = [code for *_, code in cases] + [code for _, code in envelopes]
        for label, response, code in zip(
            [name for name, *_ in cases] + [f"envelope-{index}" for index in range(len(envelopes))],
            responses,
            expected,
            strict=False,
        ):
            with self.subTest(case=label):
                self.assertFalse(response["ok"], response)
                self.assertEqual(response["error"]["code"], code)
        self.assertEqual(len(responses), len(requests))
        self.assertIs(responses[-1]["result"], False)

    def test_bounded_f5_separator_and_message_match_exactly(self):
        """A separator or message that merely contains the profile's is outside it."""

        verify = self.cases["signing::verify-ascii-hex-hash"]
        sign = self.cases["signing::sign-ascii-hex-hash"]
        digits = bytes.fromhex(verify["messageBytesHex"])
        signature = byte_tag(verify["signatureBytesHex"])
        public_key = byte_tag(verify["publicKeyHex"])
        seed = byte_tag(sign["privateKeyBytesHex"])
        self.assertNotEqual(digits.upper(), digits)
        inputs = [
            (digits, separator)
            for separator in ("dacs-listing:v1:extra:", "dacs-listing:v1::", "dacs-listing:v1", "dacs-listing:v2:")
        ] + [
            (message, "dacs-listing:v1:")
            for message in (digits + b"\x00", digits + b"0", digits + b"\n", b" " + digits, digits[:-1], digits.upper())
        ]
        requests = []
        for index, (message, separator) in enumerate(inputs):
            requests.append(execute(f"sign-{index}", "domainSepSign", [byte_tag(message.hex()), separator, seed]))
            requests.append(
                execute(f"verify-{index}", "domainSepVerify", [byte_tag(message.hex()), separator, signature, public_key])
            )
        requests.append(
            execute("exact", "domainSepVerify", [byte_tag(digits.hex()), "dacs-listing:v1:", signature, public_key])
        )
        completed, responses = run_adapter(requests)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(len(responses), len(requests))
        for sent, response in zip(requests[:-1], responses[:-1]):
            with self.subTest(case=sent["id"], params=sent["params"][:2]):
                self.assertFalse(response["ok"], response)
                self.assertEqual(response["error"]["code"], "UNSUPPORTED_CASE")
        self.assertIs(responses[-1]["result"], True)

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
            prefix + b"[" * 100_000 + b"]" * 100_000 + b"]}",
            b'{"protocol":"dacs-adapter/1","id":"a","id":"b","type":"metadata"}',
            prefix + b'{"a":1,"a":2}]}',
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

        def f5_case(descriptor, key, case_id):
            family = self.family(descriptor, "domain-separated-signing")
            return next(item for item in family[key] if item["caseId"] == case_id)

        def mismatch_case_other_separator(descriptor):
            f5_case(descriptor, "cases", "signing::reject-mismatched-ascii-hex-hash")["separator"] = "zzz"

        def raw_digest_case_other_separator(descriptor):
            f5_case(descriptor, "unsupportedCases", "signing::valid-raw-digest-profile-boundary")[
                "separator"
            ] = "dacs-bundle:v1:"

        def primitive_control_other_separator(descriptor):
            f5_case(descriptor, "primitiveControls", "signing::raw-digest-does-not-verify-golden-signature")[
                "separator"
            ] = "zzz"

        def tagged_case_selected(descriptor):
            family = self.family(descriptor, "canonicalization")
            family["excludedSourceCases"] = [
                item for item in family["excludedSourceCases"] if item["caseId"] != "negative-zero"
            ]
            family["cases"].append(
                {"caseId": "negative-zero", "sourceExpected": "pass", "expected": {"hex": "30"}}
            )

        def unsupported_code_as_expected_rejection(descriptor):
            case = next(
                item for item in self.family(descriptor, "canonicalization")["cases"]
                if item["caseId"] == "number-over-dacs-magnitude"
            )
            case["expectedErrorCode"] = "UNSUPPORTED_CASE"

        def algorithm_length_case_selected(descriptor):
            family = self.family(descriptor, "sig6-wire")
            family["excludedSourceCases"] = [
                item for item in family["excludedSourceCases"]
                if item["caseId"] != "canonical-wire-wrong-ed25519-length-rejected"
            ]
            family["cases"].append(
                {
                    "caseId": "canonical-wire-wrong-ed25519-length-rejected",
                    "sourceExpected": "reject",
                    "expected": "REJECT",
                }
            )

        def bounded_family_scored_as_executable(descriptor):
            self.family(descriptor, "domain-separated-signing")["status"] = "executable"

        def duplicated_signed_scope_case(descriptor):
            cases = self.family(descriptor, "signed-scope")["cases"]
            cases.append(copy.deepcopy(cases[0]))

        def missing_adapter_name(descriptor):
            del descriptor["adapter"]["name"]

        def oversized_limitation(descriptor):
            descriptor["adapter"]["limitations"].append("x" * 5_000_000)

        def wrapped_release_not_fixed_by_adapter(descriptor):
            # HEAD carries byte-identical primitives, so only the release binding can object.
            wrapped = descriptor["adapter"]["wrappedStandard"]
            wrapped["revision"] = git(ROOT, "rev-parse", "HEAD")
            wrapped["tree"] = git(ROOT, "rev-parse", "HEAD^{tree}")

        def canonicalization_dispatched_elsewhere(descriptor):
            self.family(descriptor, "canonicalization")["operation"] = "signedScopeHash"

        def unhashable_signed_scope_kind(descriptor):
            # A genuine source hash, so only the hashable-kind binding can object.
            happy = json.loads(pinned_text("conformance/vectors/dacs-v0.1-happy-path.json"))
            listing = next(item for item in happy["artifacts"] if item["id"] == "listing-analyze-csv")
            self.family(descriptor, "signed-scope")["cases"].append(
                {
                    "caseId": listing["id"],
                    "kind": listing["kind"],
                    "sourceExpected": listing["contentHash"],
                    "expected": {"hex": listing["contentHash"].removeprefix("sha256:")},
                }
            )

        def verify_case_run_as_sign(descriptor):
            f5_case(descriptor, "cases", "signing::unknown-separator-false")["operation"] = "domainSepSign"

        def rejection_relabelled_unsupported(descriptor):
            family = self.family(descriptor, "canonicalization")
            case = next(item for item in family["cases"] if item["caseId"] == "number-over-dacs-magnitude")
            family["cases"].remove(case)
            family["unsupportedSourceCases"].append(
                {
                    "caseId": case["caseId"],
                    "sourceExpected": case["sourceExpected"],
                    "sourceExpectedErrorCode": case["sourceExpectedErrorCode"],
                    "adapterErrorCode": "UNSUPPORTED_CASE",
                    "reason": "relabelled",
                }
            )

        def generic_f5_profile(descriptor):
            self.family(descriptor, "domain-separated-signing")["profile"] = "generic-f5"

        def unexplained_sig6_exclusion(descriptor):
            self.family(descriptor, "sig6-wire")["excludedSourceCases"][0]["reason"] = ""

        def mutable_protocol_revision(descriptor):
            descriptor["protocol"]["revision"] = "main"

        def malformed_protocol_digest(descriptor):
            descriptor["protocol"]["sha256"] = "not-a-digest"

        probe = tempfile.TemporaryDirectory()
        self.addCleanup(probe.cleanup)
        injected = Path(probe.name) / "injected"

        def option_shaped_source_revision(descriptor):
            descriptor["sources"]["sig6"]["revision"] = f"--output={injected}"

        def traversing_source_path(descriptor):
            descriptor["sources"]["sig6"]["path"] = "../outside.json"

        def normative_status(descriptor):
            descriptor["status"] = "normative"

        def undeclared_normative_member(descriptor):
            descriptor["normative"] = True

        def undeclared_family_member(descriptor):
            self.family(descriptor, "domain-separated-signing")["advertisedGenericFamily"] = True

        def missing_sig6_family(descriptor):
            descriptor["families"] = [item for item in descriptor["families"] if item["id"] != "sig6-wire"]

        def sig6_exclusion_dropped(descriptor):
            self.family(descriptor, "sig6-wire")["excludedSourceCases"].pop()

        def sig6_verdict_flipped(descriptor):
            self.family(descriptor, "sig6-wire")["cases"][0]["expected"] = "REJECT"

        def generic_family_advertised(descriptor):
            self.family(descriptor, "domain-separated-signing")["advertisedFamily"] = True

        def generic_milestone_complete(descriptor):
            self.family(descriptor, "domain-separated-signing")["genericFamilyMilestone"] = "complete"

        def blocker_claimed_resolved(descriptor):
            self.family(descriptor, "domain-separated-signing")["remainingBlocker"] = (
                "None: the shared runner already scores UNSUPPORTED_CASE as ABSTAIN."
            )

        def limitation_contradicted(descriptor):
            descriptor["adapter"]["limitations"][3] = (
                "domainSepSign/domainSepVerify implement the advertised generic domain-sep-sign family"
            )

        def exclusion_reason_rewritten(descriptor):
            self.family(descriptor, "sig6-wire")["excludedSourceCases"][0]["reason"] = "not needed"

        def protocol_repository_changed(descriptor):
            descriptor["protocol"]["repository"] = "https://github.com/example-fork/pathos-dacs-ref"

        def extra_source_corpus(descriptor):
            descriptor["sources"]["rawJson"] = dict(descriptor["sources"]["sig6"])

        def control_names_another_test(descriptor):
            lines = pinned_text("tests/test_flow_trace_signing.py").splitlines()
            name = "test_golden_signature_verifies_over_core_b7_preimage"
            start = lines.index(f"    def {name}(self):") + 1
            end = start
            while lines[end].startswith("        "):
                end += 1
            control = self.family(descriptor, "domain-separated-signing")["controlSource"]
            control.update({"test": name, "lines": f"{start}-{end}"})

        def verify_signature_altered(descriptor):
            f5_case(descriptor, "cases", "signing::verify-ascii-hex-hash")["signatureBytesHex"] = "00" * 64

        def sign_expectation_altered(descriptor):
            f5_case(descriptor, "cases", "signing::sign-ascii-hex-hash")["expected"] = {"hex": "00" * 64}

        def raw_digest_signature_altered(descriptor):
            f5_case(descriptor, "unsupportedCases", "signing::valid-raw-digest-profile-boundary")[
                "signatureBytesHex"
            ] = "00" * 64

        def sig4_form_as_unknown_separator(descriptor):
            f5_case(descriptor, "cases", "signing::unknown-separator-false")["separator"] = "dacs-x-Foo:v1:"

        def swapped_source_corpora(descriptor):
            sources = descriptor["sources"]
            sources["canonicalization"], sources["sig6"] = sources["sig6"], sources["canonicalization"]
            self.family(descriptor, "canonicalization")["source"] = "sig6"
            self.family(descriptor, "sig6-wire")["source"] = "canonicalization"

        def source_pinned_at_head(descriptor):
            descriptor["sources"]["sig6"]["revision"] = git(ROOT, "rev-parse", "HEAD")

        def control_pinned_at_head(descriptor):
            self.family(descriptor, "domain-separated-signing")["controlSource"]["revision"] = git(
                ROOT, "rev-parse", "HEAD"
            )

        def duplicated_f5_operations(descriptor):
            self.family(descriptor, "domain-separated-signing")["operations"] = [
                "domainSepSign", "domainSepVerify", "domainSepVerify",
            ]

        def undeclared_member_in_expected(descriptor):
            self.family(descriptor, "canonicalization")["cases"][0]["expected"]["normative"] = True

        def error_code_on_passing_case(descriptor):
            case = next(
                item for item in self.family(descriptor, "canonicalization")["cases"]
                if item["sourceExpected"] == "pass"
            )
            case["sourceExpectedErrorCode"] = "NUMBER_OUT_OF_RANGE"

        def signing_material_on_verify_case(descriptor):
            sign = f5_case(descriptor, "cases", "signing::sign-ascii-hex-hash")
            mismatch = f5_case(descriptor, "cases", "signing::reject-mismatched-ascii-hex-hash")
            mismatch["privateKeyBytesHex"] = sign["privateKeyBytesHex"]
            mismatch["artifactHashHex"] = sign["artifactHashHex"]

        def verification_material_on_sign_case(descriptor):
            verify = f5_case(descriptor, "cases", "signing::verify-ascii-hex-hash")
            f5_case(descriptor, "cases", "signing::sign-ascii-hex-hash")["publicKeyHex"] = "00" * 32
            f5_case(descriptor, "cases", "signing::sign-ascii-hex-hash")["signatureBytesHex"] = verify[
                "signatureBytesHex"
            ]

        def sig6_case_without_source_verdict(descriptor):
            self.family(descriptor, "sig6-wire")["cases"][0].pop("sourceExpected")

        def adapter_source_digest_wrong(descriptor):
            descriptor["adapter"]["source"]["sha256"] = "0" * 64

        for mutate in (
            normative_status,
            undeclared_normative_member,
            undeclared_family_member,
            missing_sig6_family,
            sig6_exclusion_dropped,
            sig6_verdict_flipped,
            generic_family_advertised,
            generic_milestone_complete,
            blocker_claimed_resolved,
            limitation_contradicted,
            exclusion_reason_rewritten,
            protocol_repository_changed,
            extra_source_corpus,
            control_names_another_test,
            verify_signature_altered,
            sign_expectation_altered,
            raw_digest_signature_altered,
            sig4_form_as_unknown_separator,
            swapped_source_corpora,
            source_pinned_at_head,
            control_pinned_at_head,
            duplicated_f5_operations,
            undeclared_member_in_expected,
            adapter_source_digest_wrong,
            error_code_on_passing_case,
            signing_material_on_verify_case,
            verification_material_on_sign_case,
            sig6_case_without_source_verdict,
            option_shaped_source_revision,
            traversing_source_path,
            canonicalization_dispatched_elsewhere,
            unhashable_signed_scope_kind,
            verify_case_run_as_sign,
            rejection_relabelled_unsupported,
            generic_f5_profile,
            unexplained_sig6_exclusion,
            mutable_protocol_revision,
            malformed_protocol_digest,
            mismatch_case_other_separator,
            raw_digest_case_other_separator,
            primitive_control_other_separator,
            tagged_case_selected,
            unsupported_code_as_expected_rejection,
            algorithm_length_case_selected,
            bounded_family_scored_as_executable,
            duplicated_signed_scope_case,
            missing_adapter_name,
            oversized_limitation,
            wrapped_release_not_fixed_by_adapter,
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
        self.assertFalse(injected.exists())


if __name__ == "__main__":
    unittest.main()
