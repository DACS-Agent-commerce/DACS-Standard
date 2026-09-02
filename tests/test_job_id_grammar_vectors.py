import hashlib
import json
import re
import subprocess
import sys
import unicodedata
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import dacs5_reference as DACS5_REFERENCE

VECTORS = ROOT / "conformance/vectors/security/job-id-grammar-v0.1.json"
GENERATOR = ROOT / "scripts/generate_job_id_grammar_vectors.py"
CORE = ROOT / "spec/CORE.md"
DACS5 = ROOT / "spec/DACS-5-VERIFY.md"
WORKFLOW = ROOT / ".github/workflows/validate.yml"
README = ROOT / "conformance/vectors/security/README.md"
PROFILE = ROOT / "spec/PROFILE.md"
MODULE_SPECS = {
    "core": (ROOT / "spec/CORE.md", "DACS Core", "CORE"),
    "dacs1": (ROOT / "spec/DACS-1-IDENTIFY.md", "DACS-1", "DACS-1-IDENTIFY"),
    "dacs2": (ROOT / "spec/DACS-2-VET.md", "DACS-2", "DACS-2-VET"),
    "dacs3": (ROOT / "spec/DACS-3-NEGOTIATE.md", "DACS-3", "DACS-3-NEGOTIATE"),
    "dacs4": (ROOT / "spec/DACS-4-SETTLE.md", "DACS-4", "DACS-4-SETTLE"),
    "dacs5": (ROOT / "spec/DACS-5-VERIFY.md", "DACS-5", "DACS-5-VERIFY"),
}
LEGACY_ADDRESS_SUITES = (
    ROOT / "tests/test_bundle_binding_vectors.py",
    ROOT / "tests/test_round9_ordering_contract_vectors.py",
    ROOT / "tests/test_round10_validation_predicate_vectors.py",
    ROOT / "tests/test_round11_receipt_ingress_vectors.py",
)

JOB_ID_RE = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}\Z", re.ASCII)
RELEASE_PIN_RE = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
ROLES = {"buyer", "seller", "orchestrator"}
KNOWN_ADDRESSES = {
    "buyer": "stor-180e77cf120910a90212df45f4ed0c7dce8b7ee57c8d66d7f402a7b5e3fe307b",
    "seller": "stor-831775f318b0d4aac57d082789fa5efd8f74583d2dfc0e267bcbe4c284224840",
    "orchestrator": "stor-4cadaaae064cc2257f3e101842e4ae24fd4a481fdb7dea35082f30e7ad2311d0",
}
AUTHORITATIVE_RELEASE_PIN = "0000000000000000000000000000000000000001"
AUTHORITATIVE_MODULE_VERSIONS = {
    "core": "0.3",
    "dacs1": "0.7",
    "dacs2": "0.6",
    "dacs3": "0.5",
    "dacs4": "0.7",
    "dacs5": "0.5",
}
AUTHORITATIVE_LOCAL_PROFILE = {
    "releasePin": AUTHORITATIVE_RELEASE_PIN,
    "moduleVersions": AUTHORITATIVE_MODULE_VERSIONS,
}
# These opaque references model profiles whose provenance and peer identity have
# already been authenticated by the implementation. Vector-supplied profile
# objects are deliberately never trusted as admission authority.
AUTHENTICATED_PEER_PROFILES = {
    "fixture:peer-current": {
        "releasePin": AUTHORITATIVE_RELEASE_PIN,
        "moduleVersions": dict(AUTHORITATIVE_MODULE_VERSIONS),
    },
    "fixture:peer-wrong-pin": {
        "releasePin": "f" * 40,
        "moduleVersions": AUTHORITATIVE_MODULE_VERSIONS,
    },
    "fixture:peer-partial-tuple": {
        "releasePin": AUTHORITATIVE_RELEASE_PIN,
        "moduleVersions": {
            key: value
            for key, value in AUTHORITATIVE_MODULE_VERSIONS.items()
            if key != "dacs5"
        },
    },
    "fixture:peer-extra-tuple": {
        "releasePin": AUTHORITATIVE_RELEASE_PIN,
        "moduleVersions": {
            **AUTHORITATIVE_MODULE_VERSIONS,
            "future": "0.1",
        },
    },
    "fixture:peer-non-string-pin": {
        "releasePin": 1,
        "moduleVersions": AUTHORITATIVE_MODULE_VERSIONS,
    },
    "fixture:peer-major-only": {"dacsVersion": "1"},
}


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def validate_job_id(value):
    if not isinstance(value, str) or JOB_ID_RE.fullmatch(value) is None:
        raise ValueError("job-id-validation")
    return value


def derive_bundle(job_id, role, metrics):
    validated = validate_job_id(job_id)
    if role not in ROLES:
        raise ValueError("role-validation")
    metrics["hashCalls"] += 1
    preimage = validated.encode("ascii") + b"-bundle-" + role.encode("ascii")
    return "stor-" + hashlib.sha256(preimage).hexdigest()


def is_exact_corrective_profile(profile):
    if not isinstance(profile, dict):
        return False
    release_pin = profile.get("releasePin")
    module_versions = profile.get("moduleVersions")
    return (
        isinstance(release_pin, str)
        and RELEASE_PIN_RE.fullmatch(release_pin) is not None
        and release_pin == AUTHORITATIVE_RELEASE_PIN
        and isinstance(module_versions, dict)
        and set(module_versions) == set(AUTHORITATIVE_MODULE_VERSIONS)
        and all(isinstance(value, str) for value in module_versions.values())
        and module_versions == AUTHORITATIVE_MODULE_VERSIONS
    )


def admit_authenticated_profile(vector):
    # Raw profile objects are attacker-controlled vector inputs, even if their
    # bytes happen to copy the locally configured profile exactly.
    if "localProfile" in vector or "peerProfile" in vector:
        raise ValueError("profile-admission")
    peer_ref = vector.get("peerProfileRef")
    if not isinstance(peer_ref, str):
        raise ValueError("profile-admission")
    peer = AUTHENTICATED_PEER_PROFILES.get(peer_ref)
    if (
        not is_exact_corrective_profile(AUTHORITATIVE_LOCAL_PROFILE)
        or not is_exact_corrective_profile(peer)
    ):
        raise ValueError("profile-admission")


def evaluate(vector):
    metrics = {"hashCalls": 0, "lookupCalls": 0}
    operation = vector.get("operation")
    try:
        if operation == "validate":
            canonical = validate_job_id(vector.get("jobId"))
            return "pass", {**metrics, "canonicalJobId": canonical}
        if operation == "derive-bundle":
            address = derive_bundle(vector.get("jobId"), vector.get("role"), metrics)
            return "pass", {**metrics, "logicalAddress": address}
        if operation == "lookup-bundle":
            address = derive_bundle(vector.get("jobId"), vector.get("role"), metrics)
            metrics["lookupCalls"] += 1
            return "pass", {**metrics, "logicalAddress": address}
        if operation == "derive-logical":
            canonical = validate_job_id(vector.get("jobId"))
            template = vector.get("template")
            if not isinstance(template, str) or template.count("{jobId}") != 1:
                raise ValueError("template-validation")
            return "pass", {**metrics, "logicalAddress": template.replace("{jobId}", canonical)}
        if operation == "compare":
            left = validate_job_id(vector.get("jobId"))
            right = validate_job_id(vector.get("otherJobId"))
            equal = left.encode("ascii") == right.encode("ascii")
            return ("pass" if equal else "fail"), {**metrics, "equal": equal}
        if operation == "profile-admit":
            admit_authenticated_profile(vector)
            return "pass", {**metrics, "profileAdmitted": True}
        raise ValueError("operation-validation")
    except ValueError as exc:
        return "error", {**metrics, "failureStage": str(exc)}


class JobIdGrammarVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.by_name = {vector["name"]: vector for vector in cls.data["vectors"]}

    def test_generated_file_is_current(self):
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_hash_count_and_names_are_exact(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(len(vectors), len(self.by_name))
        self.assertEqual(
            self.data["hash"], hashlib.sha256(canonical_bytes(vectors)).hexdigest()
        )

    def test_every_vector_executes_to_pinned_verdict_and_effects(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                verdict, observed = evaluate(vector)
                self.assertEqual(vector["expected"], verdict)
                for key, value in vector.get("want", {}).items():
                    self.assertEqual(value, observed.get(key), key)

    def test_bundle_known_answers_do_not_share_generator_state(self):
        job_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        for role, expected in KNOWN_ADDRESSES.items():
            with self.subTest(role=role):
                metrics = {"hashCalls": 0, "lookupCalls": 0}
                self.assertEqual(expected, derive_bundle(job_id, role, metrics))
                self.assertEqual({"hashCalls": 1, "lookupCalls": 0}, metrics)

    def test_shared_dacs5_helper_gates_current_derivation_and_marks_legacy(self):
        job_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        self.assertEqual(
            KNOWN_ADDRESSES["buyer"],
            DACS5_REFERENCE.logical_address(job_id, "buyer"),
        )
        for malformed in ("8" + job_id[1:], "cafe\u0301-job", "J"):
            with self.subTest(jobId=malformed):
                with self.assertRaisesRegex(ValueError, "job-id-validation"):
                    DACS5_REFERENCE.logical_address(malformed, "buyer")

        # Historical vector suites must name their frozen path explicitly; it
        # cannot be mistaken for current JID-1 authority.
        self.assertNotEqual(
            DACS5_REFERENCE.legacy_logical_address("café-job", "buyer"),
            DACS5_REFERENCE.legacy_logical_address("cafe\u0301-job", "buyer"),
        )

    def test_real_bb5_consumer_defaults_to_current_profile(self):
        legacy_job = "not-a-current-job"
        binding = {
            "bindingVersion": "1",
            "jobId": legacy_job,
            "role": "seller",
            "signer": "did:demos:agent:" + "22" * 32,
            "logicalAddress": DACS5_REFERENCE.legacy_logical_address(
                legacy_job, "seller"
            ),
            "nativeAddress": "stor-native-legacy",
            "bundleContentHash": "aa" * 32,
            "signature": {
                "signer": "did:demos:agent:" + "22" * 32,
                "algorithm": "ed25519",
                "value": "fixture-only",
            },
        }
        current = DACS5_REFERENCE.verify_binding(
            binding,
            None,
            expected_jobid=legacy_job,
            expected_role="seller",
        )
        self.assertFalse(current["ok"])
        self.assertIn("job-id-validation", current["reason"])

        archival = DACS5_REFERENCE.verify_legacy_binding(
            binding,
            None,
            expected_jobid=legacy_job,
            expected_role="seller",
        )
        self.assertTrue(archival["ok"])

        resolver_calls = []

        def permissive_resolver(job_id, role):
            resolver_calls.append((job_id, role))
            return "attacker-selected-address"

        address_ok, address_reason = DACS5_REFERENCE._post_fetch_address_valid(
            {"jobId": legacy_job},
            "attacker-selected-address",
            "seller",
            "aa" * 32,
            None,
            expected_jobid=legacy_job,
            pure_mapping_resolver=permissive_resolver,
        )
        self.assertFalse(address_ok)
        self.assertIn("job-id-validation", address_reason)
        self.assertEqual([], resolver_calls)

    def test_invalid_spelling_never_reaches_hash_or_lookup(self):
        invalid = [
            vector
            for vector in self.data["vectors"]
            if vector["expected"] == "error"
            and vector["operation"] in {"lookup-bundle", "compare"}
        ]
        self.assertGreaterEqual(len(invalid), 18)
        for vector in invalid:
            with self.subTest(vector=vector["name"]):
                verdict, observed = evaluate(vector)
                self.assertEqual("error", verdict)
                self.assertEqual("job-id-validation", observed["failureStage"])
                self.assertEqual(0, observed["hashCalls"])
                self.assertEqual(0, observed["lookupCalls"])

    def test_case_alias_and_unicode_normalization_are_not_canonicalizers(self):
        canonical = self.by_name["canonical-ulid"]["jobId"]
        lowercase = self.by_name["lowercase-is-not-canonical"]["jobId"]
        self.assertEqual(canonical, lowercase.upper())
        self.assertIsNone(JOB_ID_RE.fullmatch(lowercase))

        for name in (
            "crockford-i-alias-rejected",
            "crockford-l-alias-rejected",
            "crockford-o-alias-rejected",
            "crockford-u-character-rejected",
        ):
            self.assertIsNone(JOB_ID_RE.fullmatch(self.by_name[name]["jobId"]), name)

        composed = self.by_name["precomposed-unicode-rejected"]["jobId"]
        decomposed = self.by_name["decomposed-unicode-rejected"]["jobId"]
        self.assertEqual(composed, unicodedata.normalize("NFC", decomposed))
        self.assertIsNone(JOB_ID_RE.fullmatch(composed))
        self.assertIsNone(JOB_ID_RE.fullmatch(decomposed))

    def test_first_character_bound_prevents_130_bit_overflow(self):
        self.assertIsNotNone(JOB_ID_RE.fullmatch("7" + "Z" * 25))
        self.assertIsNone(JOB_ID_RE.fullmatch("8" + "0" * 25))
        self.assertIsNone(JOB_ID_RE.fullmatch("9" + "0" * 25))

    def test_corrective_profile_gate_precedes_all_job_specific_effects(self):
        cases = [
            vector for vector in self.data["vectors"]
            if vector["operation"] == "profile-admit"
        ]
        self.assertEqual(12, len(cases))
        for case in cases:
            with self.subTest(case=case["name"]):
                verdict, observed = evaluate(case)
                self.assertEqual(case["expected"], verdict)
                self.assertEqual(0, observed["hashCalls"])
                self.assertEqual(0, observed["lookupCalls"])

    def test_matching_caller_profiles_never_establish_admission(self):
        for name in (
            "caller-supplied-empty-profiles-refuse",
            "caller-supplied-partial-profiles-refuse",
            "caller-supplied-unsupported-profiles-refuse",
        ):
            with self.subTest(vector=name):
                verdict, observed = evaluate(self.by_name[name])
                self.assertEqual("error", verdict)
                self.assertEqual("profile-admission", observed["failureStage"])
                self.assertEqual(0, observed["hashCalls"])
                self.assertEqual(0, observed["lookupCalls"])

    def test_corrective_tuple_matches_every_module_header_and_profile_row(self):
        profile = PROFILE.read_text(encoding="utf-8")
        self.assertEqual(
            AUTHORITATIVE_MODULE_VERSIONS,
            self.data["syntheticProfileAdmissionFixture"]["moduleVersions"],
        )
        for module, (path, header_label, profile_label) in MODULE_SPECS.items():
            with self.subTest(module=module):
                expected = AUTHORITATIVE_MODULE_VERSIONS[module]
                document = path.read_text(encoding="utf-8")
                self.assertRegex(
                    document,
                    rf"\*\*{re.escape(header_label)} v{re.escape(expected)}\*\*",
                )
                self.assertIn(
                    f"| [{profile_label}]({path.name}) | {expected} |",
                    profile,
                )

    def test_legacy_address_suites_name_their_frozen_helper(self):
        for path in LEGACY_ADDRESS_SUITES:
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertIn("def legacy_logical_address(", source)
                self.assertNotIn("def logical_address(", source)

    def test_normative_and_ci_surfaces_are_linked(self):
        core = CORE.read_text(encoding="utf-8")
        dacs5 = DACS5.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        self.assertIn("JID-1", core)
        self.assertIn("JID-4", core)
        self.assertIn("[0-7][0-9A-HJKMNP-TV-Z]{25}", core)
        self.assertIn("jobId        = first-crockford 25crockford", core)
        self.assertNotIn("first-crockford 25*crockford", core)
        self.assertIn("ASCII(jobId)", dacs5)
        self.assertIn("generate_job_id_grammar_vectors.py --check", workflow)
        self.assertIn("job-id-grammar-v0.1.json", readme)


if __name__ == "__main__":
    unittest.main()
