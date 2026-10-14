import base64
import hashlib
import json
import re
import subprocess
import sys
import unicodedata
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


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
    ROOT / "scripts/generate_dacs5_reputation_vectors.py",
    ROOT / "tests/test_bundle_binding_vectors.py",
    ROOT / "tests/test_round9_ordering_contract_vectors.py",
    ROOT / "tests/test_round10_validation_predicate_vectors.py",
    ROOT / "tests/test_round11_receipt_ingress_vectors.py",
)

JOB_ID_RE = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}\Z", re.ASCII)
ROLES = {"buyer", "seller", "orchestrator"}
KNOWN_ADDRESSES = {
    "buyer": "stor-180e77cf120910a90212df45f4ed0c7dce8b7ee57c8d66d7f402a7b5e3fe307b",
    "seller": "stor-831775f318b0d4aac57d082789fa5efd8f74583d2dfc0e267bcbe4c284224840",
    "orchestrator": "stor-4cadaaae064cc2257f3e101842e4ae24fd4a481fdb7dea35082f30e7ad2311d0",
}
AUTHORITATIVE_RELEASE_PIN = DACS5_REFERENCE.AUTHORITATIVE_RELEASE_PIN
AUTHORITATIVE_MODULE_VERSIONS = DACS5_REFERENCE.AUTHORITATIVE_MODULE_VERSIONS
AUTHORITATIVE_LOCAL_PROFILE = DACS5_REFERENCE.AUTHORITATIVE_LOCAL_PROFILE
CURRENT_SESSION_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
CURRENT_PEER_IDENTITIES = {
    "buyer": "did:demos:agent:" + "22" * 32,
    "seller": "did:demos:agent:" + "33" * 32,
    "orchestrator": "did:demos:agent:" + "44" * 32,
}
CURRENT_PEER_IDENTITY = CURRENT_PEER_IDENTITIES["buyer"]
CURRENT_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(b"\x23" * 32)
CURRENT_PUBLIC_KEY = CURRENT_PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)
CURRENT_KEY_AUTHORITY = DACS5_REFERENCE.trusted_verification_keys({
    CURRENT_PEER_IDENTITY: CURRENT_PUBLIC_KEY,
})


def trusted_profile_context(
    *,
    session_id=CURRENT_SESSION_ID,
    expected_peer_identity=CURRENT_PEER_IDENTITY,
    participant_identity=None,
    profile=AUTHORITATIVE_LOCAL_PROFILE,
    authenticated=True,
    duplicate=False,
    role="buyer",
):
    return DACS5_REFERENCE.trusted_profile_context(
        session_id,
        expected_peer_identity,
        participant_identity=participant_identity,
        profile=profile,
        authenticated=authenticated,
        duplicate=duplicate,
        role=role,
    )


TRUSTED_PROFILE_CONTEXTS = {
    "buyer-bundle-known-answer": trusted_profile_context(
        expected_peer_identity=CURRENT_PEER_IDENTITIES["buyer"], role="buyer"
    ),
    "seller-bundle-known-answer": trusted_profile_context(
        expected_peer_identity=CURRENT_PEER_IDENTITIES["seller"], role="seller"
    ),
    "orchestrator-bundle-known-answer": trusted_profile_context(
        expected_peer_identity=CURRENT_PEER_IDENTITIES["orchestrator"],
        role="orchestrator",
    ),
    "lookup-after-validation": trusted_profile_context(
        expected_peer_identity=CURRENT_PEER_IDENTITIES["buyer"], role="buyer"
    ),
    "authenticated-corrective-profile-admitted": trusted_profile_context(),
    "unauthenticated-peer-profile-refuses": trusted_profile_context(
        authenticated=False
    ),
    "authenticated-different-release-pin-refuses": trusted_profile_context(
        profile={
            "releasePin": "f" * 40,
            "moduleVersions": AUTHORITATIVE_MODULE_VERSIONS,
        }
    ),
    "authenticated-partial-module-tuple-refuses": trusted_profile_context(
        profile={
            "releasePin": AUTHORITATIVE_RELEASE_PIN,
            "moduleVersions": {
                key: value
                for key, value in AUTHORITATIVE_MODULE_VERSIONS.items()
                if key != "dacs5"
            },
        }
    ),
    "authenticated-extra-module-tuple-refuses": trusted_profile_context(
        profile={
            "releasePin": AUTHORITATIVE_RELEASE_PIN,
            "moduleVersions": {**AUTHORITATIVE_MODULE_VERSIONS, "future": "0.1"},
        }
    ),
    "authenticated-non-string-release-pin-refuses": trusted_profile_context(
        profile={
            "releasePin": 1,
            "moduleVersions": AUTHORITATIVE_MODULE_VERSIONS,
        }
    ),
    "authenticated-major-only-discriminator-refuses": trusted_profile_context(
        profile={"dacsVersion": "1"}
    ),
    "duplicate-authenticated-peer-profile-refuses": trusted_profile_context(
        duplicate=True
    ),
    "authenticated-peer-identity-mismatch-refuses": trusted_profile_context(
        participant_identity="did:demos:agent:" + "33" * 32
    ),
    "authenticated-session-mismatch-refuses": trusted_profile_context(
        session_id="01ARZ3NDEKTSV4RRFFQ69G5FAW"
    ),
}


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def validate_job_id(value):
    """Pure JID-1 grammar check; this alone never authorizes an action."""
    if not isinstance(value, str) or JOB_ID_RE.fullmatch(value) is None:
        raise ValueError("job-id-validation")
    return value


def _derive_admitted_bundle(validated_job_id, role, metrics):
    """Private address primitive reached only after current profile admission."""
    if role not in ROLES:
        raise ValueError("role-validation")
    metrics["hashCalls"] += 1
    preimage = validated_job_id.encode("ascii") + b"-bundle-" + role.encode("ascii")
    return "stor-" + hashlib.sha256(preimage).hexdigest()


def is_exact_corrective_profile(profile):
    return DACS5_REFERENCE.is_exact_corrective_profile(profile)


def admit_authenticated_profile(
    vector, trusted_context, *, requested_role="buyer", validated_job_id=None
):
    # Profile objects and reference labels inside protocol input are attacker-
    # controlled, even if their bytes copy trusted configuration exactly.
    if any(
        field in vector for field in ("localProfile", "peerProfile", "peerProfileRef")
    ):
        raise ValueError("profile-admission")
    session_id = vector.get("sessionId")
    peer_identity = vector.get("peerIdentity")
    if (
        not isinstance(session_id, str)
        or not isinstance(peer_identity, str)
        or requested_role not in ROLES
        or (validated_job_id is not None and session_id != validated_job_id)
    ):
        raise ValueError("profile-admission")
    authoritative_participant = DACS5_REFERENCE.resolve_current_profile(
        session_id, requested_role, trusted_context
    )
    if authoritative_participant is None or authoritative_participant != peer_identity:
        raise ValueError("profile-admission")


def evaluate(vector, trusted_context=None):
    metrics = {"hashCalls": 0, "lookupCalls": 0}
    operation = vector.get("operation")
    try:
        if operation == "validate":
            canonical = validate_job_id(vector.get("jobId"))
            return "pass", {**metrics, "canonicalJobId": canonical}
        if operation == "derive-bundle":
            validated = validate_job_id(vector.get("jobId"))
            role = vector.get("role")
            admit_authenticated_profile(
                vector,
                trusted_context,
                requested_role=role,
                validated_job_id=validated,
            )
            address = _derive_admitted_bundle(validated, role, metrics)
            return "pass", {**metrics, "logicalAddress": address}
        if operation == "lookup-bundle":
            validated = validate_job_id(vector.get("jobId"))
            role = vector.get("role")
            admit_authenticated_profile(
                vector,
                trusted_context,
                requested_role=role,
                validated_job_id=validated,
            )
            address = _derive_admitted_bundle(validated, role, metrics)
            metrics["lookupCalls"] += 1
            return "pass", {**metrics, "logicalAddress": address}
        if operation == "derive-logical":
            # Grammar/template behavior is intentionally pure and non-authorizing.
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
            admit_authenticated_profile(vector, trusted_context)
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
                trusted_context = TRUSTED_PROFILE_CONTEXTS.get(vector["name"])
                verdict, observed = evaluate(vector, trusted_context)
                self.assertEqual(vector["expected"], verdict)
                for key, value in vector.get("want", {}).items():
                    self.assertEqual(value, observed.get(key), key)

    def test_bundle_known_answers_do_not_share_generator_state(self):
        names = {
            "buyer": "buyer-bundle-known-answer",
            "seller": "seller-bundle-known-answer",
            "orchestrator": "orchestrator-bundle-known-answer",
        }
        for role, expected in KNOWN_ADDRESSES.items():
            with self.subTest(role=role):
                name = names[role]
                verdict, observed = evaluate(
                    self.by_name[name], TRUSTED_PROFILE_CONTEXTS[name]
                )
                self.assertEqual("pass", verdict)
                self.assertEqual(expected, observed["logicalAddress"])
                self.assertEqual(1, observed["hashCalls"])
                self.assertEqual(0, observed["lookupCalls"])

    def test_current_bundle_operations_require_authenticated_role_profile(self):
        for name in (
            "buyer-bundle-known-answer",
            "seller-bundle-known-answer",
            "orchestrator-bundle-known-answer",
            "lookup-after-validation",
        ):
            with self.subTest(vector=name):
                verdict, observed = evaluate(self.by_name[name])
                self.assertEqual("error", verdict)
                self.assertEqual("profile-admission", observed["failureStage"])
                self.assertEqual(0, observed["hashCalls"])
                self.assertEqual(0, observed["lookupCalls"])

    def test_shared_dacs5_helper_gates_current_derivation_and_marks_legacy(self):
        job_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        authority = trusted_profile_context()
        self.assertEqual(
            KNOWN_ADDRESSES["buyer"],
            DACS5_REFERENCE.logical_address(
                job_id,
                "buyer",
                participant_identity=CURRENT_PEER_IDENTITY,
                trusted_contexts=authority,
            ),
        )
        for malformed in ("8" + job_id[1:], "cafe\u0301-job", "J"):
            with self.subTest(jobId=malformed):
                with self.assertRaisesRegex(ValueError, "job-id-validation"):
                    DACS5_REFERENCE.logical_address(
                        malformed,
                        "buyer",
                        participant_identity=CURRENT_PEER_IDENTITY,
                        trusted_contexts=trusted_profile_context(
                            session_id=malformed
                        ),
                    )

        # Historical vector suites must name their frozen path explicitly; it
        # cannot be mistaken for current JID-1 authority.
        self.assertNotEqual(
            DACS5_REFERENCE.legacy_logical_address("café-job", "buyer"),
            DACS5_REFERENCE.legacy_logical_address("cafe\u0301-job", "buyer"),
        )

    def test_real_bb5_consumer_defaults_to_current_profile(self):
        # This models a pre-correction artifact whose identifier happened already
        # to be a canonical ULID: identical address bytes do not promote it.
        legacy_job = CURRENT_SESSION_ID
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
        }
        binding["signature"] = {
            "signer": CURRENT_PEER_IDENTITY,
            "algorithm": "ed25519",
            "value": base64.urlsafe_b64encode(CURRENT_PRIVATE_KEY.sign(
                (
                    DACS5_REFERENCE.BINDING_DOMAIN
                    + DACS5_REFERENCE.binding_hash(binding)
                ).encode("utf-8")
            )).rstrip(b"=").decode("ascii"),
        }
        current = DACS5_REFERENCE.verify_binding(
            binding,
            None,
            expected_jobid=legacy_job,
            expected_role="seller",
        )
        self.assertFalse(current["ok"])
        self.assertIn("current-profile-admission", current["reason"])

        admitted = DACS5_REFERENCE.verify_binding(
            binding,
            CURRENT_KEY_AUTHORITY,
            expected_jobid=legacy_job,
            expected_role="seller",
            participant_identity=CURRENT_PEER_IDENTITY,
            trusted_contexts=trusted_profile_context(role="seller"),
        )
        self.assertTrue(admitted["ok"])

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

        fetched = {
            "faultBundleVersion": "1",
            "jobId": "not-a-current-job",
            "outcome": "aborted-by-self",
            "faultedParty": "seller",
            "anchoredByRole": "seller",
            "parties": [{
                "role": "seller",
                "primaryClaim": CURRENT_PEER_IDENTITY,
            }],
            "phaseSummary": [],
            "finalisedAt": 1,
            "signatures": [],
        }
        fetched_hash = DACS5_REFERENCE.bundle_hash(fetched)
        fetched["signatures"] = [{
            "party": CURRENT_PEER_IDENTITY,
            "algorithm": "ed25519",
            "value": base64.urlsafe_b64encode(CURRENT_PRIVATE_KEY.sign(
                (
                    DACS5_REFERENCE.FAULT_BUNDLE_DOMAIN + fetched_hash
                ).encode("utf-8")
            )).rstrip(b"=").decode("ascii"),
        }]
        address_ok, address_reason = DACS5_REFERENCE._post_fetch_address_valid(
            fetched,
            "attacker-selected-address",
            "seller",
            fetched_hash,
            CURRENT_KEY_AUTHORITY,
            expected_jobid="not-a-current-job",
            pure_mapping_resolver=permissive_resolver,
            trusted_contexts=trusted_profile_context(
                session_id="not-a-current-job", role="seller"
            ),
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
        self.assertEqual(16, len(cases))
        for case in cases:
            with self.subTest(case=case["name"]):
                trusted_context = TRUSTED_PROFILE_CONTEXTS.get(case["name"])
                verdict, observed = evaluate(case, trusted_context)
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

    def test_copied_blessed_reference_cannot_create_trusted_context(self):
        mutant = dict(self.by_name["caller-supplied-matching-profile-refuses"])
        mutant.pop("peerProfile")
        mutant["peerProfileRef"] = "fixture:peer-current"
        verdict, observed = evaluate(mutant)
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
        self.assertIn("verifier- or orchestrator-owned trusted context", core)
        self.assertIn("duplicate records for one expected participant", core)
        self.assertIn("opaque reference label has no authority", core)
        self.assertIn("ASCII(jobId)", dacs5)
        self.assertIn("generate_job_id_grammar_vectors.py --check", workflow)
        self.assertIn("job-id-grammar-v0.1.json", readme)


if __name__ == "__main__":
    unittest.main()
