"""CORE §11.1.2 admission at the real current DACS-5 consumer boundaries."""

import copy
import base64
import hashlib
import json
import re
import unittest
from pathlib import Path
from unittest import mock

import dacs5_reference as R
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
OTHER_JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
BUYER = "did:demos:buyer"
SELLER = "did:demos:seller"
ROOT = Path(__file__).resolve().parents[1]
BUYER_PRIVATE = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
SELLER_PRIVATE = Ed25519PrivateKey.from_private_bytes(b"\x22" * 32)


def public_bytes(private):
    return private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


TRUSTED_KEYS = R.trusted_verification_keys({
    BUYER: public_bytes(BUYER_PRIVATE),
    SELLER: public_bytes(SELLER_PRIVATE),
})


def expected_address(job_id, role):
    preimage = job_id.encode("ascii") + b"-bundle-" + role.encode("ascii")
    return "stor-" + hashlib.sha256(preimage).hexdigest()


def role_authority(role, identity, *, session_id=JOB_ID, profile=None,
                   authenticated=True):
    return R.trusted_role_authority(
        session_id,
        role,
        identity,
        profile=profile,
        authenticated=authenticated,
    )


def signature_value(private, domain, content_hash):
    return base64.urlsafe_b64encode(
        private.sign((domain + content_hash).encode("utf-8"))
    ).rstrip(b"=").decode("ascii")


def binding(role, signer, private, content_hash):
    address = expected_address(JOB_ID, role)
    result = {
        "bindingVersion": "1",
        "jobId": JOB_ID,
        "role": role,
        "signer": signer,
        "logicalAddress": address,
        "nativeAddress": address,
        "bundleContentHash": content_hash,
    }
    result["signature"] = {
        "signer": signer,
        "algorithm": "ed25519",
        "value": signature_value(private, R.BINDING_DOMAIN, R.binding_hash(result)),
    }
    return result


def current_receipt_fixture():
    base = {
        "faultBundleVersion": "1",
        "jobId": JOB_ID,
        "outcome": "completed",
        "faultedParty": "none",
        "parties": [
            {"role": "buyer", "primaryClaim": BUYER},
            {"role": "seller", "primaryClaim": SELLER},
        ],
        "phaseSummary": [],
        "finalisedAt": 100,
        "signatures": [],
    }
    content_hash = R.bundle_hash(base)
    base["signatures"] = [
        {
            "party": BUYER,
            "algorithm": "ed25519",
            "value": signature_value(
                BUYER_PRIVATE, R.FAULT_BUNDLE_DOMAIN, content_hash
            ),
        },
        {
            "party": SELLER,
            "algorithm": "ed25519",
            "value": signature_value(
                SELLER_PRIVATE, R.FAULT_BUNDLE_DOMAIN, content_hash
            ),
        },
    ]
    seller_bundle = {**base, "anchoredByRole": "seller"}
    buyer_bundle = {**base, "anchoredByRole": "buyer"}
    seller_binding = binding("seller", SELLER, SELLER_PRIVATE, content_hash)
    buyer_binding = binding("buyer", BUYER, BUYER_PRIVATE, content_hash)
    tagged = [{
        "bundle": seller_bundle,
        "resolvedRole": "seller",
        "counterpartyDisposition": "present",
        "counterpartyRef": {"contentHash": content_hash},
        "counterpartyRoleEvidence": {
            "kind": "binding",
            "binding": buyer_binding,
        },
        "roleEvidence": {"kind": "binding", "binding": seller_binding},
        "bb6Context": {
            "candidateBindings": [seller_binding],
            "partyMap": {SELLER: "seller"},
            "budget": 8,
        },
    }]
    receipt = R.derive(SELLER, tagged, 0, 200, "finalisedAt")
    address_tagged = [{
        "bundle": seller_bundle,
        "resolvedRole": "seller",
        "counterpartyDisposition": "present",
        "counterpartyRef": {"contentHash": content_hash},
        "counterpartyRoleEvidence": {
            "kind": "address",
            "resolvedAddress": buyer_binding["logicalAddress"],
        },
        "roleEvidence": {
            "kind": "address",
            "resolvedAddress": seller_binding["logicalAddress"],
        },
    }]
    address_receipt = R.derive(
        SELLER, address_tagged, 0, 200, "finalisedAt"
    )
    by_address = {
        seller_binding["nativeAddress"]: seller_bundle,
        buyer_binding["nativeAddress"]: buyer_bundle,
    }
    authority = R.trusted_current_context(
        [
            role_authority("seller", SELLER),
            role_authority("buyer", BUYER),
        ],
        query=R.trusted_query_authority(
            SELLER, 0, 200, "finalisedAt"
        ),
        entry_authorities=[R.trusted_entry_authority(
            content_hash,
            JOB_ID,
            "seller",
            SELLER,
            counterparty_disposition="present",
            counterparty_role="buyer",
            counterparty_participant_identity=BUYER,
            counterparty_content_hash=content_hash,
        )],
    )
    return {
        "receipt": receipt,
        "address_receipt": address_receipt,
        "binding": seller_binding,
        "deref": lambda requested_hash: (
            seller_bundle if requested_hash == content_hash else None
        ),
        "anchor_deref": lambda address: by_address.get(address),
        "authority": authority,
        "keys": TRUSTED_KEYS,
    }


def invalid_authorities():
    partial_profile = {
        "releasePin": R.AUTHORITATIVE_RELEASE_PIN,
        "moduleVersions": {
            key: value
            for key, value in R.AUTHORITATIVE_MODULE_VERSIONS.items()
            if key != "dacs5"
        },
    }
    wrong_release = {
        "releasePin": "f" * 40,
        "moduleVersions": R.AUTHORITATIVE_MODULE_VERSIONS,
    }
    wrong_modules = {
        "releasePin": R.AUTHORITATIVE_RELEASE_PIN,
        "moduleVersions": {
            **R.AUTHORITATIVE_MODULE_VERSIONS,
            "dacs5": "0.4",
        },
    }
    valid = current_receipt_fixture()["authority"]

    def with_roles(records):
        candidate = copy.deepcopy(valid)
        candidate["roleMap"] = records
        return candidate

    seller = role_authority("seller", SELLER)
    buyer = role_authority("buyer", BUYER)
    return {
        "missing": None,
        "partial-tuple": with_roles([
            role_authority("seller", SELLER, profile=partial_profile),
            role_authority("buyer", BUYER, profile=partial_profile),
        ]),
        "duplicate-role": with_roles([seller, dict(seller), buyer]),
        "release-mismatch": with_roles([
            role_authority("seller", SELLER, profile=wrong_release), buyer,
        ]),
        "module-mismatch": with_roles([
            role_authority("seller", SELLER, profile=wrong_modules), buyer,
        ]),
        "session-mismatch": with_roles([
            role_authority("seller", SELLER, session_id=OTHER_JOB_ID),
            role_authority("buyer", BUYER, session_id=OTHER_JOB_ID),
        ]),
        "malformed-session": with_roles([
            role_authority("seller", SELLER, session_id="not-a-current-job-id"),
            buyer,
        ]),
        "role-missing": with_roles([buyer]),
        "malformed-unrelated-record": with_roles([
            seller, buyer, {"sessionId": JOB_ID, "role": "orchestrator"},
        ]),
        "untrusted": with_roles([
            role_authority("seller", SELLER, authenticated=False), buyer,
        ]),
    }


class CurrentProfileConsumerAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = current_receipt_fixture()
        self.authority = self.fixture["authority"]
        self.keys = self.fixture["keys"]

    def test_current_context_requires_scalar_roles_and_finite_query_numbers(self):
        self.assertTrue(R._current_context_shape_valid(self.authority))
        for value in ([], {}, None, True):
            changed = copy.deepcopy(self.authority)
            changed["roleMap"][0]["role"] = value
            with self.subTest(role=value):
                self.assertFalse(R._current_context_shape_valid(changed))
                self.assertIsNone(R.resolve_current_profile(JOB_ID, value, self.authority))
        for value in (True, float("inf"), float("nan"), 2**53):
            changed = copy.deepcopy(self.authority)
            changed["query"]["windowEnd"] = value
            with self.subTest(window=value):
                self.assertFalse(R._current_context_shape_valid(changed))

    def test_current_address_bb5_context_and_replay_positive_controls(self):
        self.assertEqual(
            expected_address(JOB_ID, "seller"),
            R.logical_address(
                JOB_ID,
                "seller",
                participant_identity="caller-value-is-not-authority",
                trusted_contexts=self.authority,
            ),
        )
        verified = R.verify_binding(
            self.fixture["binding"],
            self.keys,
            expected_jobid=JOB_ID,
            expected_role="seller",
            participant_identity=BUYER,
            trusted_contexts=self.authority,
        )
        self.assertTrue(verified["ok"], verified["reason"])
        valid, reasons = R.validate_resolution_context(
            self.fixture["receipt"],
            self.fixture["deref"],
            pubkeys=self.keys,
            anchor_deref=self.fixture["anchor_deref"],
            trusted_contexts=self.authority,
            query_party=SELLER,
            window_start=0,
            window_end=200,
            windowing_basis="finalisedAt",
        )
        self.assertTrue(valid, reasons)
        same, replayed = R.replay_receipt(
            self.fixture["receipt"],
            self.fixture["deref"],
            SELLER,
            0,
            200,
            pubkeys=self.keys,
            anchor_deref=self.fixture["anchor_deref"],
            trusted_contexts=self.authority,
            windowing_basis="finalisedAt",
        )
        self.assertTrue(same)
        self.assertIsNotNone(replayed)

    def test_current_context_address_arm_profiles_before_mapping(self):
        mapping_calls = []

        def map_address(job_id, role):
            mapping_calls.append((job_id, role))
            return expected_address(job_id, role)

        valid, reasons = R.validate_resolution_context(
            self.fixture["address_receipt"],
            self.fixture["deref"],
            pubkeys=self.keys,
            anchor_deref=self.fixture["anchor_deref"],
            pure_mapping_resolver=map_address,
            query_party=SELLER,
            window_start=0,
            window_end=200,
            windowing_basis="finalisedAt",
        )
        self.assertFalse(valid)
        self.assertTrue(any("current-profile-admission" in r for r in reasons))
        self.assertEqual(mapping_calls, [])

        valid, reasons = R.validate_resolution_context(
            self.fixture["address_receipt"],
            self.fixture["deref"],
            pubkeys=self.keys,
            anchor_deref=self.fixture["anchor_deref"],
            pure_mapping_resolver=map_address,
            trusted_contexts=self.authority,
            query_party=SELLER,
            window_start=0,
            window_end=200,
            windowing_basis="finalisedAt",
        )
        self.assertTrue(valid, reasons)
        self.assertEqual(
            mapping_calls,
            [(JOB_ID, "seller"), (JOB_ID, "buyer")],
        )

    def test_every_current_consumer_refuses_bad_authority_before_address_derivation(self):
        for authority_name, authority in invalid_authorities().items():
            with self.subTest(authority=authority_name), mock.patch.object(
                R, "_current_logical_address", wraps=R._current_logical_address
            ) as derive_address:
                with self.assertRaisesRegex(ValueError, "current-profile-admission"):
                    R.logical_address(
                        JOB_ID,
                        "seller",
                        participant_identity=SELLER,
                        trusted_contexts=authority,
                    )
                verified = R.verify_binding(
                    self.fixture["binding"],
                    self.keys,
                    expected_jobid=JOB_ID,
                    expected_role="seller",
                    participant_identity=SELLER,
                    trusted_contexts=authority,
                )
                self.assertFalse(verified["ok"])
                self.assertEqual(verified["reason"], "current-profile-admission")
                valid, reasons = R.validate_resolution_context(
                    self.fixture["receipt"],
                    self.fixture["deref"],
                    pubkeys=self.keys,
                    anchor_deref=self.fixture["anchor_deref"],
                    trusted_contexts=authority,
                    query_party=SELLER,
                    window_start=0,
                    window_end=200,
                    windowing_basis="finalisedAt",
                )
                self.assertFalse(valid)
                self.assertTrue(any("current-" in r for r in reasons), reasons)
                self.assertEqual(
                    R.replay_receipt(
                        self.fixture["receipt"],
                        self.fixture["deref"],
                        SELLER,
                        0,
                        200,
                        pubkeys=self.keys,
                        anchor_deref=self.fixture["anchor_deref"],
                        trusted_contexts=authority,
                        windowing_basis="finalisedAt",
                    ),
                    (False, None),
                )
                derive_address.assert_not_called()

    def test_pre_correction_canonical_ulid_and_copied_profile_never_promote(self):
        artifact = copy.deepcopy(self.fixture["binding"])
        artifact["peerProfile"] = R.AUTHORITATIVE_LOCAL_PROFILE
        artifact["peerProfileRef"] = "fixture:current-profile"
        current = R.verify_binding(
            artifact,
            self.keys,
            expected_jobid=JOB_ID,
            expected_role="seller",
            participant_identity=SELLER,
        )
        self.assertFalse(current["ok"])
        self.assertEqual(current["reason"], "current-profile-admission")
        self.assertTrue(R.verify_legacy_binding(
            artifact,
            None,
            expected_jobid=JOB_ID,
            expected_role="seller",
        )["ok"])

        receipt = copy.deepcopy(self.fixture["receipt"])
        receipt["peerProfile"] = R.AUTHORITATIVE_LOCAL_PROFILE
        receipt["peerProfileRef"] = "fixture:current-profile"
        self.assertEqual(
            R.replay_receipt(
                receipt,
                self.fixture["deref"],
                SELLER,
                0,
                200,
                pubkeys=self.keys,
                anchor_deref=self.fixture["anchor_deref"],
                windowing_basis="finalisedAt",
            ),
            (False, None),
        )
        self.assertTrue(R.replay_legacy_receipt(
            receipt,
            self.fixture["deref"],
            SELLER,
            0,
            200,
            anchor_deref=self.fixture["anchor_deref"],
        )[0])

    def test_current_crypto_and_query_admission_precede_callbacks(self):
        callbacks = {
            "deref": mock.Mock(side_effect=self.fixture["deref"]),
            "anchor": mock.Mock(side_effect=self.fixture["anchor_deref"]),
            "mapping": mock.Mock(side_effect=expected_address),
        }
        for keys, authority, party, window_end, basis in (
            (None, self.authority, SELLER, 200, "finalisedAt"),
            (R.trusted_verification_keys({}, authenticated=False), self.authority,
             SELLER, 200, "finalisedAt"),
            (self.keys, self.authority, BUYER, 200, "finalisedAt"),
            (self.keys, self.authority, SELLER, 201, "finalisedAt"),
            (self.keys, self.authority, SELLER, 200, "sr2-anchor-timestamp"),
        ):
            with self.subTest(keys=keys is not None, party=party,
                              windowEnd=window_end, basis=basis):
                valid, _ = R.validate_resolution_context(
                    self.fixture["receipt"],
                    callbacks["deref"],
                    pubkeys=keys,
                    anchor_deref=callbacks["anchor"],
                    pure_mapping_resolver=callbacks["mapping"],
                    trusted_contexts=authority,
                    query_party=party,
                    window_start=0,
                    window_end=window_end,
                    windowing_basis=basis,
                )
                self.assertFalse(valid)
                for callback in callbacks.values():
                    callback.assert_not_called()

    def test_entry_authority_is_ordered_and_precedes_dereference(self):
        bad = copy.deepcopy(self.authority)
        bad["entryAuthorities"][0]["participantIdentity"] = BUYER
        anchor = mock.Mock(side_effect=self.fixture["anchor_deref"])
        valid, reasons = R.validate_resolution_context(
            self.fixture["receipt"],
            self.fixture["deref"],
            pubkeys=self.keys,
            anchor_deref=anchor,
            trusted_contexts=bad,
            query_party=SELLER,
            window_start=0,
            window_end=200,
            windowing_basis="finalisedAt",
        )
        self.assertFalse(valid)
        self.assertTrue(any("entry-authority" in reason for reason in reasons))
        anchor.assert_not_called()

    def test_legitimate_empty_query_admits_without_entry_callbacks(self):
        receipt = R.derive(SELLER, [], 0, 200, "finalisedAt")
        authority = R.trusted_current_context(
            [],
            query=R.trusted_query_authority(SELLER, 0, 200, "finalisedAt"),
        )
        keys = TRUSTED_KEYS
        anchor = mock.Mock(side_effect=AssertionError("empty result dereferenced"))
        self.assertEqual(
            R.validate_resolution_context(
                receipt,
                lambda _h: None,
                pubkeys=keys,
                anchor_deref=anchor,
                trusted_contexts=authority,
                query_party=SELLER,
                window_start=0,
                window_end=200,
                windowing_basis="finalisedAt",
            ),
            (True, []),
        )
        same, replayed = R.replay_receipt(
            receipt,
            lambda _h: None,
            SELLER,
            0,
            200,
            pubkeys=keys,
            anchor_deref=anchor,
            trusted_contexts=authority,
            windowing_basis="finalisedAt",
        )
        self.assertTrue(same)
        self.assertEqual(replayed["bundleCount"], 0)
        anchor.assert_not_called()

    def test_real_ed25519_signatures_and_role_authority_are_load_bearing(self):
        mutated = copy.deepcopy(self.fixture["binding"])
        mutated["signature"]["value"] = (
            "A" + mutated["signature"]["value"][1:]
        )
        result = R.verify_binding(
            mutated,
            self.keys,
            expected_jobid=JOB_ID,
            expected_role="seller",
            trusted_contexts=self.authority,
        )
        self.assertFalse(result["ok"])
        self.assertIn("signature does not verify", result["reason"])

        different_holder = copy.deepcopy(self.authority)
        different_holder["roleMap"][0]["participantIdentity"] = BUYER
        result = R.verify_binding(
            self.fixture["binding"],
            self.keys,
            expected_jobid=JOB_ID,
            expected_role="seller",
            trusted_contexts=different_holder,
        )
        self.assertFalse(result["ok"])
        self.assertIn("authenticated participant", result["reason"])

    def test_one_actor_may_hold_two_independently_authorized_roles(self):
        authority = R.trusted_current_context([
            role_authority("buyer", BUYER),
            role_authority("seller", BUYER),
        ])
        self.assertTrue(R.admits_current_profile(JOB_ID, "buyer", authority))
        self.assertTrue(R.admits_current_profile(JOB_ID, "seller", authority))

    def test_normative_current_and_legacy_boundaries_are_explicit(self):
        spec = (ROOT / "spec/DACS-5-VERIFY.md").read_text(encoding="utf-8")
        self.assertIn("current-profile consumer resolves", spec)
        self.assertIn("verifier- or orchestrator-owned trusted context", spec)
        self.assertIn("(jobId, role) → participant", spec)
        self.assertIn("independently authenticated verification-key", spec)
        self.assertIn("even when `bundleRefs` and `resolutionContext` are legitimately empty", spec)
        self.assertIn("explicitly selected archival/legacy replay path", spec)
        self.assertIn("explicitly selected legacy replay", spec)

    def test_core_profile_and_admission_tuple_are_identical(self):
        """CORE §11.1.2, PROFILE.md, CHANGELOG, and executable constants
        pin one identical corrective-profile tuple (PR #367 review row 2).

        The full six-stage tuple — CORE plus DACS-1 through DACS-5 — is
        parsed independently from each CORE §11.1.2 boundary sentence and
        again from the PROFILE.md candidate tables and the channel-wire
        CHANGELOG declaration, so a drift in any single stage fails; it is never
        sufficient for CORE to restate only its own version."""
        core_text = (ROOT / "spec/CORE.md").read_text(encoding="utf-8")
        profile_text = (ROOT / "spec/PROFILE.md").read_text(encoding="utf-8")
        changelog_text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        stage_keys = ("core", "dacs1", "dacs2", "dacs3", "dacs4", "dacs5")

        # Independent parse 1: the complete candidate tuple as declared by
        # every CORE §11.1.2 boundary sentence (jobId and channel wire).
        # Each match alternates major/minor captures; preserve both parts so
        # a major-version drift cannot be hidden by an unchanged minor.
        core_sentences = re.findall(
            r"CORE v(\d+)\.(\d+) together with DACS-1 v(\d+)\.(\d+), "
            r"DACS-2 v(\d+)\.(\d+), DACS-3 v(\d+)\.(\d+), "
            r"DACS-4 v(\d+)\.(\d+), and DACS-5 v(\d+)\.(\d+) declares",
            core_text,
        )
        self.assertTrue(
            core_sentences, "CORE §11.1.2 declares no candidate tuple"
        )
        core_tuples = {
            tuple(
                ".".join(sentence[index:index + 2])
                for index in range(0, len(sentence), 2)
            )
            for sentence in core_sentences
        }
        self.assertEqual(
            1,
            len(core_tuples),
            "CORE §11.1.2 boundary sentences declare different tuples",
        )
        core_tuple = dict(zip(stage_keys, core_tuples.pop()))

        # Independent parse 2: the same complete tuple from the PROFILE.md
        # candidate section tables (the last table row of each module — the
        # corrective candidate section appears after the v0.1 and v0.4
        # tables).
        module_patterns = [
            (r"\[CORE\]\(CORE\.md\) \| (\d+)\.(\d+) \|", "core"),
            (r"\[DACS-1-IDENTIFY\]\(DACS-1-IDENTIFY\.md\) \| (\d+)\.(\d+) \|", "dacs1"),
            (r"\[DACS-2-VET\]\(DACS-2-VET\.md\) \| (\d+)\.(\d+) \|", "dacs2"),
            (r"\[DACS-3-NEGOTIATE\]\(DACS-3-NEGOTIATE\.md\) \| (\d+)\.(\d+) \|", "dacs3"),
            (r"\[DACS-4-SETTLE\]\(DACS-4-SETTLE\.md\) \| (\d+)\.(\d+) \|", "dacs4"),
            (r"\[DACS-5-VERIFY\]\(DACS-5-VERIFY\.md\) \| (\d+)\.(\d+) \|", "dacs5"),
        ]
        profile_tuple = {}
        for pattern, key in module_patterns:
            matches = re.findall(pattern, profile_text)
            self.assertTrue(matches, pattern)
            profile_tuple[key] = ".".join(matches[-1])
        self.assertEqual(
            set(profile_tuple),
            set(stage_keys),
            "PROFILE.md candidate tables do not cover the complete module set",
        )

        # The two independent parses must be the same tuple, stage by stage.
        self.assertEqual(
            core_tuple,
            profile_tuple,
            "CORE §11.1.2 and PROFILE.md declare different corrective tuples",
        )

        dacs3_text = (ROOT / "spec/DACS-3-NEGOTIATE.md").read_text(encoding="utf-8")
        dacs3_header = re.search(
            r"this candidate is bound to the exact coordinated profile tuple "
            r"in `PROFILE\.md` \((CORE v[^)]*)\)",
            dacs3_text,
        )
        self.assertIsNotNone(dacs3_header, "DACS-3 declares no current tuple")
        expected_header = "CORE v{core}, DACS-1 v{dacs1}, DACS-2 v{dacs2}, " \
            "DACS-3 v{dacs3}, DACS-4 v{dacs4}, DACS-5 v{dacs5}"
        self.assertEqual(expected_header.format(**core_tuple), dacs3_header.group(1))

        laa_vectors = json.loads(
            (ROOT / "conformance/vectors/security/legacy-agreement-admission-v0.8.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(
            core_tuple,
            laa_vectors["profile"]["moduleVersions"],
            "LAA candidate metadata diverges from the corrective tuple",
        )

        # Independent parse 3: the channel-wire corrective declaration in the
        # CHANGELOG is a required CORE §11.1.2 version inventory, not prose that
        # may retain a superseded composed tuple after integration.
        changelog_match = re.search(
            r"tuple recorded in `PROFILE\.md` \(CORE v(\d+)\.(\d+), "
            r"DACS-1 v(\d+)\.(\d+), DACS-2 v(\d+)\.(\d+), DACS-3\s+"
            r"v(\d+)\.(\d+), DACS-4 v(\d+)\.(\d+), DACS-5 v(\d+)\.(\d+)\)",
            changelog_text,
        )
        self.assertIsNotNone(
            changelog_match,
            "CHANGELOG channel-wire correction declares no complete tuple",
        )
        changelog_values = changelog_match.groups()
        changelog_tuple = dict(
            zip(
                stage_keys,
                (
                    ".".join(changelog_values[index:index + 2])
                    for index in range(0, len(changelog_values), 2)
                ),
            )
        )
        self.assertEqual(
            core_tuple,
            changelog_tuple,
            "CHANGELOG channel-wire tuple differs from CORE/PROFILE",
        )
        self.assertEqual(
            core_tuple,
            {
                "core": "0.3",
                "dacs1": "0.8",
                "dacs2": "0.6",
                "dacs3": "0.6",
                "dacs4": "0.8",
                "dacs5": "0.7",
            },
            "the authoritative tuple drifted",
        )

        # Every executable admission constant set must be this exact tuple.
        import importlib.util

        def load_module(name, path):
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module

        ap2 = load_module(
            "ap2_admission_constants", ROOT / "tests/test_ap2_handler_safety_vectors.py"
        )
        jid = load_module(
            "jid_admission_constants", ROOT / "tests/test_job_id_grammar_vectors.py"
        )
        for label, module_versions in (
            ("dacs5_reference", R.AUTHORITATIVE_MODULE_VERSIONS),
            ("test_ap2_handler_safety_vectors", ap2.AUTHORITATIVE_MODULE_VERSIONS),
            ("test_job_id_grammar_vectors", jid.AUTHORITATIVE_MODULE_VERSIONS),
        ):
            self.assertEqual(
                module_versions,
                core_tuple,
                f"{label} admission constants diverge from the authoritative tuple",
            )
            self.assertEqual(
                set(module_versions),
                set(core_tuple),
                f"{label} admission tuple is not the complete closed module set",
            )

        # The generated AP2 vectors must carry the same current tuple bytes.
        ap2_vectors = json.loads(
            (ROOT / "conformance/vectors/security/ap2-handler-safety-v0.6.json")
            .read_text(encoding="utf-8")
        )
        serialized = json.dumps(ap2_vectors)
        self.assertNotIn('"dacs3": "0.5"', serialized)
        self.assertNotIn('"dacs4": "0.7"', serialized)


if __name__ == "__main__":
    unittest.main()
