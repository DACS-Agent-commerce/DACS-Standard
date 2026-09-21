"""Executable assertions for DACS-5 v0.4 SEB-1..SEB-6 candidate vectors."""

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path

import dacs5_reference as R
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance/vectors/security/bundle-settlement-evidence-bijection-v0.4.json"
SPEC = ROOT / "spec/DACS-5-VERIFY.md"
CORE = ROOT / "spec/CORE.md"


def canonical_json(value):
    return R.canonical(value)


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def resign_ebfab(bundle, seeds):
    bundle["signatures"] = []
    payload = (R.EVIDENCE_BOUND_FAULT_BUNDLE_DOMAIN + R.bundle_hash(bundle)).encode("utf-8")
    claims_by_role = {
        party["role"]: party["primaryClaim"] for party in bundle["parties"]
    }
    bundle["signatures"] = [
        {
            "party": claims_by_role[role],
            "algorithm": "ed25519",
            "value": encode(Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(seeds[role])).sign(payload)),
        }
        for role in claims_by_role
    ]


def resign_evidence(record, seed):
    record["signature"] = {
        "signer": record["signature"]["signer"],
        "algorithm": "ed25519",
        "value": "",
    }
    domain = (
        R.DELIVERY_EVIDENCE_DOMAIN
        if record.get("deliveryEvidenceVersion") == "1"
        else R.SETTLEMENT_EVIDENCE_DOMAIN
    )
    payload = (domain + R.settlement_evidence_hash(record)).encode("utf-8")
    record["signature"]["value"] = encode(
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).sign(payload)
    )


def resign_listing(listing, seed):
    listing["signature"] = {
        "signer": listing["sellerPrimaryClaim"],
        "algorithm": "ed25519",
        "value": "",
    }
    payload = (R.LISTING_DOMAIN + R.listing_hash(listing)).encode("utf-8")
    listing["signature"]["value"] = encode(
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).sign(payload)
    )


def resign_inner_artifact(artifact, seed, domain):
    signer = artifact["signature"]["signer"]
    artifact["signature"] = {
        "signer": signer,
        "algorithm": "ed25519",
        "value": "",
    }
    payload = (domain + R._signed_envelope_content_hash(artifact)).encode("utf-8")
    artifact["signature"]["value"] = encode(
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).sign(payload)
    )


def move_verified_receipt(authority, old_ref, new_ref):
    """Move current receipt authority with a legitimately replaced inner ref."""
    if old_ref == new_ref:
        return
    receipts = authority["verifiedReceiptByCanonicalRef"]
    old_key = R.canonical(old_ref).decode("utf-8")
    new_key = R.canonical(new_ref).decode("utf-8")
    receipt_authority = receipts.pop(old_key)
    receipt = receipt_authority["receipt"]
    receipt["logicalAddress"] = new_ref["anchor"]["locator"]
    receipt["nativeAddress"] = new_ref["anchor"]["locator"]
    receipt["contentHash"] = new_ref["contentHash"]
    receipts[new_key] = receipt_authority


def delivery_record_refs(record):
    """Return hash-bound inner references carried by one delivery evidence record."""
    refs = {}
    anchor = record.get("deliverableAnchor")
    content_hash = record.get("deliverableContentHash")
    if isinstance(anchor, dict) and isinstance(content_hash, str):
        refs["deliverable"] = {
            "anchor": copy.deepcopy(anchor),
            "contentHash": content_hash,
        }
    if isinstance(record.get("attestationRef"), dict):
        refs["attestation"] = copy.deepcopy(record["attestationRef"])
    return refs


def replace_top_record(authority, phase, mutate, seeds):
    """Replace one authenticated top-level record and every hash-bound reference."""
    bundle = authority["bundle"]
    for index, old_ref in enumerate(bundle["settlementEvidence"]):
        old_key = R.canonical(old_ref).decode("utf-8")
        resolution = authority["referenceValidationByCanonicalRef"].get(old_key)
        if isinstance(resolution, dict) and resolution.get("record", {}).get("phase") == phase:
            receipt = authority["verifiedReceiptByCanonicalRef"].pop(old_key)
            authority["referenceValidationByCanonicalRef"].pop(old_key)
            record = resolution["record"]
            old_inner_refs = delivery_record_refs(record)
            mutate(record)
            try:
                resign_evidence(record, seeds["seller"])
                replacement_hash = R.settlement_evidence_hash(record)
            except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
                # Malformed/non-JCS records cannot honestly be re-signed. Keep the
                # mutated record at its original resolution key so the real shape
                # gate, which precedes hash/signature verification, exercises it.
                authority["referenceValidationByCanonicalRef"][old_key] = resolution
                authority["verifiedReceiptByCanonicalRef"][old_key] = receipt
                return
            new_ref = copy.deepcopy(old_ref)
            new_ref["contentHash"] = replacement_hash
            new_key = R.canonical(new_ref).decode("utf-8")
            receipt["contentHash"] = new_ref["contentHash"]
            new_inner_refs = delivery_record_refs(record)
            for name, old_inner_ref in old_inner_refs.items():
                new_inner_ref = new_inner_refs.get(name)
                if isinstance(new_inner_ref, dict):
                    move_verified_receipt(
                        authority, old_inner_ref, new_inner_ref
                    )
            authority["referenceValidationByCanonicalRef"][new_key] = resolution
            authority["verifiedReceiptByCanonicalRef"][new_key] = receipt
            bundle["settlementEvidence"][index] = new_ref
            for entry in bundle["phaseSummary"]:
                if entry.get("attestationRef") == old_ref:
                    entry["attestationRef"] = new_ref
            resign_ebfab(bundle, seeds)
            return
    raise AssertionError("top-level record for phase %s not found" % phase)


def relink_payload_attestation(authority, seeds):
    """Re-sign one closure's payload record and refresh its current evidence link."""
    closure = authority["deliveryArtifactAuthorityByPhaseKey"][
        "3:deliver-attested-payload"
    ]
    record_entry = closure["payloadAttestationRecord"]
    record = record_entry["artifact"]
    resign_inner_artifact(
        record, seeds["orchestrator"], R.PAYLOAD_ATTESTATION_DOMAIN
    )
    record_hash = R._signed_envelope_content_hash(record)
    record_address = (
        "dacs4:payload-attestation:"
        f"{record['jobId']}:3:{record['verificationMethodHash']}:{record['attempt']}"
    )
    record_entry["logicalAddress"] = record_address
    record_entry["nativeAddress"] = record_address

    def relink(evidence):
        evidence["attestationRef"] = {
            "anchor": {"kind": "storage-program", "locator": record_address},
            "contentHash": record_hash,
            "signer": record["signature"]["signer"],
        }

    replace_top_record(
        authority, "deliver-attested-payload", relink, seeds
    )


def valid_htlc_tx_refs():
    return [
        {"kind": "htlc-lock", "chainId": 1, "contractAddress": "0xcontract", "lockTxHash": "0xlock"},
        {"kind": "htlc-reveal", "chainId": 2, "contractAddress": "0xcontract", "revealTxHash": "0xreveal"},
        {"kind": "htlc-claim", "chainId": 1, "contractAddress": "0xcontract", "claimTxHash": "0xclaim"},
    ]


def derive_phase_disposition(authority, pubkeys):
    return R.validate_ebfab_disposition(
        authority.get("bundle"),
        authority.get("listing"),
        pubkeys,
        authority.get("referenceValidationByCanonicalRef"),
        authority.get("bundleLifecycle"),
        authority.get("sessionExecutionAuthorityByPhaseKey"),
        authority.get("verifiedReceiptByCanonicalRef"),
        authority.get("deliveryArtifactAuthorityByPhaseKey"),
        authority.get("trustedNativeTransactionObservationsByCanonicalRef"),
    )


def derive_phase_keys(authority, pubkeys):
    disposition, _, phase_keys = derive_phase_disposition(authority, pubkeys)
    return phase_keys if disposition == "pass" else None


def evaluate(vector_data, authorities, pubkeys):
    authority = authorities.get(vector_data.get("executionAuthorityRef"))
    if authority is None:
        return "rejected", "execution-authority"
    authority_disposition, _, expected = derive_phase_disposition(authority, pubkeys)
    if authority_disposition == "indeterminate":
        return "indeterminate", "execution-authority-indeterminate"
    if authority_disposition != "pass":
        return "rejected", "execution-authority"

    refs = vector_data["topLevelRefs"]
    records = vector_data["authenticatedRecordByRef"]
    pointers = vector_data["pointerMap"]
    st8_reason_by_phase = {
        "pay-cross-chain-htlc": "dest-revealed-source-unclaimed",
        "pay-cross-chain-liquidity-tank": "tank-locked-unreleased",
    }

    if len(refs) != len(set(refs)):
        return "rejected", "raw-multiplicity"

    for successor in refs:
        record = records.get(successor, {})
        interim = record.get("supersedesEvidenceRef")
        if interim is not None:
            interim_record = records.get(interim, {})
            phase_key = record.get("phaseKey")
            phase = phase_key.split(":", 1)[-1] if isinstance(phase_key, str) else None
            expected_reason = st8_reason_by_phase.get(phase)
            if (
                interim in refs
                or record.get("outcome") != "success"
                or interim_record.get("jobId") != record.get("jobId")
                or interim_record.get("phaseKey") != record.get("phaseKey")
                or interim_record.get("outcome") != "failure"
                or interim_record.get("reason") != expected_reason
            ):
                return "rejected", "st8-raw-admissibility"

    authority = authorities[vector_data["executionAuthorityRef"]]
    expected_outcome_by_key = {
        f"{entry['index']}:{entry['kind']}": "success" if entry["outcome"] == "ok" else "failure"
        for entry in authority["bundle"]["phaseSummary"]
        if entry["kind"] in R.EVIDENCE_PHASES
    }
    expected_error_by_key = {
        f"{entry['index']}:{entry['kind']}": entry.get("errorClass")
        for entry in authority["bundle"]["phaseSummary"]
        if entry["kind"] in R.EVIDENCE_PHASES
    }
    for ref in refs:
        record = records.get(ref)
        phase_key = record.get("phaseKey") if isinstance(record, dict) else None
        if phase_key not in expected_outcome_by_key:
            continue
        if record.get("outcome") != expected_outcome_by_key[phase_key]:
            return "rejected", "st8-raw-admissibility"
        phase = phase_key.split(":", 1)[-1]
        expected_reason = st8_reason_by_phase.get(phase)
        expired_st8 = expected_error_by_key.get(phase_key) == "settlement-atomicity" or (
            phase == "pay-cross-chain-liquidity-tank"
            and expected_error_by_key.get(phase_key) == "substrate"
            and record.get("reason") == expected_reason
        )
        if expired_st8:
            if record.get("reason") != expected_reason:
                return "rejected", "st8-raw-admissibility"
        elif record.get("reason") in set(st8_reason_by_phase.values()):
            return "rejected", "st8-raw-admissibility"

    if any(
        ref not in records
        or records[ref].get("jobId") != authority["bundle"]["jobId"]
        or records[ref].get("phaseKey") not in expected
        for ref in refs
    ):
        return "rejected", "exact-phase-mapping"

    lifecycle_overrides = vector_data.get("referenceLifecycleByRef", {})
    default_lifecycle = authority["defaultReferenceLifecycle"]
    for ref in refs:
        lifecycle = lifecycle_overrides.get(ref, default_lifecycle)
        if authority["bundle"]["outcome"] == "completed":
            if (
                lifecycle.get("state") != "finalized"
                or lifecycle.get("independentlyResolvable") is not True
            ):
                return "rejected", "lifecycle-gate"
        elif lifecycle.get("state") not in {"included", "finalized"}:
            return "rejected", "lifecycle-gate"

    if len(refs) != len(expected):
        return "rejected", "exact-cardinality"

    mapped = [records[ref]["phaseKey"] for ref in refs]
    if len(set(mapped)) != len(mapped) or set(mapped) != set(expected):
        return "rejected", "exact-bijection"

    if len(set(pointers.values())) != len(pointers):
        return "rejected", "pointer-agreement"
    for phase_key, ref in pointers.items():
        if ref not in refs or records.get(ref, {}).get("phaseKey") != phase_key:
            return "rejected", "pointer-agreement"

    if vector_data["unrelatedAuthorityDisposition"] == "indeterminate":
        return "indeterminate", "unrelated-authority-indeterminate"
    return "verified", "ok"


class BundleSettlementEvidenceBijectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.pubkeys = {
            claim: decode(value)
            for claim, value in cls.data["publicKeys"].items()
        }

    def test_vector_hash_count_and_names(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(self.data["hash"], hashlib.sha256(canonical_json(vectors)).hexdigest())
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_all_expected_dispositions_and_reason_codes(self):
        for vector in self.data["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    evaluate(vector["input"], self.data["executionAuthorities"], self.pubkeys),
                    (vector["want"]["disposition"], vector["want"]["reasonCode"]),
                )

    def test_phase_authority_is_derived_not_caller_supplied(self):
        for vector in self.data["vectors"]:
            self.assertNotIn("expectedPhaseKeys", vector["input"])
            self.assertNotIn("recordClassByRef", vector["input"])
            self.assertNotIn("supersedesEdges", vector["input"])
            self.assertNotIn("resolvedReferencePhaseKeys", vector["input"])
        for definition in self.data["executionAuthorityDefinitions"].values():
            self.assertNotIn("listingSignatureVerified", definition)
            self.assertNotIn("bundleSignaturesVerified", definition)

        repeated = self.data["executionAuthorities"]["repeated-pay-completed"]
        self.assertEqual(
            derive_phase_keys(repeated, self.pubkeys),
            ["0:pay-dem", "1:pay-dem", "2:deliver-entitlement"],
        )
        failed = self.data["executionAuthorities"]["failed-delivery"]
        self.assertEqual(derive_phase_keys(failed, self.pubkeys), ["0:deliver-storage-program"])
        transient = self.data["executionAuthorities"]["transient-retry-exhausted"]
        self.assertEqual(
            derive_phase_keys(transient, self.pubkeys),
            ["0:deliver-storage-program"],
        )
        direct_cross_chain = self.data["executionAuthorities"]["single-htlc-direct-completed"]
        self.assertEqual(
            derive_phase_keys(direct_cross_chain, self.pubkeys),
            ["2:pay-cross-chain-htlc"],
        )
        direct_resolution = next(
            iter(direct_cross_chain["referenceValidationByCanonicalRef"].values())
        )
        self.assertNotIn("supersedesEvidenceRef", direct_resolution["record"])
        direct_receipt = next(iter(direct_cross_chain["verifiedReceiptByCanonicalRef"].values()))
        self.assertFalse(direct_receipt["logicalAddress"].endswith(":resolved"))
        failed_resolution = next(iter(failed["referenceValidationByCanonicalRef"].values()))
        self.assertFalse(failed_resolution["lifecycle"]["independentlyResolvable"])
        aborted = self.data["executionAuthorities"]["aborted-before-result"]
        self.assertEqual(derive_phase_keys(aborted, self.pubkeys), [])
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-completed-incomplete-summary"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-failed-gapped-summary"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-aborted-result-summary"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-failed-outcome-error-class"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-st8-expired-wrong-reason"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-transient-not-exhausted"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-completed-st8-interim-lifecycle"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-completed-st8-missing-supersedes"],
                self.pubkeys,
            )
        )
        self.assertIsNone(
            derive_phase_keys(self.data["executionAuthorities"]["invalid-listing-signature"], self.pubkeys)
        )
        self.assertIsNone(
            derive_phase_keys(self.data["executionAuthorities"]["invalid-bundle-signature"], self.pubkeys)
        )
        self.assertIsNone(
            derive_phase_keys(self.data["executionAuthorities"]["mismatched-listing-signer"], self.pubkeys)
        )
        self.assertIsNone(
            derive_phase_keys(
                self.data["executionAuthorities"]["invalid-completed-bundle-lifecycle"],
                self.pubkeys,
            )
        )

    def test_sequential_gate_dispatches_mixed_payment_and_current_delivery_evidence(self):
        authority = self.data["executionAuthorities"]["standard-completed"]
        records = {
            resolution["record"]["phase"]: resolution["record"]
            for resolution in authority["referenceValidationByCanonicalRef"].values()
        }
        payment = records["pay-dem"]
        delivery = records["deliver-attested-payload"]
        self.assertEqual(payment.get("evidenceVersion"), "1")
        self.assertNotIn("deliveryEvidenceVersion", payment)
        self.assertTrue(R._settlement_evidence_shape_valid(payment))
        self.assertEqual(delivery.get("deliveryEvidenceVersion"), "1")
        self.assertNotIn("evidenceVersion", delivery)
        self.assertEqual(delivery.get("phaseIndex"), 3)
        self.assertTrue(R._delivery_evidence_shape_valid(delivery))
        self.assertEqual(
            derive_phase_keys(authority, self.pubkeys),
            ["2:pay-dem", "3:deliver-attested-payload"],
        )

        for field, value in (
            ("valid", True),
            ("readable", True),
            ("asserts", ["delivered", "valid", "readable"]),
        ):
            mutated = copy.deepcopy(authority)
            replace_top_record(
                mutated,
                "deliver-attested-payload",
                lambda record, field=field, value=value: record.__setitem__(field, value),
                self.data["seeds"],
            )
            with self.subTest(unknown_top_level_field=field):
                self.assertIsNone(derive_phase_keys(mutated, self.pubkeys))

    def test_current_delivery_requires_the_resolved_phase_specific_inner_closure(self):
        valid = {
            "standard-completed": ["2:pay-dem", "3:deliver-attested-payload"],
            "repeated-pay-completed": [
                "0:pay-dem", "1:pay-dem", "2:deliver-entitlement"
            ],
        }
        for authority_name, expected in valid.items():
            authority = self.data["executionAuthorities"][authority_name]
            with self.subTest(valid=authority_name):
                self.assertEqual(derive_phase_keys(authority, self.pubkeys), expected)

            missing = copy.deepcopy(authority)
            missing["deliveryArtifactAuthorityByPhaseKey"] = {}
            with self.subTest(missing_closure=authority_name):
                self.assertIsNone(derive_phase_keys(missing, self.pubkeys))

        invalid_names = (
            "invalid-deliverable-locator-closure",
            "invalid-attestation-locator-closure",
            "invalid-attestation-content-hash-closure",
            "invalid-entitlement-locator-closure",
            "invalid-credential-delivery-omitted",
        )
        for authority_name in invalid_names:
            authority = self.data["executionAuthorities"][authority_name]
            with self.subTest(resigned_inner_attack=authority_name):
                bundle_ok, _ = R._bundle_signatures_valid(
                    authority["bundle"], self.pubkeys
                )
                self.assertTrue(bundle_ok)
                delivery_records = [
                    resolution["record"]
                    for resolution in authority["referenceValidationByCanonicalRef"].values()
                    if resolution.get("record", {}).get("deliveryEvidenceVersion") == "1"
                ]
                self.assertEqual(len(delivery_records), 1)
                record = delivery_records[0]
                signature = record["signature"]
                self.assertTrue(R.verify_sig(
                    self.pubkeys[signature["signer"]],
                    R.DELIVERY_EVIDENCE_DOMAIN,
                    R.delivery_evidence_hash(record),
                    signature["value"],
                ))
                self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

    def test_legacy_delivery_closes_every_kind_without_synthesizing_an_index(self):
        expected = {
            "legacy-storage-completed": (
                "0:deliver-storage-program",
                "deliverable",
                "dacs4:deliverable:SEB-AUTHORITY-legacy-storage-completed",
            ),
            "legacy-entitlement-completed": (
                "0:deliver-entitlement",
                "entitlementRecord",
                "dacs4:entitlement:SEB-AUTHORITY-legacy-entitlement-completed:0",
            ),
            "legacy-attested-completed": (
                "0:deliver-attested-payload",
                "deliverable",
                "dacs4:deliverable:SEB-AUTHORITY-legacy-attested-completed",
            ),
            "legacy-self-signed-attested-completed": (
                "0:deliver-attested-payload",
                "deliverable",
                "dacs4:deliverable:SEB-AUTHORITY-legacy-self-signed-attested-completed",
            ),
        }
        for authority_name, (phase_key, closure_key, address) in expected.items():
            authority = self.data["executionAuthorities"][authority_name]
            disposition, reason, phase_keys = derive_phase_disposition(
                authority, self.pubkeys
            )
            with self.subTest(authority=authority_name):
                self.assertEqual(disposition, "pass", reason)
                self.assertEqual(phase_keys, [phase_key])
                record = next(
                    resolution["record"]
                    for resolution in authority[
                        "referenceValidationByCanonicalRef"
                    ].values()
                )
                self.assertTrue(R._settlement_evidence_shape_valid(record))
                self.assertEqual(record.get("evidenceVersion"), "1")
                self.assertNotIn("deliveryEvidenceVersion", record)
                self.assertNotIn("phaseIndex", record)
                self.assertNotIn("credentialDelivery", record)
                self.assertEqual(
                    authority["deliveryArtifactAuthorityByPhaseKey"][phase_key][
                        closure_key
                    ]["logicalAddress"],
                    address,
                )

        entitlement_closure = self.data["executionAuthorities"][
            "legacy-entitlement-completed"
        ]["deliveryArtifactAuthorityByPhaseKey"]["0:deliver-entitlement"]
        self.assertIn(
            "credentialRef", entitlement_closure["entitlementRecord"]["artifact"]
        )
        self.assertNotIn("credential", entitlement_closure)
        credential_ref = entitlement_closure["entitlementRecord"]["artifact"][
            "credentialRef"
        ]
        self.assertEqual(
            credential_ref["ref"]["anchor"]["locator"],
            "dacs4:credential:SEB-AUTHORITY-legacy-entitlement-completed:0",
        )

        for authority_name in (
            "legacy-attested-completed",
            "legacy-self-signed-attested-completed",
        ):
            authority = self.data["executionAuthorities"][authority_name]
            closure = authority["deliveryArtifactAuthorityByPhaseKey"][
                "0:deliver-attested-payload"
            ]
            payload_record = closure["payloadAttestationRecord"]["artifact"]
            expected_address = (
                f"dacs4:payload-attestation:{authority['bundle']['jobId']}:"
                f"{payload_record['verificationMethodHash']}:"
                f"{payload_record['attempt']}"
            )
            self.assertEqual(
                closure["payloadAttestationRecord"]["logicalAddress"],
                expected_address,
            )
            self.assertEqual(
                payload_record["methodEvidenceRef"]["anchor"]["locator"],
                f"dacs4:method-evidence:{authority['bundle']['jobId']}",
            )

        self_signed = self.data["executionAuthorities"][
            "legacy-self-signed-attested-completed"
        ]
        self_signed_record = self_signed["deliveryArtifactAuthorityByPhaseKey"][
            "0:deliver-attested-payload"
        ]["payloadAttestationRecord"]["artifact"]
        self.assertNotIn("methodTransactionRef", self_signed_record)
        self.assertEqual(
            self_signed["trustedNativeTransactionObservationsByCanonicalRef"], {}
        )

    def test_legacy_receipt_alone_never_replaces_required_delivery_closure(self):
        dependencies = (
            ("legacy-storage-completed", "0:deliver-storage-program", "deliverable"),
            ("legacy-entitlement-completed", "0:deliver-entitlement", "entitlementRecord"),
            ("legacy-attested-completed", "0:deliver-attested-payload", "methodEvidence"),
        )
        for authority_name, phase_key, dependency in dependencies:
            authority = copy.deepcopy(
                self.data["executionAuthorities"][authority_name]
            )
            authority["deliveryArtifactAuthorityByPhaseKey"][phase_key][dependency][
                "available"
            ] = False
            with self.subTest(authority=authority_name, dependency=dependency):
                disposition, reason, _ = derive_phase_disposition(
                    authority, self.pubkeys
                )
                self.assertEqual(disposition, "indeterminate", reason)

            receipt_only = copy.deepcopy(
                self.data["executionAuthorities"][authority_name]
            )
            receipt_only["deliveryArtifactAuthorityByPhaseKey"] = {}
            with self.subTest(authority=authority_name, dependency="all"):
                disposition, reason, _ = derive_phase_disposition(
                    receipt_only, self.pubkeys
                )
                self.assertEqual(disposition, "indeterminate", reason)

        native_missing = copy.deepcopy(
            self.data["executionAuthorities"]["legacy-attested-completed"]
        )
        native_missing["trustedNativeTransactionObservationsByCanonicalRef"] = {}
        disposition, reason, _ = derive_phase_disposition(native_missing, self.pubkeys)
        self.assertEqual(disposition, "indeterminate", reason)

        for authority_map, field in (
            ("sessionExecutionAuthorityByPhaseKey", "agreementHash"),
            ("deliveryArtifactAuthorityByPhaseKey", "agreementHash"),
        ):
            agreement_missing = copy.deepcopy(
                self.data["executionAuthorities"]["legacy-attested-completed"]
            )
            agreement_missing[authority_map][
                "0:deliver-attested-payload"
            ].pop(field)
            disposition, reason, _ = derive_phase_disposition(
                agreement_missing, self.pubkeys
            )
            with self.subTest(authority=authority_map, dependency=field):
                self.assertEqual(disposition, "indeterminate", reason)

        malformed = copy.deepcopy(
            self.data["executionAuthorities"]["legacy-storage-completed"]
        )
        malformed["deliveryArtifactAuthorityByPhaseKey"][
            "0:deliver-storage-program"
        ]["deliverable"] = "malformed"
        disposition, reason, _ = derive_phase_disposition(malformed, self.pubkeys)
        self.assertEqual(disposition, "error", reason)

        contradiction = copy.deepcopy(
            self.data["executionAuthorities"]["legacy-storage-completed"]
        )
        contradiction["deliveryArtifactAuthorityByPhaseKey"][
            "0:deliver-storage-program"
        ]["deliverable"]["cleartextHash"] = "00" * 32
        disposition, reason, _ = derive_phase_disposition(
            contradiction, self.pubkeys
        )
        self.assertEqual(disposition, "fail", reason)

        repeated = self.data["executionAuthorities"][
            "legacy-repeated-storage-invalid"
        ]
        disposition, _, phase_keys = derive_phase_disposition(repeated, self.pubkeys)
        self.assertEqual(disposition, "fail")
        self.assertIsNone(phase_keys)

    def test_entitlement_terms_are_bound_to_the_signed_offering(self):
        for name in (
            "invalid-entitlement-duration-closure",
            "invalid-entitlement-renewable-closure",
        ):
            with self.subTest(authority=name):
                disposition, reason, _ = derive_phase_disposition(
                    self.data["executionAuthorities"][name], self.pubkeys
                )
                self.assertEqual(disposition, "fail", reason)

        for duration, start_shift in ((0.5, 123_456), (0, 86_400_000), (0.0001, 0)):
            authority = copy.deepcopy(
                self.data["executionAuthorities"]["repeated-pay-completed"]
            )
            deliverable_spec = authority["listing"]["offering"]["deliverable"]
            deliverable_spec["durationSec"] = duration
            resign_listing(authority["listing"], self.data["seeds"]["seller"])
            authority["bundle"]["listingRef"]["contentHash"] = R.listing_hash(
                authority["listing"]
            )
            entitlement = authority["deliveryArtifactAuthorityByPhaseKey"][
                "2:deliver-entitlement"
            ]["entitlementRecord"]["artifact"]
            entitlement["startsAt"] += start_shift
            if duration == 0.0001:
                entitlement["startsAt"] = 0.2
            entitlement["endsAt"] = entitlement["startsAt"] + duration * 1000
            resign_inner_artifact(
                entitlement,
                self.data["seeds"]["seller"],
                R.ENTITLEMENT_DOMAIN,
            )
            entitlement_hash = R._signed_envelope_content_hash(entitlement)
            replace_top_record(
                authority,
                "deliver-entitlement",
                lambda record: record.__setitem__(
                    "deliverableContentHash", entitlement_hash
                ),
                self.data["seeds"],
            )
            with self.subTest(duration=duration, start_shift=start_shift):
                disposition, reason, _ = derive_phase_disposition(
                    authority, self.pubkeys
                )
                self.assertEqual(disposition, "pass", reason)

    def test_inner_signed_extensions_preserved_but_other_types_refused(self):
        for name, phase_key, artifact_key, discriminator, domain, signer in (
            ("repeated-pay-completed", "2:deliver-entitlement", "entitlementRecord",
             "entitlementVersion", R.ENTITLEMENT_DOMAIN, "seller"),
            ("standard-completed", "3:deliver-attested-payload", "payloadAttestationRecord",
             "payloadAttestationVersion", R.PAYLOAD_ATTESTATION_DOMAIN, "orchestrator"),
        ):
            for mutation, expected in (
                ({"laterMinorAuditLabel": "preserve-me"}, "pass"),
                ({
                    "auditVersion": "inert-extension",
                    "recipeVersion": 3,
                    "railVersion": 4,
                    "listingVersion": 5,
                    "recipeRegistryVersion": 6,
                    "railRegistryVersion": 7,
                    "protocolVersion": "2",
                }, "pass"),
                ({discriminator: "99"}, "non-pass"),
                ({"evidenceVersion": "1"}, "non-pass"),
                ({"agreementVersion": "1"}, "non-pass"),
                ({"future" + discriminator[0].upper() + discriminator[1:]: "1"}, "pass"),
            ):
                authority = copy.deepcopy(self.data["executionAuthorities"][name])
                artifact = authority["deliveryArtifactAuthorityByPhaseKey"][
                    phase_key][artifact_key]["artifact"]
                artifact.update(mutation)
                resign_inner_artifact(artifact, self.data["seeds"][signer], domain)
                content_hash = R._signed_envelope_content_hash(artifact)

                def relink(record):
                    if artifact_key == "entitlementRecord":
                        record["deliverableContentHash"] = content_hash
                    else:
                        record["attestationRef"]["contentHash"] = content_hash

                replace_top_record(authority, phase_key.split(":", 1)[1], relink, self.data["seeds"])
                with self.subTest(artifact=artifact_key, mutation=mutation):
                    disposition, reason, _ = derive_phase_disposition(authority, self.pubkeys)
                    if expected == "pass":
                        self.assertEqual(disposition, "pass", reason)
                        # An extension must remain hash/signature-bound, not stripped.
                        artifact["laterMinorAuditLabel"] = "unsigned-tampering"
                        self.assertNotEqual(derive_phase_disposition(authority, self.pubkeys)[0], "pass")
                    else:
                        self.assertNotEqual(disposition, "pass", reason)

    def test_signed_listing_extension_remains_compatible(self):
        authority = copy.deepcopy(
            self.data["executionAuthorities"]["repeated-pay-completed"]
        )
        authority["listing"]["signedExtension"] = {"preserved": True}
        resign_listing(authority["listing"], self.data["seeds"]["seller"])
        authority["bundle"]["listingRef"]["contentHash"] = R.listing_hash(
            authority["listing"]
        )
        resign_ebfab(authority["bundle"], self.data["seeds"])
        self.assertEqual(
            derive_phase_disposition(authority, self.pubkeys)[0], "pass"
        )

    def test_complete_deliverable_and_method_hashes_preserve_signature_named_extensions(self):
        authority = copy.deepcopy(
            self.data["executionAuthorities"]["standard-completed"]
        )
        listing = authority["listing"]
        deliverable = listing["offering"]["deliverable"]
        method = deliverable["verificationMethod"]
        deliverable["signature"] = {"purpose": "inert-deliverable-extension"}
        method["signature"] = {"purpose": "inert-method-extension"}

        record = authority["deliveryArtifactAuthorityByPhaseKey"][
            "3:deliver-attested-payload"
        ]["payloadAttestationRecord"]["artifact"]
        record["deliverableSpecHash"] = R._complete_object_hash(deliverable)
        record["verificationMethodHash"] = R._complete_object_hash(method)
        transaction_key = R.canonical(record["methodTransactionRef"]).decode("utf-8")
        authority["trustedNativeTransactionObservationsByCanonicalRef"][transaction_key][
            "verificationMethod"
        ] = copy.deepcopy(method)

        resign_listing(listing, self.data["seeds"]["seller"])
        authority["bundle"]["listingRef"]["contentHash"] = R.listing_hash(listing)
        relink_payload_attestation(authority, self.data["seeds"])

        self.assertNotEqual(
            R._complete_object_hash(deliverable),
            R._signed_envelope_content_hash(deliverable),
        )
        self.assertNotEqual(
            R._complete_object_hash(method),
            R._signed_envelope_content_hash(method),
        )
        disposition, reason, _ = derive_phase_disposition(authority, self.pubkeys)
        self.assertEqual(disposition, "pass", reason)

    def test_full_payload_closure_supports_self_signed_without_native_transaction(self):
        authority = copy.deepcopy(
            self.data["executionAuthorities"]["standard-completed"]
        )
        closure = authority["deliveryArtifactAuthorityByPhaseKey"][
            "3:deliver-attested-payload"
        ]
        record = closure["payloadAttestationRecord"]["artifact"]
        old_method_ref = copy.deepcopy(record["methodEvidenceRef"])
        deliverable = authority["listing"]["offering"]["deliverable"]
        method = {"kind": "self-signed"}
        deliverable["verificationMethod"] = method
        assertion = closure["deliverable"]["cleartextUtf8"]
        proof_key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(self.data["seeds"]["seller"])
        )
        proof = {
            "kind": "self-signed-payload",
            "payloadContentHash": closure["deliverable"]["cleartextHash"],
            "methodInput": {
                "identifier": proof_key.public_key().public_bytes_raw().hex(),
                "assertion": assertion,
                "signature": encode(proof_key.sign(assertion.encode("utf-8"))),
            },
        }
        closure["methodEvidence"]["artifact"] = proof

        record["deliverableSpecHash"] = R._complete_object_hash(deliverable)
        record["verificationMethod"] = "self-signed"
        record["verificationMethodHash"] = R._complete_object_hash(method)
        record["methodEvidenceRef"]["contentHash"] = R._complete_object_hash(proof)
        move_verified_receipt(
            authority, old_method_ref, record["methodEvidenceRef"]
        )
        record.pop("methodTransactionRef")
        authority["trustedNativeTransactionObservationsByCanonicalRef"] = {}

        resign_listing(authority["listing"], self.data["seeds"]["seller"])
        authority["bundle"]["listingRef"]["contentHash"] = R.listing_hash(
            authority["listing"]
        )
        relink_payload_attestation(authority, self.data["seeds"])
        disposition, reason, _ = derive_phase_disposition(authority, self.pubkeys)
        self.assertEqual(disposition, "pass", reason)

        with_native_transaction = copy.deepcopy(authority)
        supplied_record = with_native_transaction[
            "deliveryArtifactAuthorityByPhaseKey"
        ]["3:deliver-attested-payload"]["payloadAttestationRecord"]["artifact"]
        supplied_record["methodTransactionRef"] = {
            "kind": "demos-web2-request",
            "value": "ab" * 32,
        }
        relink_payload_attestation(with_native_transaction, self.data["seeds"])
        self.assertNotEqual(
            derive_phase_disposition(with_native_transaction, self.pubkeys)[0], "pass"
        )

        missing_native_transaction = copy.deepcopy(
            self.data["executionAuthorities"]["standard-completed"]
        )
        transaction_bound_record = missing_native_transaction[
            "deliveryArtifactAuthorityByPhaseKey"
        ]["3:deliver-attested-payload"]["payloadAttestationRecord"]["artifact"]
        transaction_bound_record.pop("methodTransactionRef")
        relink_payload_attestation(missing_native_transaction, self.data["seeds"])
        self.assertNotEqual(
            derive_phase_disposition(missing_native_transaction, self.pubkeys)[0],
            "pass",
        )

    def test_native_authority_and_terminal_finality_have_distinct_dispositions(self):
        expected = {
            "unavailable-native-transaction-observation": "indeterminate",
            "unobserved-resigned-native-transaction": "indeterminate",
            "invalid-native-transaction-observation": "fail",
            "invalid-terminal-included-native-transaction": "fail",
        }
        for name, disposition in expected.items():
            with self.subTest(authority=name):
                actual, reason, _ = derive_phase_disposition(
                    self.data["executionAuthorities"][name], self.pubkeys
                )
                self.assertEqual(actual, disposition, reason)
                self.assertIsNone(
                    derive_phase_keys(self.data["executionAuthorities"][name], self.pubkeys)
                )

    def test_job_bound_derivation_exposes_excluded_disposition_reason(self):
        authority = copy.deepcopy(
            self.data["executionAuthorities"][
                "unavailable-native-transaction-observation"
            ]
        )
        validation_authority = copy.deepcopy(authority)
        validation_authority["publicKeys"] = self.pubkeys
        tag = {
            "bundle": authority["bundle"],
            "resolvedRole": "buyer",
            "counterpartyDisposition": None,
            "resolvedJobId": authority["bundle"]["jobId"],
            "selectedByRoleResolution": True,
            "ebfabAuthority": validation_authority,
        }
        excluded = []
        derivation = R.derive_job_bound(
            "did:demos:buyer",
            [tag],
            0,
            2_000_000_000_000,
            excluded_dispositions=excluded,
        )
        self.assertEqual(derivation["bundleCount"], 0)
        self.assertEqual(len(excluded), 1)
        self.assertEqual(excluded[0]["disposition"], "indeterminate")
        self.assertIn("unavailable", excluded[0]["reason"])

    def test_signed_contradiction_precedes_unresolved_delivery_dependency(self):
        authority = copy.deepcopy(
            self.data["executionAuthorities"]["standard-completed"]
        )
        closure = authority["deliveryArtifactAuthorityByPhaseKey"][
            "3:deliver-attested-payload"
        ]
        closure["deliverable"]["available"] = False
        payload_record = closure["payloadAttestationRecord"]["artifact"]
        payload_record["decision"] = "fail"
        resign_inner_artifact(
            payload_record,
            self.data["seeds"]["orchestrator"],
            R.PAYLOAD_ATTESTATION_DOMAIN,
        )
        replace_top_record(
            authority,
            "deliver-attested-payload",
            lambda record: record["attestationRef"].__setitem__(
                "contentHash", R._signed_envelope_content_hash(payload_record)
            ),
            self.data["seeds"],
        )
        disposition, reason, _ = derive_phase_disposition(authority, self.pubkeys)
        self.assertEqual(disposition, "fail", reason)

    def test_malformed_cleartext_is_error_in_both_actual_delivery_branches(self):
        cases = (
            ("standard-completed", "3:deliver-attested-payload"),
            ("completed-storage-delivery", "0:deliver-storage-program"),
        )
        for authority_name, phase_key in cases:
            authority = copy.deepcopy(self.data["executionAuthorities"][authority_name])
            authority["deliveryArtifactAuthorityByPhaseKey"][phase_key]["deliverable"][
                "cleartextUtf8"
            ] = chr(0xD800)
            with self.subTest(authority=authority_name):
                disposition, reason, _ = derive_phase_disposition(authority, self.pubkeys)
                self.assertEqual(disposition, "error", reason)

    def test_primary_attested_payload_closes_stored_bytes_and_storage_authority(self):
        def fresh_authority():
            return copy.deepcopy(
                self.data["executionAuthorities"]["standard-completed"]
            )

        def payload_material(authority):
            closure = authority["deliveryArtifactAuthorityByPhaseKey"][
                "3:deliver-attested-payload"
            ]
            record = next(
                resolution["record"]
                for resolution in authority[
                    "referenceValidationByCanonicalRef"
                ].values()
                if resolution.get("record", {}).get("phase")
                == "deliver-attested-payload"
            )
            payload_ref = {
                "anchor": copy.deepcopy(record["deliverableAnchor"]),
                "contentHash": record["deliverableContentHash"],
            }
            receipt_authority = authority["verifiedReceiptByCanonicalRef"][
                R.canonical(payload_ref).decode("utf-8")
            ]
            return closure, receipt_authority

        baseline = fresh_authority()
        disposition, reason, _ = derive_phase_disposition(baseline, self.pubkeys)
        self.assertEqual(disposition, "pass", reason)

        changed_bytes = fresh_authority()
        closure, _ = payload_material(changed_bytes)
        closure["deliverable"]["storedBytesBase64url"] = encode(
            b"different stored bytes"
        )
        self.assertEqual(
            derive_phase_disposition(changed_bytes, self.pubkeys)[0], "fail"
        )

        changed_commitment = fresh_authority()
        closure, _ = payload_material(changed_commitment)
        closure["deliverable"]["storedContentHash"] = "00" * 32
        self.assertEqual(
            derive_phase_disposition(changed_commitment, self.pubkeys)[0], "fail"
        )

        missing_authority = fresh_authority()
        _, receipt_authority = payload_material(missing_authority)
        receipt_authority.pop("storageBinding")
        self.assertEqual(
            derive_phase_disposition(missing_authority, self.pubkeys)[0],
            "indeterminate",
        )

        malformed_authority = fresh_authority()
        _, receipt_authority = payload_material(malformed_authority)
        receipt_authority["storageBinding"] = []
        self.assertEqual(
            derive_phase_disposition(malformed_authority, self.pubkeys)[0], "error"
        )

        for access_model in ("buyer-only", "encrypt-to-buyer"):
            private = fresh_authority()
            listing = private["listing"]
            deliverable_spec = listing["offering"]["deliverable"]
            deliverable_spec["accessModel"] = access_model
            closure, receipt_authority = payload_material(private)
            resolved = closure["deliverable"]
            if access_model == "encrypt-to-buyer":
                stored_bytes = b"fixture encrypted attested payload"
                stored_hash = hashlib.sha256(stored_bytes).hexdigest()
                resolved["storedBytesBase64url"] = encode(stored_bytes)
                resolved["storedContentHash"] = stored_hash
                binding = {
                    "effectiveAccessMode": access_model,
                    "storedContentHash": stored_hash,
                    "encryption": {
                        "recipient": "did:demos:buyer",
                        "ciphertextContentHash": stored_hash,
                    },
                }
            else:
                binding = {
                    "effectiveAccessMode": access_model,
                    "storedContentHash": resolved["storedContentHash"],
                    "acl": {
                        "mode": "restricted",
                        "allowed": ["did:demos:buyer"],
                    },
                }
            receipt_authority["storageBinding"] = binding
            record = closure["payloadAttestationRecord"]["artifact"]
            record["deliverableSpecHash"] = R._complete_object_hash(
                deliverable_spec
            )
            resign_listing(listing, self.data["seeds"]["seller"])
            private["bundle"]["listingRef"]["contentHash"] = R.listing_hash(
                listing
            )
            relink_payload_attestation(private, self.data["seeds"])
            with self.subTest(access_model=access_model):
                disposition, reason, _ = derive_phase_disposition(
                    private, self.pubkeys
                )
                self.assertEqual(disposition, "pass", reason)

    def test_primary_payload_attestation_shape_errors_after_full_relinking(self):
        source = self.data["executionAuthorities"]["standard-completed"]
        source_snapshot = canonical_json(source)
        seeds = self.data["seeds"]

        def payload_record(authority):
            return authority["deliveryArtifactAuthorityByPhaseKey"][
                "3:deliver-attested-payload"
            ]["payloadAttestationRecord"]["artifact"]

        def signed_chain(authority):
            evidence = next(
                resolution["record"]
                for resolution in authority[
                    "referenceValidationByCanonicalRef"
                ].values()
                if resolution.get("record", {}).get("phase")
                == "deliver-attested-payload"
            )
            return copy.deepcopy({
                "payloadSignature": payload_record(authority)["signature"],
                "attestationRef": evidence["attestationRef"],
                "evidenceSignature": evidence["signature"],
                "bundleSignatures": authority["bundle"]["signatures"],
            })

        baseline = copy.deepcopy(source)
        self.assertEqual(
            payload_record(baseline)["payloadAttestationVersion"], "1"
        )
        disposition, reason, _ = derive_phase_disposition(baseline, self.pubkeys)
        self.assertEqual(disposition, "pass", reason)

        signed_extension = copy.deepcopy(source)
        extension_record = payload_record(signed_extension)
        extension_record["laterMinorAuditLabel"] = "preserve-me"
        extension_before = signed_chain(signed_extension)
        relink_payload_attestation(signed_extension, seeds)
        extension_after = signed_chain(signed_extension)
        self.assertNotEqual(extension_after, extension_before)
        disposition, reason, _ = derive_phase_disposition(
            signed_extension, self.pubkeys
        )
        self.assertEqual(disposition, "pass", reason)

        malformed_fields = (
            ("jobId", ""),
            ("payloadFormat", []),
            ("verificationMethod", ""),
            ("reason", {}),
            ("agreementHash", "not-a-hash"),
            ("deliverableSpecHash", []),
            ("payloadContentHash", "00"),
            ("verificationMethodHash", "AA" * 32),
            ("attempt", True),
            ("attempt", -1),
            ("decision", "accept"),
            ("verifiedAt", []),
            ("methodEvidenceRef", {}),
            ("methodTransactionRef", {"kind": "", "value": "x"}),
        )
        for index, (field, value) in enumerate(malformed_fields):
            authority = copy.deepcopy(source)
            record = payload_record(authority)
            record["evidenceCompletionCase"] = f"field-{index}"
            record[field] = copy.deepcopy(value)
            before = signed_chain(authority)
            relink_payload_attestation(authority, seeds)
            after = signed_chain(authority)
            with self.subTest(field=field, value=value):
                self.assertNotEqual(after["payloadSignature"], before["payloadSignature"])
                self.assertNotEqual(after["attestationRef"], before["attestationRef"])
                self.assertNotEqual(after["evidenceSignature"], before["evidenceSignature"])
                self.assertNotEqual(after["bundleSignatures"], before["bundleSignatures"])
                self.assertTrue(R._signed_inner_artifact_valid(
                    record, R.PAYLOAD_ATTESTATION_DOMAIN, self.pubkeys
                ))
                self.assertFalse(R._payload_attestation_record_shape_valid(record))
                disposition, reason, _ = derive_phase_disposition(
                    authority, self.pubkeys
                )
                self.assertEqual(disposition, "error", reason)
                self.assertEqual(reason, "payload attestation record is malformed")

        for version_action in ("unsupported", "missing"):
            authority = copy.deepcopy(source)
            record = payload_record(authority)
            record["evidenceCompletionCase"] = f"version-{version_action}"
            if version_action == "unsupported":
                record["payloadAttestationVersion"] = "2"
            else:
                record.pop("payloadAttestationVersion")
            before = signed_chain(authority)
            relink_payload_attestation(authority, seeds)
            after = signed_chain(authority)
            with self.subTest(payloadAttestationVersion=version_action):
                self.assertNotEqual(after, before)
                self.assertTrue(R._signed_inner_artifact_valid(
                    record, R.PAYLOAD_ATTESTATION_DOMAIN, self.pubkeys
                ))
                disposition, reason, _ = derive_phase_disposition(
                    authority, self.pubkeys
                )
                self.assertEqual(disposition, "fail", reason)
                self.assertEqual(
                    reason, "payload attestation record has an unsupported type"
                )

        out_of_range_attempt = copy.deepcopy(source)
        out_of_range_record = payload_record(out_of_range_attempt)
        out_of_range_record["evidenceCompletionCase"] = "attempt-out-of-range"
        before = signed_chain(out_of_range_attempt)
        relink_payload_attestation(out_of_range_attempt, seeds)
        after_relink = signed_chain(out_of_range_attempt)
        self.assertTrue(R._signed_inner_artifact_valid(
            out_of_range_record, R.PAYLOAD_ATTESTATION_DOMAIN, self.pubkeys
        ))
        # Values beyond the JCS safe-integer range cannot themselves be signed.
        # Mutate only after proving the complete relinked chain is coherent.
        out_of_range_record["attempt"] = 2 ** 53
        self.assertNotEqual(after_relink, before)
        self.assertFalse(
            R._payload_attestation_record_shape_valid(out_of_range_record)
        )
        disposition, reason, _ = derive_phase_disposition(
            out_of_range_attempt, self.pubkeys
        )
        self.assertEqual(disposition, "error", reason)
        self.assertEqual(reason, "payload attestation record is malformed")

        malformed_signatures = (
            [],
            {"algorithm": "ed25519", "signer": "did:demos:orchestrator"},
            {"algorithm": "rsa", "signer": "did:demos:orchestrator", "value": "AA"},
            {"algorithm": "ed25519", "signer": [], "value": "AA"},
            {"algorithm": "ed25519", "signer": "did:demos:orchestrator", "value": "="},
        )
        for index, signature in enumerate(malformed_signatures):
            authority = copy.deepcopy(source)
            record = payload_record(authority)
            record["evidenceCompletionCase"] = f"signature-{index}"
            before = signed_chain(authority)
            relink_payload_attestation(authority, seeds)
            after_relink = signed_chain(authority)
            self.assertTrue(R._signed_inner_artifact_valid(
                record, R.PAYLOAD_ATTESTATION_DOMAIN, self.pubkeys
            ))
            # A malformed signature envelope cannot verify by definition. Apply it
            # after proving the hash-excluded signature's outer chain is coherent.
            record["signature"] = copy.deepcopy(signature)
            with self.subTest(signature=signature):
                self.assertNotEqual(
                    after_relink["payloadSignature"], before["payloadSignature"]
                )
                self.assertNotEqual(
                    after_relink["attestationRef"], before["attestationRef"]
                )
                self.assertNotEqual(
                    after_relink["evidenceSignature"], before["evidenceSignature"]
                )
                self.assertNotEqual(
                    after_relink["bundleSignatures"], before["bundleSignatures"]
                )
                self.assertFalse(R._payload_attestation_record_shape_valid(record))
                disposition, reason, _ = derive_phase_disposition(
                    authority, self.pubkeys
                )
                self.assertEqual(disposition, "error", reason)
                self.assertEqual(reason, "payload attestation record is malformed")

        self.assertEqual(canonical_json(source), source_snapshot)

    def test_primary_consumer_executes_public_and_both_credential_storage_modes(self):
        storage = self.data["executionAuthorities"]["completed-storage-delivery"]
        storage_closure = storage["deliveryArtifactAuthorityByPhaseKey"][
            "0:deliver-storage-program"
        ]["deliverable"]
        self.assertEqual(
            storage["listing"]["offering"]["deliverable"].get(
                "accessModel", "public"
            ),
            "public",
        )
        self.assertEqual(
            storage_closure["storedContentHash"], storage_closure["cleartextHash"]
        )
        self.assertNotIn("storedHash", storage_closure)
        disposition, reason, _ = derive_phase_disposition(storage, self.pubkeys)
        self.assertEqual(disposition, "pass", reason)

        for access_model in ("buyer-only", "encrypt-to-buyer"):
            private_storage = copy.deepcopy(storage)
            listing = private_storage["listing"]
            listing["offering"]["deliverable"]["accessModel"] = access_model
            resign_listing(listing, self.data["seeds"]["seller"])
            private_storage["bundle"]["listingRef"]["contentHash"] = R.listing_hash(
                listing
            )
            resign_ebfab(private_storage["bundle"], self.data["seeds"])
            resolved_storage = private_storage[
                "deliveryArtifactAuthorityByPhaseKey"
            ]["0:deliver-storage-program"]["deliverable"]
            record = next(
                resolution["record"]
                for resolution in private_storage[
                    "referenceValidationByCanonicalRef"
                ].values()
                if resolution.get("record", {}).get("phase")
                == "deliver-storage-program"
            )
            storage_ref = {
                "anchor": copy.deepcopy(record["deliverableAnchor"]),
                "contentHash": record["deliverableContentHash"],
            }
            storage_authority = private_storage[
                "verifiedReceiptByCanonicalRef"
            ][R.canonical(storage_ref).decode("utf-8")]
            if access_model == "encrypt-to-buyer":
                stored_bytes = b"fixture encrypted storage payload"
                stored_hash = hashlib.sha256(stored_bytes).hexdigest()
                resolved_storage["storedBytesBase64url"] = encode(stored_bytes)
                resolved_storage["storedContentHash"] = stored_hash
                storage_authority["storageBinding"] = {
                    "effectiveAccessMode": "encrypt-to-buyer",
                    "storedContentHash": stored_hash,
                    "encryption": {
                        "recipient": "did:demos:buyer",
                        "ciphertextContentHash": stored_hash,
                    },
                }
            else:
                storage_authority["storageBinding"] = {
                    "effectiveAccessMode": "buyer-only",
                    "storedContentHash": resolved_storage["storedContentHash"],
                    "acl": {
                        "mode": "restricted",
                        "allowed": ["did:demos:buyer"],
                    },
                }
            disposition, reason, _ = derive_phase_disposition(
                private_storage, self.pubkeys
            )
            with self.subTest(storage_access_model=access_model):
                self.assertEqual(disposition, "pass", reason)

        buyer_only = self.data["executionAuthorities"]["repeated-pay-completed"]
        buyer_credential = buyer_only["deliveryArtifactAuthorityByPhaseKey"][
            "2:deliver-entitlement"
        ]["credential"]
        exact_result, exact_bytes = R._exact_base64url_bytes(
            buyer_credential["cleartextBytesBase64url"], "buyer-only credential"
        )
        self.assertEqual(exact_result[0], "pass")
        self.assertEqual(
            hashlib.sha256(exact_bytes).hexdigest(),
            buyer_credential["storedContentHash"],
        )
        disposition, reason, _ = derive_phase_disposition(buyer_only, self.pubkeys)
        self.assertEqual(disposition, "pass", reason)

        encrypted = copy.deepcopy(buyer_only)
        encrypted_closure = encrypted["deliveryArtifactAuthorityByPhaseKey"][
            "2:deliver-entitlement"
        ]
        entitlement = encrypted_closure["entitlementRecord"]["artifact"]
        credential = encrypted_closure["credential"]
        ciphertext = b"fixture encrypted credential"
        ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
        credential_ref = copy.deepcopy(entitlement["credentialRef"])
        old_credential_ref = copy.deepcopy(credential_ref["ref"])
        credential_ref["accessModel"] = "encrypt-to-buyer"
        credential_ref["ref"]["contentHash"] = ciphertext_hash
        entitlement["credentialRef"] = credential_ref
        resign_inner_artifact(
            entitlement, self.data["seeds"]["seller"], R.ENTITLEMENT_DOMAIN
        )
        entitlement_hash = R._signed_envelope_content_hash(entitlement)
        credential["credentialRef"] = copy.deepcopy(credential_ref)
        credential["storedBytesBase64url"] = encode(ciphertext)
        credential["storedContentHash"] = ciphertext_hash
        move_verified_receipt(
            encrypted, old_credential_ref, credential_ref["ref"]
        )
        credential_receipt = encrypted["verifiedReceiptByCanonicalRef"][
            R.canonical(credential_ref["ref"]).decode("utf-8")
        ]
        credential_receipt["storageBinding"] = {
            "effectiveAccessMode": "encrypt-to-buyer",
            "storedContentHash": ciphertext_hash,
            "encryption": {
                "recipient": "did:demos:buyer",
                "ciphertextContentHash": ciphertext_hash,
            },
        }

        def bind_encrypted_credential(record):
            record["deliverableContentHash"] = entitlement_hash
            record["credentialDelivery"]["credentialRef"] = copy.deepcopy(
                credential_ref
            )

        replace_top_record(
            encrypted,
            "deliver-entitlement",
            bind_encrypted_credential,
            self.data["seeds"],
        )
        self.assertNotEqual(
            credential["storedContentHash"], credential["cleartextHash"]
        )
        disposition, reason, _ = derive_phase_disposition(encrypted, self.pubkeys)
        self.assertEqual(disposition, "pass", reason)

        for mutation in ("missing", None, "AA==", 1):
            authority = copy.deepcopy(buyer_only)
            resolved = authority["deliveryArtifactAuthorityByPhaseKey"][
                "2:deliver-entitlement"
            ]["credential"]
            if mutation == "missing":
                resolved.pop("cleartextBytesBase64url")
                expected = "indeterminate"
            else:
                resolved["cleartextBytesBase64url"] = mutation
                expected = "indeterminate" if mutation is None else "error"
            disposition, reason, _ = derive_phase_disposition(authority, self.pubkeys)
            with self.subTest(exact_bytes=mutation):
                self.assertEqual(disposition, expected, reason)

    def test_primary_dependency_availability_uses_the_shared_strict_contract(self):
        dependencies = (
            ("completed-storage-delivery", "0:deliver-storage-program", "deliverable"),
            ("repeated-pay-completed", "2:deliver-entitlement", "entitlementRecord"),
            ("repeated-pay-completed", "2:deliver-entitlement", "credential"),
            ("standard-completed", "3:deliver-attested-payload", "deliverable"),
            ("standard-completed", "3:deliver-attested-payload", "payloadAttestationRecord"),
            ("standard-completed", "3:deliver-attested-payload", "methodEvidence"),
        )
        for authority_name, phase_key, dependency in dependencies:
            unavailable = copy.deepcopy(self.data["executionAuthorities"][authority_name])
            unavailable["deliveryArtifactAuthorityByPhaseKey"][phase_key][dependency][
                "available"
            ] = False
            disposition, reason, _ = derive_phase_disposition(unavailable, self.pubkeys)
            with self.subTest(dependency=dependency, availability=False):
                self.assertEqual(disposition, "indeterminate", reason)

            missing = copy.deepcopy(self.data["executionAuthorities"][authority_name])
            missing["deliveryArtifactAuthorityByPhaseKey"][phase_key].pop(dependency)
            disposition, reason, _ = derive_phase_disposition(missing, self.pubkeys)
            with self.subTest(dependency=dependency, availability="missing-entry"):
                self.assertEqual(disposition, "indeterminate", reason)

            malformed_entry = copy.deepcopy(
                self.data["executionAuthorities"][authority_name]
            )
            malformed_entry["deliveryArtifactAuthorityByPhaseKey"][phase_key][
                dependency
            ] = []
            disposition, reason, _ = derive_phase_disposition(
                malformed_entry, self.pubkeys
            )
            with self.subTest(dependency=dependency, availability="non-mapping"):
                self.assertEqual(disposition, "error", reason)

            for malformed in (None, "true", 1, 0):
                authority = copy.deepcopy(
                    self.data["executionAuthorities"][authority_name]
                )
                authority["deliveryArtifactAuthorityByPhaseKey"][phase_key][
                    dependency
                ]["available"] = malformed
                disposition, reason, _ = derive_phase_disposition(
                    authority, self.pubkeys
                )
                with self.subTest(dependency=dependency, availability=malformed):
                    self.assertEqual(disposition, "error", reason)

    def test_reference_canonical_uses_repository_jcs_without_ascii_hash_churn(self):
        from scripts.jcs import canonicalize

        for value, expected in ((1.0, "1"), (-0.0, "0"), (1e-7, "1e-7")):
            with self.subTest(value=value):
                self.assertEqual(R.canonical({"n": value}), ('{"n":' + expected + '}').encode())
        ascii_value = {"a": 1, "z": ["ASCII", True]}
        historical = json.dumps(
            ascii_value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        self.assertEqual(R.canonical(ascii_value), historical)
        self.assertEqual(R.canonical(ascii_value), canonicalize(ascii_value).encode())

    def test_resolution_binding_rejects_every_unauthenticated_dimension(self):
        mutations = {
            "execution-job": ("sessionExecutionAuthorityByPhaseKey", "jobId", "other-job"),
            "execution-index": ("sessionExecutionAuthorityByPhaseKey", "phaseIndex", 99),
            "execution-kind": ("sessionExecutionAuthorityByPhaseKey", "phaseKind", "pay-other"),
            "execution-orchestrator": (
                "sessionExecutionAuthorityByPhaseKey",
                "phaseOrchestrator",
                "did:demos:buyer",
            ),
            "execution-rail": ("sessionExecutionAuthorityByPhaseKey", "railId", "other-rail"),
            "receipt-logical": (
                "verifiedReceiptByCanonicalRef", "logicalAddress", "dacs4:payment:forged"),
            "receipt-native": ("verifiedReceiptByCanonicalRef", "nativeAddress", "stor-forged"),
            "receipt-content": ("verifiedReceiptByCanonicalRef", "contentHash", "00" * 32),
            "receipt-transaction": (
                "verifiedReceiptByCanonicalRef",
                "transactionRef",
                {"kind": "demos-transaction", "value": ""},
            ),
            "receipt-writer": (
                "verifiedReceiptByCanonicalRef", "writer", "did:demos:buyer"),
            "receipt-nonce": ("verifiedReceiptByCanonicalRef", "nonce", -1),
        }
        for name, (authority_map, field, value) in mutations.items():
            authority = copy.deepcopy(self.data["executionAuthorities"]["standard-completed"])
            entry = next(iter(authority[authority_map].values()))
            entry[field] = value
            with self.subTest(mutation=name):
                self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

        authority = copy.deepcopy(self.data["executionAuthorities"]["standard-completed"])
        resolution = next(iter(authority["referenceValidationByCanonicalRef"].values()))
        resolution["executionAuthority"] = {"railId": "forged-rail"}
        resolution["anchorReceipt"] = {"logicalAddress": "dacs4:payment:forged"}
        self.assertIsNotNone(derive_phase_keys(authority, self.pubkeys))

    def test_attestation_ref_shape_and_resolved_address_are_exact(self):
        malformed_ref = copy.deepcopy(
            self.data["executionAuthorities"]["standard-completed"]["bundle"]
            ["settlementEvidence"][0]
        )
        del malformed_ref["anchor"]
        self.assertFalse(R._attestation_ref_shape_valid(malformed_ref))

        authority = copy.deepcopy(self.data["executionAuthorities"]["single-htlc-completed"])
        receipt = next(
            value
            for ref, value in authority["verifiedReceiptByCanonicalRef"].items()
            if authority["referenceValidationByCanonicalRef"][ref]["record"].get(
                "supersedesEvidenceRef") is not None
        )
        receipt["logicalAddress"] = "dacs4:payment:forged:resolved"
        self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

    def test_attestation_ref_rejects_unknown_anchor_kind_at_the_real_gate(self):
        authority = copy.deepcopy(self.data["executionAuthorities"]["standard-completed"])
        old_ref = authority["bundle"]["settlementEvidence"][0]
        old_key = R.canonical(old_ref).decode("utf-8")
        new_ref = copy.deepcopy(old_ref)
        new_ref["anchor"]["kind"] = "bogus"
        new_key = R.canonical(new_ref).decode("utf-8")
        authority["referenceValidationByCanonicalRef"][new_key] = (
            authority["referenceValidationByCanonicalRef"].pop(old_key)
        )
        authority["verifiedReceiptByCanonicalRef"][new_key] = (
            authority["verifiedReceiptByCanonicalRef"].pop(old_key)
        )
        authority["bundle"]["settlementEvidence"][0] = new_ref
        authority["bundle"]["phaseSummary"][2]["attestationRef"] = new_ref
        resign_ebfab(authority["bundle"], self.data["seeds"])

        self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

    def test_malformed_membership_operands_fail_closed_without_raising(self):
        mutations = {
            "bundle-outcome": lambda a: a["bundle"].__setitem__("outcome", []),
            "anchored-role": lambda a: a["bundle"].__setitem__("anchoredByRole", []),
            "party-role": lambda a: a["bundle"]["parties"][0].__setitem__("role", []),
            "phase-outcome": lambda a: a["bundle"]["phaseSummary"][0].__setitem__("outcome", []),
            "listing-signer": lambda a: (
                a["listing"].__setitem__("sellerPrimaryClaim", []),
                a["listing"]["signature"].__setitem__("signer", []),
            ),
            "evidence-signer": lambda a: next(
                iter(a["referenceValidationByCanonicalRef"].values())
            )["record"]["signature"].__setitem__("signer", []),
        }
        for name, mutate in mutations.items():
            authority = copy.deepcopy(self.data["executionAuthorities"]["standard-completed"])
            mutate(authority)
            with self.subTest(mutation=name):
                self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

    def test_signed_listing_rejects_unknown_phase_before_deriving_empty_evidence(self):
        for phase in (
            "pay-future",
            "negotiate-sealed-envelope-procurement",
            "commit-payee-bound-agreement",
            "commit-identity-bound-agreement",
            "commit-identity-bound-payee-agreement",
        ):
            authority = copy.deepcopy(self.data["executionAuthorities"]["aborted-before-result"])
            authority["listing"]["pipeline"][0]["kind"] = phase
            resign_listing(authority["listing"], self.data["seeds"]["seller"])
            authority["bundle"]["listingRef"]["contentHash"] = R.listing_hash(authority["listing"])
            resign_ebfab(authority["bundle"], self.data["seeds"])
            with self.subTest(phase=phase):
                self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

    def test_complete_settlement_evidence_shape_is_required(self):
        cases = (
            ("standard-completed", "pay-dem", "observedAt"),
            ("standard-completed", "pay-dem", "paymentAmount"),
            ("standard-completed", "pay-dem", "settlementFinality"),
            ("standard-completed", "deliver-attested-payload", "deliverableContentHash"),
            ("failed-delivery", "deliver-storage-program", "reason"),
        )
        for authority_name, phase, field in cases:
            authority = copy.deepcopy(self.data["executionAuthorities"][authority_name])
            replace_top_record(
                authority,
                phase,
                lambda record, field=field: record.pop(field),
                self.data["seeds"],
            )
            with self.subTest(authority=authority_name, phase=phase, missing=field):
                self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

    def test_expired_st8_rejects_a_known_authenticated_successor(self):
        authority = copy.deepcopy(self.data["executionAuthorities"]["single-htlc-expired"])
        interim_ref = copy.deepcopy(authority["bundle"]["settlementEvidence"][0])
        interim_key = R.canonical(interim_ref).decode("utf-8")
        interim = authority["referenceValidationByCanonicalRef"][interim_key]
        record = copy.deepcopy(interim["record"])
        record.pop("reason")
        record["outcome"] = "success"
        record["paymentTxRefs"] = valid_htlc_tx_refs()
        record["paymentAmount"] = {"amount": "1", "currency": "DEM"}
        record["settlementFinality"] = {
            "model": "htlc-reveal",
            "finalityObservedAt": record["observedAt"],
        }
        record["supersedesEvidenceRef"] = interim_ref
        resign_evidence(record, self.data["seeds"]["seller"])
        successor_ref = {
            "anchor": {"kind": "storage-program", "locator": "stor-known-successor"},
            "contentHash": R.settlement_evidence_hash(record),
        }
        successor_key = R.canonical(successor_ref).decode("utf-8")
        authority["referenceValidationByCanonicalRef"][successor_key] = {
            "record": record,
            "lifecycle": {"state": "finalized", "independentlyResolvable": True},
        }
        successor_receipt = copy.deepcopy(
            authority["verifiedReceiptByCanonicalRef"][interim_key]
        )
        successor_receipt.update({
            "logicalAddress": "dacs4:payment:%s:test-rail:2:resolved"
            % authority["bundle"]["jobId"],
            "nativeAddress": "stor-known-successor",
            "contentHash": successor_ref["contentHash"],
        })
        authority["verifiedReceiptByCanonicalRef"][successor_key] = successor_receipt

        self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

    def test_finality_bound_st8_successor_is_not_missed_by_expiry_scan(self):
        authority = copy.deepcopy(self.data["executionAuthorities"]["single-htlc-expired"])
        interim_ref = copy.deepcopy(authority["bundle"]["settlementEvidence"][0])
        interim_key = R.canonical(interim_ref).decode("utf-8")
        record = copy.deepcopy(authority["referenceValidationByCanonicalRef"][interim_key]["record"])
        record.pop("evidenceVersion")
        record.pop("reason")
        record["finalityBoundEvidenceVersion"] = "1"
        record["outcome"] = "success"
        record["paymentTxRefs"] = valid_htlc_tx_refs()
        record["paymentTxRefs"].append({
            "kind": "htlc-lock", "chainId": 2,
            "contractAddress": "0xcontract", "lockTxHash": "0xother-lock",
        })
        record["paymentAmount"] = {"amount": "1", "currency": "DEM"}
        record["settlementFinality"] = {
            "model": "htlc-reveal", "finalityObservedAt": record["observedAt"],
        }
        record["railDefinitionRef"] = {
            "anchor": {"kind": "storage-program", "locator": "stor-rail"},
            "contentHash": "a" * 64,
            "railId": "test-rail", "railVersion": 1,
        }
        record["supersedesEvidenceRef"] = interim_ref
        digest = R.settlement_evidence_hash(record)
        record["signature"]["value"] = encode(
            Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(self.data["seeds"]["seller"])
            ).sign((R.FINALITY_BOUND_SETTLEMENT_EVIDENCE_DOMAIN + digest).encode("utf-8"))
        )
        successor_ref = {
            "anchor": {"kind": "storage-program", "locator": "stor-finality-successor"},
            "contentHash": digest,
        }
        successor_key = R.canonical(successor_ref).decode("utf-8")
        authority["referenceValidationByCanonicalRef"][successor_key] = {
            "record": record,
            "lifecycle": {"state": "finalized", "independentlyResolvable": True},
        }
        successor_receipt = copy.deepcopy(authority["verifiedReceiptByCanonicalRef"][interim_key])
        successor_receipt.update({
            "logicalAddress": "dacs4:payment:%s:test-rail:2:resolved"
            % authority["bundle"]["jobId"],
            "nativeAddress": "stor-finality-successor",
            "contentHash": digest,
        })
        authority["verifiedReceiptByCanonicalRef"][successor_key] = successor_receipt
        args = (
            interim_ref,
            authority["referenceValidationByCanonicalRef"][interim_key]["record"],
            "2:pay-cross-chain-htlc", authority["bundle"], self.pubkeys,
            authority["referenceValidationByCanonicalRef"],
            authority["sessionExecutionAuthorityByPhaseKey"],
            authority["verifiedReceiptByCanonicalRef"],
            R._validate_current_evidence_receipt,
        )
        self.assertTrue(R._finality_bound_settlement_evidence_shape_valid(record))
        self.assertEqual("finality-bound", R._authenticated_evidence_wire_type(record, self.pubkeys))
        self.assertTrue(R._resolve_authenticated_evidence_binding(
            successor_ref, record, record["signature"]["signer"], authority["bundle"],
            authority["sessionExecutionAuthorityByPhaseKey"],
            authority["verifiedReceiptByCanonicalRef"], "finality-bound",
        )[0])
        self.assertTrue(R._known_authenticated_st8_successor(
            *args, expected_kind="finality-bound"
        ))
        self.assertFalse(R._known_authenticated_st8_successor(
            *args, expected_kind="evidence-bound"
        ))

    def test_transitive_st8_record_requires_the_complete_settlement_shape(self):
        authority = copy.deepcopy(self.data["executionAuthorities"]["single-htlc-completed"])
        bundle = authority["bundle"]
        old_top_ref = bundle["settlementEvidence"][0]
        old_top_key = R.canonical(old_top_ref).decode("utf-8")
        top_resolution = authority["referenceValidationByCanonicalRef"].pop(old_top_key)
        top_receipt = authority["verifiedReceiptByCanonicalRef"].pop(old_top_key)
        successor = top_resolution["record"]

        old_interim_ref = successor["supersedesEvidenceRef"]
        old_interim_key = R.canonical(old_interim_ref).decode("utf-8")
        interim_resolution = authority["referenceValidationByCanonicalRef"].pop(old_interim_key)
        interim_receipt = authority["verifiedReceiptByCanonicalRef"].pop(old_interim_key)
        interim = interim_resolution["record"]
        interim.pop("observedAt")
        resign_evidence(interim, self.data["seeds"]["seller"])
        new_interim_ref = copy.deepcopy(old_interim_ref)
        new_interim_ref["contentHash"] = R.settlement_evidence_hash(interim)
        new_interim_key = R.canonical(new_interim_ref).decode("utf-8")
        interim_receipt["contentHash"] = new_interim_ref["contentHash"]
        authority["referenceValidationByCanonicalRef"][new_interim_key] = interim_resolution
        authority["verifiedReceiptByCanonicalRef"][new_interim_key] = interim_receipt

        successor["supersedesEvidenceRef"] = new_interim_ref
        resign_evidence(successor, self.data["seeds"]["seller"])
        new_top_ref = copy.deepcopy(old_top_ref)
        new_top_ref["contentHash"] = R.settlement_evidence_hash(successor)
        new_top_key = R.canonical(new_top_ref).decode("utf-8")
        top_receipt["contentHash"] = new_top_ref["contentHash"]
        authority["referenceValidationByCanonicalRef"][new_top_key] = top_resolution
        authority["verifiedReceiptByCanonicalRef"][new_top_key] = top_receipt
        bundle["settlementEvidence"][0] = new_top_ref
        bundle["phaseSummary"][-1]["attestationRef"] = new_top_ref
        resign_ebfab(bundle, self.data["seeds"])

        self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

    def test_non_finite_timestamps_and_non_ascii_or_malformed_amounts_fail_closed(self):
        cases = (
            ("observedAt", float("nan")),
            ("observedAt", float("inf")),
            ("observedAt", 10 ** 1000),
            ("settlementFinality.finalityObservedAt", float("-inf")),
            ("paymentAmount.amount", "1.x"),
            ("paymentAmount.amount", "١.٥"),
            ("paymentAmount.unit", None),
        )
        for path, value in cases:
            authority = copy.deepcopy(self.data["executionAuthorities"]["standard-completed"])
            def mutate(record, path=path, value=value):
                target = record
                parts = path.split(".")
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = value
            replace_top_record(authority, "pay-dem", mutate, self.data["seeds"])
            with self.subTest(path=path, value=value):
                self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

        authority = copy.deepcopy(self.data["executionAuthorities"]["standard-completed"])
        record = next(
            resolution["record"]
            for resolution in authority["referenceValidationByCanonicalRef"].values()
            if resolution.get("record", {}).get("phase") == "pay-dem"
        )
        record["paymentAmount"]["currency"] = "\ud800"
        self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

        authority = copy.deepcopy(self.data["executionAuthorities"]["standard-completed"])
        replace_top_record(
            authority,
            "pay-dem",
            lambda record: record["paymentAmount"].__setitem__("amount", "0.0001"),
            self.data["seeds"],
        )
        self.assertEqual(
            derive_phase_keys(authority, self.pubkeys),
            ["2:pay-dem", "3:deliver-attested-payload"],
        )

    def test_settlement_nested_numeric_and_transaction_shapes_fail_closed(self):
        cases = (
            ("settlementFinality.finalityBlocks", 10 ** 1000),
            ("paymentTxRefs", None),
            ("paymentTxRefs", []),
            ("paymentTxRefs", [{}]),
            ("paymentTxRefs", [{"kind": "demos", "txHash": "tx", "blockNumber": 10 ** 1000}]),
            ("paymentTxRefs", [{"kind": "future", "payload": {"nested": []}}]),
            ("paymentTxRefs", [{"kind": "evm", "chainId": 1, "txHash": "0x01"}]),
            ("settlementFinality", {"model": "block-depth", "finalityBlocks": 1,
                                    "finalityObservedAt": 1}),
        )
        for path, value in cases:
            authority = copy.deepcopy(self.data["executionAuthorities"]["standard-completed"])

            def mutate(record, path=path, value=value):
                if path == "settlementFinality.finalityBlocks":
                    record["settlementFinality"] = {
                        "model": "block-depth",
                        "finalityBlocks": value,
                        "finalityObservedAt": record["observedAt"],
                    }
                elif path == "paymentTxRefs" and value is None:
                    record.pop(path)
                else:
                    record[path] = value

            replace_top_record(authority, "pay-dem", mutate, self.data["seeds"])
            with self.subTest(path=path, value=value):
                self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

        authority = copy.deepcopy(self.data["executionAuthorities"]["single-htlc-completed"])
        replace_top_record(
            authority,
            "pay-cross-chain-htlc",
            lambda record: record.__setitem__("paymentTxRefs", valid_htlc_tx_refs()[:1]),
            self.data["seeds"],
        )
        self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

        authority = copy.deepcopy(self.data["executionAuthorities"]["single-htlc-completed"])
        replace_top_record(
            authority,
            "pay-cross-chain-htlc",
            lambda record: record["paymentTxRefs"].append({
                "kind": "htlc-refund", "chainId": 1,
                "contractAddress": "0xcontract", "refundTxHash": "0xrefund",
            }),
            self.data["seeds"],
        )
        self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

        x402_event = {
            "kind": "x402-event", "httpResource": "https://example.test",
            "paymentReceiptHash": "ab" * 32, "settlementTxHash": "0x01",
            "chainId": 1, "logIndex": 0, "protocolVersion": "1",
        }
        legacy_x402 = {
            "kind": "x402", "httpResource": "https://example.test",
            "paymentReceiptHash": "ab" * 32, "protocolVersion": "1",
        }
        self.assertTrue(R._settlement_finality_matches_phase(
            "pay-x402", {"model": "block-depth"}, [x402_event]
        ))
        self.assertTrue(R._settlement_finality_matches_phase(
            "pay-x402", {"model": "provider-receipt"}, [legacy_x402]
        ))
        self.assertFalse(R._settlement_finality_matches_phase(
            "pay-x402", {"model": "provider-receipt"}, [x402_event]
        ))
        self.assertFalse(R._settlement_finality_matches_phase(
            "pay-x402", {"model": "block-depth"}, [legacy_x402]
        ))

    def test_delivery_evidence_rejects_payment_refs_and_narrows_storage_anchor(self):
        cases = (
            (
                "standard-completed",
                "deliver-attested-payload",
                lambda record: record.__setitem__(
                    "paymentTxRefs", [{"kind": "demos", "txHash": "tx"}]
                ),
            ),
            (
                "standard-completed",
                "deliver-attested-payload",
                lambda record: record.__setitem__(
                    "deliverableAnchor", {
                        "kind": "payload-store",
                        "locator": record["deliverableAnchor"]["locator"],
                    }
                ),
            ),
        )
        for authority_name, phase, mutate in cases:
            authority = copy.deepcopy(self.data["executionAuthorities"][authority_name])
            replace_top_record(authority, phase, mutate, self.data["seeds"])
            if "paymentTxRefs" in next(
                resolution["record"]
                for resolution in authority["referenceValidationByCanonicalRef"].values()
                if resolution.get("record", {}).get("phase") == phase
            ):
                self.assertIsNone(derive_phase_keys(authority, self.pubkeys))
            else:
                # DACS-4 §9.7 leaves payload-location kinds open; this must remain valid.
                self.assertEqual(
                    derive_phase_keys(authority, self.pubkeys),
                    ["2:pay-dem", "3:deliver-attested-payload"],
                )

        storage_record = {
            "evidenceVersion": "1",
            "jobId": "job",
            "phase": "deliver-storage-program",
            "outcome": "success",
            "deliverableContentHash": "ab" * 32,
            "deliverableAnchor": {"kind": "bogus", "locator": "location"},
            "observedAt": 1,
            "signature": {"algorithm": "ed25519", "signer": "did:demos:seller", "value": "x"},
        }
        self.assertFalse(R._settlement_evidence_shape_valid(storage_record))
        storage_record["deliverableAnchor"]["kind"] = "storage-program"
        self.assertTrue(R._settlement_evidence_shape_valid(storage_record))

        malformed_attestation = {
            "anchor": {"kind": "storage-program", "locator": "\ud800"},
            "contentHash": "ab" * 32,
        }
        self.assertFalse(R._attestation_ref_shape_valid(malformed_attestation))
        storage_record["signature"]["value"] = "\ud800"
        self.assertFalse(R._settlement_evidence_shape_valid(storage_record))

    def test_chain_transaction_reference_union_accepts_each_closed_arm(self):
        attestation = {
            "anchor": {"kind": "storage-program", "locator": "stor-receipt"},
            "contentHash": "ab" * 32,
            "signer": "did:demos:provider",
        }
        refs = (
            {"kind": "evm", "chainId": 1, "txHash": "0x01"},
            {"kind": "evm-event", "chainId": 1, "txHash": "0x01", "logIndex": 0},
            {"kind": "solana", "cluster": "mainnet", "signature": "1" * 64},
            {"kind": "solana-instruction", "cluster": "devnet", "signature": "1" * 64, "instructionIndex": 0},
            {"kind": "demos", "txHash": "tx", "blockNumber": 1},
            {"kind": "storage-program", "address": "stor", "writeTxHash": "tx"},
            {"kind": "ap2", "mandateId": "m", "providerRef": "p", "protocolVersion": "1", "receiptAttestation": attestation},
            {"kind": "x402", "httpResource": "https://example.test", "paymentReceiptHash": "ab" * 32, "protocolVersion": "1"},
            {"kind": "x402-event", "httpResource": "https://example.test", "paymentReceiptHash": "ab" * 32, "settlementTxHash": "0x01", "chainId": 1, "logIndex": 0, "protocolVersion": "1"},
            {"kind": "htlc-lock", "chainId": 1, "contractAddress": "0x01", "lockTxHash": "0x02"},
            {"kind": "htlc-reveal", "chainId": 1, "contractAddress": "0x01", "revealTxHash": "0x02"},
            {"kind": "htlc-claim", "chainId": 1, "contractAddress": "0x01", "claimTxHash": "0x02"},
            {"kind": "htlc-refund", "chainId": 1, "contractAddress": "0x01", "refundTxHash": "0x02"},
            {"kind": "liquidity-tank", "bridgeId": "b", "sourceChainId": 1, "destChainId": 2, "lockTxHash": "0x01", "releaseTxHash": "0x02", "recoveryDeadline": 1},
        )
        for ref in refs:
            with self.subTest(kind=ref["kind"]):
                self.assertTrue(R._chain_tx_ref_shape_valid(ref))

        malformed = copy.deepcopy(attestation)
        malformed["signer"] = "x"
        self.assertFalse(R._chain_tx_ref_shape_valid({
            "kind": "ap2", "mandateId": "m", "providerRef": "p",
            "protocolVersion": "1", "receiptAttestation": malformed,
        }))

    def test_claim_reference_gate_enforces_generic_cf2_canonical_form(self):
        for value in (
            "did:demos:seller",
            "cci-xm:evm:8453:0x1234?jurisdiction=US&scope=settlement",
        ):
            with self.subTest(valid=value):
                self.assertTrue(R._claim_reference_shape_valid(value))
        for value in (
            "x",
            "DID:demos:seller",
            "did:e\u0301",
            "did:demos:seller?scope=x&jurisdiction=US",
            "did:demos:seller?scope=bad%3aescape",
            "did:demos:seller?scope=a=b",
        ):
            with self.subTest(invalid=value):
                self.assertFalse(R._claim_reference_shape_valid(value))

    def test_attestation_signer_requires_a_canonical_claim_reference_at_the_real_gate(self):
        authority = copy.deepcopy(self.data["executionAuthorities"]["standard-completed"])
        old_ref = authority["bundle"]["settlementEvidence"][0]
        old_key = R.canonical(old_ref).decode("utf-8")
        new_ref = copy.deepcopy(old_ref)
        new_ref["signer"] = "x"
        new_key = R.canonical(new_ref).decode("utf-8")
        authority["referenceValidationByCanonicalRef"][new_key] = (
            authority["referenceValidationByCanonicalRef"].pop(old_key)
        )
        authority["verifiedReceiptByCanonicalRef"][new_key] = (
            authority["verifiedReceiptByCanonicalRef"].pop(old_key)
        )
        authority["bundle"]["settlementEvidence"][0] = new_ref
        authority["bundle"]["phaseSummary"][2]["attestationRef"] = new_ref
        resign_ebfab(authority["bundle"], self.data["seeds"])

        self.assertFalse(R._attestation_ref_shape_valid(new_ref))
        self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

    def test_malformed_reference_map_keys_cannot_crash_st8_expiry_validation(self):
        authority = copy.deepcopy(self.data["executionAuthorities"]["single-htlc-expired"])
        authority["referenceValidationByCanonicalRef"]["[" * 1200 + "]" * 1200] = {}
        self.assertEqual(
            derive_phase_keys(authority, self.pubkeys),
            ["2:pay-cross-chain-htlc"],
        )

    def test_long_shape_valid_st8_successor_reference_cannot_evade_the_scan(self):
        authority = copy.deepcopy(self.data["executionAuthorities"]["single-htlc-expired"])
        interim_ref = copy.deepcopy(authority["bundle"]["settlementEvidence"][0])
        interim_key = R.canonical(interim_ref).decode("utf-8")
        record = copy.deepcopy(authority["referenceValidationByCanonicalRef"][interim_key]["record"])
        record.pop("reason")
        record["outcome"] = "success"
        record["paymentTxRefs"] = valid_htlc_tx_refs()
        record["paymentAmount"] = {"amount": "0.1", "currency": "DEM"}
        record["settlementFinality"] = {
            "model": "htlc-reveal",
            "finalityObservedAt": record["observedAt"],
        }
        record["supersedesEvidenceRef"] = interim_ref
        resign_evidence(record, self.data["seeds"]["seller"])
        locator = "stor-" + "x" * 17_000
        successor_ref = {
            "anchor": {"kind": "storage-program", "locator": locator},
            "contentHash": R.settlement_evidence_hash(record),
        }
        successor_key = R.canonical(successor_ref).decode("utf-8")
        authority["referenceValidationByCanonicalRef"][successor_key] = {
            "record": record,
            "lifecycle": {"state": "finalized", "independentlyResolvable": True},
        }
        successor_receipt = copy.deepcopy(
            authority["verifiedReceiptByCanonicalRef"][interim_key]
        )
        successor_receipt.update({
            "logicalAddress": "dacs4:payment:%s:test-rail:2:resolved"
            % authority["bundle"]["jobId"],
            "nativeAddress": locator,
            "contentHash": successor_ref["contentHash"],
        })
        authority["verifiedReceiptByCanonicalRef"][successor_key] = successor_receipt

        self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

    def test_ebfab_shape_and_retry_marker_fail_closed(self):
        for parties in (None, [None]):
            authority = copy.deepcopy(self.data["executionAuthorities"]["standard-completed"])
            authority["bundle"]["parties"] = parties
            with self.subTest(parties=parties):
                self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

        for marker in (True, False, "true"):
            authority = copy.deepcopy(self.data["executionAuthorities"]["standard-completed"])
            authority["bundle"]["phaseSummary"][0]["retryExhausted"] = marker
            resign_ebfab(authority["bundle"], self.data["seeds"])
            with self.subTest(marker=marker):
                self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

    def test_st8_supersedes_requires_a_complete_attestation_ref(self):
        authority = copy.deepcopy(self.data["executionAuthorities"]["single-htlc-completed"])
        old_top_ref = authority["bundle"]["settlementEvidence"][0]
        old_top_key = R.canonical(old_top_ref).decode("utf-8")
        top_resolution = authority["referenceValidationByCanonicalRef"].pop(old_top_key)
        top_receipt = authority["verifiedReceiptByCanonicalRef"].pop(old_top_key)
        record = top_resolution["record"]
        old_interim_ref = copy.deepcopy(record["supersedesEvidenceRef"])
        old_interim_key = R.canonical(old_interim_ref).decode("utf-8")
        malformed_interim_ref = copy.deepcopy(old_interim_ref)
        del malformed_interim_ref["anchor"]["kind"]
        record["supersedesEvidenceRef"] = malformed_interim_ref
        resign_evidence(record, self.data["seeds"]["seller"])

        new_top_ref = copy.deepcopy(old_top_ref)
        new_top_ref["contentHash"] = R.settlement_evidence_hash(record)
        new_top_key = R.canonical(new_top_ref).decode("utf-8")
        top_receipt["contentHash"] = new_top_ref["contentHash"]
        authority["referenceValidationByCanonicalRef"][new_top_key] = top_resolution
        authority["verifiedReceiptByCanonicalRef"][new_top_key] = top_receipt
        authority["referenceValidationByCanonicalRef"][
            R.canonical(malformed_interim_ref).decode("utf-8")
        ] = copy.deepcopy(authority["referenceValidationByCanonicalRef"][old_interim_key])
        authority["verifiedReceiptByCanonicalRef"][
            R.canonical(malformed_interim_ref).decode("utf-8")
        ] = copy.deepcopy(authority["verifiedReceiptByCanonicalRef"][old_interim_key])
        authority["bundle"]["settlementEvidence"] = [new_top_ref]
        authority["bundle"]["phaseSummary"][-1]["attestationRef"] = new_top_ref
        resign_ebfab(authority["bundle"], self.data["seeds"])

        self.assertFalse(R._attestation_ref_shape_valid(malformed_interim_ref))
        self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

    def test_declared_reason_precedence_matches_reference_evaluator(self):
        vector_input = {
            "executionAuthorityRef": "standard-completed",
            "topLevelRefs": ["wrong-phase", "wrong-outcome"],
            "authenticatedRecordByRef": {
                "wrong-phase": {
                    "jobId": "SEB-AUTHORITY-standard-completed",
                    "phaseKey": "99:pay-dem",
                    "outcome": "success",
                },
                "wrong-outcome": {
                    "jobId": "SEB-AUTHORITY-standard-completed",
                    "phaseKey": "3:deliver-attested-payload",
                    "outcome": "failure",
                },
            },
            "pointerMap": {},
            "unrelatedAuthorityDisposition": "verified",
        }
        self.assertEqual(
            evaluate(vector_input, self.data["executionAuthorities"], self.pubkeys),
            ("rejected", "st8-raw-admissibility"),
        )

    def test_minor_safe_type_boundary_and_domains(self):
        spec = SPEC.read_text(encoding="utf-8")
        core = CORE.read_text(encoding="utf-8")
        self.assertEqual(self.data["artifactType"], "EvidenceBoundFaultAttestationBundle")
        self.assertIn('evidenceBoundFaultBundleVersion: "1"', spec)
        self.assertIn("MUST NOT claim SEB validation", spec)
        self.assertIn('"dacs-evidence-bound-fault-bundle:v1:"', core)
        self.assertIn('"dacs-evidence-bound-fault-bundle-pointer:v1:"', core)


if __name__ == "__main__":
    unittest.main()
