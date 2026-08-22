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
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


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
    payload = (R.SETTLEMENT_EVIDENCE_DOMAIN + R.settlement_evidence_hash(record)).encode("utf-8")
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
            mutate(record)
            resign_evidence(record, seeds["seller"])
            new_ref = copy.deepcopy(old_ref)
            new_ref["contentHash"] = R.settlement_evidence_hash(record)
            new_key = R.canonical(new_ref).decode("utf-8")
            receipt["contentHash"] = new_ref["contentHash"]
            authority["referenceValidationByCanonicalRef"][new_key] = resolution
            authority["verifiedReceiptByCanonicalRef"][new_key] = receipt
            bundle["settlementEvidence"][index] = new_ref
            for entry in bundle["phaseSummary"]:
                if entry.get("attestationRef") == old_ref:
                    entry["attestationRef"] = new_ref
            resign_ebfab(bundle, seeds)
            return
    raise AssertionError("top-level record for phase %s not found" % phase)


def valid_htlc_tx_refs():
    return [
        {"kind": "htlc-lock", "chainId": 1, "contractAddress": "0xcontract", "lockTxHash": "0xlock"},
        {"kind": "htlc-reveal", "chainId": 2, "contractAddress": "0xcontract", "revealTxHash": "0xreveal"},
        {"kind": "htlc-claim", "chainId": 1, "contractAddress": "0xcontract", "claimTxHash": "0xclaim"},
    ]


def derive_phase_keys(authority, pubkeys):
    ok, _, phase_keys = R.validate_ebfab(
        authority.get("bundle"),
        authority.get("listing"),
        pubkeys,
        authority.get("referenceValidationByCanonicalRef"),
        authority.get("bundleLifecycle"),
        authority.get("sessionExecutionAuthorityByPhaseKey"),
        authority.get("verifiedReceiptByCanonicalRef"),
    )
    return phase_keys if ok else None


def evaluate(vector_data, authorities, pubkeys):
    authority = authorities.get(vector_data.get("executionAuthorityRef"))
    expected = derive_phase_keys(authority or {}, pubkeys)
    if expected is None:
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
            "receipt-transaction": ("verifiedReceiptByCanonicalRef", "transaction", ""),
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
        authority["verifiedReceiptByCanonicalRef"][successor_key] = {
            "logicalAddress": "dacs4:payment:%s:test-rail:2:resolved" % authority["bundle"]["jobId"],
            "nativeAddress": "stor-known-successor",
            "contentHash": successor_ref["contentHash"],
            "transaction": "tx-known-successor",
            "writer": "did:demos:seller",
            "nonce": 9,
        }

        self.assertIsNone(derive_phase_keys(authority, self.pubkeys))

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
                    "deliverableAnchor", {"kind": "payload-store", "locator": "payload-1"}
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
            {"kind": "solana", "cluster": "mainnet", "signature": "sig"},
            {"kind": "solana-instruction", "cluster": "devnet", "signature": "sig", "instructionIndex": 0},
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
        authority["verifiedReceiptByCanonicalRef"][successor_key] = {
            "logicalAddress": "dacs4:payment:%s:test-rail:2:resolved" % authority["bundle"]["jobId"],
            "nativeAddress": locator,
            "contentHash": successor_ref["contentHash"],
            "transaction": "tx-long-successor",
            "writer": "did:demos:seller",
            "nonce": 10,
        }

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
