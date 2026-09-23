import base64
import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
for path in (str(ROOT), str(TESTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from dacs5_reference import (  # noqa: E402
    BUNDLE_DOMAIN,
    bundle_hash,
    bundle_type,
    derive,
    derive_job_bound,
    reconcile_authenticated_finality_copies,
    resolve_legacy_absolute_fault_pointer,
    validate_ebfab,
    validate_legacy_ebfab,
    validate_finality_bound_ebfab,
)
from frozen_dacs5_v05_reader import (  # noqa: E402
    bundle_type as frozen_bundle_type,
    pointer_type as frozen_pointer_type,
)
from scripts.jcs import canonicalize  # noqa: E402
from scripts.settlement_finality_reference import verify_finality  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
import dacs5_reference as D5  # noqa: E402
import scripts.generate_settlement_finality_verification_vectors as finality_fixtures  # noqa: E402


VECTORS = ROOT / "conformance" / "vectors" / "security" / "settlement-finality-verification.json"
GENERATOR = ROOT / "scripts" / "generate_settlement_finality_verification_vectors.py"
MODELS = {
    "block-depth", "commitment-level", "bft-final", "provider-receipt",
    "htlc-reveal", "liquidity-tank",
}


def decode_public_keys(trust):
    return {
        signer: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        for signer, value in trust["partyKeys"].items()
    }


def merge(base, override):
    value = copy.deepcopy(base)
    for key, item in (override or {}).items():
        if isinstance(item, dict) and isinstance(value.get(key), dict):
            value[key] = merge(value[key], item)
        else:
            value[key] = copy.deepcopy(item)
    return value


class SettlementFinalityVerificationVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {case["name"]: case for case in cls.data["vectors"]}
        cls.trust = cls.data["trustedFixturePolicy"]
        cls.pubkeys = decode_public_keys(cls.trust)
        cls.strong = {
            case["model"]: case for case in cls.data["dacs5"]["strongBundleCases"]
        }

    def evaluate_case(self, case):
        trust = merge(self.trust, case.get("trustedOverrides"))
        return verify_finality(case["input"], trust)

    def strong_result(self, case, *, authority=None, trust=None):
        authority = authority or case["authority"]
        return validate_finality_bound_ebfab(
            case["bundle"],
            authority["listing"],
            self.pubkeys,
            authority["referenceValidationByCanonicalRef"],
            authority["bundleLifecycle"],
            authority["sessionExecutionAuthorityByPhaseKey"],
            authority["verifiedReceiptByCanonicalRef"],
            authority.get("finalityVerificationByCanonicalRef"),
            trust or self.trust,
            legacy_agreement_authority_by_phase_key=authority.get(
                "legacyAgreementAuthorityByPhaseKey"
            ),
        )

    def entry(self, bundle, authority=None, *, evidence_receipt_contract=None):
        role = bundle["anchoredByRole"]
        party = next(item for item in bundle["parties"] if item["role"] == role)
        presence = {
            "bundleHash": bundle_hash(bundle),
            "nativeAddress": "dacs5:bundle:%s:%s" % (bundle["jobId"], role),
            "writer": party["primaryClaim"],
        }
        self.trust.setdefault("copyPresenceByJobRole", {})[
            bundle["jobId"] + ":" + role
        ] = copy.deepcopy(presence)
        entry = {
            "bundle": bundle,
            "expectedJobId": bundle["jobId"],
            "expectedRole": role,
            "copyPresence": presence,
            "authority": authority,
        }
        if evidence_receipt_contract is not None:
            entry["evidenceReceiptContract"] = evidence_receipt_contract
        return entry

    @staticmethod
    def cross_agreement_authority(case):
        """Reclose LAA around a different verifier-owned agreement than FV trusts."""
        authority = copy.deepcopy(case["authority"])
        bundle = case["bundle"]
        ref = bundle["settlementEvidence"][0]
        ref_key = canonicalize(ref)
        resolution = authority["referenceValidationByCanonicalRef"][ref_key]
        phase_key = "0:" + resolution["record"]["phase"]
        alternate_hash = "33" * 32
        resolution["agreementHash"] = alternate_hash
        laa = authority["legacyAgreementAuthorityByPhaseKey"][phase_key]["laa"]
        laa["agreement"]["contentHash"] = alternate_hash
        authority["legacyAgreementAuthorityByPhaseKey"][phase_key] = (
            D5.make_laa_phase_carrier(
                laa, bundle, authority["listing"], phase_key,
                resolution["record"], ref,
                authority["verifiedReceiptByCanonicalRef"][ref_key],
                authority["sessionExecutionAuthorityByPhaseKey"][phase_key],
            )
        )
        return authority

    def resign_bundle(self, bundle):
        digest = bundle_hash(bundle)
        seed_names = {
            "did:demos:buyer": "buyer",
            "did:demos:seller": "seller",
            "did:demos:orchestrator": "orchestrator",
        }
        for signature in bundle["signatures"]:
            seed = bytes.fromhex(
                self.data["fixturePolicyMetadata"]["seeds"][seed_names[signature["party"]]]
            )
            value = Ed25519PrivateKey.from_private_bytes(seed).sign(
                (BUNDLE_DOMAIN + digest).encode("ascii")
            )
            signature["value"] = base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    def test_generator_is_deterministic_and_corpus_hash_is_jcs_bound(self):
        subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(85, self.data["count"])
        encoded = canonicalize(self.data["vectors"]).encode("utf-8")
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), self.data["hash"])
        self.assertEqual(self.data["count"], len(self.cases))
        self.assertEqual(self.data["count"], len(self.data["vectors"]))

    def test_all_fixture_vectors_execute_their_four_value_expectation(self):
        observed = {}
        for case in self.data["vectors"]:
            with self.subTest(case=case["name"]):
                result = self.evaluate_case(case)
                observed[case["name"]] = result["decision"]
                self.assertEqual(case["expected"], result["decision"], result["reason"])
                self.assertEqual(
                    case["want"]["finalityClass"], result.get("finalityClass")
                )
        self.assertEqual({"pass", "fail", "indeterminate", "error"}, set(observed.values()))

    def test_every_finality_model_has_a_legitimate_control(self):
        controls = {
            case["input"]["rail"]["consumerFinalityProfile"]["model"]
            for case in self.data["vectors"]
            if case["name"].endswith("canonical-success")
            and self.evaluate_case(case)["decision"] == "pass"
        }
        self.assertEqual(MODELS, controls)

    def test_signed_rail_asset_must_match_the_settlement_currency(self):
        for model in MODELS:
            value = copy.deepcopy(self.cases[f"fv-{model}-canonical-success"]["input"])
            asset = value["rail"]["asset"]
            field = next(name for name in ("symbol", "isoCurrency", "canonicalSymbol") if name in asset)
            asset[field] = "WRONG"
            factory = __import__("scripts.generate_settlement_finality_verification_vectors", fromlist=["FixtureFactory"]).FixtureFactory()
            factory.rebind_rail(value)
            with self.subTest(model=model):
                self.assertEqual("fail", verify_finality(value, self.trust)["decision"])

    def test_every_finality_model_uses_only_the_verifier_local_clock(self):
        controls = {
            case["input"]["rail"]["consumerFinalityProfile"]["model"]: case["input"]
            for case in self.data["vectors"]
            if case["name"].endswith("canonical-success")
        }
        for model, control in controls.items():
            missing = copy.deepcopy(self.trust)
            missing["verificationTimeMs"] = None
            stale = copy.deepcopy(self.trust)
            stale["verificationTimeMs"] += 61_000
            future = copy.deepcopy(self.trust)
            future["verificationTimeMs"] = 0
            with self.subTest(model=model, clock="missing"):
                self.assertEqual("error", verify_finality(control, missing)["decision"])
            with self.subTest(model=model, clock="stale"):
                self.assertEqual("indeterminate", verify_finality(control, stale)["decision"])
            with self.subTest(model=model, clock="future"):
                self.assertEqual("fail", verify_finality(control, future)["decision"])

    def test_every_block_depth_ancestry_link_is_verified(self):
        control = copy.deepcopy(self.cases["fv-block-depth-canonical-success"]["input"])
        ancestry = control["context"]["observation"]["ancestryProof"]
        self.assertGreater(len(ancestry), 2)
        for index in range(len(ancestry)):
            value = copy.deepcopy(control)
            value["context"]["observation"]["ancestryProof"][index]["childId"] = "00" * 32
            with self.subTest(link=index):
                self.assertEqual("fail", verify_finality(value, self.trust)["decision"])

    def test_missing_htlc_and_tank_arms_never_pass(self):
        models = {
            "htlc-reveal": ("sourceLock", "sourceClaim", "destinationLock", "destinationReveal"),
            "liquidity-tank": ("coordinator", "source", "destination"),
        }
        for model, arms in models.items():
            control = self.cases[f"fv-{model}-canonical-success"]["input"]
            for arm in arms:
                value = copy.deepcopy(control)
                value["context"][arm] = None
                with self.subTest(model=model, arm=arm):
                    self.assertEqual("indeterminate", verify_finality(value, self.trust)["decision"])

    def test_every_provider_context_and_attestation_member_is_required(self):
        control = self.cases["fv-provider-receipt-canonical-success"]["input"]
        for field in tuple(control["context"]):
            value = copy.deepcopy(control)
            del value["context"][field]
            with self.subTest(scope="context", field=field):
                self.assertNotEqual("pass", verify_finality(value, self.trust)["decision"])
        response_hash = control["context"]["responseAttestation"]["contentHash"]
        attestation = self.trust["providerAttestations"][response_hash]
        for field in tuple(attestation):
            trust = copy.deepcopy(self.trust)
            del trust["providerAttestations"][response_hash][field]
            with self.subTest(scope="attestation", field=field):
                self.assertNotEqual("pass", verify_finality(control, trust)["decision"])

    def test_ap2_sr3_requires_authenticated_matching_native_transaction(self):
        control = self.cases["fv-ap2-sr3-canonical-success"]["input"]
        self.assertEqual("ap2-sr3", control["evidence"]["paymentTxRefs"][0]["kind"])
        self.assertIn("receiptTransactionObservation", control["context"])
        self.assertEqual(
            "pass", verify_finality(control, self.trust)["decision"]
        )

        missing = copy.deepcopy(control)
        del missing["context"]["receiptTransactionObservation"]
        with self.subTest(native="observation-missing"):
            result = verify_finality(missing, self.trust)
            self.assertEqual("indeterminate", result["decision"])
            self.assertIn("native transaction observation unavailable", result["reason"])

        no_profile = copy.deepcopy(self.trust)
        no_profile["sr3TransactionFinalityProfile"] = None
        with self.subTest(native="profile-unavailable"):
            result = verify_finality(control, no_profile)
            self.assertEqual("indeterminate", result["decision"])
            self.assertIn("finality profile unavailable", result["reason"])

        wrong_tx = copy.deepcopy(control)
        wrong_tx["context"]["receiptTransactionObservation"]["transactionRef"] = {
            "kind": "demos-web2-request", "value": "ff" * 32,
        }
        with self.subTest(native="transaction-substituted"):
            self.assertEqual("fail", verify_finality(wrong_tx, self.trust)["decision"])

        bad_block = copy.deepcopy(control)
        bad_block["context"]["receiptTransactionObservation"]["inclusionBlock"]["id"] = "00" * 32
        with self.subTest(native="inclusion-tampered"):
            self.assertEqual("fail", verify_finality(bad_block, self.trust)["decision"])

        no_bft = copy.deepcopy(control)
        no_bft["context"]["receiptTransactionObservation"]["finalityCertificate"] = None
        with self.subTest(native="finality-certificate-missing"):
            self.assertEqual("indeterminate", verify_finality(no_bft, self.trust)["decision"])

    def test_ap2_sr3_missing_authority_does_not_hide_deterministic_facts(self):
        control = self.cases["fv-ap2-sr3-canonical-success"]["input"]

        malformed = copy.deepcopy(control)
        del malformed["context"]["receiptTransactionObservation"]
        malformed["context"]["responseBytes"] = "not-base64-json"
        with self.subTest(precedence="malformed-response-bytes"):
            result = verify_finality(malformed, self.trust)
            self.assertEqual("error", result["decision"])
            self.assertIn("response bytes are malformed", result["reason"])

        mismatched = copy.deepcopy(control)
        del mismatched["context"]["receiptTransactionObservation"]
        mismatched["context"]["responseAttestation"]["contentHash"] = "00" * 32
        with self.subTest(precedence="attestation-hash-mismatch"):
            result = verify_finality(mismatched, self.trust)
            self.assertEqual("fail", result["decision"])
            self.assertIn("provider context differs from signed provider reference", result["reason"])

        absent = copy.deepcopy(control)
        del absent["context"]["receiptTransactionObservation"]
        none_present = copy.deepcopy(control)
        none_present["context"]["receiptTransactionObservation"] = None
        with self.subTest(ordering="absent-equals-none"):
            absent_result = verify_finality(absent, self.trust)
            none_result = verify_finality(none_present, self.trust)
            self.assertEqual("indeterminate", absent_result["decision"])
            self.assertEqual("indeterminate", none_result["decision"])
            self.assertEqual(absent_result["reason"], none_result["reason"])

    def test_ap2_sr3_malformed_trust_and_decision_order(self):
        control = self.cases["fv-ap2-sr3-canonical-success"]["input"]

        no_profile = copy.deepcopy(self.trust)
        no_profile["sr3TransactionFinalityProfile"] = None
        with self.subTest(native="profile-missing"):
            self.assertEqual("indeterminate", verify_finality(control, no_profile)["decision"])

        for malformed in ([], {}, {"sr3Binding": "provider-jws-v1"}):
            trust = copy.deepcopy(self.trust)
            trust["sr3TransactionFinalityProfile"] = malformed
            with self.subTest(native="profile-malformed", value=malformed):
                result = verify_finality(control, trust)
                self.assertEqual("error", result["decision"])
                self.assertIn("malformed trusted SR-3 native transaction finality", result["reason"])

        wrong_binding = copy.deepcopy(self.trust)
        wrong_binding["sr3TransactionFinalityProfile"] = {
            "sr3Binding": "other-sr3-binding-v1",
            "settlement": self.trust["sr3TransactionFinalityProfile"]["settlement"],
        }
        with self.subTest(native="profile-binding-mismatch"):
            result = verify_finality(control, wrong_binding)
            self.assertEqual("indeterminate", result["decision"])
            self.assertIn("bound to a different SR-3 binding", result["reason"])

        malformed_observation = copy.deepcopy(control)
        malformed_observation["context"]["receiptTransactionObservation"] = []
        with self.subTest(native="observation-malformed-plus-profile-missing"):
            result = verify_finality(malformed_observation, no_profile)
            self.assertEqual("error", result["decision"])
            self.assertIn("malformed SR-3 native transaction observation", result["reason"])

    def test_frozen_ap2_arm_remains_distinct_and_unchanged(self):
        ap2 = self.cases["fv-provider-receipt-canonical-success"]["input"]
        sr3 = self.cases["fv-ap2-sr3-canonical-success"]["input"]
        self.assertEqual("ap2", ap2["evidence"]["paymentTxRefs"][0]["kind"])
        self.assertNotIn("receiptTransactionObservation", ap2["context"])
        self.assertNotIn("receiptTransactionRef", ap2["evidence"]["paymentTxRefs"][0])
        self.assertEqual(
            "pass", verify_finality(ap2, self.trust)["decision"]
        )
        with self.subTest(frozen="native-authority-forbidden"):
            contaminated = copy.deepcopy(ap2)
            contaminated["context"]["receiptTransactionObservation"] = {}
            self.assertEqual("error", verify_finality(contaminated, self.trust)["decision"])
        with self.subTest(distinct="sr3-shape"):
            self.assertEqual("demos-web2-request", sr3["evidence"]["paymentTxRefs"][0]["receiptTransactionRef"]["kind"])

    def test_provider_attestation_map_boundary_is_typed_on_direct_and_composed_paths(self):
        control = self.cases["fv-provider-receipt-canonical-success"]["input"]
        self.assertEqual(
            "pass", verify_finality(control, self.trust)["decision"]
        )
        trust = copy.deepcopy(self.trust)
        trust.pop("providerAttestations")
        with self.subTest(direct="missing"):
            result = verify_finality(control, trust)
            self.assertEqual("indeterminate", result["decision"])
            self.assertIn("unavailable", result["reason"])
        unavailable = (None, {}, {"00" * 32: None})
        malformed = ([], [1, 2], "map", 7, True)
        for value in unavailable:
            trust = copy.deepcopy(self.trust)
            trust["providerAttestations"] = value
            with self.subTest(direct="unavailable", value=value):
                result = verify_finality(control, trust)
                self.assertEqual("indeterminate", result["decision"])
                self.assertIn("unavailable", result["reason"])
        for value in malformed:
            trust = copy.deepcopy(self.trust)
            trust["providerAttestations"] = value
            with self.subTest(direct="malformed", value=value):
                result = verify_finality(control, trust)
                self.assertEqual("error", result["decision"])
                self.assertIn("malformed trusted provider attestation map", result["reason"])

        composed_trust = copy.deepcopy(self.trust)
        composed = copy.deepcopy(composed_trust)
        composed.pop("copyPresenceByJobRole", None)
        case = self.strong["provider-receipt"]
        response_hash = control["context"]["responseAttestation"]["contentHash"]
        attestation = composed_trust["providerAttestations"][response_hash]
        trust = copy.deepcopy(composed_trust)
        trust.pop("providerAttestations")
        with self.subTest(composed="missing"):
            decision, reason, _ = self.strong_result(case, trust=trust)
            self.assertEqual("indeterminate", decision)
            self.assertIn("unavailable", reason)
        for label, value in (
            ("null", None),
            ("empty", {}),
            ("nonmatching", {"00" * 32: attestation}),
        ):
            trust = copy.deepcopy(composed_trust)
            trust["providerAttestations"] = value
            with self.subTest(composed="unavailable", value=label):
                decision, reason, _ = self.strong_result(case, trust=trust)
                self.assertEqual("indeterminate", decision)
                self.assertIn("unavailable", reason)
        for value in ([], [attestation], "map", 7, True):
            trust = copy.deepcopy(composed_trust)
            trust["providerAttestations"] = value
            with self.subTest(composed="malformed", value=value):
                decision, reason, _ = self.strong_result(case, trust=trust)
                self.assertEqual("error", decision)
                self.assertIn(
                    "malformed trusted provider attestation map", reason
                )
        with self.subTest(composed="canonical"):
            decision, reason, _ = self.strong_result(
                case, trust=composed_trust
            )
            self.assertEqual("pass", decision, reason)

    def test_malformed_nested_inputs_refuse_without_exceptions(self):
        control = self.cases["fv-block-depth-canonical-success"]["input"]
        mutations = []
        for field, value in (
            ("ancestryProof", {}),
            ("selectedEventProof", []),
            ("transactionInclusionProof", "proof"),
            ("authenticatedHead", {"position": True}),
            ("authorityEvidence", {"attestations": [None]}),
        ):
            candidate = copy.deepcopy(control)
            candidate["context"]["observation"][field] = value
            mutations.append((field, candidate))
        for field, value in mutations:
            with self.subTest(field=field):
                self.assertIn(
                    verify_finality(value, self.trust)["decision"],
                    {"error", "fail", "indeterminate"},
                )
        malformed_fee = copy.deepcopy(control)
        malformed_fee["evidence"]["paymentFee"] = {"amount": True, "currency": "USDC"}
        self.assertEqual("error", verify_finality(malformed_fee, self.trust)["decision"])

    def test_actual_dacs5_strong_bundle_consumer_passes_all_six_models(self):
        self.assertEqual(MODELS, set(self.strong))
        for model, case in self.strong.items():
            with self.subTest(model=model):
                decision, reason, keys = self.strong_result(case)
                self.assertEqual("pass", decision, reason)
                self.assertEqual([f"0:{case['bundle']['phaseSummary'][0]['kind']}"], keys)
                self.assertEqual(
                    {f"0:{case['bundle']['phaseSummary'][0]['kind']}": "current-eligible"},
                    keys.legacy_agreement_eligibility_by_phase_key,
                )

    def test_finality_bound_success_executes_shared_laa_qualification(self):
        case = self.strong["block-depth"]
        calls = []
        original = D5._qualify_legacy_agreement_evidence

        def recording_qualifier(*args, **kwargs):
            calls.append((args[2], args[1]))
            return original(*args, **kwargs)

        with patch.object(D5, "_qualify_legacy_agreement_evidence", recording_qualifier):
            decision, reason, keys = self.strong_result(case)
        self.assertEqual("pass", decision, reason)
        self.assertEqual([("0:pay-evm-erc20", "finality-bound")], calls)
        self.assertEqual(
            {"0:pay-evm-erc20": "current-eligible"},
            keys.legacy_agreement_eligibility_by_phase_key,
        )

    def test_finality_bound_laa_authority_is_required_and_four_state(self):
        case = self.strong["block-depth"]
        phase_key = "0:pay-evm-erc20"
        cases = []

        omitted = copy.deepcopy(case["authority"])
        omitted.pop("legacyAgreementAuthorityByPhaseKey")
        cases.append(("omitted", omitted, "indeterminate"))

        absent = copy.deepcopy(case["authority"])
        absent["legacyAgreementAuthorityByPhaseKey"] = {}
        cases.append(("phase-absent", absent, "indeterminate"))

        malformed = copy.deepcopy(case["authority"])
        malformed["legacyAgreementAuthorityByPhaseKey"] = []
        cases.append(("map-malformed", malformed, "error"))

        bad_carrier = copy.deepcopy(case["authority"])
        bad_carrier["legacyAgreementAuthorityByPhaseKey"][phase_key] = None
        cases.append(("carrier-malformed", bad_carrier, "error"))

        mismatch = copy.deepcopy(case["authority"])
        mismatch["legacyAgreementAuthorityByPhaseKey"][phase_key]["binding"][
            "sessionId"
        ] += "-wrong"
        cases.append(("carrier-mismatch", mismatch, "fail"))

        for name, authority, expected in cases:
            with self.subTest(name=name):
                decision, _, keys = self.strong_result(case, authority=authority)
                self.assertEqual(expected, decision)
                self.assertIsNone(keys)

    def test_finality_bound_preserves_laa_nonpass_dispositions(self):
        case = self.strong["block-depth"]
        for expected in ("fail", "error", "indeterminate"):
            with self.subTest(expected=expected), patch.object(
                D5,
                "_qualify_legacy_agreement_evidence",
                return_value=(expected, "sentinel-" + expected, None),
            ):
                decision, reason, keys = self.strong_result(case)
                self.assertEqual(expected, decision)
                self.assertEqual("sentinel-" + expected, reason)
                self.assertIsNone(keys)

    def test_finality_bound_refuses_noncurrent_laa_eligibility(self):
        case = self.strong["block-depth"]
        for eligibility in ("historical-only", "transition-only"):
            with self.subTest(eligibility=eligibility), patch.object(
                D5,
                "_qualify_legacy_agreement_evidence",
                return_value=("pass", "audit-only", eligibility),
            ):
                decision, reason, keys = self.strong_result(case)
                self.assertEqual("fail", decision)
                self.assertIn(eligibility, reason)
                self.assertIsNone(keys)

    def test_each_successful_payment_requires_its_own_laa_carrier(self):
        factory = finality_fixtures.FixtureFactory()
        case = factory.strong_bundle_case(
            "block-depth", job_id="FV-392-multi-payment"
        )
        bundle = case["bundle"]
        authority = case["authority"]
        listing = authority["listing"]
        phase = bundle["phaseSummary"][0]["kind"]
        first_ref = bundle["settlementEvidence"][0]
        first_key = canonicalize(first_ref)
        second_ref = copy.deepcopy(first_ref)
        second_ref["anchor"]["locator"] += "-phase-1"
        second_key = canonicalize(second_ref)

        listing["pipeline"].append({"kind": phase})
        listing["signature"] = {
            "signer": finality_fixtures.CLAIMS["seller"],
            "algorithm": "ed25519",
            "value": factory.sign_digest(
                "seller",
                finality_fixtures.LISTING_DOMAIN,
                finality_fixtures.artifact_hash(listing, "signature"),
            ),
        }
        listing_ref = {
            "listingId": listing["listingId"],
            "version": listing["listingVersion"],
            "contentHash": finality_fixtures.artifact_hash(listing, "signature"),
        }
        bundle["listingRef"] = copy.deepcopy(listing_ref)
        bundle["phaseSummary"].append({
            "index": 1,
            "kind": phase,
            "outcome": "ok",
            "attestationRef": copy.deepcopy(second_ref),
        })
        bundle["settlementEvidence"].append(copy.deepcopy(second_ref))

        candidate = authority["finalityVerificationByCanonicalRef"][first_key]
        agreement = candidate["agreement"]
        agreement["listingRef"] = copy.deepcopy(listing_ref)
        agreement_hash = finality_fixtures.artifact_hash(agreement, "signatures")
        agreement["signatures"] = [
            {
                "party": finality_fixtures.CLAIMS[role],
                "algorithm": "ed25519",
                "value": factory.sign_digest(
                    role,
                    finality_fixtures.AGREEMENT_DOMAIN,
                    agreement_hash,
                ),
            }
            for role in ("buyer", "seller")
        ]
        factory.trusted["sessionAuthorityByJob"][bundle["jobId"]][
            "agreementHash"
        ] = agreement_hash
        authority["referenceValidationByCanonicalRef"][second_key] = copy.deepcopy(
            authority["referenceValidationByCanonicalRef"][first_key]
        )
        second_receipt = copy.deepcopy(
            authority["verifiedReceiptByCanonicalRef"][first_key]
        )
        second_receipt["logicalAddress"] = second_receipt["logicalAddress"].rsplit(
            ":", 1
        )[0] + ":1"
        second_receipt["nativeAddress"] = second_ref["anchor"]["locator"]
        authority["verifiedReceiptByCanonicalRef"][second_key] = second_receipt
        authority["sessionExecutionAuthorityByPhaseKey"]["1:" + phase] = {
            **authority["sessionExecutionAuthorityByPhaseKey"]["0:" + phase],
            "phaseIndex": 1,
        }
        authority["finalityVerificationByCanonicalRef"][second_key] = copy.deepcopy(
            candidate
        )
        factory.sign_bundle(bundle, finality_fixtures.FINALITY_BUNDLE_DOMAIN)
        factory.bind_current_laa_authority(bundle, authority)

        decision, reason, keys = self.strong_result(
            case, authority=authority, trust=factory.trusted
        )
        self.assertEqual("pass", decision, reason)
        self.assertEqual({"0:" + phase, "1:" + phase}, set(keys))
        self.assertEqual(
            {"0:" + phase, "1:" + phase},
            set(authority["legacyAgreementAuthorityByPhaseKey"]),
        )

        authority["legacyAgreementAuthorityByPhaseKey"].pop("1:" + phase)
        decision, reason, keys = self.strong_result(
            case, authority=authority, trust=factory.trusted
        )
        self.assertEqual("indeterminate", decision)
        self.assertIn("unavailable", reason)
        self.assertIsNone(keys)

    def test_finality_bound_without_successful_payment_needs_no_laa_carrier(self):
        factory = finality_fixtures.FixtureFactory()
        case = factory.strong_bundle_case(
            "block-depth", job_id="FV-392-no-success"
        )
        bundle = case["bundle"]
        authority = case["authority"]
        listing = authority["listing"]
        listing["pipeline"] = [{"kind": "rate"}]
        listing["signature"] = {
            "signer": finality_fixtures.CLAIMS["seller"],
            "algorithm": "ed25519",
            "value": factory.sign_digest(
                "seller",
                finality_fixtures.LISTING_DOMAIN,
                finality_fixtures.artifact_hash(listing, "signature"),
            ),
        }
        bundle["listingRef"] = {
            "listingId": listing["listingId"],
            "version": listing["listingVersion"],
            "contentHash": finality_fixtures.artifact_hash(listing, "signature"),
        }
        bundle["phaseSummary"] = [{"index": 0, "kind": "rate", "outcome": "ok"}]
        bundle["settlementEvidence"] = []
        factory.sign_bundle(bundle, finality_fixtures.FINALITY_BUNDLE_DOMAIN)
        authority.pop("legacyAgreementAuthorityByPhaseKey")
        authority["finalityVerificationByCanonicalRef"] = {}
        with patch.object(
            D5,
            "_qualify_legacy_agreement_evidence",
            side_effect=AssertionError("no successful payment should invoke LAA"),
        ):
            decision, reason, keys = self.strong_result(
                case, authority=authority, trust=factory.trusted
            )
        self.assertEqual("pass", decision, reason)
        self.assertEqual([], keys)

    def test_finality_bound_never_coerces_ordinary_payment_wire_type(self):
        case = copy.deepcopy(self.strong["block-depth"])
        compatibility = self.data["dacs5"]["compatibility"]
        ordinary = compatibility["copies"]["evidence-bound"]
        ordinary_ref = ordinary["settlementEvidence"][0]
        bundle = case["bundle"]
        bundle["settlementEvidence"] = [copy.deepcopy(ordinary_ref)]
        bundle["phaseSummary"][0]["attestationRef"] = copy.deepcopy(ordinary_ref)
        finality_fixtures.FixtureFactory().sign_bundle(
            bundle, finality_fixtures.FINALITY_BUNDLE_DOMAIN
        )
        old_authority = compatibility["evidenceBoundAuthority"]
        authority = case["authority"]
        authority["referenceValidationByCanonicalRef"] = copy.deepcopy(
            old_authority["referenceValidationByCanonicalRef"]
        )
        authority["verifiedReceiptByCanonicalRef"] = copy.deepcopy(
            old_authority["verifiedReceiptByCanonicalRef"]
        )
        decision, reason, keys = self.strong_result(case, authority=authority)
        self.assertEqual("fail", decision)
        self.assertIn("wrong evidence family", reason)
        self.assertIsNone(keys)

    def test_strong_bundle_rejects_cross_listing_agreement(self):
        case = self.strong["block-depth"]
        authority = copy.deepcopy(case["authority"])
        candidate = next(iter(authority["finalityVerificationByCanonicalRef"].values()))
        candidate["agreement"]["listingRef"]["contentHash"] = "00" * 32
        decision, reason, phase_keys = self.strong_result(case, authority=authority)
        self.assertEqual("fail", decision)
        self.assertIn("different listing", reason)
        self.assertIsNone(phase_keys)

    def test_finality_bound_joins_laa_and_fv_agreements(self):
        case = self.strong["block-depth"]
        self.assertEqual("pass", self.strong_result(case)[0])
        authority = self.cross_agreement_authority(case)
        decision, reason, phase_keys = self.strong_result(
            case, authority=authority
        )
        self.assertEqual("fail", decision, reason)
        self.assertIn("LAA agreement differs", reason)
        self.assertIsNone(phase_keys)

        pointer_authority = {**authority, "finalityTrust": self.trust}
        pointer = resolve_legacy_absolute_fault_pointer(
            self.data["dacs5"]["pointer"], case["bundle"],
            pubkeys=self.pubkeys, finality_bound_authority=pointer_authority,
        )
        self.assertFalse(pointer["ok"])
        self.assertEqual("fail", pointer["decision"])

        legacy = self.data["dacs5"]["compatibility"]["copies"]["legacy"]
        reconciled = reconcile_authenticated_finality_copies(
            [self.entry(case["bundle"], authority), self.entry(legacy)],
            self.pubkeys, self.trust,
        )
        self.assertEqual("fail", reconciled["decision"])
        self.assertIsNone(reconciled["bundle"])

    def test_missing_finality_authority_keeps_indeterminate_on_cross_agreement(self):
        case = self.strong["block-depth"]
        authority = self.cross_agreement_authority(case)
        trust = copy.deepcopy(self.trust)
        trust.pop("sessionAuthorityByJob")
        decision, _, phase_keys = self.strong_result(
            case, authority=authority, trust=trust
        )
        self.assertEqual("indeterminate", decision)
        self.assertIsNone(phase_keys)

    def test_unsupported_passing_finality_class_precedes_agreement_mismatch(self):
        case = self.strong["block-depth"]
        authority = self.cross_agreement_authority(case)
        with patch.object(D5, "verify_finality", return_value={
            "decision": "pass", "reason": "synthetic", "finalityClass": "unsupported",
        }):
            decision, reason, phase_keys = self.strong_result(
                case, authority=authority
            )
        self.assertEqual("error", decision, reason)
        self.assertIn("unsupported passing finality class", reason)
        self.assertIsNone(phase_keys)

    def test_dacs5_refuses_malformed_finality_agreement_without_exception(self):
        case = self.strong["block-depth"]
        self.assertEqual("pass", self.strong_result(case)[0])
        for malformed in (
            None, [], "agreement", True, 7, {},
            {"listingRef": None}, {"listingRef": []}, {"listingRef": "x"},
        ):
            with self.subTest(agreement=malformed):
                authority = copy.deepcopy(case["authority"])
                candidate = next(iter(authority["finalityVerificationByCanonicalRef"].values()))
                candidate["agreement"] = malformed
                decision, reason, keys = self.strong_result(case, authority=authority)
                self.assertEqual("error", decision)
                self.assertIn("agreement", reason.lower())
                self.assertIsNone(keys)

    def test_reconciliation_refuses_malformed_parties_without_exception(self):
        case = self.strong["block-depth"]
        buyer = self.entry(case["bundle"], case["authority"])
        seller_bundle = copy.deepcopy(case["bundle"])
        seller_bundle["anchoredByRole"] = "seller"
        seller = self.entry(seller_bundle, case["authority"])
        self.assertEqual("pass", reconcile_authenticated_finality_copies(
            [buyer, seller], self.pubkeys, self.trust
        )["decision"])
        malformed_parties = [
            None, True, 7, "parties", {}, [None], [7], [], [{}], [{"role": "buyer"}],
        ]
        for bad_claim in (float("nan"), b"x", "\ud800"):
            parties = copy.deepcopy(case["bundle"]["parties"])
            parties[0]["primaryClaim"] = bad_claim
            malformed_parties.append(parties)
        for malformed in malformed_parties:
            for index in (0, 1):
                with self.subTest(parties=malformed, copy=index):
                    entries = copy.deepcopy([buyer, seller])
                    entries[index]["bundle"]["parties"] = malformed
                    result = reconcile_authenticated_finality_copies(
                        entries, self.pubkeys, self.trust
                    )
                    self.assertEqual("error", result["decision"])
                    self.assertIsNone(result["bundle"])
                    unavailable = copy.deepcopy(self.trust)
                    unavailable.pop("copyPresenceByJobRole", None)
                    self.assertEqual("error", reconcile_authenticated_finality_copies(
                        entries, self.pubkeys, unavailable
                    )["decision"])

    def test_dacs5_propagates_finality_fail_indeterminate_and_error(self):
        case = self.strong["block-depth"]
        source = next(iter(case["authority"]["finalityVerificationByCanonicalRef"].values()))
        mutations = {
            "fail": lambda value: value["context"]["observation"]["transactionRef"].__setitem__("txHash", "ff" * 32),
            "indeterminate": lambda value: value["context"]["observation"].__setitem__("authorityEvidence", None),
            "error": lambda value: value["context"]["observation"]["authenticatedHead"].__setitem__("position", True),
        }
        for expected, mutate in mutations.items():
            authority = copy.deepcopy(case["authority"])
            candidate = copy.deepcopy(source)
            mutate(candidate)
            key = next(iter(authority["finalityVerificationByCanonicalRef"]))
            authority["finalityVerificationByCanonicalRef"][key] = candidate
            with self.subTest(expected=expected):
                decision, _, _ = self.strong_result(case, authority=authority)
                self.assertEqual(expected, decision)

    def test_historical_pointer_fixture_cannot_bypass_current_profile_admission(self):
        case = self.strong["block-depth"]
        pointer = self.data["dacs5"]["pointer"]
        authority = {**case["authority"], "finalityTrust": self.trust}
        result = resolve_legacy_absolute_fault_pointer(
            pointer, case["bundle"], pubkeys=self.pubkeys,
            finality_bound_authority=authority,
        )
        self.assertTrue(result["ok"], result["reason"])
        wrong_hash = copy.deepcopy(pointer)
        wrong_hash["fullBundleContentHash"] = "00" * 32
        self.assertFalse(resolve_legacy_absolute_fault_pointer(
            wrong_hash, case["bundle"], pubkeys=self.pubkeys,
            finality_bound_authority=authority,
        )["ok"])
        wrong_domain = copy.deepcopy(pointer)
        wrong_domain["signature"]["value"] = "A" * 86
        self.assertFalse(resolve_legacy_absolute_fault_pointer(
            wrong_domain, case["bundle"], pubkeys=self.pubkeys,
            finality_bound_authority=authority,
        )["ok"])

    def test_new_new_and_all_new_older_reconciliation_paths_execute(self):
        case = self.strong["block-depth"]
        compatibility = self.data["dacs5"]["compatibility"]
        copies = compatibility["copies"]
        old_authority = compatibility["evidenceBoundAuthority"]
        second_strong = copy.deepcopy(case["bundle"])
        second_strong["anchoredByRole"] = "seller"
        pairs = [
            (second_strong, case["authority"]),
            (copies["evidence-bound"], old_authority),
            (copies["fault"], None),
            (copies["legacy"], None),
        ]
        for older, authority in pairs:
            receipt_contract = (
                "archival" if bundle_type(older) == "evidence-bound" else None
            )
            result = reconcile_authenticated_finality_copies(
                [
                    self.entry(case["bundle"], case["authority"]),
                    self.entry(
                        older,
                        authority,
                        evidence_receipt_contract=receipt_contract,
                    ),
                ],
                self.pubkeys,
                self.trust,
            )
            with self.subTest(kind=bundle_type(older)):
                self.assertEqual("pass", result["decision"], result["reason"])
                self.assertEqual("finality-bound", bundle_type(result["bundle"]))

    def test_invalid_strong_copy_cannot_fall_back_to_valid_legacy_copy(self):
        case = self.strong["block-depth"]
        authority = copy.deepcopy(case["authority"])
        key = next(iter(authority["finalityVerificationByCanonicalRef"]))
        authority["finalityVerificationByCanonicalRef"][key]["context"]["observation"]["transactionRef"]["txHash"] = "ff" * 32
        legacy = self.data["dacs5"]["compatibility"]["copies"]["legacy"]
        result = reconcile_authenticated_finality_copies(
            [self.entry(case["bundle"], authority), self.entry(legacy)],
            self.pubkeys,
            self.trust,
        )
        self.assertEqual("fail", result["decision"])
        self.assertIsNone(result["bundle"])

    def test_missing_strong_laa_carrier_cannot_fall_back_to_valid_legacy_copy(self):
        case = self.strong["block-depth"]
        authority = copy.deepcopy(case["authority"])
        authority.pop("legacyAgreementAuthorityByPhaseKey")
        legacy = self.data["dacs5"]["compatibility"]["copies"]["legacy"]
        result = reconcile_authenticated_finality_copies(
            [self.entry(case["bundle"], authority), self.entry(legacy)],
            self.pubkeys,
            self.trust,
        )
        self.assertEqual("indeterminate", result["decision"])
        self.assertIn("legacy agreement authority", result["reason"])
        self.assertIsNone(result["bundle"])

    def test_finality_pointer_requires_typed_laa_carrier_authority(self):
        case = self.strong["block-depth"]
        pointer = self.data["dacs5"]["pointer"]
        for name, replacement, expected in (
            ("missing", None, "indeterminate"),
            ("malformed", [], "error"),
        ):
            authority = copy.deepcopy(case["authority"])
            if replacement is None:
                authority.pop("legacyAgreementAuthorityByPhaseKey")
            else:
                authority["legacyAgreementAuthorityByPhaseKey"] = replacement
            authority["finalityTrust"] = self.trust
            with self.subTest(name=name):
                result = resolve_legacy_absolute_fault_pointer(
                    pointer,
                    case["bundle"],
                    pubkeys=self.pubkeys,
                    finality_bound_authority=authority,
                )
                self.assertFalse(result["ok"])
                self.assertEqual(expected, result["decision"])

    def test_archival_receipt_never_supplies_current_authority(self):
        case = self.strong["block-depth"]
        compatibility = self.data["dacs5"]["compatibility"]
        older = compatibility["copies"]["evidence-bound"]
        older_authority = compatibility["evidenceBoundAuthority"]
        strong_entry = self.entry(case["bundle"], case["authority"])
        older_entry = self.entry(
            older, older_authority, evidence_receipt_contract="archival"
        )

        # The frozen receipt can compare identities only after a complete,
        # passing current copy has independently established authority.
        positive = reconcile_authenticated_finality_copies(
            [strong_entry, older_entry], self.pubkeys, self.trust
        )
        self.assertEqual("pass", positive["decision"], positive["reason"])
        self.assertEqual("finality-bound", bundle_type(positive["bundle"]))

        absent_trust = copy.deepcopy(self.trust)
        absent_trust["copyDispositionByJobRole"] = {
            case["bundle"]["jobId"] + ":buyer": "absent"
        }
        absent = reconcile_authenticated_finality_copies(
            [{"disposition": "absent", "expectedJobId": case["bundle"]["jobId"],
              "expectedRole": "buyer"}, copy.deepcopy(older_entry)],
            self.pubkeys,
            absent_trust,
        )
        self.assertEqual("indeterminate", absent["decision"])
        self.assertEqual(
            "archival EBFAB requires independently passing finality-bound authority",
            absent["reason"],
        )
        self.assertIsNone(absent["bundle"])

        invalid_strong = copy.deepcopy(strong_entry)
        key = next(iter(invalid_strong["authority"]["finalityVerificationByCanonicalRef"]))
        invalid_strong["authority"]["finalityVerificationByCanonicalRef"][key]["context"]["observation"]["transactionRef"]["txHash"] = "ff" * 32
        invalid = reconcile_authenticated_finality_copies(
            [invalid_strong, copy.deepcopy(older_entry)], self.pubkeys, self.trust
        )
        self.assertEqual("fail", invalid["decision"])
        self.assertEqual(
            "FV rejected successful payment: observation transaction reference differs from signed evidence",
            invalid["reason"],
        )
        self.assertIsNone(invalid["bundle"])

        malformed = copy.deepcopy(older_entry)
        receipt = next(
            iter(malformed["authority"]["verifiedReceiptByCanonicalRef"].values())
        )
        receipt["transaction"] = None
        malformed_archival = reconcile_authenticated_finality_copies(
            [strong_entry, malformed], self.pubkeys, self.trust
        )
        self.assertEqual("fail", malformed_archival["decision"])
        self.assertEqual(
            "evidence does not resolve to exactly one authenticated phase receipt",
            malformed_archival["reason"],
        )
        self.assertIsNone(malformed_archival["bundle"])

    def test_reconciliation_executes_conflict_absence_and_indeterminate_paths(self):
        case = self.strong["block-depth"]
        legacy = copy.deepcopy(self.data["dacs5"]["compatibility"]["copies"]["legacy"])
        legacy["phaseSummary"][0]["outcome"] = "fail"
        self.resign_bundle(legacy)
        conflict = reconcile_authenticated_finality_copies(
            [self.entry(case["bundle"], case["authority"]), self.entry(legacy)],
            self.pubkeys,
            self.trust,
        )
        self.assertEqual("fail", conflict["decision"])
        self.assertIn("diverge", conflict["reason"])

        absent_trust = copy.deepcopy(self.trust)
        absent_trust["copyDispositionByJobRole"] = {
            case["bundle"]["jobId"] + ":seller": "absent"
        }
        absent = reconcile_authenticated_finality_copies(
            [
                self.entry(case["bundle"], case["authority"]),
                {
                    "disposition": "absent",
                    "expectedJobId": case["bundle"]["jobId"],
                    "expectedRole": "seller",
                },
            ],
            self.pubkeys,
            absent_trust,
        )
        self.assertEqual("pass", absent["decision"], absent["reason"])
        self.assertEqual("finality-bound", bundle_type(absent["bundle"]))

        unauthenticated_absent = reconcile_authenticated_finality_copies(
            [
                self.entry(case["bundle"], case["authority"]),
                {
                    "disposition": "absent",
                    "expectedJobId": case["bundle"]["jobId"],
                    "expectedRole": "seller",
                },
            ],
            self.pubkeys,
            self.trust,
        )
        self.assertEqual("indeterminate", unauthenticated_absent["decision"])

        unavailable = reconcile_authenticated_finality_copies(
            [
                self.entry(case["bundle"], case["authority"]),
                {
                    "disposition": "indeterminate",
                    "expectedJobId": case["bundle"]["jobId"],
                    "expectedRole": "seller",
                },
            ],
            self.pubkeys,
            self.trust,
        )
        self.assertEqual("indeterminate", unavailable["decision"])
        self.assertIsNone(unavailable["bundle"])

    def test_reconciliation_requires_both_role_address_dispositions(self):
        case = self.strong["block-depth"]
        buyer = self.entry(case["bundle"], case["authority"])
        for entries in ([buyer], [buyer, copy.deepcopy(buyer)]):
            with self.subTest(copy_count=len(entries)):
                result = reconcile_authenticated_finality_copies(
                    entries, self.pubkeys, self.trust
                )
                self.assertEqual("indeterminate", result["decision"])
                self.assertIn("buyer and seller", result["reason"])
                self.assertIsNone(result["bundle"])

    def test_present_copy_requires_authenticated_role_address_binding(self):
        case = self.strong["block-depth"]
        buyer = self.entry(case["bundle"], case["authority"])
        seller_bundle = copy.deepcopy(case["bundle"])
        seller_bundle["anchoredByRole"] = "seller"
        seller = self.entry(seller_bundle, case["authority"])
        seller["copyPresence"] = copy.deepcopy(buyer["copyPresence"])
        result = reconcile_authenticated_finality_copies(
            [buyer, seller], self.pubkeys, self.trust
        )
        self.assertNotEqual("pass", result["decision"])
        self.assertIsNone(result["bundle"])

    def test_missing_shared_seb_authority_is_indeterminate(self):
        case = self.strong["block-depth"]
        for field in (
            "listing",
            "sessionExecutionAuthorityByPhaseKey",
            "verifiedReceiptByCanonicalRef",
            "referenceValidationByCanonicalRef",
        ):
            with self.subTest(field=field):
                authority = copy.deepcopy(case["authority"])
                authority[field] = None
                decision, reason, phase_keys = self.strong_result(
                    case, authority=authority
                )
                self.assertEqual("indeterminate", decision)
                self.assertIn("unavailable", reason)
                self.assertIsNone(phase_keys)

        authority = copy.deepcopy(case["authority"])
        authority["referenceValidationByCanonicalRef"] = {}
        decision, reason, phase_keys = self.strong_result(case, authority=authority)
        self.assertEqual("indeterminate", decision)
        self.assertIn("unavailable", reason)
        self.assertIsNone(phase_keys)

    def test_new_bundle_and_pointer_shapes_are_closed(self):
        case = self.strong["block-depth"]
        bundle = copy.deepcopy(case["bundle"])
        bundle["producerVerified"] = True
        self.assertEqual("error", self.strong_result({**case, "bundle": bundle})[0])

        pointer = copy.deepcopy(self.data["dacs5"]["pointer"])
        pointer["producerVerified"] = True
        result = resolve_legacy_absolute_fault_pointer(
            pointer,
            case["bundle"],
            pubkeys=self.pubkeys,
            finality_bound_authority={**case["authority"], "finalityTrust": self.trust},
        )
        self.assertFalse(result["ok"])

    def test_released_ebfab_still_runs_its_old_evidence_contract(self):
        compatibility = self.data["dacs5"]["compatibility"]
        bundle = compatibility["copies"]["evidence-bound"]
        authority = compatibility["evidenceBoundAuthority"]
        current_ok, current_reason, _ = validate_ebfab(
            bundle,
            authority["listing"],
            self.pubkeys,
            authority["referenceValidationByCanonicalRef"],
            authority["bundleLifecycle"],
            authority["sessionExecutionAuthorityByPhaseKey"],
            authority["verifiedReceiptByCanonicalRef"],
        )
        self.assertFalse(current_ok)
        self.assertIn("receipt", current_reason)
        ok, reason, keys = validate_legacy_ebfab(
            bundle,
            authority["listing"],
            self.pubkeys,
            authority["referenceValidationByCanonicalRef"],
            authority["bundleLifecycle"],
            authority["sessionExecutionAuthorityByPhaseKey"],
            authority["verifiedReceiptByCanonicalRef"],
        )
        self.assertTrue(ok, reason)
        self.assertEqual(["0:pay-evm-erc20"], keys)

    def test_frozen_old_reader_refuses_new_bundle_and_pointer(self):
        case = self.strong["block-depth"]
        self.assertIsNone(frozen_bundle_type(case["bundle"]))
        self.assertIsNone(frozen_pointer_type(self.data["dacs5"]["pointer"]))
        self.assertEqual("evidence-bound", frozen_bundle_type(
            self.data["dacs5"]["compatibility"]["copies"]["evidence-bound"]
        ))

    def test_combined_current_use_reputation_derivation_remains_gated(self):
        case = self.strong["block-depth"]
        tagged = {
            "bundle": case["bundle"],
            "resolvedRole": "buyer",
            "resolvedJobId": case["bundle"]["jobId"],
            "selectedByRoleResolution": True,
        }
        party = case["bundle"]["parties"][0]["primaryClaim"]
        self.assertEqual(0, derive(party, [tagged], 0, 9_999_999_999)["bundleCount"])
        self.assertEqual(0, derive_job_bound(party, [tagged], 0, 9_999_999_999)["bundleCount"])

    def test_unknown_missing_dual_and_renamed_discriminators_refuse(self):
        case = self.strong["block-depth"]
        for name, mutate in (
            ("missing", lambda bundle: bundle.pop("finalityBoundEvidenceFaultBundleVersion")),
            ("dual", lambda bundle: bundle.__setitem__("evidenceBoundFaultBundleVersion", "1")),
            ("renamed", lambda bundle: bundle.__setitem__("futureBundleVersion", bundle.pop("finalityBoundEvidenceFaultBundleVersion"))),
        ):
            bundle = copy.deepcopy(case["bundle"])
            mutate(bundle)
            with self.subTest(name=name):
                self.assertIsNone(bundle_type(bundle))
                self.assertEqual("error", validate_finality_bound_ebfab(
                    bundle,
                    case["authority"]["listing"],
                    self.pubkeys,
                    case["authority"]["referenceValidationByCanonicalRef"],
                    case["authority"]["bundleLifecycle"],
                    case["authority"]["sessionExecutionAuthorityByPhaseKey"],
                    case["authority"]["verifiedReceiptByCanonicalRef"],
                    case["authority"]["finalityVerificationByCanonicalRef"],
                    self.trust,
                    legacy_agreement_authority_by_phase_key=case["authority"][
                        "legacyAgreementAuthorityByPhaseKey"
                    ],
                )[0])


if __name__ == "__main__":
    unittest.main()
