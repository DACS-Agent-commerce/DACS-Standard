import base64
import copy
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import dacs5_reference as D5
from finality_resolution_context_reference import (
    CAPABILITY,
    CONTEXT_VERSION,
    RESPONSE_DOMAIN,
    FinalityResolutionAuthority,
    hash_value,
    replay_finality_resolution,
    verify_composite_resolution,
)
from settlement_finality_reference import (
    _verify_single_view_finality,
    verify_finality,
)
from jcs import canonicalize


ROOT = Path(__file__).resolve().parents[1]
VECTOR = (
    ROOT / "conformance" / "vectors" / "security"
    / "finality-resolution-context-v1.json"
)
GENERATOR = ROOT / "scripts" / "generate_finality_resolution_context_vectors.py"


def decode_key(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class FinalityResolutionContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTOR.read_text())
        cls.base_trusted = cls.data["baseTrusted"]

    def authority(
        self,
        payload=None,
        *,
        records=None,
        retained=None,
        mode="current",
        replay_value=None,
        verification_time=None,
    ):
        payload = copy.deepcopy(
            payload or self.data["positive"]["authority"]
        )
        return FinalityResolutionAuthority(
            authenticated=payload["authenticated"],
            policy=payload["policy"],
            issued_query=payload["issuedQuery"],
            checkpoint_source=payload["checkpointSource"],
            policy_source=payload["policySource"],
            authority_set_source=payload["authoritySetSource"],
            base_trusted=copy.deepcopy(self.base_trusted),
            verification_time_ms=(
                payload["verificationTimeMs"]
                if verification_time is None else verification_time
            ),
            acquisition_records=tuple(copy.deepcopy(
                payload["acquisitionRecords"] if records is None else records
            )),
            retained_responses=tuple(copy.deepcopy(
                payload["retainedResponses"] if retained is None else retained
            )),
            mode=mode,
            replay_value=copy.deepcopy(replay_value),
        )

    def trust(self, authority):
        trusted = copy.deepcopy(self.base_trusted)
        trusted["finalityResolutionAuthority"] = authority
        return trusted

    def verify(self, value=None, authority=None):
        return verify_finality(
            copy.deepcopy(value or self.data["positive"]["value"]),
            self.trust(authority or self.authority()),
        )

    @staticmethod
    def replace_seat(value, payload, variant, authority_id="observer-b"):
        value = copy.deepcopy(value)
        payload = copy.deepcopy(payload)
        response = copy.deepcopy(variant["response"])
        acquisition = copy.deepcopy(variant["acquisition"])
        value["context"]["responseArtifacts"] = [
            item for item in value["context"]["responseArtifacts"]
            if item["authorityId"] != authority_id
        ] + [response]
        payload["retainedResponses"] = [
            item for item in payload["retainedResponses"]
            if item["authorityId"] != authority_id
        ] + [response]
        payload["acquisitionRecords"] = [
            item for item in payload["acquisitionRecords"]
            if item["authorityId"] != authority_id
        ] + [acquisition]
        value["context"]["replay"]["acquisitionRecords"] = copy.deepcopy(
            payload["acquisitionRecords"]
        )
        return value, payload

    def test_generator_is_deterministic(self):
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_complete_all_authority_response_set_passes(self):
        result = self.verify()
        self.assertEqual("pass", result["decision"], result["reason"])
        self.assertEqual("profile-final", result["finalityClass"])
        self.assertEqual(2, result["authorityCount"])
        self.assertEqual(
            self.data["positive"]["want"]["decision"], result["decision"]
        )

    def test_new_capability_never_falls_back_to_single_view(self):
        value = copy.deepcopy(self.data["positive"]["value"])
        value["context"]["finalityResolutionContextVersion"] = "2"
        self.assertEqual("error", self.verify(value)["decision"])
        value = copy.deepcopy(self.data["positive"]["value"])
        del value["context"]["responseArtifacts"]
        self.assertEqual("error", self.verify(value)["decision"])
        well_formed = copy.deepcopy(self.data["positive"]["value"])
        self.assertEqual(
            "indeterminate",
            verify_finality(well_formed, copy.deepcopy(self.base_trusted))["decision"],
        )
        legacy = copy.deepcopy(self.data["positive"]["value"])
        response = legacy["context"]["responseArtifacts"][0]
        legacy["context"] = response["response"]["observation"]
        self.assertEqual(
            "pass",
            _verify_single_view_finality(legacy, copy.deepcopy(self.base_trusted))["decision"],
        )

    def test_plain_caller_dictionary_is_not_acquisition_authority(self):
        value = self.data["positive"]["value"]
        trusted = copy.deepcopy(self.base_trusted)
        trusted["finalityResolutionAuthority"] = copy.deepcopy(
            self.data["positive"]["authority"]
        )
        result = verify_finality(value, trusted)
        self.assertEqual("indeterminate", result["decision"])
        self.assertIn("verifier-owned", result["reason"])

    def test_complete_profile_and_every_query_dimension_are_bound(self):
        value = self.data["positive"]["value"]
        query = value["context"]["query"]
        self.assertEqual(
            hash_value(value["rail"]["consumerFinalityProfile"]),
            query["rail"]["consumerFinalityProfileHash"],
        )
        self.assertEqual(
            {
                "agreement", "session", "subject", "rail", "binding",
                "resolutionPolicy", "authoritySetHash", "checkpoint", "nonce",
                "acquisitionBoundary",
            },
            set(query),
        )
        mutations = [
            lambda q: q["agreement"].__setitem__("contentHash", "00" * 32),
            lambda q: q["session"].__setitem__("jobId", q["session"]["jobId"] + "X"),
            lambda q: q["session"].__setitem__("phaseIndex", 1),
            lambda q: q["session"]["roleBindings"].__setitem__("buyer", "did:demos:other"),
            lambda q: q["session"].__setitem__("evaluationPurpose", "other"),
            lambda q: q["subject"].__setitem__("settlementEvidenceHash", "00" * 32),
            lambda q: q["subject"].__setitem__("transactionSubject", [{"kind": "other"}]),
            lambda q: q["rail"].__setitem__("railDefinitionHash", "00" * 32),
            lambda q: q["rail"].__setitem__("consumerFinalityProfileHash", "00" * 32),
            lambda q: q["rail"]["networkIdentity"].__setitem__("networkId", "eip155:5"),
            lambda q: q["binding"].__setitem__("codecVersion", "2"),
            lambda q: q["resolutionPolicy"].__setitem__("policyVersion", "2"),
            lambda q: q.__setitem__("authoritySetHash", "00" * 32),
            lambda q: q["checkpoint"].__setitem__("checkpointId", "other"),
            lambda q: q.__setitem__("nonce", "other"),
            lambda q: q["acquisitionBoundary"].__setitem__("expiresAt", 1_900_000_020_000),
        ]
        for mutate in mutations:
            changed = copy.deepcopy(value)
            mutate(changed["context"]["query"])
            with self.subTest(mutate=mutate):
                self.assertNotEqual("pass", self.verify(changed)["decision"])

    def test_exact_duplicate_bytes_coalesce_and_transport_order_is_irrelevant(self):
        value = copy.deepcopy(self.data["positive"]["value"])
        value["context"]["responseArtifacts"].append(
            copy.deepcopy(value["context"]["responseArtifacts"][0])
        )
        result = self.verify(value)
        self.assertEqual("pass", result["decision"], result["reason"])
        # The two authorities signed identical semantic observations while their
        # transport metadata and native-attestation arrival order differ.
        responses = value["context"]["responseArtifacts"]
        self.assertNotEqual(responses[0].get("transportMetadata"), responses[1].get("transportMetadata"))

    def test_transport_omission_cannot_erase_retained_response(self):
        value = copy.deepcopy(self.data["positive"]["value"])
        value["context"]["responseArtifacts"] = [
            value["context"]["responseArtifacts"][0]
        ]
        result = self.verify(value)
        self.assertEqual("pass", result["decision"], result["reason"])

    def test_same_authority_conflict_survives_retained_union(self):
        variant = self.data["variants"]["conflictingResponse"]
        payload = copy.deepcopy(self.data["positive"]["authority"])
        payload["retainedResponses"].append(copy.deepcopy(variant["response"]))
        payload["acquisitionRecords"].append(copy.deepcopy(variant["acquisition"]))
        value = copy.deepcopy(self.data["positive"]["value"])
        value["context"]["replay"]["acquisitionRecords"] = copy.deepcopy(
            payload["acquisitionRecords"]
        )
        result = self.verify(value, self.authority(payload))
        self.assertEqual("indeterminate", result["decision"])
        self.assertIn("inconsistent", result["reason"])

    def test_unavailable_missing_other_query_and_expiry_are_nonauthorizing(self):
        positive_value = self.data["positive"]["value"]
        positive_authority = self.data["positive"]["authority"]
        unavailable_value, unavailable_payload = self.replace_seat(
            positive_value,
            positive_authority,
            self.data["variants"]["unavailableResponse"],
        )
        result = self.verify(unavailable_value, self.authority(unavailable_payload))
        self.assertEqual("indeterminate", result["decision"])
        self.assertIn("unavailable", result["reason"])

        missing_value = copy.deepcopy(positive_value)
        missing_payload = copy.deepcopy(positive_authority)
        missing_value["context"]["responseArtifacts"] = [
            item for item in missing_value["context"]["responseArtifacts"]
            if item["authorityId"] != "observer-b"
        ]
        missing_payload["retainedResponses"] = [
            item for item in missing_payload["retainedResponses"]
            if item["authorityId"] != "observer-b"
        ]
        missing_payload["acquisitionRecords"] = [
            item for item in missing_payload["acquisitionRecords"]
            if item["authorityId"] != "observer-b"
        ]
        missing_value["context"]["replay"]["acquisitionRecords"] = copy.deepcopy(
            missing_payload["acquisitionRecords"]
        )
        result = self.verify(missing_value, self.authority(missing_payload))
        self.assertEqual("indeterminate", result["decision"])
        self.assertIn("expired", result["reason"])

        other_value, other_payload = self.replace_seat(
            positive_value,
            positive_authority,
            self.data["variants"]["otherQueryResponse"],
        )
        result = self.verify(other_value, self.authority(other_payload))
        self.assertEqual("indeterminate", result["decision"])
        self.assertEqual(["observer-b"], result["missingAuthorities"])

    def test_local_acquisition_and_signed_time_have_distinct_roles(self):
        value = copy.deepcopy(self.data["positive"]["value"])
        payload = copy.deepcopy(self.data["positive"]["authority"])
        missing = payload["acquisitionRecords"].pop()
        value["context"]["replay"]["acquisitionRecords"] = copy.deepcopy(
            payload["acquisitionRecords"]
        )
        result = self.verify(value, self.authority(payload))
        self.assertEqual("indeterminate", result["decision"])
        self.assertIn("acquisition", result["reason"])

        payload = copy.deepcopy(self.data["positive"]["authority"])
        payload["acquisitionRecords"][0]["acquiredAt"] = (
            payload["issuedQuery"]["acquisitionBoundary"]["expiresAt"] + 1
        )
        value = copy.deepcopy(self.data["positive"]["value"])
        value["context"]["replay"]["acquisitionRecords"] = copy.deepcopy(
            payload["acquisitionRecords"]
        )
        result = self.verify(value, self.authority(payload))
        self.assertEqual("indeterminate", result["decision"])
        self.assertIn("outside", result["reason"])
        self.assertTrue(missing["responseHash"])

        for name, expected, reason in (
            ("futureResponse", "fail", "after local acquisition"),
            ("staleResponse", "indeterminate", "expired before acquisition"),
        ):
            value, payload = self.replace_seat(
                self.data["positive"]["value"],
                self.data["positive"]["authority"],
                self.data["variants"][name],
                authority_id="observer-a",
            )
            result = self.verify(value, self.authority(payload))
            with self.subTest(name=name):
                self.assertEqual(expected, result["decision"])
                self.assertIn(reason, result["reason"])

    def test_malformed_response_and_signature_failure_precede_missing_seat(self):
        value = copy.deepcopy(self.data["positive"]["value"])
        value["context"]["responseArtifacts"][0]["response"]["unexpected"] = True
        self.assertEqual("error", self.verify(value)["decision"])
        value = copy.deepcopy(self.data["positive"]["value"])
        value["context"]["responseArtifacts"][0]["signature"]["value"] = "A" * 86
        self.assertEqual("fail", self.verify(value)["decision"])

    def test_underlying_authenticated_contract_contradiction_is_fail(self):
        value, payload = self.replace_seat(
            self.data["positive"]["value"],
            self.data["positive"]["authority"],
            self.data["variants"]["contradictoryResponse"],
            authority_id="observer-a",
        )
        result = self.verify(value, self.authority(payload))
        self.assertEqual("fail", result["decision"])
        self.assertIn("economics", result["reason"])

    def test_error_and_fail_precede_incomplete_acquisition_in_any_order(self):
        value, payload = self.replace_seat(
            self.data["positive"]["value"],
            self.data["positive"]["authority"],
            self.data["variants"]["contradictoryResponse"],
            authority_id="observer-a",
        )
        value["context"]["responseArtifacts"] = [
            item for item in value["context"]["responseArtifacts"]
            if item["authorityId"] != "observer-b"
        ]
        payload["retainedResponses"] = [
            item for item in payload["retainedResponses"]
            if item["authorityId"] != "observer-b"
        ]
        payload["acquisitionRecords"] = [
            item for item in payload["acquisitionRecords"]
            if item["authorityId"] != "observer-b"
        ]
        value["context"]["replay"]["acquisitionRecords"] = copy.deepcopy(
            payload["acquisitionRecords"]
        )
        for reverse in (False, True):
            candidate = copy.deepcopy(value)
            retained = copy.deepcopy(payload)
            if reverse:
                candidate["context"]["responseArtifacts"].reverse()
                retained["retainedResponses"].reverse()
            with self.subTest(reverse=reverse):
                self.assertEqual(
                    "fail",
                    self.verify(candidate, self.authority(retained))["decision"],
                )

        malformed = copy.deepcopy(value)
        malformed["context"]["responseArtifacts"][0]["response"]["extra"] = True
        self.assertEqual(
            "error",
            self.verify(malformed, self.authority(payload))["decision"],
        )

        stale_value, stale_payload = self.replace_seat(
            self.data["positive"]["value"],
            self.data["positive"]["authority"],
            self.data["variants"]["staleResponse"],
            authority_id="observer-a",
        )
        for response in stale_value["context"]["responseArtifacts"]:
            if response["authorityId"] == "observer-b":
                response["signature"]["value"] = "A" * 86
        for response in stale_payload["retainedResponses"]:
            if response["authorityId"] == "observer-b":
                response["signature"]["value"] = "A" * 86
        for reverse in (False, True):
            candidate = copy.deepcopy(stale_value)
            retained = copy.deepcopy(stale_payload)
            if reverse:
                candidate["context"]["responseArtifacts"].reverse()
                retained["retainedResponses"].reverse()
            with self.subTest(stale_before_signature_failure=not reverse):
                self.assertEqual(
                    "fail",
                    self.verify(candidate, self.authority(retained))["decision"],
                )

    def test_checkpoint_is_bound_to_source_rail_and_native_head(self):
        value, payload = self.replace_seat(
            self.data["positive"]["value"],
            self.data["positive"]["authority"],
            self.data["variants"]["checkpointMismatchResponse"],
            authority_id="observer-a",
        )
        result = self.verify(value, self.authority(payload))
        self.assertEqual("fail", result["decision"])
        self.assertIn("checkpoint", result["reason"])

        payload = copy.deepcopy(self.data["positive"]["authority"])
        payload["checkpointSource"]["contentHash"] = "00" * 32
        value = copy.deepcopy(self.data["positive"]["value"])
        value["context"]["replay"]["checkpointSource"] = copy.deepcopy(
            payload["checkpointSource"]
        )
        self.assertEqual(
            "fail",
            self.verify(value, self.authority(payload))["decision"],
        )

    def test_acquisition_cannot_postdate_verifier_decision_time(self):
        payload = copy.deepcopy(self.data["positive"]["authority"])
        first_acquired = min(
            record["acquiredAt"] for record in payload["acquisitionRecords"]
        )
        result = self.verify(
            authority=self.authority(
                payload,
                verification_time=first_acquired - 1,
            )
        )
        self.assertEqual("indeterminate", result["decision"])
        self.assertIn("decision time", result["reason"])

        latest_acquired = max(
            record["acquiredAt"] for record in payload["acquisitionRecords"]
        )
        result = self.verify(
            authority=self.authority(
                payload,
                verification_time=latest_acquired,
            )
        )
        self.assertEqual("pass", result["decision"], result["reason"])

    def test_replay_uses_recorded_policy_and_is_not_a_current_decision(self):
        current = self.verify()
        record = current["replayRecord"]
        payload = copy.deepcopy(self.data["positive"]["authority"])
        replay_authority = self.authority(
            payload,
            records=record["acquisitionRecords"],
            retained=record["retainedResponses"],
            mode="replay",
            replay_value=self.data["positive"]["value"],
        )
        self.assertEqual(
            "indeterminate",
            self.verify(authority=replay_authority)["decision"],
        )
        replay = replay_finality_resolution(
            record,
            replay_authority,
            legacy_verifier=_verify_single_view_finality,
        )
        self.assertEqual("pass", replay["decision"], replay["reason"])
        self.assertTrue(replay["historicalReplay"])
        self.assertFalse(replay["currentFinalityDecision"])
        changed = copy.deepcopy(record)
        changed["policy"]["authorityEpoch"] = "other"
        self.assertEqual(
            "fail",
            replay_finality_resolution(
                changed,
                replay_authority,
                legacy_verifier=_verify_single_view_finality,
            )["decision"],
        )

    def test_composite_legs_have_independent_complete_gates(self):
        composite = self.data["composite"]
        legs = [
            {
                "legId": item["legId"],
                "value": copy.deepcopy(item["value"]),
                "authority": self.authority(item["authority"]),
            }
            for item in composite["legs"]
        ]
        result = verify_composite_resolution(
            legs,
            composite["relationship"],
            legacy_verifier=_verify_single_view_finality,
        )
        self.assertEqual("pass", result["decision"], result["reason"])
        self.assertEqual(2, len(result["legResults"]))
        queries = [leg["value"]["context"]["query"] for leg in legs]
        self.assertNotEqual(
            queries[0]["subject"]["settlementEvidenceHash"],
            queries[1]["subject"]["settlementEvidenceHash"],
        )
        self.assertNotEqual(
            queries[0]["rail"]["consumerFinalityProfileHash"],
            queries[1]["rail"]["consumerFinalityProfileHash"],
        )
        self.assertNotEqual(queries[0]["checkpoint"], queries[1]["checkpoint"])

        crossed = copy.deepcopy(legs)
        crossed[0]["value"], crossed[1]["value"] = (
            crossed[1]["value"],
            crossed[0]["value"],
        )
        self.assertEqual(
            "fail",
            verify_composite_resolution(
                crossed,
                composite["relationship"],
                legacy_verifier=_verify_single_view_finality,
            )["decision"],
        )

        duplicate_relationship = copy.deepcopy(composite["relationship"])
        duplicate_relationship["legIds"] = ["source", "source"]
        duplicate_legs = copy.deepcopy(legs)
        duplicate_legs[1]["legId"] = "source"
        self.assertEqual(
            "error",
            verify_composite_resolution(
                duplicate_legs,
                duplicate_relationship,
                legacy_verifier=_verify_single_view_finality,
            )["decision"],
        )

        for unavailable_index in (0, 1):
            mixed = copy.deepcopy(legs)
            mixed[unavailable_index]["authority"] = {}
            mixed[1 - unavailable_index]["unexpected"] = True
            with self.subTest(unavailable_index=unavailable_index):
                result = verify_composite_resolution(
                    mixed,
                    composite["relationship"],
                    legacy_verifier=_verify_single_view_finality,
                )
                self.assertEqual("error", result["decision"])
                self.assertEqual(2, len(result["legResults"]))

        for mismatch_index in (0, 1):
            mixed = copy.deepcopy(legs)
            payload = copy.deepcopy(
                composite["legs"][mismatch_index]["authority"]
            )
            payload["issuedQuery"]["session"]["jobId"] = (
                payload["issuedQuery"]["session"]["jobId"] + "-other"
            )
            mixed[mismatch_index]["authority"] = self.authority(payload)
            mixed[1 - mismatch_index]["unexpected"] = True
            with self.subTest(relationship_mismatch_index=mismatch_index):
                result = verify_composite_resolution(
                    mixed,
                    composite["relationship"],
                    legacy_verifier=_verify_single_view_finality,
                )
                self.assertEqual("error", result["decision"])
                self.assertEqual(2, len(result["legResults"]))

        destination = self.data["composite"]["legs"][1]
        value, payload = self.replace_seat(
            destination["value"],
            destination["authority"],
            destination["unavailableVariant"],
        )
        legs[1] = {
            "legId": destination["legId"],
            "value": value,
            "authority": self.authority(payload),
        }
        result = verify_composite_resolution(
            legs,
            composite["relationship"],
            legacy_verifier=_verify_single_view_finality,
        )
        self.assertEqual("indeterminate", result["decision"])
        self.assertIn("unavailable", result["reason"])

    def test_dacs5_consumer_revalidates_the_same_resolution_boundary(self):
        case = copy.deepcopy(self.data["dacs5Consumer"])
        pubkeys = {
            identity: decode_key(key)
            for identity, key in self.base_trusted["partyKeys"].items()
        }
        authority = case["authority"]
        decision, reason, phase_keys = D5.validate_finality_bound_ebfab(
            case["bundle"],
            authority["listing"],
            pubkeys,
            authority["referenceValidationByCanonicalRef"],
            authority["bundleLifecycle"],
            authority["sessionExecutionAuthorityByPhaseKey"],
            authority["verifiedReceiptByCanonicalRef"],
            authority["finalityVerificationByCanonicalRef"],
            self.trust(self.authority()),
        )
        self.assertEqual("pass", decision, reason)
        self.assertEqual(["0:pay-evm-erc20"], phase_keys)

        key_authority = D5.trusted_verification_keys(pubkeys)
        trusted_context = D5.trusted_profile_context(
            case["bundle"]["jobId"],
            case["bundle"]["parties"][0]["primaryClaim"],
            role="buyer",
        )
        pointer_result = D5.resolve_absolute_fault_pointer(
            case["pointer"],
            case["bundle"],
            pubkeys=key_authority,
            finality_bound_authority={
                **authority,
                "finalityTrust": self.trust(self.authority()),
            },
            trusted_contexts=trusted_context,
            expected_jobid=case["bundle"]["jobId"],
            expected_role="buyer",
        )
        self.assertTrue(pointer_result["ok"], pointer_result["reason"])
        for field, replacement in (
            ("fullBundleContentHash", "00" * 32),
            ("signature", {
                **case["pointer"]["signature"],
                "value": "A" * 86,
            }),
        ):
            changed = copy.deepcopy(case["pointer"])
            changed[field] = replacement
            result = D5.resolve_absolute_fault_pointer(
                changed,
                case["bundle"],
                pubkeys=key_authority,
                finality_bound_authority={
                    **authority,
                    "finalityTrust": self.trust(self.authority()),
                },
                trusted_contexts=trusted_context,
                expected_jobid=case["bundle"]["jobId"],
                expected_role="buyer",
            )
            self.assertFalse(result["ok"])

    def test_independent_profile_query_and_response_signature_oracle(self):
        value = self.data["positive"]["value"]
        query = value["context"]["query"]
        response = value["context"]["responseArtifacts"][0]

        profile_digest = hashlib.sha256(
            canonicalize(value["rail"]["consumerFinalityProfile"]).encode("utf-8")
        ).hexdigest()
        query_digest = hashlib.sha256(
            canonicalize(query).encode("utf-8")
        ).hexdigest()
        response_body = {
            key: item for key, item in response.items() if key != "signature"
        }
        response_digest = hashlib.sha256(
            canonicalize(response_body).encode("utf-8")
        ).hexdigest()
        preimage = (
            b"dacs-finality-observation-response:v1:"
            + response_digest.encode("ascii")
        )

        self.assertEqual(
            "e794f50cdd76a4b3f59ef7822745e5885cb535770ff84eae8398fc90deb2b936",
            profile_digest,
        )
        self.assertEqual(query["rail"]["consumerFinalityProfileHash"], profile_digest)
        self.assertEqual(
            "754d4b0946e3622af4314a91f1e6a95fdb8f8434b83867dcd54789e6dce1a34d",
            query_digest,
        )
        self.assertEqual(response["queryHash"], query_digest)
        self.assertEqual(
            "06b20e0268a00114ca283a8825d0be740fb244ba55d42f74c93ee5f52dbbe969",
            response_digest,
        )
        self.assertEqual(
            "0ee0b3737645d58e83e426dd2e23943cb66b7ed8d7a1e156104a3dd7db688ffb",
            hashlib.sha256(preimage).hexdigest(),
        )

        seat = next(
            seat for seat in self.data["positive"]["authority"]["policy"]["authorities"]
            if seat["authorityId"] == response["authorityId"]
        )
        key = next(
            key for key in seat["verificationKeys"]
            if key["keyId"] == response["signature"]["keyId"]
        )
        Ed25519PublicKey.from_public_bytes(
            decode_key(key["publicKey"])
        ).verify(
            decode_key(response["signature"]["value"]),
            preimage,
        )

    def test_registered_response_domain_and_fixture_only_scope(self):
        self.assertEqual("dacs-finality-observation-response:v1:", RESPONSE_DOMAIN)
        self.assertEqual(CONTEXT_VERSION, "1")
        self.assertEqual(CAPABILITY, "finality-resolution-context-v1")
        self.assertTrue(self.data["fixtureOnly"])
        self.assertEqual(2, self.data["authorityCount"])


if __name__ == "__main__":
    unittest.main()
