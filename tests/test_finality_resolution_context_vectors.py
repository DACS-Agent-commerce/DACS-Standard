import base64
import copy
import hashlib
import json
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT / "scripts"), str(ROOT / "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import dacs5_reference as D5
import finality_resolution_context_reference as FRC
import generate_finality_resolution_context_vectors as GEN
from finality_resolution_context_reference import (
    CAPABILITY,
    CONTEXT_VERSION,
    RESPONSE_DOMAIN,
    FinalityResolutionAuthority,
    hash_value,
    response_signature_hash,
    replay_finality_resolution,
    verify_composite_resolution,
)
from settlement_finality_reference import (
    _verify_single_view_finality,
    verify_finality,
)
from jcs import canonicalize

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
        mode=None,
        replay_value=None,
        verification_time=None,
    ):
        payload = copy.deepcopy(
            payload or self.data["positive"]["authority"]
        )
        mode = mode or payload.get("mode", "current")
        if replay_value is None:
            replay_value = payload.get("replayValue")
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

    def execute_vector(self, case):
        """Run one committed case through its named entry point, JSON only."""
        payload = copy.deepcopy(case["input"])
        if case["operation"] == "verify":
            return self.verify(payload["value"], self.authority(payload["authority"]))
        if case["operation"] == "verify-composite":
            legs = [
                {
                    "legId": leg["legId"],
                    "value": leg["value"],
                    "authority": self.authority(leg["authority"]),
                }
                for leg in payload["legs"]
            ]
            return verify_composite_resolution(
                legs,
                payload["relationship"],
                legacy_verifier=_verify_single_view_finality,
            )
        if case["operation"] == "replay":
            return replay_finality_resolution(
                payload["replayRecord"],
                self.authority(payload["authority"]),
                legacy_verifier=_verify_single_view_finality,
            )
        raise AssertionError("unknown vector operation %r" % case["operation"])

    def case(self, name):
        return next(v for v in self.data["vectors"] if v["name"] == name)

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
        # The single-view observation is genuine on its own, so only FRC-1's
        # selected-capability rule refuses it at the FV entry point.
        self.assertEqual(
            "pass",
            _verify_single_view_finality(legacy, copy.deepcopy(self.base_trusted))["decision"],
        )
        for trusted in (copy.deepcopy(self.base_trusted), self.trust(self.authority())):
            result = verify_finality(copy.deepcopy(legacy), trusted)
            self.assertEqual("error", result["decision"])
            self.assertIn("cannot fall back to a single-view context", result["reason"])
        committed = self.case("frc1-single-view-under-capability")["input"]["value"]
        observer_a = next(
            response for response in self.data["positive"]["value"]["context"]["responseArtifacts"]
            if response["authorityId"] == "observer-a"
        )
        self.assertEqual(observer_a["response"]["observation"], committed["context"])
        self.assertEqual(
            {key: item for key, item in legacy.items() if key != "context"},
            {key: item for key, item in committed.items() if key != "context"},
        )

    def test_frc1_vectors_reject_a_single_view_fallback(self):
        """Wrong implementation: verify any non-FRC context through FV."""

        def falls_back(value, trusted):
            context = value.get("context") if isinstance(value, dict) else None
            if isinstance(context, dict) and (
                "finalityResolutionContextVersion" in context
                or context.get("capability") == CAPABILITY
            ):
                return verify_finality(value, trusted)
            return _verify_single_view_finality(value, trusted)

        for name in (
            "frc1-single-view-under-capability",
            "frc1-fork-view-under-capability",
        ):
            case = self.case(name)
            value = case["input"]["value"]
            self.assertEqual(
                CAPABILITY,
                value["rail"]["consumerFinalityProfile"]["finalityResolutionCapability"],
            )
            self.assertEqual("chain", value["context"]["kind"])
            trusted = self.trust(self.authority(case["input"]["authority"]))
            with self.subTest(case=name):
                self.assertEqual("error", self.execute_vector(case)["decision"])
                self.assertEqual(
                    "pass", falls_back(copy.deepcopy(value), trusted)["decision"]
                )
        # #416's own conflict resolves to indeterminate; its fork view alone
        # would pass a falling-back verifier.
        self.assertEqual(
            "indeterminate",
            self.execute_vector(self.case("fv-conflicting-authenticated-heads"))["decision"],
        )

        case = self.case("frc1-context-without-signed-capability")
        value = case["input"]["value"]
        self.assertNotIn(
            "finalityResolutionCapability", value["rail"]["consumerFinalityProfile"]
        )
        self.assertEqual(self.data["positive"]["value"]["context"], value["context"])
        self.assertEqual("error", self.execute_vector(case)["decision"])
        original = FRC.derive_query

        def without_capability_check(candidate, *args, **kwargs):
            candidate = copy.deepcopy(candidate)
            candidate["rail"]["consumerFinalityProfile"][
                "finalityResolutionCapability"
            ] = CAPABILITY
            return original(candidate, *args, **kwargs)

        # Skipping only the signed-capability requirement leaves the query
        # binding, which reports a contradiction instead of a refusal.
        with mock.patch.object(FRC, "derive_query", without_capability_check):
            self.assertEqual("fail", self.execute_vector(case)["decision"])

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

    def test_equivalent_sufficient_authentication_sets_are_one_view(self):
        case = self.case("equivalent-sufficient-authentication-sets")
        value = case["input"]["value"]
        views = {
            response["authorityId"]: response["response"]["observation"]
            for response in value["context"]["responseArtifacts"]
        }
        attestations = {
            authority_id: view["observation"]["authorityEvidence"]["attestations"]
            for authority_id, view in views.items()
        }
        threshold = value["rail"]["consumerFinalityProfile"]["settlement"]["observation"]["threshold"]
        self.assertEqual(threshold + 1, len(attestations["observer-a"]))
        self.assertEqual(threshold, len(attestations["observer-b"]))
        self.assertEqual(
            FRC._projection(views["observer-a"]), FRC._projection(views["observer-b"])
        )
        self.assertEqual("pass", self.execute_vector(case)["decision"])

        # Each view is still authenticated on its own: below the threshold
        # observer-b's view does not verify, so the pair cannot pass.
        thin = copy.deepcopy(views["observer-b"])
        del thin["observation"]["authorityEvidence"]["attestations"][threshold - 1:]
        key = GEN.Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(GEN.AUTHORITY_SEEDS["observer-b-key"])
        )
        query = case["input"]["authority"]["issuedQuery"]
        response = GEN.signed_response(
            key,
            authority_id="observer-b",
            key_id="observer-b-key",
            query=query,
            checkpoint=query["checkpoint"],
            arm={"status": "observed", "observation": thin},
        )
        changed, payload = self.replace_seat(
            value, case["input"]["authority"],
            {
                "response": response,
                "acquisition": GEN.acquisition(response, query["nonce"], GEN.ACQUIRED_AT),
            },
        )
        self.assertNotEqual("pass", self.verify(changed, self.authority(payload))["decision"])

    def test_bft_certificate_order_and_sufficient_set_are_one_view(self):
        case = self.case("bft-equivalent-certificate-signature-sets")
        value = case["input"]["value"]
        self.assertEqual(
            "bft-final", value["rail"]["consumerFinalityProfile"]["settlement"]["kind"]
        )
        views = {
            response["authorityId"]: response["response"]["observation"]
            for response in value["context"]["responseArtifacts"]
        }
        signers = {
            authority_id: [
                signature["validatorId"]
                for signature in view["observation"]["finalityCertificate"]["signatures"]
            ]
            for authority_id, view in views.items()
        }
        self.assertEqual(["validator-c", "validator-b", "validator-a"], signers["observer-a"])
        self.assertEqual(["validator-a", "validator-b"], signers["observer-b"])
        for view in views.values():
            candidate = copy.deepcopy(value)
            candidate["context"] = copy.deepcopy(view)
            result = _verify_single_view_finality(candidate, copy.deepcopy(self.base_trusted))
            self.assertEqual("pass", result["decision"], result["reason"])
        self.assertEqual(
            FRC._projection(views["observer-a"]), FRC._projection(views["observer-b"])
        )
        self.assertEqual("pass", self.execute_vector(case)["decision"])

        # The certificate's block and validator set remain finality meaning.
        moved = copy.deepcopy(views["observer-b"])
        moved["observation"]["finalityCertificate"]["blockId"] = "00" * 32
        self.assertNotEqual(FRC._projection(views["observer-b"]), FRC._projection(moved))

        below = self.case("bft-certificate-below-quorum")
        thin = next(
            response["response"]["observation"]
            for response in below["input"]["value"]["context"]["responseArtifacts"]
            if response["authorityId"] == "observer-b"
        )
        self.assertEqual(
            ["validator-a"],
            [s["validatorId"] for s in thin["observation"]["finalityCertificate"]["signatures"]],
        )
        result = self.execute_vector(below)
        self.assertEqual("fail", result["decision"], result["reason"])
        self.assertIn("quorum", result["reason"])

    def test_observation_instant_is_not_finality_meaning(self):
        case = self.case("equivalent-views-observed-at-different-instants")
        views = {
            response["authorityId"]: response["response"]["observation"]["observation"]
            for response in case["input"]["value"]["context"]["responseArtifacts"]
        }
        heads = {authority_id: view["authenticatedHead"] for authority_id, view in views.items()}
        self.assertEqual(
            heads["observer-a"]["observedAt"] + 2000, heads["observer-b"]["observedAt"]
        )
        self.assertEqual(
            {k: v for k, v in heads["observer-a"].items() if k != "observedAt"},
            {k: v for k, v in heads["observer-b"].items() if k != "observedAt"},
        )
        self.assertEqual("pass", self.execute_vector(case)["decision"])

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

    def assert_valid_native_view(self, response):
        seat = next(
            seat for seat in self.data["positive"]["authority"]["policy"]["authorities"]
            if seat["authorityId"] == response["authorityId"]
        )
        key = next(
            key for key in seat["verificationKeys"]
            if key["keyId"] == response["signature"]["keyId"]
        )
        Ed25519PublicKey.from_public_bytes(decode_key(key["publicKey"])).verify(
            decode_key(response["signature"]["value"]),
            (RESPONSE_DOMAIN + response_signature_hash(response)).encode("ascii"),
        )
        self.assertEqual(
            hash_value(self.data["positive"]["authority"]["issuedQuery"]),
            response["queryHash"],
        )
        candidate = copy.deepcopy(self.data["positive"]["value"])
        candidate["context"] = copy.deepcopy(response["response"]["observation"])
        result = _verify_single_view_finality(candidate, copy.deepcopy(self.base_trusted))
        self.assertEqual("pass", result["decision"], result["reason"])
        return candidate["context"]["observation"]["authenticatedHead"]["id"]

    def assert_sibling_forks(self, canonical, replacement):
        left = canonical["response"]["observation"]["observation"]
        right = replacement["response"]["observation"]["observation"]
        for member in ("networkId", "genesisHash", "transactionRef"):
            self.assertEqual(left[member], right[member])
        self.assertEqual(
            left["selectedEventProof"]["eventBytes"],
            right["selectedEventProof"]["eventBytes"],
        )
        self.assertEqual(left["inclusionBlock"]["parentId"], right["inclusionBlock"]["parentId"])
        self.assertNotEqual(left["inclusionBlock"]["id"], right["inclusionBlock"]["id"])
        self.assertEqual(left["authenticatedHead"]["position"], right["authenticatedHead"]["position"])
        self.assertNotEqual(left["authenticatedHead"]["id"], right["authenticatedHead"]["id"])

    def materialized(self, name):
        case = next(v for v in self.data["vectors"] if v["name"] == name)
        return case, copy.deepcopy(case["input"]["value"]), copy.deepcopy(case["input"]["authority"])

    def test_materialized_cases_execute_their_expectation(self):
        self.assertEqual(49, self.data["count"])
        self.assertEqual(self.data["count"], len(self.data["vectors"]))
        self.assertEqual(
            hashlib.sha256(json.dumps(
                self.data["vectors"], separators=(",", ":"), sort_keys=True,
            ).encode("utf-8")).hexdigest(),
            self.data["hash"],
        )
        decisions = set()
        for case in self.data["vectors"]:
            self.assertIn(case["operation"], {"verify", "verify-composite", "replay"})
            self.assertIn("input", case)
            with self.subTest(case=case["name"]):
                result = self.execute_vector(case)
                self.assertEqual(case["expected"], result["decision"], result["reason"])
            decisions.add(result["decision"])
        self.assertEqual({"pass", "fail", "indeterminate", "error"}, decisions)

    def test_closed_shape_and_acquisition_cases_fail_a_verifier_missing_their_guard(self):
        """Source mutants: each removes one FRC-5/FRC-8/FRC-9 guard.

        ``pass`` shows the case is otherwise valid; ``None`` requires only
        that the mutant's verdict differs from the committed one.
        """
        source = (ROOT / "scripts" / "finality_resolution_context_reference.py").read_text(encoding="utf-8")

        def mutant(old, new):
            self.assertEqual(1, source.count(old), old)
            module = types.ModuleType("finality_resolution_guard_mutant")
            module.__file__ = FRC.__file__
            # Dataclass processing resolves the defining module by name.
            with mock.patch.dict(sys.modules, {module.__name__: module}):
                exec(compile(source.replace(old, new), FRC.__file__, "exec"), module.__dict__)
            return module

        guards = [
            ('if not _exact(response, required, {"transportMetadata"}):',
             'if not isinstance(response, dict) or not required <= set(response):',
             "pass", ["response-extra-member"]),
            ('    if "transportMetadata" in response and not isinstance(response["transportMetadata"], dict):\n'
             '        return False\n', "", "pass",
             ["response-transport-metadata-not-object", "response-transport-metadata-null"]),
            # FRC-8 projection: authentication evidence is not finality meaning.
            ('"networkId", "genesisHash", "transactionRef", "transactionInclusionProof",',
             '"networkId", "genesisHash", "transactionRef", "transactionInclusionProof", "authorityEvidence",',
             "indeterminate", ["equivalent-sufficient-authentication-sets"]),
            ('PROJECTED_HEAD_MEMBERS = ("id", "position", "header")',
             'PROJECTED_HEAD_MEMBERS = ("id", "position", "header", "observedAt")',
             "indeterminate", ["equivalent-views-observed-at-different-instants"]),
            ('PROJECTED_CERTIFICATE_MEMBERS = ("kind", "validatorSetHash", "blockId")',
             'PROJECTED_CERTIFICATE_MEMBERS = ("kind", "validatorSetHash", "blockId", "signatures")',
             "indeterminate", ["bft-equivalent-certificate-signature-sets"]),
            ('return _exact(arm, {"status", "observation"}) and', "return", "pass",
             ["response-observed-arm-extra-member"]),
            ('return _exact(arm, {"status", "reason"}) and', "return", None,
             ["response-unavailable-arm-extra-member"]),
            ('or record.get("queryNonce") != authority.issued_query.get("nonce")\n', "", "pass",
             ["acquisition-record-other-nonce"]),
            ('or record.get("status") != "obtained"\n', "", "pass",
             ["acquisition-record-not-obtained"]),
            ('or record["responseHash"] in records\n', "", "pass",
             ["acquisition-record-duplicate-response-hash"]),
            ('if acquisition["authorityId"] != response["authorityId"]:', "if False:", "pass",
             ["acquisition-authority-differs-from-responder"]),
            ('}) or replay_record.get("finalityResolutionReplayVersion") != "1":', "}):", "pass",
             ["replay-record-version-unknown"]),
            ('return {"decision": "error", "reason": "malformed verifier-owned resolution authority"}',
             'return {"decision": "indeterminate", "reason": unavailable}', None,
             ["resolution-authority-policy-malformed", "replay-authority-policy-malformed",
              "composite-leg-authority-policy-malformed"]),
            # FRC-4 / CORE SIG-6 on the observation response envelope.
            ('if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:', "if False:", "pass",
             ["response-signature-nonminimal-base64url"]),
            # CORE §B.7 SIG-7: the wire stage is part of the response shape
            # (error); a non-empty-string check lets it fall through to fail.
            ('or not _signature_wire(signature.get("value"))', 'or not _nonempty(signature.get("value"))', "fail",
             ["response-signature-nonminimal-base64url"]),
            ("if not _verify_response_signature(response, seat):", "if False:", "pass",
             ["response-signature-invalid"]),
            # FRC-2 query and provenance binding.
            ('if context["query"] != authority.issued_query:', "if False:", None,
             ["transported-query-differs"]),
            ('or authority.policy_source.get("contentHash") != hash_value(authority.policy)\n', "", "pass",
             ["resolution-policy-source-differs"]),
            # FRC-5 local acquisition time.
            ('if not boundary["issuedAt"] <= acquisition["acquiredAt"] <= boundary["expiresAt"]:', "if False:", "pass",
             ["response-acquired-outside-query-boundary"]),
            ('if acquisition["acquiredAt"] > authority.verification_time_ms:', "if False:", None,
             ["response-acquired-after-decision-time"]),
            # FRC-9 replay inputs and classification.
            ('return {"decision": "indeterminate", "reason": "recorded replay commerce inputs unavailable"}',
             'return {"decision": "pass", "reason": "mutant"}', "pass",
             ["replay-commerce-inputs-unavailable"]),
            ('    if classification is not None:\n        return classification\n    if authority.mode != "replay":',
             '    if authority.mode != "replay":', None, ["replay-authority-policy-malformed"]),
            # FV entry: each structural rule of the verifier-owned policy.
            ('        or not policy["authorities"]\n    ):', "    ):", None,
             ["resolution-authority-policy-authorities-empty"]),
            ("return len(authority_ids) == len(set(authority_ids))", "return True", None,
             ["resolution-authority-policy-duplicate-authority-id"]),
            ("        if len(key_ids) != len(set(key_ids)):\n            return False\n", "", None,
             ["resolution-authority-policy-duplicate-key-id"]),
            ("            or not keys\n", "", None,
             ["resolution-authority-policy-seat-without-keys"]),
            ('                or key.get("algorithm") != "ed25519"\n', "", None,
             ["resolution-authority-policy-key-algorithm-unknown"]),
            ('        or len(policy["unavailableReasons"]) != len(set(policy["unavailableReasons"]))\n', "", None,
             ["resolution-authority-policy-unavailable-reasons-duplicate"]),
        ]
        for old, new, mutant_decision, names in guards:
            module = mutant(old, new)
            for name in names:
                case = self.case(name)
                payload = copy.deepcopy(case["input"])
                with self.subTest(case=name, guard=old):
                    self.assertEqual(case["expected"], self.execute_vector(case)["decision"])
                    if case["operation"] == "replay":
                        result = module.replay_finality_resolution(
                            payload["replayRecord"], self.authority(payload["authority"]),
                            legacy_verifier=_verify_single_view_finality,
                        )
                    elif case["operation"] == "verify-composite":
                        result = module.verify_composite_resolution(
                            [
                                {"legId": leg["legId"], "value": leg["value"],
                                 "authority": self.authority(leg["authority"])}
                                for leg in payload["legs"]
                            ],
                            payload["relationship"],
                            legacy_verifier=_verify_single_view_finality,
                        )
                    else:
                        result = module.verify_finality_resolution_context(
                            payload["value"], self.authority(payload["authority"]),
                            legacy_verifier=_verify_single_view_finality,
                        )
                    if mutant_decision is None:
                        self.assertNotEqual(case["expected"], result["decision"], result["reason"])
                    else:
                        self.assertEqual(mutant_decision, result["decision"], result["reason"])

    def test_materialized_replay_record_is_the_current_decision_record(self):
        case = self.case("recorded-policy-replay")
        self.assertEqual(
            self.verify()["replayRecord"], case["input"]["replayRecord"]
        )
        authority = case["input"]["authority"]
        self.assertEqual("replay", authority["mode"])
        self.assertEqual(self.data["positive"]["value"], authority["replayValue"])
        result = self.execute_vector(case)
        self.assertTrue(result["historicalReplay"])
        self.assertFalse(result["currentFinalityDecision"])
        # The same recorded authority cannot authorize a current decision.
        self.assertEqual(
            "indeterminate",
            self.verify(authority=self.authority(authority))["decision"],
        )

    def test_unknown_response_version_is_malformed_not_ignored(self):
        case = self.case("response-version-unknown")
        responses = {
            response["authorityId"]: response
            for response in case["input"]["value"]["context"]["responseArtifacts"]
        }
        unknown = responses["observer-a"]
        self.assertEqual("2", unknown["finalityObservationResponseVersion"])
        self.assertEqual("1", responses["observer-b"]["finalityObservationResponseVersion"])
        # Genuinely signed by the configured key, for the issued query, and
        # acquired by the verifier: only the closed version value differs.
        seat = next(
            seat for seat in case["input"]["authority"]["policy"]["authorities"]
            if seat["authorityId"] == "observer-a"
        )
        Ed25519PublicKey.from_public_bytes(
            decode_key(seat["verificationKeys"][0]["publicKey"])
        ).verify(
            decode_key(unknown["signature"]["value"]),
            (RESPONSE_DOMAIN + response_signature_hash(unknown)).encode("ascii"),
        )
        self.assertEqual(
            hash_value(case["input"]["authority"]["issuedQuery"]), unknown["queryHash"]
        )
        self.assertIn(
            hash_value(unknown),
            [record["responseHash"] for record in case["input"]["authority"]["acquisitionRecords"]],
        )
        result = self.execute_vector(case)
        self.assertEqual("error", result["decision"])
        self.assertIn("malformed finality observation response", result["reason"])

        original = FRC._response_shape

        def version_blind(response):
            if isinstance(response, dict):
                response = dict(response, finalityObservationResponseVersion="1")
            return original(response)

        with mock.patch.object(FRC, "_response_shape", version_blind):
            self.assertEqual("pass", self.execute_vector(case)["decision"])

        case = self.case("response-status-unknown")
        unknown = next(
            response for response in case["input"]["value"]["context"]["responseArtifacts"]
            if response["authorityId"] == "observer-a"
        )
        self.assertEqual("finalized", unknown["response"]["status"])
        self.assertIn(
            hash_value(unknown),
            [record["responseHash"] for record in case["input"]["authority"]["acquisitionRecords"]],
        )
        result = self.execute_vector(case)
        self.assertEqual("error", result["decision"])
        self.assertIn("malformed finality observation response", result["reason"])

        def status_blind(response):
            # Wrong implementation: any non-unavailable arm is an observation.
            if isinstance(response, dict) and isinstance(response.get("response"), dict):
                arm = response["response"]
                if arm.get("status") != "unavailable":
                    response = dict(response, response=dict(arm, status="observed"))
            return original(response)

        with mock.patch.object(FRC, "_response_shape", status_blind):
            self.assertEqual("pass", self.execute_vector(case)["decision"])

    def test_issued_query_binds_the_presented_settlement_evidence(self):
        case = self.case("issued-query-other-evidence")
        value = case["input"]["value"]
        positive = self.data["positive"]["value"]
        self.assertEqual(positive["context"], value["context"])
        self.assertEqual(
            positive["evidence"]["paymentTxRefs"], value["evidence"]["paymentTxRefs"]
        )
        self.assertNotEqual(positive["evidence"], value["evidence"])
        # The presented evidence is genuine: the historical single-view
        # contract accepts it beside an authority's signed native view.
        observed = copy.deepcopy(value)
        observed["context"] = copy.deepcopy(
            value["context"]["responseArtifacts"][0]["response"]["observation"]
        )
        self.assertEqual(
            "pass",
            _verify_single_view_finality(observed, copy.deepcopy(self.base_trusted))["decision"],
        )
        result = self.execute_vector(case)
        self.assertEqual("fail", result["decision"])
        self.assertIn("issued query does not bind", result["reason"])

        issued = case["input"]["authority"]["issuedQuery"]
        with mock.patch.object(
            FRC, "derive_query", lambda *args, **kwargs: copy.deepcopy(issued)
        ):
            self.assertEqual("pass", self.execute_vector(case)["decision"])

    def test_conflicting_authenticated_heads_reach_frc7(self):
        case, value, payload = self.materialized("fv-conflicting-authenticated-heads")
        responses = {
            response["authorityId"]: response
            for response in value["context"]["responseArtifacts"]
        }
        self.assertEqual(value["context"]["responseArtifacts"], payload["retainedResponses"])
        self.assertEqual(["observer-a", "observer-b"], sorted(responses))
        self.assert_valid_native_view(responses["observer-a"])
        self.assert_valid_native_view(responses["observer-b"])
        self.assert_sibling_forks(responses["observer-a"], responses["observer-b"])
        result = self.verify(value, self.authority(payload))
        self.assertEqual(case["expected"], result["decision"])
        self.assertIn("configured authorities supplied conflicting finalized views", result["reason"])

    def test_retained_reorg_reaches_frc7(self):
        case, value, payload = self.materialized("fv-reorg-unresolved")
        transported = value["context"]["responseArtifacts"]
        retained_only = [
            response for response in payload["retainedResponses"]
            if response not in transported
        ]
        self.assertEqual(1, len(retained_only))
        before = retained_only[0]
        self.assertEqual("observer-a", before["authorityId"])
        self.assertEqual(
            sorted(["observer-a", "observer-b"]),
            sorted(response["authorityId"] for response in transported),
        )
        self.assert_valid_native_view(before)
        for after in transported:
            self.assert_valid_native_view(after)
            self.assert_sibling_forks(before, after)
            self.assertGreater(after["signedObservationTime"], before["signedObservationTime"])
        self.assertEqual(
            1,
            len({
                hash_value(response["response"]["observation"])
                for response in transported
            }),
        )
        result = self.verify(value, self.authority(payload))
        self.assertEqual(case["expected"], result["decision"])
        self.assertIn("one authority supplied unresolved inconsistent observations", result["reason"])

        # Without the retained pre-reorganisation response -- equivalently,
        # letting each authority's latest signed response win -- the
        # replacement fork alone is complete consistent coverage.
        before_hash = hash_value(before)
        self.assertIn(
            before_hash,
            [record["responseHash"] for record in payload["acquisitionRecords"]],
        )
        payload["retainedResponses"].remove(before)
        payload["acquisitionRecords"] = [
            record for record in payload["acquisitionRecords"]
            if record["responseHash"] != before_hash
        ]
        value["context"]["replay"]["acquisitionRecords"] = copy.deepcopy(
            payload["acquisitionRecords"]
        )
        result = self.verify(value, self.authority(payload))
        self.assertEqual("pass", result["decision"], result["reason"])

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
            additional_commit_phase=authority.get("additionalCommitPhase"),
            agreement_selection_result=authority.get("agreementSelectionResult"),
            legacy_agreement_authority_by_phase_key=authority[
                "legacyAgreementAuthorityByPhaseKey"
            ],
        )
        self.assertEqual("pass", decision, reason)
        self.assertEqual(["2:pay-evm-erc20"], phase_keys)

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
            "7b3a284df3ca11f9aae6976c50188db53b320943259db445a5506e260da9af5b",
            query_digest,
        )
        self.assertEqual(response["queryHash"], query_digest)
        self.assertEqual(
            "1af364dfb377f1057cca64ec4dba9e4aad78757cf67c91293a53cbad3a52a5ee",
            response_digest,
        )
        self.assertEqual(
            "46498bcc6ce15f152614988a265b5cd5bfe14aa8dc95226931d1cb09aa97fa3c",
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
