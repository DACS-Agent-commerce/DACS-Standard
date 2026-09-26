"""Ordinary compatibility controls for the shared synthetic receipt consumer."""
import base64
import copy
import unittest

from scripts import generate_reputation_authenticated_window_vectors as awt_fixtures
from scripts import generate_reputation_participation_vectors as spa_fixtures
from scripts import reputation_evidence as evidence
from tests import test_reputation_authenticated_window_vectors as awt
from tests import test_reputation_participation_vectors as spa


class ReceiptCompatibilityTests(unittest.TestCase):
    def test_known_unissued_and_exact_expiry_fail(self):
        context = spa.fixture_verifier_state()
        record = context["challengeState"][0]
        challenge = {"jobId": record["jobId"], "nonce": record["nonce"]}
        duration = context["challengePolicy"]["duration"]
        self.assertEqual(spa.ChallengeStore([], duration).consume_presented(challenge, 1500), "fail")
        store = spa.ChallengeStore([record], duration)
        self.assertEqual(store.consume_presented(challenge, record["expiresAt"]), "fail")
        self.assertEqual(store.records[(record["jobId"], record["nonce"])]["status"], "consumed")
        self.assertEqual(spa.ChallengeStore([record], duration).consume_presented(challenge, record["expiresAt"] - 1), "pass")

    def test_adapter_limit_does_not_reclassify_unavailable_signature_algorithm(self):
        encoded = base64.urlsafe_b64encode(b"x" * (evidence.FIXTURE_MAX_DECODED_BYTES + 1)).rstrip(b"=").decode("ascii")
        for algorithm in ("ecdsa-secp256k1", "sr1-aggregate"):
            self.assertEqual(evidence.verify_detached_signature_status(
                {"algorithm": algorithm, "signer": spa_fixtures.ADAPTER, "value": encoded},
                domain="fixture-compatibility:", digest="ab" * 32, signer_field="signer",
            ), "indeterminate")
        self.assertIsNone(evidence.decode_canonical_object(encoded))

    def test_decimal_height_and_optional_block_members(self):
        self.assertTrue(evidence._valid_block_ref({"id": "block"}))
        for height in ("0", "123456789012345678901234567890"):
            self.assertTrue(evidence._valid_block_ref({"id": "block", "height": height}))
        for height in (
            "00", "020", "NaN", "+1", "-1", "1.0", "2e3", " 1", "1 ", "١",
            "", [], 1,
        ):
            self.assertFalse(evidence._valid_block_ref({"id": "block", "height": height}))

    def test_known_channel_fields_and_signed_extensions(self):
        message = {"channelId": "channel", "sentAt": 1000, "refs": {"repliesTo": 1}, "extension": {"v": 1}}
        self.assertTrue(spa.valid_channel_envelope_fields(message))
        for field, value in (("channelId", []), ("sentAt", "1000"), ("sentAt", True), ("refs", []), ("refs", {"repliesTo": "1"})):
            candidate = copy.deepcopy(message)
            candidate[field] = value
            self.assertFalse(spa.valid_channel_envelope_fields(candidate))
        message["refs"]["extension"] = "preserved"
        self.assertTrue(spa.valid_channel_envelope_fields(message))

    def test_awt_observation_failure_preserves_exact_final_receipt(self):
        prior = awt_fixtures.receipt(native_order=20)
        observation = awt_fixtures.receipt(
            disposition="indeterminate", native_order=21, preserved_receipt=prior,
        )
        status, selected, history = awt.resolve_anchor_history(awt_fixtures.BUNDLE, [prior, observation])
        self.assertEqual(status, "pass")
        self.assertEqual(selected, prior)
        self.assertIn(observation, history)
        self.assertFalse(evidence.verify_anchor_receipt(
            observation,
            expected_binding={field: awt_fixtures.BUNDLE[field] for field in evidence.ANCHOR_BINDING_FIELDS},
            adapter_domain=awt.ANCHOR_ADAPTER_DOMAIN, adapter_policy=awt.ANCHOR_POLICY,
            trusted_adapter=awt.TRUSTED_ANCHOR_ADAPTER, authorized_signer=awt_fixtures.BUNDLE["writer"],
        ))
        self.assertEqual(awt.resolve_anchor_history(awt_fixtures.BUNDLE, [prior, observation], selected=prior)[0], "pass")
        self.assertEqual(awt.resolve_anchor_history(awt_fixtures.BUNDLE, [observation])[0], "indeterminate")
        self.assertEqual(awt.resolve_anchor_history(awt_fixtures.BUNDLE, [prior, observation], selected=observation)[0], "indeterminate")

    def test_spa_observation_failure_preserves_deadline_receipt(self):
        data = spa_fixtures.one_sided_input()
        participation = data["participationEvidence"]
        admission = participation["admission"]
        prior = participation["admissionReceipt"]
        observation = copy.deepcopy(prior)
        observation["observationDisposition"] = "indeterminate"
        observation["preservedReceiptHash"] = evidence.jcs_hash(prior)
        observation["observedAt"] += 1
        order = spa_fixtures.receipt_adapter_evidence(prior)["nativeOrder"]
        spa_fixtures.seal_receipt(observation, native_order=order + 1)
        participation["admissionReceiptHistory"].append(observation)
        status, selected = spa.receipt_status(data, admission, admission["signature"]["signer"], {"nonce": "9"})
        self.assertEqual(status, "pass")
        self.assertEqual(selected, prior)
        self.assertEqual(spa.evaluate_one_sided(
            data, challenge_store=spa.ChallengeStore(spa.fixture_verifier_state()["challengeState"], 1000),
            verifier_now=1500, anchor_binding={"nonce": "9"},
        )[0], "pass")
