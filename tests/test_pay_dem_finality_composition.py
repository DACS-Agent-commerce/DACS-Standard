"""Native-payment finality composition and recovery regressions."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from tests import test_pay_dem_execution_vectors as pay
from tests import test_alternative_payment_projection_vectors as apr
from scripts import generate_settlement_finality_verification_vectors as fvgen
from scripts.settlement_finality_reference import (
    artifact_hash, canonical_bytes, verify_finality, verify_transaction_inclusion,
)


class PayDemFinalityCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pay_cases = {v['name']: v for v in pay.generator.load_vectors(pay.VECTORS.read_text())['vectors']}
        cls.apr_data = json.loads(apr.VECTORS.read_text())
        cls.apr_cases = {v['name']: v for v in cls.apr_data['vectors']}

    def payment(self, name='delivery-fv-form-result'):
        return copy.deepcopy(self.pay_cases[name])

    def replacement(self):
        return apr.materialize(self.apr_data, self.apr_cases['fresh-job-after-conclusive-no-settlement'])

    def test_malformed_claims_do_not_depend_on_execution_authentication(self):
        for missing in (True, False):
            for claims in ({fvgen.CLAIMS['buyer']: [42]}, {fvgen.CLAIMS['buyer']: [{'claim': 'key:ab?a=%xx', 'control': 'presentation-signature'}]}):
                factory = fvgen.FixtureFactory()
                value = factory.model_input('bft-final')
                observation = value['context']['observation']
                if missing:
                    observation.pop('executionResult')
                else:
                    observation['executionResult']['attestations'] = []
                factory.trusted['demosPayerKeyClaims'] = claims
                with self.subTest(missing=missing, claims=claims):
                    self.assertEqual('error', verify_finality(value, factory.trusted)['decision'])
                    factory.trusted['demosPayerKeyClaims'] = {fvgen.CLAIMS['buyer']: [fvgen.controlled_claim('key:' + factory.demos_key('buyer'))]}
                    self.assertEqual('indeterminate', verify_finality(value, factory.trusted)['decision'])

    def test_malformed_claims_survive_unavailable_inclusion(self):
        for absent in ('observation', 'transaction-proof'):
            factory = fvgen.FixtureFactory()
            value = factory.model_input('bft-final')
            if absent == 'observation':
                value['context']['observation'] = None
            else:
                value['context']['observation']['transactionInclusionProof'] = None
            factory.trusted['demosPayerKeyClaims'] = {fvgen.CLAIMS['buyer']: [42]}
            self.assertEqual('error', verify_finality(value, factory.trusted)['decision'])
            factory.trusted['demosPayerKeyClaims'] = {fvgen.CLAIMS['buyer']: [fvgen.controlled_claim('key:' + factory.demos_key('buyer'))]}
            self.assertEqual('indeterminate', verify_finality(value, factory.trusted)['decision'])

    def test_identity_fixture_native_rails_name_their_finality_network(self):
        data = json.loads((pay.ROOT / 'conformance/vectors/security/identity-bundle-hash-binding-v0.1.json').read_text())
        rails = []
        def walk(value):
            if isinstance(value, dict):
                if value.get('phaseHandler') == 'pay-dem':
                    rails.append(value)
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
        walk(data)
        self.assertTrue(rails)
        for rail in rails:
            self.assertEqual('bft-final', rail['consumerFinalityProfile']['settlement']['kind'])
            self.assertEqual(pay.generator.NETWORK['networkId'], rail['consumerFinalityProfile']['settlement']['networkId'])

    def test_jcs_vector_hash_accepts_equivalent_numbers_and_rejects_edits(self):
        from scripts.validate_security_vectors import validate_set
        path = pay.ROOT / 'conformance/vectors/security/settlement-finality-verification.json'
        data = json.loads(path.read_text())
        self.assertEqual([], validate_set(str(path))[0])
        data['vectors'][-1]['note'] += 'changed without updating the hash'
        with tempfile.TemporaryDirectory() as scratch:
            modified = Path(scratch) / path.name
            modified.write_text(json.dumps(data))
            self.assertTrue(any('hash' in error for error in validate_set(str(modified))[0]))

    def test_fixture_domain_is_separate_from_the_production_registry(self):
        from scripts.validate_domain_separators import registered_domains
        from scripts.validate_conformance_vectors import load_registered_domain_separators
        from scripts import specsource
        domain = 'dacs-fixture-demos-execution:v1:'
        self.assertIn(domain, registered_domains(specsource.spec_text(pay.ROOT)))
        self.assertNotIn(domain, load_registered_domain_separators(pay.ROOT))

    def test_execution_result_signature_matches_the_documented_domain(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        from scripts.settlement_finality_reference import DEMOS_EXECUTION_DOMAIN, b64url_decode, hash_value
        factory = fvgen.FixtureFactory()
        result = factory.model_input('bft-final')['context']['observation']['executionResult']
        payload = {k: v for k, v in result.items() if k != 'attestations'}
        attestation = result['attestations'][0]
        key = Ed25519PublicKey.from_public_bytes(b64url_decode(factory.trusted['demosExecutionPolicy']['authorityKeys'][attestation['authorityRef']]))
        signature = b64url_decode(attestation['value'])
        key.verify(signature, (DEMOS_EXECUTION_DOMAIN + hash_value(payload)).encode('utf-8'))
        with self.assertRaises(InvalidSignature):
            key.verify(signature, canonical_bytes(payload))
        self.assertIn('dacs-fixture-demos-execution:v1:', (pay.ROOT / 'spec/CORE.md').read_text())

    def test_malformed_result_has_one_verdict_in_consumer_and_delivery(self):
        for name in ('delivery-fv-form-result', 'consumer-confirmed-gate-passes'):
            for label in ('empty', 'attestations', 'extra', 'record'):
                case = self.payment(name)
                read = case['protocolInput']['recordRead']
                result = copy.deepcopy(self.payment()['protocolInput']['recordRead']['executionResult'])
                if label == 'empty':
                    result = {}
                elif label == 'attestations':
                    result['attestations'] = 'not-an-array'
                elif label == 'extra':
                    result['extra'] = 1
                else:
                    result.pop('record')
                read['executionResult'] = result
                with self.subTest(name=name, label=label):
                    verdict, effect = pay.evaluate(case)
                    self.assertEqual('error', verdict)
                    self.assertFalse(effect['deliveryAuthorized'])
            self.assertEqual(self.pay_cases[name]['expected'], pay.evaluate(self.payment(name))[0])

    def test_full_fv_observation_is_a_valid_failure_carrier(self):
        value = self.replacement()
        context = value['runtime']['priorPaymentContext']
        proof = context['resolution']['payDemFailureProof']
        # The FV-form carrier includes the selected event. The inclusion
        # helper must accept it without interpreting event economics.
        factory = fvgen.FixtureFactory()
        proof['selectedEventProof'] = factory.model_input('bft-final')['context']['observation']['selectedEventProof']
        context['disposition']['reconciliationEvidenceRefs'][0]['contentHash'] = apr.digest(proof)
        from scripts import generate_alternative_payment_projection_vectors as generator
        generator.sign_all(value)
        self.assertEqual(('pass', None), apr.evaluate(value))
        trust = value['runtime']['payDemReconciliationTrust']
        self.assertEqual('pass', verify_transaction_inclusion(proof, trust['finalityProfile'], proof['transactionRef'], trust['finalityTrust'])[0])
        proof['finalityCertificate']['signatures'][0]['value'] = 'A' * 86
        self.assertNotEqual('pass', verify_transaction_inclusion(proof, trust['finalityProfile'], proof['transactionRef'], trust['finalityTrust'])[0])

    def test_native_send_has_no_job_or_execution_status_event(self):
        factory = fvgen.FixtureFactory()
        value = factory.model_input('bft-final', job_id='ANOTHER-JOB')
        observation = value['context']['observation']
        from scripts.settlement_finality_reference import decode_json_bytes
        _, event = decode_json_bytes(observation['selectedEventProof']['eventBytes'])
        self.assertEqual({'transactionRef', 'transactionId'}, set(event))
        observation.pop('selectedEventProof')
        self.assertEqual('pass', verify_finality(value, factory.trusted)['decision'])
        record = factory.demos_send_record(observation['transactionRef'], status='failed')
        value['context']['observation'] = factory.chain_observation(
            value['rail']['consumerFinalityProfile']['settlement'], observation['transactionRef'], event,
            'bft-final', record=record, state=factory.committed('rolled-back'))
        self.assertEqual('fail', verify_finality(value, factory.trusted)['decision'])

    def test_unrelated_applied_proof_cannot_veto_a_valid_signed_payment(self):
        for field, other in (('txHash', pay.generator.OTHER_TX_HASH), ('networkId', 'demos:other'),
                             ('genesisHash', 'aa' * 32), ('blockNumber', pay.generator.BLOCK + 1)):
            case = self.payment()
            case['protocolInput']['recordRead']['appliedTransfer'][field] = other
            with self.subTest(field=field):
                self.assertEqual('pass', pay.evaluate(case)[0])
                case['protocolInput']['recordRead'].pop('executionResult')
                self.assertEqual('indeterminate', pay.evaluate(case)[0])
        case = self.payment()
        read = case['protocolInput']['recordRead']
        pay.generator.with_state(read, pay.generator.committed("no-op"))
        self.assertEqual('fail', pay.evaluate(case)[0])

    def test_equivalent_json_block_numbers_preserve_authenticated_payment(self):
        factory = fvgen.FixtureFactory()
        value = factory.model_input('bft-final')
        result = value['context']['observation']['executionResult']
        original = canonical_bytes(result)
        result['appliedTransfer']['blockNumber'] = float(result['appliedTransfer']['blockNumber'])
        self.assertEqual(original, canonical_bytes(result))
        self.assertEqual('pass', verify_finality(value, factory.trusted)['decision'])
        result['appliedTransfer']['blockNumber'] = True
        self.assertEqual('indeterminate', verify_finality(value, factory.trusted)['decision'])

    def test_apr_preserves_unavailable_or_stale_verification(self):
        for unavailable in ('keys', 'stale'):
            value = self.replacement()
            trust = value['runtime']['payDemReconciliationTrust']['finalityTrust']
            if unavailable == 'keys':
                trust['observationAuthorityKeys'] = {}
            else:
                trust['verificationTimeMs'] += 7_200_000
            with self.subTest(unavailable=unavailable):
                self.assertEqual(('indeterminate', 'prior-disposition-proof'), apr.evaluate(value))
        self.assertEqual(('pass', None), apr.evaluate(self.replacement()))

    def test_apr_retention_is_carried_by_the_signed_disposition(self):
        value = self.replacement()
        context = value['runtime']['priorPaymentContext']
        self.assertNotIn('retainedTransfer', context['executionAuthority'])
        self.assertEqual(context['disposition']['priorJobId'], context['disposition']['retainedPayDemTransfer']['jobId'])
        self.assertEqual(('pass', None), apr.evaluate(value))
        context['disposition']['retainedPayDemTransfer']['txHash'] = pay.generator.OTHER_TX_HASH
        self.assertNotEqual('pass', apr.evaluate(value)[0])
        from scripts import generate_alternative_payment_projection_vectors as generator
        generator.sign_all(value)
        self.assertEqual(('fail', 'prior-disposition-proof'), apr.evaluate(value))

    def payout(self, address):
        factory = fvgen.FixtureFactory()
        value = factory.model_input('bft-final')
        agreement = value['agreement']
        agreement['payeeBoundAgreementVersion'] = agreement.pop('agreementVersion')
        agreement['terms']['payoutBindings'] = [{'railId': value['rail']['railId'], 'phaseIndex': 0, 'payeeAddress': address}]
        digest = artifact_hash(agreement, 'signatures')
        for signature, role in zip(agreement['signatures'], ('buyer', 'seller')):
            signature['value'] = factory.sign_digest(role, 'dacs-payee-bound-agreement:v1:', digest)
        factory.trusted['sessionAuthorityByJob'][agreement['jobId']]['agreementHash'] = digest
        return factory, value

    def test_signed_payout_destination_may_differ_from_party_signing_key(self):
        key = 'ab' * 32
        factory, value = self.payout('KEY:' + key + '?unknown=ok')
        observation = value['context']['observation']
        record = factory.demos_send_record(observation['transactionRef'], to='0x' + key,
            data=['native', {'nativeOperation': 'send', 'args': [key, '5000000000']}])
        value['context']['observation'] = factory.chain_observation(value['rail']['consumerFinalityProfile']['settlement'],
            observation['transactionRef'], {}, 'bft-final', record=record)
        self.assertEqual('pass', verify_finality(value, factory.trusted)['decision'])
        original = factory.demos_send_record(observation['transactionRef'])
        value['context']['observation'] = factory.chain_observation(value['rail']['consumerFinalityProfile']['settlement'],
            observation['transactionRef'], {}, 'bft-final', record=original)
        self.assertEqual('fail', verify_finality(value, factory.trusted)['decision'])

    def test_legacy_destination_authority_is_required_and_not_inferred(self):
        factory = fvgen.FixtureFactory()
        value = factory.model_input('bft-final')
        factory.trusted['sessionAuthorityByJob'][value['agreement']['jobId']].pop('payeeAddress')
        self.assertEqual('indeterminate', verify_finality(value, factory.trusted)['decision'])

    def test_payout_projection_is_checked_before_agreement_commitment(self):
        from scripts import generate_alternative_payment_projection_vectors as generator
        key = pay.generator.PAYEE_KEY
        for address, expected in ((key, 'pass'), ('0x' + key, 'pass'), ('KEY:' + key + '?a=b', 'pass'),
                                  ('did:demos:agent:' + key, 'pass'), ('demos:0x' + key, 'fail'),
                                  ('0x' + key.upper(), 'fail'), ('0X' + key, 'fail')):
            value = generator.make_base('dem')
            value['operation'] = 'validate-pipeline'
            value['agreement']['terms']['payoutBindings'][0]['payeeAddress'] = address
            generator.sign_all(value)
            with self.subTest(address=address):
                self.assertEqual(expected, apr.evaluate(value)[0])
                preflight = copy.deepcopy(next(v for v in self.pay_cases.values() if v['operation'] == 'rail-preflight' and v['expected'] == 'pass')['protocolInput'])
                preflight['payeeAddress'] = address
                self.assertEqual(expected, pay.rail_preflight(preflight, frozenset())[0])

    def test_open_payment_recovers_after_pause_maximum_without_another_egress(self):
        from tests import pay_dem_reference_handler as handler
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            first = handler.PayerHandler(handler.Store(work / 'store'), handler.Node(work, 'first'), 'first',
                fv5=handler.Fv5Authority('unfinalized'))
            pending = first.pay(pay.generator.signed())
            self.assertEqual('indeterminate', pending['expected'])
            self.assertEqual('remain-paused-re-read-only', pending['onPauseExpiry'])
            calls = handler.read_lines(work / 'egress.jsonl')
            # A freshly acquired proof after a two-hour authority outage.
            later = handler.PayerHandler(handler.Store(work / 'store'), handler.Node(work, 'later'), 'later',
                fv5=handler.Fv5Authority('policy'), clock_ms=pay.generator.FINALITY_TRUST['verificationTimeMs'] + 7_200_000)
            from unittest.mock import patch
            with patch.object(pay.generator, 'OBSERVED_AT', pay.generator.OBSERVED_AT + 7_200_000):
                result = later.pay(pay.generator.signed())
            self.assertEqual('pass', result['expected'])
            self.assertEqual(calls, handler.read_lines(work / 'egress.jsonl'))
        spec = (pay.ROOT / 'spec/DACS-5-VERIFY.md').read_text()
        self.assertIn('no elapsed time proves that it cannot settle', spec)


if __name__ == '__main__':
    unittest.main()
