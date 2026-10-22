"""Evidence-boundary and recovery regressions for the native-send profile."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from tests import test_pay_dem_execution_vectors as pay
from tests import pay_dem_reference_handler as handler
from scripts import generate_settlement_finality_verification_vectors as fvgen
from scripts.settlement_finality_reference import _demos_native_send, verify_finality


def uppercase_payment(factory, *, keys=False):
    value = factory.model_input('bft-final')
    reference = value['evidence']['paymentTxRefs'][0]
    reference['txHash'] = reference['txHash'].upper()
    factory.resign_evidence(value['evidence'])
    record = factory.demos_send_record(reference)
    if keys:
        for field in ('from', 'from_ed25519_address', 'to'):
            record['content'][field] = '0x' + record['content'][field][2:].upper()
        record['content']['data'][1]['args'][0] = record['content']['data'][1]['args'][0].upper()
        record['content']['gcr_edits'] = factory.demos_send_edits(record['content'], reference['txHash'])
    value['context']['observation'] = factory.chain_observation(
        value['rail']['consumerFinalityProfile']['settlement'], reference, {}, 'uppercase-payment', record=record)
    return value


class PayDemSweepRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {v['name']: v for v in pay.generator.load_vectors(pay.VECTORS.read_text())['vectors']}

    def test_valid_json_overflow_numbers_refuse_without_crashing(self):
        # json.loads accepts this valid JSON number as float infinity.
        huge = json.loads('1e400')
        for operation in ('included-confirmed', 'delivery-after-all-gates'):
            for field in ('blockNumber', 'nonce', 'amount'):
                case = copy.deepcopy(self.cases[operation])
                record = case['protocolInput']['recordRead']['record']
                (record if field == 'blockNumber' else record['content'])[field] = huge
                with self.subTest(operation=operation, field=field):
                    self.assertNotEqual('pass', pay.evaluate(case)[0])
                    with tempfile.TemporaryDirectory() as scratch:
                        payee = handler.Payee(handler.Store(Path(scratch) / 'store'), Path(scratch), 'test')
                        payee.provision()
                        self.assertNotEqual('pass', payee.deliver(pay.generator.JOB_ID, read=case['protocolInput']['recordRead']))
        allowed = copy.deepcopy(self.cases['delivery-after-all-gates']['protocolInput']['recordRead'])
        allowed['record']['blockNumber'] = float(allowed['record']['blockNumber'])
        with tempfile.TemporaryDirectory() as scratch:
            payee = handler.Payee(handler.Store(Path(scratch) / 'store'), Path(scratch), 'allowed')
            payee.provision()
            self.assertEqual('pass', payee.deliver(pay.generator.JOB_ID, read=allowed))
        self.assertTrue(pay._safe_integer(42.0))
        for value in (huge, -huge, float('nan'), True, 2**53):
            self.assertFalse(pay._safe_integer(value))

    def test_payee_derives_applied_authentication_from_its_own_source(self):
        read = copy.deepcopy(self.cases['delivery-after-all-gates']['protocolInput']['recordRead'])
        self.assertNotIn('appliedTransfer', read['executionResult'])
        read['appliedTransfer']['committedBalances'] = {
            'payerBeforeOs': '2000000000', 'payerAfterOs': '500000000',
            'payeeBeforeOs': '0', 'payeeAfterOs': pay.generator.AMOUNT_OS, 'feeOs': '0'}
        # Presenter claims the full payment, while the payee's source saw no apply.
        with tempfile.TemporaryDirectory() as scratch:
            payee = handler.Payee(handler.Store(Path(scratch) / 'store'), Path(scratch), 'test')
            payee.provision()
            payee.applied_authority = handler.AppliedAuthority(pay.generator.NETWORK, 'failed')
            self.assertNotEqual('pass', payee.deliver(pay.generator.JOB_ID, read=read))
            self.assertEqual(set(), payee.delivered())
            payee.applied_authority = None
            self.assertEqual('indeterminate', payee.deliver(pay.generator.JOB_ID, read=read))
            # A configured source can establish payment even if presented flags lie.
            payee.applied_authority = handler.AppliedAuthority(pay.generator.NETWORK)
            read['appliedTransferAuthenticated'] = False
            read['appliedTransfer']['committedBalances'] = pay.generator.ROLLED_BACK
            self.assertEqual('pass', payee.deliver(pay.generator.JOB_ID, read=read))

    def test_consistently_uppercase_certified_payment_never_passes(self):
        # Isolate the key-format boundary too: phase comparisons and carried
        # balance proofs must not mask a decoder accepting noncanonical keys.
        factory = fvgen.FixtureFactory()
        reference = factory.model_input('bft-final')['evidence']['paymentTxRefs'][0]
        record = factory.demos_send_record(reference)
        self.assertIsNotNone(_demos_native_send(record))
        for field in ('from', 'from_ed25519_address', 'to'):
            record['content'][field] = '0x' + record['content'][field][2:].upper()
        record['content']['data'][1]['args'][0] = record['content']['data'][1]['args'][0].upper()
        self.assertIsNone(_demos_native_send(record))
        for keys in (False, True):
            factory = fvgen.FixtureFactory()
            self.assertEqual('pass', verify_finality(factory.model_input('bft-final'), factory.trusted)['decision'])
            value = uppercase_payment(factory, keys=keys)
            with self.subTest(keys=keys):
                self.assertIn(verify_finality(value, factory.trusted)['decision'], ('error', 'indeterminate'))

    def test_bft_native_profile_refuses_another_reference_kind(self):
        for event_type in ('transfer', 'tank-source-lock'):
            factory = fvgen.FixtureFactory()
            self.assertEqual('pass', verify_finality(factory.model_input('bft-final'), factory.trusted)['decision'])
            value = factory.model_input('bft-final')
            profile = value['rail']['consumerFinalityProfile']
            profile['settlement'] = factory.chain_profile('bft-final')
            factory.rebind_rail(value)
            reference = {'kind': 'evm-event', 'chainId': 1, 'txHash': 'ab' * 32, 'logIndex': 0}
            value['evidence']['paymentTxRefs'] = [reference]
            factory.resign_evidence(value['evidence'])
            session = factory.trusted['sessionAuthorityByJob'][value['agreement']['jobId']]
            event = factory.common_event(reference, session, event_type=event_type)
            if event_type != 'transfer':
                event.update(bridgeId='another-bridge', transferId='a-lock')
            value['context']['observation'] = factory.chain_observation(
                profile['settlement'], reference, event, 'non-demos-bft')
            with self.subTest(event_type=event_type):
                self.assertEqual('error', verify_finality(value, factory.trusted)['decision'])

    def test_deliver_first_payment_can_recover_identical_bytes(self):
        for outcome in ('transport-error', 'timeout', 'refused-not-valid', 'insufficient-balance'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                # PIPE-4 permits this completed delivery before the payment phase.
                (work / 'delivered-first').write_text('delivery complete')
                store = handler.Store(work / 'store')
                first = handler.PayerHandler(store, handler.Node(work, 'first', confirm=outcome), 'first')
                tx = pay.generator.signed()
                self.assertEqual('indeterminate', first.pay(tx)['expected'])
                later = handler.PayerHandler(store, handler.Node(work, 'later'), 'later', recovery=handler.RecoveryAuthority(pay.generator.NETWORK))
                self.assertEqual('indeterminate', later.advance()['expected'])
                self.assertEqual('pass', later.recover()['expected'])
                calls = handler.read_lines(work / 'egress.jsonl')
                self.assertTrue(all(handler.same_signed_bytes(tx, call['transaction']) for call in calls))
                self.assertEqual('pass', later.recover()['expected'])
                self.assertEqual(calls, handler.read_lines(work / 'egress.jsonl'))

    def test_recovery_requires_absent_record_mempool_and_active_network_authority(self):
        from unittest.mock import patch
        for scenario in ('no-authority', 'wrong-network', 'inactive', 'ambiguous-fork', 'pending', 'mempool-unavailable',
                         'record-unavailable', 'malformed-record', 'record-found'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                first = handler.PayerHandler(handler.Store(work / 'store'), handler.Node(work, 'first', confirm='timeout'), 'first')
                first.pay(pay.generator.signed())
                source = handler.RecoveryAuthority(pay.generator.NETWORK)
                if scenario == 'no-authority': source = None
                if scenario == 'wrong-network': source = handler.RecoveryAuthority(pay.generator.OTHER_NETWORK)
                if scenario == 'inactive': source.nonce_active = False
                if scenario == 'ambiguous-fork': source.nonce_active = 'true'
                node = handler.Node(work, 'later')
                later = handler.PayerHandler(first.store, node, 'later', recovery=source)
                read = {'state': 'not-found'}
                if scenario == 'record-unavailable': read = {'state': 'unavailable'}
                if scenario == 'malformed-record': read = []
                if scenario == 'record-found': read = {'state': 'found', 'record': pay.generator.record('pending')}
                mempool = 'present' if scenario == 'pending' else 'unavailable' if scenario == 'mempool-unavailable' else 'absent'
                calls = handler.read_lines(work / 'egress.jsonl')
                with patch.object(node, 'read', return_value=read), patch.object(node, 'mempool', return_value=mempool):
                    self.assertEqual('indeterminate', later.recover()['expected'])
                self.assertEqual(calls, handler.read_lines(work / 'egress.jsonl'))

    def test_concurrent_recovery_serializes_one_fresh_submission(self):
        from concurrent.futures import ThreadPoolExecutor
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            first = handler.PayerHandler(handler.Store(work / 'store'), handler.Node(work, 'first', confirm='timeout'), 'first')
            first.pay(pay.generator.signed())
            later = [handler.PayerHandler(first.store, handler.Node(work, label), label,
                recovery=handler.RecoveryAuthority(pay.generator.NETWORK)) for label in ('second', 'third')]
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda payer: payer.recover(), later))
            self.assertEqual(['pass', 'pass'], [r['expected'] for r in results])
            self.assertEqual(['confirm', 'confirm', 'broadcast'],
                             [v['call'] for v in handler.read_lines(work / 'egress.jsonl')])

    def test_recovery_never_reopens_a_proven_failure(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            first = handler.PayerHandler(handler.Store(work / 'store'), handler.Node(work, 'first', record_status='failed'),
                'first', fv5=handler.Fv5Authority('policy', 'failed'))
            self.assertEqual('fail', first.pay(pay.generator.signed())['expected'])
            calls = handler.read_lines(work / 'egress.jsonl')
            later = handler.PayerHandler(first.store, handler.Node(work, 'later'), 'later',
                fv5=handler.Fv5Authority('policy'), recovery=handler.RecoveryAuthority(pay.generator.NETWORK))
            self.assertNotEqual('pass', later.recover()['expected'])
            self.assertEqual(calls, handler.read_lines(work / 'egress.jsonl'))

    def test_recovery_after_retention_before_confirm(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            first = handler.PayerHandler(handler.Store(work / 'store'), handler.Node(work, 'first'), 'first', crash_at='after-retain')
            with self.assertRaises(handler.Crashed):
                first.pay(pay.generator.signed())
            later = handler.PayerHandler(first.store, handler.Node(work, 'later'), 'later', recovery=handler.RecoveryAuthority(pay.generator.NETWORK))
            self.assertEqual('pass', later.recover()['expected'])


if __name__ == '__main__':
    unittest.main()
