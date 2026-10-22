"""Monotonic retry history and authenticated nonce exhaustion regressions."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests import pay_dem_reference_handler as handler
from tests import test_pay_dem_execution_vectors as pay
from tests import test_alternative_payment_projection_vectors as apr
from scripts import generate_alternative_payment_projection_vectors as aprgen

ROOT = Path(__file__).resolve().parents[1]


class RecoveryFinalityTests(unittest.TestCase):
    def first(self, work, outcome='timeout'):
        payer = handler.PayerHandler(handler.Store(work / 'store'), handler.Node(work, 'first', confirm=outcome), 'first')
        self.assertEqual('indeterminate', payer.pay(pay.generator.signed())['expected'])
        return payer

    def later(self, work, store, **options):
        return handler.PayerHandler(store, handler.Node(work, 'later'), 'later',
                                   recovery=handler.RecoveryAuthority(pay.generator.NETWORK), **options)

    def test_recovery_balance_cannot_erase_possible_egress(self):
        for outcome in ('insufficient-balance', 'refused-not-valid', 'timeout', 'transport-error', 'crash-after-retain'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                if outcome == 'crash-after-retain':
                    first = handler.PayerHandler(handler.Store(work / 'store'), handler.Node(work, 'first'), 'first', crash_at='after-retain')
                    with self.assertRaises(handler.Crashed): first.pay(pay.generator.signed())
                else: first = self.first(work, outcome)
                later = self.later(work, first.store)
                later.node.balance = 'insufficient'
                later.node.outcomes['confirm'] = 'insufficient-balance'
                self.assertEqual('substrate', later.recover()['errorClass'])
                self.assertIsNone(first.store.read(first.journal)['result'])
                self.assertEqual('pass', self.later(work, first.store).recover()['expected'])

    def test_recovery_crashes_preserve_one_transfer_and_fresh_confirm(self):
        for point in ('before-recovery-journal', 'after-recovery-journal', 'before-confirm', 'after-confirm',
                      'after-confirm-journal', 'before-broadcast', 'after-broadcast', 'after-broadcast-journal'):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                first = self.first(work)
                later = self.later(work, first.store, crash_at=point)
                with self.assertRaises(handler.Crashed): later.recover()
                final = self.later(work, first.store)
                self.assertEqual('pass', final.recover()['expected'])
                self.assertIsNone(first.store.read(first.journal)['result'])
                calls = handler.read_lines(work / 'egress.jsonl')
                self.assertTrue(all(handler.same_signed_bytes(pay.generator.signed(), c['transaction']) for c in calls))
                self.assertTrue(all(c['retainedAtEgress'] for c in calls))
                self.assertEqual(1, len(list(first.store.journals())))

    def test_initial_crash_points_with_recovery_authority_configured(self):
        from tests.test_pay_dem_crash_restart import PAYER_POINTS
        for point in PAYER_POINTS:
            with self.subTest(point=point), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                store = handler.Store(work / 'store')
                first = self.later(work, store, crash_at=point)
                with self.assertRaises(handler.Crashed): first.pay(pay.generator.signed())
                final = self.later(work, store)
                result = final.pay(pay.generator.signed()) if store.read(final.journal) is None else final.recover()
                self.assertEqual('pass', result['expected'])
                self.assertEqual(1, len(list(store.journals())))
                calls = handler.read_lines(work / 'egress.jsonl')
                self.assertTrue(all(c['retainedAtEgress'] for c in calls))
                self.assertTrue(all(handler.same_signed_bytes(pay.generator.signed(), c['transaction']) for c in calls))

    def test_saved_recovery_arm_needs_fresh_checks_even_in_the_same_start(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            first = self.first(work)
            later = self.later(work, first.store)
            later.node.balance = 'insufficient'
            self.assertEqual('substrate', later.recover()['errorClass'])
            calls = handler.read_lines(work / 'egress.jsonl')
            later.node.balance = 'sufficient'
            later.recovery.nonce_active = False
            self.assertEqual('substrate', later.advance()['errorClass'])
            self.assertEqual('substrate', later.recover()['errorClass'])
            self.assertEqual(calls, handler.read_lines(work / 'egress.jsonl'))
            later.recovery.nonce_active = True
            later.node.pending_state = 'present'
            self.assertEqual('substrate', later.recover()['errorClass'])
            self.assertEqual(calls, handler.read_lines(work / 'egress.jsonl'))
            later.node.pending_state = 'absent'
            self.assertEqual('pass', later.recover()['expected'])

    def test_nonce_consumption_requires_authenticated_final_absence(self):
        for fault in (None, 'signature', 'network', 'genesis', 'retention', 'nonce', 'present', 'unfinalized', 'block', 'fork'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                first = self.first(work)
                later = self.later(work, first.store)
                later.recovery.account_nonce = pay.generator.NONCE
                later.recovery.proof_fault = fault
                later.node.outcomes['confirm'] = 'refused-not-valid'
                result = later.recover()
                if fault is not None:
                    self.assertEqual('substrate', result['errorClass'])
                    self.assertIsNone(first.store.read(first.journal)['result'])
                    continue
                self.assertEqual('permanent', result['errorClass'])
                entry = first.store.read(first.journal)
                self.assertEqual('nonce-exhaustion', entry['failureProof']['kind'])
                self.assertEqual('permanent', later.advance()['errorClass'])
                self.assertEqual('permanent', self.later(work, first.store).advance()['errorClass'])
                # Losing trust never reopens the ended phase, even if a later RPC reports success.
                later.bindings[0]['executionResultPolicy']['authorityKeys'] = {}
                later.node.relays_confirm = True
                self.assertEqual('substrate', later.advance()['errorClass'])
                data = json.loads(apr.VECTORS.read_text())
                case = next(v for v in data['vectors'] if v['name'] == 'fresh-job-after-conclusive-no-settlement')
                value = apr.materialize(data, case)
                value['runtime']['payDemReconciliationTrust']['nonceEnforcement'] = copy.deepcopy(later.bindings[0]['nonceEnforcement'])
                context = value['runtime']['priorPaymentContext']
                apr_proof = pay.generator.nonce_exhaustion_proof(context['disposition']['retainedPayDemTransfer'])
                context['resolution']['payDemFailureProof'] = apr_proof
                context['disposition']['reconciliationEvidenceRefs'][0]['contentHash'] = apr.digest(apr_proof)
                aprgen.sign_all(value)
                self.assertEqual(('pass', None), apr.evaluate(value))
                context['disposition']['retainedPayDemTransfer']['nonce'] += 1
                aprgen.sign_all(value)
                self.assertEqual(('fail', 'prior-disposition-proof'), apr.evaluate(value))

    def test_nonce_state_quorum_accepts_any_threshold_and_ignores_bad_extras(self):
        proof = pay.generator.nonce_exhaustion_proof(pay.generator.retained())
        value = {'railNetwork': pay.generator.NETWORK, **pay.generator.FINALITY,
                 'fv5Policy': pay.generator.FV5_POLICY, 'retainedTransfer': pay.generator.retained(),
                 'nonceEnforcement': pay.generator.binding_entry()['nonceEnforcement']}
        result = proof['authentication']
        payload = {k: v for k, v in result.items() if k != 'attestations'}
        message = (pay.generator.DEMOS_EXECUTION_DOMAIN + pay.generator.hash_value(payload)).encode('ascii')
        result['attestations'] = [
            {'authorityRef': name, 'algorithm': 'ed25519',
             'value': pay.generator._b64u(pay.generator.FV5_SIGNERS[name].sign(message))}
            for name in ('execution-b', 'execution-c')]
        result['attestations'] += [None, {'authorityRef': 'unknown', 'algorithm': 'ed25519', 'value': 'invalid'}]
        self.assertTrue(pay.nonce_exhaustion_valid(proof, value))
        result['accountNonce'] = float(result['accountNonce'])
        result['blockNumber'] = float(result['blockNumber'])
        result['retainedTransfer'] = dict(reversed(list(result['retainedTransfer'].items())))
        result['nonceEnforcement'] = dict(reversed(list(result['nonceEnforcement'].items())))
        value['nonceEnforcement']['activationHeight'] = 0.0
        self.assertTrue(pay.nonce_exhaustion_valid(proof, value))
        malformed = copy.deepcopy(proof)
        malformed['authentication']['blockId'] = float('inf')
        self.assertFalse(pay.nonce_exhaustion_valid(malformed, value))
        result['attestations'] = [result['attestations'][0]] * 2
        self.assertFalse(pay.nonce_exhaustion_valid(proof, value))
        value['fv5Policy'] = copy.deepcopy(value['fv5Policy'])
        value['fv5Policy']['authorityKeys']['execution-c'] = value['fv5Policy']['authorityKeys']['execution-b']
        self.assertFalse(pay.nonce_exhaustion_valid(proof, value))

    def test_recovery_fork_attestation_is_bound_and_active(self):
        for fault in (None, 'integer-valued', 'missing', 'network', 'genesis', 'future', 'digest', 'ambiguous'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                first = self.first(work)
                later = self.later(work, first.store)
                attestation = later.bindings[0].get('nonceEnforcement')
                self.assertIsInstance(attestation, dict)
                if fault == 'integer-valued': attestation['activationHeight'] = 0.0
                elif fault == 'missing': later.bindings[0].pop('nonceEnforcement')
                elif fault == 'network': attestation['networkId'] = 'demos:another'
                elif fault == 'genesis': attestation['genesisHash'] = pay.generator.OTHER_GENESIS['genesisHash']
                elif fault == 'future': attestation['activationHeight'] = later.node.current_block + 1
                elif fault == 'digest': attestation['sealedGenesisHash'] = '0' * 64
                elif fault == 'ambiguous': attestation['activationHeight'] = True
                self.assertEqual('pass' if fault in (None, 'integer-valued') else 'indeterminate', later.recover()['expected'])

    def test_nonce_terminal_write_survives_both_crash_edges(self):
        for point in ('before-failure-proof', 'after-failure-proof'):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                first = self.first(work)
                later = self.later(work, first.store, crash_at=point)
                later.recovery.account_nonce = pay.generator.NONCE
                calls = handler.read_lines(work / 'egress.jsonl')
                with self.assertRaises(handler.Crashed): later.recover()
                final = self.later(work, first.store)
                final.recovery.account_nonce = pay.generator.NONCE
                self.assertEqual('permanent', final.recover()['errorClass'])
                self.assertEqual(calls, handler.read_lines(work / 'egress.jsonl'))

    def test_reference_bearing_fixtures_match_generator(self):
        process = subprocess.run([sys.executable, 'scripts/generate_artifact_reference_fixtures.py', '--check'],
                                 cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(0, process.returncode, process.stdout + process.stderr)


if __name__ == '__main__':
    unittest.main()
