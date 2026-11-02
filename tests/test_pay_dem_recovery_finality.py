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

    def test_possible_egress_stays_open_without_resubmission(self):
        for outcome in ('insufficient-balance', 'refused-not-valid', 'timeout', 'transport-error', 'crash-after-retain'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                if outcome == 'crash-after-retain':
                    first = handler.PayerHandler(handler.Store(work / 'store'), handler.Node(work, 'first'), 'first', crash_at='after-retain')
                    with self.assertRaises(handler.Crashed): first.pay(pay.generator.signed())
                else:
                    first = self.first(work, outcome)
                calls = handler.read_lines(work / 'egress.jsonl')
                for boot in ('later', 'again'):
                    later = self.later(work, first.store)
                    self.assertEqual({'expected': 'indeterminate', **pay.HANDLER_WANT['indeterminate']}, later.recover())
                    self.assertIsNone(first.store.read(first.journal)['result'])
                self.assertEqual(calls, handler.read_lines(work / 'egress.jsonl'))

    def test_initial_crash_points_with_local_fork_pin_send_nothing_on_recovery(self):
        from tests.test_pay_dem_crash_restart import PAYER_POINTS
        for point in PAYER_POINTS:
            with self.subTest(point=point), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                store = handler.Store(work / 'store')
                first = self.later(work, store, crash_at=point)
                with self.assertRaises(handler.Crashed): first.pay(pay.generator.signed())
                calls = handler.read_lines(work / 'egress.jsonl')
                final = self.later(work, store)
                result = final.recover()
                # Before retention there is no phase to recover. After broadcast,
                # independently verified execution may resolve the original effect.
                self.assertIn(result.get('expected'), (None, 'pass', 'indeterminate'))
                self.assertEqual(calls, handler.read_lines(work / 'egress.jsonl'))
                self.assertTrue(all(c['retainedAtEgress'] for c in calls))

    def test_nonce_terminal_is_refused_even_with_valid_fixture_authentication(self):
        for fault in (None, 'signature', 'network', 'genesis', 'retention', 'nonce', 'present', 'unfinalized', 'block', 'fork'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                first = self.first(work)
                later = self.later(work, first.store)
                later.recovery.account_nonce = pay.generator.NONCE
                later.recovery.proof_fault = fault
                calls = handler.read_lines(work / 'egress.jsonl')
                result = later.recover()
                self.assertEqual({'expected': 'indeterminate', **pay.HANDLER_WANT['indeterminate']}, result)
                self.assertEqual(result, later.advance())
                self.assertEqual(result, self.later(work, first.store).recover())
                self.assertIsNone(first.store.read(first.journal)['result'])
                self.assertNotIn('failureProof', first.store.read(first.journal))
                self.assertEqual(calls, handler.read_lines(work / 'egress.jsonl'))

    def test_saved_nonce_terminal_does_not_authorize_resume_or_compensation(self):
        value = pay.generator.classify('saved-nonce', 'indeterminate', 'DEM-4', [], '', read=pay.generator.NOT_FOUND)['protocolInput']
        value['retainedFailureProof'] = pay.generator.nonce_exhaustion_proof(pay.generator.retained())
        value['nonceEnforcement'] = pay.generator.binding_entry()['nonceEnforcement']
        self.assertEqual('indeterminate', pay.resume(value, frozenset())[0])
        self.assertEqual(('indeterminate', {'reconciliationEvidence': False}), pay.apr_evidence(value, frozenset()))
        data = json.loads(apr.VECTORS.read_text())
        case = next(v for v in data['vectors'] if v['name'] == 'fresh-job-after-nonce-exhaustion-number-nonce')
        self.assertEqual(('indeterminate', 'prior-disposition-proof'), apr.evaluate(apr.materialize(data, case)))

    def test_saved_retry_arm_and_caller_flag_grant_no_egress(self):
        cases = {v['name']: v for v in pay.generator.document()['vectors']}
        value = pay.generator.decode_exact_members(copy.deepcopy(cases['recovery-gate-allowed']))
        value['protocolInput'].pop('recoveryCheck')
        value['protocolInput']['recoveryAuthorized'] = True
        self.assertEqual(('fail', {'broadcastPermitted': False}), pay.evaluate(value))

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

    def test_reference_bearing_fixtures_match_generator(self):
        process = subprocess.run([sys.executable, 'scripts/generate_artifact_reference_fixtures.py', '--check'],
                                 cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(0, process.returncode, process.stdout + process.stderr)


if __name__ == '__main__':
    unittest.main()
