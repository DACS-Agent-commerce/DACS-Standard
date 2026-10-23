"""Keep native-payment corpus metadata and composed verdicts on one contract."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import test_alternative_payment_projection_vectors as apr
from tests import test_pay_dem_execution_vectors as pay
from tests import pay_dem_reference_handler as handler
from scripts import generate_alternative_payment_projection_vectors as aprgen

ROOT = Path(__file__).resolve().parents[1]


class PayDemSweepContractTests(unittest.TestCase):
    def test_unresolved_payment_prose_has_no_timeout_terminal(self):
        plan = (ROOT / 'spec/CONFORMANCE-PLAN.md').read_text()
        threats = (ROOT / 'spec/THREAT-MODEL.md').read_text()
        self.assertNotIn('end `failed-substrate` without replacement', plan)
        self.assertNotIn('strands the phase at `failed-substrate`', threats)
        self.assertIn('remain non-terminal `substrate-failure-paused`', plan)
        self.assertIn('read-only DEM-6 recovery', threats)

    def test_unrelated_authorities_never_refute_payment_in_mapping(self):
        mapping = (ROOT / 'spec/DEMOS-MAPPING.md').read_text()
        self.assertNotIn('A contradiction covers another transaction', mapping)
        self.assertIn('An authority for another network/genesis, transaction or block is irrelevant', mapping)

    def test_apr_malformed_result_keeps_error(self):
        data = json.loads(apr.VECTORS.read_text())
        case = next(v for v in data['vectors'] if v['name'] == 'fresh-job-after-conclusive-no-settlement')
        base = apr.materialize(data, case)
        self.assertEqual(('pass', None), apr.evaluate(base))
        unknown_policy = copy.deepcopy(base)
        unknown_policy['runtime']['payDemReconciliationTrust']['fv5Policy']['kind'] = 'unregistered-result-policy'
        self.assertEqual(('indeterminate', 'prior-disposition-proof'), apr.evaluate(unknown_policy))
        for label in ('empty', 'attestations', 'unknown', 'record', 'kind'):
            value = copy.deepcopy(base)
            context = value['runtime']['priorPaymentContext']
            proof = context['resolution']['payDemFailureProof']
            result = proof['executionResult']
            if label == 'empty':
                proof['executionResult'] = {}
            elif label == 'attestations':
                result['attestations'] = 'not-an-array'
            elif label == 'unknown':
                result['extra'] = 1
            elif label == 'record':
                result.pop('record')
            else:
                result['kind'] = 'another-kind'
            context['disposition']['reconciliationEvidenceRefs'][0]['contentHash'] = apr.digest(proof)
            aprgen.sign_all(value)
            with self.subTest(label=label):
                self.assertEqual(('error', 'prior-disposition-proof'), apr.evaluate(value))

    def test_pay_dem_destination_uses_applicable_tier(self):
        data = json.loads((ROOT / 'conformance/vectors/security/payee-destination-binding-v0.1.json').read_text())
        cases = {v['name']: v for v in data['vectors']}
        old_id = cases['pb2-tier1-pay-dem-intrinsic-matches']
        self.assertFalse(old_id['bindingContext']['tier1Intrinsic'])
        self.assertEqual(3, old_id['want']['bindingTier'])
        for name, expected in (('pb2-tier2-pay-dem-controlled-claim-matches', 'pass'),
                               ('pb2-tier2-pay-dem-unavailable-no-downgrade', 'indeterminate')):
            self.assertEqual(expected, cases[name]['expected'])
            self.assertTrue(cases[name]['bindingContext']['tier2Applicable'])

    def test_historical_hash_normalization_excludes_demos(self):
        data = json.loads((ROOT / 'conformance/vectors/security/sb2-settlement-uniqueness-v0.1.json').read_text())
        self.assertEqual('non-demos-settlement-tx-id-canonicalisation-and-same-tuple-idempotency-only',
                         data['conformanceProfile']['normativeScope'])

    def test_rereads_use_network_binding_authority_and_trust(self):
        network = pay.generator.OTHER_NETWORK
        other = pay.generator.binding_entry()
        own = pay.generator.binding_entry(network)
        other['executionResultPolicy']['authorityKeys'] = {}
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            node = handler.Node(work, 'test')
            payer = handler.PayerHandler(handler.Store(work / 'store'), node, 'test',
                                        rail_network=network, bindings=[other, own])
            trust, policy = payer._trust()
            self.assertEqual(own['executionResultPolicy']['authorityKeys'], policy['authorityKeys'])
            self.assertEqual(own['bftFinalTrust']['validatorSets'], trust['validatorSets'])
            with patch.object(node, 'read', return_value={'state': 'found', 'record': pay.generator.record('confirmed')}):
                read = payer._read(pay.generator.TX_HASH)
                self.assertEqual(network, {k: read['appliedTransfer'][k] for k in network})

    def test_completing_broadcast_is_same_node_and_in_reference_window(self):
        for scenario in ('same-node', 'other-node', 'one-block', 'too-late', 'malformed-response'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                node = handler.Node(work, 'test')
                node.identity = 'pinned-node'
                node.current_block = pay.generator.CONFIRM_REFERENCE_BLOCK
                original = node.confirm
                def confirmed(transaction):
                    response = original(transaction)
                    if scenario == 'malformed-response':
                        return {'response': []}
                    if scenario == 'other-node':
                        node.identity = 'another-pinned-node'
                    if scenario in ('one-block', 'too-late'):
                        node.current_block += 1 if scenario == 'one-block' else 2
                    return response
                with patch.object(node, 'confirm', side_effect=confirmed):
                    payer = handler.PayerHandler(handler.Store(work / 'store'), node, 'test')
                    result = payer.pay(pay.generator.signed())
                allowed = scenario in ('same-node', 'one-block')
                self.assertEqual('pass' if allowed else 'indeterminate', result['expected'])
                self.assertEqual(['confirm', 'broadcast'] if allowed else ['confirm'],
                                 [v['call'] for v in handler.read_lines(work / 'egress.jsonl')])


if __name__ == '__main__':
    unittest.main()
