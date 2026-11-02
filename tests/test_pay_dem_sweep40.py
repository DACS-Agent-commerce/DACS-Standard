"""Payment authority and recovery conformance regressions."""
import copy
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tests import pay_dem_reference_handler as handler
from tests import test_pay_dem_execution_vectors as pay
from settlement_finality_reference import verify_transaction_inclusion, bft_final_trust, verify_finality
from scripts import generate_settlement_finality_verification_vectors as fv
from scripts.settlement_finality_reference import artifact_hash

ROOT = Path(__file__).resolve().parents[1]


class Sweep40Tests(unittest.TestCase):
    def test_all_payment_rules_resume_before_evidence_anchoring(self):
        for filename in ('DACS-4-SETTLE.md', 'DACS-5-VERIFY.md', 'CONFORMANCE-PLAN.md', 'THREAT-MODEL.md'):
            with self.subTest(filename=filename):
                text = ' '.join((ROOT / 'spec' / filename).read_text().split())
                for obsolete in ('until DEM-3 success is anchored', 'until success evidence is anchored',
                                 'a later DEM-3 success is anchored and resumes'):
                    self.assertNotIn(obsolete, text)

    def test_conflicting_local_genesis_never_authorizes_retry_or_nonce_terminal(self):
        raw = (ROOT / 'conformance/fixtures/settlement/demos-pinned-genesis.json').read_bytes()
        disabled = json.loads(raw)
        disabled['forks']['nonceEnforcement'] = {'activationHeight': None}
        for genesis in (raw, json.dumps(disabled).encode()):
            for consumed in (False, True):
                with self.subTest(consumed=consumed, digest=hashlib.sha256(genesis).hexdigest()), tempfile.TemporaryDirectory() as scratch:
                    work = Path(scratch)
                    first = handler.PayerHandler(handler.Store(work / 'store'),
                        handler.Node(work, 'first', confirm='timeout'), 'first')
                    self.assertEqual('indeterminate', first.pay(pay.generator.signed())['expected'])
                    authority = handler.RecoveryAuthority(pay.generator.NETWORK, sealed_genesis=genesis,
                        pinned_digest=hashlib.sha256(genesis).hexdigest())
                    if consumed:
                        authority.account_nonce = pay.generator.NONCE
                    later = handler.PayerHandler(first.store, handler.Node(work, 'later'), 'later', recovery=authority)
                    later.bindings[0]['nonceEnforcement'] = pay.generator.nonce_enforcement(
                        pay.generator.NETWORK, genesis, hashlib.sha256(genesis).hexdigest())
                    calls = handler.read_lines(work / 'egress.jsonl')
                    self.assertEqual({'expected': 'indeterminate', **pay.HANDLER_WANT['indeterminate']}, later.recover())
                    self.assertEqual(calls, handler.read_lines(work / 'egress.jsonl'))
                    self.assertIsNone(first.store.read(first.journal)['result'])

    def test_recovery_notes_do_not_authorize_local_fork_retries(self):
        text = (ROOT / 'spec/DACS-4-SETTLE.md').read_text()
        self.assertIn('This profile prohibits resubmission', text)
        self.assertNotIn('Active nonce enforcement prevents a duplicate apply', text)
        self.assertNotIn("If the binding's provisioned effective-fork attestation", text)

    def test_inclusion_body_is_the_proven_transaction(self):
        reference = {'kind': 'demos', 'txHash': pay.generator.TX_HASH, 'blockNumber': pay.generator.BLOCK}
        honest = pay.generator.inclusion_proof()
        other = pay.generator.inclusion_proof(tx_hash=pay.generator.OTHER_TX_HASH)
        self.assertEqual('pass', verify_transaction_inclusion(honest, pay.generator.FINALITY_PROFILE,
            reference, pay.generator.FINALITY_TRUST)[0])
        own = dict(reference, txHash=pay.generator.OTHER_TX_HASH)
        self.assertEqual('pass', verify_transaction_inclusion(other, pay.generator.FINALITY_PROFILE,
            own, pay.generator.FINALITY_TRUST)[0])
        other['transactionRef'] = copy.deepcopy(reference)
        self.assertEqual(('fail', 'raw transaction does not bind the network or reference'),
            verify_transaction_inclusion(other, pay.generator.FINALITY_PROFILE, reference, pay.generator.FINALITY_TRUST))

    def test_inclusion_verifier_refusals(self):
        g = pay.generator
        reference = {'kind': 'demos', 'txHash': g.TX_HASH, 'blockNumber': g.BLOCK}
        honest = g.inclusion_proof()
        cases = [(None, g.FINALITY_PROFILE, reference, 'indeterminate'),
                 ({}, g.FINALITY_PROFILE, reference, 'error'),
                 (honest, {}, reference, 'error')]
        for member in ('networkId', 'genesisHash'):
            bad = copy.deepcopy(honest)
            bad[member] = 'another-network' if member == 'networkId' else '0' * 64
            cases.append((bad, g.FINALITY_PROFILE, reference, 'fail'))
        bad = copy.deepcopy(honest)
        bad['transactionRef']['txHash'] = g.OTHER_TX_HASH
        cases.append((bad, g.FINALITY_PROFILE, reference, 'fail'))
        bad = copy.deepcopy(honest)
        wrong_profile = {'kind': 'evm-event', 'chainId': 1, 'txHash': g.TX_HASH, 'logIndex': 0}
        bad['transactionRef'] = wrong_profile
        cases.append((bad, g.FINALITY_PROFILE, wrong_profile, 'fail'))
        bad = copy.deepcopy(honest)
        bad['transactionInclusionProof']['root'] = '0' * 64
        cases.append((bad, g.FINALITY_PROFILE, reference, 'fail'))
        for fault in ('missing-member', 'events-root', 'networkId', 'genesisHash', 'transactionRef', 'txHash'):
            bad = copy.deepcopy(honest)
            proof = bad['transactionInclusionProof']
            body = json.loads(base64.urlsafe_b64decode(proof['transactionBytes'] + '=='))
            if fault == 'missing-member':
                body.pop('txHash')
            elif fault == 'events-root':
                body['eventsRoot'] = 'malformed'
            elif fault == 'transactionRef':
                body[fault] = dict(reference, txHash=g.OTHER_TX_HASH)
            else:
                body[fault] = 'another-network' if fault == 'networkId' else '0' * 64
            raw = g.canonicalize(body).encode()
            proof['transactionBytes'] = g._b64u(raw)
            proof['leafHash'] = hashlib.sha256(b'\x00' + raw).hexdigest()
            proof['root'] = hashlib.sha256(b'\x01' + bytes.fromhex(proof['leafHash'])
                                            + bytes.fromhex(proof['siblingHash'])).hexdigest()
            cases.append((bad, g.FINALITY_PROFILE, reference,
                          'error' if fault in ('missing-member', 'events-root') else 'fail'))
        for observation, profile, ref, expected in cases:
            with self.subTest(expected=expected, observation=observation):
                self.assertEqual(expected, verify_transaction_inclusion(observation, profile, ref, g.FINALITY_TRUST)[0])

    def test_substituted_certified_body_refuses_every_payment_path(self):
        g = pay.generator
        cases = {v['name']: g.decode_exact_members(copy.deepcopy(v)) for v in g.document()['vectors']}
        for name, expected in (('included-confirmed', 'indeterminate'),
                               ('included-failed', 'indeterminate'),
                               ('consumer-confirmed-gate-passes', 'fail'),
                               ('delivery-after-all-gates', 'fail')):
            # Both the good and hostile observations are fully certified. Only
            # the hostile proof's external reference lies about its proven body.
            for substituted in (False, True):
                value = copy.deepcopy(cases[name])
                data = value['protocolInput']
                read = data['recordRead']
                proof = g.inclusion_proof(tx_hash=g.OTHER_TX_HASH if substituted else g.TX_HASH)
                proof['transactionRef']['txHash'] = g.TX_HASH
                read['inclusionProof'] = proof
                block = proof['inclusionBlock']['id']
                data['inclusionObservation'] = {'blockId': block, 'blockNumber': g.BLOCK}
                read['executionResult'] = g.execution_result(read['record'], block=block)
                read['appliedTransfer']['blockId'] = block
                with self.subTest(name=name, substituted=substituted):
                    self.assertEqual(expected if substituted else ('fail' if name == 'included-failed' else 'pass'),
                                     pay.evaluate(value)[0])
        value = copy.deepcopy(cases['resume-reuses-failure-proof']['protocolInput'])
        proof = value['retainedFailureProof']
        inclusion = g.inclusion_proof(tx_hash=g.OTHER_TX_HASH)
        inclusion['transactionRef']['txHash'] = g.TX_HASH
        proof['inclusionProof'] = inclusion
        proof['authentication'] = g.execution_result(proof['record'], block=inclusion['inclusionBlock']['id'])
        # Prevent a subsequent fresh read from independently proving failure.
        value['recordRead'] = {'state': 'not-found'}
        self.assertEqual('indeterminate', pay.resume(value, frozenset())[0])
        self.assertEqual(('indeterminate', {'reconciliationEvidence': False}), pay.apr_evidence(value, frozenset()))

    def test_nonce_witness_cannot_hide_the_retained_leaf_under_another_reference(self):
        g = pay.generator
        value = {'railNetwork': g.NETWORK, **g.FINALITY, 'fv5Policy': g.FV5_POLICY,
                 'retainedTransfer': g.retained(), 'nonceEnforcement': g.binding_entry()['nonceEnforcement']}
        honest = g.nonce_exhaustion_proof(g.retained())
        self.assertTrue(pay.nonce_exhaustion_valid(honest, value))
        hidden = g.nonce_exhaustion_proof(g.retained(), fault='contradictory-witness')
        hidden['inclusionProof']['transactionRef']['txHash'] = g.OTHER_TX_HASH
        self.assertFalse(pay.nonce_exhaustion_valid(hidden, value))
        self.assertEqual(('indeterminate', {'reconciliationEvidence': False}),
                         pay.apr_evidence(dict(value, retainedFailureProof=honest), frozenset()))

    def test_saved_nonce_terminal_is_reverified_after_handler_restart(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            first = handler.PayerHandler(handler.Store(work / 'store'),
                handler.Node(work, 'first', confirm='timeout'), 'first')
            first.pay(pay.generator.signed())
            entry = first.store.read(first.journal)
            # A terminal retained by the earlier profile is not current authority.
            entry['result'] = {'expected': 'fail', **pay.HANDLER_WANT['fail']}
            entry['failureProof'] = pay.generator.nonce_exhaustion_proof(entry['retainedTransfer'])
            first.store.write(first.journal, entry)
            later = handler.PayerHandler(first.store, handler.Node(work, 'later'), 'later')
            calls = handler.read_lines(work / 'egress.jsonl')
            expected = {'expected': 'indeterminate', **pay.HANDLER_WANT['indeterminate']}
            self.assertEqual(expected, later.recover())
            self.assertEqual(expected, later.advance())
            self.assertEqual(calls, handler.read_lines(work / 'egress.jsonl'))
            self.assertEqual(entry, first.store.read(first.journal))

    def test_malformed_finality_trust_is_refused(self):
        g = pay.generator
        self.assertEqual('pass', bft_final_trust(g.FINALITY_PROFILE, g.FINALITY_TRUST)[0])
        self.assertEqual('error', bft_final_trust({}, g.FINALITY_TRUST)[0])
        self.assertEqual('error', bft_final_trust(g.FINALITY_PROFILE, [])[0])
        trust = dict(g.FINALITY_TRUST, observationAuthorityKeys=[])
        self.assertEqual('error', bft_final_trust(g.FINALITY_PROFILE, trust)[0])

    def test_malformed_result_precedes_forged_inclusion(self):
        data = json.loads((ROOT / 'conformance/vectors/security/settlement-finality-verification.json').read_text())
        case = next(v for v in data['vectors'] if v['name'] == 'fv-bft-final-result-member-missing')
        value = copy.deepcopy(case['input'])
        value['context']['observation']['finalityCertificate']['signatures'][0]['value'] = 'A' * 86
        self.assertEqual('error', verify_finality(value, dict(data['trustedFixturePolicy'], **case.get('trustedOverrides', {})))['decision'])

    def test_signed_payout_binding_shape_refusals_and_other_phase_control(self):
        for fault in (None, 'missing-selected', 'duplicate', 'extra-member', 'another-phase'):
            factory = fv.FixtureFactory()
            value = factory.model_input('bft-final')
            agreement = value['agreement']
            agreement['payeeBoundAgreementVersion'] = agreement.pop('agreementVersion')
            session = factory.trusted['sessionAuthorityByJob'][agreement['jobId']]
            binding = {'railId': session['railId'], 'phaseIndex': session['phaseIndex'],
                       'payeeAddress': factory.demos_key('seller')}
            bindings = [binding]
            if fault == 'missing-selected':
                binding['phaseIndex'] += 1
            elif fault == 'duplicate':
                bindings.append(copy.deepcopy(binding))
            elif fault == 'extra-member':
                binding['extra'] = True
            elif fault == 'another-phase':
                bindings.append(dict(binding, phaseIndex=binding['phaseIndex'] + 1))
            agreement['terms']['payoutBindings'] = bindings
            digest = artifact_hash(agreement, 'signatures')
            for signature, role in zip(agreement['signatures'], ('buyer', 'seller')):
                signature['value'] = factory.sign_digest(role, 'dacs-payee-bound-agreement:v1:', digest)
            session['agreementHash'] = digest
            with self.subTest(fault=fault):
                self.assertEqual('pass' if fault in (None, 'another-phase') else 'error',
                                 verify_finality(value, factory.trusted)['decision'])

    def test_ordinary_failure_still_resolves_and_is_journaled(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            payer = handler.PayerHandler(handler.Store(work / 'store'),
                handler.Node(work, 'first', record_status='failed'), 'first',
                fv5=handler.Fv5Authority('policy', 'failed'))
            expected = {'expected': 'fail', **pay.HANDLER_WANT['fail']}
            self.assertEqual(expected, payer.pay(pay.generator.signed()))
            self.assertEqual(expected, payer.store.read(payer.journal)['result'])
            self.assertEqual(expected, payer.recover())
            resumed = handler.PayerHandler(payer.store, handler.Node(work, 'resumed'), 'resumed')
            self.assertEqual(expected, resumed.advance())


if __name__ == '__main__':
    unittest.main()
