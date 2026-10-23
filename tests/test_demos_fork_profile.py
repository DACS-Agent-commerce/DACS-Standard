"""Effective fork provisioning must use the actual pinned node and genesis."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
import tempfile

from demos_fork_profile import nonce_enforcement, MAX_SEALED_GENESIS_BYTES

from tests import pay_dem_reference_handler as handler
from tests import test_pay_dem_execution_vectors as pay
from tests import test_alternative_payment_projection_vectors as apr
from scripts import generate_alternative_payment_projection_vectors as aprgen

ROOT = Path(__file__).resolve().parents[1]
GENESIS = ROOT / 'conformance/fixtures/settlement/demos-pinned-genesis.json'
GENESIS_HASH = 'a6b140dd38f05558d2319243656d2ff2f93cc5f6ffb16dcd6b13077e10d56184'


class DemosForkProfileTests(unittest.TestCase):
    def test_recovery_uses_real_pinned_genesis_with_absent_nonce_override(self):
        raw = GENESIS.read_bytes()
        self.assertEqual(GENESIS_HASH, hashlib.sha256(raw).hexdigest())
        self.assertNotIn('nonceEnforcement', json.loads(raw)['forks'])
        authority = handler.RecoveryAuthority(pay.generator.NETWORK)
        self.assertEqual(GENESIS_HASH, authority.sealed_genesis_hash)
        self.assertEqual(0, authority.activation_height)
        self.assertEqual(GENESIS_HASH, pay.generator.binding_entry()['nonceEnforcement']['sealedGenesisHash'])

    def authority(self, height):
        genesis = json.loads(GENESIS.read_bytes())
        genesis['forks']['nonceEnforcement'] = {'activationHeight': height}
        raw = json.dumps(genesis).encode()
        digest = hashlib.sha256(raw).hexdigest()
        authority = handler.RecoveryAuthority(pay.generator.NETWORK, sealed_genesis=raw, pinned_digest=digest)
        profile = nonce_enforcement(pay.generator.NETWORK, raw, digest)
        return authority, profile

    def test_genesis_override_is_honored_including_disabled_and_integer_valued(self):
        for height in (0, 0.0, 41, 41.0, None):
            with self.subTest(height=height):
                authority, profile = self.authority(height)
                self.assertEqual(height, profile['activationHeight'])
                self.assertFalse(authority.permits(pay.generator.NETWORK, profile, 41))
                self.assertFalse(authority.permits(pay.generator.OTHER_NETWORK, profile, 41))

    def test_provisioning_refuses_wrong_build_tampering_and_ambiguous_overrides(self):
        raw = GENESIS.read_bytes()
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            handler.RecoveryAuthority(pay.generator.NETWORK, sealed_genesis=raw + b' ')
        with self.assertRaisesRegex(ValueError, 'unsupported node build'):
            handler.RecoveryAuthority(pay.generator.NETWORK, node_commit='0' * 40)
        for entry in ({}, None, {'activationHeight': True}, {'activationHeight': -1},
                      {'activationHeight': 1.5}, {'activationHeight': '0'}, {'activationHeight': 2**53}):
            with self.subTest(entry=entry):
                genesis = json.loads(raw)
                genesis['forks']['nonceEnforcement'] = entry
                altered = json.dumps(genesis).encode()
                with self.assertRaises(ValueError):
                    nonce_enforcement(pay.generator.NETWORK, altered, hashlib.sha256(altered).hexdigest())
        duplicate = b'{"forks":{},"forks":{"nonceEnforcement":{"activationHeight":0}}}'
        with self.assertRaises(ValueError):
            nonce_enforcement(pay.generator.NETWORK, duplicate, hashlib.sha256(duplicate).hexdigest())
        oversized = b' ' * (MAX_SEALED_GENESIS_BYTES + 1)
        with self.assertRaisesRegex(ValueError, 'bounded exact bytes'):
            nonce_enforcement(pay.generator.NETWORK, oversized, hashlib.sha256(oversized).hexdigest())

    def test_genesis_pins_never_authorize_retry_or_nonce_terminal(self):
        for height in (0, 41, 42, None):
            with self.subTest(height=height), tempfile.TemporaryDirectory() as scratch:
                work = Path(scratch)
                first = handler.PayerHandler(handler.Store(work / 'store'),
                    handler.Node(work, 'first', confirm='timeout'), 'first')
                first.pay(pay.generator.signed())
                authority, profile = self.authority(height)
                authority.account_nonce = pay.generator.NONCE
                later = handler.PayerHandler(first.store, handler.Node(work, 'later'), 'later', recovery=authority)
                later.node.current_block = 41
                later.bindings[0]['nonceEnforcement'] = profile
                calls = handler.read_lines(work / 'egress.jsonl')
                self.assertEqual('substrate', later.recover()['errorClass'])
                self.assertEqual(calls, handler.read_lines(work / 'egress.jsonl'))
                self.assertIsNone(first.store.read(first.journal)['result'])
                self.assertNotIn('failureProof', first.store.read(first.journal))

    def test_equal_future_and_contradictory_witness_corpus_cases_are_independent(self):
        cases = {v['name']: v for v in pay.generator.document()['vectors']}
        for name, guard in (
                ('recovery-gate-future-activation', 'recovery-requires-all-conditions'),
                ('nonce-exhaustion-future-activation', 'nonce-exhaustion-proof-valid'),
                ('nonce-exhaustion-contradictory-witness', 'nonce-exhaustion-proof-valid')):
            vector = pay.generator.decode_exact_members(copy.deepcopy(cases[name]))
            with self.subTest(name=name):
                self.assertNotEqual('pass', pay.evaluate(vector)[0])
                self.assertEqual('pass', pay.evaluate(vector, {guard})[0])

    def test_apr_nonce_projection_accepts_numeric_values_on_both_proof_paths(self):
        data = json.loads(apr.VECTORS.read_text())
        names = ('fresh-job-after-conclusive-no-settlement', 'fresh-job-after-nonce-exhaustion-number-nonce')
        for name in names:
            case = next(v for v in data['vectors'] if v['name'] == name)
            for nonce in (pay.generator.NONCE, float(pay.generator.NONCE), str(pay.generator.NONCE),
                          True, 1.5, -1):
                with self.subTest(name=name, nonce=nonce):
                    value = apr.materialize(data, case)
                    value['runtime']['priorPaymentContext']['disposition']['retainedPayDemTransfer']['nonce'] = nonce
                    aprgen.sign_all(value)
                    allowed = type(nonce) in (int, float) and nonce == pay.generator.NONCE
                    self.assertEqual((('indeterminate', 'prior-disposition-proof') if 'nonce-exhaustion' in name else ('pass', None))
                                     if allowed else ('fail', 'prior-disposition-proof'), apr.evaluate(value))

    def test_nonce_proof_requires_the_pinned_build_even_when_statement_and_trust_agree(self):
        for commit, allowed in ((pay.generator.NODE_COMMIT, True), ('0' * 40, False), (None, False)):
            with self.subTest(commit=commit):
                fork = pay.generator.binding_entry()['nonceEnforcement']
                if commit is None:
                    fork.pop('nodeCommit')
                else:
                    fork['nodeCommit'] = commit
                proof = pay.generator.nonce_exhaustion_proof(pay.generator.retained(), nonce_fork=fork)
                value = {'railNetwork': pay.generator.NETWORK, **pay.generator.FINALITY,
                         'fv5Policy': pay.generator.FV5_POLICY, 'retainedTransfer': pay.generator.retained(),
                         'nonceEnforcement': fork}
                self.assertEqual(allowed, pay.nonce_exhaustion_valid(proof, value))

    def test_malformed_provisioning_inputs_are_refused(self):
        raw = GENESIS.read_bytes()
        for network in ({}, [], dict(pay.generator.NETWORK, genesisHash='invalid')):
            with self.subTest(network=network), self.assertRaisesRegex(ValueError, 'network identity'):
                nonce_enforcement(network, raw, GENESIS_HASH)
        for raw in (b'[]', b'{"forks":[]}'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, 'object|forks'):
                nonce_enforcement(pay.generator.NETWORK, raw, hashlib.sha256(raw).hexdigest())

    def test_out_of_profile_nonce_is_refused_before_signature(self):
        transfer = pay.generator.retained(nonce=2**53)
        self.assertFalse(pay.complete_transfer(transfer))
        with self.assertRaises(ValueError):
            aprgen.digest(transfer)

    def test_restart_plan_distinguishes_resume_and_authorized_recovery(self):
        plan = (ROOT / 'spec/CONFORMANCE-PLAN.md').read_text()
        self.assertIn('plain resume sends nothing automatically', plan)
        self.assertIn('explicit DEM-6 recovery remains read-only on the pinned profile', plan)
        self.assertNotIn('check that no signed effect leaves after the restart', plan)

    def test_standard_defines_effective_default_and_numeric_apr_nonce(self):
        mapping = (ROOT / 'spec/DEMOS-MAPPING.md').read_text()
        self.assertIn('DEFAULT_FORK_CONFIG.nonceEnforcement.activationHeight', mapping)
        settle = (ROOT / 'spec/DACS-4-SETTLE.md').read_text()
        self.assertIn('txHash: string; nonce: number', settle)


if __name__ == '__main__':
    unittest.main()
