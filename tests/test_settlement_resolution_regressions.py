"""Receipt lifecycle, numeric admission and retained session regression checks."""
import copy
import json
import unittest

import test_settlement_contract_vectors as vectors
from scripts.generate_settlement_finality_verification_vectors import FixtureFactory
from scripts.settlement_finality_reference import verify_finality

ref = vectors.ref
gen = vectors.generator


class SettlementResolutionRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vectors.SettlementContractTests.setUpClass()
        cls.fixture = vectors.SettlementContractTests()
        cls.rail_case = next(c for c in cls.fixture.rails['cases']
                             if c['name'] == 'rail-authority-pinned-before-start')
        cls.target = next(c for c in cls.fixture.data['amendmentTargets']
                          if c['name'] == 'ordinary-target')

    def pins(self, case, raw=None):
        return {**vectors.TRUST, 'public_keys': self.fixture.rails['publicKeys'],
                'steward': self.fixture.rails['steward'],
                'registry_writer': self.fixture.rails['registryWriter'], 'job_id': gen.JOB_ID,
                'retained_state': raw if raw is not None else vectors.received(case['retainedState'])}

    def test_lifecycle_conflicts_are_reconciled_before_finality(self):
        # CORE SR2-7 and DACS-4 RTB-1 / AMEND-1: a genuine reorg cannot
        # disappear merely because it does not itself satisfy the success gate.
        for omit_block in (False, True):
            target = copy.deepcopy(self.target)
            original = target['resolved']['anchorReceipts'][0]
            changed = {'state': 'reorged'}
            if omit_block:
                changed['blockRef'] = ...
            reorg = self.fixture.resign_receipt(original, **changed)
            self.assertEqual(self.fixture.consume(target)[0], 'valid')
            for history in ([original, reorg], [reorg, original]):
                target['resolved']['anchorReceipts'] = history
                self.assertEqual(self.fixture.consume(target)[0], 'indeterminate')
            # An unauthenticated conflicting assertion is discarded (SR2-12).
            reorg['state'] = 'dropped'
            target['resolved']['anchorReceipts'] = [original, reorg]
            self.assertEqual(self.fixture.consume(target)[0], 'valid')
            # A different transaction short of finality is not an
            # otherwise-qualifying immutable-address carrier (CORE §5).
            unfinished = self.fixture.resign_receipt(original, state='included',
                transactionRef={'kind': 'demos-transaction', 'value': 'tx-unfinished'})
            target['resolved']['anchorReceipts'] = [original, unfinished]
            self.assertEqual(self.fixture.consume(target)[0], 'valid')
            for member in ('railRegistryIndexReceipts', 'railDefinitionReceipts'):
                case = copy.deepcopy(self.rail_case)
                original = case['authority'][member][0]
                reorg = self.fixture.resign_receipt(original, **changed)
                self.assertEqual(self.fixture.resolve_rail(case)[0], 'verified')
                for history in ([original, reorg], [reorg, original]):
                    case['authority'][member] = history
                    self.assertEqual(self.fixture.resolve_rail(case)[0], 'indeterminate', member)

    def test_equivalent_numbers_preserve_hashes_and_rail_resolution(self):
        paths = [('session', 'startedAt'), ('session', 'railRegistryVersion'),
                 ('retainedState', 'session', 'startedAt'),
                 ('retainedState', 'session', 'railRegistryVersion'),
                 ('rail', 'railVersion'), ('rail', 'governance', 'acceptedAt'),
                 ('authority', 'railRegistryIndex', 'revision'),
                 ('authority', 'railRegistryIndex', 'entries', 0, 'version')]
        for member in ('railRegistryIndexReceipts', 'railDefinitionReceipts'):
            paths.extend([('authority', member, 0, 'observedAt'),
                          ('authority', member, 0, 'blockRef', 'timestamp')])
        for path in paths:
            case = copy.deepcopy(self.rail_case)
            parent = case
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = float(parent[path[-1]])
            self.assertEqual(ref.jcs_bytes(case), ref.jcs_bytes(self.rail_case), path)
            self.assertEqual(self.fixture.resolve_rail(case)[0], 'verified', path)
        case = copy.deepcopy(self.rail_case)
        case['railRef']['railVersion'] = 1.0
        self.assertEqual(self.fixture.resolve_rail(case)[0], 'verified')
        # Versions are mathematical positive safe integers, never booleans.
        for bad in (True, False, 0, -1, 1.5, float('inf'), float('nan'), 2**53):
            case = copy.deepcopy(self.rail_case)
            case['session']['railRegistryVersion'] = bad
            self.assertEqual(self.fixture.resolve_rail(case)[0], 'rejected', repr(bad))
        for bad in (True, -1, float('inf'), float('nan'), 2**53):
            case = copy.deepcopy(self.rail_case)
            case['session']['startedAt'] = bad
            self.assertEqual(self.fixture.resolve_rail(case)[0], 'rejected', repr(bad))
        # Time members are JSON numbers, rather than integer-only versions.
        case = copy.deepcopy(self.rail_case)
        case['session']['startedAt'] += 0.5
        case['retainedState'] = gen.retained_state(case['session'])
        case['rail']['governance']['acceptedAt'] += 0.5
        case['rail'] = gen.sign(case['rail'], 'steward', ref.RAIL_DOMAIN)
        case['authority'] = gen.rail_authority(case['rail'], index_time=1799999750000.5,
                                               rail_time=1799999740000.5)
        self.assertEqual(self.fixture.resolve_rail(case)[0], 'verified')

    def test_retention_preserves_exact_raw_text_and_decomposed_member_names(self):
        case = copy.deepcopy(self.rail_case)
        state = copy.deepcopy(case['retainedState'])
        state['cafe\u0301'] = {'note': 'cafe\u0301'}
        state = gen.sign(state, 'network', ref.RETAINED_STATE_DOMAIN)
        raw = vectors.received(state)
        status, reason, retained = ref.resolve_session_rail_state(
            case['session'], case['railRef'], case['rail'], case['authority'], **self.pins(case, raw))
        self.assertEqual(status, 'verified', reason)
        projected = json.loads(json.dumps(retained.fixture_projection(), ensure_ascii=False))
        self.assertEqual(projected['retainedStateText'].encode('utf-8'), raw)
        policy = {**vectors.TRUST, 'public_keys': self.fixture.rails['publicKeys']}
        reference = {'anchor': case['authority']['railRegistryIndex']['entries'][0]['anchor']}
        self.assertEqual(ref.verify_retained_rail(projected, case['rail'], reference,
                                                 gen.JOB_ID, policy)[0], 'verified')
        projected['retainedStateText'] = projected['retainedStateText'].replace('cafe\u0301', 'caf\u00e9')
        self.assertEqual(ref.verify_retained_rail(projected, case['rail'], reference,
                                                 gen.JOB_ID, policy)[0], 'rejected')

    def test_missing_retained_rail_does_not_hide_independent_failures(self):
        for model in ('block-depth', 'commitment-level', 'bft-final', 'provider-receipt',
                      'htlc-reveal', 'liquidity-tank'):
            for missing in ('sessionRailAuthorityByJob', 'railAuthorityPolicy'):
                factory = FixtureFactory()
                value = factory.model_input(model)
                self.assertEqual(verify_finality(value, factory.trusted)['decision'], 'pass', model)
                factory.trusted.pop(missing)
                self.assertEqual(verify_finality(value, factory.trusted)['decision'], 'indeterminate')
                changed = copy.deepcopy(value)
                changed['evidence']['paymentAmount']['amount'] = '11'
                factory.resign_evidence(changed['evidence'])
                self.assertEqual(verify_finality(changed, factory.trusted)['decision'], 'fail', model)
                changed = copy.deepcopy(value)
                changed['context'] = []
                self.assertEqual(verify_finality(changed, factory.trusted)['decision'], 'error', model)
        factory = FixtureFactory()
        value = factory.model_input('block-depth')
        factory.trusted.pop('sessionRailAuthorityByJob')
        # This signed false claim is decidable from the available proof.
        value['evidence']['paymentTxRefs'][0]['txHash'] = 'ff' * 32
        factory.resign_evidence(value['evidence'])
        self.assertEqual(verify_finality(value, factory.trusted)['decision'], 'fail')

    def test_registry_history_selects_the_pinned_snapshot(self):
        cases = []
        for revision in (1, 2):
            case = copy.deepcopy(self.rail_case)
            case['session']['railRegistryVersion'] = revision
            case['retainedState'] = gen.retained_state(case['session'])
            case['authority'] = gen.rail_authority(case['rail'], revision=revision)
            self.assertEqual(self.fixture.resolve_rail(case)[0], 'verified')
            cases.append(case)
        history = [c['authority']['railRegistryIndexReceipts'][0] for c in cases]
        for case in cases:
            for receipts in (history, list(reversed(history))):
                case['authority']['railRegistryIndexReceipts'] = receipts
                self.assertEqual(self.fixture.resolve_rail(case)[0], 'verified')
            # Two different publications of this exact snapshot still conflict.
            selected = history[case['session']['railRegistryVersion'] - 1]
            second = self.fixture.resign_receipt(selected,
                       transactionRef={'kind': 'demos-transaction', 'value': 'tx-conflicting'})
            case['authority']['railRegistryIndexReceipts'] = [*history, second]
            self.assertEqual(self.fixture.resolve_rail(case)[0], 'indeterminate')
        # A different snapshot alone cannot authenticate the selected bytes.
        case = copy.deepcopy(self.rail_case)
        case['authority']['railRegistryIndexReceipts'] = [history[1]]
        self.assertNotEqual(self.fixture.resolve_rail(case)[0], 'verified')

    def test_model_depth_is_bounded_before_canonicalization(self):
        # CORE CF-5: depth 128 is admitted and 129 is refused independently
        # of the host recursion limit. Cyclic host objects are never JSON.
        for depth, admitted in ((128, True), (129, False), (600, False), (2000, False)):
            nested = None
            for _ in range(depth):
                nested = [nested]
            self.assertEqual(ref.in_number_profile(nested), admitted, depth)
        cycle = []
        cycle.append(cycle)
        self.assertFalse(ref.in_number_profile(cycle))
        for depth, expected in ((128, 'verified'), (129, 'rejected')):
            case = copy.deepcopy(self.rail_case)
            nested = None
            for _ in range(depth - 2):  # RailDefinition + parameters are two containers.
                nested = [nested]
            case['rail']['parameters']['nested'] = nested
            if depth == 128:
                case['rail'] = gen.sign(case['rail'], 'steward', ref.RAIL_DOMAIN)
                case['authority'] = gen.rail_authority(case['rail'])
            self.assertEqual(self.fixture.resolve_rail(case)[0], expected, depth)
        for where in ('rail', 'index', 'index-receipt', 'definition-receipt'):
            case = copy.deepcopy(self.rail_case)
            nested = None
            for _ in range(600):
                nested = [nested]
            if where == 'rail':
                case['rail']['parameters']['nested'] = nested
            elif where == 'index':
                case['authority']['railRegistryIndex']['nested'] = nested
            else:
                member = ('railRegistryIndexReceipts' if where == 'index-receipt'
                          else 'railDefinitionReceipts')
                case['authority'][member][0]['blockRef']['nested'] = nested
            self.assertIn(self.fixture.resolve_rail(case)[0], {'rejected', 'indeterminate'}, where)
        case = copy.deepcopy(self.rail_case)
        _, _, retained = ref.resolve_session_rail_state(
            case['session'], case['railRef'], case['rail'], case['authority'], **self.pins(case))
        policy = {**vectors.TRUST, 'public_keys': self.fixture.rails['publicKeys']}
        reference = {'anchor': case['authority']['railRegistryIndex']['entries'][0]['anchor']}
        for where in ('candidate', 'retained-index'):
            binding, candidate = retained.fixture_projection(), copy.deepcopy(case['rail'])
            if where == 'candidate':
                candidate['parameters']['nested'] = nested
            else:
                binding['authority']['railRegistryIndex']['nested'] = nested
            self.assertEqual(ref.verify_retained_rail(binding, candidate, reference,
                                                     gen.JOB_ID, policy)[0], 'rejected', where)
