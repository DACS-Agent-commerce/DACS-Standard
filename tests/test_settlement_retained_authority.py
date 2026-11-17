"""Runtime capability and retained session authority regressions."""
import copy
import unittest
from unittest import mock

import test_settlement_contract_vectors as vectors
from scripts.generate_settlement_finality_verification_vectors import FixtureFactory
from scripts.settlement_finality_reference import verify_finality


class RetainedAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vectors.SettlementContractTests.setUpClass()
        cls.fixture = vectors.SettlementContractTests()

    def test_payment_handler_requires_runtime_signer(self):
        value = next(v['input'] for v in self.fixture.data['phaseInputs'] if v['name'] == 'ordinary-input')
        handler = mock.Mock(side_effect=lambda value: {'ok': 'signer' in value['sessionContext']})
        result = vectors.ref.dispatch_payment(vectors.BINDINGS['ordinary'], value, handler)
        self.assertTrue(result['ok'])

    def test_inert_runtime_signers_never_reach_either_payment_handler(self):
        # CORE B.5: an unavailable capability is indeterminate before dispatch.
        for name, identity_bound in (("ordinary-input", False), ("identity-bound-input", True)):
            value = next(v["input"] for v in self.fixture.data["phaseInputs"] if v["name"] == name)
            class MissingSign:
                def is_available(self):
                    return True

            class MissingReadiness:
                def sign(self, payload):
                    raise AssertionError("admission must not sign")

            class NoncallableSign(MissingSign):
                sign = "unusable"

            class NoncallableReadiness(MissingReadiness):
                is_available = True

            for signer in (None, object(), {}, False, "fixture-signer", MissingSign(),
                           MissingReadiness(), NoncallableSign(), NoncallableReadiness()):
                with self.subTest(path=name, signer=type(signer).__name__):
                    handler = mock.Mock(return_value={"status": "accepted", "ok": True})
                    binding = vectors.ref.PhaseBinding(
                        "pay-dem", identity_bound, vectors.ibh("verified"), signer)
                    result = vectors.ref.dispatch_payment(binding, value, handler)
                    self.assertEqual((result["status"], result["ok"], result.get("errorClass")),
                                     ("indeterminate", False, "substrate"))
                    handler.assert_not_called()

    def test_signer_readiness_is_boolean_and_preserves_failure_causes(self):
        for name, identity_bound in (("ordinary-input", False), ("identity-bound-input", True)):
            value = next(v["input"] for v in self.fixture.data["phaseInputs"] if v["name"] == name)
            for readiness in (False, None, 0, 1, "ready", {}, TimeoutError("local signer locked")):
                signer = mock.Mock(spec=vectors.ref.SubstrateSigner)
                if isinstance(readiness, Exception):
                    signer.is_available.side_effect = readiness
                else:
                    signer.is_available.return_value = readiness
                with self.subTest(path=name, readiness=readiness):
                    handler = mock.Mock()
                    binding = vectors.ref.PhaseBinding("pay-dem", identity_bound, vectors.ibh("verified"), signer)
                    result = vectors.ref.dispatch_payment(binding, value, handler)
                    self.assertEqual((result["status"], result["ok"], result.get("errorClass")),
                                     ("indeterminate", False, "substrate"))
                    if isinstance(readiness, Exception):
                        self.assertIn("TimeoutError: local signer locked", result["reason"])
                    handler.assert_not_called()
                    signer.sign.assert_not_called()

    def test_ready_signers_dispatch_without_signing_or_changing_wire_input(self):
        for name, identity_bound in (("ordinary-input", False), ("identity-bound-input", True)):
            value = next(v["input"] for v in self.fixture.data["phaseInputs"] if v["name"] == name)
            before = copy.deepcopy(value)
            for label in ("first-runtime-fixture", "second-runtime-fixture"):
                signer = vectors.FixtureSigner(label)
                handler = mock.Mock(return_value={"status": "accepted", "ok": True})
                binding = vectors.ref.PhaseBinding("pay-dem", identity_bound, vectors.ibh("verified"), signer)
                self.assertEqual(vectors.ref.dispatch_payment(binding, value, handler)["status"], "accepted")
                self.assertEqual(signer.sign_calls, 0)
                self.assertIs(handler.call_args.args[0]["sessionContext"]["signer"], signer)
                self.assertEqual(value, before)

    def test_late_authority_cannot_be_backdated_by_caller(self):
        case = copy.deepcopy(next(c for c in self.fixture.rails['cases'] if c['name'] == 'index-receipt-after-session-start'))
        self.assertEqual(self.fixture.resolve_rail(case)[0], 'rejected')
        case['session']['startedAt'] += 100000
        self.assertEqual(self.fixture.resolve_rail(case)[0], 'rejected')

    def test_later_finality_consumer_refuses_signed_profile_substitution(self):
        factory = FixtureFactory()
        value = factory.model_input('block-depth')
        self.assertEqual(verify_finality(value, factory.trusted)['decision'], 'pass')
        value['rail']['consumerFinalityProfile']['settlement']['requiredDepth'] = 1
        value['evidence']['settlementFinality']['finalityBlocks'] = 1
        factory.rebind_rail(value)
        self.assertEqual(verify_finality(value, factory.trusted)['decision'], 'fail')

    def test_runtime_capability_is_trusted_and_missing_capability_never_dispatches(self):
        value = copy.deepcopy(next(v['input'] for v in self.fixture.data['phaseInputs'] if v['name'] == 'ordinary-input'))
        before = copy.deepcopy(value)
        signer = vectors.FixtureSigner()
        payload = b"fixture runtime signing payload"
        def handler(runtime):
            self.assertIs(runtime['sessionContext']['signer'], signer)
            self.assertEqual(signer.sign_calls, 0)
            signature = runtime['sessionContext']['signer'].sign(payload)
            signer.key.public_key().verify(signature, payload)
            return {'ok': True}
        result = vectors.ref.dispatch_payment(vectors.ref.PhaseBinding('pay-dem', signer=signer), value, handler)
        self.assertTrue(result['ok'])
        self.assertEqual(signer.sign_calls, 1)
        self.assertEqual(value, before)
        handler = mock.Mock()
        result = vectors.ref.dispatch_payment(vectors.ref.PhaseBinding('pay-dem'), value, handler)
        self.assertEqual((result['status'], result['errorClass']), ('indeterminate', 'substrate'))
        handler.assert_not_called()
        value['sessionContext']['signer'] = {'kind': 'caller-capability'}
        result = vectors.ref.dispatch_payment(vectors.ref.PhaseBinding('pay-dem', signer=signer), value, handler)
        self.assertEqual(result['status'], 'rejected')
        handler.assert_not_called()

    def test_caller_cannot_replace_any_retained_session_or_registry_pin(self):
        case = next(c for c in self.fixture.rails['cases'] if c['name'] == 'rail-authority-pinned-before-start')
        self.assertEqual(self.fixture.resolve_rail(case)[0], 'verified')
        for field, value in (('startedAt', case['session']['startedAt'] + 100000), ('railRegistryVersion', 2)):
            changed = copy.deepcopy(case)
            changed['session'][field] = value
            self.assertEqual(self.fixture.resolve_rail(changed)[0], 'rejected', field)
            # Changing the retained projection without its independent root's signature also fails.
            changed['retainedState']['session'][field] = value
            self.assertEqual(self.fixture.resolve_rail(changed)[0], 'rejected', field)
        for pins in ({'registry_writer': vectors.generator.OUTSIDER_WRITER},
                     {'steward': vectors.generator.CLAIMS['seller']},
                     {'job_id': 'different-job'}):
            self.assertEqual(self.fixture.resolve_rail(case, **pins)[0], 'rejected', pins)
        self.assertEqual(self.fixture.resolve_rail(case, retained_state=None)[0], 'indeterminate')
        # CF-3 parameters do not change an authenticated steward identity.
        self.assertEqual(self.fixture.resolve_rail(case, steward=self.fixture.rails['steward'] + '?role=audit')[0], 'verified')

    def test_amendment_pins_require_retained_authority_and_allow_the_actual_orchestrator(self):
        targets = {v['name']: v for v in self.fixture.data['amendmentTargets']}
        for arm in vectors.TARGET_ARMS:
            with self.subTest(arm=arm):
                self.assertEqual(self.fixture.consume(targets[arm + '-target'])[0], 'valid')
                self.assertEqual(self.fixture.consume(targets[arm + '-target'], writer=vectors.generator.OUTSIDER_WRITER)[0], 'violation')
                self.assertEqual(self.fixture.consume(targets[arm + '-seller-signed'], orchestrator=vectors.generator.CLAIMS['seller'])[0], 'violation')
                # A seller really selected as phase orchestrator is allowed.
                fixture = copy.copy(self.fixture)
                fixture.data = copy.deepcopy(self.fixture.data)
                fixture.data['retainedState'] = vectors.generator.retained_state(orchestrator=vectors.generator.CLAIMS['seller'])
                self.assertEqual(fixture.consume(targets[arm + '-seller-signed'], orchestrator=vectors.generator.CLAIMS['seller'])[0], 'valid')

    def test_finality_reauthenticates_retained_receipts_and_snapshot(self):
        for member in ('railRegistryIndexReceipts', 'railDefinitionReceipts'):
            factory = FixtureFactory()
            value = factory.model_input('block-depth')
            job_id = value['evidence']['jobId']
            retained = factory.trusted['sessionRailAuthorityByJob'][job_id]
            self.assertEqual(verify_finality(value, factory.trusted)['decision'], 'pass')
            retained['authority'][member][0]['blockRef']['timestamp'] += 1
            retained['status'] = 'verified'  # A saved success cannot replace proof verification.
            self.assertEqual(verify_finality(value, factory.trusted)['decision'], 'indeterminate')
        factory = FixtureFactory()
        value = factory.model_input('block-depth')
        binding = factory.trusted['sessionRailAuthorityByJob'][value['evidence']['jobId']]
        binding['authority']['railRegistryIndex']['revision'] += 1
        self.assertEqual(verify_finality(value, factory.trusted)['decision'], 'fail')

    def test_dacs5_bundle_consumer_refuses_the_same_signed_rail_substitution(self):
        import test_settlement_finality_verification_vectors as fv_tests
        factory = FixtureFactory()
        value = factory.model_input('block-depth')
        value['rail']['consumerFinalityProfile']['settlement']['requiredDepth'] = 1
        value['evidence']['settlementFinality']['finalityBlocks'] = 1
        factory.rebind_rail(value)
        # Build a fully consistent signed bundle/receipt closure around the
        # replacement, while the verifier retains the original session rail.
        case = factory.strong_bundle_case('block-depth', value=value)
        consumer = fv_tests.SettlementFinalityVerificationVectorTests()
        consumer.pubkeys = fv_tests.decode_public_keys(factory.trusted)
        decision, reason, _ = consumer.strong_result(case, trust=factory.trusted)
        self.assertEqual(decision, 'fail', reason)
        self.assertIn('retained session definition', reason)

    def test_dacs5_current_use_refuses_a_fully_reclosed_weaker_rail(self):
        import generate_current_use_reputation_vectors as current
        import dacs5_reference as d5
        factory = current.CurrentUseFixtureFactory()
        job_id = current.CURRENT_FINALITY_JOB_IDS['block-depth']
        value = factory.finality.model_input('block-depth', job_id=job_id)
        value['rail']['consumerFinalityProfile']['settlement']['requiredDepth'] = 1
        value['evidence']['settlementFinality']['finalityBlocks'] = 1
        factory.finality.rebind_rail(value)
        factory.finality.controls[('block-depth', job_id)] = copy.deepcopy(value)
        fixture = factory.build()
        party = current.CLAIMS['buyer']
        result = d5.derive_current_use_replayable(
            party, [fixture['currentRequestsByModel']['block-depth']],
            *current.FIXTURE_QUERY_WINDOW, fixture['dependencies'], fixture['verifierConfig'],
            pubkeys=factory.current_keys,
            trusted_contexts=factory.current_authority(party, current.FIXTURE_QUERY_WINDOW))
        self.assertEqual(result['decision'], 'fail', result['reason'])
        self.assertIsNone(result['derivation'])
        self.assertIn('retained session definition', result['reason'])

    def test_native_seconds_projection_keeps_late_authority_late(self):
        # DEMOS-MAPPING A.2: synthetic established receipts authenticate the
        # adapter's millisecond projection; this is not a native Demos codec.
        session = {'startedAt': 1800000000000, 'railRegistryVersion': 1}
        base = next(c for c in self.fixture.rails['cases'] if c['expected'] == 'verified')
        for seconds, expected in ((1799999999, 'verified'), (1800000000, 'verified'),
                                  (1800000001, 'rejected')):
            case = copy.deepcopy(base)
            case['session'] = session
            case['retainedState'] = vectors.generator.retained_state(session)
            case['authority'] = vectors.generator.rail_authority(case['rail'], index_time=seconds * 1000)
            self.assertEqual(self.fixture.resolve_rail(case)[0], expected, seconds)

    def test_malformed_or_missing_retained_state_never_authorizes_finality(self):
        for changed in (None, [], {'retainedStateText': None}, {'retainedStateText': 'x' * (vectors.ref.MAX_ARTIFACT_BYTES + 1)}):
            factory = FixtureFactory()
            value = factory.model_input('block-depth')
            factory.trusted['sessionRailAuthorityByJob'][value['evidence']['jobId']] = changed
            result = verify_finality(value, factory.trusted)
            self.assertIn(result['decision'], {'fail', 'indeterminate', 'error'}, result)
        factory = FixtureFactory()
        value = factory.model_input('block-depth')
        factory.trusted['sessionRailAuthorityByJob'] = ['untrusted-map']
        self.assertEqual(verify_finality(value, factory.trusted)['decision'], 'indeterminate')
        for member in ('rail', 'railRef', 'authority'):
            factory = FixtureFactory()
            value = factory.model_input('block-depth')
            factory.trusted['sessionRailAuthorityByJob'][value['evidence']['jobId']][member] = None
            self.assertEqual(verify_finality(value, factory.trusted)['decision'], 'fail', member)
        factory = FixtureFactory()
        value = factory.model_input('block-depth')
        factory.trusted['railAuthorityPolicy']['public_keys'] = None
        self.assertEqual(verify_finality(value, factory.trusted)['decision'], 'indeterminate')

    def test_resolution_returns_immutable_exact_identity_only_after_verification(self):
        case = copy.deepcopy(next(c for c in self.fixture.rails['cases'] if c['name'] == 'rail-authority-pinned-before-start'))
        pins = {**vectors.TRUST, 'public_keys': self.fixture.rails['publicKeys'],
                'steward': self.fixture.rails['steward'], 'registry_writer': self.fixture.rails['registryWriter'],
                'retained_state': vectors.received(case['retainedState']), 'job_id': vectors.generator.JOB_ID}
        status, reason, retained = vectors.ref.resolve_session_rail_state(
            case['session'], case['railRef'], case['rail'], case['authority'], **pins)
        self.assertEqual(status, 'verified', reason)
        self.assertEqual(retained.definition_hash, vectors.ref.content_hash(case['rail']))
        original = retained.fixture_projection()
        case['authority']['railRegistryIndex']['revision'] += 1
        case['rail']['railVersion'] += 1
        projected = retained.fixture_projection()
        projected['rail']['railVersion'] += 1
        self.assertEqual(retained.fixture_projection(), original)
        self.assertEqual(original['snapshotHash'], vectors.ref.sha256_hex(vectors.ref.jcs_bytes(original['authority']['railRegistryIndex'])))
        status, _, missing = vectors.ref.resolve_session_rail_state(
            case['session'], case['railRef'], case['rail'], case['authority'], **pins)
        self.assertEqual(status, 'rejected')
        self.assertIsNone(missing)
