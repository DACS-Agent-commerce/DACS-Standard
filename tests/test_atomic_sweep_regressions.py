"""Composed regressions for the four cold reviews of the Atomic candidate."""
import copy
import json
import unittest
from unittest.mock import patch

from test_atomic_cold_review_regressions import (
    R, G, PINS, admission, audit_fixture, agreement_variant, listing_variant,
)


def resign_anchor(anchor, edit):
    """Reissue an authentic synthetic receipt after editing its proven subject."""
    edit(anchor)
    kind = anchor['evidence']['kind']
    domain = R._PUBLICATION_TEST_DOMAIN if kind == 'test-anchor-publication' else R._ANCHOR_TEST_DOMAIN
    proof = json.loads(R.b64u_decode(anchor['evidence']['value']))
    proof.pop('signature')
    for key in proof.keys() & anchor.keys():
        proof[key] = copy.deepcopy(anchor[key])
    anchor['evidence'] = G.encoded_evidence(kind, proof, 'network', domain)


def republish(data, edit, signers=('buyer', 'seller', 'orchestrator')):
    entry = data['st11Closure']['bundle']
    bundle = copy.deepcopy(entry['bundle'])
    edit(bundle)
    bundle = G.sign_bundle(bundle, signers)
    data['st11Closure']['bundle'] = G.published_bundle(data['purchaseIntent'], bundle)


def asserted_purchase(*args, **kwargs):
    intent = ORIGINAL_PURCHASE(*args, **kwargs)
    for op in intent['operations'][:2]:
        op['kind'] = 'assert-artifact'
        op['payload'] = {'artifact': op['payload']['artifact']}
    return intent


ORIGINAL_PURCHASE = G.purchase_intent


def vets(intent, large=False):
    return {role: G.registry_anchor_receipt(
        f"dacs2:composite:{intent['jobId']}:{R.cf4_encode(G.CLAIMS[role])}",
        intent['operations'][i]['payload']['artifact'],
        label='x' * 30000 if large and role == 'buyer' else role, nonce=str(10+i))
        for i, role in enumerate(('buyer', 'seller'))}


class AtomicSweepRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = audit_fixture()
        cls.purchase = admission()

    def verdict(self, surface, data, expected):
        got = R.evaluate_vector({'surface': surface, 'input': data})
        self.assertEqual(got[0], expected, got)

    def test_cold_1_complete_vet_proof_size(self):
        with patch.object(G, 'purchase_intent', asserted_purchase):
            data = admission()
        data['vetReceipts'] = vets(data['intent'])
        G.add_composed_limit_evidence(data)
        self.verdict('purchase-admission', data, 'pass')
        before = len(R.proof_package_bytes(R.composed_proof_material(data), data['proofReservationEvidence']))
        data['vetReceipts'] = vets(data['intent'], large=True)
        G.add_composed_limit_evidence(data)
        after = len(R.proof_package_bytes(R.composed_proof_material(data), data['proofReservationEvidence']))
        self.assertGreater(after, before + 30000)
        got = R.evaluate_vector({'surface': 'purchase-admission', 'input': data})
        self.assertEqual(got[0], 'fail', got)
        self.assertIn('committed state is not rolled back', got[1])

    def test_cold_2_party_order_is_by_role(self):
        for reverse in (False, True):
            with patch.object(G, 'purchase_intent', asserted_purchase), agreement_variant(
                    lambda a: a['parties'].reverse() if reverse else None):
                data = audit_fixture()
                data['vetReceipts'] = vets(data['purchaseIntent'])
                purchase = admission(data['purchaseIntent'])
                purchase['vetReceipts'] = data['vetReceipts']
                G.add_composed_limit_evidence(purchase)
                self.verdict('purchase-admission', purchase, 'pass')
                self.verdict('audit', data, 'pass')
                bad = copy.deepcopy(data)
                bad['vetReceipts']['buyer'] = bad['vetReceipts']['seller']
                self.verdict('audit', bad, 'fail')

    def test_cold_3_publication_block_shape(self):
        self.verdict('audit', self.audit, 'pass')
        for block in ({}, {'id': ''}, {'id': 'b', 'height': '01'},
                      {'id': 'b', 'height': '\u0661'}, {'id': 'b', 'timestamp': True}):
            data = copy.deepcopy(self.audit)
            anchor = data['st11Closure']['settlementEvidence'][0]['publication']['anchorReceipt']
            resign_anchor(anchor, lambda a: a.update(blockRef=block))
            self.verdict('audit', data, 'fail')
        # CORE permits omitted optional height and timestamp on this receipt.
        data = copy.deepcopy(self.audit)
        anchor = data['st11Closure']['settlementEvidence'][0]['publication']['anchorReceipt']
        resign_anchor(anchor, lambda a: a.update(blockRef={'id': 'b'}))
        self.verdict('audit', data, 'pass')

    def test_cold2_1_unresolved_amendments_cannot_finalize(self):
        self.verdict('audit', self.audit, 'pass')
        ref = {'anchor': {'kind': 'storage-program', 'locator': 'missing'}, 'contentHash': '01'*32}
        data = copy.deepcopy(self.audit)
        republish(data, lambda b: b.update(amendments=[ref]))
        self.verdict('audit', data, 'fail')
        data['sessionStateAfter'] = 'audit-pending'
        self.verdict('audit', data, 'indeterminate')
        data = copy.deepcopy(self.audit)
        entry = data['st11Closure']['settlementEvidence'][0]
        evidence = G.resign_atomic_evidence({**entry['evidence'], 'amendmentRefs': [ref]})
        data['st11Closure']['settlementEvidence'][0] = G.published_evidence(evidence, entry['evidenceAddress'])
        self.verdict('audit', data, 'fail')

    def test_cold2_2_publication_writer_authority(self):
        self.verdict('audit', self.audit, 'pass')
        data = copy.deepcopy(self.audit)
        for entry in data['st11Closure']['settlementEvidence']:
            resign_anchor(entry['publication']['anchorReceipt'], lambda a: a.update(writer='native:outsider'))
        self.verdict('audit', data, 'fail')

    def failure(self, *, ordinary=False):
        p = self.audit['purchaseIntent']
        pr = self.audit['purchaseReceipt']
        payment = self.audit['st11Closure']['settlementEvidence'][0]
        failed = G.failed_delivery_material(p, pr)
        if ordinary:
            evidence = R.sign_embedded({
                'deliveryEvidenceVersion': '1', 'jobId': p['jobId'], 'phaseIndex': 3,
                'phase': 'deliver-storage-program', 'outcome': 'failure',
                'reason': 'seller declined delivery', 'observedAt': 1800000040000,
            }, G.CLAIMS['orchestrator'], G.SEEDS['orchestrator'], b'dacs-delivery-evidence:v1:')
            address = f"dacs4:delivery:{p['jobId']}:3"
            anchor = G.registry_anchor_receipt(address, evidence, label='failure', nonce='3')
            resign_anchor(anchor, lambda a: a.update(writer=G.CLAIMS['orchestrator']))
            failed = {'failureDeliveryEvidence': {'evidence': evidence, 'evidenceAddress': address,
                                                  'publication': {'anchorReceipt': anchor}}}
        entries = [payment, failed['failureDeliveryEvidence']]
        bundle = G.role_bundle(p, entries, role='buyer', outcome='failed-counterparty',
                               faulted='seller', signers=('buyer', 'seller', 'orchestrator'))
        return {**PINS, **failed, 'publicKeys': G.PUBLIC_KEYS, 'capability': G.capability(),
                'purchaseIntent': p, 'purchaseReceipt': pr, 'paymentEvidence': payment,
                'authorizationAuthority': G.authorization_authority(p), 'remedy': 'ordinary-failure-record',
                'failureRecord': G.published_bundle(p, bundle, state='included')}

    def test_cold2_3_refusal_before_completion(self):
        data = self.failure(ordinary=True)
        self.assertNotIn('failureCompletionReceipt', data)
        self.verdict('post-purchase', data, 'pass')
        for edit in (lambda e: e.update(jobId='01K1DPA0000000000000000001'),
                     lambda e: e.update(phaseIndex=2)):
            bad = copy.deepcopy(data)
            evidence = bad['failureDeliveryEvidence']['evidence']
            edit(evidence)
            bad['failureDeliveryEvidence']['evidence'] = R.sign_embedded(
                evidence, G.CLAIMS['orchestrator'], G.SEEDS['orchestrator'], b'dacs-delivery-evidence:v1:')
            self.verdict('post-purchase', bad, 'fail')

    def test_cold2_4_declined_rating_is_nonfatal(self):
        original = G.role_bundle
        def with_rating(*a, **kw):
            b = original(*a, **kw)
            b['phaseSummary'][-1] = {'index': 4, 'kind': 'rate', 'outcome': 'fail', 'errorClass': 'counterparty'}
            return G.sign_bundle(b, ('buyer', 'seller', 'orchestrator'))
        with listing_variant(lambda l: l['pipeline'].append({'kind': 'rate'})), patch.object(G, 'role_bundle', with_rating):
            data = audit_fixture()
        self.verdict('audit', data, 'pass')
        republish(data, lambda b: b['phaseSummary'][3].update(outcome='fail', errorClass='counterparty'))
        self.verdict('audit', data, 'fail')

    def test_cold2_5_omitted_public_access(self):
        with listing_variant(lambda l: l['offering']['deliverable'].pop('accessModel', None)):
            data = admission()
        self.verdict('purchase-admission', data, 'pass')
        self.assertNotIn('accessModel', data['authority']['listing']['offering']['deliverable'])
        for mode in ('buyer-only', 'encrypt-to-buyer'):
            with listing_variant(lambda l: l['offering']['deliverable'].update(accessModel=mode)):
                self.verdict('purchase-admission', admission(), 'fail')

    def test_coldr2_1_registered_rail_snapshot_and_unsigned_hash(self):
        data = copy.deepcopy(self.purchase)
        rail = data['authority']['railDefinition']
        anchor = G.registry_anchor_receipt(f"dacs4:rail:{R.cf4_encode(rail['railId'])}:1", rail,
                                         label='standard-rail', nonce='201')
        index = {'registryIndexVersion': '1', 'registryKind': 'rail', 'revision': 1, 'entries': [
            {'id': rail['railId'], 'version': 1,
             'anchor': {'kind': 'storage-program', 'locator': anchor['nativeAddress']},
             'contentHash': R.artifact_content_hash(rail)}]}
        def set_index():
            data['authority'].update(railRegistryIndex=index, railDefinitionReceipt=anchor,
                railRegistryIndexReceipt=G.registry_anchor_receipt('dacs4:registry:v0.1', index,
                                                                  label='standard-index', nonce='200'))
            G.add_composed_limit_evidence(data)
        set_index()
        self.verdict('purchase-admission', data, 'pass')
        index['description'] = 'retained registry metadata'
        set_index()
        self.verdict('purchase-admission', data, 'pass')
        index['entries'][0]['contentHash'] = R.sha256_hex(R.jcs_bytes(rail))
        set_index()
        self.verdict('purchase-admission', data, 'fail')

    def test_coldr2_2_concrete_rail_replacement_reference_forbidden(self):
        self.verdict('purchase-admission', self.purchase, 'pass')
        ref = {'anchor': {'kind': 'storage-program', 'locator': 'prior'}, 'contentHash': '01'*32}
        with agreement_variant(lambda a: a['terms'].update(priorPaymentDispositionRef=ref)):
            self.verdict('purchase-admission', admission(), 'fail')

    def test_coldr2_3_duplicate_encoded_proof_members_refused(self):
        evidence = self.purchase['capability']['evidence']
        R.verify_encoded_evidence(evidence, evidence['kind'], G.PUBLIC_KEYS, R._CAPABILITY_TEST_DOMAIN,
                                  expected_signer=G.CLAIMS['network'])
        raw = R.b64u_decode(evidence['value'])
        subject = json.loads(raw)
        field = next(k for k in subject if k != 'signature')
        duplicate = ('{' + json.dumps(field) + ':' + json.dumps(subject[field]) + ',').encode() + raw[1:]
        bad = {**evidence, 'value': R.b64u(duplicate)}
        with self.assertRaises(R.Invalid):
            R.verify_encoded_evidence(bad, bad['kind'], G.PUBLIC_KEYS, R._CAPABILITY_TEST_DOMAIN,
                                      expected_signer=G.CLAIMS['network'])
        data = copy.deepcopy(self.audit)
        proof = data['purchaseReceipt']['finalityEvidence']
        raw = R.b64u_decode(proof['value'])
        proof['value'] = R.b64u(b'{"workId":"wrong",' + raw[1:])
        self.verdict('audit', data, 'fail')

    def test_coldr2_4_standard_bundle_binding(self):
        data = copy.deepcopy(self.audit)
        entry = data['st11Closure']['bundle']
        anchor = entry['anchorReceipt']
        b = entry['bundle']
        binding = {'bindingVersion': '1', 'jobId': b['jobId'], 'role': b['anchoredByRole'],
            'logicalAddress': anchor['logicalAddress'], 'nativeAddress': anchor['nativeAddress'],
            'bundleContentHash': anchor['contentHash'], 'signer': G.CLAIMS[b['anchoredByRole']],
            'anchorTx': anchor['transactionRef']['value']}
        entry['bundleBinding'] = R.sign_embedded(binding, binding['signer'], G.SEEDS[b['anchoredByRole']],
                                                 b'dacs-bundle-binding:v1:')
        self.verdict('audit', data, 'pass')
        mismatched = {**binding, 'signer': G.CLAIMS['buyer']}
        entry['bundleBinding'] = R.sign_embedded(mismatched, binding['signer'], G.SEEDS[b['anchoredByRole']],
                                                 b'dacs-bundle-binding:v1:')
        self.verdict('audit', data, 'fail')
        entry['bundleBinding'] = R.sign_embedded(binding, binding['signer'], G.SEEDS[b['anchoredByRole']],
                                                 R._BINDING_TEST_DOMAIN)
        self.verdict('audit', data, 'fail')

    def test_coldr2_5_nonabort_failure_requires_all_signatures(self):
        data = self.failure()
        self.verdict('post-purchase', data, 'pass')
        for signers in (('buyer',), ('buyer', 'seller'), ('buyer', 'orchestrator')):
            b = G.sign_bundle(data['failureRecord']['bundle'], signers)
            bad = {**data, 'failureRecord': G.published_bundle(data['purchaseIntent'], b, state='included')}
            self.verdict('post-purchase', bad, 'fail')

    def test_cold2r2_native_vet_references(self):
        original = G.agreement_document
        def native(*a, **kw):
            agreement = original(*a, **kw)
            for party in agreement['parties']:
                logical = party['vetRecordRef']['anchor']['locator']
                party['vetRecordRef']['anchor']['locator'] = 'stor-' + R.sha256_hex(logical.encode())[:40]
            return G.resign_payee_agreement(agreement)
        with patch.object(G, 'purchase_intent', asserted_purchase), patch.object(G, 'agreement_document', native):
            data = audit_fixture()
            data['vetReceipts'] = vets(data['purchaseIntent'])
            purchase = admission(data['purchaseIntent'])
        purchase['vetReceipts'] = data['vetReceipts']
        G.add_composed_limit_evidence(purchase)
        self.verdict('purchase-admission', purchase, 'pass')
        self.verdict('audit', data, 'pass')
        bad = copy.deepcopy(purchase)
        bad['vetReceipts']['buyer'] = bad['vetReceipts']['seller']
        G.add_composed_limit_evidence(bad)
        self.verdict('purchase-admission', bad, 'fail')

    def test_cold2r2_native_amendment_target(self):
        p = self.audit['purchaseIntent']
        entry = self.audit['st11Closure']['settlementEvidence'][0]
        digest = R.atomic_evidence_hash(entry['evidence'])
        address = f"dacs4:amendment:{p['jobId']}:{digest}:0"
        data = {**PINS, 'publicKeys': G.PUBLIC_KEYS, 'capability': G.capability(),
                'purchaseIntent': p, 'purchaseReceipt': self.audit['purchaseReceipt'],
                'paymentEvidence': entry, 'authorizationAuthority': G.authorization_authority(p),
                'remedy': 'settlement-amendment', 'amendmentAddress': address}
        for locator, expected in ((entry['evidenceAddress'], 'pass'),
                (entry['publication']['anchorReceipt']['nativeAddress'], 'pass'), ('unrelated', 'fail')):
            amendment = R.sign_embedded({'amendmentVersion': '1', 'jobId': p['jobId'],
                'amendsEvidenceRef': {'anchor': {'kind': 'storage-program', 'locator': locator}, 'contentHash': digest},
                'amendmentType': 'partial-refund', 'refundAmount': {'amount': '1', 'currency': 'DEM'},
                'reason': 'refund', 'observedAt': 1800000050000},
                G.CLAIMS['seller'], G.SEEDS['seller'], R._AMENDMENT_DOMAIN)
            data.update(amendment=amendment, amendmentReceipt=G.registry_anchor_receipt(
                address, amendment, label='refund', nonce='970'))
            self.verdict('post-purchase', data, expected)
