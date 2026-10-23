"""Signed, composed regressions for the Atomic candidate's ordinary contracts."""
import copy
import itertools
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import atomic_work_reference as R
import generate_atomic_work_vectors as G
import settlement_contract_reference as PC
import validate_conformance_vectors as CV
import dacs5_reference as SEB
import generate_bundle_settlement_evidence_vectors as BG
from test_bundle_settlement_evidence_bijection_vectors import derive_phase_disposition, resign_ebfab

PINS = dict(expectedNetworkAuthority=G.CLAIMS['network'],
            expectedProofProfile='demos-bft-proof/test-1',
            expectedRailRegistryAuthority=G.CLAIMS['network'])


def admission(intent=None):
    intent = intent or G.purchase_intent(current_profile=True)
    return {**G.composed_purchase_admission(intent, G.final_receipt(intent)), **PINS}


def variant(builder, edit, sign):
    original = getattr(G, builder)
    def changed(*a, **kw):
        result = original(*a, **kw)
        edit(result)
        return sign(result)
    return patch.object(G, builder, changed)


def agreement_variant(edit):
    return variant('agreement_document', edit, G.resign_payee_agreement)


def listing_variant(edit):
    return variant('listing_fixture', edit, G.resign_listing)


def audit_fixture():
    p = G.purchase_intent(current_profile=True); pr = G.final_receipt(p)
    c = G.completion_intent(pr); cr = G.final_receipt(c)
    entries = []
    for intent, receipt, op in ((p, pr, 'payment'), (c, cr, 'delivery')):
        ev = G.settlement_evidence(intent, receipt, op)
        generation = pr['paymentSlot']['after']['generation'] if op == 'payment' else None
        entries.append(G.published_evidence(ev, R.atomic_evidence_address(ev, generation)))
    return {**PINS, 'capability': G.capability(), 'publicKeys': G.PUBLIC_KEYS,
            'purchaseIntent': p, 'purchaseReceipt': pr, 'completionIntent': c, 'completionReceipt': cr,
            'authorizationAuthority': G.authorization_authority(p),
            'dependencyProofs': G.audit_dependency_proofs('purchase',pr)+G.audit_dependency_proofs('completion',cr),
            'operations': [{'kind':'storage-program-put','idempotencyKey':'bundle'}],
            'st11Closure': {'settlementEvidence':entries,'bundle':G.published_bundle(p,G.role_bundle(p,entries))},
            'sessionStateBefore':'audit-pending','sessionStateAfter':'finalised'}


class AtomicColdReviewRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.purchase = admission()
        cls.audit = audit_fixture()

    def verdict(self, surface, data, expected):
        got = R.evaluate_vector({'surface':surface,'input':data})
        self.assertEqual(got[0], expected, got)

    def test_payout_binding_applies_to_current_agreement(self):
        self.verdict('purchase-admission', self.purchase, 'pass')
        p=G.purchase_intent(current_profile=True,payout_address='dem-other-destination')
        self.verdict('purchase-admission', admission(p), 'fail')

    def test_optional_roster_accounts_and_present_expectations(self):
        for role in ('payer','seller'):
            p=G.purchase_intent(current_profile=True)
            next(b for b in p['roleRoster'] if b['role']==role).pop('nativeAccount',None)
            self.verdict('purchase-admission', admission(p), 'pass')
        for role in ('buyer','seller','orchestrator','payer'):
            p=G.purchase_intent(current_profile=True)
            next(b for b in p['roleRoster'] if b['role']==role)['nativeAccount']='wrong-account'
            d=admission(p)
            if role=='orchestrator': d['authority']['orchestratorBundle']=G.identity_bundle(role);G.add_composed_limit_evidence(d)
            self.verdict('purchase-admission', d, 'fail')
        for role in ('buyer','orchestrator'):
            original=G.identity_bundle
            def mapped(*args,**kw):
                b=original(*args,**kw)
                for c in b['claims']:
                    if c['ref']==G.CLAIMS[role]: c['metadata']={'nativeAccount':f'dem-test-{role}'}
                unsigned={k:v for k,v in b.items() if k!='presentation'}
                digest=R._identity_bundle_hash(b)
                b['presentation']['signatures'][0]['signature']=R.b64u(R.ed25519_sign(G.SEEDS[args[0]],b'dacs-bundle-presentation:v1:'+digest.encode()))
                return b
            with patch.object(G,'identity_bundle',mapped):
                p=G.purchase_intent(current_profile=True)
                next(v for v in p['roleRoster'] if v['role']==role)['nativeAccount']=f'dem-test-{role}'
                d=admission(p)
                if role=='orchestrator':d['authority']['orchestratorBundle']=G.identity_bundle(role);G.add_composed_limit_evidence(d)
                self.verdict('purchase-admission',d,'pass')
                next(v for v in p['roleRoster'] if v['role']==role)['nativeAccount']='wrong-account'
                d=admission(p)
                if role=='orchestrator':d['authority']['orchestratorBundle']=G.identity_bundle(role);G.add_composed_limit_evidence(d)
                self.verdict('purchase-admission',d,'fail')

    def test_all_agreement_selectors_are_exclusive(self):
        for selector in ('agreementVersion','identityBoundAgreementVersion','payeeBoundAgreementVersion','sealedSelectionAgreementVersion'):
            with agreement_variant(lambda a:a.update({selector:'1'})):
                self.verdict('purchase-admission',admission(),'fail')

    def test_complete_pc1_type_gate_before_payment(self):
        with agreement_variant(lambda a:a['terms'].update(deadline=False)):
            self.verdict('purchase-admission',admission(),'fail')
        self.verdict('purchase-admission',self.purchase,'pass')

    def test_currency_and_exact_os_precision(self):
        def price(amount,currency):
            with listing_variant(lambda l:l['pricing']['price'].update(amount=amount,currency=currency)), agreement_variant(lambda a:a['terms']['price'].update(amount=amount,currency=currency)):
                return admission()
        self.verdict('purchase-admission',price('10','USDC'),'fail')
        self.verdict('purchase-admission',price('0.0000000001','DEM'),'fail')
        self.verdict('purchase-admission',price('0.000000001','DEM'),'pass')

    def test_delivery_before_payment_is_ineligible(self):
        with listing_variant(lambda l:l['pipeline'].__setitem__(slice(2,4),[l['pipeline'][3],l['pipeline'][2]])):
            p=G.purchase_intent(current_profile=True,payout_bindings=[{'railId':G.TEST_RAIL_ID,'phaseIndex':3,'payeeAddress':'dem-test-seller'}])
            p['phaseIndex']=3
            p['operations'][4]['payload']['slotKey']['phaseIndex']=3
            key=p['operations'][4]['payload']['slotKey']
            p['operations'][4]['payload']['conflictDigest']=R.conflict_digest({**key,'agreementHash':R._agreement_hash(p['operations'][2]['payload']['artifact']),'commitmentLogicalAddress':f"dacs3:commit:{p['jobId']}",'payer':'dem-test-payer','payee':'dem-test-seller','asset':'DEM','amount':'10'})
            d=admission(p)
            self.verdict('purchase-admission',d,'fail')
            self.assertIn('PIPE-4',R.evaluate_vector({'surface':'purchase-admission','input':d})[1])
            with patch.object(R,'_verify_atomic_delivery_eligibility',return_value=None):
                self.verdict('purchase-admission',d,'pass')

    def test_unsupported_access_mode_refused_before_purchase(self):
        for mode in ('buyer-only','encrypt-to-buyer'):
            with listing_variant(lambda l:l['offering']['deliverable'].update(accessModel=mode)):
                self.verdict('purchase-admission',admission(),'fail')
        self.verdict('purchase-admission',self.purchase,'pass')

    def test_completion_without_undefined_additional_terms(self):
        with agreement_variant(lambda a:a['terms'].pop('additionalTerms',None)):
            d=admission(); self.verdict('purchase-admission',d,'pass')
            p=d['intent'];pr=d['receipt'];c=G.completion_intent(pr);cr=G.final_receipt(c)
            cd={**G.composed_completion_admission(p,pr,c,cr),**PINS}
            self.verdict('completion-admission',cd,'pass')
            self.assertEqual(c['operations'][1]['payload']['logicalAddress'],f"dacs4:deliverable:{p['jobId']}:3")
            c['operations'][1]['payload']['logicalAddress']=f"dacs4:deliverable:{p['jobId']}"
            self.verdict('completion-admission',{**G.composed_completion_admission(p,pr,c,G.final_receipt(c)),**PINS},'fail')

    def test_completion_checks_canonical_purchase_commitment(self):
        p=G.purchase_intent(current_profile=True)
        p['operations'][3]['payload']['logicalAddress']=f"dacs3:other:{p['jobId']}"
        pr=G.final_receipt(p);c=G.completion_intent(pr)
        self.verdict('completion-admission',{**G.composed_completion_admission(p,pr,c,G.final_receipt(c)),**PINS},'fail')

    def test_documented_session_outputs_need_no_aliases(self):
        source=self.purchase['authority']['sessionContextSource']['priorPhaseOutputs']
        self.assertNotIn('agreementHash',source);self.assertNotIn('commitmentHash',source)
        self.assertIn('negotiate-fixed-price',source)
        self.verdict('purchase-admission',self.purchase,'pass')

    def test_asserted_vet_consumes_finalized_receipts(self):
        p=G.purchase_intent(current_profile=True)
        receipts={}
        for index,role in ((0,'buyer'),(1,'seller')):
            op=p['operations'][index]
            receipts[role]=G.registry_anchor_receipt(op['payload']['logicalAddress'],op['payload']['artifact'],label=role,nonce=str(index+10))
            op['kind']='assert-artifact';op['payload']={'artifact':op['payload']['artifact']}
        d=admission(p);d['vetReceipts']=receipts;G.add_composed_limit_evidence(d)
        self.verdict('purchase-admission',d,'pass')
        d['vetReceipts']['buyer']['state']='included'
        self.verdict('purchase-admission',d,'fail')
        del d['vetReceipts']
        self.verdict('purchase-admission',d,'indeterminate')

    def test_nfd_member_names_remain_distinct(self):
        p=copy.deepcopy(self.purchase['intent']);p['e\u0301']={'label':'accepted'};p['é']={'label':'distinct'}
        R.validate_intent(p)
        self.assertNotEqual(R.work_id(p),R.work_id(self.purchase['intent']))

    def test_rail_optional_metadata_and_printable_id(self):
        rail=G.rail_definition(G.TEST_RAIL_ID)
        rail['governance']['deprecated']=False
        rail=R.sign_embedded(rail,G.CLAIMS['network'],G.SEEDS['network'],R._RAIL_DOMAIN)
        R._verify_rail_definition(rail,G.PUBLIC_KEYS,G.CLAIMS['network'])
        rail['railId']='native/DEM!'
        rail=R.sign_embedded(rail,G.CLAIMS['network'],G.SEEDS['network'],R._RAIL_DOMAIN)
        R._verify_rail_definition(rail,G.PUBLIC_KEYS,G.CLAIMS['network'])
        rail['governance']['deprecated']='false'
        with self.assertRaises(R.Invalid): R._verify_rail_definition(rail,G.PUBLIC_KEYS,G.CLAIMS['network'])

    def test_evidence_unknown_metadata_and_price_units(self):
        d=copy.deepcopy(self.purchase)
        d.update(d['settlement']);ev=d['evidence'];ev['kind']='audit-copy'
        ev=G.resign_atomic_evidence(ev);d['evidence']=ev;d['auditPublication']=G.atomic_publication(ev,d['evidenceAddress'])
        self.verdict('settlement',d,'pass')
        with listing_variant(lambda l:l['pricing']['price'].update(unit='per-call')),agreement_variant(lambda a:a['terms']['price'].update(unit='per-call')):
            d=admission();self.verdict('purchase-admission',d,'pass')
            self.assertEqual(d['settlement']['evidence']['paymentAmount']['unit'],'per-call')

    def test_receipt_winner_diagnostic_is_inert(self):
        d=copy.deepcopy(self.purchase)
        receipt=d['receipt'];receipt['winningAttempt']['diagnostic']='observer copy'
        receipt=G.rebind_receipt_finality(receipt);d['receipt']=receipt
        # This focused gate compares only the two named identity members.
        R.evaluate_attempts(d)

    def test_evidence_structural_error_and_semantic_failure(self):
        for value,expected in ((False,'error'),(3,'fail')):
            d=copy.deepcopy(self.purchase);d.update(d['settlement'])
            ev=copy.deepcopy(d['evidence']);ev['phaseIndex']=value;ev=G.resign_atomic_evidence(ev)
            d['evidence']=ev;d['auditPublication']=G.atomic_publication(ev,d['evidenceAddress'])
            self.verdict('settlement',d,expected)

    def test_mixed_lifecycle_evidence_selectors_refused(self):
        self.assertTrue(CV.lifecycle_evidence_kind_matches('SettlementEvidence',{'evidenceVersion':'1'}))
        self.assertFalse(CV.lifecycle_evidence_kind_matches('SettlementEvidence',{'evidenceVersion':'1','atomicEvidenceVersion':'1'}))

    def test_success_evidence_members_match_schema_and_seb(self):
        for phase,foreign in (('pay-dem','deliverableContentHash'),('deliver-storage-program','paymentAmount')):
            entry=next(e for e in self.audit['st11Closure']['settlementEvidence'] if e['evidence']['phase']==phase)
            ev=copy.deepcopy(entry['evidence'])
            R.validate_schema(ev,'atomic-settlement-evidence-v1.schema.json')
            self.assertTrue(SEB._atomic_settlement_evidence_shape_valid(ev))
            ev[foreign]='00'*32 if phase=='pay-dem' else {'amount':'10','currency':'DEM'}
            with self.assertRaises(R.Invalid):R.validate_schema(ev,'atomic-settlement-evidence-v1.schema.json')
            self.assertFalse(SEB._atomic_settlement_evidence_shape_valid(ev))

    def test_publication_hash_composes_with_references(self):
        self.verdict('audit',self.audit,'pass')
        bundle=self.audit['st11Closure']['bundle']['bundle']
        self.assertEqual(bundle['agreementRef']['contentHash'],R._agreement_hash(self.audit['authorizationAuthority']['agreement']))
        for entry in self.audit['st11Closure']['settlementEvidence']:
            publication=entry['publication']['anchorReceipt']
            self.assertEqual(publication['contentHash'],R.atomic_evidence_hash(entry['evidence']))
            self.assertIn((publication['nativeAddress'],publication['contentHash']),R._evidence_refs(self.audit['st11Closure']['bundle']['bundle']))

    def test_replay_binds_signed_bytes_even_when_content_hash_is_unchanged(self):
        d=copy.deepcopy(self.purchase);d.update(d['settlement']);ev=d['evidence']
        d['auditPublication']=G.atomic_publication(ev,d['evidenceAddress'],mode='replay')
        self.verdict('settlement',d,'pass')
        old=copy.deepcopy(ev);old['signature']['diagnostic']='earlier envelope'
        self.assertEqual(R.atomic_evidence_hash(ev),R.atomic_evidence_hash(old))
        d['auditPublication']=G.atomic_publication(ev,d['evidenceAddress'],mode='replay',existing_evidence=old)
        self.verdict('settlement',d,'fail')
        d['auditPublication']['existingCanonicalBytes']=R.b64u(R.jcs_bytes(ev))
        self.verdict('settlement',d,'fail')

    def test_signed_bundle_dependencies_cannot_be_substituted(self):
        changes=[lambda b:b['listingRef'].update(contentHash='00'*32),
                 lambda b:b['parties'][0].update(bundleHash='00'*32),
                 lambda b:b.update(railRegistryVersion=2),
                 lambda b:b.update(recipeRegistryVersion=2),
                 lambda b:b['phaseSummary'][0].update(kind='rate'),
                 lambda b:b['vetRecords'][0].update(contentHash='00'*32),
                 lambda b:b['agreementRef'].update(contentHash='00'*32),
                 lambda b:b['parties'].pop(1)]
        for change in changes:
            d=copy.deepcopy(self.audit);bundle=d['st11Closure']['bundle']['bundle'];change(bundle)
            bundle=G.sign_bundle(bundle,('buyer','seller','orchestrator'))
            d['st11Closure']['bundle']=G.published_bundle(d['purchaseIntent'],bundle)
            self.verdict('audit',d,'fail')

    def test_audit_refuses_false_proven_outputs(self):
        for phase,key,value in (('pay-dem','paymentAmount',{'amount':'999','currency':'DEM'}),('deliver-storage-program','deliverableContentHash','00'*32),('deliver-storage-program','deliverableAnchor',{'kind':'storage-program','locator':'elsewhere'})):
            d=copy.deepcopy(self.audit);entries=d['st11Closure']['settlementEvidence']
            i=next(i for i,e in enumerate(entries) if e['evidence']['phase']==phase)
            ev=copy.deepcopy(entries[i]['evidence']);ev[key]=value;ev=G.resign_atomic_evidence(ev)
            entries[i]=G.published_evidence(ev,entries[i]['evidenceAddress'])
            d['st11Closure']['bundle']=G.published_bundle(d['purchaseIntent'],G.role_bundle(d['purchaseIntent'],entries))
            self.verdict('audit',d,'fail')
            with patch.object(R,'verify_settlement',return_value=None):
                self.verdict('audit',d,'pass')

    def test_complete_bundle_dependencies_and_orchestrator_signature(self):
        for member in ('listingRef','phaseSummary','vetRecords','recipeRegistryVersion','railRegistryVersion','finalisedAt','agreementRef'):
            d=copy.deepcopy(self.audit);bundle=d['st11Closure']['bundle']['bundle'];del bundle[member]
            bundle=G.sign_bundle(bundle,('buyer','seller','orchestrator'))
            d['st11Closure']['bundle']=G.published_bundle(d['purchaseIntent'],bundle)
            self.verdict('audit',d,'fail')
        d=copy.deepcopy(self.audit);bundle=d['st11Closure']['bundle']['bundle']
        bundle=G.sign_bundle(bundle,('buyer','seller'))
        d['st11Closure']['bundle']=G.published_bundle(d['purchaseIntent'],bundle)
        self.verdict('audit',d,'fail')

    def test_buyer_can_also_orchestrate_without_extra_bundle_party(self):
        with patch.dict(G.CLAIMS,{'orchestrator':G.CLAIMS['buyer']}), patch.dict(G.SEEDS,{'orchestrator':G.SEEDS['buyer']}):
            d=audit_fixture()
            self.assertEqual({p['role'] for p in d['st11Closure']['bundle']['bundle']['parties']},{'buyer','seller'})
            self.verdict('audit',d,'pass')

    def test_post_payment_abort_refused_and_failure_allowed(self):
        p=self.audit['purchaseIntent'];pr=self.audit['purchaseReceipt'];entry=self.audit['st11Closure']['settlementEvidence'][0]
        failed=G.failed_delivery_material(p,pr)
        d={**PINS,**failed,'publicKeys':G.PUBLIC_KEYS,'capability':G.capability(),'purchaseIntent':p,'purchaseReceipt':pr,'paymentEvidence':entry,'authorizationAuthority':G.authorization_authority(p),'remedy':'ordinary-failure-record'}
        for outcome,fault,expected in (('failed-counterparty','seller','pass'),('aborted-by-self','buyer','fail'),('aborted-by-other','seller','fail')):
            bundle=G.role_bundle(p,[entry,failed['failureDeliveryEvidence']],role='buyer',outcome=outcome,faulted=fault,signers=('buyer','seller','orchestrator'))
            d['failureRecord']=G.published_bundle(p,bundle,state='included')
            self.verdict('post-purchase',d,expected)

    def test_post_payment_audit_substrate_failure_keeps_successful_delivery(self):
        p=self.audit['purchaseIntent'];pr=self.audit['purchaseReceipt']
        entries=self.audit['st11Closure']['settlementEvidence']
        bundle=G.role_bundle(p,entries,role='buyer',outcome='failed-substrate',faulted='none',signers=('buyer','seller','orchestrator'))
        bundle['phaseSummary'][-1]={'index':3,'kind':'deliver-storage-program','outcome':'ok'}
        bundle=G.sign_bundle(bundle,('buyer','seller','orchestrator'))
        d={**PINS,'publicKeys':G.PUBLIC_KEYS,'capability':G.capability(),'purchaseIntent':p,'purchaseReceipt':pr,
           'paymentEvidence':entries[0],'authorizationAuthority':G.authorization_authority(p),'remedy':'ordinary-failure-record',
           'failureCompletionIntent':self.audit['completionIntent'],'failureCompletionReceipt':self.audit['completionReceipt'],
           'failureDeliveryEvidence':entries[1],'failureRecord':G.published_bundle(p,bundle,state='included')}
        self.verdict('post-purchase',d,'pass')

    def test_complete_amendment_required_members(self):
        p=self.audit['purchaseIntent'];entry=self.audit['st11Closure']['settlementEvidence'][0]
        digest=R.atomic_evidence_hash(entry['evidence']);address=f"dacs4:amendment:{p['jobId']}:{digest}:0"
        original={'amendmentVersion':'1','jobId':p['jobId'],'amendsEvidenceRef':{'anchor':{'kind':'storage-program','locator':entry['evidenceAddress']},'contentHash':digest},'amendmentType':'partial-refund','refundAmount':{'amount':'1','currency':'DEM'},'reason':'','observedAt':1800000050000}
        d={**PINS,'publicKeys':G.PUBLIC_KEYS,'capability':G.capability(),'purchaseIntent':p,'purchaseReceipt':self.audit['purchaseReceipt'],'paymentEvidence':entry,'authorizationAuthority':G.authorization_authority(p),'remedy':'settlement-amendment','amendmentAddress':address}
        for removed in (None,'reason','observedAt'):
            a=copy.deepcopy(original)
            if removed:del a[removed]
            a=R.sign_embedded(a,G.CLAIMS['seller'],G.SEEDS['seller'],R._AMENDMENT_DOMAIN)
            d['amendment']=a;d['amendmentReceipt']=G.registry_anchor_receipt(address,a,label='amendment',nonce='970')
            self.verdict('post-purchase',d,'pass' if removed is None else 'fail')

    def test_amendment_consumes_actual_atomic_publication(self):
        entry=self.audit['st11Closure']['settlementEvidence'][0]
        ev=entry['evidence'];digest=R.atomic_evidence_hash(ev)
        a={'amendmentVersion':'1','jobId':ev['jobId'],'amendsEvidenceRef':{'anchor':{'kind':'storage-program','locator':entry['evidenceAddress']},'contentHash':digest},'amendmentType':'correction','reason':'audit','observedAt':1800000050000}
        a=R.sign_embedded(a,G.CLAIMS['seller'],G.SEEDS['seller'],R._AMENDMENT_DOMAIN)
        a=json.dumps(a).encode('utf-8')
        # AMEND-1 now authenticates the enclosing session before resolving the
        # target. Supply the same fixture root and retained authority as the
        # actual Atomic publication, rather than bare caller-selected pins.
        source=self.audit['authorizationAuthority']['sessionContextSource']
        state=R.sign_embedded({
            'jobId':ev['jobId'],
            'session':{key:source[key] for key in ('startedAt','railRegistryVersion')},
            'orchestrator':G.CLAIMS['orchestrator'],'writer':G.CLAIMS['orchestrator'],
            'steward':G.CLAIMS['network'],'registryWriter':G.CLAIMS['network'],
        },G.CLAIMS['network'],G.SEEDS['network'],PC.RETAINED_STATE_DOMAIN)
        kwargs=dict(amendment_address=f"dacs4:amendment:{ev['jobId']}:{digest}:0",orchestrator=G.CLAIMS['orchestrator'],writer=G.CLAIMS['orchestrator'],public_keys=G.PUBLIC_KEYS,network_authority=G.CLAIMS['network'],network_id=ev['networkId'],proof_profile=PINS['expectedProofProfile'],validator_set_id='test-validator-set-1',retained_state=json.dumps(state).encode('utf-8'))
        resolved={'artifact':json.dumps(ev).encode('utf-8'),'anchorReceipts':[entry['publication']['anchorReceipt']],'publication':entry['publication']}
        self.assertEqual(PC.consume_amendment_target(a,lambda _:resolved,**kwargs)[0],'valid')
        duplicate=copy.deepcopy(resolved)
        proof=duplicate['anchorReceipts'][0]['evidence']
        raw=R.b64u_decode(proof['value'])
        proof['value']=R.b64u(b'{"writer":"ignored-first-value",'+raw[1:])
        self.assertNotEqual(PC.consume_amendment_target(a,lambda _:duplicate,**kwargs)[0],'valid')
        bad=copy.deepcopy(resolved);bad['anchorReceipts'][0]['contentHash']='00'*32
        self.assertNotEqual(PC.consume_amendment_target(a,lambda _:bad,**kwargs)[0],'valid')
        self.assertEqual(PC.consume_amendment_target(a,lambda _:resolved,**{**kwargs,'retained_state':None})[0],'indeterminate')
        self.assertEqual(PC.consume_amendment_target(a,lambda _:resolved,**{**kwargs,'writer':'native:outsider'}),
                         ('violation','amendment authority differs from retained session state'))
        # The base's carrier selection also applies to actual Atomic proofs:
        # equal copies collapse; two authenticated unequal receipts do not.
        duplicate={**resolved,'anchorReceipts':resolved['anchorReceipts']*2}
        self.assertEqual(PC.consume_amendment_target(a,lambda _:duplicate,**kwargs)[0],'valid')
        other=copy.deepcopy(entry['publication'])
        other['anchorReceipt']['nonce']='951'
        proof=json.loads(R.b64u_decode(other['anchorReceipt']['evidence']['value']))
        proof.pop('signature');proof['nonce']='951'
        other['anchorReceipt']['evidence']=G.encoded_evidence('test-anchor-publication',proof,'network',R._PUBLICATION_TEST_DOMAIN)
        equivocal={**resolved,'anchorReceipts':[*resolved['anchorReceipts'],other['anchorReceipt']],
                   'publications':[entry['publication'],other]}
        status,reason=PC.consume_amendment_target(a,lambda _:equivocal,**kwargs)
        self.assertEqual(status,'indeterminate')
        self.assertIn('equivocation',reason)
        changed=R.sign_embedded({**ev,'observedAt':ev['observedAt']+1},G.CLAIMS['orchestrator'],G.SEEDS['orchestrator'],R.EVIDENCE_DOMAIN)
        other=G.atomic_publication(changed,entry['evidenceAddress'])
        equivocal={**resolved,'anchorReceipts':[*resolved['anchorReceipts'],other['anchorReceipt']],
                   'publications':[entry['publication'],other]}
        status,reason=PC.consume_amendment_target(a,lambda _:equivocal,**kwargs)
        self.assertEqual(status,'indeterminate')
        self.assertIn('equivocation',reason)
        contradiction={**resolved,'anchorReceipts':[other['anchorReceipt']],'publication':other}
        self.assertEqual(PC.consume_amendment_target(a,lambda _:contradiction,**kwargs),
                         ('violation','authentic amendment target anchor binds another content hash'))

    def test_seb_uses_actual_publication_and_checks_all_member_orders(self):
        authority=BG.make_atomic_authority()
        pubkeys={k:R.b64u_decode(v) for k,v in G.PUBLIC_KEYS.items()}
        self.assertEqual(derive_phase_disposition(authority,pubkeys)[0],'pass')
        refs=authority['bundle']['settlementEvidence'];keys=[SEB.canonical(v).decode() for v in refs]
        authority['atomicEvidenceAdmissionByCanonicalRef'].pop(keys[0])
        authority['referenceValidationByCanonicalRef'][keys[1]]['record']['signature']['value']='A'*86
        for order in itertools.permutations(refs):
            d=copy.deepcopy(authority);d['bundle']['settlementEvidence']=list(order)
            BG._sign_atomic_bundle(d['bundle'])
            self.assertEqual(derive_phase_disposition(d,pubkeys)[0],'fail')

    def test_validation_dependency_pins_shared(self):
        workflow=(ROOT/'.github/workflows/validate.yml').read_text()
        guide=(ROOT/'CONTRIBUTING.md').read_text()
        self.assertIn('-r requirements-validation.txt',workflow)
        self.assertIn('-r requirements-validation.txt',guide)
        self.assertIn('referencing==0.37.0',(ROOT/'requirements-validation.txt').read_text())


if __name__=='__main__':unittest.main()
