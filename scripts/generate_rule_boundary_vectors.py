#!/usr/bin/env python3
"""Deterministic signature-authorization and HTLC submit-time fixture corpora."""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, utils

try:
    from .generate_settlement_finality_verification_vectors import FixtureFactory, OBSERVED_AT
    from .signature_authorization_reference import TYPES, digest
    from .secp256k1_fixture import SECP256K1_ORDER, deterministic_ecdsa_signature, fixture_private_value
except ImportError:
    from generate_settlement_finality_verification_vectors import FixtureFactory, OBSERVED_AT
    from signature_authorization_reference import TYPES, digest
    from secp256k1_fixture import SECP256K1_ORDER, deterministic_ecdsa_signature, fixture_private_value

ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / 'conformance/vectors/security'


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def raw(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def load(name):
    return json.loads((SECURITY / name).read_text())


def document(name, spec, vectors, **extra):
    return dict(set=name, spec=spec, tier='candidate',
                scope='fixture-only; signature gate or handler precondition, not full artifact admission',
                provenance={'generator': 'scripts/generate_rule_boundary_vectors.py'},
                count=len(vectors), hash=hashlib.sha256(json.dumps(vectors, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                vectors=vectors, **extra)


def signature_document():
    factory = FixtureFactory()
    fv = factory.model_input('block-depth')
    listing = load('listing-preserve-unknown-v0.1.json')['fixtures']['listing-with-inert-extension']['listing']
    marker = load('revocation-binding-v0.3.json')['fixtures']['markers']['valid-v3']
    bundle = json.loads((ROOT / 'conformance/vectors/examples/attestation-bundle.json').read_text())['artifact']
    channel = next(v['message'] for v in load('canonical-channel-message-v0.6.json')['vectors']
                   if v['name'] == 'canonical-valid-first')
    templates = {'ListingSignature': listing, 'RevocationSignature': marker,
                 'AgreementSignature': fv['agreement'], 'ComponentSignature': fv['evidence'],
                 'RailSignature': fv['rail'], 'BundleSignature': bundle,
                 'ChannelMessageSignature': channel,
                 'RecipeSignature': load('recipe-parser-applicability-v0.5.json')['vectors'][0]['recipe'],
                 'VerifyResultSignature': load('verifyresult-acceptance-v0.1.json')['vectors'][0]['verifyResult']}
    vectors = []
    for typ, (domain, member, field, _) in TYPES.items():
        variants = [
            ('ed25519-valid', 'pass'), ('ecdsa-valid', 'pass'), ('ed448-outside-set', 'error'),
            ('wire-padding', 'error'), ('decoded-length', 'fail'), ('invalid-signature', 'fail'),
            ('key-unavailable', 'indeterminate'), ('algorithm-unimplemented', 'indeterminate'),
            ('key-metadata-mismatch', 'fail'), ('unauthorized-signer', 'fail'),
            ('ecdsa-r-zero', 'fail'), ('ecdsa-s-zero', 'fail'),
            ('ecdsa-r-order', 'fail'), ('ecdsa-s-order', 'fail'),
            ('ecdsa-trailing-bytes', 'fail'), ('ecdsa-nonminimal-integer', 'fail'),
        ]
        if member == 'signatures':
            variants += [('required-signature-missing', 'fail'),
                         ('required-signature-missing-key-unavailable', 'fail')]
        if typ == 'BundleSignature':
            variants += [('abort-self-single-signed', 'pass'),
                         ('abort-other-single-signed', 'pass'),
                         ('abort-single-signed-key-unavailable', 'indeterminate'),
                         ('failed-perm-single-signed', 'fail'),
                         ('failed-counterparty-single-signed', 'fail'),
                         ('failed-substrate-single-signed', 'fail')]
        if typ == 'ChannelMessageSignature':
            variants += [('signature-version-missing', 'error'),
                         ('signature-version-unsupported', 'error'),
                         ('signature-version-nonstring', 'error'),
                         ('signature-extra-member', 'error')]
        for variant, expected in variants:
            algorithm = 'ecdsa-secp256k1' if (variant.startswith('ecdsa-') or variant in {'algorithm-unimplemented', 'key-metadata-mismatch'}) else 'ed448' if variant == 'ed448-outside-set' else 'ed25519'
            artifact = copy.deepcopy(templates[typ])
            claims = ['did:example:signature-primary', 'did:example:signature-secondary']
            authorized = claims[:]
            if typ == 'ListingSignature':
                artifact['seller']['identity']['claims'] = [{'ref': c} for c in claims]
                artifact['seller']['identity']['presentedBy'] = claims[0]
            if member == 'signatures':
                artifact['parties'] = [dict(p, primaryClaim=claims[i]) for i, p in enumerate(artifact['parties'])]
            # Listings intentionally use the second seller claim as an allowed control.
            signers = claims if member == 'signatures' else [claims[1]]
            partial = variant.startswith(('required-signature-missing', 'abort-')) or variant.endswith('-single-signed')
            if partial:
                signers = signers[:1]
            if typ == 'BundleSignature':
                if variant.startswith('abort-'):
                    artifact['outcome'] = 'aborted-by-other' if variant.startswith('abort-other') else 'aborted-by-self'
                elif variant.startswith('failed-'):
                    artifact['outcome'] = variant.removesuffix('-single-signed')
            signatures, keys = [], {}
            for signer in signers:
                label = ('DACS signature gate public test fixture ' + signer).encode()
                ed = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label).digest())
                scalar = fixture_private_value(label)
                secp = ec.derive_private_key(scalar, ec.SECP256K1())
                ed4 = ed448.Ed448PrivateKey.from_private_bytes(hashlib.sha512(label).digest()[:57])
                key = {'ed25519': ed, 'ecdsa-secp256k1': secp, 'ed448': ed4}[algorithm]
                public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint) if algorithm == 'ecdsa-secp256k1' else key.public_key().public_bytes_raw()
                keys[signer] = {'algorithm': algorithm, 'publicKey': b64(public)}
                signatures.append({field: signer, 'algorithm': algorithm, 'value': ''})
                if typ == 'ChannelMessageSignature':
                    signatures[-1]['signatureVersion'] = '1'
            artifact[member] = signatures if member == 'signatures' else signatures[0]
            message = (domain + digest(artifact, typ)).encode('ascii')
            for signature in signatures:
                signer = signature[field]
                label = ('DACS signature gate public test fixture ' + signer).encode()
                if algorithm == 'ecdsa-secp256k1':
                    value = deterministic_ecdsa_signature(fixture_private_value(label), message)
                elif algorithm == 'ed448':
                    value = ed448.Ed448PrivateKey.from_private_bytes(hashlib.sha512(label).digest()[:57]).sign(message)
                else:
                    value = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label).digest()).sign(message)
                signature['value'] = b64(value)
            first = signatures[0]
            envelope = 'pass' if partial else expected
            if variant.endswith('key-unavailable'):
                keys.pop(first[field])
                envelope = 'indeterminate'
            if variant == 'signature-version-missing': first.pop('signatureVersion')
            if variant == 'signature-version-unsupported': first['signatureVersion'] = '2'
            if variant == 'signature-version-nonstring': first['signatureVersion'] = 1
            if variant == 'signature-extra-member': first['extra'] = True
            if variant in {'ecdsa-r-zero', 'ecdsa-s-zero', 'ecdsa-r-order', 'ecdsa-s-order', 'ecdsa-trailing-bytes', 'ecdsa-nonminimal-integer'}:
                der = raw(first['value'])
                r, s = utils.decode_dss_signature(der)
                if variant == 'ecdsa-r-zero': der = utils.encode_dss_signature(0, s)
                elif variant == 'ecdsa-s-zero': der = utils.encode_dss_signature(r, 0)
                elif variant == 'ecdsa-r-order': der = utils.encode_dss_signature(SECP256K1_ORDER, s)
                elif variant == 'ecdsa-s-order': der = utils.encode_dss_signature(r, SECP256K1_ORDER)
                elif variant == 'ecdsa-trailing-bytes': der += b'\x00'
                else:
                    # Add a redundant leading zero to r, adjusting both lengths.
                    der = bytes([der[0], der[1] + 1, der[2], der[3] + 1, 0]) + der[4:]
                first['value'] = b64(der)
            if variant == 'wire-padding': first['value'] += '='
            if variant == 'decoded-length': first['value'] = b64(raw(first['value'])[:-1])
            if variant == 'invalid-signature':
                damaged = bytearray(raw(first['value'])); damaged[0] ^= 1; first['value'] = b64(damaged)
            if variant == 'key-metadata-mismatch': keys[first[field]]['algorithm'] = 'ed25519'
            if variant == 'unauthorized-signer': authorized = ['did:example:another-owner']; envelope = 'pass'
            vectors.append({'name': typ + '-' + variant, 'signatureType': typ, 'input': artifact,
                            'trusted': {'keys': keys, 'authorizedClaims': authorized,
                                        'implemented': ['ed25519'] if variant in {'algorithm-unimplemented', 'key-metadata-mismatch'} else ['ed25519', 'ecdsa-secp256k1']},
                            'expected': expected, 'want': {'envelope': envelope, 'artifact': expected}})
    return document('signature-authorization-v0.1', 'CORE §B.7 SIG-7; DACS-1 §6.3.4; DACS-2 §7.4/§7.5; DACS-3 §8.3.3/§8.5; DACS-4 §9.4/§9.7; DACS-5 §10.4.1', vectors)


def htlc_document():
    factory = FixtureFactory()
    value = factory.model_input('htlc-reveal')
    observation = value['context']['sourceLock']
    event = json.loads(raw(observation['selectedEventProof']['eventBytes']))
    profile = value['rail']['consumerFinalityProfile']['source']
    reference = observation['transactionRef']
    now = OBSERVED_AT + 10_000
    trusted = copy.deepcopy(factory.trusted)
    trusted['verificationTimeMs'] = now
    authority = dict(source_profile=profile, source_lock_ref=reference,
                     expected_economics={k: event[k] for k in ('jobId', 'phaseIndex', 'asset', 'amount', 'currency', 'payer', 'payee')},
                     source_contract=event['contractAddress'], source_hash_algorithm=event['hashAlgorithm'],
                     source_hashlock=event['hashlock'], source_expiry=event['expiry'], trusted=trusted)
    vectors = []
    def add(name, obs, decision, **extra):
        vectors.append(dict(name=name, input={'sourceObservation': obs}, expected=decision,
                            want={'maySubmit': decision == 'pass'}, **extra))
    add('actual-source-finality-observed', observation, 'pass')
    # Both have already waited beyond the estimated 600-second delay. Actual
    # source head depth, not elapsed time, distinguishes unsafe from safe.
    slow = factory.chain_observation(profile, reference, event, 'htlc:slow-source', head_position=110)
    add('estimated-delay-elapsed-source-not-final', slow, 'fail', note='Pinned delay elapsed; authenticated source depth is 11, below required 12. No destination submission.')
    add('actual-finality-at-required-depth', factory.chain_observation(profile, reference, event, 'htlc:exact-finality', head_position=111), 'pass')
    for suffix, timestamp, expected in (
        ('missing', None, 'error'), ('noninteger', str(event['minedAt']), 'error'),
        ('boolean', True, 'error'), ('mismatch', event['minedAt'] + 1, 'fail'),
    ):
        add('source-inclusion-timestamp-' + suffix,
            factory.chain_observation(profile, reference, event, 'htlc:timestamp:' + suffix,
                                      block_timestamp=timestamp), expected)
    add('source-observation-unavailable', None, 'indeterminate')
    forged = copy.deepcopy(observation)
    forged['authorityEvidence']['attestations'][0]['value'] = forged['authorityEvidence']['attestations'][1]['value']
    add('source-authority-signature-invalid', forged, 'fail')
    other = copy.deepcopy(observation); other['transactionRef'] = dict(reference, lockTxHash='00' * 32)
    add('source-lock-reference-substitution', other, 'fail')
    add('source-finality-observed-after-submit', factory.chain_observation(profile, reference, event, 'htlc:future-observation', observed_at=now + 1), 'fail')
    add('source-observation-stale', factory.chain_observation(profile, reference, event, 'htlc:stale-observation', observed_at=now - 61_000), 'indeterminate')
    wrong = copy.deepcopy(event); wrong['hashlock'] = '00' * 32
    add('other-authenticated-source-lock', factory.chain_observation(profile, reference, wrong, 'htlc:other-lock'), 'fail')
    malformed = copy.deepcopy(observation); malformed['extra'] = True
    add('source-observation-malformed', malformed, 'error')
    return document('htlc-submission-safety-v0.1', 'DACS-4 §9.5.4 HTLC-8 payee submission gate', vectors,
                    trustedFixtureAuthority=authority,
                    signedRail=value['rail'], authenticatedSession=factory.trusted['sessionAuthorityByJob'][event['jobId']],
                    description='Host supplies authority from authenticated rail/session/source lock and local clock. Fixture RPC proofs establish actual finality; elapsed sourceFinalitySec alone never permits submission.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    for data in (signature_document(), htlc_document()):
        path = SECURITY / (data['set'] + '.json')
        rendered = json.dumps(data, indent=2) + '\n'
        if args.write: path.write_text(rendered)
        elif not path.exists() or path.read_text() != rendered: raise SystemExit('stale ' + str(path))
        print(('wrote ' if args.write else 'verified ') + path.name)


if __name__ == '__main__':
    main()
