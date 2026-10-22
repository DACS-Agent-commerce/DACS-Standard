"""CORE SIG-7 signature gates, separate from full artifact admission.

The type is selected by the enclosing operation, never by candidate metadata.
Keys and authorized claims are verifier-owned; a pass establishes signatures
only, not current Listing/Revocation/Bundle lifecycle authority.
"""
from __future__ import annotations

import base64
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

try:
    from .jcs import canonicalize
    from .secp256k1_fixture import SECP256K1_ORDER
except ImportError:
    from jcs import canonicalize
    from secp256k1_fixture import SECP256K1_ORDER

ALGORITHMS = frozenset({'ed25519', 'ecdsa-secp256k1', 'sr1-aggregate'})
# type: (domain, signature member, signer member, additional hash omissions)
TYPES = {
    'ListingSignature': ('dacs-listing:v1:', 'signature', 'signer', ()),
    'RevocationSignature': ('dacs-revocation:v1:', 'signature', 'signer', ()),
    'AgreementSignature': ('dacs-agreement:v1:', 'signatures', 'party', ()),
    'ComponentSignature': ('dacs-finality-bound-evidence:v1:', 'signature', 'signer', ()),
    'RailSignature': ('dacs-rail:v1:', 'signature', 'signer', ()),
    'BundleSignature': ('dacs-bundle:v1:', 'signatures', 'party', ('anchoredByRole',)),
    'ChannelMessageSignature': ('dacs-canonical-channel-message:v1:', 'signature', 'signer', ()),
    'RecipeSignature': ('dacs-recipe:v1:', 'signature', 'signer', ()),
    'VerifyResultSignature': ('dacs-verifyresult:v1:', 'signature', 'signer', ()),
}


def decode(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', value) or len(value) % 4 == 1:
        raise ValueError('noncanonical signature value')
    raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b'=').decode() != value:
        raise ValueError('noncanonical signature value')
    return raw


def digest(artifact, signature_type):
    _, member, _, extra = TYPES[signature_type]
    return hashlib.sha256(canonicalize({k: v for k, v in artifact.items()
                                       if k not in (member, *extra)}).encode()).hexdigest()


def verify_envelope(envelope, message, keys, *, signer_field='signer', allowed=ALGORITHMS,
                    implemented=ALGORITHMS):
    if not isinstance(envelope, dict):
        return 'error'
    algorithm = envelope.get('algorithm')
    if not isinstance(algorithm, str) or algorithm not in allowed:
        return 'error'
    try:
        raw = decode(envelope.get('value'))
    except ValueError:
        return 'error'
    signer = envelope.get(signer_field)
    if not isinstance(signer, str) or not signer:
        return 'error'
    key = keys.get(signer)
    # A key: claim binds Ed25519 even when the resolver does not hold a key.
    metadata = 'ed25519' if re.fullmatch(r'key:[0-9a-f]{64}', signer) else None
    if ((metadata is not None and metadata != algorithm)
            or (key is not None and key['algorithm'] != algorithm)):
        return 'fail'
    if algorithm == 'ed25519' and len(raw) != 64:
        return 'fail'
    if algorithm == 'ecdsa-secp256k1':
        try:
            r, s = utils.decode_dss_signature(raw)
            if utils.encode_dss_signature(r, s) != raw or not (1 <= r < SECP256K1_ORDER and 1 <= s <= SECP256K1_ORDER // 2):
                return 'fail'
        except ValueError:
            return 'fail'
    if key is None or algorithm not in implemented or algorithm == 'sr1-aggregate':
        return 'indeterminate'
    try:
        public = decode(key['publicKey'])
        if algorithm == 'ed25519':
            ed25519.Ed25519PublicKey.from_public_bytes(public).verify(raw, message)
        else:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public).verify(raw, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return 'fail'
    return 'pass'


def authorize_signatures(artifact, signature_type, keys, authorized_claims, *, implemented=ALGORITHMS):
    """Return envelope verdict and containing artifact's signature-gate verdict."""
    domain, member, field, _ = TYPES[signature_type]
    signatures = artifact.get(member)
    signatures = signatures if member == 'signatures' else [signatures]
    if not isinstance(signatures, list) or not signatures:
        return {'envelope': 'error', 'artifact': 'error'}
    message = (domain + digest(artifact, signature_type)).encode('ascii')
    results = [verify_envelope(s, message, keys, signer_field=field, implemented=implemented)
               for s in signatures]
    decision = next((v for v in ('error', 'fail', 'indeterminate') if v in results), 'pass')
    signers = [s.get(field) for s in signatures if isinstance(s, dict)]
    if decision != 'error' and (len(signers) != len(set(signers)) or any(s not in authorized_claims for s in signers)):
        decision = 'fail'
    if decision == 'pass' and member == 'signatures' and set(signers) != set(authorized_claims):
        decision = 'fail'
    return {'envelope': next((v for v in ('error', 'fail', 'indeterminate') if v in results), 'pass'),
            'artifact': decision}
