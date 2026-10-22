"""HTLC-8 handler gate; no transaction is constructed, signed or submitted.

The host creates authority from the authenticated signed rail, retained session,
exact source-lock transaction and its own clock. Candidate data supplies only
an observation. This fixture codec is not a registered production binding.
"""
from dataclasses import dataclass

try:
    from .settlement_finality_reference import _verify_chain_observation
except ImportError:
    from settlement_finality_reference import _verify_chain_observation


@dataclass(frozen=True)
class HtlcSubmissionAuthority:
    source_profile: dict
    source_lock_ref: dict
    expected_economics: dict
    source_contract: str
    source_hash_algorithm: str
    source_hashlock: str
    source_expiry: int
    trusted: dict


def verify_htlc_submission(observation, *, authority):
    """Only pass permits the payee to submit; every other verdict pauses/refuses."""
    if not isinstance(authority, HtlcSubmissionAuthority):
        return {'decision': 'indeterminate', 'maySubmit': False,
                'reason': 'authenticated HTLC submission authority unavailable'}
    try:
        result, event = _verify_chain_observation(
            observation, authority.source_profile, authority.source_lock_ref,
            authority.expected_economics, authority.trusted)
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, RecursionError):
        return {'decision': 'error', 'maySubmit': False,
                'reason': 'malformed HTLC submission observation or authority'}
    decision = result['decision']
    reason = result['reason']
    if event is not None and (
        event.get('eventType') != 'htlc-lock'
        or event.get('contractAddress') != authority.source_contract
        or event.get('hashAlgorithm') != authority.source_hash_algorithm
        or event.get('hashlock') != authority.source_hashlock
        or event.get('expiry') != authority.source_expiry
    ):
        if decision != 'error':
            decision = 'fail'
            reason = 'authenticated source lock differs from the retained swap'
    return {'decision': decision, 'maySubmit': decision == 'pass', 'reason': reason}
