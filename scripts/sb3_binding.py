"""DACS-4 §9.5.8 SB-3: the branch that required binding evidence falls in.

The `sb3-binding-required` corpus and the negotiated x402 evaluator read the
same closed evidence model, `{"state": ...}`, through this one classifier.
"""

from __future__ import annotations


# Unavailable RPC or provider evidence, pruned history, an unresolved
# `isValidSignature`, and a reorganisation that removed the observation.
UNAVAILABLE_STATES = frozenset({
    "unavailable-rpc",
    "unavailable-pruned-history",
    "unavailable-signature-authority",
    "unavailable-reorged",
})
KNOWN_STATES = frozenset({"match", "mismatch", "absent", "malformed"}) | UNAVAILABLE_STATES


def binding_branch(evidence: object) -> str:
    """The SB-3 branch of one binding-evidence value.

    Returns `match`, `mismatch`, `absent`, `unavailable` (any `unavailable-*`
    state) or `malformed`. Anything but an object whose only member is a known
    string `state` is malformed: a missing or non-object value, a missing or
    non-string state, an unknown state, or an extra member.
    """
    if not isinstance(evidence, dict) or set(evidence) != {"state"}:
        return "malformed"
    state = evidence["state"]
    if not isinstance(state, str) or state not in KNOWN_STATES:
        return "malformed"
    if state in UNAVAILABLE_STATES:
        return "unavailable"
    return state
