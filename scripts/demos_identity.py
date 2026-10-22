"""Read-only DACS-1 identity projection for DEMOS-MAPPING §A.2.

Never rewrite the signed reference. Only the leading scheme is case folded;
identifier bytes stay case sensitive and unknown well-formed qualifiers do not
participate in identity (DACS-1 §6.3.1, CORE §B.1 CF-2/CF-3).
"""
import re
import sys
from pathlib import Path

# The adapter-pinned reference uses sibling imports. Resolve them here for
# fresh package consumers as well as direct script entry points.
SCRIPTS = str(Path(__file__).resolve().parent)
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)
from dacs_reference import _parse_parameters  # noqa: E402

_KEY_CLAIM = re.compile(r"(?P<scheme>(?ai:key|did)):(?P<identifier>[0-9a-f]{64}|demos:agent:[0-9a-f]{64})\Z")
_ADDRESS = re.compile(r"(?:0x)?([0-9a-f]{64})\Z")


def demos_key_claim(value):
    """Return (canonical scheme, key), None for other claims, or raise for
    malformed parameters. Parameters are validated before being ignored."""
    if not isinstance(value, str):
        return None
    identity, separator, parameters = value.partition("?")
    if separator:
        # Read grammar accepts any parameter order. Validate each member
        # without rewriting the authenticated reference or adding a new
        # uniqueness requirement to DACS-1's key=value grammar.
        for member in parameters.split("&"):
            _parse_parameters(member)
    match = _KEY_CLAIM.fullmatch(identity)
    if match is None:
        return None
    scheme, identifier = match["scheme"].lower(), match["identifier"]
    if scheme == "key" and len(identifier) == 64:
        return scheme, identifier
    if scheme == "did" and identifier.startswith("demos:agent:"):
        return scheme, identifier.removeprefix("demos:agent:")
    return None


def demos_party_address(value):
    """Project a native address or a well-formed Demos ClaimReference."""
    match = _ADDRESS.fullmatch(value) if isinstance(value, str) else None
    if match:
        return match[1]
    try:
        claim = demos_key_claim(value)
    except ValueError:
        return None
    return claim[1] if claim else None
