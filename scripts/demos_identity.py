"""Read-only DACS-1 identity projection for DEMOS-MAPPING §A.2.

Never rewrite the signed reference. Only the leading scheme is case folded;
identifier bytes stay case sensitive and unknown well-formed qualifiers do not
participate in identity (DACS-1 §6.3.1, CORE §B.1 CF-2/CF-3).
"""
import importlib.util
import re
import sys
from pathlib import Path


def _load_sibling(name, module_name):
    """Load exact sibling bytes; a cached module from another tree is no substitute."""
    path = Path(__file__).resolve().with_name(name + ".py")
    if module_name in sys.modules:
        module = sys.modules[module_name]
        origin = getattr(module, "__file__", None)
        if not isinstance(origin, str) or Path(origin).resolve() != path:
            raise ImportError(f"{module_name} is not the Demos identity reader's sibling {path}")
        return module
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    # dataclasses in the pinned reference need the module registered during load.
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


# Preserve the adapter-pinned reference's bytes and absolute JCS import. Resolve
# JCS by path first, refusing a foreign cache entry rather than using its code.
# The reference has a consumer-private name, so an unrelated top-level
# dacs_reference can coexist without supplying this reader's claim grammar.
_jcs = _load_sibling("jcs", "jcs")
_reference = _load_sibling("dacs_reference", __name__ + "._dacs_reference")
if _reference.jcs is not _jcs:
    raise ImportError("dacs_reference does not use the Demos identity reader's sibling jcs")
_parse_parameters = _reference._parse_parameters

_KEY_CLAIM = re.compile(r"(?P<scheme>(?ai:key|did)):(?P<identifier>[0-9a-f]{64}|demos:agent:[0-9a-f]{64})\Z")
_ADDRESS = re.compile(r"(?:0x)?([0-9a-f]{64})\Z")


def demos_key_claim(value):
    """Return (canonical scheme, key), None for other claims, or raise for
    malformed claims. Grammar is validated before non-Demos claims are skipped."""
    if not isinstance(value, str):
        raise ValueError("ClaimReference must be a string")
    identity, separator, parameters = value.partition("?")
    if separator:
        # Read grammar accepts any parameter order. Validate each member
        # without rewriting the authenticated reference or adding a new
        # uniqueness requirement to DACS-1's key=value grammar.
        for member in parameters.split("&"):
            _parse_parameters(member)
    # Validate the entire identity, including the registered scheme's
    # identifier grammar, before deciding whether it projects to a Demos key.
    # The read rules fold only the scheme and permit unknown schemes and
    # arbitrary qualifier order; never pass signed bytes through a producer's
    # canonical-parameter check or silently repair the identifier.
    scheme, delimiter, identifier = identity.partition(":")
    if not delimiter:
        raise ValueError("ClaimReference lacks a scheme delimiter")
    if re.fullmatch(r"(?ai:[a-z][a-z0-9-]*)", scheme) is None:
        raise ValueError("ClaimReference scheme is not ASCII")
    scheme = scheme.lower()
    _reference.parse_claim_reference(
        scheme + ":" + identifier,
        registered_schemes=_reference.REGISTERED_SCHEMES | {scheme},
    )
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
