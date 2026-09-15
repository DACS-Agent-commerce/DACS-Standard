#!/usr/bin/env python3
"""Shared, fail-closed primitives for the repository's reference consumers.

This module is an offline conformance model, not a durable production nonce or
receipt store.  It centralises the strict JCS and ClaimReference boundaries used
by the DACS-1/Vet and HTLC fixtures, plus the verifier-owned mutable nonce state
needed to model CORE SN-1..SN-4 without putting that state in signed artifacts.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import threading
import unicodedata
from typing import Any, Iterable
from urllib.parse import quote, unquote_to_bytes

import jcs


SAFE_INTEGER = 2**53 - 1
_SCHEME = re.compile(r"^[a-z][a-z0-9-]*$")
_KEY = re.compile(r"^[0-9a-f]{64}$")
_LEI = re.compile(r"^[0-9A-Z]{20}$")
_POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
_DID_METHOD = re.compile(r"^[a-z0-9]+$")
_DID_ID_CHAR = re.compile(r"^[A-Za-z0-9._-]$")
_DID_DEMOS_AGENT = re.compile(r"^demos:agent:[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32,}$")
_ULID = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
_UPPER_HEX = frozenset("0123456789ABCDEF")
_HEX = frozenset("0123456789ABCDEFabcdef")

# DACS-1 v0.x registered claim schemes used by current artifacts.  Historical
# generic ``cci:<hex>`` spellings are deliberately absent; current key signers
# use the explicit registered ``key`` scheme.
REGISTERED_SCHEMES = frozenset(
    {
        "cci-xm",
        "cci-web2",
        "cci-pqc",
        "cci-ud",
        "cci-nomis",
        "cci-humanpassport",
        "cci-ethos",
        "cci-tlsn",
        "stor-cred",
        "did",
        "erc8004",
        "domain",
        "key",
        "substrate-validator-set",
        "lei",
        "finra-crd",
        "sam-uei",
        "fedramp",
        "naics",
        "cmmc",
    }
)


class DuplicateJSONMember(ValueError):
    """A JSON object repeated an exact member name."""


def loads_unique_json(value: str | bytes | bytearray) -> Any:
    """Parse JSON while rejecting exact duplicate member names recursively."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise DuplicateJSONMember(f"invalid JSON: duplicate JSON member {key!r}")
            result[key] = item
        return result

    def reject_constant(constant: str) -> None:
        raise ValueError(f"invalid JSON: non-JSON numeric constant {constant}")

    try:
        return json.loads(
            value,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON: {error.msg}") from error
    except UnicodeDecodeError as error:
        raise ValueError("invalid JSON: input is not valid UTF-8") from error


def canonical_bytes(value: Any) -> bytes:
    """Return the repository's strict CORE §B.2 JCS bytes."""

    return jcs.canonicalize(value).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def canonical_equal(left: Any, right: Any) -> bool:
    return canonical_bytes(left) == canonical_bytes(right)


def exact_safe_integer(value: Any, *, minimum: int | None = None) -> bool:
    if type(value) is not int or not -SAFE_INTEGER <= value <= SAFE_INTEGER:
        return False
    return minimum is None or value >= minimum


def price_term_unit_is_valid(value: Any) -> bool:
    """Validate PriceTerm's optional unit without imposing content semantics."""

    return isinstance(value, dict) and (
        "unit" not in value or isinstance(value["unit"], str)
    )


@dataclass(frozen=True)
class ClaimReference:
    canonical: str
    scheme: str
    identifier: str
    parameters: tuple[tuple[str, str], ...]

    @property
    def identity(self) -> tuple[str, str]:
        """CF-3 identity; parameters intentionally do not participate."""

        return self.scheme, self.identifier


def _validate_percent_escapes(value: str, *, component: str) -> None:
    index = 0
    while index < len(value):
        if value[index] != "%":
            index += 1
            continue
        if (
            index + 2 >= len(value)
            or value[index + 1] not in _UPPER_HEX
            or value[index + 2] not in _UPPER_HEX
        ):
            raise ValueError(
                f"{component} percent escape must be '%' plus exactly two uppercase hex digits"
            )
        index += 3


def _parse_parameters(value: str | None) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if not value:
        raise ValueError("ClaimReference parameters must not be empty")
    parsed: list[tuple[str, str]] = []
    for member in value.split("&"):
        if member.count("=") != 1:
            raise ValueError("ClaimReference parameter must contain one '='")
        key, parameter_value = member.split("=", 1)
        if not key:
            raise ValueError("ClaimReference parameter key must not be empty")
        for component_name, component in (("parameter key", key), ("parameter value", parameter_value)):
            if any(ch.isspace() or unicodedata.category(ch).startswith("C") for ch in component):
                raise ValueError(f"ClaimReference {component_name} contains whitespace or a control")
            _validate_percent_escapes(component, component=component_name)
            for reserved in (":", "?", "=", "&"):
                if reserved in component:
                    raise ValueError(
                        f"ClaimReference {component_name} contains unescaped reserved delimiter"
                    )
        parsed.append((key, parameter_value))
    if len({key for key, _ in parsed}) != len(parsed):
        raise ValueError("ClaimReference parameter keys must be unique")
    if parsed != sorted(parsed, key=lambda item: item[0]):
        raise ValueError("ClaimReference parameters are not in canonical key order")
    return tuple(parsed)


def _validate_did(identifier: str) -> None:
    if ":" not in identifier:
        raise ValueError("DID identifier must contain a method and method-specific id")
    method, method_specific = identifier.split(":", 1)
    if _DID_METHOD.fullmatch(method) is None or not method_specific or method_specific.endswith(":"):
        raise ValueError("DID method or method-specific id is malformed")
    if method == "demos" and _DID_DEMOS_AGENT.fullmatch(identifier) is None:
        raise ValueError("Demos agent DID must be demos:agent:<64 lowercase hex>")
    index = 0
    while index < len(method_specific):
        ch = method_specific[index]
        if ch == "%":
            if (
                index + 2 >= len(method_specific)
                or method_specific[index + 1] not in _HEX
                or method_specific[index + 2] not in _HEX
            ):
                raise ValueError(
                    "DID percent escape must be '%' plus exactly two hex digits"
                )
            index += 3
            continue
        if ch != ":" and _DID_ID_CHAR.fullmatch(ch) is None:
            raise ValueError("DID method-specific id contains an invalid byte spelling")
        index += 1


def _validate_domain(identifier: str) -> None:
    if (
        not identifier.isascii()
        or identifier != identifier.lower()
        or identifier.endswith(".")
        or len(identifier.encode("ascii")) > 253
    ):
        raise ValueError("domain identifier is not canonical")
    try:
        import idna

        if idna.encode(identifier, uts46=False, std3_rules=True).decode("ascii") != identifier:
            raise ValueError("domain identifier is not canonical")
    except (UnicodeError, ValueError) as error:
        raise ValueError("domain identifier is not canonical") from error
    labels = identifier.split(".")
    if any(not label or len(label.encode("ascii")) > 63 for label in labels):
        raise ValueError("domain identifier is not canonical")
    import ipaddress

    try:
        ipaddress.ip_address(identifier)
    except ValueError:
        return
    raise ValueError("IP literals are not domain identifiers")


def parse_claim_reference(
    value: Any, *, registered_schemes: Iterable[str] = REGISTERED_SCHEMES
) -> ClaimReference:
    """Parse one signed CF-2 byte form without repairing it in place."""

    if not isinstance(value, str) or not value or value != unicodedata.normalize("NFC", value):
        raise ValueError("ClaimReference must be a non-empty NFC string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("ClaimReference is not valid UTF-8") from error
    if ":" not in value:
        raise ValueError("ClaimReference lacks a scheme delimiter")
    scheme, remainder = value.split(":", 1)
    if _SCHEME.fullmatch(scheme) is None:
        raise ValueError("ClaimReference scheme is not canonical lowercase ASCII")
    if scheme not in frozenset(registered_schemes):
        raise ValueError("ClaimReference scheme is not registered")
    if remainder.count("?") > 1:
        raise ValueError("ClaimReference contains multiple parameter delimiters")
    identifier, parameter_text = (
        remainder.split("?", 1) if "?" in remainder else (remainder, None)
    )
    if (
        not identifier
        or any(ch.isspace() or unicodedata.category(ch).startswith("C") for ch in identifier)
    ):
        raise ValueError("ClaimReference identifier is empty or contains whitespace/control")
    parameters = _parse_parameters(parameter_text)

    if scheme == "key" and _KEY.fullmatch(identifier) is None:
        raise ValueError(f"{scheme} identifier must be 32-byte lowercase hex")
    if scheme in {"lei", "cci-lei"} and _LEI.fullmatch(identifier) is None:
        raise ValueError("LEI identifier must be exactly 20 uppercase alphanumerics")
    if scheme in {"finra-crd", "cci-finra-crd"} and _POSITIVE_DECIMAL.fullmatch(identifier) is None:
        raise ValueError("FINRA CRD identifier must be a canonical positive decimal")
    if scheme == "did":
        _validate_did(identifier)
    if scheme == "domain":
        _validate_domain(identifier)
    if scheme == "cci-xm":
        # Generic references retain name-style subchains. PB-2's EVM numeric
        # chain profile is a separate settlement eligibility check.
        components = identifier.split(":", 2)
        if len(components) != 3 or not all(components):
            raise ValueError("cci-xm requires chain, subchain, and address")
    if scheme in {"cci-web2", "cci-pqc", "stor-cred", "substrate-validator-set"}:
        components = identifier.split(":", 1)
        if len(components) != 2 or not all(components):
            raise ValueError(f"{scheme} requires two non-empty components")
        if scheme == "cci-web2" and components[0] not in {
            "twitter", "github", "discord", "telegram",
        }:
            raise ValueError("cci-web2 platform is not registered")
        if scheme == "cci-pqc" and components[0] not in {"falcon", "ml-dsa"}:
            raise ValueError("cci-pqc algorithm is not registered")
        # Substrate registration/roster and opaque issued credential/key
        # semantics require the owning authenticated resolver, not this parser.
    if scheme == "erc8004":
        components = identifier.split(":")
        if (
            len(components) != 3
            or _POSITIVE_DECIMAL.fullmatch(components[0]) is None
            or re.fullmatch(r"0x[0-9a-f]{40}", components[1]) is None
            or re.fullmatch(r"0|[1-9][0-9]*", components[2]) is None
            or len(components[2]) > 78
            or int(components[2]) >= 2**256
        ):
            raise ValueError("erc8004 requires canonical chain, contract, and uint256 token id")
    if scheme == "sam-uei" and re.fullmatch(r"[0-9A-Z]{12}", identifier) is None:
        raise ValueError("UEI identifier must be 12 uppercase alphanumerics")
    if scheme == "naics" and re.fullmatch(r"[0-9]{6}", identifier) is None:
        raise ValueError("NAICS identifier must be six digits")

    return ClaimReference(value, scheme, identifier, parameters)


def cf4_encode(value: str) -> str:
    if not isinstance(value, str) or value != unicodedata.normalize("NFC", value):
        raise ValueError("CF-4 source segment must be an NFC string")
    return quote(value, safe="-._~")


def cf4_decode(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("CF-4 segment must be a string")
    _validate_percent_escapes(value, component="CF-4 segment")
    try:
        decoded = unquote_to_bytes(value).decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("CF-4 segment is not valid UTF-8") from error
    if cf4_encode(decoded) != value:
        raise ValueError("CF-4 segment is not canonically encoded")
    return decoded


def composite_logical_address(job_id: Any, evaluated_party: Any) -> str:
    if not isinstance(job_id, str) or _ULID.fullmatch(job_id) is None:
        raise ValueError("composite jobId must be a canonical ULID")
    reference = parse_claim_reference(evaluated_party)
    return f"dacs2:composite:{job_id}:{cf4_encode(reference.canonical)}"


def presentation_nonce(bundle: Any) -> str | None:
    """Extract the existing nonce conveyance without authenticating caller state."""

    if not isinstance(bundle, dict):
        return None
    presentation = bundle.get("presentation")
    if not isinstance(presentation, dict):
        return None
    kind = presentation.get("kind")
    if not isinstance(kind, str):
        return None
    if kind in {"per-claim", "session-key", "sr1-root"}:
        nonce = bundle.get("sessionNonce")
        return nonce if isinstance(nonce, str) else None
    if kind != "siwd":
        return None
    message = presentation.get("message")
    if not isinstance(message, str):
        return None
    matches = [line[7:] for line in message.splitlines() if line.startswith("Nonce: ")]
    return matches[0] if len(matches) == 1 and matches[0] else None


@dataclass(frozen=True)
class NonceIssuance:
    challenge_id: str
    nonce: str
    job_id: str
    actor: str
    evaluated_party: str
    phase_index: int
    attempt: int
    expected_verifier: str
    issued_by: str
    issued_at: int
    expires_at: int


class NonceRejected(ValueError):
    """The verifier-owned challenge could not authorize this invocation."""


class NonceLedger:
    """Issuer-owned mutable SN-4 state retained for this reference runtime."""

    _FIELDS = {
        "challengeId",
        "nonce",
        "jobId",
        "actor",
        "evaluatedParty",
        "phaseIndex",
        "attempt",
        "expectedVerifier",
        "issuedBy",
        "issuedAt",
        "expiresAt",
    }

    def __init__(self, issuance_records: Any, *, registered_schemes: Iterable[str] = REGISTERED_SCHEMES):
        if not isinstance(issuance_records, list):
            raise ValueError("trusted nonce issuances must be a list")
        self._lock = threading.Lock()
        self._records: dict[str, NonceIssuance] = {}
        self._consumed: dict[str, int] = {}
        nonces: set[str] = set()
        schemes = frozenset(registered_schemes)
        for item in issuance_records:
            issuance = self._parse_issuance(item, registered_schemes=schemes)
            if issuance.challenge_id in self._records or issuance.nonce in nonces:
                raise ValueError("trusted nonce issuances must be unique")
            self._records[issuance.challenge_id] = issuance
            nonces.add(issuance.nonce)

    @classmethod
    def _parse_issuance(cls, item: Any, *, registered_schemes: Iterable[str] = REGISTERED_SCHEMES) -> NonceIssuance:
        if not isinstance(item, dict) or set(item) != cls._FIELDS:
            raise ValueError("trusted nonce issuance has the wrong shape")
        if not isinstance(item.get("challengeId"), str) or not item["challengeId"]:
            raise ValueError("trusted nonce challengeId is invalid")
        nonce = item.get("nonce")
        if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None or len(nonce) % 2:
            raise ValueError("issued nonce must be canonical lowercase hex with at least 128 bits")
        if not isinstance(item.get("jobId"), str) or _ULID.fullmatch(item["jobId"]) is None:
            raise ValueError("issued nonce jobId is invalid")
        if not isinstance(item.get("actor"), str) or item["actor"] not in {"buyer", "seller"}:
            raise ValueError("issued nonce actor is invalid")
        parse_claim_reference(item.get("evaluatedParty"), registered_schemes=registered_schemes)
        parse_claim_reference(item.get("expectedVerifier"), registered_schemes=registered_schemes)
        parse_claim_reference(item.get("issuedBy"), registered_schemes=registered_schemes)
        if item["issuedBy"] != item["expectedVerifier"]:
            raise ValueError("issued nonce authority is not the expected verifier")
        for name in ("phaseIndex", "attempt", "issuedAt", "expiresAt"):
            if not exact_safe_integer(item.get(name), minimum=0):
                raise ValueError(f"issued nonce {name} is not an exact safe integer")
        if item["attempt"] < 1 or item["expiresAt"] < item["issuedAt"]:
            raise ValueError("issued nonce attempt or lifetime is invalid")
        return NonceIssuance(
            item["challengeId"],
            nonce,
            item["jobId"],
            item["actor"],
            item["evaluatedParty"],
            item["phaseIndex"],
            item["attempt"],
            item["expectedVerifier"],
            item["issuedBy"],
            item["issuedAt"],
            item["expiresAt"],
        )

    def consume(self, challenge_id: Any, presented_nonce: Any, trusted_now: Any) -> NonceIssuance:
        """Consume an exact issued nonce before any later presentation checks.

        Missing and wrong nonces never authorize and do not consume another
        issuance.  An exact nonce is consumed on the attempt even when it is
        expired or a later bundle/record check fails.
        """

        if not isinstance(challenge_id, str) or not isinstance(presented_nonce, str):
            raise NonceRejected("session nonce missing")
        if not exact_safe_integer(trusted_now, minimum=0):
            raise NonceRejected("trusted nonce time is invalid")
        issuance = self._records.get(challenge_id)
        if issuance is None or presented_nonce != issuance.nonce:
            raise NonceRejected("session nonce does not match verifier issuance")
        with self._lock:
            if challenge_id in self._consumed:
                raise NonceRejected("session nonce was already consumed")
            self._consumed[challenge_id] = trusted_now
        if trusted_now < issuance.issued_at or trusted_now > issuance.expires_at:
            raise NonceRejected("session nonce is outside its verifier-issued lifetime")
        return issuance

    def consumed(self, challenge_id: str) -> bool:
        with self._lock:
            return challenge_id in self._consumed
