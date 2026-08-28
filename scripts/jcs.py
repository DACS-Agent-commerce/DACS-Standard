#!/usr/bin/env python3
"""RFC 8785 (JCS) canonicalisation for DACS lifecycle artifacts.

The value model is finite IEEE-754 binary64 numbers with magnitude no greater
than 2**53 - 1, strings, the literals true/false/null, arrays, and objects.
Integers and fractional numbers are both supported. Numbers outside the DACS
safe-magnitude profile, NaN, and +/-Infinity are rejected fail-closed.

CPython's float ``repr`` supplies the shortest round-trippable binary64 digits.
``_encode_float`` rewrites only their decimal-point/exponent presentation to
the ECMAScript thresholds required by RFC 8785: fixed notation for magnitudes
in [1e-6, 1e21), scientific notation otherwise, and ``0`` for negative zero.
The repository's deterministic vectors pin the exact UTF-8 bytes, including
RFC 8785 Appendix B edge cases.

From this the content hash (CORE §B.2) and the §B.7 signature payload derive. The
module is dependency-free so a §B.2 hash reproduces from a clean clone.

CF-1 (CORE §B.2). CF-1 binds "every JSON string *value*" to NFC. This module
follows that literal wording: string **values** are NFC-normalised before
serialisation; object **member names (keys)** are serialised and UTF-16-sorted
**as received**, exactly as RFC 8785 specifies (RFC 8785 performs no Unicode
normalisation of its own). This matches the in-repo precedent — the `nfc_deep`
helpers (test_x402_receipt_hash_vectors.py, run_lifecycle_walkthrough.py) fold
NFC over values only. CORE §B.2 makes that values-only scope explicit.
Canonically equivalent member names therefore remain distinct. Invalid Unicode
(a lone surrogate, in a key or a value) is rejected — that is a well-formedness
matter, not a CF-1 normalisation matter.
"""

from __future__ import annotations

import math
import unicodedata
from typing import Any

_SAFE_INT_MAX = 2 ** 53 - 1  # 9_007_199_254_740_991

# RFC 8785 §3.2.2.2 short escapes; all other C0 controls use lowercase \u00xx.
_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: "\\\"",
    0x5C: "\\\\",
}


def _ensure_utf8(text: str) -> None:
    """Reject strings that are not valid UTF-8 (e.g. a lone surrogate)."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"string is not valid UTF-8 (lone surrogate?): {text!r}") from exc


def _encode_string(text: str) -> str:
    """Serialise a (well-formed) string per RFC 8785 §3.2.2.2. No normalisation here."""
    out = ["\""]
    for ch in text:
        cp = ord(ch)
        escape = _SHORT_ESCAPES.get(cp)
        if escape is not None:
            out.append(escape)
        elif cp < 0x20:
            out.append("\\u%04x" % cp)  # lowercase hex, four digits
        else:
            out.append(ch)  # RFC 8785 emits the literal (UTF-8) code point
    out.append("\"")
    return "".join(out)


def _encode_value_string(text: str) -> str:
    # CF-1: string *values* are NFC-normalised before serialisation.
    _ensure_utf8(text)
    return _encode_string(unicodedata.normalize("NFC", text))


def _encode_key(key: str) -> str:
    # Member names are serialised AS RECEIVED (RFC 8785 performs no normalisation);
    # CF-1's literal wording binds values, not keys. Well-formedness still enforced.
    _ensure_utf8(key)
    return _encode_string(key)


def _encode_number(value: Any) -> str:
    # bool is a subclass of int and MUST be checked before the int branch;
    # booleans are JSON literals, never numbers.
    if isinstance(value, bool):
        raise ValueError("bool is not a JSON number")
    if isinstance(value, int):
        if abs(value) > _SAFE_INT_MAX:
            raise ValueError(
                f"integer {value} exceeds the IEEE-754 double safe-integer range "
                f"+/-{_SAFE_INT_MAX} (CORE §B.2 — carry large integers as strings)"
            )
        return str(value)
    if isinstance(value, float):
        return _encode_float(value)
    raise TypeError(f"unsupported number type: {type(value).__name__}")


def _encode_float(value: float) -> str:
    """Serialize one finite binary64 value using RFC 8785's ECMAScript form."""
    if not math.isfinite(value):
        raise ValueError(f"non-finite number {value!r} is not valid JSON (CORE §B.2)")
    if abs(value) > _SAFE_INT_MAX:
        raise ValueError(
            f"number {value!r} exceeds the DACS safe-magnitude range "
            f"+/-{_SAFE_INT_MAX} (CORE §B.2 — carry larger quantities as strings)"
        )
    # ECMAScript JSON.stringify(-0) is "0".
    if value == 0:
        return "0"

    shortest = repr(value).lower()
    sign = ""
    if shortest.startswith("-"):
        sign, shortest = "-", shortest[1:]

    if "e" in shortest:
        mantissa, exponent_text = shortest.split("e", 1)
        exponent = int(exponent_text)
    else:
        mantissa, exponent = shortest, 0

    if "." in mantissa:
        whole, fraction = mantissa.split(".", 1)
        digits = whole + fraction
        decimal_position = len(whole) + exponent
    else:
        digits = mantissa
        decimal_position = len(mantissa) + exponent

    # Keep the decimal position tied to the first significant digit. Trailing
    # zero removal does not move that position.
    while len(digits) > 1 and digits.startswith("0"):
        digits = digits[1:]
        decimal_position -= 1
    digits = digits.rstrip("0") or "0"

    magnitude = abs(value)
    if 1e-6 <= magnitude < 1e21:
        if decimal_position <= 0:
            body = "0." + "0" * (-decimal_position) + digits
        elif decimal_position >= len(digits):
            body = digits + "0" * (decimal_position - len(digits))
        else:
            body = digits[:decimal_position] + "." + digits[decimal_position:]
    else:
        body = digits[0]
        if len(digits) > 1:
            body += "." + digits[1:]
        output_exponent = decimal_position - 1
        body += "e" + ("+" if output_exponent >= 0 else "") + str(output_exponent)
    return sign + body


def _canonicalize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _encode_value_string(value)
    if isinstance(value, (int, float)):
        return _encode_number(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ValueError(f"object member name must be a string, got {type(key).__name__}")
            _ensure_utf8(key)
        # RFC 8785 §3.2.3: sort member names by their UTF-16 code units, as received.
        ordered = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_encode_key(k) + ":" + _canonicalize(v) for k, v in ordered) + "}"
    raise TypeError(f"unserialisable type: {type(value).__name__}")


def canonicalize(value: Any) -> str:
    """Return the RFC 8785 (JCS) canonical JSON string for ``value`` (see module docstring)."""
    return _canonicalize(value)
