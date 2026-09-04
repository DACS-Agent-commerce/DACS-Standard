#!/usr/bin/env python3
"""Raw JSON admission for signed or content-hashed DACS documents.

JCS operates on an already parsed value and therefore cannot detect information
that a permissive parser discarded, notably duplicate member names or a number
rounded before the DACS safe-magnitude check.  This module implements CORE
CF-5: validate the UTF-8 JSON text and its raw number tokens before returning an
object model that may be passed to :mod:`jcs`.

Two independent parsers are exposed for the conformance corpus:

``loads``
    CPython's JSON parser with token-preserving numeric hooks and a
    duplicate-detecting object-pairs hook.

``loads_reference``
    A small recursive-descent parser used only as an independent executable
    oracle.  It shares the profile predicates, but not CPython's JSON parser.

Both raise :class:`RawJsonProfileError` with ``stage`` equal to ``"parse"`` or
``"profile"``.  Canonicalization is deliberately a later, separate operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import json
import math
import re
from typing import Any, Callable


SAFE_MAGNITUDE = Decimal(2**53 - 1)
_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


class RawJsonProfileError(ValueError):
    """A deterministic raw-input refusal before canonicalization."""

    def __init__(self, stage: str, code: str, message: str):
        super().__init__(f"{stage}:{code}: {message}")
        self.stage = stage
        self.code = code


@dataclass(frozen=True)
class _RawNumber:
    token: str


def _error(stage: str, code: str, message: str) -> RawJsonProfileError:
    return RawJsonProfileError(stage, code, message)


def _decode(raw: bytes | str) -> str:
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise _error("parse", "INVALID-UTF8", "input is not well-formed UTF-8") from exc
    elif isinstance(raw, str):
        text = raw
    else:
        raise TypeError("raw JSON input must be bytes or str")
    if text.startswith("\ufeff"):
        raise _error("parse", "BOM", "a UTF-8 BOM is not part of a DACS JSON text")
    return text


def _constant(token: str) -> Any:
    raise _error("parse", "NON-JSON-CONSTANT", f"{token} is not a JSON number")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _error(
                "profile", "DUPLICATE-MEMBER", f"duplicate decoded member name {key!r}"
            )
        result[key] = value
    return result


def _contains_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _admit_number(token: str) -> int | float:
    try:
        exact = Decimal(token)
    except InvalidOperation as exc:  # defensive; the JSON grammar checked first
        raise _error("parse", "INVALID-NUMBER", f"invalid JSON number {token!r}") from exc
    if "." not in token and "e" not in token.lower():
        if exact.copy_abs() > SAFE_MAGNITUDE:
            raise _error(
                "profile",
                "NUMBER-OUTSIDE-DACS-MAGNITUDE",
                f"number {token!r} exceeds +/-{SAFE_MAGNITUDE}",
            )
        return int(token)
    value = float(token)
    if not math.isfinite(value):
        raise _error(
            "profile", "NUMBER-NOT-BINARY64", f"number {token!r} overflows binary64"
        )
    if exact != 0 and value == 0:
        raise _error(
            "profile", "NUMBER-NOT-BINARY64", f"number {token!r} underflows binary64"
        )
    if exact.copy_abs() > SAFE_MAGNITUDE:
        raise _error(
            "profile",
            "NUMBER-OUTSIDE-DACS-MAGNITUDE",
            f"number {token!r} exceeds +/-{SAFE_MAGNITUDE}",
        )
    return value


def _admit_tree(value: Any) -> Any:
    if isinstance(value, _RawNumber):
        return _admit_number(value.token)
    if isinstance(value, str):
        if _contains_surrogate(value):
            raise _error("profile", "INVALID-UNICODE", "lone UTF-16 surrogate in string")
        return value
    if isinstance(value, list):
        return [_admit_tree(item) for item in value]
    if isinstance(value, dict):
        admitted: dict[str, Any] = {}
        for key, item in value.items():
            if _contains_surrogate(key):
                raise _error(
                    "profile", "INVALID-UNICODE", "lone UTF-16 surrogate in member name"
                )
            admitted[key] = _admit_tree(item)
        return admitted
    return value


def loads(raw: bytes | str) -> Any:
    """Admit raw JSON through the CPython-backed CF-5 parser."""

    text = _decode(raw)
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_RawNumber,
            parse_float=_RawNumber,
            parse_constant=_constant,
        )
    except RawJsonProfileError:
        raise
    except json.JSONDecodeError as exc:
        code = "TRAILING-DATA" if exc.msg == "Extra data" else "INVALID-JSON"
        raise _error("parse", code, str(exc)) from exc
    except RecursionError as exc:
        raise _error("parse", "INVALID-JSON", str(exc)) from exc
    return _admit_tree(parsed)


class _ReferenceParser:
    """Independent recursive-descent JSON parser for cross-parser vectors."""

    def __init__(self, text: str):
        self.text = text
        self.pos = 0

    def parse(self) -> Any:
        self._space()
        value = self._value()
        self._space()
        if self.pos != len(self.text):
            raise _error("parse", "TRAILING-DATA", "data follows the first JSON value")
        return value

    def _space(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos] in " \t\r\n":
            self.pos += 1

    def _peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def _take(self, expected: str) -> None:
        if not self.text.startswith(expected, self.pos):
            raise _error("parse", "INVALID-JSON", f"expected {expected!r} at {self.pos}")
        self.pos += len(expected)

    def _value(self) -> Any:
        char = self._peek()
        if char == '"':
            return self._string()
        if char == "{":
            return self._object()
        if char == "[":
            return self._array()
        if char == "t":
            self._take("true")
            return True
        if char == "f":
            self._take("false")
            return False
        if char == "n":
            self._take("null")
            return None
        for extension in ("NaN", "Infinity", "-Infinity"):
            if self.text.startswith(extension, self.pos):
                raise _error(
                    "parse", "NON-JSON-CONSTANT", f"{extension} is not a JSON number"
                )
        match = _NUMBER_RE.match(self.text, self.pos)
        if match is not None:
            self.pos = match.end()
            return _RawNumber(match.group(0))
        raise _error("parse", "INVALID-JSON", f"expected a JSON value at {self.pos}")

    def _object(self) -> dict[str, Any]:
        self._take("{")
        self._space()
        pairs: list[tuple[str, Any]] = []
        if self._peek() == "}":
            self.pos += 1
            return {}
        while True:
            if self._peek() != '"':
                raise _error("parse", "INVALID-JSON", f"expected member name at {self.pos}")
            key = self._string()
            self._space()
            self._take(":")
            self._space()
            pairs.append((key, self._value()))
            self._space()
            char = self._peek()
            if char == "}":
                self.pos += 1
                return _pairs(pairs)
            if char != ",":
                raise _error("parse", "INVALID-JSON", f"expected ',' or '}}' at {self.pos}")
            self.pos += 1
            self._space()

    def _array(self) -> list[Any]:
        self._take("[")
        self._space()
        result: list[Any] = []
        if self._peek() == "]":
            self.pos += 1
            return result
        while True:
            result.append(self._value())
            self._space()
            char = self._peek()
            if char == "]":
                self.pos += 1
                return result
            if char != ",":
                raise _error("parse", "INVALID-JSON", f"expected ',' or ']' at {self.pos}")
            self.pos += 1
            self._space()

    def _string(self) -> str:
        self._take('"')
        out: list[str] = []
        while self.pos < len(self.text):
            char = self.text[self.pos]
            self.pos += 1
            if char == '"':
                return "".join(out)
            if ord(char) < 0x20:
                raise _error("parse", "INVALID-JSON", "unescaped control in string")
            if char != "\\":
                out.append(char)
                continue
            if self.pos >= len(self.text):
                raise _error("parse", "INVALID-JSON", "unterminated escape")
            escape = self.text[self.pos]
            self.pos += 1
            simple = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f",
                      "n": "\n", "r": "\r", "t": "\t"}
            if escape in simple:
                out.append(simple[escape])
                continue
            if escape != "u":
                raise _error("parse", "INVALID-JSON", f"invalid escape \\{escape}")
            unit = self._hex_unit()
            if 0xD800 <= unit <= 0xDBFF and self.text.startswith("\\u", self.pos):
                saved = self.pos
                self.pos += 2
                low = self._hex_unit()
                if 0xDC00 <= low <= 0xDFFF:
                    out.append(chr(0x10000 + ((unit - 0xD800) << 10) + low - 0xDC00))
                    continue
                self.pos = saved
            out.append(chr(unit))
        raise _error("parse", "INVALID-JSON", "unterminated string")

    def _hex_unit(self) -> int:
        token = self.text[self.pos:self.pos + 4]
        if len(token) != 4 or any(ch not in "0123456789abcdefABCDEF" for ch in token):
            raise _error("parse", "INVALID-JSON", "invalid Unicode escape")
        self.pos += 4
        return int(token, 16)


def loads_reference(raw: bytes | str) -> Any:
    """Admit raw JSON through the independent recursive-descent parser."""

    try:
        return _admit_tree(_ReferenceParser(_decode(raw)).parse())
    except RawJsonProfileError:
        raise
    except RecursionError as exc:
        raise _error("parse", "INVALID-JSON", "JSON nesting exceeds parser limits") from exc


def classify(parser: Callable[[bytes | str], Any], raw: bytes | str) -> tuple[str, str | None]:
    """Return the conformance verdict and optional refusal code for ``parser``."""

    try:
        parser(raw)
    except RawJsonProfileError as exc:
        return f"reject-{exc.stage}", exc.code
    return "accept", None
