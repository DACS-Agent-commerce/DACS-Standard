#!/usr/bin/env python3
"""Raw JSON admission for signed or content-hashed DACS documents.

JCS operates on an already parsed value and therefore cannot detect information
that a permissive parser discarded, notably duplicate member names or a number
rounded before the DACS safe-magnitude check.  This module implements CORE
CF-5: validate the UTF-8 JSON text and its raw number tokens before returning an
object model that may be passed to :mod:`jcs`.

Two independent bytes-only parsers are exposed for the conformance corpus:

``loads``
    CPython's JSON tokenizer for scalar lexemes, combined with an explicit
    container stack and token-preserving numeric hooks.

``loads_reference``
    A small independently implemented lexer and explicit-stack parser used
    only as an executable oracle.  It shares the profile predicates, but not
    CPython's JSON parser.

Both require the exact externally received bytes; decoded ``str`` input is
refused because it cannot prove that the original byte sequence passed strict
UTF-8 admission.  Both raise :class:`RawJsonProfileError` with ``stage`` equal
to ``"parse"`` or ``"profile"``.  Canonicalization is deliberately a later,
separate operation.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import json
import math
import re
from typing import Any, Callable


SAFE_MAGNITUDE = Decimal(2**53 - 1)
MAX_NESTING_DEPTH = 128
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


def _decode(raw: bytes) -> str:
    if not isinstance(raw, bytes):
        raise TypeError(
            "CF-5 external admission requires the exact received JSON bytes; "
            "decoded text is not admissible"
        )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _error("parse", "INVALID-UTF8", "input is not well-formed UTF-8") from exc
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


def _check_nesting(text: str) -> None:
    """Enforce CF-5's host-independent container-depth bound iteratively."""

    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_NESTING_DEPTH:
                raise _error(
                    "profile",
                    "JSON-NESTING-TOO-DEEP",
                    f"container nesting exceeds {MAX_NESTING_DEPTH}",
                )
        elif char in "]}" and depth:
            depth -= 1


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
    """Apply the profile predicates without consuming the Python call stack."""

    result: Any = None
    active_containers: set[int] = set()
    # action, input value, output parent, output key/index, container depth
    stack: list[tuple[str, Any, Any, Any, int]] = [
        ("visit", value, None, None, 0)
    ]

    while stack:
        action, item, parent, key, depth = stack.pop()
        if action == "leave":
            active_containers.remove(item)
            continue
        if action == "dict-item":
            if _contains_surrogate(key):
                raise _error(
                    "profile", "INVALID-UNICODE", "lone UTF-16 surrogate in member name"
                )
            stack.append(("visit", item, parent, key, depth))
            continue

        if isinstance(item, _RawNumber):
            admitted = _admit_number(item.token)
        elif isinstance(item, str):
            if _contains_surrogate(item):
                raise _error(
                    "profile", "INVALID-UNICODE", "lone UTF-16 surrogate in string"
                )
            admitted = item
        elif isinstance(item, (list, dict)):
            identity = id(item)
            if identity in active_containers:
                # A JSON parser cannot construct this, but keeping the private
                # traversal cycle-safe avoids an accidental unbounded loop.
                raise _error("profile", "INVALID-JSON", "container cycle in parsed tree")
            if depth >= MAX_NESTING_DEPTH:
                raise _error(
                    "profile",
                    "JSON-NESTING-TOO-DEEP",
                    f"container nesting exceeds {MAX_NESTING_DEPTH}",
                )
            active_containers.add(identity)
            stack.append(("leave", identity, None, None, depth))
            if isinstance(item, list):
                admitted = [None] * len(item)
                for index in range(len(item) - 1, -1, -1):
                    stack.append(
                        ("visit", item[index], admitted, index, depth + 1)
                    )
            else:
                admitted = {}
                for member_name, member_value in reversed(list(item.items())):
                    stack.append(
                        (
                            "dict-item",
                            member_value,
                            admitted,
                            member_name,
                            depth + 1,
                        )
                    )
        else:
            admitted = item

        if parent is None:
            result = admitted
        else:
            parent[key] = admitted

    return result


def _parse_with_stdlib_tokens(text: str) -> Any:
    """Parse containers iteratively while CPython decodes independent scalars."""

    decoder = json.JSONDecoder(
        parse_int=_RawNumber,
        parse_float=_RawNumber,
        parse_constant=_constant,
    )
    missing = object()
    root: Any = missing
    pos = 0
    # Frames deliberately hold pairs until an object closes.  This preserves
    # the existing parse-before-duplicate-error ordering for malformed objects.
    frames: list[dict[str, Any]] = []

    def add_value(item: Any) -> None:
        nonlocal root
        if not frames:
            root = item
            return
        frame = frames[-1]
        if frame["kind"] == "array":
            frame["items"].append(item)
        else:
            frame["pairs"].append((frame["key"], item))
            frame["key"] = None
        frame["state"] = "comma-or-end"

    while True:
        while pos < len(text) and text[pos] in " \t\r\n":
            pos += 1

        needs_value = False
        if not frames:
            if root is not missing:
                if pos != len(text):
                    raise _error(
                        "parse", "TRAILING-DATA", "data follows the first JSON value"
                    )
                return root
            needs_value = True
        else:
            frame = frames[-1]
            state = frame["state"]
            char = text[pos] if pos < len(text) else ""
            if frame["kind"] == "array":
                if state == "first-value-or-end" and char == "]":
                    pos += 1
                    frames.pop()
                    add_value(frame["items"])
                    continue
                if state in ("first-value-or-end", "value"):
                    needs_value = True
                elif char == "]":
                    pos += 1
                    frames.pop()
                    add_value(frame["items"])
                    continue
                elif char == ",":
                    pos += 1
                    frame["state"] = "value"
                    continue
                else:
                    raise _error(
                        "parse", "INVALID-JSON", f"expected ',' or ']' at {pos}"
                    )
            elif state == "first-key-or-end" and char == "}":
                pos += 1
                frames.pop()
                add_value(_pairs(frame["pairs"]))
                continue
            elif state in ("first-key-or-end", "key"):
                if char != '"':
                    raise _error(
                        "parse", "INVALID-JSON", f"expected member name at {pos}"
                    )
                try:
                    member_name, pos = decoder.raw_decode(text, pos)
                except json.JSONDecodeError as exc:
                    raise _error("parse", "INVALID-JSON", str(exc)) from exc
                frame["key"] = member_name
                frame["state"] = "colon"
                continue
            elif state == "colon":
                if char != ":":
                    raise _error("parse", "INVALID-JSON", f"expected ':' at {pos}")
                pos += 1
                frame["state"] = "value"
                continue
            elif state == "value":
                needs_value = True
            elif char == "}":
                pos += 1
                frames.pop()
                add_value(_pairs(frame["pairs"]))
                continue
            elif char == ",":
                pos += 1
                frame["state"] = "key"
                continue
            else:
                raise _error(
                    "parse", "INVALID-JSON", f"expected ',' or '}}' at {pos}"
                )

        if needs_value:
            if pos >= len(text):
                raise _error("parse", "INVALID-JSON", f"expected a JSON value at {pos}")
            char = text[pos]
            if char == "[":
                pos += 1
                frames.append(
                    {"kind": "array", "items": [], "state": "first-value-or-end"}
                )
                continue
            if char == "{":
                pos += 1
                frames.append(
                    {
                        "kind": "object",
                        "pairs": [],
                        "key": None,
                        "state": "first-key-or-end",
                    }
                )
                continue
            try:
                item, pos = decoder.raw_decode(text, pos)
            except json.JSONDecodeError as exc:
                raise _error("parse", "INVALID-JSON", str(exc)) from exc
            add_value(item)


def loads(raw: bytes) -> Any:
    """Admit exact received bytes through the CPython-backed CF-5 parser."""

    text = _decode(raw)
    _check_nesting(text)
    try:
        parsed = _parse_with_stdlib_tokens(text)
    except RawJsonProfileError:
        raise
    except json.JSONDecodeError as exc:
        code = "TRAILING-DATA" if exc.msg == "Extra data" else "INVALID-JSON"
        raise _error("parse", code, str(exc)) from exc
    except RecursionError as exc:
        raise _error("parse", "INVALID-JSON", str(exc)) from exc
    try:
        return _admit_tree(parsed)
    except RawJsonProfileError:
        raise
    except RecursionError as exc:  # defensive: CF-5's depth check must prevent this
        raise _error(
            "profile", "JSON-NESTING-TOO-DEEP", "tree admission exceeded host limits"
        ) from exc


class _ReferenceParser:
    """Independent explicit-stack JSON parser for cross-parser vectors."""

    def __init__(self, text: str):
        self.text = text
        self.pos = 0

    def parse(self) -> Any:
        missing = object()
        root: Any = missing
        frames: list[dict[str, Any]] = []

        def add_value(item: Any) -> None:
            nonlocal root
            if not frames:
                root = item
                return
            frame = frames[-1]
            if frame["kind"] == "array":
                frame["items"].append(item)
            else:
                frame["pairs"].append((frame["key"], item))
                frame["key"] = None
            frame["state"] = "comma-or-end"

        while True:
            self._space()
            needs_value = False
            if not frames:
                if root is not missing:
                    if self.pos != len(self.text):
                        raise _error(
                            "parse",
                            "TRAILING-DATA",
                            "data follows the first JSON value",
                        )
                    return root
                needs_value = True
            else:
                frame = frames[-1]
                state = frame["state"]
                char = self._peek()
                if frame["kind"] == "array":
                    if state == "first-value-or-end" and char == "]":
                        self.pos += 1
                        frames.pop()
                        add_value(frame["items"])
                        continue
                    if state in ("first-value-or-end", "value"):
                        needs_value = True
                    elif char == "]":
                        self.pos += 1
                        frames.pop()
                        add_value(frame["items"])
                        continue
                    elif char == ",":
                        self.pos += 1
                        frame["state"] = "value"
                        continue
                    else:
                        raise _error(
                            "parse",
                            "INVALID-JSON",
                            f"expected ',' or ']' at {self.pos}",
                        )
                elif state == "first-key-or-end" and char == "}":
                    self.pos += 1
                    frames.pop()
                    add_value(_pairs(frame["pairs"]))
                    continue
                elif state in ("first-key-or-end", "key"):
                    if char != '"':
                        raise _error(
                            "parse",
                            "INVALID-JSON",
                            f"expected member name at {self.pos}",
                        )
                    frame["key"] = self._string()
                    frame["state"] = "colon"
                    continue
                elif state == "colon":
                    self._take(":")
                    frame["state"] = "value"
                    continue
                elif state == "value":
                    needs_value = True
                elif char == "}":
                    self.pos += 1
                    frames.pop()
                    add_value(_pairs(frame["pairs"]))
                    continue
                elif char == ",":
                    self.pos += 1
                    frame["state"] = "key"
                    continue
                else:
                    raise _error(
                        "parse",
                        "INVALID-JSON",
                        f"expected ',' or '}}' at {self.pos}",
                    )

            if needs_value:
                char = self._peek()
                if char == "[":
                    self.pos += 1
                    frames.append(
                        {
                            "kind": "array",
                            "items": [],
                            "state": "first-value-or-end",
                        }
                    )
                    continue
                if char == "{":
                    self.pos += 1
                    frames.append(
                        {
                            "kind": "object",
                            "pairs": [],
                            "key": None,
                            "state": "first-key-or-end",
                        }
                    )
                    continue
                add_value(self._scalar_value())

    def _space(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos] in " \t\r\n":
            self.pos += 1

    def _peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def _take(self, expected: str) -> None:
        if not self.text.startswith(expected, self.pos):
            raise _error("parse", "INVALID-JSON", f"expected {expected!r} at {self.pos}")
        self.pos += len(expected)

    def _scalar_value(self) -> Any:
        char = self._peek()
        if char == '"':
            return self._string()
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


def loads_reference(raw: bytes) -> Any:
    """Admit exact received bytes through the independent reference parser."""

    try:
        text = _decode(raw)
        _check_nesting(text)
        return _admit_tree(_ReferenceParser(text).parse())
    except RawJsonProfileError:
        raise
    except RecursionError as exc:
        raise _error(
            "profile", "JSON-NESTING-TOO-DEEP", "processing exceeded host limits"
        ) from exc


def classify(parser: Callable[[bytes], Any], raw: bytes) -> tuple[str, str | None]:
    """Return the conformance verdict and optional refusal code for ``parser``."""

    try:
        parser(raw)
    except RawJsonProfileError as exc:
        return f"reject-{exc.stage}", exc.code
    return "accept", None
