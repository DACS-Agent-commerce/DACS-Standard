"""SDK JSON.stringify serialization for CORE-admitted JSON values.

Preserve insertion order and strings; only array-index keys move ahead of
other members, as in JavaScript. DACS JCS sorting/NFC normalization must not
change a Demos transaction's signed content.
"""
from jcs import _encode_number, _encode_string


def stringify(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _encode_number(value)
    if isinstance(value, str):
        value.encode("utf-8")  # CORE disallows lone surrogates.
        return _encode_string(value)
    if isinstance(value, list):
        return "[" + ",".join(stringify(item) for item in value) + "]"
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        # An index has at most ten digits, so int() never meets Python's digit limit.
        indexes = sorted((key for key in value if key.isascii() and key.isdecimal() and len(key) <= 10
                          and str(int(key)) == key and int(key) < 2**32 - 1), key=int)
        keys = indexes + [key for key in value if key not in indexes]
        return "{" + ",".join(stringify(key) + ":" + stringify(value[key]) for key in keys) + "}"
    raise ValueError("not a CORE-admitted JSON value")
