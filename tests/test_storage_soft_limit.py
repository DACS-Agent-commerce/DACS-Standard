import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.jcs import canonicalize  # noqa: E402
from scripts.storage_soft_limit_reference import (  # noqa: E402
    SOFT_LIMIT_BYTES,
    package_bundle,
    package_deliverable,
    payload_bytes,
)

SUBSTRATE_CAP_BYTES = 1_048_576
URL = "https://storage.example/full"


def bundle_of_size(size):
    """A JSON bundle whose RFC 8785 UTF-8 serialization is exactly ``size`` bytes."""
    empty = len(canonicalize({"bundleVersion": "1", "padding": ""}).encode("utf-8"))
    return {"bundleVersion": "1", "padding": "x" * (size - empty)}


class StorageSoftLimitTests(unittest.TestCase):
    def test_limit_is_128_kib_and_stricter_than_the_substrate_cap(self):
        self.assertEqual(131_072, SOFT_LIMIT_BYTES)
        self.assertLess(SOFT_LIMIT_BYTES, SUBSTRATE_CAP_BYTES)

    def test_deliverable_boundary(self):
        for size, kind in (
            (SOFT_LIMIT_BYTES - 1, "direct"),
            (SOFT_LIMIT_BYTES, "direct"),
            (SOFT_LIMIT_BYTES + 1, "extended-pointer"),
        ):
            payload = b"\x00" * size
            with self.subTest(size=size):
                packaged = package_deliverable(payload, URL)
                self.assertEqual(kind, packaged["kind"])
                if kind == "direct":
                    self.assertEqual(payload, packaged["payload"])
                else:
                    self.assertEqual(
                        {"externalUrl": URL, "externalContentHash": hashlib.sha256(payload).hexdigest()},
                        packaged["record"],
                    )

    def test_bundle_boundary_measures_canonical_utf8_bytes(self):
        for size, kind in (
            (SOFT_LIMIT_BYTES, "direct"),
            (SOFT_LIMIT_BYTES + 1, "extended-pointer"),
        ):
            bundle = bundle_of_size(size)
            data = canonicalize(bundle).encode("utf-8")
            self.assertEqual(size, len(data))
            with self.subTest(size=size):
                packaged = package_bundle(bundle, URL)
                self.assertEqual(kind, packaged["kind"])
                if kind == "direct":
                    self.assertEqual(data, packaged["payload"])
                else:
                    record = packaged["record"]
                    self.assertEqual(("1", "extended", URL), (
                        record["bundleVersion"], record["pointerKind"], record["fullBundleUrl"],
                    ))
                    # The consumer resolves the pointer by this hash.
                    self.assertEqual(hashlib.sha256(data).hexdigest(), record["fullBundleContentHash"])

    def test_multibyte_text_is_measured_in_bytes_not_characters(self):
        # 65,536 two-byte characters: half the limit in characters, past it in bytes.
        bundle = {"bundleVersion": "1", "padding": "é" * (SOFT_LIMIT_BYTES // 2)}
        text = canonicalize(bundle)
        self.assertLess(len(text), SOFT_LIMIT_BYTES)
        self.assertGreater(len(text.encode("utf-8")), SOFT_LIMIT_BYTES)
        self.assertEqual("extended-pointer", package_bundle(bundle, URL)["kind"])
        self.assertEqual(
            "extended-pointer",
            package_deliverable(("é" * (SOFT_LIMIT_BYTES // 2 + 1)).encode("utf-8"), URL)["kind"],
        )

    def test_json_payload_is_measured_after_canonicalization(self):
        # Whitespace a producer might write is not part of the measured bytes.
        bundle = bundle_of_size(SOFT_LIMIT_BYTES)
        self.assertEqual(SOFT_LIMIT_BYTES, len(payload_bytes(bundle)))
        self.assertEqual("direct", package_bundle(bundle, URL)["kind"])


if __name__ == "__main__":
    unittest.main()
