import base64
import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import dacs5_reference as R  # noqa: E402
from scripts.jcs import canonicalize  # noqa: E402
from scripts.storage_soft_limit_reference import (  # noqa: E402
    SOFT_LIMIT_BYTES,
    attestation_bundle_hash,
    extended_bundle_pointer,
    fits_soft_limit,
    package_bundle,
    package_deliverable,
    payload_bytes,
)

SUBSTRATE_CAP_BYTES = 1_048_576
URL = "https://storage.example/full"
VECTORS = ROOT / "conformance" / "vectors" / "security"


def key(seed):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def committed_fab_case():
    """The signed FAB and fault-typed pointer of `fab-pointer-valid` (seller anchors)."""
    case = next(
        v for v in load(VECTORS / "fab-bundle-extended-pointer-v0.3.json")["vectors"]
        if v["name"] == "fab-pointer-valid"
    )
    return case["dereferenced"], case["pointer"], key("c3" * 32)


def padded(bundle, size):
    """``bundle`` plus an inert member, so its RFC 8785 UTF-8 form is exactly ``size`` bytes."""
    value = dict(bundle, padding="")
    value["padding"] = "x" * (size - len(payload_bytes(value)))
    return value


def verify_pointer_signature(pointer, signing_key, domain):
    unsigned = {k: v for k, v in pointer.items() if k != "signature"}
    digest = hashlib.sha256(canonicalize(unsigned).encode("utf-8")).hexdigest()
    value = pointer["signature"]["value"]
    signing_key.public_key().verify(
        base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)),
        (domain + digest).encode("utf-8"),
    )


class StorageSoftLimitTests(unittest.TestCase):
    def test_limit_is_128_kib_and_stricter_than_the_substrate_cap(self):
        self.assertEqual(131_072, SOFT_LIMIT_BYTES)
        self.assertLess(SOFT_LIMIT_BYTES, SUBSTRATE_CAP_BYTES)
        self.assertTrue(fits_soft_limit(b"\x00" * SOFT_LIMIT_BYTES))
        self.assertFalse(fits_soft_limit(b"\x00" * (SOFT_LIMIT_BYTES + 1)))

    def test_deliverable_boundary(self):
        for size, kind in (
            (SOFT_LIMIT_BYTES - 1, "direct"),
            (SOFT_LIMIT_BYTES, "direct"),
            (SOFT_LIMIT_BYTES + 1, "extended-pointer"),
        ):
            payload = b"\x00" * size
            with self.subTest(size=size):
                packaged = package_deliverable(payload, URL)
                if kind == "direct":
                    self.assertEqual({"kind": "direct", "payload": payload}, packaged)
                else:
                    self.assertEqual({
                        "kind": "extended-pointer",
                        "record": {
                            "externalUrl": URL,
                            "externalContentHash": hashlib.sha256(payload).hexdigest(),
                        },
                    }, packaged)

    def test_bundle_boundary_measures_canonical_utf8_bytes(self):
        bundle, _, seller = committed_fab_case()
        for size, kind in (
            (SOFT_LIMIT_BYTES, "direct"),
            (SOFT_LIMIT_BYTES + 1, "extended-pointer"),
        ):
            value = padded(bundle, size)
            data = canonicalize(value).encode("utf-8")
            self.assertEqual(size, len(data))
            with self.subTest(size=size):
                packaged = package_bundle(value, URL, seller)
                if kind == "direct":
                    self.assertEqual({"kind": "direct", "payload": data}, packaged)
                    continue
                record = packaged["record"]
                self.assertEqual(
                    {"faultBundleVersion", "pointerKind", "fullBundleUrl",
                     "fullBundleContentHash", "signature"},
                    set(record),
                )
                self.assertEqual(("1", "extended", URL), (
                    record["faultBundleVersion"], record["pointerKind"], record["fullBundleUrl"],
                ))
                # The consumer recomputes the §10.4.1 hash, which omits the
                # signing members, not the hash of the whole stored bytes.
                self.assertEqual(attestation_bundle_hash(value), record["fullBundleContentHash"])
                self.assertEqual(R.bundle_hash(value), record["fullBundleContentHash"])
                self.assertNotEqual(hashlib.sha256(data).hexdigest(), record["fullBundleContentHash"])
                self.assertEqual("did:demos:seller", record["signature"]["signer"])
                verify_pointer_signature(record, seller, R.FAULT_POINTER_DOMAIN)

    def test_deliverable_pointer_itself_must_fit_exact_canonical_byte_limit(self):
        payload = b"x" * (SOFT_LIMIT_BYTES + 1)
        record = package_deliverable(payload, URL)["record"]
        for extra, allowed in ((0, True), (1, False)):
            for character in ("x", "é"):
                count = (SOFT_LIMIT_BYTES - len(payload_bytes(record))) // len(character.encode())
                url = URL + character * count
                # Use ASCII to reach the exact byte boundary in either case.
                url += "x" * (SOFT_LIMIT_BYTES - len(payload_bytes(dict(record, externalUrl=url))) + extra)
                with self.subTest(extra=extra, character=character):
                    if allowed:
                        pointer = package_deliverable(payload, url)["record"]
                        self.assertEqual(SOFT_LIMIT_BYTES, len(payload_bytes(pointer)))
                    else:
                        with self.assertRaisesRegex(ValueError, "pointer exceeds"):
                            package_deliverable(payload, url)

    def test_signed_bundle_pointer_itself_must_fit_with_signature(self):
        bundle, _, seller = committed_fab_case()
        bundle = padded(bundle, SOFT_LIMIT_BYTES + 1)
        record = extended_bundle_pointer(bundle, URL, seller)
        url = URL + "x" * (SOFT_LIMIT_BYTES - len(payload_bytes(record)))
        pointer = package_bundle(bundle, url, seller)["record"]
        self.assertEqual(SOFT_LIMIT_BYTES, len(payload_bytes(pointer)))
        verify_pointer_signature(pointer, seller, R.FAULT_POINTER_DOMAIN)
        with self.assertRaisesRegex(ValueError, "pointer exceeds"):
            package_bundle(bundle, url + "x", seller)

    def test_pointer_reproduces_each_committed_typed_pointer(self):
        """The producer emits exactly the signed pointer each consumer corpus accepts."""
        fab, fab_pointer, seller = committed_fab_case()
        ebfab_case = next(
            case for case in load(
                ROOT / "conformance" / "fixtures"
                / "evidence-bound-fault-bundle-compatibility-v0.4.json"
            )["pointerCases"]
            if case["name"] == "ebfab-pointer-ebfab-pass"
        )
        finality = load(VECTORS / "settlement-finality-verification.json")["dacs5"]
        finality_bundle = next(
            case["bundle"] for case in finality["strongBundleCases"]
            if case["model"] == "block-depth"
        )
        for name, bundle, pointer, signing_key in (
            ("fault", fab, fab_pointer, seller),
            ("evidence-bound", ebfab_case["bundle"], ebfab_case["pointer"], key("a1" * 32)),
            ("finality-bound", finality_bundle, finality["pointer"], key("22" * 32)),
        ):
            with self.subTest(family=name):
                self.assertEqual(
                    pointer,
                    extended_bundle_pointer(bundle, pointer["fullBundleUrl"], signing_key),
                )
        self.assertTrue(R.resolve_fab_pointer(fab_pointer, fab)["ok"])

    def test_pointer_refuses_bundles_it_cannot_type_or_sign(self):
        bundle, _, seller = committed_fab_case()
        legacy = {k: v for k, v in bundle.items() if k not in {"faultBundleVersion", "faultedParty"}}
        legacy["bundleVersion"] = "1"
        two = dict(bundle, bundleVersion="1")
        untyped = {k: v for k, v in bundle.items() if k != "faultBundleVersion"}
        unanchored = dict(bundle, anchoredByRole="orchestrator")
        for value in (legacy, two, untyped, unanchored):
            with self.assertRaises(ValueError):
                package_bundle(padded(value, SOFT_LIMIT_BYTES + 1), URL, seller)
        ebfab = {k: v for k, v in bundle.items() if k != "faultBundleVersion"}
        ebfab["evidenceBoundFaultBundleVersion"] = "1"
        for url in ("http://storage.example/full", "https://user@storage.example/full", "/full"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                extended_bundle_pointer(ebfab, url, seller)
        self.assertIn(
            "evidenceBoundFaultBundleVersion",
            extended_bundle_pointer(ebfab, URL, seller),
        )

    def test_multibyte_text_is_measured_in_bytes_not_characters(self):
        bundle, _, seller = committed_fab_case()
        # Two-byte characters: under the limit in characters, past it in bytes.
        value = copy.deepcopy(bundle)
        value["padding"] = "é" * (SOFT_LIMIT_BYTES // 2)
        text = canonicalize(value)
        self.assertLess(len(text), SOFT_LIMIT_BYTES)
        self.assertGreater(len(text.encode("utf-8")), SOFT_LIMIT_BYTES)
        self.assertEqual("extended-pointer", package_bundle(value, URL, seller)["kind"])
        self.assertEqual(
            "extended-pointer",
            package_deliverable(("é" * (SOFT_LIMIT_BYTES // 2 + 1)).encode("utf-8"), URL)["kind"],
        )

    def test_json_payload_is_measured_after_canonicalization(self):
        # Whitespace a producer might write is not part of the measured bytes.
        bundle, _, seller = committed_fab_case()
        value = padded(bundle, SOFT_LIMIT_BYTES)
        self.assertEqual(SOFT_LIMIT_BYTES, len(payload_bytes(value)))
        self.assertLess(SOFT_LIMIT_BYTES, len(json.dumps(value, indent=2).encode("utf-8")))
        self.assertEqual("direct", package_bundle(value, URL, seller)["kind"])


if __name__ == "__main__":
    unittest.main()
