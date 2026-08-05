"""Executable vectors for DACS-1 canonical DNS-domain claim references (#275).

Pure standard library. Validates two operations against
``conformance/fixtures/identity/domain-claim-canonicalization.json``:

  * ``validate-host`` — strict validation of a ``domain:`` identifier as the
    canonical lowercase ASCII A-label form (DACS-1 §6.3.1 ``domain:<dns>`` row).
  * ``resolve-ref`` — the DACS-1 §6.3.2 ordered Layer-2 resolution of a claim
    ``ref`` into its effective claim reference: a legacy ``web2:domain:<host>``
    alias is lowercased (ingestion) then validated; a ``domain:<host>`` ref is
    validated as-authored; anything else resolves to nothing.

Each of the nine hostname grammar guards is an independently toggleable
predicate so the mutation-pin campaign can disable exactly one and confirm
exactly one fixture case reddens. Guard letters follow the Stage-2b design:
  C1  label / total length          C7  uppercase rejected at validation
  C3  no leading/trailing hyphen    C8  non-ASCII rejected
  C4  no trailing dot               C10 xn-- Punycode round-trip
  C6  forbidden ASCII characters    C11 IP literal rejected
                                    C12 all-numeric labels rejected (non-IP)
An always-on, non-campaign structural check owns the empty-host and
interior-empty-label rejections so it never disturbs a single-guard pin.
"""
from __future__ import annotations

import codecs
import ipaddress
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "conformance" / "fixtures" / "identity" / "domain-claim-canonicalization.json"
IDENTITY_EXAMPLE = ROOT / "conformance" / "vectors" / "examples" / "identity-bundle.json"

# Letters, digits, dot, hyphen — the only ASCII characters a canonical domain
# identifier may contain. Uppercase letters are intentionally allowed HERE so
# that the uppercase rejection is owned solely by guard C7 (not C6).
_ALLOWED_ASCII = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789.-"
)


def _labels(host: str) -> list[str]:
    return host.split(".")


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _xn_round_trips(label: str) -> bool:
    """True iff an ``xn--`` label decodes to a non-empty string and re-encodes
    byte-identically (canonical A-label byte-check only — NOT an assertion of
    IDNA2008/UTS-46 validity, which is a producer obligation)."""
    payload = label[4:]  # strip the "xn--" ACE prefix
    try:
        decoded = codecs.decode(payload.encode("ascii"), "punycode")
    except Exception:
        return False
    if decoded == "":
        return False
    try:
        re_encoded = codecs.encode(decoded, "punycode").decode("ascii")
    except Exception:
        return False
    return re_encoded == payload


# Each guard maps a name to a predicate that returns True when the host is BAD
# by that guard's single rule. Disabling one guard must let exactly its own
# reject vector through.
GUARDS = {
    "C8": lambda h: any(ord(c) >= 128 for c in h),
    "C7": lambda h: h != h.lower(),
    "C4": lambda h: h.endswith("."),
    "C6": lambda h: any(ord(c) < 128 and c not in _ALLOWED_ASCII for c in h),
    "C11": lambda h: _is_ip_literal(h),
    "C12": lambda h: bool(_labels(h))
    and all(lb.isascii() and lb.isdigit() for lb in _labels(h))
    and not _is_ip_literal(h),
    "C1": lambda h: len(h) > 253 or any(len(lb) > 63 for lb in _labels(h) if lb != ""),
    "C3": lambda h: any(
        (lb.startswith("-") or lb.endswith("-")) for lb in _labels(h) if lb != ""
    ),
    "C10": lambda h: any(
        lb.startswith("xn--") and not _xn_round_trips(lb) for lb in _labels(h)
    ),
}
GUARD_ORDER = ["C8", "C7", "C4", "C6", "C11", "C12", "C1", "C3", "C10"]


def _struct_bad(host: str) -> bool:
    """Always-on structural rejection (empty host, interior/leading empty
    label). A single *trailing* empty label is left to guard C4 (trailing dot)
    so C4's pin stays uniquely owned."""
    if host == "":
        return True
    labels = _labels(host)
    interior = labels[:-1] if labels and labels[-1] == "" else labels
    return any(lb == "" for lb in interior)


def validate_host(host: str, skip: frozenset = frozenset()) -> tuple[bool, object]:
    """Return (accepted, canonical). ``canonical`` is the host itself when
    accepted (it is already lowercase ASCII once every guard passes), else
    None. ``skip`` disables the named guards — used only by the pin campaign."""
    if _struct_bad(host):
        return (False, None)
    for name in GUARD_ORDER:
        if name in skip:
            continue
        if GUARDS[name](host):
            return (False, None)
    return (True, host)


def resolve_ref(ref: str, skip: frozenset = frozenset()) -> object:
    """DACS-1 §6.3.2 Layer-2 effective-reference resolution for the domain
    scheme. Returns the effective ``domain:<host>`` string or None."""
    if ref.startswith("web2:domain:"):
        # Legacy read alias: ingestion lowercases the host, then validates.
        host = ref[len("web2:domain:"):].lower()
        ok, canon = validate_host(host, skip)
        return f"domain:{canon}" if ok else None
    if ref.startswith("domain:"):
        # Canonical form: validated as authored (uppercase rejected).
        host = ref[len("domain:"):]
        ok, canon = validate_host(host, skip)
        return f"domain:{canon}" if ok else None
    return None


def _load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class DomainClaimCanonicalizationVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = _load_fixture()

    def test_kind_and_specrefs(self):
        self.assertEqual(self.data["kind"], "DomainClaimCanonicalizationCases")
        self.assertTrue(all(r.startswith("§") for r in self.data["specRefs"]))

    def test_all_cases(self):
        for case in self.data["cases"]:
            with self.subTest(case=case["id"]):
                if case["op"] == "validate-host":
                    accepted, canonical = validate_host(case["input"])
                    self.assertEqual(accepted, case["expected"]["accepted"])
                    self.assertEqual(canonical, case["expected"]["canonical"])
                elif case["op"] == "resolve-ref":
                    self.assertEqual(
                        resolve_ref(case["input"]), case["expected"]["effectiveRef"]
                    )
                else:  # pragma: no cover - guard against a malformed fixture
                    self.fail(f"unknown op: {case['op']}")

    def test_guard_pin_map_is_complete_and_each_pin_is_solely_owned(self):
        """Each of the nine campaign guards must, when disabled, flip exactly
        one validate-host reject case to accepted — proving the guard is real
        and the pin is uniquely owned (no gaps)."""
        pins = self.data["validateHostGuardPins"]
        self.assertEqual(set(pins), set(GUARD_ORDER))
        by_id = {c["id"]: c for c in self.data["cases"] if c["op"] == "validate-host"}
        for guard, pin_id in pins.items():
            with self.subTest(guard=guard):
                flipped = []
                for cid, case in by_id.items():
                    base_ok = case["expected"]["accepted"]
                    now_ok, _ = validate_host(case["input"], skip=frozenset({guard}))
                    if now_ok != base_ok:
                        flipped.append(cid)
                self.assertEqual(
                    flipped, [pin_id],
                    f"disabling {guard} must flip only {pin_id}, flipped {flipped}",
                )

    def test_identity_bundle_example_uses_canonical_domain_claim(self):
        """Guard the shipped example fixture: its domain claim must be the
        canonical form and resolve to itself; no web2:domain: alias survives."""
        bundle = json.loads(IDENTITY_EXAMPLE.read_text(encoding="utf-8"))
        claims = bundle["artifact"]["claims"]
        refs = [c["ref"] for c in claims]
        self.assertNotIn(
            "web2:domain:alice.example", refs,
            "the example still carries the legacy web2:domain: alias",
        )
        domain_refs = [r for r in refs if r.startswith("domain:")]
        self.assertEqual(domain_refs, ["domain:alice.example"])
        for ref in domain_refs:
            self.assertEqual(resolve_ref(ref), ref)
            ok, canon = validate_host(ref[len("domain:"):])
            self.assertTrue(ok)
            self.assertEqual("domain:" + canon, ref)


if __name__ == "__main__":
    unittest.main()
