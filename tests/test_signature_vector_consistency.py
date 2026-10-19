"""Cross-corpus CORE §B.7 signature consistency.

Walks every committed JSON file under ``conformance/`` and checks every
signature object (a member carrying a string ``algorithm`` and a ``value``)
whose algorithm is registered in the spec's signature-envelope enum, using the
shared checker in ``signature_encoding``.  A conformance vector must expect the
same verdict from every conforming verifier, so:

* ``capability``: a case expecting ``error``/``indeterminate`` because an
  algorithm is unsupported or unavailable must not carry a value that a
  verifier implementing that algorithm rejects (it would answer ``fail``);
* ``encoding``: a value that violates §B.7 under a registered algorithm must be
  expected to ``fail`` (``reject`` in the encoding corpus) unless the case says
  it is about malformed input.

Content outside a ``vectors``/``cases`` member (fixtures, examples, metadata)
declares no verdict, so any §B.7 violation there is reported.  Run as a script
with JSON paths to check scratch files.
"""
from __future__ import annotations

import base64
import json
import re
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(ROOT / "tests"))

from signature_encoding import (  # noqa: E402
    CHECKED_ALGORITHMS,
    registered_signature_algorithms,
    signature_value_violation,
)


CORPUS_ROOT = ROOT / "conformance"
CASE_LISTS = ("vectors", "cases")
CASE_TEXT_FIELDS = ("name", "id", "caseId", "note", "reason", "expectedReason", "summary")
CAPABILITY_VERDICTS = frozenset({"error", "indeterminate"})
FAIL_VERDICTS = frozenset({"fail", "reject"})
CAPABILITY_TEXT = re.compile(
    r"\b(?:unsupported|unavailable|unimplemented|unknown|not (?:implemented|supported))\b"
    r"[\w\s-]{0,40}?\balgorithm"
    r"|\balgorithm\b[\w\s-]{0,40}?"
    r"\b(?:unsupported|unavailable|unimplemented|not (?:implemented|supported))\b",
    re.IGNORECASE,
)
MALFORMED_TEXT = re.compile(
    r"(?<!not )(?<!not-)\b(?:malformed|invalid|inauthentic|unauthenticated|non-?canonical"
    r"|padded|padding|standard-base64|whitespace|impossible|residual|wrong[- ]length"
    r"|list-valued|forged|tamper(?:ed)?|corrupt(?:ed)?)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class AllowedOffender:
    file: str
    case: str
    values: frozenset
    reason: str
    follow_up: str


# Offenders kept on purpose. Each entry names the file, the case ("*" for
# every case in the file) and the exact offending values; any other offender
# still fails, and an entry that matches nothing fails as stale, so fixing a
# vector forces its entry out.
ALLOWED_OFFENDERS = (
    AllowedOffender(
        file="conformance/vectors/security/legacy-agreement-admission-v0.8.json",
        case="*",
        values=frozenset({
            "fixture-signature-buyer",
            "fixture-signature-seller",
            "fixture-signature-orchestrator",
            "fixture-transition-evidence-signature",
        }),
        reason=(
            "the LAA corpus models signature verification with an explicit "
            "signatureValid flag and carries opaque labels as values; replacing "
            "them changes the corpus input model, not just its values"
        ),
        follow_up=(
            "carry real Ed25519 signatures over the LAA domains, or drop the "
            "SIG-6 value member from the modelled signature objects"
        ),
    ),
    AllowedOffender(
        file="conformance/fixtures/settlement-evidence-payment-success.json",
        case="<file>",
        values=frozenset({"fixture-rail-signature"}),
        reason="released v0.4 fixture; its embedded RailDefinition signature is a placeholder",
        follow_up="re-sign the embedded RailDefinition when the fixture is next regenerated for a release",
    ),
    AllowedOffender(
        file="conformance/vectors/examples/rating-record.json",
        case="<file>",
        values=frozenset({"sig:example-rating-signature"}),
        reason="released v0.4 shape example; its RatingRecord signature is a placeholder",
        follow_up="replace with a real Ed25519 signature when the example is next regenerated for a release",
    ),
)


@dataclass(frozen=True)
class Case:
    file: str
    case_id: str
    verdict: object
    text: str
    node: object
    path: str


@dataclass(frozen=True)
class Offender:
    file: str
    case_id: str
    path: str
    value: object
    rule: str
    reason: str

    def __str__(self):
        return "%s :: %s :: %s — %s: %s" % (
            self.file, self.case_id, self.path or "/", self.rule, self.reason,
        )


def corpus_files(root=CORPUS_ROOT):
    return sorted(root.rglob("*.json"))


def _relative(path):
    path = Path(path).resolve()
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _case_text(item):
    return " ".join(
        item[field] for field in CASE_TEXT_FIELDS if isinstance(item.get(field), str)
    )


def cases_of(path, document):
    """Split a document into verdict-bearing cases plus one file-level remainder."""
    file = _relative(path)
    if isinstance(document, dict):
        for key in CASE_LISTS:
            items = document.get(key)
            if isinstance(items, list) and items and all(isinstance(i, dict) for i in items):
                for index, item in enumerate(items):
                    case_id = next(
                        (item[f] for f in ("name", "id", "caseId") if isinstance(item.get(f), str)),
                        "%s[%d]" % (key, index),
                    )
                    yield Case(file, case_id, item.get("expected"), _case_text(item),
                               item, "/%s/%d" % (key, index))
                rest = {k: v for k, v in document.items() if k != key}
                yield Case(file, "<file>", None, "", rest, "")
                return
    yield Case(file, "<file>", None, "", document, "")


def signature_objects(node, path=""):
    """Yield ``(path, algorithm, value)`` for every object with both members."""
    if isinstance(node, dict):
        algorithm = node.get("algorithm")
        if isinstance(algorithm, str) and "value" in node:
            yield path, algorithm, node["value"]
        for key, child in node.items():
            yield from signature_objects(child, "%s/%s" % (path, key))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from signature_objects(child, "%s/%d" % (path, index))


def case_offenders(case, registered):
    verdict = case.verdict if isinstance(case.verdict, str) else None
    capability = verdict in CAPABILITY_VERDICTS and CAPABILITY_TEXT.search(case.text)
    expects_fail = verdict in FAIL_VERDICTS
    malformed = MALFORMED_TEXT.search(case.text)
    for path, algorithm, value in signature_objects(case.node, case.path):
        if algorithm not in registered:
            continue
        violation = signature_value_violation(algorithm, value)
        if violation is None:
            continue
        if capability:
            yield Offender(
                case.file, case.case_id, path, value, "capability",
                "expects %r for an unsupported/unavailable algorithm, but a "
                "verifier implementing %s rejects this value (%s) and answers "
                "'fail'" % (case.verdict, algorithm, violation),
            )
        elif not expects_fail and not malformed:
            yield Offender(
                case.file, case.case_id, path, value, "encoding",
                "%s value violates CORE §B.7 (%s) but the case expects %r and "
                "does not say it is about malformed input"
                % (algorithm, violation, case.verdict),
            )


def find_offenders(paths, registered=None):
    registered = registered_signature_algorithms() if registered is None else registered
    offenders = []
    for path in paths:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        for case in cases_of(path, document):
            offenders.extend(case_offenders(case, registered))
    return offenders


def allowed_by(offender):
    return [
        entry for entry in ALLOWED_OFFENDERS
        if entry.file == offender.file
        and entry.case in ("*", offender.case_id)
        and isinstance(offender.value, str)
        and offender.value in entry.values
    ]


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# A genuine canonical-DER low-S secp256k1 value from the channel corpus
# (`canonical-ecdsa-valid`), and 64 bytes in fixed-width r||s shape.
CANONICAL_ECDSA = (
    "MEUCIQC9dj_q9CNETiGezQOQ0Cal2NBx4NA-abbTlBe-1BX9mQIgBdBdCwenhrY_Ail5KwAcVUt09pQdBaXhTLEVvht-G5k"
)
FIXED_WIDTH_64 = _b64url(bytes(range(1, 65)))


def _document(*vectors):
    return {"set": "constructed", "vectors": list(vectors)}


def _vector(name, expected, note, signature, **extra):
    return {"name": name, "expected": expected, "note": note,
            "input": {"marker": {"signature": signature}}, **extra}


class SignatureEncodingHelperTests(unittest.TestCase):
    def test_sig6_wire_rejections(self):
        good = _b64url(bytes(64))
        self.assertIsNone(signature_value_violation("ed25519", good))
        for spelling in (
            good + "==", "+" + good[1:], "/" + good[1:], good[:10] + " " + good[10:],
            "A", "AB", "", None, ["bad"], 7,
        ):
            with self.subTest(value=spelling):
                self.assertTrue(
                    signature_value_violation("ed25519", spelling).startswith("SIG-6: ")
                )

    def test_ed25519_length(self):
        self.assertIn("63 bytes", signature_value_violation("ed25519", _b64url(bytes(63))))
        self.assertIn("65 bytes", signature_value_violation("ed25519", _b64url(bytes(65))))

    def test_ecdsa_der_low_s(self):
        from cryptography.hazmat.primitives.asymmetric import utils
        from signature_encoding import SECP256K1_ORDER, decode_b64url

        self.assertIsNone(signature_value_violation("ecdsa-secp256k1", CANONICAL_ECDSA))
        r, s = utils.decode_dss_signature(decode_b64url(CANONICAL_ECDSA))
        rejected = {
            "fixed-width": FIXED_WIDTH_64,
            "high-s": _b64url(utils.encode_dss_signature(r, SECP256K1_ORDER - s)),
            "zero-r": _b64url(utils.encode_dss_signature(0, s)),
            "r-at-order": _b64url(utils.encode_dss_signature(SECP256K1_ORDER, s)),
            "trailing-byte": _b64url(decode_b64url(CANONICAL_ECDSA) + b"\x00"),
            "non-minimal-length": _b64url(
                b"\x30\x81" + decode_b64url(CANONICAL_ECDSA)[1:]
            ),
        }
        for name, value in rejected.items():
            with self.subTest(case=name):
                self.assertTrue(
                    signature_value_violation("ecdsa-secp256k1", value).startswith(
                        "ecdsa-secp256k1 value: "
                    )
                )

    def test_sr1_aggregate_checks_wire_only(self):
        self.assertIsNone(signature_value_violation("sr1-aggregate", _b64url(bytes(96))))
        self.assertTrue(
            signature_value_violation("sr1-aggregate", "AA==").startswith("SIG-6: ")
        )

    def test_unknown_algorithm_has_no_checker(self):
        with self.assertRaises(ValueError):
            signature_value_violation("rsa-pss", _b64url(bytes(64)))


class SignatureVectorConsistencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registered = registered_signature_algorithms()
        cls.files = corpus_files()
        cls.offenders = find_offenders(cls.files, cls.registered)

    def test_registered_algorithms_come_from_the_spec_and_all_have_checkers(self):
        # A newly registered algorithm fails here until it has a checker.
        self.assertEqual(
            {"ed25519", "ecdsa-secp256k1", "sr1-aggregate"}, set(self.registered)
        )
        self.assertLessEqual(self.registered, CHECKED_ALGORITHMS)

    def test_walk_reaches_every_registered_signature_object(self):
        # Cross-check the structural walk against a plain text scan of every
        # committed corpus file, so no nesting shape escapes the check.
        pattern = re.compile(
            r'"algorithm"\s*:\s*"(%s)"' % "|".join(map(re.escape, sorted(self.registered)))
        )

        def labelled(node):
            if isinstance(node, dict):
                algorithm = node.get("algorithm")
                count = int(isinstance(algorithm, str) and algorithm in self.registered)
                return count + sum(labelled(child) for child in node.values())
            if isinstance(node, list):
                return sum(labelled(child) for child in node)
            return 0

        checked = 0
        for path in self.files:
            text = path.read_text(encoding="utf-8")
            document = json.loads(text)
            with self.subTest(file=_relative(path)):
                self.assertEqual(len(pattern.findall(text)), labelled(document))
            checked += sum(
                1 for case in cases_of(path, document)
                for _, algorithm, _ in signature_objects(case.node, case.path)
                if algorithm in self.registered
            )
        security = {p for p in self.files if p.parent.name == "security"}
        self.assertGreater(len(security), 60)
        self.assertGreater(checked, 6000)

    def test_committed_corpora_are_consistent(self):
        unexpected = [o for o in self.offenders if not allowed_by(o)]
        if unexpected:
            self.fail(
                "%d signature vector(s) carry a verdict that depends on the verifier:\n%s"
                % (len(unexpected), "\n".join(map(str, unexpected)))
            )

    def test_allow_list_is_exact_and_not_stale(self):
        for entry in ALLOWED_OFFENDERS:
            with self.subTest(file=entry.file, case=entry.case):
                self.assertTrue((ROOT / entry.file).is_file())
                self.assertTrue(entry.reason and entry.follow_up)
                matched = {
                    o.value for o in self.offenders if entry in allowed_by(o)
                }
                self.assertEqual(set(entry.values), matched, "stale allow-list values")

    def test_rules_on_constructed_cases(self):
        ed25519_64 = _b64url(bytes(range(64)))
        cases = {
            # The PR #426 rail case: a registered algorithm labelled onto a
            # fixed-width value, expected `error` "unsupported algorithm".
            # Its name says malformed, which must not exempt it.
            "fv-rail-signature-envelope-malformed": (
                "error", "names an unsupported algorithm",
                {"algorithm": "ecdsa-secp256k1", "signer": "x", "value": FIXED_WIDTH_64},
                "capability",
            ),
            "spa-style-algorithm-unavailable": (
                "indeterminate", "a registered algorithm unavailable to the resolver",
                {"algorithm": "ecdsa-secp256k1", "signer": "x", "value": ed25519_64},
                "capability",
            ),
            "capability-with-canonical-der": (
                "indeterminate", "a registered algorithm unavailable to the resolver",
                {"algorithm": "ecdsa-secp256k1", "signer": "x", "value": CANONICAL_ECDSA},
                None,
            ),
            "unregistered-algorithm-error": (
                "error", "names an unsupported algorithm",
                {"algorithm": "rsa-pss", "signer": "x", "value": FIXED_WIDTH_64},
                None,
            ),
            "placeholder-in-a-pass-case": (
                "pass", "unrelated rule",
                {"algorithm": "ed25519", "signer": "x", "value": "fixture-signature"},
                "encoding",
            ),
            "placeholder-not-invalid-wording": (
                "indeterminate", "the source is not invalid",
                {"algorithm": "ed25519", "signer": "x", "value": "fixture-signature"},
                "encoding",
            ),
            "bad-value-expected-fail": (
                "fail", "unrelated rule",
                {"algorithm": "ecdsa-secp256k1", "signer": "x", "value": FIXED_WIDTH_64},
                None,
            ),
            "malformed-signature-error": (
                "error", "a malformed signature value is refused",
                {"algorithm": "ed25519", "signer": "x", "value": ed25519_64 + "=="},
                None,
            ),
        }
        document = _document(*(
            _vector(name, expected, note, signature)
            for name, (expected, note, signature, _) in cases.items()
        ))
        document["fixture"] = {"signature": {
            "algorithm": "ed25519", "signer": "x", "value": "fixture-only",
        }}
        found = {
            o.case_id: o.rule
            for case in cases_of(ROOT / "constructed.json", document)
            for o in case_offenders(case, self.registered)
        }
        expected = {name: rule for name, (_, _, _, rule) in cases.items() if rule}
        expected["<file>"] = "encoding"
        self.assertEqual(expected, found)

    def test_report_names_file_case_and_reason(self):
        document = _document(_vector(
            "fv-rail-signature-envelope-malformed", "error",
            "names an unsupported algorithm",
            {"algorithm": "ecdsa-secp256k1", "signer": "x", "value": FIXED_WIDTH_64},
        ))
        [offender] = [
            o for case in cases_of(ROOT / "conformance/x.json", document)
            for o in case_offenders(case, self.registered)
        ]
        self.assertEqual(
            "conformance/x.json :: fv-rail-signature-envelope-malformed :: "
            "/vectors/0/input/marker/signature — capability: expects 'error' for "
            "an unsupported/unavailable algorithm, but a verifier implementing "
            "ecdsa-secp256k1 rejects this value (ecdsa-secp256k1 value: 64 raw "
            "bytes are not a DER signature) and answers 'fail'",
            str(offender),
        )


def main(argv):
    offenders = find_offenders(argv)
    for offender in offenders:
        print(offender)
    return 1 if offenders else 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        sys.exit(main(sys.argv[1:]))
    unittest.main()
