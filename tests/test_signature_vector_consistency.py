"""Cross-corpus signature-value consistency.

Walks every committed JSON file under ``conformance/`` and checks every
signature object (a member carrying a string ``algorithm`` and a ``value``)
whose algorithm is registered in the spec's signature-envelope enum, using the
shared checker in ``signature_encoding``.  A conformance vector must expect the
same verdict from every conforming verifier, so the verdict a case expects
must be one that the value's defect gives for every verifier:

* ``wire``: a SIG-6 (CORE §B.7) wire defect is found by every verifier before
  any algorithm or key question, so the case must expect a rejection.
* ``format``: a canonical value whose decoded bytes are not the algorithm's
  pinned signature format is found only by a verifier that checks that
  format, which then rejects the signature, so the case must expect ``fail``
  or ``reject``.  ``error`` or ``indeterminate`` holds only for a verifier
  that stops at an unimplemented algorithm, and ``pass`` only for one that
  skips the check.  Which formats a corpus pins is ``pinned_formats``'s
  answer (``signature_encoding``).

Where a corpus's spec fixes the verdict of each stage, ``VERDICT_CONTRACTS``
holds exactly that verdict (DACS-3 §8.3.3: malformed encoding is ``error``);
any other corpus may expect any rejection of the stage (``STAGE_VERDICTS``).

Neither rule can see a well-encoded value whose signer claim names another
algorithm's key, so every case where a ``key:`` (Ed25519) claim signs under a
non-Ed25519 algorithm without expecting a rejection is pinned, with its
reason, in ``KEY_CLAIM_RELABELS``.

The rules read verdicts, never case wording.  A case is the outermost object
carrying a verdict member (``expected`` or ``verdict``) wherever it sits, so a
corpus may keep its cases under any member name or map.  An entry of a
top-level map that cases reference by name (``SHARED_REFERENCES``) is judged
under the verdict of every case referencing it; other content outside every
case declares no verdict and admits no defect.  Anything kept on purpose is
in ``ALLOWED_OFFENDERS``.  Run as a script with JSON paths to check scratch
files.
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
    FORMAT,
    WIRE,
    algorithm_unions,
    pinned_formats,
    registered_signature_algorithms,
    signature_value_defect,
)


CORPUS_ROOT = ROOT / "conformance"
VERDICT_MEMBERS = ("expected", "verdict")
CASE_ID_MEMBERS = ("name", "id", "caseId")
REJECTIONS = frozenset({"fail", "reject", "rejected"})
STAGE_VERDICTS = {WIRE: REJECTIONS | {"error"}, FORMAT: REJECTIONS}

# Corpora whose spec fixes the verdict a signature defect of each stage
# gives: only that verdict is accepted there.
VERDICT_CONTRACTS = {
    "conformance/vectors/security/canonical-channel-message-v0.6.json": (
        {WIRE: frozenset({"error"}), FORMAT: frozenset({"fail"})},
        "DACS-3 §8.3.3: malformed structure or encoding is error; a "
        "well-encoded signature that does not verify fails",
    ),
    "conformance/vectors/security/revocation-state-completeness-v0.8.json": (
        {WIRE: frozenset({"indeterminate"}), FORMAT: frozenset({"indeterminate"})},
        "DACS-1 RSC-7: any RSC failure returns indeterminate, so a listing, "
        "head or marker signature that any verifier rejects or cannot check "
        "gives indeterminate",
    ),
    "conformance/vectors/security/signature-value-encoding-v0.1.json": (
        {WIRE: frozenset({"reject"}), FORMAT: frozenset({"reject"})},
        "a binary accept/reject corpus for SIG-6 and the Ed25519 length",
    ),
}

# Top-level maps whose entries cases name instead of embedding: the member a
# case holds the entry's key in -> the map.
SHARED_REFERENCES = {"executionAuthorityRef": "executionAuthorities"}


@dataclass(frozen=True)
class AllowedOffender:
    file: str
    cases: frozenset
    paths: frozenset
    rules: frozenset
    algorithms: frozenset
    values: frozenset
    reason: str
    follow_up: str | None = None


# Offenders kept on purpose. Each entry names the file, the cases ("*" for
# every case in the file), the JSON paths ("*" matches one path step), the
# rules and algorithms it covers and the exact offending values; any other
# offender still fails, and an entry with a case, path or value that matches
# nothing fails as stale, so fixing a vector forces its entry out. An entry
# with a follow-up is debt; one without is a value that does not decide its
# case's verdict.
ALLOWED_OFFENDERS = (
    AllowedOffender(
        file="conformance/vectors/security/legacy-agreement-admission-v0.8.json",
        cases=frozenset({"*"}),
        paths=frozenset({
            "/vectors/*/input/reservation/signatures/*",
            "/vectors/*/input/transitionEvidence/signature",
        }),
        rules=frozenset({WIRE, FORMAT}),
        algorithms=frozenset({"ed25519"}),
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
        cases=frozenset({"<file>"}),
        paths=frozenset({"/paymentInput/rail/signature"}),
        rules=frozenset({WIRE}),
        algorithms=frozenset({"ed25519"}),
        values=frozenset({"fixture-rail-signature"}),
        reason="released v0.4 fixture; its embedded RailDefinition signature is a placeholder",
        follow_up="re-sign the embedded RailDefinition when the fixture is next regenerated for a release",
    ),
    AllowedOffender(
        file="conformance/vectors/examples/rating-record.json",
        cases=frozenset({"<file>"}),
        paths=frozenset({"/artifact/signature"}),
        rules=frozenset({WIRE}),
        algorithms=frozenset({"ed25519"}),
        values=frozenset({"sig:example-rating-signature"}),
        reason="released v0.4 shape example; its RatingRecord signature is a placeholder",
        follow_up="replace with a real Ed25519 signature when the example is next regenerated for a release",
    ),
    AllowedOffender(
        file="conformance/vectors/security/registry-bootstrap-v0.1.json",
        cases=frozenset({
            "invalid-key-pinned-root-sibling-is-discarded",
            "invalid-first-root-copy-cannot-suppress-valid-identity",
            "invalid-first-root-copy-cannot-suppress-unresolved-identity",
            "rotation-missing-predecessor-authorization",
            "invalid-first-successor-copy-cannot-suppress-valid-identity",
            "invalid-first-successor-copy-cannot-suppress-unresolved-identity",
            "invalid-successor-is-discarded",
            "invalid-same-key-root-cannot-suppress-valid-root",
        }),
        paths=frozenset({"/vectors/*/input/descriptors/*/authorizationSignature"}),
        rules=frozenset({FORMAT}),
        algorithms=frozenset({"ed25519"}),
        values=frozenset({"AA"}),
        reason=(
            "a deliberately invalid descriptor copy: registry key identifiers are "
            "Ed25519 keys (CORE §5), so every bootstrap verifier checks this "
            "one-byte value, rejects it and discards the copy; the verdict comes "
            "from the remaining descriptors"
        ),
    ),
)


# Cases where a `key:` claim, which names an Ed25519 key (CORE §5), signs
# under another registered algorithm and the case does not expect a
# rejection. Encoding cannot show these: a verifier that resolves the claim
# proves an algorithm-metadata mismatch, which DACS-3 §8.3.3 makes `fail` for
# a ChannelMessage even without key bytes. Every such case is listed with why
# its verdict holds or what follows up, so a new one fails until reviewed.
KEY_CLAIM_RELABELS = {
    ("conformance/vectors/security/reputation-participation-admission-v0.7.json",
     "spa-supported-channel-algorithm-unavailable"): (
        "the expected indeterminate holds only for a resolver without "
        "ecdsa-secp256k1; unchanged since before this check (80dea9a). Follow-up: "
        "expect fail, as canonical-algorithm-key-confusion does, or re-key the "
        "case under a claim whose authenticated key metadata is ecdsa-secp256k1"
    ),
    ("conformance/vectors/security/reputation-participation-admission-v0.7.json",
     "spa-rating-supported-algorithm-unavailable"): (
        "a RatingRecord labelled sr1-aggregate over the rater's own Ed25519 "
        "signature; indeterminate holds only for a resolver without sr1-aggregate. "
        "Follow-up: as for spa-supported-channel-algorithm-unavailable"
    ),
    ("conformance/vectors/security/reputation-participation-admission-v0.7.json",
     "spa-commit-proposal-algorithm-unavailable"): (
        "an sr1-aggregate AgreementSignature by a key: party; no spec text at "
        "this base makes that mismatch fail outside DACS-3 channel messages. "
        "Follow-up: re-check when an ordered signature verdict lands in CORE §B.7"
    ),
    ("conformance/vectors/security/reputation-participation-admission-v0.7.json",
     "spa-rfq-unrelated-malformed-and-unavailable-sources-ignored"): (
        "SPA selects the RFQ source by messageHash and this envelope is never "
        "selected, so its signature cannot decide the verdict"
    ),
}
KEY_CLAIM_MEMBERS = ("signer", "party")


@dataclass(frozen=True)
class Case:
    file: str
    case_id: str
    verdict: object
    node: object
    path: str
    formats: frozenset


@dataclass(frozen=True)
class Offender:
    file: str
    case_id: str
    path: str
    algorithm: str
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


def _is_case(node):
    return isinstance(node, dict) and any(m in node for m in VERDICT_MEMBERS)


def _verdict(node):
    for member in VERDICT_MEMBERS:
        value = node.get(member)
        if isinstance(value, dict):
            value = value.get("verdict")
        if isinstance(value, str):
            return value
    return None


def _without_cases(node):
    if _is_case(node):
        return None
    if isinstance(node, dict):
        return {key: _without_cases(child) for key, child in node.items()}
    if isinstance(node, list):
        return [_without_cases(child) for child in node]
    return node


def _references(node, member):
    """Yield every string held by ``member`` anywhere in ``node``."""
    if isinstance(node, dict):
        for key, child in node.items():
            if key == member and isinstance(child, str):
                yield child
            else:
                yield from _references(child, member)
    elif isinstance(node, list):
        for child in node:
            yield from _references(child, member)


def cases_of(path, document):
    """Yield every outermost verdict-bearing object, each referenced shared
    entry once per case referencing it, then the file remainder."""
    file = _relative(path)
    formats = pinned_formats(document)
    found = []

    def visit(node, where):
        if _is_case(node):
            case_id = next(
                (node[f] for f in CASE_ID_MEMBERS if isinstance(node.get(f), str)),
                where or "/",
            )
            found.append(Case(file, case_id, _verdict(node), node, where, formats))
        elif isinstance(node, dict):
            for key, child in node.items():
                visit(child, "%s/%s" % (where, key))
        elif isinstance(node, list):
            for index, child in enumerate(node):
                visit(child, "%s/%d" % (where, index))

    visit(document, "")
    yield from found
    remainder = _without_cases(document)
    if remainder is None:
        return
    for member, shared in SHARED_REFERENCES.items():
        entries = remainder.get(shared) if isinstance(remainder, dict) else None
        if not isinstance(entries, dict):
            continue
        referenced = set()
        for case in found:
            for name in sorted(set(_references(case.node, member))):
                if name in entries:
                    referenced.add(name)
                    yield Case(file, case.case_id, case.verdict, entries[name],
                               "/%s/%s" % (shared, name), formats)
        # An entry no case references stays in the remainder, which declares
        # no verdict.
        remainder[shared] = {k: v for k, v in entries.items() if k not in referenced}
    yield Case(file, "<file>", None, remainder, "", formats)


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


def accepted_verdicts(file, stage):
    contract = VERDICT_CONTRACTS.get(file)
    return contract[0][stage] if contract is not None else STAGE_VERDICTS[stage]


def case_offenders(case, registered):
    verdict = case.verdict.lower() if isinstance(case.verdict, str) else None
    for path, algorithm, value in signature_objects(case.node, case.path):
        if algorithm not in registered:
            continue
        defect = signature_value_defect(algorithm, value, case.formats)
        if defect is None:
            continue
        stage, why = defect
        accepted = accepted_verdicts(case.file, stage)
        if verdict in accepted:
            continue
        expects = "declares no verdict" if verdict is None else "expects %r" % case.verdict
        if case.file in VERDICT_CONTRACTS:
            reason = (
                "%s value has a %s defect (%s); its corpus's spec makes that %s, "
                "but the case %s"
                % (algorithm, stage, why, " or ".join(map(repr, sorted(accepted))), expects)
            )
        elif stage == WIRE:
            reason = (
                "%s value has a wire defect (%s), which every verifier rejects "
                "before any algorithm or key check, but the case %s"
                % (algorithm, why, expects)
            )
        else:
            reason = (
                "%s value has a format defect (%s): a verifier that checks %s "
                "rejects the signature and answers 'fail', but the case %s"
                % (algorithm, why, algorithm, expects)
            )
        yield Offender(case.file, case.case_id, path, algorithm, value, stage, reason)


def key_claim_relabels(case, registered):
    """Yield paths where a ``key:`` claim signs under a non-Ed25519 algorithm.

    Only cases that expect neither a rejection nor their corpus's contracted
    signature-failure verdict are yielded.
    """
    verdict = case.verdict.lower() if isinstance(case.verdict, str) else None
    if verdict in REJECTIONS | accepted_verdicts(case.file, FORMAT):
        return

    def visit(node, where):
        if isinstance(node, dict):
            algorithm = node.get("algorithm")
            if (
                isinstance(algorithm, str)
                and algorithm in registered and algorithm != "ed25519"
                and any(isinstance(node.get(m), str) and node[m].startswith("key:")
                        for m in KEY_CLAIM_MEMBERS)
            ):
                yield where
            for key, child in node.items():
                yield from visit(child, "%s/%s" % (where, key))
        elif isinstance(node, list):
            for index, child in enumerate(node):
                yield from visit(child, "%s/%d" % (where, index))

    yield from visit(case.node, case.path)


def find_offenders(paths, registered=None):
    registered = registered_signature_algorithms() if registered is None else registered
    offenders = []
    for path in paths:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        for case in cases_of(path, document):
            offenders.extend(case_offenders(case, registered))
    return offenders


def path_matches(pattern, path):
    """Match a JSON path against a pattern whose ``*`` is one path step."""
    steps, wanted = path.split("/"), pattern.split("/")
    return len(steps) == len(wanted) and all(
        w == "*" or w == s for w, s in zip(wanted, steps)
    )


def allowed_by(offender):
    return [
        entry for entry in ALLOWED_OFFENDERS
        if entry.file == offender.file
        and ("*" in entry.cases or offender.case_id in entry.cases)
        and any(path_matches(p, offender.path) for p in entry.paths)
        and offender.rule in entry.rules
        and offender.algorithm in entry.algorithms
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
ED25519_64 = _b64url(bytes(range(64)))
# The same 64 bytes with non-zero residual bits in the last character: not the
# minimal Base64URL spelling (the PR #426 `*-nonminimal-base64url` cases).
NONMINIMAL_ED25519 = ED25519_64[:-1] + "x"


# The channel corpus's key-fixture pin of the ECDSA format.
ECDSA_PIN = {"algorithm": "ecdsa-secp256k1", "signatureEncoding": "canonical-DER-low-S"}
CHANNEL_CORPUS = "conformance/vectors/security/canonical-channel-message-v0.6.json"


def _document(*vectors, pin=True):
    document = {"set": "constructed", "vectors": list(vectors)}
    if pin:
        document["authenticatedKeyFixtures"] = [dict(ECDSA_PIN)]
    return document


def _vector(name, expected, note, signature, **extra):
    return {"name": name, "expected": expected, "note": note,
            "input": {"marker": {"signature": signature}}, **extra}


def _ecdsa(value):
    return {"algorithm": "ecdsa-secp256k1", "signer": "x", "value": value}


def _ed25519(value):
    return {"algorithm": "ed25519", "signer": "x", "value": value}


class SignatureEncodingHelperTests(unittest.TestCase):
    def test_sig6_wire_rejections(self):
        good = _b64url(bytes(64))
        self.assertIsNone(signature_value_defect("ed25519", good))
        for spelling in (
            good + "==", "+" + good[1:], "/" + good[1:], good[:10] + " " + good[10:],
            "A", "AB", "", None, ["bad"], 7, NONMINIMAL_ED25519,
        ):
            with self.subTest(value=spelling):
                stage, why = signature_value_defect("ed25519", spelling)
                self.assertEqual(WIRE, stage)
                self.assertTrue(why.startswith("SIG-6: "))

    def test_ed25519_length(self):
        for size in (63, 65, 1):
            with self.subTest(size=size):
                stage, why = signature_value_defect("ed25519", _b64url(bytes(size)))
                self.assertEqual(FORMAT, stage)
                self.assertIn("%d bytes" % size, why)

    def test_ecdsa_der_low_s(self):
        from cryptography.hazmat.primitives.asymmetric import utils
        from signature_encoding import SECP256K1_ORDER, decode_b64url

        self.assertIsNone(signature_value_defect("ecdsa-secp256k1", CANONICAL_ECDSA))
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
                stage, why = signature_value_defect("ecdsa-secp256k1", value)
                self.assertEqual(FORMAT, stage)
                self.assertTrue(why.startswith("ecdsa-secp256k1 value: "))

    def test_sr1_aggregate_checks_wire_only(self):
        self.assertIsNone(signature_value_defect("sr1-aggregate", _b64url(bytes(96))))
        self.assertEqual(WIRE, signature_value_defect("sr1-aggregate", "AA==")[0])

    def test_ecdsa_format_is_checked_only_where_pinned(self):
        # No spec text picks one ECDSA format for every envelope, so a
        # fixed-width r||s value is a format defect only under a corpus pin;
        # the wire stage is checked everywhere.
        unpinned = pinned_formats({"vectors": [_ecdsa(FIXED_WIDTH_64)]})
        self.assertEqual(frozenset({"ed25519"}), unpinned)
        self.assertIsNone(signature_value_defect("ecdsa-secp256k1", FIXED_WIDTH_64, unpinned))
        self.assertEqual(
            WIRE, signature_value_defect("ecdsa-secp256k1", FIXED_WIDTH_64 + "=", unpinned)[0]
        )
        self.assertEqual(
            FORMAT, signature_value_defect("ed25519", _b64url(bytes(63)), unpinned)[0]
        )
        pinned = pinned_formats({"keys": [dict(ECDSA_PIN)]})
        self.assertEqual(frozenset({"ed25519", "ecdsa-secp256k1"}), pinned)
        self.assertEqual(
            FORMAT, signature_value_defect("ecdsa-secp256k1", FIXED_WIDTH_64, pinned)[0]
        )
        # The channel corpus is the committed corpus that pins it.
        channel = json.loads((ROOT / CHANNEL_CORPUS).read_text(encoding="utf-8"))
        self.assertIn("ecdsa-secp256k1", pinned_formats(channel))
        # A pin this checker does not know fails instead of checking nothing.
        for unknown in (
            {"algorithm": "ecdsa-secp256k1", "signatureEncoding": "p1363-fixed-width"},
            {"algorithm": "sr1-aggregate", "signatureEncoding": "canonical-DER-low-S"},
        ):
            with self.subTest(pin=unknown), self.assertRaises(ValueError):
                pinned_formats({"keys": [unknown]})

    def test_unknown_algorithm_has_no_checker(self):
        with self.assertRaises(ValueError):
            signature_value_defect("rsa-pss", _b64url(bytes(64)))

    def test_algorithm_member_parser(self):
        text = "\n".join((
            'algorithm: "ed25519" | "ecdsa-secp256k1"',
            '  algorithm?: "sr1-aggregate"',
            '  algorithm: "a"',
            '    | "b"',
            '    | "c";',
        ))
        self.assertEqual(
            [{"ed25519", "ecdsa-secp256k1"}, {"sr1-aggregate"}, {"a", "b", "c"}],
            [set(u) for u in algorithm_unions(text)],
        )
        # An algorithm member this parser cannot read fails instead of
        # registering nothing.
        for unreadable in ("algorithm: string", "algorithm?: SignatureAlgorithm",
                           'algorithm: "ed25519" | Other'):
            with self.subTest(line=unreadable), self.assertRaises(ValueError):
                list(algorithm_unions(unreadable))


class SignatureVectorConsistencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registered = registered_signature_algorithms()
        cls.files = corpus_files()
        cls.offenders = find_offenders(cls.files, cls.registered)

    def offenders_in(self, document, path="constructed.json"):
        return [
            o for case in cases_of(ROOT / path, document)
            for o in case_offenders(case, self.registered)
        ]

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

        def labelled(node, where=""):
            # Paths of every object labelled with a registered algorithm.
            if isinstance(node, dict):
                algorithm = node.get("algorithm")
                own = [where] if isinstance(algorithm, str) and algorithm in self.registered else []
                return own + [p for key, child in node.items()
                              for p in labelled(child, "%s/%s" % (where, key))]
            if isinstance(node, list):
                return [p for index, child in enumerate(node)
                        for p in labelled(child, "%s/%d" % (where, index))]
            return []

        checked = 0
        for path in self.files:
            text = path.read_text(encoding="utf-8")
            document = json.loads(text)
            # A shared entry is judged once per referencing case, so compare
            # the set of paths reached, not a count.
            in_cases = {
                p for case in cases_of(path, document)
                for p in labelled(case.node, case.path)
            }
            with self.subTest(file=_relative(path)):
                self.assertEqual(len(pattern.findall(text)), len(labelled(document)))
                self.assertEqual(set(labelled(document)), in_cases)
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
            with self.subTest(file=entry.file, cases=sorted(entry.cases)):
                self.assertTrue((ROOT / entry.file).is_file())
                self.assertTrue(entry.reason)
                self.assertTrue(entry.follow_up is None or entry.follow_up)
                matched = [o for o in self.offenders if entry in allowed_by(o)]
                self.assertEqual(
                    set(entry.values), {o.value for o in matched}, "stale allow-list values"
                )
                self.assertEqual(
                    set(entry.paths),
                    {p for p in entry.paths for o in matched if path_matches(p, o.path)},
                    "stale allow-list paths",
                )
                if "*" not in entry.cases:
                    self.assertEqual(
                        set(entry.cases), {o.case_id for o in matched},
                        "stale allow-list cases",
                    )

    def test_key_claim_relabels_are_all_reviewed(self):
        found = set()
        for path in self.files:
            document = json.loads(path.read_text(encoding="utf-8"))
            for case in cases_of(path, document):
                if any(True for _ in key_claim_relabels(case, self.registered)):
                    found.add((case.file, case.case_id))
        self.assertEqual(set(KEY_CLAIM_RELABELS), found)
        for key, reason in KEY_CLAIM_RELABELS.items():
            with self.subTest(case=key[1]):
                self.assertTrue(reason)

    def test_key_claim_relabel_detection(self):
        # The shape review F1 found: the buyer's key: claim under
        # ecdsa-secp256k1 with a well-encoded value still expects
        # `indeterminate`; the encoding rules cannot see it, this one does.
        key = "key:" + "70" * 32
        shapes = {
            "channel-relabel": ("indeterminate", {"algorithm": "ecdsa-secp256k1",
                                                  "signer": key, "value": CANONICAL_ECDSA}),
            "party-relabel": ("error", {"algorithm": "sr1-aggregate", "party": key,
                                        "value": ED25519_64}),
            "key-confusion-fail": ("fail", {"algorithm": "ecdsa-secp256k1",
                                            "signer": key, "value": CANONICAL_ECDSA}),
            "did-claim": ("indeterminate", {"algorithm": "ecdsa-secp256k1",
                                            "signer": "did:example:x", "value": CANONICAL_ECDSA}),
            "ed25519-key-claim": ("pass", {"algorithm": "ed25519", "signer": key,
                                           "value": ED25519_64}),
        }
        document = _document(*(
            _vector(name, expected, "", signature)
            for name, (expected, signature) in shapes.items()
        ))
        found = {
            case.case_id for case in cases_of(ROOT / "constructed.json", document)
            if any(True for _ in key_claim_relabels(case, self.registered))
        }
        self.assertEqual({"channel-relabel", "party-relabel"}, found)
        self.assertEqual([], self.offenders_in(document))

    def test_verdict_contracts_name_committed_corpora(self):
        for file, (stages, reason) in VERDICT_CONTRACTS.items():
            with self.subTest(file=file):
                self.assertTrue((ROOT / file).is_file())
                self.assertTrue(reason)
                self.assertEqual({WIRE, FORMAT}, set(stages))
                for verdicts in stages.values():
                    self.assertTrue(verdicts)
                    self.assertLessEqual(verdicts, STAGE_VERDICTS[WIRE] | {"indeterminate"})
        # Every committed corpus that holds a DACS-3 §8.3.3 channel-message
        # signature is under the DACS-3 contract (a version bump renames the
        # file and must carry the contract along).
        for path in self.files:
            document = json.loads(path.read_text(encoding="utf-8"))
            spec = document.get("spec", "") if isinstance(document, dict) else ""
            if "DACS-3 §8.3.3" in spec and any(
                algorithm in self.registered
                for case in cases_of(path, document)
                for _, algorithm, _ in signature_objects(case.node, case.path)
            ):
                with self.subTest(file=_relative(path)):
                    self.assertEqual(
                        {WIRE: {"error"}, FORMAT: {"fail"}},
                        VERDICT_CONTRACTS[_relative(path)][0],
                    )

    def test_contracted_corpora_accept_only_their_verdict(self):
        # DACS-3 §8.3.3 makes malformed encoding `error`: a channel case with
        # a padded value expecting `fail` (or a binary `reject`) is wrong even
        # though another corpus could accept it.
        rows = {
            "padded-error": ("error", _ed25519(ED25519_64 + "=="), None),
            "padded-fail": ("fail", _ed25519(ED25519_64 + "=="), WIRE),
            "padded-reject": ("reject", _ed25519(ED25519_64 + "=="), WIRE),
            "fixed-width-fail": ("fail", _ecdsa(FIXED_WIDTH_64), None),
            "fixed-width-error": ("error", _ecdsa(FIXED_WIDTH_64), FORMAT),
        }
        document = _document(*(
            _vector(name, expected, "", signature)
            for name, (expected, signature, _) in rows.items()
        ))
        expected = {name: rule for name, (_, _, rule) in rows.items() if rule}
        self.assertEqual(
            expected,
            {o.case_id: o.rule for o in self.offenders_in(document, CHANNEL_CORPUS)},
        )
        # The same cases outside a contracted corpus accept any rejection.
        self.assertEqual(
            {"fixed-width-error": FORMAT},
            {o.case_id: o.rule for o in self.offenders_in(document)},
        )
        # RSC-7: only `indeterminate`; the encoding corpus: only `reject`.
        rsc = "conformance/vectors/security/revocation-state-completeness-v0.8.json"
        encoding = "conformance/vectors/security/signature-value-encoding-v0.1.json"
        for path, good, bad in ((rsc, "indeterminate", "fail"), (encoding, "reject", "error")):
            with self.subTest(file=path):
                both = _document(_vector("good", good, "", _ed25519("")),
                                 _vector("bad", bad, "", _ed25519("")))
                self.assertEqual(["bad"], [o.case_id for o in self.offenders_in(both, path)])

    def test_unpinned_ecdsa_values_are_checked_at_the_wire_stage_only(self):
        # A Base64URL fixed-width r||s ECDSA value in a corpus that pins no
        # ECDSA format, expected `pass`: no rule in force makes it a defect.
        document = _document(
            _vector("fixed-width-pass", "pass", "", _ecdsa(FIXED_WIDTH_64)),
            _vector("padded-pass", "pass", "", _ecdsa(CANONICAL_ECDSA + "=")),
            pin=False,
        )
        self.assertEqual(
            [("padded-pass", WIRE)],
            [(o.case_id, o.rule) for o in self.offenders_in(document)],
        )

    def test_verdicts_by_defect_stage(self):
        # Each row: expected verdict, signature, offending rule or None.
        # Notes are deliberately worded to tempt a wording exemption; the
        # rules must ignore them.
        rows = {
            "wire-error": ("error", _ed25519(ED25519_64 + "=="), None),
            "wire-fail": ("fail", _ed25519("+" + ED25519_64[1:]), None),
            "wire-reject": ("reject", _ed25519(""), None),
            "wire-rejected": ("rejected", _ed25519(""), None),
            "wire-upper-reject": ("REJECT", _ed25519(""), None),
            "wire-indeterminate": ("indeterminate", _ed25519(ED25519_64 + "=="), WIRE),
            "wire-pass": ("pass", _ed25519("fixture-signature"), WIRE),
            "format-fail": ("fail", _ecdsa(FIXED_WIDTH_64), None),
            "format-reject": ("reject", _ed25519(_b64url(bytes(63))), None),
            "format-error": ("error", _ecdsa(FIXED_WIDTH_64), FORMAT),
            "format-indeterminate": ("indeterminate", _ecdsa(ED25519_64), FORMAT),
            "format-pass": ("pass", _ed25519(_b64url(bytes(1))), FORMAT),
            "canonical-der-indeterminate": ("indeterminate", _ecdsa(CANONICAL_ECDSA), None),
            "unregistered-algorithm-error": (
                "error", {"algorithm": "rsa-pss", "signer": "x", "value": FIXED_WIDTH_64}, None,
            ),
        }
        document = _document(*(
            _vector(name, expected, "a malformed, invalid, padded value", signature)
            for name, (expected, signature, _) in rows.items()
        ))
        document["fixture"] = {"signature": _ed25519("not a signature")}
        found = {o.case_id: o.rule for o in self.offenders_in(document)}
        expected = {name: rule for name, (_, _, rule) in rows.items() if rule}
        expected["<file>"] = WIRE
        self.assertEqual(expected, found)

    def test_pr426_nonminimal_wire_cases_expecting_error_are_consistent(self):
        # PR #426 at e34bb46 moves its non-minimal Base64URL cases to `error`
        # (a wire defect); worded outside any vocabulary, they must pass.
        note = ("the value is not the minimal Base64URL spelling, so it fails "
                "the SIG-6 wire stage")
        document = _document(
            _vector("fv-evidence-signature-nonminimal-base64url", "error", note,
                    _ed25519(NONMINIMAL_ED25519)),
            _vector("response-signature-nonminimal-base64url", "error", note,
                    _ed25519(NONMINIMAL_ED25519)),
        )
        self.assertEqual([], self.offenders_in(document))

    def test_format_defects_are_reported_whatever_the_wording(self):
        # A fixed-width 64-byte ecdsa-secp256k1 value is a format defect: a
        # verifier implementing the algorithm answers `fail`, so `error` or
        # `indeterminate` is never consistent, however the case is worded.
        notes = (
            "names an unsupported algorithm",
            "names an algorithm the verifier does not implement",
            "a registered algorithm the fixture resolver does not implement",
            "names ecdsa-secp256k1, which this verifier lacks",
            "a registered algorithm the verifier cannot use",
            "a malformed signature value is refused",
            "the signature encoding is invalid",
        )
        for expected in ("error", "indeterminate"):
            for note in notes:
                with self.subTest(expected=expected, note=note):
                    document = _document(_vector(
                        "fv-rail-signature-envelope-malformed", expected, note,
                        _ecdsa(FIXED_WIDTH_64),
                    ))
                    self.assertEqual(
                        [FORMAT], [o.rule for o in self.offenders_in(document)]
                    )

    def test_cases_are_found_under_any_member_name(self):
        # PR #434 keeps cases under `phaseInputs` and `amendmentTargets`.
        # Cases are found by their verdict member wherever they sit, including
        # a hash-keyed map of cases, so a rejected empty value is consistent
        # and a format defect is reported under its own case, not the file.
        # (Shared records that cases name instead of holding are
        # test_shared_entries_take_the_verdicts_of_the_cases_referencing_them.)
        document = {
            "set": "constructed",
            "authenticatedKeyFixtures": [dict(ECDSA_PIN)],
            "phaseInputs": [
                {"name": "ordinary-agreement-signature-value-empty",
                 "expected": "rejected", "signature": _ed25519("")},
            ],
            "amendmentTargets": [
                {"name": "ordinary-rail-signature-value-empty",
                 "expected": "rejected", "rail": {"signature": _ed25519("")}},
                {"name": "ordinary-target-algorithm-ecdsa-secp256k1",
                 "expected": "indeterminate", "signature": _ecdsa(FIXED_WIDTH_64)},
            ],
            "records": {
                "ab" * 32: {"name": "hash-keyed-record", "expected": "fail",
                            "evidence": {"signature": _ed25519("")}},
            },
            "verdictCases": [
                {"id": "verdict-member-case", "verdict": "fail",
                 "signature": _ed25519("")},
            ],
        }
        found = [(o.case_id, o.path, o.rule) for o in self.offenders_in(document)]
        self.assertEqual(
            [("ordinary-target-algorithm-ecdsa-secp256k1",
              "/amendmentTargets/1/signature", FORMAT)],
            found,
        )

    def test_shared_entries_take_the_verdicts_of_the_cases_referencing_them(self):
        # The PR #435 shape: an empty-signature record in a shared
        # `executionAuthorities` map with no verdict of its own, which a
        # vector expecting `fail` names by `executionAuthorityRef`.
        def authority(signature):
            return {"referenceValidationByCanonicalRef": {
                "ab" * 32: {"record": {"signature": signature}},
            }}

        def vector(name, expected, ref):
            return {"name": name, "expected": expected,
                    "input": {"executionAuthorityRef": ref}}

        document = {
            "set": "constructed",
            "executionAuthorities": {
                "atomic-shape-signature-value": authority(_ed25519("")),
                "standard-completed": authority(_ed25519(ED25519_64)),
            },
            "vectors": [
                vector("bundle-settlement-bijection-atomic-shape-signature-value",
                       "fail", "atomic-shape-signature-value"),
                vector("standard", "pass", "standard-completed"),
            ],
        }
        self.assertEqual([], self.offenders_in(document))
        record = ("/executionAuthorities/atomic-shape-signature-value/"
                  "referenceValidationByCanonicalRef/%s/record/signature" % ("ab" * 32))
        # A `pass` case naming the same record is inconsistent, and is
        # reported under that case.
        document["vectors"].append(
            vector("shares-the-broken-record", "pass", "atomic-shape-signature-value")
        )
        self.assertEqual(
            [("shares-the-broken-record", record, WIRE)],
            [(o.case_id, o.path, o.rule) for o in self.offenders_in(document)],
        )
        # A record no case names declares no verdict, so its defect is the
        # file's.
        document["vectors"] = document["vectors"][1:2]
        self.assertEqual(
            [("<file>", record, WIRE)],
            [(o.case_id, o.path, o.rule) for o in self.offenders_in(document)],
        )
        # A corpus that is a bare list has no shared maps.
        self.assertEqual(
            [("/1", "/1/signature", WIRE)],
            [(o.case_id, o.path, o.rule) for o in self.offenders_in([
                {"expected": "fail", "signature": _ed25519("")},
                {"expected": "pass", "signature": _ed25519("")},
            ])],
        )
        # Every declared map is one a committed corpus references (today the
        # bijection corpus's), so a stale declaration fails.
        used = set()
        for path in self.files:
            for case in cases_of(path, json.loads(path.read_text(encoding="utf-8"))):
                if case.case_id != "<file>" and case.path.count("/") == 2:
                    used.add(case.path.split("/")[1])
        self.assertLessEqual(set(SHARED_REFERENCES.values()), used)

    def test_allow_list_covers_only_its_rules_and_algorithms(self):
        laa = "conformance/vectors/security/legacy-agreement-admission-v0.8.json"
        placeholder = "fixture-signature-buyer"
        where = "/vectors/7/input/reservation/signatures/0"
        ed25519 = Offender(laa, "laa-new", where, "ed25519", placeholder, WIRE, "")
        relabelled = Offender(laa, "laa-new", where, "ecdsa-secp256k1", placeholder, WIRE, "")
        released = Offender(
            "conformance/vectors/examples/rating-record.json", "<file>", "/artifact/signature",
            "ed25519", "sig:example-rating-signature", FORMAT, "",
        )
        self.assertTrue(allowed_by(ed25519))
        self.assertEqual([], allowed_by(relabelled))
        self.assertEqual([], allowed_by(released))
        # The same case and value at another path is not covered.
        for elsewhere in ("/completely/unrelated/nested/path",
                          "/vectors/7/input/reservation/signatures/0/inner",
                          "/vectors/7/input/agreement/signature"):
            with self.subTest(path=elsewhere):
                self.assertEqual([], allowed_by(Offender(
                    laa, "laa-new", elsewhere, "ed25519", placeholder, WIRE, "",
                )))
        self.assertTrue(path_matches("/a/*/b", "/a/12/b"))
        self.assertFalse(path_matches("/a/*/b", "/a/1/2/b"))

    def test_report_names_file_case_and_reason(self):
        document = _document(_vector(
            "fv-rail-signature-envelope-malformed", "error",
            "names an unsupported algorithm", _ecdsa(FIXED_WIDTH_64),
        ))
        [offender] = self.offenders_in(document, "conformance/x.json")
        self.assertEqual(
            "conformance/x.json :: fv-rail-signature-envelope-malformed :: "
            "/vectors/0/input/marker/signature — format: ecdsa-secp256k1 value "
            "has a format defect (ecdsa-secp256k1 value: 64 raw bytes are not a "
            "DER signature): a verifier that checks ecdsa-secp256k1 rejects the "
            "signature and answers 'fail', but the case expects 'error'",
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
