"""Guard-removal witnesses for conformance corpora.

A case that is claimed to catch a rule must change its verdict when the
reference loses that rule's guard; otherwise an earlier, generic gate decides
it and a verifier ignoring the rule still gets it right.  A corpus test module
declares its witnesses as::

    GUARD_WITNESSES = guard_witness.CorpusWitnesses(
        corpus="<set name>",
        path=VECTORS,
        evaluate=lambda case: ...,          # committed case -> verdict
        guards={"<guard id>": <zero-argument context manager factory>},
        cases={"<case name>": "<guard id>"},
        controls={"<guard id>": ("<case name>", ...)},
    )

and lists the module in ``tests/test_guard_witnesses.py``.  For each guard the
harness runs its cases and controls with the guard in place (each must give
its committed verdict), then with the guard removed: every witness case must
give a different verdict and every control must keep its own, so a removal
that breaks the reference wholesale does not count.

The documentation paths in ``test_guard_witnesses.CLAIM_DOCUMENTS`` are
scanned for the quantified witness phrasings in ``CLAIM_PHRASE``. A matching
paragraph must carry a marker naming the corpus and the witnessed cases::

    <!-- guard-witness-claim: corpus=<set> cases=<a>,<b> [controls=<c>] -->

Every listed case needs a witness entry, every ``controls`` case must be a
declared control of a guard the listed cases witness (so the harness shows
that guard's removal leaves it unchanged), and every backticked case name (or
``*`` glob) in that paragraph must appear in ``cases`` or ``controls``.  A
claiming paragraph that lists ``controls`` must declare them to be controls
(e.g. "they are controls") in a separate sentence that makes no witness claim.
Unrelated uses such as "access-control" or "version control" do not qualify.
The phrase matching is lexical, not a proof of arbitrary natural-language claims.
``unwitnessed=<d>`` covers a named case in a paragraph that makes no such
claim; in a claiming paragraph it contradicts the claim and is refused, so
narrow the claim or add the witness.
"""
from __future__ import annotations

import copy
import fnmatch
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, ContextManager, Mapping, Sequence


@dataclass(frozen=True)
class CorpusWitnesses:
    corpus: str
    path: Path
    evaluate: Callable[[dict], str]
    guards: Mapping[str, Callable[[], ContextManager]]
    cases: Mapping[str, str]
    controls: Mapping[str, Sequence[str]]

    def vectors(self):
        document = json.loads(Path(self.path).read_text(encoding="utf-8"))
        return {vector["name"]: vector for vector in document["vectors"]}


def witness_failures(witnesses):
    """Return every reason the declared witnesses do not hold (empty if they do)."""
    problems = []
    declared_set = json.loads(Path(witnesses.path).read_text(encoding="utf-8")).get("set")
    if not witnesses.corpus == Path(witnesses.path).stem == declared_set:
        problems.append("corpus %r does not name %s (set %r)"
                        % (witnesses.corpus, witnesses.path, declared_set))
    vectors = witnesses.vectors()
    for name in [*witnesses.cases, *(c for cs in witnesses.controls.values() for c in cs)]:
        if name not in vectors:
            problems.append("%s: case %r is not in the corpus" % (witnesses.corpus, name))
    for case, guard in witnesses.cases.items():
        if guard not in witnesses.guards:
            problems.append("%s: case %r names undeclared guard %r" % (witnesses.corpus, case, guard))
    if problems:
        return problems

    def verdict(name):
        return witnesses.evaluate(copy.deepcopy(vectors[name]))

    for guard, remove in witnesses.guards.items():
        cases = [case for case, owner in witnesses.cases.items() if owner == guard]
        controls = list(witnesses.controls.get(guard, ()))
        label = "%s / %s" % (witnesses.corpus, guard)
        if not cases:
            problems.append("%s: guard has no witness case" % label)
        if not controls:
            problems.append("%s: guard has no control case" % label)
        for name in cases + controls:
            actual = verdict(name)
            if actual != vectors[name]["expected"]:
                problems.append("%s: %r gives %r with the guard in place, committed %r"
                                % (label, name, actual, vectors[name]["expected"]))
        with remove():
            removed = {name: verdict(name) for name in cases + controls}
        for name in cases:
            if removed[name] == vectors[name]["expected"]:
                problems.append("%s: %r still gives %r without the guard, so it does not witness it"
                                % (label, name, removed[name]))
        for name in controls:
            if removed[name] != vectors[name]["expected"]:
                problems.append("%s: control %r changes to %r without the guard, so the removal is not narrow"
                                % (label, name, removed[name]))
    return problems


# A paragraph claims its cases catch their rule when it quantifies over them
# (each/every/all) and uses one of these phrasings.
CLAIM_QUANTIFIER = re.compile(r"\b(?:each|every|all)\b", re.IGNORECASE)
_GUARD = r"(?:own\s+|named\s+)?(?:[\w-]+\s+)?(?:rule|guard|check)"
CLAIM_PHRASE = re.compile(
    r"\bgets?\s+(?:it\s+|them\s+)?wrong\b"
    r"|\bverifier\s+(?:that\s+)?(?:ignor|skip|omit|drop|miss|lack)\w*\b[^.;]{0,60}?\b(?:rule|guard|check)"
    r"|\bmissing\s+only\s+(?:its|their)\b[^.;]{0,30}?\b(?:rule|guard|check)"
    r"|\b(?:skipping|removing|dropping|disabling|ignoring)\b[^.;]{0,60}?\b(?:turns|makes)\s+(?:it|them|each)\b"
    r"|\b(?:catch|catches|pin|pins|witness|witnesses|isolate|isolates)\s+"
    r"(?:its|their|one|exactly\s+one)\s+" + _GUARD + r"\b"
    r"|\bonly\s+by\s+(?:its|their)\s+" + _GUARD + r"\b"
    r"|\bby\s+exactly\s+one\s+(?:rule|guard|check)\b"
    r"|\b(?:pass(?:es)?|succeeds?|accept(?:s|ed)?)`?\s+(?:if|when)\b[^.;]{0,60}?"
    r"\b(?:rule|guard|check)\s+(?:is|are)\s+(?:removed|dropped|skipped|disabled|ignored)\b"
    r"|\bonly\s+when\s+(?:its|their)\s+" + _GUARD + r"\s+(?:is|are)\s+(?:removed|dropped|skipped|disabled)\b",
    re.IGNORECASE,
)
CONTROL_DECLARATION = re.compile(
    r"\b(?:are|is|as|stay|remain)\s+(?:the\s+|a\s+)?controls?\b", re.IGNORECASE,
)
MARKER = re.compile(r"<!--\s*guard-witness-claim:(.*?)-->", re.DOTALL)
LIST_ITEM = re.compile(r"^ {0,3}(?:[-*+]|\d+\.)\s")
BACKTICKED = re.compile(r"`([^`\s]+)`")


def markdown_blocks(text):
    """Yield ``(first line number, block text)`` per paragraph or list item."""
    block, start, fenced = [], 0, False
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            if block:
                yield start, "\n".join(block)
            block = []
            continue
        if fenced:
            continue
        if not line.strip() or LIST_ITEM.match(line):
            if block:
                yield start, "\n".join(block)
            block = []
            if not line.strip():
                continue
        if not block:
            start = number
        block.append(line)
    if block:
        yield start, "\n".join(block)


def is_witness_claim(block):
    prose = MARKER.sub(" ", block)
    flat = " ".join(prose.split())
    return bool(CLAIM_QUANTIFIER.search(flat) and CLAIM_PHRASE.search(flat))


def declares_controls(block):
    prose = " ".join(MARKER.sub(" ", block).split())
    return any(
        CONTROL_DECLARATION.search(sentence) and not CLAIM_PHRASE.search(sentence)
        for sentence in re.split(r"[.!?](?:\s+|$)", prose)
    )


def parse_marker(body):
    fields = {}
    for token in body.split():
        key, sep, value = token.partition("=")
        if not sep or key in fields:
            raise ValueError("malformed guard-witness-claim token %r" % token)
        fields[key] = value
    unknown = set(fields) - {"corpus", "cases", "controls", "unwitnessed"}
    if unknown or "corpus" not in fields or not fields.get("cases"):
        raise ValueError(
            "guard-witness-claim needs corpus= and cases=, and allows only "
            "controls= and unwitnessed="
        )
    return (
        fields["corpus"],
        [c for c in fields["cases"].split(",") if c],
        [c for c in fields.get("controls", "").split(",") if c],
        [c for c in fields.get("unwitnessed", "").split(",") if c],
    )


def claim_problems(documents, registry):
    """Check witness claims in ``{label: markdown text}`` against ``registry``.

    ``registry`` maps a corpus set name to its ``CorpusWitnesses``.
    """
    problems = []
    names_by_corpus = {}
    for label, text in documents.items():
        for line, block in markdown_blocks(text):
            where = "%s:%d" % (label, line)
            markers = MARKER.findall(block)
            claim = is_witness_claim(block)
            if claim and not markers:
                problems.append(
                    "%s: claims each case catches its rule but has no "
                    "guard-witness-claim marker" % where
                )
            for body in markers:
                try:
                    corpus, cases, controls, unwitnessed = parse_marker(body)
                except ValueError as exc:
                    problems.append("%s: %s" % (where, exc))
                    continue
                witnesses = registry.get(corpus)
                if witnesses is None:
                    problems.append("%s: no guard witnesses are registered for %s" % (where, corpus))
                    continue
                if corpus not in names_by_corpus:
                    names_by_corpus[corpus] = set(witnesses.vectors())
                names = names_by_corpus[corpus]
                witnessed = {witnesses.cases[c] for c in cases if c in witnesses.cases}
                for case in cases:
                    if case not in witnesses.cases:
                        problems.append("%s: %s has no guard witness entry" % (where, case))
                for case in controls:
                    guards = {g for g, cs in witnesses.controls.items() if case in cs}
                    if not guards:
                        problems.append("%s: control %s is not a declared control" % (where, case))
                    elif not guards & witnessed:
                        problems.append(
                            "%s: control %s is declared only for %s, not for a guard "
                            "the listed cases witness" % (where, case, ", ".join(sorted(guards)))
                        )
                if claim and controls and not declares_controls(block):
                    problems.append(
                        "%s: claims each case catches its rule but lists controls %s "
                        "without calling them controls; say which cases are controls, "
                        "not witnesses, or narrow the claim" % (where, ",".join(controls))
                    )
                for case in unwitnessed:
                    if case not in names:
                        problems.append("%s: unwitnessed %s is not a %s case" % (where, case, corpus))
                    elif claim:
                        problems.append(
                            "%s: claims each case catches its rule but leaves %s "
                            "unwitnessed; witness it, list it as a control, or "
                            "narrow the claim" % (where, case)
                        )
                covered = set(cases) | set(controls) | set(unwitnessed)
                for token in BACKTICKED.findall(MARKER.sub(" ", block)):
                    named = fnmatch.filter(names, token) if "*" in token else (
                        [token] if token in names else []
                    )
                    for case in named:
                        if case not in covered:
                            problems.append(
                                "%s: names %s, which the marker lists neither as "
                                "witnessed nor as a control" % (where, case)
                            )
    return problems
