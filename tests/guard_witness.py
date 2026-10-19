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

A CHANGELOG or corpus README paragraph that says each/every case catches its
rule must carry a marker naming the corpus and the witnessed cases::

    <!-- guard-witness-claim: corpus=<set> cases=<a>,<b> [unwitnessed=<c>] -->

Every listed case needs a witness entry, and every backticked case name (or
``*`` glob) in that paragraph must appear in ``cases`` or ``unwitnessed``.
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
    if Path(witnesses.path).stem != witnesses.corpus:
        problems.append("corpus %r does not name %s" % (witnesses.corpus, witnesses.path))
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
# (each/every) and uses one of these phrasings.
CLAIM_QUANTIFIER = re.compile(r"\b(?:each|every)\b", re.IGNORECASE)
CLAIM_PHRASE = re.compile(
    r"\bgets?\s+(?:it\s+|them\s+)?wrong\b"
    r"|\bverifier\s+(?:that\s+)?(?:ignor|skipp|omitt|dropp|miss|lack)\w*\b[^.;]{0,60}?\b(?:rule|guard|check)"
    r"|\bmissing\s+only\s+(?:its|their)\b[^.;]{0,30}?\b(?:rule|guard|check)"
    r"|\b(?:skipping|removing|dropping|disabling|ignoring)\b[^.;]{0,60}?\bturns\s+(?:it|them|each)\b"
    r"|\b(?:catch|catches|pin|pins|witness|witnesses|isolate|isolates)\s+(?:its|their)\s+(?:own\s+|named\s+)?(?:[\w-]+\s+)?(?:rule|guard)\b"
    r"|\bonly\s+by\s+(?:its|their)\s+(?:own\s+|named\s+)?(?:[\w-]+\s+)?(?:rule|guard)\b",
    re.IGNORECASE,
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


def parse_marker(body):
    fields = {}
    for token in body.split():
        key, sep, value = token.partition("=")
        if not sep or key in fields:
            raise ValueError("malformed guard-witness-claim token %r" % token)
        fields[key] = value
    unknown = set(fields) - {"corpus", "cases", "unwitnessed"}
    if unknown or "corpus" not in fields or not fields.get("cases"):
        raise ValueError("guard-witness-claim needs corpus= and cases= only")
    return (
        fields["corpus"],
        [c for c in fields["cases"].split(",") if c],
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
            if is_witness_claim(block) and not markers:
                problems.append(
                    "%s: claims each case catches its rule but has no "
                    "guard-witness-claim marker" % where
                )
            for body in markers:
                try:
                    corpus, cases, unwitnessed = parse_marker(body)
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
                for case in cases:
                    if case not in witnesses.cases:
                        problems.append("%s: %s has no guard witness entry" % (where, case))
                for case in unwitnessed:
                    if case not in names:
                        problems.append("%s: unwitnessed %s is not a %s case" % (where, case, corpus))
                covered = set(cases) | set(unwitnessed)
                for token in BACKTICKED.findall(MARKER.sub(" ", block)):
                    named = fnmatch.filter(names, token) if "*" in token else (
                        [token] if token in names else []
                    )
                    for case in named:
                        if case not in covered:
                            problems.append(
                                "%s: names %s, which the marker neither lists as "
                                "witnessed nor as unwitnessed" % (where, case)
                            )
    return problems
