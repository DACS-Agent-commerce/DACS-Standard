#!/usr/bin/env python3
"""Validate the delivery-or-remedy candidate profile and its rule-to-case matrix.

The candidate in docs/delivery-or-remedy-candidate.md is pre-normative, so the
spec validators (which read spec/ only) never see it. This checker pins it:

- labelled rule IDs are unique, gap-free per family, and disjoint from spec/;
- every capitalized requirement keyword sits in a labelled rule, and no
  prohibition is phrased as "No ... MAY"; a "MAY ... only" restriction counts
  as a requirement;
- every rule reference resolves in the candidate or in spec/;
- every type in SIGNED_TYPES is defined once with exactly one version member
  and is signed by exactly one `"dacs-x-...:vN:" || <operand>` line whose
  version matches; every signing-domain line in a code block has that form,
  every signed type is in the inventory, and no candidate domain is in the
  CORE registry; every other quoted `dacs-*:vN:` literal is registered;
- the verifier result vocabulary is the DACS four-way disposition;
- every requirement-bearing rule is listed by at least one rejection or
  indeterminate case, a process case lists only PROCESS_RULES (the only rules
  it covers), every case lists only defined rules, and every case declares
  expected results allowed for its kind;
- the document stays pre-normative, every external pin links to a 40-hex
  commit, and the **Checked against** commit is an ancestor of HEAD whose
  spec/ equals spec/ at the candidate's latest revision (the working tree
  while the document has uncommitted edits); a later spec/ change that does
  not revise the candidate does not fail the check;
- the generated rule-to-case matrix is in sync with the document.

The matrix pins a SHA-256 of every rule, case, type block, and section, so a
normative edit fails CI until the matrix is regenerated with --write and the
diff is reviewed. It is not an executable oracle: no case has a signed vector.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import specsource  # noqa: E402
import validate_domain_separators  # noqa: E402
import validate_rule_ids  # noqa: E402

DOC = ROOT / "docs" / "delivery-or-remedy-candidate.md"
MATRIX = ROOT / "conformance" / "candidates" / "delivery-or-remedy" / "rule-case-matrix.json"

RULE_DEF_RE = re.compile(r"^- \((DR[A-Z]*-\d+)\) (.+)$")
CASE_RE = re.compile(r"^- \*\*([PRIQ])(\d+)\*\* — (.+?) \*Expected:\* (.+?) \*Rules:\* (.+)\.$")
CASE_START_RE = re.compile(r"^- \*\*[PRIQ]\d+\*\*")
EXPECTED_RESULT_RE = re.compile(r"`(pass|fail|indeterminate|error)`")
# Results each case kind may expect: positive, rejection, indeterminate, process.
ALLOWED_EXPECTED = {
    "P": {"pass"},
    "R": {"fail", "error"},
    "I": {"indeterminate"},
    "Q": {"pass"},
}
# Case kinds that can fail an implementation that ignores a rule.
NEGATIVE_KINDS = {"R", "I"}
# Obligations on the document and the registration process. A process case
# expects only `pass`, so it may list these and nothing else.
PROCESS_RULES = {"DRG-2", "DRC-10", "DRC-11"}
CANDIDATE_REF_RE = re.compile(r"\bDR[A-Z]*-\d+\b")
INLINE_CODE_RE = re.compile(r"`[^`]*`")
KEYWORD_RE = re.compile(r"\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|REQUIRED|MAY)\b")
NO_MAY_RE = re.compile(r"\bNo\b[^.;]*\bMAY\b")
MAY_ONLY_RE = re.compile(r"\bMAY\b[^.;]*\bonly\b")
# Any code line that looks like a signing payload; it must then match SIGNING_DOMAIN_RE.
DOMAIN_LINE_RE = re.compile(r'"dacs-[^"]*"\s*\|\|')
SIGNING_DOMAIN_RE = re.compile(r'^"(dacs-[a-z0-9-]+):v(\d+):" \|\| ([a-z0-9_]+_hash)$')
ANY_DOMAIN_RE = re.compile(r"(dacs-[a-z0-9-]+:v\d+:)")
VERSION_MEMBER_RE = re.compile(r'^\s*([a-z][A-Za-z]*Version): "(\d+)"')
SIGNATURE_MEMBER_RE = re.compile(r"^  (signature|signatures): ")
TYPE_RE = re.compile(r"^type ([A-Za-z0-9]+) =")
CHECKED_AGAINST_RE = re.compile(r"^\*\*Checked against:\*\* DACS-Standard `next` at `([0-9a-f]{40})`\.")
EXTERNAL_PINS_HEADING = "**External pins:**"
LINK_RE = re.compile(r"\]\((https?://[^)\s]+)\)")
PINNED_LINK_RE = re.compile(r"^https://github\.com/[^/]+/[^/]+/blob/[0-9a-f]{40}/")
STATUS_PREFIX = "**Status:** pre-normative review candidate"
RESULT_VOCABULARY = '"pass" | "fail" | "indeterminate" | "error"'
FORBIDDEN_RESULTS = ("`verified`", "`rejected`")
# Standards and algorithm names that match the generic rule-ID shape.
NON_RULE_FAMILIES = {"SHA", "BP"}
# Every signed candidate artifact: its version member and the hash operand of
# its signing payload. A signed type outside this inventory, or one that loses
# its version member or signing domain, is a structural error.
SIGNED_TYPES = {
    "JobEscrowRailDefinition": ("jobEscrowRailVersion", "job_escrow_rail_hash"),
    "DeliveryOrRemedyAgreement": ("deliveryOrRemedyAgreementVersion", "agreement_overlay_hash"),
    "EscrowJobRef": ("escrowJobRefVersion", "escrow_job_ref_hash"),
    "EscrowFundingEvidence": ("escrowFundingEvidenceVersion", "escrow_funding_evidence_hash"),
    "ExecutionEvaluation": ("executionEvaluationVersion", "execution_evaluation_hash"),
    "EscrowDecision": ("escrowDecisionVersion", "escrow_decision_hash"),
    "DisputeCase": ("disputeCaseVersion", "dispute_case_hash"),
    "DisputeOutcome": ("disputeOutcomeVersion", "dispute_outcome_hash"),
    "EscrowTerminalEvidence": ("escrowTerminalEvidenceVersion", "terminal_evidence_hash"),
}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def rule_number(rule_id: str) -> int:
    return int(rule_id.rsplit("-", 1)[1])


def split_lines(text: str) -> list[tuple[int, str, bool]]:
    """Return (line number, line, inside code fence) for every line."""
    out: list[tuple[int, str, bool]] = []
    in_code = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("```"):
            in_code = not in_code
            out.append((number, line, True))
            continue
        out.append((number, line, in_code))
    return out


def code_blocks(text: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if line.startswith("```"):
            if current is None:
                current = []
            else:
                blocks.append(current)
                current = None
            continue
        if current is not None:
            current.append(line)
    return blocks


def sections(text: str) -> list[tuple[str, str]]:
    """Return (heading, body) for every ## and ### heading, plus the preamble."""
    out: list[tuple[str, list[str]]] = [("preamble", [])]
    in_code = False
    for line in text.splitlines():
        if line.startswith("```"):
            in_code = not in_code
        if not in_code and (line.startswith("## ") or line.startswith("### ")):
            out.append((line.lstrip("#").strip(), []))
            continue
        out[-1][1].append(line)
    return [(heading, "\n".join(body)) for heading, body in out]


def parse_rules(text: str) -> list[dict]:
    rules: list[dict] = []
    heading = "preamble"
    for _number, line, in_code in split_lines(text):
        if in_code:
            continue
        if line.startswith("## ") or line.startswith("### "):
            heading = line.lstrip("#").strip()
            continue
        match = RULE_DEF_RE.match(line)
        if match:
            rule_text = match.group(2)
            keywords = sorted(set(KEYWORD_RE.findall(rule_text)))
            rules.append({
                "id": match.group(1),
                "section": heading,
                "keywords": keywords,
                "requirement": (
                    any(k.startswith(("MUST", "SHALL", "REQUIRED")) for k in keywords)
                    or MAY_ONLY_RE.search(rule_text) is not None
                ),
                "text": rule_text,
            })
    return rules


def parse_cases(text: str) -> list[dict]:
    cases: list[dict] = []
    heading = ""
    for _number, line, in_code in split_lines(text):
        if in_code:
            continue
        if line.startswith("### "):
            heading = line.lstrip("#").strip()
            continue
        match = CASE_RE.match(line)
        if match:
            expected: list[str] = []
            for result in EXPECTED_RESULT_RE.findall(match.group(4)):
                if result not in expected:
                    expected.append(result)
            cases.append({
                "id": f"{match.group(1)}{match.group(2)}",
                "kind": match.group(1),
                "number": int(match.group(2)),
                "section": heading,
                "description": match.group(3),
                "expectedText": match.group(4),
                "expected": expected,
                "rules": [r.strip() for r in match.group(5).split(",")],
            })
    return cases


def type_bodies(text: str) -> list[tuple[str, list[str]]]:
    """Return (name, lines) for every `type X =` block inside a code fence."""
    types: list[tuple[str, list[str]]] = []
    for block in code_blocks(text):
        start = None
        for index, line in enumerate(block):
            match = TYPE_RE.match(line)
            if match:
                if start is not None:
                    types.append((start[1], block[start[0]:index]))
                start = (index, match.group(1))
        if start is not None:
            types.append((start[1], block[start[0]:]))
    return types


def parse_types(text: str) -> list[dict]:
    return [_type_entry(lines, name) for name, lines in type_bodies(text)]


def _type_entry(lines: list[str], name: str) -> dict:
    body = "\n".join(lines).rstrip()
    return {"name": name, "sha256": sha256_text(body)}


def signing_domains(text: str) -> tuple[list[dict], list[str]]:
    """Return candidate signing domains, checked against SIGNED_TYPES."""
    domains: list[dict] = []
    errors: list[str] = []
    operands = {operand: name for name, (_member, operand) in SIGNED_TYPES.items()}

    versions: dict[str, str] = {}
    definitions: dict[str, int] = {}
    for name, lines in type_bodies(text):
        definitions[name] = definitions.get(name, 0) + 1
        signed = any(SIGNATURE_MEMBER_RE.match(line) for line in lines)
        if name not in SIGNED_TYPES:
            if signed:
                errors.append(f"signed type {name} is not in the signed-type inventory")
            continue
        member, _operand = SIGNED_TYPES[name]
        if not signed:
            errors.append(f"signed type {name} has no signature member")
        found = [m.groups() for m in map(VERSION_MEMBER_RE.match, lines) if m]
        if [m for m, _v in found] != [member]:
            errors.append(f'signed type {name} must declare exactly one version member {member}: "<n>"')
        if found:
            versions[name] = found[0][1]
    for name in SIGNED_TYPES:
        if definitions.get(name, 0) == 0:
            errors.append(f"signed type {name} is not defined")
        elif definitions[name] > 1:
            errors.append(f"signed type {name} is defined more than once")

    signed_by: dict[str, int] = {}
    for number, line, in_code in split_lines(text):
        if not in_code or not DOMAIN_LINE_RE.search(line):
            continue
        match = SIGNING_DOMAIN_RE.match(line.strip())
        if not match:
            errors.append(f"line {number}: malformed signing-domain line: {line.strip()}")
            continue
        kind, version, operand = match.groups()
        if not kind.startswith("dacs-x-"):
            errors.append(f"line {number}: candidate signing domain {kind}:v{version}: must use the dacs-x- form")
            continue
        type_name = operands.get(operand)
        if type_name is None:
            errors.append(f"line {number}: signing domain {kind}:v{version}: signs unknown operand {operand}")
            continue
        signed_by[type_name] = signed_by.get(type_name, 0) + 1
        if type_name in versions and version != versions[type_name]:
            errors.append(
                f"signing domain {kind}:v{version}: does not match {type_name} version \"{versions[type_name]}\""
            )
        domains.append({"domain": f"{kind}:v{version}:", "signs": type_name})
    for name in SIGNED_TYPES:
        count = signed_by.get(name, 0)
        if count != 1:
            errors.append(f"signed type {name} has {count} signing domains; exactly one is required")
    return domains, errors


def external_pin_errors(lines: list[str]) -> list[str]:
    """Every link in the **External pins:** list must name a 40-hex commit."""
    errors: list[str] = []
    try:
        start = lines.index(EXTERNAL_PINS_HEADING)
    except ValueError:
        return [f"missing '{EXTERNAL_PINS_HEADING}' list"]
    started = False
    for line in lines[start + 1:]:
        if line.startswith("- "):
            started = True
            for url in LINK_RE.findall(line):
                if not PINNED_LINK_RE.match(url):
                    errors.append(f"external pin {url} does not link to a 40-hex commit")
        elif started or line.strip():
            # The list ends at its first non-item line; text before any item means no list.
            break
    if not started:
        errors.append(f"'{EXTERNAL_PINS_HEADING}' list is empty")
    return errors


def checked_against(text: str) -> str | None:
    return next((m.group(1) for m in map(CHECKED_AGAINST_RE.match, text.splitlines()) if m), None)


SHALLOW_CLONE_ERROR = (
    "the **Checked against** pin cannot be verified in a shallow clone; "
    "fetch full history (git fetch --unshallow)"
)


def pin_errors(root: Path, commit: str, doc: Path = DOC) -> list[str]:
    """The pin must be an ancestor of HEAD, and spec/ at the candidate's latest
    revision must equal it (DRG-2).

    The latest revision is the commit that last changed `doc`, or the working
    tree when `doc` has uncommitted edits or is not a tracked file of `root`.
    A later spec/ change that does not revise the candidate does not fail.
    """
    def git(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)

    try:
        shallow = git("rev-parse", "--is-shallow-repository")
    except FileNotFoundError:
        return ["git is required to verify the **Checked against** pin"]
    if shallow.stdout.strip() == "true":
        return [SHALLOW_CLONE_ERROR]
    exists = git("rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}")
    if exists.returncode != 0:
        return [f"**Checked against** commit {commit} is not a commit in this repository"]
    if git("merge-base", "--is-ancestor", commit, "HEAD").returncode != 0:
        return [f"**Checked against** commit {commit} is not an ancestor of HEAD"]
    revision = candidate_revision(git, root, doc)
    if revision is None:
        diff = git("diff", "--quiet", commit, "--", "spec/")
        where = "the working tree"
    else:
        diff = git("diff", "--quiet", commit, revision, "--", "spec/")
        where = f"commit {revision}, the candidate's latest revision"
    if diff.returncode == 1:
        return [
            f"spec/ differs from the **Checked against** commit {commit} at {where}; "
            "re-audit every cited rule and update the pin (DRG-2)"
        ]
    if diff.returncode != 0:
        return [f"could not compare spec/ with the **Checked against** commit {commit}: {diff.stderr.strip()}"]
    return []


def candidate_revision(git, root: Path, doc: Path) -> str | None:
    """Commit that last changed `doc`, or None when `doc` is not that committed file."""
    try:
        relative = doc.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None
    if git("diff", "--quiet", "HEAD", "--", relative).returncode != 0:
        return None
    return git("log", "-1", "--format=%H", "HEAD", "--", relative).stdout.strip() or None


def validate_text(text: str, spec_text: str) -> list[str]:
    errors: list[str] = []
    rules = parse_rules(text)
    rule_ids = [rule["id"] for rule in rules]
    defined = set(rule_ids)

    lines = text.splitlines()
    if len(lines) < 3 or not lines[2].startswith(STATUS_PREFIX):
        errors.append("status line must remain 'pre-normative review candidate' until executable vectors exist")
    if checked_against(text) is None:
        errors.append("missing '**Checked against:** DACS-Standard `next` at `<40-hex commit>`.' pin")
    errors.extend(external_pin_errors(lines))

    seen: set[str] = set()
    for rule_id in rule_ids:
        if rule_id in seen:
            errors.append(f"duplicate rule ID: {rule_id}")
        seen.add(rule_id)
    families: dict[str, list[int]] = {}
    for rule_id in seen:
        families.setdefault(validate_rule_ids.rule_family(rule_id), []).append(rule_number(rule_id))
    for family, numbers in sorted(families.items()):
        missing = sorted(set(range(1, max(numbers) + 1)) - set(numbers))
        if missing:
            errors.append(f"rule family {family} has gaps: " + ", ".join(f"{family}-{n}" for n in missing))

    spec_defined = validate_rule_ids.defined_rule_ids(spec_text)
    spec_families = {validate_rule_ids.rule_family(rule_id) for rule_id in spec_defined}
    for family in sorted(set(families) & spec_families):
        errors.append(f"candidate rule family {family} collides with a spec/ rule family")

    for number, line, in_code in split_lines(text):
        if in_code:
            continue
        is_rule = RULE_DEF_RE.match(line) is not None
        if CASE_START_RE.match(line) and not CASE_RE.match(line):
            errors.append(
                f"line {number}: malformed case line; use "
                "'- **<ID>** — <description> *Expected:* <results>. *Rules:* <rule IDs>.'"
            )
        if not is_rule and KEYWORD_RE.search(line):
            errors.append(f"line {number}: capitalized requirement keyword outside a labelled rule")
        if is_rule and NO_MAY_RE.search(line):
            errors.append(f"line {number}: prohibition phrased as 'No ... MAY'; use MUST NOT")
        for token in validate_rule_ids.RULE_ID_RE.findall(INLINE_CODE_RE.sub("", line)):
            if not validate_rule_ids.is_rule_like(token):
                continue
            if validate_rule_ids.rule_family(token) in NON_RULE_FAMILIES:
                continue
            if CANDIDATE_REF_RE.fullmatch(token):
                if token not in defined:
                    errors.append(f"line {number}: reference to undefined candidate rule {token}")
            elif token not in spec_defined:
                errors.append(f"line {number}: reference to rule {token} that spec/ does not define")

    domains, domain_errors = signing_domains(text)
    errors.extend(domain_errors)
    registered = validate_domain_separators.registered_domains(spec_text)
    domain_names = [entry["domain"] for entry in domains]
    for domain in sorted({d for d in domain_names if domain_names.count(d) > 1}):
        errors.append(f"candidate signing domain used for more than one artifact: {domain}")
    for domain in sorted(set(ANY_DOMAIN_RE.findall(text))):
        if domain.startswith("dacs-x-"):
            if domain in registered:
                errors.append(f"candidate domain collides with a registered domain: {domain}")
        elif domain not in registered:
            errors.append(f"non-extension domain is not registered in CORE: {domain} (candidates use dacs-x-)")

    verifier = dict(sections(text)).get("9. Verification result and ordering", "")
    verifier_blocks = code_blocks(verifier)
    if not verifier_blocks or verifier_blocks[0] != [RESULT_VOCABULARY]:
        errors.append(f"section 9 result vocabulary must be exactly {RESULT_VOCABULARY}")
    for token in FORBIDDEN_RESULTS:
        if token in text:
            errors.append(f"non-DACS verifier result {token} used; use pass/fail/indeterminate/error")

    cases = parse_cases(text)
    if not cases:
        errors.append("section 11 defines no cases")
    case_ids = [case["id"] for case in cases]
    for case_id in sorted({c for c in case_ids if case_ids.count(c) > 1}):
        errors.append(f"duplicate case ID: {case_id}")
    by_kind: dict[str, list[int]] = {}
    for case in cases:
        by_kind.setdefault(case["kind"], []).append(case["number"])
    for kind, numbers in sorted(by_kind.items()):
        missing = sorted(set(range(1, max(numbers) + 1)) - set(numbers))
        if missing:
            errors.append(f"case family {kind} has gaps: " + ", ".join(f"{kind}{n}" for n in missing))
    covered: set[str] = set()
    negative: set[str] = set()
    for case in cases:
        allowed = ALLOWED_EXPECTED[case["kind"]]
        if not case["expected"]:
            errors.append(f"case {case['id']} declares no expected result")
        elif not set(case["expected"]) <= allowed:
            errors.append(
                f"case {case['id']} expects {', '.join(case['expected'])}; "
                f"{case['kind']} cases may expect only {', '.join(sorted(allowed))}"
            )
        for rule_id in case["rules"]:
            if rule_id not in defined:
                errors.append(f"case {case['id']} lists undefined rule {rule_id}")
            covered.add(rule_id)
            if case["kind"] in NEGATIVE_KINDS:
                negative.add(rule_id)
            elif case["kind"] == "Q":
                if rule_id in PROCESS_RULES:
                    negative.add(rule_id)
                else:
                    errors.append(
                        f"process case {case['id']} lists {rule_id}, which is not a process rule; "
                        "list it in a rejection or indeterminate case"
                    )
    for rule in rules:
        if not rule["requirement"]:
            continue
        if rule["id"] not in covered:
            errors.append(f"requirement {rule['id']} is not exercised by any section 11 case")
        elif rule["id"] not in negative:
            errors.append(
                f"requirement {rule['id']} is exercised only by positive or process cases; "
                "list it in a rejection or indeterminate case"
            )
    return errors


def build_matrix(text: str) -> dict:
    rules = parse_rules(text)
    cases = parse_cases(text)
    case_index: dict[str, list[str]] = {}
    for case in cases:
        for rule_id in case["rules"]:
            case_index.setdefault(rule_id, []).append(case["id"])
    domains, _ = signing_domains(text)
    return {
        "document": "docs/delivery-or-remedy-candidate.md",
        "status": "pre-normative",
        "checkedAgainst": checked_against(text),
        "executableVectorCount": 0,
        "rules": [
            {
                "id": rule["id"],
                "section": rule["section"],
                "keywords": rule["keywords"],
                "requirement": rule["requirement"],
                "textSha256": sha256_text(rule["text"]),
                "cases": case_index.get(rule["id"], []),
            }
            for rule in rules
        ],
        "cases": [
            {
                "id": case["id"],
                "section": case["section"],
                "textSha256": sha256_text(case["description"]),
                "expected": case["expected"],
                "expectedTextSha256": sha256_text(case["expectedText"]),
                "rules": case["rules"],
            }
            for case in cases
        ],
        "types": parse_types(text),
        "signingDomains": domains,
        "sections": [{"heading": h, "sha256": sha256_text(body)} for h, body in sections(text)],
    }


def render_matrix(matrix: dict) -> str:
    return json.dumps(matrix, indent=2, ensure_ascii=False) + "\n"


def validate(doc: Path = DOC, matrix_path: Path | None = MATRIX, root: Path = ROOT) -> list[str]:
    text = doc.read_text(encoding="utf-8")
    errors = validate_text(text, specsource.spec_text(root))
    commit = checked_against(text)
    if commit is not None:
        errors.extend(pin_errors(root, commit, doc))
    if matrix_path is not None:
        expected = render_matrix(build_matrix(text))
        if not matrix_path.exists():
            errors.append(f"missing rule-to-case matrix: {matrix_path}")
        elif matrix_path.read_text(encoding="utf-8") != expected:
            errors.append(
                "rule-to-case matrix is stale; review the normative change and run "
                "scripts/validate_candidate_profile.py --write"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the delivery-or-remedy candidate profile")
    parser.add_argument("--doc", type=Path, default=DOC)
    parser.add_argument("--matrix", type=Path, default=MATRIX)
    parser.add_argument("--write", action="store_true", help="regenerate the rule-to-case matrix")
    args = parser.parse_args(argv)
    if args.write:
        errors = validate(args.doc, None)
        if not errors:
            args.matrix.parent.mkdir(parents=True, exist_ok=True)
            args.matrix.write_text(render_matrix(build_matrix(args.doc.read_text(encoding="utf-8"))), encoding="utf-8")
    else:
        errors = validate(args.doc, args.matrix)
    if errors:
        print("candidate profile validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("candidate profile OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
