#!/usr/bin/env python3
"""Validate the delivery-or-remedy candidate profile and its rule-to-case matrix.

The candidate in docs/delivery-or-remedy-candidate.md is pre-normative, so the
spec validators (which read spec/ only) never see it. This checker pins it:

- labelled rule IDs are unique, gap-free per family, and disjoint from spec/;
- every capitalized requirement keyword sits in a labelled rule, and no
  prohibition is phrased as "No ... MAY";
- every rule reference resolves in the candidate or in spec/;
- every candidate signing domain uses the CORE SIG-4 `dacs-x-` form, matches
  the version of the artifact type it signs, and is disjoint from the CORE
  registry; every other quoted `dacs-*:vN:` literal is registered;
- the verifier result vocabulary is the DACS four-way disposition;
- every requirement-bearing rule is listed by at least one section 11 case,
  and every case lists only defined rules;
- the document stays pre-normative and pins the Standard revision it was
  checked against;
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
CASE_RE = re.compile(r"^- \*\*([PRIQ])(\d+)\*\* — (.+?) \*Rules:\* (.+)\.$")
CANDIDATE_REF_RE = re.compile(r"\bDR[A-Z]*-\d+\b")
INLINE_CODE_RE = re.compile(r"`[^`]*`")
KEYWORD_RE = re.compile(r"\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|REQUIRED|MAY)\b")
NO_MAY_RE = re.compile(r"\bNo\b[^.;]*\bMAY\b")
SIGNING_DOMAIN_RE = re.compile(r'^"(dacs-x-[a-z0-9-]+):v(\d+):" \|\| [a-z_]+_hash$')
ANY_DOMAIN_RE = re.compile(r"(dacs-[a-z0-9-]+:v\d+:)")
VERSION_MEMBER_RE = re.compile(r'^\s*[a-z][A-Za-z]*Version: "(\d+)"')
TYPE_RE = re.compile(r"^type ([A-Za-z0-9]+) =")
CHECKED_AGAINST_RE = re.compile(r"^\*\*Checked against:\*\* DACS-Standard `next` at `([0-9a-f]{40})`\.")
STATUS_PREFIX = "**Status:** pre-normative review candidate"
RESULT_VOCABULARY = '"pass" | "fail" | "indeterminate" | "error"'
FORBIDDEN_RESULTS = ("`verified`", "`rejected`")
# Standards and algorithm names that match the generic rule-ID shape.
NON_RULE_FAMILIES = {"SHA", "BP"}


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
                "requirement": any(k.startswith(("MUST", "SHALL", "REQUIRED")) for k in keywords),
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
            cases.append({
                "id": f"{match.group(1)}{match.group(2)}",
                "kind": match.group(1),
                "number": int(match.group(2)),
                "section": heading,
                "description": match.group(3),
                "rules": [r.strip() for r in match.group(4).split(",")],
            })
    return cases


def parse_types(text: str) -> list[dict]:
    types: list[dict] = []
    for block in code_blocks(text):
        start = None
        for index, line in enumerate(block):
            match = TYPE_RE.match(line)
            if match:
                if start is not None:
                    types.append(_type_entry(block[start[0]:index], start[1]))
                start = (index, match.group(1))
        if start is not None:
            types.append(_type_entry(block[start[0]:], start[1]))
    return types


def _type_entry(lines: list[str], name: str) -> dict:
    body = "\n".join(lines).rstrip()
    return {"name": name, "sha256": sha256_text(body)}


def signing_domains(text: str) -> tuple[list[dict], list[str]]:
    """Return candidate signing domains with the version of the type they sign."""
    domains: list[dict] = []
    errors: list[str] = []
    latest_version: tuple[str, str] | None = None
    current_type = None
    for _number, line, in_code in split_lines(text):
        if not in_code:
            continue
        type_match = TYPE_RE.match(line)
        if type_match:
            current_type = type_match.group(1)
        version_match = VERSION_MEMBER_RE.match(line)
        if version_match and current_type is not None:
            latest_version = (current_type, version_match.group(1))
        domain_match = SIGNING_DOMAIN_RE.match(line.strip())
        if domain_match:
            kind, version = domain_match.group(1), domain_match.group(2)
            if latest_version is None:
                errors.append(f"signing domain {kind}:v{version}: has no preceding versioned artifact type")
                continue
            type_name, type_version = latest_version
            if version != type_version:
                errors.append(
                    f"signing domain {kind}:v{version}: does not match {type_name} version \"{type_version}\""
                )
            domains.append({"domain": f"{kind}:v{version}:", "signs": type_name})
    return domains, errors


def validate_text(text: str, spec_text: str) -> list[str]:
    errors: list[str] = []
    rules = parse_rules(text)
    rule_ids = [rule["id"] for rule in rules]
    defined = set(rule_ids)

    lines = text.splitlines()
    if not lines or not lines[2].startswith(STATUS_PREFIX):
        errors.append("status line must remain 'pre-normative review candidate' until executable vectors exist")
    if not any(CHECKED_AGAINST_RE.match(line) for line in lines):
        errors.append("missing '**Checked against:** DACS-Standard `next` at `<40-hex commit>`.' pin")

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
    for case in cases:
        for rule_id in case["rules"]:
            if rule_id not in defined:
                errors.append(f"case {case['id']} lists undefined rule {rule_id}")
            covered.add(rule_id)
    for rule in rules:
        if rule["requirement"] and rule["id"] not in covered:
            errors.append(f"requirement {rule['id']} is not exercised by any section 11 case")
    return errors


def build_matrix(text: str) -> dict:
    rules = parse_rules(text)
    cases = parse_cases(text)
    case_index: dict[str, list[str]] = {}
    for case in cases:
        for rule_id in case["rules"]:
            case_index.setdefault(rule_id, []).append(case["id"])
    checked = next((m.group(1) for m in map(CHECKED_AGAINST_RE.match, text.splitlines()) if m), None)
    domains, _ = signing_domains(text)
    return {
        "document": "docs/delivery-or-remedy-candidate.md",
        "status": "pre-normative",
        "checkedAgainst": checked,
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
