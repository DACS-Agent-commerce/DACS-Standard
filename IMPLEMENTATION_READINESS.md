# DACS Implementation Readiness

This document tracks additive repository improvements that make DACS easier to implement, validate, and review without changing v0.1 conformance semantics. Normative roadmap items remain tracked in [ROADMAP.md](./ROADMAP.md).

## Current implementation-readiness items

1. [x] Add a visible implementation-readiness inventory so contributors can identify small, reviewable work without guessing from the full roadmap.
2. [x] Add dependency-free Markdown documentation validation for relative links and section anchors, with tests.
3. [x] Add a minimal conformance-vector manifest for §14 with stable IDs and expected pass/fail outcomes.
4. [x] Add a small script that recomputes deterministic JSON content hashes for the example artifacts.
5. [x] Add a CI workflow that runs the documentation and conformance validators on every pull request.
6. [x] Add machine-readable JSON examples for the remaining core artifacts named in the spec: IdentityBundle, RatingRecord, and negative-path examples.
7. [x] Add a glossary index mapping key terms to specification sections.
8. [x] Add a rule-ID index for conformance rules such as BP-*, LP-*, SIG-*, PC-*, RT-*, RAV-*.
9. [x] Add an operational-builder-guide outline for the roadmap's implementation and capital/finality topics.
10. [x] Add issue templates for spec defects, implementation reports, and editorial fixes matching CONTRIBUTING.md's preferred report format.

## Implemented in `feat/implementation-readiness-tooling`

This branch completes 10 of 10 identified implementation-readiness items (100%):

- Item 1: this implementation-readiness inventory.
- Item 2: `scripts/validate-docs.py` plus `tests/test_validate_docs.py`.
- Item 3: `conformance/vectors/dacs-v0.1-happy-path.json`.
- Item 4: `scripts/validate_conformance_vectors.py` plus `tests/test_validate_conformance_vectors.py`.
- Item 5: `.github/workflows/validate.yml` runs validators and unit tests on pull requests.
- Item 6: `conformance/vectors/examples/identity-bundle.json`, `conformance/vectors/examples/rating-record.json`, and `conformance/vectors/dacs-v0.1-negative-paths.json`.
- Item 7: `docs/glossary-index.md` maps key terms to specification sections.
- Item 8: `docs/rule-id-index.md` maps labelled rule families to spec sections and §14 test-plan hooks.
- Item 9: `docs/operational-builder-guide.md` outlines implementation, capital/float, undercapitalised-session, key-custody, and settlement-finality topics.
- Item 10: `.github/ISSUE_TEMPLATE/` includes spec-defect, implementation-report, and editorial-fix templates aligned with `CONTRIBUTING.md`.

## Follow-on hardening in this branch

The branch also carries narrow repository-health hardening that preserves v0.1
semantics:

- `scripts/validate_domain_separators.py` catches drift between quoted
  `dacs...:v1:` prefixes in the spec and the closed CORE §B.7 registry.
- `scripts/validate_rule_ids.py` catches undefined labelled-rule references and
  keeps `docs/rule-id-index.md` aligned with rule families defined in the spec.
- `scripts/validate_spec_tables.py` smoke-tests selected registry tables for
  duplicate or malformed rows.
- `conformance/vectors/dacs-v0.1-negative-paths.json` remains a canonical
  negative-path vector set and now uses registered domain separators so the
  intended failures stay focused on the ruleRefs under `expectedResult`.
- `conformance/fixtures/` remains non-normative roadmap/prototype material and
  is excluded from default canonical vector validation.

## Selection criteria

An implementation-readiness item should be:

- additive and non-breaking;
- small enough for a focused pull request;
- useful to implementers or reviewers immediately;
- safe to land without resolving future v0.2 design questions.
