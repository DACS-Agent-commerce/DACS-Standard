# Bounded repository audit — 14 September 2026

Status: **informational intake; not implementation acceptance, scope ratification,
release approval, or merge authorization**. This is an agent-authored assessment.
The existing [coordinator queue](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/398)
remains the coordination venue; this report does not create a second queue or
reopen completed review decisions.

## Scope and revision boundary

The audit inspected public source at:

- `main`: `4bb9e48a1095ab32c06c25b7c0b52018d3ce4091` (entry-point documentation and validation setup).
- `next`: `ff8c289d22d07e09a1733b1ae7791100bfdbd923` (profile, conformance tooling, CI, and focused JSON review).

This report is submitted on a newer integration base,
`d45c0a292006b2fd2e40d2dbe0cd7ed518ad0f20`. Findings below are historical,
revision-pinned observations, not assertions that every observation remains
unrepaired on that base or on private successors. Existing fixes and tracking
must be reconciled before assigning implementation work. The PR adds only this
report; it does not implement the proposed repairs.

Excluded: exhaustive review of every module or open PR, private successors,
live settlement, deployed implementations, branch-protection enforcement,
and full end-to-end protocol certification. Private approval summaries in the
public queue were not independently verified.

## A1 — Local validation instructions do not match CI (medium)

**Evidence:** the audited main
[README, lines 129–143](https://github.com/DACS-Agent-commerce/DACS-Standard/blob/4bb9e48a1095ab32c06c25b7c0b52018d3ce4091/README.md#L129-L143)
claims dependency-free tooling and presents ordinary unittest discovery as
equivalent to CI. Main's
[workflow, lines 32–36 and 74–87](https://github.com/DACS-Agent-commerce/DACS-Standard/blob/4bb9e48a1095ab32c06c25b7c0b52018d3ce4091/.github/workflows/validate.yml#L32-L87)
installs `cryptography==46.0.5` and fails on any skipped test. The audited next
[workflow](https://github.com/DACS-Agent-commerce/DACS-Standard/blob/ff8c289d22d07e09a1733b1ae7791100bfdbd923/.github/workflows/validate.yml#L32-L137)
also installs `idna==3.10` and retains the no-skips gate.

**Impact:** documented local execution is a weaker validation contract than CI;
contributors may mistake it for acceptance evidence. This does not establish
that hosted CI skipped required checks.

**Proposed repair:** document dependencies and reuse one validation entry point
for local and hosted checks, including the no-skips policy. Reconcile the
contribution guide with the same contract.

**Acceptance:** following the instructions in a clean environment executes the
intended checks; missing dependencies or skipped tests result in nonzero exit.

**Evidence status:** source-confirmed; no clean-environment full workflow was
completed in this audit. Suggested owner: validation/documentation maintainer,
subject to coordinator assignment.

## A2 — Cross-run evidence lacks enforced corpus revision binding (medium)

**Evidence:** the audited
[`diff_vector_runs.py`, lines 69–132](https://github.com/DACS-Agent-commerce/DACS-Standard/blob/ff8c289d22d07e09a1733b1ae7791100bfdbd923/scripts/diff_vector_runs.py#L69-L132)
requires `set`, `impl`, and `results`, then loads expected cases from the local
checkout. It does not require a corpus digest or immutable implementation
revision. Its comparison uses case identities and verdicts.

**Impact:** old recorded results can still compare successfully after corpus
inputs change if case names and expected verdicts remain unchanged. Verdict
agreement alone does not prove execution against the current inputs.

**Existing mitigation:** the
[promotion policy, lines 63–80](https://github.com/DACS-Agent-commerce/DACS-Standard/blob/ff8c289d22d07e09a1733b1ae7791100bfdbd923/conformance/vectors/security/CROSS-RUN.md#L63-L80)
requires immutable revision evidence and steward review. This observation is
an automation gap, not evidence of an improper promotion or a protocol exploit.
Different implementation labels also do not independently establish different
implementation provenance.

**Proposed repair:** scope a versioned run-evidence format that requires a corpus
digest, implementation commit, and runner revision, with a defined digest
encoding and explicit treatment of older run files. Do not silently treat old
files as current promotion evidence. Human provenance review remains separate.

**Acceptance:** changing a vector input while preserving its case name and
expected verdict invalidates the old run; missing or mismatched revision
metadata fails current-evidence validation. Existing abstention and distinct-ID
checks remain intact.

**Evidence status:** source-confirmed omission; no runtime reproduction in this
audit. Suggested owner: conformance-tooling maintainer. Design/scope ratification
and compatibility decisions remain open; this report does not authorize changes.

## A3 — Coverage documentation contradicts itself (low)

**Evidence:** the audited next
[conformance README summary](https://github.com/DACS-Agent-commerce/DACS-Standard/blob/ff8c289d22d07e09a1733b1ae7791100bfdbd923/conformance/README.md#L9)
reports 36 golden Verify cases, while its
[detailed Verify section](https://github.com/DACS-Agent-commerce/DACS-Standard/blob/ff8c289d22d07e09a1733b1ae7791100bfdbd923/conformance/README.md#L61)
says 49.

**Impact:** readers receive conflicting coverage claims. This observation does
not independently establish the correct current count.

**Proposed repair:** derive published counts from the manifest and check generated
sections in CI, preserving golden/candidate/historical distinctions.

**Acceptance:** all generated coverage claims match the applicable manifest;
status changes update the documentation without reclassifying historical evidence.

**Evidence status:** directly observed documentation contradiction. May overlap
with existing repairs; reconcile before opening additional work. Suggested owner:
conformance-documentation maintainer.

## Release boundary and positive observations

The audited
[PROFILE, lines 37–65](https://github.com/DACS-Agent-commerce/DACS-Standard/blob/ff8c289d22d07e09a1733b1ae7791100bfdbd923/spec/PROFILE.md#L37-L65)
explicitly marks the corrective candidate as inadmissible for live use until a
coordinated release records the required immutable identifier and authenticated
module composition. A green integration branch does not clear that boundary.

Positive observations include read-only CI permissions, explicit failure on
skipped tests, deterministic fixture checks, abstention-aware cross-run
comparison, and separate technical-review, promotion, release, and merge gates.
These are process strengths, not a certification of production safety.

## Verification evidence and limitations

- GitHub's run listing reported successful hosted validation for audited next
  at `ff8c289d22d07e09a1733b1ae7791100bfdbd923`:
  [workflow run 34770122205](https://github.com/DACS-Agent-commerce/DACS-Standard/actions/runs/34770122205).
  This is hosted status evidence, not a locally reproduced full workflow.
- The focused JSON review recorded 20 passing `test_jcs.py` tests and 11 passing
  `test_raw_json_profile_vectors.py` tests. Its completion report additionally
  recorded 5 passing `test_canonical_json_vectors.py` tests.
- A recorded seeded comparison of 104,798 finite DACS-safe binary64 values
  against Node `JSON.stringify` found zero mismatches. This is supplementary
  bounded evidence; the ad hoc probe is not a committed reproducible harness and
  must not substitute for required acceptance evidence.
- No reproducible correctness defect was identified in the inspected JSON
  modules. This does not cover every caller or prove exhaustive conformance.
- The complete local workflow was not completed. Execution authorization was
  unavailable for the attempted full validation path. A worker's manifest check
  also could not resolve historical pins in the shallow checkout; that limitation
  is not an established repository defect.

No changes to protocol source, conformance vectors, approval state, or release
state are proposed by this report. All findings remain intake observations until
reconciled with existing work and explicitly dispositioned under the coordinator
workflow. Subsequent PR validation applies to this documentation change only and
does not retroactively expand the audit's coverage.
