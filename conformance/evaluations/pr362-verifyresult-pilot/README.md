# DACS Standard PR #362 evaluation pilot package

This directory packages the existing #362 VerifyResult protocol evaluation as
a reusable local author/reviewer artifact for the #401 follow-up. It preserves
the historical evidence byte-for-byte and adds a path-independent runner. The
current recorded result is 12/12 passing cases (11 protocol cases and one
historical mutant) plus 7/7 rejected altered-report controls.
The current grader also carries a verifier-only disposition control showing
that an honestly reported deterministic failure is accepted while changing it
to `pass` is rejected.

This remains a Draft protocol/conformance pilot. It is not a Harbor agent task,
does not contain a real agent trajectory, and does not establish consumer-model
quality, SDK interoperability, full JCS coverage, live behavior, or production
readiness.

## Inputs and provenance

- Required origin: `https://github.com/DACS-Agent-commerce/DACS-Standard.git`
- Required candidate: `37010daa0a7c5900afcda6e314f1ae53f3afeb7b`
- Required base object: `ff8c289d22d07e09a1733b1ae7791100bfdbd923`
- Frozen cases SHA-256:
  `cc07a0f2c6ca251a7afb1540d9b61780221eeec1c3639836c32294f995640f57`
- Recorded runtime: CPython 3.12.6 and `cryptography` 46.0.5

The checkout must be clean. The intended procedure supplies no network or
live-system access and asks the runner to write only to the fresh output
directory supplied by the caller. Those are external execution assumptions:
the portable runner is not a network or filesystem sandbox. It independently
checks the candidate's Git identity and tracked/untracked status before and
after execution, but it cannot observe arbitrary network access, concurrent
mutation, or writes outside the paths it checks.
Set `PYTHON_BIN` when `python3` is not the recorded interpreter. See [Task.md one-time setup](Task.md#one-time-setup-before-offline-evaluation) for an exact CPython 3.12.6 environment and both required Git objects, including the separate base fetch for shallow checkouts.

## Commands

From this directory, verify the byte-preserved historical result by rerunning
the deterministic cases:

```sh
PYTHON_BIN=/path/to/python3 ./run.sh verify-historical /path/to/DACS-Standard
```

Create new evidence in a new directory. The wrapper never replaces an existing
result:

```sh
PYTHON_BIN=/path/to/python3 ./run.sh reproduce /path/to/DACS-Standard /path/to/new-output
```

Verify the complete fresh bundle with the portable harness:

```sh
PYTHON_BIN=/path/to/python3 ./run.sh verify-bundle /path/to/new-output
```

The one-argument form resolves the candidate path recorded in the manifest.
For a relocated checkout, supply it explicitly as a final argument. The strict
verifier requires exactly `results.json`, `grader-calibration.json`, and
`reproducibility-manifest.json`; validates their schemas, identities, digests,
runtime and command relationships; reruns the deterministic cases and grader
controls; and evaluates P1-P5. It reports `runValidity`,
`candidateDisposition`, and `artifactScore` separately. A valid, honestly
reported candidate failure has `runValidity.status: valid` and
`candidateDisposition: fail`; missing, corrupt, or inconsistent evidence has
`runValidity.status: invalid`, no candidate disposition, and no score.

Absolute locations in a generated run manifest describe that run; the
invocation itself has no hard-coded checkout or output path. The historical
manifest retains its original authoring paths solely to preserve its bytes and
provenance. Reviewers should use the commands above with their own paths.

## Layout

- `Task.md` is the precise Draft author/reviewer contract, including state,
  effects, scoring, invalid-run conditions, and assurance limits.
- `cases.json` is an exact working copy of the frozen historical case set.
- `runner/eval_pr362.py` is the portable adaptation. It requires explicit paths,
  protects existing outputs, strictly verifies complete fresh bundles, and can
  reproduce the historical record's deterministic case content while
  authenticating the exact historical harness digest.
- `requirements.txt` records the one non-stdlib runtime dependency used by the
  evaluator.
- `historical/` contains byte-preserved public source, case, result,
  calibration, manifest, and proposal artifacts. The original bytecode cache
  and internal workflow/review records are intentionally not published.
- `historical/SOURCE-INVENTORY.md` records the source hashes and publication
  decisions, including the omitted bytecode hash.
- `evidence-format-proposal.md` maps the pilot to possible #270/#402 evidence
  fields without adopting a schema.
- `ARTIFACTS.sha256` lists exact hashes for review. It excludes itself.

## Evidence interpretation

The protocol outcome, run validity, and author/reviewer artifact score are
separate. A valid run can reveal a candidate failure. Setup, pin, dependency,
missing/corrupt bundle evidence, or verifier faults make a run invalid and must
not become a candidate score.
The package's exact decision rules are in `Task.md`.

The reusable status vocabulary and evidence fields are proposal material for
coordination with #270/#402. Nothing here changes the DACS Standard or adopts a
normative cross-repository record format.
