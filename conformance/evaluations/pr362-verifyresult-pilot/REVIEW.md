# Package review evidence

**Review status:** Draft package ready for independent author/reviewer review.

## Deterministic results

- Verified repository origin:
  `https://github.com/DACS-Agent-commerce/DACS-Standard.git`.
- Verified candidate commit:
  `37010daa0a7c5900afcda6e314f1ae53f3afeb7b`.
- Verified base commit object:
  `ff8c289d22d07e09a1733b1ae7791100bfdbd923`.
- The base is an ancestor of the candidate and the candidate checkout was clean
  before and after evaluation.
- The portable current runner reproduced the historical record's deterministic
  case content and authenticated the digest of the byte-preserved historical
  harness. It did not rerun the historical harness.
- The portable fresh run passed 12/12 cases: 11 protocol cases and one
  historical-defect mutant.
- The regenerated evidence-checker calibration accepted the untampered baseline
  and rejected 7/7 altered-report controls.
- Its verifier-only disposition control accepted an honestly reported
  deterministic failure and rejected the same record after its aggregate was
  changed to `pass`; candidate code and frozen cases were not mutated.
- Fresh and historical case decisions, calls, observations, and notes are
  equivalent. The schema-v2 fresh result intentionally omits the legacy
  `forbiddenEffectsObserved` field because the runner did not independently
  observe general effects; its assurance boundary, timestamps, and portable
  harness digest also differ from the preserved schema-v1 record.
- The historical result passed the legacy-record verification path. The fresh
  result, calibration record, and reproducibility manifest passed the strict
  complete-bundle verifier together.
- A second write to the occupied fresh-output directory was rejected, proving
  the wrapper's no-silent-replacement behavior.
- Every published source-file copy under `historical/` was checked
  byte-for-byte against the supplied public source artifact. The omitted inert
  `.pyc` hash is retained in `historical/SOURCE-INVENTORY.md`.

## Commands exercised

```sh
PYTHON_BIN=/path/to/python3 ./run.sh verify-historical /path/to/pr362-checkout
PYTHON_BIN=/path/to/python3 ./run.sh reproduce /path/to/pr362-checkout /path/to/new-output
PYTHON_BIN=/path/to/python3 ./run.sh verify-bundle /path/to/new-output
```

The publication-candidate reproduction was executed after relocation with the
same recorded runtime, Python 3.12.6 with `cryptography` 46.0.5, and explicit
candidate/case/output arguments encoded by `run.sh reproduce`.

The reported absence of network access, live-system access, and arbitrary
candidate/source mutation depends on external execution assumptions. The
portable runner is not a network or filesystem sandbox. It checks exact Git
identity and clean status before and after execution and authenticates the
files named by the bundle, but it does not independently observe general
network activity or writes outside checked paths and does not claim container
isolation.

Repair-verification reproduction SHA-256 values:

- portable runner:
  `f966bc6c4039207a6de48b56b653b8b0bf738cfe5093ed5419517d866ed3fc0d`;
- `results.json`:
  `9b391d49717fd1a4a8c7dc679b8ec7ac1bf56d0e7e3eff9cba7b7cb9e93debd6`;
- `grader-calibration.json`:
  `70a0c55e597a27873d7d34fe14b8cce483e5704441f1c95919d6198de2fcd758`;
- `reproducibility-manifest.json`:
  `3a0be6747dacde4f22cabfe58b34079c882d4dcae2a99a68344e13faf7a0ab03`.

## Assurance decision

This evidence supports independent verification of the package as a portable
reproduction of the bounded #362 protocol pilot, subject to the external
execution assumptions above. It does not support calling the artifact a
completed Harbor agent Task or making claims about consumer-model performance,
general JCS, a second cryptographic implementation, SDK interoperability, live
behavior, general side effects, latency, memory, cost, merge, release, or
deployment readiness.

The next review decision is whether to accept the Draft `Task.md`, portable
runner adaptation, and non-normative evidence-format proposal for the #401
follow-up. A later Harbor/agent task would need its own reviewed
instruction, isolated environment and hidden verifier, plus an authorized model
run plan and full trajectory review.
