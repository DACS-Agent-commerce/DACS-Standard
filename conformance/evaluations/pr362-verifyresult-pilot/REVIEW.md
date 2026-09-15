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
- The byte-preserved historical record passed a deterministic rerun against the
  byte-preserved historical harness.
- The portable fresh run passed 12/12 cases: 11 protocol cases and one
  historical-defect mutant.
- The regenerated evidence-checker calibration accepted the untampered baseline
  and rejected 7/7 altered-report controls.
- Its verifier-only disposition control accepted an honestly reported
  deterministic failure and rejected the same record after its aggregate was
  changed to `pass`; candidate code and frozen cases were not mutated.
- Fresh and historical case-result arrays are byte-equivalent after JSON
  extraction. At record level, only run timestamps and the intentionally new
  portable-harness digest differ.
- Both the historical and portable fresh results passed the portable verifier.
- A second write to the occupied fresh-output directory was rejected, proving
  the wrapper's no-silent-replacement behavior.
- Every published source-file copy under `historical/` was checked
  byte-for-byte against the supplied public source artifact. The omitted inert
  `.pyc` hash is retained in `historical/SOURCE-INVENTORY.md`.

## Commands exercised

```sh
PYTHON_BIN=/path/to/python3 ./run.sh verify-historical /path/to/pr362-checkout
PYTHON_BIN=/path/to/python3 ./run.sh reproduce /path/to/pr362-checkout /path/to/new-output
PYTHON_BIN=/path/to/python3 ./run.sh verify-portable /path/to/pr362-checkout /path/to/new-output/results.json
```

The publication-candidate reproduction was executed after relocation with the
same recorded runtime, Python 3.12.6 with `cryptography` 46.0.5, and explicit
candidate/case/output arguments encoded by `run.sh reproduce`.

Relocated reproduction SHA-256 values:

- portable runner:
  `af18aa44c1d9ac479172cc1535a249147f6c001ed0ad9b0051c867810ad8a421`;
- `results.json`:
  `7cf2257632739d5243ad9c0cdc7b1ff6fa0f0deb4beb453d7577e6d5b18e3e1f`;
- `grader-calibration.json`:
  `4172de6b9785550f26adee0683417692af0629a08684cabfa75377c7eae3c5f0`;
- `reproducibility-manifest.json`:
  `008a15256c732eba1be0f133a339cc069078e9f03fe1321b14f653d50eb14327`.

## Assurance decision

This evidence supports acceptance of the package as a portable reproduction of
the bounded #362 protocol pilot. It does not support calling the artifact a
completed Harbor agent Task or making claims about consumer-model performance,
general JCS, a second cryptographic implementation, SDK interoperability, live
behavior, general side effects, latency, memory, cost, merge, release, or
deployment readiness.

The next review decision is whether to accept the Draft `Task.md`, portable
runner adaptation, and non-normative evidence-format proposal for the #401
follow-up. A later Harbor/agent task would need its own reviewed
instruction, isolated environment and hidden verifier, plus an authorized model
run plan and full trajectory review.
