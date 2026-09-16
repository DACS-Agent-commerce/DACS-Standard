# Task: DACS Standard PR #362 VerifyResult protocol evaluation pilot

**Status:** Draft

This is the control-plane specification for a reusable local author/reviewer
artifact. It is not copied into any evaluated-agent workspace. No Harbor task,
consumer-model trial, or real-agent trace is included in this package.

## Purpose and evidence

- **Work:** reproduce and independently check the bounded PR #362 protocol
  evaluation without changing its historical evidence.
- **Capability:** construct and review deterministic conformance evidence for
  signature-omitted `VerifyResult` identity, signature authentication, trusted
  recipe authority, reference closure, and retained-nonce rejection.
- **Why this matters:** the protocol change separates signed-artifact identity
  from signature authentication. A self-consistent producer and consumer can
  otherwise agree on the same defect.
- **Source evidence:** `historical/cases.json`, `historical/eval_pr362.py`,
  `historical/results.json`, `historical/grader-calibration.json`,
  `historical/reproducibility-manifest.json`, and
  `historical/proposal-401.md` are byte-preserved public source artifacts.
- **Repository provenance:** origin
  `https://github.com/DACS-Agent-commerce/DACS-Standard.git`, candidate
  `37010daa0a7c5900afcda6e314f1ae53f3afeb7b`, and base
  `ff8c289d22d07e09a1733b1ae7791100bfdbd923`.
- **Publication base:** this proposal directory is added from public `next` at
  `d45c0a292006b2fd2e40d2dbe0cd7ed518ad0f20`; that merge commit is not the
  candidate evaluated by the frozen historical result.
- **Difference from a completed agent benchmark:** this package reuses an
  existing protocol/conformance review pilot. It does not evaluate a model loop,
  tool-use policy, session, Harbor adapter, or consumer agent.

## One-time setup before offline evaluation

The runtime pin is **exactly CPython 3.12.6**, not any Python 3.12 release.
The runner refuses 3.12.14 and other unvalidated versions before executing a
case. Keep that pin when reproducing the historical evidence.

Prepare the public Git objects and runtime before the offline evaluation phase.
These setup commands may download public source and dependencies. With `uv`
already installed, run from this package directory; choose fresh directories
outside the candidate checkout:

```sh
PILOT_CANDIDATE=/absolute/path/to/new-pilot-candidate
PILOT_VENV=/absolute/path/to/new-pilot-venv

git init "$PILOT_CANDIDATE"
git -C "$PILOT_CANDIDATE" remote add origin https://github.com/DACS-Agent-commerce/DACS-Standard.git
git -C "$PILOT_CANDIDATE" fetch --depth=1 origin 37010daa0a7c5900afcda6e314f1ae53f3afeb7b
git -C "$PILOT_CANDIDATE" checkout --detach 37010daa0a7c5900afcda6e314f1ae53f3afeb7b
git -C "$PILOT_CANDIDATE" fetch --depth=1 origin ff8c289d22d07e09a1733b1ae7791100bfdbd923
git -C "$PILOT_CANDIDATE" cat-file -e ff8c289d22d07e09a1733b1ae7791100bfdbd923^{commit}

uv python install 3.12.6
uv venv --python 3.12.6 "$PILOT_VENV"
uv pip install --python "$PILOT_VENV/bin/python" -r requirements.txt
"$PILOT_VENV/bin/python" -c 'import platform, cryptography; assert platform.python_implementation() == "CPython"; assert platform.python_version() == "3.12.6"; assert cryptography.__version__ == "46.0.5"'
git -C "$PILOT_CANDIDATE" status --porcelain
```

The final Git status must be empty. A shallow candidate fetch alone does not
supply the required base object; the separate base fetch above is intentional.
An existing clean checkout with both exact objects and the named origin is
also valid. An already available CPython 3.12.6 environment with the pinned
dependencies may replace the `uv` setup.

After setup, run locally without network:

```sh
PYTHON_BIN="$PILOT_VENV/bin/python" ./run.sh verify-historical "$PILOT_CANDIDATE"
PYTHON_BIN="$PILOT_VENV/bin/python" ./run.sh reproduce "$PILOT_CANDIDATE" /absolute/path/to/new-output
PYTHON_BIN="$PILOT_VENV/bin/python" ./run.sh verify-portable "$PILOT_CANDIDATE" /absolute/path/to/new-output/results.json
```

## Author/reviewer input

Use a clean checkout of the named DACS Standard origin at the exact candidate
commit. Verify the preserved historical result by rerunning the deterministic
cases, then create a fresh result in a new output directory and verify it with
the portable runner. Report candidate disposition, run validity, case evidence,
grader-control evidence, exact artifact hashes, and all assurance limits. Do not
use network or live systems, modify the candidate checkout, replace historical
evidence, run a paid model trial, or claim Harbor/consumer-agent calibration.

There are no later turns, model prompts, secrets, credentials, or external
context. The package README supplies only the invocation syntax and public
scope boundary.

## Relevant author/reviewer conditions

- The portable runner accepts the candidate, cases, output, result, and
  historical-harness locations as explicit arguments.
- It loads the candidate's public generator and reference consumer, and uses a
  separately coded safe-subset hash/signature oracle for expected behavior.
- `PYTHONDONTWRITEBYTECODE=1` prevents import cache writes in the candidate.
- The recorded compatible runtime is CPython 3.12.6 with `cryptography` 46.0.5.
  A missing or materially different dependency is an unvalidated runtime, not
  evidence about the candidate.
- The task uses no judge, tool server, session memory, network, credentials, or
  live service.

## Environment and effects

- **Starting state:** an immutable frozen case document with SHA-256
  `cc07a0f2c6ca251a7afb1540d9b61780221eeec1c3639836c32294f995640f57`
  and a clean checkout at the exact origin/head/base above.
- **Visible information:** the package README, portable runner, frozen cases,
  and public files in the pinned checkout.
- **Hidden information:** none for this author/reviewer artifact. If converted
  into an agent Task later, `Task.md`, exact expectations, verifier controls,
  and historical results must stay outside the agent-visible environment.
- **Reads:** Git metadata and five pinned candidate files named in the
  reproducibility manifest.
- **Writes:** only the caller-selected fresh output directory. The three files
  written are `results.json`, `grader-calibration.json`, and
  `reproducibility-manifest.json`.
- **Prohibited effects:** any candidate or source-evidence mutation, network or
  live-system access, payment, delivery, chain activity, repository posting,
  merge, release, deployment, or credential access.
- **Isolation:** the candidate and cases are immutable inputs. A fresh output
  directory supplies run separation. Existing outputs are refused unless the
  caller explicitly invokes the runner's `--replace-output` option; the wrapper
  never uses that option.
- **Production difference:** all data is deterministic and local. No production
  provider, SDK implementation, chain, or effect instrumentation is present.

## Verification and scoring

Pass iff the pinned, clean checkout produces all eleven protocol-case outcomes
and the one historical-mutant detection defined by the frozen cases, the result
verifier accepts the untampered record, and all seven altered-report controls
are rejected.

| ID | Required result | Independent evidence | Pass condition |
|---|---|---|---|
| P1 | Exact provenance and input integrity | Git origin/head/base/clean checks; case and harness SHA-256 | Every pin and digest matches before cases run |
| P2 | Protocol behavior | Safe-subset oracle plus actual candidate `authenticate_result` and `evaluate` calls | All 11 `EVAL-*` records match their frozen expectations |
| P3 | Historical-defect sensitivity | Test-only full-signed-object-hash mutant | `CAL-001` detects signature-only identity instability without modifying the candidate |
| P4 | Evidence-record integrity | Deterministic rerun and stable-field comparison | Untampered record accepted; changed status, observations, count/order, head, or origin rejected in all 7 controls; verifier-only honest-fail record accepted and altered-pass record rejected |
| P5 | Honest assurance boundary | Manifest, README, and review evidence | No unsupported Harbor, model, SDK, JCS, live, or general side-effect claim |

For the exact candidate pilot, `candidateDisposition` is `pass` only when P2
and P3 pass. A protocol-case failure in an otherwise valid run is a valid
candidate result, not an infrastructure error. The reusable author/reviewer
artifact earns `artifactScore: 1.0` only when P1 through P5 all pass; otherwise
it earns `0.0` pending repair. This package does not alter the historical
independent review's evidence-quality score of 3/4.

Accepted operational alternatives are any clean checkout with the same exact
Git objects and origin, any writable fresh output directory outside the
candidate, and another Python executable only after compatibility is recorded.
Case order, case IDs, stable observations, expected decisions, and pin digests
are not interchangeable.

### Invalid-run conditions

A run is invalid and receives no candidate disposition when the checkout has a
wrong origin/head/base or tracked changes; the frozen case bytes differ; a
required file or dependency is missing; setup/import/execution fails; evidence
is missing or corrupt; the recorded harness digest cannot be resolved; the
runtime writes to the candidate; or any prohibited external effect occurs.
Missing/corrupt evidence remains an infrastructure/evidence failure rather than
a candidate failure. The portable runner intentionally raises on these
conditions instead of synthesizing a zero score.

## Fairness and leakage

- The task is solvable from the packaged runner/cases and the public pinned
  checkout; no private fact or external service is required.
- Expected behavior is recomputed from an independent safe-subset oracle and
  checked against actual candidate calls rather than trusting a producer's
  self-report.
- Byte-preserved historical results are verification targets, never inputs to
  the candidate consumer.
- Likely shortcuts include checking only result metadata, trusting case IDs,
  hashing the signed object, trusting the artifact's signer as authority, or
  treating a passing producer/consumer pair as independent evidence. The
  protocol and grader controls are designed to expose those shortcuts within
  this scope.
- A realistic wrong result changes or empties a stable case observation while
  retaining plausible metadata. A prohibited collateral change modifies the
  candidate or preserved source evidence.

## Limits and open decisions

- Coverage is exactly 11 protocol cases plus 1 historical mutant and 7
  altered-report controls.
- The independent oracle covers ASCII strings/member names, booleans/null,
  arrays/objects, and integers with magnitude at most 2^53-1. It does not cover
  a second cryptographic implementation, general Unicode/fractional JCS, or raw
  byte admission.
- There is no second SDK, general interoperability result, live behavior,
  production effect tracing, performance result, Harbor run, paid model trial,
  consumer-model trace, or scored agent capability evidence.
- The evaluation-record vocabulary and fields are a coordination proposal for
  #270/#402. They do not make a normative format decision.
- Human review remains needed before this Draft can be promoted, before a
  Harbor task is built, or before a reusable record format is adopted.
- Run plan: deterministic local controls only; no model, judge, paid trial,
  live dependency, or additional cost is authorized or claimed.
