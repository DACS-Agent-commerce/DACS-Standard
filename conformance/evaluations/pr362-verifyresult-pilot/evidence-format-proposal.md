# Evaluation evidence fields for #270/#402 coordination

**Status: non-normative Draft proposal.** This document describes a possible
exchange shape for discussion. It does not change the DACS Standard, approve a
cross-repository schema, or require another repository to adopt these names.

| Proposed field | Meaning in this pilot | Constraint |
|---|---|---|
| `recordKind` | Protocol/conformance evaluation | Keep distinct from agent, SDK, workflow, and live-operation records |
| `caseId` | Stable local case identifier | Identifier does not imply global registry or normative status |
| `requirements` | Standard clauses interpreted by the case set | Cite the exact Standard revision; unresolved interpretation stays visible |
| `repository` / `revision` / `base` | Exact evaluated Git objects and origin | Verify objects and cleanliness before execution |
| `environment` | Runtime, dependency versions, oracle scope, externally supplied controls, and runner observations | Distinguish a sandbox-enforced property from an external execution assumption; record frozen/simulated/live boundary and material omissions |
| `expected` | Case-specific observable decision or invariant | Keep exact hidden truth with the Task/verifier when evaluating an agent |
| `forbiddenEffects` | Outcomes or mutations that invalidate success | Distinguish asserted protocol guards from general effect instrumentation |
| `actualEvidence` | Candidate calls, oracle observations, artifact hashes | Recompute independently where practical; do not trust self-report |
| `candidateDisposition` | Pass/fail for the evaluated candidate | Only for a valid run |
| `runValidity` | Valid/invalid plus classified reason | Setup, dependency, harness, verifier, or cleanup faults are not candidate failures |
| `status` | `pass`, `fail`, `blocked`, `skipped`, or justified `not_applicable` | Never convert unavailable evidence into pass or zero |
| `limitations` | Unassessed scope and assurance boundaries | Required beside every aggregate conclusion |
| `blockers` / `followUp` | Unresolved evidence and next review action | Do not imply authorization for live tests, writes, merge, release, or deployment |

The current pilot can populate these fields from `cases.json`, `results.json`,
`grader-calibration.json`, and `reproducibility-manifest.json`. It cannot
populate model, Harness, Harbor, SDK interoperability, general JCS, live-effect,
latency, memory, or cost evidence. Those remain absent or `not assessed`, not
passing defaults.
