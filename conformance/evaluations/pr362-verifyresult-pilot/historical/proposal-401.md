We propose three connected evaluation frameworks for DACS: the Standard, the SDK, and our development workflow. The aim is to make quality measurable, identify gaps, and support review with reproducible evidence.

This is a proposal for discussion. Scores, weights and thresholds should be calibrated through a pilot before becoming acceptance requirements.

### Shared principles

- **Separate correctness from quality scores.** A high readability or efficiency score cannot offset a protocol violation or unauthorized effect.
- **Attach evidence to conclusions.** Record the revision, scope, environment, checks and limitations behind each result.
- **Distinguish missing evidence from failure.** Use `pass`, `fail`, `blocked`, `skipped`, and justified `not applicable` outcomes for executable checks.
- **Preserve assurance boundaries.** Offline simulation, local-chain testing and authorized live execution establish different things.
- **Evaluate supported scope explicitly.** Do not imply full protocol coverage from a passing subset.
- **Keep human approval separate.** Evaluation results do not replace repository review or deployment authorization.

### 1. Standard evaluation

The Standard should define coherent, testable behavior that independent implementers can understand consistently.

| Dimension | Evaluation questions |
|---|---|
| Normative precision | Are actors, obligations, conditions and precedence explicit? |
| Completeness | Are supported inputs, outputs, failures and state transitions defined? |
| Internal consistency | Do prose, schemas, examples and conformance vectors agree? |
| Readability | Can readers locate, understand and explain requirements without undocumented context? |
| Implementability | Can implementations satisfy requirements using the information the protocol makes available? |
| Protocol efficiency | Are required computation, storage and network operations practical and bounded where necessary? |
| Security properties | Are authority, trust assumptions and failure behavior explicit? |
| Evolution and compatibility | Are versioning, extensions and reader/writer compatibility rules unambiguous? |

Readability should assess direct language, consistent terminology, logical ordering, visible requirements, useful examples and accurate cross-references. Shorter text is valuable only when it preserves precision.

Proposed evaluation methods:

- **Independent interpretation:** Ask readers to derive an algorithm and acceptance cases from a section. Record divergent interpretations and missing information.
- **Requirement traceability:** Map each normative requirement to executable cases or a justified review method. Map each conformance assertion back to its requirement.
- **Interoperability:** Have independent implementations exchange artifacts and compare acceptance, rejection and recovery decisions.
- **Complexity assessment:** Evaluate the work required as artifact counts, histories and participant counts grow.

Unresolved contradictions or ambiguity affecting authorization, payment or state transitions should block the affected conformance claim. An SDK agreeing with its own fixtures is insufficient evidence of independent interoperability.

### 2. SDK evaluation

The SDK should implement its named Standard revision correctly, expose usable public APIs, and remain understandable and efficient.

| Dimension | Evaluation questions |
|---|---|
| Protocol correctness | Does behavior match applicable requirements and independently sourced vectors? |
| Lifecycle completion | Do supported buyer/seller flows produce the expected states and verified artifacts? |
| Authorization boundaries | Are invalid signatures, identities and evidence rejected before prohibited effects? |
| Recovery | Can interrupted sessions reconcile without duplicate payment or delivery? |
| API and type design | Are contracts clear, invalid states constrained and package boundaries respected? |
| Readability and maintainability | Are responsibilities, invariants, state transitions and failure paths understandable? |
| Runtime efficiency | Are latency, memory, parsing, hashing and lookup costs appropriate as inputs grow? |
| Resource discipline | Are retries, concurrency, external calls and persistence operations controlled? |
| Test quality | Do tests use meaningful oracles, realistic failures and observable effects? |
| Developer experience | Can users complete supported tasks through documented public APIs? |

The existing conformance, lifecycle, recovery and package-consumer checks provide starting material. The first step is to map them to requirements and identify uncovered behavior.

Proposed benchmark scenarios include:

- Bundle verification with increasing artifact counts.
- Discovery and validation with increasing listing counts.
- Parsing near supported input limits.
- Recovery with growing session histories.
- Concurrent sessions and unavailable dependencies.

Record latency distributions, peak memory, external calls, storage operations and retries under a specified runtime and workload. Set performance budgets after establishing repeatable baselines. Optimizations must preserve authentication, freshness, finality and replay protections.

For developer experience, use tasks such as installation, listing publication/discovery, Vet rejection, completed commerce, crash recovery and bundle verification. Agent-assisted runs should record the model, tools, documentation, prompt and execution budget, and use independent acceptance checks.

### 3. Development workflow and operations evaluation

This framework evaluates how work reaches an accepted outcome. It should reward reliable completion, effective review and responsible resource use.

| Dimension | Evaluation questions |
|---|---|
| Completion | Was the authorized outcome completed, or was remaining work accurately preserved and explained? |
| Working efficiency | Did exploration, tool calls, tests and handoffs contribute to the outcome? |
| Rework | Were additional cycles caused by missed requirements, regressions, incomplete evidence or changing scope? |
| Rejection handling | Were review feedback, CI failures and execution refusals classified and handled correctly? |
| Coordination | Were ownership, dependency order and handoffs clear, with existing work preserved? |
| Verification | Did checks cover the affected behavior and exact reviewed revision? |
| Resource use | What time and cost were required per accepted outcome? |
| Release discipline | Were artifact identity, required approvals, provenance and recovery arrangements established? |
| Operational readiness | Where applicable, are deployment health, failure detection and rollback procedures verifiable? |

**Rejection counts should never be scored without context.**

| Event | What to assess |
|---|---|
| Review rejection | Missed requirement, discovered defect, unresolved design decision or changed scope |
| CI failure | Implementation regression, infrastructure failure, dependency issue or flaky test |
| Permission or safeguard refusal | Whether the constraint was already known and the blocker was handled appropriately |
| Approval request | Whether approval was required or authorization already covered the action |

A justified refusal or a reviewer detecting a defect can demonstrate a successful control. Evading a safeguard, making an unauthorized mutation or falsely claiming successful verification should fail the relevant workflow gate.

Efficiency also needs context. Repeating tests after a change or failure is useful; rerunning unchanged checks without an unresolved question is usually waste. Parallel work should be assessed by useful outcomes and coordination cost, not worker count.

Measure active work separately from external waiting. Compare similar task classes and record scope changes. Operational evaluations should use existing evidence or authorized environments; this proposal does not authorize production testing.

### Scoring approach

Use the following shared anchors for qualitative dimensions, supplemented by dimension-specific examples:

| Score | Meaning |
|---|---|
| 0 | Demonstrated serious deficiency |
| 1 | Major weaknesses requiring substantial rework |
| 2 | Adequate in part, with material gaps |
| 3 | Meets the defined expectations with evidence |
| 4 | Demonstrably exceeds expectations in a useful, reproducible way |

Use **not assessed** when evidence is missing. Do not convert missing evidence to a zero or passing score.

Report dimension scores separately during the pilot. Avoid an overall weighted score until we understand whether it hides important weaknesses. Each deduction should include evidence, its practical consequence and an acceptance condition for improvement.

### Evaluation records

Each evaluation should identify:

- Stable case ID, requirement and purpose.
- Repository commit, Standard revision and supported profile.
- Environment, inputs, workload and any injected fault.
- Expected outputs and forbidden effects.
- Grader or reviewer, result and evidence.
- Limitations, blockers and follow-up action.

Normative fixture provenance should identify the source revision. Any fixtures ahead of the SDK’s global Standard pin must retain their separate provenance.

### Making the framework operational

The rubrics need supporting infrastructure so results are reproducible, independently assessed and useful for improvement. The following are proposed capabilities, not prerequisites for starting the pilot:

- **Versioned evaluation cases and ownership.** Maintain representative tasks, known defects and failure scenarios with named owners, expected outcomes and revision history. Keep held-out cases separate from examples used to improve prompts, skills or implementations. Private cases remain in their authorized venues.
- **Calibrated graders and independent acceptance.** Have reviewers score the same examples, resolve disagreements and assess missed defects and false positives where applicable. Calibrate model-assisted grading against human-reviewed examples. The producing agent's confidence or self-reported success is not acceptance evidence.
- **Reproducible run records.** Extend evaluation records with model/version, prompt and skill revisions, tool configuration, dependency versions, permissions and execution budget. Record repeated-run variability and unavailable measurements honestly; do not retain secrets or private runtime state merely for reproducibility.
- **Change control and rollback.** Review and evaluate material changes to models, prompts, skills and tool access against the same baseline. Retain previous configurations and a rollback path. Configuration changes do not expand task authorization.
- **Execution boundaries.** Define task permissions, isolated workspaces, secret handling and treatment of untrusted repository or tool content. Preserve existing safeguards and approval gates; evaluation runs do not authorize live testing or production changes.
- **Operational feedback.** Turn escaped defects, failed handoffs and avoidable rework into regression cases. Measure the complete cost of an accepted outcome, including human review effort and repair rounds, while separating external waiting and recording defects discovered after acceptance.
- **Adoption and exception ownership.** Name who maintains cases, accepts results, approves time-bounded exceptions and decides whether a model or workflow change is an improvement. Exceptions must identify their scope, rationale and remaining risk, and cannot override existing authorization or approval requirements.

For the initial pilot, implement only a small versioned benchmark, grader calibration and a reproducible run record. Use that evidence to decide which additional infrastructure is justified, rather than making the entire framework a prerequisite for useful evaluation.

### Proposed pilot

1. Inventory existing SDK checks and build a requirement-to-evaluation matrix.
2. Select a bounded Standard section and supported SDK flow that implement the same requirements.
3. Evaluate readability, correctness, recovery and efficiency for that scope.
4. Apply the workflow rubric to a small sample of comparable completed tasks.
5. Have independent reviewers score the same samples and examine disagreements.
6. Refine the anchors, establish baselines and propose any acceptance thresholds.
7. Store agreed criteria in the relevant repositories and track implementation gaps through issues.

The pilot should produce scorecards, an evidence index, a gap list and proposed follow-up work. It should not claim comprehensive Standard or SDK coverage.

### Questions for maintainers

- Are these dimensions appropriate, and which important qualities are missing?
- Which Standard section and SDK flow should we pilot?
- Which conditions should block acceptance, and which should remain advisory?
- What workloads represent realistic SDK use?
- What evidence can we retain for workflow evaluation without exposing credentials or private runtime state?
- Who should own the rubrics and review changes to them?

Existing repository approval policies remain in force, including the distinct Standard and SDK human-review gates and separate authorization for deployment.
