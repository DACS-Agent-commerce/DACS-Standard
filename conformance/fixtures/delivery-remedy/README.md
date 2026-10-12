# Delivery-or-remedy candidate fixtures

**Status:** non-normative review tooling for [issue
#356](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/356). These
files do not change DACS conformance, register an ERC-8183 rail, or make any
deployment available.

The pack turns the pre-normative
[delivery-or-remedy candidate](../../../docs/delivery-or-remedy-candidate.md)
into executable review evidence:

- `candidate-vectors-v0.1.json` contains deterministic, signed synthetic
  lifecycle inputs for full release, evaluator rejection/refund before or
  after submission, pre-submission expiry, and post-submission expiry. Its
  cases cover non-circular delivery binding and relayed evaluator execution.
  Negative cases cover escrow-phase pairing, exact hash-to-`bytes32` mapping,
  role and account collisions, deadline divergence, and premature expiry
  recovery. They also cover one terminal per decision, native job, and
  terminal event, release/refund direction, full-budget and zero-fee
  requirements, and the four-result verification boundary.
- `deployment-capabilities-v0.1.json` derives DRC-1 through DRC-13 outcomes
  from explicit capability evidence. It includes a synthetic all-pass control
  that is permanently marked `fixtureOnly`, individual rule regressions, and
  a pinned assessment of
  [`erc-8183/base-contracts@142e669`](https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183.sol).
  The pinned reference is `rejected`, remains unregistered, and is never
  reported as available. Its source facts fail DRC-1 through DRC-7 and DRC-13;
  DRC-8 and DRC-10 through DRC-12 stay unknown without deployment evidence.
  The manifest records both halves of DRC-13 from the source as `false`. There
  is no separately enforced per-job submission cutoff
  (`submissionCutoffEnforced`; DREB-13). Expiry recovery does not open at the
  evaluation deadline (`expiryRecoveryDeadlineEnforced`; DREB-15): `claimRefund`
  on a `Submitted` job reverts until `expiredAt + EVALUATION_GRACE_PERIOD`, a
  one-hour constant (`ERC8183.sol` lines 78 and 869–870), and on a `Funded` job
  with a pending claim it reverts with `PendingClaimExists` (lines 871–872).

The synthetic control proves only that the checker can observe all thirteen
positive capability predicates. Those predicates come from the manifest
itself, so the capability evaluator always reports
`registrationEligible: false`. A manifest's own `fixtureOnly` and
`registrationStatus` labels cannot change that. Registration needs
independently resolved deployment and registry facts that this pack does not
model.

The protocol verifier requires the finality records embedded in signed funding
and terminal artifacts to use the exact DACS-4 `SettlementFinalityRecord`
`block-depth` shape at the rail's finality depth. It checks those records
against non-empty canonical event references plus resolver observations of
block identity, timestamp, and confirmation depth. Event finality, submission
timing, expiry-recovery timing, and Vet freshness are derived from those
observations.

Native observations come from a synthetic fixture resolver whose key the
verifier pins (DRV-1). Each lifecycle carries one `resolverEvidence` record,
signed under `dacs-x-delivery-remedy-fixture-resolver:v1:`. The record binds
the job, the agreement-selected rail definition, the native contract and job,
and the exact `nativeEventInputs`. It also carries:

- `terminalCall`: the terminal transaction's native caller, outer submitter,
  and caller account type (DREB-18, DREB-21, DREB-22);
- `priorTerminals`: the complete set of terminal transactions the resolver
  observed before this lifecycle's terminal event for its native job or
  decision, each with its native job, event identity, and decision hash
  (DRD-8, DRL-4, DRT-4);
- `nativeState`: the resolved native job state and capability facts read by
  DREB-13, DREB-15, DREB-16, DREB-20, DRL-7, and DRT-7;
- `deliveryDigestAnchor`: the block in which the exact delivery digest was
  anchored, or `null` when the resolver has no such evidence (DRP-9);
- `statuses`: the resolver's availability outcomes.

The verifier reads these facts only from the signed record.

The escrow job, both escrow phases, and the native target follow the
agreement-selected rail. Evaluation results, decision dispositions, and the
terminal evidence's `terminalState` each have a closed value set. A value
outside the closed value set, including an array, an object, or an unknown
string, is malformed input and returns `error` before any stage reads it.
A number outside the CORE §B.2 profile (NaN, an infinity, or an integer
beyond 2^53 − 1) is malformed too, as is a boolean or any float, including an
integral float such as `8453.0`, where an integer is read, and a rail
`paymentToken` or `contractAddress` that is not a lower-case `0x` EVM address.
So is a lifecycle that nests arrays and objects more than 64 deep:
the pack's deepest lifecycle nests 7, and the bound is checked iteratively
before anything is hashed, because canonicalisation recurses once per level.
A batch gives one malformed lifecycle its own `error` and still judges the
others. The command line lists a pack it cannot parse as an error, and a pack
file nested more than 64 deep too. It checks that bound on the parsed value,
so the error is the same whether or not the interpreter's JSON parser refuses
a deep text itself (Python 3.12 does; 3.13 and later can parse it). Called
directly, `verify_vector_pack` and `verify_deployment_pack` check the same
bound on the whole pack before they copy or hash it, and return a pack that
exceeds it as a pack error; they do not judge its lifecycles one by one.
The verifier reports malformed input (candidate §9 step 2) under DRV-3, the
malformed-encoding rule: nothing is repaired before hashing or comparison.
DRV-2 keeps unavailable or inconsistent RPC data `indeterminate`, as for an
unavailable `agreementResolution`. The candidate names no rule for an
unsupported §9 step-1 artifact discriminator (a phase kind, an overlay,
resolver-evidence or deployment-manifest version, or a capability profile),
so those `error` cases keep the fixture label `DRV-2`. The step-1 label is
pending #371's named §9 step-1 rule. An unsupported `deliver-*` kind as the
one delivery is not such a case: DRP-3 requires a supported delivery step,
so it is `rejected` under DRP-3. The pack supports only the
`deliver-storage-program` kind it models, so a `deliver-entitlement` or
`deliver-attested-payload` step is rejected under DRP-3 too. A resolver status whose applicability
contradicts the lifecycle is `rejected` under DRV-6: the pinned resolver's
authenticated record contradicts the signed terminal and delivery evidence.
That holds for an applicable status marked `not-applicable` and for an
inapplicable one marked `verified` or `contradictory`. An inapplicable
`unavailable` is not a contradiction: it asserts nothing, and candidate §9
step 5 makes only required evidence `indeterminate`. The candidate's DRP-7,
DRT-3 and DRT-12 make delivery evidence and `decisionRef` absent, but they
do not govern the resolver record. So the applicable checks decide the
verdict (DRV-7). Only `accept` with `release-to-provider` and `reject` with
`refund-to-client` can authorize a terminal action. A release decision needs
delivery evidence (DRD-3), and a decision without delivery evidence must rest
on a DisputeOutcome (DRD-9). The native job description (DREB-1) is read
from the authenticated creation event.

Every artifact describes the overlay's job. The bilateral agreement must be
the one for that `jobId`, with the overlay's buyer and seller in their roles
(DRA-1). The evaluation and decision must reference the exact escrow job
(DRD-8). Funding evidence must bind the exact overlay (DRF-1); another signed
artifact that binds a different overlay is rejected under DRV-4.

The overlay's `budgetBaseUnits` must be the bilateral agreement's price
converted with the rail's pinned token decimals (DRA-10), as DACS-4 §9.5.2
steps 2 and 3 convert a `PriceTerm`. The price currency must be the rail's
`paymentTokenSymbol`, and `amount × 10^tokenDecimals` is computed exactly from
the CD-1 decimal text as string arithmetic: the fraction is padded to
`tokenDecimals` digits, leading zeros are stripped, and the result is compared
with `budgetBaseUnits` as minimal decimal text, with no integer or float
conversion and no length limit. A wrong amount, currency, or decimals, or a
zero price (DACS-4 §9.3 requires an agreed `PriceTerm.amount` strictly greater
than zero), is rejected under DRA-10. A price with more fractional digits than
the token carries is an `error` under DRV-3: DACS-4 §9.13 makes excess
precision an error, and no base-unit budget equals it. A price carrying
DACS-4's optional `unit` qualifier is an `error` too. A qualifier such as
`per-call` makes `amount` a rate per unit rather than the agreed total, and
neither DACS-4 §9.5.2 nor DRA-10 defines how a rate converts to one escrow
budget, so the verifier does not read such a price as the budget's amount.

Delivery evidence is a DACS-4 §9.7 delivery `SettlementEvidence` with the
members a storage-program delivery carries: `evidenceVersion`, `jobId`,
`phase`, `outcome`, `reason` exactly on a failure, `deliverableContentHash`,
`deliverableAnchor`, `observedAt`, and `signature`. A success carries the
content hash and anchor (DACS-4 §9.6.1). A failure may omit either or both,
since §9.7 makes them optional; a failure without a content hash binds no
delivered-artifact input. Any other member is malformed input. That fixture
shape has no `attestationRef` (DACS-4 DPA-6) and no entitlement binding, so
the pack models only storage-program delivery. An attested-payload or
entitlement delivery never verifies: its step is rejected under DRP-3, and
the signed evidence must name the agreed step's kind (DRE-2), so relabelling
a step cannot skip the anchor checks. Every anchor is checked whatever kind
a producer names. §9.7 has no phase-index member, and DACS-4 defines no logical address
for delivery evidence. The record is bound to its phase through the session
instead: the pipeline has exactly one delivery step, at the overlay's
`deliveryPhaseIndex` (DRP-3, DRA-11), and the record's `jobId` and `phase`
must be that job and that step's kind (DRE-2, DRP-7).
`deliverableContentHash` must be the content hash of the delivered-artifact
input. DACS-4 §9.6.1 writes the deliverable as a Storage Program at
`dacs4:deliverable:{jobId}`, but its step 5 elides the anchor locator
(`locator: …`), so the text does not fix the locator form. A storage-program
success must carry `kind: "storage-program"` and one of two locator forms.
The logical form `dacs4:deliverable:{jobId}` must name the overlay's `jobId`.
The logical form is a fixture choice, not a DACS-4 §9.6.1 requirement. A
native Storage Program address, `stor-` followed by exactly 40 lower-case
hexadecimal digits (DACS-5 §10.4.2), is the form the lifecycle walkthrough
emits; the verifier checks only its kind and syntax. DACS-5 §10.4.2 tells the
two `stor-` forms apart by length: 64 digits is a logical address, such as a
role bundle's, and DACS-4 §9.6.1 gives the deliverable no logical address in
that form. Another kind, another job's logical address, a 64-digit or
upper-case `stor-` value, or a locator in neither form is rejected (DRE-2). The verifier resolves
neither form, so it does not prove that a Storage Program exists at the
address or holds the content-hashed payload. It also cannot tell whether a
native address is this job's Storage Program, because the fixture models no
logical-to-native resolver. The delivery outcome does not
choose the disposition; the evaluation under the bound rule does. Each
evaluation subject reference must resolve to a lifecycle record the verifier
authenticated: the escrow job, the funding evidence, or the delivery evidence
(DRE-3). Both first-profile disclosure policies admit those records. Any other
subject is `indeterminate` (DRE-5), because public resolution and the
explicit-party supply proof (DRQ-2) are not modeled.

Delivery/submission ordering (DRP-9) rests on authenticated evidence that the
exact delivery digest was fixed before the native submission. The resolver's
`deliveryDigestAnchor` must name this delivery's digest in an earlier block
than the submission event, with an earlier block time, and the signed
delivery evidence cannot record a later time than the anchor. Without an
anchor, or with one in the submission's own block, the
result is `indeterminate`. The synthetic submission transaction identity
commits to its deliverable argument, as an EVM transaction hash commits to its
calldata. The verifier does not search delivery content for encodings of the
submission.

Replay state belongs to the verifier. Callers pass a `DecisionLedger` to
`evaluate_lifecycles`, which evaluates a set of lifecycles together, or to
`evaluate_protocol`, which evaluates one. Each lifecycle that passes every
check before the replay comparison records its terminal: native job, terminal
event and its authenticated position, decision, and attested history.
Verifying the same terminal again is idempotent. Two different terminals
conflict when they share a decision (DRD-8) or a native job (DRL-4), or when
one terminal event settles two native jobs (DRT-4). The pinned resolver
attests `priorTerminals` as the complete earlier history, so a conflict with
one of them is rejected.

For conflicts with a terminal in the ledger, the verifier chooses the earlier
terminal from authenticated canonical event position: block number, then the
block-scoped log index, which also orders transactions within a block. The
later terminal is rejected. The earlier one holds only if the later
terminal's attested history names it. Otherwise the resolver's records
contradict each other, and the earlier one is `indeterminate`. When the
positions cannot order the pair, both are `indeterminate`. One event claimed
by two native jobs is rejected for both.

`evaluate_lifecycles` records every terminal before it compares any, so its
verdicts are the same in every order of its input. `evaluate_protocol` judges
one lifecycle on the terminals already known. When the resolver's records
agree, a later terminal carries the earlier one in its attested history and
is rejected even if it arrives first, so arrival order changes no verdict.

When the resolver's records contradict each other, a verdict issued before
the contradicting record arrived can no longer stand. The ledger keeps the
verdict it issued for each recorded terminal. An evaluation that changes an
earlier verdict lists the change under `revises` in every result it returns:
the terminal (its `priorTerminals`-style identity, block, and attested
history), the `previous` verdict, and the verdict that replaces it. A
revision never upgrades a verdict: `verified` can become `indeterminate` or
`rejected`, and `indeterminate` can become `rejected`. A later arrival that
conflicts with a verified terminal is never `verified`, so two conflicting
terminals never both verify in one ledger. The verdicts issued, with their
revisions applied, are the verdicts of evaluating everything seen so far as
one set, whatever the arrival order. A verdict therefore holds for the
evidence evaluated so far, and a caller that acts on a `verified` verdict
before the whole set is known must also act on its revisions. The verifier
never consults arrival order itself.

The ledger is an in-memory, single-process fixture. It is not durable, and it
does not provide concurrent or cross-process one-use enforcement; none is
claimed.

Each base lifecycle is its own job, so the standalone positive vectors verify
in any order and any number of times through one ledger. The pack runner gives
each vector a fresh ledger. A vector's `evaluatedWith` list names other
vectors evaluated together with it, as one set.

The remaining `native` fields are producer projections that the verifier pins
to authenticated values:

- chain, contract, and runtime code, to the escrow job and selected rail;
- client, provider, evaluator, cutoff, and `expiredAt`, to the signed overlay,
  whose values the authenticated creation event also carries (DRJ-3);
- token and budget, to the rail and overlay;
- payout receiver, to the seller account; a release's recipient is
  authenticated by its terminal event;
- `fundedAtSec`, to the funding event;
- deliverable and reason, to recomputed content hashes; the submission and
  terminal events carry the authenticated values;
- terminal state and action, and the portable state history, to the signed
  terminal evidence and the authenticated submission classification.

Some lifecycle statements are not yet derived from authenticated evidence.
In `executionContext`, `fundingFinalizedBeforeDelivery` (DRP-6),
`dacs5PurchaseCount` (DRP-8), `acceptedRails` (DRP-10), the commitment
receipt's `status` (DRP-11), `terminalGate`, and `lateDeliveryDisabled`
(DRP-12) are orchestrator statements whose values are checked but not proven. Their vectors exercise the
predicate, not the evidence behind it, so these rules are listed in the
`promotionBlockedProofs` ledger described below.

Each lifecycle fixture also carries `reproductionInputs`: the public test-key
seeds, role-bundle and Vet-record bodies, evaluation rule, delivered artifact or
dispute case, runtime-bytecode preimage, and native event/log observations with
their transaction and block-hash preimages. The verifier independently
recomputes their keys, hashes, references, event identities, chain binding,
ordering, and positive bindings. It also derives policy from the authenticated
rail definition and checks accountability projections against authenticated
findings. These are synthetic inputs, not a live chain resolver, production
identity registry, or eligible deployment.

The resolver's `statuses`, `nativeState`, and `deliveryDigestAnchor` objects
are explicit fixture boundaries for authenticated resolver outcomes such as
registry availability, cross-substrate ordering, native capability facts, and
delivery-digest fixation. The anchor is synthetic and non-normative: it
demonstrates the verdicts that such evidence supports, not its normative
proof shape. Each status has to
match the lifecycle's applicability: an applicable status is never
`not-applicable`, and an inapplicable one is `not-applicable` or
`unavailable`. An authenticated status that does not match is a DRV-6
contradiction. Funding and terminal finality are still
derived from the observations and embedded records, not from the status. The
pack exercises unavailable and contradictory outcomes but does not claim to
implement those external resolvers.

A record that a signed artifact references but the caller did not supply is
`indeterminate` (candidate §9 step 5, §11.3 case 5), even when every resolver
status is available. That covers delivery evidence the terminal references
for an authenticated native submission (DRE-5), a decision an evaluator
terminal references (DRD-4), and the evaluation or DisputeOutcome a decision
rests on (DRD-2). A record that something present contradicts is still
rejected. Examples are a released terminal with no decision reference, a
decision reference on an expiry refund (DRD-7), delivery evidence on a
lifecycle with no native submission (DRT-12), and a resolver record that
marks the evidence not applicable (DRV-6).

The fixture resolver key is synthetic and its seed is
derived in the public generator. The pack therefore demonstrates verifier
behavior, not a live resolver. Promotion still requires real authenticated
resolver evidence and a second implementation. Nothing in this pack can register
a rail or authorize a transaction.

Each negative is a consistent signed lifecycle plus one edit. The generator
checks, before it writes or checks the pack, that each negative becomes
`verified` once the guard that decides it is removed. Any other outcome,
including an exception, fails the check, with two listed exceptions.
`FOLLOW_ON_FINDINGS` lists 21 negatives whose single defect reaches one exact
second finding once its guard is removed. Some of those defects break a
second rule. For a record that was not supplied, a later check finds the
lifecycle inconsistent instead. `STRUCTURAL_NEGATIVES` lists 12 negatives that
remove or malform a structure the verifier reads. Without their guard the
verifier raises, so isolation is not claimed for them.

The unit suite also requires every verifier guard to be decided by a vector
or by an exact-finding shape case.

Every candidate rule ID is accounted for mechanically. Each executable vector
lists the rules its positive or negative path exercises. These lists are
rule-accounting tags, not proof that a guard ran; the guard audit above is
that proof.

The pack's `promotionBlockedRules` ledger names the remaining rules and the
concrete capability needed before they can be promoted. Those entries are
intentionally not marked as executed: they cover SR-2 logical addressing and
anchoring, live proxy/authority resolution, explicit-party evidence proof,
retry orchestration, and the future transcript and post-terminal
dispute-revision profiles. The test suite fails if a spec rule is absent from
both sets or appears in both. No verifier finding reports a promotion-blocked
rule.

The separate `promotionBlockedProofs` ledger names rules whose vectors run
against a synthetic evidence shape whose normative proof shape is undefined.
It holds DRP-9, whose digest anchor is a fixture boundary, and DRE-2 and
DRP-7, whose delivery evidence is bound to its phase through the session
because DACS-4 defines no logical address for delivery evidence. It also holds
DRP-6, DRP-8, DRP-10, DRP-11, and DRP-12, whose `executionContext` inputs are
orchestrator statements rather than authenticated evidence. Finally, it holds
DRA-14. The pack checks the bound values fixed at creation and funding, but
it models no later replacement, so no vector shows a mutable replacement
preventing progression.

### Synthetic proof limits

Beyond the two ledgers, these assumptions come from the synthetic resolver or
the fixture itself. The vectors depend on them and do not prove them:

- **`priorTerminals` completeness** (DRD-8, DRL-4, DRT-4). The verifier treats
  the resolver-attested `priorTerminals` as the complete set of earlier
  terminal transactions for the native job, decision, and terminal event. A
  terminal the resolver omits is detected only if it is evaluated in the same
  ledger. No normative completeness proof, such as an authenticated range or
  index proof, is defined or checked.
- **Native event-set completeness** (DRT-12). The verifier derives the
  pre/post-submission classification from the resolver's event set. It treats
  a lifecycle with no submission event as never submitted, so it assumes the
  resolver-attested `nativeEventInputs` include every submission event for the
  native job. A submission the resolver omits makes a post-submission refund
  look pre-submission. No completeness proof for the event set is defined or
  checked.
- **Block-scoped log index** (DRD-8, DRL-4, DRT-4). Conflicting terminals are
  ordered by authenticated block number, then log index. This assumes the log
  index is block-scoped, as EVM receipts report it. A transaction-scoped index,
  or a ledger without block-scoped indexes, needs its own position rule and is
  not covered.
- **Deliverable anchor locator** (DRE-2, DRP-7). The `dacs4:deliverable:{jobId}`
  locator is compared, not resolved, so the Storage Program's existence and
  contents at that address are not proven.
- **Native locator binding** (DRE-2, DRP-7). A native `stor-…` locator is
  accepted on its kind and syntax only. The binding from
  `dacs4:deliverable:{jobId}` to that native address is not modelled, so a
  native address of another job's Storage Program would be accepted. Proving it
  needs a published logical-to-native binding and a resolver.
- **Currency binding through `paymentTokenSymbol`** (DRA-10). Candidate §8.4
  pins `paymentToken` and `tokenDecimals` but no token symbol, and DRA-10
  says nothing about currency. The pack takes the currency check from DACS-4
  §9.5.2 step 2, which matches `amount.currency` against `rail.asset.symbol`,
  and gives the fixture rail a `paymentTokenSymbol` field for it. That field is
  this pack's assumption, so a rail definition without it is `error`. Whether
  the candidate rail pins a symbol, or binds the price currency some other way
  (for example to `paymentToken` itself), is for #371 to settle.
- **Replay ledger durability**. The `DecisionLedger` is in-memory and
  single-process, as described above; durable or cross-process one-use
  enforcement is not claimed.

## Reproduce

From the repository root:

```sh
python3 scripts/generate_delivery_remedy_candidate_vectors.py --check
python3 scripts/verify_delivery_remedy_candidate_vectors.py
python3 -m unittest tests.test_delivery_remedy_candidate_vectors -v
```

Regenerate after an intentional fixture change with:

```sh
python3 scripts/generate_delivery_remedy_candidate_vectors.py --write
```

The generator uses fixed Ed25519 seeds only for public test fixtures. They are
not operational keys.

## Promotion boundary

These fixtures stay under `conformance/fixtures/`, not the canonical
`conformance/vectors/` tier. Promotion still requires steward acceptance of
the artifact shapes, an independently reproduced implementation, complete
authenticated deployment evidence, and a separately registered rail
revision.
