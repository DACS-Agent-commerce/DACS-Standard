# Delivery-or-remedy candidate fixtures

**Status:** non-normative review tooling for [issue
#356](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/356). These
files do not change DACS conformance, register an ERC-8183 rail, or make any
deployment available.

The pack turns the pre-normative
[delivery-or-remedy candidate](../../../docs/delivery-or-remedy-candidate.md)
into executable review evidence. Every result is one of the candidate's four
verification results: `pass`, `fail`, `indeterminate`, or `error` (§9).

- `candidate-vectors-v0.1.json` holds 496 lifecycle and mapping vectors over
  deterministic, signed synthetic lifecycles: full release, evaluator
  rejection and refund before or after submission, a dispute-outcome release
  and refund, pre-submission expiry, and post-submission expiry. The
  positives also cover each reachable row of the candidate §7 projection
  table, relayed evaluator execution, and the DACS-1 claim forms the
  candidate admits. Negative cases cover the §2 pipeline and commit phase,
  the steward-signed rail definition and its DRC-14 and DRC-17 pins, the
  DACS-3 payee-bound agreement and the overlay, exact hash-to-`bytes32`
  mapping, role and account collisions, the §4.1 crosswalk, the §6.2
  evaluation matrix, the §6.4 dispute table, deadline divergence, premature
  expiry recovery, decision ordering, and finality. They also cover one
  terminal per decision, native job, and terminal event, release/refund
  direction, full-budget and zero-fee requirements, the §3.1 wire rules, and
  the four-result verification boundary.
- `deployment-capabilities-v0.1.json` derives DRC-1 through DRC-13 outcomes
  from explicit capability evidence. It includes a synthetic all-pass control
  that is permanently marked `fixtureOnly`, individual rule regressions, and
  a pinned assessment of
  [`erc-8183/base-contracts@142e669`](https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183.sol).
  The pinned reference is `fail`, remains unregistered, and is never reported
  as available. Its source facts fail DRC-1 through DRC-7 and DRC-13; DRC-8
  and DRC-10 through DRC-12 stay unknown without deployment evidence. DRC-7
  requires that the deployment have no hook, and DRC-8 counts an upgradeable
  payment token against it. The manifest records both halves of DRC-13 from
  the source as `false`. There is no separately enforced per-job submission
  cutoff (`submissionCutoffEnforced`; DREB-13). Expiry recovery does not open
  at the evaluation deadline (`expiryRecoveryDeadlineEnforced`; DREB-15):
  `claimRefund` on a `Submitted` job reverts until
  `expiredAt + EVALUATION_GRACE_PERIOD`, a one-hour constant (`ERC8183.sol`
  lines 78 and 869–870), and on a `Funded` job with a pending claim it reverts
  with `PendingClaimExists` (lines 871–872).

The synthetic control proves only that the checker can observe all thirteen
positive capability predicates. Those predicates come from the manifest
itself, so the capability evaluator always reports
`registrationEligible: false`. A manifest's own `fixtureOnly` and
`registrationStatus` labels cannot change that. Registration needs
independently resolved deployment and registry facts that this pack does not
model.

## Lifecycle model

Each lifecycle runs the candidate §2 pipeline: the
`x-commit-delivery-or-remedy-agreement` commit phase with `agreementPhase`
`commit-payee-bound-agreement`, an `x-job-escrow` fund phase, one
`deliver-storage-program` step, and an `x-job-escrow` terminal phase. The
commit phase binds a DACS-3 `PayeeBoundAgreementDocument`, signed by both
parties under `dacs-payee-bound-agreement:v1:`, and the
`DeliveryOrRemedyAgreement` overlay, signed by buyer, seller, and evaluator.
The rail is a candidate `JobEscrowRailDefinition` (§2.2, §8.4): a DACS-4
`RailDefinition` of `railType` `x-evm-erc8183`, with its `asset`, `network`,
`governance`, and `consumerFinalityProfile` members, and
`ERC8183ProfileParameters` whose literal-typed fields must have exactly the
DRC-14 values. It is signed under `dacs-x-job-escrow-rail:v1:` by a synthetic
registry steward whose key the verifier pins (DRR-2). Its availability is
`mocked`: DACS-4 RAV-R2 makes a mocked rail selectable only in an explicitly
configured non-production mode, and this offline verifier is that mode and
accepts nothing else. A `disabled` or `failed` rail is `fail` under DRR-5, and
any other availability is `error`.

The rail pins every entrypoint and event it relies on as an `AbiFunctionPin`
or `AbiEventPin`: its complete ordered `inputs`, the signature they
reproduce, and the selector or `topic0` derived from that signature by
keccak-256 (DRC-17). The event pins are exactly the crosswalk events and the
configuration event. Each canonical ERC-8183 field is read from the one input
of its name (DRC-20), so a `PaymentReleased` pin without a `provider` input is
`error`. `configurationEvidence` names the configuration event by `topic0`,
its cutoff and policy inputs by index, and the 32-byte policy word for
`evaluator-rejection` (DRC-21). An observed log carries the decoded values of
its topics after `topic0` and of its data, each in order, and is read through
the pin's `indexed` layout; a log that does not fit it is `fail` (DRC-18). The
verifier carries a pure-Python keccak-256, tested against known answers, and
uses it for those pins, EIP-55 checksums, and runtime code hashes (DRW-2). It
decodes calldata and logs only for the pinned fixture implementation ABI
(DRC-18); see the synthetic proof limits below. Each native transaction is
matched to its §4.1 crosswalk row by its prior native status, entrypoint, and
caller (DRL-10, DRL-11), and must emit exactly that row's logs.

The references in funding and terminal evidence are derived, so two
producers write the same bytes (DRW-7). Each event reference list is exactly
its transition's required events, in ascending log order, from one
transaction. Each `AttestationRef` omits `signer` and is a `storage-program`
anchor at the artifact's logical address, never a native `stor-` address.

P13's two producers resolve the same funding and decision writes through one
binding and reproduce the same terminal evidence. I8's two byte-identical
funding or decision writes at different native addresses yield `indeterminate`
under DRAA-4. Both summaries are retained, neither is selected, and DRC-15 is
not evaluated from either copy, including when their finality times fall on
opposite sides of the terminal transaction. Receiving the exact same receipt
twice still describes one write. A consumer with one receipt needs no proof
that no other write exists. The verifier's ledger retains every
authenticated summary bound to its logical address, so two writes carried by
different lifecycles, in one batch or in successive calls, are the same
equivocation: no lifecycle whose terminal evidence references that address
then passes, and a `pass` already issued for it is revised to `indeterminate`.

The protocol verifier requires the finality records embedded in signed funding
and terminal artifacts to use the exact DACS-4 `SettlementFinalityRecord`
`block-depth` shape at the rail's finality depth. Each authenticated log names
its block and the block at the rail's confirmation depth (`finalityBlock`,
block n + N − 1, or `null` while it does not exist). The records must quote
that block: `finalityObservedAt` and `observedAt` are its timestamp in
milliseconds (DRW-6), so a wall-clock observation time is `fail`. Every block
identity must reproduce, and one block number has one timestamp across every
log, finality block, and anchor of the lifecycle, rising with the block number
(DRF-8). A record altered together with its block therefore still fails.
Event finality, submission timing, expiry-recovery timing, and Vet freshness
are derived from those observations.

Native observations come from a synthetic fixture resolver whose key the
verifier pins (DRV-1). Each lifecycle carries one `resolverEvidence` record,
signed under `dacs-x-delivery-remedy-fixture-resolver:v1:`. The record binds
the job, the agreement-selected rail definition, the native contract and job,
and the exact `nativeEventInputs`. It also carries:

- `transactions`: each native transaction's entrypoint selector and decoded
  calldata, its native caller, outer submitter, and caller account type, and
  the native status before and after it (DRL-10, DREB-18, DREB-21, DREB-22);
- `priorTerminals`: the complete set of terminal transactions the resolver
  observed before this lifecycle's terminal event for its native job or
  decision, each with its native job, event identity, and decision hash
  (DRD-8, DRL-4, DRT-4);
- `nativeState`: the resolved native job state, capability facts, and the
  code found at the escrow, token, and implementation addresses, read by
  DREB-13, DREB-15, DREB-16, DREB-20, DRJ-5, DRJ-11, DRL-7, and DRT-7;
- `deliveryDigestAnchor`: the block in which the exact delivery digest was
  anchored, or `null` when the resolver has no such evidence (DRP-9);
- `decisionAnchor`: the consensus timestamp of the Demos block that finalized
  the decision, or `null` when it is unavailable (DRC-15, DRC-19);
- `statuses`: the resolver's availability outcomes.

The verifier reads these facts only from the signed record.

The decision is ordered before the terminal transaction only through that
anchor (DRC-19). With the rail's `maxCrossSubstrateSkewMs` widened by the
1000 ms of a Demos second, a decision finalized more than that before the
terminal block is before it, one finalized more than that after it is `fail`
under DRD-11, and one within it is `indeterminate` under DRC-15. Without an
anchor the order is `indeterminate` (DRD-10); a time the decision or
orchestrator reports never orders it.

## Inputs and results

The escrow job, both escrow phases, and the native target follow the
agreement-selected rail. Evaluation results, criterion outcomes, findings,
decision dispositions and stages, dispute roles and recommendations, and the
terminal evidence's `terminalState` each have a closed value set. A value
outside the closed value set, including an array, an object, or an unknown
string, is malformed input and returns `error` before any stage reads it.
A number outside the CORE §B.2 profile (NaN, an infinity, or an integer
beyond 2^53 − 1) is malformed too, as is a boolean or any float, including an
integral float such as `8453.0`, where an integer is read. The §3.1 wire
rules are checked as written: a native address is `0x` and 40 lower-case
hexadecimal digits and a claim address is one case or valid EIP-55 (DRW-1), a
code hash is `0x` and 64 lower-case digits (DRW-2), a transaction hash is
lower-case (DRW-3), and a time is a non-negative safe integer (DRW-4); each
violation is `error` under its rule, and a zero address or empty-code hash
where a deployment is named is `fail`. So is a lifecycle that nests arrays
and objects more than 64 deep: the pack's deepest lifecycle nests 8, and the
bound is checked iteratively before anything is hashed, because
canonicalisation recurses once per level. A batch gives one malformed
lifecycle its own `error` and still judges the others. The command line
lists a pack it cannot parse as an error, and a pack file nested more than 64
deep too. It checks that bound on the parsed value, so the error is the same
whether or not the interpreter's JSON parser refuses a deep text itself
(Python 3.12 does; 3.13 and later can parse it). Called directly,
`verify_vector_pack` and `verify_deployment_pack` check the same bound on the
whole pack before they copy or hash it, and return a pack that exceeds it as a
pack error; they do not judge its lifecycles one by one.

The verifier reports malformed input (candidate §9 step 2) under DRV-3, the
malformed-encoding rule: nothing is repaired before hashing or comparison.
DRV-2 keeps unavailable or inconsistent RPC data `indeterminate`, as for an
unavailable `agreementResolution`. The candidate names no rule for an
unsupported §9 step-1 artifact discriminator (a phase kind; an overlay,
bilateral-agreement, escrow-job, funding, delivery-evidence, evaluation,
dispute-case, dispute, decision, terminal, resolver-evidence, or
deployment-manifest version; or a deployment capability profile), nor for the
identity-bound commit and the implementation ABIs this pack does not model, so
those `error` cases keep the fixture label `DRV-2`. Where the candidate names
the rule, the result cites it: a rail version, type, or phase handler
(DRR-6), a profile literal such as the capability or decision-ordering profile
(DRC-14), an evaluation rule version or kind (DRE-9), and an `agreementPhase`
outside DRP-14's two values (DRP-14). The overlay, the bilateral agreement, or
an escrow artifact with no version discriminator is malformed input (DRV-3); a
rail or rule without one is unsupported under DRR-6 or DRE-9. The step-1 label
is pending #371's named §9 step-1 rule. An unsupported `deliver-*` kind as the
one delivery is not such a case: DRP-3 requires a supported delivery step, so
it is `fail` under DRP-3. The pack supports only the `deliver-storage-program`
kind it models, so a `deliver-entitlement` or `deliver-attested-payload` step
is `fail` under DRP-3 too.

A resolver status whose applicability contradicts the lifecycle is `fail`
under DRV-6: the pinned resolver's authenticated record contradicts the
signed terminal and delivery evidence. That holds for an applicable status
marked `not-applicable` and for an inapplicable one marked `verified` or
`contradictory`. An inapplicable `unavailable` is not a contradiction: it
asserts nothing, and candidate §9 step 5 makes only required evidence
`indeterminate`. The candidate's DRP-7, DRT-3 and DRT-12 make delivery
evidence and `decisionRef` absent, but they do not govern the resolver
record. So the applicable checks decide the verdict (DRV-7).

## Parties, references, and amounts

Every artifact describes the overlay's job. The bilateral agreement must be
the one for that `jobId`, its `parties` must name the overlay's buyer and
seller in their roles with the bundles the overlay binds (DRA-17), and its
`terms.rail` must be the selected rail and version (DRA-22). Claims follow
the DACS-1 §6.3.1 grammar: a lower-case scheme, CORE CF-2 canonical
parameters, a Demos agent key of 64 lower-case hexadecimal digits, and an
EVM `cci-xm` claim whose address satisfies DRW-1. Parties are compared by
CORE CF-3 identity, without `?` parameters and with an EVM address compared
as its 20 bytes (DRW-5): an evaluator claim that differs from the buyer's only
by a parameter or by the letter case of its address is the buyer (DRA-6), and
a `faultedParty` with a parameter is still the agreement party (DRX-5). A
claim that is not canonical, such as one with an upper-case scheme, is
`error`, and so is an EVM claim whose address is not an address, whatever the
chain shows. So is a `cci-xm` EVM claim outside the DACS-1 PB-2 spelling: an
`evm` family in another letter case, or a chain ID with a leading zero, a
sign, or a `0x` prefix. Such a claim cannot respell one account as a second
party.

Every reference is a DACS-2 `AttestationRef`, `{anchor: {kind, locator},
contentHash, signer?}`, with an anchor kind of `storage-program`, `ipfs`, or
`https`. A reference to a candidate artifact names its §6.5 logical address,
`dacs4:x-job-escrow:{jobId}:…`, under a `storage-program` anchor; a numeric
segment spelled other than as minimal decimal is `error` (DRAA-2). A
`signer`, when present, must be a canonical claim and name the referenced
artifact's authenticated signer (DRV-6). The evaluation and decision must
reference the exact escrow job (DRD-8). Funding evidence must bind the exact
overlay (DRF-1); another signed artifact that binds a different overlay is
`fail` under DRV-4.

The overlay's `budgetBaseUnits` must be the bilateral agreement's
`terms.price` converted with the rail asset's decimals (DRA-10), as DACS-4
§9.5.2 steps 2 and 3 convert a `PriceTerm`. The price currency must be the
rail asset's `symbol` (DRA-21), and `amount × 10^decimals` is computed exactly
from the CD-1 decimal text as string arithmetic: the fraction is padded to the
token's decimals, leading zeros are stripped, and the result is compared with
`budgetBaseUnits` as minimal decimal text, with no integer or float
conversion, so a price of any length converts exactly. The budget itself is
at most 2^256 − 1. The candidate rail escrows an ERC-20 `paymentToken` (§8.4),
whose amounts are uint256 as its `decimals()` is a uint8, and every native
amount must equal the budget (DREB-11, DRF-2, DRT-5, DRT-6). A larger budget
is an `error` under DRV-3, and so is a larger pre-terminal provider payout in
the resolver's native state, the one native amount not compared with the
budget. Any other native amount above the bound differs from the budget, so
the rule that compares it fails it. A wrong amount or decimals, a price with
more fractional digits than the token carries, or a zero price (DACS-4 §9.3
requires an agreed `PriceTerm.amount` strictly greater than zero) is `fail`
under DRA-10. A price carrying DACS-4's optional `unit` qualifier is an
`error`. That is a limitation of this fixture, not a candidate rule; see
**`PriceTerm.unit`** under the synthetic proof limits below.

## Delivery, evaluation, and decisions

Delivery evidence is the DACS-4 `DeliveryEvidence` the candidate requires
(DRP-7, PDE-1): `deliveryEvidenceVersion`, `jobId`, `phaseIndex`, `phase`,
`outcome`, `reason` exactly on a failure, `deliverableContentHash`,
`deliverableAnchor`, `observedAt`, and `signature`. Its `phaseIndex` must be
the overlay's `deliveryPhaseIndex` and its `phase` that step's kind (DRE-2,
DRP-7), and a historical delivery-shaped `SettlementEvidence` does not
satisfy the profile. A failure never passes (DRP-7). `deliverableContentHash`
must be the content hash of the delivered-artifact input, and the deliverable
anchor must be the `storage-program` address `dacs4:deliverable:{jobId}:{phaseIndex}`
(PDE-3); the record itself is referenced at
`dacs4:delivery:{jobId}:{phaseIndex}`. The pack models only storage-program
delivery: an attested-payload or entitlement delivery never passes, since its
step is `fail` under DRP-3 and the signed evidence must name the agreed step's
kind (DRE-2), so relabelling a step cannot skip the anchor checks.

The evaluation is executed under its bound `EvaluationRule` (DRE-8): the
rule kind `evaluator-judgement-v1`, non-empty criteria with unique IDs
(DRE-9), and one `criterionResults` entry per criterion in the rule's order.
The result must be the one the §6.2 matrix derives from those outcomes, and
the finding one the matrix permits for it (DRE-10). Each evaluation subject
reference must resolve to a lifecycle record the verifier authenticated: the
escrow job, the funding evidence, or the delivery evidence (DRE-3). Both
first-profile disclosure policies admit those records. Any other subject is
`indeterminate` (DRE-5), because public resolution and the explicit-party
supply proof (DRQ-2) are not modeled.

Only `accept` with `release-to-provider` and `reject` with `refund-to-client`
can authorize a terminal action. A release decision needs delivery evidence
(DRD-3), and a decision without delivery evidence must rest on a
`DisputeOutcome` (DRD-9). A dispute outcome must answer its `DisputeCase`,
signed by the party that opened it (DRX-7), and recommend the disposition the
§6.4 table permits for its finding (DRX-9). The decision's `decisionStage`
must match the terminal transaction's prior native status, and only a
`post-submission` decision carries delivery evidence (DRD-13, DRD-14). The
native job description (DREB-1) is read from the authenticated `createJob`
calldata: the UTF-8 bytes of `dacs-x-delivery-remedy:v1:` followed by the
overlay's content hash.

Delivery/submission ordering (DRP-9) rests on authenticated evidence that the
exact delivery digest was fixed before the native submission. The resolver's
`deliveryDigestAnchor` must name this delivery's digest in an earlier block
than the submission event, with an earlier block time, and the signed
delivery evidence cannot record a later time than the anchor. Without an
anchor, or with one in the submission's own block, the result is
`indeterminate`. The synthetic submission transaction identity commits to its
deliverable argument, as an EVM transaction hash commits to its calldata. The
verifier does not search delivery content for encodings of the submission.

The DRT-14 projection is recomputed from the terminal state and the finding
by the §7 table. A contradictory projection is `fail`, and a pair the table
does not list projects no buyer or seller fault.

## Replay

Replay state belongs to the verifier. Callers pass a `DecisionLedger` to
`evaluate_lifecycles`, which evaluates a set of lifecycles together, or to
`evaluate_protocol`, which evaluates one. Each lifecycle that passes every
check before the replay comparison records its terminal: native job, terminal
event and its authenticated position, decision, and attested history.
Verifying the same terminal again is idempotent, and it reproduces one
terminal evidence hash: a second, distinct evidence record for that terminal
is `fail` for both (DRT-16). Two different terminals
conflict when they share a decision (DRD-8) or a native job (DRL-4), or when
one terminal event settles two native jobs (DRT-4). The pinned resolver
attests `priorTerminals` as the complete earlier history, so a conflict with
one of them is `fail`.

For conflicts with a terminal in the ledger, the verifier chooses the earlier
terminal from authenticated canonical event position: block number, then the
block-scoped log index, which also orders transactions within a block. The
later terminal is `fail`. The earlier one holds only if the later terminal's
attested history names it. Otherwise the resolver's records contradict each
other, and the earlier one is `indeterminate`. When the positions cannot
order the pair, both are `indeterminate`. One event claimed by two native
jobs is `fail` for both.

`evaluate_lifecycles` records every terminal before it compares any, so its
verdicts are the same in every order of its input. `evaluate_protocol` judges
one lifecycle on the terminals already known. When the resolver's records
agree, a later terminal carries the earlier one in its attested history and
is `fail` even if it arrives first, so arrival order changes no verdict.

When the resolver's records contradict each other, a verdict issued before
the contradicting record arrived can no longer stand. The ledger keeps the
verdict it issued for each recorded terminal. An evaluation that changes an
earlier verdict lists the change under `revises` in every result it returns:
the terminal (its `priorTerminals`-style identity, block, and attested
history), the `previous` verdict, and the verdict that replaces it. A
revision never upgrades a verdict: `pass` can become `indeterminate` or
`fail`, and `indeterminate` can become `fail`. A later arrival that conflicts
with a passing terminal never passes, so two conflicting terminals never both
pass in one ledger. The verdicts issued, with their revisions applied, are
the verdicts of evaluating everything seen so far as one set, whatever the
arrival order. A verdict therefore holds for the evidence evaluated so far,
and a caller that acts on a `pass` verdict before the whole set is known must
also act on its revisions. The verifier never consults arrival order itself.

The ledger is an in-memory, single-process fixture. It is not durable, and it
does not provide concurrent or cross-process one-use enforcement; none is
claimed.

Each base lifecycle is its own job, so the standalone positive vectors pass
in any order and any number of times through one ledger. The pack runner gives
each vector a fresh ledger. A vector's `evaluatedWith` list names other
vectors evaluated together with it, as one set.

## Producer projections and reproduction inputs

The remaining `native` fields are producer projections that the verifier pins
to authenticated values:

- chain, contract, and runtime code, to the escrow job and selected rail;
- client, provider, evaluator, cutoff, and `expiredAt`, to the signed overlay,
  whose values the authenticated creation and configuration logs also carry
  (DRJ-3);
- token and budget, to the rail and overlay;
- payout receiver, to the seller account; a release's recipient is
  authenticated by its transfer log;
- `fundedAtSec`, to the funding log's block;
- deliverable and reason, to recomputed content hashes; the submission and
  terminal calldata and logs carry the authenticated values;
- terminal state and action, and the portable state history, to the signed
  terminal evidence and the crosswalk rows of the authenticated transactions.

Some lifecycle statements are not yet derived from authenticated evidence.
In `executionContext`, `fundingFinalizedBeforeDelivery` (DRP-6),
`dacs5PurchaseCount` (DRP-8), `acceptedRails` (DRP-10), the commitment
receipts (DRP-11), `terminalGate`, and `lateDeliveryDisabled` (DRP-12) are
orchestrator statements whose values are checked but not proven. Their
vectors exercise the predicate, not the evidence behind it, so these rules
are listed in the `promotionBlockedProofs` ledger described below.

Each lifecycle fixture also carries `reproductionInputs`: the public test-key
seeds, role-bundle and Vet-record bodies, the delivered artifact, the
runtime-bytecode preimage, and native log observations with their transaction
and block-hash preimages. The verifier independently recomputes their keys,
hashes, references, event identities, chain binding, ordering, and positive
bindings. It also derives policy from the authenticated rail definition and
checks accountability projections against authenticated findings. These are
synthetic inputs, not a live chain resolver, production identity registry, or
eligible deployment.

The resolver's `statuses`, `nativeState`, `deliveryDigestAnchor`, and
`decisionAnchor` objects are explicit fixture boundaries for authenticated
resolver outcomes such as registry availability, cross-substrate ordering,
native capability facts, and delivery-digest fixation. The anchors are
synthetic and non-normative: they demonstrate the verdicts that such evidence
supports, not its normative proof shape. Each status has to match the
lifecycle's applicability: an applicable status is never `not-applicable`,
and an inapplicable one is `not-applicable` or `unavailable`. An
authenticated status that does not match is a DRV-6 contradiction. Funding
and terminal finality are still derived from the observations and embedded
records, not from the status. The pack exercises unavailable and
contradictory outcomes but does not claim to implement those external
resolvers.

A record that a signed artifact references but the caller did not supply is
`indeterminate` (candidate §9 step 5, §11.3 case I5), even when every
resolver status is available. That covers delivery evidence the terminal
references for an authenticated native submission (DRE-5), a decision an
evaluator terminal references (DRD-4), the evaluation or `DisputeOutcome` a
decision rests on (DRD-2), the `DisputeCase` an outcome answers (DRX-7), and
the evaluation rule the overlay binds (DRE-8). A record that something
present contradicts is still `fail`. Examples are a released terminal with
no decision reference, a decision reference on an expiry refund (DRD-7),
delivery evidence on a lifecycle with no native submission (DRT-12), and a
resolver record that marks the evidence not applicable (DRV-6).

The fixture resolver and registry steward keys are synthetic, and their seeds
are derived in the public generator. The pack therefore demonstrates verifier
behavior, not a live resolver or registry. Promotion still requires real
authenticated resolver evidence and a second implementation. Nothing in this
pack can register a rail or authorize a transaction.

## Source pins

The lifecycle pack's `sourcePins` records the candidate's External pins: the
canonical ERC-8183 text and the reference contract, EIP-155, EIP-55,
EIP-1052, ERC-1271, ERC-2771, RFC 8785, the ULID specification behind the JID
range (DRAA-1), and `@kynesyslabs/demosdk` 4.0.16 (npm `dist.integrity`
`sha512-nVhp1uC+tFGzhew9c8XIajTMmELopx7gd0joqqzDd2XyUuFDcqrda51NYqvX5C8+L3Xgnie/mRf7JRqZ7r3tHA==`).
It also records the DACS commit the candidate was checked against and the
SHA-256 of the candidate and of each DACS document it cites. The verifier
refuses a pack with other pins before it runs any vector. It compares the
candidate's hash with the checkout, so the pack is stale once the candidate
changes. It compares each `spec/` document's hash with that document at the
Checked-against commit, read with `git show`, so a later `spec/` edit that
does not re-pin the candidate leaves the pack valid. That read needs the
commit in the clone's history, as CI's full fetch provides. The generator and verifier are not
hashed into the pack: `generate_delivery_remedy_candidate_vectors.py --check`
in CI ties the pack to the tools that produced it, and pinning their bytes
would also refuse every review mutant of the tools before any vector ran.

## Isolation audit

Each negative is a consistent signed lifecycle plus one edit. The generator
checks, before it writes or checks the pack, that each negative passes once
the guard that decides it is removed. Any other outcome, including an
exception, fails the check, with two listed exceptions.
`FOLLOW_ON_FINDINGS` lists 111 negatives whose single defect reaches one exact
second finding once its guard is removed. Some of those defects break a
second rule. For a record that was not supplied, a later check finds the
lifecycle inconsistent instead. `STRUCTURAL_NEGATIVES` lists 30 negatives
that remove or malform a structure the verifier reads. Without their guard
the verifier raises, or another shape guard decides first, so isolation is
not claimed for them.

The unit suite also requires every verifier guard to be decided by a vector
or by an exact-finding shape case.

## Rule accounting

Every candidate rule ID is accounted for mechanically. Each executable vector
lists the rules its positive or negative path exercises. These lists are
rule-accounting tags, not proof that a guard ran; the guard audit above is
that proof.

The pack's `promotionBlockedRules` ledger names the rules no vector executes
and the concrete capability needed before they can be promoted. They cover
SR-2 logical addressing and anchoring, the anchoring
order of the overlay and evaluation (DRA-12, DRE-7), later mutation of the
bound job (DRA-14), live proxy and authority resolution, the evaluator EOA's
control proof (DREB-17), explicit-party evidence proof, gate and
`PhaseHandlerResult` receipts, retry orchestration, the deployment check for
trusted forwarders (DREB-24), and the future transcript and post-terminal
dispute-revision profiles. The test suite fails if a spec rule is absent from
both the vectors and the ledgers or appears both as executed and as
unexecuted. No verifier finding reports an unexecuted rule.

The separate `promotionBlockedProofs` ledger names rules whose vectors run
against a synthetic evidence shape whose normative proof shape is undefined.
Negatives may exercise them, but no `pass` vector claims one, and the
verifier refuses a pack where one does. It holds DRP-9, whose digest anchor is
a fixture boundary, and DRE-2 and DRP-7, whose `DeliveryEvidence` is checked
without the SR-2 receipts that would finalize and resolve it. It holds DRAA-4:
the optional resolver-signed `qualifiedArtifactWrites` inputs summarize
qualifying finalized funding and decision writes by logical address, native
address, content hash, transaction, writer, nonce, and consensus finality time.
They are synthetic proof-verifier outputs, not CORE `AnchorReceipt` proof
bytes. The pack checks equivocation over these summaries; it does not verify
native receipt proofs or enforce producer write-once behavior. It holds DRF-8,
whose chain facts come from the fixture chain and resolver rather than FV-1
through FV-10, and DRW-6, whose confirmation-depth block time comes from the
same resolver: a consistent shift of every block time is not detected. It
holds DRC-14, whose `implementationRevision` names a fixture implementation
with no published DRC-10 source, so only its spelling is checked. It holds
DRJ-11 and DRW-2, whose payment-token and implementation code hashes are
compared with the resolver's statement but not reproduced from bytecode (only
the escrow code is); a delegating escrow is therefore never verified. It holds
DRE-8, whose evaluation rule is resolved by hash and job but whose anchoring
before the overlay is not ordered. It holds DRR-2, whose steward signature is checked without a
registry snapshot, and DRR-3 and DRP-10, whose accepted rails are the
orchestrator's statement rather than a resolved Listing. It also holds DRP-6,
DRP-8, DRP-11, and DRP-12, whose `executionContext` inputs are orchestrator
statements rather than authenticated evidence. Finally, it holds DRA-4, DRA-8,
and DRA-9: role bundles and Vet records are unsigned fixture inputs bound by
hash, not authenticated DACS-1 bundles or DACS-2 composite records, and no
role proves control of its EVM account.

### Synthetic proof limits

Beyond the two ledgers, these assumptions come from the synthetic resolver or
the fixture itself. The vectors depend on them and do not prove them:

- **`priorTerminals` completeness** (DRD-8, DRL-4, DRT-4). The verifier treats
  the resolver-attested `priorTerminals` as the complete set of earlier
  terminal transactions for the native job, decision, and terminal event. A
  terminal the resolver omits is detected only if it is evaluated in the same
  ledger. No normative completeness proof, such as an authenticated range or
  index proof, is defined or checked.
- **Transaction-set completeness** (DRL-10, DRT-12). The verifier derives the
  pre/post-submission classification from the terminal transaction's
  resolver-attested prior native status, and checks every attested
  transaction against the crosswalk. It assumes the resolver attests every
  transaction for the native job. No completeness proof for the transaction
  or event set is defined or checked.
- **Block-scoped log index** (DRD-8, DRL-4, DRT-4). Conflicting terminals are
  ordered by authenticated block number, then log index. This assumes the log
  index is block-scoped, as EVM receipts report it. A transaction-scoped index,
  or a ledger without block-scoped indexes, needs its own position rule and is
  not covered.
- **Fixture chain and resolver** (DRF-8). Block and transaction identities are
  fixture-chain preimages: a block hash is the SHA-256 of its chain, number,
  and timestamp, and a transaction hash the SHA-256 of its preimage, not an
  EVM header or transaction hash. The verifier checks that the resolver's
  facts reproduce and agree with each other and with the signed records, not
  that a chain produced them; FV-1 through FV-10 are not executed.
- **Fixture implementation ABI** (DRC-17, DRC-18, DRC-20, DRC-21, DRJ-3,
  DRJ-4). The rail pins the ABI of a fixture implementation, not a deployed
  one: the canonical ERC-8183 interface, with its parameter names and
  `indexed` layout, extended with a `submissionCutoff` argument to
  `createJob` and a `JobConfigured(uint256,uint256,bytes32)` log carrying the
  submission cutoff and a one-word pre-submission policy (`evaluator-rejection`
  as a right-padded `bytes32`), which DREB-13 and DRA-15 need and the canonical
  interface does not emit. Its selectors and
  topics are computed from those signatures. The verifier decodes only this
  ABI, so a rail pinning another, including the reference contract's
  `createJob`, is `error`. A deployment's real ABI needs its own pins and
  decoding. The fixture also fixes its emission order: a transaction's logs,
  by `logIndex`, are the events in the order its §4.1 row lists them, so the
  state log comes before the transfer log (`JobRejected`, then `Refunded`;
  `JobExpired`, then `Refunded`). Canonical ERC-8183 `reject` and
  `claimRefund` emit `Refunded` first, and the candidate's §4.1 states no
  order, so a deployment's emission order needs its own rule as well.
- **Deliverable anchor locator** (DRE-2, DRP-7). The
  `dacs4:deliverable:{jobId}:{phaseIndex}` locator is compared, not resolved,
  so the Storage Program's existence and contents at that address are not
  proven.
- **`PriceTerm.unit`** (DRA-10). The pack reads an agreement price only when
  its members are exactly `amount` and `currency`. DACS-4's `PriceTerm` may
  also carry an optional `unit` qualifier, and DRA-10, which converts "the
  exact agreement price", does not exclude it. The pack still returns `error`
  (DRV-3) for such a price rather than convert it. This is the fixture's
  limitation, not a candidate rule, and it fails closed: no price with `unit`
  passes. Whether such a price states the agreed total (a metered
  agreement's `terms.price` is the computed total, DACS-3 MTR-4) or a rate,
  and so whether DRA-10 converts its `amount`, is for #371 to settle.
- **Role and Vet records** (DRA-4, DRA-8, DRA-9). Role bundles and Vet records
  are unsigned fixture inputs that the overlay and agreement bind by hash. The
  verifier checks the hashes, the evaluator requirement, and a fixture
  validity window, not authenticated DACS-1 bundles, DACS-2 composite records,
  or control of each role's EVM account.
- **Payee-bound agreement only** (DRP-14). The commit phase models
  `commit-payee-bound-agreement`. The candidate's
  `commit-identity-bound-payee-agreement` arm needs the CORE IBH-1 through
  IBH-6 gates, which this pack does not model, so it is `error`.
- **No EIP-1271 support** (DREB-18, DREB-22). The verifier supports no chain
  and code for EIP-1271 evaluator accounts, so a terminal call by a contract
  evaluator is `fail` under DREB-18 whatever its outer submitter, and the
  candidate's relayed EIP-1271 positive cannot be produced here. Only an EOA
  evaluator passes, and an EOA call with another outer submitter is `fail`
  under DREB-22.
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
