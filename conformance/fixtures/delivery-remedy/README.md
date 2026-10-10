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
  reported as available.

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
agreement-selected rail. Evaluation results and decision dispositions are
closed discriminators. Only `accept` with `release-to-provider` and `reject`
with `refund-to-client` can authorize a terminal action. A release decision
needs delivery evidence (DRD-3), and a decision without delivery evidence must
rest on a DisputeOutcome (DRD-9). The native job description (DREB-1) is read
from the authenticated creation event.

Every artifact describes the overlay's job. The bilateral agreement must be
the one for that `jobId`, with the overlay's buyer and seller in their roles
(DRA-1). The evaluation and decision must reference the exact escrow job
(DRD-8). Funding evidence must bind the exact overlay (DRF-1); another signed
artifact that binds a different overlay is rejected under DRV-4.

Delivery evidence is a DACS-4 §9.7 delivery `SettlementEvidence` with the
members a storage-program delivery carries: `evidenceVersion`, `jobId`,
`phase`, `outcome`, `reason` exactly on a failure, `deliverableContentHash`,
`deliverableAnchor`, `observedAt`, and `signature`. A success carries the
content hash and anchor (DACS-4 §9.6.1). A failure may omit either or both,
since §9.7 makes them optional; a failure without a content hash binds no
delivered-artifact input. Any other member is malformed input. That fixture
shape has no `attestationRef`, so attested-payload delivery evidence (DACS-4
DPA-6) is not modeled and fails closed. §9.7 has no phase-index member, and DACS-4 defines no logical address
for delivery evidence. The record is bound to its phase through the session
instead: the pipeline has exactly one delivery step, at the overlay's
`deliveryPhaseIndex` (DRP-3, DRA-11), and the record's `jobId` and `phase`
must be that job and that step's kind (DRE-2, DRP-7).
`deliverableContentHash` must be the content hash of the delivered-artifact
input; the anchor's locator is not resolved. The delivery outcome does not
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
`dacs5PurchaseCount` (DRP-8), the commitment receipt's `status` (DRP-11),
`terminalGate`, and `lateDeliveryDisabled` (DRP-12) are orchestrator
statements whose values are checked but not proven. Their vectors exercise the
predicate, not the evidence behind it.

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
match the lifecycle's applicability. Funding and terminal finality are still
derived from the observations and embedded records, not from the status. The
pack exercises unavailable and contradictory outcomes but does not claim to
implement those external resolvers.

The fixture resolver key is synthetic and its seed is
derived in the public generator. The pack therefore demonstrates verifier
behavior, not a live resolver. Promotion still requires real authenticated
resolver evidence and a second implementation. Nothing in this pack can register
a rail or authorize a transaction.

Each negative is a consistent signed lifecycle plus one edit. The generator
checks, before it writes or checks the pack, that each negative becomes
`verified` once the guard that decides it is removed. Any other outcome,
including an exception, fails the check, with two listed exceptions.
`FOLLOW_ON_FINDINGS` lists five negatives whose single defect also breaks a
second rule, each with that exact finding. `STRUCTURAL_NEGATIVES` lists nine
negatives that remove a structure the verifier reads. Without their guard the
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
because DACS-4 defines no logical address for delivery evidence.

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
