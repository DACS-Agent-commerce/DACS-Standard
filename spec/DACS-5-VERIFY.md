# DACS-5: Verify — Verify

*Normative module of DACS v0.1. Read the [Primer](../PRIMER.md) first; shared types, signatures, canonical form, the session model, and substrate requirements live in [CORE](CORE.md). Section numbers are retained from the unified specification; per the §→document map in [CORE](CORE.md), cross-references of the form §6–§10 point to sibling module documents, and §A / §12–§14 to the companion references (Demos mapping, threat model, glossary, conformance plan). The [conformance vectors](../conformance/) exercise this module's rules.*

## Chapter 10 — DACS-5: Verify

**Stage:** Verify (5th of 5). **Status:** Draft — **DACS-5 v0.7** on the common DACS v0.1 baseline. v0.7 adds the target-signed `SessionParticipationAdmission` and SPA-1..SPA-8: the current profile cannot turn one party's invented roster plus the other party's absence into blame, and ordinary ratings require an authenticated completed rate phase and exact target role. v0.6 adds the structurally distinct `AuthenticatedWindowReputationDerivation`: the current reputation-bearing profile whose window clock is the exact reconciled bundle anchor's authenticated, finalized SR-2 inclusion timestamp. v0.5 makes APR-7 effective-pipeline recomputation mandatory for `pay-alternative` Listings before phase-summary or SettlementEvidence admission. v0.4 adds the non-terminal `audit-pending` gate, requires every successful bundle dependency plus the completed bundle itself to be finalized and independently resolvable, adds the `EvidenceBoundFaultAttestationBundle` type with SEB-1..SEB-6 exact settlement-evidence binding, and adds structurally distinct settlement-verified reputation derivation types while preserving the released v0.3 `ReputationDerivation` and `ReplayableReputationDerivation` version-1 semantics. v0.3 added `PayeeBoundAgreementDocument` consumption alongside the legacy agreement artifact, the signed `BundleBinding` artifact with BB-1..BB-8 logical→native bundle resolution §10.4.2, and the `FaultAttestationBundle` artifact — absolute hashed `faultedParty` attribution as a distinct type under its own `dacs-fault-bundle:v1:` domain §10.4.1. **Depends on:** SR-1 for cross-substrate primary-claim keying, SR-2 for bundle anchoring; composes with the ERC-8004 reputation registry as an OPTIONAL publication surface. **Used by:** all subsequent DACS-1 reputation lookups, external auditors and regulators.

### 10.1 Abstract

DACS-5 specifies how a completed session is anchored, signed, and converted into a reputation signal. It defines:

- A **session record schema** — the live, mutable state the orchestrator maintains while a session runs (phase results, error classifications, event log); off-chain by default.
- An **attestation bundle format** — the frozen end-of-session artifact, signed by both parties and anchored via SR-2. Bundles are the audit unit.
- A **session-state machine** — deterministic, forward-only transitions from `draft` to a terminal state (`finalised`, the `*-failed` states, `failed-substrate`, the `aborted-by-*` states), enumerated normatively in §10.3.1.
- A **reputation derivation algorithm** — a deterministic, per-primary-claim function from a set of bundles to headline metrics (completion rate, dispute rate, average rating, observed transactional volume).
- A **signed participation admission** — the exact target-signed active obligation required before a one-sided bundle may blame an absent non-signer in current-profile reputation.
- An **optional rate phase** — a counterparty rating producing a RatingRecord referenced from an authenticated completed rate phase.
- An **ERC-8004 publication surface** — the recommended mapping from DACS-5 metrics to ERC-8004 registry entries.

Reputation keys against the bundle's **primary identity claim**, not a wallet, signing key, or session pubkey — preventing low-tier reputation from laundering into high-tier presentations.

### 10.2 Motivation

The Verify stage answers three questions no other stage does: *did this transaction happen the way the parties say?* (a cryptographic, anchored audit trail anyone can inspect); *what did each party think of the other?* (a structured rating); *how does it feed future reputation?* (a deterministic update keyed against the party's primary claim).

No existing standard covers these end-to-end: ERC-8004 specifies on-chain reputation entries but not how the underlying transactions are evidenced; marketplace ratings are operator-controlled and non-portable; audit-log standards (RFC 5424, OpenTelemetry) handle observability but not cross-counterparty non-repudiation.

DACS-5 fills the gap with three layered, anchored, signed artifacts: the session record (working state), the attestation bundle (the closed audit unit), and the reputation derivation (the public summary). Reputation keying is deliberate: a great `key:…` micropayment-tier reputation must not launder into a fresh `lei:…` presentation, so derivation partitions by the bundle's primary claim and accumulates tier-distinct metrics. One wallet holding `key:…`, `did:…`, and `lei:…` accumulates three separate reputations; consumers MAY surface the cross-claim relationship (via SR-1) informationally, without inheritance.

### 10.3 Session record

The live, mutable state document an orchestrator maintains during a session.

```
type SessionRecord = {
  recordVersion: "1"
  jobId: string                              // ULID or substrate-equivalent
  state: SessionState
  listingRef: { listingId: string; version: number; contentHash: string }
  parties: SessionParty[]                    // buyer + seller (+ optionally orchestrator)
  pipeline: PhaseStep[]
  phaseResults: PhaseEntry[]                 // one per executed phase
  startedAt: number                          // unix ms
  lastUpdatedAt: number
  endedAt?: number                           // set on terminal state
  recipeRegistryVersion: number              // DACS-2 registry pinned at session start
  railRegistryVersion: number                // DACS-4 registry pinned at session start
  amendments?: AttestationRef[]              // refunds and other amendments
}
type SessionState =
  | "draft"
  | "vet-pending" | "vet-completed" | "vet-failed"
  | "negotiate-pending" | "negotiate-completed" | "negotiate-failed"
  | "commit-pending" | "commit-completed" | "commit-failed"
  | "settle-pending" | "settle-asymmetric" | "settle-completed" | "settle-failed"
  | "rate-pending" | "rate-completed"
  | "audit-pending"
  | "finalised"
  | "aborted-by-self" | "aborted-by-other"
  | "substrate-failure-paused" | "failed-substrate"
type SessionParty = {
  role: "buyer" | "seller" | "orchestrator"
  bundleHash: string                         // sha256 of the verified IdentityBundle
  primaryClaim: ClaimReference               // bundle.presentedBy
  vetRecordRef?: AttestationRef              // post-Vet
}
type PhaseEntry = {
  index: number                              // position in pipeline
  step: PhaseStep
  invokedAt: number
  result: PhaseHandlerResult
  contextDelta: Record<string, unknown>      // merged into running context
}
```

`finalised` is the existing DACS session-state token. CORE §5.1 `finalized` is the SR-2 transaction state. The spellings are intentionally not aliases: a session reaches `finalised` only after ST-11 verifies the required SR-2 `finalized` receipts.

#### 10.3.1 State transitions

Transitions are deterministic and forward-only. The orchestrator advances state only when the corresponding phase returns `ok: true`; on phase `ok: false` it transitions to that phase’s `*-failed` state and classifies per the phase’s `errorClass`. The only permitted non-forward transition is resume from `substrate-failure-paused` (ST-7 below). New sessions get new jobIds; a failed/aborted session is never reopened.

**Transition table (normative).** The following table enumerates every legal `(from → to)` pair. A transition not listed is illegal; a conformant orchestrator MUST NOT perform it, and a §14.5 conformance run tests exactly this pair-set.

| From | To (legal next states) | Trigger |
|------|------------------------|---------|
| `draft` | `vet-pending` | session opens; first phase scheduled |
| `vet-pending` | `vet-completed` \| `vet-failed` \| `substrate-failure-paused` \| `aborted-by-self` \| `aborted-by-other` | Vet phase result |
| `vet-completed` | `negotiate-pending` | next phase scheduled |
| `negotiate-pending` | `negotiate-completed` \| `negotiate-failed` \| `substrate-failure-paused` \| `aborted-by-self` \| `aborted-by-other` | Negotiate phase result |
| `negotiate-completed` | `commit-pending` | next phase scheduled |
| `commit-pending` | `commit-completed` \| `commit-failed` \| `substrate-failure-paused` \| `aborted-by-self` \| `aborted-by-other` | agreement commitment phase result |
| `commit-completed` | `settle-pending` | next phase scheduled |
| `settle-pending` | `settle-completed` \| `settle-asymmetric` \| `settle-failed` \| `substrate-failure-paused` \| `aborted-by-self` \| `aborted-by-other` | Settle phase result |
| `settle-asymmetric` | `settle-completed` \| `settle-failed` \| `substrate-failure-paused` | ST-8 (cross-chain asymmetric open state; substrate pause per ST-7) |
| `settle-completed` | `rate-pending` (pipeline has a rate phase) \| `audit-pending` (no rate phase) | ST-4 |
| `rate-pending` | `rate-completed` \| `audit-pending` | ST-5 |
| `rate-completed` | `audit-pending` | rate phase done |
| `audit-pending` | `finalised` \| `substrate-failure-paused` | ST-11 completed-bundle audit gate; ST-7 pause |
| `substrate-failure-paused` | the paused-from state it paused from (a `*-pending` state, or `settle-asymmetric`) \| `failed-substrate` | ST-7 |

**Rules:**

- (ST-1) **Forward-only.** Except for ST-7 resume, a transition MUST move toward a terminal state per the table. The orchestrator MUST NOT re-enter an earlier `*-pending` state (e.g. negotiate after commit).
- (ST-2) **Phase failure.** A phase returning `ok: false` MUST transition to that phase’s `*-failed` state, classified by the phase’s `errorClass`. An agreement commitment rejection (a CA-3 re-commitment for an already-anchored jobId, an artifact/phase mismatch, or an agreement failing the §8.5.2 listing-conformance checks) is a `commit-pending → commit-failed` transition (forward-only; it MUST NOT be folded back into `negotiate-failed`).
- (ST-3) **Abort.** A party MAY withdraw, or decline to co-sign, in `vet-pending`, `negotiate-pending`, or `commit-pending`; it MAY also withdraw in `settle-pending` only before any payment reaches rail finality and before any irreversible delivery/value release. Doing so terminates the session in an abort state. `rate-pending`, `audit-pending`, `settle-asymmetric`, and `substrate-failure-paused` are never abort-eligible: a party cannot relabel an already-irreversible commercial result as an abort. Withdrawing before being bound or before an irreversible effect is a legitimate exercise of a party’s right to decline — it is NOT a protocol violation, and an abort outcome is therefore distinct from a `*-failed` performance failure. The abort state is recorded from the perspective of the party anchoring the bundle (per §10.4.3 / §10.11): the withdrawing party’s own bundle records `aborted-by-self`; the non-withdrawing party’s bundle records `aborted-by-other`. (A withdrawing party need not anchor a bundle at all; the §10.11 bundle-suppression rule lets the non-withdrawing party’s single-signed `aborted-by-other` bundle stand.) How an abort bears on reputation is governed by §10.5 / §10.11, not by this transition rule. Abort states are terminal.
- (ST-4) **Rate branch.** `settle-completed` transitions to `rate-pending` iff the listing pipeline contains a rate phase; otherwise to `audit-pending`.
- (ST-5) **Rate is non-fatal.** A rate phase that fails or is declined does NOT fail the session: `rate-pending` transitions through `rate-completed` or directly to `audit-pending` regardless of rate outcome (per §10.6, absence of a rating does not block bundle production). There is deliberately no `rate-failed` state. A rate step parameter `{required: true}` is advisory for the rater’s own policy; it MUST NOT change this transition.
- (ST-6) **Terminal states.** The terminal states are exactly: `finalised`, `vet-failed`, `negotiate-failed`, `commit-failed`, `settle-failed`, `failed-substrate`, `aborted-by-self`, `aborted-by-other`. `SessionRecord.endedAt` MUST be set on entry to any terminal state. A failed/aborted terminal produces its bundle on entry; a successful session produces and finalizes its completed bundle during ST-11 before entry to `finalised`. `draft`, all `*-pending`, all non-failed `*-completed`, `rate-pending`, `audit-pending`, `settle-asymmetric`, and `substrate-failure-paused` are non-terminal.
- (ST-7) **Substrate-failure pause & resume.**
  - *Pause.* On `errorClass: "substrate"` (SR-2 or SR-3 unavailable, etc.) at any `*-pending` state **or at `settle-asymmetric`** (e.g. SR-2 is transiently unavailable when the orchestrator tries to anchor the ST-8 `:resolved` success record), the orchestrator MAY transition to `substrate-failure-paused`, recording the **paused-from state** (a `*-pending` state or `settle-asymmetric`), and retry per a backoff schedule.
  - *Resume.* On a successful retry the session resumes to the recorded paused-from state (the one permitted non-forward transition); the resumed phase/anchor MUST be idempotent or safe to re-drive (a phase that may have already broadcast an external effect — e.g. a pay-* phase — MUST check for that effect before re-issuing it).
  - *settle-asymmetric pause.* For a `settle-asymmetric` pause the retry window is additionally bounded by `expiry_source` (ST-8); if SR-2 cannot be reached to anchor the `:resolved` record before the per-listing pause maximum, the session transitions to `failed-substrate` (reputation-neutral) — NOT `failed-counterparty`, since the loss was substrate-induced, not a counterparty fault. (This applies only when the `htlc-claim` itself reached source-chain finality and only the *anchoring* is substrate-blocked; a payee that never claimed within the window is the genuine `failed-counterparty` loss of ST-8(b), not a substrate pause.)
  - *Time bound.* Pauses MUST be time-bounded; after a per-listing maximum pause (default 3600 seconds) the session MUST transition to `failed-substrate` (terminal). A successful resume clears the substrate condition: a subsequent failure of the resumed (or any later) phase is classified solely by that phase's own `errorClass`, independent of the prior `substrate` pause or pause-cycle count.
  - *Precedence over abort.* If, at an ST-3 abort-eligible state, a party withdrawal/decline and a `substrate` condition arise together, the abort wins: the session MUST enter the abort state rather than `substrate-failure-paused`. At `rate-pending`, `audit-pending`, `settle-asymmetric`, or a post-irreversibility `settle-pending`, ST-3 is unavailable and the substrate path wins.
- (ST-8) **Asymmetric open state & resolution.** A settle phase MAY reach an *asymmetric open* state in which value is committed on one leg but the resolving leg has not yet completed, within a **bounded recovery window**. Two cases reach it:
  - **HTLC-9 `dest-revealed-source-unclaimed`** (§9.5.4): the payer has claimed the destination (the preimage is public) but the payee's source-side `htlc-claim` has not yet landed; the payee retains a guaranteed window to claim the source (HTLC-7). Window bound = `expiry_source` (HTLC-7/HTLC-8). The asymmetric state MUST NOT be entered until the payer's destination claim has reached destination-chain finality (before that it is the in-flight/benign-timeout branch).
  - **tank `tank-locked-unreleased`** (§9.5.5): a liquidity-tank source lock reached finality but the destination release has not, and the substrate's native recovery path is still open. Window bound = `recoveryDeadline` (the substrate recovery-window deadline carried on the interim `liquidity-tank` txRef). The asymmetric state MUST NOT be entered until the source lock has reached finality.

  This is **not** a terminal failure. On detecting it, the settle phase anchors an interim SettlementEvidence (`outcome: "failure"`, `reason: dest-revealed-source-unclaimed` for HTLC-9 or `tank-locked-unreleased` for the tank) and the orchestrator transitions `settle-pending → settle-asymmetric` (non-terminal) rather than to `settle-failed`. The orchestrator MUST watch for the resolving leg until the case's window bound. *(This replaces routing a recoverable tank lock through the ST-7 substrate pause, whose per-listing pause maximum is far shorter than a substrate recovery window and would finalise a still-recoverable lock prematurely.)*

  **Resolution:**
  - (a) **Resolved** — the resolving leg completes within the window: HTLC-9, the `htlc-claim` reaches source-chain finality; tank, the bridge reaches `completed` (the destination release lands).
    - The pay phase returns `ok: true` and anchors a superseding `outcome: "success"` SettlementEvidence at the PC-2 address with a `:resolved` segment (`dacs4:payment:{jobId}:{railId}:{phaseIndex}:resolved`).
    - The success record carries `settlementFinality`, `paymentAmount`, the full txRef set (HTLC-9: `htlc-lock` + `htlc-reveal` + `htlc-claim`; tank: the `liquidity-tank` txRef with both `lockTxHash` and `releaseTxHash`), and `supersedesEvidenceRef` pointing to the interim record.
    - The orchestrator then resumes any remaining settle-stage phases per PIPE-3/PIPE-4. The session reaches `settle-completed` only once the whole settle stage completes; ST-4 then applies. The terminal `completed` bundle's settlementEvidence ref is the resolved success record.
    - *Blocked anchor.* If SR-2 is unavailable when anchoring the `:resolved` record, the session pauses (`settle-asymmetric → substrate-failure-paused`, ST-7) and retries within the case's window bound. Only if it cannot anchor before the pause maximum does the session go `failed-substrate` (reputation-neutral): a substrate-blocked anchor of an otherwise-final settlement MUST NOT be recorded as `failed-counterparty`.
  - (b) **Expired** — the window passes with the resolving leg incomplete. The interim failure record stands and the session transitions `settle-asymmetric → settle-failed` (terminal). The bundle records the cause **by case**: **HTLC-9 → `failed-counterparty`** (the payee never claimed the source — the genuine unresolved asymmetric loss, which DACS-X dispute may later address); **tank → `failed-substrate`** (reputation-neutral — the substrate's recovery path did not deliver the release or return the lock within `recoveryDeadline`; no party is at fault, exactly as the §9.5.5 substrate-recoverable lock is never `failed-counterparty`).
  - *Window bound.* The recovery window MUST be bounded by the case's bound — `expiry_source` for HTLC-9, `recoveryDeadline` for the tank. An implementation MAY finalise to `settle-failed` earlier only if the resolving leg can no longer complete.

> **Note (non-normative).** ST-8 adds no per-phase sub-state; the §10.3.1 transition table is per-stage. On resolution the HTLC pay *phase* returns ok, and the orchestrator's normal PIPE-3/PIPE-4 sequencer drives any remaining phases, exactly as a non-asymmetric settle would. Because resolution flows through the normal terminal states, DACS-5 derivation reads the terminal bundle `outcome` directly: no amendment scan is required, and no `correction` amendment is used for the success path.

- (ST-9) **Session-deadline timeout.** An ST-3 abort-eligible action state can have no exit when **neither** a party decision, a phase result, nor a substrate condition ever arrives — a counterparty simply goes silent. On a **session deadline** lapsing in `vet-pending`, `negotiate-pending`, `commit-pending`, or a pre-irreversibility `settle-pending`, with no pending phase result, the waiting party MAY finalise the session as **`aborted-by-other`** carrying the §10.4 `TimeoutMarker`, `endedAt` set, single-signed via the §10.11 bundle-suppression path. No new state or `outcome` is introduced. ST-9 MUST NOT fire from `rate-pending`, `audit-pending`, `settle-asymmetric`, `substrate-failure-paused`, or a post-irreversibility `settle-pending`; those states resolve through ST-5, ST-7, ST-8, or ST-11 without rewriting completed effects as an abort.
  - **Attribution.** The timeout is attributed to the party who **owed the awaited action** at that `*-pending` state — an objective state-machine fact, never motive inferred from silence. Conflicting cross-claims are reconciled by the dual-bundle rules (§10.4.3 / §10.11), exactly as for a disputed abort.
  - **Objective deadline.** The deadline MUST be an **objective** time — an SR-2 anchor time where the phase has one, else an agreed channel/substrate time source — and MUST NOT be a party-supplied `sentAt` / `generatedAt` / wall-clock value (a party could otherwise claim "not yet expired" to keep a stale session alive, or "already expired" to dodge a commitment). It is fixed at session/phase start, sourced per the listing or negotiate pattern.
  - **Reputation.** The timeout bundle remains an audit artifact whether or not the other party participated. It becomes reputation-bearing against a non-signing alleged obligor only when the current-profile deriver verifies that party's exact `SessionParticipationAdmission` under SPA-1..SPA-6. Authoritative absence proves non-publication, not participation; without the admission, the one-sided job is excluded from current-profile metrics without fault. The five older derivation shapes retain their frozen historical/partial semantics under AWT-8 and MUST NOT be presented as satisfying this participation-safe rule.
  - **Precedence.** Lowest. If a party decision (ST-3) or a substrate condition (ST-7) also applies, those win; the timeout fires only when nothing else did and the deadline lapsed. (CORE §B.8 SN-4 separately bounds the verifier's challenge-nonce lifetime for an abandoned session; ST-9 is the complementary state-machine terminal that gives the session a real end state.)

- (ST-10) **Policy-permitted pre-commit cancellation.** A listing MAY advertise a `cancellationPolicy` (DACS-1 §6). When that policy permits cancellation and a party withdraws while the session is still **pre-commit** — a `vet-pending` or `negotiate-pending` state, before `commit-completed` — the withdrawal is the same `aborted-by-self` transition as ST-3, with **no new state and no new `outcome`**; the anchoring party MAY additionally attach a `cancellation` marker (§10.4) recording the `claimedPolicy` value. The marker does not alter the recorded `outcome`; it is an assertion, evaluated at reputation-derivation time, that the withdrawal exercised an **advertised** right rather than bailing on a counterparty who had no notice. Without the marker, a pre-commit withdrawal is an ordinary ST-3 abort.
  - **Teeth (verification).** A consumer MUST treat the marker as established only if it resolves the bundle's `listingRef` `(listingId, version, contentHash)` to a listing whose `ListingSignature` (DACS-1) is present and verifies over the listing payload, **and** that **signed** listing's `cancellationPolicy` permits cancellation at the point the session ended (`pre-commit` for a pre-commit-state withdrawal), **and** the session did end pre-commit (no `agreementRef`; no `commit-completed` in `phaseSummary`). The binding policy MUST be read from the signed listing, never from the marker's self-asserted `claimedPolicy` — the signature over the listing is what makes the advertised policy non-repudiable.
  - **Trichotomy (do not collapse).** The teeth check has three outcomes, mirroring the §7.5.1 `pass`/`fail`/`indeterminate` decision semantics and the SB-3 third branch:
    - *resolves and permits* → the marker is **established**; §10.5.1 treats the `aborted-by-self` as **reputation-neutral**.
    - *resolves and forbids* (policy `none`, or a `pre-commit` claim on a session that actually reached `commit-completed`) → the marker is **refuted**; the `aborted-by-self` stands as the party-fault it already is.
    - *cannot be resolved* (listing pruned, signature transiently unverifiable, substrate unreachable) → the claim is **neither established nor refuted**: the consumer MUST NOT grant neutrality — that would rebuild the self-declared "don't count this" the teeth exist to prevent, since any party could cite an unresolvable listing for a free pass — and MUST NOT book the cancellation as a *fresh* fault on the unproven claim. The session is **indeterminate for reputation**, excluded from the derivation denominators pending resolution, exactly as an unresolved §7.5.1 `indeterminate`.
  - **Symmetry.** A policy-permitted cancellation is neutral for both parties — there is no `-by-self`/`-by-other` blame to split. The counterparty's copy, if any, records `aborted-by-other` per ST-3, and the same teeth check applied to it yields the same neutral result; mutual notice is what earns the mutual neutrality. Because the neutrality is symmetric, a consumer MUST resolve the `cancellation` marker across **both** non-divergent copies of the session — a marker carried on *either* copy establishes the cancellation for *both* parties' scores. A one-sided marker is **not** a §10.4.3 canonical divergence (that definition is scoped to `outcome` / `phaseSummary`), so it MUST NOT be treated as an advisory one-sided field; otherwise the neutral (and the indeterminate) verdict would collapse for the party whose own copy omits the marker (§10.5.1 resolves it at jobId reconciliation).
  - **Precedence.** A cancellation is a deliberate party action and ranks **with** abort (ST-3), above the ST-9 timeout: a party electing to cancel within an open deadline does so as a party decision, not a timeout. `with-fee` cancellation — a cancellation owing a fee after `commit-completed` — is **not defined** here; only the `pre-commit` case is honoured, and a `with-fee` value confers no neutrality.

- (ST-11) **Completed-bundle audit gate.** After the last successful settle/rate step, the session enters `audit-pending`; it does not enter `finalised` merely because commercial performance is complete. During `audit-pending`, the producer MUST:
  1. obtain and verify a CORE §5.1 `finalized` `AnchorReceipt` for every required DACS-2 composite record, the DACS-3 commitment, and every DACS-4 settlement/delivery evidence record;
  2. independently resolve each receipt's native address, recompute the referenced artifact's canonical content hash, and match its logical/session bindings;
  3. construct and obtain all required signatures on the completed bundle, anchor the role-specific copy under §10.4.2, and obtain a verified `finalized` receipt for the bundle itself; and
  4. publish the applicable logical→native `BundleBinding` on a write-input substrate.

  Only then may `audit-pending → finalised`. External indexer visibility never gates this transition. A rail-final payment whose `SettlementEvidence` anchor is pending remains a successful payment under DACS-4 PC-7 while the session remains `audit-pending`; the producer MUST retry only the idempotent evidence anchor and MUST NOT resubmit payment. If a required anchor has an established `dropped`, `replaced`, `expired`, or `reorged` state, or an `indeterminate` observation disposition over its preserved state, the producer follows CORE §5.1 reconciliation and remains non-terminal. SR-2 unavailability transitions `audit-pending → substrate-failure-paused`; ST-7 resumes to `audit-pending` or, after its bounded retry period, transitions to `failed-substrate`. It MUST NOT rewrite a rail-final payment as a payment failure or attribute the substrate failure to either party.

**State → bundle `outcome` mapping (normative).** Every terminal state maps to exactly one bundle `outcome` (all three bundle types share the enum) (§10.4), partitioned by the terminal phase’s `errorClass` where applicable:

| Terminal state | errorClass | Bundle `outcome` |
|----------------|-----------|------------------|
| `finalised` | — | `completed` |
| `vet-failed` / `negotiate-failed` / `commit-failed` / `settle-failed` | `permanent` | `failed-perm` |
| (same) | `counterparty` | `failed-counterparty` |
| (same) | `transient` (retry budget exhausted) | `failed-perm` |
| (same) | `settlement-atomicity` | `failed-counterparty` |
| (same) | `substrate` | resolves via ST-7 to `failed-substrate`, never a `*-failed` terminal |
| `failed-substrate` | `substrate` | `failed-substrate` |
| `aborted-by-self` | — | `aborted-by-self` |
| `aborted-by-other` | — | `aborted-by-other` |

- `transient` after retry-budget exhaustion is a permanent inability to complete the phase → `failed-perm`.
- `settlement-atomicity` (one side of a cross-chain settlement landed, the other did not) is attributed to the counterparty/rail, not the local party → `failed-counterparty`.
- A `settle-failed` with `settlement-atomicity` is reached only **after** the asymmetric open state (ST-8) has been entered and its recovery window has expired without resolution. While the window is open the session is in the non-terminal `settle-asymmetric` state, and an `htlc-claim` reaching source-chain finality within the window resolves it forward (the pay phase returns ok and the per-stage sequencer completes any remaining settle phases) through `settle-completed → audit-pending → finalised` (terminal `completed`) per ST-8/ST-11 — so a late-settling-but-successful cross-chain swap is recorded as `completed`, not as a failure.
- No terminal state lacks an `outcome`, and no `outcome` lacks a producing terminal state; `settle-asymmetric` is non-terminal and therefore produces no bundle until it resolves.

#### 10.3.2 Signed participation admission (SPA-1..SPA-8)

`SessionRecord` is mutable orchestrator state and cannot prove that a named counterparty joined a session. Before a one-sided abort can blame a party that did not sign the terminal bundle, that party signs a distinct admission only after the named phase becomes active and the named action becomes due:

```
type SessionParticipationAdmission = {
  participationAdmissionVersion: "1"
  jobId: string
  listingRef: { listingId: string; version: number; contentHash: string }
  agreementRef?: AttestationRef                 // REQUIRED only after commit-completed; for settle-stage obligations it exactly equals the terminal bundle's agreementRef
  proposedAgreementHash?: string                // REQUIRED only for a commit-pending/co-sign-agreement obligation; lowercase 64-hex hash of the exact proposed AgreementArtifact
  parties: ParticipationParty[]                 // exact admitted roster, canonical ascending (role, primaryClaim, bundleHash)
  completedPrefix: ParticipationPhase[]         // every earlier effective-pipeline phase, indices 0..phaseIndex-1, each acknowledged successful
  phaseIndex: number
  phaseKind: PhaseType                          // the concrete effective-pipeline phase now active; never pay-alternative or rate
  pendingState: "vet-pending" | "negotiate-pending" | "commit-pending" | "settle-pending"
  obligorRole: "buyer" | "seller"              // role whose exact primary claim signs this admission
  owedAction: "present-credentials" | "respond-to-negotiation" | "co-sign-agreement" | "authorize-payment" | "deliver"
  deadline: number                              // unix ms accepted by the obligor; tested only against authenticated consensus time
  deadlinePolicy: "obligor-admitted-absolute-consensus-deadline"
  deadlineClock: "sr2-finalized-inclusion-timestamp"
  sessionNonce: string                          // signer-generated 32-byte nonce, lowercase 64-hex, fresh across that signer's sessions
  admittedAt: number                           // advisory producer time; never establishes activation or deadline passage
  signature: ComponentSignature                // obligor signature under dacs-participation-admission:v1:
}

type ParticipationParty = {
  role: "buyer" | "seller" | "orchestrator"
  primaryClaim: ClaimReference
  bundleHash: string
}

type ParticipationPhase = {
  index: number
  kind: PhaseType
  outcome: "ok"
}
```

The artifact follows the §B.2 canonical-form template, omitting `signature`. Its hash is `sha256(canonical_JCS(admission_without_signature))`; `signature.value` is over `"dacs-participation-admission:v1:" || admission_hash` and uses CORE §B.7 SIG-6. It is anchored by the obligor through SR-2 at `dacs5:participation:{jobId}:{obligorRole}:{phaseIndex}` (each segment CF-4 encoded). The admission's independently verified finalized receipt is the authenticated activation acknowledgement; `admittedAt` is never a clock or ordering source.

- (SPA-1) **Type and signer.** A verifier MUST require exactly `participationAdmissionVersion: "1"`, the closed schema above, a canonical hash, the registered domain, and a valid signature whose `signature.signer` equals the unique `parties[].primaryClaim` at `obligorRole`. Unknown, stripped, or multiply-present type discriminators are rejected before the artifact is used.
- (SPA-2) **Exact session and roster.** `jobId` and `listingRef` MUST equal the selected terminal bundle's values byte-for-byte. The canonical `parties` set MUST equal the projection `(role, primaryClaim, bundleHash)` of that bundle's complete party set; every role is unique. For a settle-stage obligation, `agreementRef` is REQUIRED and MUST equal the bundle's reference in full canonical form. For a commit-stage obligation, `proposedAgreementHash` is REQUIRED and `agreementRef` is absent. Both agreement members are absent in vet/negotiate admissions. A mismatch is rejection, never partial credit.
- (SPA-3) **Authenticated activation.** The verifier MUST resolve and verify the signed Listing and independently derive its effective pipeline, applying DACS-4 APR-1..APR-4 when `pay-alternative` is projected. `phaseIndex` MUST select `phaseKind` in that effective pipeline. `completedPrefix` MUST be the duplicate-free, ordered, contiguous prefix `0..phaseIndex-1` of that same pipeline, every entry `outcome: "ok"`, and MUST full-canonical-value match the corresponding successful entries in the terminal bundle's authenticated `phaseSummary`. The admission signature is the obligor's acknowledgement that this exact prefix completed and the next named action became due; a phase omitted from the prefix, outside the pipeline, or never reached cannot borrow the admission.
- (SPA-4) **Exact obligation and policy.** `(pendingState, phaseKind, owedAction)` MUST follow this closed mapping: `vet-pending` + `vet-credentials` + `present-credentials`; `negotiate-pending` + any `negotiate-*` + `respond-to-negotiation`; `commit-pending` + either `commit-*` + `co-sign-agreement`; or `settle-pending` + a concrete `pay-*` + `authorize-payment`, or a `deliver-*` + `deliver`. `pay-alternative`, `rate`, post-irreversibility settlement, and every other combination are ineligible. `deadlinePolicy` MUST be exactly `obligor-admitted-absolute-consensus-deadline`: the obligor accepts the absolute deadline and the only permitted comparison clock in the same signed artifact. The selected bundle MUST carry a `TimeoutMarker` whose `pendingState`, `phaseIndex`, `phaseKind`, `obligorRole`, `owedAction`, `deadline`, `deadlinePolicy`, and `deadlineClock` equal the admission fields exactly; `obligorRole` MUST be the bundle role against which the abort would be attributed.
- (SPA-5) **Objective time and anchor binding.** The current derivation MUST independently verify an established/finalized SR-2 receipt for the exact admission at its exact logical/native address, content hash, transaction, writer, nonce, and applicable finality evidence. Its `blockRef.timestamp` MUST be strictly earlier than `deadline`; the exact selected terminal bundle's AWT-verified `windowReceipt.blockRef.timestamp` MUST be at or after `deadline`; and both receipts MUST use the same substrate clock domain. Every known admission-receipt snapshot is reconciled with AWT-4's native-order/lifecycle rules. Missing, non-final, reorged, replaced-only, mismatched, or unorderably conflicting proof is `indeterminate`; neither `admittedAt`, bundle `finalisedAt`, nor observer time may substitute.
- (SPA-6) **One-sided blame gate.** In `derive_authenticated_window`, if the selected authoritative bundle lacks all §10.4.1 required signatures and would attribute an abort to a party whose bundle signature is absent, that job enters `reconciled` only after SPA-1..SPA-5 verify the absent party's admission and the bundle's exact `TimeoutMarker`. Authoritative bundle absence remains independently REQUIRED by §10.4.3/guard (iv). Missing, rejected, or indeterminate admission or timeout evidence excludes the job from every current-profile numerator, denominator, rating, volume, `bundleCount`, and `bundleRefs`, without creating a different fault. A single-signed abort whose blamed party signed that exact bundle is self-admitted and does not require a separate admission.
- (SPA-7) **Ordinary-rating admission.** `derive_authenticated_window` MUST aggregate a `RatingRecord` only from a fully §10.4.1-signed `completed` bundle whose independently verified signed Listing/effective pipeline contains exactly the referenced `rate` phase and whose authenticated `phaseSummary` records that phase at the same index with `outcome: "ok"`. The rating reference MUST be present in that bundle; `r.jobId` MUST equal the bundle job; `r.rater` and `r.target` MUST each equal a unique buyer/seller `parties[].primaryClaim`; they MUST differ; and `r.targetRole` MUST equal the exact role of `r.target`. An abort, failure, absent/non-successful rate phase, role mismatch, or non-roster target is excluded from ordinary rating metrics. A dispute/adjudication rating requires a future distinct DACS-X artifact and is not a `RatingRecord` shortcut.
- (SPA-8) **Replay and compatibility.** `AuthenticatedWindowResolutionContextEntry.participationEvidence` is REQUIRED exactly for the SPA-6 external-admission case and absent otherwise. Replay re-resolves the admission, signature, Listing/effective pipeline, exact roster/obligation/prefix, all receipt history, objective time relation, and selected bundle before comparing metrics. Changed, omitted, unused, or substituted evidence makes the current receipt non-conforming. The five pre-current derivation shapes and their rating rules remain byte- and meaning-compatible historical/partial signals under AWT-8; they cannot claim SPA-safe reputation.

#### 10.3.3 Persistence and visibility

SessionRecord is off-chain by default. The orchestrator persists it locally. Counterparties MAY exchange partial views (e.g., the buyer needs to see the seller’s VerifyResultRef from Vet) but each side maintains its own canonical SessionRecord. On bundle production (end of session), the bundle’s contents are derived from the SessionRecord; the SessionRecord itself is not anchored on chain.

### 10.4 Attestation bundle

The frozen end-of-session artifact. Signed by all parties; anchored via SR-2.

Three bundle types share this section. The legacy **`AttestationBundle`** (`bundleVersion: "1"`) reads fault role-relatively. **`FaultAttestationBundle`** (`faultBundleVersion: "1"`) carries absolute hashed fault attribution. DACS-5 v0.4 adds **`EvidenceBoundFaultAttestationBundle`** (`evidenceBoundFaultBundleVersion: "1"`), which preserves the fault bundle fields and additionally makes SEB-1..SEB-6 part of that distinct type's validity contract. Rules apply to all three types except where they name a narrower type.

```
type AttestationBundle = {

  bundleVersion: "1"                                    // the legacy class's §11.2.5 version literal. Fault is read role-relatively from `outcome` (§10.4.1); new v0.3 production anchors FaultAttestationBundle instead

  jobId: string

  outcome: "completed" | "failed-perm" | "failed-counterparty" | "failed-substrate" | "aborted-by-self" | "aborted-by-other"

  anchoredByRole: "buyer" | "seller" | "orchestrator"   // provenance: which party anchored THIS copy; `outcome` is spelled from this party's perspective and, on this legacy class, fault is read role-relatively through it (§10.5.1). Excluded from the hash; forgery-protected by the §10.4.2 cross-check

  listingRef: { listingId: string; version: number; contentHash: string }

  agreementRef?: AttestationRef               // present iff the session reached commit-completed or later; omitted only when terminated before the agreement commitment phase (see §10.4.3)

  cancellation?: CancellationMarker           // present only on an aborted-by-self/other claimed as a policy-permitted pre-commit cancellation (§10.3.1 ST-10); verified at reputation-derivation time against the signed listing, never trusted as asserted

  timeout?: TimeoutMarker                     // present on an ST-9 timeout abort; current-profile one-sided blame against a non-signer requires its exact SPA-bound facts

  parties: BundleParty[]

  phaseSummary: BundlePhaseEntry[]

  vetRecords: AttestationRef[]                // composite verification records

  settlementEvidence: AttestationRef[]

  amendments?: AttestationRef[]

  ratingRefs?: AttestationRef[]               // when the rate phase ran

  recipeRegistryVersion: number               // DACS-2 registry pinned at session start

  railRegistryVersion: number                 // DACS-4 registry pinned at session start

  finalisedAt: number

  signatures: BundleSignature[]               // both buyer and seller (and orchestrator if separate)

}

type CancellationMarker = {

  claimedPolicy: "pre-commit"                 // the listing cancellationPolicy value the canceller invokes; only "pre-commit" is honoured (with-fee is reserved, not defined). The consumer reads the binding policy from the signed listing, never from this asserted value (§10.3.1 ST-10).

}

type TimeoutMarker = {
  pendingState: "vet-pending" | "negotiate-pending" | "commit-pending" | "settle-pending"
  phaseIndex: number
  phaseKind: PhaseType
  obligorRole: "buyer" | "seller"
  owedAction: "present-credentials" | "respond-to-negotiation" | "co-sign-agreement" | "authorize-payment" | "deliver"
  deadline: number
  deadlinePolicy: "obligor-admitted-absolute-consensus-deadline"
  deadlineClock: "sr2-finalized-inclusion-timestamp"
}

type BundleParty = {

  role: "buyer" | "seller" | "orchestrator"

  bundleHash: string

  primaryClaim: ClaimReference

}

type BundlePhaseEntry = {

  index: number

  kind: PhaseType

  outcome: "ok" | "fail"

  errorClass?: "permanent" | "transient" | "counterparty" | "substrate" | "settlement-atomicity"

  retryExhausted?: true                       // OPTIONAL and non-action-bearing for released AttestationBundle/FaultAttestationBundle v1. SEB-1 requires it exactly when an EBFAB terminal `fail` with errorClass `transient` maps to `failed-perm`; it is hashed through phaseSummary and authenticated by that EBFAB's signatures.

  txRefs?: ChainTxRef[]

  attestationRef?: AttestationRef             // OPTIONAL per-phase back-pointer to the artifact this phase produced (settle → its SettlementEvidence, vet → its VerifyResult). The authoritative attestation set is the top-level settlementEvidence[] / vetRecords[]; see §10.4.3.

}

type BundleSignature = {

  party: ClaimReference                       // primary claim of the signer

  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"

  value: string                               // unpadded Base64URL (CORE §B.7 SIG-6) signature over the type's §10.4.1 registered domain separator || attestation_bundle_hash, NOT the raw bundle hash

}
```

**FaultAttestationBundle (v0.3 production type).** The absolute-fault variant of the end-of-session artifact. Identical to `AttestationBundle` in every shared field's meaning; it differs in exactly two ways: its version literal is `faultBundleVersion` (its structural discriminator — CORE §11.1.2 new-type refusal), and it carries the REQUIRED hashed `faultedParty`. It signs under its own `dacs-fault-bundle:v1:` domain (§B.7).

```
type FaultAttestationBundle = {
  faultBundleVersion: "1"                     // the type's §11.2.5 version literal and structural discriminator: a FaultAttestationBundle carries `faultBundleVersion` and never `bundleVersion`
  jobId: string
  outcome: "completed" | "failed-perm" | "failed-counterparty" | "failed-substrate" | "aborted-by-self" | "aborted-by-other"
  faultedParty: "buyer" | "seller" | "orchestrator" | "none"   // REQUIRED. The ABSOLUTE party responsible for `outcome`, perspective-independent (unlike `anchoredByRole`). Hashed. Permissible-set and consistency rule in §10.4.1
  anchoredByRole: "buyer" | "seller" | "orchestrator"   // provenance: which party anchored THIS copy. `outcome` is spelled from this party's perspective, but fault attribution does NOT read `outcome` through this field — it reads the absolute hashed `faultedParty` (§10.5.1). Excluded from the hash; forgery-protected by the §10.4.2 cross-check
  listingRef: { listingId: string; version: number; contentHash: string }
  agreementRef?: AttestationRef
  cancellation?: CancellationMarker
  timeout?: TimeoutMarker
  parties: BundleParty[]
  phaseSummary: BundlePhaseEntry[]
  vetRecords: AttestationRef[]
  settlementEvidence: AttestationRef[]
  amendments?: AttestationRef[]
  ratingRefs?: AttestationRef[]
  recipeRegistryVersion: number
  railRegistryVersion: number
  finalisedAt: number
  signatures: BundleSignature[]               // both buyer and seller (and orchestrator if separate); each value over the FaultAttestationBundle domain-separated payload (§10.4.1)
}
```

**EvidenceBoundFaultAttestationBundle (v0.4 exact-set type).** This type has every shared field and absolute-fault rule of `FaultAttestationBundle`, but replaces `faultBundleVersion` with the structural discriminator `evidenceBoundFaultBundleVersion`. Its validity additionally requires the SEB-1..SEB-6 exact-set contract in §10.4.3. It signs under the distinct `dacs-evidence-bound-fault-bundle:v1:` domain. The new discriminator and domain prevent an older reader from accepting the object while silently omitting the new action-bearing validation.

```
type EvidenceBoundFaultAttestationBundle = {
  evidenceBoundFaultBundleVersion: "1"        // structural discriminator; carries neither bundleVersion nor faultBundleVersion
  jobId: string
  outcome: "completed" | "failed-perm" | "failed-counterparty" | "failed-substrate" | "aborted-by-self" | "aborted-by-other"
  faultedParty: "buyer" | "seller" | "orchestrator" | "none"
  anchoredByRole: "buyer" | "seller" | "orchestrator"
  listingRef: { listingId: string; version: number; contentHash: string }
  agreementRef?: AttestationRef
  cancellation?: CancellationMarker
  timeout?: TimeoutMarker
  parties: BundleParty[]
  phaseSummary: BundlePhaseEntry[]
  vetRecords: AttestationRef[]
  settlementEvidence: AttestationRef[]
  amendments?: AttestationRef[]
  ratingRefs?: AttestationRef[]
  recipeRegistryVersion: number
  railRegistryVersion: number
  finalisedAt: number
  signatures: BundleSignature[]
}
```

A consumer that does not support `EvidenceBoundFaultAttestationBundle` MUST reject its discriminator as unsupported and MUST NOT strip or rename it to reinterpret the object as either older bundle type (CORE §11.1.2). Conversely, an SEB-conforming consumer MUST NOT claim SEB validation for an `AttestationBundle` or `FaultAttestationBundle`; those released types retain their v0.3 validity semantics.

Except for discriminator, signature-domain, extended-pointer, and SEB-specific rules, every rule naming `FaultAttestationBundle` also applies to `EvidenceBoundFaultAttestationBundle`. For pair reconciliation both are absolute-fault types: any pair of absolute-fault copies uses the `faultedParty` plus outcome-class rule, including a mixed pair of these two types. Only an `EvidenceBoundFaultAttestationBundle` copy makes an SEB claim.

#### 10.4.1 Canonical serialisation, hash, and domain-separated signature

Per the §B.2 canonical-form template, omit `signatures` and `anchoredByRole` identically for all three bundle types. Every other field is hashed, including exactly one type discriminator and `faultedParty` on either absolute-fault type. The **attestation-bundle hash** (`attestation_bundle_hash`) is sha256(canonical_form), hex-encoded. Each `BundleSignature.value` MUST use the matching domain-separated payload:

signed_bytes := "dacs-bundle:v1:" || attestation_bundle_hash            (AttestationBundle)
signed_bytes := "dacs-fault-bundle:v1:" || attestation_bundle_hash      (FaultAttestationBundle)
signed_bytes := "dacs-evidence-bound-fault-bundle:v1:" || attestation_bundle_hash (EvidenceBoundFaultAttestationBundle)

The three domains are distinct §B.7 registry entries: a signature over one type MUST NOT validate for another.

`BundleSignature.value` and each DACS-5 `ComponentSignature.value`, including a
rating signature, MUST use CORE §B.7 SIG-6. The encoded value carries the
signature over `signed_bytes`, not over the raw bundle hash.

> **Note (non-normative).** `anchoredByRole` is per-copy — buyer vs seller vs orchestrator — and is carried only for derive()'s perspective read (§10.5.1); it is excluded from the hashed canonical form exactly like `signatures` so the two-sided copies remain canonically equal in the happy path. This is a recognised, specified omission, not a SIG-5 silent strip.

**Absolute fault attribution (`faultedParty`).** `faultedParty` names the party responsible for `outcome` in absolute terms, independent of which copy carries it. It is REQUIRED on both absolute-fault bundle types and does not exist on legacy `AttestationBundle`. It is hashed. For a copy whose `anchoredByRole` is R, the permissible values are fixed by `outcome`:

| `outcome` | permissible `faultedParty` |
|-----------|----------------------------|
| `completed` | `none` |
| `failed-substrate` | `none` |
| `failed-perm` | R |
| `aborted-by-self` | R |
| `failed-counterparty` | any party role in this session's `parties[]` other than R |
| `aborted-by-other` | any party role in this session's `parties[]` other than R |

- A `FaultAttestationBundle` producer MUST set `faultedParty` to the actual responsible party within the permissible set. In a two-party session the counterparty rows admit exactly one value (the buyer↔seller involution partner), preserving the prior exact mapping byte-for-byte; in a session with a distinct orchestrator the producer names whichever non-R party was responsible. An orchestrator-anchored copy (R = orchestrator) follows the same rule.
- A consumer MUST reject a `FaultAttestationBundle` copy that omits `faultedParty`.
- A consumer MUST reject a `FaultAttestationBundle` copy whose `faultedParty` is outside the permissible set for its `(outcome, anchoredByRole)`.
- The perspective-paired copies of one session MUST carry an identical `faultedParty`, since they name the same responsible party in absolute terms.

*Example.* A seller aborts. The buyer anchors `{outcome: "aborted-by-other", anchoredByRole: "buyer", faultedParty: "seller"}` and the seller's own copy anchors `{outcome: "aborted-by-self", anchoredByRole: "seller", faultedParty: "seller"}`. The role-relative `outcome` spelling differs, but both name the seller, so the absolute attribution is identical and the deriver reads fault from `faultedParty` (§10.5.1).

Under DACS-5 v0.4 a producer claiming SEB-1..SEB-6 exact-set conformance MUST anchor `EvidenceBoundFaultAttestationBundle` records. Existing `AttestationBundle` and `FaultAttestationBundle` records remain valid under their released semantics; neither gains the SEB contract retroactively.

> **Note (non-normative).** `faultedParty` makes fault role-invariant. On the legacy `AttestationBundle`, fault is read from the role-relative `outcome` through the unhashed `anchoredByRole`, so a counterparty could re-anchor a single-signed abort under its own role and silently reverse blame. Hashing fault as an absolute party closes that rebind: it either contradicts the mapping and is rejected, or forces a re-signed divergent copy that voids the side under §10.4.3(d). Legacy `AttestationBundle` records are never rewritten and keep the pre-faultedParty residual; `FaultAttestationBundle` closes it under v0.3.

The three registered bundle prefixes prevent cross-protocol and cross-type signature replay even if hash bytes collide.

Verification and signer rules:

- Verifiers MUST recompute the canonical form, the bundle hash, and the prefixed signed_bytes, and verify each signature against the appropriate party’s primary-claim key.
- Required signers: buyer + seller. If the orchestrator is a distinct party (not buyer or seller), the orchestrator signature is also REQUIRED.
- Bundles whose outcome is `completed`, `failed-perm`, `failed-counterparty`, or `failed-substrate` and that are missing any required signature MUST be rejected by consumers.
- A bundle whose outcome is `aborted-by-self` or `aborted-by-other` MAY carry a single signature; consumers MUST NOT reject it on that basis but MUST classify it per the bundle-suppression rule in §10.11.

#### 10.4.2 Anchoring

The bundle MUST be anchored via SR-2. **Two-sided anchoring scheme:**

- Each signing party (buyer, seller, and orchestrator if distinct) anchors its own bundle at a party-specific **logical** address: `stor-{sha256(jobId + "-bundle-" + role)}` where role is "buyer", "seller", or "orchestrator". How this logical address maps to the substrate's native address is governed by the "Logical vs native bundle addresses" rules below (BB-1..BB-8). On a write-input-mapping substrate the native address is **not** recomputed from this logical form — it is resolved through the published `BundleBinding`.
- **Each anchored copy MUST set `anchoredByRole` to the role of the anchoring party, and that value MUST equal the `role` segment of the logical address the copy is bound to (§10.4.2).**
- **A consumer MUST reject a copy whose `anchoredByRole` does not match the role under which it was resolved:** on a pure-mapping substrate, the `role` segment of the address it was fetched from; on a write-input-mapping substrate, the verified `role` of the `BundleBinding` it was resolved through (BB-4/BB-5). Since `anchoredByRole` is excluded from the hash per §10.4.1, this cross-check is what protects it from forgery. On a pure-mapping substrate the address itself carries the role; on a write-input substrate the role is carried by the binding, established jointly by the BB-4 signature verification and the BB-5 post-fetch check that `signer` is the bundle party holding `role`.
- **A consumer MUST reject a `FaultAttestationBundle` copy whose hashed `faultedParty` is outside the §10.4.1 permissible set for its `(outcome, anchoredByRole)`.** A copy re-anchored under the wrong role fails this check, since `faultedParty` is hashed and absolute.

In the happy case both sides’ bundles are canonically equal (they differ only in the unhashed `anchoredByRole`) and consumers can read either; in the divergence case both sides are independently retrievable for dispute purposes (see §10.4.3).

**Logical vs native bundle addresses.** The role-specific `stor-{sha256(jobId + "-bundle-" + role)}` value is the bundle's *logical* address: substrate-independent, and derivable by any party from `(jobId, role)` alone. It is an address kind in its own right (CORE §B.1 CF-4 table); it is not a `dacsN:`-form address. The universal mapping rule (DEMOS-MAPPING §A.2) applies to it identically: on a pure-mapping substrate the native address is computed directly from the logical form; on a write-input-mapping substrate it MUST be resolved through a published `BundleBinding` and is not recomputable from the logical form.

**Demos binding (bundle).** On Demos, StorageProgram addressing folds write inputs into the native address, exactly as for listings (DACS-1 §6.3.4):

```
logical_bundle_address := "stor-" + sha256(jobId + "-bundle-" + role)             // 64 hex; derivable offline
storageProgramName     := implementation-defined colon-free StorageProgram name   // opaque write input
native_address         := "stor-" + first40hex( sha256( deployerAddress + ":" + storageProgramName + ":" + nonce + ":" + salt ) )
```

Both forms carry the `stor-` prefix and are distinguished by digest length: the logical form carries 64 hex characters, the native form 40. `storageProgramName` is an opaque write input: DACS defines no reversible logical→name encoding, and different conforming producers MAY choose different names for the same logical address. A consumer MUST NOT treat the name as a resolution key.

**BundleBinding (normative object).**

```
type BundleBinding = {
  bindingVersion: "1"
  jobId: string
  role: "buyer" | "seller" | "orchestrator"
  logicalAddress: string          // the derived logical bundle address, carried explicitly
  nativeAddress: string           // the write-input-derived native address the copy is anchored at
  bundleContentHash: string       // the anchored copy's §10.4.1 `attestation_bundle_hash` (sha256 hex of its canonical form), matched byte-for-byte at BB-5
  anchorTx?: string               // the SR-2 anchor transaction — the canonical pointer, when known
  signer: ClaimReference          // primary claim of the anchoring party; MUST be a party to the bundle
  signature: ComponentSignature   // over "dacs-bundle-binding:v1:" || sha256(canonical form), per §B.7; canonical form per the §B.2 template, omitting `signature`
}
```

Rules:

- (BB-1) On a write-input-mapping substrate, each anchoring party MUST publish a signed `BundleBinding` for its own anchored copy.
- (BB-2) Each anchoring party MUST make its signed binding available on its own §6.3.5 well-known index or on a §6.3.6 catalog. Where neither surface is available to the party, delivery of the signed binding to the counterparty for carriage satisfies this rule.
- (BB-3) A `BundleBinding` is self-authenticating; any discovery surface MAY serve any signed binding verbatim.
- (BB-4) A consumer MUST verify a `BundleBinding` before use: `signature.signer` MUST equal the top-level `signer`, and `signature` MUST verify over the domain-separated payload against `signer`'s primary-claim key. A binding failing either check MUST be discarded.
- (BB-5) A consumer resolves a side's native address from `(jobId, role)` by first deriving the logical address (§10.4.2). On a pure-mapping substrate the native address is then computed directly from the logical form, and no `BundleBinding` is involved. On a write-input-mapping substrate the consumer MUST resolve through published bindings, applying every check below and rejecting on any failure:
  1. resolve `BundleBinding`s whose `logicalAddress` matches, from the discovery surfaces it consults;
  2. reject any binding failing BB-4;
  3. reject any binding whose `bindingVersion` the consumer does not support;
  4. reject any binding whose `jobId` or `role` does not equal the requested `(jobId, role)`;
  5. reject any binding whose `logicalAddress` does not equal the logical address derived from its own signed `jobId` and `role` (§10.4.2);
  6. fetch each surviving `nativeAddress`;
  7. reject any fetched bundle whose `jobId` does not equal the binding's `jobId`;
  8. reject any fetched bundle whose §10.4.1 `attestation_bundle_hash` does not equal the binding's `bundleContentHash`, byte-for-byte;
  9. reject any fetched bundle whose signing party holding `role` is not the binding `signer`, or that fails the §10.4.2 `anchoredByRole` cross-check or the §10.4.1 signature rules.
  The lookup takes no `storageProgramName` input. A validly-signed but internally inconsistent binding MUST be rejected, never accepted as a resolution context.
- (BB-6) Multiplicity and authorization. The candidate set for one `(jobId, role)` is the BB-4-valid bindings passing BB-5 checks 1–5, grouped by authenticated `signer`. A candidate is **authorized** when its `signer` is established as the bundle party holding `role`: pre-fetch, by matching the role→primary-claim map of an already-fetched copy of the same `jobId` carrying all §10.4.1 required signatures; otherwise post-fetch, by BB-5 check 9. Where such a co-signed map is available the consumer MUST prune the candidate set to the mapped signer's bindings before any fetch. In a reputation-derivation context the role→primary-claim map is always constructible — from the scored party's own copy, the pinned agreement's `parties[]` (§7.5.2 resolution), or a co-signed copy — so the prune is MANDATORY there and MUST be applied before any candidate consumes fetch work in that path. The consumer MUST fetch candidates' distinct `nativeAddress` values in ascending `bundleContentHash` order (ties broken by ascending `nativeAddress` — a total order), at most N = 8 authorized-or-unresolved candidates per authenticated `signer` per `(jobId, role)`; a signer's candidates never consume another signer's budget, so an outsider cannot exhaust the honest role-holder's allocation. A fetched copy failing post-fetch authorization is discarded and **inert**: it MUST NOT count toward collapse, precedence, or void. If the budget exhausts while candidate addresses remain unfetched, the side's read disposition is `indeterminate` (BB-7) — never `absent`, never a void. Among **authorized** copies: canonically equal copies (§10.4.1) collapse to one retrieved copy; among canonically unequal copies, one carrying all §10.4.1 required signatures takes precedence and lesser-signed copies MUST be discarded; only when canonically unequal authorized copies are of equal signature standing is the side equivocating without a governing record — the consumer MUST NOT select among them and that side's read disposition is `indeterminate`. §10.4.3 classification proceeds on the read dispositions so established.
- (BB-7) Fail closed. A side for which no BB-4-valid candidate resolves, any of whose signers' candidates cannot all be fetched within that signer's BB-6 budget, whose authorized copies diverge at equal signature standing (BB-6), or whose every fetched copy fails a BB-5 post-fetch check, has the §10.4.3 read disposition `indeterminate`: neither `present` nor authoritatively `absent`, and it MUST NOT be promoted to either. Fetched content that fails validation is rejected content, never absence evidence. A consumer MUST NOT recompute a native address from the logical form on a write-input substrate and MUST NOT query the logical form as though it were a native address.
- (BB-8) Suppression diligence and the one-sided gate. On a write-input substrate, the §10.4.3(b) one-sided classification is reachable for a missing side only when both hold: (i) a BB-4-valid, BB-5-consistent binding resolves that side's `nativeAddress`, and (ii) an SR-2 read of that address is authoritatively `absent` under the substrate binding's declared absence-evidence policy (CORE §5) — the publication-without-anchoring case. Non-discovery of a binding, on however many surfaces, establishes `indeterminate`, never absence. A consumer SHOULD consult at minimum the party's own §6.3.5 well-known index and the §6.3.6 catalogs it uses for the session; consulting more surfaces improves discovery, but no quantity of consulted surfaces converts non-observation into `absent`.

> **Note (non-normative).** Only the anchorer holds the write inputs (deployer address, storage-program name, nonce, salt), so no other party can produce its mapping — hence BB-1's per-party publication. Carrying a binding confers no authorship: the signature, not the carrier, binds it to the anchoring role. Delivery to the counterparty alone leaves retrievability at the counterparty's discretion, so publication to a catalog is the recommended floor for a party with no surface of its own.

> **Note (non-normative).** BB-6's protections now key on the *authenticated-and-authorized* predicate, not the observable candidate count — the same lesson SE-9 applied to sealed commits. Only the role holder can author authorized same-role copies, so collapse, precedence, and void operate on a set an outsider cannot enter: an outsider's flood is pruned pre-fetch when a co-signed party map is available, and is inert post-fetch otherwise. That degrades the attack from fabricating a one-sided classification to at worst suppressing a side into `indeterminate` — the already-priced read-censorship residual (§10.11), which excludes rather than blames.
>
> A void remains reachable only through equal-standing divergence among authorized copies, i.e. self-inflicted equivocation; under the §10.4.3 absence gate that side is `indeterminate`, so the session is excluded from reputation rather than resolved against either party.

> **Note (non-normative).** The BB-6 bound N = 8 is a fetch budget — a denial-of-service floor on retrieval work, not a protocol constant and not a void trigger: exhaustion yields `indeterminate`, never a classification. It is steward-tunable; a future minor can raise it without a major bump. Ascending `bundleContentHash` order keeps which candidates are fetched deterministic across consumers; a consumer MAY re-run resolution with a larger budget to lift an exhaustion-`indeterminate`.
>
> The budget bounds work *per authenticated signer*; total work across arbitrarily many distinct signer keys is **not** bounded on the anchored/no-map path, since a signer set is free to mint. A consumer MAY apply a total-work cap across signers; exhausting any such cap — like a per-signer budget's — yields `indeterminate` per BB-7, never a classification. An outsider signer set suppressing a side into `indeterminate` is the already-priced read-censorship residual (§10.11): it excludes the session, not either party. The derivation-context prune above is therefore mandatory — it removes the unbounded-signer surface on the scoring path.

> **Note (non-normative).** The load-bearing integrity checks are post-fetch — the content hash, the `anchoredByRole` cross-check, and the §10.4.1 signatures — so a wrong or poisoned binding yields at worst a fetch that fails verification, the same posture as §6.3.6 catalog poisoning. Retrievability is weaker: a binding suppressed from every surface a consumer reaches is indistinguishable from a never-published one, and the side resolves `indeterminate` — the session is then excluded from reputation (§10.4.3 / §10.5.1 guard (iv)); it does not fail open into one-sided blame.

> **Note (non-normative).** This is the completeness residual §10.5.3 already discloses (no authoritative "which bundles exist" oracle). BB-2 narrows it but does not close it; because discovery is scoped to the surfaces a given consumer consults, two consumers with different surface sets can legitimately reach different classifications for the same session — one resolving both copies (`unified`/`divergent`) where another, missing a binding, resolves `indeterminate`. Neither reaches one-sided attribution without the BB-8 gate.
>
> A party's remediation is publication to a surface its counterparties' consumers reach — BB-2 makes the own-surface or catalog route primary for exactly this reason. Adjudication of a fabricated one-sided abort remains a DACS-X dispute concern.

> **Note (non-normative).** *Forward note.* A future SDK capability to anchor a StorageProgram at a caller-chosen address — or a Demos-native deterministic derivation hashing only the logical address — would restore the pure-mapping case and let consumers resolve without the published binding, exactly as anticipated for listings in §6.3.4. Until then BB-1..BB-8 govern.

Bundles MUST fit within the substrate’s storage-cap soft limit (128 KB on Demos Storage Programs).

**Extended-pointer pattern for large sessions.** Sessions with extensive evidence (large transcripts, attestation chains, multi-party verifications, e.g. a sealed-envelope auction with 50 bidders’ commits and reveals) MAY exceed the size cap. In that case the bundle at the canonical address contains a pointer record:

```
type BundleExtendedPointer = {
  bundleVersion: "1"
  pointerKind: "extended"
  fullBundleUrl: string
  fullBundleContentHash: string
  segmentRefs?: AttestationRef[]              // optional segmented anchoring
  signature: ComponentSignature
}
```

and the full bundle is hosted externally; fullBundleContentHash binds it. Consumers MUST verify the external bundle’s hash against the on-chain pointer before treating it as authoritative.

Under DACS-5 v0.3 a producer anchoring a `FaultAttestationBundle` too large for the size cap uses the fault-typed pointer:

```
type FaultBundleExtendedPointer = {
  faultBundleVersion: "1"                       // discriminator: a FAB pointer carries faultBundleVersion and never bundleVersion (mirrors §10.4.1)
  pointerKind: "extended"
  fullBundleUrl: string
  fullBundleContentHash: string                 // the dereferenced full FaultAttestationBundle's §10.4.1 attestation_bundle_hash
  segmentRefs?: AttestationRef[]
  signature: ComponentSignature                 // over "dacs-fault-bundle-pointer:v1:" || sha256(canonical(pointer minus signature))
}
```

An oversized `EvidenceBoundFaultAttestationBundle` uses its own pointer type and domain:

```
type EvidenceBoundFaultBundleExtendedPointer = {
  evidenceBoundFaultBundleVersion: "1"
  pointerKind: "extended"
  fullBundleUrl: string                       // absolute HTTPS URL without userinfo
  fullBundleContentHash: string
  segmentRefs?: AttestationRef[]
  signature: ComponentSignature                 // over "dacs-evidence-bound-fault-bundle-pointer:v1:" || sha256(canonical(pointer minus signature))
}
```

For an extended-pointer anchoring, the record at the resolved `nativeAddress` is the pointer. Its discriminator and signature domain MUST match the dereferenced bundle type. The pointer signature's `signer` MUST equal the unique `parties[].primaryClaim` for the dereferenced bundle's `anchoredByRole`; another party or merely known key is unauthorized. Before hashing or admission, a consumer MUST validate the complete pointer shape (including a string `fullBundleUrl`, sha256 `fullBundleContentHash`, and every optional `segmentRefs` member), the dereferenced bundle under its full type schema and signature rules, and any supplied `BundleBinding` under BB-4/BB-5; an object containing only a discriminator or matching hash is not valid content. The new `EvidenceBoundFaultBundleExtendedPointer` further requires an absolute HTTPS `fullBundleUrl` with a host and no userinfo as part of its signed type shape. This strengthening does not reinterpret the released `BundleExtendedPointer` or `FaultBundleExtendedPointer` v1 shapes: their string URL remains structurally valid, and URL syntax is non-action-bearing until the deployment fetch gate. A dereferenced EBFAB MUST additionally pass SEB-1..SEB-6 using the same signed listing, exact evidence resolutions, authenticated phase-orchestrator authority, and lifecycle evidence required on the direct path; unavailable authority causes refusal, never a weaker pointer-only acceptance. Before fetching any pointer URL, the consumer MUST apply its deployment's egress policy, require a fetchable scheme it supports, resolve DNS safely, and reject loopback, link-local, private, metadata-service, and otherwise forbidden destinations after every redirect; URL shape validation alone is not an SSRF boundary. BB-5 check 8 and the §10.4.1 comparison apply to the **dereferenced full bundle**: `binding.bundleContentHash` MUST equal `pointer.fullBundleContentHash` MUST equal the recomputed §10.4.1 hash of the dereferenced bundle — three values, one identity. A pointer whose shape or signature fails, whose type mismatches, whose binding is unverified, whose EBFAB fails SEB, or whose dereferenced content hash mismatches is rejected content (BB-7), never absence.

#### 10.4.3 Bundle production rules

**Alternative-payment effective pipeline.** For every bundle type whose signed
Listing contains `pay-alternative`, both producer and consumer MUST apply
DACS-4 APR-7 before interpreting `phaseSummary`, selecting required settlement
evidence, comparing two bundle copies, or deriving reputation. The independently
recomputed concrete pipeline is authoritative at the preserved phase index;
the raw Listing placeholder is not an executed phase. This gate applies even to
released bundle shapes because the new Listing phase was unknown—and therefore
unusable—to pre-APR readers; it does not reinterpret any historical valid
Listing or bundle bytes.

A failed or aborted bundle MUST be produced when the session reaches its terminal state. A completed bundle MUST instead be constructed, signed, anchored, finalized, and made independently resolvable during `audit-pending`; its finalized receipt is the prerequisite for the `finalised` terminal transition (ST-11). The bundle MUST include references to:

- all DACS-2 composite verification records;
- the DACS-3 agreement (if any);
- DACS-4 settlement evidence — one entry per phase invocation that ran to an outcome and produced a qualifying SR-2 record, whether that record's outcome is success or failure. For a completed bundle the record is `finalized` and independently resolvable under ST-11; an EBFAB for a failed or aborted terminal requires an established `included` or `finalized` record under SEB-1. An ST-8-resolved cross-chain settle phase contributes exactly its `:resolved` success record; its superseded interim failure record is reachable only through `supersedesEvidenceRef` and is not listed independently. If the ST-8 window expires unresolved, the interim `dest-revealed-source-unclaimed` or `tank-locked-unreleased` failure record stands as that phase's terminal evidence and IS the top-level member. Both parties' `settlementEvidence[]` arrays MUST contain the same applicable terminal member, so the two-sided copies stay canonically equal (§10.4.1). A successful `deliver-attested-payload` entry is valid only after its DACS-4 §9.6.3 `attestationRef` resolves through the complete DPA-3..DPA-9 chain (`PayloadAttestationRecord` → method evidence/native transaction → exact delivered payload hash); these transitive dependencies are required referenced artifacts for CORE §5.1 SR2-9 finalization/resolution and MUST NOT be replaced by the SettlementEvidence signer's assertion;
- DACS-4 amendments (refunds);
- DACS-5 ratings (if the rate phase ran).

The bundle MUST NOT include references to any record outside the session’s scope.

**EvidenceBoundFaultAttestationBundle exact-set validation (SEB-1..SEB-6).** These rules define validity only for `EvidenceBoundFaultAttestationBundle`. Its producer and consumer validate the authoritative top-level `settlementEvidence[]` against the authenticated executed phase set as follows. The two perspective copies MUST contain the same applicable terminal members. An ST-8-resolved phase lists only its `:resolved` success record; an expired phase lists its standing interim failure record.

- (SEB-1) **Authenticated execution authority and deterministic `P`.** First verify the EBFAB discriminator, canonical hash, type-specific `dacs-evidence-bound-fault-bundle:v1:` signatures, and required signer set under §10.4.1. Then resolve `listingRef` to the DACS-1 `Listing`, require `(listingId, version, contentHash)` to match, and verify its `dacs-listing:v1:` signature. For an ordinary Listing, its ordered `pipeline[]` is the phase-definition authority unchanged. For a Listing containing `pay-alternative`, the consumer MUST resolve and verify `agreementRef` plus the selected authenticated RailDefinition, run DACS-4 APR-1..APR-4, and use only that independently recomputed effective pipeline as phase-definition authority. A selected reference outside the signed alternatives, a deterministic projection contradiction, or a raw `pay-alternative` execution claim is rejected; unavailable otherwise-consistent Agreement/registry authority is `indeterminate`. The consumer MUST NOT obtain the choice or projected handler from `phaseSummary`, SettlementEvidence, or a caller. The domain-verified EBFAB's signed `phaseSummary[]` is the execution-result authority only when it is a complete, outcome-consistent trace. Its entries MUST be the ordered contiguous prefix `0..n` of the applicable phase-definition authority with no gap or reordering, and each `kind` MUST equal the effective phase at that index. A `completed` bundle covers the full effective pipeline and contains no failed phase other than the non-fatal `rate` result permitted by ST-5. A `failed-perm` trace is an `ok` prefix followed by terminal `fail` with `errorClass: "permanent"`, or `"transient"` plus the signed `retryExhausted: true` marker; a first-attempt or otherwise unproven transient failure is not terminal. A `failed-counterparty` trace has terminal `"counterparty"` or `"settlement-atomicity"`. A `failed-substrate` trace is either such a prefix ending in `fail`/`errorClass: "substrate"`, or the full completed pipeline when the substrate failure arose at the ST-11 audit gate. An aborted trace is a strict `ok` prefix ending before the invocation that returned no result. Reject every other trace; in particular, removing the same phase from both `phaseSummary[]` and `settlementEvidence[]` cannot shrink the expected set, and a terminal error class cannot contradict the bundle `outcome`. Derive `P` locally by selecting each authenticated `phaseSummary` entry whose kind is a DACS-4 §9.7 `PaymentPhaseType` or `DeliveryPhaseType` and whose handler returned the recorded `ok` or `fail` result. Key each member by `(index, kind)`: repeated kinds at distinct indices are distinct members; both successful and failed handler results are members. A DACS-4 invocation entered but aborted before returning a result has no `phaseSummary` result entry and is not in `P`; an aborting producer MUST NOT synthesize one. For ST-8, the one pipeline index contributes exactly one key: resolved uses the superseding `:resolved` success record, while window expiry uses the standing interim failure record. `P` MUST NOT be accepted from a caller, derived from `settlementEvidence[]`, or inferred from optional `phaseSummary[].attestationRef` values.
**SR-2 lifecycle at each SEB validation point.** Before any referenced record can satisfy `P`, its `AnchorReceipt` and binding-defined evidence MUST establish matching logical address, native address, content hash, transaction, writer, nonce where applicable, `jobId`, and phase index/kind. For a failed or aborted bundle, each selected SettlementEvidence anchor MUST have an established `included` or `finalized` receipt; the EBFAB itself MUST likewise have an established `included` or `finalized` receipt before a consumer admits it. `Submitted`, `accepted`, index visibility, or an indeterminate observation does not satisfy either gate. For a successful completed bundle, ST-11 is stricter: every selected record MUST be `finalized` and independently resolvable before the EBFAB is signed, and the EBFAB itself MUST be anchored, independently resolvable, and `finalized` before the session may leave `audit-pending` for `finalised`. Structural SEB checks MAY run on the signed pre-anchor EBFAB during ST-11, but that does not make it a terminal completed audit artifact.
- (SEB-2) Inspect the raw top-level array before set formation. Its full canonical `AttestationRef` values MUST be duplicate-free. For an ST-8-resolved phase, the superseded interim failure record MUST NOT occupy a top-level slot, whether alone or beside its `:resolved` successor; only the success record is top-level and it binds the interim through `supersedesEvidenceRef`. For an ST-8-expired phase, the standing interim failure record MUST occupy that phase's single top-level slot because no resolved successor exists.
- (SEB-3) Resolve every top-level reference to the exact signed DACS-4 §9.7 `SettlementEvidence`, validate the complete `AttestationRef` shape, recompute its `contentHash`, verify its `dacs-evidence:v1:` signature, and authenticate its binding to this bundle's `jobId`, its phase kind, its phase index, and the phase-orchestrator signing authority recovered from the SB-1 evidence anchor/session execution authority. The authenticated SR-2 receipt MUST bind the exact logical address, native address, content hash, transaction, writer, and nonce where applicable; its writer and the evidence signer MUST equal that phase orchestrator, which need not be a buyer/seller bundle party. For a payment phase, recompute the exact PC-2 address from the authenticated `(jobId, railId, phaseIndex)` tuple; only an ST-8 successor uses the exact same address plus the terminal `:resolved` segment. A suffix match or caller-supplied phase/index label is not authority. For a delivery phase whose evidence address is binding-defined, the authenticated session execution authority MUST supply that exact expected logical address and the SR-2 receipt MUST match it. The record's `success`/`failure` outcome MUST match the signed phase entry's `ok`/`fail` result. Each resolved member MUST map to exactly one key in `P`; a non-evidence phase, another session, an outcome contradiction, or an unknown/mismatched phase key is rejected. ST-8 terminal selection is derived from the binding-verified exact PC-2 logical address plus authenticated record content, never from caller-supplied record-class or edge metadata. For a successful cross-chain phase, the verifier MUST compare the verified receipt against both recomputed addresses: the exact ordinary PC-2 address represents a direct success and carries no supersession requirement, while the exact `:resolved` address represents an ST-8 successor and MUST carry a hashed `supersedesEvidenceRef`. An address matching neither is rejected. The superseded reference MUST resolve to a signed same-job, same-phase interim failure at the exact ordinary PC-2 address with the phase-specific reason (`pay-cross-chain-htlc` → `dest-revealed-source-unclaimed`; `pay-cross-chain-liquidity-tank` → `tank-locked-unreleased`), and that interim reference MUST NOT also be top-level. Conversely, a supersession edge on a record not bound at the exact `:resolved` address is rejected. The interim record is a transitive evidence dependency and its signer MUST likewise equal the authenticated phase orchestrator: a `completed` EBFAB requires its receipt to be `finalized` and independently resolvable under ST-11, while a failed terminal requires at least `included` or `finalized`. An expired interim record is admissible only against the corresponding signed terminal `fail` result — HTLC with `errorClass: "settlement-atomicity"`, tank with `errorClass: "substrate"` per ST-8(b) — and MUST carry that same phase-specific reason; any other cross-chain failure follows its ordinary non-ST-8 error class.
- (SEB-4) After SEB-2 and SEB-3, the mapping `P → settlementEvidence[]` MUST be a bijection: every key in `P` has exactly one top-level member and every top-level member maps to exactly one key in `P`. Two canonically distinct references resolving to the same phase key violate injectivity. Missing, extra, duplicated, aliased, or reused members are rejected; cardinality equality alone is insufficient.
- (SEB-5) A `phaseSummary[].attestationRef` remains OPTIONAL. Omission alone MUST NOT reject a bundle. When present for a phase in `P`, it MUST be full-canonical-value equal to that phase's unique top-level member. Two distinct phase entries MUST NOT reuse one member, and a pointer outside the top-level array or to another phase's member is rejected.
- (SEB-6) Deterministic contradictions visible in the signed listing/EBFAB authority, signed raw array, authenticated phase keys, lifecycle receipts, or present optional pointers — including authority mismatch, multiplicity, cardinality, forbidden ST-8 representation, lifecycle failure, exact-mapping failure, and SEB-5 pointer disagreement — are `rejected` before unrelated reference-resolution uncertainty is considered. When SEB-1 through SEB-5 pass and an otherwise required unrelated authority remains unavailable, the overall consumer result MUST be `indeterminate`; uncertainty MUST NOT downgrade an already established SEB rejection.

For every completed bundle type, every required reference above MUST resolve to an artifact with a verified CORE §5.1 `finalized` receipt whose logical address, native address, content hash, transaction, writer, nonce (where applicable), and session bindings match. A mere submission, durable `accepted` receipt, non-final `included` receipt, or index hit is insufficient. The producer MUST NOT omit a required reference merely because its anchor is still catching up; it remains in `audit-pending` instead.

**Per-phase `attestationRef` (optional).** A `phaseSummary[]` entry's `attestationRef` is **OPTIONAL** — the authoritative attestation set is the bundle's top-level `vetRecords[]` and `settlementEvidence[]` arrays (per the rules above), and a bundle that omits the per-phase pointer is well-formed. A validator MUST NOT reject a bundle solely because a `phaseSummary` entry omits `attestationRef`. A phase that produced an attestation meeting the applicable SR-2 gate above — a settle phase → its `SettlementEvidence`, a vet phase → its `VerifyResult` — **SHOULD** carry `attestationRef` linking to it, so the per-phase → evidence mapping is unambiguous in multi-phase pipelines where the flat top-level arrays alone cannot say which record belongs to which phase invocation.

**For sessions terminating before the agreement commitment phase**, the bundle MUST include the available `vetRecords` and omit `agreementRef`. When a Vet or Negotiate handler actually returned `fail`, `phaseSummary` marks that result and the session uses the corresponding `failed-*` outcome. A no-result ST-3/ST-9 `aborted-by-self` or `aborted-by-other` instead ends before that invocation produces a result, so its strict completed prefix contains no synthetic failed entry, exactly as SEB-1 requires.

**For sessions terminating with failed-substrate**, the bundle’s outcome captures the substrate failure; the failure does not count as either party’s fault in DACS-5 reputation derivation.

Two parties producing independent bundles for the same session MUST converge on the same session facts or MUST surface the divergence as a dispute. Convergence is canonical-form equality (which excludes the per-copy `anchoredByRole` and `signatures` fields per §10.4.1, so happy-path copies are equal despite different `anchoredByRole` values). For a pair of absolute-fault copies (`FaultAttestationBundle` or `EvidenceBoundFaultAttestationBundle`) convergence is instead agreement on `faultedParty` and outcome class, with role-relative `outcome` spellings that differ only per the §10.4.1 permissible-set mapping: such a pair converges even though the canonical forms or type discriminators differ.

Each side anchors its own bundle at its own derived address. The two `stor-{sha256(jobId + "-bundle-{role}")}` values are the **logical** bundle addresses (§10.4.2). A consumer looking up "the bundle(s) for session X" resolves each side's native address per the §10.4.2 binding rules (BB-5): on a pure-mapping substrate by direct computation; on a write-input-mapping substrate such as Demos through that side's published `BundleBinding`s, never by recomputation (BB-6/BB-7). The consumer then queries both sides' resolved native addresses.

**Definition — "canonically diverge" (normative, defined once).** The two copies' canonical forms differ in `outcome`, or in a shared-index `phaseSummary` entry's `kind`/`outcome`/`errorClass` — i.e. a *contradiction* about what happened. A `phaseSummary` entry present in one copy and absent in the other **is** a divergence: the entry set is a normative input, and a copy asserting a phase the other's record denies is a contradiction about which phases ran, not advisory skew (it is also the guard against a fabricated phase entry that would otherwise escape entry-wise comparison). For an EBFAB/EBFAB pair, the full-canonical `settlementEvidence[]` member sets MUST also be equal after both copies pass SEB independently; distinct authenticated records resolving to the same phase key still diverge across the pair. A difference confined to advisory fields (e.g. `finalisedAt` skew, one-sided `ratingRefs`, amendment ordering) is NOT a divergence.

For any **absolute-fault pair** — EBFAB/EBFAB, EBFAB/FAB, or FAB/FAB — the `outcome` contradiction is read on the absolute `faultedParty` and the outcome class (`completed`, `failed-substrate`, abort, or failure), not the role-relative `outcome` spelling. Two absolute-fault copies naming the same `faultedParty` and class do not diverge, even where one reads `aborted-by-self` and the other `aborted-by-other`; the shared-index `phaseSummary` limb applies unchanged. Each EBFAB copy MUST first pass SEB-1..SEB-6 independently. A failed SEB copy is rejected content, not an older bundle type and not authoritative absence; its discriminator MUST NOT be stripped or renamed to rescue the pair.

Legacy `AttestationBundle` copies are compared on a common implied-fault surface. Each copy's role-relative `outcome` is mapped through its `anchoredByRole`, the §10.4.1 permissible-set table, and **that copy's own authenticated `parties[]` roster** to an implied-fault set. A consumer MUST NOT union or otherwise import roles from the other copy when deriving either set. After the existing outcome-class check, the pair diverges when those sets are disjoint. A non-empty intersection means the two fault assertions are compatible and does NOT diverge. The shared-index `phaseSummary` limb applies unchanged.

In a two-party session each implied-fault set is a singleton, so this produces the same results as `perspective_flip`: partner spellings converge and two copies that both blame their counterparty diverge. With a distinct orchestrator, buyer and seller copies that both read `failed-counterparty` or both read `aborted-by-other` instead intersect only at `orchestrator` and converge on that attribution.

`perspective_flip` remains the §10.5.1 scoring rule when a counterparty-anchored legacy copy is the authoritative copy. It is not the legacy pair comparator because it models only the buyer↔seller perspective.

**Absolute-fault/legacy pairs (normative).** When one side anchors an EBFAB or FAB and the other a legacy `AttestationBundle`, the pair is compared on the common fault surface. The legacy copy's role-relative `outcome` is mapped through its `anchoredByRole`, its own authenticated `parties[]` roster, and the §10.4.1 permissible-set table to an **implied-fault set** (a singleton in a two-party roster, preserving the prior exact mapping byte-for-byte); roles carried only by the absolute-fault copy MUST NOT enlarge that set. The legacy outcome class is read directly. The pair canonically diverges when the absolute copy's `faultedParty` is **not a member** of that set, when the outcome classes contradict, or on the shared-index `phaseSummary` limb.

**Exhaustive pair classification and authority (normative).** Validate each copy under its own discriminator, domain, signer, lifecycle, and — for EBFAB — SEB contract before pair comparison. The six unordered type pairs are exhaustive:

| Pair | Comparison | Authoritative copy when non-divergent |
| --- | --- | --- |
| EBFAB / EBFAB | absolute-fault + shared `phaseSummary` + equal full-canonical `settlementEvidence[]` member sets; both copies pass SEB | scored party's own copy; either for a non-scoring auditor |
| EBFAB / FAB | absolute-fault + shared `phaseSummary`; EBFAB passes SEB | EBFAB |
| EBFAB / legacy | absolute-fault/legacy + shared `phaseSummary`; EBFAB passes SEB | EBFAB |
| FAB / FAB | absolute-fault + shared `phaseSummary` | scored party's own copy; either for a non-scoring auditor |
| FAB / legacy | absolute-fault/legacy + shared `phaseSummary` | FAB |
| legacy / legacy | legacy implied-fault-set + shared `phaseSummary` | scored party's own copy; either for a non-scoring auditor |

The type-precedence order is therefore EBFAB > FAB > legacy, but only after both copies validate and the pair is non-divergent. This precedence is not a validity fallback: an invalid EBFAB makes that returned side rejected content under rule (a), so an older copy cannot override, erase, or falsely inherit the failed SEB claim. A valid EBFAB's exact-set result remains authoritative even though an otherwise-valid older bundle type carries no SEB claim of its own.

Consumers MUST:

- (a) resolve each side's native address per the §10.4.2 binding rules (BB-5) — on a write-input substrate through that side's published `BundleBinding`, never by recomputation — then fetch both addresses and retain the CORE SR-2 read disposition for each. An address whose `BundleBinding` cannot be resolved and verified per §10.4.2 has the read disposition `indeterminate`. A consumer MAY enter rule (b) only when exactly one valid bundle is `present` and the other expected address is authoritatively `absent`. If fewer than two valid copies are present and any missing address is `indeterminate`, the overall lookup is `indeterminate`. If neither copy is present, the lookup is `absent` only when both expected addresses are authoritatively `absent`; otherwise it is `indeterminate`. Returned content that fails §10.4.1, §10.4.2, or the §10.4.3 SEB contract applicable to EBFAB is rejected content, not absence, and MUST be rejected under those rules;
- (b) if exactly one valid bundle is present and the other expected address is authoritatively absent, classify by the present copy's signature set:
  - a copy carrying all §10.4.1 required signatures and, when it is an EBFAB, passing SEB-1..SEB-6 is the unified session bundle; the missing copy is an anchoring omission, not an abort, and no abort outcome is attributed to either party;
  - a single-signed copy with an abort outcome is classified per the §10.11 bundle-suppression rule: `aborted-by-self` for the non-signer, `aborted-by-other` for the signer;
  - a single-signed copy with any other outcome is rejected per §10.4.1, leaving no valid bundle for the session;
- (c) if both are present and do NOT diverge under the exhaustive table, treat them as the unified session bundle. Select the authoritative copy by EBFAB > FAB > legacy; within an equal-type pair, a reputation deriver prefers the scored party's own anchored copy and a non-scoring auditor MAY use either. The EBFAB preference preserves its validated exact-set result across mixed pairs; an older copy never replaces it merely because it is older, self-anchored, or otherwise preferred by the legacy scoring rule;
- (d) if both are present and canonically diverge (a contradiction per the definition above), treat the session as disputed — each bundle stands on its own signatures and consumers must decide an out-of-band dispute-handling policy (e.g., flag for human review). This discretion does **not** extend to DACS-5 `ReputationDerivation`: a conforming `derive()` MUST exclude the jobId from ALL metrics under §10.5.1 guard (ii) and MUST NOT select either party's copy for party-specific reputation.

v0.1 does not specify a dispute resolution path; divergence is handled out-of-band. A future minor version (DACS-X, dispute) may specify selective transcript disclosure under signed party agreement or arbitrator order.

`absent`, `indeterminate`, `one-sided`, `unified`, and `divergent` are consumer lookup dispositions, not values of the §10.4.1 bundle `outcome` enum. In particular, `indeterminate` records that the two-address observation was incomplete; it asserts neither absence nor a canonical contradiction.

### 10.5 Reputation derivation

A deterministic function from a set of attestation bundles to a small set of headline reputation metrics, keyed by primary claim.

```
type ReputationDerivation = {
  derivationVersion: "1"
  partyPrimaryClaim: ClaimReference            // the party being scored
  windowStart: number                          // unix ms
  windowEnd: number                            // unix ms
  bundleCount: number
  metrics: {
    completionRate: number | null              // null when party_fault_denom == 0 (bundleCount == 0, or all reconciled bundles failed-substrate)
    counterpartyAdjustedCompletionRate: number | null   // blame-weighted: completionRate with counterparty-caused outcomes (failed-counterparty, aborted-by-other) also dropped from the denominator; null when party_blame_denom == 0
    counterpartyFaultRate: number | null
    averageBuyerRating: number | null
    averageSellerRating: number | null
    observedTransactionalVolume: PriceTerm[]   // sum of agreement.terms.price, by currency
    transactionCountByCurrency: { currency: string; count: number }[]   // per-currency count of the completed sessions composing observedTransactionalVolume; [] on the empty path
  }
  computedAt: number
  windowingBasis: "finalisedAt" | "sr2-anchor-timestamp"   // which clock the §10.5.1 window was applied against; re-derivation MUST use the same one (§10.5.3 determinism receipt)
  bundleRefs: AttestationRef[]                 // exactly the reconciled set (§10.5.1), in canonical ascending-contentHash order (§10.5.3 determinism receipt)
}
```

**`ReplayableReputationDerivation` (released replayable receipt).** This historical v1 type remains byte- and meaning-compatible: `replayableDerivationVersion: "1"` does not require a `resolvedJobId` member and a consumer MUST NOT treat an extension with that name as action-bearing. It carries the previously released `resolutionContext` needed to reproduce legacy/FAB reconciliation. Like `ReputationDerivation`, it is unsigned derivation-record data and has no CORE §B.7 domain.

A consumer that does not support this type MUST reject an object carrying `replayableDerivationVersion` as unsupported, and MUST NOT reinterpret it as a `ReputationDerivation` by discarding the discriminator (CORE §11.1.2 new-type refusal). Conversely a replay consumer MUST reject an object lacking `replayableDerivationVersion: "1"` or carrying `derivationVersion`: no replay claim exists on the legacy type.

```
type ReplayableReputationDerivation = {
  replayableDerivationVersion: "1"             // the type's §11.2.5 version literal and structural discriminator (CORE §11.1.2 new-type refusal): a ReplayableReputationDerivation carries `replayableDerivationVersion` and never `derivationVersion`
  partyPrimaryClaim: ClaimReference            // the party being scored
  windowStart: number                          // unix ms
  windowEnd: number                            // unix ms
  bundleCount: number
  metrics: {
    completionRate: number | null              // null when party_fault_denom == 0 (bundleCount == 0, or all reconciled bundles failed-substrate)
    counterpartyAdjustedCompletionRate: number | null   // blame-weighted: completionRate with counterparty-caused outcomes (failed-counterparty, aborted-by-other) also dropped from the denominator; null when party_blame_denom == 0
    counterpartyFaultRate: number | null
    averageBuyerRating: number | null
    averageSellerRating: number | null
    observedTransactionalVolume: PriceTerm[]   // sum of agreement.terms.price, by currency
    transactionCountByCurrency: { currency: string; count: number }[]   // per-currency count of the completed sessions composing observedTransactionalVolume; [] on the empty path
  }
  computedAt: number
  windowingBasis: "finalisedAt" | "sr2-anchor-timestamp"   // which clock the §10.5.1 window was applied against; re-derivation MUST use the same one (§10.5.3 determinism receipt)
  bundleRefs: AttestationRef[]                 // exactly the reconciled set (§10.5.1), in canonical ascending-contentHash order (§10.5.3 determinism receipt)
  resolutionContext: ResolutionContextEntry[]   // REQUIRED (empty array only when bundleRefs is empty): one entry per reconciled jobId (§10.5.1) — the resolution facts the applicable algorithm consumed that the copies themselves cannot carry. Never part of any signed bundle (§10.5.1 guard (iv)); it is derivation-record data.
}

type SettlementVerifiedReputationDerivation =
  Omit<ReputationDerivation, "derivationVersion"> & {
    settlementVerifiedDerivationVersion: "1"    // structural discriminator; never carries derivationVersion or either replayable discriminator
  }

type ReplayableSettlementVerifiedReputationDerivation =
  Omit<ReplayableReputationDerivation, "replayableDerivationVersion" | "resolutionContext"> & {
    replayableSettlementVerifiedDerivationVersion: "1"  // structural discriminator; never carries any other derivation discriminator
    resolutionContext: JobBoundResolutionContextEntry[]  // settlement-verified replay is job-bound; EBFAB evidence cannot be replayed through the released context contract
  }

type ResolutionContextEntry = {
  contentHash: string                           // keys the entry to its bundleRefs member (ascending-contentHash order, §10.5.3)
  resolvedRole: "buyer" | "seller"              // the §10.5.1 input-precondition role under which the authoritative copy was resolved
  roleEvidence:                                   // exactly ONE of (XOR — the authenticated backing for resolvedRole):
    | { kind: "binding"; binding: BundleBinding }  // write-input substrate: the verified BB-4/BB-5 binding; binding.bundleContentHash MUST equal contentHash and binding.role MUST equal resolvedRole
    | { kind: "address"; resolvedAddress: string } // pure-mapping substrate: the anchor address whose role segment MUST equal resolvedRole
  bb6Context?: {                                  // REQUIRED iff roleEvidence.kind == "binding": the BB-6 multiplicity inputs to reproduce why the authoritative copy won selection
    candidateBindings: BundleBinding[]            // the BB-4-valid, BB-5(checks 1-5) candidate set the deriver resolved over for (jobId, resolvedRole)
    partyMap: object | null                       // the authenticated {signer -> role} role-holder map used to prune pre-fetch, or null if none was available
    budget: number                               // the per-signer fetch budget used (8)
  }
  counterpartyDisposition: "present" | "absent"   // the §10.4.3 read disposition of the OTHER expected buyer/seller address
  counterpartyRef?: AttestationRef                 // REQUIRED iff counterpartyDisposition == "present": the counterparty copy reconciled against — lets a rederiver re-run §10.4.3 divergence + authority selection
  counterpartyRoleEvidence?:                       // REQUIRED iff counterpartyDisposition == "present": same XOR shape as roleEvidence, authenticating the OTHER role under which the counterparty copy resolved
    | { kind: "binding"; binding: BundleBinding }  // binding.jobId == the entry's jobId, binding.role == the counterparty's role, binding.bundleContentHash == counterpartyRef.contentHash
    | { kind: "address"; resolvedAddress: string } // pure-mapping substrate: the counterparty anchor address whose role segment MUST equal the counterparty's role
  absenceEvidenceRef?: { kind: string; locator: string; contentHash: string }   // REQUIRED iff counterpartyDisposition == "absent": a hash-bound reference to the AbsenceEvidence object; contentHash MUST equal sha256(canonical(AbsenceEvidence)) and the object MUST be dereferenceable at replay
  absenceBinding?: BundleBinding                   // REQUIRED iff counterpartyDisposition == "absent" on a write-input substrate: the BB-4-valid binding resolving the MISSING side's nativeAddress (role == the missing side's role, jobId == the entry's jobId); its nativeAddress MUST equal the dereferenced AbsenceEvidence.nativeAddress
}

type AbsenceEvidence = {
  kind: string                                    // the substrate absence-evidence mechanism (e.g. "non-membership-proof"); CORE §5 owns policy semantics, DACS-5 defines only the binding relation
  nativeAddress: string                           // the missing side's native address the authoritative-absence read was performed against
  finalizedStateRef: string                       // the finalized state / finality anchor the CORE §5 policy evaluated absence against
}
```

**`JobBoundReplayableReputationDerivation` (strengthened replayable receipt).** EBFAB replay and any producer claiming that returned content was bound to the trusted requested session identity MUST use a job-bound replay type. When retaining released metric semantics, the producer uses this distinct type. It carries `jobBoundReplayableDerivationVersion: "1"`, never `replayableDerivationVersion`, `derivationVersion`, or either settlement-verified discriminator, and uses `JobBoundResolutionContextEntry`. Unknown, stripped, relabelled, unsupported, or multiply-present derivation discriminators are rejected before any replay action.

```
type JobBoundReplayableReputationDerivation = Omit<ReplayableReputationDerivation,
  "replayableDerivationVersion" | "resolutionContext"> & {
  jobBoundReplayableDerivationVersion: "1"
  resolutionContext: JobBoundResolutionContextEntry[]
}

type JobBoundResolutionContextEntry = ResolutionContextEntry & {
  resolvedJobId: string                         // REQUIRED trusted requested session identity from the role address or verified BundleBinding; MUST equal the dereferenced copy's jobId
}

type AuthenticatedWindowReputationDerivation =
  Omit<ReplayableSettlementVerifiedReputationDerivation,
    "replayableSettlementVerifiedDerivationVersion" | "windowingBasis" | "resolutionContext"> & {
    authenticatedWindowDerivationVersion: "1"   // exclusive structural discriminator for the DACS-5 v0.6 current profile
    windowingBasis: "sr2-finalized-inclusion-timestamp"
    resolutionContext: AuthenticatedWindowResolutionContextEntry[]
  }

type AuthenticatedWindowResolutionContextEntry = JobBoundResolutionContextEntry & {
  windowReceipt: AnchorReceipt                  // exact authoritative bundle anchor's established finalized receipt; blockRef.timestamp is the only window clock
  windowReceiptHistory: AnchorReceipt[]         // every verified snapshot consumed by AWT-4, including windowReceipt, in binding-native order with canonical-receipt-hash tie-break
  participationEvidence?: ParticipationEvidenceContext  // REQUIRED exactly when SPA-6 needs the absent blamed party's external admission; absent otherwise
}

type ParticipationEvidenceContext = {
  admissionRef: AttestationRef                  // exact SessionParticipationAdmission; contentHash and anchor bind the dereferenced canonical bytes
  admissionReceipt: AnchorReceipt               // exact established/finalized receipt whose blockRef.timestamp proves pre-deadline activation acknowledgement
  admissionReceiptHistory: AnchorReceipt[]      // every verified snapshot consumed when reconciling the admission anchor under SPA-5/AWT-4
}
```

The released v1 path neither requires nor acts on `resolvedJobId`; adding, removing, or changing such an unknown extension cannot strengthen or alter its semantics. A job-bound consumer instead verifies `resolvedJobId` against the dereferenced authoritative copy and uses it for every role, counterparty, candidate-binding, and absence-binding job relation before reconciliation. EBFAB is not admissible to the released v1 derivation path. A producer replaying EBFAB with released metric semantics uses `JobBoundReplayableReputationDerivation`; a producer also claiming RSV-1 through RSV-4 uses `ReplayableSettlementVerifiedReputationDerivation`, whose context is job-bound by definition.

**Settlement-verified type boundary (normative).** `SettlementVerifiedReputationDerivation`, `ReplayableSettlementVerifiedReputationDerivation`, and `AuthenticatedWindowReputationDerivation` are the only derivation types that apply RSV-1 through RSV-4, settlement-reference multiset comparison, and the successful-payment floor for volume. Their shared fields have the settlement-verified meanings defined in §10.5.1. A producer claiming those semantics MUST emit exactly one matching discriminator and MUST NOT emit `derivationVersion`, `replayableDerivationVersion`, `jobBoundReplayableDerivationVersion`, or another settlement-verified/current-profile discriminator. A consumer that does not support the encountered discriminator MUST reject the object as unsupported before type-specific action; it MUST NOT discard or rename the discriminator and reinterpret the object as either released version-1 type. Conversely, `ReputationDerivation` and `ReplayableReputationDerivation` retain their DACS-5 v0.3 meanings and MUST NOT be evaluated under RSV. The discriminator therefore distinguishes pre-RSV from RSV-enforced output using object bytes alone, without repository-revision knowledge.

**Authenticated-window current profile (AWT-1..AWT-8 plus SPA-1..SPA-8; normative).** `AuthenticatedWindowReputationDerivation` is the only current reputation-bearing DACS-5 profile. It is settlement-verified, job-bound, replayable, participation-safe for one-sided blame, and rate-phase-bound from inception. The five older derivation shapes remain frozen for compatibility and are historical/partial signals; none can satisfy a request for current-profile reputation, even when it carries the string `windowingBasis: "sr2-anchor-timestamp"`.

- (AWT-1) A current-profile object MUST carry exactly `authenticatedWindowDerivationVersion: "1"`, MUST carry `windowingBasis: "sr2-finalized-inclusion-timestamp"`, and MUST NOT carry any other derivation discriminator. Unknown, missing, or multiply-present discriminators are rejected before metrics are used.
- (AWT-2) After ordinary type/signature validation, two-sided reconciliation, authoritative-copy selection, and RSV admission, the deriver MUST resolve and independently verify `windowReceipt` under the applicable CORE §5.1 SR-2 binding. The receipt MUST have `observationDisposition == "established"`, `state == "finalized"`, and a `blockRef.timestamp`; its `substrate`, `logicalAddress`, `nativeAddress`, `contentHash`, `transactionRef`, `writer`, and applicable `nonce` MUST bind the exact selected authoritative bundle and its verified resolution context. Receipt fields without valid binding-defined evidence do not authenticate time.
- (AWT-3) The window clock is exclusively `windowReceipt.blockRef.timestamp`: the consensus timestamp of the block or equivalent ordered state in which that exact bundle-anchor transaction was included. `accepted` supplies no block clock, `included` without authenticated finality is insufficient, and neither `observedAt`, bundle `finalisedAt`, an indexer timestamp, nor wall-clock comparison may substitute. A deterministic-BFT binding MAY establish inclusion and finality in one authenticated receipt as CORE §5.1 permits.
- (AWT-4) The consumer MUST reconcile every verified receipt/history for the exact `(substrate, logicalAddress, nativeAddress, contentHash)` anchor using the binding's authenticated native ordering and the CORE §5.1 lifecycle graph. A `replaced` or `reorged` transaction is inert. A replacement qualifies only through its own independently verified finalized receipt for the exact bundle. Duplicate snapshots of one receipt tuple collapse; if more than one otherwise-valid surviving finalized inclusion disagrees on transaction, block identity, consensus timestamp, or native order and the binding cannot prove one canonical history, the time disposition is `indeterminate`.
- (AWT-5) A missing, unavailable, pruned, malformed, non-final, mismatched, reorged-without-finalized-re-entry, or unorderably conflicting time proof makes that jobId `indeterminate` and non-countable for this derivation. It is excluded from every metric, `bundleCount`, and `bundleRefs` without attributing fault. The deriver MUST NOT fall back to `finalisedAt` or choose the earliest/latest attacker-favourable receipt.
- (AWT-6) Windowing occurs only after authoritative-copy selection and AWT-2..AWT-5. A qualifying job is counted iff `windowStart <= windowReceipt.blockRef.timestamp <= windowEnd`; both boundaries are inclusive. A large `finalisedAt`/consensus-time skew SHOULD be surfaced for audit but does not change membership or establish misbehaviour by itself.
- (AWT-7) Every included `bundleRefs` member MUST have exactly one context entry carrying the exact verified `windowReceipt` used for membership and `windowReceiptHistory`, the complete set of receipt snapshots the deriver consumed for AWT-4. The history includes the selected receipt, collapses byte-identical duplicates, and is ordered by binding-authenticated native order with canonical receipt hash as a tie-break; `observedAt` never orders it. Replay re-verifies every disclosed proof, exact-bundle binding, lifecycle/finality, conflict reconciliation, selected receipt, and inclusive boundary before re-running RSV and the metrics. Any changed, omitted, substituted, misordered, or unverifiable disclosed time evidence makes the receipt non-conforming; replay MUST NOT recompute through another clock. As with `bundleRefs`, no receipt can prove that an unavailable observation source disclosed every extant snapshot; this is a completeness residual, not permission to ignore a known conflict.
- (AWT-8) A consumer MAY use an older derivation only under an explicitly historical/partial policy. If the policy claims that the producer predates the current profile, that selection MUST be backed by authenticated era evidence pinning the producer/session to an exact DACS profile revision (for example, a trust-policy-authenticated implementation/profile commit); the derivation discriminator, `computedAt`, `finalisedAt`, and producer assertion are not era evidence. Without that evidence the object remains an untrusted partial signal, never current-profile reputation.

A supported replay receipt's `resolutionContext`:

- MUST contain exactly one `ResolutionContextEntry` per `bundleRefs` member, keyed by `contentHash`;
- MUST NOT, in a published receipt, include a one-copy jobId whose entry lacks a valid `absenceEvidenceRef`. §10.5.1 guard (iv) already excludes it from the metrics, so publication likewise requires the evidence that qualified the inclusion;
- for the current type, MUST additionally carry `participationEvidence` exactly when SPA-6 admits a one-sided abort that blames an absent non-signer, and MUST NOT carry it on another entry;
- MAY share a `contentHash` across two different jobIds only if byte-identical, in which case those entries deduplicate with `bundleRefs`.

Replay consumes each entry's `roleEvidence`, its `bb6Context` when `roleEvidence.kind == "binding"`, and either `counterpartyRef` + `counterpartyRoleEvidence` (present) or `absenceEvidenceRef` + `absenceBinding` (absent). A receipt whose entry omits any member REQUIRED for its disposition is non-conforming.

Three relations make each authenticated copy independently checkable at replay:

- **Counterparty authentication.** `anchoredByRole` is excluded from the §10.4.1 bundle hash, so a bare `counterpartyRef` cannot authenticate the role under which the counterparty copy resolved. The entry MUST carry the verified `counterpartyRoleEvidence` that did; its binding, when present, has `jobId` equal to the entry's jobId, `role` equal to the counterparty's role, and `bundleContentHash` equal to `counterpartyRef.contentHash`.
- **BB-6 reproduction.** A binding-backed entry MUST carry the `bb6Context` multiplicity inputs that reproduce why the authoritative copy won BB-6 selection. A replay that re-runs BB-6 over `candidateBindings` under `partyMap` and `budget` and reaches a `resolvedNativeAddress` other than `roleEvidence.binding.nativeAddress` is non-conforming.
- **Absence relation.** `absenceBinding.nativeAddress` MUST equal the dereferenced `AbsenceEvidence.nativeAddress`. `absenceBinding` MUST itself be BB-4-valid, with `role` equal to the missing side's role and `jobId` equal to the entry's jobId. BB-5 check 8 (`bundleContentHash` byte-equality with fetched content) is inapplicable to `absenceBinding` — the missing side's bundle never anchored, so no fetched content exists to match; the binding is verified per BB-4 with `jobId` and `role` equality and the `nativeAddress` relation above.

A deriver publishing a released-semantics replayable receipt emits `replayableDerivationVersion: "1"` in place of `derivationVersion`. A deriver making the stronger requested-session binding claim while retaining released metric semantics emits `jobBoundReplayableDerivationVersion: "1"`. A settlement-verified replayable receipt emits `replayableSettlementVerifiedDerivationVersion: "1"` and no other derivation discriminator. A current-profile receipt emits `authenticatedWindowDerivationVersion: "1"`. Every job-bound form includes `resolvedJobId` in every context entry; the current form additionally includes `windowReceipt`, `windowReceiptHistory`, and the conditional SPA-8 `participationEvidence`. All four set `resolutionContext := [entry(b) for b in reconciled]` in the same canonical ascending-`contentHash` order as `bundleRefs`.

**Replay (normative, extends the §10.5.3 determinism receipt).** All four replayable types MUST satisfy the common checks below and are non-conforming if their context is missing, mis-keyed, lacks any member REQUIRED for their type or an entry's disposition, or fails any check. The RSV-labelled checks apply to `ReplayableSettlementVerifiedReputationDerivation` and `AuthenticatedWindowReputationDerivation`; the job-bound checks apply to `JobBoundReplayableReputationDerivation` and both RSV replay types; the AWT checks apply only to `AuthenticatedWindowReputationDerivation`:

- it MUST satisfy the §10.5.3 (1)–(3) determinism-receipt contract;
- re-running the algorithm selected by the receipt discriminator (`derive` for released v1, `derive_job_bound` for job-bound released metrics, `derive_settlement_verified` for settlement-verified v1, or `derive_authenticated_window` for the current profile) under the recorded `windowingBasis`, each copy's `resolutionContext` entry supplied as its §10.5.1 tag, MUST reproduce byte-identical `metrics` and `bundleCount`;
- **re-verify `roleEvidence`** — a binding-backed entry's binding MUST pass BB-4, with `jobId` equal to the authoritative copy's jobId, `role` equal to `resolvedRole`, and `bundleContentHash` equal to the entry's `contentHash`;
- **reproduce BB-6 selection** — re-run BB-6 over `bb6Context.candidateBindings` under `partyMap` and `budget`, requiring disposition `present` with `resolvedNativeAddress` equal to `roleEvidence.binding.nativeAddress`;
- **re-run reconciliation** — dereference `counterpartyRef`, verify `counterpartyRoleEvidence` per the counterparty-authentication relation, and require the applicable type's divergence predicate against the authoritative copy to be false; settlement-verified types additionally require exact `settlementEvidence[]` reference-multiset agreement;
- **re-run RSV admission (settlement-verified types only)** — resolve and independently verify every presented SettlementEvidence under RSV-1/RSV-2 from immutable, hash-bound or finalized-state-bound authority; require `verified` before comparing metrics. `rejected` or `indeterminate` makes the receipt unverifiable and MUST NOT produce an alternative metric set;
- **re-check absence** — dereference `AbsenceEvidence`, require `absenceEvidenceRef.contentHash` to equal its `sha256(canonical)`, verify `absenceBinding` per the absence relation, and require `absenceBinding.nativeAddress` to equal `AbsenceEvidence.nativeAddress`.
- **job-bound types only** — require each non-empty `resolvedJobId` to equal the dereferenced authoritative copy's `jobId` and use that trusted value, rather than returned content, in every job-binding check. The released v1 type performs its historical checks against the authenticated copy's `jobId` and makes no stronger claim.
- **EBFAB in any job-bound type** — resolve and re-verify the signed listing, exact SettlementEvidence resolutions including authenticated phase-orchestrator authority, transitive ST-8 evidence, and bundle/evidence lifecycle state referenced by the EBFAB. A replay implementation whose configured authority resolvers cannot recover that material MUST refuse; it MUST NOT rederive while silently dropping SEB validation.
- **authenticated-window type only** — perform AWT-2 through AWT-7 over each entry's `windowReceipt` and require its exact finalized-inclusion timestamp to remain inside the receipt's inclusive window before metric comparison.
- **current one-sided external blame only** — require the exact SPA-8 `participationEvidence`, re-run SPA-1..SPA-6 including admission-anchor history and the admission/bundle deadline relation, and refuse the receipt if the context is missing, substituted, invalid, or unexpectedly present on a path that did not consume it.
- **current ratings only** — re-run SPA-7 against the signed Listing/effective pipeline, fully signed completed bundle, successful rate-phase entry, exact rating reference, and exact party-role map before comparing either rating metric.

The discriminators are unsigned but type-authoritative. A consumer MUST reject any receipt carrying no recognized derivation discriminator, multiple derivation discriminators, or a discriminator inconsistent with its claimed type. In particular it MUST NOT strip a settlement-verified discriminator and process the remaining fields under released v1 semantics.

> **Note (non-normative).** A conforming replay proves the receipt's *internal consistency* and the *authentication* of the evidence it re-verifies — the `roleEvidence`/`counterpartyRoleEvidence` bindings, the `partyMap` against the bundle roster, and the `bb6Context` candidates (BB-4/BB-5). It does NOT prove *completeness* or faithful disclosure: a deriver that omits relevant bundles from `bundleRefs` is not detected by replay — the §10.5.3 completeness residual (no authoritative "which bundles exist" oracle; #251-adjacent).

#### 10.5.1 Derivation algorithm

The algorithm below is `derive_settlement_verified` and emits `SettlementVerifiedReputationDerivation` or its replayable counterpart. The released `derive` algorithm and its two version-1 output types retain the DACS-5 v0.3 semantics; implementations MUST NOT label output from this algorithm with either released discriminator. For an executable definition of released `derive`, use the algorithm below with exactly three settlement-verified limbs disabled: it uses only the §10.4.3 divergence predicate, does not call `verify_presented_settlement_evidence`, and applies the released volume rule (a completed bundle with a valid `agreementRef` contributes its Agreement price without requiring presented successful-payment evidence). All other reconciliation, denominator, rating, ordering, windowing, and receipt rules are shared.

The job-bound `derive_job_bound` path retains the released metric semantics but emits `JobBoundReplayableReputationDerivation`; it is the minimum replayable path for EBFAB. A replayable settlement-verified derivation applies both the job-bound and RSV requirements and emits `ReplayableSettlementVerifiedReputationDerivation`.

`derive_authenticated_window` is the current-profile path. It applies the same validation, two-sided reconciliation, authoritative-copy selection, RSV admission, outcome formulas, and canonical ordering as `derive_settlement_verified`, then adds the SPA-6 one-sided-participation gate and SPA-7 rating gate and changes the order and source of window admission as follows:

```
derive_authenticated_window(party, bundles, windowStart, windowEnd):

  candidates := [b for b in bundles
                  where party in {p.primaryClaim for p in b.parties}]

  # Run the §10.5.1 settlement-verified validation/reconciliation loop over all
  # candidates first; do NOT pre-filter on b.finalisedAt or any receipt assertion.
  selected := settlement_verified_reconcile(party, candidates)

  reconciled := []
  outcomes := []
  for authoritative, outcome, context in selected:
    timeVerdict, receipt, history := verify_finalized_window_receipt(authoritative, context)
    if timeVerdict != "verified":
      continue                                      # AWT-5: indeterminate/non-countable; no fault
    participationVerdict := verify_one_sided_participation_if_required(
      authoritative, outcome, context, receipt)
    if participationVerdict != "verified":
      continue                                      # SPA-6: no admission-backed blame; no fault
    if windowStart <= receipt.blockRef.timestamp <= windowEnd:
      context.windowReceipt := receipt              # exact proof used; replayed under AWT-7
      context.windowReceiptHistory := history       # complete consumed/reconciled snapshot set
      reconciled.append(authoritative)
      outcomes.append(outcome)

  # Apply the unchanged settlement-verified outcome, volume, cancellation,
  # uniqueness, null/empty, bundleRefs, and resolutionContext rules below.
  # Rating collection is the SPA-7 current-profile variant: only a fully signed
  # completed bundle's authenticated successful rate phase may contribute.
  return AuthenticatedWindowReputationDerivation(
    authenticatedWindowDerivationVersion="1",
    windowingBasis="sr2-finalized-inclusion-timestamp",
    ...participation_safe_settlement_verified_metrics(reconciled, outcomes),
    resolutionContext=sort([context(b) for b in reconciled], by contentHash)
  )
```

`verify_finalized_window_receipt` is exactly AWT-2 through AWT-5, including all known receipt snapshots for the anchor; it is not a lookup for whichever receipt gives a favourable timestamp. `settlement_verified_reconcile` denotes the existing inner loop below, beginning with type/signature validation and ending with authoritative-copy selection plus RSV admission. `verify_one_sided_participation_if_required` returns `verified` without external evidence when the authoritative bundle is fully signed or the blamed party signed that exact abort bundle; otherwise it performs SPA-1..SPA-6 and consumes exactly the entry's `participationEvidence`. Moving the window and participation filters after reconciliation is load-bearing: two copies must be reconciled before either copy's time or alleged absent signer can affect inclusion, and every proof must bind the exact copy that actually feeds the metrics.

*Input precondition: each admitted input copy is resolution-context-tagged with the role under which it resolved (the anchor-address role on a pure-mapping substrate; the verified `BundleBinding`'s role per BB-4/BB-5 on a write-input substrate). A job-bound derivation additionally carries the trusted requested `jobId` from the role address or verified `BundleBinding`; it MUST equal the dereferenced copy before that copy may enter grouping or fallback. The authenticated-window path additionally receives all known SR-2 receipt snapshots for the resolved anchor and applies AWT-2 through AWT-7. EBFAB requires a job-bound path. The released replayable v1 path retains its historical input contract and does not consume `resolvedJobId`.*

*Settlement uniqueness (SB-2, §9.5.8): across the bundles reconciled below, a `settlement-tx-id` bound to more than one `(jobId, phaseIndex)` is counted once (earliest `observedAt`), so a reused settlement transaction cannot inflate `observedTransactionalVolume` or completion across jobs.*

```
derive_settlement_verified(party, bundles, windowStart, windowEnd):

  scoped := [b for b in bundles

              where party in {p.primaryClaim for p in b.parties}

              AND windowStart <= b.finalisedAt <= windowEnd]

  if scoped is empty:

    return SettlementVerifiedReputationDerivation with bundleCount=0, bundleRefs=[], observedTransactionalVolume=[], transactionCountByCurrency=[], and the scalar metrics (completionRate, counterpartyAdjustedCompletionRate, counterpartyFaultRate, averageBuyerRating, averageSellerRating) null

  # Per-jobId reconciliation to the scored party's perspective.
  # Two-sided anchoring (§10.4.2) means one jobId may contribute up to two
  # buyer/seller-anchored bundles (plus, in 3-party sessions, an
  # orchestrator-anchored copy), each recording `outcome` from ITS anchorer's
  # perspective. Counting raw `outcome` across copies would double-count, and
  # could ingest copies §10.4.1 says MUST be rejected. Collapse to one
  # signature-validated, perspective-adjusted outcome per jobId.
  # DACS-5 reputation is keyed to buyer/seller primary claims; orchestrator
  # reputation is out of scope for v0.1, so orchestrator-anchored copies are
  # evidence-only and are NOT used as a reputation perspective here.
  reconciled := []   // one authoritative bundle per jobId
  outcomes := []     // its outcome, perspective-adjusted to the scored party (index-aligned with reconciled)
  cancelled_jobids := {}   // jobIds with an established §10.3.1 ST-10 policy-permitted cancellation (neutral for BOTH parties), resolved across both non-divergent copies
  orchestrator_fault_jobids := {}   // jobIds whose authoritative FaultAttestationBundle names faultedParty "orchestrator", or whose non-divergent legacy pair has the singleton implied-fault intersection {orchestrator} — neutral for buyer and seller (orchestrator reputation is out of scope in v0.1)
  for jobId, copies in (scoped grouped by b.jobId):
    # (1) §10.4.1 signature validation: a non-abort outcome (completed / failed-perm /
    #     failed-counterparty / failed-substrate) MUST carry all required signatures;
    #     only aborts MAY be single-signed. Drop copies that fail this.
    # (2) §10.4.2 integrity: drop any copy failing the §10.4.2 anchoredByRole cross-check —
    #     against the anchor-address role segment on a pure-mapping substrate, or against the
    #     verified BundleBinding's role (BB-4/BB-5) on a write-input substrate. The anchoredByRole
    #     cross-check is copy-integrity only; it is NOT the fault source.
    # (2b) Type-specific validation: require exactly one supported discriminator and its matching
    #     signature domain; on either absolute-fault type require faultedParty consistency; on EBFAB
    #     additionally run SEB-1..SEB-6. Invalid returned content is rejected, never absence and never
    #     reinterpreted as an older type by stripping or renaming the discriminator.
    copies := [b for b in copies where valid_type_domain_and_signatures(b)
               AND anchoredByRole_matches_resolution_context(b)
               AND faultedParty_consistent_if_absolute(b)
               AND seb_valid_if_ebfab(b)]
    copies := [b for b in copies where b.anchoredByRole in {"buyer", "seller"}]   // orchestrator copies are evidence-only
    # (3) BB-6 multiplicity: canonically-equal same-role copies collapse to one; among
    #     divergent same-role copies a fully-§10.4.1-signed copy takes precedence over
    #     lesser-signed ones; equal-standing divergence voids the side (BB-7 not-retrieved).
    for role in {"buyer", "seller"}:
      role_copies := [b for b in copies where b.anchoredByRole == role]
      if |distinct canonical forms of role_copies| <= 1:
        copies := copies minus (role_copies minus one)              // collapse duplicates
      else if exactly one canonical form carries all §10.4.1 required signatures:
        copies := copies minus (role_copies minus that copy)        // full-signature precedence
      else:
        copies := copies minus role_copies                          // equal standing — BB-6 void
    if copies is empty: continue
    if |copies| == 1 AND the missing buyer/seller address was not authoritatively absent under §10.4.3: continue
    role_of_party := the role of the BundleParty p in copies[0].parties where p.primaryClaim == party
    self_copy := the b in copies where b.anchoredByRole == role_of_party        // scored party's own copy, if present
    cp        := the b in copies where b.anchoredByRole != role_of_party        // at most one (the buyer/seller counterparty copy)
    if self_copy exists AND cp exists AND self_copy and cp diverge under the settlement-verified predicate (the §10.4.3 predicate plus a different settlementEvidence reference multiset):
      continue   // (§10.4.3(d)) genuine dispute — EXCLUDE this jobId from ALL metrics (numerator and denominator), do not silently trust self_copy
    pair_faults := the common absolute-fault set established by self_copy and cp under §10.4.3, or {} when only one copy exists
    if self_copy exists AND cp exists AND bundle_type_rank(self_copy) != bundle_type_rank(cp):
      authoritative := the copy with greater bundle_type_rank         // EBFAB > FAB > legacy; both already valid and non-divergent
    else if self_copy exists:
      authoritative := self_copy
    else:
      authoritative := cp                                                       // only a counterparty copy exists (e.g. §10.11 suppression)
    settlement_verdict := verify_presented_settlement_evidence(authoritative)
    if settlement_verdict != "verified":
      continue   // RSV-3: rejected or indeterminate nested evidence excludes the jobId from ALL metrics without assigning fault
    outcome := scored_outcome(authoritative, role_of_party)                     // fault from either absolute type's faultedParty, or the legacy role-relative residual; see below
    # (ST-10) policy-permitted cancellation — resolve the `cancellation` marker across BOTH
    # non-divergent copies of this jobId (a marker on EITHER self_copy or cp counts). A one-sided
    # marker is NOT a §10.4.3 canonical divergence (that guard is scoped to outcome / phaseSummary),
    # so it MUST be resolved here, not treated as an advisory one-sided field — otherwise the
    # neutral/indeterminate verdict would collapse for the party whose own copy lacks the marker.
    marker := the `cancellation` marker carried on self_copy or cp, whichever has one (if any)
    if marker exists:
      run the §10.3.1 ST-10 teeth check on (listingRef, pre-commit phase facts):
        cannot resolve   -> continue                    // indeterminate — EXCLUDE jobId from ALL metrics (never neutral, never a fresh fault), exactly like the §10.4.3(d) dispute case
        resolves+permits -> cancelled_jobids.add(jobId)  // established: reputation-neutral for BOTH parties, whether the scored-party outcome is aborted-by-self OR aborted-by-other
        resolves+forbids -> (no-op)                      // invalid marker — the abort stays its ordinary fault bucket below
    if (authoritative is an absolute-fault type AND authoritative.faultedParty == "orchestrator") OR pair_faults == {"orchestrator"}:
      orchestrator_fault_jobids.add(jobId)
    reconciled.append(authoritative); outcomes.append(outcome)
  # scored_outcome(b, R) -> the scored party's perspective outcome for reconciled copy b:
  #   completed -> completed ; failed-substrate -> failed-substrate
  #   FaultAttestationBundle or EvidenceBoundFaultAttestationBundle: read the absolute hashed faultedParty (§10.4.1). The scored party
  #     is at fault iff b.faultedParty == R; when b.faultedParty == "orchestrator" the outcome is
  #     spelled not-at-fault for the scored buyer/seller and the jobId is neutralised below. With outcome-class abort|failure from b.outcome:
  #       (fault, abort)   -> aborted-by-self       (fault, failure)   -> failed-perm
  #       (¬fault, abort)  -> aborted-by-other      (¬fault, failure)  -> failed-counterparty
  #     This reads fault from the absolute field, NOT from b.outcome via anchoredByRole.
  #   legacy AttestationBundle: no faultedParty — the disclosed role-relative residual (§10.4.1):
  #     b.outcome if b.anchoredByRole == R, else perspective_flip(b.outcome).
  #   absolute-fault bundle with faultedParty == "orchestrator": neither buyer nor seller is at
  #     fault — the jobId joins the orchestrator-fault neutral class below (excluded from both
  #     fault denominators, retained in bundleCount), regardless of the abort|failure class.
  # perspective_flip (legacy AttestationBundle only): aborted-by-self <-> aborted-by-other ;
  #   failed-perm <-> failed-counterparty ; completed / failed-substrate unchanged.
  # divergence rule (self_copy, cp): per the exhaustive §10.4.3 table. Absolute-fault pairs diverge iff they differ in
  #   faultedParty, in outcome-class ({completed, failed-substrate, abort, failure}), or in a
  #   phaseSummary entry — NOT in the role-relative outcome spelling, which the absolute
  #   faultedParty reconciles (the invariant: paired copies carry an identical faultedParty). For
  #   a legacy pair, use the §10.4.3 implied-fault-set definition (disjoint sets diverge); for a
  #   mixed pair, use the §10.4.3 mixed-version rule (implied absolute fault vs faultedParty).
  #   For this settlement-verified type, every pair kind also diverges when its copies have
  #   different settlementEvidence reference multisets.
  # The §10.4.1 filter guarantees a non-abort outcome here is fully-signed and thus legitimately attributable.
  # All downstream metrics use `reconciled` (deduped bundles) / `outcomes`, never raw `scoped`.

  completed := [o for o in outcomes where o == "completed"]

  failed_perm := [o for (b, o) in zip(reconciled, outcomes) where o == "failed-perm" AND b.jobId not in orchestrator_fault_jobids]   // party-fault: stays in party_fault_denom but not in |completed|, so it depresses completionRate; v0.1 surfaces no separate party-fault rate metric

  failed_counterparty := [o for (b, o) in zip(reconciled, outcomes) where o == "failed-counterparty" AND b.jobId not in orchestrator_fault_jobids]

  failed_substrate := [o for o in outcomes where o == "failed-substrate"]

  cancelled_neutral := [b for b in reconciled where b.jobId in cancelled_jobids]   // established §10.3.1 ST-10 policy-permitted cancellations — reputation-neutral for BOTH parties, so collected by jobId (NOT by outcome string: the scored-party outcome may be aborted-by-self OR aborted-by-other). Excluded from every fault bucket and from both denominators below, yet still counted in |outcomes| (an observable, non-fault session — we attribute, we do not hide). A marker that resolved-and-forbade was never added to cancelled_jobids and stays its ordinary abort fault; a marker that could not be resolved was already dropped from `outcomes` (loop `continue` above).

  aborted_by_self := [o for (b, o) in zip(reconciled, outcomes) where o == "aborted-by-self" AND b.jobId not in cancelled_jobids AND b.jobId not in orchestrator_fault_jobids]   // party-initiated abort (§10.11): like failed_perm, depresses completionRate via the denominator; no separate metric in v0.1. A policy-cancelled abort is excluded here (it is in cancelled_neutral instead).

  aborted_by_other := [o for (b, o) in zip(reconciled, outcomes) where o == "aborted-by-other" AND b.jobId not in cancelled_jobids AND b.jobId not in orchestrator_fault_jobids]   // counterparty abort, with policy-cancelled ones excluded — so the non-cancelling party does NOT eat a counterparty fault on a validly-cancelled session (ST-10 symmetry)

  counterparty_fault_count := |aborted_by_other| + |failed_counterparty|

  orchestrator_fault_neutral := [b for b in reconciled where b.jobId in orchestrator_fault_jobids]   // orchestrator-fault sessions (§10.4.1 permissible set): neither scored party is at fault; excluded from both fault denominators like failed_substrate, retained in bundleCount

  party_fault_denom := |outcomes| − |failed_substrate| − |cancelled_neutral| − |orchestrator_fault_neutral|   // a verified policy-permitted cancellation (§10.3.1 ST-10) is neutral — dropped from the denominator exactly like failed_substrate, so it neither counts as completion nor as fault

  completionRate := |completed| / party_fault_denom   when party_fault_denom > 0 else null

  party_blame_denom := party_fault_denom − counterparty_fault_count   // also drop counterparty-caused outcomes (already counted above): a counterparty's abort/failure is not the scored party's fault
  counterpartyAdjustedCompletionRate := |completed| / party_blame_denom   when party_blame_denom > 0 else null

  counterpartyFaultRate := counterparty_fault_count / party_fault_denom  same gate

  # Collect ratings by fetching each bundle's referenced rating records

  ratings_targeting_party_as_seller := []

  ratings_targeting_party_as_buyer := []

  for b in reconciled:

    for ratingRef in (b.ratingRefs or []):

      r := fetch_and_verify_rating(ratingRef)   // RatingRecord

      // r.signature MUST verify against r.rater's primary-claim key

      // (same key class as a BundleSignature). Bind the rater to THIS session:

      if r is null: continue                                       // fetch_and_verify_rating failed: anchor unreadable, contentHash mismatch, or signature invalid → exclude (mirrors the agreementRef mismatch-excludes rule)

      if r.jobId != b.jobId: continue                              // not this session

      if not is_integer(r.value) or r.value < 1 or r.value > 5: continue   // RT-2: exclude out-of-range rating (§10.6.1)

      if r.rater not in {p.primaryClaim for p in b.parties}: continue   // rater was not a party here

      if r.rater == party: continue                                // no self-rating toward one's own score

      if r.target == party AND r.targetRole == "seller":

        ratings_targeting_party_as_seller.append(r.value)

      if r.target == party AND r.targetRole == "buyer":

        ratings_targeting_party_as_buyer.append(r.value)

  averageSellerRating := mean(ratings_targeting_party_as_seller)

                         when ratings_targeting_party_as_seller else null

  averageBuyerRating  := mean(ratings_targeting_party_as_buyer)

                         when ratings_targeting_party_as_buyer else null

  volume_terms := []

  for b in reconciled where b.outcome == "completed" AND agreementRef present AND b has at least one RSV-verified SettlementEvidence whose outcome == "success" AND phase is a DACS-4 §9.7 PaymentPhaseType:

    agreement := fetch_and_verify_agreement(b.agreementRef)   // DACS-3 AgreementArtifact

    volume_terms.append(agreement.terms.price)

  volume := groupSumByCurrency(volume_terms)
  txCountByCurrency := countByCurrency(volume_terms)   // per-currency count over the same completed set as volume

  bundleCount := |reconciled|   // one per distinct jobId after two-sided reconciliation, not |scoped|
  // Note: `reconciled` MAY be empty even when `scoped` is not (every jobId's copies were dropped by guard (i)
  // or excluded as divergent by guard (ii)); the denominator gates below then yield the same all-null /
  // bundleCount=0 result as the `scoped`-empty early return — there is no separate code path.

  bundleRefs := sort([ref(b) for b in reconciled], ascending by contentHash)   // deduped authoritative copies (matches bundleCount); canonical ascending-contentHash order per the §10.5.3 determinism receipt; empty when reconciled is empty
  windowingBasis := <"finalisedAt" | "sr2-anchor-timestamp">   // record which clock the window predicate was applied against (§10.5.1); re-derivation MUST use the same basis

  return SettlementVerifiedReputationDerivation with computed metrics
```

**Two-sided reconciliation (normative).** Two-sided anchoring (§10.4.2) can place two bundles for one jobId in the input, each recording `outcome` from *its anchorer's* perspective. The deriver MUST collapse the input to one authoritative bundle per jobId before partitioning (the `reconciled` step above). It MUST interpret `outcome` relative to the *scored* party, not the anchorer. The read rules:

- The authoritative copy's scored outcome is `scored_outcome(authoritative, role_of_party)` uniformly: on either absolute-fault type fault is read from the hashed `faultedParty`; on a legacy `AttestationBundle` it is the role-relative residual — read literally from the scored party's own copy, or through `perspective_flip` from a counterparty copy. The authoritative type is selected by EBFAB > FAB > legacy after validation and non-divergence.
- `perspective_flip` (`aborted-by-self ↔ aborted-by-other`, `failed-perm ↔ failed-counterparty`) exists only inside that legacy branch — e.g. the §10.11 bundle-suppression case where only a counterparty-anchored legacy copy survives. The aborter still takes the hit and the victim does not; a `FaultAttestationBundle` never needs the flip, since `faultedParty` is perspective-independent.

> **Note (non-normative).** Reading raw `outcome` across both copies (the pre-reconciliation behaviour) would double-count an abort against the victim and invert the §10.11 guarantee; the reconciliation closes that.

Three normative guards apply during reconciliation:

- (i) **type and signature validation first** — each copy MUST carry exactly one supported discriminator, verify under that type's domain, satisfy §10.4.1, and, for EBFAB, pass SEB-1..SEB-6 before it is considered. A single-signed bundle is valid only for an abort outcome; a single-signed `completed`/`failed-*` MUST be dropped. This closes the attack where a lone counterparty-anchored `failed-counterparty` is perspective-flipped to depress the victim's score. Any copy failing the §10.4.2 `anchoredByRole` cross-check — against the anchor-address role on a pure-mapping substrate, or against the verified `BundleBinding`'s role (BB-4/BB-5) on a write-input substrate — MUST be dropped. Divergent same-role copies resolve per BB-6 before the self/counterparty selection below — a fully-signed copy takes precedence over lesser-signed divergents, and only equal-standing divergence voids the side — preserving the at-most-one-copy-per-role invariant;
- (ii) **divergence → exclusion** — the scored party's own copy and a counterparty copy *canonically diverge* under the exhaustive §10.4.3 table when they contradict in outcome class/absolute fault, in a shared-index `phaseSummary` entry's `kind`/`outcome`/`errorClass`, or by a `phaseSummary` entry present in only one copy. Absolute-fault pairs compare `faultedParty`; absolute/legacy pairs compare it with the legacy implied-fault set; legacy pairs compare both implied-fault sets. For a settlement-verified derivation only, extend that predicate with exact canonical `settlementEvidence[]` reference-multiset equality: an added, removed, duplicated, or substituted full `AttestationRef` diverges, while array order alone is immaterial. A job divergent under the applicable predicate is a §10.4.3(d) dispute and MUST be excluded from ALL metrics, rather than silently trusting either copy. Exclusion removes the jobId from both the numerator and `party_fault_denom`, so a disputed session neither helps nor harms the score. There is no `disputed` value in the `outcome` enum (§10.4.1); this is an exclusion, not an outcome;
- (iii) **buyer/seller only** — `perspective_flip` is a buyer↔seller involution. Orchestrator-anchored copies are evidence-only and are not used as a reputation perspective (orchestrator reputation is out of scope for v0.1). This also makes the counterparty-copy selection unambiguous: at most one buyer/seller counterparty copy per jobId.

A fourth normative guard applies to any one-copy jobId, followed by the current-profile participation guard where that one copy blames a non-signer:

- (iv) **authoritative absence before one-copy attribution** — the missing buyer/seller address MUST have the §10.4.3 disposition `absent` before the present copy may be selected, perspective-flipped, or used to attribute an abort. In the job-bound path, each resolution tag MUST carry the trusted requested `jobId` established from the role address or verified `BundleBinding`; a consumer binds returned content and every rejection to that requested identity, never to returned content's self-asserted `jobId`. Returned content that is an invalid EBFAB — including content that omits or alters its `jobId` — is rejected for the requested session, not absent; an older copy on the other side therefore cannot become authoritative through this guard. A missing, unqualified, or `indeterminate` read disposition excludes the jobId from ALL metrics. Implementations MUST retain the two-address read dispositions as derivation context and MUST NOT add them to any signed bundle type. EBFAB or any stronger job-binding claim is published only as `JobBoundReplayableReputationDerivation`, `ReplayableSettlementVerifiedReputationDerivation`, or the stronger current `AuthenticatedWindowReputationDerivation`, according to the semantics claimed; the released `ReplayableReputationDerivation` v1 remains unchanged and makes no such claim. A caller that supplies one raw copy without that context has not established absence, so the deriver MUST exclude it. For current-profile output, authoritative absence is still only a non-publication fact: when the selected one-copy abort would blame an absent non-signer, the independent SPA-6 admission gate is also REQUIRED before the job enters any metric.

**Presented SettlementEvidence admission (RSV-1..RSV-4; settlement-verified types only).** This guard runs on the selected `authoritative` copy before it enters `reconciled`. When both buyer and seller copies exist, the settlement-verified divergence limb first requires their canonical `settlementEvidence[]` reference multisets to agree; comparison uses each full canonical `AttestationRef`, including multiplicity, while array order alone is immaterial. A producer therefore cannot make its own semantically contradictory reference silently control the other copy's settlement-verified reputation input:

- (RSV-1) `verify_presented_settlement_evidence` MUST resolve every `AttestationRef` in `authoritative.settlementEvidence`, verify its content hash and SettlementEvidence signature, and return exactly `verified`, `rejected`, or `indeterminate`. Whether the presented multiset is complete is the separate §10.4.3 production rule, not this guard.
- (RSV-2) Each resolved artifact MUST pass the applicable DACS-4 consumer rules against authority independent of the evidence under test: the authenticated Agreement and session, executed phase index, pinned rail/asset/network, resolved transaction parties/destination/amount, finality, and SB-1 through SB-3. The deriver MUST NOT infer expected economics from the SettlementEvidence itself, from the outer bundle's signatures, or from `fetch_and_verify_agreement` alone.
- (RSV-3) If any presented artifact is `rejected` or `indeterminate`, the deriver MUST exclude the entire jobId from every metric for that derivation. It MUST NOT convert the semantic contradiction or unavailable authority into a new outcome or fault attribution; exclusion removes the job from numerator, denominators, volume, ratings, `bundleCount`, and `bundleRefs` alike.
- **Conservative-attribution residual.** RSV-3 can remove an otherwise fault-bearing job from a denominator when its evidence is invalid. That is an accepted conservative cost: a rejected artifact proves that the job is unsafe as a settlement-verified reputation input, but its phase-orchestrator signature and the outer bundle signatures do not by themselves adjudicate which buyer/seller caused the semantic contradiction. A one-sided reference-multiset change is excluded by the settlement-verified divergence limb; a jointly presented invalid reference remains non-attributive. Resolving either case into party fault requires the out-of-band dispute/adjudication layer, not inference by `derive_settlement_verified()`.
- (RSV-4) A `verified` result admits the job to the unchanged reconciliation and non-volume metric formulas below. This rule verifies only the evidence multiset presented by the authoritative copy; it neither proves that the multiset is complete nor makes an optional `phaseSummary[].attestationRef` mandatory. An empty multiset is vacuously verified for this presented-evidence guard, but supplies no verified payment record and therefore contributes no `observedTransactionalVolume` or `transactionCountByCurrency` under the Volume rule below.

For `ReplayableSettlementVerifiedReputationDerivation` and `AuthenticatedWindowReputationDerivation`, RSV is re-executed from the hash-bound `settlementEvidence[]`, Agreement/session/phase/rail authority, and finalized transaction evidence before metric comparison. `rejected` or `indeterminate` at replay makes the receipt unverifiable; a replayer MUST NOT silently recompute a different metric set. The RSV verdict is derived evidence, not a trusted disposition to copy into `resolutionContext`. An authority input that is not immutable or bound to the finalized state used by the original verification cannot produce `verified`.

**Versioning.** DACS-5 v0.3 and both original version-1 derivation types were released in the DACS v0.4 profile at `4bb9e48a1095ab32c06c25b7c0b52018d3ce4091`. RSV changed which bundles enter metrics and therefore shipped additively in DACS-5 v0.4 only through `settlementVerifiedDerivationVersion: "1"` and `replayableSettlementVerifiedDerivationVersion: "1"`; the job-bound replay type was likewise additive. AWT changes window admission and replay evidence, so DACS-5 v0.6 introduced `authenticatedWindowDerivationVersion: "1"` on the unreleased `next` line rather than changing any of those five shapes. SPA-1..SPA-8 complete that new type's first action-bearing release contract in v0.7; no released receipt is reinterpreted. Existing discriminators retain their released meaning. In particular, all five historical discriminators remain frozen. After the current type's first release, any future action-bearing change to any derivation type requires another structurally distinguishable type or a major compatibility path under CORE §11.1.2.

**Fault attribution.** "party_at_fault" is otherwise recorded in the bundle’s phaseSummary errorClass. `counterparty` implies the other party. `permanent` on a non-cross-chain rail, with no settlement-atomicity flag and a successful pre-pay state, generally implies the local party at fault — absent the §7.8.2 counterparty-malformed-presentation carve-out, which maps a counterparty-malformed `error` to `counterparty`, not `permanent`. The classification rules are spelled out in the per-phase errorClass tables in chapters 7 and 9.

**Neutral exclusions from the fault denominator.** Three classes are excluded from the party-fault denominator — `party_fault_denom = |outcomes| − |failed_substrate| − |cancelled_neutral| − |orchestrator_fault_neutral|`: **`failed-substrate`** sessions (substrate-induced, nobody's fault) and **established §10.3.1 ST-10 policy-permitted cancellations** (an advertised, signed cancellation right, neutral for *both* parties — resolved across both non-divergent copies, so the exclusion applies whether the scored-party outcome is `aborted-by-self` or `aborted-by-other`), and **orchestrator-fault sessions** (either absolute-fault type naming `faultedParty: "orchestrator"`, or a non-divergent legacy pair whose per-copy implied-fault sets intersect only at `orchestrator`). In the latter case the singleton intersection, not the scored party's selected legacy spelling, is the established absolute attribution. A distinct orchestrator, not the scored buyer or seller, was responsible; orchestrator reputation is out of scope in v0.1 (§10.5.1 guard (iii)). None of the three classes damages either party's reputation; all remain in `bundleCount` as observable, non-fault sessions.

**Null vs empty metrics.** The **scalar** metrics (completionRate, counterpartyAdjustedCompletionRate, counterpartyFaultRate, averageBuyerRating, averageSellerRating) produce numeric values when their denominator > 0. With denominator == 0 (e.g., bundleCount=0, or all sessions failed-substrate; for `counterpartyAdjustedCompletionRate`, also when every reconciled bundle was counterparty-caused) they produce null — distinct from zero, signalling "no signal" rather than "zero signal". The **array** metrics `observedTransactionalVolume` and `transactionCountByCurrency` (non-nullable) and `bundleRefs` (a non-nullable `AttestationRef[]`) produce `[]` on the empty path: an empty list, never null. Every return path therefore yields a schema-total derivation of the selected type.

**Rating metrics.** The averageBuyerRating / averageSellerRating metrics are computed by walking each reconciled bundle’s ratingRefs, fetching the referenced RatingRecord, and verifying its signature against the rater’s primary-claim key (the same key class as a BundleSignature, per §10.4.1). Under the five historical/partial derivation shapes, a RatingRecord MUST be discarded — not aggregated — unless it binds to the session being scored under the frozen checks below:

- the deriver MUST require r.jobId == b.jobId;
- r.rater MUST be one of the bundle’s parties[].primaryClaim;
- r.rater MUST NOT equal the scored party (no self-rating).

Only the remaining records’ values, whose target matches the scored party, are aggregated; the metric is null when no qualifying ratings exist. The current `derive_authenticated_window` path additionally applies SPA-7 before aggregation: a historical shape's successful checks do not establish a completed rate phase or authenticated target role and cannot be upgraded by relabelling its receipt.

**Settlement-verified volume metric.** For the settlement-verified types, observedTransactionalVolume is computed after RSV-1 through RSV-4 have admitted the job's presented SettlementEvidence. A successful **payment** record is a DACS-4 §9.7 `SettlementEvidence` whose `outcome == "success"` and whose `phase` is a member of the closed `PaymentPhaseType` set defined there; a `DeliveryPhaseType` record is not payment evidence. For each reconciled bundle whose `outcome` is `completed`, whose `agreementRef` is present, and whose RSV-verified multiset contains at least one such successful payment record, the deriver MUST resolve the AttestationRef to its AgreementArtifact via fetch_and_verify_agreement(agreementRef), then sum agreement.terms.price grouped by currency. The Agreement establishes the agreed price; by itself it does not establish that the price settled. A completed bundle with no presented payment evidence contributes no volume, even if it remains eligible for non-volume metrics; §10.4.3 completeness is evaluated separately. Non-completed bundles (failed, aborted) contribute no volume: the metric reports value transacted, not value agreed. Resolution follows the §7.5.2 attestation resolution algorithm:

- fetch the anchor at agreementRef.anchor.locator;
- compare the hashed bytes to agreementRef.contentHash — a mismatch MUST cause that bundle to be excluded;
- parse the result as a DACS-3 AgreementArtifact, selecting its schema and signing domain from the required version discriminator.

agreementRef is an AttestationRef, not an inline AgreementArtifact, so the volume step MUST dereference it before reading terms.price.

**Rating de-duplication (normative).** Under two-sided anchoring (§10.4.2) both parties' bundles for one jobId may appear in the input before reconciliation, and `ratingRefs` is an array — so a naive walk would count the same rating more than once. The deriver MUST aggregate at most one rating per `(r.rater, r.jobId, r.targetRole)` tuple, last-writer-wins by `ratedAt` on a tie. A rating therefore contributes once per session-direction, not once per anchored bundle copy or per duplicate ref. (This is a counting rule; RT-1/RT-2 already bound each rating's value range.)

**`completionRate` denominator scope.** `party_fault_denom` excludes `failed-substrate` and established §10.3.1 ST-10 policy cancellations; it retains counterparty-fault and ordinary (non-cancelled) abort sessions. This is intentional: `completionRate` measures completed-vs-attempted, not blame. It leaves a residual griefing surface, however — a counterparty that repeatedly opens and aborts sessions depresses the target's `completionRate` through `aborted-by-other`. `counterpartyFaultRate` partially offsets this (it rises in step over the same denominator), and consumers SHOULD read the two metrics together rather than `completionRate` alone. A blame-weighted completion metric is a roadmap candidate.

The legacy algorithm above bounds against `b.finalisedAt`, a producer-set wall-clock value (§10.4), because changing that released behavior would reinterpret existing receipts. It is retained only for the five historical/partial shapes under AWT-8. Current-profile derivation MUST use `derive_authenticated_window`: the exact selected bundle's authenticated finalized-inclusion `blockRef.timestamp` is authoritative, and `finalisedAt` is advisory only. Implementations SHOULD flag material skew for audit without changing membership.

> **Note (non-normative).** This parallels the chain-timestamp discipline already required for sealed-envelope commits in §8.4.3 (SE-2), where the substrate anchor — not the producer’s clock — decides the timestamp.

#### 10.5.2 Per-primary-claim keying

The same wallet may hold multiple primary claims (key:…, did:…, lei:…). DACS-5 reputation is computed *per primary claim*. A great reputation against key:0xabc... does NOT inherit into a brand-new lei:984500ABCDEF… presentation, even though the same wallet may control both. Consumers querying reputation MUST query with the specific primary claim used in the current bundle’s presentedBy, not a wallet identifier or session pubkey. The `presentedBy` claim MUST be **control-proven** (DACS-1 §6.3.2 step (6)) to key reputation — a claim resting only on a DACS-2 existence/validity check (e.g. a bare-registry `lei` lookup the presenter does not provably control) does not qualify as a reputation key; this prevents keying reputation onto a public identifier the presenter merely cited. SR-1 (cross-substrate identity aggregation) is the substrate primitive that makes the wallet ↔ multi-primary-claim relationship explicit. It allows consumers to optionally surface "this party also has reputation under primary claim X" — informationally, NOT as inheritance.

#### 10.5.3 Computation surfaces

Derivation MAY be computed:

- (a) lazily by a querying party, over a set of bundles they fetched themselves — highest trust;
- (b) by a DACS-5 catalog operator (similar to a DACS-1 catalog — indexed for performance, but consumers MUST verify against the underlying bundles for high-stakes decisions);
- (c) on chain via an ERC-8004 reputation registry write per §10.7.

Each surface is a different point on the trust / performance trade-off; for a given discriminator, the selected algorithm is the same.

**Determinism receipt (normative).** Because the surfaces above can feed a derivation algorithm different inputs, every published derivation MUST be independently reproducible from its own contents under the algorithm selected by its discriminator:

- (1) `bundleRefs` MUST be exactly the applicable algorithm's `reconciled` set — the post-window-filter, two-sided-reconciled authoritative bundles it actually aggregated (one per jobId) — neither a superset nor a subset;
- (2) `bundleRefs` MUST be serialised in **canonical order: ascending lexicographic by `AttestationRef.contentHash`** (the same tie-break discipline as SE-5). Because `contentHash` is a sha256 digest the ordering is total; two refs sharing a `contentHash` reference byte-identical content and collapse to one entry. Two derivers that computed identical metrics over the same set therefore cannot disagree on `bundleRefs` byte-order;
- (3) a consumer that re-runs `derive` for a released v1 discriminator, `derive_settlement_verified` for a historical/partial settlement-verified discriminator, or `derive_authenticated_window` for the current discriminator under the recorded `windowingBasis` and context MUST obtain byte-identical `metrics` and `bundleCount`.

Historical/partial receipts remain reproducible relative to their declared legacy `windowingBasis`; that fact does not make their producer-controlled membership suitable for current decisions. A current-profile receipt has only `sr2-finalized-inclusion-timestamp` and carries the exact proof for every counted bundle under AWT-7. This makes published membership auditable against its declared inputs. It does NOT establish *completeness*: whether `bundleRefs` contains every relevant bundle is out of scope — no authoritative "which bundles exist" oracle is defined, and catalogs are best-effort per (b). Conformance: given a fixed discriminator, `bundleRefs` set, window, `windowingBasis`, and resolution context, the selected algorithm's output is byte-identical across implementations.

#### 10.5.4 Category-scoped derivation

The §10.5.1 derivation algorithm is unscoped: it aggregates all bundles for a party within a time window regardless of the service category involved. This is useful for overall reputation but obscures domain-specific track records — a party with excellent DeFi data delivery and a poor regulatory-data track record looks identical to one that is mediocre across the board.

**Category-scoped derivation** restricts the bundle set to sessions whose service category — the `offering.category` of the **listing** the agreement was formed against (the `AgreementArtifact` itself carries only `listingRef`, not the category) — matches a given category prefix before applying the §10.5.1 algorithm:

```
derive_category_scoped(party, bundles, windowStart, windowEnd, categoryScope):

  // 1. Filter to bundles whose agreement's category is within categoryScope
  category_bundles := [b for b in bundles
                        where b.agreementRef is present
                        AND fetch_category(b.agreementRef) starts_with categoryScope]

  // 2. Apply the standard §10.5.1 derive() algorithm over category_bundles
  return derive(party, category_bundles, windowStart, windowEnd)
```

`derive_settlement_verified_category_scoped` applies the identical category filter and then calls `derive_settlement_verified`; it emits only a settlement-verified discriminator. The released `derive_category_scoped` continues to call released `derive` and MUST NOT emit a settlement-verified discriminator.

`derive_authenticated_window_category_scoped` applies the identical category filter and then calls `derive_authenticated_window`; it is the only category-scoped path that emits current-profile reputation. The category lookup does not supply or modify anchor time: every admitted bundle still satisfies AWT-1..AWT-8 through its own exact `windowReceipt`.

`fetch_category` performs the full two-step resolution:

- (1) resolve the bundle's `agreementRef` to its `AgreementArtifact`, per the §7.5.2 attestation resolution algorithm;
- (2) resolve that document's `listingRef` to the Listing, verifying the fetched bytes against `listingRef.contentHash`, and return the Listing's `offering.category`.

Bundles whose `agreementRef` **or** `listingRef` cannot be resolved, or whose listing content-hash does not match, MUST be excluded from the category-scoped set — not treated as matching any category.

**`categoryScope` matching rule.** Let `cat = fetch_category(b.agreementRef)` (the resolved listing's `offering.category`). A bundle's category matches `categoryScope` if and only if `cat == categoryScope` OR `cat` starts with `categoryScope + "."`. Examples: scope `"data.finance"` matches `"data.finance"`, `"data.finance.fx"`, `"data.finance.equities"` but NOT `"data.financetools"`.

**Use in `ReputationHint` (§6.3.6).** The `ReputationHint` attached to a `ListingSummary` is computed by applying `derive_category_scoped` with `categoryScope` equal to the listing's `offering.category`, or a prefix thereof. Catalogs MAY broaden the scope when the listing category has fewer than a minimum number of qualifying bundles, provided the `reputationHint.categoryScope` field accurately reflects which scope was used. Consumers MUST read `reputationHint.categoryScope` to understand what population is reflected. Because the lightweight hint carries neither a derivation discriminator nor AWT replay context, it is always a historical/partial fast-path pre-filter and never current-profile reputation. Any action-bearing consumer re-derives through `derive_authenticated_window_category_scoped` from the underlying bundles and exact receipt evidence.

**Relationship to §10.5.2 per-primary-claim keying.** Category scoping is an orthogonal filter applied after the per-primary-claim scope; it does not change the identity keying rule.

### 10.6 The rate phase (optional)

A DACS-5 phase that produces structured ratings between parties at session end.

```
type RatingRecord = {
  ratingVersion: "1"
  jobId: string
  rater: ClaimReference                        // primary claim of the rating party
  target: ClaimReference                       // primary claim of the rated party
  targetRole: "buyer" | "seller"
  value: number                                // 1..5 inclusive integer
  freeText?: string                            // optional; max 1000 chars
  dimensions?: Record<string, number>          // optional per-dimension scores (timeliness, communication, etc.)
  ratedAt: number
  signature: ComponentSignature
}
```

#### 10.6.1 Phase contract

rate is OPTIONAL in a pipeline. When present, the phase MUST:

- run after all settle-* phases complete with ok: true;
- produce one RatingRecord per direction (buyer→seller, seller→buyer);
- sign each RatingRecord over the domain-separated payload "dacs-rating:v1:" || sha256(canonical_JCS(record_without_signature)) per §B.7;
- anchor each RatingRecord via SR-2 at dacs5:rating:{jobId}:{rater} (where {rater} is the RatingRecord.rater ClaimReference rendered per the CORE §B.1 logical-address escaping rule (CF-4) for colon-containing claim references);
- include both ratingRefs in the bundle.

Sellers and buyers MAY decline to rate; absence of a rating does not block bundle production. The pipeline step parameters MAY specify { required: true | false } per side.

**Rating bounds & dimensions (rules RT-1, RT-2).**

- (RT-1) A rate-phase producer MUST reject — and MUST NOT anchor — a RatingRecord whose `value` is not an integer in the inclusive range [1,5], or whose `freeText` exceeds 1000 characters.
- (RT-2) A reputation deriver MUST exclude (not clamp) any RatingRecord failing RT-1 from aggregation, so a malformed or hostile self-signed rating cannot enter `averageBuyerRating` / `averageSellerRating` even if a producer skips RT-1.

RT-1/RT-2 validate record shape and value only. Current-profile admission additionally requires SPA-7's fully signed completed bundle, authenticated successful rate phase, exact reference, and exact rater/target role map. A standalone valid rating signature is not evidence that the named target participated.

The optional `dimensions` field is **opaque pass-through metadata**: DACS-5 reputation derivation does not interpret or aggregate it, it carries no protocol semantics, its keys and value ranges are unconstrained, and consumers MUST NOT rely on it for any conformance-bearing decision.

> **Note (non-normative).** A canonical dimension namespace with per-dimension reputation is a roadmap candidate.

### 10.7 ERC-8004 publication surface

DACS-5 bundles can OPTIONALLY be reflected to the Ethereum ERC-8004 reputation / validation registries for EVM-side consumers.

#### 10.7.1 Mapping

When a party holds an erc8004 claim in their bundle, the publisher MAY write a reputation/validation registry entry referencing the bundle anchor. The publisher MUST:

- include in the registry entry the bundleAnchorLocator and bundleContentHash;
- sign the registry write with the key that owns the ERC-8004 token;
- rate-limit registry writes to avoid spam (suggested: at most one write per session per direction).

#### 10.7.2 Consumption

EVM-side consumers MAY read ERC-8004 entries as a discovery surface for DACS-5 bundles. They MUST fetch the referenced bundle and validate it independently. The ERC-8004 entry is a pointer, not a substitute for the bundle.

**Substrate decoupling.** Publication to ERC-8004 is OPTIONAL and is a Demos-to-Ethereum cross-pollination convenience. Other substrates MAY define equivalent publication surfaces (e.g., a Solana reputation program, a Bitcoin OP_RETURN scheme). DACS-5 does not require any particular publication surface; the bundle is the canonical artifact.

### 10.8 Conformance summary

| Role | Requirements |
| --- | --- |
| Orchestrator | Maintain SessionRecord per §10.3; transition states deterministically; after an abort-eligible phase becomes active, obtain and anchor the alleged obligor's exact `SessionParticipationAdmission` before relying on a later one-sided timeout for current reputation; produce bundle on terminal state |
| Bundle producer | Anchor `FaultAttestationBundle` under v0.3 semantics, or `EvidenceBoundFaultAttestationBundle` when claiming SEB-1..SEB-6; set `faultedParty` per §10.4.1; sign under the selected type domain; preserve ST-11 for completed bundles; anchor per §10.4.2; publish a signed BundleBinding per anchored copy on a write-input substrate (BB-1/BB-2); include all required references per §10.4.3 |
| Bundle consumer | Resolve native addresses per BB-4..BB-8 (verify bindings and role authorization, prune to the co-signed party map where available, apply the authorized-candidate multiplicity rule, fail closed to `indeterminate`; one-sided classification only after a resolved binding plus policy-qualified authoritative absence); require exactly one supported discriminator and its matching domain; reject a copy whose `faultedParty` contradicts its (outcome, anchoredByRole); run SEB-1..SEB-6 on EBFAB before pair selection; recompute canonical hashes, verify domain-separated signatures, and dereference and validate every contained AttestationRef; reconcile by EBFAB > FAB > legacy only after validity and non-divergence |
| Reputation deriver | For current decisions emit only `AuthenticatedWindowReputationDerivation`: apply RSV-1..RSV-4, require job-bound replay context, enforce AWT-1..AWT-8 over the exact selected bundle's finalized SR-2 inclusion receipt, enforce SPA-1..SPA-6 before external one-sided blame, and apply SPA-7 to every rating; preserve every older discriminator as historical/partial without reinterpretation; partition by primary claim; treat failed-substrate per the denominator rule; return null for zero-denominator scalar metrics; set `bundleRefs` to exactly the applicable algorithm's `reconciled` set in canonical ascending-`contentHash` order, and emit a derivation reproducible byte-for-byte from `bundleRefs` plus `resolutionContext` per §10.5.3 |
| Rate phase handler | One RatingRecord per direction; reject out-of-range `value` (non-integer or ∉[1,5]) / over-length `freeText` before anchoring (RT-1); anchor each; include it only in the fully signed completed bundle for the authenticated successful rate phase (SPA-7) |
| ERC-8004 publisher (optional) | §10.7.1 mapping; rate-limit writes; sign with token-owner key |

### 10.9 Rationale

**Session record off-chain by default.** Anchoring every state transition would dominate session economics for no audit benefit — the bundle captures what auditors need; intermediate state is operational noise. Off-chain SessionRecord + on-chain bundle is the right split.

**Bundle as the audit unit vs individual phase records.** Each phase already anchors its evidence; the bundle is the unifying envelope auditors start from and walk references out of. Without it, every consumer would reconstruct the session graph from disparate anchors.

**Domain-separated bundle signature.** The `dacs-bundle:v1:`, `dacs-fault-bundle:v1:`, and `dacs-evidence-bound-fault-bundle:v1:` prefixes prevent confusing a bundle signature with any other DACS signature or bundle type even when hash bytes collide — part of the §B.7 universal scheme.

**Per-primary-claim reputation vs wallet-keyed.** Wallet-keying would let a strong `key:0xabc…` reputation launder into a fresh `lei:…`. Per-primary-claim keying prevents it; a wallet honestly holding multiple claims accumulates separate reputations, surfaced cross-claim (via SR-1) without inheritance.

**Substrate-failure exclusion from party-fault denominators.** A session that fails because the substrate was down is nobody's fault; counting it would deter parties from transacting during substrate strain. Excluding `failed-substrate` keeps the metric honest.

**Null vs zero metrics.** A new party (bundleCount=0) has no signal, not a zero signal — zero would read as "completed 0%". Null forces consumers to handle "no data" deliberately rather than treating new parties as worst-rated.

**Optional rate phase.** Mandatory ratings create noise (friction-avoidance 5-stars) and retaliation exposure; optional, decline-able rating matches institutional and marketplace norms.

**Participation admission rather than orchestrator assertion.** Authoritative absence can establish that no bundle appeared at an address, but not that the address owner ever accepted a session. Binding the exact active obligation to the alleged obligor's own signature preserves one-sided suppression handling without letting an accuser manufacture counterparties or reuse a general session opt-in for a phase that never became active.

**ERC-8004 publication optional.** It's the dominant EVM reputation registry, but DACS-5 ships on substrates with no Ethereum-mainnet write path.

**Extended-pointer pattern for oversized bundles.** Some sessions exceed the storage-program cap (multi-party auctions, long attestation chains); the pattern keeps the canonical artifact at the on-chain address and ferries the rest off-chain with content-hash binding rather than hard-failing.

### 10.10 Backwards compatibility

**TimeoutMarker extension.** `timeout` is an optional, signature-covered bundle field under CORE SIG-5. Readers of the five historical derivation shapes preserve the field but remain neither required nor permitted to give it the new SPA meaning; their released algorithms are unchanged. Only the distinct current `AuthenticatedWindowReputationDerivation` acts on `TimeoutMarker`, and a bundle without it remains a valid audit artifact but cannot support SPA-6 one-sided current-profile blame. This preserves the CORE §11.1.2 additivity contract.

**ERC-8004 registries.** §10.7 specifies the publication surface; DACS-5 *reads* the ERC-8004 registry format for EVM consumers and leaves ERC-8004 unchanged. **Reputation integrity is DACS's own responsibility, not inherited from ERC-8004** — the ERC-8004 Draft explicitly out-of-scopes Sybil resistance, so anti-Sybil rests on DACS-5's per-primary-claim keying (§10.5) and the collusion/farming mitigations in §10.11, not on the registry pointer.

**Operator-marketplace ratings.** A marketplace migrating to DACS-5 MAY backfill historical ratings as operator-signed RatingRecord-equivalents; new DACS-5 ratings stand alone and are clearly distinguishable from the operator-signed history.

**Audit-log standards.** A consumer MAY convert a DACS-5 bundle to RFC 5424 / OpenTelemetry at read time; DACS-5 defines only the bundle.

### 10.11 Security considerations

**HTLC asymmetric-loss metric blind spot (known residual).** On a window-expired ST-8 asymmetric loss, both legs map to `settle-failed`/`settlement-atomicity` → `failed-counterparty` (§10.3.1). DACS-5 v0.1 cannot distinguish, at the metric level, the **payer who already received destination value** from the **payee who is owed source value** — the payer's copy reads `failed-counterparty` (and, perspective-flipped, may even read as party-fault), so neither `completionRate` nor `counterpartyFaultRate` reflects who actually profited. This is a DACS-X dispute concern, not resolvable in v0.1's blame model; consumers SHOULD treat any `failed-counterparty` whose phaseSummary carries an HTLC-9 `settlement-atomicity` marker as requiring out-of-band review rather than as a clean counterparty fault.

**Invented participant / unilateral blame.** *Threat:* an attacker invents a job naming a victim who never joined, waits until its chosen timeout, then publishes a single-signed `aborted-by-other` bundle. Authoritative absence would correctly prove non-publication while proving nothing about participation. *Mitigation:* a fully signed bundle proves its signers' participation; a current-profile one-sided abort can blame an absent non-signer only with that target's SPA-1..SPA-6 admission for the exact roster, active phase, action, and deadline. Without it the job is audit-only and excluded from all current metrics. A unilateral bundle can influence the alleged counterparty only when the alleged counterparty previously signed that exact admission.

**Bundle suppression.** *Threat:* a party who accepted an active obligation then refuses both the action and the terminal bundle, hoping to prevent publication. *Mitigation:* the counterparty's bundle attempt records the claimed abort. Current-profile consumers apply blame only after both the missing role's address is authoritatively absent under §10.4.3 and the missing party's earlier exact participation admission verifies under SPA-1..SPA-6. The two proofs answer different questions: absence proves no role copy was published; admission proves the non-signer had joined and accepted the due action.

*Implementation note:* a one-sided bundle MUST follow the same canonical form and signing rules. The §10.4.1 missing-signature rejection applies only to non-abort outcomes, so a single-signed abort remains a valid audit artifact. Current-profile reputation is a further gate: the resolution context carries both authoritative absence and, when the absent non-signer is blamed, the exact SPA-8 participation evidence. Neither proof substitutes for the other.

**Bundle-copy read censorship.** *Threat:* malicious read infrastructure withholds one anchored copy so two divergent bundles appear to be a clean one-copy session. *Mitigation:* §10.4.3 applies the CORE SR-2 absence-evidence policy before any one-sided classification, and §10.5.1 guard (iv) excludes an unqualified one-copy jobId from every reputation metric. A binding without authoritative absence support therefore loses one-copy reputation availability but does not fail open into party blame.

**Sybil reputation farming.** *Threat:* an attacker creates many cheap primary claims (key:…) and farms self-deal reputation between them. *Mitigation:* DACS-5 metrics are partitioned by primary claim and do not inherit; Sybil farming over key:… claims accumulates reputation only against those claims, not against higher-tier presentations. The DACS-2 supplementary signals (counterparty being a known Sybil cluster) feed back into Vet for any party who cares.

**Replay across sessions.** *Threat:* an attacker captures a signed bundle and replays it as a different session’s bundle. *Mitigation:* the bundle includes jobId; the signature payload includes the bundle hash which includes jobId. Replay against a different jobId fails verification.

**Cross-protocol and cross-type signature confusion.** *Threat:* a bundle or participation-admission signature is replayed as another DACS artifact, or an EBFAB discriminator is stripped/renamed so its signatures are tried against an older bundle type. *Mitigation:* §B.7 assigns distinct domains to all three bundle types, `SessionParticipationAdmission`, and `RatingRecord`. A consumer requires exactly one supported discriminator and verifies only under its matching domain. A signature produced under an admission, rating, other artifact, or another bundle type cannot validate even when the remaining fields or hash bytes align.

**Reputation poisoning via collusion.** *Threat:* two colluding parties run many fake sessions to inflate each other’s reputation. *Mitigation:* this is fundamentally hard to prevent at the protocol level. DACS-5 mitigates by per-primary-claim keying (collusion inflates only one tier of reputation), by transactional-volume reporting (consumers can see if a party’s reputation comes from many tiny sessions vs few large ones), and by composability with external signal sources. The volume signal is **weak and must not be over-trusted**: `observedTransactionalVolume` is reported per-currency, unnormalised, with no FX conversion (§10.5), so a colluding pair transacting across many low-significance currencies can keep every `PriceTerm` row small and evade the "few large vs many tiny" heuristic; cross-currency rows are not comparable or summable. The v0.2 `transactionCountByCurrency` metric (§10.5.1) supplies the per-currency transaction count strengthening that heuristic; an FX-normalised aggregate remains roadmap. Consumers SHOULD read volume alongside `bundleCount` and external signals rather than as a standalone collusion gate. Consumers handling stakes worth the cost of collusion SHOULD weigh DACS-5 metrics against external signals.

**Invented-roster rating.** *Threat:* an attacker puts a victim in a one-sided bundle and attaches a low self-signed RatingRecord, even though no eligible rate phase completed. *Mitigation:* SPA-7 admits ordinary ratings only from a fully signed `completed` bundle with an independently authenticated successful rate phase and an exact unique target-role match. Abort/failure ratings and non-roster targets are excluded; dispute ratings require a future distinct DACS-X artifact.

**Orchestrator misclassification of errorClass.** *Threat:* the orchestrator classifies a counterparty failure as a substrate failure (or vice versa) to bias reputation. *Mitigation:* the bundle phaseSummary carries the errorClass; both parties sign the bundle; a party that disagrees with the classification refuses to co-sign, terminating the session as aborted-by-other. A single-signed abort bundle is valid (§10.4.1), but a single-signed `failed-*` bundle is not — so refusal denies the misclassified bundle its second signature rather than letting the honest party publish a competing unilateral fault classification. Adjudicating which classification was correct is a DACS-X concern.

**Bundle anchor unavailability.** *Threat:* the SR-2 anchor becomes unreadable after the session ends (e.g. storage program purged, IPFS unpinned). *Mitigation:* on-substrate anchoring (Demos Storage Programs) provides indefinite availability under substrate operation. Off-substrate anchoring (IPFS, HTTPS) is best-effort. Listings concerned with long-term auditability SHOULD use on-substrate anchoring for bundles regardless of which surface the rest of the session uses.

**Time-bound reputation windows.** *Threat:* an old, no-longer-representative reputation is presented as current; a producer backdates or forward-dates `finalisedAt`; or it cherry-picks a replacement, reorged, or conflicting receipt to move an outcome across a boundary. *Mitigation:* current-profile derivation enforces AWT-1..AWT-8. It reconciles the exact bundle first, independently verifies one canonical finalized SR-2 inclusion and its consensus timestamp, binds that receipt into replay context, uses inclusive boundaries, and makes missing or unorderably conflicting evidence non-countable without a `finalisedAt` fallback. The released shapes are labelled historical/partial and cannot satisfy a current-profile query.

**ERC-8004 write spamming.** *Threat:* an attacker writes many fake ERC-8004 entries pointing at fabricated bundles. *Mitigation:* ERC-8004 entries are pointers; consumers MUST fetch and validate the bundle. Fake bundles fail at validation. The cost of writing many ERC-8004 entries (gas) is a natural rate limit; DACS-5 publishers SHOULD additionally enforce per-session rate limits.
