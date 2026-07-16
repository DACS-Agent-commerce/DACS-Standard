# DACS-5: Verify — Verify

*Normative module of DACS v0.1. Read the [Primer](../PRIMER.md) first; shared types, signatures, canonical form, the session model, and substrate requirements live in [CORE](CORE.md). Section numbers are retained from the unified specification; per the §→document map in [CORE](CORE.md), cross-references of the form §6–§10 point to sibling module documents, and §A / §12–§14 to the companion references (Demos mapping, threat model, glossary, conformance plan). The [conformance vectors](../conformance/) exercise this module's rules.*

## Chapter 10 — DACS-5: Verify

**Stage:** Verify (5th of 5). **Status:** Draft — **DACS-5 v0.3** (on the common DACS v0.1 baseline; v0.2 additions: the blame-weighted `counterpartyAdjustedCompletionRate` + `transactionCountByCurrency` reputation metrics §10.5.1, the ST-9 session-deadline timeout terminal §10.3.1, and the ST-10 policy-permitted pre-commit cancellation §10.3.1; v0.3 adds `PayeeBoundAgreementDocument` consumption alongside the legacy agreement artifact, the signed `BundleBinding` artifact + BB-1..BB-8 logical→native bundle resolution §10.4.2, and the `FaultAttestationBundle` artifact — absolute hashed `faultedParty` fault attribution as a distinct type under its own `dacs-fault-bundle:v1:` domain — §10.4.1). **Depends on:** SR-1 (preferred for cross-substrate primary-claim keying), SR-2 (required for bundle anchoring); composes with ERC-8004 reputation registry as an OPTIONAL publication surface. **Used by:** all subsequent DACS-1 sessions (reputation lookups), external auditors and regulators.

### 10.1 Abstract

DACS-5 specifies how a completed session is anchored, signed, and converted into a reputation signal. It defines:

- A **session record schema** — the live, mutable state the orchestrator maintains while a session runs (phase results, error classifications, event log); off-chain by default.
- An **attestation bundle format** — the frozen end-of-session artifact, signed by both parties and anchored via SR-2. Bundles are the audit unit.
- A **session-state machine** — deterministic, forward-only transitions from `draft` to a terminal state (`finalised`, the `*-failed` states, `failed-substrate`, the `aborted-by-*` states), enumerated normatively in §10.3.1.
- A **reputation derivation algorithm** — a deterministic, per-primary-claim function from a set of bundles to headline metrics (completion rate, dispute rate, average rating, observed transactional volume).
- An **optional rate phase** — a counterparty rating producing a RatingRecord referenced from the bundle.
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
| `settle-completed` | `rate-pending` (pipeline has a rate phase) \| `finalised` (no rate phase) | ST-4 |
| `rate-pending` | `rate-completed` \| `finalised` | ST-5 |
| `rate-completed` | `finalised` | rate phase done |
| `substrate-failure-paused` | the paused-from state it paused from (a `*-pending` state, or `settle-asymmetric`) \| `failed-substrate` | ST-7 |

**Rules:**

- (ST-1) **Forward-only.** Except for ST-7 resume, a transition MUST move toward a terminal state per the table. The orchestrator MUST NOT re-enter an earlier `*-pending` state (e.g. negotiate after commit).
- (ST-2) **Phase failure.** A phase returning `ok: false` MUST transition to that phase’s `*-failed` state, classified by the phase’s `errorClass`. An agreement commitment rejection (a CA-3 re-commitment for an already-anchored jobId, an artifact/phase mismatch, or an agreement failing the §8.5.2 listing-conformance checks) is a `commit-pending → commit-failed` transition (forward-only; it MUST NOT be folded back into `negotiate-failed`).
- (ST-3) **Abort.** At any `*-pending` state a party MAY withdraw, or decline to co-sign, before the phase reaches a `*-completed`/`*-failed` result; doing so terminates the session in an abort state. Withdrawing before being bound is a legitimate exercise of a party’s right to decline — it is NOT a protocol violation, and an abort outcome is therefore distinct from a `*-failed` performance failure. The abort state is recorded from the perspective of the party anchoring the bundle (per §10.4.3 / §10.11): the withdrawing party’s own bundle records `aborted-by-self`; the non-withdrawing party’s bundle records `aborted-by-other`. (A withdrawing party need not anchor a bundle at all; the §10.11 bundle-suppression rule lets the non-withdrawing party’s single-signed `aborted-by-other` bundle stand.) How an abort bears on reputation is governed by §10.5 / §10.11, not by this transition rule. Abort states are terminal.
- (ST-4) **Rate branch.** `settle-completed` transitions to `rate-pending` iff the listing pipeline contains a rate phase; otherwise directly to `finalised`.
- (ST-5) **Rate is non-fatal.** A rate phase that fails or is declined does NOT fail the session: `rate-pending` transitions to `finalised` regardless of rate outcome (per §10.6, absence of a rating does not block bundle production). There is deliberately no `rate-failed` state. A rate step parameter `{required: true}` is advisory for the rater’s own policy; it MUST NOT change this transition.
- (ST-6) **Terminal states.** The terminal states are exactly: `finalised`, `vet-failed`, `negotiate-failed`, `commit-failed`, `settle-failed`, `failed-substrate`, `aborted-by-self`, `aborted-by-other`. `SessionRecord.endedAt` MUST be set on entry to any terminal state, and a bundle MUST be produced (§10.4.3). `draft`, all `*-pending`, all non-failed `*-completed`, `rate-pending`, `settle-asymmetric`, and `substrate-failure-paused` are non-terminal.
- (ST-7) **Substrate-failure pause & resume.**
  - *Pause.* On `errorClass: "substrate"` (SR-2 or SR-3 unavailable, etc.) at any `*-pending` state **or at `settle-asymmetric`** (e.g. SR-2 is transiently unavailable when the orchestrator tries to anchor the ST-8 `:resolved` success record), the orchestrator MAY transition to `substrate-failure-paused`, recording the **paused-from state** (a `*-pending` state or `settle-asymmetric`), and retry per a backoff schedule.
  - *Resume.* On a successful retry the session resumes to the recorded paused-from state (the one permitted non-forward transition); the resumed phase/anchor MUST be idempotent or safe to re-drive (a phase that may have already broadcast an external effect — e.g. a pay-* phase — MUST check for that effect before re-issuing it).
  - *settle-asymmetric pause.* For a `settle-asymmetric` pause the retry window is additionally bounded by `expiry_source` (ST-8); if SR-2 cannot be reached to anchor the `:resolved` record before the per-listing pause maximum, the session transitions to `failed-substrate` (reputation-neutral) — NOT `failed-counterparty`, since the loss was substrate-induced, not a counterparty fault. (This applies only when the `htlc-claim` itself reached source-chain finality and only the *anchoring* is substrate-blocked; a payee that never claimed within the window is the genuine `failed-counterparty` loss of ST-8(b), not a substrate pause.)
  - *Time bound.* Pauses MUST be time-bounded; after a per-listing maximum pause (default 3600 seconds) the session MUST transition to `failed-substrate` (terminal). A successful resume clears the substrate condition: a subsequent failure of the resumed (or any later) phase is classified solely by that phase's own `errorClass`, independent of the prior `substrate` pause or pause-cycle count.
  - *Precedence over abort.* If, at a `*-pending` state, a party withdrawal/decline (ST-3) and a `substrate` condition arise together, the abort wins: the session MUST enter the abort state rather than `substrate-failure-paused`. An abort is a terminal exercise of a party's right (a party decision); a substrate pause exists only for transient substrate unavailability with no party decision. Both are legal next states from a `*-pending` state per the transition table; this rule resolves which applies when both fire at once.
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

- (ST-9) **Session-deadline timeout.** A `*-pending` state has no exit when **neither** a party decision (ST-3), a phase result, nor a substrate condition (ST-7) ever arrives — a counterparty simply goes silent, leaving the session in `*-pending` indefinitely. On a **session deadline** lapsing in a `*-pending` state with no pending phase result, the waiting party MAY finalise the session as **`aborted-by-other`** carrying a `timeout` reason marker, `endedAt` set, single-signed via the §10.11 bundle-suppression path. No new state or `outcome` is introduced — the timeout reuses the existing `*-pending → aborted-by-other` transition.
  - **Attribution.** The timeout is attributed to the party who **owed the awaited action** at that `*-pending` state — an objective state-machine fact, never motive inferred from silence. Conflicting cross-claims are reconciled by the dual-bundle rules (§10.4.3 / §10.11), exactly as for a disputed abort.
  - **Objective deadline.** The deadline MUST be an **objective** time — an SR-2 anchor time where the phase has one, else an agreed channel/substrate time source — and MUST NOT be a party-supplied `sentAt` / `generatedAt` / wall-clock value (a party could otherwise claim "not yet expired" to keep a stale session alive, or "already expired" to dodge a commitment). It is fixed at session/phase start, sourced per the listing or negotiate pattern.
  - **Reputation.** `aborted-by-other` already sits in the §10.5 counterparty-fault set, so the silent party bears the same mark it would by aborting (no cheaper escape than an honest decline) and the waiting party stays neutral (blame-weighted completion drops counterparty-caused outcomes, §10.5.1). The `timeout` marker preserves the audit distinction from a stated decline without changing the reputation treatment.
  - **Precedence.** Lowest. If a party decision (ST-3) or a substrate condition (ST-7) also applies, those win; the timeout fires only when nothing else did and the deadline lapsed. (CORE §B.8 SN-4 separately bounds the verifier's challenge-nonce lifetime for an abandoned session; ST-9 is the complementary state-machine terminal that gives the session a real end state.)

- (ST-10) **Policy-permitted pre-commit cancellation.** A listing MAY advertise a `cancellationPolicy` (DACS-1 §6). When that policy permits cancellation and a party withdraws while the session is still **pre-commit** — a `vet-pending` or `negotiate-pending` state, before `commit-completed` — the withdrawal is the same `aborted-by-self` transition as ST-3, with **no new state and no new `outcome`**; the anchoring party MAY additionally attach a `cancellation` marker (§10.4) recording the `claimedPolicy` value. The marker does not alter the recorded `outcome`; it is an assertion, evaluated at reputation-derivation time, that the withdrawal exercised an **advertised** right rather than bailing on a counterparty who had no notice. Without the marker, a pre-commit withdrawal is an ordinary ST-3 abort.
  - **Teeth (verification).** A consumer MUST treat the marker as established only if it resolves the bundle's `listingRef` `(listingId, version, contentHash)` to a listing whose `ListingSignature` (DACS-1) is present and verifies over the listing payload, **and** that **signed** listing's `cancellationPolicy` permits cancellation at the point the session ended (`pre-commit` for a pre-commit-state withdrawal), **and** the session did end pre-commit (no `agreementRef`; no `commit-completed` in `phaseSummary`). The binding policy MUST be read from the signed listing, never from the marker's self-asserted `claimedPolicy` — the signature over the listing is what makes the advertised policy non-repudiable.
  - **Trichotomy (do not collapse).** The teeth check has three outcomes, mirroring the §7.5.1 `pass`/`fail`/`indeterminate` decision semantics and the SB-3 third branch:
    - *resolves and permits* → the marker is **established**; §10.5.1 treats the `aborted-by-self` as **reputation-neutral**.
    - *resolves and forbids* (policy `none`, or a `pre-commit` claim on a session that actually reached `commit-completed`) → the marker is **refuted**; the `aborted-by-self` stands as the party-fault it already is.
    - *cannot be resolved* (listing pruned, signature transiently unverifiable, substrate unreachable) → the claim is **neither established nor refuted**: the consumer MUST NOT grant neutrality — that would rebuild the self-declared "don't count this" the teeth exist to prevent, since any party could cite an unresolvable listing for a free pass — and MUST NOT book the cancellation as a *fresh* fault on the unproven claim. The session is **indeterminate for reputation**, excluded from the derivation denominators pending resolution, exactly as an unresolved §7.5.1 `indeterminate`.
  - **Symmetry.** A policy-permitted cancellation is neutral for both parties — there is no `-by-self`/`-by-other` blame to split. The counterparty's copy, if any, records `aborted-by-other` per ST-3, and the same teeth check applied to it yields the same neutral result; mutual notice is what earns the mutual neutrality. Because the neutrality is symmetric, a consumer MUST resolve the `cancellation` marker across **both** non-divergent copies of the session — a marker carried on *either* copy establishes the cancellation for *both* parties' scores. A one-sided marker is **not** a §10.4.3 canonical divergence (that definition is scoped to `outcome` / `phaseSummary`), so it MUST NOT be treated as an advisory one-sided field; otherwise the neutral (and the indeterminate) verdict would collapse for the party whose own copy omits the marker (§10.5.1 resolves it at jobId reconciliation).
  - **Precedence.** A cancellation is a deliberate party action and ranks **with** abort (ST-3), above the ST-9 timeout: a party electing to cancel within an open deadline does so as a party decision, not a timeout. `with-fee` cancellation — a cancellation owing a fee after `commit-completed` — is **not defined** here; only the `pre-commit` case is honoured, and a `with-fee` value confers no neutrality.

**State → bundle `outcome` mapping (normative).** Every terminal state maps to exactly one bundle `outcome` (both bundle types share the enum) (§10.4), partitioned by the terminal phase’s `errorClass` where applicable:

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
- A `settle-failed` with `settlement-atomicity` is reached only **after** the asymmetric open state (ST-8) has been entered and its recovery window has expired without resolution. While the window is open the session is in the non-terminal `settle-asymmetric` state, and an `htlc-claim` reaching source-chain finality within the window resolves it forward (the pay phase returns ok and the per-stage sequencer completes any remaining settle phases) to `settle-completed → finalised` (terminal `completed`) per ST-8 — so a late-settling-but-successful cross-chain swap is recorded as `completed`, not as a failure.
- No terminal state lacks an `outcome`, and no `outcome` lacks a producing terminal state; `settle-asymmetric` is non-terminal and therefore produces no bundle until it resolves.

#### 10.3.2 Persistence and visibility

SessionRecord is off-chain by default. The orchestrator persists it locally. Counterparties MAY exchange partial views (e.g., the buyer needs to see the seller’s VerifyResultRef from Vet) but each side maintains its own canonical SessionRecord. On bundle production (end of session), the bundle’s contents are derived from the SessionRecord; the SessionRecord itself is not anchored on chain.

### 10.4 Attestation bundle

The frozen end-of-session artifact. Signed by all parties; anchored via SR-2.

Two bundle types share this section. The legacy **`AttestationBundle`** (`bundleVersion: "1"`) is the pre-fault-attribution class: fault is read role-relatively from its `outcome`. The **`FaultAttestationBundle`** (`faultBundleVersion: "1"`, defined after the shared component types below) is the v0.3 production type carrying absolute hashed fault attribution. Every rule in §10.4–§10.5 applies to both types alike except where it names one type.

```
type AttestationBundle = {

  bundleVersion: "1"                                    // the legacy class's §11.2.5 version literal. Fault is read role-relatively from `outcome` (§10.4.1); new v0.3 production anchors FaultAttestationBundle instead

  jobId: string

  outcome: "completed" | "failed-perm" | "failed-counterparty" | "failed-substrate" | "aborted-by-self" | "aborted-by-other"

  anchoredByRole: "buyer" | "seller" | "orchestrator"   // provenance: which party anchored THIS copy; `outcome` is spelled from this party's perspective and, on this legacy class, fault is read role-relatively through it (§10.5.1). Excluded from the hash; forgery-protected by the §10.4.2 cross-check

  listingRef: { listingId: string; version: number; contentHash: string }

  agreementRef?: AttestationRef               // present iff the session reached commit-completed or later; omitted only when terminated before the agreement commitment phase (see §10.4.3)

  cancellation?: CancellationMarker           // present only on an aborted-by-self/other claimed as a policy-permitted pre-commit cancellation (§10.3.1 ST-10); verified at reputation-derivation time against the signed listing, never trusted as asserted

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

  txRefs?: ChainTxRef[]

  attestationRef?: AttestationRef             // OPTIONAL per-phase back-pointer to the artifact this phase produced (settle → its SettlementEvidence, vet → its VerifyResult). The authoritative attestation set is the top-level settlementEvidence[] / vetRecords[]; see §10.4.3.

}

type BundleSignature = {

  party: ClaimReference                       // primary claim of the signer

  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"

  value: string                               // unpadded Base64URL (CORE §B.7 SIG-6) of the ed25519/ecdsa signature over the type's §10.4.1 domain-separated payload ("dacs-bundle:v1:" or "dacs-fault-bundle:v1:") || attestation_bundle_hash, NOT the raw bundle hash

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

#### 10.4.1 Canonical serialisation, hash, and domain-separated signature

Per the §B.2 canonical-form template, omitting the `signatures` **and `anchoredByRole`** fields — identically for both bundle types. Every other field is hashed, including the type's version literal (`bundleVersion` / `faultBundleVersion`) and, on a `FaultAttestationBundle`, `faultedParty`. The **attestation-bundle hash** (`attestation_bundle_hash`) is the content hash of that canonical form — sha256(canonical_form), hex-encoded — a computed value, not a stored field (distinct from `BundleParty.bundleHash`, which hashes a party's IdentityBundle), computed identically for both types. Each BundleSignature.value MUST be computed over the type's domain-separated payload:

signed_bytes := "dacs-bundle:v1:" || attestation_bundle_hash            (AttestationBundle)
signed_bytes := "dacs-fault-bundle:v1:" || attestation_bundle_hash      (FaultAttestationBundle)

The two domains are distinct §B.7 registry entries: a signature over one type MUST NOT validate as a signature over the other.

`BundleSignature.value` and each DACS-5 `ComponentSignature.value`, including a
rating signature, MUST use CORE §B.7 SIG-6. The encoded value carries the
signature over `signed_bytes`, not over the raw bundle hash.

> **Note (non-normative).** `anchoredByRole` is per-copy — buyer vs seller vs orchestrator — and is carried only for derive()'s perspective read (§10.5.1); it is excluded from the hashed canonical form exactly like `signatures` so the two-sided copies remain canonically equal in the happy path. This is a recognised, specified omission, not a SIG-5 silent strip.

**Absolute fault attribution (`faultedParty`).** `faultedParty` names the party responsible for `outcome` in absolute terms, independent of which copy carries it. It is REQUIRED on a `FaultAttestationBundle` and does not exist on the legacy `AttestationBundle`. It is part of the hashed canonical form. For a copy whose `anchoredByRole` is R, the permissible values are fixed by `outcome`:

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

Under DACS-5 v0.3 a producer MUST anchor `FaultAttestationBundle` records. A consumer MUST classify an `AttestationBundle` as the legacy class and read its fault role-relatively from `outcome`, never from a `faultedParty` field.

> **Note (non-normative).** `faultedParty` makes fault role-invariant. On the legacy `AttestationBundle`, fault is read from the role-relative `outcome` through the unhashed `anchoredByRole`, so a counterparty could re-anchor a single-signed abort under its own role and silently reverse blame. Hashing fault as an absolute party closes that rebind: it either contradicts the mapping and is rejected, or forces a re-signed divergent copy that voids the side under §10.4.3(d). Legacy `AttestationBundle` records are never rewritten and keep the pre-faultedParty residual; `FaultAttestationBundle` closes it under v0.3.

The "dacs-bundle:v1:" and "dacs-fault-bundle:v1:" string prefixes prevent cross-protocol signature confusion: an attacker capturing a bundle signature MUST NOT be able to replay it as a listing signature, agreement signature, the other bundle type's signature, or any other DACS signature even if the hash bytes collide.

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
  bundleContentHash: string       // the anchored copy's §10.4.1 `attestation_bundle_hash` (computed identically for both bundle types) (sha256 hex of its canonical form), matched byte-for-byte at BB-5
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
- (BB-6) Multiplicity and authorization. The candidate set for one `(jobId, role)` is the BB-4-valid bindings passing BB-5 checks 1–5, grouped by authenticated `signer`. A candidate is **authorized** when its `signer` is established as the bundle party holding `role`: pre-fetch, by matching the role→primary-claim map of an already-fetched copy of the same `jobId` carrying all §10.4.1 required signatures; otherwise post-fetch, by BB-5 check 9. Where such a co-signed map is available the consumer MUST prune the candidate set to the mapped signer's bindings before any fetch. In a reputation-derivation context the role→primary-claim map is always constructible — from the scored party's own copy, the pinned agreement's `parties[]` (§7.5.2 resolution), or a co-signed copy — and the prune is therefore MANDATORY there. The consumer MUST fetch candidates' distinct `nativeAddress` values in ascending `bundleContentHash` order (ties broken by ascending `nativeAddress` — a total order), at most N = 8 authorized-or-unresolved candidates per authenticated `signer` per `(jobId, role)`; a signer's candidates never consume another signer's budget, so an outsider cannot exhaust the honest role-holder's allocation. A fetched copy failing post-fetch authorization is discarded and **inert**: it MUST NOT count toward collapse, precedence, or void. If the budget exhausts while candidate addresses remain unfetched, the side's read disposition is `indeterminate` (BB-7) — never `absent`, never a void. Among **authorized** copies: canonically equal copies (§10.4.1) collapse to one retrieved copy; among canonically unequal copies, one carrying all §10.4.1 required signatures takes precedence and lesser-signed copies MUST be discarded; only when canonically unequal authorized copies are of equal signature standing is the side equivocating without a governing record — the consumer MUST NOT select among them and that side's read disposition is `indeterminate`. §10.4.3 classification proceeds on the read dispositions so established.
- (BB-7) Fail closed. A side for which no BB-4-valid candidate resolves, any of whose signers' candidates cannot all be fetched within that signer's BB-6 budget, whose authorized copies diverge at equal signature standing (BB-6), or whose every fetched copy fails a BB-5 post-fetch check, has the §10.4.3 read disposition `indeterminate`: neither `present` nor authoritatively `absent`, and it MUST NOT be promoted to either. Fetched content that fails validation is rejected content, never absence evidence. A consumer MUST NOT recompute a native address from the logical form on a write-input substrate and MUST NOT query the logical form as though it were a native address.
- (BB-8) Suppression diligence and the one-sided gate. On a write-input substrate, the §10.4.3(b) one-sided classification is reachable for a missing side only when both hold: (i) a BB-4-valid, BB-5-consistent binding resolves that side's `nativeAddress`, and (ii) an SR-2 read of that address is authoritatively `absent` under the substrate binding's declared absence-evidence policy (CORE §5) — the publication-without-anchoring case. Non-discovery of a binding, on however many surfaces, establishes `indeterminate`, never absence. A consumer SHOULD consult at minimum the party's own §6.3.5 well-known index and the §6.3.6 catalogs it uses for the session; consulting more surfaces improves discovery, but no quantity of consulted surfaces converts non-observation into `absent`.

> **Note (non-normative).** Only the anchorer holds the write inputs (deployer address, storage-program name, nonce, salt), so no other party can produce its mapping — hence BB-1's per-party publication. Carrying a binding confers no authorship: the signature, not the carrier, binds it to the anchoring role. Delivery to the counterparty alone leaves retrievability at the counterparty's discretion, so publication to a catalog is the recommended floor for a party with no surface of its own.

> **Note (non-normative).** BB-6's protections now key on the *authenticated-and-authorized* predicate, not the observable candidate count — the same lesson SE-9 applied to sealed commits. Only the role holder can author authorized same-role copies, so collapse, precedence, and void operate on a set an outsider cannot enter: an outsider's flood is pruned pre-fetch when a co-signed party map is available, and is inert post-fetch otherwise, degrading the attack from fabricating a one-sided classification to at worst suppressing a side into `indeterminate` — the already-priced read-censorship residual (§10.11), which excludes rather than blames. A void remains reachable only through equal-standing divergence among authorized copies, i.e. self-inflicted equivocation; under the §10.4.3 absence gate that side is `indeterminate`, so the session is excluded from reputation rather than resolved against either party.

> **Note (non-normative).** The BB-6 bound N = 8 is a fetch budget — a denial-of-service floor on retrieval work, not a protocol constant and not a void trigger: exhaustion yields `indeterminate`, never a classification. It is steward-tunable; a future minor can raise it without a major bump. Ascending `bundleContentHash` order keeps which candidates are fetched deterministic across consumers; a consumer MAY re-run resolution with a larger budget to lift an exhaustion-`indeterminate`.

> **Note (non-normative).** The load-bearing integrity checks are post-fetch — the content hash, the `anchoredByRole` cross-check, and the §10.4.1 signatures — so a wrong or poisoned binding yields at worst a fetch that fails verification, the same posture as §6.3.6 catalog poisoning. Retrievability is weaker: a binding suppressed from every surface a consumer reaches is indistinguishable from a never-published one, and the side resolves `indeterminate` — the session is then excluded from reputation (§10.4.3 / §10.5.1 guard (iv)); it does not fail open into one-sided blame.

> **Note (non-normative).** This is the completeness residual §10.5.3 already discloses (no authoritative "which bundles exist" oracle). BB-2 narrows it but does not close it; because discovery is scoped to the surfaces a given consumer consults, two consumers with different surface sets can legitimately reach different classifications for the same session — one resolving both copies (`unified`/`divergent`) where another, missing a binding, resolves `indeterminate`. Neither reaches one-sided attribution without the BB-8 gate. A party's remediation is publication to a surface its counterparties' consumers reach — BB-2 makes the own-surface or catalog route primary for exactly this reason. Adjudication of a fabricated one-sided abort remains a DACS-X dispute concern.

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

For an extended-pointer anchoring, the record at the resolved `nativeAddress` is the pointer. BB-5 check 8 and the §10.4.1 comparison apply to the **dereferenced full bundle**: `binding.bundleContentHash` MUST equal `pointer.fullBundleContentHash` MUST equal the recomputed §10.4.1 hash of the dereferenced bundle — three values, one identity. A pointer whose signature fails, or whose dereferenced content hash mismatches, is rejected content (BB-7), never absence.

#### 10.4.3 Bundle production rules

A bundle MUST be produced when the session reaches a terminal state. The bundle MUST include references to:

- all DACS-2 composite verification records;
- the DACS-3 agreement (if any);
- DACS-4 settlement evidence — one entry per executed phase invocation, **except** an ST-8-resolved cross-chain settle phase, which contributes exactly its `:resolved` success record. The interim `dest-revealed-source-unclaimed` failure record is NOT listed independently in `settlementEvidence[]` and is reachable only via that record's `supersedesEvidenceRef`. Both parties' `settlementEvidence[]` arrays MUST therefore contain identical entries — the resolved record, not the interim — so the two-sided copies stay canonically equal (§10.4.1);
- DACS-4 amendments (refunds);
- DACS-5 ratings (if the rate phase ran).

The bundle MUST NOT include references to any record outside the session’s scope.

**Per-phase `attestationRef` (optional).** A `phaseSummary[]` entry's `attestationRef` is **OPTIONAL** — the authoritative attestation set is the bundle's top-level `vetRecords[]` and `settlementEvidence[]` arrays (per the rules above), and a bundle that omits the per-phase pointer is well-formed. A validator MUST NOT reject a bundle solely because a `phaseSummary` entry omits `attestationRef`. A phase that produced a durable anchored attestation — a settle phase → its `SettlementEvidence`, a vet phase → its `VerifyResult` — **SHOULD** carry `attestationRef` linking to it, so the per-phase → evidence mapping is unambiguous in multi-phase pipelines where the flat top-level arrays alone cannot say which record belongs to which phase invocation.

**For sessions terminating before the agreement commitment phase** (aborted-by-self/other in Vet or Negotiate), the bundle MUST include the available vetRecords and a phaseSummary marking the failed phase; agreementRef is omitted.

**For sessions terminating with failed-substrate**, the bundle’s outcome captures the substrate failure; the failure does not count as either party’s fault in DACS-5 reputation derivation.

Two parties producing independent bundles for the same session MUST converge on the same session facts or MUST surface the divergence as a dispute. Convergence is canonical-form equality (which excludes the per-copy `anchoredByRole` and `signatures` fields per §10.4.1, so happy-path copies are equal despite different `anchoredByRole` values) — or, for a `FaultAttestationBundle` perspective pair, agreement on `faultedParty` and outcome class with role-relative `outcome` spellings that differ only per the §10.4.1 permissible-set mapping: such a pair converges even though the canonical forms differ. Each side anchors its own bundle at its own derived address. The two `stor-{sha256(jobId + "-bundle-{role}")}` values are the **logical** bundle addresses (§10.4.2). A consumer looking up "the bundle(s) for session X" resolves each side's native address per the §10.4.2 binding rules (BB-5): on a pure-mapping substrate by direct computation; on a write-input-mapping substrate such as Demos through that side's published `BundleBinding`s, never by recomputation (BB-6/BB-7). The consumer then queries both sides' resolved native addresses.

**Definition — "canonically diverge" (normative, defined once).** The two copies' canonical forms differ in `outcome`, or in a shared-index `phaseSummary` entry's `kind`/`outcome`/`errorClass` — i.e. a *contradiction* about what happened. A `phaseSummary` entry present in one copy and absent in the other **is** a divergence: the entry set is a normative input, and a copy asserting a phase the other's record denies is a contradiction about which phases ran, not advisory skew (it is also the guard against appending a fabricated phase entry that would otherwise escape entry-wise comparison). A difference confined to advisory fields (e.g. `finalisedAt` skew, one-sided `ratingRefs`, amendment ordering) is NOT a divergence. For a `FaultAttestationBundle` pair the `outcome` contradiction is read on the absolute `faultedParty` and the outcome class (`completed`, `failed-substrate`, abort, or failure), not the role-relative `outcome` spelling. Two `FaultAttestationBundle` copies naming the same `faultedParty` and class do not diverge, even where one reads `aborted-by-self` and the other `aborted-by-other`; the shared-index `phaseSummary` limb applies to both versions unchanged. Legacy `AttestationBundle` copies are reconciled through the §10.5.1 `perspective_flip` mapping before comparison: a counterparty-anchored copy is mapped to the scored party's perspective, and the pair diverges only if the perspective-reconciled outcomes then contradict — implying different faulted parties, or differing in outcome class. Perspective-partner spellings (`aborted-by-self` ↔ `aborted-by-other`, `failed-perm` ↔ `failed-counterparty`) are the same event seen from two sides and do NOT diverge; the shared-index `phaseSummary` limb applies unchanged. (This aligns the definition with the `perspective_flip` machinery the §10.5.1 deriver already applies — guard (ii) — which the prior "outcome-spelling" clause contradicted: it called perspective partners divergent even though the deriver reconciles them.)

**Mixed-version pairs (normative).** When one side of a session anchors a `FaultAttestationBundle` and the other a legacy `AttestationBundle`, the pair is compared on the common fault surface: the legacy copy's role-relative `outcome` is mapped through its `anchoredByRole` per the §10.4.1 permissible-set table to an **implied-fault set** — the set of parties in this session's `parties[]` the legacy outcome permits (a singleton in a two-party session, preserving the prior exact mapping byte-for-byte), and its outcome class is read directly. The pair canonically diverges when the `FaultAttestationBundle`'s `faultedParty` is **not a member** of that set, when the outcome classes contradict, or on the shared-index `phaseSummary` limb (unchanged for all pairs). A non-divergent mixed pair is a unified session bundle whose authoritative copy for derivation is the `FaultAttestationBundle` (§10.5.1). Every same-session pair is therefore classified by exactly one of: the canonical-equality rule, the `FaultAttestationBundle`-pair rule, this mixed-version rule, or the legacy `outcome`-spelling rule — there is no unclassified pair.

Consumers MUST:

- (a) resolve each side's native address per the §10.4.2 binding rules (BB-5) — on a write-input substrate through that side's published `BundleBinding`, never by recomputation — then fetch both addresses and retain the CORE SR-2 read disposition for each. An address whose `BundleBinding` cannot be resolved and verified per §10.4.2 has the read disposition `indeterminate`. A consumer MAY enter rule (b) only when exactly one valid bundle is `present` and the other expected address is authoritatively `absent`. If fewer than two valid copies are present and any missing address is `indeterminate`, the overall lookup is `indeterminate`. If neither copy is present, the lookup is `absent` only when both expected addresses are authoritatively `absent`; otherwise it is `indeterminate`. Returned content that fails §10.4.1 or §10.4.2 validation is not absence and MUST be rejected under those rules;
- (b) if exactly one valid bundle is present and the other expected address is authoritatively absent, classify by the present copy's signature set:
  - a copy carrying all §10.4.1 required signatures is the unified session bundle; the missing copy is an anchoring omission, not an abort, and no abort outcome is attributed to either party;
  - a single-signed copy with an abort outcome is classified per the §10.11 bundle-suppression rule: `aborted-by-self` for the non-signer, `aborted-by-other` for the signer;
  - a single-signed copy with any other outcome is rejected per §10.4.1, leaving no valid bundle for the session;
- (c) if both are present and do NOT diverge (canonically equal, differing only in advisory fields, or a `FaultAttestationBundle` perspective pair — or non-divergent mixed-version pair — agreeing on the absolute fault and outcome class per the definitions above), treat as the unified session bundle — a reputation-deriving consumer prefers the scored party's own anchored copy where they differ advisorily, except that in a mixed-version pair the `FaultAttestationBundle` copy is authoritative (matching §10.5.1's reconciliation), while a consumer with no scoring context (e.g. an auditor) MAY treat either copy as canonical for non-reputation purposes, since by definition they agree on every contradiction-bearing field;
- (d) if both are present and canonically diverge (a contradiction per the definition above), treat the session as disputed — each bundle stands on its own signatures and consumers must decide an out-of-band dispute-handling policy (e.g., flag for human review). This discretion does **not** extend to DACS-5 `ReputationDerivation`: a conforming `derive()` MUST exclude the jobId from ALL metrics under §10.5.1 guard (ii) and MUST NOT select either party's copy for party-specific reputation.

v0.1 does not specify a dispute resolution path; divergence is handled out-of-band. A future minor version (DACS-X, dispute) may specify selective transcript disclosure under signed party agreement or arbitrator order.

`absent`, `indeterminate`, `one-sided`, `unified`, and `divergent` are consumer lookup dispositions, not values of the §10.4.1 bundle `outcome` enum (common to both bundle types). In particular, `indeterminate` records that the two-address observation was incomplete; it asserts neither absence nor a canonical contradiction.

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
  resolutionContext: ResolutionContextEntry[]   // one entry per reconciled jobId (§10.5.1): the resolution facts derive() consumed that the copies themselves cannot carry. REQUIRED (empty array only when bundleRefs is empty). Never part of any signed bundle (§10.5.1 guard (iv)); it is derivation-record data.
  bundleRefs: AttestationRef[]                 // exactly the reconciled set (§10.5.1), in canonical ascending-contentHash order (§10.5.3 determinism receipt)
}

type ResolutionContextEntry = {
  contentHash: string                           // keys the entry to its bundleRefs member (ascending-contentHash order, §10.5.3)
  resolvedRole: "buyer" | "seller"              // the §10.5.1 input-precondition role under which the authoritative copy was resolved
  roleEvidence:                                   // exactly ONE of (XOR — the authenticated backing for resolvedRole):
    | { kind: "binding"; binding: BundleBinding }  // write-input substrate: the verified BB-4/BB-5 binding; binding.bundleContentHash MUST equal contentHash and binding.role MUST equal resolvedRole
    | { kind: "address"; resolvedAddress: string } // pure-mapping substrate: the anchor address whose role segment MUST equal resolvedRole
  counterpartyDisposition: "present" | "absent"   // the §10.4.3 read disposition of the OTHER expected buyer/seller address
  counterpartyRef?: AttestationRef                 // REQUIRED iff counterpartyDisposition == "present": the counterparty copy reconciled against — lets a rederiver re-run §10.4.3 divergence + authority selection
  absenceEvidenceRef?: { kind: string; locator: string; contentHash: string }   // REQUIRED iff counterpartyDisposition == "absent": an opaque, hash-bound reference to the substrate-policy-defined absence evidence (CORE §5) the deriver relied on
  absenceBinding?: BundleBinding                   // REQUIRED iff counterpartyDisposition == "absent" on a write-input substrate: the BB-5-consistent binding resolving the MISSING side's nativeAddress for (jobId, role) — proves the absence evidence attaches to the counterparty's actual address
}
```

A derivation MUST contain exactly one `ResolutionContextEntry` per `bundleRefs` member, keyed by `contentHash`. A one-copy jobId whose entry lacks a valid `absenceEvidenceRef` MUST NOT be included in a published derivation — §10.5.1 guard (iv) already excludes it from the metrics, and this rule extends that exclusion to the receipt: publication requires the evidence that qualified the inclusion. Two reconciled copies of different jobIds MAY share a `contentHash` only if byte-identical; entries are then deduplicated with `bundleRefs`. Replay (§10.5.3 (4)) consumes each entry's `roleEvidence`, plus `counterpartyRef` on a present disposition or `absenceEvidenceRef` and `absenceBinding` on an absent one. A receipt whose entry omits any member REQUIRED for its disposition is non-conforming.

#### 10.5.1 Derivation algorithm

*Input precondition: each input copy is resolution-context-tagged — the role under which it was resolved (the anchor-address role on a pure-mapping substrate; the verified `BundleBinding`'s role per BB-4/BB-5 on a write-input substrate) accompanies the copy, since neither bundle type carries its resolving context.*

*Settlement uniqueness (SB-2, §9.5.8): across the bundles reconciled below, a `settlement-tx-id` bound to more than one `(jobId, phaseIndex)` is counted once (earliest `observedAt`), so a reused settlement transaction cannot inflate `observedTransactionalVolume` or completion across jobs.*

```
derive(party, bundles, windowStart, windowEnd):

  scoped := [b for b in bundles

              where party in {p.primaryClaim for p in b.parties}

              AND windowStart <= b.finalisedAt <= windowEnd]

  if scoped is empty:

    return ReputationDerivation with bundleCount=0, bundleRefs=[], observedTransactionalVolume=[], transactionCountByCurrency=[], and the scalar metrics (completionRate, counterpartyAdjustedCompletionRate, counterpartyFaultRate, averageBuyerRating, averageSellerRating) null

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
  orchestrator_fault_jobids := {}   // jobIds whose authoritative FaultAttestationBundle names faultedParty "orchestrator" — neutral for buyer and seller (orchestrator reputation is out of scope in v0.1)
  for jobId, copies in (scoped grouped by b.jobId):
    # (1) §10.4.1 signature validation: a non-abort outcome (completed / failed-perm /
    #     failed-counterparty / failed-substrate) MUST carry all required signatures;
    #     only aborts MAY be single-signed. Drop copies that fail this.
    # (2) §10.4.2 integrity: drop any copy failing the §10.4.2 anchoredByRole cross-check —
    #     against the anchor-address role segment on a pure-mapping substrate, or against the
    #     verified BundleBinding's role (BB-4/BB-5) on a write-input substrate. The anchoredByRole
    #     cross-check is copy-integrity only; it is NOT the fault source.
    # (2b) §10.4.1 faultedParty consistency: drop any FaultAttestationBundle copy that omits faultedParty
    #     or whose faultedParty violates its (outcome, anchoredByRole) permissible set (§10.4.1) — the cross-role-rebind reject.
    copies := [b for b in copies where valid_signatures_per_§10.4.1(b) AND anchoredByRole_matches_resolution_context(b) AND faultedParty_consistent_per_§10.4.1(b)]
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
    if self_copy exists AND cp exists AND self_copy and cp diverge (divergence rule below):
      continue   // (§10.4.3(d)) genuine dispute — EXCLUDE this jobId from ALL metrics (numerator and denominator), do not silently trust self_copy
    if self_copy exists AND cp exists AND exactly one of them is a FaultAttestationBundle:
      authoritative := that FaultAttestationBundle copy               // non-divergent mixed-version pair (§10.4.3): absolute fault is authoritative
    else if self_copy exists:
      authoritative := self_copy
    else:
      authoritative := cp                                                       // only a counterparty copy exists (e.g. §10.11 suppression)
    outcome := scored_outcome(authoritative, role_of_party)                     // fault from the absolute faultedParty (FaultAttestationBundle), or the legacy role-relative residual (AttestationBundle); see below
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
    if authoritative is a FaultAttestationBundle AND authoritative.faultedParty == "orchestrator":
      orchestrator_fault_jobids.add(jobId)
    reconciled.append(authoritative); outcomes.append(outcome)
  # scored_outcome(b, R) -> the scored party's perspective outcome for reconciled copy b:
  #   completed -> completed ; failed-substrate -> failed-substrate
  #   FaultAttestationBundle: read the absolute hashed faultedParty (§10.4.1). The scored party
  #     is at fault iff b.faultedParty == R; when b.faultedParty == "orchestrator" the outcome is
  #     spelled not-at-fault for the scored buyer/seller and the jobId is neutralised below. With outcome-class abort|failure from b.outcome:
  #       (fault, abort)   -> aborted-by-self       (fault, failure)   -> failed-perm
  #       (¬fault, abort)  -> aborted-by-other      (¬fault, failure)  -> failed-counterparty
  #     This reads fault from the absolute field, NOT from b.outcome via anchoredByRole.
  #   legacy AttestationBundle: no faultedParty — the disclosed role-relative residual (§10.4.1):
  #     b.outcome if b.anchoredByRole == R, else perspective_flip(b.outcome).
  #   FaultAttestationBundle with faultedParty == "orchestrator": neither buyer nor seller is at
  #     fault — the jobId joins the orchestrator-fault neutral class below (excluded from both
  #     fault denominators, retained in bundleCount), regardless of the abort|failure class.
  # perspective_flip (legacy AttestationBundle only): aborted-by-self <-> aborted-by-other ;
  #   failed-perm <-> failed-counterparty ; completed / failed-substrate unchanged.
  # divergence rule (self_copy, cp): per the single §10.4.3 definition incl. its mixed-version rule. For a FaultAttestationBundle pair, they diverge iff they differ in
  #   faultedParty, in outcome-class ({completed, failed-substrate, abort, failure}), or in a
  #   phaseSummary entry (§10.4.3) — NOT in the role-relative outcome spelling, which the absolute
  #   faultedParty reconciles (the invariant: paired copies carry an identical faultedParty). For
  #   a legacy pair, the §10.4.3 perspective-reconciled definition (flip the counterparty copy, then compare implied fault + outcome class — partner spellings do not diverge); for a mixed pair, the §10.4.3 mixed-version rule (implied absolute fault vs faultedParty).
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

  for b in reconciled where b.outcome == "completed" AND agreementRef present:

    agreement := fetch_and_verify_agreement(b.agreementRef)   // DACS-3 AgreementArtifact

    volume_terms.append(agreement.terms.price)

  volume := groupSumByCurrency(volume_terms)
  txCountByCurrency := countByCurrency(volume_terms)   // per-currency count over the same completed set as volume

  bundleCount := |reconciled|   // one per distinct jobId after two-sided reconciliation, not |scoped|
  // Note: `reconciled` MAY be empty even when `scoped` is not (every jobId's copies were dropped by guard (i)
  // or excluded as divergent by guard (ii)); the denominator gates below then yield the same all-null /
  // bundleCount=0 result as the `scoped`-empty early return — there is no separate code path.

  bundleRefs := sort([ref(b) for b in reconciled], ascending by contentHash)   // deduped authoritative copies (matches bundleCount); canonical ascending-contentHash order per the §10.5.3 determinism receipt; empty when reconciled is empty
  resolutionContext := [entry(b) for b in reconciled, same order]   // per-jobId resolution facts (resolvedRole, counterparty disposition, absence evidence ref) — the §10.5.3 receipt's replay context; empty when reconciled is empty
  windowingBasis := <"finalisedAt" | "sr2-anchor-timestamp">   // record which clock the window predicate was applied against (§10.5.1); re-derivation MUST use the same basis

  return ReputationDerivation with computed metrics
```

**Two-sided reconciliation (normative).** Two-sided anchoring (§10.4.2) can place two bundles for one jobId in the input, each recording `outcome` from *its anchorer's* perspective. The deriver MUST collapse the input to one authoritative bundle per jobId before partitioning (the `reconciled` step above). It MUST interpret `outcome` relative to the *scored* party, not the anchorer. The read rules:

- The authoritative copy's scored outcome is `scored_outcome(authoritative, role_of_party)` uniformly: on a `FaultAttestationBundle` fault is read from the absolute hashed `faultedParty`; on a legacy `AttestationBundle` it is the role-relative residual — read literally from the scored party's own copy, or through `perspective_flip` from a counterparty copy.
- `perspective_flip` (`aborted-by-self ↔ aborted-by-other`, `failed-perm ↔ failed-counterparty`) exists only inside that legacy branch — e.g. the §10.11 bundle-suppression case where only a counterparty-anchored legacy copy survives. The aborter still takes the hit and the victim does not; a `FaultAttestationBundle` never needs the flip, since `faultedParty` is perspective-independent.

> **Note (non-normative).** Reading raw `outcome` across both copies (the pre-reconciliation behaviour) would double-count an abort against the victim and invert the §10.11 guarantee; the reconciliation closes that.

Three normative guards apply during reconciliation:

- (i) **signature validation first** — each copy MUST pass §10.4.1 before it is considered. A single-signed bundle is valid only for an abort outcome; a single-signed `completed`/`failed-*` MUST be dropped. This closes the attack where a lone counterparty-anchored `failed-counterparty` is perspective-flipped to depress the victim's score. Any copy failing the §10.4.2 `anchoredByRole` cross-check — against the anchor-address role on a pure-mapping substrate, or against the verified `BundleBinding`'s role (BB-4/BB-5) on a write-input substrate — MUST be dropped. Divergent same-role copies resolve per BB-6 before the self/counterparty selection below — a fully-signed copy takes precedence over lesser-signed divergents, and only equal-standing divergence voids the side — preserving the at-most-one-copy-per-role invariant;
- (ii) **divergence → exclusion** — the scored party's own copy and a counterparty copy *canonically diverge* when they contradict in `outcome`, in a shared-index `phaseSummary` entry's `kind`/`outcome`/`errorClass`, or by a `phaseSummary` entry present in only one copy — the single §10.4.3 definition, whose `FaultAttestationBundle`-pair rule reads the `outcome` contradiction on the absolute `faultedParty` and outcome class, and whose mixed-version rule compares the implied absolute fault, and whose legacy rule compares perspective-reconciled outcomes through `perspective_flip` (partner spellings are one event, not a contradiction) — never on mere advisory-field skew. A divergent jobId is a §10.4.3(d) dispute and MUST be excluded from ALL metrics, rather than silently trusting the self-copy. Exclusion removes the jobId from both the numerator and `party_fault_denom`, so a disputed session neither helps nor harms the score. There is no `disputed` value in the `outcome` enum (§10.4.1); this is an exclusion, not an outcome;
- (iii) **buyer/seller only** — `perspective_flip` is a buyer↔seller involution. Orchestrator-anchored copies are evidence-only and are not used as a reputation perspective (orchestrator reputation is out of scope for v0.1). This also makes the counterparty-copy selection unambiguous: at most one buyer/seller counterparty copy per jobId.

A fourth normative guard applies to any one-copy jobId:

- (iv) **authoritative absence before one-copy attribution** — the missing buyer/seller address MUST have the §10.4.3 disposition `absent` before the present copy may be selected, perspective-flipped, or used to attribute an abort. A missing, unqualified, or `indeterminate` read disposition excludes the jobId from ALL metrics. Implementations MUST retain the two-address read dispositions as derivation context — published as the derivation's `resolutionContext` (§10.5.3) — and MUST NOT add them to the signed bundle (either type). A caller that supplies one raw copy without that context has not established absence, so the deriver MUST exclude it.

**Fault attribution.** "party_at_fault" is otherwise recorded in the bundle’s phaseSummary errorClass. `counterparty` implies the other party. `permanent` on a non-cross-chain rail, with no settlement-atomicity flag and a successful pre-pay state, generally implies the local party at fault — absent the §7.8.2 counterparty-malformed-presentation carve-out, which maps a counterparty-malformed `error` to `counterparty`, not `permanent`. The classification rules are spelled out in the per-phase errorClass tables in chapters 7 and 9.

**Neutral exclusions from the fault denominator.** Three classes are excluded from the party-fault denominator — `party_fault_denom = |outcomes| − |failed_substrate| − |cancelled_neutral| − |orchestrator_fault_neutral|`: **`failed-substrate`** sessions (substrate-induced, nobody's fault) and **established §10.3.1 ST-10 policy-permitted cancellations** (an advertised, signed cancellation right, neutral for *both* parties — resolved across both non-divergent copies, so the exclusion applies whether the scored-party outcome is `aborted-by-self` or `aborted-by-other`), and **orchestrator-fault sessions** (a `FaultAttestationBundle` naming `faultedParty: "orchestrator"` — a distinct orchestrator, not the scored buyer or seller, was responsible; orchestrator reputation is out of scope in v0.1, §10.5.1 guard (iii)). None of the three damages either party's reputation; both remain in `bundleCount` as observable, non-fault sessions.

**Null vs empty metrics.** The **scalar** metrics (completionRate, counterpartyAdjustedCompletionRate, counterpartyFaultRate, averageBuyerRating, averageSellerRating) produce numeric values when their denominator > 0. With denominator == 0 (e.g., bundleCount=0, or all sessions failed-substrate; for `counterpartyAdjustedCompletionRate`, also when every reconciled bundle was counterparty-caused) they produce null — distinct from zero, signalling "no signal" rather than "zero signal". The **array** metrics `observedTransactionalVolume` and `transactionCountByCurrency` (non-nullable) and `bundleRefs` (a non-nullable `AttestationRef[]`) produce `[]` on the empty path: an empty list, never null. Every return path therefore yields a schema-total `ReputationDerivation`.

**Rating metrics.** The averageBuyerRating / averageSellerRating metrics are computed by walking each reconciled bundle’s ratingRefs, fetching the referenced RatingRecord, and verifying its signature against the rater’s primary-claim key (the same key class as a BundleSignature, per §10.4.1). A RatingRecord MUST be discarded — not aggregated — unless it binds to the session being scored:

- the deriver MUST require r.jobId == b.jobId;
- r.rater MUST be one of the bundle’s parties[].primaryClaim;
- r.rater MUST NOT equal the scored party (no self-rating).

Only the remaining records’ values, whose target matches the scored party, are aggregated; the metric is null when no qualifying ratings exist.

**Volume metric.** The observedTransactionalVolume metric is computed analogously. For each reconciled bundle whose `outcome` is `completed` and whose agreementRef is present, the deriver MUST resolve the AttestationRef to its AgreementArtifact via fetch_and_verify_agreement(agreementRef), then sum agreement.terms.price grouped by currency. Non-completed bundles (failed, aborted) contribute no volume: the metric reports value transacted, not value agreed. Resolution follows the §7.5.2 attestation resolution algorithm:

- fetch the anchor at agreementRef.anchor.locator;
- compare the hashed bytes to agreementRef.contentHash — a mismatch MUST cause that bundle to be excluded;
- parse the result as a DACS-3 AgreementArtifact, selecting its schema and signing domain from the required version discriminator.

agreementRef is an AttestationRef, not an inline AgreementArtifact, so the volume step MUST dereference it before reading terms.price.

**Rating de-duplication (normative).** Under two-sided anchoring (§10.4.2) both parties' bundles for one jobId may appear in the input before reconciliation, and `ratingRefs` is an array — so a naive walk would count the same rating more than once. The deriver MUST aggregate at most one rating per `(r.rater, r.jobId, r.targetRole)` tuple, last-writer-wins by `ratedAt` on a tie. A rating therefore contributes once per session-direction, not once per anchored bundle copy or per duplicate ref. (This is a counting rule; RT-1/RT-2 already bound each rating's value range.)

**`completionRate` denominator scope.** `party_fault_denom` excludes `failed-substrate` and established §10.3.1 ST-10 policy cancellations; it retains counterparty-fault and ordinary (non-cancelled) abort sessions. This is intentional: `completionRate` measures completed-vs-attempted, not blame. It leaves a residual griefing surface, however — a counterparty that repeatedly opens and aborts sessions depresses the target's `completionRate` through `aborted-by-other`. `counterpartyFaultRate` partially offsets this (it rises in step over the same denominator), and consumers SHOULD read the two metrics together rather than `completionRate` alone. A blame-weighted completion metric is a roadmap candidate.

The windowing predicate above bounds against `b.finalisedAt`, which is a producer-set wall-clock value (§10.4) with no anchoring-time cross-check. Because the bundle is anchored via SR-2, a consensus-attested write time is also available. Consumers performing high-stakes derivation SHOULD bound the window against the bundle’s SR-2 anchor timestamp — the substrate’s consensus-attested write time — rather than, or in addition to, the self-asserted `finalisedAt`. They SHOULD flag a `finalisedAt` that diverges materially from the anchor time. `finalisedAt` is otherwise advisory; the anchor time is authoritative for windowing.

> **Note (non-normative).** This parallels the chain-timestamp discipline already required for sealed-envelope commits in §8.4.3 (SE-2), where the substrate anchor — not the producer’s clock — decides the timestamp.

#### 10.5.2 Per-primary-claim keying

The same wallet may hold multiple primary claims (key:…, did:…, lei:…). DACS-5 reputation is computed *per primary claim*. A great reputation against key:0xabc... does NOT inherit into a brand-new lei:984500ABCDEF… presentation, even though the same wallet may control both. Consumers querying reputation MUST query with the specific primary claim used in the current bundle’s presentedBy, not a wallet identifier or session pubkey. The `presentedBy` claim MUST be **control-proven** (DACS-1 §6.3.2 step (6)) to key reputation — a claim resting only on a DACS-2 existence/validity check (e.g. a bare-registry `lei` lookup the presenter does not provably control) does not qualify as a reputation key; this prevents keying reputation onto a public identifier the presenter merely cited. SR-1 (cross-substrate identity aggregation) is the substrate primitive that makes the wallet ↔ multi-primary-claim relationship explicit. It allows consumers to optionally surface "this party also has reputation under primary claim X" — informationally, NOT as inheritance.

#### 10.5.3 Computation surfaces

Derivation MAY be computed:

- (a) lazily by a querying party, over a set of bundles they fetched themselves — highest trust;
- (b) by a DACS-5 catalog operator (similar to a DACS-1 catalog — indexed for performance, but consumers MUST verify against the underlying bundles for high-stakes decisions);
- (c) on chain via an ERC-8004 reputation registry write per §10.7.

Each surface is a different point on the trust / performance trade-off; the algorithm is the same.

**Determinism receipt (normative).** Because the surfaces above can feed `derive()` different inputs, a published `ReputationDerivation` MUST be independently reproducible from its own contents:

- (1) `bundleRefs` MUST be exactly the §10.5.1 `reconciled` set — the post-window-filter, two-sided-reconciled authoritative bundles `derive()` actually aggregated (one per jobId) — neither a superset nor a subset;
- (2) `bundleRefs` MUST be serialised in **canonical order: ascending lexicographic by `AttestationRef.contentHash`** (the same tie-break discipline as SE-5). Because `contentHash` is a sha256 digest the ordering is total; two refs sharing a `contentHash` reference byte-identical content and collapse to one entry. Two derivers that computed identical metrics over the same set therefore cannot disagree on `bundleRefs` byte-order;
- (3) `resolutionContext` MUST contain exactly one entry per `bundleRefs` member, keyed by `contentHash` in the same canonical order, carrying the resolution facts the copies cannot: the resolved role of each authoritative copy and, for every one-copy jobId, the counterparty address's `absenceEvidenceRef` — the authoritative-absence evidence the deriver relied on (§10.5.1 guard (iv)). Each entry also carries its `resolvedRole` backing (`roleEvidence`), a `counterpartyRef` for a two-copy jobId, and a write-input `absenceBinding` for a one-copy jobId;
- (4) a consumer that re-runs `derive(partyPrimaryClaim, deref(bundleRefs), windowStart, windowEnd)` under the recorded `windowingBasis`, supplying each copy's `resolutionContext` entry as its §10.5.1 input-precondition tag, MUST obtain byte-identical `metrics` and `bundleCount`. That replay re-runs §10.4.3 reconciliation against each `counterpartyRef`, re-verifies each `roleEvidence`, and re-checks each `absenceBinding` against its `absenceEvidenceRef`. A derivation that is missing, mis-keyed, or lacks any member REQUIRED for an entry's disposition is insufficient for replay and is non-conforming.

Because §10.5.1 lets high-stakes consumers window against the SR-2 anchor timestamp rather than the producer-set `finalisedAt`, two derivers using different windowing bases legitimately compute different sets. The receipt is therefore defined **relative to the declared `windowingBasis`**, which a conforming derivation MUST record. This makes any published derivation auditable against its declared inputs, including the one-copy absence evidence that admitted each single-sided jobId. It does NOT establish *completeness*: whether `bundleRefs` contains every relevant bundle is out of scope — no authoritative "which bundles exist" oracle is defined, and catalogs are best-effort per (b). Conformance: given a fixed `bundleRefs` set, window, and `windowingBasis`, `derive()` output is byte-identical across implementations.

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

`fetch_category` performs the full two-step resolution:

- (1) resolve the bundle's `agreementRef` to its `AgreementArtifact`, per the §7.5.2 attestation resolution algorithm;
- (2) resolve that document's `listingRef` to the Listing, verifying the fetched bytes against `listingRef.contentHash`, and return the Listing's `offering.category`.

Bundles whose `agreementRef` **or** `listingRef` cannot be resolved, or whose listing content-hash does not match, MUST be excluded from the category-scoped set — not treated as matching any category.

**`categoryScope` matching rule.** Let `cat = fetch_category(b.agreementRef)` (the resolved listing's `offering.category`). A bundle's category matches `categoryScope` if and only if `cat == categoryScope` OR `cat` starts with `categoryScope + "."`. Examples: scope `"data.finance"` matches `"data.finance"`, `"data.finance.fx"`, `"data.finance.equities"` but NOT `"data.financetools"`.

**Use in `ReputationHint` (§6.3.6).** The `ReputationHint` attached to a `ListingSummary` is computed by applying `derive_category_scoped` with `categoryScope` equal to the listing's `offering.category`, or a prefix thereof. Catalogs MAY broaden the scope when the listing category has fewer than a minimum number of qualifying bundles, provided the `reputationHint.categoryScope` field accurately reflects which scope was used. Consumers MUST read `reputationHint.categoryScope` to understand what population is reflected. The hint is only a fast-path pre-filter and MUST be verified against underlying bundles for high-stakes decisions.

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
| Orchestrator | Maintain SessionRecord per §10.3; transition states deterministically; produce bundle on terminal state |
| Bundle producer | Anchor `FaultAttestationBundle` with `faultedParty` per the §10.4.1 permissible-set rule; sign per §10.4.1; anchor per §10.4.2; publish a signed BundleBinding per anchored copy on a write-input substrate (BB-1/BB-2); include all required references per §10.4.3 |
| Bundle consumer | Resolve native addresses per BB-4..BB-8 (verify bindings and role authorization, prune to the co-signed party map where available, apply the authorized-candidate multiplicity rule, fail closed to `indeterminate`; one-sided classification only after a resolved binding plus policy-qualified authoritative absence); reject a copy whose `faultedParty` contradicts its (outcome, anchoredByRole) per §10.4.1; recompute canonical hash; verify domain-separated signatures; dereference and validate every contained AttestationRef |
| Reputation deriver | Apply algorithm in §10.5.1 verbatim; partition by primary claim; treat failed-substrate per the denominator rule; return null for zero-denominator scalar metrics; set `bundleRefs` to exactly the §10.5.1 `reconciled` set in canonical ascending-`contentHash` order, record the `windowingBasis` used, and emit a derivation reproducible byte-for-byte from `bundleRefs` per the §10.5.3 determinism receipt |
| Rate phase handler | One RatingRecord per direction; reject out-of-range `value` (non-integer or ∉[1,5]) / over-length `freeText` before anchoring (RT-1); anchor each; include in bundle |
| ERC-8004 publisher (optional) | §10.7.1 mapping; rate-limit writes; sign with token-owner key |

### 10.9 Rationale

**Session record off-chain by default.** Anchoring every state transition would dominate session economics for no audit benefit — the bundle captures what auditors need; intermediate state is operational noise. Off-chain SessionRecord + on-chain bundle is the right split.

**Bundle as the audit unit vs individual phase records.** Each phase already anchors its evidence; the bundle is the unifying envelope auditors start from and walk references out of. Without it, every consumer would reconstruct the session graph from disparate anchors.

**Domain-separated bundle signature.** The `dacs-bundle:v1:` / `dacs-fault-bundle:v1:` prefixes prevent confusing a bundle signature with any other DACS signature even when hash bytes collide — part of the §B.7 universal scheme.

**Per-primary-claim reputation vs wallet-keyed.** Wallet-keying would let a strong `key:0xabc…` reputation launder into a fresh `lei:…`. Per-primary-claim keying prevents it; a wallet honestly holding multiple claims accumulates separate reputations, surfaced cross-claim (via SR-1) without inheritance.

**Substrate-failure exclusion from party-fault denominators.** A session that fails because the substrate was down is nobody's fault; counting it would deter parties from transacting during substrate strain. Excluding `failed-substrate` keeps the metric honest.

**Null vs zero metrics.** A new party (bundleCount=0) has no signal, not a zero signal — zero would read as "completed 0%". Null forces consumers to handle "no data" deliberately rather than treating new parties as worst-rated.

**Optional rate phase.** Mandatory ratings create noise (friction-avoidance 5-stars) and retaliation exposure; optional, decline-able rating matches institutional and marketplace norms.

**ERC-8004 publication optional.** It's the dominant EVM reputation registry, but DACS-5 ships on substrates with no Ethereum-mainnet write path.

**Extended-pointer pattern for oversized bundles.** Some sessions exceed the storage-program cap (multi-party auctions, long attestation chains); the pattern keeps the canonical artifact at the on-chain address and ferries the rest off-chain with content-hash binding rather than hard-failing.

### 10.10 Backwards compatibility

**ERC-8004 registries.** §10.7 specifies the publication surface; DACS-5 *reads* the ERC-8004 registry format for EVM consumers and leaves ERC-8004 unchanged. **Reputation integrity is DACS's own responsibility, not inherited from ERC-8004** — the ERC-8004 Draft explicitly out-of-scopes Sybil resistance, so anti-Sybil rests on DACS-5's per-primary-claim keying (§10.5) and the collusion/farming mitigations in §10.11, not on the registry pointer.

**Operator-marketplace ratings.** A marketplace migrating to DACS-5 MAY backfill historical ratings as operator-signed RatingRecord-equivalents; new DACS-5 ratings stand alone and are clearly distinguishable from the operator-signed history.

**Audit-log standards.** A consumer MAY convert a DACS-5 bundle to RFC 5424 / OpenTelemetry at read time; DACS-5 defines only the bundle.

### 10.11 Security considerations

**HTLC asymmetric-loss metric blind spot (known residual).** On a window-expired ST-8 asymmetric loss, both legs map to `settle-failed`/`settlement-atomicity` → `failed-counterparty` (§10.3.1). DACS-5 v0.1 cannot distinguish, at the metric level, the **payer who already received destination value** from the **payee who is owed source value** — the payer's copy reads `failed-counterparty` (and, perspective-flipped, may even read as party-fault), so neither `completionRate` nor `counterpartyFaultRate` reflects who actually profited. This is a DACS-X dispute concern, not resolvable in v0.1's blame model; consumers SHOULD treat any `failed-counterparty` whose phaseSummary carries an HTLC-9 `settlement-atomicity` marker as requiring out-of-band review rather than as a clean counterparty fault.

**Bundle forgery.** *Threat:* an attacker produces a fake bundle claiming a session that did not happen, hoping to influence reputation. *Mitigation:* the bundle must be co-signed by both parties; signatures use domain-separated payloads; consumers verify both signatures against the parties’ verified primary claims. A unilateral bundle cannot influence the counterparty’s reputation.

**Bundle suppression.** *Threat:* a party who performed badly in a session refuses to sign the bundle, hoping to prevent its publication. *Mitigation:* the counterparty's bundle attempt records the non-signer's claimed outcome. Consumers MUST apply the `aborted-by-self`/`aborted-by-other` attribution only after the missing role's address is authoritatively absent under §10.4.3. The non-signer's reputation takes the appropriate hit when that gate is satisfied.

*Implementation note:* a one-sided bundle MUST follow the same canonical form and signing rules. The absent counterparty signature flags the claimed outcome, while the SR-2 absence evidence qualifies its use for reputation. The §10.4.1 missing-signature rejection applies only to non-abort outcomes, so a single-signed abort bundle reaches this classification rather than being rejected.

**Bundle-copy read censorship.** *Threat:* malicious read infrastructure withholds one anchored copy so two divergent bundles appear to be a clean one-copy session. *Mitigation:* §10.4.3 applies the CORE SR-2 absence-evidence policy before any one-sided classification, and §10.5.1 guard (iv) excludes an unqualified one-copy jobId from every reputation metric. A binding without authoritative absence support therefore loses one-copy reputation availability but does not fail open into party blame.

**Sybil reputation farming.** *Threat:* an attacker creates many cheap primary claims (key:…) and farms self-deal reputation between them. *Mitigation:* DACS-5 metrics are partitioned by primary claim and do not inherit; Sybil farming over key:… claims accumulates reputation only against those claims, not against higher-tier presentations. The DACS-2 supplementary signals (counterparty being a known Sybil cluster) feed back into Vet for any party who cares.

**Replay across sessions.** *Threat:* an attacker captures a signed bundle and replays it as a different session’s bundle. *Mitigation:* the bundle includes jobId; the signature payload includes the bundle hash which includes jobId. Replay against a different jobId fails verification.

**Cross-protocol signature confusion.** *Threat:* a bundle signature is replayed as some other DACS signature (listing, agreement) where the underlying hash bytes happen to align. *Mitigation:* the universal signature scheme in §B.7 defines per-artifact domain separators across the entire DACS v0.1 stack; the bundle domain separators are "dacs-bundle:v1:" and "dacs-fault-bundle:v1:", and other artifact kinds use their own separators per the table in §B.7. A signature produced under any artifact kind cannot validate as a signature under any other kind, even when the hash bytes coincide.

**Reputation poisoning via collusion.** *Threat:* two colluding parties run many fake sessions to inflate each other’s reputation. *Mitigation:* this is fundamentally hard to prevent at the protocol level. DACS-5 mitigates by per-primary-claim keying (collusion inflates only one tier of reputation), by transactional-volume reporting (consumers can see if a party’s reputation comes from many tiny sessions vs few large ones), and by composability with external signal sources. The volume signal is **weak and must not be over-trusted**: `observedTransactionalVolume` is reported per-currency, unnormalised, with no FX conversion (§10.5), so a colluding pair transacting across many low-significance currencies can keep every `PriceTerm` row small and evade the "few large vs many tiny" heuristic; cross-currency rows are not comparable or summable. The v0.2 `transactionCountByCurrency` metric (§10.5.1) supplies the per-currency transaction count strengthening that heuristic; an FX-normalised aggregate remains roadmap. Consumers SHOULD read volume alongside `bundleCount` and external signals rather than as a standalone collusion gate. Consumers handling stakes worth the cost of collusion SHOULD weigh DACS-5 metrics against external signals.

**Orchestrator misclassification of errorClass.** *Threat:* the orchestrator classifies a counterparty failure as a substrate failure (or vice versa) to bias reputation. *Mitigation:* the bundle phaseSummary carries the errorClass; both parties sign the bundle; a party that disagrees with the classification refuses to co-sign, terminating the session as aborted-by-other. A single-signed abort bundle is valid (§10.4.1), but a single-signed `failed-*` bundle is not — so refusal denies the misclassified bundle its second signature rather than letting the honest party publish a competing unilateral fault classification. Adjudicating which classification was correct is a DACS-X concern.

**Bundle anchor unavailability.** *Threat:* the SR-2 anchor becomes unreadable after the session ends (e.g. storage program purged, IPFS unpinned). *Mitigation:* on-substrate anchoring (Demos Storage Programs) provides indefinite availability under substrate operation. Off-substrate anchoring (IPFS, HTTPS) is best-effort. Listings concerned with long-term auditability SHOULD use on-substrate anchoring for bundles regardless of which surface the rest of the session uses.

**Time-bound reputation windows.** *Threat:* an old, no-longer-representative reputation is presented as current; or a producer backdates or forward-dates the self-asserted `finalisedAt` to move a session out of a scrutinised window or to cluster volume into a favourable one. *Mitigation:* derivations are window-bounded; consumers querying reputation MUST specify a window and SHOULD weight recent windows more heavily. The algorithm does not specify weighting (consumers choose); it does require explicit window bounds in every derivation. Against producer-chosen `finalisedAt`, consumers performing high-stakes derivation SHOULD window against the SR-2 anchor timestamp per §10.5.1, so that the substrate — not the bundle producer — decides window membership.

**ERC-8004 write spamming.** *Threat:* an attacker writes many fake ERC-8004 entries pointing at fabricated bundles. *Mitigation:* ERC-8004 entries are pointers; consumers MUST fetch and validate the bundle. Fake bundles fail at validation. The cost of writing many ERC-8004 entries (gas) is a natural rate limit; DACS-5 publishers SHOULD additionally enforce per-session rate limits.
