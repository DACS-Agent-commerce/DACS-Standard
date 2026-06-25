# DACS-5: Verify — Verify

*Normative module of DACS v0.1. Read the [Primer](../PRIMER.md) first; shared types, signatures, canonical form, the session model, and substrate requirements live in [CORE](CORE.md). Section numbers are retained from the unified specification; per the §→document map in [CORE](CORE.md), cross-references of the form §6–§10 point to sibling module documents, and §A / §12–§14 to the companion references (Demos mapping, threat model, glossary, conformance plan). The [conformance vectors](../conformance/) exercise this module's rules.*

## Chapter 10 — DACS-5: Verify

**Stage:** Verify (5th of 5). **Status:** Draft — **DACS-5 v0.2** (on the common DACS v0.1 baseline; adds the blame-weighted `counterpartyAdjustedCompletionRate` + `transactionCountByCurrency` reputation metrics §10.5.1, the ST-9 session-deadline timeout terminal §10.3.1, and the ST-10 policy-permitted pre-commit cancellation §10.3.1). **Depends on:** SR-1 (preferred for cross-substrate primary-claim keying), SR-2 (required for bundle anchoring); composes with ERC-8004 reputation registry as an OPTIONAL publication surface. **Used by:** all subsequent DACS-1 sessions (reputation lookups), external auditors and regulators.

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
| `commit-pending` | `commit-completed` \| `commit-failed` \| `substrate-failure-paused` \| `aborted-by-self` \| `aborted-by-other` | commit-agreement result |
| `commit-completed` | `settle-pending` | next phase scheduled |
| `settle-pending` | `settle-completed` \| `settle-asymmetric` \| `settle-failed` \| `substrate-failure-paused` \| `aborted-by-self` \| `aborted-by-other` | Settle phase result |
| `settle-asymmetric` | `settle-completed` \| `settle-failed` \| `substrate-failure-paused` | ST-8 (cross-chain asymmetric open state; substrate pause per ST-7) |
| `settle-completed` | `rate-pending` (pipeline has a rate phase) \| `finalised` (no rate phase) | ST-4 |
| `rate-pending` | `rate-completed` \| `finalised` | ST-5 |
| `rate-completed` | `finalised` | rate phase done |
| `substrate-failure-paused` | the paused-from state it paused from (a `*-pending` state, or `settle-asymmetric`) \| `failed-substrate` | ST-7 |

**Rules:**

- (ST-1) **Forward-only.** Except for ST-7 resume, a transition MUST move toward a terminal state per the table. The orchestrator MUST NOT re-enter an earlier `*-pending` state (e.g. negotiate after commit).
- (ST-2) **Phase failure.** A phase returning `ok: false` MUST transition to that phase’s `*-failed` state, classified by the phase’s `errorClass`. A commit-agreement rejection (a CA-3 re-commitment for an already-anchored jobId, or an agreement failing the §8.5.2 listing-conformance checks) is a `commit-pending → commit-failed` transition (forward-only; it MUST NOT be folded back into `negotiate-failed`).
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
  - **Symmetry.** A policy-permitted cancellation is neutral for both parties — there is no `-by-self`/`-by-other` blame to split. The counterparty's copy, if any, records `aborted-by-other` per ST-3, and the same teeth check applied to it yields the same neutral result; mutual notice is what earns the mutual neutrality.
  - **Precedence.** A cancellation is a deliberate party action and ranks **with** abort (ST-3), above the ST-9 timeout: a party electing to cancel within an open deadline does so as a party decision, not a timeout. `with-fee` cancellation — a cancellation owing a fee after `commit-completed` — is **not defined** here; only the `pre-commit` case is honoured, and a `with-fee` value confers no neutrality.

**State → bundle `outcome` mapping (normative).** Every terminal state maps to exactly one AttestationBundle `outcome` (§10.4), partitioned by the terminal phase’s `errorClass` where applicable:

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

```
type AttestationBundle = {

  bundleVersion: "1"

  jobId: string

  outcome: "completed" | "failed-perm" | "failed-counterparty" | "failed-substrate" | "aborted-by-self" | "aborted-by-other"

  anchoredByRole: "buyer" | "seller" | "orchestrator"   // the role of the party that anchored THIS copy; `outcome` is recorded from this party's perspective (matches the §10.4.2 role-derived anchor address)

  listingRef: { listingId: string; version: number; contentHash: string }

  agreementRef?: AttestationRef               // present iff the session reached commit-completed or later; omitted only when terminated before commit-agreement (see §10.4.3)

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

  attestationRef?: AttestationRef

}

type BundleSignature = {

  party: ClaimReference                       // primary claim of the signer

  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"

  value: string                               // ed25519/ecdsa over the domain-separated payload "dacs-bundle:v1:" || attestation_bundle_hash, NOT the raw bundle hash (§10.4.1)

}
```

#### 10.4.1 Canonical serialisation, hash, and domain-separated signature

Per the §B.2 canonical-form template, omitting the `signatures` **and `anchoredByRole`** fields. The **attestation-bundle hash** (`attestation_bundle_hash`) is the content hash of that canonical form — sha256(canonical_form), hex-encoded — a computed value, not a stored field (distinct from `BundleParty.bundleHash`, which hashes a party's IdentityBundle). Each BundleSignature.value MUST be computed over a domain-separated payload:

signed_bytes := "dacs-bundle:v1:" || attestation_bundle_hash

> **Note (non-normative).** `anchoredByRole` is per-copy — buyer vs seller vs orchestrator — and is carried only for derive()'s perspective read (§10.5.1); it is excluded from the hashed canonical form exactly like `signatures` so the two-sided copies remain canonically equal in the happy path. This is a recognised, specified omission, not a SIG-5 silent strip.

The "dacs-bundle:v1:" string prefix prevents cross-protocol signature confusion: an attacker capturing a bundle signature MUST NOT be able to replay it as a listing signature, agreement signature, or any other DACS signature even if the hash bytes collide.

Verification and signer rules:

- Verifiers MUST recompute the canonical form, the bundle hash, and the prefixed signed_bytes, and verify each signature against the appropriate party’s primary-claim key.
- Required signers: buyer + seller. If the orchestrator is a distinct party (not buyer or seller), the orchestrator signature is also REQUIRED.
- Bundles whose outcome is `completed`, `failed-perm`, `failed-counterparty`, or `failed-substrate` and that are missing any required signature MUST be rejected by consumers.
- A bundle whose outcome is `aborted-by-self` or `aborted-by-other` MAY carry a single signature; consumers MUST NOT reject it on that basis but MUST classify it per the bundle-suppression rule in §10.11.

#### 10.4.2 Anchoring

The bundle MUST be anchored via SR-2. **Two-sided anchoring scheme:**

- Each signing party (buyer, seller, and orchestrator if distinct) anchors its own bundle at a party-specific address: stor-{sha256(jobId + "-bundle-" + role)} where role is "buyer", "seller", or "orchestrator".
- **Each anchored copy MUST set `anchoredByRole` to the role of the anchoring party, and that value MUST equal the `role` segment of the address it is anchored at.**
- **A consumer MUST reject a copy whose `anchoredByRole` does not match the address it was fetched from.** Since `anchoredByRole` is excluded from the hash per §10.4.1, this address cross-check — not the signature — is what protects it from being forged.

In the happy case both sides’ bundles are canonically equal (they differ only in the unhashed `anchoredByRole`) and consumers can read either; in the divergence case both sides are independently retrievable for dispute purposes (see §10.4.3).

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

#### 10.4.3 Bundle production rules

A bundle MUST be produced when the session reaches a terminal state. The bundle MUST include references to:

- all DACS-2 composite verification records;
- the DACS-3 agreement (if any);
- DACS-4 settlement evidence — one entry per executed phase invocation, **except** an ST-8-resolved cross-chain settle phase, which contributes exactly its `:resolved` success record. The interim `dest-revealed-source-unclaimed` failure record is NOT listed independently in `settlementEvidence[]` and is reachable only via that record's `supersedesEvidenceRef`. Both parties' `settlementEvidence[]` arrays MUST therefore contain identical entries — the resolved record, not the interim — so the two-sided copies stay canonically equal (§10.4.1);
- DACS-4 amendments (refunds);
- DACS-5 ratings (if the rate phase ran).

The bundle MUST NOT include references to any record outside the session’s scope.

**For sessions terminating before commit-agreement** (aborted-by-self/other in Vet or Negotiate), the bundle MUST include the available vetRecords and a phaseSummary marking the failed phase; agreementRef is omitted.

**For sessions terminating with failed-substrate**, the bundle’s outcome captures the substrate failure; the failure does not count as either party’s fault in DACS-5 reputation derivation.

Two parties producing independent bundles for the same session MUST converge on identical bundle content (by canonical-form equality — which excludes the per-copy `anchoredByRole` and `signatures` fields per §10.4.1, so the happy-path copies are equal despite carrying different `anchoredByRole` values) or MUST surface the divergence as a dispute. Each side anchors its own bundle at its own derived address; a consumer looking up "the bundle(s) for session X" MUST query both sides’ expected addresses: `stor-{sha256(jobId + "-bundle-buyer")}` and `stor-{sha256(jobId + "-bundle-seller")}` (or substrate-equivalent two-sided addressing).

**Definition — "canonically diverge" (normative, defined once).** The two copies' canonical forms differ in `outcome`, or in a `phaseSummary` entry's `outcome`/`errorClass` — i.e. a *contradiction* about what happened. A difference confined to advisory fields (e.g. `finalisedAt` skew, one-sided `ratingRefs`, amendment ordering) is NOT a divergence. (This is the same definition the §10.5.1 deriver applies — guard (ii) — so a consumer and a deriver never reach opposite verdicts, and a party cannot force a spurious "disputed" classification by perturbing an advisory field.)

Consumers MUST:

- (a) fetch both addresses;
- (b) if exactly one bundle is present, classify by the present copy's signature set:
  - a copy carrying all §10.4.1 required signatures is the unified session bundle; the missing copy is an anchoring omission, not an abort, and no abort outcome is attributed to either party;
  - a single-signed copy with an abort outcome is classified per the §10.11 bundle-suppression rule: `aborted-by-self` for the non-signer, `aborted-by-other` for the signer;
  - a single-signed copy with any other outcome is rejected per §10.4.1, leaving no valid bundle for the session;
- (c) if both are present and do NOT diverge (canonically equal, or differing only in advisory fields), treat as the unified session bundle — a reputation-deriving consumer prefers the scored party's own anchored copy where they differ advisorily (matching §10.5.1's reconciliation), while a consumer with no scoring context (e.g. an auditor) MAY treat either copy as canonical for non-reputation purposes, since by definition they agree on every contradiction-bearing field;
- (d) if both are present and canonically diverge (a contradiction per the definition above), treat the session as disputed — each bundle stands on its own signatures and consumers must decide policy (e.g., trust the buyer’s bundle for buyer-reputation, the seller’s for seller-reputation; or flag for human review).

v0.1 does not specify a dispute resolution path; divergence is handled out-of-band. A future minor version (DACS-X, dispute) may specify selective transcript disclosure under signed party agreement or arbitrator order.

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

#### 10.5.1 Derivation algorithm

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
  for jobId, copies in (scoped grouped by b.jobId):
    # (1) §10.4.1 signature validation: a non-abort outcome (completed / failed-perm /
    #     failed-counterparty / failed-substrate) MUST carry all required signatures;
    #     only aborts MAY be single-signed. Drop copies that fail this.
    # (2) §10.4.2 integrity: drop any copy whose anchoredByRole != its anchor-address role.
    copies := [b for b in copies where valid_signatures_per_§10.4.1(b) AND anchoredByRole_matches_address(b)]
    copies := [b for b in copies where b.anchoredByRole in {"buyer", "seller"}]   // orchestrator copies are evidence-only
    if copies is empty: continue
    role_of_party := the role of the BundleParty p in copies[0].parties where p.primaryClaim == party
    self_copy := the b in copies where b.anchoredByRole == role_of_party        // scored party's own copy, if present
    cp        := the b in copies where b.anchoredByRole != role_of_party        // at most one (the buyer/seller counterparty copy)
    # (ST-10) indeterminate cancellation: if the authoritative copy (self_copy if present, else cp)
    # carries a `cancellation` marker the consumer CANNOT resolve to a verified signed-listing policy
    # (listing pruned / signature transiently unverifiable / substrate unreachable), the cancellation
    # claim is neither established nor refuted — EXCLUDE this jobId from ALL metrics (never neutral,
    # never a fresh fault), exactly like the §10.4.3(d) dispute `continue` below.
    cancel_copy := self_copy if self_copy exists else cp
    if cancel_copy.cancellation exists AND the §10.3.1 ST-10 teeth check cannot be resolved: continue
    if self_copy exists:
      if cp exists AND cp canonically diverges from self_copy (contradictory outcome / phaseSummary):
        continue   // (§10.4.3(d)) genuine dispute — EXCLUDE this jobId from ALL metrics (numerator and denominator), do not silently trust self_copy
      reconciled.append(self_copy); outcomes.append(self_copy.outcome)          // read literally — recorded from party's own perspective
    else:
      reconciled.append(cp);        outcomes.append(perspective_flip(cp.outcome))   // only a counterparty copy exists (e.g. §10.11 suppression); re-interpret relative to the scored party
  # perspective_flip (buyer<->seller counterparty perspective -> scored-party perspective):
  #   completed -> completed ; failed-substrate -> failed-substrate
  #   aborted-by-self <-> aborted-by-other
  #   failed-perm <-> failed-counterparty   (anchorer's own perm-failure = counterparty failed, from party's view; and vice-versa)
  # Only buyer/seller copies reach perspective_flip; the §10.4.1 filter guarantees a
  # non-abort outcome here is fully-signed and thus legitimately attributable.
  # All downstream metrics use `reconciled` (deduped bundles) / `outcomes`, never raw `scoped`.

  completed := [o for o in outcomes where o == "completed"]

  failed_perm := [o for o in outcomes where o == "failed-perm"]   // party-fault: stays in party_fault_denom but not in |completed|, so it depresses completionRate; v0.1 surfaces no separate party-fault rate metric

  failed_counterparty := [o for o in outcomes where o == "failed-counterparty"]

  failed_substrate := [o for o in outcomes where o == "failed-substrate"]

  aborted_by_self := [o for o in outcomes where o == "aborted-by-self"]   // party-initiated abort (§10.11): like failed_perm, depresses completionRate via the denominator; no separate metric in v0.1

  cancelled_neutral := [o in aborted_by_self where o's reconciled bundle carries a `cancellation` marker the consumer RESOLVED to a verified policy-permitted pre-commit cancellation (§10.3.1 ST-10)]   // reputation-neutral: an advertised, signed cancellation right — dropped from the fault denominator like failed_substrate, NOT a fault. A marker that resolves-and-forbids is NOT collected here and stays an ordinary aborted-by-self fault; a marker that could not be resolved was already dropped from `outcomes` (loop above). The cancelled count stays observable for any consumer that wants a soft reliability signal — we attribute, we do not hide.

  aborted_by_other := [o for o in outcomes where o == "aborted-by-other"]

  counterparty_fault_count := |aborted_by_other| + |failed_counterparty|

  party_fault_denom := |outcomes| − |failed_substrate| − |cancelled_neutral|   // a verified policy-permitted cancellation (§10.3.1 ST-10) is neutral — dropped from the denominator exactly like failed_substrate, so it neither counts as completion nor as fault

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

    agreement := fetch_and_verify_agreement(b.agreementRef)   // DACS-3 AgreementDocument

    volume_terms.append(agreement.terms.price)

  volume := groupSumByCurrency(volume_terms)
  txCountByCurrency := countByCurrency(volume_terms)   // per-currency count over the same completed set as volume

  bundleCount := |reconciled|   // one per distinct jobId after two-sided reconciliation, not |scoped|
  // Note: `reconciled` MAY be empty even when `scoped` is not (every jobId's copies were dropped by guard (i)
  // or excluded as divergent by guard (ii)); the denominator gates below then yield the same all-null /
  // bundleCount=0 result as the `scoped`-empty early return — there is no separate code path.

  bundleRefs := sort([ref(b) for b in reconciled], ascending by contentHash)   // deduped authoritative copies (matches bundleCount); canonical ascending-contentHash order per the §10.5.3 determinism receipt; empty when reconciled is empty
  windowingBasis := <"finalisedAt" | "sr2-anchor-timestamp">   // record which clock the window predicate was applied against (§10.5.1); re-derivation MUST use the same basis

  return ReputationDerivation with computed metrics
```

**Two-sided reconciliation (normative).** Two-sided anchoring (§10.4.2) can place two bundles for one jobId in the input, each recording `outcome` from *its anchorer's* perspective. The deriver MUST collapse the input to one authoritative bundle per jobId before partitioning (the `reconciled` step above). It MUST interpret `outcome` relative to the *scored* party, not the anchorer. The read rules:

- When the scored party's own anchored copy is present (`b.anchoredByRole` == the scored party's role), `outcome` is read literally: `aborted-by-self` means "this party aborted"; `aborted-by-other` means "the counterparty aborted against this party".
- When only a counterparty-anchored copy exists (e.g. the §10.11 bundle-suppression case, where the withdrawing party did not anchor), `outcome` is read through `perspective_flip`: `aborted-by-self ↔ aborted-by-other` and `failed-perm ↔ failed-counterparty`. The aborter still takes the hit and the victim does not.

> **Note (non-normative).** Reading raw `outcome` across both copies (the pre-reconciliation behaviour) would double-count an abort against the victim and invert the §10.11 guarantee; the reconciliation closes that.

Three normative guards apply during reconciliation:

- (i) **signature validation first** — each copy MUST pass §10.4.1 before it is considered. A single-signed bundle is valid only for an abort outcome; a single-signed `completed`/`failed-*` MUST be dropped. This closes the attack where a lone counterparty-anchored `failed-counterparty` is perspective-flipped to depress the victim's score. Any copy whose `anchoredByRole` does not match its anchor-address role (§10.4.2) MUST be dropped;
- (ii) **divergence → exclusion** — the scored party's own copy and a counterparty copy *canonically diverge* when they contradict in `outcome` or in a `phaseSummary` entry's `outcome`/`errorClass` (the single §10.4.3 definition) — NOT on mere advisory-field skew. A divergent jobId is a §10.4.3(d) dispute and MUST be excluded from ALL metrics, rather than silently trusting the self-copy. Exclusion removes the jobId from both the numerator and `party_fault_denom`, so a disputed session neither helps nor harms the score. There is no `disputed` value in the `outcome` enum (§10.4.1); this is an exclusion, not an outcome;
- (iii) **buyer/seller only** — `perspective_flip` is a buyer↔seller involution. Orchestrator-anchored copies are evidence-only and are not used as a reputation perspective (orchestrator reputation is out of scope for v0.1). This also makes the counterparty-copy selection unambiguous: at most one buyer/seller counterparty copy per jobId.

**Fault attribution.** "party_at_fault" is otherwise recorded in the bundle’s phaseSummary errorClass. `counterparty` implies the other party. `permanent` on a non-cross-chain rail, with no settlement-atomicity flag and a successful pre-pay state, generally implies the local party at fault — absent the §7.8.2 counterparty-malformed-presentation carve-out, which maps a counterparty-malformed `error` to `counterparty`, not `permanent`. The classification rules are spelled out in the per-phase errorClass tables in chapters 7 and 9.

**failed-substrate denominator.** failed-substrate sessions are excluded from the party-fault denominator: party_fault_denom = |outcomes| − |failed_substrate|. This ensures substrate-induced failures do not damage either party’s reputation.

**Null vs empty metrics.** The **scalar** metrics (completionRate, counterpartyAdjustedCompletionRate, counterpartyFaultRate, averageBuyerRating, averageSellerRating) produce numeric values when their denominator > 0. With denominator == 0 (e.g., bundleCount=0, or all sessions failed-substrate; for `counterpartyAdjustedCompletionRate`, also when every reconciled bundle was counterparty-caused) they produce null — distinct from zero, signalling "no signal" rather than "zero signal". The **array** metrics `observedTransactionalVolume` and `transactionCountByCurrency` (non-nullable) and `bundleRefs` (a non-nullable `AttestationRef[]`) produce `[]` on the empty path: an empty list, never null. Every return path therefore yields a schema-total `ReputationDerivation`.

**Rating metrics.** The averageBuyerRating / averageSellerRating metrics are computed by walking each reconciled bundle’s ratingRefs, fetching the referenced RatingRecord, and verifying its signature against the rater’s primary-claim key (the same key class as a BundleSignature, per §10.4.1). A RatingRecord MUST be discarded — not aggregated — unless it binds to the session being scored:

- the deriver MUST require r.jobId == b.jobId;
- r.rater MUST be one of the bundle’s parties[].primaryClaim;
- r.rater MUST NOT equal the scored party (no self-rating).

Only the remaining records’ values, whose target matches the scored party, are aggregated; the metric is null when no qualifying ratings exist.

**Volume metric.** The observedTransactionalVolume metric is computed analogously. For each reconciled bundle whose `outcome` is `completed` and whose agreementRef is present, the deriver MUST resolve the AttestationRef to its AgreementDocument via fetch_and_verify_agreement(agreementRef), then sum agreement.terms.price grouped by currency. Non-completed bundles (failed, aborted) contribute no volume: the metric reports value transacted, not value agreed. Resolution follows the §7.5.2 attestation resolution algorithm:

- fetch the anchor at agreementRef.anchor.locator;
- compare the hashed bytes to agreementRef.contentHash — a mismatch MUST cause that bundle to be excluded;
- parse the result as a DACS-3 AgreementDocument.

agreementRef is an AttestationRef, not an inline AgreementDocument, so the volume step MUST dereference it before reading terms.price.

**Rating de-duplication (normative).** Under two-sided anchoring (§10.4.2) both parties' bundles for one jobId may appear in the input before reconciliation, and `ratingRefs` is an array — so a naive walk would count the same rating more than once. The deriver MUST aggregate at most one rating per `(r.rater, r.jobId, r.targetRole)` tuple, last-writer-wins by `ratedAt` on a tie. A rating therefore contributes once per session-direction, not once per anchored bundle copy or per duplicate ref. (This is a counting rule; RT-1/RT-2 already bound each rating's value range.)

**`completionRate` denominator scope.** `party_fault_denom` excludes only `failed-substrate`; it retains counterparty-fault and abort sessions. This is intentional: `completionRate` measures completed-vs-attempted, not blame. It leaves a residual griefing surface, however — a counterparty that repeatedly opens and aborts sessions depresses the target's `completionRate` through `aborted-by-other`. `counterpartyFaultRate` partially offsets this (it rises in step over the same denominator), and consumers SHOULD read the two metrics together rather than `completionRate` alone. A blame-weighted completion metric is a roadmap candidate.

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
- (3) a consumer that re-runs `derive(partyPrimaryClaim, deref(bundleRefs), windowStart, windowEnd)` under the recorded `windowingBasis` MUST obtain byte-identical `metrics` and `bundleCount`.

Because §10.5.1 lets high-stakes consumers window against the SR-2 anchor timestamp rather than the producer-set `finalisedAt`, two derivers using different windowing bases legitimately compute different sets. The receipt is therefore defined **relative to the declared `windowingBasis`**, which a conforming derivation MUST record. This makes any published derivation auditable against its declared inputs. It does NOT establish *completeness*: whether `bundleRefs` contains every relevant bundle is out of scope — no authoritative "which bundles exist" oracle is defined, and catalogs are best-effort per (b). Conformance: given a fixed `bundleRefs` set, window, and `windowingBasis`, `derive()` output is byte-identical across implementations.

#### 10.5.4 Category-scoped derivation

The §10.5.1 derivation algorithm is unscoped: it aggregates all bundles for a party within a time window regardless of the service category involved. This is useful for overall reputation but obscures domain-specific track records — a party with excellent DeFi data delivery and a poor regulatory-data track record looks identical to one that is mediocre across the board.

**Category-scoped derivation** restricts the bundle set to sessions whose service category — the `offering.category` of the **listing** the agreement was formed against (the `AgreementDocument` itself carries only `listingRef`, not the category) — matches a given category prefix before applying the §10.5.1 algorithm:

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

- (1) resolve the bundle's `agreementRef` to its `AgreementDocument`, per the §7.5.2 attestation resolution algorithm;
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
| Bundle producer | Sign per §10.4.1; anchor per §10.4.2; include all required references per §10.4.3 |
| Bundle consumer | Recompute canonical hash; verify domain-separated signatures; dereference and validate every contained AttestationRef |
| Reputation deriver | Apply algorithm in §10.5.1 verbatim; partition by primary claim; treat failed-substrate per the denominator rule; return null for zero-denominator scalar metrics; set `bundleRefs` to exactly the §10.5.1 `reconciled` set in canonical ascending-`contentHash` order, record the `windowingBasis` used, and emit a derivation reproducible byte-for-byte from `bundleRefs` per the §10.5.3 determinism receipt |
| Rate phase handler | One RatingRecord per direction; reject out-of-range `value` (non-integer or ∉[1,5]) / over-length `freeText` before anchoring (RT-1); anchor each; include in bundle |
| ERC-8004 publisher (optional) | §10.7.1 mapping; rate-limit writes; sign with token-owner key |

### 10.9 Rationale

**Session record off-chain by default.** Anchoring every state transition would dominate session economics for no audit benefit — the bundle captures what auditors need; intermediate state is operational noise. Off-chain SessionRecord + on-chain bundle is the right split.

**Bundle as the audit unit vs individual phase records.** Each phase already anchors its evidence; the bundle is the unifying envelope auditors start from and walk references out of. Without it, every consumer would reconstruct the session graph from disparate anchors.

**Domain-separated bundle signature.** The `dacs-bundle:v1:` prefix prevents confusing a bundle signature with any other DACS signature even when hash bytes collide — part of the §B.7 universal scheme.

**Per-primary-claim reputation vs wallet-keyed.** Wallet-keying would let a strong `key:0xabc…` reputation launder into a fresh `lei:…`. Per-primary-claim keying prevents it; a wallet honestly holding multiple claims accumulates separate reputations, surfaced cross-claim (via SR-1) without inheritance.

**Substrate-failure exclusion from party-fault denominators.** A session that fails because the substrate was down is nobody's fault; counting it would deter parties from transacting during substrate strain. Excluding `failed-substrate` keeps the metric honest.

**Null vs zero metrics.** A new party (bundleCount=0) has no signal, not a zero signal — zero would read as "completed 0%". Null forces consumers to handle "no data" deliberately rather than treating new parties as worst-rated.

**Optional rate phase.** Mandatory ratings create noise (friction-avoidance 5-stars) and retaliation exposure; optional, decline-able rating matches institutional and marketplace norms.

**ERC-8004 publication optional.** It's the dominant EVM reputation registry, but DACS-5 ships on substrates with no Ethereum-mainnet write path.

**Extended-pointer pattern for oversized bundles.** Some sessions exceed the storage-program cap (multi-party auctions, long attestation chains); the pattern keeps the canonical artifact at the on-chain address and ferries the rest off-chain with content-hash binding rather than hard-failing.

### 10.10 Backwards compatibility

**ERC-8004 registries.** §10.7 specifies the publication surface; DACS-5 inherits ERC-8004's read semantics for EVM consumers and leaves ERC-8004 unchanged.

**Operator-marketplace ratings.** A marketplace migrating to DACS-5 MAY backfill historical ratings as operator-signed RatingRecord-equivalents; new DACS-5 ratings stand alone and are clearly distinguishable from the operator-signed history.

**Audit-log standards.** A consumer MAY convert a DACS-5 bundle to RFC 5424 / OpenTelemetry at read time; DACS-5 defines only the bundle.

### 10.11 Security considerations

**HTLC asymmetric-loss metric blind spot (known residual).** On a window-expired ST-8 asymmetric loss, both legs map to `settle-failed`/`settlement-atomicity` → `failed-counterparty` (§10.3.1). DACS-5 v0.1 cannot distinguish, at the metric level, the **payer who already received destination value** from the **payee who is owed source value** — the payer's copy reads `failed-counterparty` (and, perspective-flipped, may even read as party-fault), so neither `completionRate` nor `counterpartyFaultRate` reflects who actually profited. This is a DACS-X dispute concern, not resolvable in v0.1's blame model; consumers SHOULD treat any `failed-counterparty` whose phaseSummary carries an HTLC-9 `settlement-atomicity` marker as requiring out-of-band review rather than as a clean counterparty fault.

**Bundle forgery.** *Threat:* an attacker produces a fake bundle claiming a session that did not happen, hoping to influence reputation. *Mitigation:* the bundle must be co-signed by both parties; signatures use domain-separated payloads; consumers verify both signatures against the parties’ verified primary claims. A unilateral bundle cannot influence the counterparty’s reputation.

**Bundle suppression.** *Threat:* a party who performed badly in a session refuses to sign the bundle, hoping to prevent its publication. *Mitigation:* the non-signing party’s outcome (aborted-by-self) is recorded in the counterparty’s bundle attempt; consumers seeing a bundle with only one signature MUST classify the session as aborted-by-self for the non-signer and aborted-by-other for the signer. The non-signer’s reputation takes the appropriate hit even if they refuse to sign. (Implementation note: a one-sided bundle MUST follow exactly the same canonical form and signing rules; the absence of the counterparty’s signature is what flags the outcome. This is the carve-out referenced by §10.4.1 — the reject-missing-required-signature rule applies only to the non-abort outcomes, so a one-signature `aborted-by-self`/`aborted-by-other` bundle reaches this classification rather than being rejected.)

**Sybil reputation farming.** *Threat:* an attacker creates many cheap primary claims (key:…) and farms self-deal reputation between them. *Mitigation:* DACS-5 metrics are partitioned by primary claim and do not inherit; Sybil farming over key:… claims accumulates reputation only against those claims, not against higher-tier presentations. The DACS-2 supplementary signals (counterparty being a known Sybil cluster) feed back into Vet for any party who cares.

**Replay across sessions.** *Threat:* an attacker captures a signed bundle and replays it as a different session’s bundle. *Mitigation:* the bundle includes jobId; the signature payload includes the bundle hash which includes jobId. Replay against a different jobId fails verification.

**Cross-protocol signature confusion.** *Threat:* a bundle signature is replayed as some other DACS signature (listing, agreement) where the underlying hash bytes happen to align. *Mitigation:* the universal signature scheme in §B.7 defines per-artifact domain separators across the entire DACS v0.1 stack; the bundle domain separator is "dacs-bundle:v1:" and other artifact kinds use their own separators per the table in §B.7. A signature produced under any artifact kind cannot validate as a signature under any other kind, even when the hash bytes coincide.

**Reputation poisoning via collusion.** *Threat:* two colluding parties run many fake sessions to inflate each other’s reputation. *Mitigation:* this is fundamentally hard to prevent at the protocol level. DACS-5 mitigates by per-primary-claim keying (collusion inflates only one tier of reputation), by transactional-volume reporting (consumers can see if a party’s reputation comes from many tiny sessions vs few large ones), and by composability with external signal sources. The volume signal is **weak and must not be over-trusted**: `observedTransactionalVolume` is reported per-currency, unnormalised, with no FX conversion and no per-row transaction count (§10.5), so a colluding pair transacting across many low-significance currencies can keep every `PriceTerm` row small and evade the "few large vs many tiny" heuristic; cross-currency rows are not comparable or summable. Consumers SHOULD read volume alongside `bundleCount` and external signals rather than as a standalone collusion gate. (A per-row transaction count and an FX-normalised aggregate would strengthen it — roadmap.) Consumers handling stakes worth the cost of collusion SHOULD weigh DACS-5 metrics against external signals.

**Orchestrator misclassification of errorClass.** *Threat:* the orchestrator classifies a counterparty failure as a substrate failure (or vice versa) to bias reputation. *Mitigation:* the bundle phaseSummary carries the errorClass; both parties sign the bundle; a party that disagrees with the classification refuses to co-sign, terminating the session as aborted-by-other. A single-signed abort bundle is valid (§10.4.1), but a single-signed `failed-*` bundle is not — so refusal denies the misclassified bundle its second signature rather than letting the honest party publish a competing unilateral fault classification. Adjudicating which classification was correct is a DACS-X concern.

**Bundle anchor unavailability.** *Threat:* the SR-2 anchor becomes unreadable after the session ends (e.g. storage program purged, IPFS unpinned). *Mitigation:* on-substrate anchoring (Demos Storage Programs) provides indefinite availability under substrate operation. Off-substrate anchoring (IPFS, HTTPS) is best-effort. Listings concerned with long-term auditability SHOULD use on-substrate anchoring for bundles regardless of which surface the rest of the session uses.

**Time-bound reputation windows.** *Threat:* an old, no-longer-representative reputation is presented as current; or a producer backdates or forward-dates the self-asserted `finalisedAt` to move a session out of a scrutinised window or to cluster volume into a favourable one. *Mitigation:* derivations are window-bounded; consumers querying reputation MUST specify a window and SHOULD weight recent windows more heavily. The algorithm does not specify weighting (consumers choose); it does require explicit window bounds in every derivation. Against producer-chosen `finalisedAt`, consumers performing high-stakes derivation SHOULD window against the SR-2 anchor timestamp per §10.5.1, so that the substrate — not the bundle producer — decides window membership.

**ERC-8004 write spamming.** *Threat:* an attacker writes many fake ERC-8004 entries pointing at fabricated bundles. *Mitigation:* ERC-8004 entries are pointers; consumers MUST fetch and validate the bundle. Fake bundles fail at validation. The cost of writing many ERC-8004 entries (gas) is a natural rate limit; DACS-5 publishers SHOULD additionally enforce per-session rate limits.
