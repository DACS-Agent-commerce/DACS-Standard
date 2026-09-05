# DACS-3: Negotiate — Negotiate

*Normative module of DACS v0.1. Read the [Primer](../PRIMER.md) first; shared types, signatures, canonical form, the session model, and substrate requirements live in [CORE](CORE.md). Section numbers are retained from the unified specification; per the §→document map in [CORE](CORE.md), cross-references of the form §6–§10 point to sibling module documents, and §A / §12–§14 to the companion references (Demos mapping, threat model, glossary, conformance plan). The [conformance vectors](../conformance/) exercise this module's rules.*

## Chapter 8 — DACS-3: Negotiate

**Stage:** Negotiate (3rd of 5). **Status:** Draft — **DACS-3 v0.6** (on the common DACS v0.1 baseline; v0.6 adds SAC-1..SAC-10, the structurally distinct complete sealed-envelope phases, signed bidder record, reproducible `SealedSelectionReceipt`, and `SealedSelectionAgreementDocument`; only an authenticated current finalized complete record-set view can select, and the current profile supports only the fully specified lowest/highest-price rules; v0.5 binds a `pay-alternative` Listing to exactly one complete `terms.rail` selection, validates payee-bound payout coverage against the DACS-4 APR effective pipeline, and signs any cross-job replacement through `priorPaymentDispositionRef`; v0.4 removes the commitment-timestamp circularity, makes the commitment signature explicit, and requires a finalized commitment before irreversible Settle effects; v0.3 adds the optional `feeSchedule` cost-disclosure on agreement artifacts §8.5.3, the optional `AgreementParty.encryptionKey` binding for `encrypt-to-buyer` private delivery, DACS-4 §9.6.1, sealed-envelope procurement role binding / SE-8 and same-bidder commit authority / SE-9, the minor-safe `PayeeBoundAgreementDocument` plus `commit-payee-bound-agreement` phase for DACS-4 §9.5.1 PB-1, and metered-pricing quantity carriage `terms.meteredQuantity` with the MTR-1..5 recompute + unrecognized-pricing-kind fail-closed rules §8.5.2). **Depends on:** SR-2 (required for public commitments), SR-4 (required for genuinely private negotiation patterns), and a registered authenticated candidate-set binding for complete sealed-envelope selection; references DACS-1 listings and DACS-2 verified bundles. **Used by:** DACS-4 (pricing + rail input to settlement), DACS-5 (agreement reference in session bundle).

### 8.1 Abstract

DACS-3 specifies how parties arrive at agreed terms and bind themselves cryptographically to the outcome. It defines:

- A **negotiation channel model** — abstract requirements for a private coordination surface keyed to participant identities. RFQ contents remain private; sealed bids publish only commitments before the reveal deadline and intentionally publish signed openings afterward for auditable selection. Realised in v0.1 by SR-4; substrates without SR-4 host only negotiate-fixed-price.
- A **closed set of negotiation patterns** as phase types: negotiate-fixed-price (acceptance), negotiate-rfq (bounded offer/counter), historical sealed-envelope demand / procurement, and the structurally distinct complete sealed-envelope demand / procurement profile — each with a uniform input/output contract.
- Three **agreement artifact schemas** — the legacy AgreementDocument, the structurally distinct PayeeBoundAgreementDocument, and the selection-bound SealedSelectionAgreementDocument, each carrying final terms, deliverable reference, deadlines, and all-party signatures.
- Three corresponding **agreement commitment phases** — anchor the agreement hash on the public chain, producing the binding artifact every downstream stage references.

RFQ negotiation contents stay between participants. Sealed-auction bids remain confidential until reveal, after which their signed openings and the selection proof are deliberately public so independent readers can reproduce the outcome.

### 8.2 Motivation

Negotiation is where commerce most consistently breaks open standards. Identity, payment, and discovery can run publicly with little privacy cost to their *contents* (the durable identities they bind do stay visible at the audit layer — an accepted accountability-over-privacy tradeoff, §12.1). Pricing, term-sheet drafts, sealed bids, and RFQ counters cannot: they involve MNPI, competitive pricing, or discussions that harm participants if exposed. A public RFQ telegraphs market information institutional desks pay to keep private; sealed-bid procurement cannot run on a public mempool; regulated pre-trade negotiation is bound by MNPI rules public visibility violates.

DACS-3 separates two historically-fused concerns:

- **Negotiation content** lives in a private channel whose membership is bound to the same identities that hold value on chain (so in-channel signatures equal public-chain signatures). RFQ content remains private unless disclosed; sealed-auction openings are the explicit exception and become public only in the reveal phase.
- **Commitment** lives on chain: a single hash of the final agreement is anchored, so anyone can verify a binding agreement exists between the named parties at a known time without reading its contents.

This separation is what makes institutional/regulated flows possible on a public-permissionless substrate, and most distinguishes DACS from standards (AP2, x402, ERC-8004, W3C VC, zkTLS) that assume public negotiation or none. Not every transaction needs it: a fixed-price micropayment has nothing to negotiate — "acceptance is the negotiation" via negotiate-fixed-price (SR-2 only, any substrate). The substrate-locked patterns (rfq, sealed-envelope) are opt-in per listing.

### 8.3 Negotiation channel model

A negotiation channel is a coordination surface with the following properties.

#### 8.3.1 Required properties

(CH-1) **Identity-keyed membership.** The channel’s member set is a list of ClaimReferences, **fixed for the channel's lifetime in v0.1**. Each member’s primary claim MUST appear in their verified DACS-1 bundle. The member set is established by the §8.3.2 binding-proof flow before negotiation begins and MUST NOT change mid-channel. Dynamic membership (mid-negotiation add/remove governed by an admission policy) is reserved for a future version: the `membership-change` message type and an `admissionPolicy` schema are deliberately **not** defined in v0.1, and `membership-change` is correspondingly absent from the v0.1 `ChannelMessage.type` set.

(CH-2) **Confidentiality.** Non-members MUST NOT be able to read channel contents. The public chain sees only commitments and agreement hashes for fixed-price/RFQ operation. Sealed-envelope is the explicit exception: it exposes only the bid hash before the commit deadline, then publishes the signed `{bid, salt}` opening during the reveal window as required by §8.4.3/§8.4.4. A raw RFQ offer/counter or any sealed bid before its reveal MUST NOT be published.

(CH-3) **Authenticity.** Every message in the channel MUST be signed by its author’s primary key (the key associated with the author’s primary claim). Verifiers MUST be able to validate signatures using the same keys used in DACS-2 verification.

(CH-4) **Liveness.** The channel MUST deliver messages to all members within a bounded delay. Members MUST be able to detect channel-level failure (partition, censorship by the channel operator) and abort.

(CH-5) **Termination.** The channel MUST produce a terminal state. Terminal states are: (a) a signed AgreementArtifact; (b) an abort signed by any party; (c) timeout. The terminal state is referenced by the listing's agreement commitment phase (if agreement) or recorded as a failed Negotiate stage (otherwise).

(CH-6) **Per-session channelId uniqueness.** The substrate MUST derive a per-session-unique `channelId`, and an orchestrator MUST reject a session that reuses a `channelId` from a prior session. Without this the cross-session offer-replay defence (§8.3.3 envelope `channelId` + monotonic `sequence`) is vacuous — a reused `channelId` would let a session-A offer verify in session B. The threat and replay analysis are detailed in §8.12.

#### 8.3.2 SR-4 realisation

On Demos, L2PS (Layer-2 Privacy Subnets) is the SR-4 implementation. Channel sessions are subnets; messages stay between subnet members; the public chain stores only commitment hashes and the final agreement hash (as Storage Programs).

For v0.1, subnet membership MUST be bindable to the participants’ CCI primary claims, so that channel-message signatures verify against the same key that holds value on-chain and the agreement commitment anchor’s parties match the channel members. Until CCI-keyed membership ships, implementations MAY use a binding-proof step: each participant signs an "L2PS subnet X membership = CCI Y" attestation with their CCI primary key, anchored as a Storage Program before negotiation begins.

Other substrates MAY implement SR-4 via TEE-based confidential channels, zk-based privacy circuits, or permissioned-overlay networks bound to public-chain identity, provided they satisfy CH-1 through CH-6. DACS-3 does not standardise the wire protocol or the cryptographic envelope — those are SR-4 implementation choices — but does standardise the messages’ semantic shape.

#### 8.3.3 Message envelope (substrate-independent)

```
type ChannelMessage = {
  channelId: string                    // substrate-derived; opaque to DACS-3; MUST be unique per session (see CH-6)
  sequence: number                     // monotonic per channel, starts at 1
  sender: ClaimReference               // author's primary claim
  sentAt: number                       // unix ms
  type: "offer" | "counter" | "accept" | "reject"
       | "sealed-envelope-commit" | "sealed-envelope-reveal"
       | "abort"
  body: unknown                        // type-specific. Sealed-envelope commit/reveal bodies are defined in §8.4.3; RFQ offer/counter/accept/reject bodies are implementation-defined (the authoritative agreed terms live only in the signed AgreementArtifact, not the channel body)
  refs?: { repliesTo?: number }
  signature: ChannelMessageSignature   // see below
}
```

The envelope follows the §B.2 canonical-form template, omitting the `signature` field; the signature is computed over:
signed_bytes := "dacs-channelmsg:v1:" || envelope_hash
Implementations MAY add transport-level fields (routing, framing) outside the signed envelope; signed envelope contents MUST NOT change between sender and receiver.

#### 8.3.4 Channel failure detection and abort

A member MUST treat the channel as failed when any of the following holds:

- a message they sent is not acknowledged by a quorum of members within the channel’s liveness bound;
- a member they expect to respond does not respond within a per-pattern timeout;
- they observe contradictory views of the channel state from different sources (channel-operator forking).

On detected failure, the member MAY send an abort message (best-effort), abandon the channel, and record the failure in the session record (DACS-5) with classification counterparty or substrate as appropriate. An abort terminates the channel and the Negotiate phase. The abort message’s signed envelope MAY be anchored via SR-2 as an audit artifact. The phase returns PhaseHandlerResult with ok: false and an error class.

### 8.4 Negotiation patterns

The closed v0.x set at this revision. Each is a DACS-3 phase type with a phase-handler contract.

#### 8.4.1 negotiate-fixed-price

Acceptance of the listing’s posted terms. No private channel required.

```
type NegotiateFixedPriceInput = {
  jobId: string
  listingHash: string                  // pinned listing's content hash
  listingRef: { listingId: string; version: number }
  buyerBundle: IdentityBundle          // post-Vet
  sellerBundle: IdentityBundle         // post-Vet
  buyerVetRef: AttestationRef          // from DACS-2
  sellerVetRef: AttestationRef         // from DACS-2
  sessionContext: SessionContext
}
type NegotiateFixedPriceOutput = PhaseHandlerResult & {
  contextDelta?: {   // present only on ok:true; a failed phase returns a bare PhaseHandlerResult (no agreement)
    "negotiate-fixed-price": {
      agreementHash: string
      agreementRef: AttestationRef
    }
  }
}
```

**Procedure.** The orchestrator (or buyer agent, depending on actor) MUST:

1. construct the AgreementArtifact selected by the listing's commitment phase with derivedFromPattern: "fixed-price", copying terms directly from the listing’s pricing, acceptedRails (using the buyer’s selected rail; `terms.rail` is omitted for a zero-pay pipeline per §8.5.2 rule 3), deliverable, and deadline (computed as now + listing.terms.deadlineSecAfterCommit), and including the required payout bindings when the selected artifact is payee-bound;
2. collect buyer signature;
3. collect seller co-signature;
4. anchor the agreement artifact via SR-2;
5. return agreementHash and agreementRef.

**Seller-side auto-accept (optional)**

A listing MAY declare terms.acceptanceModel: "auto-accept", in which case the seller pre-issues a **template acceptance commitment** alongside the listing rather than a per-session signature. The mechanism:

- The seller publishes, at listing-anchor time, a separate AutoAcceptCommitment record: { listingRef, listingContentHash, acceptanceModel: "auto-accept", validUntil, sellerSignature } where sellerSignature is the seller’s signature over the domain-separated payload "dacs-auto-accept-commitment:v1:" || sha256(canonical(commitment)). This commits the seller to auto-accepting any buyer signature against the listed terms within validUntil.
- At orchestrator time, the orchestrator: (1) **verifies** the AutoAcceptCommitment is anchored, unrevoked, and still valid (see *Two-phase validity* below); (2) **constructs** the per-session AgreementArtifact selected by the listing's commitment phase with `derivedFromPattern: "fixed-price"`; (3) **computes** the agreement hash; (4) **constructs an auto-accept seller signature** — an Ed25519 signature by the seller’s primary key over `"dacs-auto-accept-instance:v1:" || agreementHash || autoAcceptCommitmentHash`.

  *Two-phase validity (step 1).* `validUntil` is checked twice because the per-session `committedAt` does not exist until the commitment is finalized, so it cannot gate the signature pre-anchor: **provisionally** against the current clock at signing time (an already-expired commitment MUST NOT produce an instance signature), then **authoritatively** re-checking `committedAt ≤ validUntil` against the commitment's finalized CORE §5.1 receipt timestamp at the agreement commitment phase, per the §8.5.2 ordering note.

  *Instance signature (step 4).* This signature is **NOT pre-issued** — it MUST be produced live by the seller’s keyholder or by an authorised auto-signer the seller has explicitly delegated to. The pre-issued AutoAcceptCommitment authorises the auto-signer to produce instance signatures within its scope.

Listings using auto-accept MUST publish the AutoAcceptCommitment alongside the listing, and the buyer’s orchestrator MUST verify the commitment before relying on auto-accept. A pre-issued per-instance signature (signing a placeholder agreement hash) MUST NOT be used; the per-instance signature binds to a specific agreement hash. Sellers operating auto-accept MUST hold the auto-signing key in a system that produces live instance signatures on demand (HSM, TEE, hot wallet with rate-limiting).

**Substrate:** SR-2 only.

#### 8.4.2 negotiate-rfq

Bounded multi-turn offer-and-counter exchange in a private channel.

```
type NegotiateRfqInput = {
  jobId: string
  listingHash: string
  listingRef: { listingId: string; version: number }
  buyerBundle: IdentityBundle
  sellerBundle: IdentityBundle
  buyerVetRef: AttestationRef
  sellerVetRef: AttestationRef
  parameters: {
    maxTurns: number                   // hard cap; default 6; MUST be >= 2
    timeoutSec: number                 // per-turn timeout
    channelSubnet?: string             // SR-4 channel id; substrate-specific
    rfqInitiator?: "buyer" | "seller"  // who sends the first offer; default "buyer"
  }
  sessionContext: SessionContext
}
type NegotiateRfqOutput = PhaseHandlerResult & {
  contextDelta?: {   // present only on ok:true; a failed phase (reject / maxTurns / timeout) returns a bare PhaseHandlerResult
    "negotiate-rfq": {
      agreementHash: string
      agreementRef: AttestationRef
      turnCount: number
      channelTranscriptRef?: AttestationRef  // optional; member-only-decryptable
    }
  }
}
```

**Procedure.** The orchestrator (driving the buyer-side flow) MUST:

1. establish an SR-4 channel between buyerBundle.presentedBy and sellerBundle.presentedBy;
2. send an initial offer — buyer (or seller, per the negotiate-rfq `rfqInitiator` phase parameter; default `buyer`) sends a turn of type offer with proposed terms;
3. iterate — each side MAY respond with counter, accept, or reject; iteration continues until accept is received (proceed), reject is received (terminate; counterparty class), maxTurns is reached without accept (terminate; counterparty class), or timeoutSec elapses without a response (terminate; counterparty or substrate class);
4. construct the AgreementArtifact selected by the listing's commitment phase with `derivedFromPattern: "rfq"` and the agreed terms, including the required payout bindings when payee-bound, then sign and send it as a final message;
5. collect co-signatures from all parties;
6. anchor the agreement via SR-2;
7. optionally, if all parties consent, anchor the encrypted transcript via SR-2 with a channelTranscriptRef. Consent MUST be explicit; default is no transcript anchoring.

**Conformance.**

- (RFQ-1) maxTurns MUST be ≥ 2.
- (RFQ-2) Each turn MUST conform to the channel message envelope.
- (RFQ-3) Final terms MUST conform to the listing’s pricing band — counters proposing terms outside the band MUST be rejected client-side; signed agreements with out-of-band terms MUST be rejected by the declared agreement commitment phase.
- (RFQ-4) Implementations MUST enforce the turn timeout; missed-timeout abandonment MUST be treated as channel failure.

**Substrate:** SR-2 + SR-4.

#### 8.4.3 negotiate-sealed-envelope / negotiate-sealed-envelope-procurement

Sealed-bid procurement: all bidders submit hash-committed bids before a deadline; bids are revealed after the deadline; winner is selected per the listing’s selection criterion.

> **Historical profile.** These phase kinds retain their released SE-1..SE-9 semantics for audit and already pinned sessions, but they do not authenticate candidate-set completeness. A DACS-3 v0.6 implementation starting a new sealed-envelope session MUST use the §8.4.4 complete phase kind and selection-bound commitment instead. It MUST NOT advertise an SE-only run as omission-resistant or SAC-verified.

```
type NegotiateSealedEnvelopeInput = {
  jobId: string
  listingHash: string
  listingRef: { listingId: string; version: number }
  buyerBundles: IdentityBundle[]       // all bidders' bundles; field name predates the demand/procurement mode split
  sellerBundle: IdentityBundle         // listing publisher
  buyerVetRefs: AttestationRef[]
  sellerVetRef: AttestationRef
  parameters: NegotiateSealedEnvelopeParameters
  sessionContext: SessionContext
}
type NegotiateSealedEnvelopeParameters =
  | {                                  // negotiate-sealed-envelope (demand/default)
    commitDeadline: number             // unix ms; MUST be > now
    revealWindow: number               // seconds after commitDeadline; MUST be >= 60
    selectionRule: "lowest-price" | "highest-price" | "first-acceptable" | "rule-ref:<contentHash>:<uri>"
    auctionMode?: "demand"             // optional no-op marker; absent and "demand" have identical semantics (SE-8)
    channelSubnet?: string
  }
  | {                                  // negotiate-sealed-envelope-procurement
    commitDeadline: number
    revealWindow: number
    selectionRule: "lowest-price" | "highest-price" | "first-acceptable" | "rule-ref:<contentHash>:<uri>"
    auctionMode: "procurement"         // explicit procurement marker; valid only on the procurement phase kind (SE-8)
    channelSubnet?: string
  }
type NegotiateSealedEnvelopeOutput = PhaseHandlerResult & {
  contextDelta?: {   // present only on ok:true; a failed phase (no winning bid) returns a bare PhaseHandlerResult
    "negotiate-sealed-envelope"?: {
      agreementHash: string
      agreementRef: AttestationRef
      winningBidderClaim: ClaimReference
      revealedBidRefs: AttestationRef[]
      losingBidderClaims: ClaimReference[]
    }
    "negotiate-sealed-envelope-procurement"?: {
      agreementHash: string
      agreementRef: AttestationRef
      winningBidderClaim: ClaimReference
      revealedBidRefs: AttestationRef[]
      losingBidderClaims: ClaimReference[]
    }
  }
}
```

Exactly one contextDelta key is present on success, and it MUST equal the phase kind that ran. The two keys carry the same payload shape; the split keeps session-state consumers keyed by pipeline phase kind from reading a procurement result as a demand-phase result.

**Procedure.** The orchestrator MUST:

1. **Channels** — establish SR-4 channels between the seller and each bidder.
2. **Bidder commit phase** (before commitDeadline) — each bidder constructs a bid and a fresh salt (per SE-7) and computes:

   `bidHash = sha256("dacs-sealed-bid:v1:" || sha256(canonical_JCS(bid)) || salt)`

   expressed as a **lowercase hex string** (the same convention as every other DACS hash, so the SE-5 lexicographic tie-break is deterministic). The bid is hashed to a fixed 32-byte digest before concatenation so the bid/salt boundary is unambiguous, and the leading domain tag separates this commitment from any other sha256 usage. `commitTimestamp` is part of the commit *message* envelope and is NOT in the bidHash preimage (only `canonical_JCS(bid)` + salt are hashed). Each bidder sends a `sealed-envelope-commit` message `{bidHash, bidderClaim, commitTimestamp}`, where:
   - the message’s `bidderClaim` MUST equal the channel-envelope sender (the authenticated signer, CH-3); a commit whose `bidderClaim` ≠ sender MUST be excluded — bidder identity is the authenticated signer, not a free-text body field;
   - `commitTimestamp` is informational only and MUST NOT be used for any deadline gate, ordering, or tie-break (the SR-2 anchor timestamp is authoritative per SE-2/SE-5);
   - the commit message’s bidHash MUST also be anchored via SR-2.
3. **commitDeadline and same-bidder authority** — no further commits are accepted; the orchestrator records the set of received commits. Before matching reveals, it MUST resolve one authoritative commit per authenticated `bidderClaim` under SE-9. Later same-bidder commits are inert; they do not give the bidder a choice of commitments at reveal time.
4. **Bidder reveal phase** (within revealWindow) — each bidder sends a `sealed-envelope-reveal` message `{bid, salt}` opening its SE-9-authoritative bidHash; the orchestrator verifies `sha256("dacs-sealed-bid:v1:" || sha256(canonical_JCS(bid)) || salt) == bidHash` (mismatches, including a reveal that opens only a non-authoritative same-bidder commit, cause exclusion). **Each bidder MUST anchor its own reveal record via SR-2 before revealWindow expiry** (the bidder, not the orchestrator, so an honest bidder retains objective proof of its write); the anchored reveal record MUST contain the openable `{bid, salt}` (verifiable against the authoritative committed bidHash). The intended selection input is anchored, in-window reveals rather than the orchestrator's channel inbox, but this historical profile does not authenticate that discovery returned every such record. It provides integrity and an excluded bidder's challenge evidence, not non-omission; §8.4.4 supplies the complete-set gate.
5. **Selection** operates over the resolved anchored reveal records available under this historical profile, in order:
   - **Exclusions first** — the orchestrator MUST first exclude (i) any bid whose `price.currency` ≠ the listing-declared currency and (ii) any bid with non-positive `price.amount` (§9.3).
   - **Reserve** — then, if the auction PricingSpec declares `reservePrice` (whose `currency` MUST equal the listing-declared currency — a mismatched-currency reserve is a non-conformant listing), exclude bids failing the reserve: for `highest-price` and for `first-acceptable`/`rule-ref` the reserve is a price **floor** (`amount < reservePrice` excluded); for `lowest-price` it is a **ceiling** (`amount > reservePrice` excluded). The comparison uses CD-1-canonical full-precision decimals and a bid whose `amount == reservePrice` is **admitted** (the bound is inclusive). If the candidate set is empty after these exclusions, the phase fails with no winning bid (bare PhaseHandlerResult → `negotiate-failed`, errorClass per step 6).
   - **Selection rule** — the orchestrator applies the phase-step `parameters.selectionRule`, which is content-hash-bound into the listing pipeline per §6.3.4 and is the authoritative selection rule; the auction PricingSpec's own `selectionRule` MUST equal it (a listing whose two values disagree is non-conformant).
   - **Tie-break ladder** — ties resolved by earliest SR-2 anchor timestamp of each bidder's SE-9-authoritative commit (the same objective, substrate-determined timestamp SE-2 uses for the deadline gate — *not* the self-reported `commitTimestamp` field); any remaining ties (authoritative commits anchored in the same block / with equal anchor timestamps) resolved by ascending lexicographic order of the lowercase-hex `bidHash` string (per step 2).
6. **No winning bid / agreement construction** — if the selection rule yields no winner (an empty candidate set — all bids excluded for currency/non-positive/reserve, or all bidders failed to reveal per SE-4 — or a `first-acceptable`/`rule-ref` rule that no bid satisfies), the phase fails with no winning bid (bare PhaseHandlerResult; errorClass `counterparty` when the emptiness is bidder-caused, `permanent` for a structural listing defect; → `negotiate-failed`). Otherwise construct the AgreementArtifact selected by the listing's commitment phase from the winning bid, including the required payout bindings when payee-bound, with `derivedFromPattern: "sealed-envelope"` and roles assigned by the pinned sealed-envelope phase kind (SE-8): for demand (`negotiate-sealed-envelope`), the winning bidder is the agreement `buyer` and the listing publisher is the `seller`; for procurement (`negotiate-sealed-envelope-procurement` with `"procurement"` `auctionMode`), the listing publisher is the agreement `buyer` and the winning bidder is the `seller`. In both modes, `bid.price` is the amount payable by the agreement `buyer` to the agreement `seller`; the money direction is defined by the agreement roles, never by which party ran the auction. Then collect the agreement `buyer` and agreement `seller` co-signatures — equivalently, the listing publisher and winning bidder after SE-8 role assignment. Losing bidders are listed as bidder-non-winning parties and their signatures are not required.
7. **Anchor** the agreement via SR-2 (each reveal record was already anchored by its own bidder in step 4).

**Sealed bid body schema**

The body of a sealed-envelope-reveal message (the revealed `bid`, and therefore the value committed to in step 2) MUST conform to:
```
type SealedBid = {
  price: PriceTerm                     // the bid amount and currency
  deliverable?: DeliverableRef         // what the bidder undertakes to deliver
  terms?: Record<string, unknown>      // additional pattern- or listing-specific terms
}
```
The `bid` over which `bidHash` is computed in step (2) is exactly this `SealedBid` object in its RFC 8785 JCS canonical form. All bids in a single session MUST be denominated in the listing-declared currency; a revealed bid whose `price.currency` does not match MUST be excluded from selection.

**Selection rules and the rule-ref binding requirement**
`parameters.selectionRule` is one of `"lowest-price"`, `"highest-price"`, `"first-acceptable"` (per listing-defined acceptance criteria), or `"rule-ref:<contentHash>:<uri>"`:

- **lowest-price / highest-price** — the orchestrator MUST order revealed bids by `bid.price.amount` (compared as a decimal, full precision) ascending or descending respectively. This comparison is well-defined only because every candidate bid is in the listing-declared currency (mismatched-currency bids are already excluded above), so `amount` values are directly comparable and a cross-currency comparison can never occur.
- **first-acceptable** — the orchestrator MUST evaluate revealed bids in ascending order of the SR-2 anchor timestamp of each bidder's SE-9-authoritative commit (the same objective clock as SE-2/SE-5, not the self-reported `commitTimestamp` field) against the listing-declared acceptance predicate, and select the first that satisfies it. The acceptance predicate MUST be deterministic given the bid set and MUST be fixed before bids open — content-hash-bound into the listing (the same anti-swap discipline as rule-ref), so it cannot be changed after bids are seen; a non-deterministic or post-bid-mutable predicate MUST NOT be used.
- **rule-ref** — the rule MUST be anchored as a Storage Program (or fetched from an HTTPS URI and content-hash-bound). The URI is purely informational; the `<contentHash>` in the selection-rule string is the authoritative binding. Orchestrators MUST fetch the rule at `<uri>` (or the substrate anchor), compute sha256 of the canonical form, and verify it matches `<contentHash>`. Mismatch MUST exclude the rule and fail the selection step with `errorClass: permanent`. This prevents a seller from changing the selection algorithm after bids have been submitted by changing the content served at `<uri>`.

**Conformance.**

- (SE-1) commitDeadline MUST be at least 60 seconds in the future at session start.
- (SE-2) Every bidder commit MUST be anchored before commitDeadline; commits whose anchor timestamp is after commitDeadline MUST be excluded.
- (SE-3) Every revealed bid MUST be anchored via SR-2 before revealWindow expiry; reveals whose anchor timestamp is after revealWindow expiry MUST be excluded. This mirrors SE-2: the substrate anchor timestamp — not a channel message's self-reported sentAt or the orchestrator's wall clock — is the authoritative clock that decides whether a reveal occurred in-window.
- (SE-4) Bidders failing reveal MUST be excluded from selection and MAY be marked with a failure-to-reveal reputation event (DACS-5).
- (SE-5) The selection rule MUST be deterministic; ties MUST resolve consistently. The tie-break MUST use the objective SR-2 anchor timestamp of each bidder's SE-9-authoritative commit (the same clock as SE-2), MUST NOT use the self-reported commitTimestamp field, and MUST resolve same-anchor-timestamp ties by ascending lexicographic order of the lowercase-hex bidHash string (step 2).
- (SE-6) rule-ref selection rules MUST be content-hash-bound and the rule content MUST itself be deterministic given the bid set.
- (SE-7) **Bid-commitment salt.** The `salt` used in the bidHash commitment MUST be generated from a cryptographically-secure random source with at least 256 bits (32 bytes) of entropy, MUST NOT be reused across bids or sessions, and MUST be carried on the wire as a base64url string so the bytes hashed are unambiguous to both committer and verifier; the commitment input is the raw decoded salt bytes. This closes the pre-reveal brute-force leak created by anchoring bidHash publicly (§8.12) for low-entropy structured bids, and aligns the sealed-envelope salt with the HTLC-1 salt discipline.
- (SE-8) **Sealed-envelope role assignment.** The sealed-envelope mode is read from the pinned listing's phase kind. `negotiate-sealed-envelope` is the demand phase: absent `auctionMode` and present `"demand"` have identical demand semantics. `negotiate-sealed-envelope-procurement` is the procurement phase and MUST carry `auctionMode: "procurement"`. A present-but-unresolvable or malformed `auctionMode`, or a missing `auctionMode` on the procurement phase, MUST cause the declared agreement commitment phase to reject the agreement with a recorded `unresolvable-auctionMode` reason; it MUST NOT be coerced to demand. For demand, the winning bidder MUST be the agreement `buyer` and the listing publisher MUST be the `seller`; for procurement, the listing publisher MUST be the agreement `buyer` and the winning bidder MUST be the `seller`. `bid.price` is always the amount payable by the agreement `buyer` to the agreement `seller`. This keeps procurement minor-safe under CORE §11.1.2: valid procurement listings use a new phase kind that older readers reject during listing validation; no valid procurement listing is encoded as an optional discriminator on the legacy demand phase.
- (SE-9) **Same-bidder commit authority.** For each authenticated `bidderClaim`, the orchestrator MUST consider every structurally valid commit whose SR-2 anchor is in-window under SE-2. It MUST collapse records sharing the exact tuple `bidderClaim, anchorTimestamp, bidHash` and order the remainder by the ascending tuple `anchorTimestamp, bidHash`. The first commit in that total order is the bidder's sole authoritative commit. Every later same-bidder commit is inert and MUST NOT be matched to a reveal or enter selection. A reveal that opens a non-authoritative commit but not the authoritative commit MUST exclude that bidder as a bidHash mismatch. `commitTimestamp` MUST NOT affect authority. If an otherwise candidate same-bidder commit has an unresolvable SR-2 anchor timestamp, authority for that bidder is `indeterminate` until it resolves; the orchestrator MUST NOT silently select another commit for that bidder. Exact duplicates do not create a second choice.

**Substrate:** SR-2 + SR-4.

#### 8.4.4 Complete sealed-envelope profile (SAC-1..SAC-10)

The §8.4.3 phases prove the integrity and timeliness of every record that a reader finds, but their historical wire shape does not prove that the reader found every record. They remain valid under their released semantics and MUST NOT be described as candidate-set-complete. A new listing that requires omission-resistant winner selection uses the structurally distinct `negotiate-sealed-envelope-complete` or `negotiate-sealed-envelope-procurement-complete` phase followed by `commit-selection-bound-agreement`. An older reader rejects those unknown phase kinds before acting under CORE §11.1.2.

The complete phases use the §8.4.3 deadlines, bid body, reserve, price comparison, salt, and demand/procurement role rules except where this section strengthens them. Their parameters are:

```
type CandidateSetBindingRef = {
  bindingId: string                         // stable identifier in the substrate binding registry
  bindingVersion: string                    // canonical positive decimal
  definitionRef: AttestationRef             // exact immutable binding definition and content hash
}

type NegotiateCompleteSealedEnvelopeParameters =
  | {
    commitDeadline: number
    revealWindow: number
    selectionRule: "lowest-price" | "highest-price"
    candidateSetBinding: CandidateSetBindingRef
    auctionMode?: "demand"
    channelSubnet?: string
  }
  | {
    commitDeadline: number
    revealWindow: number
    selectionRule: "lowest-price" | "highest-price"
    candidateSetBinding: CandidateSetBindingRef
    auctionMode: "procurement"
    channelSubnet?: string
  }
```

The complete phases use the §8.4.3 input fields with `parameters: NegotiateCompleteSealedEnvelopeParameters`. On success exactly one context key matching the executing complete phase is returned, with this payload:

```
type NegotiateCompleteSealedEnvelopeResult = {
  agreementHash: string
  agreementRef: AttestationRef
  selectionReceiptRef: AttestationRef
  winningBidderClaim: ClaimReference
  revealedBidRefs: AttestationRef[]
  losingBidderClaims: ClaimReference[]
}
```

The overall output is `PhaseHandlerResult` plus either `contextDelta["negotiate-sealed-envelope-complete"]` or `contextDelta["negotiate-sealed-envelope-procurement-complete"]` carrying that result. A failed or indeterminate selection returns a bare failed `PhaseHandlerResult` and no agreement, receipt-as-success, or partial context delta.

`revealedBidRefs` is the canonical receipt order of every authenticated reveal record, including deterministically excluded reveals; it is not only the eligible or winning subset. `losingBidderClaims` is the ascending canonical-ClaimReference list of every bidder with an authenticated non-winning decision. The two arrays are projections of the verified receipt and MUST NOT be supplied by the channel inbox.

`CandidateSetBindingRef.definitionRef` resolves through SR-2 to the exact registered substrate policy that verifies complete enumeration at a current finalized state. The policy MUST define the record-address prefix query, evidence authentication, finality and maximum-lag rule, canonical native ordering, writer admission, per-job record/byte resource ceilings, same-logical-address conflict handling, independent-observer threshold where applicable, and fork/reorg reconciliation. Exceeding a declared ceiling fails the phase; it never authorizes selection over a truncated prefix. A self-signed orchestrator index, catalog response, ordinary RPC result, or unqualified `not found` policy cannot be registered. The listing signature fixes the reference before any bidder commits.

Each bidder anchors its own signed record, not merely an untyped reveal payload:

```
type SealedAuctionRecord = {
  sealedAuctionRecordVersion: "1"
  recordKind: "commit" | "reveal"
  jobId: string
  listingRef: { listingId: string; version: number; contentHash: string }
  phaseIndex: number
  bidderClaim: ClaimReference
  bidHash: string                            // lowercase 64-hex
  commitRef?: AttestationRef                 // REQUIRED for reveal; forbidden for commit
  bid?: SealedBid                            // REQUIRED for reveal; forbidden for commit
  salt?: string                              // REQUIRED for reveal; forbidden for commit; unpadded Base64URL, >=32 decoded bytes
  createdAt: number                          // signed construction metadata; never deadline/order authority
  signature: {
    algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"
    signer: ClaimReference                   // MUST equal bidderClaim
    value: string                            // dacs-sealed-auction-record:v1:
  }
}

type SealedCandidateSetEntry = {
  recordRef: AttestationRef
  anchorReceipt: AnchorReceipt
  orderKey: string                           // binding-defined canonical native order key
}

type CandidateSetCompletenessEvidence = {
  substrate: string
  finalizedState: {
    id: string
    height?: string
    timestamp: number
  }
  recordSetHash: string                      // sha256(JCS(entries))
  recordCount: string                        // canonical unsigned decimal
  proof: { kind: string; value: string }     // interpreted only by the pinned binding definition
}

type SealedRecordDecision = {
  recordContentHash: string
  disposition: "admitted-commit" | "admitted-reveal" | "duplicate" | "excluded"
  reason?: "malformed-record" | "wrong-session" | "bad-signature" | "wrong-address"
         | "unfinalized" | "late-commit" | "late-reveal" | "non-authoritative-commit"
         | "duplicate-reveal" | "bid-hash-mismatch"
}

type SealedBidDecision = {
  bidderClaim: ClaimReference
  authoritativeCommitRef?: AttestationRef
  revealRef?: AttestationRef
  bidContentHash?: string
  price?: PriceTerm
  disposition: "eligible" | "excluded"
  reason?: "no-authoritative-commit" | "no-valid-reveal" | "currency-mismatch"
         | "non-positive-price" | "reserve-price"
}

type SealedSelectionReceipt = {
  sealedSelectionReceiptVersion: "1"
  jobId: string
  listingRef: { listingId: string; version: number; contentHash: string }
  phaseIndex: number
  phaseKind: "negotiate-sealed-envelope-complete"
           | "negotiate-sealed-envelope-procurement-complete"
  candidateSetBinding: CandidateSetBindingRef
  collectionPrefix: string                   // dacs3:auction:{jobId}, with CF-4 encoding
  selectionRule: "lowest-price" | "highest-price"
  entries: SealedCandidateSetEntry[]         // complete canonical set, sorted by (orderKey, contentHash)
  completenessEvidence: CandidateSetCompletenessEvidence
  recordDecisions: SealedRecordDecision[]    // exactly one, same order, for every entries member
  bidDecisions: SealedBidDecision[]          // exactly one per canonical bidder identity, sorted by ClaimReference bytes
  winner?: {
    bidderClaim: ClaimReference
    authoritativeCommitRef: AttestationRef
    revealRef: AttestationRef
    bidContentHash: string
    price: PriceTerm
    commitAnchorTimestamp: number
    bidHash: string
  }
  createdAt: number                          // signed metadata; never set/finality/order authority
  signature: {
    algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"
    signer: ClaimReference                   // authenticated session orchestrator
    value: string                            // dacs-sealed-selection-receipt:v1:
  }
}
```

The canonical record logical addresses are:

- commit: `dacs3:auction:{jobId}:commit:{bidderClaim}:{bidHash}`;
- reveal: `dacs3:auction:{jobId}:reveal:{bidderClaim}:{bidHash}`.
- selection receipt: `dacs3:selection:{jobId}:{phaseIndex}`.

`bidderClaim` is first canonicalized under CF-2 and CF-4-encoded; `jobId` and `bidHash` use their canonical grammars. The collection prefix is `dacs3:auction:{jobId}`. Each `SealedAuctionRecord` follows CORE §B.2 with `signature` omitted and is signed over `"dacs-sealed-auction-record:v1:" || recordContentHash`. A reveal's `commitRef` MUST resolve the exact signed commit record it opens. A binding MUST prevent two different canonical record contents from becoming authoritative at one logical address; conflicting finalized writes/views are `indeterminate` unless the binding supplies one authenticated canonical outcome under its registered fork/conflict rule.

The authenticated session orchestrator anchors exactly one immutable `SealedSelectionReceipt` at the derived selection-receipt address. Its SR-2 receipt MUST bind that logical address, exact content hash, writer, transaction, nonce where applicable, and finalized state. A conflicting second receipt for the same `(jobId, phaseIndex)` rejects selection; first-seen discovery order does not choose between conflicts.

The complete-profile procedure is the §8.4.3 procedure with these mandatory replacements after channel establishment:

1. bidders sign and anchor the typed commit and reveal records above at their derived logical addresses;
2. after `revealDeadline := commitDeadline + revealWindow*1000`, the selector resolves the pinned candidate-set binding and obtains the complete prefix result at a current finalized state whose consensus timestamp is at least `revealDeadline`;
3. it resolves and verifies every returned record and receipt, derives every record and bid decision, and computes the winner using only the built-in price rule and SE-5 tie-break;
4. it signs and anchors the exact `SealedSelectionReceipt`; and
5. the listing publisher and winner resolve and independently recompute that receipt before co-signing the `SealedSelectionAgreementDocument` in §8.5.

**Complete-profile conformance.** These requirements are evaluated before an agreement signature is accepted:

- (SAC-1) **Structural capability gate.** A DACS-3 v0.6 implementation starting a new sealed-envelope session MUST use exactly one complete sealed phase and immediately follow it with `commit-selection-bound-agreement`. The phase MUST carry exactly one closed `CandidateSetBindingRef`. The historical sealed phases and agreement types remain audit-readable and may finish an already pinned session under their old meaning, but MUST NOT start a new v0.6-profile session or be upgraded by inference, an optional field, or local policy.
- (SAC-2) **Typed bidder authority.** Every considered record MUST have the exact closed shape for its `recordKind`, exact job/listing/phase tuple, canonical bidder claim and derived logical address, a canonical content hash, a valid bidder signature under `"dacs-sealed-auction-record:v1:"`, and a verified finalized SR-2 receipt. Transaction submitter, Storage Program owner, channel sender hints, and `createdAt` do not replace the record signature or receipt. A malformed shape, wrong session/address/hash, invalid signature, contradictory receipt, or other authenticated-invalid record rejects the whole selection; unavailable signature/key/receipt authority makes it `indeterminate`. Neither case is an exclusion that can improve another bidder's rank. Only a fully authenticated record may then receive a deterministic eligibility exclusion such as late anchor, non-authoritative commit, duplicate reveal, bid-hash mismatch, currency, positivity, or reserve.
- (SAC-3) **Authenticated complete current set.** The exact binding definition MUST resolve at `definitionRef`, match `bindingId`/`bindingVersion`, and pass its authenticated governance, writer-admission, resource, conflict, and finality rules. Its proof MUST bind the collection prefix, exact ordered `(recordRef, receipt, orderKey)` set through `recordSetHash`, `recordCount`, and one exact finalized state that is current under the definition's maximum-lag and fork policy. Missing, stale, partially enumerated, conflicting, self-asserted, unsupported, over-ceiling, or silently truncated evidence cannot select: an authenticated policy contradiction is `rejected`; unavailable/unorderable authority is `indeterminate`. A valid proof for an older finalized state is not current merely because it is signed.
- (SAC-4) **Canonical enumeration and replay.** `entries` MUST contain every record in the binding result exactly once and be sorted by ascending binding-defined `orderKey`, then `recordRef.contentHash`. Every receipt MUST bind the entry's exact logical/native address, content hash, transaction, writer, nonce where applicable, and finalized state. `recordSetHash := sha256(JCS(entries))`; `recordCount` is the decimal array length. A replayer MUST resolve the same bytes and reproduce the same set from the retained proof. Omission, duplication, substitution, attacker ordering, or an unused returned record invalidates the receipt.
- (SAC-5) **Deterministic candidate derivation.** The evaluator MUST apply SE-2, SE-3, SE-7, and SE-9 to the complete set, then the currency, positivity, and inclusive reserve filters in §8.4.3. For one authoritative commit, exact duplicate reveals collapse; remaining otherwise-valid matching reveals are ordered by `(anchor timestamp, orderKey, recordContentHash)`, the first is authoritative, and later matches are recorded `duplicate-reveal`. A reveal opening only a non-authoritative commit is recorded `bid-hash-mismatch`. `recordDecisions` contains exactly one decision per entry in entry order; `bidDecisions` contains exactly one per canonical bidder identity in ascending canonical bytes. Every exclusion reason is derived from authenticated record bytes and receipts. If any fact needed to decide authority or eligibility is unavailable, the whole selection is `indeterminate`; the evaluator MUST NOT discard that bidder and continue.
- (SAC-6) **Closed deterministic rule profile.** The complete profile supports only `lowest-price` and `highest-price`, using CD-1 full-precision comparison followed by SE-5's `(commit anchor timestamp, bidHash)` ladder. `first-acceptable`, `rule-ref:*`, an unknown rule, caller-supplied predicate, clock, randomness, network result, or implementation-dependent numeric operation is unsupported and MUST fail before any rule fetch or execution. A future deterministic VM requires a new structurally distinguishable phase type with exact input/output encoding, numeric semantics, resource ceiling, error mapping, and no ambient I/O.
- (SAC-7) **Receipt reproduction and authority.** The receipt MUST have the closed shape above, copy the signed listing tuple/phase/binding/rule exactly, and carry the authenticated session orchestrator's valid signature over `"dacs-sealed-selection-receipt:v1:" || receiptContentHash`, with only `signature` omitted for the hash. A consumer MUST independently re-run SAC-2..SAC-6; the signed `recordDecisions`, `bidDecisions`, and `winner` are assertions to compare with recomputation, not trusted inputs. A no-winner receipt is valid only when the recomputed eligible set is empty; it produces a failed phase and no agreement.
- (SAC-8) **Agreement binding.** A successful receipt MUST be finalized and independently resolvable through an exact `AttestationRef`. `SealedSelectionAgreementDocument.selectionReceiptRef` MUST reference those exact canonical receipt bytes. Agreement validation resolves the receipt, verifies SAC-2..SAC-7, requires its exact job/listing/phase tuple, and recomputes that its winner supplies the agreement price, deliverable, and winning party. A missing, stale, substituted, no-winner, or non-reproducible receipt blocks commitment and every Settle effect.
- (SAC-9) **Role and payout closure.** Demand-complete assigns the winner as agreement buyer and publisher as seller; procurement-complete assigns publisher as agreement buyer and winner as seller. The selection-bound agreement always uses `PayeeBoundAgreementTerms`: `payoutBindings` is empty for a zero-pay pipeline and otherwise exactly covers every effective concrete payment under §8.5/PB/APR. Non-winning bidders are informational parties only and do not sign the agreement or authorize settlement.
- (SAC-10) **Disposition and precedence.** A deterministic malformed/mismatched record, proof, receipt, rule, or agreement is `rejected`; unavailable or unorderable binding, key, finality, resolution, or fork evidence is `indeterminate`; only complete successful recomputation is `verified`. Both `rejected` and `indeterminate` fail the phase before agreement commitment. No discovery result, channel inbox, locally cached candidate list, producer timestamp, or party signature can turn an incomplete set into `verified`.

**Substrate:** SR-2 + SR-4 + a registered candidate-set binding satisfying SAC-3/SAC-4. A substrate without that binding MUST refuse both complete phase kinds with a clear capability-missing result; it MUST NOT fall back to §8.4.3 while claiming completeness.

### 8.5 Agreement artifacts

The canonical output of any negotiation pattern is an `AgreementArtifact`. The listing's commitment phase selects its artifact type: `commit-agreement` produces the legacy `AgreementDocument`; `commit-payee-bound-agreement` produces a `PayeeBoundAgreementDocument`; and `commit-selection-bound-agreement` produces a `SealedSelectionAgreementDocument`. A pipeline that requires DACS-4 payee-destination binding MUST use one of the latter two. The three artifacts deliberately have different required version discriminators and signing domains, so a reader rejects an unsupported type before settlement rather than silently ignoring action-bearing payout or selection terms.

```
type AgreementTerms = {
  deliverable: DeliverableRef        // DACS-4 reference
  price: PriceTerm                   // DACS-4 reference
  // Present iff the pinned listing prices `metered`. First-class in terms so JCS places it
  // under every signature and the agreement hash. Quantity is `"0"` or `[1-9][0-9]*` (MTR-4).
  meteredQuantity?: { quantity: string; unit: string }
  rail?: PaymentRailRef              // present iff the pipeline has a concrete pay-* or pay-alternative phase; APR selection uses complete canonical bytes
  deadline: number                   // unix ms; settle-by deadline
  priceAnchor?: PriceAnchor          // optional informational audit record
  feeSchedule?: FeeSchedule          // optional disclosure-only fee structure (§8.5.3)
  additionalTerms?: Record<string, unknown>
}

type PayeeBoundAgreementTerms = {
  deliverable: DeliverableRef
  price: PriceTerm
  // Same metered carriage and canonical quantity contract as AgreementTerms (MTR-1..4).
  meteredQuantity?: { quantity: string; unit: string }
  rail?: PaymentRailRef
  deadline: number
  priceAnchor?: PriceAnchor
  feeSchedule?: FeeSchedule
  payoutBindings: PayoutBinding[]    // REQUIRED; exactly one entry for every concrete payment in the effective pipeline
  priorPaymentDispositionRef?: AttestationRef // present only when this fresh-job APR selection is an explicit replacement of a prior signed selection
  additionalTerms?: Record<string, unknown>
}

type AgreementDocument = {
  agreementVersion: "1"
  jobId: string
  listingRef: {
    listingId: string
    version: number
    contentHash: string              // pinned listing content hash
  }
  parties: AgreementParty[]
  terms: AgreementTerms
  derivedFromPattern: "fixed-price" | "rfq" | "sealed-envelope"
  derivedFromChannel?: {
    subnet: string
    lastMessageHash: string
  }
  generatedAt: number
  signatures: AgreementSignature[]
}

type PayeeBoundAgreementDocument = {
  payeeBoundAgreementVersion: "1"
  jobId: string
  listingRef: {
    listingId: string
    version: number
    contentHash: string              // pinned listing content hash
  }
  parties: AgreementParty[]
  terms: PayeeBoundAgreementTerms
  derivedFromPattern: "fixed-price" | "rfq" | "sealed-envelope"
  derivedFromChannel?: {
    subnet: string
    lastMessageHash: string
  }
  generatedAt: number
  signatures: AgreementSignature[]
}

type SealedSelectionAgreementDocument = {
  sealedSelectionAgreementVersion: "1"
  jobId: string
  listingRef: {
    listingId: string
    version: number
    contentHash: string
  }
  parties: AgreementParty[]
  terms: PayeeBoundAgreementTerms
  derivedFromPattern: "sealed-envelope"
  selectionReceiptRef: AttestationRef       // exact finalized SealedSelectionReceipt required by SAC-8
  derivedFromChannel?: {
    subnet: string
    lastMessageHash: string
  }
  generatedAt: number
  signatures: AgreementSignature[]
}

type AgreementArtifact = AgreementDocument | PayeeBoundAgreementDocument | SealedSelectionAgreementDocument

type AgreementParty = {

  role: "buyer" | "seller" | "bidder-non-winning"

  bundleHash: string                   // sha256 of the post-Vet IdentityBundle

  primaryClaim: ClaimReference         // pulled from bundle.presentedBy

  vetRecordRef: AttestationRef         // DACS-2 composite verification record

  encryptionKey?: string               // optional party encryption public key; binds which key an encrypt-to-buyer deliverable is sealed to (DACS-4 §9.6.1, DV-3). Distinct from the signing key.

}

type PayoutBinding = {

  railId: string                       // with phaseIndex, the §9.5.1/PC-2 phase-anchor key

  phaseIndex: number                   // one entry per phase invocation, so PIPE-5 repeats carry distinct destinations deterministically

  payeeAddress: string                 // the rail-specific destination the payee binds by co-signing

}

// Optional: competitive context for best-execution audit.

type CompetitiveContext = {

  pattern: "rfq" | "sealed-envelope"

  receivedQuotes: Array<{

    fromParty: ClaimReference

    quoteHash: string                  // hash of the losing quote contents

    quoteRef?: AttestationRef

  }>

}

// AgreementArtifact.terms.additionalTerms MAY include "competitiveContext: CompetitiveContext".

// Optional: SR-3-attested reference price snapshot included in the agreement for audit purposes.
// Both parties sign the AgreementArtifact (including priceAnchor when present), so the snapshot
// becomes part of the agreement's content hash and cannot be altered after commitment.
//
// priceAnchor does NOT constrain terms.price — the agreed price may differ from the snapshot
// (e.g. due to negotiation, markup, or discount). Its purpose is to provide an auditable,
// consensus-backed reference point for price-discovery analysis and dispute context.

type PriceAnchor = {

  // The asset whose price is being snapshotted (e.g. "BTC", "ETH", "SOL").
  asset: string

  // The currency in which the price is expressed (e.g. "USD", "USDC").
  quoteCurrency: string

  // The price at snapshot time, in CD-1 canonical decimal form.
  price: string

  // The SR-3 DAHR attestation that produced this price snapshot.
  // attestationRef.anchor points to the on-chain commitment of the fetch;
  // attestationRef.contentHash is sha256 of the raw response body bytes.
  attestationRef: AttestationRef

  // The unix ms timestamp at which the SR-3 fetch was performed.
  // SHOULD match the timestamp in the DAHR on-chain commitment record.
  observedAt: number

  // The URL template used to fetch the price (e.g. exchange API endpoint).
  // Included so consumers can independently verify the data source.
  sourceUrl: string

}

type AgreementSignature = {

  party: ClaimReference

  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"

  value: string                        // unpadded Base64URL (CORE §B.7 SIG-6) over the artifact's domain-separated agreement hash

}
```

An artifact MUST carry exactly one of `agreementVersion`, `payeeBoundAgreementVersion`, and `sealedSelectionAgreementVersion`; carrying more than one or none is invalid. `AgreementDocument` MUST NOT carry `terms.payoutBindings`, `terms.priorPaymentDispositionRef`, or `selectionReceiptRef`. `PayeeBoundAgreementDocument` MUST NOT carry `selectionReceiptRef`. `PayeeBoundAgreementDocument.terms.payoutBindings` and `SealedSelectionAgreementDocument.terms.payoutBindings` are REQUIRED and MUST contain exactly one entry for every concrete payment invocation in the pinned listing's DACS-4 effective pipeline, and no entry for any other invocation; the array is empty only for a zero-pay pipeline. For an ordinary listing that effective pipeline is the signed pipeline unchanged; for `pay-alternative`, APR-4 places the selected concrete handler at the projection phase's original index. Each entry's `railId` MUST equal that concrete phase's `parameters.rail`; `phaseIndex` is its bare-integer pipeline index (`BundlePhaseEntry.index`, §9.5.1 PC-2). The `(railId, phaseIndex)` key MUST be unique. `priorPaymentDispositionRef`, when present, is action-bearing signed replacement metadata and MUST satisfy APR-6 before the new Agreement is committed or authorized; it is not an informational `additionalTerms` value. A `SealedSelectionAgreementDocument` additionally MUST carry the exact top-level `selectionReceiptRef` required by SAC-8. These rules place every payment destination, replacement claim, and complete selection result under every party signature and the agreement hash, while keeping both earlier artifact types' meanings unchanged.

#### 8.5.1 Canonical serialisation and signature

Each artifact follows the §B.2 canonical-form template, omitting the `signatures` field. Each `AgreementSignature.value` is computed over the payload selected by the required version discriminator:

| Artifact | Signed bytes |
| --- | --- |
| `AgreementDocument` | `"dacs-agreement:v1:" || agreement_hash` |
| `PayeeBoundAgreementDocument` | `"dacs-payee-bound-agreement:v1:" || agreement_hash` |
| `SealedSelectionAgreementDocument` | `"dacs-sealed-selection-agreement:v1:" || agreement_hash` |

Every DACS-3 signature-envelope `value`, including channel-message, agreement,
commitment, and transcript signatures, MUST use CORE §B.7 SIG-6.

A verifier MUST select the artifact schema and signing domain before interpreting `terms`. It MUST reject an artifact carrying more than one supported version discriminator or none, and MUST NOT strip an unknown discriminator and retry verification as another artifact type.

**Decimal amounts (CD-1).** Every `PriceTerm.amount` is in minimal-digit canonical decimal form per **rule CD-1 (CORE §B.2)** — producers canonicalise before the agreement hash, verifiers before the §8.5.2 price-band and price-equality comparisons.

**Verification & required signers.** Verifiers MUST recompute the canonical form, agreement hash, and domain-separated payload, and for each required party, resolve the primary claim’s key (per DACS-2 verification) and verify the signature. Required signers by pattern:

| Pattern | Required signers |
| --- | --- |
| negotiate-fixed-price | buyer + seller (the seller signature may be an auto-accept instance signature per §8.4.1) |
| negotiate-rfq | buyer + seller |
| negotiate-sealed-envelope / negotiate-sealed-envelope-procurement | agreement buyer + agreement seller after SE-8 role assignment (equivalently, listing publisher + winning bidder; non-winning bidders’ signatures are not required) |
| negotiate-sealed-envelope-complete / negotiate-sealed-envelope-procurement-complete | agreement buyer + agreement seller after SAC-9 role assignment (equivalently, listing publisher + receipt-proven winner; non-winning bidders’ signatures are not required) |

**`priceAnchor` canonical-form note.** `priceAnchor` is optional and **non-normative for agreement validity** — informational only. When present:

- it is included in the JCS canonical form (the same as any other field in `terms`) and is therefore covered by both parties’ signatures, and its `priceAnchor.price` MUST be in CD-1 canonical decimal form;
- **tolerance** — a verifier that does not understand `priceAnchor` MUST NOT reject the agreement on that basis, and its absence MUST NOT cause rejection;
- **audit use (conditional)** — when a consumer *does* use `priceAnchor` for audit, it MUST resolve `priceAnchor.attestationRef` to a valid SR-3 attestation and confirm `attestationRef.contentHash` equals sha256 of the raw response body.

#### 8.5.2 Listing conformance validation

A verifier MUST validate the agreement against its referenced listing — checked in order:

1. **Currency** — `terms.price.currency` MUST equal the listing pricing currency (negotiable pricing → `bandCenter.currency`; fixed pricing → the listed price currency; metered pricing → `unitPrice.currency`). A band or equality comparison across differing currencies MUST be rejected **before any amount comparison**.
2. **Price within band** — first, if the pinned listing's `PricingSpec.kind` is not one this reader recognizes, commit-agreement MUST reject with a recorded `unrecognized-pricing-kind` reason (rule MTR-5) and MUST NOT accept an agreement whose price it validated against no recognized pricing model — the fail-closed instance for the pricing union, the same discipline as check 8's `unresolvable-auctionMode`. Otherwise `terms.price` MUST satisfy the recognized kind:
   - *Negotiable pricing* — within the band declared by the negotiable variant's `minPct` / `maxPct` (non-negative percentages) around `bandCenter`. The admissible band is the **inclusive** interval [`bandCenter.amount × (100 − minPct) / 100`, `bandCenter.amount × (100 + maxPct) / 100`]. Each computed bound MUST be **rounded half-up to the number of fractional digits of `bandCenter.amount` in its CD-1 canonical form** (CORE §B.2) — NOT to any "currency precision", which is undefined at listing time (settlement precision is tied to `rail.asset.decimals`, not the listing currency) — then canonicalised per CD-1. `terms.price.amount`, compared as a full-precision CD-1 decimal, MUST be ≥ the lower bound and ≤ the upper bound (boundaries inclusive). A verifier MUST reject the listing if the computed lower bound is ≤ 0.
   - *fixed-price over negotiable pricing* — if `derivedFromPattern == "fixed-price"`, `terms.price` MUST instead equal `bandCenter` exactly per CD-1, not merely lie within the band (see PS-3).
   - *Fixed pricing* — equal to the listed price.
   - *Metered pricing* — `terms.meteredQuantity` MUST be present, `terms.meteredQuantity.unit` MUST equal the metered variant's `unit`, and `terms.price` MUST equal `max(minTotal ?? 0, unitPrice.amount × quantity)` in CD-1 canonical form, where `quantity = terms.meteredQuantity.quantity` (rules MTR-1..4). If `terms.meteredQuantity` is absent or its `unit` mismatches, commit-agreement MUST reject.
3. **Rail** — `terms.rail` MUST be present if and only if the listing pipeline contains a concrete `PaymentPhaseType` or `pay-alternative` phase (PIPE-1, §9.5). For an ordinary concrete phase it MUST appear in `listing.acceptedRails` under the existing complete-reference comparison. For `pay-alternative`, it MUST full-canonical-value match exactly one signed `parameters.alternatives` member under APR-3; matching only `railId`, `railVersion`, or array position is insufficient. For a zero-pay (intake-only / settled-out-of-band) pipeline, `terms.rail` MUST be absent.
4. **Deliverable** — `terms.deliverable` MUST conform to the listing’s `offering.deliverable`: `terms.deliverable.deliverableType` MUST equal the listing `offering.deliverable` kind; `terms.deliverable.hash` MUST equal the canonical `DeliverableRef.hash` of the listing’s `offering.deliverable` (per §9.3); `terms.deliverable.schemaUrl` MUST equal the listing `offering.deliverable.schemaUrl` (both absent, or both present and equal).
5. **Deadline** — `terms.deadline` MUST be ≤ `committedAt + listing.terms.deadlineSecAfterCommit`. For a new `FinalityCommitmentRecord`, `committedAt` is the consensus timestamp in its finalized CORE §5.1 `AnchorReceipt` (§8.6); for a legacy `CommitmentRecord`, it is the signed legacy field after CA-8 cross-checks it against authenticated historical anchor time. This is the same objective, substrate-determined clock SE-2 uses — NOT the finality record's signed `createdAt` or the agreement's self-reported `generatedAt`, either of which a party could backdate to widen the settle window.
6. **Not expired** — the listing's `validity.notAfter` (if set) MUST be ≥ `committedAt`; the listing MUST NOT have expired between read and its agreement commitment phase (the §6.3.4 step-3 read-time check governs discovery; this re-check governs commit, closing the read-to-commit interval).
7. **Pattern** — `derivedFromPattern` MUST match the listing's pipeline-declared negotiation phase after mapping phase kind to agreement pattern: `negotiate-fixed-price` → `"fixed-price"`, `negotiate-rfq` → `"rfq"`, and all four historical/complete sealed-envelope phase kinds → `"sealed-envelope"`.
8. **Sealed-envelope role direction** — for `derivedFromPattern == "sealed-envelope"`, the agreement party roles and `terms.price` direction MUST match the pinned listing's sealed-envelope phase kind per SE-8 or SAC-9. If `auctionMode` is required but missing, or present but unresolvable/malformed, validation MUST reject with a recorded `unresolvable-auctionMode` reason. If the roles are inverted relative to the pinned mode, validation MUST reject before Settle. A complete phase additionally MUST resolve and reproduce `selectionReceiptRef` under SAC-8; a historical phase MUST NOT be relabelled complete by attaching that field.
9. **Artifact/commit-phase match** — `commit-agreement` MUST reference an `AgreementDocument`; `commit-payee-bound-agreement` MUST reference a `PayeeBoundAgreementDocument`; and `commit-selection-bound-agreement` MUST reference a `SealedSelectionAgreementDocument` whose receipt satisfies SAC-8. Both payout-bearing types MUST satisfy the exact effective-pipeline coverage rules in §8.5 and APR-5. Any mismatch, missing entry/reference, duplicate key, wrong railId/index, extra entry, or cross-type coercion MUST be rejected before Settle.
10. **Claimed replacement** — `terms.priorPaymentDispositionRef` MUST be absent unless this is a fresh-job replacement under a `pay-alternative` Listing. When present, the commitment handler MUST complete APR-6 disposition resolution, signature/writer/finality verification, exact prior Agreement/selection/index binding, exact `replacementJobId` equality with this Agreement's `jobId`, and closed-state proof checks before accepting the new Agreement. An unavailable otherwise-consistent disposition is `indeterminate`; an open, malformed, mismatched, reused-for-another-job, or disproven disposition rejects and permits zero replacement-rail authorization calls.

Checks 5 and 6 are the two `committedAt`-relative checks — see the ordering note below. Agreements failing any check MUST be rejected by the declared agreement commitment phase.

For a `pay-alternative` listing, checks 3 and 9 MUST recompute APR-3/APR-4 from the verified signed Listing, the Agreement bytes being verified, and the authenticated session-start rail definition; check 10 applies whenever a replacement is claimed. A caller-supplied projected phase, cached handler name, or unsigned prior-payment state is not agreement authority. The projection, payout, and replacement checks run before either Agreement signature is accepted and before the commitment handler can produce a commitment record.

**Metered pricing (MTR-1..5).** The `metered` `PricingSpec` variant (DACS-4) prices per unit of measured usage; its total is fixed only once the quantity is known, so it is computed into `terms.price` at commit and validated by check 2's metered arm.

- **(MTR-1)** `unitPrice.currency` defines the metered listing's pricing currency; `terms.price.currency` MUST equal it (check 1).
- **(MTR-2)** if `minTotal` is present, `minTotal.currency` MUST equal `unitPrice.currency`.
- **(MTR-3)** `unit` MUST be a non-empty label.
- **(MTR-4)** for a metered listing, `terms.price` MUST equal `max(minTotal ?? 0, unitPrice.amount × quantity)` in CD-1 canonical form, where `quantity = terms.meteredQuantity.quantity` is a **non-negative integer** count of whole `unit`s. The quantity string MUST use the canonical unsigned-decimal form `"0"` or `[1-9][0-9]*`; a sign, leading zero, decimal point, or exponent MUST be rejected. Where the raw job measurement is not a whole number of units, `quantity` MUST be rounded **up** (ceil) to the next whole unit, so two implementations derive the same quantity from the same job. `unitPrice.amount × quantity` is exact (a CD-1 decimal times a non-negative integer; no rounding in the product). To avoid an agreement that passes commit-agreement but cannot settle because its exact total exceeds a selected rail's asset precision (§9.13), a metered listing SHOULD express `unitPrice.amount` and `minTotal.amount` (when present) at a precision supported by every rail in `acceptedRails`. MTR-4 binds `terms.price` to the *declared* quantity; the binding of the declared quantity to the *actual* job is the buyer's computation co-signed by the seller — a co-signed assertion, dispute-visible via the deliverable, **not** a measurement-correctness proof.
- **(MTR-5)** a transacting reader MUST reject an agreement at commit-agreement whose pinned listing carries an unrecognized `PricingSpec.kind`, with a recorded `unrecognized-pricing-kind` reason (check 2). A pre-metered reader already refuses `kind: "metered"` at the DACS-1 §6.3.4 schema-conformance step because `PricingSpec` is a closed discriminated union. MTR-5 independently prevents commit-agreement from treating an unrecognized kind as a vacuous pass and supplies the executable fail-closed guard for later pricing-kind additions. Together, the listing gate and commit gate ensure that a reader refuses a kind it cannot price rather than accepting an amount it validated against nothing (§11.1.2).

**Ordering of the `committedAt`-relative checks.** For a newly produced `FinalityCommitmentRecord`, checks 5 and 6 reference the consensus timestamp in its finalized SR-2 receipt (§8.6), which only exists *after* the signed record is submitted. The checks therefore run in two phases:

- **Pre-anchor (§8.6 step 3).** The value-independent checks — currency, price-band, rail, deliverable, pattern, sealed-envelope role direction, and artifact/commit-phase match — gate here. The orchestrator also runs a *provisional* check of the deadline and `notAfter` against the current clock.
- **Post-finality (authoritative).** Once the finality commitment is finalized, the orchestrator MUST derive `committedAt` from `AnchorReceipt.blockRef.timestamp` and re-evaluate checks 5 and 6. Any consumer/verifier reading that type MUST likewise derive and check the value from the verified receipt; it MUST NOT accept a party- or orchestrator-supplied timestamp as `committedAt`. Historical legacy records follow the CA-8 legacy arm instead.

A finality commitment whose receipt-derived `committedAt`, or a legacy commitment whose CA-8-verified signed `committedAt`, violates either check is invalid.

> **Note (non-normative).** The new type's separation of signed `createdAt` from receipt-derived `committedAt` removes the former circularity without mutating the frozen legacy type. The §6.3.4 read-time check still governs discovery.

#### 8.5.3 Fee disclosure (`feeSchedule`)

An `AgreementArtifact` MAY carry a `terms.feeSchedule` — an optional, signed pre-commit disclosure of the fee structure, for regulated-context cost transparency. It is **disclosure-only**: both parties sign it with the agreement, but it does **not** alter `terms.price` and a consumer **MUST NOT** gate settlement on it. It is the non-repudiable record that fees were disclosed before commit.

```
type FeeSchedule = {
  priceBasis: "inclusive" | "exclusive"     // REQUIRED when feeSchedule present: is terms.price all-in, or are fees added on top?
  items: FeeItem[]
  oneOffTotal: PriceTerm                     // sum of the non-recurring items; currency MUST equal terms.price.currency
  recurringTotal?: PriceTerm                 // sum of recurring items' per-period amounts; present iff any item carries recurrence
  minimumTermSeconds?: number                // subscription minimum commitment (disclosure)
  earlyTerminationFee?: FeeItem              // disclosure shape only; fee-bearing-cancellation semantics are governed by §10.3.1, not here
  disclosureNote?: string                    // optional free-text / regulatory-basis citation
}
type FeeItem = {
  kind: "network" | "platform" | "processing" | "spread" | "subscription" | "other"
  collector: ClaimReference | "substrate"    // who collects this fee; "substrate" for a network (validator) fee
  label?: string
  fixed?: PriceTerm                           // exactly one of { fixed, rateBps }
  rateBps?: number                            // basis points of terms.price.amount; resolved to an amount per DACS-4 §9.7.2
  toleranceBps?: number                       // network-fee reconciliation tolerance (§9.7.2); meaningful only for kind == "network"; absent ⇒ reconcile exactly
  recurrence?: {                              // present iff this is an ongoing/recurring fee — disclosure only, never a charge trigger
    period: "daily" | "weekly" | "monthly" | "quarterly" | "annual" | { everySeconds: number }
    count?: number                            // fixed number of charges; omit for open-ended
    until?: number                            // unix ms end bound (alternative to count)
  }
}
```

Normative:
- (FS-1) When `feeSchedule` is present, `priceBasis` is REQUIRED, and `oneOffTotal.currency` MUST equal `terms.price.currency`.
- (FS-2) Each `FeeItem` MUST carry **exactly one** of `fixed` / `rateBps`.
- (FS-3) `feeSchedule` is disclosure-only: it MUST NOT alter `terms.price`, and a consumer MUST NOT gate settlement on it. Whether the disclosed fees reconcile against actual settlement is an **informational** check defined in DACS-4 §9.7.2.
- (FS-4) A `recurrence` block **discloses a committed ongoing cost** — it MUST NOT be read as a charge trigger and MUST NOT appear in any settlement-gating path. Recurring *settlement* is out of scope here (modelled as a sequence of correlated sessions; see the streaming/subscription roadmap item).
- (FS-5) `earlyTerminationFee` is a disclosure shape only; the semantics of a fee-bearing cancellation are governed by the §10.3.1 cancellation rules, not by this field.

### 8.6 Agreement commitment phases

The DACS-3 phases that anchor an agreement hash on the public chain are `commit-agreement` for the legacy artifact, `commit-payee-bound-agreement` for the payee-bound artifact, and `commit-selection-bound-agreement` for the complete sealed-envelope artifact. They share the procedure and commitment-record shape below, but their input schemas and context-delta keys are distinct.

```
type CommitAgreementInput = {
  jobId: string
  agreement: AgreementDocument
  listingRef: { listingId: string; version: number; contentHash: string }
  sessionContext: SessionContext
}
type CommitAgreementOutput = PhaseHandlerResult & {
  contextDelta: {
    "commit-agreement": {
      agreementHash: string
      anchorTxRef: TxRef
      anchorReceipt: AnchorReceipt
      committedAt: number
    }
  }
}

type CommitPayeeBoundAgreementInput = {
  jobId: string
  agreement: PayeeBoundAgreementDocument
  listingRef: { listingId: string; version: number; contentHash: string }
  sessionContext: SessionContext
}
type CommitPayeeBoundAgreementOutput = PhaseHandlerResult & {
  contextDelta: {
    "commit-payee-bound-agreement": {
      agreementHash: string
      anchorTxRef: TxRef
      anchorReceipt: AnchorReceipt
      committedAt: number
    }
  }
}

type CommitSelectionBoundAgreementInput = {
  jobId: string
  agreement: SealedSelectionAgreementDocument
  listingRef: { listingId: string; version: number; contentHash: string }
  sessionContext: SessionContext
}
type CommitSelectionBoundAgreementOutput = PhaseHandlerResult & {
  contextDelta: {
    "commit-selection-bound-agreement": {
      agreementHash: string
      selectionReceiptRef: AttestationRef
      anchorTxRef: TxRef
      anchorReceipt: AnchorReceipt
      committedAt: number
    }
  }
}
```

**Procedure.** The applicable commitment handler MUST:

1. require the artifact selected by the phase kind (`AgreementDocument` for `commit-agreement`; `PayeeBoundAgreementDocument` for `commit-payee-bound-agreement`; `SealedSelectionAgreementDocument` for `commit-selection-bound-agreement`), then compute `agreementHash = sha256(canonical_JCS(agreement))` with signatures omitted;
2. verify all required signatures are present and valid;
3. validate the agreement against the listing per §8.5.2. The **value checks** (currency / band / rail / deliverable / pattern) gate **here**; the two **`committedAt`-relative checks** (deadline, `notAfter`) are re-evaluated against the finalized receipt timestamp after step 6, per the §8.5.2 ordering note. Any validation failure MUST cause the phase to fail with class `permanent`;
4. construct a `FinalityCommitmentRecord`. The earlier `CommitmentRecord` remains a read-only legacy artifact so historical sessions stay verifiable:

```
// Legacy artifact produced by DACS-3 v0.1-v0.3. New producers MUST NOT emit it.
type CommitmentRecord = {
  dacsVersion: "1"
  jobId: string
  agreementHash: string
  listingRef: { listingId: string; version: number; contentHash: string }
  parties: ClaimReference[]          // primary claims of signing parties
  pattern: "fixed-price" | "rfq" | "sealed-envelope"
  committedAt: number                // legacy signed field; validated against the historical anchor
}

// Additive new artifact introduced by DACS-3 v0.4.
type FinalityCommitmentRecord = {
  finalityCommitmentVersion: "1"     // structural discriminator; mutually exclusive with dacsVersion
  jobId: string
  agreementHash: string
  listingRef: { listingId: string; version: number; contentHash: string }
  parties: ClaimReference[]          // primary claims of signing parties
  pattern: "fixed-price" | "rfq" | "sealed-envelope"
  createdAt: number                  // unix ms; record-construction time, inside the signed scope
  signature: {
    algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"
    signer: ClaimReference            // authenticated session orchestrator
    value: string                     // unpadded Base64URL, CORE §B.7 SIG-6
  }
}

type AgreementCommitmentRecord = CommitmentRecord | FinalityCommitmentRecord
```

5. set `createdAt`, sign the new record over the domain-separated payload `"dacs-finality-commitment:v1:" || sha256(canonical_JCS(finalityCommitmentRecord_without_signature))`, and submit it via SR-2 at logical address `dacs3:commit:{jobId}`;
6. wait for and verify a CORE §5.1 `finalized` `AnchorReceipt` binding that logical address, the native address, record content hash, transaction, writer, and nonce; derive `committedAt` exclusively from `anchorReceipt.blockRef.timestamp`; then run the authoritative §8.5.2 checks 5 and 6. If the binding's finality profile declares inclusion final, one receipt MAY establish `included` and `finalized`;
7. return `agreementHash`, `anchorTxRef`, `anchorReceipt`, and receipt-derived `committedAt` under the executing phase's context-delta key, also returning the exact `selectionReceiptRef` for `commit-selection-bound-agreement`. A handler MUST NOT return `ok: true` when finality or the authoritative checks remain pending.

**Conformance.**

- (CA-1) The orchestrator MUST NOT advance to any DACS-4 payment, value release, or irreversible delivery until the listing's declared agreement commitment phase returns `ok: true` with a verified `finalized` `anchorReceipt`. Signatures alone permit commitment submission, not irreversible effects.
- (CA-2) Commitment records MUST be anchored on the public chain (not in a private channel).
- (CA-3) Once either commitment-record type is anchored, its canonical record content is immutable for that `jobId`. A re-commitment that changes that content—including an attempt to replace a legacy record with a finality record or vice versa—MUST be rejected. This does not prohibit CORE §5.1 replacement of the **carrying native transaction** when the replacement carries byte-identical canonical record content at the same logical address and the replacement receipt is independently verified.
- (CA-4) The agreement artifact itself MAY be anchored separately (publicly or privately). For institutional flows, the agreement artifact is typically NOT anchored on the public chain — only its hash is. Parties retain the agreement artifact off-chain (or encrypted-anchored).
- (CA-5) A commitment handler MUST reject either other phase's artifact type before signature or listing-term interpretation. It MUST NOT coerce among `AgreementDocument`, `PayeeBoundAgreementDocument`, and `SealedSelectionAgreementDocument` by dropping an unknown version discriminator, `terms.payoutBindings`, or `selectionReceiptRef`.
- (CA-6) **Commitment authority.** The authenticated session orchestrator is the protocol authority for the commitment phase. For a `FinalityCommitmentRecord`, a consumer MUST verify the embedded step 5 signature under `"dacs-finality-commitment:v1:"` against that orchestrator's primary claim. For a legacy `CommitmentRecord`, it MUST verify the historical external/carried signature under `"dacs-commitment:v1:"`. The SR-2 transaction submitter, deployer, owner, and native address MUST NOT establish agreement authority or a buyer/seller role.
- (CA-7) **Agreement binding.** A consumer MUST verify the agreement's required party signatures, recompute `agreementHash`, and match it to the applicable `AgreementCommitmentRecord`. When CA-4 is used, the separate agreement anchor's deployer, owner, and native address MUST NOT affect acceptance.
- (CA-8) **Timestamp separation.** `FinalityCommitmentRecord.createdAt` is signed construction metadata. Its authoritative `committedAt` is not a record field: it is the consensus timestamp of the verified finalized receipt. A consumer MUST reject a finality-commitment flow that substitutes `createdAt`, `observedAt`, an RPC response time, or an indexer timestamp for `committedAt`. When consuming a legacy `CommitmentRecord`, a new reader MUST verify that its signed `committedAt` equals the authenticated historical anchor timestamp; mismatch is rejected.
- (CA-9) **Minor-safe type distinction.** A producer conforming to DACS-3 v0.4 or later MUST emit `FinalityCommitmentRecord`, never the legacy type. A reader MUST select the commitment-record type before signature or timestamp interpretation: exactly one of `dacsVersion: "1"` or `finalityCommitmentVersion: "1"` MUST be present. Both, neither, or an unsupported discriminator MUST be rejected. Independently, it MUST select exactly one of the three agreement discriminators and require the matching commitment phase before interpreting terms. A reader MUST NOT coerce types by dropping `committedAt`, `createdAt`, `signature`, payout/selection bindings, or a discriminator. Readers that do not implement a new type safely reject it as unsupported under CORE §11.1.2.

> **Note (non-normative).** The orchestrator is accountable for causing the commitment phase to anchor successfully. It need not be the raw substrate key recorded as a StorageProgram deployer or owner. A buyer- or seller-submitted transaction therefore does not change which parties authored the agreement; their agreement signatures and the committed hash establish that fact.

### 8.7 Channel transcript and disclosure

Negotiation channels produce a transcript: the ordered sequence of signed messages between participants. The transcript is private to channel members. When a transcript is anchored (see disclosure policies below), its signature is computed over the domain-separated payload "dacs-transcript:v1:" || sha256(canonical_JCS(transcript_without_signatures)) per §B.7.

```
type ChannelTranscript = {
  transcriptVersion: "1"
  channelId: string
  members: ClaimReference[]
  messages: ChannelMessage[]
  generatedAt: number
  signatures: TranscriptSignature[]
}
```

**Default disclosure: none.** By default, the transcript is not anchored on the public chain. Only the agreement hash (via the applicable agreement commitment phase) is public. The DACS-1 listing’s terms.transcriptDisclosurePolicy controls this per-listing:

- "none" (default) — transcripts stay in the channel; no anchoring required.
- "encrypted-anchored-recommended" — orchestrators SHOULD anchor transcripts encrypted to channel members; not required.
- "encrypted-anchored-required" — orchestrators MUST anchor encrypted transcripts; absence of transcript anchor MUST fail the phase. Recommended for sessions whose counterparty is a regulated entity that may be subject to subpoena.

If all channel members consent, the transcript MAY be encrypted to the member set and anchored via SR-2. The AgreementArtifact.derivedFromChannel.lastMessageHash provides a verifiable hook from the public agreement to the (private) transcript. A future DACS standard (proposed DACS-X dispute) MAY require selective transcript disclosure under signed party agreement or arbitrator order. v0.1 does not specify dispute resolution; parties intending to support dispute SHOULD anchor encrypted transcripts at agreement time so disclosure is technically possible later.

### 8.8 Pattern selection by listing

A DACS-1 listing’s pipeline declares which negotiation pattern is used. Each PhaseStep of kind negotiate-* specifies the pattern and its parameters.

**Validation.**

- (PS-1) A pipeline MUST contain exactly one negotiate-* phase.
- (PS-2) A pipeline MUST contain exactly one agreement commitment phase — `commit-agreement`, `commit-payee-bound-agreement`, or `commit-selection-bound-agreement` — immediately following the negotiate-* phase. A complete sealed phase MUST use `commit-selection-bound-agreement`; that commitment phase MUST NOT follow fixed-price, RFQ, or a historical sealed phase.
- (PS-3) The listing’s pricing model MUST be compatible with the chosen pattern: negotiate-fixed-price MUST be fixed, negotiable (in which case fixed-price uses the band’s centre), or metered (the rate is fixed and units are measured, so the total is deterministic and acceptance is the negotiation); negotiate-rfq MUST be negotiable or metered; all historical and complete sealed-envelope phase kinds MUST be auction. A metered listing MUST therefore use negotiate-fixed-price or negotiate-rfq.

**Fallback to fixed-price.** A listing offering negotiate-rfq MAY declare fixedPriceFallback: true in the pipeline step. When true, a buyer that does not wish to negotiate MAY signal acceptance of the listed centre-price via negotiate-fixed-price. The orchestrator selects which pattern runs based on buyer signal. The fallback path produces the artifact selected by the listing's agreement commitment phase with derivedFromPattern: "fixed-price".

**Multi-quote RFQ (deferred to v0.2).** The v0.1 negotiate-rfq phase is bilateral (one buyer, one seller). Real institutional RFQ is often one-to-many — a buyer queries N liquidity providers, collects quotes, picks one. v0.1 does not support multi-quote RFQ directly; the closest pattern is negotiate-sealed-envelope with selectionRule: first-acceptable or lowest-price. A first-class negotiate-multi-quote phase is anticipated for v0.2.

### 8.9 Conformance summary

| Role | Requirements |
| --- | --- |
| Channel implementation | CH-1 through CH-6; message envelope; failure detection |
| negotiate-fixed-price | §8.4.1 procedure; signature collection; SR-2 anchoring |
| negotiate-rfq | §8.4.2 procedure; RFQ-1 through RFQ-4; channel turn timeouts |
| negotiate-sealed-envelope / negotiate-sealed-envelope-procurement | §8.4.3 procedure; SE-1 through SE-9; deterministic selection; rule-ref content-hash binding; mode-bound role assignment; same-bidder commit authority |
| complete sealed-envelope phases | §8.4.4 SAC-1 through SAC-10; authenticated current complete set; typed bidder records; built-in deterministic price selection; reproducible selection receipt; selection-bound agreement |
| all three agreement commitment phases | CA-1 through CA-9; artifact-specific signature, finalized receipt, timestamp separation, minor-safe type distinction, and conformance validation |
| Listing publisher | PS-1 through PS-3 |
| Substrate without SR-4 | MUST support negotiate-fixed-price; MUST refuse RFQ and every sealed-envelope phase with a clear substrate-capability-missing error |
| Substrate without a SAC-3 candidate-set binding | MUST refuse both complete sealed-envelope phases; MUST NOT fall back to a historical sealed phase while claiming completeness |

### 8.10 Rationale

**Three patterns vs more/fewer/open.** Three is the smallest set covering the demonstrated surface: fixed-price (micropayments, SaaS), RFQ (institutional bilateral), sealed-envelope (sealed-bid procurement). Open registries lose conformance testability; more patterns (english/dutch auction, multi-round delta-RFQ) are deferred to v2.

**Closed pattern set vs open.** A closed set lets every conforming orchestrator handle every conforming listing; an open set lets listings declare unsupported patterns — fragmentation by design.

**Common agreement terms across patterns.** Settle and Verify consume agreements regardless of how negotiated, so both agreement artifact types share the same pattern-agnostic terms; pattern-specific data lives in `additionalTerms` / optional fields. The separate payee-bound artifact exists only to make the action-bearing destination contract structurally rejectable by legacy readers.

**Transcript private by default vs anchored-encrypted.** Default-anchoring transcripts is expensive and adoption-hostile (operators won't anchor negotiation history, even encrypted). Default-private with opt-in anchoring matches institutional practice; regulated flows opt in.

**Agreement commitment as a separate phase.** A separate phase makes the on-chain commitment visible in the pipeline, lets the orchestrator validate signature/conformance before binding, and gives Settle/Verify a clear hook; implicit commitment hides the binding moment and complicates recovery. Distinct legacy and payee-bound phase kinds also give older listing readers a structural refusal point.

**SR-4 abstract, not a fixed realisation.** Substrates may realise it via private subnets (Demos), TEEs, permissioned channels, or zk-confidential channels; DACS-3 specifies the abstract capability and per-pattern requirements, not a winner.

**Sealed-envelope: commit before public opening.** The on-chain commit hash prevents back-dating/repudiation and keeps the bid confidential before the deadline. The later signed public opening makes timeliness, candidate completeness, and winner reproduction independently auditable. This profile prioritizes verifiable fair selection over post-award secrecy of losing bids; a future zero-knowledge selection profile would require a distinct proof system and phase type.

### 8.11 Backwards compatibility

**Commitment records.** DACS-3 v0.4 adds `FinalityCommitmentRecord` as a distinct artifact type; it does not mutate the v0.1-v0.3 `CommitmentRecord`. New producers emit only the finality type. New readers retain the legacy validation arm for historical audit, including the `"dacs-commitment:v1:"` signature and the cross-check between its signed `committedAt` and authenticated historical anchor time. Legacy readers encounter `finalityCommitmentVersion` instead of `dacsVersion` and reject the unsupported type before acting, as required by CA-9 and CORE §11.1.2.

**Complete sealed-envelope selection.** DACS-3 v0.6 does not retrofit completeness into the historical `negotiate-sealed-envelope` phase or either earlier agreement type. It adds two negotiation phase kinds, one agreement type, one commitment phase, typed bidder records, and a selection receipt. An older reader rejects the unknown phase/type before action. Historical auctions remain reproducible only to the extent of the records their released semantics supplied and MUST NOT be relabelled SAC-complete. New publishers requiring omission resistance use the complete profile; this is additive new-type refusal, not an optional action-bearing field.

**Institutional RFQ workflows.** A negotiate-rfq run maps to existing bilateral RFQ as a Bloomberg-chat RFQ maps to a Symphony RFQ: same semantic shape, different transport (the SR-4 channel). Existing desks wrap their negotiation logic as a DACS-3 phase without changing it.

**Sealed-bid government procurement.** negotiate-sealed-envelope-procurement covers FAR Part 14's commit-then-reveal with cryptographic commitment (vs physical envelopes); the selection-rule abstraction (lowest-price / first-acceptable / rule-ref) covers FAR's "lowest responsive responsible bidder" and "best value". EU/UK equivalents map similarly.

**Off-chain negotiation systems.** An existing RFQ system / procurement portal / B2B negotiation tool MAY serve as the SR-4 channel provided it satisfies CH-1..CH-6; the public-chain binding and agreement shape are the only DACS-3 additions.

**ERC-8183 escrow.** A DACS-3 agreement whose `terms.rail` is an EVM rail MAY reference an ERC-8183 escrow as the settlement vehicle; the DACS-4 rail definition carries the contract address.

**Future patterns.** New patterns (auctions, multi-round delta-RFQ) are added via the DACS-3 version process — registering the phase-handler contract, parameters, and substrate requirements.

### 8.12 Security considerations

**Channel-operator censorship.** *Threat:* the SR-4 channel operator drops messages, preventing a party from responding within the timeout. *Mitigation:* CH-4 mandates liveness detection. Members observing missed deliveries (no acknowledgement from a quorum) MUST treat the channel as failed. On Demos, Private Negotiation provides per-message acknowledgements; equivalent SR-4 implementations on other substrates SHOULD do the same.

**Channel-operator forking.** *Threat:* the channel operator shows different views to different members, creating mutual misunderstanding. *Mitigation:* channel message envelopes carry monotonic sequence numbers and signatures; members SHOULD periodically exchange "current state" attestations and detect forks. SR-4 implementations are expected to provide a tamper-evident message log.

**Replay of offers across sessions.** *Threat:* an attacker captures a signed offer from session A and replays it in session B. *Mitigation:* the channel message envelope includes channelId and sequence (per-channel monotonic). This defence holds only if channelId is unique per session: **(CH-6) channelId MUST be unique per session** — the substrate MUST derive a per-session-unique channelId, and an orchestrator MUST reject a session that reuses a channelId from a prior session. (Without CH-6 the replay defence is vacuous: a reused channelId would let a session-A offer verify in session B.) Given CH-6, an offer replayed into a different channel fails signature verification because the channelId differs; replayed in the same channel it duplicates a sequence number and is rejected.

**Signature stripping or rebinding between channel and agreement.** *Threat:* an attacker takes a signature produced inside the channel and reuses it on a different agreement artifact. *Mitigation:* channel-message signatures are over the message envelope (including channelId); agreement-artifact signatures are over the artifact-specific domain and agreement hash (which includes jobId, listingRef, and all terms). The scopes are non-overlapping; neither a channel signature nor one agreement type's signature validates as the other agreement type.

**Sealed-envelope front-running.** *Threat:* a bidder learns competitors’ bids before reveal. *Mitigation:* *before reveal*, bids stay encrypted in the channel and only the bid hash is public; *at reveal*, openable `{bid, salt}` records are anchored publicly (§8.4.3 step 4 — intentional, so relay-suppression resistance and SE-3 timestamping work). The channel’s confidentiality ensures non-members cannot read pre-reveal bids; the cryptographic commitment ensures the bidder cannot change their bid after observing competitors at reveal time (the only residual move — delaying one's own reveal to read earlier ones — yields nothing actionable, since the delayer's bid is already committed). Operators SHOULD use SR-4 implementations with member-exclusive encryption.

**Sealed-envelope post-deadline submission.** *Threat:* a bidder submits a commit after commitDeadline, claiming clock skew. *Mitigation:* SE-2 mandates the commit’s public-chain anchor timestamp (objective, substrate-determined) be ≤ commitDeadline. Clock skew at the bidder is irrelevant; the chain decides the timestamp.

**Sealed-envelope same-bidder commit swapping.** *Threat:* one bidder anchors multiple in-window commitments and waits until reveal time to open whichever committed bid is then more favourable. Different implementations might also choose earliest, latest, or reject-all and derive different winners from the same anchored record set. *Mitigation:* SE-9 makes the earliest SR-2-anchored commit authoritative, uses ascending lowercase-hex `bidHash` as the same-anchor total-order limb, and makes every later same-bidder commit inert. A reveal opening only a later commit is excluded.

**Agreement-listing mismatch.** *Threat:* a signed agreement contains terms outside the listing’s pricing band or with an unaccepted rail. *Mitigation:* validation rules; the declared agreement commitment phase must reject. Both sides also SHOULD validate before signing.

**Unrecognized pricing kind vacuous-pass.** *Threat:* a listing carries a `PricingSpec.kind` a reader does not implement (a newer kind, or a malformed one); the reader skips the price check it has no arm for and accepts an agreement whose `terms.price` was validated against nothing, letting an arbitrary amount settle. *Mitigation:* DACS-1 schema conformance rejects a value outside the reader's closed `PricingSpec` union, and MTR-5 independently requires commit-agreement to reject an unrecognized pricing kind with a recorded `unrecognized-pricing-kind` reason before any settle. A pre-metered reader therefore refuses `metered` at listing validation; a reader implementing MTR-5 also fails closed at the transaction gate for later unknown kinds. The metered arithmetic threat (a total that does not match `unitPrice × quantity`) is caught by MTR-4's recompute.

**Multi-party signing race.** *Threat:* one party signs an agreement; before the other co-signs, the first party publicly commits and locks the other in. *Mitigation:* both agreement commitment phases require all required signatures present. A unilaterally-signed agreement fails CA. A future minor version MAY add pending-co-signature semantics for asynchronous flows; v0.1 requires synchronous signature collection.

**Public-chain timing analysis.** *Threat:* the pattern of commitment timestamps on the public chain reveals negotiation patterns. *Mitigation:* this is a fundamental property of any commit-on-chain protocol. Parties concerned with timing leak SHOULD use SR-4 channels with timing-padded delivery, anchor commitments at random intervals within a window, or settle through privacy-preserving rails. DACS-3 does not standardise timing obfuscation.

**Identity substitution between Vet and agreement signature.** *Threat:* a party’s bundle is verified in DACS-2 but they sign the agreement with a different key. *Mitigation:* AgreementSignature.party references the primary claim from the bundle. The signature key MUST be the one bound to that claim. Mismatches cause the agreement commitment phase to fail.

**Channel-membership exfiltration.** *Threat:* the channel operator (or a compromised member) leaks the negotiation transcript publicly. *Mitigation:* DACS-3 cannot prevent this technically — once a member sees the transcript, they can leak it. Listings handling sensitive flows SHOULD restrict membership to known counterparties; the leak risk reduces to counterparty-trust risk, which DACS-2 verification helps quantify.

**Late-revealing bidder denial-of-service.** *Threat:* in sealed-envelope, a bidder commits and then deliberately fails to reveal, hoping to disrupt the auction. *Mitigation:* SE-4 excludes non-revealing bidders from selection and marks them with a reputation event. Repeated failures damage their DACS-5 reputation. Listings MAY require a stake from bidders (escrowed at commit, returned on reveal) to make denial-of-service costly; v0.1 does not standardise stake.

**Orchestrator / seller reveal manipulation.** *Threat:* the sealed-envelope channels are seller↔bidder and the orchestrator drives them, so the orchestrator (and, when the seller acts as orchestrator, the seller) is a member of every bidder's channel and could (a) learn each revealed bid as it arrives during the revealWindow and steer a favoured bidder, or (b) suppress an honest low bid from the candidate list. The bidHash commitment prevents *changing* a bid but does not prove complete discovery. *Mitigation:* bidder-owned signed anchors prevent the orchestrator from suppressing the write. For the complete profile, SAC-3/SAC-4 additionally authenticate a current finalized complete prefix result, SAC-5 accounts for every returned record, SAC-6 removes unspecified rule execution, and SAC-7/SAC-8 bind reproducible selection into the co-signed agreement. Omission becomes detectable rather than merely challengeable by an excluded bidder. *Residual:* the single-orchestrator model still cannot prevent a channel member leaking interim reveals before reveal-window close; sensitive listings SHOULD use a neutral orchestrator or a commit-to-all-then-reveal-to-all discipline. A simultaneous-reveal cryptographic scheme remains a roadmap candidate. The historical §8.4.3 profile lacks SAC completeness and MUST disclose that limitation.

**RFQ session-initiation flooding.** *Threat:* a malicious counterparty repeatedly opens RFQ sessions and sends valueless `counter` turns up to `maxTurns`, forcing the victim's orchestrator to establish an SR-4 channel and process and sign turns at near-zero cost to the attacker. *Mitigation:* RFQ-1..RFQ-4 and `timeoutSec` bound a single session's turn count and per-turn wait, but v0.1 does not standardise a cap on the rate of session initiations per counterparty. Orchestrators SHOULD enforce a per-counterparty session-initiation rate limit (analogous to the per-session ERC-8004 write rate limit of §10.11) and MAY require a DACS-2 verification floor before admitting an RFQ initiator. This is a partial defence: the asymmetry between the attacker's initiation cost and the victim's per-session processing cost is not removed by v0.1.

**Sealed-envelope commit-spam.** *Threat:* SE-2 requires every bidder commit to be anchored via SR-2, and SE-1/SE-2 impose no stake and no bidder-eligibility check; an attacker floods an open auction with junk commits, each forcing an SR-2 anchor, inflating the seller's anchoring cost and the §10.4.2 extended-pointer bundle size. *Mitigation:* the optional bidder-stake mechanism noted above (escrowed at commit) makes commit-spam costly, and listings MAY restrict the bidder set or require a DACS-2 verification floor at commit; sellers SHOULD rate-limit commit anchoring per counterparty. This is a partial defence because v0.1 does not standardise stake or a bidder-eligibility check; an open, stakeless auction remains exposed to anchoring-cost amplification.
