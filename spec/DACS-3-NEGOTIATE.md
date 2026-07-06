# DACS-3: Negotiate — Negotiate

*Normative module of DACS v0.1. Read the [Primer](../PRIMER.md) first; shared types, signatures, canonical form, the session model, and substrate requirements live in [CORE](CORE.md). Section numbers are retained from the unified specification; per the §→document map in [CORE](CORE.md), cross-references of the form §6–§10 point to sibling module documents, and §A / §12–§14 to the companion references (Demos mapping, threat model, glossary, conformance plan). The [conformance vectors](../conformance/) exercise this module's rules.*

## Chapter 8 — DACS-3: Negotiate

**Stage:** Negotiate (3rd of 5). **Status:** Draft — **DACS-3 v0.2** (on the common DACS v0.1 baseline; adds the optional `feeSchedule` cost-disclosure on the AgreementDocument §8.5.3, and the optional `AgreementParty.encryptionKey` binding for `encrypt-to-buyer` private delivery, DACS-4 §9.6.1). **Depends on:** SR-2 (required for public commitments), SR-4 (required for genuinely private negotiation patterns); references DACS-1 listings and DACS-2 verified bundles. **Used by:** DACS-4 (pricing + rail input to settlement), DACS-5 (agreement reference in session bundle).

### 8.1 Abstract

DACS-3 specifies how parties arrive at agreed terms and bind themselves cryptographically to the outcome. It defines:

- A **negotiation channel model** — abstract requirements for a private coordination surface keyed to participant identities, with the public chain seeing only commitments. Realised in v0.1 by SR-4; substrates without SR-4 host only negotiate-fixed-price.
- A **closed set of negotiation patterns** as phase types: negotiate-fixed-price (acceptance), negotiate-rfq (bounded offer/counter), negotiate-sealed-envelope (commit-then-reveal sealed bid) — each with a uniform input/output contract.
- An **agreement document schema** — the canonical signed JSON output of any pattern, carrying final terms, deliverable reference, deadlines, and all-party signatures.
- A **commit-agreement phase** — anchors the agreement hash on the public chain, producing the binding artifact every downstream stage references.

Negotiation contents stay between participants; the chain receives only what binds them to the outcome.

### 8.2 Motivation

Negotiation is where commerce most consistently breaks open standards. Identity, payment, and discovery can run publicly with little privacy cost to their *contents* (the durable identities they bind do stay visible at the audit layer — an accepted accountability-over-privacy tradeoff, §12.1). Pricing, term-sheet drafts, sealed bids, and RFQ counters cannot: they involve MNPI, competitive pricing, or discussions that harm participants if exposed. A public RFQ telegraphs market information institutional desks pay to keep private; sealed-bid procurement cannot run on a public mempool; regulated pre-trade negotiation is bound by MNPI rules public visibility violates.

DACS-3 separates two historically-fused concerns:

- **Negotiation content** lives in a private channel whose membership is bound to the same identities that hold value on chain (so in-channel signatures equal public-chain signatures), but whose contents never become public.
- **Commitment** lives on chain: a single hash of the final agreement is anchored, so anyone can verify a binding agreement exists between the named parties at a known time without reading its contents.

This separation is what makes institutional/regulated flows possible on a public-permissionless substrate, and most distinguishes DACS from standards (AP2, x402, ERC-8004, W3C VC, zkTLS) that assume public negotiation or none. Not every transaction needs it: a fixed-price micropayment has nothing to negotiate — "acceptance is the negotiation" via negotiate-fixed-price (SR-2 only, any substrate). The substrate-locked patterns (rfq, sealed-envelope) are opt-in per listing.

### 8.3 Negotiation channel model

A negotiation channel is a coordination surface with the following properties.

#### 8.3.1 Required properties

(CH-1) **Identity-keyed membership.** The channel’s member set is a list of ClaimReferences, **fixed for the channel's lifetime in v0.1**. Each member’s primary claim MUST appear in their verified DACS-1 bundle. The member set is established by the §8.3.2 binding-proof flow before negotiation begins and MUST NOT change mid-channel. Dynamic membership (mid-negotiation add/remove governed by an admission policy) is reserved for a future version: the `membership-change` message type and an `admissionPolicy` schema are deliberately **not** defined in v0.1, and `membership-change` is correspondingly absent from the v0.1 `ChannelMessage.type` set.

(CH-2) **Confidentiality.** Non-members MUST NOT be able to read channel contents. The public chain MUST see only commitments (envelope commitments, agreement hash) and never raw offer/counter/reveal payloads.

(CH-3) **Authenticity.** Every message in the channel MUST be signed by its author’s primary key (the key associated with the author’s primary claim). Verifiers MUST be able to validate signatures using the same keys used in DACS-2 verification.

(CH-4) **Liveness.** The channel MUST deliver messages to all members within a bounded delay. Members MUST be able to detect channel-level failure (partition, censorship by the channel operator) and abort.

(CH-5) **Termination.** The channel MUST produce a terminal state. Terminal states are: (a) a signed AgreementDocument; (b) an abort signed by any party; (c) timeout. The terminal state is referenced by commit-agreement (if agreement) or recorded as a failed Negotiate stage (otherwise).

(CH-6) **Per-session channelId uniqueness.** The substrate MUST derive a per-session-unique `channelId`, and an orchestrator MUST reject a session that reuses a `channelId` from a prior session. Without this the cross-session offer-replay defence (§8.3.3 envelope `channelId` + monotonic `sequence`) is vacuous — a reused `channelId` would let a session-A offer verify in session B. The threat and replay analysis are detailed in §8.12.

#### 8.3.2 SR-4 realisation

On Demos, L2PS (Layer-2 Privacy Subnets) is the SR-4 implementation. Channel sessions are subnets; messages stay between subnet members; the public chain stores only commitment hashes and the final agreement hash (as Storage Programs).

For v0.1, subnet membership MUST be bindable to the participants’ CCI primary claims, so that channel-message signatures verify against the same key that holds value on-chain and the commit-agreement anchor’s parties match the channel members. Until CCI-keyed membership ships, implementations MAY use a binding-proof step: each participant signs an "L2PS subnet X membership = CCI Y" attestation with their CCI primary key, anchored as a Storage Program before negotiation begins.

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
  body: unknown                        // type-specific. Sealed-envelope commit/reveal bodies are defined in §8.4.3; RFQ offer/counter/accept/reject bodies are implementation-defined (the authoritative agreed terms live only in the signed AgreementDocument, not the channel body)
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

The v0.1 closed set. Each is a DACS-3 phase type with a phase-handler contract.

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

1. construct an AgreementDocument with derivedFromPattern: "fixed-price", copying terms directly from the listing’s pricing, acceptedRails (using the buyer’s selected rail; `terms.rail` is omitted for a zero-pay pipeline per §8.5.2 rule 3), deliverable, and deadline (computed as now + listing.terms.deadlineSecAfterCommit);
2. collect buyer signature;
3. collect seller co-signature;
4. anchor the agreement document via SR-2;
5. return agreementHash and agreementRef.

**Seller-side auto-accept (optional)**

A listing MAY declare terms.acceptanceModel: "auto-accept", in which case the seller pre-issues a **template acceptance commitment** alongside the listing rather than a per-session signature. The mechanism:

- The seller publishes, at listing-anchor time, a separate AutoAcceptCommitment record: { listingRef, listingContentHash, acceptanceModel: "auto-accept", validUntil, sellerSignature } where sellerSignature is the seller’s signature over the domain-separated payload "dacs-auto-accept-commitment:v1:" || sha256(canonical(commitment)). This commits the seller to auto-accepting any buyer signature against the listed terms within validUntil.
- At orchestrator time, the orchestrator: (1) **verifies** the AutoAcceptCommitment is anchored, unrevoked, and still valid (see *Two-phase validity* below); (2) **constructs** the per-session AgreementDocument with `derivedFromPattern: "fixed-price"`; (3) **computes** the agreement hash; (4) **constructs an auto-accept seller signature** — an Ed25519 signature by the seller’s primary key over `"dacs-auto-accept-instance:v1:" || agreementHash || autoAcceptCommitmentHash`.

  *Two-phase validity (step 1).* `validUntil` is checked twice because the per-session `committedAt` does not exist until the commitment is anchored, so it cannot gate the signature pre-anchor: **provisionally** against the current clock at signing time (an already-expired commitment MUST NOT produce an instance signature), then **authoritatively** re-checking `committedAt ≤ validUntil` against the anchored commitment timestamp (`committedAt`, defined in the §8.6 CommitmentRecord) at commit-agreement, per the §8.5.2 ordering note.

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
4. construct the AgreementDocument with `derivedFromPattern: "rfq"` and the agreed terms, sign and send as a final message;
5. collect co-signatures from all parties;
6. anchor the agreement via SR-2;
7. optionally, if all parties consent, anchor the encrypted transcript via SR-2 with a channelTranscriptRef. Consent MUST be explicit; default is no transcript anchoring.

**Conformance.**

- (RFQ-1) maxTurns MUST be ≥ 2.
- (RFQ-2) Each turn MUST conform to the channel message envelope.
- (RFQ-3) Final terms MUST conform to the listing’s pricing band — counters proposing terms outside the band MUST be rejected client-side; signed agreements with out-of-band terms MUST be rejected by commit-agreement.
- (RFQ-4) Implementations MUST enforce the turn timeout; missed-timeout abandonment MUST be treated as channel failure.

**Substrate:** SR-2 + SR-4.

#### 8.4.3 negotiate-sealed-envelope

Sealed-bid procurement: all bidders submit hash-committed bids before a deadline; bids are revealed after the deadline; winner is selected per the listing’s selection criterion.

```
type NegotiateSealedEnvelopeInput = {
  jobId: string
  listingHash: string
  listingRef: { listingId: string; version: number }
  buyerBundles: IdentityBundle[]       // all bidders' bundles
  sellerBundle: IdentityBundle         // listing publisher
  buyerVetRefs: AttestationRef[]
  sellerVetRef: AttestationRef
  parameters: {
    commitDeadline: number             // unix ms; MUST be > now
    revealWindow: number               // seconds after commitDeadline; MUST be >= 60
    selectionRule: "lowest-price" | "highest-price" | "first-acceptable" | "rule-ref:<contentHash>:<uri>"
    auctionMode?: "demand" | "procurement"  // default "demand"; governs sealed-envelope role assignment (SE-8)
    channelSubnet?: string
  }
  sessionContext: SessionContext
}
type NegotiateSealedEnvelopeOutput = PhaseHandlerResult & {
  contextDelta?: {   // present only on ok:true; a failed phase (no winning bid) returns a bare PhaseHandlerResult
    "negotiate-sealed-envelope": {
      agreementHash: string
      agreementRef: AttestationRef
      winningBidderClaim: ClaimReference
      revealedBidRefs: AttestationRef[]
      losingBidderClaims: ClaimReference[]
    }
  }
}
```

**Procedure.** The orchestrator MUST:

1. **Channels** — establish SR-4 channels between the seller and each bidder.
2. **Bidder commit phase** (before commitDeadline) — each bidder constructs a bid and a fresh salt (per SE-7) and computes:

   `bidHash = sha256("dacs-sealed-bid:v1:" || sha256(canonical_JCS(bid)) || salt)`

   expressed as a **lowercase hex string** (the same convention as every other DACS hash, so the SE-5 lexicographic tie-break is deterministic). The bid is hashed to a fixed 32-byte digest before concatenation so the bid/salt boundary is unambiguous, and the leading domain tag separates this commitment from any other sha256 usage. `commitTimestamp` is part of the commit *message* envelope and is NOT in the bidHash preimage (only `canonical_JCS(bid)` + salt are hashed). Each bidder sends a `sealed-envelope-commit` message `{bidHash, bidderClaim, commitTimestamp}`, where:
   - the message’s `bidderClaim` MUST equal the channel-envelope sender (the authenticated signer, CH-3); a commit whose `bidderClaim` ≠ sender MUST be excluded — bidder identity is the authenticated signer, not a free-text body field;
   - `commitTimestamp` is informational only and MUST NOT be used for any deadline gate, ordering, or tie-break (the SR-2 anchor timestamp is authoritative per SE-2/SE-5);
   - the commit message’s bidHash MUST also be anchored via SR-2.
3. **commitDeadline** — no further commits are accepted; the orchestrator records the set of received commits.
4. **Bidder reveal phase** (within revealWindow) — each bidder sends a `sealed-envelope-reveal` message `{bid, salt}` matching their prior bidHash; the orchestrator verifies `sha256("dacs-sealed-bid:v1:" || sha256(canonical_JCS(bid)) || salt) == bidHash` (mismatches cause exclusion). **Each bidder MUST anchor its own reveal record via SR-2 before revealWindow expiry** (the bidder, not the orchestrator — so a malicious orchestrator cannot suppress an honest in-window reveal by withholding its anchor); the anchored reveal record MUST contain the openable `{bid, salt}` (verifiable against the committed bidHash). **The authoritative candidate set for selection is the set of anchored, in-window, bidHash-matching reveal records — NOT the orchestrator's channel inbox** — so the orchestrator cannot exclude an honest bid by claiming it never arrived in-channel (this also gives the objective anchor timestamp for SE-3 and on-chain proof of timely reveal).
5. **Selection** operates over that authoritative anchored reveal set, in order:
   - **Exclusions first** — the orchestrator MUST first exclude (i) any bid whose `price.currency` ≠ the listing-declared currency and (ii) any bid with non-positive `price.amount` (§9.3).
   - **Reserve** — then, if the auction PricingSpec declares `reservePrice` (whose `currency` MUST equal the listing-declared currency — a mismatched-currency reserve is a non-conformant listing), exclude bids failing the reserve: for `highest-price` and for `first-acceptable`/`rule-ref` the reserve is a price **floor** (`amount < reservePrice` excluded); for `lowest-price` it is a **ceiling** (`amount > reservePrice` excluded). The comparison uses CD-1-canonical full-precision decimals and a bid whose `amount == reservePrice` is **admitted** (the bound is inclusive). If the candidate set is empty after these exclusions, the phase fails with no winning bid (bare PhaseHandlerResult → `negotiate-failed`, errorClass per step 6).
   - **Selection rule** — the orchestrator applies the phase-step `parameters.selectionRule`, which is content-hash-bound into the listing pipeline per §6.3.4 and is the authoritative selection rule; the auction PricingSpec's own `selectionRule` MUST equal it (a listing whose two values disagree is non-conformant).
   - **Tie-break ladder** — ties resolved by earliest SR-2 anchor timestamp of the bidder's commit (the same objective, substrate-determined timestamp SE-2 uses for the deadline gate — *not* the self-reported `commitTimestamp` field); any remaining ties (commits anchored in the same block / with equal anchor timestamps) resolved by ascending lexicographic order of the lowercase-hex `bidHash` string (per step 2).
6. **No winning bid / agreement construction** — if the selection rule yields no winner (an empty candidate set — all bids excluded for currency/non-positive/reserve, or all bidders failed to reveal per SE-4 — or a `first-acceptable`/`rule-ref` rule that no bid satisfies), the phase fails with no winning bid (bare PhaseHandlerResult; errorClass `counterparty` when the emptiness is bidder-caused, `permanent` for a structural listing defect; → `negotiate-failed`). Otherwise construct the AgreementDocument from the winning bid with `derivedFromPattern: "sealed-envelope"` and roles assigned by `auctionMode` (SE-8): for `"demand"` (including absent/default), the winning bidder is the agreement `buyer` and the listing publisher is the `seller`; for `"procurement"`, the listing publisher is the agreement `buyer` and the winning bidder is the `seller`. In both modes, `bid.price` is the amount payable by the agreement `buyer` to the agreement `seller`; the money direction is defined by the agreement roles, never by which party ran the auction. Then collect the seller's and the winning bidder's co-signatures — the §8.5.1 required signers (losing bidders are listed as bidder-non-winning parties and their signatures are not required).
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
- **first-acceptable** — the orchestrator MUST evaluate revealed bids in ascending order of the SR-2 anchor timestamp of each bidder's commit (the same objective clock as SE-2/SE-5, not the self-reported `commitTimestamp` field) against the listing-declared acceptance predicate, and select the first that satisfies it. The acceptance predicate MUST be deterministic given the bid set and MUST be fixed before bids open — content-hash-bound into the listing (the same anti-swap discipline as rule-ref), so it cannot be changed after bids are seen; a non-deterministic or post-bid-mutable predicate MUST NOT be used.
- **rule-ref** — the rule MUST be anchored as a Storage Program (or fetched from an HTTPS URI and content-hash-bound). The URI is purely informational; the `<contentHash>` in the selection-rule string is the authoritative binding. Orchestrators MUST fetch the rule at `<uri>` (or the substrate anchor), compute sha256 of the canonical form, and verify it matches `<contentHash>`. Mismatch MUST exclude the rule and fail the selection step with `errorClass: permanent`. This prevents a seller from changing the selection algorithm after bids have been submitted by changing the content served at `<uri>`.

**Conformance.**

- (SE-1) commitDeadline MUST be at least 60 seconds in the future at session start.
- (SE-2) Every bidder commit MUST be anchored before commitDeadline; commits whose anchor timestamp is after commitDeadline MUST be excluded.
- (SE-3) Every revealed bid MUST be anchored via SR-2 before revealWindow expiry; reveals whose anchor timestamp is after revealWindow expiry MUST be excluded. This mirrors SE-2: the substrate anchor timestamp — not a channel message's self-reported sentAt or the orchestrator's wall clock — is the authoritative clock that decides whether a reveal occurred in-window.
- (SE-4) Bidders failing reveal MUST be excluded from selection and MAY be marked with a failure-to-reveal reputation event (DACS-5).
- (SE-5) The selection rule MUST be deterministic; ties MUST resolve consistently. The tie-break MUST use the objective SR-2 anchor timestamp of each bidder's commit (the same clock as SE-2), MUST NOT use the self-reported commitTimestamp field, and MUST resolve same-anchor-timestamp ties by ascending lexicographic order of the lowercase-hex bidHash string (step 2).
- (SE-6) rule-ref selection rules MUST be content-hash-bound and the rule content MUST itself be deterministic given the bid set.
- (SE-7) **Bid-commitment salt.** The `salt` used in the bidHash commitment MUST be generated from a cryptographically-secure random source with at least 256 bits (32 bytes) of entropy, MUST NOT be reused across bids or sessions, and MUST be carried on the wire as a base64url string so the bytes hashed are unambiguous to both committer and verifier; the commitment input is the raw decoded salt bytes. This closes the pre-reveal brute-force leak created by anchoring bidHash publicly (§8.12) for low-entropy structured bids, and aligns the sealed-envelope salt with the HTLC-1 salt discipline.
- (SE-8) **Sealed-envelope role assignment.** `auctionMode` is read from the pinned listing's `negotiate-sealed-envelope` phase parameters. If absent, it defaults to `"demand"`; if present, it MUST resolve to exactly `"demand"` or `"procurement"`. Present-but-unresolvable or malformed `auctionMode` MUST cause commit-agreement to reject the agreement with a recorded `unresolvable-auctionMode` reason; it MUST NOT be coerced to `"demand"`. For `"demand"`, the winning bidder MUST be the agreement `buyer` and the listing publisher MUST be the `seller`; for `"procurement"`, the listing publisher MUST be the agreement `buyer` and the winning bidder MUST be the `seller`. `bid.price` is always the amount payable by the agreement `buyer` to the agreement `seller`.

**Substrate:** SR-2 + SR-4.

### 8.5 Agreement document

The canonical output of any negotiation pattern.

```
type AgreementDocument = {

  agreementVersion: "1"

  jobId: string

  listingRef: {

    listingId: string

    version: number

    contentHash: string                // pinned listing content hash

  }

  parties: AgreementParty[]

  terms: {

    deliverable: DeliverableRef        // DACS-4 reference

    price: PriceTerm                   // DACS-4 reference

    rail?: PaymentRailRef              // DACS-4 reference; present iff the pipeline has a pay-* phase (§8.5.2 rule 3). When present, MUST appear in listing.acceptedRails

    deadline: number                   // unix ms; settle-by deadline

    // Optional SR-3-attested reference price snapshot both parties sign against.
    // When present, both parties attest that price was determined relative to this anchor.
    // Does not replace or constrain terms.price — it is an informational audit record.
    priceAnchor?: PriceAnchor

    // Optional signed disclosure of the fee structure (regulated-context cost transparency, §8.5.3).
    // Both parties sign it with the agreement; it does NOT alter terms.price and does NOT gate Settle.
    feeSchedule?: FeeSchedule

    additionalTerms?: Record<string, unknown>

  }

  derivedFromPattern: "fixed-price" | "rfq" | "sealed-envelope"

  derivedFromChannel?: {

    subnet: string

    lastMessageHash: string

  }

  generatedAt: number

  signatures: AgreementSignature[]

}

type AgreementParty = {

  role: "buyer" | "seller" | "bidder-non-winning"

  bundleHash: string                   // sha256 of the post-Vet IdentityBundle

  primaryClaim: ClaimReference         // pulled from bundle.presentedBy

  vetRecordRef: AttestationRef         // DACS-2 composite verification record

  encryptionKey?: string               // optional party encryption public key; binds which key an encrypt-to-buyer deliverable is sealed to (DACS-4 §9.6.1, DV-3). Distinct from the signing key.

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

// AgreementDocument.terms.additionalTerms MAY include "competitiveContext: CompetitiveContext".

// Optional: SR-3-attested reference price snapshot included in the agreement for audit purposes.
// Both parties sign the AgreementDocument (including priceAnchor when present), so the snapshot
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

  value: string                        // signature over agreement hash

}
```

#### 8.5.1 Canonical serialisation and signature

The agreement follows the §B.2 canonical-form template, omitting the `signatures` field; each `AgreementSignature.value` is computed over:
signed_bytes := "dacs-agreement:v1:" || agreement_hash

**Decimal amounts (CD-1).** Every `PriceTerm.amount` is in minimal-digit canonical decimal form per **rule CD-1 (CORE §B.2)** — producers canonicalise before the agreement hash, verifiers before the §8.5.2 price-band and price-equality comparisons.

**Verification & required signers.** Verifiers MUST recompute the canonical form, agreement hash, and domain-separated payload, and for each required party, resolve the primary claim’s key (per DACS-2 verification) and verify the signature. Required signers by pattern:

| Pattern | Required signers |
| --- | --- |
| negotiate-fixed-price | buyer + seller (the seller signature may be an auto-accept instance signature per §8.4.1) |
| negotiate-rfq | buyer + seller |
| negotiate-sealed-envelope | seller + winning bidder (non-winning bidders’ signatures are not required) |

**`priceAnchor` canonical-form note.** `priceAnchor` is optional and **non-normative for agreement validity** — informational only. When present:

- it is included in the JCS canonical form (the same as any other field in `terms`) and is therefore covered by both parties’ signatures, and its `priceAnchor.price` MUST be in CD-1 canonical decimal form;
- **tolerance** — a verifier that does not understand `priceAnchor` MUST NOT reject the agreement on that basis, and its absence MUST NOT cause rejection;
- **audit use (conditional)** — when a consumer *does* use `priceAnchor` for audit, it MUST resolve `priceAnchor.attestationRef` to a valid SR-3 attestation and confirm `attestationRef.contentHash` equals sha256 of the raw response body.

#### 8.5.2 Listing conformance validation

A verifier MUST validate the agreement against its referenced listing — checked in order:

1. **Currency** — `terms.price.currency` MUST equal the listing pricing currency (negotiable pricing → `bandCenter.currency`; fixed pricing → the listed price currency). A band or equality comparison across differing currencies MUST be rejected **before any amount comparison**.
2. **Price within band** — `terms.price` MUST lie within the listing’s pricing band:
   - *Negotiable pricing* — within the band declared by the negotiable variant's `minPct` / `maxPct` (non-negative percentages) around `bandCenter`. The admissible band is the **inclusive** interval [`bandCenter.amount × (100 − minPct) / 100`, `bandCenter.amount × (100 + maxPct) / 100`]. Each computed bound MUST be **rounded half-up to the number of fractional digits of `bandCenter.amount` in its CD-1 canonical form** (CORE §B.2) — NOT to any "currency precision", which is undefined at listing time (settlement precision is tied to `rail.asset.decimals`, not the listing currency) — then canonicalised per CD-1. `terms.price.amount`, compared as a full-precision CD-1 decimal, MUST be ≥ the lower bound and ≤ the upper bound (boundaries inclusive). A verifier MUST reject the listing if the computed lower bound is ≤ 0.
   - *fixed-price over negotiable pricing* — if `derivedFromPattern == "fixed-price"`, `terms.price` MUST instead equal `bandCenter` exactly per CD-1, not merely lie within the band (see PS-3).
   - *Fixed pricing* — equal to the listed price.
3. **Rail** — `terms.rail` MUST be present if and only if the listing pipeline contains a `pay-*` phase (PIPE-1, §9.5). When present, it MUST appear in `listing.acceptedRails`. For a zero-pay (intake-only / settled-out-of-band) pipeline — one with no `pay-*` phase — `terms.rail` MUST be absent.
4. **Deliverable** — `terms.deliverable` MUST conform to the listing’s `offering.deliverable`: `terms.deliverable.deliverableType` MUST equal the listing `offering.deliverable` kind; `terms.deliverable.hash` MUST equal the canonical `DeliverableRef.hash` of the listing’s `offering.deliverable` (per §9.3); `terms.deliverable.schemaUrl` MUST equal the listing `offering.deliverable.schemaUrl` (both absent, or both present and equal).
5. **Deadline** — `terms.deadline` MUST be ≤ `committedAt + listing.terms.deadlineSecAfterCommit`, where `committedAt` is the SR-2 anchor timestamp of the commitment record (§8.6) — the same objective, substrate-determined clock SE-2 uses — NOT the self-reported `generatedAt`, which a party could backdate to widen the settle window.
6. **Not expired** — the listing's `validity.notAfter` (if set) MUST be ≥ `committedAt`; the listing MUST NOT have expired between read and commit-agreement (the §6.3.4 step-3 read-time check governs discovery; this re-check governs commit, closing the read-to-commit interval).
7. **Pattern** — `derivedFromPattern` MUST match the listing’s pipeline-declared negotiation pattern.
8. **Sealed-envelope role direction** — for `derivedFromPattern == "sealed-envelope"`, the agreement party roles and `terms.price` direction MUST match the pinned listing's declared `auctionMode` per SE-8. If `auctionMode` is present but unresolvable/malformed, validation MUST reject with a recorded `unresolvable-auctionMode` reason. If the roles are inverted relative to the pinned mode, validation MUST reject before Settle.

Checks 5 and 6 are the two `committedAt`-relative checks — see the ordering note below. Agreements failing any check MUST be rejected by commit-agreement.

**Ordering of the `committedAt`-relative checks.** Checks 5 and 6 reference `committedAt` — the commitment record's SR-2 anchor timestamp (§8.6) — which only exists *after* the commitment is anchored (§8.6 step 5). The checks therefore run in two phases:

- **Pre-anchor (§8.6 step 3).** The value-independent checks — currency, price-band, rail, deliverable, pattern, and sealed-envelope role direction — gate here. The orchestrator also runs a *provisional* check of the deadline and `notAfter` against the current clock.
- **Post-anchor (authoritative).** Once the commitment is anchored, the orchestrator MUST re-evaluate checks 5 and 6 against the actual anchored `committedAt`. Any consumer/verifier reading the anchored commitment MUST likewise re-check them against `committedAt`.

A commitment whose anchored `committedAt` violates either check is invalid.

> **Note (non-normative).** The two-phase discipline keeps `committedAt` the objective anti-backdating clock without a circular dependency on an as-yet-unanchored value. The §6.3.4 read-time check still governs discovery.

#### 8.5.3 Fee disclosure (`feeSchedule`)

An `AgreementDocument` MAY carry a `terms.feeSchedule` — an optional, signed pre-commit disclosure of the fee structure, for regulated-context cost transparency. It is **disclosure-only**: both parties sign it with the agreement, but it does **not** alter `terms.price` and a consumer **MUST NOT** gate settlement on it. It is the non-repudiable record that fees were disclosed before commit.

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

### 8.6 Commitment phase (commit-agreement)

The DACS-3 phase that anchors the agreement hash on the public chain.

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
      committedAt: number
    }
  }
}
```

**Procedure.** The orchestrator MUST:

1. compute `agreementHash = sha256(canonical_JCS(agreement))` with signatures omitted;
2. verify all required signatures are present and valid;
3. validate the agreement against the listing per §8.5.2. The **value checks** (currency / band / rail / deliverable / pattern) gate **here**; the two **`committedAt`-relative checks** (deadline, `notAfter`) are re-evaluated against the anchored `committedAt` after step 5, per the §8.5.2 ordering note. Any validation failure MUST cause the phase to fail with class `permanent`;
4. construct the on-chain commitment record:

```
type CommitmentRecord = {
  dacsVersion: "1"
  jobId: string
  agreementHash: string
  listingRef: { listingId: string; version: number; contentHash: string }
  parties: ClaimReference[]          // primary claims of signing parties
  pattern: "fixed-price" | "rfq" | "sealed-envelope"
  committedAt: number
}
```

5. anchor the commitment record via SR-2 at address `dacs3:commit:{jobId}` (or substrate-equivalent), with the orchestrator signature over the domain-separated payload `"dacs-commitment:v1:" || sha256(canonical_JCS(commitmentRecord_without_signature))`;
6. return agreementHash and anchorTxRef.

**Conformance.**

- (CA-1) The orchestrator MUST NOT advance to DACS-4 (Settle) until commit-agreement returns ok: true.
- (CA-2) Commitment records MUST be anchored on the public chain (not in a private channel).
- (CA-3) Once anchored, the commitment is immutable. Re-commitments for the same jobId MUST be rejected.
- (CA-4) The agreement document itself MAY be anchored separately (publicly or privately). For institutional flows, the agreement document is typically NOT anchored on the public chain — only its hash is. Parties retain the agreement document off-chain (or encrypted-anchored).

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

**Default disclosure: none.** By default, the transcript is not anchored on the public chain. Only the agreement hash (via commit-agreement) is public. The DACS-1 listing’s terms.transcriptDisclosurePolicy controls this per-listing:

- "none" (default) — transcripts stay in the channel; no anchoring required.
- "encrypted-anchored-recommended" — orchestrators SHOULD anchor transcripts encrypted to channel members; not required.
- "encrypted-anchored-required" — orchestrators MUST anchor encrypted transcripts; absence of transcript anchor MUST fail the phase. Recommended for sessions whose counterparty is a regulated entity that may be subject to subpoena.

If all channel members consent, the transcript MAY be encrypted to the member set and anchored via SR-2. The AgreementDocument.derivedFromChannel.lastMessageHash provides a verifiable hook from the public agreement to the (private) transcript. A future DACS standard (proposed DACS-X dispute) MAY require selective transcript disclosure under signed party agreement or arbitrator order. v0.1 does not specify dispute resolution; parties intending to support dispute SHOULD anchor encrypted transcripts at agreement time so disclosure is technically possible later.

### 8.8 Pattern selection by listing

A DACS-1 listing’s pipeline declares which negotiation pattern is used. Each PhaseStep of kind negotiate-* specifies the pattern and its parameters.

**Validation.**

- (PS-1) A pipeline MUST contain exactly one negotiate-* phase.
- (PS-2) A pipeline MUST contain exactly one commit-agreement phase, immediately following the negotiate-* phase.
- (PS-3) The listing’s pricing model MUST be compatible with the chosen pattern: negotiate-fixed-price MUST be fixed or negotiable (in which case fixed-price uses the band’s centre); negotiate-rfq MUST be negotiable; negotiate-sealed-envelope MUST be auction.

**Fallback to fixed-price.** A listing offering negotiate-rfq MAY declare fixedPriceFallback: true in the pipeline step. When true, a buyer that does not wish to negotiate MAY signal acceptance of the listed centre-price via negotiate-fixed-price. The orchestrator selects which pattern runs based on buyer signal. The fallback path produces a normal AgreementDocument with derivedFromPattern: "fixed-price".

**Multi-quote RFQ (deferred to v0.2).** The v0.1 negotiate-rfq phase is bilateral (one buyer, one seller). Real institutional RFQ is often one-to-many — a buyer queries N liquidity providers, collects quotes, picks one. v0.1 does not support multi-quote RFQ directly; the closest pattern is negotiate-sealed-envelope with selectionRule: first-acceptable or lowest-price. A first-class negotiate-multi-quote phase is anticipated for v0.2.

### 8.9 Conformance summary

| Role | Requirements |
| --- | --- |
| Channel implementation | CH-1 through CH-6; message envelope; failure detection |
| negotiate-fixed-price | §8.4.1 procedure; signature collection; SR-2 anchoring |
| negotiate-rfq | §8.4.2 procedure; RFQ-1 through RFQ-4; channel turn timeouts |
| negotiate-sealed-envelope | §8.4.3 procedure; SE-1 through SE-8; deterministic selection; rule-ref content-hash binding; mode-bound role assignment |
| commit-agreement | CA-1 through CA-4; signature and conformance validation |
| Listing publisher | PS-1 through PS-3 |
| Substrate without SR-4 | MUST support negotiate-fixed-price; MUST refuse negotiate-rfq and negotiate-sealed-envelope with a clear substrate-capability-missing error |

### 8.10 Rationale

**Three patterns vs more/fewer/open.** Three is the smallest set covering the demonstrated surface: fixed-price (micropayments, SaaS), RFQ (institutional bilateral), sealed-envelope (sealed-bid procurement). Open registries lose conformance testability; more patterns (english/dutch auction, multi-round delta-RFQ) are deferred to v2.

**Closed pattern set vs open.** A closed set lets every conforming orchestrator handle every conforming listing; an open set lets listings declare unsupported patterns — fragmentation by design.

**Single AgreementDocument shape across patterns.** Settle and Verify consume agreements regardless of how negotiated, so a uniform shape keeps them pattern-agnostic; pattern-specific data lives in `additionalTerms` / optional fields.

**Transcript private by default vs anchored-encrypted.** Default-anchoring transcripts is expensive and adoption-hostile (operators won't anchor negotiation history, even encrypted). Default-private with opt-in anchoring matches institutional practice; regulated flows opt in.

**commit-agreement as a separate phase.** A separate phase makes the on-chain commitment visible in the pipeline, lets the orchestrator validate signature/conformance before binding, and gives Settle/Verify a clear hook; implicit commitment hides the binding moment and complicates recovery.

**SR-4 abstract, not a fixed realisation.** Substrates may realise it via private subnets (Demos), TEEs, permissioned channels, or zk-confidential channels; DACS-3 specifies the abstract capability and per-pattern requirements, not a winner.

**Sealed-envelope: commit anchored, reveal in channel.** The on-chain commit hash prevents back-dating/repudiation; the in-channel reveal avoids leaking losing bids — matching government sealed-bid practice.

### 8.11 Backwards compatibility

**Institutional RFQ workflows.** A negotiate-rfq run maps to existing bilateral RFQ as a Bloomberg-chat RFQ maps to a Symphony RFQ: same semantic shape, different transport (the SR-4 channel). Existing desks wrap their negotiation logic as a DACS-3 phase without changing it.

**Sealed-bid government procurement.** negotiate-sealed-envelope covers FAR Part 14's commit-then-reveal with cryptographic commitment (vs physical envelopes); the selection-rule abstraction (lowest-price / first-acceptable / rule-ref) covers FAR's "lowest responsive responsible bidder" and "best value". EU/UK equivalents map similarly.

**Off-chain negotiation systems.** An existing RFQ system / procurement portal / B2B negotiation tool MAY serve as the SR-4 channel provided it satisfies CH-1..CH-6; the public-chain binding and agreement shape are the only DACS-3 additions.

**ERC-8183 escrow.** A DACS-3 agreement whose `terms.rail` is an EVM rail MAY reference an ERC-8183 escrow as the settlement vehicle; the DACS-4 rail definition carries the contract address.

**Future patterns.** New patterns (auctions, multi-round delta-RFQ) are added via the DACS-3 version process — registering the phase-handler contract, parameters, and substrate requirements.

### 8.12 Security considerations

**Channel-operator censorship.** *Threat:* the SR-4 channel operator drops messages, preventing a party from responding within the timeout. *Mitigation:* CH-4 mandates liveness detection. Members observing missed deliveries (no acknowledgement from a quorum) MUST treat the channel as failed. On Demos, Private Negotiation provides per-message acknowledgements; equivalent SR-4 implementations on other substrates SHOULD do the same.

**Channel-operator forking.** *Threat:* the channel operator shows different views to different members, creating mutual misunderstanding. *Mitigation:* channel message envelopes carry monotonic sequence numbers and signatures; members SHOULD periodically exchange "current state" attestations and detect forks. SR-4 implementations are expected to provide a tamper-evident message log.

**Replay of offers across sessions.** *Threat:* an attacker captures a signed offer from session A and replays it in session B. *Mitigation:* the channel message envelope includes channelId and sequence (per-channel monotonic). This defence holds only if channelId is unique per session: **(CH-6) channelId MUST be unique per session** — the substrate MUST derive a per-session-unique channelId, and an orchestrator MUST reject a session that reuses a channelId from a prior session. (Without CH-6 the replay defence is vacuous: a reused channelId would let a session-A offer verify in session B.) Given CH-6, an offer replayed into a different channel fails signature verification because the channelId differs; replayed in the same channel it duplicates a sequence number and is rejected.

**Signature stripping or rebinding between channel and agreement.** *Threat:* an attacker takes a signature produced inside the channel and reuses it on a different agreement document. *Mitigation:* channel-message signatures are over the message envelope (including channelId); agreement-document signatures are over the agreement hash (which includes jobId, listingRef, and all terms). The two scopes are non-overlapping; a channel signature does not validate as an agreement signature.

**Sealed-envelope front-running.** *Threat:* a bidder learns competitors’ bids before reveal. *Mitigation:* *before reveal*, bids stay encrypted in the channel and only the bid hash is public; *at reveal*, openable `{bid, salt}` records are anchored publicly (§8.4.3 step 4 — intentional, so relay-suppression resistance and SE-3 timestamping work). The channel’s confidentiality ensures non-members cannot read pre-reveal bids; the cryptographic commitment ensures the bidder cannot change their bid after observing competitors at reveal time (the only residual move — delaying one's own reveal to read earlier ones — yields nothing actionable, since the delayer's bid is already committed). Operators SHOULD use SR-4 implementations with member-exclusive encryption.

**Sealed-envelope post-deadline submission.** *Threat:* a bidder submits a commit after commitDeadline, claiming clock skew. *Mitigation:* SE-2 mandates the commit’s public-chain anchor timestamp (objective, substrate-determined) be ≤ commitDeadline. Clock skew at the bidder is irrelevant; the chain decides the timestamp.

**Agreement-listing mismatch.** *Threat:* a signed agreement contains terms outside the listing’s pricing band or with an unaccepted rail. *Mitigation:* validation rules; commit-agreement must reject. Both sides also SHOULD validate before signing.

**Multi-party signing race.** *Threat:* one party signs an agreement; before the other co-signs, the first party publicly commits and locks the other in. *Mitigation:* commit-agreement requires all required signatures present. A unilaterally-signed agreement fails CA. A future minor version MAY add pending-co-signature semantics for asynchronous flows; v0.1 requires synchronous signature collection.

**Public-chain timing analysis.** *Threat:* the pattern of commitment timestamps on the public chain reveals negotiation patterns. *Mitigation:* this is a fundamental property of any commit-on-chain protocol. Parties concerned with timing leak SHOULD use SR-4 channels with timing-padded delivery, anchor commitments at random intervals within a window, or settle through privacy-preserving rails. DACS-3 does not standardise timing obfuscation.

**Identity substitution between Vet and agreement signature.** *Threat:* a party’s bundle is verified in DACS-2 but they sign the agreement with a different key. *Mitigation:* AgreementSignature.party references the primary claim from the bundle. The signature key MUST be the one bound to that claim. Mismatches cause commit-agreement to fail.

**Channel-membership exfiltration.** *Threat:* the channel operator (or a compromised member) leaks the negotiation transcript publicly. *Mitigation:* DACS-3 cannot prevent this technically — once a member sees the transcript, they can leak it. Listings handling sensitive flows SHOULD restrict membership to known counterparties; the leak risk reduces to counterparty-trust risk, which DACS-2 verification helps quantify.

**Late-revealing bidder denial-of-service.** *Threat:* in sealed-envelope, a bidder commits and then deliberately fails to reveal, hoping to disrupt the auction. *Mitigation:* SE-4 excludes non-revealing bidders from selection and marks them with a reputation event. Repeated failures damage their DACS-5 reputation. Listings MAY require a stake from bidders (escrowed at commit, returned on reveal) to make denial-of-service costly; v0.1 does not standardise stake.

**Orchestrator / seller reveal manipulation.** *Threat:* the sealed-envelope channels are seller↔bidder and the orchestrator drives them, so the orchestrator (and, when the seller acts as orchestrator, the seller) is a member of every bidder's channel and could (a) learn each revealed bid as it arrives during the revealWindow and steer a favoured bidder, or (b) suppress an honest low bid by withholding its reveal anchor so SE-3 excludes it. The bidHash commitment prevents *changing* a bid but not these manipulations. *Mitigation (v0.1):* reveal records are anchored by the **bidder**, not the orchestrator (procedure step 4), so an excluded bidder holds on-chain proof of a timely in-window reveal and the orchestrator cannot silently drop it; SE-5 makes selection deterministic and rule-ref-bound (SE-6) so a favoured-bidder steer is detectable against the anchored bid set. *Residual:* v0.1's single-orchestrator model still trusts the orchestrator not to leak interim reveals to the seller before revealWindow close; listings sensitive to this SHOULD use a neutral (non-seller) orchestrator or a commit-to-all-then-reveal-to-all discipline. A simultaneous-reveal cryptographic scheme is a roadmap candidate.

**RFQ session-initiation flooding.** *Threat:* a malicious counterparty repeatedly opens RFQ sessions and sends valueless `counter` turns up to `maxTurns`, forcing the victim's orchestrator to establish an SR-4 channel and process and sign turns at near-zero cost to the attacker. *Mitigation:* RFQ-1..RFQ-4 and `timeoutSec` bound a single session's turn count and per-turn wait, but v0.1 does not standardise a cap on the rate of session initiations per counterparty. Orchestrators SHOULD enforce a per-counterparty session-initiation rate limit (analogous to the per-session ERC-8004 write rate limit of §10.11) and MAY require a DACS-2 verification floor before admitting an RFQ initiator. This is a partial defence: the asymmetry between the attacker's initiation cost and the victim's per-session processing cost is not removed by v0.1.

**Sealed-envelope commit-spam.** *Threat:* SE-2 requires every bidder commit to be anchored via SR-2, and SE-1/SE-2 impose no stake and no bidder-eligibility check; an attacker floods an open auction with junk commits, each forcing an SR-2 anchor, inflating the seller's anchoring cost and the §10.4.2 extended-pointer bundle size. *Mitigation:* the optional bidder-stake mechanism noted above (escrowed at commit) makes commit-spam costly, and listings MAY restrict the bidder set or require a DACS-2 verification floor at commit; sellers SHOULD rate-limit commit anchoring per counterparty. This is a partial defence because v0.1 does not standardise stake or a bidder-eligibility check; an open, stakeless auction remains exposed to anchoring-cost amplification.
