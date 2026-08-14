# DACS — Demos Agent Commerce Standards

**Introduction and DACS-1 through DACS-5**

> Draft — **DACS Core v0.3** (on the first-public-release DACS v0.1 baseline). v0.3 adds the optional, capability-gated Atomic DACS Work profile; v0.2 defines the normative SR-2 write lifecycle, portable anchor receipts, and cross-stage anchoring gates. See [CHANGELOG](../CHANGELOG.md) for normative change history.

## About this document

This document specifies DACS — the Demos Agent Commerce Standards — across five per-stage standards: DACS-1 (Identify), DACS-2 (Vet), DACS-3 (Negotiate), DACS-4 (Settle), and DACS-5 (Verify). Shared material (terminology, substrate capabilities, the Demos production mapping, references) is presented once in the front and back matter rather than repeated per chapter. Each per-stage chapter contains the material specific to that stage. The companion DACS Dev Tasks working document is published separately and is **not** part of the standards.

<!-- prose-lint: allow reason="RFC-2119 boilerplate necessarily enumerates the keywords" -->
**Normative language.** This document uses the RFC 2119 / RFC 8174 keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, interpreted as in those RFCs. Keywords are normative only when in uppercase.

**Section numbering.** The front matter is numbered §1–§5 (prose introduction) followed by three lettered cross-cutting reference sections — **§A Demos production mapping**, **§B Global terminology** (claim references, anchoring/signing, shared phase-handler types, the closed registries, and the universal signature scheme §B.7), and **§C Composed open standards**. The five per-stage standards are then **Chapters 6–10** (DACS-1..5), with back matter in **Chapters 11–14**. The lettering of §A–§C deliberately keeps the foundational reference sections out of the chapters' §6/§7/§8 numbering namespace, so a citation such as §B.7 (the universal signature scheme) versus §7.7 (the DACS-2 composite verification record) is unambiguous.

**Versioning.** This document is **DACS v0.1**, the first publicly released version. v0.1 is a common baseline: all five per-stage standards plus the front-matter substrate-binding, the threat model, the glossary, and the conformance plan are published together at v0.1. From this baseline onward, each per-stage standard versions independently — a standard that gains capabilities bumps its own minor version (v0.2, v0.3, …) without forcing the others, through to v1.0 — the version at which a standard is considered ready for unsupervised production use.

> **Note (non-normative).** Earlier drafts circulated internally under per-stage version numbers (DACS-1..5 v0.1, paper v0.7) and a brief v0.8 cut that consolidated review-pass revisions; those numbers are retired and reset to the common v0.1 baseline.

## Abstract

Autonomous agents are transacting with agents they have never met. Open standards exist for fragments of what a transaction requires — identity registries, payment authorisation, HTTP-layer micropayments, capability discovery — but each addresses one slice of the problem. Nothing in widespread use composes the fragments into a working commerce lifecycle, which is why agents that need the full lifecycle today fall back to closed operator marketplaces.

**DACS — Demos Agent Commerce Standards** — is the protocol Demos uses for agent commerce. It is organised around the five stages every agent-to-agent transaction passes through: **Identify, Vet, Negotiate, Settle, Verify.** For each stage, DACS composes with the existing standards that already work and adds new standards where the open ecosystem has gaps. Each new standard names the substrate capability it depends on. DACS is built for the Demos Network, but the capability-level specification is kept clean of Demos-specific dependencies so a substrate that provides the same capabilities can host a compatible implementation.

This document is the **normative reference** (Core + the five stage modules). A non-normative overview — the five-stage lifecycle, the nine-artifact spine, and a worked end-to-end example — is in the [Primer](../PRIMER.md); read it first if you are new to DACS.

## 1. The problem

An agent transacting with another agent today chooses between three options:

- **Pre-integrated bilateral trust** — works for small ecosystems, breaks at scale.
- **A closed operator marketplace** — scales, but the operator captures rents, controls access, and becomes a single point of trust.
- **Open standards** — the only path that scales without conceding a marketplace position, but only if a *complete lifecycle* exists.

Today the open standards cover stages, not the lifecycle. A buyer can discover a seller, recognise its identity, and authorise a payment. But with open standards alone it cannot (a) declare and verify a stakes-appropriate bundle of identity claims, (b) negotiate terms in private, or (c) produce an end-to-end session record the participants own. These gaps map to four of the five stages and are why institutional and regulated agents still fall back to operator marketplaces. DACS provides the lifecycle on a public, permissionless substrate — composing the standards that already work and filling the gaps that remain.

*The [Primer](../PRIMER.md) gives the full motivation (including why this matters now, and how DACS relates to AP2, x402, ERC-8004, ERC-8183, and A2A) plus a worked end-to-end example.*

## 2. The approach

DACS follows three principles.

**Composition.** Identity, payment, and several forms of credential attestation already have working standards with real adoption. There is no value in replacing them, and reinventing them slows everyone down. DACS uses composition, not replacement.

**Gap-filling.** Where there are real gaps, DACS specifies a new standard. New standards stay narrow in scope and are designed to compose cleanly with the rest of the stack.

**Stated substrate requirements.** Each new DACS standard names the substrate capability it depends on. The capability is the requirement, stated in the spec. Which substrate provides it is operational detail. This keeps DACS substrate-agnostic in specification while staying honest about what the new standards actually need underneath.
Three things follow:

- **Adopters keep what they already have.** A seller using existing identity, payment, and credential tooling does not abandon any of it to adopt DACS.
- **DACS is replaceable in parts.** If a better identity standard supersedes a pre-existing standard, the DACS standard referencing identity updates its pointers and the rest of the stack is unaffected.
- **DACS is substrate-portable in principle.** The substrate requirements are explicit. Any substrate that implements them can host a DACS implementation.

## 3. The five stages

Every agent-to-agent transaction, whether a $5 data lookup or a $5M institutional swap, passes through five stages:

- **Identify** — who is transacting, what is being offered, and how do they find each other.
- **Vet** — each party verifies the other’s claims against authoritative sources.
- **Negotiate** — parties arrive at agreed terms (price, scope, deadlines, deliverable spec) and commit to them.
- **Settle** — value is exchanged and the deliverable is provided.
- **Verify** — the complete transaction is anchored as an audit artifact; reputation is derived from it.

DACS is one standard per stage. Each standard either fully composes existing open standards for that stage, or specifies what is needed to close the gaps. Phase types specific to a stage (e.g. negotiate-rfq, pay-cross-chain-htlc) belong to that stage’s standard.

| Standard | Stage | Scope |
| --- | --- | --- |
| DACS-1 | Identify | Agent identity, signed and anchored service listings, discovery (.well-known/agent.json extension and off-chain catalog) |
| DACS-2 | Vet | Method-pluggable credential attestation against authoritative sources |
| DACS-3 | Negotiate | Private negotiation phases (RFQ, sealed envelope, fixed price), agreement commitment |
| DACS-4 | Settle | Payment rail registry, payment phases, delivery phases |
| DACS-5 | Verify | Session record, attestation bundle, reputation derivation |

The stages are sequential within a transaction. The standards are published together at the v0.1 baseline and version independently thereafter. Chapters 6–10 below specify them in detail.

## 4. Per-stage summary

A compact summary of what each stage composes, what it adds, and which substrate capabilities it depends on. Chapters 6–10 expand each row in full.

| Stage | Existing standards used | DACS additions | Substrate capabilities |
| --- | --- | --- | --- |
| Identify (DACS-1) | ERC-8004, W3C DIDs, A2A, authority and platform identifiers | Identity claim reference scheme; identity bundle schema; listing schema; .well-known extension; catalog API | SR-2; SR-1 optional |
| Vet (DACS-2) | W3C VC, TLSNotary, zkTLS | Method-pluggable recipe registry; proxy-attestation method for public-registry credentials; composite verification record | SR-2, SR-3 |
| Negotiate (DACS-3) | (none widely adopted) | Private negotiation phases; agreement commitment | SR-4 (private patterns), SR-2 |
| Settle (DACS-4) | AP2, x402, ERC-20, SPL, HTLC | Payment rail registry; payment and delivery phases (incl. Liquidity Tanks) | SR-2, SR-5 (cross-chain only) |
| Verify (DACS-5) | ERC-8004 reputation registry (publication surface) | Session record; attestation bundle; reputation derivation | SR-1, SR-2 |

Three stages compose substantially with existing standards (Identify, Vet, Settle). Two stages are gap-filled almost entirely (Negotiate, Verify). All five reference the same small set of substrate capabilities introduced in chapter 5.

## 5. Substrate capabilities

Every DACS standard names the substrate capability it depends on. The capabilities below are the complete set; each per-stage chapter cites a subset by ID.

| ID | Capability | Description | Used by |
| --- | --- | --- | --- |
| SR-1 | Cross-substrate identity aggregation | Optional. A composition primitive binding one root key to multiple sub-identities — per-substrate keys, verified Web2 identifiers, authority-issued identifiers, platform accounts — presented under a single signature. Cross-Context Identities (CCI) is the Demos implementation. | DACS-1, DACS-5 |
| SR-2 | Anchored, immutable storage | Content-addressed key-value storage with chain-anchored writes, suitable for signed documents up to a soft size limit. Storage Programs is the Demos implementation. | DACS-1, 2, 3, 4, 5 |
| SR-3 | Consensus-backed proxy attestation of HTTP responses | A substrate primitive that, given a fetch specification, returns a response signed by a consensus set of validators and anchors the attestation on chain at production throughput. DAHR (Data Agnostic HTTPS Relay) is the Demos implementation. | DACS-2 (one of several methods) |
| SR-4 | Identity-keyed private coordination channels | Private channels whose membership is bound to the substrate’s public-chain identity and whose contents stay between members. The public chain sees only commitments. L2PS (Layer-2 Privacy Subnets) is the Demos implementation. | DACS-3 (private negotiation patterns) |
| SR-5 | Multi-chain coordinated atomic settlement | Atomic settlement across substrates. May be provided by substrate-native cross-chain transactions, HTLC contracts on participating chains, or pre-funded liquidity primitives such as Liquidity Tanks on Demos. | DACS-4 (cross-chain settlement only) |

A substrate shipping all five can host a full DACS implementation. A substrate that ships some subset can host DACS partially: listings whose pipelines require unsupported capabilities are unfulfillable there, but the rest of the stack still works.

### 5.1 SR-2 write lifecycle and anchor receipts

An SR-2 write is not complete merely because a client submitted bytes or an RPC endpoint acknowledged them. Every SR-2 binding MUST expose the following portable lifecycle semantics, even when its native API uses different names:

```
submitted → accepted | rejected
accepted  → included | dropped | replaced | expired
included  → finalized | reorged
dropped | expired | reorged → accepted | included | replaced
```

- `submitted` is a local fact: the writer attempted to send the transaction. It carries no substrate guarantee.
- `accepted` means the binding has authenticated evidence that the substrate validated and **durably admitted** the transaction under its declared admission policy. An ordinary RPC, HTTP, relay, or mempool acknowledgement is not durable acceptance unless the binding proves that acknowledgement has this property.
- `included` means consensus recorded the transaction in a block or equivalent ordered state.
- `finalized` means the included transaction satisfies the binding's declared finality profile.
- `rejected`, `dropped`, `replaced`, `expired`, and `reorged` are non-success outcomes with their ordinary meanings. `replaced` MUST identify the replacing transaction when known.

**Indeterminate is an observation disposition, not a lifecycle state.** An observer that cannot establish a newer lifecycle state reports `observationDisposition: "indeterminate"` over the last established state. This is permitted after **any** lifecycle state, including `included`, `finalized`, and `rejected`, without adding an edge to the graph. It MUST NOT erase, demote, or promote the preserved state and MUST NOT itself authorize resubmission or satisfy a new protocol gate. A later established observation is validated as a graph transition from that preserved state.

The graph is not a promise that every substrate exposes every intermediate state. A deterministic-BFT binding MAY declare that valid inclusion is final, in which case one authenticated observation establishes both `included` and `finalized`. A binding that cannot prove durable admission MUST omit `accepted` as a usable gate and wait for `included` or `finalized`. `finalized` and `rejected` are terminal for that native transaction. `replaced` is terminal for the replaced transaction; the replacement has its own receipt sequence. `dropped`, `expired`, and `reorged` are recoverable lifecycle outcomes: the same native transaction MAY be durably readmitted or re-included, as the re-entry edges show.

**Indexer visibility is orthogonal.** `indexed` is an observation that an external read/index service currently returns the artifact; it is not an SR-2 transaction state and has no state-transition edge. An implementation MAY report visibility as `indexed`, `not-indexed`, or `indeterminate`, but:

- (SR2-1) indexer visibility MUST NOT gate DACS protocol progress;
- (SR2-2) visibility MUST NOT promote a transaction to `accepted`, `included`, or `finalized`; and
- (SR2-3) lack of visibility MUST NOT demote an otherwise authenticated lifecycle state.

**Portable receipt.** A lifecycle observation is represented by an immutable `AnchorReceipt` snapshot:

```
type AnchorReceipt = {
  receiptVersion: "1"
  substrate: string                    // stable substrate/network identifier
  finalityProfile: string              // binding-defined profile applied by the observer
  logicalAddress: string               // canonical DACS logical artifact address
  nativeAddress: string                // substrate-native content address
  contentHash: string                  // sha256 of the artifact's canonical content
  transactionRef: {
    kind: string                       // binding-defined transaction-reference kind
    value: string                      // canonical native transaction identifier
  }
  writer: string                       // canonical native writer/account identifier
  nonce?: string                       // REQUIRED when the substrate uses a writer nonce
  state: "submitted" | "accepted" | "included" | "finalized"
       | "rejected" | "dropped" | "replaced" | "expired"
       | "reorged"
  observationDisposition: "established" | "indeterminate"
  preservedReceiptHash?: string        // REQUIRED when disposition is indeterminate;
                                       // sha256(canonical_JCS(prior established receipt))
  observedAt: number                   // unix ms; observer time, not consensus time
  blockRef?: {
    id: string                         // canonical block/state identifier
    height?: string                    // decimal string; avoids JSON safe-integer ambiguity
    timestamp?: number                 // consensus timestamp, unix ms
  }
  replacementTransactionRef?: {              // REQUIRED for state == "replaced" when known
    kind: string
    value: string
  }
  evidence: {
    kind: string                       // binding-defined proof/receipt kind
    value: string                      // canonical encoded evidence or evidence locator
  }
}
```

`AnchorReceipt` is evidence *about* an artifact anchor; it is not itself required to be anchored, avoiding an infinite receipt-about-receipt regress. A later observation produces another immutable snapshot for the same `(substrate, logicalAddress, nativeAddress, contentHash, transactionRef)` tuple. It MUST NOT mutate or silently replace an earlier snapshot. An `established` snapshot claims the lifecycle state shown in `state`. An `indeterminate` snapshot MUST repeat the prior established receipt's state and carry its canonical hash in `preservedReceiptHash`; a consumer MUST verify that referenced prior receipt before relying on the preserved state. If no established receipt newer than local submission exists, the writer first retains the `submitted` receipt and an indeterminate observation preserves that baseline.

- (SR2-4) Every receipt MUST carry binding-defined evidence for its claimed observation. An `established` receipt claiming `accepted`, `included`, or `finalized` MUST carry enough authenticated evidence for an independent consumer to verify that state. An `indeterminate` receipt MUST carry evidence of the observation failure or unorderable conflict and MUST satisfy the preserved-receipt rules above; it cannot establish a lifecycle state on its own. The receipt fields alone are assertions, not proof.
- (SR2-5) Every receipt MUST bind one canonical logical address, its actual native address, the artifact content hash, transaction reference, writer, and applicable nonce. On a mismatch in any available binding, a consumer MUST reject the receipt as invalid; the mismatch is not an `indeterminate` observation and does not identify a different artifact.
- (SR2-6) An `included` or `finalized` receipt MUST carry `blockRef`. A `finalized` receipt MUST identify the finality profile under which finality was established. Consensus time for an anchor is `blockRef.timestamp`; `observedAt` MUST NOT substitute for it.
- (SR2-7) Consumers MUST validate each `established` lifecycle transition against the graph above. In particular, `dropped`, `expired`, or `reorged` cannot themselves satisfy a success gate, but a later authenticated `accepted`/`included`/`finalized` snapshot MAY do so through the defined re-entry path. A `replaced` transaction cannot satisfy a gate unless the consumer separately verifies a qualifying receipt for the replacement. Each SR-2 binding MUST define how authenticated native evidence orders and reconciles snapshots for one transaction; `observedAt` MUST NOT determine precedence. Conflicting snapshots that the binding cannot order produce an `indeterminate` observation disposition over the unchanged last established state, including when that state is `included` or `finalized`.

**Cross-stage gates.** DACS distinguishes reversible progression, irreversible effects, and terminal audit publication:

| DACS point | Minimum SR-2 requirement |
| --- | --- |
| DACS-1 active listing publication/discovery | `finalized`, and independently resolvable |
| DACS-2 Vet result | verified durable `accepted` MAY permit reversible progression; `finalized` required by terminal bundle production |
| DACS-3 agreement signature | valid required party signatures permit commitment submission; no SR-2 state is implied |
| DACS-3 commitment | `finalized` before any payment or irreversible delivery; only a `dacs-purchase-v1` Work satisfying every DACS-3 AWP-6..AWP-11 condition may validate and co-finalize that commitment with its payment |
| DACS-4 payment | payment rail's declared finality; its SR-2 evidence anchor MAY catch up asynchronously |
| DACS-5 completed terminal bundle | every required referenced artifact `finalized` and independently resolvable; bundle anchor itself `finalized` |

- (SR2-8) A reversible step MAY progress on verified durable `accepted` when
  its stage rule permits it. Every payment, release of value, or irreversible
  delivery MUST wait for the agreement commitment's `finalized` receipt,
  except that one `dacs-purchase-v1` Work MAY validate and co-finalize the
  commitment with its payment only when every DACS-3 AWP-6 through AWP-11
  condition is satisfied. Any missing condition restores the ordinary
  finalized-receipt gate before signing or submission. This exception does not
  apply to an irreversible delivery. A binding MAY satisfy the ordinary gate
  at `included` only when its declared finality profile makes inclusion final.
- (SR2-9) A `completed` bundle MAY be constructed and signed in preparation for anchoring, but it MUST NOT be treated as terminal or published as a completed audit artifact until every required referenced SR-2 artifact and the bundle itself meet the `finalized` and independent-resolution requirements. Rail-final payment success is not reversed while its evidence anchor catches up; the session remains non-terminal until the audit prerequisites are met.

**SR-2 read outcomes and authoritative absence (normative).** An SR-2 read has one of three dispositions: `present`, `absent`, or `indeterminate`. `present` means content was returned for the requested native address; the consuming rule still verifies its canonical hash, signatures, and artifact-specific bindings. `absent` means the applicable substrate binding's declared absence-evidence policy established that no record exists at that address in the policy's referenced finalized state. Every other no-content result is `indeterminate`, including a transport error, an ordinary unqualified `not found`, a stale response, or mutually inconsistent state views.

An SR-2 binding MAY omit authoritative absence support. A binding that supports a DACS decision whose outcome depends on absence MUST declare an absence-evidence policy specifying:

- the finalized state or finality rule against which absence is evaluated;
- how each response or proof is authenticated;
- the independence and threshold requirements when a read quorum is used; and
- the freshness and state-consistency checks applied before combining responses.

A finalized non-membership proof or a binding-defined authenticated independent quorum MAY satisfy that policy. DACS does not prescribe one mechanism or a universal quorum number. When the binding has no declared policy, or a read does not satisfy it, a consumer MUST return `indeterminate` rather than promote non-observation to `absent`. This requirement changes no signed artifact shape; absence evidence is substrate read context retained by the consumer.

**Substrate-coupling status in v0.1.**

- **SR-1, SR-2, and SR-5 are specified at the protocol level.** Another substrate that ships an equivalent primitive (cross-substrate identity aggregation; content-addressed anchored storage; atomic cross-chain settlement) can interoperate with DACS implementations on Demos at the artifact level: the bundles, listings, and evidence records validate the same way.
- **SR-3 and SR-4 are specified at the trust-property level only in v0.1.** Two substrates each shipping their own SR-3 (consensus-backed proxy attestation) or SR-4 (identity-keyed private coordination) implementations will *not* be wire-protocol interoperable. The trust properties listed under CH-1..CH-6 for SR-4 and under §7.3.5 for SR-3 are the conformance bar v0.1 requires; the underlying message formats and consensus signatures are substrate-specific. Consequence, until the v2 wire formats ship (see note below): a session begun on substrate A cannot be completed on substrate B if it uses any SR-3- or SR-4-dependent phase.

> **Note (non-normative).** v2 of DACS-2 and DACS-3 is expected to specify wire formats for SR-3 attestation envelopes and SR-4 channel messages that enable cross-substrate interoperability.

**Reference substrate.** The **Demos Network** is the substrate against which DACS was designed and, as of this draft, the only substrate that ships all five capabilities natively. The DACS specifications cite the substrate capabilities (SR-1 through SR-5), not the Demos primitives themselves; this separation keeps the artifact-level specification portable while staying honest about which primitives are concretely realised today and where v2 work is needed.

### 5.2 Atomic DACS Work profile

The Atomic DACS Work profile is an optional execution profile for a successful
DACS purchase. It compiles existing DACS artifacts and phase results into two
atomic business Works. It does not replace the underlying DACS-2 through DACS-5
artifact rules.

The normative machine-readable schemas are:

- [`AtomicDacsWorkIntentV1`](schemas/atomic-dacs-work-intent-v1.schema.json);
- [`AtomicWorkAuthorizationV1`](schemas/atomic-work-authorization-v1.schema.json);
- [`AtomicWorkAttemptV1`](schemas/atomic-work-attempt-v1.schema.json); and
- [`AtomicWorkReceiptV1`](schemas/atomic-work-receipt-v1.schema.json).

The closed v1 operation-payload contracts are:

- [`AtomicAssertArtifactPayloadV1`](schemas/atomic-assert-artifact-payload-v1.schema.json);
- [`AtomicStorageProgramPutPayloadV1`](schemas/atomic-storage-program-put-payload-v1.schema.json);
- [`AtomicPaymentSlotCasPayloadV1`](schemas/atomic-payment-slot-cas-payload-v1.schema.json);
- [`AtomicNativeDemTransferPayloadV1`](schemas/atomic-native-dem-transfer-payload-v1.schema.json); and
- [`AtomicAssertWorkReceiptPayloadV1`](schemas/atomic-assert-work-receipt-payload-v1.schema.json).

These payload schemas define portable signed intent data, not a Demos SDK
class or native transaction encoding. The authenticated execution profile
still determines how a node realizes each contract and how its effects are
proved.

Demos already provides a generic Atomic Work execution primitive. This section
defines the narrower DACS-specific binding over that primitive; it does not
require Atomic Work to be rebuilt and does not assert that a requirement is
absent from an unpublished Demos release. The capability gate below establishes
which exact release, native mapping, consensus guarantees, and proof behavior
may make a DACS Atomic-profile claim.

#### 5.2.1 Scope, capability, and fallback

- (AW-1) An implementation MUST use this profile only after verifying an
  authenticated `AtomicWorkCapabilityV1` for the selected network and execution
  profile. Its evidence MUST authenticate the exact network, execution profile,
  proof profile, validator-set identifier, supported algorithms, operation
  kinds, payload-schema identifiers, and enforced limits. The expected
  `networkAuthority` MUST come from the authenticated network binding or a
  separately trusted profile registry; a capability's self-declared authority
  and a key bundled only by its presenter MUST NOT bootstrap that trust root.
- (AW-2) An implementation that lacks a verified capability MUST use the
  existing multi-transaction lifecycle or refuse the session before any Atomic
  Work is signed.
- (AW-3) After an Atomic Work is signed or submitted, an implementation MUST
  NOT silently submit the corresponding payment through another profile or the
  legacy path.
- (AW-4) A successful v1 lifecycle consists of an Atomic Purchase Work, agent
  execution, an Atomic Completion Work, and an idempotent audit-finalisation
  tail.
- (AW-5) An implementation MUST NOT describe the complete current-model DACS
  lifecycle as exactly two consensus transactions.

`AtomicWorkCapabilityV1` has this minimum shape:

```
type AtomicWorkCapabilityV1 = {
  capabilityVersion: "1"
  networkAuthority: ClaimReference
  networkId: string
  executionProfile: string
  workVersions: "1"[]
  profiles: ("dacs-purchase-v1" | "dacs-completion-v1")[]
  operationKinds: AtomicWorkOperationKindV1[]
  payloadSchemas: Record<AtomicWorkOperationKindV1, string>
  authorizationAlgorithms: ("ed25519" | "ecdsa-secp256k1" | "sr1-aggregate")[]
  proofProfile: string
  validatorSetId: string
  limits: {
    maxCanonicalBytes: number
    maxOperations: number
    maxExecutionTimeMs: number
    maxProofBytes: number
    feeRule: string
  }
  evidence: { kind: string; value: string }
}
```

A self-reported SDK feature flag or successful simulation is not capability
evidence.

> **Note (non-normative).** The two Works optimize the irreversible business
> path. Current DACS-4 evidence and DACS-5 bundles still depend on finalized
> receipt fields and therefore remain in the audit tail.

#### 5.2.2 Canonical unsigned intent and `workId`

```
type AtomicDacsWorkIntentV1 = {
  workVersion: "1"
  executionProfile: string
  profile: "dacs-purchase-v1" | "dacs-completion-v1"
  networkId: string
  railId: string
  jobId: string
  phaseIndex: number
  expiresAt: number
  priorFailureReceiptCommitment?: string
  roleRoster: AtomicWorkRoleBindingV1[]
  operations: AtomicWorkOperationV1[]
}

type AtomicWorkRoleBindingV1 = {
  role: "buyer" | "seller" | "orchestrator" | "payer"
  signer: ClaimReference
  nativeAccount?: string
}

type AtomicWorkOperationV1 = {
  operationId: string
  kind: AtomicWorkOperationKindV1
  critical: true
  dependsOn: string[]
  requiredRoles: ("buyer" | "seller" | "orchestrator" | "payer")[]
  payload: Record<string, unknown>
}

type AtomicWorkOperationKindV1 =
  | "assert-artifact"
  | "storage-program-put"
  | "payment-slot-cas"
  | "native-dem-transfer"
  | "assert-work-receipt"
```

`nativeAccount`, when present, is a signed expectation rather than an authority
claim. The selected execution profile MUST independently derive the native
account for that signer and role from authenticated identity, agreement, payer,
and rail inputs and MUST compare it byte-for-byte with `nativeAccount` and any
account-bearing operation payload. A value that cannot be independently
derived or does not match MUST be rejected; a caller-supplied roster value MUST
NOT establish account ownership, payment authority, or signer-to-account
linkage.

- (AW-6) The unsigned intent MUST be a pure JSON data value conforming to
  `AtomicDacsWorkIntentV1`.
- (AW-7) An intent MUST NOT contain a runtime class, callback, `Map`, `Set`,
  mutable SDK object, or implementation-defined serialized value.
- (AW-8) Producers MUST apply CF-1 and CF-2 before RFC 8785 JCS serialization.
- (AW-9) Every JSON number in an intent MUST satisfy the §B.2 safe-integer
  constraint.
- (AW-10) `roleRoster` MUST be ordered as buyer, seller, orchestrator, payer,
  omitting absent roles without reordering the remaining roles.
- (AW-11) Each role MUST occur at most once in `roleRoster`; one signer MAY
  hold more than one distinct role.
- (AW-12) Each `requiredRoles` array MUST follow the same role order and MUST
  contain no duplicate.
- (AW-13) `operations` array order is execution order and MUST NOT be inferred
  from object-member order or implementation iteration order.

The canonical bytes and identifier are:

```
canonicalWorkBytes = UTF8(JCS(unsignedIntent))
workId = lowerhex(SHA-256(
  UTF8("dacs-atomic-work:v1:") || canonicalWorkBytes
))
```

- (AW-14) The `workId` preimage MUST include every unsigned-intent member,
  including unknown preserved members.
- (AW-15) Authorizations, simulations, receipts, observations, outer nonce,
  outer fee, transport signature, attempt ID, and native transaction hash MUST
  remain outside `canonicalWorkBytes`. The only receipt-derived intent member
  is `priorFailureReceiptCommitment`, when required for a slot retry under DACS-4
  AWS-12.
- (AW-16) A producer or node MUST derive `workId`; a caller-supplied value MUST
  be recomputed before admission.
- (AW-17) A claimed `workId` with different canonical bytes MUST be rejected.
- (AW-18) Identical canonical bytes presented under a different claimed ID
  MUST be rejected or normalized to the derived ID before admission.
- (AW-19) `executionProfile` MUST identify fork-independent bytes or pin every
  fork rule that can affect execution or receipt interpretation.
- (AW-20) A node MUST reject an unsupported or mismatched execution profile
  before executing any operation.
- (AW-76) `expiresAt` is a Unix-millisecond consensus cutoff. At the consensus
  transition that would execute the first operation, the authenticated
  consensus timestamp MUST be strictly less than `expiresAt`; equality is
  expired. An expired Work MUST be rejected before any operation executes. A
  receipt for included execution MUST therefore have `blockRef.timestamp <
  expiresAt`. Client, signer, RPC, and Indexer clocks MUST NOT decide this
  predicate.

`workId` is the immutable business-intent identifier. It is not a native
transaction hash and has no synonymous `intentId` in v1.

#### 5.2.3 Operation and dependency validation

- (AW-21) Every `operationId` MUST match `[a-z][a-z0-9-]{0,63}` and be unique
  within the intent.
- (AW-22) Every dependency MUST name an earlier operation in the signed array.
- (AW-23) A dependency cycle, unknown dependency, self-dependency, or future
  dependency MUST be rejected before authorization or execution.
- (AW-24) Every v1 operation MUST have `critical: true`.
- (AW-25) The v1 operation-kind set is closed to the five kinds in
  `AtomicWorkOperationKindV1`.
- (AW-26) Every critical operation effect MUST participate in the same isolated
  business-state overlay.
- (AW-27) A client preflight or simulation MUST NOT substitute for node-enforced
  isolation, ordering, validation, or rollback.
- (AW-28) An XM, Web2, HTTP, bridge, L2PS, messaging, or other externally
  irreversible action MUST NOT appear as a rollback-covered v1 operation.
- (AW-29) An unknown operation kind MUST be rejected before any operation
  executes.

The operation names above identify semantic families. The five published
payload schemas provide their portable signed wire grammar. The authenticated
`executionProfile` and capability select those exact schema identifiers and
pin their native execution and proof interpretation, including artifact
hash/signature checks, Storage Program address realization, payment-slot CAS,
native-transfer account authority, and prior-receipt verification.

- (AW-77) A node MUST reject an operation before authorization or execution if
  its payload does not conform to the selected execution profile's advertised
  byte-exact schema, or if that advertised identifier is not the published v1
  schema for the operation kind. An implementation MUST NOT infer missing
  payload members from an SDK object, caller state, or operation label. For
  `storage-program-put`, `writeCondition: { kind: "create-only" }` rejects an
  existing different value but reconciles an already committed byte-identical
  value; `writeCondition: { kind: "compare-and-set", expectedContentHash }`
  requires authenticated current content with that exact hash and MUST reject
  absence or a different hash. Neither condition permits overwrite based on
  ordinary read non-observation.

Generic Demos Atomic Work support does not by itself qualify these schemas for
the DACS-specific binding. A Demos implementation MUST NOT claim that binding
until §A.6 pins the native realization and proof contract for these schemas. At
the semantic level, `assert-artifact` verifies complete immutable artifact bytes
and their existing signatures;
`storage-program-put` writes complete immutable bytes under its signed
condition; `payment-slot-cas` applies §9.5.10; `native-dem-transfer` moves
native DEM; and `assert-work-receipt` verifies a prior finalized Work receipt.

#### 5.2.4 Operation authorizations

```
type AtomicWorkAuthorizationV1 = {
  authorizationVersion: "1"
  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"
  workId: string
  executionProfile: string
  networkId: string
  railId: string
  jobId: string
  phaseIndex: number
  operationId: string
  operationIndex: number
  operationKind: AtomicWorkOperationKindV1
  role: "buyer" | "seller" | "orchestrator" | "payer"
  signer: ClaimReference
  value: string
}
```

The signed authorization bytes are:

```
authorizationHash = lowerhex(SHA-256(
  UTF8(JCS(authorizationWithoutValue))
))
signedAuthorizationBytes =
  UTF8("dacs-atomic-work-authorization:v1:") || ASCII(authorizationHash)
```

- (AW-30) An authorization MUST sign every envelope member except `value`, and
  its algorithm MUST be supported by the verified capability.
- (AW-31) A verifier MUST recompute `workId` before verifying an authorization.
- (AW-32) The operation ID, index, and kind MUST match the signed intent at
  that index.
- (AW-33) The role and signer MUST match one canonical `roleRoster` entry, and
  that entry MUST independently match the pre-execution DACS authority: buyer
  and seller match the corresponding verified signed `AgreementParty` primary
  claim; orchestrator matches the verified finalized commitment-record signer
  and, when present, the authenticated `SessionContext.parties` orchestrator;
  payer matches `PaymentPhaseInput.payer.payingKey`, after verifying that key
  appears in the pinned payer bundle and that the input's `bundleHash` and
  `primaryClaim` match the agreement buyer. A self-consistent roster is not
  role authority. A later DACS-5 `BundleParty` map is an AWB-3 audit
  cross-check, not a circular pre-execution input.
- (AW-34) The verifier MUST verify one authorization for every operation role
  listed in `requiredRoles`.
- (AW-35) A mutation of any signed authorization member MUST invalidate the
  authorization.
- (AW-36) An authorization for another Work, network, session, payment slot,
  operation, role, signer, version, or algorithm MUST NOT be replayed.
- (AW-37) The outer submitter or fee payer MUST NOT establish a DACS role or an
  operation authorization.
- (AW-38) A Vet verifier signature MUST NOT authorize payment unless that same
  signer separately holds and authorizes the payer role.

Signature-value encoding follows SIG-6.

#### 5.2.5 Transport attempts, replacement, and winner selection

```
type AtomicWorkAttemptV1 = {
  attemptVersion: "1"
  workId: string
  attemptId: string
  nativeTransactionRef: { kind: string; value: string }
  canonicalWorkBytes: string
  authorizations: AtomicWorkAuthorizationV1[]
  nonce?: string
  fee?: string
}
```

`canonicalWorkBytes` is carried in JSON as the exact RFC 8785 JCS text; its
UTF-8 encoding MUST equal §5.2.2 `canonicalWorkBytes` byte-for-byte. It is not
Base64URL and a parser/re-serializer output is not a substitute for comparing
the carried text. `authorizations` carries the complete envelopes required by
the Work; a transport MAY additionally index them elsewhere, but such an index
does not replace this attempt-to-authorization binding.

- (AW-39) Every attempt for one `workId` MUST carry byte-identical
  `canonicalWorkBytes` and authorizations valid for that Work.
- (AW-40) Each native envelope or transaction hash MUST identify a distinct
  transport attempt without changing `workId`.
- (AW-41) A replacement attempt MAY be admitted only after authenticated
  lifecycle evidence proves the superseded attempt cannot later execute.
- (AW-42) Local-clock expiry, a transport timeout, or ordinary `not found` MUST
  leave replacement authority `indeterminate`.
- (AW-43) The authoritative ledger MUST select at most one winning included
  attempt for a `workId`.
- (AW-44) After a winner is selected, every late or competing attempt MUST be
  fenced before any business effect.
- (AW-45) Exact replay after selection MUST return or reconstruct the winner's
  status and MUST NOT execute the Work again.

The Work ledger relation is:

```
canonicalWorkBytes <-> workId -> transportAttempts[] -> winningAttempt?
```

Receipt order, authenticated lifecycle evidence, and the winner ledger are
consensus facts. Client observation time MUST NOT select a winner.

#### 5.2.6 Authenticated Work receipts and rollback

```
type AtomicWorkReceiptV1 = {
  receiptVersion: "1"
  executionProfile: string
  profile: "dacs-purchase-v1" | "dacs-completion-v1"
  networkId: string
  workId: string
  winningAttempt: {
    attemptId: string
    nativeTransactionRef: { kind: string; value: string }
  }
  blockRef: { id: string; height?: string; timestamp: number }
  outcome: "committed" | "rolled-back"
  failedOperationId?: string
  operationResults: AtomicWorkOperationReceiptLeafV1[]
  operationReceiptRoot: string
  businessState: {
    preRoot: string
    postRoot: string
    effectsRoot: string
    evidence: { kind: string; value: string }
  }
  paymentSlot: {
    key: {
      networkId: string
      railId: string
      jobId: string
      phaseIndex: number
    }
    before: Record<string, unknown>
    after: Record<string, unknown>
  }
  slotStateEvidence: { kind: string; value: string }
  envelopeEffects: { nonceConsumed: boolean; feeCharged: string }
  receiptCommitment: string
  finalityEvidence: { kind: string; value: string }
}

type AtomicWorkOperationReceiptLeafV1 = {
  operationId: string
  operationIndex: number
  operationKind: AtomicWorkOperationKindV1
  inputHash: string
  status: "committed" | "rolled-back" | "not-executed"
  outputHash?: string
  storageOutput?: {
    logicalAddress: string
    nativeAddress: string
    contentHash: string
    writer: string
    nonce?: string
  }
  errorCode?: string
}
```

For every leaf, the portable input commitment is derived from the exact signed
operation payload:

```
inputHash = lowerhex(SHA-256(UTF8(JCS(operation.payload))))
```

The authenticated execution profile MUST define the byte-exact derivation and
verification procedure for each kind's optional `outputHash` and for
`businessState.effectsRoot`; those values are not SDK annotations. A receipt
verifier MUST recompute every `inputHash` from the canonical Work before
accepting the operation root, and MUST verify profile-defined output/effect
commitments under the selected proof profile.

The consensus-bound receipt core is the complete receipt with
`receiptCommitment`, `finalityEvidence`, the detachable
`businessState.evidence`, `slotStateEvidence`, the post-transition
`blockRef.id`, and, for a Purchase receipt only, the terminal
`paymentSlot.after.receiptCommitment` or
`paymentSlot.after.failureReceiptCommitment` back-reference omitted. A
Completion receipt preserves the complete terminal Purchase slot state in both
`before` and `after`, including the Purchase commitment back-reference; that
prior value is not self-referential to the Completion receipt and remains in
the Completion core. Every other slot member remains in the core. Its
commitment is:

```
receiptCommitment = lowerhex(SHA-256(
  UTF8("dacs-atomic-work-receipt:v1:") || UTF8(JCS(receiptCore))
))
```

The detachable `finalityEvidence` authenticates that exact
`receiptCommitment` together with the finalized `blockRef.id`; the detachable
business-state evidence proves the core's business roots, and
`slotStateEvidence` carries or resolves an authenticated slot-state proof for
the exact key/before/after members (excluding only the circular
Purchase terminal commitment back-reference already reconstructed above).
The canonical commitment is then inserted at the top level and, for Purchase,
into the applicable terminal slot back-reference. Completion inserts only its
top-level commitment and MUST NOT replace the Purchase commitment copied in
its unchanged slot state. The canonical content hash used to resolve the
complete receipt envelope is the ordinary CORE §B.2
`sha256(UTF8(JCS(workReceipt)))`, including both members. This separates the
same-transition consensus commitment from the later-served proof envelope and
avoids a circular proof preimage.

- (AW-46) A receipt MUST bind the canonical Work, winning attempt, network,
  finalized block, ordered operation results, business roots, slot transition,
  and envelope effects. For Purchase, its `paymentSlot.key` MUST equal the
  intent's structured `(networkId, railId, jobId, phaseIndex)` tuple. A
  committed Purchase MUST prove a terminal `settled` slot; a rolled-back
  Purchase MUST prove the same generation's terminal `rolled-back` recovery
  metadata with its failure-receipt hash. For Completion, the key and unchanged
  terminal `settled` state (`before == after`) MUST be copied from the
  independently verified Purchase receipt; Completion's own `phaseIndex`
  continues to identify its delivery phase and MUST NOT be substituted for the
  Purchase payment phase index.
- (AW-47) Receipt fields alone MUST NOT establish finality or execution.
- (AW-48) `finalityEvidence` MUST be independently verifiable against an
  authenticated validator set or trusted checkpoint and MUST authenticate the
  exact `receiptCommitment`. `businessState.evidence` MUST independently prove
  the reported business roots under the selected proof profile. The receipt's
  evidence closure MUST additionally prove the exact slot key, prior state,
  terminal state, generation, Work, and conflict digest from authenticated
  consensus state; an authenticated finality proof over a receipt assertion is
  not by itself a slot-state proof.
- (AW-49) A receipt MUST be obtainable or reconstructible from finalized
  consensus data without public Indexer hydration.
- (AW-50) Business-state commit and `receiptCommitment` MUST occur in one
  consensus transition. A verifier MUST recompute `receiptCommitment` from the
  receipt core before verifying the detachable finality proof. It MUST NOT
  include the transition's not-yet-determined block ID or detachable proof
  bytes, or either self-referential Purchase terminal-slot commitment field,
  in that commitment. For a Purchase receipt, the applicable terminal-slot
  commitment field MUST equal the recomputed top-level value. For Completion,
  the unchanged `before` and `after` terminal fields MUST instead retain the
  independently verified Purchase receipt's commitment and are included in
  the Completion core. Finality evidence binds the resulting block ID back to
  the commitment, and each detached proof MUST bind the exact committed subject
  it proves.
- (AW-51) The receipt's operation array MUST reproduce the signed operation
  order exactly. Its RFC 6962 tree MUST NOT duplicate or drop an odd leaf.

Operation leaves and their root are computed as follows:

```
leafHash = SHA-256(
  0x00 || UTF8("dacs-atomic-operation-receipt:v1:") || UTF8(JCS(leaf))
)
nodeHash = SHA-256(0x01 || leftRaw32 || rightRaw32)
emptyRoot = SHA-256(emptyByteString)
```

For more than one leaf, the tree uses RFC 6962's recursive split at the largest
power of two smaller than the leaf count.

- (AW-52) A committed receipt MUST mark every operation `committed`.
- (AW-53) A rolled-back receipt MUST mark executed critical operations
  `rolled-back` and later operations `not-executed`.
- (AW-54) A rolled-back receipt MUST prove equality of all profile-declared
  critical business-state domains. The `paymentSlot` execution/recovery
  metadata is an explicit, receipt-bound rollback exception: its terminal
  `rolled-back` state records failure and fences the generation but is excluded
  from the business roots and cannot itself transfer value or authorize
  payment without DACS-4 AWS-11 and AWS-12.
- (AW-55) A rolled-back receipt MUST prove unchanged value or non-membership
  for every payment or artifact output the Work could have created.
- (AW-56) Outer fee charging and nonce consumption MAY persist after business
  rollback and MUST be reported separately.
- (AW-57) Fee or nonce consumption MUST NOT authorize another payment.
- (AW-58) An included rollback receipt proves an included failure only; it MUST
  NOT prove that another attempt was never admitted or included.
- (AW-59) Pre-admission rejection, drop, and expiry require authenticated
  lifecycle or authoritative non-inclusion evidence under §5.1.
- (AW-60) Missing proof material MUST produce `indeterminate`; contradicted
  proof material MUST be rejected.

Crash recovery follows the consensus boundary:

- (AW-61) A crash before durable admission MUST be reconciled without inferring
  absence.
- (AW-62) A crash during overlay execution MUST leave no committed business
  effect.
- (AW-63) A crash after consensus commit MUST recover the same receipt and
  winner by `workId`.
- (AW-64) Receipt-service unavailability after commit MUST remain
  `indeterminate` and MUST NOT authorize resubmission.

#### 5.2.7 Projection to `AnchorReceipt`

```
type DemosWorkOperationRefV1 = {
  kind: "demos-work-operation-v1"
  networkId: string
  workId: string
  operationIndex: number
  operationId: string
  operationKind: AtomicWorkOperationKindV1
}
```

Each committed `storage-program-put` result projects to a CORE §5.1
`AnchorReceipt`. The projection uses the operation leaf and the verified outer
receipt, not a client-generated receipt.

- (AW-65) The projected receipt MUST copy `logicalAddress`, `nativeAddress`,
  `contentHash`, `writer`, and nonce from the verified operation leaf.
- (AW-66) The projected receipt MUST copy block, finality, network, and
  lifecycle state from the verified Work receipt.
- (AW-67) Its `transactionRef.kind` MUST be
  `demos-work-operation-v1`.
- (AW-68) Its `transactionRef.value` MUST be `<workId>/<operationId>` using the
  canonical lowercase `workId` and the validated operation ID. The evidence
  that resolves this value MUST carry the complete structured
  `DemosWorkOperationRefV1`, including its network, operation index, and kind.
- (AW-69) Its evidence MUST carry or resolve the Work receipt, operation leaf,
  inclusion path, and finality proof.
- (AW-70) A projected receipt MUST remain independently verifiable when the
  public Indexer is unavailable or behind consensus. The consumer MUST also
  verify the artifact-specific role or writer authority required by the
  consuming rule; a valid receipt and matching hash alone do not grant control
  of a logical address.

One Work receipt may project multiple `AnchorReceipt`s. Every projection has a
different operation reference and retains all SR2-4 through SR2-6 checks.

#### 5.2.8 Limits and security boundary

- (AW-71) A node MUST enforce the authenticated capability's canonical-byte,
  operation-count, execution-time, proof-byte, and fee limits before committing
  business effects or returning proof material as conforming evidence.
- (AW-72) A client-side limit check MUST NOT substitute for node enforcement.
- (AW-73) A client-generated receipt, status, slot label, or rollback summary
  MUST NOT be treated as authoritative.
- (AW-74) A proof-bound structured identity MUST be compared component-wise and
  type-strictly; a concatenated display string MUST NOT control a safety
  decision.
- (AW-75) An implementation MUST preserve the last authenticated state when a
  later observation is `indeterminate`.

> **Note (non-normative).** The principal threats are cross-Work double
> settlement, authorization replay, transport replacement races, partial
> critical state, receipt substitution, false absence, and transport-sender
> role confusion. The rules above keep every safety decision on authenticated
> consensus or DACS signature evidence.

#### 5.2.9 Security considerations

Atomic batching concentrates several existing trust boundaries in one
consensus transition. The principal attacks are two Works racing the same
payment slot, authorization replay into another context, a late transport
attempt executing after a winner, partial critical state surviving rollback,
receipt or proof substitution, false absence authorizing a retry, and confusion
between the outer sender and a DACS role. AW-14 through AW-77, DACS-4 AWS-1
through AWS-29, and DACS-5 AWB-1 through AWB-10 address those attacks.

The profile inherits the advertised substrate's consensus, validator-set,
key-resolution, and data-availability assumptions. It adds no fair-exchange
guarantee between Purchase and Completion, no authenticated-absence guarantee
where the binding has none, and no reason to trust client or Indexer summaries.
A Demos implementation may provide generic Atomic Work independently; it MUST
NOT claim the DACS-specific binding until §A.6's runtime and proof contracts are
pinned and independently demonstrated.

## A. Demos production mapping

Moved to **[DEMOS-MAPPING.md](DEMOS-MAPPING.md)** (section numbering retained). Which Demos substrate primitives are live today, what the Demos team adds for v0.1, and which dependencies are third-party — for each substrate capability SR-1..SR-5.

## B. Global terminology

Terms used in more than one per-stage chapter are defined here once. Per-stage chapters define only terms unique to that stage.

### B.1 Claim references and identity

- **Claim.** A fact a party asserts about itself (e.g., "this agent’s FINRA CRD is 12345").
- **Claim reference.** A typed identifier referring to the external system that authoritatively holds a claim. The reference is of the form <scheme>:<identifier>[?<parameters>]. Grammar and v0.1 registry defined in chapter 6 (DACS-1).
- **ClaimReference (type).** The typed equivalent of a claim reference used in JSON schemas throughout the spec.
- **Primary identity claim.** The claim within a bundle that serves as the canonical identifier of the party for reputation, audit, and addressing purposes. Determined by the presentedBy field of the bundle and the primaryClaimSelector of the requirement.
- **Identity bundle.** An ordered set of claims a party presents about itself, each independently verifiable, plus a presentation signature. Full schema in chapter 6 (DACS-1).

**Canonical form and identity (rules CF-2, CF-3).** A ClaimReference has two distinct canonical forms. The *canonical byte form* is **the bytes embedded** whenever the reference appears inside a hashed or signed document, so the JCS canonical form is reproducible. The *canonical identity* is **the value compared** for matching, reputation keying, and the §7.3.2 cross-session replay defence:

- (CF-2) **Canonical byte form.** Before a ClaimReference is embedded in any document that is JCS-canonicalised, hashed, signed, or compared, it MUST be in canonical form:
  - (a) **Scheme** lowercased — this promotes the SHOULD-emit-lowercase scheme rule (§6.3.1) to a MUST for any reference that is hashed, signed, or compared;
  - (b) **Identifier** NFC-normalised (rule CF-1, §B.2) and otherwise per the scheme's identifier rule (§6.3.1);
  - (c) **Parameters**, if present, sorted by key in Unicode code-point order and joined with the fixed `&`/`=` separators, with the reserved characters `:`, `?`, `&`, `=`, and `%` percent-encoded using uppercase hex (e.g. `%3A`). Sorting parameters into canonical order is NOT the "silent stripping" prohibited by the §6.3.1 forwarding rule — no parameter is dropped, only deterministically ordered.
- (CF-3) **Canonical identity.** The identity of a party for matching, reputation keying, and replay defence is the pair (canonical Scheme, canonical Identifier) **only**. Parameters are advisory qualifiers and MUST NOT contribute to identity: `cci-xm:evm:mainnet:0xA?jurisdiction=US` and `cci-xm:evm:mainnet:0xA` are the same party and MUST key to the same reputation record. Wherever this specification requires two references to match "canonically" or "by canonical scheme and identifier" (§6.3.2, §7.3.2, §6.6), it means equality of this (Scheme, Identifier) pair after CF-1/CF-2 normalisation.

**Rule CF-4 (logical-address delimiter encoding).** A `dacsN:` logical address is colon-delimited, but a variable segment can itself contain the `:` delimiter (and, for a ClaimReference, also `?`, `&`, `=`): `sellerPrimaryClaim` is a ClaimReference (e.g. `cci-xm:evm:mainnet:0x1234`). The rules:

- Every colon-bearing variable segment (`sellerPrimaryClaim` and the equivalent segments of derived addresses) MUST have its reserved delimiters — `:`, `?`, `&`, `=`, `%` — percent-encoded with uppercase hex **before** the address is assembled.
- `sellerPrimaryClaim` MUST already be in CF-2 canonical form before encoding.
- `listingId` is constrained to URL-safe ASCII per §6.3.4, so it carries no reserved delimiters to encode.

After encoding, the only unescaped colons are the fixed structural delimiters, so a reader knowing the pattern splits on them and percent-decodes each segment back to its exact original value.

> **Note (non-normative).** Left raw, the boundaries between segments are undecidable from the string alone, so the universal reversibility guarantee (§"Logical vs native addresses") would be unsatisfiable on any substrate that parses the logical address directly. This is the same `%3A`-style encoding the specification already uses for `primaryClaimRef` in the discovery/catalog surface.

Worked example — primary claim `cci-xm:evm:mainnet:0x1234`, `listingId` `my-listing`, version 3:

```
logical_address := "dacs1:cci-xm%3Aevm%3Amainnet%3A0x1234:my-listing:v3"
```

The CF-4-encoded `logical_address` is the reversibly-parseable canonical identifier. CF-4 governs only how the address *string* is written so it parses back unambiguously — it does **not** itself assert a native-address formula. How the string maps to a substrate's *native* address (pure recomputation vs published write-input binding) is governed by the front-matter universal rule and, for Demos, the DACS-1 §6.3.4 Demos-binding block.

Rule CF-4 (above) applies identically to every logical-address kind. Per address, the **variable** segments (which MUST be percent-encoded) and the **fixed structural** segments (which MUST NOT) are:

| Address | Variable segment(s) — encode | Fixed segments — don't |
| --- | --- | --- |
| `dacs1:{sellerPrimaryClaim}:{listingId}:v{listingVersion}` (listing) | `sellerPrimaryClaim` (a ClaimReference) | `listingId`, `v{listingVersion}` |
| `dacs1-revoked:{sellerPrimaryClaim}:{listingId}:v{listingVersion}` (revocation marker) | `sellerPrimaryClaim` | `listingId`, `v{listingVersion}` |
| `dacs4:payment:{jobId}:{railId}:{phaseIndex}` (+ optional `:resolved`, §9.5.1 PC-2) | `railId` — e.g. `evm-erc20:1:USDC` → `evm-erc20%3A1%3AUSDC` | `jobId`, `phaseIndex`, `resolved` |
| `dacs4:payment:{jobId}:{railId}:{phaseIndex}:atomic:{generation}:{atomicSettlementId}` (Atomic payment evidence, §9.7.3) | `railId` | `jobId`, `phaseIndex`, `atomic`, `generation`, `atomicSettlementId` |
| `dacs4:delivery:{jobId}:{phaseIndex}:atomic:{atomicSettlementId}` (Atomic delivery evidence, §9.7.3) | none | `jobId`, `phaseIndex`, `atomic`, `atomicSettlementId` |
| `dacs4:payload-attestation:{jobId}:{verificationMethodHash}:{attempt}` (§9.6.3 DPA-1..DPA-9) | none — `verificationMethodHash` is lowercase hex and `attempt` is a non-negative integer | `jobId`, `verificationMethodHash`, `attempt` |
| `dacs2:{jobId}:{scheme}:{identifier}:v{recipeVersion}` (attestation, CM-2) | `identifier` — e.g. a CCI identifier `evm:mainnet:0x1234` | `jobId`, `scheme`, `v{recipeVersion}` |
| `dacs2:composite:{jobId}:{evaluatedParty}` (§7.7.2) | `evaluatedParty` (a ClaimReference) | `jobId` |
| `dacs3:commit:{jobId}` (agreement commitment, §8.6) | none | `jobId` |
| `dacs5:rating:{jobId}:{rater}` (§10.6.1) | `rater` (a ClaimReference) | `jobId` |
| `stor-{sha256(...)}` (DACS-5 role-specific bundle, §10.4.2) | none — hash-based, no colon-bearing segment | — |

In every case `{jobId}` is a ULID (no reserved delimiters), `{scheme}` is a reserved-delimiter-free token (§6.3.1 grammar), and `phaseIndex`/`resolved`/`v{recipeVersion}` are fixed structural segments — none need encoding.

### B.2 Anchoring and signing

- **Anchored.** Stored on the substrate with authenticated `included` or stronger evidence such that an anchor reference (substrate-native pointer plus content hash) is sufficient for any party with substrate access to retrieve the canonical content and verify integrity. A consuming rule MAY explicitly require `finalized`, or explicitly permit durable `accepted` before retrieval; the bare term does neither. Realized by SR-2.
- **Signed.** Carrying an Ed25519 (or equivalent) signature over the RFC 8785 canonical-JSON serialisation of the document’s signed scope, where the signed scope is all fields except the signature field itself.
- **Canonical form.** RFC 8785 JSON Canonicalization Scheme (JCS) serialisation of the document with the signature(s) field omitted.
- **Content hash.** sha256 hex of the canonical form.
- **Per-artifact canonical-form template.** Every signed DACS artifact follows the same discipline: canonical form = the JCS serialisation with the artifact's hash-excluded field(s) omitted (normally the signature field); artifact hash = the content hash of that form; signature = over the domain-separated payload per §B.7 — `signed_bytes := <separator> || <artifact hash>` for single-hash separators, composite-payload separators per the §B.7 note — with verifiers reconstructing everything independently (SIG-2). Each artifact's defining section states only the artifact-specific facts: the omitted field(s), the exact domain separator, and any exceptions to this template.
- **Numeric safe-integer constraint.** Every JSON number in a signed or content-hashed DACS document MUST lie within the IEEE-754 double safe-integer range. Any quantity that may exceed it (token IDs, uint256 values, large on-chain counters or block numbers) MUST be carried as a decimal string — or, where ABI conventions apply, a `0x`-prefixed hex string — rather than a bare JSON number. Producers MUST NOT emit, and readers SHOULD reject, a signed or content-hashed document containing a JSON number outside this range.

  > **Note (non-normative).** RFC 8785 JCS defines a canonical serialisation only for JSON numbers within the IEEE-754 double range; integers above 2^53−1 (9,007,199,254,740,991) have no reproducible canonical form. The string carriage keeps the canonical form and content hash reproducible across serializers.

- **Unicode normalisation (rule CF-1).** Before computing the canonical form, every JSON string value in a signed or content-hashed DACS document MUST be Unicode-normalised to NFC. Both producers and verifiers MUST apply NFC at this stage, so the canonical form, content hash, and signatures are reproducible across implementations regardless of the input's precomposed/decomposed form. This lifts the per-field NFC requirement on `Identifier` (§B.1, CF-2) into a single normative pre-hash step covering the whole signed scope.

  > **Note (non-normative).** RFC 8785 JCS performs no Unicode normalisation — it preserves whatever code points are present, hence this rule. Most DACS string fields are ASCII, for which NFC is a no-op; the rule binds the non-ASCII surface (e.g. `cci-ud`, `cci-web2` usernames, `domain:` identifiers).

- **Canonical decimal (rule CD-1).** Every `PriceTerm.amount` string MUST be in minimal-digit canonical decimal form: no leading zeros (except a single `0` before the decimal point); no trailing zeros after the decimal point; `.` as the only separator; no `+` sign; no exponent. Producers MUST canonicalise `amount` per CD-1 before computing any agreement hash, `SettlementEvidence` hash, or other JCS hash. Verifiers MUST canonicalise `amount` per CD-1 before any price-band or price-equality comparison. Two parties formatting the same value differently MUST therefore reproduce identical canonical bytes, hashes, and signatures.

  > **Note (non-normative).** RFC 8785 JCS canonicalises JSON *numbers* but preserves *string* bytes verbatim — and monetary amounts are carried as strings — so without CD-1 two parties formatting the same economic value differently (e.g. `"1.50"` vs `"1.5"`) would produce different bytes, hashes, and signatures.

### B.3 Verification and evidence

- **Verification reference.** A reference to a DACS-2 VerifyResult that attests a claim against its authority.
- **AttestationRef.** A reference to an anchored attestation: anchor locator + content hash + (optional) signer. Defined in chapter 7 (DACS-2).
- **VerifyResult.** The uniform record produced by every DACS-2 verification method. Defined in chapter 7.
- **VerifyResultRef.** A reference to an anchored VerifyResult: anchor + contentHash + recipeVersion (recipeVersion is load-bearing for staleness checks).
- **Composite verification record.** The anchored document produced by the vet-credentials phase, aggregating freshness checks, supplementary signals, and deal-specific claims. Defined in chapter 7.
- **PayloadAttestationRecord.** The DACS-4 delivery-verification artifact that binds method-native evidence to exact payload bytes, a job, a committed agreement, and its DeliverableSpec. It is distinct from a claim-oriented DACS-2 VerifyResult. Defined in §9.6.3.

### B.4 Session, pipeline, and phases

- **Listing.** A signed, anchored JSON document conforming to chapter 6; the canonical contract for a transaction.
- **Pipeline.** The ordered sequence of PhaseStep entries declared in a listing.
- **Phase / PhaseStep.** A single unit of work in the pipeline; kind names a closed set defined across DACS-2..5.
- **Session.** A per-transaction lifecycle from Identify through Verify.
- **Session record.** The live state document for an active session. Held off-chain by the orchestrator; the bundle is the on-chain artifact. Defined in chapter 10 (DACS-5).
- **Attestation bundle.** The frozen end-of-session artifact, anchored via SR-2. The audit unit. Defined in chapter 10.
- **Agreement document.** The canonical signed JSON document produced by a negotiation pattern. Defined in chapter 8 (DACS-3).
- **SettlementEvidence.** The uniform record produced by every DACS-4 payment and delivery phase. Defined in chapter 9.

### B.5 Shared phase-handler types

Every phase handler in the stack consumes a SessionContext and returns a PhaseHandlerResult. The full TypeScript declarations:

```
type SessionContext = {
  jobId: string
  listingRef: { listingId: string; version: number; contentHash: string }
  recipeRegistryVersion: number             // DACS-2 registry pinned at session start
  railRegistryVersion: number               // DACS-4 registry pinned at session start
  parties: SessionParty[]
  priorPhaseOutputs: Record<string, unknown> // accumulated contextDelta from completed phases
  signer: SubstrateSigner                   // substrate-specific signing capability
  startedAt: number                         // unix ms
}
type PhaseHandlerResult = {
  ok: boolean
  reason?: string                           // when !ok
  txRefs?: ChainTxRef[]                     // chain references produced by this invocation
  explorerUrls?: string[]                   // human-readable handles, parallel to txRefs
  contextDelta?: Record<string, unknown>    // merged into SessionRecord.PhaseEntry.contextDelta
  attestationRef?: AttestationRef           // anchored evidence reference
  anchorReceipt?: AnchorReceipt             // latest verified SR-2 lifecycle snapshot, when this invocation writes an anchor
  errorClass?: "permanent" | "transient" | "counterparty" | "substrate" | "settlement-atomicity"
}
```

Conformance: phase handlers MUST accept a SessionContext and return a PhaseHandlerResult. On ok: true the orchestrator merges contextDelta into the corresponding PhaseEntry and records txRefs in the session event log; on ok: false the orchestrator classifies the failure per errorClass and applies the retry policy in chapter 10.

### B.6 Closed registries — v0.1 scope

The v0.1 set of identity schemes (DACS-1), verification methods (DACS-2), negotiation patterns (DACS-3), payment phases (DACS-4), and delivery phases (DACS-4) are **closed**. New entries are added in subsequent minor versions of the relevant standard via the governance process in chapter 11. Implementations MAY support pre-standard "experimental" entries prefixed x-; these MUST be treated as unknown by conforming readers unless out-of-band agreement exists.

### B.7 Universal signature scheme — domain-separated signing

Every signature in DACS — across DACS-1 (listings, revocations), DACS-2 (VerifyResults, composite records, recipes), DACS-3 (channel messages, agreements, commitments), DACS-4 (settlement evidence, payload attestations, amendments, rails, entitlements), and DACS-5 (bundles, ratings) — MUST be computed over a domain-separated payload. The domain separator prevents cross-protocol signature replay: a signature produced under one artifact kind MUST NOT validate as a signature under any other artifact kind, even when the underlying hash bytes coincide.
The canonical payload to be signed is:

```
signed_bytes := domain_separator || artifact_hash

domain_separator := "dacs-" || artifact_kind || ":v" || version_tag || ":"

artifact_hash    := the sha256 hex of the RFC 8785 canonical form of the

                    signed document, with the signature field(s) omitted
```

**`version_tag` binding.** `version_tag` is the **major** version of the per-stage standard that defines the artifact kind. All minor versions within a major (v0.1, v0.2, …) share the same `version_tag`; only a major break (v1 → v2) bumps it. The v0.x registry below therefore uses `:v1:` for every kind. An existing artifact kind's separator stays frozen across independent per-stage minor versions — a DACS-2 v0.2 VerifyResult still signs under `dacs-verifyresult:v1:` — while a new artifact type added in a minor appends its own `:v1:` entry. (Forward-readability of signed artifacts across a minor bump is what SIG-5 below guarantees.)

The v0.x registry of domain separators at this revision is closed:

| Artifact | Domain separator | Defined in |
| --- | --- | --- |
| DACS-1 listing | "dacs-listing:v1:" | §6.3.4 |
| DACS-1 listing revocation marker | "dacs-revocation:v1:" | §6.3.4 |
| DACS-1 identity bundle presentation | "dacs-bundle-presentation:v1:" | §6.3.2 |
| DACS-2 VerifyResult | "dacs-verifyresult:v1:" | §7.5 |
| DACS-2 composite verification record | "dacs-composite:v1:" | §7.7 |
| DACS-2 recipe | "dacs-recipe:v1:" | §7.4 |
| DACS-3 channel message | "dacs-channelmsg:v1:" | §8.3.3 |
| DACS-3 agreement | "dacs-agreement:v1:" | §8.5 |
| DACS-3 payee-bound agreement | "dacs-payee-bound-agreement:v1:" | §8.5 |
| DACS-3 commitment record | "dacs-commitment:v1:" | §8.6 |
| DACS-3 finality commitment record | "dacs-finality-commitment:v1:" | §8.6 |
| DACS-3 channel transcript | "dacs-transcript:v1:" | §8.7 |
| Atomic Work operation authorization | "dacs-atomic-work-authorization:v1:" | §5.2 |
| DACS-4 settlement evidence | "dacs-evidence:v1:" | §9.7 |
| DACS-4 Atomic Work settlement evidence | "dacs-atomic-evidence:v1:" | §9.7.3 |
| DACS-4 settlement amendment | "dacs-amendment:v1:" | §9.7.1 |
| DACS-4 rail definition | "dacs-rail:v1:" | §9.4 |
| DACS-4 entitlement record | "dacs-entitlement:v1:" | §9.6.2 |
| DACS-4 payload attestation record | "dacs-payload-attestation:v1:" | §9.6.3 |
| DACS-5 attestation bundle | "dacs-bundle:v1:" | §10.4.1 |
| DACS-5 fault attestation bundle | "dacs-fault-bundle:v1:" | §10.4.1 |
| DACS-5 evidence-bound fault attestation bundle | "dacs-evidence-bound-fault-bundle:v1:" | §10.4.1 |
| DACS-5 BundleBinding | "dacs-bundle-binding:v1:" | §10.4.2 |
| DACS-5 FaultAttestationBundle extended pointer | "dacs-fault-bundle-pointer:v1:" | §10.4.2 |
| DACS-5 EvidenceBoundFaultAttestationBundle extended pointer | "dacs-evidence-bound-fault-bundle-pointer:v1:" | §10.4.2 |
| DACS-5 rating record | "dacs-rating:v1:" | §10.6 |
| DACS-1 bundle session-key root binding | "dacs-session-binding:v1:" | §6.3.2 |
| DACS-3 auto-accept commitment | "dacs-auto-accept-commitment:v1:" | §8.4.1 |
| DACS-3 auto-accept instance | "dacs-auto-accept-instance:v1:" | §8.4.1 |

**Payload shape — single-hash vs composite.** Most artifacts use the single-hash payload `domain_separator || artifact_hash`. Three entries are *composite-payload* separators that, by design, prepend the separator to more than one framed value rather than a single artifact hash:

- `dacs-session-binding:v1:` (`|| session_key || bundle_hash`, §6.3.2);
- `dacs-auto-accept-commitment:v1:` (`|| sha256(canonical(commitment))`, single-hash);
- `dacs-auto-accept-instance:v1:` (`|| agreementHash || autoAcceptCommitmentHash`, §8.4.1).

For composite-payload separators each appended value MUST be a fixed-length hex sha256 digest (or, for `session_key`, the fixed-length hex public key) so the concatenation is unambiguously parseable. This is the sanctioned exception to the single-`artifact_hash` shape; these separators are first-class registry entries, not `dacs-x-` extensions.

**Non-signature hash-domain tags.** The table above registers *signature* domain separators (SIG-1 scopes to signatures). Eight further `dacs-*:v1:` tags domain-separate normative hashes that are not signature payloads:

- `dacs-sealed-bid:v1:` — the sealed-envelope commitment preimage `sha256("dacs-sealed-bid:v1:" || sha256(canonical_JCS(bid)) || salt)` (§8.4.3);
- `dacs-sb3:v1:` — the EIP-3009 session-binding nonce preimage `sha256(UTF8("dacs-sb3:v1:") || UTF8(NFC(jobId)) || 0x3a || ASCII(decimal(phaseIndex)))` (§9.5.8);
- `dacs-ap2-idem:v1:` — the AP2 provider idempotency-key preimage `sha256(UTF8("dacs-ap2-idem:v1:") || UTF8(NFC(jobId)) || 0x3a || ASCII(decimal(phaseIndex)))` (§9.5.6 AP2-6);
- `"dacs-atomic-work:v1:"` — the immutable Atomic Work intent identifier (§5.2);
- `"dacs-atomic-work-receipt:v1:"` — the Atomic Work same-transition receipt-core commitment (§5.2);
- `"dacs-atomic-operation-receipt:v1:"` — the Atomic Work operation receipt-leaf hash (§5.2); and
- `"dacs-atomic-payment-slot:v1:"` and `"dacs-atomic-settlement-id:v1:"` — the Atomic payment conflict and operation-level settlement identities (§9.5.10 and §9.7.3).

All eight follow the same domain-separation discipline, preventing cross-use of
the resulting hashes. None is a signature `signed_bytes`, so SIG-1 and the
"sign every artifact kind" conformance do not apply to them. The three Atomic
Work identifier and receipt tags are introduced by the CORE v0.3 candidate;
the two Atomic payment and settlement tags are introduced by the DACS-4 v0.7
candidate; the AP2 idempotency tag is introduced by DACS-4 v0.6; and the
sealed-bid and SB-3 tags remain owned by their cited DACS-3 and DACS-4 sections.
Collectively these are the sanctioned non-signature hash-domain tags for the
current candidate profile, not a claim that every tag existed in the frozen
DACS v0.1 baseline. The `:v1:` suffix versions each wire-domain grammar
independently of the owning standard version.

**Signature-value wire encoding.** This rule covers every DACS-owned signature
envelope whose cryptographic result is carried in a string field named `value`.
The field MUST encode the raw signature bytes as RFC 4648 §5 Base64URL, using
the URL-safe `-` and `_` alphabet and omitting all `=` padding:

```
signature_value := base64url(signature_bytes).remove_trailing("=")
```

The canonical string is non-empty and contains only `A-Z`, `a-z`, `0-9`, `-`,
and `_`.

A verifier MUST reject padding, whitespace, the standard-Base64 `+` or `/`
characters, impossible lengths, invalid residual bits, and every other
non-canonical spelling before cryptographic verification.

It MUST decode the value and compare it with an unpadded Base64URL re-encoding
of the decoded bytes.
The comparison MUST be exact.

Decoded length and internal signature format remain algorithm-specific. A
verifier MUST validate them separately.

This rule applies to DACS signature envelopes such as `ListingSignature`,
`RevocationSignature`, `AgreementSignature`, `ComponentSignature`, and
`BundleSignature`. It does not override encodings defined by a composed protocol
and carried in a protocol-specific field, such as a SIWD wallet `signature` or a
Solana `ChainTxRef.signature`. A producer importing such a signature into a DACS
`value` field MUST decode the upstream representation and re-encode its raw bytes
in the canonical DACS form.

Draft artifacts produced before SIG-6 used standard Base64, Base64URL, and hex.
Those spellings are legacy inputs, not alternate conforming encodings.

An implementation MAY expose an explicitly selected legacy-import path supplied
with the source encoding out of band. That path MUST strictly decode the declared
encoding, preserve the exact signature bytes, and emit the canonical DACS value.

It MUST NOT auto-detect by trying decoders or accept the legacy spelling on the
conforming verification path.

Re-encoding the same bytes does not change the signed payload because signature
fields are omitted from the artifact hash. An immutable stored serialization
still needs a migrated publication. If a dependent artifact commits the complete
stored serialization, its reference MUST be updated and the dependent artifact
MUST be regenerated and re-signed.

**Conformance.**

- (SIG-1) Every signature in the DACS v0.x line MUST be computed over the appropriate domain-separated payload from the table above (single-hash or composite per the note above).
- (SIG-2) Verifiers MUST reconstruct the domain separator and artifact hash(es) independently and MUST NOT trust either supplied as-is by a counterparty.
- (SIG-3) Signatures whose payload computation cannot be reproduced exactly MUST be rejected.
- (SIG-4) An artifact kind not in the current v0.x table MUST use a domain separator of the form "dacs-x-" || kind || ":v" || version || ":" until accepted into a future version of the registry.
- (SIG-5) **Preserve-unknown.** A verifier MUST reconstruct the signed payload (canonical form and artifact hash) over the document **as received**, including any fields it does not recognise. It MUST NOT strip, drop, or otherwise omit unrecognised fields before recomputing the canonical form — doing so changes the hash and would reject a validly-signed document produced under a later minor version. A verifier MAY ignore the *meaning* of unknown fields but MUST include their bytes in the hash.
- (SIG-6) **Canonical signature value.** Producers and verifiers MUST apply the unpadded Base64URL wire encoding, canonicality check, algorithm-specific validation, and legacy-import boundary defined above.

> **Note (non-normative).** SIG-5 is what makes the "forward-readable shapes" guarantee of §11.1.2 hold for signed artifacts: an older verifier can still verify a newer minor version's signature, interpreting only the fields it knows.

**Algorithm.** The signing algorithm itself (Ed25519, ECDSA-secp256k1, or sr1-aggregate) is independent of the domain-separation rule; the domain separator is prepended to the signed bytes regardless of algorithm. The byte-exact rules:

- Implementations MUST NOT compute a signature over the artifact hash without the separator, and MUST NOT compute a signature over the canonical form directly — always over the prepended-separator-then-hash payload.
- `artifact_hash` MUST be the lowercase hex string of the sha256 digest.
- The `domain_separator` (a UTF-8 string) and `artifact_hash` (an ASCII hex string) are concatenated as UTF-8 byte sequences with no separator byte.

### B.8 Session nonce

The **session nonce** is the value that binds an identity presentation — and the DACS-2 checks performed against it — to one specific session, so a presentation captured in one session cannot be replayed in another. It is the anti-replay anchor referenced by the DACS-1 presentation binding (§6.3.2), the §6.6 replay defence, and the DACS-2 holder-binding / attestation-binding checks (§7.3.2). Its *conveyance* is artifact-specific (the DACS-1 `sessionNonce` field for per-claim/session-key presentations, or the SIWD `Nonce` for the `siwd` kind — §6.3.2); its *provenance* is the shared discipline defined here.

A session nonce is **a challenge the verifier issues**, not a value the presenter chooses. The "verifier" is the party that performs the §6.3.2 nonce-match check — the counterparty receiving the presentation, or the orchestrator acting on its behalf.

**Conformance — session nonce (SN-1..SN-4).**

- (SN-1) **Generator.** The verifier MUST generate the session nonce; a presenter-supplied nonce MUST NOT be trusted as the session binding. (A bundle MAY carry a `sessionNonce` the presenter copied from the verifier's challenge — what SN-1 forbids is the verifier accepting a nonce it did not itself issue for this session.)
- (SN-2) **Entropy and form (issuance-side).** The nonce MUST carry at least 128 bits of entropy from a cryptographically secure RNG and MUST be fresh per session. The native `sessionNonce` field (§6.3.2) MUST be a lowercase-hex string of at least 32 hex characters; for the `siwd` kind the EIP-4361 `Nonce` carries the verifier-issued session nonce (validated by the §6.3.2 match check). These are obligations on the **issuer** — the verifier, per SN-1 — *at generation time*. A verifier validating a *presented* nonce relies on the §6.3.2 match against the nonce it issued, which already guarantees a conformant presented value (the issued nonce is well-formed by construction); it is **not** required to re-check entropy or hex-length on the presented value. A unilateral format re-check on the presented nonce is redundant and MUST NOT be treated as a conformance divergence.
- (SN-3) **Issuance and binding.** The verifier MUST issue the nonce to the presenter before the presentation is produced, bound to the session's `jobId`. The transport of the challenge is substrate- and protocol-specific and is out of scope; the value the verifier matches against MUST be the one it generated for this session. The verifier MUST compare the presented nonce against the nonce it issued for this `jobId` and reject any mismatch.
- (SN-4) **Single-use and retention.** A verifier MUST accept a session nonce at most once for the `jobId` it was issued for. On any presentation *attempt* carrying the issued nonce, the verifier MUST mark it consumed and reject any later presentation carrying it for that `jobId` — consumed on attempt, not only on success, so a challenge cannot be probed repeatedly. The verifier MUST retain the issued/consumed record at least until the bound session reaches a §10.3.1 terminal state. It MUST also enforce a **bounded challenge lifetime**: a nonce issued for a session still in a `*-pending` state when that lifetime elapses MUST cause any later presentation carrying it to be rejected. The lifetime is verifier-set, not a fixed CORE value — a short micropayment and a multi-hour RFQ differ legitimately. A nonce issued for one `jobId` MUST NOT validate a presentation for any other `jobId`.

> **Note (non-normative).** This is the standard SIWD/EIP-4361 challenge-response shape, lifted to a shared primitive because both DACS-1 (presentation) and DACS-2 (holder-/attestation-binding) depend on the same nonce having these properties. Constraining provenance — not just the match check — is what stops two conforming implementations from disagreeing on the very value the replay defence rests on.

## C. Composed open standards

DACS composes with the following open standards. Each per-stage chapter cites the relevant entries by name; backwards-compatibility implications are stated per-stage.

| Standard | Composed by | Touchpoint |
| --- | --- | --- |
| ERC-8004 Trustless Agents | DACS-1, DACS-5 | Identity scheme; optional reputation publication surface |
| ERC-8183 Job Escrow (proposed) | DACS-4 | Future rail (v0.2) |
| W3C DIDs v1.0 | DACS-1 | Identity scheme |
| W3C Verifiable Credentials Data Model 2.0 | DACS-2 | verifiable-credential method |
| AP2 Agent Payments Protocol | DACS-4 | pay-ap2 rail envelope (FIDO Alliance custodian from April 2026) |
| x402 HTTP 402 revival | DACS-4 | pay-x402 rail envelope |
| A2A .well-known/agent.json | DACS-1 | Discovery extension |
| TLSNotary (PSE rebuild, 2024) | DACS-2 | tlsnotary method (distinct from native cci-tlsn context) |
| Reclaim Protocol / Pluto zkTLS | DACS-2 | zktls method |
| HTLC contracts (generic) | DACS-4 | pay-cross-chain-htlc; used by the reference implementation today |
| ERC-20 / SPL | DACS-4 | pay-evm-erc20 / pay-solana-spl |
| ACME / RFC 8555 | DACS-2 | domain-tls-control method |

### C.1 Contributes-vs-must-bind (composition matrix)

Each composed standard contributes a *kind of evidence*; DACS must still bind that evidence to a specific action itself. Citing an upstream standard is never an endorsement — DACS does not inherit a property the upstream does not itself claim.

| Layer | Contributes (evidence) | DACS must still bind itself | Status in v0.1 |
| --- | --- | --- | --- |
| **AP2** | mandate / payer-intent evidence (SD-JWT + key-binding) | that the cited mandate maps to *this* action | specified (pay-ap2 not yet reference-backed) |
| **x402** | payment authorization + settlement evidence (EIP-3009 / EIP-712 auth; `PAYMENT-RESPONSE`) | on-chain confirmation of the settlement reference (§9.5.8 SB-3) | live (reference-backed) |
| **ERC-8004** | identity anchor / registry reference | reputation integrity, anti-Sybil, delegation scope, task outcome | live (identity anchor / optional publication) |
| **A2A** | discovery surface / agent-card metadata (agent-card authenticity when `AgentCardSignature` present) | listing / message / session / settlement trust (remains DACS-side) | live (discovery) |
| **DACS** | — | the verifier act that binds those references to one action | — |

**Invariant.** External references travel, but DACS records its own verifier act. If a critical AP2, x402, ERC-8004, or A2A reference is unresolvable or ambiguous, the DACS result is `indeterminate` or `error`, never a borrowed `pass`.

## Document map

DACS v0.1 is published as a Core document, one module per stage, and four companion references. Chapter and section numbers are retained across the split.

| Document | Contains | Chapters |
| --- | --- | --- |
| [PRIMER](../PRIMER.md) | non-normative overview + worked example | — |
| **CORE** (this doc) | framing (§1–5), shared terminology & types & signatures (§B), composed standards (§C), governance (§11) | 1–5, 11 |
| [DACS-1-IDENTIFY](DACS-1-IDENTIFY.md) | identity, listings, discovery | 6 |
| [DACS-2-VET](DACS-2-VET.md) | verification methods, recipes, vet phase | 7 |
| [DACS-3-NEGOTIATE](DACS-3-NEGOTIATE.md) | channels, negotiation patterns, agreement commit | 8 |
| [DACS-4-SETTLE](DACS-4-SETTLE.md) | rails, payment & delivery phases, settlement evidence | 9 |
| [DACS-5-VERIFY](DACS-5-VERIFY.md) | session record, attestation bundle, reputation | 10 |
| [DEMOS-MAPPING](DEMOS-MAPPING.md) | Demos production mapping (companion reference) | §A |
| [THREAT-MODEL](THREAT-MODEL.md) | unified threat model (companion reference) | 12 |
| [GLOSSARY](GLOSSARY.md) | glossary (companion reference, informative) | 13 |
| [CONFORMANCE-PLAN](CONFORMANCE-PLAN.md) | conformance test plan (companion reference) | 14 |
| [PROFILE](PROFILE.md) | the v0.1 version set | — |

A cross-reference to §6.x lives in DACS-1, §7.x in DACS-2, §8.x in DACS-3, §9.x in DACS-4, §10.x in DACS-5, §A in DEMOS-MAPPING, §12.x in THREAT-MODEL, §13 in GLOSSARY, §14.x in CONFORMANCE-PLAN; everything else is in this Core document.

## Chapter 11 — Stewardship, versioning, follow-on

### 11.1 Stewardship and versioning

#### 11.1.1 Current steward

DACS v0.1 is stewarded by **KyneSys Labs**. This means:

- the registry signing key currently used to sign recipes (DACS-2) and rail definitions (DACS-4) is held by KyneSys Labs;
- the canonical anchored addresses for those registries are written by KyneSys Labs;
- spec changes between minor versions are reviewed and merged by KyneSys Labs.

This is a single-steward arrangement — phase PA-2 in the progressive-anchoring scheme defined in §7.4.4. It is **not** the long-term governance target; it is the honest description of where v0.1 sits at time of publication.
Multi-party governance — a constituted working group, formal multi-signature schemes for the registries, sub-authority delegation by domain (sanctions lists, financial regulation, settlement rails) — is open work. v0.1 ships under single-steward semantics so the standard can move forward; transitioning to a multi-party arrangement is anticipated as the ecosystem of implementers, reviewers, and operators grows. The PA-2 → PA-3 transition (§7.4.4) is the formal anchor point for that change.

**(GOV-1)** Implementations consuming the registries MUST disclose to their users which signing key they treat as authoritative and MUST NOT misrepresent the current steward as a constituted multi-party body. Third-party implementations (such as PATH-OS Labs’ reference) MAY operate against the same canonical registries; the steward arrangement governs who writes the registries, not who reads them.

#### 11.1.2 Versioning

DACS v0.1 is a common baseline: all five per-stage standards, the front-matter substrate-binding, the threat model, the glossary, and the conformance plan are published together at v0.1, the first publicly released version. From this baseline onward each per-stage standard versions independently — a standard that gains capabilities bumps its own version without forcing the others, and a pipeline composes a coherent set of per-stage versions. Within a standard, major versions (v1, v2, …) break compatibility; minor versions (v0.2, v0.3, …) add capabilities while preserving forward-readable shapes. v1.0 is the version at which a standard is considered ready for unsupervised production use.

**Additivity contract (normative).** A minor version MUST be **additive and forward-readable**: it adds only *optional* fields, new registry entries, and new artifact/phase *types*, leaving every field an existing reader already reads unchanged in meaning. Anything an older reader must **act on** to remain correct — a new *required* field, a new value of an existing enum the reader branches on, or a change to the semantics of an existing field — is a **breaking change and MUST be a major bump**, never a minor. This contract is load-bearing for cross-minor compatibility (§11.2.5): because a minor never introduces something an older reader is obligated to act on, an older reader safely consumes a newer-minor artifact by preserving unknown fields (SIG-5) and interpreting only what it knows — and a major-version gate alone (no per-artifact minor field) suffices to catch the only skew that can break a reader.

**New-type refusal (normative).** A new artifact or phase type added in a minor version MUST be structurally distinguishable from every existing type before any type-specific action occurs. An implementation that does not support the new type MUST reject it as unsupported; it MUST NOT reinterpret it as an existing type by discarding an unknown discriminator or action-bearing field. This structural refusal is the safe minor-version behaviour expressly permitted for new artifact/phase types above. Adding act-requiring semantics to an optional field of an existing artifact is not equivalent and remains a breaking change.

**Registry freezing and growth.** v0.1 freezes the registries (claim schemes in DACS-1, methods/recipes in DACS-2, patterns in DACS-3, rails in DACS-4) as an immutable baseline. Later additions happen via minor-version registry updates released by the current steward, **appended to the same registry-index document** (`dacs2:registry:v0.1` / `dacs4:registry:v0.1`). That index address is the registry's **major-version line**: the `:v0.1` suffix denotes the v0.x line, not a content snapshot. The index document grows additively across minor versions and is re-addressed only on a major (v1 → v2) bump. A consumer therefore always resolves the same address and sees every v0.x entry; "frozen at v0.1" means the original baseline entries are immutable (never mutated in place), not that the index stops growing. Each entry carries its own `recipeVersion` / `railVersion` for per-session pinning (§7.4.3 / §9.4.3).

#### 11.1.3 Conformance philosophy

Each spec’s conformance section enumerates the requirements an implementation must satisfy to claim conformance to that spec. Cross-spec conformance (a full DACS-1…DACS-5 implementation) is the conjunction of per-spec conformance for every spec the implementation covers. Implementations MAY cover a strict subset (e.g., DACS-1 + DACS-4 only, for a payment-rail aggregator that does not negotiate or rate); conformance is then to the implemented subset.

#### 11.1.4 Substrate stance

DACS does not standardise the substrate. The substrate-capability statements (SR-1 through SR-5) are the abstract contract. Any substrate that provides them can host a compatible implementation. Demos is the substrate against which DACS was designed and ships all five capabilities natively; other substrates (Ethereum L1+L2 stack with bridges, Polkadot, Cosmos with privacy zones) MAY satisfy varying subsets and host correspondingly varying DACS subsets. SR-1, SR-2, and SR-5 are protocol-specified; SR-3 and SR-4 are trust-property specified in v0.1, with wire-protocol harmonisation expected in v2.

#### 11.1.5 Composition stance

DACS composes with the existing open ecosystem and does not seek to replace standards that already work. Where existing standards have gaps relevant to agent commerce (negotiation patterns, end-to-end audit), DACS specifies new standards as narrowly as possible, with explicit substrate dependencies. The composed-standards table in §C is the comprehensive list of touchpoints; when an underlying standard updates, the corresponding DACS standard’s registry entry updates in the next minor version.

### 11.2 Follow-on topics

Seven areas are deliberately out of scope for v0.1 and intended for subsequent standards.

#### 11.2.1 Dispute resolution (DACS-X, anticipated)

v0.1 produces signed, anchored bundles. v0.1 does not specify what happens when parties disagree about a bundle’s contents, contest a settlement amendment, or wish to invoke an arbitrator. A follow-on standard (working name DACS-X) is anticipated to specify:

- a dispute initiation phase referencing one or more bundles;
- selective transcript disclosure protocols (revealing channel transcripts to a named arbitrator under signed party agreement);
- arbitrator credentialing patterns (likely composing DACS-1 + DACS-2 — arbitrators are agents with verified credentials);
- dispute outcome bundles that supersede or annotate the original session bundles.

#### 11.2.2 Open phase set

v0.1’s phase types are closed across DACS-2/3/4/5. v2 may relax this to permit ecosystem-defined phases under the steward’s oversight. Until then, x- experimental phases provide an escape valve for out-of-band agreement.

#### 11.2.3 Multi-party transactions beyond bilateral

v0.1 negotiation is bilateral (except sealed-envelope, which is one seller / many bidders). True multi-party transactions — syndicated trades, multi-seller bundles, escrow-with-arbitrator three-party flows — are out of scope. DACS-3 v0.2 will likely add a negotiate-multi-quote pattern; truly multi-party flows are likely v2 territory.

#### 11.2.4 Streaming / continuous-flow rails

v0.1 rails are discrete-transaction. Streaming payment rails (Sablier-style, payment per second of usage) and continuous-delivery rails (per-second compute, per-byte data feed) are out of scope. A future DACS-4 v0.2 entry (rail type continuous) is anticipated.

#### 11.2.5 Cross-DACS-version compatibility

Each per-stage standard specifies forward-compatibility within itself (a later-minor reader handles earlier-minor bundles of the same standard). Cross-version compatibility (a DACS-1 v2 listing pipelined against a DACS-3 v0.1 negotiator) is deferred; pipelines MUST currently use a coherent set of per-stage versions.

**Version-signalling scope.** Every anchored artifact carries a type-specific `*Version` literal (`dacsVersion`, `bundleVersion`, `faultBundleVersion`, `evidenceBoundFaultBundleVersion`, `agreementVersion`, `payeeBoundAgreementVersion`, `evidenceVersion`, `ratingVersion`, `resultVersion`) that records the **major** version of that artifact type only; in the v0.x line these are all `"1"`. The listing-validation "dacsVersion supported" gate (§6.3.4 step 2) is therefore a **major-version** check — it rejects a listing whose major the reader does not implement.

The **§11.1.2 additivity contract** makes the major-only signal sufficient for *minor* skew, in both directions, with **no per-artifact minor-version field**:

- **later-reads-earlier** — a later-minor reader knows a superset of the shapes and reads any earlier-minor artifact of a type it supports directly; no signal needed.
- **older-reads-newer, same type** — a newer minor adds only optional, forward-readable fields to an existing artifact type. An older reader preserves them via SIG-5 and is **never obligated to act on them** (anything act-requiring is, by the additivity contract, a major bump), so it consumes that artifact correctly.
- **older-reads-newer, new type** — an older reader rejects a newly registered artifact or phase type at its structural type gate, before type-specific action. A newer minor MAY require behaviour for that new type precisely because an older implementation cannot mistake it for a type it already acts on.

The only version difference that can require a reader to reinterpret a type it already supports is a **major** break, which the type's major-version gate rejects. A new minor-version type is instead safely unsupported and rejected at its structural gate. A per-artifact **producing-minor-version field is therefore unnecessary**, not merely deferred. What remains genuinely deferred is **cross-major** compatibility — a different-major standard pipelined against an earlier one — per the paragraph above.

#### 11.2.6 Multi-party governance and registry stewardship

The transition from single-steward (PA-2) to multi-party constituted governance (PA-3) for the recipe and rail registries is itself follow-on work. v0.1 does not specify the constitution mechanism, multi-signature thresholds, sub-authority delegation, or transition procedure. These are open questions for the working group that the ecosystem chooses to constitute. Until that body exists, the current steward operates under the disclosure rules in §11.1.1.

#### 11.2.7 Selective-disclosure / minimised-claim presentation

v0.1 discloses a presented bundle's full `claims[]` set and its `presentedBy` primary claim to every counterparty (§6.3.2 scope note). The DACS-2 zkTLS / TLSNotary methods hide the secret inside a claim's verification but not which claims a party holds. A follow-on standard is anticipated to add bundle-layer selective disclosure — per-claim blinding, commitments with selective open, proof-of-possession-without-disclosure, and an unlinkable or rotating primary-claim presentation that preserves reputation continuity without exposing the durable high-tier identity in low-stakes interactions. Until then, the only minimisation is presenter-side bundle pruning, with the linkability caveat in §6.3.2.

### 11.3 Closing

Agent commerce is moving from prototype to production. DACS is a contribution toward keeping the lifecycle on public infrastructure: a stack that composes with the existing open standards where they work, fills the gaps where they don’t, and makes substrate dependencies explicit. A reference implementation runs the lifecycle end-to-end on the Demos substrate; an independent third-party reference implementation implements the DACS-1 + DACS-2-GLEIF + DACS-5 verifier subset against the same spec.
What this document is **not**: a finished standard ready for unsupervised production at every scale. The honest list of remaining work — beyond the per-stage follow-on topics in §11.2 — includes:

- protocol-level wire specifications for SR-3 and SR-4 (currently trust-property specified only);
- expansion of independent reference-implementation coverage beyond the current third-party verifier;
- engagement with the maintainers of every composed standard (ERC-8004, AP2 via FIDO Alliance, W3C VC, A2A) to convert "DACS composes with X" from a unilateral claim into a documented cross-maintainer conversation;
- a unified threat-model audit (§12) reviewed by parties outside the current stewardship;
- constitution of multi-party governance (§11.2.6);
- conformance test suites (§14) ready for implementers to run against.

Some of these will reveal gaps that need new work, not just refinement. The intent of v0.1 is to ship a coherent baseline that the next 6–12 months of implementation experience and ecosystem engagement can sharpen. It is not the final word on agent commerce.

## Chapter 12 — Unified threat model

Moved to **[THREAT-MODEL.md](THREAT-MODEL.md)** (section numbering retained). Adversary model, trust boundaries, threat catalogue, and the composite trust property. Where this chapter restates per-chapter threats, the per-chapter mitigation is normative; this chapter's framing is informative.

## Chapter 13 — Glossary

Moved to **[GLOSSARY.md](GLOSSARY.md)** (section numbering retained). A single alphabetical glossary across all five per-stage standards and the front/back matter. Informative; per-chapter definitions are normative.

## Chapter 14 — Conformance test plan

Moved to **[CONFORMANCE-PLAN.md](CONFORMANCE-PLAN.md)** (section numbering retained). The conformance requirements and golden-vector test plan, per role and per module. Machine-readable fixtures live in [conformance/](../conformance/).

## References

Cross-stage references for DACS-1 through DACS-5. Per-stage chapters may cite additional substrate-specific or standard-specific material inline.

**Normative — RFCs**

- RFC 2119 — *Key words for use in RFCs to Indicate Requirement Levels*. Bradner. 1997.
- RFC 4648 — *The Base16, Base32, and Base64 Data Encodings*. Josefsson. 2006.
- RFC 7231 §6.5.2 — *Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content — 402 Payment Required*. Fielding & Reschke. 2014.
- RFC 8174 — *Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words*. Leiba. 2017.
- RFC 8555 — *Automatic Certificate Management Environment (ACME)*. Barnes et al. 2019.
- RFC 8785 — *JSON Canonicalization Scheme (JCS)*. Rundgren et al. 2020.

**Companion DACS specifications**

- **DACS-1 — Agent Identity, Discovery and Listing**, chapter 6 of this document.
- **DACS-2 — Credential Attestation**, chapter 7 of this document.
- **DACS-3 — Negotiation**, chapter 8 of this document.
- **DACS-4 — Settlement: Payment Rails and Delivery Phases**, chapter 9 of this document.
- **DACS-5 — Verification, Session Records and Reputation**, chapter 10 of this document.

**Ethereum ecosystem**

- **ERC-8004** — *Trustless Agents*. Davide Crapis et al. Ethereum Foundation, Ethereum Improvement Proposals draft.
- **ERC-8183** — *Standard for Job Escrow*. Proposed standard for EVM-native escrow primitive supporting job-style transactions.

**W3C and related**

- **W3C Decentralized Identifiers (DIDs) v1.0**. W3C Recommendation, 2022.
- **W3C Verifiable Credentials Data Model 2.0**. W3C Recommendation Track.
- **W3C Verifiable Credentials Status List 2021**.

**Payment standards**

- **AP2 — Agent Payments Protocol**. Google. Donated to FIDO Alliance, April 2026.
- **x402 — HTTP 402 revival**. Coinbase, Cloudflare, Anthropic.

**Agent communication**

- **A2A** — *Agent2Agent Protocol*. .well-known/agent.json discovery surface.

**Verification and attestation**

- **TLSNotary**. Privacy & Scaling Explorations (PSE) rebuild, 2024.
- **Reclaim Protocol**. zkTLS proof system for HTTP responses.
- **DECO** — *Liabilities-and-Verifiability Decentralized Oracle Layer*. Earlier zkTLS-style construction.

**Demos / Kynesys**

- **Demos Whitepaper**. Kynesys Labs.
- **Kynesys SDK**, package @kynesyslabs/demosdk. Modules: identities, storage, bridge (Native Bridges + Rubic), demoswork (L2PS workflow), web2 (DAHR).

**Identifiers and utility**

- **ULID** — *Universally Unique Lexicographically Sortable Identifier*.

**Procurement frameworks**

- **FAR Part 14** — *Sealed Bidding*. US Federal Acquisition Regulation.
- **FAR Part 15** — *Contracting by Negotiation*. US Federal Acquisition Regulation.
- **EU Directive 2014/24/EU** — *Public Procurement Directive*.
