# DACS — Demos Agent Commerce Standards

**Introduction and DACS-1 through DACS-5**

> Published as DACS **v0.1** — the first publicly released version. See [CHANGELOG](../CHANGELOG.md) for normative change history.

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

**Substrate-coupling status in v0.1.**

- **SR-1, SR-2, and SR-5 are specified at the protocol level.** Another substrate that ships an equivalent primitive (cross-substrate identity aggregation; content-addressed anchored storage; atomic cross-chain settlement) can interoperate with DACS implementations on Demos at the artifact level: the bundles, listings, and evidence records validate the same way.
- **SR-3 and SR-4 are specified at the trust-property level only in v0.1.** Two substrates each shipping their own SR-3 (consensus-backed proxy attestation) or SR-4 (identity-keyed private coordination) implementations will *not* be wire-protocol interoperable. The trust properties listed under CH-1..CH-6 for SR-4 and under §7.3.5 for SR-3 are the conformance bar v0.1 requires; the underlying message formats and consensus signatures are substrate-specific. Consequence, until the v2 wire formats ship (see note below): a session begun on substrate A cannot be completed on substrate B if it uses any SR-3- or SR-4-dependent phase.

> **Note (non-normative).** v2 of DACS-2 and DACS-3 is expected to specify wire formats for SR-3 attestation envelopes and SR-4 channel messages that enable cross-substrate interoperability.

**Reference substrate.** The **Demos Network** is the substrate against which DACS was designed and, as of this draft, the only substrate that ships all five capabilities natively. The DACS specifications cite the substrate capabilities (SR-1 through SR-5), not the Demos primitives themselves; this separation keeps the artifact-level specification portable while staying honest about which primitives are concretely realised today and where v2 work is needed.

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
| `dacs2:{jobId}:{scheme}:{identifier}:v{recipeVersion}` (attestation, CM-2) | `identifier` — e.g. a CCI identifier `evm:mainnet:0x1234` | `jobId`, `scheme`, `v{recipeVersion}` |
| `dacs2:composite:{jobId}:{evaluatedParty}` (§7.7.2) | `evaluatedParty` (a ClaimReference) | `jobId` |
| `dacs5:rating:{jobId}:{rater}` (§10.6.1) | `rater` (a ClaimReference) | `jobId` |
| `stor-{sha256(...)}` (DACS-5 role-specific bundle, §10.4.3) | none — hash-based, no colon-bearing segment | — |

In every case `{jobId}` is a ULID (no reserved delimiters), `{scheme}` is a reserved-delimiter-free token (§6.3.1 grammar), and `phaseIndex`/`resolved`/`v{recipeVersion}` are fixed structural segments — none need encoding.

### B.2 Anchoring and signing

- **Anchored.** Stored on the substrate such that an anchor reference (substrate-native pointer plus content hash) is sufficient for any party with substrate access to retrieve the canonical content and verify integrity. Realized by SR-2.
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
  errorClass?: "permanent" | "transient" | "counterparty" | "substrate" | "settlement-atomicity"
}
```

Conformance: phase handlers MUST accept a SessionContext and return a PhaseHandlerResult. On ok: true the orchestrator merges contextDelta into the corresponding PhaseEntry and records txRefs in the session event log; on ok: false the orchestrator classifies the failure per errorClass and applies the retry policy in chapter 10.

### B.6 Closed registries — v0.1 scope

The v0.1 set of identity schemes (DACS-1), verification methods (DACS-2), negotiation patterns (DACS-3), payment phases (DACS-4), and delivery phases (DACS-4) are **closed**. New entries are added in subsequent minor versions of the relevant standard via the governance process in chapter 11. Implementations MAY support pre-standard "experimental" entries prefixed x-; these MUST be treated as unknown by conforming readers unless out-of-band agreement exists.

### B.7 Universal signature scheme — domain-separated signing

Every signature in DACS — across DACS-1 (listings, revocations), DACS-2 (VerifyResults, composite records, recipes), DACS-3 (channel messages, agreements, commitments), DACS-4 (settlement evidence, amendments, rails, entitlements), and DACS-5 (bundles, ratings) — MUST be computed over a domain-separated payload. The domain separator prevents cross-protocol signature replay: a signature produced under one artifact kind MUST NOT validate as a signature under any other artifact kind, even when the underlying hash bytes coincide.
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
| DACS-3 channel transcript | "dacs-transcript:v1:" | §8.7 |
| DACS-4 settlement evidence | "dacs-evidence:v1:" | §9.7 |
| DACS-4 settlement amendment | "dacs-amendment:v1:" | §9.7.1 |
| DACS-4 rail definition | "dacs-rail:v1:" | §9.4 |
| DACS-4 entitlement record | "dacs-entitlement:v1:" | §9.6.2 |
| DACS-5 attestation bundle | "dacs-bundle:v1:" | §10.4.1 |
| DACS-5 rating record | "dacs-rating:v1:" | §10.6 |
| DACS-1 bundle session-key root binding | "dacs-session-binding:v1:" | §6.3.2 |
| DACS-3 auto-accept commitment | "dacs-auto-accept-commitment:v1:" | §8.4.1 |
| DACS-3 auto-accept instance | "dacs-auto-accept-instance:v1:" | §8.4.1 |

**Payload shape — single-hash vs composite.** Most artifacts use the single-hash payload `domain_separator || artifact_hash`. Three entries are *composite-payload* separators that, by design, prepend the separator to more than one framed value rather than a single artifact hash:

- `dacs-session-binding:v1:` (`|| session_key || bundle_hash`, §6.3.2);
- `dacs-auto-accept-commitment:v1:` (`|| sha256(canonical(commitment))`, single-hash);
- `dacs-auto-accept-instance:v1:` (`|| agreementHash || autoAcceptCommitmentHash`, §8.4.1).

For composite-payload separators each appended value MUST be a fixed-length hex sha256 digest (or, for `session_key`, the fixed-length hex public key) so the concatenation is unambiguously parseable. This is the sanctioned exception to the single-`artifact_hash` shape; these separators are first-class registry entries, not `dacs-x-` extensions.

**Commitment-hash domain tags.** The table above registers *signature* domain separators (SIG-1 scopes to signatures). One further `dacs-*:v1:` tag is a **commitment-hash** domain, not a signature payload: `dacs-sealed-bid:v1:` (the sealed-envelope bidHash preimage `sha256("dacs-sealed-bid:v1:" || sha256(canonical_JCS(bid)) || salt)`, §8.4.3). It follows the same domain-separation discipline (preventing cross-use of the hash) but is NOT a signature `signed_bytes`, so SIG-1 and the "sign every artifact kind" conformance do not apply to it; it is the one sanctioned commitment-hash domain tag in v0.1.

**Conformance.**

- (SIG-1) Every signature in the DACS v0.x line MUST be computed over the appropriate domain-separated payload from the table above (single-hash or composite per the note above).
- (SIG-2) Verifiers MUST reconstruct the domain separator and artifact hash(es) independently and MUST NOT trust either supplied as-is by a counterparty.
- (SIG-3) Signatures whose payload computation cannot be reproduced exactly MUST be rejected.
- (SIG-4) An artifact kind not in the current v0.x table MUST use a domain separator of the form "dacs-x-" || kind || ":v" || version || ":" until accepted into a future version of the registry.
- (SIG-5) **Preserve-unknown.** A verifier MUST reconstruct the signed payload (canonical form and artifact hash) over the document **as received**, including any fields it does not recognise. It MUST NOT strip, drop, or otherwise omit unrecognised fields before recomputing the canonical form — doing so changes the hash and would reject a validly-signed document produced under a later minor version. A verifier MAY ignore the *meaning* of unknown fields but MUST include their bytes in the hash.

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

**Version-signalling scope.** Every anchored artifact carries a type-specific `*Version` literal (`dacsVersion`, `bundleVersion`, `agreementVersion`, `payeeBoundAgreementVersion`, `evidenceVersion`, `ratingVersion`, `resultVersion`) that records the **major** version of that artifact type only; in the v0.x line these are all `"1"`. The listing-validation "dacsVersion supported" gate (§6.3.4 step 2) is therefore a **major-version** check — it rejects a listing whose major the reader does not implement.

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
