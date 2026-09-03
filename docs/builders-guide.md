# Building Agent Commerce on Demos

**A technical case for builders evaluating where to ship.**

---

## 1. The problem you're actually solving

If you're building an agent that takes money or instructions from another agent — autonomous procurement, AI-to-AI APIs, agent-mediated bookings, machine-readable RFQs, automated content moderation, scheduled API access — you're building agent commerce. You've probably already hit the four problems everyone hits:

1. **How does my agent know the counterparty agent is what it claims?** Wallet addresses don't carry identity. Credentials don't compose across chains. A LEI on one substrate is invisible to an agent on another.
2. **How do I verify the counterparty's claims without trusting a centralised service?** OAuth says nothing about LEI. KYC providers are walled. Verifiable credentials work only when both sides speak the same VC profile.
3. **How do I negotiate, settle, and prove what happened in a way the next agent — or a regulator — can audit?** Direct API calls leave no trail. Smart-contract escrow leaves a trail but only on one chain. Cross-chain leaves a trail nobody can stitch together.
4. **How does any of this work when the buyer is on one chain and the seller is on another?** Today: it doesn't. You either constrain both parties to one chain (loses the whole point) or you build the bridge yourself (loses the whole project to bridge maintenance).

Most agent commerce projects solve one of these and punt on the rest. The result is the current state of the field: working demos, no production, no interoperability, and a creeping feeling that the right primitives haven't been built yet.

This document is about why we think the right primitives have been built, what the open standard built on top of them looks like, and why Demos is the substrate that runs the whole thing today.

---

## 2. DACS: the open standard for agent commerce

DACS — **D**emos **A**gent **C**ommerce **S**tandards — is a five-stage protocol for verifiable agent commerce. It specifies what artifacts get produced at each stage, what they're signed against, how they're anchored, and how the resulting audit trail composes.

The lifecycle:

> **Identify → Vet → Negotiate → Settle → Verify**

Each stage produces a signed, content-addressed artifact. The final stage produces an **AttestationBundle** — a single signed document that references everything that happened in the session. A consumer reading the bundle can dereference every artifact, verify every signature, and confirm the audit trail end-to-end.

### Why open

DACS is not a Demos product. It's the standard Demos publishes, but it's specified at the **substrate-capability level** — meaning any substrate that ships the five required primitives (SR-1..SR-5, more on these in §4) can host a conformant DACS implementation. Bundles, listings, agreements, and evidence records produced on one substrate can be read and verified by anyone with substrate access. The audit format is the standard; the substrate is the deployment choice.

This matters because closed agent-commerce stacks already exist. The closed alternatives consolidate fast: when the agent ecosystem rallies around one platform's API, that platform takes the whole rent. DACS is the contribution we make to keeping the lifecycle on public infrastructure — composable with the existing open standards where they work (W3C VC, ERC-8004, x402, AP2, TLSNotary, A2A) and filling the gaps where they don't.

### What DACS specifies

Briefly, per stage:

- **DACS-1 Identify.** Identity bundles — typed claims (LEI, jurisdiction, wallet addresses, DIDs, OAuth attestations) presented under one signature, cross-substrate-bound via SR-1. Listings — signed offer documents anchored on-chain that declare what an agent will do and what it requires of buyers.
- **DACS-2 Vet.** A recipe registry mapping claim schemes to verification-method families (nine methods in v0.4, covering W3C VC, OAuth, TLSNotary, consensus-backed proxy attestation, EVM RPC reads, fresh ACME-style domain control, persistent Demos GCR domain binding, and self-signed). Each method produces a uniform `VerifyResult` shape with a four-valued `decision` (`pass | fail | indeterminate | error`). An aggregation algorithm produces an overall decision against the listing's requirements, with explicit precedence (failures > errors > indeterminates) and a normative `availability` field on every recipe so consumers can tell a live attestation path from a mocked or operator-gated one.
- **DACS-3 Negotiate.** Three negotiation patterns: fixed-price (buyer accepts listed terms), RFQ (bounded multi-turn bilateral), sealed-envelope (multi-bidder procurement with cryptographic commit-reveal). All three produce a signed `AgreementArtifact`: the legacy `AgreementDocument`, or `PayeeBoundAgreementDocument` when the listing selects payee-bound settlement.
- **DACS-4 Settle.** Seven payment phase types covering EVM ERC-20, Solana SPL, cross-chain HTLC, cross-chain liquidity-tank, AP2 (FIDO Alliance Agent Payments), x402 (Coinbase's HTTP 402 micropayment scheme), and native DEM. Three delivery phase types cover storage-program-anchored deliverables, signed entitlement records, and DACS-2-attested payloads. Payments produce `SettlementEvidence`; deliveries produce signed phase-bound `DeliveryEvidence`. Every rail carries the same `availability` field as recipes so orchestrators preflight-check before selecting.
- **DACS-5 Verify.** Session bundle assembly, two-sided anchoring, per-primary-claim reputation derivation, optional ERC-8004 publication. The bundle is the audit unit that survives the session.

The full standard is ~95 pages with conformance rules, error classes, signature registries, threat model, and conformance test plans. For an architectural read, the trace document (companion artifact) walks one end-to-end session through all five stages in pseudocode. For implementers, the spec chapters carry the conformance bar.

### Where DACS doesn't reinvent anything

A common failure mode in new protocols is to reinvent things that already work. DACS deliberately composes:

| Standard | Role in DACS |
|---|---|
| W3C Verifiable Credentials | First-class DACS-2 method for credential-based verification |
| ERC-8004 (agent identity) | DACS-1 claim scheme + optional DACS-5 reputation publication target |
| AP2 (FIDO Alliance) | DACS-4 fiat-payment phase type |
| x402 (Coinbase) | DACS-4 HTTP-micropayment phase type |
| TLSNotary | DACS-1 CCI claim context + DACS-2 method |
| ACME (RFC 8555) | DACS-2 domain-control method |
| A2A (Google) | DACS-1 listing discovery surface |
| RFC 8785 (JCS) | Canonical-form serialisation everywhere |
| EIP-4361 (SIWE/SIWD) | DACS-1 identity bundle presentation |

DACS is what makes these standards compose into a single verifiable session, not a replacement for them.

---

## 3. The substrate problem

DACS is portable in specification. Any substrate that ships five primitives — SR-1 through SR-5 — can host a conformant implementation. The primitives are:

- **SR-1** — cross-substrate identity aggregation
- **SR-2** — anchored immutable storage with content hashes
- **SR-3** — consensus-backed proxy attestation of external HTTPS fetches
- **SR-4** — identity-keyed private coordination channels
- **SR-5** — multi-chain coordinated atomic settlement

Here's the honest part: **as of today, no other substrate ships all five.**

Generic L1s ship SR-2 (some flavour of anchored storage). EVM chains ship most of SR-2. A few projects are building SR-3 or SR-5 in isolation. Nobody else has SR-1 cross-substrate identity that actually composes across EVM + Solana + UTXO + Cosmos chains. Nobody else has SR-4 identity-keyed private channels at the substrate layer. Nobody else has SR-5 atomic cross-chain settlement that doesn't reduce to "bridge + hope."

This is not because the primitives are exotic. It's because building five different primitives, each load-bearing for agent commerce, requires either a clean-sheet substrate or several years of careful protocol surgery on an existing one. Demos is the former.

---

## 4. Why Demos is where DACS runs end-to-end today

Demos is a clean-sheet substrate. It was designed for cross-substrate composition and verifiable execution from the ground up. The DACS standard was written against it — not because Demos owns DACS, but because we needed all five primitives to exist somewhere to prove the standard could be implemented end-to-end.

Here's the substrate-to-primitive mapping:

| Primitive | Demos implementation | Production status |
|---|---|---|
| **SR-1** Cross-substrate identity | **CCI / DemosID.** Eight CCI contexts in production (EVM family, Solana, TLSNotary, DID-key, DID-web, ERC-8004, X.509, SIWE). One root identity binds sub-identities across substrates. | **Live.** |
| **SR-2** Anchored storage | **Storage Programs.** Content-addressed key-value storage with 128 KB cap, addressable on-chain, queryable from any substrate. | **Live.** |
| **SR-3** Consensus-backed proxy | **DAHR (Data Agnostic HTTPS Relay).** Validators perform the HTTPS fetch, co-sign a transaction asserting (URL, time, body hash). Body returned inline, hash anchored. | **Live** (hash-commitment mode); validator-body-signed mode is the v0.2+ strengthening. |
| **SR-4** Private channel | **L2PS (Layer-2 Privacy Subnets).** Identity-keyed subnets with member-only encrypted messaging, transcript export, optional anchoring. | **Substrate live;** CCI-keyed membership API + structured channel envelopes on the build backlog (DACS-3 Tier 1). |
| **SR-5** Atomic cross-chain settlement | **Native Bridges / Liquidity Tanks.** Pre-funded pools on source + destination, lock-source/release-destination atomically within a substrate epoch. Accessed via `WorkStep` of context `xm` in `DemosWork`. | **Phase 1 live** (ETH Sepolia + Polygon Amoy, USDC unidirectional). Phase 2-4 (Solana destination, bidirectional, validator-set co-signing, 15-day emergency recovery) on roadmap. |

Three of the five primitives are live. Two are substrate-live with SDK ergonomics on the backlog. **No primitive is theoretical.**

The reference implementation (`agent-commerce-demo`, ~929 LOC) runs an end-to-end DACS-1..DACS-5 session today against the Demos substrate. Real Solana Anchor program + real Base Sepolia EVM HTLC contract for cross-chain settlement. Real DAHR proxy fetches against real authority APIs (GLEIF, FINRA, OFAC). Real Storage Programs holding real signed bundles.

This isn't "we will build agent commerce." It's "agent commerce composes, end-to-end, today, on this substrate."

---

## 5. What that means in practice

What a builder gets when they build agent commerce on Demos:

**One SDK, every chain.** `@kynesyslabs/demosdk` exposes a unified surface across EVM (every major L1 + L2), Solana, UTXO chains, Cosmos chains. A buyer agent connecting to a Demos node can address counterparties on any of them through one set of APIs. CCI handles the sub-identity binding; XM (cross-messaging) handles the cross-chain calls.

**Identity that composes.** A buyer agent presents a single SIWD-signed bundle carrying its LEI, its EVM address on Base, its Solana address, its W3C VC credentials, and its DID. The seller's orchestrator runs DACS-2 verification across the bundle — DAHR-proxy-attested GLEIF lookup for the LEI, EVM RPC read for the ERC-8004 token, W3C VC validation for the credential — and produces a single signed `CompositeVerificationRecord`. All of this anchored, all of it auditable, all of it computed once and reusable per the recipe's freshness window.

**Negotiation that's actually private.** DACS-3's RFQ and sealed-envelope patterns run over L2PS subnets. Bids are private to channel members. The negotiation transcript stays in the subnet (with optional encrypted anchoring). Only the final agreement hash and its commitment record are publicly anchored by default. The buyer's first offer doesn't get front-run by every other bidder.

**Settlement that's atomic, cross-chain.** Buyer pays USDC on Base, seller receives USDC on Solana. One `WorkStep` of context `xm` in a `DemosWork`. The Demos node routes through a Liquidity Tank if available, falls through to HTLC if not. Both produce uniform `SettlementEvidence` records. The agent code is the same call either way.

**Audit that survives.** Every session ends with an `AttestationBundle` — co-signed by both parties, anchored at role-specific addresses on Demos. A consumer reading the bundle weeks or months later can dereference every artifact, verify every signature, replay the session. Reputation is keyed per primary identity claim (LEI, ERC-8004 token, DID), not per wallet address — meaning reputation is portable across substrates and key rotations.

**Composition with existing standards is real.** A DACS session can accept a buyer who authenticates with W3C VC, pays through AP2, holds an ERC-8004 agent token, and discovers the listing via A2A. None of that is hypothetical: each composition is a defined DACS-2 method, DACS-4 phase type, or DACS-1 claim scheme.

---

## 6. Cost-of-not picture

What you'd build if you tried to do this on a generic L1:

- An identity layer that binds wallet addresses to off-chain credentials, with revocation, rotation, and cross-chain awareness — call it 6 months of protocol work.
- An attestation service that lets validators (or some trust quorum) prove they fetched data from external HTTPS endpoints. Either you build your own validator-set TLS attestation, or you trust a centralised relay. 4 months.
- A private-channel layer. Off-chain WebSockets give you no substrate-mediated liveness, no identity-keyed membership, no transcript anchoring. Building it on-chain requires either trusted-execution environments or homomorphic encryption. 6-12 months.
- Cross-chain settlement that isn't a bridge. HTLC works but takes minutes and pays gas on both sides. Pre-funded pools work but require operator trust. Real atomicity across heterogeneous chains: 12+ months and a security audit budget that exceeds most teams' total runway.
- A specification that ties all of the above into one verifiable session. The thing this document is about: ~95 pages, multiple iterations, ongoing standards work.

Total: 2-3 years of platform engineering before you ship the first agent. With Demos you ship in the first sprint.

This is not a marketing argument; it's the calendar.

---

## 7. Where we are vs. where the industry is

The agent commerce field has three current shapes:

**Closed agent platforms.** OpenAI / Anthropic / others build agent runtimes with internal commerce APIs. Beautifully integrated, fast, no interoperability, no auditability, full rent capture by the platform. If their stack is the answer, you're a tenant.

**Open agent protocols on generic L1s.** ERC-8004, x402, A2A, AP2. Each one solves a slice. None of them compose into a verifiable session. A buyer using ERC-8004 identity, paying through x402, against an agent discovered via A2A, produces no audit artifact — three separate transactions on three different surfaces with no link between them. The composition is the problem; the individual standards are good.

**DACS on Demos.** The composition exists, the substrate ships all five primitives the composition requires, and the audit unit (the bundle) is one signed document a consumer can verify end-to-end. This isn't a slice. It's the lifecycle.

We're not claiming we've finished the work. The honest list of what's not done is in the spec (DACS-3 substrate work for L2PS CCI-keyed channels, SR-5 Phase 2-4 expansion, cross-substrate test of the artifact-level portability claim against a non-Demos substrate, formal engagement with the maintainers of the standards we compose with, constitution of multi-party governance to replace the current single-steward arrangement). But the parts that need to exist for builders to start building exist, and one independent third-party reference implementation (PATH-OS Labs' `pathos-dacs-ref`) was built against earlier drafts of the spec — the third-party-implementability claim is no longer just a claim.

---

## 8. What we'd ask you to do next

If you're building agent commerce — actively, not theoretically — three things:

1. **Read the trace document.** End-to-end happy path in TypeScript-ish pseudocode against the real SDK. Eight pages. Tells you whether DACS-on-Demos maps to your mental model of what your agent needs to do.

2. **Run the reference implementation.** `agent-commerce-demo` runs an end-to-end DACS-1..DACS-5 session against Demos testnet. You can fork it, swap in your buyer or seller logic, ship a working agent in a day. The honest test: does the lifecycle the reference shows match the lifecycle your agent needs?

3. **Tell us where the spec is wrong.** DACS v0.1 is the first publicly released version. We're actively seeking implementation feedback from builders who'll hit edge cases we didn't anticipate. If you build against it and find a corner that doesn't compose, that's the most valuable thing we can hear right now — and it's the kind of input that goes into v0.2, not into a future major version where it's harder to absorb.

---

## Appendix A — How to evaluate this honestly

A builder reading this document should be skeptical. Three questions worth asking:

**Is the standard real, or is it marketing for the chain?** Read the spec. ~95 pages of conformance rules, error classes, threat catalogue, conformance test plan. That's standards-work shape, not marketing-deck shape. The substrate-capability separation (SR-1..5 specified independently of Demos) is the load-bearing test for openness — it's the work we did so other substrates can host conformant DACS implementations when they're ready.

**Is the substrate real, or is it a roadmap?** Run the reference implementation against testnet. Three of five primitives are live in production. The other two are substrate-live with SDK ergonomics in active build (Tier 1 backlog, not "someday"). If any primitive is missing for your use case, we can tell you exactly when it ships.

**Is the composition with existing standards real, or is it a slide?** Pick one — ERC-8004, x402, AP2, W3C VC, TLSNotary, A2A — and read the corresponding chapter of the spec. Each one has a defined integration: which DACS-2 method, which DACS-4 phase, which DACS-1 claim scheme. The integrations are normative parts of the standard, not afterthoughts.

If those three checks come out negative, this document was wrong. If they come out positive, the substrate where you ship is a strategic decision, not just a technical one — and we'd argue Demos is the substrate that's closest to ready today.

---

## Appendix B — Pointers

- **[DACS spec (v0.1)](../spec/CORE.md).** The full normative standard.
- **[CHANGELOG](../CHANGELOG.md).** Normative change history; what's in v0.1 and what changed between drafts.
- **[DACS flow trace](./flow-trace.md).** End-to-end happy path, TypeScript pseudocode + sequence diagram.
- **agent-commerce-demo.** KyneSys Labs' reference implementation; runs end-to-end DACS-1..DACS-5 against Demos testnet.
- **pathos-dacs-ref.** PATH-OS Labs' independent third-party reference implementation; DACS-1 publisher, DACS-2 GLEIF verifier, and DACS-5 envelope-receipt verifier CLI. MIT licensed.
- **[`@kynesyslabs/demosdk`](https://www.npmjs.com/package/@kynesyslabs/demosdk).** Unified SDK across substrates. NPM package.
- **[Demos documentation](https://demos.sh).** Substrate primitives, RPC, wallet integration.
- **[Feedback channel](https://github.com/DACS-Agent-commerce/DACS-Standard/issues).** For spec questions and implementation issues; PATH-OS-style "section §, file path, alternate interpretation" reports are the highest signal. See [CONTRIBUTING](../CONTRIBUTING.md).
