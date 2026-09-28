# DACS Primer — Demos Agent Commerce Standards

*A ~5-page overview. Read this to understand DACS. The normative reference is [CORE](spec/CORE.md) (the data model + universal rules) plus one module per stage; this primer is non-normative.*

---

## What DACS is

Autonomous agents are transacting with agents they have never met. Open standards exist for *fragments* of what a transaction requires — identity registries, payment authorisation, HTTP micropayments, capability discovery — but each covers one slice, and nothing in wide use composes them into a working **commerce lifecycle**. That gap is why agents needing the full lifecycle fall back to closed operator marketplaces.

**DACS** is the protocol Demos uses for agent commerce. It is organised around the five stages every agent-to-agent transaction passes through — **Identify, Vet, Negotiate, Settle, Verify** — composing the existing standards that already work and adding new ones only where the open ecosystem has gaps. Each new standard names the *substrate capability* it depends on, so DACS stays substrate-portable in specification while honest about what it needs underneath.

## 1. The problem

An agent transacting with another agent today has three options:

- **pre-integrated bilateral trust** — breaks at scale;
- a **closed operator marketplace** — scales, but the operator captures rents and becomes a single point of trust;
- **open standards** — the only path that scales without conceding a marketplace position, *if* a complete lifecycle exists.

Today the open standards cover stages, not the lifecycle.

A buyer agent can already discover a seller, recognise its identity, and authorise a payment using open standards. What it **cannot** do with open standards alone:

- **Declare and verify a bundle of identity claims** appropriate to the stakes — a signing key for a micropayment; LEI + regulatory registration + sanctions clearance for an institutional trade — each checked against the right authority.
- **Negotiate in private** — sealed-bid procurement, cross-counterparty RFQ, and MNPI-touching term negotiation, without leaking to a public mempool.
- **Produce an end-to-end session record** anchoring identity, verification, negotiation, payment, delivery, and attestation into one audit artifact the participants own.

These gaps map to four of the five stages, and they are why regulated agents still fall back to operator platforms. The closed alternatives are consolidating fast (AP2, x402, ERC-8004, ERC-8183, A2A each ship one slice; full-stack platforms build the rest behind operator APIs). DACS is the Demos contribution to keeping the lifecycle on public infrastructure.

## 2. The approach

Three principles:

- **Composition, not replacement.** Identity, payment, and several credential-attestation standards already work and have adoption; DACS uses them.
- **Gap-filling.** Where there are real gaps, DACS adds a narrow new standard that composes cleanly.
- **Stated substrate requirements.** Each new standard names the substrate capability it needs (the capability is the requirement; which substrate provides it is operational detail).

Consequences: adopters keep their existing identity/payment/credential tooling; DACS is replaceable in parts (swap a superseded standard, update the pointer); DACS is substrate-portable in principle (any substrate implementing the capabilities can host it).

## 3. The five stages

Every transaction — a $5 lookup or a $5M swap — passes through five stages, one DACS standard each:

| Standard | Stage | Scope |
| --- | --- | --- |
| **DACS-1** | **Identify** | agent identity, signed/anchored service listings, discovery |
| **DACS-2** | **Vet** | method-pluggable credential attestation against authoritative sources |
| **DACS-3** | **Negotiate** | private negotiation (RFQ, sealed-envelope, fixed-price) + agreement commitment |
| **DACS-4** | **Settle** | payment rail registry, payment phases, delivery phases |
| **DACS-5** | **Verify** | session record, attestation bundle, reputation derivation |

Stages are sequential within a transaction. The standards publish together at the v0.1 baseline and version independently thereafter.

## 4. The spine — nine artifacts that chain

Under the five stages, DACS is really **one signed artifact per stage, chained by content-hash references**, all sharing one signature + canonical-form discipline. This is the whole data model in miniature:

```
  ClaimReference            a typed identity pointer:  lei:5493… / did:web:… / key:0x…
        │
        ▼
  IdentityBundle  ──(DACS-1)     the claims a party presents
        │
        │   ─(DACS-2)→  CompositeVerificationRecord   proof each claim was checked vs its authority
        ▼
  Listing         ──(DACS-1)     the seller's signed offer = the binding contract
        │
        ▼
  AgreementArtifact ──(DACS-3)   the final terms, signed by both parties (legacy or payee-bound)
        │
        ▼
  SettlementEvidence / DeliveryEvidence ──(DACS-4)  proof a payment / delivery happened
        │
        ▼
  AttestationBundle ──(DACS-5)   the frozen, two-party-signed audit record of the whole session
        │
        ▼
  ReputationDerivation + RatingRecord ──(DACS-5)   reputation, keyed to the primary claim
```

Every other type in the spec is a sub-structure of one of these (price terms, tx refs, signatures), a registry entry that says *what methods/rails exist* (recipes, rail definitions), or per-variant phase I/O. Get the nine, and you have the model.

## 5. Substrate capabilities

Each standard cites a subset of five capabilities. A substrate shipping all five can host full DACS; a subset hosts it partially.

| ID | Capability | Demos implementation | Used by |
| --- | --- | --- | --- |
| **SR-1** | Cross-substrate identity aggregation (optional) | Cross-Context Identities (CCI) | DACS-1, 5 |
| **SR-2** | Anchored, immutable content-addressed storage | Storage Programs | all |
| **SR-3** | Consensus-backed proxy attestation of HTTP responses | DAHR | DACS-2 |
| **SR-4** | Identity-keyed private coordination channels | L2PS | DACS-3 |
| **SR-5** | Multi-chain coordinated atomic settlement | Liquidity Tanks / HTLC | DACS-4 |

*v0.1 coupling status:* SR-1/SR-2/SR-5 are specified at the protocol level (artifact-interoperable across substrates); SR-3/SR-4 are specified at the trust-property level only (not yet wire-interoperable cross-substrate — a v2 item).

## 6. Worked example — one transaction, end to end

A buyer agent **B** wants an attested price-feed snapshot from seller agent **S**. Mid-stakes: a signing key plus a verified domain is enough; fixed price; paid in USDC on Base; delivered as a DACS-2-attested payload.

1. **Identify.** S has published a **Listing** (signed, anchored) declaring: required bundle = `{ key, domain }`; offering = "attested price snapshot"; pipeline = `[negotiate-fixed-price, commit-payee-bound-agreement, pay-evm-erc20, deliver-attested-payload]`; rail = `evm-erc20:8453:USDC`; price = 5 USDC. B discovers it via S's `.well-known/agent.json` listings index. B assembles its own **IdentityBundle** (`key:0xB…` + a `domain:b-agent.example` claim with a `verifiedBy` reference).
2. **Vet.** Each side runs `vet-credentials` over the other's bundle against the listing's requirement. S's `domain` claim is checked via the `domain-tls-control` recipe; B's via its own. Each produces a **CompositeVerificationRecord** (anchored). Both pass → proceed.
3. **Negotiate.** The price is fixed, so "acceptance is the negotiation": `negotiate-fixed-price` → both parties sign a **PayeeBoundAgreementDocument** binding the listing, the 5-USDC term, the payment destination, the deliverable spec, and a deadline. `commit-payee-bound-agreement` anchors its hash — the binding moment.
4. **Settle.** `pay-evm-erc20` moves 5 USDC on Base; the handler waits for finality and anchors **SettlementEvidence** (an event-level tx ref + `settlementFinality`). Then `deliver-attested-payload`: S fetches the price, produces a DACS-4 payload-attestation record composing the selected DACS-2 method, writes the payload at its phase-indexed Storage Program address, and anchors **DeliveryEvidence** (signed phase index + deliverable hash/anchor + attestation ref). Pipeline order (PIPE) gates delivery on payment success.
5. **Verify.** Both parties anchor a co-signed **AttestationBundle** — the session's frozen audit record (identity → vet → agreement → both settlements). Optionally each rates the other (**RatingRecord**). Later, a consumer runs **ReputationDerivation** over S's bundles, keyed to S's primary claim, yielding S's completion rate / rating / volume.

One transaction; nine artifacts; each anchored and signed; the whole thing auditable by anyone with substrate access — and no operator in the middle.

## 7. How to read the rest

| You are… | Read |
| --- | --- |
| evaluating DACS / new to it | **this Primer** (you're done) |
| implementing the shared model | **[CORE](spec/CORE.md)** — data model, signatures, canonical form, session/phase model, substrate requirements, governance |
| implementing one stage | CORE + that stage's module — **Identify / Vet / Negotiate / Settle / Verify** |
| writing conformance tests | the module's Conformance index → the executable vectors in [`conformance/`](conformance/) |

*Profile:* a given DACS release pins a coherent version set (e.g. `DACS v0.1 = Core 0.1 + Identify 0.1 + Vet 0.1 + Negotiate 0.1 + Settle 0.1 + Verify 0.1`). Which stages/methods/rails a release ships is a profile decision.
