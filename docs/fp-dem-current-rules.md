# FP-DEM: current rules and known gaps

This non-normative map lists where the specification states the rules for one
transaction shape, and which open issues and pull requests affect it. The
specification text remains authoritative; this page only points to it.

**FP-DEM** here means a session that:

- negotiates with `negotiate-fixed-price`, DACS-3 §8.4.1;
- pays with `pay-dem` on the `demos-native:DEM` rail, DACS-4 §9.5.9; and
- delivers with `deliver-storage-program`, DACS-4 §9.6.1.

The Standard has no separate FP-DEM profile document. The rows below are the
sections such a session passes through.

**Revision.** The map follows the unreleased `next` branch at `df7bc20`. The
latest coordinated release is v0.4, and "DACS v0.1" remains the unqualified
profile name; see [PROFILE](../spec/PROFILE.md) for both and for the status of
`next`. Section numbers can move before the next release.

Sections resolve in the module files under [`spec/`](../spec/): §5 and §B in
CORE, §6 in DACS-1, §7 in DACS-2, §8 in DACS-3, §9 in DACS-4, and §10 in
DACS-5.

## Current rules

Rules are listed by labelled family, defined mainly in the cited section.
Some families span other sections. "—" marks a section whose procedure has no
labelled family. The "Covers" wording follows the [rule-ID index](rule-id-index.md).

| Stage | Section | Rule families | Covers |
|-------|---------|---------------|--------|
| Shared | §B.1 | JID-* | Job identifier grammar and equality |
| Shared | §B.1 / §B.2 | CF-* | Canonical form and raw JSON admission |
| Shared | §B.7 | SIG-* | Domain-separated signatures |
| Shared | §B.8 | SN-* | Session-nonce provenance |
| Shared | §5.1 | SR2-* | SR-2 writes, receipts, and logical-to-native resolution |
| Identify | §6.3.2 | BP-*, BR-* | IdentityBundle producers and readers |
| Identify | §6.3.2.1 | IT-* | Identity-tier derivation |
| Identify | §6.3.3 | MA-* | Bundle-requirement matching |
| Identify | §6.3.4 | LP-*, LR-* | Listing publishers and readers |
| Identify | §6.3.4 | LRR-* | Listing-time rail resolution and pay-phase binding |
| Identify | §6.3.4 | RB-*, RSC-* | Listing revocation markers and revocation state |
| Vet | §7.8 | VPC-* | Vet phase contract, where the pipeline has Vet phases |
| Negotiate | §8.4.1 | — | `negotiate-fixed-price` procedure |
| Negotiate | §8.5.1 | CD-* | Canonical decimal handling |
| Negotiate | §8.5.3 | FS-* | `feeSchedule` disclosure |
| Negotiate | §8.6 | CA-* | Agreement commitment phase validation |
| Negotiate | §8.8 | PS-* | Negotiation pattern selection |
| Settle | §9.4.3 | RD-* | Rail definitions and finality profiles |
| Settle | §9.4.4 | RAV-R* | Rail availability |
| Settle | §9.5.1 | PC-* | Payment phase common contract |
| Settle | §9.5.1 | PB-* | Payee-destination binding |
| Settle | §9.5.1 | LAA-* | Legacy agreement activation |
| Settle | §9.5.8 | SB-* | Session-bound settlement evidence |
| Settle | §9.5.9 | — | `pay-dem` procedure and `bft-final` finality |
| Settle | §9.6.1 | DV-* | Deliverable access / privacy (private delivery, credential handover) |
| Settle | §9.7.0 | FV-*, FRC-* | Consumer-verifiable finality and finality resolution |
| Settle | §9.7.0 | FP-*, PDE-* | Final settlement data propagation and phase-bound delivery evidence |
| Settle | §9.9.1 | PIPE-* | Pipeline shape and phase ordering |
| Verify | §10.3.1 | ST-* | Session state transitions |
| Verify | §10.3.2 | SPA-* | Signed participation admission |
| Verify | §10.4.2 | BB-* | Bundle logical-to-native binding |
| Verify | §10.4.3 | SEB-* | SettlementEvidence exact set and phase bijection |
| Verify | §10.5.1 | RSV-* | SettlementEvidence admission before reputation |
| Verify | §10.6.1 | RT-* | Rating bounds and derivation |

## Known gaps

Open issues, and open pull requests whose base is `next`, that affect the
rows above, including related optional design work. All 33 open items were
enumerated on 2026-10-15; the list has no issue-number cutoff.

| Number | Kind | Section | What is open |
|--------|------|---------|--------------|
| #419 | issue | §6.3.1, §6.3.2 | `presentedBy` control for `did:demos:agent` claims |
| #425 | issue | §6.3.4 | A pure logical-to-native mapping for Demos Listing versions, and absence and current-value policies |
| #408 | issue | §6.3.4 | A full verifier-owned Listing admission evaluator in the conformance reference |
| #386 | issue | §B.7 | Algorithm-specific signature and key profiles, including Ed25519 |
| #331 | issue | §7.8.1 | Authenticated provenance for the counterparty requirement in VPC-2 |
| #383 | issue | §7.4, §7.7.1, §7.12 | Same-claim multi-method quorum and trust-domain independence; current alternatives remain OR choices |
| #292 | issue | §8.6, §10.4 | A proposed batched deal-close commitment preserving per-party evidence and the existing gates before effects |
| #410 | issue | §9.5.1 | PB-* cases that no committed vector exercises yet |
| #426 | draft PR | §9.7.0 and others | Vectors for FV-1..FV-10 guards and other recently merged rules, with some clarifications |
| #374 | issue | §10.5 | Binding reputation derivations to a complete per-claim session set |
| #356, #371 | issue, draft PR | — | A pre-normative delivery-or-remedy profile; its first binding is an EVM escrow rail, not `pay-dem` |
| #99 | issue | §8.7, §10.10 | An optional DACS-X dispute-output interface and deterministic fixture contract |

Related conformance work remains open in #270: a neutral suite shared across
implementations. It concerns evidence for the rules above rather than a new
FP-DEM procedure. The older issue #220 concerns provider-rail reversals and
does not apply to the DEM rail.

Two issues on this path are still open although pull requests for them have
merged into `next`: #381 (§10.4; merged #391 and #417) and #382 (§9.7.0;
merged #392 and #416).
