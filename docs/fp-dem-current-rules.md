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
CORE, §6 in DACS-1, §7 in DACS-2, §8 in DACS-3, §9 in DACS-4, §10 in DACS-5,
§11 in CORE, and §14 in CONFORMANCE-PLAN.

## Current rules

Each rule ID is paired with its defining section at the pinned revision.
Rules sharing a section occupy one row; split families have separate rows.
"—" points to a procedure or contract without a labelled rule family.
The "Covers" wording follows the [rule-ID index](rule-id-index.md).

Conditional rules remain conditional: the Vet methods, registry anchoring,
private delivery, refunds and corrections, fee disclosure, reputation modes
and implementation reporting below apply only where their source sections say
so. PS-3 lets `negotiate-fixed-price` run over a metered listing, so MTR-1..MTR-4
apply when the listing is metered; MTR-5 applies to every agreement.
This map does not select those options. Other payment rails, alternative
payment selection, other negotiation patterns, private negotiation channels,
attested-payload delivery and the `deliver-entitlement` credential rules
(DV-5, DV-6 in §9.6.2) are outside this shape.

| Stage | Section | Rule IDs | Covers |
|-------|---------|----------|--------|
| Shared | §5.1 | SR2-1, SR2-2, SR2-3, SR2-4, SR2-5, SR2-6, SR2-7, SR2-8, SR2-9, SR2-10, SR2-11, SR2-12, SR2-13 | SR-2 write lifecycle, portable receipts, logical-to-native resolution, bounded discovery, visibility separation, and stage gates |
| Shared | §11.1.1 | GOV-1 | Registry governance & phase disclosure |
| Shared | §B.1 | CF-2, CF-3, CF-4 | Canonical form, raw JSON admission, and logical-address encoding |
| Shared | §B.1 | JID-1, JID-2, JID-3, JID-4 | Canonical byte-exact job identifier grammar, derivation gate, and equality |
| Shared | §B.2 | CD-1 | Canonical decimal handling |
| Shared | §B.2 | CF-1, CF-5 | Canonical form, raw JSON admission, and logical-address encoding |
| Shared | §B.2 | IBH-1, IBH-2, IBH-3, IBH-4, IBH-5, IBH-6 | Identity-bound agreement digest derivation, authenticated companion joins, and cross-stage enforcement |
| Shared | §B.7 | SIG-1, SIG-2, SIG-3, SIG-4, SIG-5, SIG-6 | Universal domain-separated signatures |
| Shared | §B.8 | SN-1, SN-2, SN-3, SN-4 | Session-nonce provenance (verifier-generated anti-replay) |
| Identify | §6.3.1 | DCR-1, DCR-2, DCR-3, DCR-4, DCR-5, DCR-6, DCR-7, DCR-8 | Canonical DNS-domain identity, Demos legacy alias compatibility, deduplication, metadata, and control boundary |
| Identify | §6.3.2 | BP-1, BP-2, BP-3, BP-4 | Bundle producers for IdentityBundle |
| Identify | §6.3.2 | BR-1, BR-2, BR-3, BR-4, BR-5 | Bundle readers for IdentityBundle |
| Identify | §6.3.2.1 | IT-1, IT-2, IT-3 | Deterministic identity-tier derivation |
| Identify | §6.3.3 | MA-1, MA-2, MA-3 | Bundle-requirement matching |
| Identify | §6.3.3 | PCR-1, PCR-2, PCR-3, PCR-4, PCR-5, PCR-6 | Presence-only ClaimRequirement matching, mixed Vet aggregation, and control/tier boundary |
| Identify | §6.3.4 | LP-1, LP-2, LP-3, LP-4, LP-5, LP-6, LP-7 | Listing publishers |
| Identify | §6.3.4 | LR-1, LR-2, LR-3 | Listing readers |
| Identify | §6.3.4 | LRR-1, LRR-2, LRR-3, LRR-4, LRR-5, LRR-6 | Listing-time canonical payment-rail resolution and pay-phase binding |
| Identify | §6.3.4 | RB-1, RB-2, RB-3, RB-4, RB-5, RB-6 | Listing-revocation marker binding, retained discovery, and fail-closed resolution |
| Identify | §6.3.4 | RSC-1, RSC-2, RSC-3, RSC-4, RSC-5, RSC-6, RSC-7, RSC-8, RSC-9, RSC-10 | Current listing-revocation state head, append-only completeness proofs, and new-session admission |
| Vet (if present) | §7.3.1 | CM-1, CM-2, CM-3, CM-4, CM-5 | Content-addressed anchoring |
| Vet (if present) | §7.3.10 | DGCR-1, DGCR-2, DGCR-3, DGCR-4, DGCR-5, DGCR-6 | Persistent Demos GCR domain verification |
| Vet (if present) | §7.4.1 | PRA-1, PRA-2, PRA-3, PRA-4, PRA-5 | Recipe parser applicability and selected-method execution |
| Vet (if present) | §7.4.1 | PSP-1, PSP-2, PSP-3, PSP-4, PSP-5 | ParserSpec parse/match semantics |
| Vet (if present) | §7.4.3 | RA-1, RA-2, RA-3, RA-4, RA-5, RA-6 | Recipe-family authoring and resolution |
| Vet (if present) | §7.4.4 | GOV-2, GOV-3 | Registry governance & phase disclosure |
| Vet (if present) | §7.4.4 | PA-1, PA-2, PA-3 | Progressive-anchoring phases |
| Vet (if present) | §7.4.5 | RAV-1, RAV-2, RAV-3, RAV-4, RAV-5, RAV-6, RAV-7 | Recipe availability values and consumers |
| Vet (if present) | §7.6.1 | VP-C1, VP-C2, VP-C3 | VerifyResult caching semantics |
| Vet (if present) | §7.6.1 | VP-R1, VP-R2, VP-R3, VP-R4 | VerifyResult retry semantics |
| Vet (if present) | §7.7 | WN-1, WN-2, WN-3, WN-4, WN-5, WN-6 | Advisory verification warnings |
| Vet (if present) | §7.7.1 | CRQ-1, CRQ-2, CRQ-3, CRQ-4 | ClaimRequirement candidate qualification before aggregation |
| Vet (if present) | §7.8.1 | VPC-1, VPC-2, VPC-3, VPC-4, VPC-5 | Vet phase contract |
| Negotiate | §8.5.2 | MTR-1, MTR-2, MTR-3, MTR-4, MTR-5 | Metered pricing (per-unit total recompute + unrecognized-kind fail-closed) |
| Negotiate | §8.5.3 | FS-1, FS-2, FS-3, FS-4, FS-5 | FeeSchedule disclosure on agreement artifacts |
| Negotiate | §8.6 | CA-1, CA-2, CA-3, CA-4, CA-5, CA-6, CA-7, CA-8, CA-9, CA-10 | Agreement commitment phase validation |
| Negotiate | §8.8 | PS-1, PS-2, PS-3 | Negotiation pattern selection |
| Settle | §9.4.3 | RD-1, RD-2, RD-3, RD-4, RD-5, RD-6, RD-7 | Rail definition authoring and finality-profile requirements |
| Settle | §9.4.4 | RAV-R1, RAV-R2, RAV-R3, RAV-R4, RAV-R5 | Rail availability values and orchestrators |
| Settle | §9.5.1 | LAA-1, LAA-2, LAA-3, LAA-4, LAA-5, LAA-6, LAA-7 | Legacy agreement activation and historical-era admission |
| Settle | §9.5.1 | PB-1, PB-2, PB-3 | Payee-destination binding (agreement carriage + identity-binding ladder + exact EIP-155 `cci-xm` rail applicability) |
| Settle | §9.5.1 | PC-1, PC-2, PC-3, PC-4, PC-5, PC-6, PC-7 | Payment phase common contract |
| Settle | §9.5.8 | SB-1, SB-2, SB-3 | Session-bound settlement evidence (full PC-2 address binding, signed event identity, deterministic projection, legacy replay, tx↔session binding, anti-double-count) |
| Settle | §9.6.1 | DV-1, DV-2, DV-3, DV-4 | Deliverable access / privacy (private delivery, credential handover) |
| Settle | §9.7.0 | FP-1, FP-2, FP-3, FP-4 | Final settlement data and transitive evidence/bundle propagation |
| Settle | §9.7.0 | FRC-1, FRC-2, FRC-3, FRC-4, FRC-5, FRC-6, FRC-7, FRC-8, FRC-9, FRC-10, FRC-11 | Verifier-issued multi-authority finality resolution, retained conflict union, replay, and composite gating |
| Settle | §9.7.0 | FV-1, FV-2, FV-3, FV-4, FV-5, FV-6, FV-7, FV-8, FV-9, FV-10 | Consumer-verifiable canonical settlement finality |
| Settle | §9.7.0 | PDE-1, PDE-2, PDE-3, PDE-4, PDE-5, PDE-6, PDE-7 | Phase-bound delivery evidence, phase-indexed artifact addresses, exact entitlement-credential delivery binding, legacy reads, and DACS-5 one-to-one mapping |
| Settle | §9.7.0, §10.4.3 | PDE-8 | Phase-bound delivery evidence, phase-indexed artifact addresses, exact entitlement-credential delivery binding, legacy reads, and DACS-5 one-to-one mapping |
| Settle | §9.7.1 | AMEND-1, AMEND-2, AMEND-3, AMEND-4 | Settlement amendment validation |
| Settle | §9.7.2 | FR-1, FR-2, FR-3, FR-4 | Disclosed-fee reconciliation (informational) |
| Settle | §9.9.1 | PIPE-1, PIPE-2, PIPE-3, PIPE-4, PIPE-5, PIPE-6 | Pipeline shape and phase ordering |
| Verify | §10.3.1 | ST-1, ST-2, ST-3, ST-4, ST-5, ST-6, ST-7, ST-8, ST-9, ST-10, ST-11 | Session state transitions |
| Verify | §10.3.2 | SPA-1, SPA-2, SPA-3, SPA-4, SPA-5, SPA-6, SPA-7, SPA-8 | Signed participation admission, one-sided blame, and ordinary-rating admission |
| Verify | §10.4 | LAB-1, LAB-2, LAB-3, LAB-4, LAB-5, LAB-6, LAB-7 | Current-use admission of original legacy bundle mappings and strictly pre-checkpoint receipts |
| Verify | §10.4.2 | BB-1, BB-2, BB-3, BB-4, BB-5, BB-6, BB-7, BB-8 | Bundle logical→native binding (publication, carriage, verification, resolution, multiplicity-void, fail-closed, suppression diligence) |
| Verify | §10.4.3 | SEB-1, SEB-2, SEB-3, SEB-4, SEB-5, SEB-6 | SettlementEvidence exact-set and phase-bijection validation |
| Verify | §10.5 | AWT-1, AWT-2, AWT-3, AWT-4, AWT-5, AWT-6, AWT-7, AWT-8 | Standalone independently verified business-outcome occurrence window (narrower than combined current-use) |
| Verify | §10.5.1 | CUAW-1, CUAW-2, CUAW-3, CUAW-4, CUAW-5, CUAW-6 | Exclusive composed current-use authenticated-window admission, all-job occurrence, and complete replay |
| Verify | §10.5.1 | CUR-1, CUR-2, CUR-3, CUR-4, CUR-5, CUR-6, CUR-7, CUR-8 | Explicit all-or-nothing current-use dependency derivation and replay with its original window clock |
| Verify | §10.5.1 | RSV-1, RSV-2, RSV-3, RSV-4 | SettlementEvidence semantic admission before reputation |
| Verify | §10.6.1 | RT-1, RT-2 | Rating bounds and derivation handling |
| Report | §14.10 | IM-1, IM-2, IM-3, IM-4, IM-5, IM-6, IM-7, IM-8 | Implementation manifest claims, capability status, and evidence |
| Negotiate | §8.4.1 | — | `negotiate-fixed-price` procedure |
| Negotiate | §8.5.1, §8.5.2 | — | Agreement serialisation and listing-conformance validation |
| Settle | §9.5.9 | — | `pay-dem` procedure and `bft-final` finality |
| Settle | §9.6.1 | — | `deliver-storage-program` procedure |
| Shared | §11.1.2 | — | Versioning and authenticated corrective-profile admission |
| Verify | §10.4.1 | — | Bundle type, signature and required-signer validation |

## Known gaps

Open issues, and open pull requests whose base is `next`, that affect the
rows above, including related optional design work. All 35 open items other
than the pull request adding this map were enumerated on 2026-10-18; the list
has no issue-number cutoff. Open pull
requests were checked for a `next` base. The disposition of #330 below was
checked against the pinned specification and its open issue on the same date.

| Number | Kind | Section | What is open |
|--------|------|---------|--------------|
| #419 | issue | §6.3.1, §6.3.2 | `presentedBy` control for `did:demos:agent` claims |
| #341 | draft PR | §6.3.4 | A negotiated x402 rail candidate that also makes DACS-1 LRR-5 name the pre-registry rejections, so LRR-4 and LRR-5 agree when the registry is unavailable |
| #425 | issue | §6.3.4 | A pure logical-to-native mapping for Demos Listing versions, and absence and current-value policies |
| #408 | issue | §6.3.4 | A full verifier-owned Listing admission evaluator in the conformance reference |
| #430 | draft PR | §6.3.4 | Listing-admission script fixes for wrong-typed pipeline kinds and required capabilities, related to #408 |
| #386 | issue | §B.7 | Algorithm-specific signature and key profiles, including Ed25519 |
| #331 | issue | §7.8.1 | Authenticated provenance for the counterparty requirement in VPC-2 |
| #383 | issue | §7.4, §7.7.1, §7.12 | Same-claim multi-method quorum and trust-domain independence; current alternatives remain OR choices |
| #292 | issue | §8.6, §10.4 | A proposed batched deal-close commitment preserving per-party evidence and the existing gates before effects |
| #336, #320 | PR, issue | §9.4.3, §9.5.1, §9.7.1, §10.4.3 | A candidate Atomic DACS Work profile (RFC #320). For every profile it also changes rail resolution (§9.4.3), PC-1 arm selection (§9.5.1) and the AMEND-1 discriminator and signature-domain check (§9.7.1); it adds Atomic handling at SEB-3 |
| #410 | issue | §9.5.1 | PB-* cases that no committed vector exercises yet |
| #432 | draft PR | §9.5.9, §9.5.1, §9.5.8, §9.7.0 | `pay-dem` success only on a bound, executed transaction record (DEM-1..DEM-7); a node's `included` status is not settlement |
| #426 | draft PR | §9.6.1, §9.7.0, §10.4.2, DEMOS-MAPPING §A.2 and others | Vectors for FV-1..FV-10 guards and other recently merged rules, with some clarifications, including the Storage Program soft limit below |
| #374 | issue | §10.5 | Binding reputation derivations to a complete per-claim session set |
| #356, #371 | issue, draft PR | — | A pre-normative delivery-or-remedy profile; its first binding is an EVM escrow rail, not `pay-dem` |
| #99 | issue | §10.4.2, §10.4.3, §11.2.1 | An optional DACS-X dispute-output interface and deterministic fixture contract over the bundle divergence walk |

#432 concerns the payment step itself. At the pinned revision, §9.5.9 step 5
returns success once the transfer reaches the terminal `included` state, and
its failure modes expect a failed transfer to reach `failed`. #432 reports
that `kynesyslabs/node` at `61b8e75aa8db5e408c49e1c3a89db4d673f45578` stores a
`confirmed` or `failed` record for each transaction, while
`getTransactionStatus` reports `included` for every stored record, failed ones
included; it pins `@kynesyslabs/demosdk` 4.0.16 (npm integrity
`sha512-nVhp1uC+tFGzhew9c8XIajTMmELopx7gd0joqqzDd2XyUuFDcqrda51NYqvX5C8+L3Xgnie/mRf7JRqZ7r3tHA==`).
A handler that follows step 5 as written can therefore report a failed
transfer as settled. A read-only query to `node2.demos.sh` on 2026-10-18 is
consistent with this; it is an observation of a live node, not a pin.
`getTransactionStatus` returned `included` at block 480877 for transaction
`85b8fcdcee48822742a39e1b9877f5e2f8dde36430e8e486e3a8b0c9a7744cbd`, and
`getTxByHash` returned the same transaction with status `failed`
(`TX_NONCE_INVALID_LOW`). This map records the gap and does not change §9.5.9.

No open issue tracks these vector gaps yet:

- no committed vector exercises the §8.4.1 procedure or its auto-accept
  requirements: an expired commitment, a live instance signature over the
  actual `agreementHash` rather than a placeholder or pre-issued one, and the
  buyer's check of the commitment before relying on auto-accept;
- no committed conformance vector or v0.4 suite case exercises PS-1 or PS-2.
  The DACS-5 reference regression test
  (`tests/test_current_evidence_boundary_regressions.py`) and
  `scripts/listing_artifact.py` do check missing, duplicate and non-adjacent
  phases on a fixed-price pipeline;
- no committed vector exercises the PS-3 requirement that the listing's
  pricing model be compatible with the chosen pattern, such as fixed-price
  over an auction listing. `neg-ps3-fixed-over-negotiable` and the `ps3-*`
  vectors in `agreement-listing-v0.1` cover only the negotiable band-centre
  clause;
- no committed vector exercises the §9.6.1 extended pointer
  (`externalUrl`, `externalContentHash`) for payloads above the Storage
  Program soft limit. DV-1..DV-4 have expected outputs only in the
  `private-deliverables-v0.1` security set, which is not part of the
  conformance manifest.

§9.6.1 gives that soft limit as a 128 KB Storage Program cap. The same
128 KB appears in DACS-5 §10.4.2 (bundles MUST fit within it), in
DEMOS-MAPPING §A.2 ("128 KB cap") and in the GLOSSARY entry for Storage
Program ("128 KB soft cap"). The Demos node enforces 1 MiB
(`STORAGE_PROGRAM_MAX_SIZE_BYTES = 1048576` in `GCRStorageProgramRoutines.ts`
at `kynesyslabs/node` `61b8e75`), as does `@kynesyslabs/demosdk` 4.0.16.
Open draft PR #426 proposes stating 128 KB in all four places as a DACS soft
limit of 131,072 bytes, stricter than the 1 MB substrate cap, and adds a
reference test of that boundary rather than a conformance vector.

`pay-dem` `bft-final` finality (§9.5.9, §9.7.0) and the `demos-native:DEM`
registry entry (§9.4.2; resolved per §9.4.3) also depend on two open upstream
issues that §9.5.9 reaches through #382:

- DACS-Agent-commerce/dacs-sdk#284: pin the Demos mainnet trust bootstrap
  before funded live use;
- kynesyslabs/node#994: publish an authoritative Demos mainnet trust
  descriptor and live DEM registry entry.

Related conformance work remains open in #270: a neutral suite shared across
implementations. It concerns evidence for the rules above rather than a new
FP-DEM procedure. The older issue #220 concerns provider-rail reversals and
does not apply to the DEM rail.

Two issues on this path are still open although pull requests for them have
merged into `next`: #381 (§10.4; merged #391 and #417) and #382 (§9.7.0;
merged #392 and #416).

Issue #330 also remains open. Merged work includes #333 and #418.
Its original credential-delivery wire-binding
concern is addressed in this revision by the distinct `DeliveryEvidence`
shape (§9.7), PDE-5 (§9.7.0), DV-5 (§9.6.2), and PDE-8 (§10.4.3). Those sections
separate current credential delivery from historical delivery-shaped
`SettlementEvidence`. The issue body predates this shape and has no follow-up
comments identifying a remaining gap. It is recorded here for reconciliation,
without asserting a remaining normative defect or closing the issue.
