# Rule-ID index

This non-normative index helps implementers locate labelled conformance rules in the specification. The specification text remains authoritative.

## Rule families

| Rule family | Role / surface | Spec section | Test-plan hook |
|-------------|----------------|--------------|----------------|
| AMEND-* | Settlement amendment validation | §9.7.1 | §14.4 |
| AP2-* | `pay-ap2` provider-receipt verification, session binding, split credential scope, capture semantics, idempotency-key derivation, and `transaction_id` tuple binding / replay-safe retry | §9.5.6 | §14.4 |
| APR-* | Signed alternative-payment selection, projection, retry, and audit recomputation | §9.9.1 | §14.4 |
| BB-* | Bundle logical→native binding (publication, carriage, verification, resolution, multiplicity-void, fail-closed, suppression diligence) | §10.4.2 | §14.5 |
| BP-* | Bundle producers for IdentityBundle | §6.3.2 | §14.1 |
| BR-* | Bundle readers for IdentityBundle | §6.3.2 | §14.1 |
| CA-* | Agreement commitment phase validation | §8.6 | §14.3 |
| CD-* | Canonical decimal handling | §8.5.1 | §14.6 |
| CF-* | Canonical form and logical-address encoding | §B.1 / §B.2 / §6.3.4 | §14.6 |
| CH-* | Private-channel message handling | §8.3.1 | §14.3 |
| CM-* | Content-addressed anchoring | §7.3.1 | §14.8 |
| CRQ-* | ClaimRequirement candidate qualification before aggregation | §7.7.1 | §14.2 |
| DV-* | Deliverable access / privacy (private delivery, credential handover) | §9.6.1 / §9.6.2 | §14.4 |
| DCR-* | Canonical DNS-domain identity, Demos legacy alias compatibility, deduplication, metadata, and control boundary | §6.3.1 | §14.1 |
| DGCR-* | Persistent Demos GCR domain verification | §7.3.10 | §14.2 |
| DPA-* | Attested-payload listing coherence, exact-byte method proof, commerce binding, success closure, and minor-safe record typing | §9.6.3 | §14.4 |
| FP-* | Final settlement data and transitive evidence/bundle propagation | §9.7 | §14.4 |
| FR-* | Disclosed-fee reconciliation (informational) | §9.7.2 | §14.4 |
| FS-* | FeeSchedule disclosure on agreement artifacts | §8.5.3 | §14.3 |
| GOV-* | Registry governance & phase disclosure | §11.1.1 / §7.4.4 | §14.7 |
| HTLC-* | Cross-chain HTLC payment rail | §9.5.4 | §14.4 |
| IT-* | Deterministic identity-tier derivation | §6.3.2.1 | §14.1 |
| IM-* | Implementation manifest claims, capability status, and evidence | §14.10 | §14.10 |
| LP-* | Listing publishers | §6.3 | §14.1 |
| LR-* | Listing readers | §6.3 | §14.1 |
| LRR-* | Listing-time canonical payment-rail resolution and pay-phase binding | §6.3.4 | §14.1 |
| MA-* | Bundle-requirement matching | §6.3.3 | §14.1 |
| MTR-* | Metered pricing (per-unit total recompute + unrecognized-kind fail-closed) | §8.5.2 | §14.3 |
| PA-* | Progressive-anchoring phases | §7.4.4 | §14.7 |
| PB-* | Payee-destination binding (agreement carriage + identity-binding ladder + exact EIP-155 `cci-xm` rail applicability) | §9.5.1 | §14.4 |
| PC-* | Payment phase common contract | §9.5 | §14.4 |
| PCR-* | Presence-only ClaimRequirement matching, mixed Vet aggregation, and control/tier boundary | §6.3.3 / §7.7.1 | §14.1 / §14.2 |
| PIPE-* | Pipeline shape and phase ordering | §9.9 | §14.4 |
| PS-* | Negotiation pattern selection | §8.8 | §14.3 |
| PRA-* | Recipe parser applicability and selected-method execution | §7.4.1 / §7.6 | §14.2 |
| PSP-* | ParserSpec parse/match semantics | §7.4.1 | §14.2 |
| RA-* | Recipe-family authoring and resolution | §7.4.3 | §14.2 |
| RAV-* | Recipe availability values and consumers | §7.4.5 | §14.2 |
| RAV-R* | Rail availability values and orchestrators | §9.4.4 | §14.4 |
| RD-* | Delivery phase required data | §9.4.3 | §14.4 |
| RFQ-* | RFQ negotiation turns | §8.4.2 | §14.3 |
| RB-* | Listing-revocation marker binding, retained discovery, and fail-closed resolution | §6.3.4 | §14.1 |
| RT-* | Rating bounds and derivation handling | §10.6.1 | §14.5 |
| RSV-* | SettlementEvidence semantic admission before reputation | §10.5.1 | §14.5 |
| SB-* | Session-bound settlement evidence (full PC-2 address binding, signed event identity, deterministic projection, legacy replay, tx↔session binding, anti-double-count) | §9.5.8 | §14.4 |
| SE-* | Sealed-envelope negotiation | §8.4.3 | §14.3 |
| SEB-* | SettlementEvidence exact-set and phase-bijection validation | §10.4.3 | §14.5 |
| SIG-* | Universal domain-separated signatures | §B.7 | §14.6 |
| SN-* | Session-nonce provenance (verifier-generated anti-replay) | §B.8 | §14.6 |
| SR2-* | SR-2 write lifecycle, portable receipts, logical-to-native resolution, bounded discovery, visibility separation, and stage gates | §5.1 | §14.8 / §14.11 |
| ST-* | Session state transitions | §10.3.1 | §14.5 |
| VP-C* | VerifyResult caching semantics | §7.6.1 | §14.2 |
| VP-R* | VerifyResult retry semantics | §7.6.1 | §14.2 |
| VPC-* | Vet phase contract | §7.8 | §14.2 |
| WN-* | Advisory verification warnings | §7.7 | §14.2 |
| X402-* | x402 settlement-response selection, canonical receipt hashing, and evidence consistency | §9.5.7 | §14.4 |

## How to use this index

- Treat it as a navigation aid only; rule wording lives in the linked spec sections.
- Prefer rule-family tests that point at the §14 conformance plan before adding one-off checks.
- Substrate-capability checks are indexed separately in [§14.8](../spec/CONFORMANCE-PLAN.md#148-substrate-capability-tests).
- Update this index when a new labelled rule family is added to the specification.
- Run `python3 scripts/validate_rule_ids.py` and `python3 scripts/validate_rule_id_index.py` before opening a PR that edits labelled rules or this index. The latter checks that each family's cited section actually defines that family, so the pointers cannot drift silently.
