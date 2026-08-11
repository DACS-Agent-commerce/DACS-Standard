# DACS — Glossary (Chapter 13)

> Part of **DACS v0.1**. Companion reference to [CORE](CORE.md) — moved out of the Core document to keep the normative reading surface compact. Original section numbering is retained, so existing citations (e.g. §13.x) remain stable.

A single alphabetical glossary across all five per-stage standards and the front/back matter. Informative; per-chapter definitions are normative.

---

## Chapter 13 — Glossary

A single alphabetical glossary across all five per-stage standards, the front matter, and the back matter. Terms defined in multiple chapters are cross-referenced. This glossary is informative; per-chapter definitions are normative.

- **AgreementArtifact.** Either DACS-3 signed agreement type: the legacy AgreementDocument or the PayeeBoundAgreementDocument. Defined in §8.5.
- **AgreementDocument.** The legacy DACS-3 signed agreement artifact. It preserves pre-payee-binding semantics and does not carry payout bindings. Defined in §8.5.
- **Anchor / Anchored.** Stored on the substrate such that an anchor reference (substrate-native pointer plus content hash) is sufficient for any party with substrate access to retrieve canonical content and verify integrity. Realised by SR-2.
- **AttestationBundle.** The frozen end-of-session artifact, signed by all parties, anchored via SR-2. The DACS-5 audit unit. Defined in §10.4. Legacy fault semantics: fault is read role-relatively from `outcome`. See FaultAttestationBundle.
- **AttestationRef.** A reference to an anchored attestation: anchor locator + content hash + (optional) signer. Defined in §7.5.
- **anchoredByRole.** Per-copy AttestationBundle field naming the role (buyer/seller/orchestrator) that anchored that copy; the copy's `outcome` is recorded from that party's perspective. Excluded from the hashed canonical form (so the two-sided copies stay equal) and integrity-checked against the anchor address instead. Defined in §10.4.1/§10.4.2.
- **Auto-accept commitment.** A pre-issued seller-side commitment authorising auto-acceptance of buyer signatures under negotiate-fixed-price. Defined in §8.4.1.
- **Bundle (identity bundle).** An ordered set of claims a party presents about itself, each independently verifiable, plus a presentation signature. Defined in §6.3.2.
- **BundleParty.** A party reference within a DACS-5 AttestationBundle. Defined in §10.4.
- **Canonical form.** RFC 8785 JCS serialisation of a document with signature field(s) omitted.
- **Catalog.** An off-chain index aggregating DACS-1 listings across many sellers for discovery. Defined in §6.3.6.
- **CCI (Cross-Context Identities).** The Demos implementation of SR-1 — cross-substrate identity aggregation. Demos product feature; not a DACS specification term.
- **Claim.** A fact a party asserts about itself.
- **Claim reference / ClaimReference.** A typed identifier referring to the external system that holds a claim. Grammar in §6.3.1; type definition in §7.1.
- **ClaimRequirement.** A listing-side declaration of which claims a buyer or seller bundle must include. Defined in §6.3.3.
- **Commit-agreement.** The DACS-3 phase that anchors a legacy AgreementDocument hash on the public chain. Defined in §8.6.
- **Commit-payee-bound-agreement.** The DACS-3 phase that anchors a PayeeBoundAgreementDocument hash on the public chain. Defined in §8.6.
- **CommitmentRecord.** The on-chain record produced by either DACS-3 agreement commitment phase. Defined in §8.6.
- **CompositeVerificationRecord.** The document the DACS-2 vet-credentials phase produces, aggregating freshness checks, supplementary signals, and deal-specific claims. Defined in §7.7.
- **Content hash.** sha256 hex of the canonical form of a document.
- **DACS-1..5.** The five per-stage standards: Identify, Vet, Negotiate, Settle, Verify.
- **DACS-X.** Anticipated future standard for dispute resolution; not part of v0.1.
- **DAHR (Data Agnostic HTTPS Relay).** The Demos implementation of SR-3 — consensus-backed proxy attestation of HTTP responses.
- **Deliverable / DeliverableSpec / DeliverableRef.** The thing being delivered to the buyer; spec defines its shape; ref points to a specific instance. Defined in §9.3.
- **Domain separator.** A protocol-specific string prepended to a hash before signing, preventing cross-protocol signature replay. Universal registry in §B.7.
- **EntitlementRecord.** A DACS-4 deliverable record granting time-bound access to a service. Defined in §9.6.2.
- **errorClass.** A classification of why a phase failed: permanent, transient, counterparty, substrate, settlement-atomicity. Used in PhaseHandlerResult and BundlePhaseEntry.
- **DeliveryEvidence.** The current DACS-4 signed evidence artifact for one delivery invocation; binds `jobId`, `phaseIndex`, phase kind, exact phase-indexed artifact address/hash, and conditional credential delivery. Defined in §9.7.
- **Evidence (SettlementEvidence / DeliveryEvidence).** The anchored DACS-4 audit record: `SettlementEvidence` for current payment phases and `DeliveryEvidence` for current delivery phases. Historical delivery-shaped `SettlementEvidence` is a restricted legacy form. Defined in §9.7.
- **Extended-pointer pattern.** A pattern for handling artifacts larger than the substrate’s anchored-storage cap: the canonical address contains a pointer with externalUrl + externalContentHash; payload is hosted externally. Used by deliverables (§9.6.1) and bundles (§10.4.2).
- **FaultAttestationBundle.** The v0.3 end-of-session artifact carrying absolute hashed `faultedParty` fault attribution; structurally distinguished from the legacy AttestationBundle by its `faultBundleVersion` literal and signed under its own `dacs-fault-bundle:v1:` domain. Defined in §10.4/§10.4.1.
- **Fixed-price negotiation.** DACS-3 pattern in which the buyer accepts the listed terms. Defined in §8.4.1.
- **HKDF.** The key derivation function specified in RFC 5869; used in HTLC preimage derivation per §9.5.4.
- **HTLC.** Hash Time-Locked Contract; the generic atomic-swap pattern used by pay-cross-chain-htlc. §9.5.4.
- **IdentityBundle.** See "Bundle".
- **Indeterminate.** A DACS-2 VerifyResult.decision value indicating the authority returned a parseable response that conclusively neither confirmed nor denied the claim. Distinct from "error" (verifier could not reach a decision at all). §7.5.1.
- **Error (decision value).** A DACS-2 VerifyResult.decision value indicating verification could not complete due to transport failure, parser exception, or other verifier-side failure. Distinct from "indeterminate" (authority answered, but ambiguously). §7.5.1.
- **JCS.** JSON Canonicalization Scheme; RFC 8785; used for canonical-form serialisation throughout.
- **jobId.** Per-session unique identifier; ULID or substrate-equivalent. Defined in §10.3.
- **L2PS (Layer-2 Privacy Subnets).** The Demos implementation of SR-4 — identity-keyed private coordination channels.
- **Liquidity Tank.** The Demos implementation of SR-5 — pre-funded cross-chain settlement primitive.
- **Listing.** A signed, anchored JSON document declaring an agent’s offering. The canonical contract for a transaction. Defined in §6.3.4.
- **Listing reachability.** A time-stamped operational observation that at least one advertised engagement surface responds. It is distinct from listing signature validity, conformance, revocation, identity, and reputation. Defined in §6.3.4/§6.3.6.
- **ListingIndex / ListingSummary.** Discovery data structures; not the source of truth. Defined in §6.3.5–6.3.6.
- **negotiate-fixed-price / negotiate-rfq / negotiate-sealed-envelope.** The three DACS-3 negotiation patterns. §8.4.
- **PayeeBoundAgreementDocument.** The DACS-3 agreement artifact whose required payout bindings are signed under a distinct domain and enforced by DACS-4 PB-1 through PB-3. Defined in §8.5.
- **PayloadAttestationRecord.** The DACS-4 record binding method-native verification evidence to exact delivered payload bytes, a job, its committed agreement, and the signed DeliverableSpec. It is distinct from a claim-oriented DACS-2 VerifyResult. §9.6.3.
- **PaymentRailRef / RailDefinition.** Reference to and full definition of a DACS-4 payment rail. §9.3, §9.4.
- **Per-claim keying.** DACS-5 rule that reputation is keyed against the bundle’s primary identity claim, not a wallet or signing key. §10.5.2.
- **perspective_flip.** The DACS-5 reconciliation mapping that re-interprets a counterparty-anchored bundle's `outcome` relative to the scored party (aborted-by-self ↔ aborted-by-other; failed-perm ↔ failed-counterparty). Buyer↔seller only. §10.5.1.
- **Phase / PhaseStep / PhaseType.** A single unit of work in a session pipeline. PhaseType is the closed enumeration across DACS-2..5. §6.3.4.
- **PhaseHandlerResult.** The return shape of every phase handler. §B.5 (front matter).
- **Pipeline.** The ordered sequence of PhaseStep entries declared in a listing. §6.3.4.
- **Presentation signature.** The signature on an identity bundle. §6.3.2.
- **sr1-root presentation.** A bundle-presentation kind in which a single SR-1 root key co-signs every claim under one aggregate signature, producing a single cryptographic artifact for the whole bundle. The natural presentation for a party self-binding a single document. §6.3.2.
- **Primary identity claim.** The claim within a bundle that serves as the canonical identifier of the party for reputation, audit, and addressing.
- **Rate phase.** Optional DACS-5 phase producing structured ratings between parties. §10.6.
- **RatingRecord.** A signed rating from one party about another. §10.6.
- **Recipe.** A DACS-2 binding of claim scheme to verification method, parsing rules, and defaults. §7.4.
- **Recipe availability.** A normative field on every Recipe declaring operational status: live | operator_gated | closed_data | bilateral | mocked | disabled | failed. Verifiers MUST inspect before running. §7.4.5.
- **Rail availability.** A normative field on every RailDefinition declaring operational status, with the same value set and semantics as recipe availability. Orchestrators MUST inspect before selecting. §9.4.4.
- **RFQ (Request For Quote).** DACS-3 bilateral negotiation pattern; bounded multi-turn offer-and-counter. §8.4.2.
- **Sealed-envelope.** DACS-3 sealed-bid procurement pattern. §8.4.3.
- **Session.** A per-transaction lifecycle from Identify through Verify.
- **SessionContext.** The context object every phase handler receives. §B.5 (front matter).
- **SessionRecord.** The orchestrator’s mutable working-state document. §10.3.
- **settle-asymmetric.** Non-terminal DACS-5 session state for the HTLC-9 cross-chain open case (payer claimed the destination, payee's source claim not yet final); resolves forward to settle-completed on a final htlc-claim, or to settle-failed on window expiry. §10.3.1 (ST-8).
- **SettlementAmendment.** A post-settlement record for refunds and corrections. §9.7.1.
- **SIWD (Sign-In With Demos).** Demos-wallet authentication pattern; EIP-4361-style envelope. Used for bundle presentation signatures.
- **SR-1..5.** Substrate requirements: SR-1 cross-substrate identity aggregation; SR-2 anchored immutable storage; SR-3 consensus-backed proxy attestation; SR-4 identity-keyed private coordination; SR-5 multi-chain coordinated atomic settlement. Defined in §5 (front matter).
- **Stor-backed credential.** A DACS-1 claim scheme whose verification result is anchored as a Storage Program. §6.3.1.
- **Storage Program.** The Demos implementation of SR-2 — content-addressed anchored key-value storage. 128 KB soft cap.
- **Substrate.** The underlying blockchain or protocol stack that hosts a DACS implementation. Demos is the v0.1 reference substrate.
- **Substrate-validator-set claim.** A ClaimReference identifying a substrate validator-set epoch; used as the signer for consensus-backed-proxy attestations. §7.5.
- **supersedesEvidenceRef.** SettlementEvidence field on an ST-8 `:resolved` success record pointing to the interim failure record it supersedes; a same-phase supersession, not a refund amendment. §9.7 / ST-8.
- **TxRef / ChainTxRef.** Discriminated union of on-chain transaction references. §9.3.
- **Universal signature scheme.** The cross-stack domain-separation scheme requiring every DACS signature to bind to a per-artifact-kind separator. §B.7.
- **ULID.** Universally Unique Lexicographically Sortable Identifier; recommended jobId format.
- **validator-set claim.** See "Substrate-validator-set claim".
- **VerifyResult / VerifyResultRef.** The uniform record every DACS-2 method produces; reference to an anchored VerifyResult. §7.5.
- **Vet-credentials phase.** The DACS-2 phase that runs verification across the counterparty’s bundle. §7.8.
- **Well-known/agent.json.** The A2A capability-discovery surface that DACS extends with a dacs block. §6.3.5.
