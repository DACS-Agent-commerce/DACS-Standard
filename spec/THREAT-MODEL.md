# DACS — Unified threat model (Chapter 12)

> Part of **DACS v0.1**. Companion reference to [CORE](CORE.md) — moved out of the Core document to keep the normative reading surface compact. Original section numbering is retained, so existing citations (e.g. §12.x) remain stable.

Adversary model, trust boundaries, threat catalogue, and the composite trust property. Where this chapter restates per-chapter threats, the per-chapter mitigation is normative; this chapter's framing is informative.

---

## Chapter 12 — Unified threat model

This chapter collects, partitions, and rationalises the per-chapter security considerations into a unified threat model. It is the artifact a security review would start from. Where this chapter restates per-chapter threats, the per-chapter mitigation is normative; this chapter’s framing is informative.

### 12.1 Scope and non-goals

DACS’s security goals are:

- (a) cryptographic non-repudiation of every per-session artifact (listings, bundles, agreements, evidence) by the parties that produced them;
- (b) tamper-evident audit trail — any modification of an anchored artifact is detectable by content-hash comparison;
- (c) limited-trust substrate dependency — the substrate is trusted for liveness and consensus per its own security model, not for application-layer semantics;
- (d) prevention of cross-protocol signature confusion via the universal domain-separation scheme in §B.7;
- (e) prevention of replay across sessions via per-session jobIds, nonces, and content hashes;
- (f) substrate-failure isolation in reputation derivation so substrate outages do not damage party reputations.

Non-goals:

- DACS does **not** prevent collusion between buyer and seller. Two parties who jointly fabricate a session produce a valid session; the audit trail records what they say happened, not what objectively happened.
- DACS does **not** prevent denial-of-service by a counterparty or by the substrate. It produces evidence of the failure for reputation purposes, but does not guarantee progress.
- DACS does **not** prevent regulatory non-compliance. It produces artifacts useful for compliance audit but does not enforce any specific regulatory regime.
- DACS does **not** provide unconditional privacy. The SR-4 channel contents stay between members, but member identity and timing of commitments are visible on the public chain by design.

**The visibility non-goal extends to the audit layer.** Anchored DACS-5 bundles, commit-agreement records, and DACS-2 vet attestations carry party **primary claims — durable authority-issued identities (LEI, FINRA-CRD, …) — in cleartext at derivable addresses**. A passive observer can therefore reconstruct the **counterparty graph** (who transacted with whom, correlatable across every session an identity runs) with **no cryptography to break**, and can read each vet attestation's `scheme:identifier:decision` (e.g. "party X was screened against OFAC → clear"). DACS accepts this by design — it is an *accountability* standard, and a public, verifiable audit trail necessarily exposes the relationship. Raw private *values* behind a verification are separately protected by the §7.5 public-anchor data-minimisation rule; only predicate outcomes are exposed.

> **Note (non-normative).** A confidentiality layer that anchors these records **encrypted to the parties** while keeping the content hash public for tamper-evidence is roadmap work, not v0.1.

### 12.2 Adversary model

The threat model assumes adversaries with the following capabilities; per-threat mitigations specify which class is being defended against.

| Adversary class | Capabilities | Assumed not capable of |
| --- | --- | --- |
| Network observer | Reads all public-chain traffic; can perform timing analysis on commitments; **can reconstruct the counterparty graph from anchored bundles / commit-agreement records / vet attestations (cleartext primary claims at derivable addresses) and read each vet attestation's scheme:identifier:decision**; cannot read private-channel contents. | Breaking standard cryptographic primitives (sha256, Ed25519, ECDSA-secp256k1 under standard assumptions); recovering the raw private values behind a verification (predicate-outcome-only under §7.5 minimisation). |
| Network active attacker | Can drop, delay, reorder, or inject messages on transport links; can MITM TLS sessions if PKI is compromised. | Forging signatures by valid private keys; producing sha256 preimages. |
| Malicious counterparty | Operates a fully-conformant DACS implementation but maximises self-interest within the protocol; signs everything they’re willing to be held to and refuses to sign anything else. | Forging the other party’s signatures; controlling validator-set consensus on the substrate. |
| Compromised authority | A registry authority (GLEIF, FINRA, OFAC, etc.) returns false data, either by deliberate compromise or by API corruption. | Forging substrate-validator signatures over the false response (validators sign the fetch result, not the data’s factuality). |
| Substrate validator-set minority | A minority of substrate validators is compromised; the consensus protocol’s normal Byzantine bound holds. | Producing valid consensus signatures on falsehoods (assuming the BFT assumption holds). |
| Substrate validator-set majority | A majority of substrate validators is compromised. | (none — above the substrate’s security floor; DACS inherits the failure.) |
| Substrate operator (rotating shard) | For Liquidity Tank-style SR-5: the rotating validator shard operating tanks is partially compromised within its multisig threshold. | Bypassing the 2/3 BFT multisig or the deployer emergency-recovery path. |
| Channel operator (SR-4) | Operates the private negotiation channel; can drop messages, fork views, observe all member messages. | Forging member signatures inside the channel; observing messages encrypted to a member subset (with realisation-appropriate encryption). |
| Recipe-registry attacker | Compromises the recipe registry signing key, attempts to push poisoned recipes. | Backdating recipe-version pinning; affecting already-pinned sessions. |
| Sybil attacker | Generates unlimited low-tier (key:…) identities and farms self-deal reputation. | Generating authority-issued claims (lei, finra-crd, etc.) without owning the underlying registrations. |
| Malicious orchestrator | Drives the session pipeline, assigns `errorClass`, constructs the SessionRecord, and MAY be a distinct REQUIRED signer (§10.4.1); can misclassify failures, drop or reorder phase results, or selectively anchor. | Forging buyer/seller signatures, or producing a both-sided-signed bundle without honest-party consent (§10.11 two-sided independent bundles; party-disagreement → aborted-by-other). |
| Malicious infrastructure | Operates discovery/index/storage infrastructure a party depends on (catalog API, listings index, anchor host); can serve poisoned, stale, or withheld data on the read path. | Forging the signatures on the signed artifacts it serves (consumers dereference anchors and verify content hashes + signatures independently). |
| Malicious verifier | Runs the DACS-2 vet path; can mis-run a recipe, substitute a method, or assert a decision the authority did not return. | Forging the authority's signed/consensus-anchored response, or a recipe steward signature; producing a VerifyResult that re-derives correctly under method/recipe-version checks. |
| Spam / resource-exhaustion adversary | Floods a public surface (ERC-8004 registry writes, negotiation-channel griefing, mempool) to raise cost or degrade availability. | Forging identities or claims (each write/identity costs); breaking liveness of correctly-rate-limited or staked surfaces. |

**Reconciling the §12.4 "Primary adversary" column with this model.** Every §12.4 row's adversary resolves to a class above, with two conventions:

- (a) **Variants of an existing class** — "competing bidder" and "two colluding counterparties" are *Malicious counterparty* (single and colluding); "public-mempool observer" is *Network observer*; "storage operator" is *Malicious infrastructure*.
- (b) **Non-adversary conditions** — "time" (TOCTOU / stale-window races) and "implementation bug" (e.g. decimal overflow) are **environmental / robustness** conditions, not adversaries. The threat is real and the cited mitigation stands, but there is no actor to model; these rows are defended by deterministic rules and bounds, not by an adversary assumption.

### 12.3 Trust boundaries

A reader following the audit trail from a DACS-5 bundle backwards through the lifecycle crosses these trust boundaries; each boundary has its own assumptions.

- **Party-to-party cryptographic boundary.** Every signed artifact (listing, bundle, agreement, evidence, rating) is verifiable against the signer’s primary-claim key. Trust assumption: the signing key has not been compromised at or before the artifact’s timestamp. Mitigation: key-rotation handling per §6.6 (DACS-1 security considerations).
- **Party-to-authority boundary.** A DACS-2 VerifyResult of method consensus-backed-proxy depends on the authority (GLEIF, FINRA, OFAC, etc.) being honest at fetch time and on the TLS PKI between the substrate validators and the authority. Mitigation: the recipe’s alternatives mechanism (§7.4) lets high-stakes schemes declare additional independent verification methods (§7.12); the v0.2 strengthening (§7.3.5) will tighten the consensus-backed-proxy method itself.
- **Party-to-substrate boundary.** Every anchor (listings, bundles, evidence, recipes, rails) depends on the substrate’s SR-2 implementation for availability and content integrity. Trust assumption: substrate validator-set is honest per the substrate’s consensus protocol. Mitigation: on-substrate anchoring (Storage Programs on Demos) provides indefinite availability; off-substrate anchoring (IPFS, HTTPS) is best-effort.
- **Substrate-to-substrate boundary (cross-chain).** SR-5 atomic settlement crosses chains and depends on the SR-5 mechanism’s trust model (HTLC: cryptographic only; Liquidity Tank: substrate operator; substrate-native: substrate consensus). Mitigation: explicit rail-trust-model disclosure in rail definitions; per-stake rail selection.
- **Party-to-recipe-registry boundary.** Verification routes through recipes whose signing authority is the registry steward (currently KyneSys Labs, per §7.4.4 and §11.1.1). Trust assumption: the steward’s signing key is honest and uncompromised. Mitigation: monotonic recipe-version pinning per session; emergency-revision discipline (§7.4.4). Residual risk under PA-2: steward-key compromise; PA-3 multi-signature governance is the v0.2+ mitigation pathway.

### 12.4 Threat catalogue

Every per-chapter security threat, indexed by adversary class and mitigation status. The threats are stated normatively in the per-chapter sections; this is the cross-reference.

| Threat | Primary adversary | Where mitigated | Status |
| --- | --- | --- | --- |
| Forged listing | malicious counterparty | §6.6 + §B.7 (signatures + domain separator) | mitigated |
| Signed Listing extension stripped or rejected by a closed-key verifier | implementation bug / minor-version skew | §B.7 SIG-5 + §11.1.2 additivity; signed Listing conformance vectors | mitigated |
| Identity-bundle replay | network observer | §6.3.2 (session nonce) + §6.6 | mitigated |
| Attestation-bundle replay across sessions | malicious counterparty | §10.11 (jobId bound into the bundle hash) | mitigated |
| Catalog poisoning | malicious infrastructure | §6.3.6 (clients dereference anchors) | mitigated |
| Anchor-receipt forgery / state promotion | malicious infrastructure or writer | CORE §5.1 SR2-4..SR2-6 (binding-defined authenticated evidence; logical/native/hash/transaction/writer/nonce checks; block/finality proof) | mitigated subject to substrate evidence security |
| Anchor snapshot reordering / false replacement | malicious infrastructure or stale observer | CORE §5.1 SR2-7 (binding-defined authenticated evidence ordering; `observedAt` never establishes precedence; replacement independently verified) | mitigated; unresolved conflicts remain indeterminate |
| Identity-claim substitution | malicious counterparty | §6.6 (pinned bundle hash) | mitigated |
| Old presenter-asserted claim reused for presence-only matching | malicious counterparty / time | §6.3.2 session-nonce binding + §6.3.3 PCR-2/PCR-5 (signed exact claim; optional presenter `expiresAt` enforced; presence supplies no authority freshness, verification, tier, or control) | accepted by design for existence-only presence; controlled `key:` use still requires the live presentation signature |
| Domain-alias claim/tier inflation or legacy-artifact rewrite | malicious counterparty / implementation divergence | §6.3.1 DCR-3..DCR-5 (canonical-only production; original-byte verification before permanent alias normalization; semantic deduplication) | mitigated |
| Copied, stale, or falsely refreshed Demos domain-GCR binding | malicious counterparty / malicious infrastructure | §6.3.1 DCR-6..DCR-8 + §7.3.10 DGCR-1..DGCR-6 (authenticated GCR/source match; Ed25519 host/account proof; inclusion-time effective window; bundle-account control; no fresh-proof substitution) | mitigated subject to Demos consensus and configured effective window |
| Method substitution | malicious verifier | §7.12 (method field comparison) | mitigated |
| Recipe poisoning | recipe-registry attacker | §7.12 (signed recipes + pinned recipeVersion) | mitigated |
| Substrate validator capture (SR-3) | substrate validator-set majority | §7.12 (multi-method alternatives) | partial — v0.2 strengthening planned |
| Authority-endpoint TLS MITM (forged authority response) | network active attacker (PKI compromise) | §7.3.5 (v0.2 validator-body-signed) + §7.4 (multi-method alternatives) | partial — v0.2 strengthening planned, residual in v0.1 |
| Negative-match fail-open (truncated sanctions list clears a listed party) | malicious infrastructure / lossy fetch | §7.4.1 PSP-5 (completeness floor before a negative `pass`) | mitigated |
| Parser/method confusion overrides a method-native verdict or forces an inert parser contract | malicious verifier / implementation divergence | §7.4.1 PRA-1..PRA-5 + §7.6 (closed method classification; producer/steward shape enforcement; native readers ignore parser members regardless value; missing/invalid required parsers and unknown methods fail before invocation) | mitigated |
| Verifiable-presentation replay (verified VC re-presented by a non-holder) | malicious counterparty | §7.3.2 (VP holder-binding to session nonce) | mitigated |
| HTLC preimage-reveal front-running | network observer / MEV | §9.5.4 (claims are beneficiary-bound — a front-runner cannot redirect funds; ordering/MEV is a chain-level concern, not a DACS theft vector) | mitigated (theft) / residual (ordering) |
| Rail availability-field poisoning, mocked production selection, or stale discovery/mode-hint override | malicious infrastructure / counterparty / misconfigured operator | §6.3.4 LRR-6 + §9.4.4 RAV-R1..RAV-R5 (disabled/failed new-session prohibition; mocked production-session prohibition; production mode from trusted local operator policy; disabled in-flight distinction; complete signed pinned definition authority; discovery and counterparty hints are non-authoritative) | mitigated |
| Self-declared, handler-drifting, or unregistered listing rail | malicious counterparty / malicious infrastructure | §6.3.4 LRR-1..LRR-6 + §9.4.3 RD-6 (canonical registry resolution, exact version/signature binding, same-railId handler invariance, unavailable authority indeterminate, no silent PA-2 fallback) | mitigated |
| Alternative-payment downgrade, handler substitution, or double authorization after ambiguous settlement | malicious counterparty / orchestrator / implementation divergence | §8.5.2 + §9.9.1 APR-1..APR-8 + §10.4.3 (full-reference signed selection; authenticated projection; concrete evidence; selection lock; reconcile-only retry; fresh-job replacement bound to a finalized signed `PriorPaymentDisposition` and exact prior Agreement/selection/index; durable pre-authorization closure or proof-backed terminal reconciliation; independent audit recomputation) | mitigated |
| Cross-session offer replay (channelId reuse) | malicious counterparty | §8.12 CH-6 (channelId unique per session) | mitigated |
| Counterparty-graph reconstruction (cleartext primary claims at derivable anchor addresses) | network observer | §12.1 (accepted by design — public audit trail; requires no crypto; encrypted-to-parties anchoring is roadmap) | accepted by design |
| Vet-attestation disclosure (anchored VerifyResult reveals "party X screened against authority Y → outcome Z") | network observer | §7.5 (public-anchor data minimisation — predicate outcomes only, no raw PII) + §12.1 (scheme:identifier:decision accepted by design) | partial — raw PII minimised; relationship/decision accepted by design |
| VerifyResult replay | malicious verifier | §7.12 (identifier + bundle hash binding) | mitigated |
| TOCTOU authority change | time | §7.12 (maxAge tightening) | parameter-driven |
| Indeterminate exploitation | malicious counterparty | §7.5.1 + §7.7.1 (aggregation) | mitigated |
| Channel-operator censorship | channel operator | §8.12 (CH-4 liveness detection) | mitigated (substrate-dependent) |
| Channel-operator forking | channel operator | §8.12 (monotonic sequence + cross-check) | mitigated |
| Offer replay across sessions | network observer | §8.12 (channelId in envelope) | mitigated |
| Cross-artifact signature replay | malicious counterparty | §B.7 universal domain separators | mitigated |
| HTLC asymmetric-loss blame ambiguity (window-expired ST-8 reads failed-counterparty for both sides) | time / malicious counterparty | §10.11 (out-of-band review of settlement-atomicity-marked failed-counterparty) | partial — DACS-X dispute concern |
| HTLC free-option abandonment (payer declines reveal after market move; payee capital locked) | malicious counterparty | §9.5.4 HTLC-10 (prefer liquidity-tank or payer stake; DACS-5 records the pattern) | partial — known HTLC property, not standardised in v0.1 |
| Sealed-envelope front-running | competing bidder | §8.12 (hash commitment + private channel) | mitigated |
| Sealed-envelope post-deadline submission | malicious counterparty | §8.4.3 (chain-timestamp anchoring) | mitigated |
| Sealed-envelope same-bidder commit swapping | malicious bidder / implementation divergence | §8.4.3 SE-9 (earliest anchored commit authoritative; same-anchor bidHash total order; later commits inert) | mitigated |
| Sealed-envelope procurement role inversion | malicious orchestrator / implementation bug | §8.4.3 SE-8 + §8.5.2 (pinned-mode role-direction validation at the agreement commitment phase) | mitigated |
| Agreement-listing mismatch | malicious counterparty | §8.5.2 (validation in the agreement commitment phase) | mitigated |
| Payee-bound terms ignored by an older payer | minor-version skew | §8.5 distinct PayeeBoundAgreementDocument + §8.6 distinct commitment phase + §9.5.1 structural artifact gate + CORE §11.1.2 new-type refusal | mitigated |
| EVM payee-control proof applied to the wrong chain through `mainnet` / `testnet` / `sepolia` alias guessing | malicious counterparty / implementation divergence | §6.3.1 EVM `cci-xm` settlement-chain profile + §9.4.3 RD-5 + §9.5.1 PB-2 exact `eip155:<chainId>` equality | mitigated; name-style legacy claims remain readable but do not establish tier 2 |
| Re-entrancy on EVM rails | malicious counterparty | §9.13 (phase-handler ordering) | implementation-dependent |
| MEV front-running on payments | public-mempool observer | §9.13 (private mempool option) | parameter-driven |
| Cross-chain atomicity failure | time / chain operator | §9.13 (HTLC timelocks) | mitigated for HTLC; SR-5 implementation-dependent for tanks |
| Liquidity-tank operator compromise | substrate operator | §9.13 (substrate consensus + 15-day recovery) | partial — substrate-trust-floor |
| AP2 checkout/mandate replay or retry double-charge | network observer / retry race | §9.5.6 AP2-5..AP2-7 (status reconciliation; byte-exact tuple-derived provider idempotency key; atomic `transaction_id` → `(jobId, phaseIndex)` binding; exact-tuple resume without a second payment; cross-tuple rejection) | mitigated subject to provider idempotency guarantees and durable handler state |
| AP2 privileged provider credential exposure through SR-3 | malicious or compromised relay | §9.5.6 AP2-3 (distinct create/metadata and payment-status-only credentials; privileged credential never relayed; incapable integration refused at registration) | mitigated subject to provider credential-scope enforcement |
| x402 settlement-reference forgery | malicious server | §9.5.8 SB-3 (`jobId` + `phaseIndex` bound into the byte-exact `dacs-sb3:v1:` EIP-3009 nonce, or `jobId` into the Permit2 witness; DACS confirms the on-chain settlement, never trusts `PAYMENT-RESPONSE` alone) | mitigated — DACS-side binding, not inherited |
| x402 receipt reserialization / substitution | implementation bug or malicious server | §9.5.7 X402-1..X402-4 (versioned header selection; complete decoded-object JCS hash; transaction/network cross-check) | mitigated |
| Attested-payload self-assertion or cross-session proof replay | malicious counterparty or orchestrator | §9.6.3 DPA-1..DPA-9 (method required before session; exact-byte method proof; job/agreement/spec/method binding; PayloadAttestationRecord required for success; settlement signature never substitutes) | mitigated subject to selected method's disclosed trust floor |
| Repeated-delivery address collision or one evidence/artifact counted for two invocations | malicious counterparty, orchestrator, or implementation divergence | §9.7 PDE-1..PDE-8 (signed phase index; exact phase-indexed evidence/artifact addresses; independent renewal/attempt streams; DACS-5 one-to-one mapping; legacy restricted to one unambiguous invocation) | mitigated |
| Credential-delivery replay, ciphertext-hash substitution, or delivered/valid/readable collapse | malicious seller or orchestrator | §9.6.2 DV-5/DV-6 + §9.7 PDE-4..PDE-7 (exact EntitlementRecord hash/anchor, credential ref/access mode, cleartext digest, renewal and delivered-only binding; unresolved stays indeterminate) | mitigated for anchored delivery; endpoint-side bearer-token revocation remains outside DACS |
| Refund laundering | malicious seller | §9.13 (anchored amendments) | mitigated |
| Decimal-overflow on cross-decimal pay | implementation bug | §9.13 (string-decimal arithmetic) | mitigated |
| Bundle forgery | malicious counterparty | §10.11 (co-signature requirement) | mitigated |
| Bundle suppression | malicious counterparty | §10.11 + §10.4.3 authoritative-absence gate | mitigated when authoritative absence is available; otherwise indeterminate |
| Bundle-copy read censorship (a hidden divergent copy appears one-sided) | malicious infrastructure | CORE §5 SR-2 absence evidence + §10.4.3 / §10.5.1 guard (iv) | mitigated for integrity; one-copy availability depends on the substrate binding |
| Sybil reputation farming | sybil attacker | §10.11 (per-primary-claim keying) | mitigated for cross-tier; not for same-tier |
| Reputation collusion | two colluding counterparties | §10.11 (volume disclosure + external signals) | partial — protocol cannot prevent |
| Orchestrator error-class misclassification | malicious orchestrator | §10.11 (party-disagreement → aborted-by-other) | mitigated |
| Bundle anchor unavailability | storage operator | §10.11 (on-substrate anchoring) | mitigated (substrate-dependent) |
| Stale reputation windows | time | §10.11 (explicit window bounds) | consumer-driven |
| ERC-8004 write spamming | spam adversary | §10.11 (gas cost + per-session rate limit) | mitigated |
| RFQ session-initiation flooding | malicious counterparty | §8.12 (per-counterparty session-rate limit + optional DACS-2 admission floor) | partial — maxTurns/timeoutSec bound a session, not the initiation rate |
| Sealed-envelope commit-spam | malicious counterparty | §8.12 (optional bidder stake + commit-anchor rate limit) | partial — v0.1 does not standardise stake or bidder eligibility |

### 12.5 Composite trust property

A DACS-5 bundle that validates against all per-chapter conformance rules and whose contained references all dereference and validate provides the following composite trust property to a consumer:

> "Two or more parties identified by the named primary claims (with the trust profile each claim’s scheme implies) participated in a session against the named listing version, agreed to the named terms, exchanged the named settlements, and produced this audit record. The substrate operator did not collude with the parties to forge the record. The recipe registry was not compromised at the time of the verifications. The composed external standards (W3C VC, TLSNotary, ACME, etc.) behaved per their own security models."

This is the composite security claim of DACS v0.1. Each clause has explicit mitigation in the per-chapter sections; each has explicit residual risk in this chapter’s adversary model.
