# DACS — Conformance test plan (Chapter 14)

> Part of **DACS v0.1**. Companion reference to [CORE](CORE.md) — moved out of the Core document to keep the normative reading surface compact. Original section numbering is retained, so existing citations (e.g. §14.x) remain stable.

The conformance requirements and golden-vector test plan, per role and per module. Machine-readable fixtures live in [conformance/](../conformance/).

---

## Chapter 14 — Conformance test plan

This chapter sketches the test categories an implementer should cover to claim conformance to each DACS standard. It is a **plan, not a test suite**; the test suite itself (test vectors, expected outputs, golden files) is produced separately and tracked alongside reference implementations. Where a chapter’s conformance summary enumerates labelled rules (e.g., BP-1, LR-2, CM-3), the test plan groups them into runnable categories.

The non-normative [`conformance/walkthrough/`](../conformance/walkthrough/)
provides a dependency-free executable onboarding path through one pinned
five-stage artifact set. It links each operation back to the rule and vector IDs
below; it does not add or replace conformance requirements.

### 14.1 DACS-1 — Identify

Exercise each rule at its normative home; full text is not restated (define-once). Fixtures under `conformance/`.

| Rules | Home | Exercise (intent) | Vectors |
| --- | --- | --- | --- |
| Claim-reference parser | §6.3.1 | every scheme: valid canonical / valid non-canonical (canonicalise on read) / invalid grammar (reject) / unknown-scheme (not silently accepted); EVM `cci-xm` PB profile requires lowercase `evm`, a canonical positive-decimal chain ID, and a non-empty otherwise-opaque address, maps only that chain ID to `eip155:<chainId>`, ignores ClaimReference parameters for chain selection, and never guesses `mainnet` / `testnet` / `sepolia` | `conformance/vectors/`; `conformance/vectors/security/cci-xm-rail-chain-applicability-v0.5.json` |
| DCR-1..DCR-8 (domain canonicalization and Demos alias) | §6.3.1 | canonical lower-case IDNA A-label production; invalid host rejection; permanent legacy read after original-byte verification; no rehash/resign; alias dedup before tier/`oneOf`/reputation; current dual emission rejection; GCR metadata preservation; exact account-bound control; persistent/fresh separation | `conformance/vectors/security/domain-claim-gcr-v0.4.json` |
| BP-1..BP-4 (bundle producer) | §6.3.2 | produce → canonical form → hash → domain-separated sign → anchor round-trip | `conformance/fixtures/identity/` |
| BR-1..BR-5 (bundle reader) | §6.3.2 | accept-conformant; reject unsigned / missing-required-`verifiedBy` / unverified-`presentedBy`-when-selector-set; unknown-scheme → unverified; Demos agent DID scheme-case and identifier-canonicalisation cases; SIWD `dacs:<hex>` Resource + session-`Nonce` match | `conformance/fixtures/identity/` |
| match() (BundleRequirement) | §6.3.3 | required missing / required failing / oneOf satisfied / oneOf unsatisfied / selector match / mismatch | `conformance/vectors/` |
| LP-1..LP-6, LR-1..LR-3 | §6.3 | publisher: sign / anchor / version-monotonicity / revocation, pay-rail resolution before active publication, plus SHOULD-level operational reachability; reader: halt-on-first-failure, revoked/rail-indeterminate refusal, size-cap | `conformance/vectors/` |
| LRR-1..LRR-6 (listing-time rail resolution) | §6.3.4 | pay-phase↔accepted-ref binding; duplicate JCS-ref rejection while permitting distinct same-ID requirements; every advertised-ref resolution; same-ID handler invariance; exact rail/version/hash/signature/handler binding; conclusive unknown/mismatch rejection; unavailable authority indeterminate; PA-1 latest selection; PA-2/PA-3 no in-code fallback; explicit listing-time/session-start boundary | `conformance/vectors/security/listing-rail-registry-resolution-v0.4.json` |
| RB-1..RB-6 (revocation binding) | §6.3.4 | anchor/sign marker; retain revoked discovery entry; resolve opaque native anchor; verify hash/signature/tuple; revoked/indeterminate refusal; successful-absence boundary | `conformance/vectors/security/revocation-binding-v0.3.json` |
| Discovery | §6.3.5 / §6.3.6 | well-known parser; catalog endpoint shape; listing and revocation anchor cross-checks from retained discovery records | `conformance/vectors/` |
| IT-1..IT-3 (identity tier) | §6.3.2.1 | derive from verified-and-fresh claims only; ignore self-asserted; deterministic; institutional precedence; stale-`verifiedBy` does not elevate | `conformance/fixtures/identity/` |

### 14.2 DACS-2 — Vet

| Rules | Home | Exercise (intent) | Vectors |
| --- | --- | --- | --- |
| CM-1..CM-5 (method common) | §7.3 | per-method: input-shape; pass/fail/indeterminate; attestation anchoring; `VerifyResult` with correct method; canonical form + domain-sep signature | `conformance/fixtures/` |
| RA-1..RA-6 + resolution | §7.4 | steward-sig + domain separator; canonical anchoring; scheme-global version monotonicity across families; same-family supersede-on-replace; no active method overlap; `(scheme, method, version)` lookup; content-hash; version pinning | `conformance/` |
| DGCR-1..DGCR-6 (`demos-gcr-domain`) | §7.3.10 | authenticated finalized GCR resolution; exact host/account/proof/source match; real Ed25519 proof vector; unavailable authority indeterminate; inclusion-time freshness; bundle-account control; no fresh-control substitution | `conformance/vectors/security/domain-claim-gcr-v0.4.json` |
| PSP-1..PSP-5 | §7.5.1 | match-predicate per format; parse-fail → error (not fail); negative-match inversion; `indeterminateOn` before match; dataMap extraction non-deciding; deterministic (no script/sub-fetch/redirect); PSP-5 completeness floor before a negative `pass` | `conformance/` |
| VP-R1..VP-R4, VP-C1..VP-C3 | §7.6.1 | transient retry / permanent no-retry / new-attestation / no-retry-on-indeterminate; reuse within effective window; maxAge tightens never widens | `conformance/` |
| Aggregation | §7.7.1 | classify_required branches; oneOf within-group precedence error>indeterminate>fail; cross-accumulator fail>error>indeterminate; VPC-4 counterparty-malformed attribution | `conformance/` |
| RAV-1..RAV-7, RAV-R1..RAV-R5 | §7.4.5, §9.4.4 | recipe availability consumer+steward behaviour; rail preflight; no mocked/disabled/failed production-session selection; disabled in-flight continuation; RAV-R5 authoritative signed read with discovery hints ignored for protocol decisions | `conformance/vectors/security/rail-availability-selection-v0.1.json` + `tests/test_rail_availability_selection_vectors.py` |
| VPC-1..VPC-5, MA-1..MA-3 | §7.8, §6.3.3 | phase order / two-sided; durable-acceptance minimum before reversible return; no broadcast-ack promotion; idempotent same-address reconciliation to finality; fail-or-indeterminate; matching + `presentedBy` verification | `conformance/` |
| WN-1..WN-6 (warnings) | §7.7 | advisory-only; MUST NOT move `overallDecision`; preserved on `pass`; `suggestedRetryAfterMs` doesn't override recipe; unknown-code conservative | `conformance/fixtures/` |

### 14.3 DACS-3 — Negotiate

| Rules | Home | Exercise (intent) | Vectors |
| --- | --- | --- | --- |
| Channel envelope + failure | §8.3.3, §8.12 | channelmsg domain-sep sig; sequence monotonicity; signature scope; liveness-exceeded → channel-failed; abort round-trip | `conformance/` |
| negotiate-fixed-price | §8.4.1 | live signature path; auto-accept commitment + instance-signature path; reject pre-issued per-instance signatures | `conformance/` |
| RFQ-1..RFQ-4 | §8.4.2 | maxTurns; turn-timeout; out-of-band-terms rejection at the agreement commitment phase | `conformance/` |
| SE-1..SE-9 | §8.4.3 | commitDeadline (chain-timestamped); reveal-window vs SR-2 anchor (SE-3); mismatch exclusion; anchored-reveal-set selection (relay-suppression); exclusion ordering (currency/non-positive before reserve); reserve floor/ceiling inclusive; tie-break (SE-5); empty-set → negotiate-failed; rule-ref content-hash binding (SE-6); bidHash domain-sep + salt floor (SE-7); sealed-envelope role assignment and commit rejection for role inversion / missing or unresolvable procurement `auctionMode` (SE-8); earliest same-bidder commit authority with same-anchor bidHash total order and later-commit reveal exclusion (SE-9) | `conformance/` |
| MTR-1..MTR-5 | §8.5.2 | metered currency/unit validation; canonical unsigned-integer quantity; ceil for fractional raw units; exact `unitPrice × quantity` / floor recompute; unrecognized pricing kind rejected before commit | `conformance/vectors/security/metered-pricing-v0.3.json` + `tests/test_metered_pricing_vectors.py` |
| PS-1..PS-3 | §8.8 | exactly-one negotiate phase; exactly one of the two agreement commitment phases immediately follows; pattern ↔ pricing-model compatibility | `conformance/` |
| Agreement validation | §8.5.2 | price-band / rail-acceptance / deliverable / deadline / pattern checks; artifact ↔ commitment-phase match; exact pay-phase payout-binding coverage; `priceAnchor` valid-when-present, optional | `conformance/` |
| Agreement-artifact minor compatibility | §8.5, CORE §11.1.2 / §11.2.5 | legacy reader accepts AgreementDocument and structurally rejects PayeeBoundAgreementDocument before action; current reader accepts both; reject both/neither discriminators and cross-domain signatures | `conformance/vectors/security/payee-destination-binding-v0.1.json` |
| CA-1..CA-9 | §8.6 | refuse irreversible Settle effects until finalized receipt; double-commit reject across both record types; immutability after anchor; type-specific domain-separated commitment signature; reject artifact/phase coercion; orchestrator authority independent of SR-2 deployer/owner/address; agreement binding by verified party signatures + `agreementHash`; finality record's signed `createdAt` distinct from receipt-derived `committedAt`; legacy `committedAt` historical-anchor cross-check; exact-one discriminator and anti-coercion; SIG-2 cross-domain replay refusal | `conformance/vectors/security/payee-destination-binding-v0.1.json`; `conformance/vectors/security/commitment-anchor-authority-v0.3.json`; `conformance/vectors/security/commitment-record-compatibility-v0.1.json`; `conformance/vectors/security/sr2-anchor-lifecycle-v0.1.json` |
| Commitment-record minor compatibility | §8.6 / §8.11, CORE §11.1.2 | legacy `CommitmentRecord` remains readable under its frozen shape/domain; new `FinalityCommitmentRecord` is structurally distinct and uses its own domain; legacy-only reader refuses new type; current reader accepts exactly one supported discriminator; both/neither/cross-domain/coercion attempts reject | `conformance/vectors/security/commitment-record-compatibility-v0.1.json` |

### 14.4 DACS-4 — Settle

Exercise each rule at its normative home; the full rule text is **not** restated here (define-once — same discipline as the §12.4 threat index). "Exercise" is one-line test intent; executable fixtures live under `conformance/`.

| Rules | Home | Exercise (intent) | Vectors |
| --- | --- | --- | --- |
| RD-1..RD-6 | §9.4.3 | steward-sig + domain separator; anchor; version monotonicity; railType↔asset/network consistency, including identical positive `asset.chainId` / `network.chainId` for EVM assets; same-railId phase-handler invariance | `conformance/fixtures/settlement/`; `conformance/vectors/security/listing-rail-registry-resolution-v0.4.json`; `conformance/vectors/security/cci-xm-rail-chain-applicability-v0.5.json` |
| PC-1..PC-7 | §9.5.1 | input-shape; anchored evidence; `attestationRef`/`anchorReceipt` deferrable after rail finality under PC-7; all `errorClass` values; PC-5 currency-resolution; PC-6 `settlementFinality` present-on-success/absent-on-delivery; PC-7 all-rail evidence catch-up without payment resubmission | `conformance/fixtures/settlement/`; `conformance/vectors/security/sr2-anchor-lifecycle-v0.1.json` |
| PB-1..PB-3 | §9.5.1 | payee-bound destination match/mismatch; exact `(railId, phaseIndex)` coverage; tier-1/2/3 selection including tier-1 intrinsic and tier-2 controlled-claim positive cases; EVM tier-2 applicability derived by exact CAIP-2 chain equality from lowercase `evm` + canonical chain ID + non-empty opaque address rather than a pre-filled flag or name alias; applicable-unresolvable pause with exact recorded cause; resolver `error` stays `error`; no downgrade; SB-3 fallback is not imported into the pre-pay gate; legacy agreement follows legacy behaviour and carries no PB claim | `conformance/vectors/security/payee-destination-binding-v0.1.json`; `conformance/vectors/security/cci-xm-rail-chain-applicability-v0.5.json` |
| X402-1..X402-4 | §9.5.7 | v1/v2 response-header selection; recursive CF-1 NFC pre-pass then full decoded-object JCS hash; JSON/base64 normalization; extensions and unknown members preserved; malformed/non-success refusal; hash and transaction/network mismatch rejection | `conformance/vectors/security/x402-receipt-hash-v0.1.json` |
| SB-1..SB-3 | §9.5.8 | settlement bound to `(jobId, phaseIndex)` (SB-1); a `settlement-tx-id` reused under a second `(jobId, phaseIndex)` is counted once across a consumer's set (SB-2); optional on-chain `jobId` binding — for `pay-x402` EIP-3009, byte-exact `SHA-256(UTF8("dacs-sb3:v1:") || UTF8(NFC(jobId)) || 0x3a || ASCII(decimal(phaseIndex)))`, match/mismatch, malformed input, NFC, and retry/no-random-substitution behaviour (SB-3) | `conformance/vectors/security/sb2-settlement-uniqueness-v0.1.json`; `conformance/vectors/security/sb3-eip3009-nonce-v0.1.json` |
| HTLC-1..HTLC-10 | §9.5.4 | buyerSalt entropy/confidentiality/non-reuse; HKDF derivation + input-uniqueness; canonical claim order; per-chain hashlocks; timelock asymmetry on absolute expiry (pinned params, source-finality margin); HTLC-9/ST-8 asymmetric resolution; HTLC-10 free-option | `conformance/fixtures/settlement/htlc9-asymmetric.json` |
| CD-1 | §B.2 | economically-equal decimals (`"1.50"`=`"1.5"`) → identical hashes/signatures | `conformance/vectors/` (CD-1) |
| AMEND-1..AMEND-4 | §9.7.1 | `amendsEvidenceRef` resolves + jobId match; refund/partial-refund reference success-only; summed `refundAmount` ≤ `paymentAmount`; flagged-amendment not treated as valid unwind | `conformance/fixtures/settlement/` |
| FP-1..FP-4 | §9.7 | placeholder draft never signed/anchored/referenced; final source fields rebuild evidence hash/signature; final evidence ref and duplicated tx refs propagate into the bundle; bundle hash/signatures recompute; stale propagation or unrelated semantic change rejects | `conformance/vectors/security/settlement-finalization-propagation-v0.3.json` |
| DPA-1..DPA-9 | §9.6.3 | missing listing method rejected before payment; distinct PayloadAttestationRecord discriminator/domain; exact payload-byte digest; job/agreement/DeliverableSpec/method binding; native proof and transaction verification; pass-only success gate; required SettlementEvidence hash/anchor/ref closure; unresolved proof remains indeterminate; seller evidence signature cannot substitute; cross-session replay and cross-type coercion reject; DAHR UTF-8/hash/tx profile | `conformance/vectors/security/payload-attestation-binding-v0.1.json` |
| PIPE-1..PIPE-6 | §9.9 | ≥1 deliver (pay-* optional, §6.3.4(8)); deterministic ordering; pay↔deliver gating; phase repetition; finalized DACS-3 commitment before payment or irreversible delivery | `conformance/vectors/security/sr2-anchor-lifecycle-v0.1.json` |
| Per-rail procedures | §9.5.2–§9.5.7 | erc20/spl decimal-conversion (no float) + finality wait; **spl ATA create-if-missing gated on `createPayeeAtaIfMissing`, payer-funded rent, create-failure → errorClass**; tank BridgeOperation lifecycle + route scope; ap2/x402 mandate-revocation + receipt-signature | `conformance/fixtures/settlement/` |
| Delivery phases | §9.6 | storage-program (normal + extended-pointer); entitlement sig/anchor/scope; attested-payload composing method-native DACS-2 evidence through the DACS-4 PayloadAttestationRecord and DPA gate | `conformance/fixtures/`; `conformance/vectors/security/payload-attestation-binding-v0.1.json` |

### 14.5 DACS-5 — Verify

| Rules | Home | Exercise (intent) | Vectors |
| --- | --- | --- | --- |
| ST-1..ST-11 (state machine) | §10.3.1 | every `(from→to)` legal-only; illegal-pair reject (ST-1); abort/timeout only in action-pending states before irreversible effects (ST-3/ST-9), never rate/audit pending; rate branch + non-fatal (ST-4/5); ST-7 pause→resume / →failed-substrate including audit-pending; ST-8 `settle-asymmetric` forward-resolution, non-terminal; ST-10 cancellation; ST-11 `audit-pending` requires finalized/resolvable dependencies and bundle before `finalised`; terminal→`outcome` map (ST-6) | `conformance/fixtures/settlement/`; `conformance/vectors/security/sr2-anchor-lifecycle-v0.1.json` |
| Bundle production | §10.4 | two-sided anchoring at role addresses; `anchoredByRole` ↔ address (mismatch rejected); canonical-equality happy path (excludes anchoredByRole/signatures); `dacs-bundle:v1:` / `dacs-fault-bundle:v1:` sigs; v0.3 production anchors FaultAttestationBundle; extended-pointer; publish a signed BundleBinding per anchored copy on a write-input substrate (BB-1/BB-2) | `conformance/fixtures/` |
| Bundle consumption | §10.4.3 | two-sided resolution (derive logical → resolve signed BundleBinding → fetch native, BB-5, never recomputation); an unresolvable or unverifiable binding → indeterminate; one-sided only after authoritative absence; unqualified `not found`, transport failure, or inconsistent state views → indeterminate; independent second copy restores normal unified/divergent classification; divergence = bundle `outcome`, shared-index `phaseSummary.kind`/`outcome`/`errorClass`, or entry-presence contradiction (advisory skew is NOT divergence); out-of-band dispute handling; consumer verdicts are not bundle outcome values; DACS-5 reputation excludes divergent and indeterminate jobIds | `conformance/fixtures/`; `conformance/vectors/security/bundle-absence-evidence-v0.3.json`; `conformance/vectors/security/phase-kind-divergence-v0.3.json` |
| BB-1..BB-8 (bundle binding) | §10.4.2 | per-copy publication + reachable-surface requirement (BB-1/BB-2); self-authenticating carriage (BB-3); signature/signer verification (BB-4); resolution without `storageProgramName`, signer holds the claimed role (BB-5 check 9 role-match); authorized-candidate multiplicity — co-signed party-map pruning, unauthorized copies inert, canonically-equal collapse, full-signature precedence, budget exhaustion → indeterminate, equal-standing authorized divergence → indeterminate (BB-6); fail closed to indeterminate, never recompute (BB-7); one-sided only after a resolved binding plus policy-qualified authoritative absence (BB-8) | `conformance/vectors/security/bundle-binding-v0.1.json`; `conformance/vectors/security/outsider-binding-flooding-v0.3.json` (BB-6 per-signer budget, BB-5 check 9 role-match cross-role-insider, and the executed collapse / full-signature-precedence / equal-standing-void ladder); `conformance/vectors/security/receipt-rederivation-v0.3.json` (BB-6 replay reconstruction — the complete anchored-map rebuild from every candidate bundle with genuine BB-5 check-8 byte recompute: equal-standing two-full void ⇒ refuse, unfetchable-candidate ⇒ refuse, poisoned-candidate check-8 ⇒ inert / honest resolves); `conformance/vectors/security/fab-bundle-extended-pointer-v0.3.json` (BB-5 pointer triple-identity); `conformance/vectors/security/unresolved-vs-absent-v0.3.json` (BB-8) |
| Reputation derivation | §10.5.1 | all outcome partitions; party-fault denominator excl. failed-substrate; **blame-weighted `counterpartyAdjustedCompletionRate` additionally excludes failed-counterparty + aborted-by-other** (null when that denominator is 0); **`transactionCountByCurrency` matches `observedTransactionalVolume` currencies**; null vs zero; empty-input totality; two-sided reconciliation + `perspective_flip`; reconciliation guards including divergent-job exclusion and guard (iv) exclusion of a raw one-copy input without authoritative-absence context; rating de-duplication | `conformance/fixtures/reputation/`; `conformance/fixtures/session-bundles-reputation.json`; `conformance/vectors/security/bundle-absence-evidence-v0.3.json` |
| Determinism receipt | §10.5.3 | `bundleRefs` = `reconciled` set, ascending-`contentHash` order; `resolutionContext` one entry per ref (resolvedRole; one-copy jobIds carry `absenceEvidenceRef`); re-derive byte-identical `metrics`/`bundleCount` under recorded `windowingBasis` with the recorded context; omitting basis, context, or mis-ordering is non-conforming | `conformance/` |
| Category-scoped derivation | §10.5.4 | prefix filter before §10.5.1; non-resolving `agreementRef` excluded; exact-or-`category+"."` prefix; hint accuracy | `conformance/` |
| RT-1, RT-2 (rate phase) | §10.6.1 | run-after-settle; one-record-per-direction; rating domain-sep sig; RT-1 producer-reject out-of-range/over-length; RT-2 deriver-exclude non-conforming; `dimensions` opaque | `conformance/` |
| ERC-8004 publication (optional) | §10.7 | token-owner-signed entry; bundle-anchor pointer; rate-limit | `conformance/` |

### 14.6 Universal signature scheme & canonical form (SIG-1..SIG-6, CF-1..CF-4, CD-1, SN-1..SN-4)

A cross-cutting test category that every conforming implementation runs once:

- Sign every artifact kind in §B.7 with a known key; verify with the same key against the domain-separated payload; reject if the verifier reconstructs without the separator.
- Cross-artifact replay test: take a valid signature on artifact kind A, attempt to verify it as a signature on artifact kind B with the same hash bytes; verification MUST fail.
- Unknown-artifact x-* prefix test: implementations encountering an unknown domain separator MUST reject; experimental x- separators MUST be accepted only with out-of-band agreement.
- **CF-1 (NFC).** A document carrying a non-ASCII identifier supplied in NFD form MUST hash and verify identically to the same document supplied in NFC form; a verifier MUST normalise before recomputing the canonical form.
- **CF-2/CF-3 (ClaimReference canonical form & identity).** `CCI-LEI:…` and `cci-lei:…` MUST produce identical content hashes when embedded in a signed document (scheme case-folded). Two references differing only in parameter order MUST produce identical canonical bytes; two references differing only in the presence/value of parameters MUST resolve to the same reputation key (parameters excluded from identity).
- **CF-4 (logical-address encoding).** A logical address built from a multi-colon primary claim MUST round-trip: assemble → derive native address → split the logical address back into `{sellerPrimaryClaim, listingId, listingVersion}` and percent-decode each to the exact originals. Likewise, per address kind:
  - the DACS-4 payment-evidence address `dacs4:payment:{jobId}:{railId}:{phaseIndex}` MUST round-trip a multi-colon `railId` (e.g. `evm-erc20:1:USDC`) — the encoded railId splits back to its exact original while `phaseIndex`/`resolved` remain unescaped fixed segments;
  - the DACS-2 addresses `dacs2:{jobId}:{scheme}:{identifier}:v{recipeVersion}` and `dacs2:composite:{jobId}:{evaluatedParty}` MUST round-trip a multi-colon `{identifier}` / `{evaluatedParty}` (e.g. `evm:mainnet:0x1234`) while `{scheme}`/`v{recipeVersion}` remain unescaped;
  - the DACS-5 rating address `dacs5:rating:{jobId}:{rater}` MUST round-trip a multi-colon `{rater}`.

  An address whose variable segments are left raw (unescaped) MUST be rejected as malformed.
- **CD-1 (canonical decimal).** `"1.50"` and `"1.5"` as `PriceTerm.amount` MUST produce identical agreement hashes and signatures.
- **SN-1..SN-4 (session nonce).** A presenter-chosen nonce the verifier did not issue MUST be rejected (SN-1); a native `sessionNonce` below 128 bits / not ≥32 lowercase-hex chars MUST be rejected (SN-2); a **same-session** replay of an already-consumed nonce MUST be rejected (SN-4); a nonce still unconsumed past its bounded challenge lifetime MUST be rejected (SN-4 retention); and a nonce issued for one `jobId` MUST NOT validate a presentation for another `jobId` — the cross-session case is caught by the §6.3.2 match against the jobId-issued nonce (SN-3), not SN-4.
- **SIG-5 (preserve-unknown).** A verifier built against schema vN MUST successfully verify the signature on a document produced under vN+1 that adds an unknown field, by hashing the document as received (unknown field included); a verifier that strips the unknown field before hashing (and thus rejects) FAILS this test. The concrete Listing cases are `conformance/vectors/security/listing-preserve-unknown-v0.1.json`: an unchanged signed Listing carrying one inert unknown top-level field passes, while mutation or removal of that field fails the signature. A separately signed Listing with an unknown phase kind still refuses as unsupported under §11.1.2's new-type rule.
- **SIG-6 (signature-value encoding).** Decode an unpadded Base64URL `value` whose bytes produce both `-` and `_`; exact re-encoding passes. Standard Base64 for the same bytes, padded Base64URL, whitespace, impossible lengths, and non-zero residual bits MUST fail before cryptographic verification. After canonical decoding, algorithm-specific length and signature validation still apply. The concrete cases are `conformance/vectors/security/signature-value-encoding-v0.1.json`.

### 14.7 Governance (GOV-1..GOV-3)

- **GOV-1 steward disclosure.** A registry consumer surfaces which signing key it treats as authoritative and does not present the single steward as a constituted multi-party body.
- **GOV-2 anchoring-phase disclosure.** An implementation discloses its operating phase (in-code / single-signer / multisig).
- **GOV-3 anchoring-phase verification.** A consumer reads the resolved recipe's `governance.anchoring` and evaluates each pinned recipeVersion against the phase recorded at pin time; a recipe marked `in-code` is not treated as canonically anchored.

### 14.8 Substrate-capability tests

For substrates other than Demos that claim conformance, additional capability tests apply:

- **SR-1.** Sub-identity binding test: a root key binds N sub-identities, presents under a single SR-1 signature, verifier resolves each to its claim scheme.
- **SR-2 (SR2-1..SR2-9).** Exercise the lifecycle graph (`submitted → accepted|rejected`; `accepted → included|dropped|replaced|expired`; `included → finalized|reorged`; authenticated `dropped|expired|reorged` re-entry), and reject illegal promotion. Exercise `observationDisposition: indeterminate` after intermediate and terminal states without adding a graph edge: it hash-links and preserves the last established receipt, never demotes/promotes state, and never permits resubmission. Order conflicting snapshots by binding-authenticated evidence, never `observedAt`; independently verify carrying-transaction replacements. Verify durable-admission evidence before `accepted`; require block evidence for `included`/`finalized`; bind logical/native address, content hash, transaction, writer, nonce, and finality profile in each receipt; treat `indexed` as orthogonal and never gating. Exercise reversible Vet progression on qualifying `accepted`, finalized commitment before irreversible effects, rail-final payment with asynchronous evidence catch-up/no resubmission, and completed-bundle `audit-pending` until all dependencies and the bundle are finalized/resolvable. Also run anchor-write → retrieve → content-hash round-trip and size-cap enforcement. A binding claiming authoritative absence exercises its declared finalized non-membership proof or authenticated independent quorum; unqualified `not found`, transport failure, stale response, and inconsistent state views remain `indeterminate`. Concrete lifecycle cases: `conformance/vectors/security/sr2-anchor-lifecycle-v0.1.json`.
- **SR-3.** Fetch-specification → consensus-signed commitment → anchor; body-hash verification by independent consumer. (v0.1 conformance bar is trust-property; v2 will add wire-protocol tests.)
- **SR-4.** Channel-establish → member-only-message-delivery → non-member-cannot-read; CH-1..CH-6 each as a test (CH-6: channelId unique per session — cross-session offer-replay rejected). (v0.1 trust-property; v2 wire-protocol.)
- **SR-5.** Cross-chain lock → release with bounded-time atomicity; refund path on counterparty timeout.

### 14.9 Out of scope for v0.1 conformance

The following are not part of v0.1 conformance and SHOULD NOT be tested as such:

- Cross-substrate interoperability for SR-3- or SR-4-dependent phases (deferred to v2).
- Multi-party transactions beyond bilateral plus sealed-envelope (deferred).
- Streaming / continuous-flow rails (deferred).
- Cross-major DACS pipelines (deferred). Same-major cross-minor handling of existing and newly registered artifact/phase types is required by CORE §11.1.2 / §11.2.5 and is in scope above.
- Dispute *resolution* flows (DACS-X, anticipated). Divergence *detection* — the two-sided lookup plus canonical-divergence classification and out-of-band handling of §10.4.3(d) — **is** in scope for v0.1 conformance; DACS-5 reputation handling is already pinned to §10.5.1 exclusion, while only the dispute-resolution layer is deferred.

### 14.10 Implementation conformance claims

An `ImplementationManifest` is an optional machine-readable report describing what
one implementation supports and the evidence behind its claims. Publishing a manifest
does not change transaction behaviour or make the report a trusted protocol artifact.

```
type ImplementationManifest = {
  manifestVersion: "1"
  generatedAt: string                         // RFC 3339 timestamp
  implementation: {
    name: string
    version: string
    repository: string
    commit: string                            // 40 lower-case hex
  }
  profile: {
    id: "DACS-v0.1"
    repository: string
    commit: string                            // exact specification revision
    documents: Record<"CORE" | "DACS-1" | "DACS-2" | "DACS-3" | "DACS-4" | "DACS-5", string>
  }
  roles: ("buyer" | "seller" | "orchestrator" | "verifier" | "directory-indexer")[]
  conformanceSuite: {
    repository: string
    commit: string
    manifestPath: string
    manifestSha256: string                    // 64 lower-case hex
  }
  claims: ImplementationClaim[]
  capabilities: CapabilitySupport[]
  testRuns: DeterministicTestRun[]
  liveTests: LiveTest[]
  deviations: ImplementationDeviation[]
}

type ImplementationClaim = {
  id: string
  level: "full-profile" | "module" | "role" | "capability" | "experimental"
  result: "conformant" | "conformance-tested" | "implemented" | "experimental"
  roles: ImplementationManifest["roles"]
  modules: ("CORE" | "DACS-1" | "DACS-2" | "DACS-3" | "DACS-4" | "DACS-5")[]
  capabilityRefs: string[]
  ruleRefs: string[]                           // labelled rule ids or document-scoped section refs
  evidenceRefs: string[]                       // DeterministicTestRun ids
}

type CapabilitySupport = {
  ref: string
  kind: "claim-scheme" | "verification-method" | "negotiation-pattern" |
        "payment-phase" | "payment-rail" | "delivery-type" |
        "substrate-capability" | "bundle-operation" |
        "reputation-operation" | "directory-operation"
  id: string                                   // normative token, registry id, SR id, or x-* token
  modules: ImplementationClaim["modules"]
  roles: ImplementationManifest["roles"]
  supportStatus: "implemented" | "experimental" | "unsupported"
  availability?: "live" | "operator_gated" | "closed_data" | "bilateral" |
                 "mocked" | "disabled" | "failed"
  testStatus: "not_tested" | "partial" | "passed" | "failed"
  evidenceRefs: string[]
}

type DeterministicTestRun = {
  id: string
  result: "pass" | "fail"
  caseIds: string[]                             // ids from the pinned conformance manifest
  command: string
}

type LiveTest = {
  id: string
  capabilityRefs: string[]
  result: "pass" | "fail" | "inconclusive"
  executedAt: string                           // RFC 3339 timestamp
  evidence: string
}

type ImplementationDeviation = {
  id: string
  capabilityRefs: string[]
  ruleRefs: string[]                           // labelled rule ids or document-scoped section refs
  status: "open" | "resolved"
  effect: "nonconforming" | "operational"
  description: string
}
```

Claim language is fixed:

| `level` | Permitted claim |
| --- | --- |
| `full-profile` | “DACS v0.1 conformant” |
| `module` | “DACS-N vX.Y conformant for the declared roles” |
| `role` | “DACS v0.1 ROLE conformant for the declared modules” |
| `capability` | “DACS v0.1 conformance-tested for CAPABILITY” or “implements CAPABILITY” |
| `experimental` | “experimental DACS extension x-*” |

- (IM-1) A manifest MUST pin the profile revision and conformance-suite manifest by repository, commit, path, and SHA-256 hash.
- (IM-2) Each capability MUST report support, availability, and test status on their separate axes. `availability` MAY be omitted for a non-operational library capability.
- (IM-3) A passing claim MUST name its roles, modules, capabilities, rule references, and deterministic evidence. An unqualified full-profile claim MUST cover every pinned document.
- (IM-4) `conformance-tested` requires passing deterministic runs whose case ids exist in the pinned conformance manifest. Live tests MUST NOT substitute for deterministic evidence.
- (IM-5) An open `nonconforming` deviation invalidates every `conformant` or `conformance-tested` claim referencing its affected capability. It does not invalidate an `implemented` or `experimental` claim, because those results do not assert conformance. An `operational` deviation MUST NOT be presented as a protocol failure.
- (IM-6) An experimental capability MUST use an `x-` identifier. It MUST NOT appear in a `conformant` or `conformance-tested` claim.
- (IM-7) A manifest MUST NOT override registry availability, substrate preflight, or runtime verification. Consumers MUST treat it as self-asserted reporting metadata. An unrecognized optional member MUST be preserved where integrity processing requires SIG-5 behaviour. Until a supported specification revision defines that member, it MUST NOT affect conformance evaluation or be assigned authorization, registry, substrate-preflight, runtime-verification, or transaction semantics.
- (IM-8) `manifestVersion` follows CORE §11.1.2. Additive optional fields preserve version `"1"`; changed required fields or enum semantics require a new major value.

Every `ruleRefs` entry MUST resolve in the profile revision named by `profile.commit`. A reference is either a labelled rule id such as `SIG-5`, or a document-scoped section reference such as `DACS-5-10.5.1`. The repository validator resolves both forms against the supported specification sources in its checkout. A consumer evaluating a different pinned revision MUST perform equivalent resolution against that revision; an unresolved reference invalidates the manifest.

The normative JSON shape is
[`conformance/implementation-manifest.schema.json`](../conformance/implementation-manifest.schema.json).
Repository examples and dependency-free validation live under
[`conformance/implementation-manifests/`](../conformance/implementation-manifests/).
