# DACS Security Conformance Vectors

Language-neutral conformance vectors for the **security / anti-abuse requirements**
of DACS. Each set targets one rule surface — the generated index below lists every
set with its spec citation, so this paragraph never needs editing when a set is
added. These complement the lifecycle vectors in the
parent directory: where those assert that a well-formed five-stage session
validates, these are intended to assert that the **anti-abuse rules** behave
identically across independent implementations (SB-2's EVM row is cross-run-
converged; the others await a second impl). Derived from the §12.4 threat-to-test matrix
(published in `pathos-dacs-ref`; tracked in #158).

> **Shape note (why this is a subdirectory).** Each set is *verifier-input/output
> pairs* (a case's input fields → an `expected` §7.5.1 verdict), not five-stage
> lifecycle bundles, and **each carries its own schema** (described per-set below).
> The canonical `scripts/validate_conformance_vectors.py` run globs
> `conformance/vectors/*.json` non-recursively, so files here (like `../examples/`)
> are intentionally excluded from the lifecycle shape-check — the candidate-tier
> checks (`scripts/validate_security_vectors.py`) cover them instead.

Cross-running a set against another implementation — and the candidate → golden
promotion path — is specified in [CROSS-RUN.md](CROSS-RUN.md).

<!-- BEGIN GENERATED: security-vector-index (scripts/generate_security_vector_index.py) -->

| Set | Spec surface | Vectors | Verdicts used |
| --- | --- | --- | --- |
| [`agreement-listing-v0.1.json`](agreement-listing-v0.1.json) | DACS §8.5.2 | 30 | `accept` / `indeterminate` / `reject` |
| [`ap2-handler-safety-v0.6.json`](ap2-handler-safety-v0.6.json) | DACS-4 v0.6 §9.5.6 checkout admission + AP2-3/AP2-6/AP2-7 | 30 | `error` / `fail` / `pass` |
| [`artifact-reference-shapes-v0.1.json`](artifact-reference-shapes-v0.1.json) | DACS-2 §7.5.2 AttestationRef; DACS-4 §9.3 ChainTxRef | 23 | `fail` / `pass` |
| [`atomic-work-audit-role-v0.1.json`](atomic-work-audit-role-v0.1.json) | DACS-5 §10.4.2 AWB-1..AWB-10 | 15 | `fail` / `indeterminate` / `pass` |
| [`atomic-work-authorization-v0.1.json`](atomic-work-authorization-v0.1.json) | CORE §5.2 AW-30..AW-38 | 21 | `fail` / `indeterminate` / `pass` |
| [`atomic-work-execution-recovery-v0.1.json`](atomic-work-execution-recovery-v0.1.json) | CORE §5.2 AW-39..AW-75 | 53 | `fail` / `indeterminate` / `pass` |
| [`atomic-work-identity-v0.1.json`](atomic-work-identity-v0.1.json) | CORE §5.2 AW-1..AW-29, AW-76..AW-77 | 37 | `fail` / `pass` |
| [`atomic-work-purchase-completion-v0.1.json`](atomic-work-purchase-completion-v0.1.json) | DACS-3 §8.6.1 AWP-1..AWP-21 | 30 | `fail` / `indeterminate` / `pass` |
| [`atomic-work-settlement-slot-v0.1.json`](atomic-work-settlement-slot-v0.1.json) | DACS-4 §9.5.10 and §9.7.3 AWS-1..AWS-29 | 49 | `error` / `fail` / `indeterminate` / `pass` |
| [`bundle-absence-evidence-v0.3.json`](bundle-absence-evidence-v0.3.json) | CORE §5 SR-2; DACS-5 §10.4.3 / §10.5.1 guard (iv) | 4 | `fail` / `indeterminate` / `pass` |
| [`bundle-binding-v0.1.json`](bundle-binding-v0.1.json) | DACS-5 §10.4.2 BB-1..BB-8 + §10.4.1 faultedParty | 9 | `fail` / `indeterminate` / `pass` |
| [`bundle-settlement-evidence-bijection-v0.4.json`](bundle-settlement-evidence-bijection-v0.4.json) | DACS-5 §10.4.3 SEB-1..SEB-6 | 30 | `fail` / `indeterminate` / `pass` |
| [`cci-xm-rail-chain-applicability-v0.5.json`](cci-xm-rail-chain-applicability-v0.5.json) | DACS-1 §6.3.1 EVM cci-xm settlement-chain profile; DACS-4 §9.4.3 RD-5 and §9.5.1 PB-2 | 20 | `error` / `indeterminate` / `pass` |
| [`channel-message-replay-v0.1.json`](channel-message-replay-v0.1.json) | DACS-3 §8.3.3 + CH-6 (channel-message replay / channelId reuse) | 15 | `error` / `fail` / `indeterminate` / `pass` |
| [`claim-requirement-qualification-v0.3.json`](claim-requirement-qualification-v0.3.json) | DACS-2 §7.7.1 CRQ-1..CRQ-4 | 36 | `error` / `fail` / `indeterminate` / `pass` |
| [`commitment-anchor-authority-v0.3.json`](commitment-anchor-authority-v0.3.json) | DACS-3 §8.6 CA-6/CA-7 | 4 | `fail` / `pass` |
| [`commitment-record-compatibility-v0.1.json`](commitment-record-compatibility-v0.1.json) | DACS-3 §8.6 CA-6/CA-8/CA-9 and §8.11; CORE §11.1.2 | 10 | `fail` / `pass` |
| [`domain-claim-gcr-v0.4.json`](domain-claim-gcr-v0.4.json) | DACS-1 §6.3.1 DCR-1..DCR-8; DACS-2 §7.3.10 DGCR-1..DGCR-6 | 49 | `error` / `fail` / `indeterminate` / `pass` |
| [`fab-bundle-extended-pointer-v0.3.json`](fab-bundle-extended-pointer-v0.3.json) | DACS-5 §10.4.2 extended-pointer FaultAttestationBundle path + §10.4.1 triple-identity (E7) | 4 | `fail` / `pass` |
| [`fault-bundle-perspective-pair-v0.3.json`](fault-bundle-perspective-pair-v0.3.json) | DACS-5 §10.4.3 FaultAttestationBundle-pair rule + §10.4.1 permissible set | 3 | `fail` / `pass` |
| [`feeschedule-reconciliation-v0.1.json`](feeschedule-reconciliation-v0.1.json) | DACS-3 §8.5.3 (FS-1..FS-5); DACS-4 §9.7.2 (FR-1..FR-4) | 17 | `diverged` / `fail` / `indeterminate` / `pass` / `reconciles` |
| [`legacy-orchestrator-reputation-parity-v0.3.json`](legacy-orchestrator-reputation-parity-v0.3.json) | DACS-5 §10.5.1 orchestrator-fault neutral exclusion | 6 | `pass` |
| [`legacy-three-party-fault-reconciliation-v0.3.json`](legacy-three-party-fault-reconciliation-v0.3.json) | DACS-5 §10.4.3 legacy implied-fault-set reconciliation | 5 | `fail` / `pass` |
| [`listing-preserve-unknown-v0.1.json`](listing-preserve-unknown-v0.1.json) | CORE §B.7 SIG-3/SIG-5; §11.1.2 additivity and new-type refusal; DACS-1 §6.3.4; DACS-4 §9.6.3 DPA-1 | 4 | `fail` / `pass` |
| [`listing-rail-registry-resolution-v0.4.json`](listing-rail-registry-resolution-v0.4.json) | DACS-1 §6.3.4 LRR-1..LRR-6; DACS-4 §9.4.3 | 29 | `fail` / `indeterminate` / `pass` |
| [`metered-pricing-v0.3.json`](metered-pricing-v0.3.json) | DACS-3 §8.5.2 MTR-1..MTR-5; DACS-4 §9.4 PricingSpec | 22 | `accept` / `reject` |
| [`mixed-version-reconciliation-v0.3.json`](mixed-version-reconciliation-v0.3.json) | DACS-5 §10.4.3 mixed-version rule + §10.5.1 authoritative selection | 8 | `fail` / `pass` |
| [`outsider-binding-flooding-v0.3.json`](outsider-binding-flooding-v0.3.json) | DACS-5 §10.4.2 BB-6 authorized-candidate multiplicity + BB-7 side-level exhaustion (round-6 blocker #3) | 11 | `indeterminate` / `pass` |
| [`payee-destination-binding-v0.1.json`](payee-destination-binding-v0.1.json) | DACS-3 §8.5/§8.6 PayeeBoundAgreementDocument compatibility; DACS-4 §9.5.1 PB-1..PB-3 | 28 | `error` / `fail` / `indeterminate` / `pass` |
| [`payload-attestation-binding-v0.1.json`](payload-attestation-binding-v0.1.json) | DACS-4 §9.6.3 DPA-1..DPA-9; §9.7; CORE §B.7; Demos §A.3 | 22 | `fail` / `indeterminate` / `pass` |
| [`phase-kind-divergence-v0.3.json`](phase-kind-divergence-v0.3.json) | DACS-5 §10.4.3 / §10.5.1 guard (ii) shared-index phase-kind divergence | 1 | `reject` |
| [`private-deliverables-v0.1.json`](private-deliverables-v0.1.json) | DACS-4 §9.3 / §9.6.1 / §9.6.2 (DV-1..DV-6) | 16 | `ACL-dropped` / `clean-negative` / `fail` / `indeterminate` / `pass` / `readable` |
| [`rail-availability-selection-v0.1.json`](rail-availability-selection-v0.1.json) | DACS-4 §9.4.4 (RAV-R1/R2/R3/R5); DACS-1 §6.3.4 (LRR-6) | 28 | `error` / `fail` / `indeterminate` / `pass` |
| [`receipt-rederivation-v0.3.json`](receipt-rederivation-v0.3.json) | DACS-5 §10.5 ReplayableReputationDerivation replay (authenticated per-copy validation) + §10.5.3 (1)-(3); round-6 blockers #1/#2 | 16 | `fail` / `pass` |
| [`recipe-parser-applicability-v0.5.json`](recipe-parser-applicability-v0.5.json) | DACS-2 §7.4.1/§7.6 PRA-1..PRA-5 parser applicability | 22 | `error` / `pass` |
| [`reputation-settlement-reference-divergence-v0.4.json`](reputation-settlement-reference-divergence-v0.4.json) | DACS-5 v0.4 §10.5.1 settlement-verified reference-multiset divergence limb | 6 | `fail` / `pass` |
| [`reputation-settlement-semantics-v0.4.json`](reputation-settlement-semantics-v0.4.json) | DACS-5 v0.4 §10.5.1 RSV-1..RSV-4; settlement-verified types; consumes existing DACS-4 rules | 17 | `accept` / `indeterminate` / `reject` |
| [`revocation-binding-v0.3.json`](revocation-binding-v0.3.json) | DACS-1 §6.3.4 RB-1..RB-6 revocation-marker discovery and fail-closed resolution | 14 | `fail` / `indeterminate` / `pass` |
| [`sb2-settlement-uniqueness-v0.1.json`](sb2-settlement-uniqueness-v0.1.json) | DACS §9.5.8 (SB-2); SB-1 key | 20 | `error` / `fail` / `indeterminate` / `pass` |
| [`sb3-eip3009-nonce-v0.1.json`](sb3-eip3009-nonce-v0.1.json) | DACS-4 §9.5.8 (SB-3 EIP-3009 nonce binding) | 14 | `error` / `fail` / `pass` |
| [`sealed-envelope-deadline-v0.1.json`](sealed-envelope-deadline-v0.1.json) | DACS-3 §8.4.3 (SE-2/SE-3/SE-4 + CH-3 + commitment binding) | 15 | `error` / `fail` / `indeterminate` / `pass` |
| [`sealed-envelope-multicommit-v0.1.json`](sealed-envelope-multicommit-v0.1.json) | DACS-3 §8.4.3 (SE-9 same-bidder commit authority) | 4 | `fail` / `pass` |
| [`settlement-event-identity-v0.6.json`](settlement-event-identity-v0.6.json) | DACS-4 §9.5.8 SB-1/SB-2 signed event identity and legacy replay | 28 | `error` / `fail` / `indeterminate` / `pass` |
| [`settlement-finalization-propagation-v0.3.json`](settlement-finalization-propagation-v0.3.json) | DACS-4 §9.7 FP-1..FP-4; DACS-5 §10.4.1 and §10.4.3 | 6 | `fail` / `pass` |
| [`signature-value-encoding-v0.1.json`](signature-value-encoding-v0.1.json) | CORE §B.7 SIG-6 | 10 | `accept` / `reject` |
| [`sr2-anchor-lifecycle-v0.1.json`](sr2-anchor-lifecycle-v0.1.json) | CORE §5.1 SR2-1..SR2-9; DACS-1 §6.3.4 LP-1; DACS-2 §7.8 VPC-3/VPC-5; DACS-3 §8.6 CA-1/CA-8; DACS-4 §9.5.1 PC-7 and §9.9 PIPE-6; DACS-5 §10.3.1 ST-11 | 25 | `fail` / `pass` |
| [`unresolved-vs-absent-v0.3.json`](unresolved-vs-absent-v0.3.json) | DACS-5 §10.4.3(b) + §10.4.2 BB-8 + CORE §5 absence-evidence policy | 4 | `indeterminate` / `pass` |
| [`verifyresult-acceptance-v0.1.json`](verifyresult-acceptance-v0.1.json) | DACS-2 §7.12 | 13 | `error` / `fail` / `indeterminate` / `pass` |
| [`vp-replay-v0.1.json`](vp-replay-v0.1.json) | DACS §7.3.2 | 13 | `error` / `fail` / `indeterminate` / `pass` |
| [`x402-receipt-hash-v0.1.json`](x402-receipt-hash-v0.1.json) | DACS-4 §9.5.7 X402-1..X402-4 canonical x402 settlement-response hashing | 12 | `error` / `fail` / `pass` |

_This table is generated from the set files — do not edit by hand._
_Regenerate with `python3 scripts/generate_security_vector_index.py --write`._

<!-- END GENERATED: security-vector-index -->

## Included sets

### `ap2-handler-safety-v0.6.json` — §9.5.6 checkout admission + AP2-3/AP2-6/AP2-7

30 candidate vectors execute the DACS-owned AP2 handler boundaries introduced
in DACS-4 v0.6. They pin provider idempotency-key bytes, NFC handling,
job/phase separation, malformed phase refusal, exact compact-JWS transaction-ID
derivation, CheckoutMandate `_sd_alg` selection and SHA-256 fallback, signature-
byte sensitivity, and refusal of malformed or unsupported algorithms. The
composed admission cases require separate verified CheckoutMandate and
PaymentMandate artifacts, enforce the DACS signature profile, and reject a
transaction-ID mismatch before AP2-7 reservation or provider submission.

The same set executes first-use binding, exact-tuple retry/resume, cross-job and
cross-phase replay refusal, and fail-closed conflicting-store handling. An exact
retry never submits or counts a second payment. Provider capability, mandate
cryptographic verification, and checkout signature generation remain modeled
inputs: the cases do not claim to introspect a live provider credential, replace
AP2 signature verification, or prove a signer's nonce-generation implementation.
Regenerate, verify, and execute with:

```sh
python3 scripts/generate_ap2_handler_safety_vectors.py --write
python3 scripts/generate_ap2_handler_safety_vectors.py --check
python3 -m unittest tests.test_ap2_handler_safety_vectors -v
```

### `payload-attestation-binding-v0.1.json` — §9.6.3 DPA-1..DPA-9

22 candidate vectors make the attested-payload success gate executable. The two
positive cases carry genuine deterministic Ed25519 signatures over the distinct
`dacs-payload-attestation:v1:` and `dacs-evidence:v1:` domains: one composes a
finalized DAHR `web2Request` commitment, and one proves that `self-signed`
remains available only as an explicitly selected minimal-trust method with a
real payload-bound proof.

Negative cases reject a listing with no method before payment, a
seller/orchestrator evidence signature used as a substitute, VerifyResult
coercion, an unsupported discriminator, cross-domain signature replay,
job/agreement/DeliverableSpec/method/payload mismatch, a bad native-evidence
hash, missing or unauthenticated DAHR transaction evidence, request/response
substitution, a non-pass payload decision, a stale record reference, and
cross-session replay. An otherwise well-formed but unavailable method proof
stays `indeterminate`.

Every vector carries the signed listing context, committed agreement tuple,
exact UTF-8 payload, method-native evidence, `PayloadAttestationRecord`,
record reference, and signed `SettlementEvidence`. Public test seeds are
included for independent reproduction. Regenerate or verify byte determinism:

```sh
python3 scripts/generate_payload_attestation_vectors.py --write
python3 scripts/generate_payload_attestation_vectors.py --check
python3 -m unittest tests.test_payload_attestation_vectors -v
```

### `cci-xm-rail-chain-applicability-v0.5.json` — §6.3.1 EVM profile + §9.4.3 RD-5 / §9.5.1 PB-2

20 candidate vectors make the PB-2 EVM chain-applicability predicate
executable. Exact positive-decimal chain IDs map one-to-one to CAIP-2
`eip155:<chainId>` and cover Ethereum mainnet, Base mainnet, Ethereum Sepolia,
and Base Sepolia. A different numeric chain, a leading-zero or zero spelling,
and the human labels `mainnet`, `testnet`, `sepolia`, and `base` do not
establish tier 2 and leave the signed tier-3 assertion available.

The address component must be non-empty but is otherwise opaque for chain
selection; optional ClaimReference parameters do not change the derived chain.
An empty or parameter-only address and a non-lowercase `evm` family spelling do
not establish tier 2.

The set also pins three fail-closed boundaries: an exact chain match becomes
tier-2-applicable before SR-1 resolution, so an unavailable or erroneous
linkage cannot downgrade to tier 3; conflicting EVM asset/network chain IDs
fail RD-5; and an x402 resource rail that exposes no single EIP-155 chain in
its pinned definition cannot gain tier 2 retroactively from a later receipt.
Run the dependency-free executable predicate with
`python3 -m unittest tests.test_cci_xm_rail_chain_applicability_vectors -v`.

### `metered-pricing-v0.3.json` — §8.5.2 MTR-1..MTR-5

22 candidate vectors make the metered-pricing commit gate executable. They pin
currency and unit agreement, the canonical unsigned-integer quantity grammar,
ceil derivation for fractional raw usage, exact decimal multiplication and
`minTotal` flooring, and fail-closed handling of an unknown pricing kind.

The valid zero-quantity case carries a positive `minTotal`: MTR-4 permits a
zero quantity, while the underlying `PriceTerm` contract still requires a
positive final amount. Invalid cases cover every forbidden quantity spelling
(leading zero, sign, decimal point, and exponent), missing or mismatched units,
currency disagreement, non-canonical or incorrect totals, and an unexpected
metered quantity on a non-metered price.

Each entry names an executable `surface`: `quantity-derivation` maps a decimal
raw measurement to the ceiled canonical quantity, while
`agreement-validation` carries the pinned `pricing`, signed `terms`, expected
verdict, and exact reason or computed amount. Run the dependency-free reference
assertions with `python3 -m unittest tests.test_metered_pricing_vectors -v`.

### `bundle-settlement-evidence-bijection-v0.4.json` — §10.4.3 SEB-1..SEB-6

30 candidate vectors bind an `EvidenceBoundFaultAttestationBundle` raw top-level
`settlementEvidence[]` array to the
phase keys derived from a signature-verified DACS-1 listing pipeline and the
domain-verified EBFAB `phaseSummary`; no caller-supplied expected set is trusted.
They cover exact
pointerless and pointer-bearing positives; missing, equal-count duplicate,
coverage-complete duplicate, distinct-reference alias, extra, wrong-phase, non-evidence-phase, pointer
reuse/conflict/dangling, and structural-before-uncertainty negatives; plus all
four ST-8 top-level representations. Resolved ST-8 lists only the success
successor; expired ST-8 lists the standing interim failure; known-successor
suppression rejects. Repeated kinds remain distinct by index, a failed invocation
is included, an invocation aborted before returning a result is excluded, and
`accepted` evidence fails both the completed and failed/aborted lifecycle gates.
Optional per-phase pointers remain optional.

Each input selects a named execution authority carrying a real Ed25519-signed
listing and EBFAB, bound by the EBFAB `listingRef`. The evaluator cryptographically
verifies both canonical hashes and domains before deriving `P`; corrupted listing
or bundle signatures, a listing signer not authorized by the declared publisher,
and an unfinalized or unresolvable completed EBFAB reject. Inputs keep raw
full-canonical reference keys, independently resolved phase keys, present optional
pointers, SR-2 lifecycle overrides, ST-8 record classes/supersession edges, and
unrelated authority disposition separate. Stable
outputs use `verified`, `rejected`, or `indeterminate` plus one normative
`reasonCode`; `reasonPrecedence` fixes cross-run code selection. The evaluator
derives `P` from those authenticated artifacts and tests the exact SR-2 vocabulary:
completed evidence is `finalized` and independently resolvable; failed/aborted
evidence is `included` or `finalized` without importing that stricter ST-11
resolution requirement.

The deterministic signed compatibility fixture
[`evidence-bound-fault-bundle-compatibility-v0.4.json`](../../fixtures/evidence-bound-fault-bundle-compatibility-v0.4.json)
verifies real Ed25519 signatures under the EBFAB domain, discriminator exclusivity,
unknown/stripped-discriminator refusal, cross-type replay failure, rejection of a
correctly signed but SEB-invalid EBFAB, and non-divergent EBFAB/EBFAB, EBFAB/FAB,
and EBFAB/legacy authority. The authoritative EBFAB hash and validated phase set
are pinned even though the otherwise-valid older type carries no SEB claim. A
second independently SEB-valid EBFAB with a different canonical record for the
same phase key diverges, and FAB/EBFAB extended-pointer type swaps reject under
their distinct signed pointer domains.

The candidate set has independent producer/consumer evidence: DACS Forge
produced the signed fixture at
[`4218eb93`](https://github.com/mj-deving/dacs-forge/commit/4218eb93c6c20c3f6cc7d2d4f485e454c3858de8),
and `dacs-verify` consumed the serialized artifact and these vector bytes at
[`03a03667`](https://github.com/mj-deving/dacs-verify/commit/03a036676fb624ab5374fd5f971267a11b2d2905).
This is not yet formal run-file convergence under `CROSS-RUN.md`; a Demos
cross-run and golden promotion remain pending.

### `bundle-absence-evidence-v0.3.json` — CORE §5 SR-2 + DACS-5 §10.4.3 / §10.5.1 guard (iv)

4 candidate vectors for the two-address bundle-read gate introduced by #251.
They keep a single unqualified `not found`, a transport error, and inconsistent
finalized-state views `indeterminate`; allow one-sided classification only when
the substrate binding's declared absence policy is satisfied; and restore the
normal divergent-copy exclusion when an independent view returns the hidden
counterparty copy.

The included `2-of-3` read is an example policy chosen by the fixture, not a DACS
quorum requirement. CORE permits a finalized non-membership proof or another
binding-defined authenticated independent quorum, provided the binding declares
finality, authentication, independence/threshold, freshness, and state-
consistency rules. The current Demos mapping declares no such policy, so its
ordinary `not found` path exercises the indeterminate case.

#### Vector schema

Each entry in `vectors[]`:

| field | meaning |
|-------|---------|
| `name` | stable case id |
| `expected` | §7.5.1 verdict: `pass` \| `fail` \| `indeterminate` |
| `binding.absenceEvidencePolicy` | binding-defined policy, or `null` when none exists |
| `reads` / `variants` | positive content, absence observations, or failure/state-skew inputs |
| `want.readDispositions` | CORE SR-2 result per buyer/seller address where applicable |
| `want.lookupDisposition` | DACS-5 consumer result: `one-sided`, `divergent`, or `indeterminate` |
| `want.reputationEffect` | `include` only after authoritative absence; otherwise `exclude` |

This is a candidate set. Independent cross-run convergence and golden promotion
remain pending.

### `phase-kind-divergence-v0.3.json` — §10.4.3 / §10.5.1 guard (ii)

One candidate comparator case isolates the ruling's exact fork: the two bundle
copies have the same `jobId`, bundle outcome, phase-index set, per-entry
outcome, and absent `errorClass`, but the shared index names different phase
kinds. The expected consumer verdict is `divergent`; a DACS-5 reputation
deriver excludes the jobId from every metric and does not select either copy.

### `reputation-settlement-reference-divergence-v0.4.json` — DACS-5 v0.4 §10.5.1 settlement-verified divergence limb

Six candidate vectors pin the cross-copy comparison used only by the new
settlement-verified derivation types before RSV. The
comparison is a multiset of full canonical `AttestationRef` values: added,
removed, duplicated, or substituted references make the two copies divergent,
as does the same content hash under a different anchor. A pure array reorder
remains unified. `expected` is the comparison check (`pass`/`fail`);
`want.lookupDisposition` carries the protocol result (`unified`/`divergent`).

### `reputation-settlement-semantics-v0.4.json` — DACS-5 v0.4 §10.5.1 RSV-1..RSV-4

17 candidate vectors for the DACS-4/DACS-5 composition edge under the
structurally distinct settlement-verified derivation types: the selected
authoritative bundle's presented SettlementEvidence must pass independent
semantic authority before the job enters reputation, after two present copies
have agreed on the exact reference multiset. The positive arm admits
one verified completed job and counts the Agreement price once. One-field
adversarial arms reject amount, payer, payee/destination, session, phase, rail,
and finality contradictions. Transaction rejection and authority-indeterminate
arms both exclude the job without fault. A semantically invalid `failed-perm`
bundle pins the symmetric denominator effect.

Most inputs hold the presented reference multiset at one. Two-reference arms
prove that one invalid member rejects the entire multiset and that two valid
payments count the Agreement price once. Empty, delivery-only, failed-payment,
and out-of-set `pay-*` arms pin eligible non-volume output, including an empty
`transactionCountByCurrency`. §10.4.3 evidence completeness remains separate.
`input` and `want` are
neutral post-reconciliation projections, not new wire artifacts.
Cryptographic/reference validation and the independent
Agreement/session/phase/rail/transaction fixtures precede this projection.

Each vector carries an `expected` semantic disposition (`accept`, `reject`, or
`indeterminate`) and a stable `want` projection covering admission, completion
numerator, both denominators, volume, and the non-attributive disposition.
This is a candidate set. Independent semantic cross-run and golden promotion
remain pending. SB-1 through SB-3 are exercised by their dedicated
`sb2-settlement-uniqueness-v0.1.json` and `sb3-eip3009-nonce-v0.1.json` sets;
this family does not duplicate their multi-job and rail-specific schemas.

### `revocation-binding-v0.3.json` — §6.3.4 RB-1..RB-6

14 candidate scenarios for resolving and validating a listing revocation marker
without knowing its StorageProgram name. The two positive marker fixtures use
real Ed25519 signatures over `"dacs-revocation:v1:" || markerContentHash` and
pin both opaque-name and convention-name native-address derivations. Consumers
receive only the published `RevocationBinding`; producer write inputs remain
fixture provenance and are not resolution inputs.

Coverage includes logical-address derivation, marker content-hash and signature
checks, the exact listing-tuple match, the retained `status: "revoked"`
condition, unreachable anchors, stale or hash-inconsistent discovery state, and
the current-model successful `absent` path. The expected top-level verdict is
the new-session admission result: a verified revocation is `fail`, a completed
active/no-binding check is `pass`, and any incomplete or inconsistent check is
`indeterminate`.

Two multi-surface cases pin RB-6 precedence: a verified marker wins over an
active mirror, while an indeterminate revoked record prevents another active
mirror from manufacturing a clean absence result.

Each entry in `vectors[]` carries `surface`, `markerRead`, optional binding or
signature overrides, and `want` with the exact `RevocationCheck`, session
effect, and failing step. The common `fixtures` block holds the listing context,
signed markers, bindings, and producer-only Demos write inputs. Cross-running
against the offered producer and reader fixtures remains pending.

### `x402-receipt-hash-v0.1.json` — §9.5.7 X402-1..X402-4

12 candidate vectors pin the existing `paymentReceiptHash` to SHA-256 over the
RFC 8785 JCS form of the complete decoded successful x402 `SettlementResponse`
after recursively NFC-normalising every JSON string value under CORE CF-1. They
cover v1 `X-PAYMENT-RESPONSE` and v2 `PAYMENT-RESPONSE`, prove that property
order, whitespace, and decomposed-versus-precomposed Unicode do not change the
hash, and require extension members to remain in the canonical object.

Negative cases reject an extension mutation, the live #246 placeholder
`sha256(settlementTxHash)`, a version/header mismatch, invalid base64, a
non-success response, a transaction mismatch, and a v2 CAIP-2 network/chainId
mismatch. The fixtures use the official x402 v1/v2 response shapes at
`x402-foundation/x402@22a7677` but define DACS canonicalization rather than
treating any SDK's JSON serializer as authoritative.

#### Vector schema

Each entry carries `protocolVersion`, the received `responseHeader`, optional
`evidence`, and `want`. Positive cases pin the JCS string and receipt hash;
negative cases pin the rejection reason. This is a candidate set. Independent
implementation cross-run and golden promotion remain pending.

### `listing-preserve-unknown-v0.1.json` — CORE §B.7 SIG-3/SIG-5 + §11.1.2 + DPA-1

4 candidate vectors pin forward-readable Listing verification without making
action discriminants fail open. A complete Listing carries one inert unknown
top-level field and a real Ed25519 signature over
`"dacs-listing:v1:" || listing_hash`:

- the unchanged document passes even when the reader does not recognise the
  field's meaning;
- mutating or removing the field changes the recomputed hash and invalidates
  the signature; and
- a separately signed Listing with an unknown phase kind passes its signature
  check but refuses as unsupported under §11.1.2's new-type rule.

The fixtures also carry a DPA-1-compatible, locally supported `self-signed`
verification method, a valid per-claim IdentityBundle presentation, a raw public
key, byte-exact artifact hashes, and the hash produced by an erroneous known-key
projection. The declared reader capabilities let a runner execute signature,
phase-kind, and DPA-1 eligibility before comparing the overall Listing
disposition. This distinguishes a closed top-level allowlist from required-field
validation without importing a language-specific Listing schema.

#### Vector schema

| field | meaning |
|-------|---------|
| `fixture` | complete signed Listing selected from the top-level `fixtures` map |
| `transform` | no change, one unknown-field mutation, or removal before verification |
| `expected` | verifier verdict: `pass` or `fail` |
| `want.computedArtifactHash` | `sha256(JCS(listing-with-signature-omitted))` after the transform |
| `want.signature` | expected Ed25519 result before semantic Listing validation |
| `want.listingDisposition` | accept, reject, or refuse as an unsupported new type |

Run the dependency-free reference assertions with
`python3 -m unittest tests.test_listing_preserve_unknown_vectors -v`.

### `signature-value-encoding-v0.1.json` — CORE §B.7 SIG-6

10 candidate vectors pin the textual wire encoding independently of signature
generation. The byte fixture is a real 64-byte Ed25519 signature from the
minimum lifecycle set; its canonical spelling contains both `-` and `_`,
so an implementation cannot accidentally pass with an alphabet-neutral value.

The conforming path accepts only exact unpadded Base64URL. It rejects the same
bytes in padded standard Base64, padded Base64URL, whitespace-bearing form,
impossible-length form, and a spelling with non-zero residual bits. One case
then passes the wire decoder but fails the separate Ed25519 length check.
Legacy standard Base64 and lowercase hex convert only when the importer receives
an explicit out-of-band source encoding; an undeclared legacy value rejects.

Run the dependency-free assertions with
`python3 -m unittest tests.test_signature_value_encoding_vectors -v`.

### `sb3-eip3009-nonce-v0.1.json` — §9.5.8 SB-3 (byte-exact x402 EIP-3009 binding)

14 candidate vectors pin the EIP-3009 `bytes32 nonce` that binds a `pay-x402`
authorization to `(jobId, phaseIndex)`. The positive vectors reproduce the live
Base Sepolia value reported in #241 and prove job/phase separation plus NFC
normalization.

Negative vectors distinguish a well-formed mismatch — `fail` with no SB-3
fallback — from malformed nonce/phase input (`error`). Retry vectors pin
the no-double-charge rule: a previously used authorization resumes only when
chain evidence proves the same transfer already settled; otherwise used or
cancelled state fails closed and never causes a fresh nonce. One valid-ULID case
exercises the full input shape; the live, Unicode, mismatch, malformed, and retry
cases are explicitly marked `derivation-only`, so their verdict does not imply
full artifact-schema acceptance.

#### Vector schema

Each entry carries `op` (`derive`, `verify-binding`, or `retry`), `jobId`, and
`phaseIndex`. Verification cases add `presentedNonce`; retry cases add
`priorAuthorization`. Every case whose valid raw inputs reach derivation carries
`expectedNonce`; malformed inputs rejected before derivation deliberately do
not. `validationScope` distinguishes `derivation-only` from `full-input`.
`expected` is the §7.5.1 verdict, while `want` pins the derived nonce/binding
branch or retry action. Textual nonce fixtures use the canonical lower-case
`0x` + 64-hex form.

The set-level `hash` is sha256 over the compact JSON `vectors` array. The generic
security-vector validator checks that envelope, and the focused dependency-free
test recomputes every pinned nonce, the NFC equivalence, malformed-input refusal,
binding comparisons, and retry reuse:

`python3 -m unittest tests.test_sb3_eip3009_nonce_vectors -v`

Candidate set; independent implementation cross-run pending.

### `settlement-event-identity-v0.6.json` — §9.5.8 SB-1/SB-2 signed projection

Twenty-eight genuinely signed `SettlementEvidence` vectors exercise the DACS-4 v0.6
event-identity boundary before SB-2 consumes a key. Current EVM, Solana, and
x402 evidence carries its log/instruction coordinate in the signed transaction
reference; authenticated ledger data must select the same asset, payer, payee,
and amount. The complete PC-2 address tuple must independently match the signed
job, the authenticated agreement/phase rail (after CF-4 encoding), and the
authenticated pipeline phase index. Legacy envelope-only evidence is projected
only when exactly one ledger event matches. Multiple matches or unavailable
ledger data remain `indeterminate`, and an unsigned caller/indexer coordinate is
ignored.

The set includes batched transfers with distinct keys, cross-job reuse, missing
and malformed coordinates, a signed-index/ledger mismatch, legacy unambiguous
and ambiguous replay, discriminator stripping, cross-type signature replay,
three independently signed full-address mismatch negatives, and a CF-4 rail
segment positive.
Regenerate and execute it with:

```bash
python3 scripts/generate_settlement_event_identity_vectors.py --check
python3 -m unittest tests.test_settlement_event_identity_vectors -v
```

### `sb2-settlement-uniqueness-v0.1.json` — §9.5.8 SB-2 (settlement-tx uniqueness)

20 vectors for the cross-session / cross-phase double-count defence: a single
on-chain settlement MUST be counted **at most once** per `(jobId, phaseIndex)`,
keyed on the canonical `settlement-tx-id` pinned in **SB-1** (#161, commit
`072dc33`):

- **evm / x402:** `evm:{chainId}:{txHash}:{logIndex}`
- **solana:** `solana:{cluster}:{signature}:{instructionIndex}`

with SB-1's canonicalisation enforced: `chainId`/`logIndex`/`instructionIndex`
decimal with no leading zeros; `txHash` lower-case hex with no `0x` (so a `0x` or
upper-case re-spelling **collapses to one key** and cannot dodge the consumed
set); `signature` base58 decoding to **exactly 64 bytes**; and a malformed ref
(wrong-length / odd hex / non-64-byte base58 sig / missing coordinates) →
`error`, **never minting a distinct key**.

This set is built off the SN-4 single-use template, scope-inverted to settlement
(cX3po, #159 / #161). It is the `pathos-dacs-ref` independent implementation of
the §9.5.8 row; `mj-deving/dacs-verify` carries the second. On EVM the two impls
were cross-run case-for-case and agreed on **6/6** decisions (#159,
`issuecomment-4797534308`).

#### Vector schema

This earlier set starts at the already-projected `settlementRef` boundary and
remains the consumer-ledger/key-canonicalisation suite. The v0.6 set above is
the signed-evidence projection prerequisite that feeds it.

Each entry in `vectors[]`:

| field      | meaning |
|------------|---------|
| `name`     | stable case id |
| `decision` | expected §7.5.1 4-value verdict: `pass` \| `fail` \| `indeterminate` \| `error` (never collapsed) |
| `effect`   | settlement-counting effect: `count` \| `already-counted` \| `reject` \| `no-decision` \| `verifier-error` |
| `consumed` | prior consumed-set state, mapping canonical `settlement-tx-id` → the `{jobId, phaseIndex}` that already counted it (`{}` = empty ledger; `null` = ledger unreadable) |
| `record`   | the settlement record under test (`settlementRef`, `jobId`, `phaseIndex`) |
| `note`     | human-readable rationale |

The `decision`/`effect` split is deliberate: an idempotent re-presentation is a
`pass` whose `effect` is `already-counted`, so a consumer can never read
idempotent success as licence to count the settlement again.

#### Deterministic Solana fixture (cross-impl convergence)

So the Solana row converges byte-identically across impls, the valid Solana
signature used here is deterministic — base58 of 64 bytes each `0x05`:

```
6pc4LiB8KHAPvbUbkozrTcPL5zXspYBdATv5raNDyVbhiKjrKokLb9o111kxTD5KkPVd7UBSCcFcnWFkrJ82Hu6
```

(87 base58 chars decoding to exactly 64 bytes). Any conforming implementation
keying on the SB-1 form and reusing this signature should derive the same Solana
key; Solana cross-run convergence between impls remains pending (only the EVM row
has been cross-run to date — see Status).

#### Running

The vectors are language-neutral data: feed each `record` + `consumed` to your
SB-2 verifier and assert `(decision, effect)`. The reference run lives in
`pathos-dacs-ref`:

```
npx tsx conformance/security-vectors/sb2-settlement-uniqueness/run.mts
# → 20/20 vectors pass
```

### `commitment-anchor-authority-v0.3.json` — §8.6 CA-6/CA-7

Four vectors distinguish agreement authority from physical SR-2 ownership. Buyer- and
seller-deployed commitment anchors produce the same accepted result when the orchestrator
signature, party-signed agreement, and `agreementHash` match. A physical owner cannot replace
the orchestrator signer or rescue a mismatched agreement hash. The pinned agreement reuses the
signed legacy fixture from `payee-destination-binding-v0.1`; the commitment signature uses a
deterministic test-only Ed25519 key.

The decision inputs retain `deployer`, `owner`, and `nativeAddress` so implementations can prove
those values do not enter authority or agreement-binding decisions. They remain useful
operational metadata for substrate retrieval and audit.

### `payee-destination-binding-v0.1.json` — §8.5/§8.6 artifact compatibility + §9.5.1 PB-1..PB-3

28 candidate vectors for the §8.5/§8.6 agreement-artifact gate and the §9.5.1
payee-destination gate. They model both the pre-Settle artifact decision and the
pre-submission decision an orchestrator makes before sending money: the artifact
is accepted/refused under the selected reader and commitment phase, the
destination is bound by the agreement / applicable payout binding tier, the
payment is refused before submit, the session pauses as `indeterminate` when an
applicable binding cannot be resolved, or a resolver/input `error` surfaces
without downgrade.

Coverage:

- **Agreement-artifact compatibility** — legacy readers accept
  `AgreementDocument` and structurally refuse `PayeeBoundAgreementDocument`;
  current readers accept both while applying PB only to the payee-bound type;
  legacy `AgreementDocument` artifacts carrying `terms.payoutBindings` reject;
  both/neither version discriminators reject; cross-domain signatures reject.
- **CA-5 phase/artifact match** — `commit-agreement` rejects payee-bound artifacts,
  and `commit-payee-bound-agreement` rejects legacy artifacts.
- **PB-1 agreement binding and coverage** — agreement-carried `payeeAddress`
  matches the phase destination; a mismatch aborts before payment; missing,
  duplicate, wrong-rail, and extra payout-binding entries fail the artifact gate
  as `permanent`.
- **PB-2 payout binding tiers** — a resolved tier-2 binding cannot be downgraded to
  a different phase destination; a matching controlled linked claim binds at tier
  2; `pay-dem` intrinsic addressing binds at tier 1; an applicable-but-unresolvable
  tier-2 binding pauses instead of falling through to tier 3; a resolver `error`
  remains `error`.
- **PB-3 fallback separation** — SB-3 post-field fallback is not imported as a
  payee-destination fallback, including the x402 absent-or-unverifiable jobId
  binding posture.
- **Repeated pay phases** — repeated phases are bound independently by
  `(railId, phaseIndex)`.

Artifact gate failures are ordered for exact-vector reproducibility:
discriminator, reader support, legacy `payoutBindings` ban, commit phase,
signatures, then payee-bound payout coverage.

DACS-3 §8.5 defines the `PayeeBoundAgreementDocument` signature input as
`"dacs-payee-bound-agreement:v1:" || agreement_hash`; the cross-domain vectors
also exercise §B.7/SIG-2 by replaying legacy agreement signatures under the
payee-bound domain and vice versa.

This candidate set does not assign a failure class for the separate
no-satisfiable-tier refusal case; that classification remains outside this
artifact-compatibility repair packet.

#### Vector schema

Each entry in `vectors[]`:

| field | meaning |
|-------|---------|
| `name` | stable case id |
| `rule` | PB rule family under test |
| `op` | operation surface: agreement-artifact gate, signature-domain check, or pre-pay destination decision |
| `readerMode` | agreement reader under test: `legacy` or `current` |
| `commitPhase` | commitment phase being exercised, when the case targets artifact/phase matching |
| `expected` | §7.5.1 verdict: `pass` \| `fail` \| `indeterminate` \| `error` |
| `note` | human-readable rationale |
| `agreement` | complete signed `AgreementDocument` or `PayeeBoundAgreementDocument` fixture |
| `artifactHash` | pinned `sha256(JCS(agreement-without-signatures))` for the fixture |
| `signatureDomain` | domain separator used to verify the fixture signatures |
| `listing` | listing/pipeline fixture used for artifact coverage and phase matching |
| `phaseInput` / `phaseInputs` | one payment phase or repeated payment phases under test |
| `bindingContext` / `bindingContexts` | resolved or unresolved binding evidence available to the payer |
| `want` | expected submit/refuse/pause outcome and any bound destination; repeated-phase cases use `want.results[]` |

Complete agreement fixtures carry the DACS-3 §8.5 fields needed for the signed
scope: version discriminator, `jobId`, `listingRef`, `parties`,
`derivedFromPattern`, `terms`, `generatedAt`, and `signatures`. `agreementHash`
is recomputed from JCS with `signatures` omitted; it is not a document field.

The set-level `publicKeys` map gives every agreement-signature party's Ed25519
public key as Base64URL raw bytes without padding. Agreement `signatures[].value`
entries use the same unpadded Base64URL encoding required by CORE §B.7 SIG-6. To reproduce the
signature verdicts, remove `signatures`, compute `artifactHash =
sha256(JCS(agreement-without-signatures))`, then verify each signature over
`signatureDomain || artifactHash` using the matching `publicKeys[signature.party]`.
The signed payload concatenates the UTF-8 domain-separator bytes with the
lowercase 64-character hash encoded as ASCII bytes.

`pass` means the destination is bound and payment may be submitted. `fail` means
the payer aborts before submission. `indeterminate` means ST-7-style pause before
submission because an applicable binding cannot be resolved. `error` means a
resolver/input error is surfaced as error, with no tier-3 downgrade and no
payment. This set is candidate data only; cross-run convergence and any golden
promotion remain pending.

### `agreement-listing-v0.1.json` — §8.5.2 (agreement ↔ listing validation)

30 vectors for the §8.5.2 check that a signed `AgreementDocument`'s terms are
permitted by the listing it cites — **7 ordered checks**: currency, price-band,
rail, deliverable, deadline, expiry, and cancellation/pattern. Price-band math is
**exact-decimal (BigInt)** — no float drift — so a price one minor-unit outside
the band fails deterministically across impls.

#### Vector schema
Each entry in `vectors[]`:

| field         | meaning |
|---------------|---------|
| `name`        | stable case id |
| `expected`    | §7.5.1 verdict: `pass` \| `fail` \| `indeterminate` \| `error` (never collapsed) |
| `committedAt` | commit timestamp (for deadline/expiry checks) |
| `agreement`   | the `AgreementDocument` under test |
| `listing`     | the cited listing whose terms bound the agreement |

Run (reference): `npx tsx conformance/security-vectors/agreement-listing/run.mts` → 30/30.

### `vp-replay-v0.1.json` — §7.3.2 (verifiable-presentation holder-binding / anti-replay)

13 vectors for VP holder-binding: a presentation is accepted only if a **holder
proof** (the key controlling the credential subject) verifies over a **challenge
that includes the session nonce**. Rejects both replay modes — a non-holder
presenter, and a valid presentation re-played across a different session (nonce
mismatch). Models the VC Data-Integrity `challenge` discipline, not a generic jti.

#### Vector schema
| field          | meaning |
|----------------|---------|
| `name`         | stable case id |
| `expected`     | §7.5.1 verdict (4-value, never collapsed) |
| `sessionNonce` | the verifier's fresh per-session nonce the holder proof must bind |
| `presentation` | the VP under test (holder proof + subject) |

Plus a top-level `keys` map (public keys) so verification is self-contained.
Run (reference): `npx tsx conformance/security-vectors/vp-replay/run.mts` → 13/13.

### `channel-message-replay-v0.1.json` — §8.3.3 + CH-6 (channel-message replay / channelId reuse)

15 vectors for the cross-session / in-channel offer-replay defence (threat-matrix
row #14 — the DACS-normative replay analog of the SR-4/L2PS nonce-reuse case, which
was correctly **declined** as a DACS vector because the crypto envelope is left to
implementations). A `ChannelMessage` is admitted only if **all** hold, as the
§7.5.1 4-value decision (never collapsed):

- **CH-6** — the session's `channelId` MUST NOT be one reused from a prior session
  (`priorChannelIds`); a reused session channel → `fail` (the whole session is rejected).
- **channel binding** — `message.channelId == sessionChannelId`; a foreign-channel
  message (a genuine message from another session presented here) → `fail`.
- **signature** — over `"dacs-channelmsg:v1:" || sha256(JCS(envelope − signature))`
  by the sender's self-describing `cci:<hex>` key. An unresolvable sender key →
  `indeterminate` (NOT `fail`); an invalid signature → `fail`.
- **monotonic sequence** — strictly greater than the highest already seen in the
  channel (starts at 1, §8.3.3); a duplicate or decreasing `sequence` → `fail`.

A cross-session replay fails **both** ways: keep the old `channelId` → channel-binding
`fail`; rewrite it → the signature (computed over the original `channelId`) breaks.
Malformed artifacts — a non-canonicalisable `body`, a non-integer/negative
`ctx.lastSequence`, or a non-string `priorChannelIds` element — return `error`,
never collapsing to `fail` (so bad context cannot bypass the replay gate).

#### Vector schema
| field      | meaning |
|------------|---------|
| `name`     | stable case id |
| `expected` | §7.5.1 verdict (4-value, never collapsed) |
| `message`  | the `ChannelMessage` under test (channelId, sequence, sender, signature, body…) |
| `ctx`      | per-case `{ sessionChannelId, lastSequence, priorChannelIds }` |

Self-contained (sender keys are self-describing `cci:<hex>`; signatures are real
ed25519 over the §8.3.3 signed scope). Run (reference):
`npx tsx conformance/security-vectors/channel-message-replay/run.mts` → 20/20
(15 persisted vectors + 5 non-serialisable robustness assertions).

### `claim-requirement-qualification-v0.3.json` — §7.7.1 CRQ-1..CRQ-4

36 candidate vectors for qualifying authenticated, resolved `VerifyResult`
objects against the complete applicable `ClaimRequirement` predicate before
decision classification. The set covers exact positive matching, absent
listing constraints with an implicit session-start version pin, competing old
and current recipe results, wrong recipe version, the inclusive and exceeded age
boundaries, parameter mismatch and absence, additional unrequested result data,
same-scheme cross-satisfaction, negative and positive `oneOf` selection,
preservation of applicable `error` and `indeterminate`, stale-indeterminate
exclusion, an unrelated-result control, and fail-closed missing, unresolvable,
wrong-job, and internally mismatched production contexts. Replay coverage uses
genuinely signed synthetic `AttestationBundle`, `CompositeVerificationRecord`,
and `VerifyResult` fixtures and includes the valid path, a signed wrong-job
substitution, a same-job bundle missing the exact record reference, substituted
requirement and result projections, and refusal of an unsigned `SessionRecord`.
The eight additional preflight/reuse cases require exact latest-family
selection, reject a non-live latest version without falling back to an older
live version, classify explicit and implicit unresolved versions as `error`
before decision precedence, and distinguish cache eligibility from aggregation
applicability. Cross-session non-pass reuse requires authenticated exact
originating-parameter equivalence; otherwise a current-predicate rerun replaces
the cached decision or the phase returns `error` when no rerun is available.

The inputs begin after reference, hash, signature, recipe-authority,
attestation, and governing freshness validation. Those failures retain their
governing dispositions and are not reclassified by this set. A declared
`ClaimRequirement.maxAge` is an additional bound and cannot widen that baseline.
`resolvedResults` is therefore a neutral projection of already-authenticated
DACS `VerifyResult` fields, not a new wire artifact. The set-level
`recipeRegistries` project the exact snapshots selected by each authenticated
production or replay authority; `latestByFamily` supplies the implicit pin and
`versionsByFamily` proves exact version existence plus availability. Parameter
matching requires every requested own key to be present and canonically equal;
additional extracted-data keys remain valid. `resultReuse` is neutral
pre-aggregation cache provenance and optional rerun output; it is not a field
added to `VerifyResult` v1.

#### Vector schema

Each entry in `recipeRegistries[]` contains `recipeRegistryVersion`,
`latestByFamily`, and `versionsByFamily`; `latestByScheme` remains only as a
negative control against scheme-wide fallback. `authenticatedSessionStarts`
models the trusted in-process production boundary. `replayBundles` and
`replayRecords` contain concrete domain-signed fixtures; `publicKeys` allows
independent bundle, record, and result signature verification. Each entry in `vectors[]` contains `name`, `expected`
(§7.5.1 four-value verdict), `note`, and `input`.
`input.aggregationAuthority` selects either a production `vetInput` plus its
authenticated session-start state or a replay bundle plus exact record reference;
`input.generatedAt` is the fixed aggregation
time; `input.requirement` is the canonical `BundleRequirement`; and
`input.resolvedResults` contains the authenticated result projections available
to §7.7.1. Optional `input.resultReuse` supplies parallel, neutral cache context
for cross-session cases.

This is a candidate set. Independent cross-run convergence and golden promotion
remain pending.

### `verifyresult-acceptance-v0.1.json` — §7.12 (VerifyResult acceptance)

13 vectors for the §7.12 consumer-side acceptance checks — three threat rows from the §12.4 matrix (#158) in one set:

- **method substitution (#6):** `VerifyResult.method` MUST be in the recipe's `defaultMethod` ∪ `alternatives`; an unaccepted method is rejected.
- **recipe poisoning (#7):** the recipe's steward signature MUST verify and `recipeVersion` MUST equal the version pinned for the session.
- **VerifyResult replay (#17):** `identifier` MUST match the claim under verification per the CF-3 canonical identity; `bundleHash` binds the result to a bundle. **Cross-session cache eligibility within `validUntil` is explicitly permitted** (and tested) — a conformant implementation MUST NOT blanket-reject it. VP-C1 and CRQ-2 remain the subsequent applicability gate: a cached pass is requalified under the consuming requirement, while a non-pass needs authenticated exact originating-parameter equivalence or a current-predicate rerun.

Decision is the §7.5.1 four-value verdict, never collapsed: a steward key that cannot be resolved → `indeterminate` (not `fail`); malformed input → `error`. The set deliberately includes the SAFE cases (permitted cross-session reuse; CF-3 `cci:0x`/case canonicalisation) so existence of the rule can't be satisfied by blanket rejection.

#### Vector schema
Each entry in `vectors[]`:

| field | meaning |
|-------|---------|
| `name` | stable case id |
| `expected` | §7.5.1 verdict: `pass` \| `fail` \| `indeterminate` \| `error` (never collapsed) |
| `note` | human-readable rationale |
| `verifyResult` | the VerifyResult under test (`identifier`, `method`, `bundleHash?`, `validUntil?`) |
| `recipe` | the cited recipe (`method`, `alternatives?`, `recipeVersion`, `stewardSig`) |
| `ctx` | consumer context (`claimUnderVerification`, `pinnedRecipeVersion`, `expectedBundleHash?`, `stewardPub`, `now?`) |

Run (reference): `npx tsx conformance/security-vectors/verifyresult-acceptance/run.mts` → 13/13.

### `rail-availability-selection-v0.1.json` — §9.4.4 (rail-availability selection + poisoning)

28 executable vectors for the §9.4.4 rail-availability rules, the availability-field poisoning defence (#158 gap #13), and #325. Every authenticated case signs the complete `RailDefinition` with only `signature` omitted, uses the normative `dacs-rail:v1:` payload and unpadded Base64URL `RailSignature.value`, and pins that same complete-document digest:

- **RAV-R2** — any new session MUST NOT select `disabled` or `failed`; a new production session additionally MUST NOT select `mocked`. Production mode is explicit trusted local operator policy; counterparty or discovery hints cannot establish non-production mode. A session that pinned a live definition continues under that pin when a later registry revision marks the rail `disabled`.
- **RAV-R3** — `operator_gated` / `closed_data` / `bilateral` are selectable ONLY when the operator-side preflight is satisfied (a runtime check).
- **RAV-R5 / LRR-6 (poisoning)** — `availability` MUST be read from the steward-signed **and pinned/anchored** `dacs-rail:v1:` definition. The signature and pin cover the complete definition, including unknown future members under SIG-5. A valid signature alone is insufficient: an unsigned/counterparty copy, or a validly-signed-but-**stale/cached** copy that is not the pinned definition, MUST NOT steer selection. Discovery hints may prefilter or inform a UI but cannot establish, refute, or override the authoritative result.

Decision is the §7.5.1 four-value verdict, never collapsed: a steward key that cannot be resolved, or no pinned reference to compare against, → `indeterminate` (not a silent pass); malformed def / unknown availability value → `error`.

#### Vector schema
Each entry in `vectors[]`: `name`, `expected` (§7.5.1 4-value), `note`, `rail` (`railId`, `availability`, `railVersion`, `stewardSig`), `ctx` (`stewardPub`, `operatorPreflightOk`, `pinnedRailDigest`, `sessionState`, `production`, optional `discoveryAvailabilityHint`, optional `laterRegistryRailDefinition`). The set records the exact scalar projection, digest, signature domain, and deterministic generator used for this availability-decision fixture; full RailDefinition schema and RD validation precede this decision. The optional later-registry field documents the signed revision observed after the session pinned its original live definition; it is contextual evidence rather than a decision input, and the verdict remains derived from the authenticated original pin.

Run (reference): `python3 -m unittest tests.test_rail_availability_selection_vectors` → 7 tests / 26 vectors. Regenerate with `python3 scripts/generate_rail_availability_selection_vectors.py --write`; CI checks the generated bytes with `--check`.

### `sealed-envelope-deadline-v0.1.json` — §8.4.3 (sealed-envelope bid admission)

15 vectors for whether a sealed bid is admitted to the auction candidate set (#158 gap #27):

- **SE-2 deadline gate** — the authoritative time is the **SR-2 anchor timestamp**; the self-reported `commitTimestamp` MUST NOT gate. A commit anchored after `commitDeadline` is late → excluded, and an on-time self-report does not save it (both directions tested).
- **SE-3 reveal window** — the reveal MUST be anchored within `[commitDeadline, commitDeadline + revealWindow]`; out-of-window (early or late) → excluded.
- **SE-4** — a committed bidder MUST reveal; a missing reveal → excluded.
- **CH-3** — the commit's `bidderClaim` MUST equal the authenticated sender → else excluded.
- **Commitment binding** — the revealed `{bid, salt}` MUST reproduce `bidHash = sha256("dacs-sealed-bid:v1:" || sha256(JCS(bid)) || salt)` (exact lowercase hex); a different bid/salt, or a non-lowercase-hex committed hash, → excluded / error.

§7.5.1 four-value, never collapsed: an unresolvable SR-2 anchor timestamp → `indeterminate`; malformed commit / non-hex salt / non-lowercase-hex bidHash → `error`. Boundary instants are deliberately not asserted.

#### Vector schema
A top-level `ctx` (`commitDeadline`, `revealWindowSec`, `authenticatedSender`); each entry in `vectors[]`: `name`, `expected`, `note`, `commit` (`bidHash`, `bidderClaim`, `commitTimestamp`, `anchorTimestamp`), `reveal` (`bid`, `salt`, `anchorTimestamp`) or `null`.

Run (reference): `npx tsx conformance/security-vectors/sealed-envelope-deadline/run.mts` → 15/15.

### `sealed-envelope-multicommit-v0.1.json` — §8.4.3 SE-9 (same-bidder commit authority)

4 vectors pin the authoritative commitment when one bidder anchors multiple
in-window commits (#209):

- the earliest SR-2 anchor timestamp wins and self-reported `commitTimestamp`
  never affects authority;
- revealing only a later same-bidder commit excludes that bidder as a bidHash
  mismatch;
- a lowest-price case proves the resulting winner differs from an incorrect
  latest-commit implementation; and
- equal anchor timestamps use ascending lowercase-hex `bidHash`, independent of
  collection order.

#### Vector schema

Each entry carries `commits[]`, `reveals[]`, and a `subjectBidderClaim`.
`expected` is the subject bidder's admission verdict after SE-9 authority
resolution. `expectedAuthoritativeCommits`, `expectedAdmittedBidderClaims`, and
`expectedWinnerClaim` pin the intermediate authority/admission decisions and the
final selection result. Commit and reveal hashes use the §8.4.3
`dacs-sealed-bid:v1:` preimage with 32-byte base64url salts.

Candidate set; independent implementation cross-run pending.

### `private-deliverables-v0.1.json` — §9.3 / §9.6.1 / §9.6.2 (DV-1..DV-6, private delivery + entitlement credentials)

16 vectors for the private-delivery (`accessModel`) and `credentialRef`-entitlement
rules — the six DV rows defined at §9.6.1 and §9.6.2. They assert that access mode,
buyer binding, audit trail, and the delivered/valid/readable gates behave identically
across implementations, and that the DV-6 readability verdict is **never collapsed**:

- **DV-1 content-hash invariant (§9.6.1)** — `deliverableContentHash` MUST be the
  sha256 of the **cleartext** canonical payload, byte-identical across `public` /
  `buyer-only` / `encrypt-to-buyer`, never the ciphertext. A pass case shows the same
  digest across all three modes; a fail case takes the hash over the ciphertext.
- **DV-2 access-mode fidelity (§9.6.1)** — a declared non-`public` deliverable resolved
  as delivered `public` ⇒ `indeterminate` (a provenanced `confidentiality-downgrade`
  flag), never `pass`; over-provision (declared `public`, delivered private) is NOT a
  violation (`pass`).
- **DV-3 buyer binding (§9.6.1)** — under `buyer-only` the ACL `allowed` entry MUST be
  the agreement-bound buyer `AgreementParty` (§8.5) address (a foreign, separately-
  presented address ⇒ `fail`); under `encrypt-to-buyer` the payload MUST be sealed to
  that party's `AgreementParty.encryptionKey` (a different key ⇒ `fail`).
- **DV-4 ACL-mutation auditability (§9.6.1)** — a deliverable ACL mutation SHOULD be an
  anchored+signed record, and MUST be for a `credentialRef` entitlement (§9.6.2); an
  unanchored `credentialRef` ACL mutation ⇒ `fail`.
- **DV-5 three gates never collapsed (§9.6.2)** — for a `credentialRef` entitlement,
  `SettlementEvidence` asserts ONLY **delivered** (binds the `credentialRef` + credential
  cleartext digest at the settled `renewalSeq`), never **valid** or **readable**; evidence
  that over-asserts `readable` ⇒ `fail`.
- **DV-6 readability verdict, do-not-collapse (§9.6.2)** — in `allowed` & not blacklisted
  ⇒ **readable** (`pass`); entitlement window lapsed ⇒ **clean-negative** (`fail`,
  lifecycle); buyer dropped from `allowed` / blacklisted ⇒ **ACL-dropped
  (channel-unreadable)** (`fail`); ACL/storage unresolvable ⇒ **indeterminate** — a
  transient outage MUST NOT be read as channel-unreadable. One vector per arm.

Decision is the §7.5.1 four-value verdict, never collapsed. Because DV-6's four
readability outcomes do not map one-to-one onto the four verdicts (both `clean-negative`
and `ACL-dropped` are negatives), the four-way readability label is carried in a
**companion `readability` field** alongside the top `expected` verdict (mirroring how
`sb2-settlement-uniqueness` splits `decision`/`effect`). DV-2's downgrade case likewise
carries a companion `flag`, and DV-5 an `assertedGates` list.

#### Vector schema
Each entry in `vectors[]`:

| field | meaning |
|-------|---------|
| `name` | stable case id |
| `expected` | §7.5.1 verdict: `pass` \| `fail` \| `indeterminate` \| `error` (never collapsed) |
| `rule` | the DV rule exercised (`DV-1`..`DV-6`) |
| `note` | human-readable rationale |
| `readability` | *(DV-6 only)* four-way readability label: `readable` \| `clean-negative` \| `ACL-dropped` \| `indeterminate` |
| `flag` | *(DV-2 downgrade only)* `confidentiality-downgrade` |
| `assertedGates` | *(DV-5 only)* the gates the `SettlementEvidence` asserts |
| `agreementBuyer` | the agreement-bound buyer `AgreementParty` (§8.5): `role`, `primaryClaim`, resolved `address`, `encryptionKey` |
| `delivery` / `deliveries` | the delivery under test (`accessModel`, `deliverableContentHash`, `hashedOver`, `acl`, `sealedTo`, declared/delivered mode…) |
| `entitlement` | *(DV-4..6)* the EntitlementRecord binding (`jobId`, `renewalSeq`, `credentialRef`, `startsAt`, `endsAt`) |
| `aclMutation` / `settlementEvidence` / `acl` / `now` | per-rule context for DV-4 (audit record), DV-5 (evidence gates), DV-6 (ACL + evaluation instant) |

Fixtures are deterministic: addresses/keys are fixed hex; `deliverableContentHash` values
are the real `sha256` of the canonical (JCS) cleartext payload (`hashedOver: "cleartext"`),
and the DV-1 fail case's hash is `sha256` over a distinct ciphertext byte-string; timestamps
are integer unix-ms. Entitlement window is `[1750000000000, 1750003600000]`.

#### Running
Language-neutral data: feed each vector's inputs to a §9.6 verifier and assert `expected`
(plus `readability` for DV-6). The set-level `hash` is
`sha256(JSON.stringify(vectors))` with sorted keys and ASCII-escaped output (the
`verifyresult-acceptance` convention); `count` MUST equal `vectors.length` (16). This set
awaits a reference `run.mts` and a second independent impl to cross-run against.

### `feeschedule-reconciliation-v0.1.json` — §8.5.3 FS-1..FS-5 + §9.7.2 FR-1..FR-4 (fee disclosure + disclosed-fee reconciliation)

17 vectors for the optional DACS-3 `feeSchedule` cost-disclosure (§8.5.3) and the informational DACS-4 disclosed-fee reconciliation (§9.7.2), requested by RB on #186. Two distinct operations are exercised, so each vector carries an `op` discriminator and its `expected` verdict is read in that op's vocabulary:

- **`validate-feeschedule`** — is the `feeSchedule` shape conformant? `expected` ∈ the §7.5.1 4-value `pass` \| `fail` \| `indeterminate` \| `error`. Covers **FS-1** (priceBasis REQUIRED + `oneOffTotal.currency == terms.price.currency`), **FS-2** (each `FeeItem` exactly one of `fixed`\|`rateBps`), **FS-5** (`earlyTerminationFee` is a disclosure shape only, semantics per §10.3.1).
- **`reconcile`** — does the disclosure reconcile against actual settlement? `expected` ∈ the **FR-4 trichotomy** `reconciles` \| `diverged` \| `indeterminate` (+`error` for malformed), *never collapsed* — a transient/absent resolution is `indeterminate`, never silently `diverged`. Covers **FR-1** (only `kind=="network"` reconciles vs `SettlementEvidence.paymentFee`; platform/processing/spread/subscription stay disclosure-only), **FR-2** (`rateBps → amount = price.amount × rateBps ÷ 10000`, canonical decimal, **half-up to the settlement asset's decimals**), **FR-3** (expected payer-total via `priceBasis` inclusive vs exclusive), **FR-4** (the reconciles/diverged/indeterminate trichotomy), and **FS-4** (a `recurrence` item is an ongoing disclosed cost, reconciled on the one-off only — never a charge trigger / never in a gating path).
- **`settle-gate`** — proves **FS-3**: a disclosed fee that mismatches actual settlement MUST NOT gate settlement; the settlement verdict stays `pass`. A `reconcile` op on the same data would return `diverged`, but that is informational and never blocks/reverts/retries settlement.

Fee math is exact-decimal (no float): the FR-2 boundary case `50 × 25 ÷ 10000 = 0.125` rounds **half-up** to `0.13` at 2-decimal precision (half-even would wrongly give `0.12`).

#### Vector schema

Each entry in `vectors[]`:

| field                | meaning |
|----------------------|---------|
| `name`               | stable case id |
| `rule`               | the normative rule exercised: `FS-1`..`FS-5` (§8.5.3) or `FR-1`..`FR-4` (§9.7.2) |
| `op`                 | operation under test: `validate-feeschedule` \| `reconcile` \| `settle-gate` |
| `expected`           | verdict in `op`'s vocabulary (see above) |
| `note`               | human-readable rationale (with the arithmetic where it applies) |
| `agreement`          | the `AgreementDocument` slice under test (`terms.price` + `terms.feeSchedule`) |
| `settlement`         | `SettlementEvidence` slice (`paymentAmount`, `paymentFee?`, `outcome`…) — present for `reconcile`/`settle-gate`; absent for pure validation |
| `rail`               | settlement `AssetSpec` (carries `decimals` for FR-2 rounding) — present where decimals matter |
| `expectedPayerTotal` | expected payer-total for the FR-3 `priceBasis` cases (distinguishes inclusive vs exclusive) |
| `reconciliation`     | provenanced divergence detail on the FR-4 `diverged` case (`signedDelta`, `breachedToleranceBps`, `direction`) |

#### Hash / count convention

`count` is the number of `vectors[]`. `hash` is `sha256(canonical_json(vectors))` where `canonical_json` is exactly `scripts/validate_conformance_vectors.py::canonical_json` (`json.dumps(..., sort_keys=True, separators=(",",":"), ensure_ascii=False)`) applied to the `vectors` array. Regenerate with the set's builder; the security subdirectory is excluded from the lifecycle shape-check glob (see the shape note above), so the §-references (validated by `scripts/validate_spec_refs.py`) are the CI-enforced surface here.

#### Running

Language-neutral data: feed each `agreement` (+ `settlement`/`rail` where present) to your §8.5.3 / §9.7.2 implementation and assert `expected` for the given `op`. Reference run (pending) lives in `pathos-dacs-ref`:

```
npx tsx conformance/security-vectors/feeschedule-reconciliation/run.mts
# → 17/17 vectors pass
```

### `settlement-finalization-propagation-v0.3.json` — §9.7 FP-1..FP-4

Six candidate cases pin the difference between an in-memory settlement draft and the
final DACS-4/DACS-5 artifact set. The positive case changes one EVM transaction hash,
recomputes the evidence hash, updates both bundle reference sites and the duplicated
phase transaction reference, then requires both signature layers to be regenerated.
The fixture carries byte-recomputable draft/final evidence and bundle hashes.

The negative cases reject a signed or anchored placeholder, a stale bundle reference,
a stale `phaseSummary[].txRefs` value, stale evidence/bundle signatures, and an unrelated
agreement mutation. The operation accepts only the source change plus its transitive
integrity closure; `BundleParty.bundleHash` remains unchanged because it hashes the
party's DACS-1 identity bundle.

Run the dependency-free executable checks from the repository root:

```sh
python3 -m unittest tests.test_settlement_finalization_propagation_vectors -v
```

## Status

**Proposed / candidate** — independent reference-impl security vectors, derived
from the §12.4 threat matrix (#158), offered for the shared suite; pending
maintainer disposition of normative status and of whether they fold into the
generated `conformance/MANIFEST.json` surface alongside `dacs-verify`'s. SB-2's
EVM row is cross-run-converged with `dacs-verify` (#159); agreement-listing and
vp-replay await a second independent impl to cross-run against.
`feeschedule-reconciliation` was authored on RB's request (#186) covering §8.5.3
FS-1..FS-5 + §9.7.2 FR-1..FR-4; awaiting a second independent impl to cross-run against.
