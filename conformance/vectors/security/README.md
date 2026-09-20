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

> **JID-1 profile boundary.** Vector sets created before the declared JID-1
> corrective profile commonly use short, descriptive `jobId` labels. Those
> cases are frozen rule-local or derivation-only legacy fixtures: they may
> reproduce the historical rule named by their set, but they are not current
> full-input sessions and cannot authorize a current address, lookup, signature,
> payment, or other effect. A current-profile runner applies
> `job-id-grammar-v0.1.json` and the exact-profile admission gate before running
> any job-specific surface. Tests that intentionally replay old labels must call
> an explicitly named legacy helper.

<!-- BEGIN GENERATED: security-vector-index (scripts/generate_security_vector_index.py) -->

| Set | Spec surface | Vectors | Verdicts used |
| --- | --- | --- | --- |
| [`agreement-listing-v0.1.json`](agreement-listing-v0.1.json) | DACS §8.5.2 | 30 | `accept` / `indeterminate` / `reject` |
| [`alternative-payment-projection-v0.1.json`](alternative-payment-projection-v0.1.json) | DACS-1 §6.3.4 LRR; DACS-3 §8.5.2; DACS-4 §9.9.1 APR-1..APR-8; DACS-5 §10.4.3 | 45 | `fail` / `indeterminate` / `pass` |
| [`ap2-handler-safety-v0.6.json`](ap2-handler-safety-v0.6.json) | DACS-4 v0.8 current composed profile (JID-1 boundary declared at v0.7): §9.5.6 AP2-3/AP2-6/AP2-7 plus CORE §11.1.2 and JID-1 | 66 | `error` / `fail` / `pass` |
| [`artifact-reference-shapes-v0.1.json`](artifact-reference-shapes-v0.1.json) | DACS-2 §7.5.2 AttestationRef; DACS-4 §9.3 ChainTxRef | 26 | `fail` / `pass` |
| [`bundle-absence-evidence-v0.3.json`](bundle-absence-evidence-v0.3.json) | CORE §5 SR-2; DACS-5 §10.4.3 / §10.5.1 guard (iv) | 4 | `fail` / `indeterminate` / `pass` |
| [`bundle-binding-v0.1.json`](bundle-binding-v0.1.json) | DACS-5 §10.4.2 BB-1..BB-8 + §10.4.1 faultedParty | 9 | `fail` / `indeterminate` / `pass` |
| [`bundle-settlement-evidence-bijection-v0.4.json`](bundle-settlement-evidence-bijection-v0.4.json) | DACS-5 §10.4.3 SEB-1..SEB-6 | 30 | `fail` / `indeterminate` / `pass` |
| [`canonical-channel-message-v0.6.json`](canonical-channel-message-v0.6.json) | DACS-3 §8.3.3 CH-6..CH-10 + CORE §B.7 SIG-2/SIG-5/SIG-6 | 55 | `error` / `fail` / `indeterminate` / `pass` |
| [`canonical-json-v0.1.json`](canonical-json-v0.1.json) | CORE §B.2 RFC 8785 JCS + CF-1 | 25 | `fail` / `pass` |
| [`cci-xm-rail-chain-applicability-v0.5.json`](cci-xm-rail-chain-applicability-v0.5.json) | DACS-1 §6.3.1 EVM cci-xm settlement-chain profile; DACS-4 §9.4.3 RD-5 and §9.5.1 PB-2 | 31 | `error` / `indeterminate` / `pass` |
| [`channel-message-replay-v0.1.json`](channel-message-replay-v0.1.json) | DACS-3 §8.3.3 + CH-6 (channel-message replay / channelId reuse) | 15 | `error` / `fail` / `indeterminate` / `pass` |
| [`claim-requirement-qualification-v0.3.json`](claim-requirement-qualification-v0.3.json) | DACS-2 §7.7.1 CRQ-1..CRQ-4 | 36 | `error` / `fail` / `indeterminate` / `pass` |
| [`commitment-anchor-authority-v0.3.json`](commitment-anchor-authority-v0.3.json) | DACS-3 §8.6 CA-6/CA-7 | 4 | `fail` / `pass` |
| [`commitment-record-compatibility-v0.1.json`](commitment-record-compatibility-v0.1.json) | DACS-3 §8.6 CA-6/CA-8/CA-9 and §8.11; CORE §11.1.2 | 10 | `fail` / `pass` |
| [`current-use-authenticated-window-v1.json`](current-use-authenticated-window-v1.json) | DACS-5 unallocated CUAW-1..CUAW-6 composing CUR-1..CUR-8 and AWT-1..AWT-8 | 15 | `indeterminate` / `pass` |
| [`current-use-reputation-v1.json`](current-use-reputation-v1.json) | DACS-5 unallocated current-use candidate §10.4 LAB-1..LAB-7 and §10.5.1 CUR-1..CUR-8 | 8 | `pass` |
| [`domain-claim-gcr-v0.4.json`](domain-claim-gcr-v0.4.json) | DACS-1 §6.3.1 DCR-1..DCR-8; DACS-2 §7.3.10 DGCR-1..DGCR-6 | 63 | `error` / `fail` / `indeterminate` / `pass` |
| [`fab-bundle-extended-pointer-v0.3.json`](fab-bundle-extended-pointer-v0.3.json) | DACS-5 §10.4.2 extended-pointer FaultAttestationBundle path + §10.4.1 triple-identity (E7) | 4 | `fail` / `pass` |
| [`fault-bundle-perspective-pair-v0.3.json`](fault-bundle-perspective-pair-v0.3.json) | DACS-5 §10.4.3 FaultAttestationBundle-pair rule + §10.4.1 permissible set | 3 | `fail` / `pass` |
| [`feeschedule-reconciliation-v0.1.json`](feeschedule-reconciliation-v0.1.json) | DACS-3 §8.5.3 (FS-1..FS-5); DACS-4 §9.7.2 (FR-1..FR-4) | 17 | `diverged` / `fail` / `indeterminate` / `pass` / `reconciles` |
| [`finality-resolution-context-v1.json`](finality-resolution-context-v1.json) | DACS-4 #392 D2 finality resolution context version 1 | 11 | `fail` / `indeterminate` / `pass` |
| [`identity-bundle-hash-binding-v0.1.json`](identity-bundle-hash-binding-v0.1.json) | CORE §B.2 IBH-1..IBH-6; DACS-1 §6.3.4; DACS-2 §7.7; DACS-3 §8.5/§8.6; DACS-4 §9.5/§9.9.1; DACS-5 §10.4/§10.5.1 | 383 | `error` / `fail` / `indeterminate` / `pass` |
| [`job-id-grammar-v0.1.json`](job-id-grammar-v0.1.json) | CORE §11.1.2 and §B.1 JID-1..JID-4; DACS-5 §10.3 and §10.4.2 | 47 | `error` / `fail` / `pass` |
| [`legacy-agreement-admission-v0.8.json`](legacy-agreement-admission-v0.8.json) | DACS-4 v0.8 §9.5.1 LAA-1..LAA-7; DACS-3 v0.6 §8.6 CA-10 | 166 | `error` / `fail` / `indeterminate` / `pass` |
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
| [`presence-only-claim-requirement-v0.7.json`](presence-only-claim-requirement-v0.7.json) | DACS-1 §6.3.3 PCR-1..PCR-6; DACS-2 §7.7.1 | 47 | `error` / `fail` / `indeterminate` / `pass` |
| [`private-deliverables-v0.1.json`](private-deliverables-v0.1.json) | DACS-4 §9.3 / §9.6.1 / §9.6.2 (DV-1..DV-6) | 16 | `ACL-dropped` / `clean-negative` / `fail` / `indeterminate` / `pass` / `readable` |
| [`rail-availability-selection-v0.1.json`](rail-availability-selection-v0.1.json) | DACS-4 §9.4.4 (RAV-R1/R2/R3/R5); DACS-1 §6.3.4 (LRR-6) | 28 | `error` / `fail` / `indeterminate` / `pass` |
| [`raw-json-profile-v0.1.json`](raw-json-profile-v0.1.json) | CORE §B.2 CF-5 raw JSON admission | 59 | `accept` / `reject` |
| [`receipt-rederivation-v0.3.json`](receipt-rederivation-v0.3.json) | DACS-5 §10.5 ReplayableReputationDerivation replay (authenticated per-copy validation) + §10.5.3 (1)-(3); round-6 blockers #1/#2 | 16 | `fail` / `pass` |
| [`recipe-parser-applicability-v0.5.json`](recipe-parser-applicability-v0.5.json) | DACS-2 §7.4.1/§7.6 PRA-1..PRA-5 parser applicability | 22 | `error` / `pass` |
| [`registry-bootstrap-v0.1.json`](registry-bootstrap-v0.1.json) | CORE §5 RegistryBootstrapDescriptor; DACS-1 §6.3.4 LRR-2; DACS-2 §7.4.3; DACS-4 §9.4.3 | 79 | `fail` / `indeterminate` / `pass` |
| [`reputation-authenticated-window-v0.6.json`](reputation-authenticated-window-v0.6.json) | DACS-5 v0.6 §10.5 AWT-1..AWT-8 authenticated outcome window | 185 | `error` / `fail` / `indeterminate` / `pass` |
| [`reputation-participation-admission-v0.7.json`](reputation-participation-admission-v0.7.json) | DACS-5 v0.7 §10.3.2/§10.5 SPA-1..SPA-8 exact participation and rating admission | 170 | `fail` / `indeterminate` / `pass` |
| [`reputation-settlement-reference-divergence-v0.4.json`](reputation-settlement-reference-divergence-v0.4.json) | DACS-5 v0.4 §10.5.1 settlement-verified reference-multiset divergence limb | 6 | `fail` / `pass` |
| [`reputation-settlement-semantics-v0.4.json`](reputation-settlement-semantics-v0.4.json) | DACS-5 v0.4 §10.5.1 RSV-1..RSV-4; settlement-verified types; consumes existing DACS-4 rules | 24 | `accept` / `indeterminate` / `reject` |
| [`revocation-binding-v0.3.json`](revocation-binding-v0.3.json) | DACS-1 v0.3 §6.3.4 RB-1..RB-6 historical revocation-marker discovery and fail-closed resolution | 14 | `fail` / `indeterminate` / `pass` |
| [`revocation-state-completeness-v0.8.json`](revocation-state-completeness-v0.8.json) | DACS-1 v0.8 §6.3.4 RSC-1..RSC-10 authoritative revocation completeness | 102 | `fail` / `indeterminate` / `pass` |
| [`sb2-collision-authority-v0.8.json`](sb2-collision-authority-v0.8.json) | DACS-4 §9.5.8 SB-2 authenticated collision authority | 32 | `error` / `fail` / `indeterminate` / `pass` |
| [`sb2-settlement-uniqueness-v0.1.json`](sb2-settlement-uniqueness-v0.1.json) | Historical DACS v0.1 §9.5.8 (SB-2); SB-1 key only | 20 | `error` / `fail` / `indeterminate` / `pass` |
| [`sb3-binding-required-v0.8.json`](sb3-binding-required-v0.8.json) | DACS-4 §9.5.8 SB-3 required-binding four-value gate | 22 | `error` / `fail` / `indeterminate` / `pass` |
| [`sb3-eip3009-nonce-v0.1.json`](sb3-eip3009-nonce-v0.1.json) | DACS-4 §9.5.8 (SB-3 EIP-3009 nonce binding) | 14 | `error` / `fail` / `pass` |
| [`sealed-auction-completeness-v0.6.json`](sealed-auction-completeness-v0.6.json) | DACS-3 §8.4.4 SAC-1..SAC-12 | 82 | `fail` / `indeterminate` / `pass` |
| [`sealed-envelope-deadline-v0.1.json`](sealed-envelope-deadline-v0.1.json) | DACS-3 §8.4.3 (SE-2/SE-3/SE-4 + CH-3 + commitment binding) | 15 | `error` / `fail` / `indeterminate` / `pass` |
| [`sealed-envelope-multicommit-v0.1.json`](sealed-envelope-multicommit-v0.1.json) | DACS-3 §8.4.3 (SE-9 same-bidder commit authority) | 4 | `fail` / `pass` |
| [`settlement-event-identity-v0.6.json`](settlement-event-identity-v0.6.json) | DACS-4 §9.5.8 SB-1 signed event identity and legacy replay | 28 | `error` / `fail` / `indeterminate` / `pass` |
| [`settlement-finality-verification.json`](settlement-finality-verification.json) | DACS-4 unallocated finality proposal §9.7.0 FV-1..FV-10; DACS-5 typed finality consumer | 85 | `error` / `fail` / `indeterminate` / `pass` |
| [`settlement-finalization-propagation-v0.3.json`](settlement-finalization-propagation-v0.3.json) | DACS-4 §9.7 FP-1..FP-4; DACS-5 §10.4.1 and §10.4.3 | 6 | `fail` / `pass` |
| [`signature-value-encoding-v0.1.json`](signature-value-encoding-v0.1.json) | CORE §B.7 SIG-6 | 10 | `accept` / `reject` |
| [`sr2-anchor-lifecycle-v0.1.json`](sr2-anchor-lifecycle-v0.1.json) | CORE §5.1 SR2-1..SR2-9; DACS-1 §6.3.4 LP-1; DACS-2 §7.8 VPC-3/VPC-5; DACS-3 §8.6 CA-1/CA-8; DACS-4 §9.5.1 PC-7 and §9.9 PIPE-6; DACS-5 §10.3.1 ST-11 | 25 | `fail` / `pass` |
| [`sr2-logical-native-resolution-v0.1.json`](sr2-logical-native-resolution-v0.1.json) | CORE §5 SR2-10..SR2-13; DACS-1 §6.3.4; DACS-5 §10.4.2 | 39 | `fail` / `indeterminate` / `pass` |
| [`unresolved-vs-absent-v0.3.json`](unresolved-vs-absent-v0.3.json) | DACS-5 §10.4.3(b) + §10.4.2 BB-8 + CORE §5 absence-evidence policy | 4 | `indeterminate` / `pass` |
| [`verifyresult-acceptance-v0.1.json`](verifyresult-acceptance-v0.1.json) | DACS-2 §7.12 | 13 | `error` / `fail` / `indeterminate` / `pass` |
| [`vp-replay-v0.1.json`](vp-replay-v0.1.json) | DACS §7.3.2 | 13 | `error` / `fail` / `indeterminate` / `pass` |
| [`x402-receipt-hash-v0.1.json`](x402-receipt-hash-v0.1.json) | DACS-4 §9.5.7 X402-1..X402-4 canonical x402 settlement-response hashing | 12 | `error` / `fail` / `pass` |

_This table is generated from the set files — do not edit by hand._
_Regenerate with `python3 scripts/generate_security_vector_index.py --write`._

<!-- END GENERATED: security-vector-index -->

## Included sets

### `sealed-auction-completeness-v0.6.json` — §8.4.4 SAC-1..SAC-12

82 deterministic cases exercise the structurally distinct complete
sealed-envelope profile. Real Ed25519 signatures cover bidder commit/reveal
records, the selection receipt, its modeled candidate-set binding proof, and
the publisher/winner agreement. Each commit/reveal record carries a
`channelId` and a context-bound `bidHash` computed as
`sha256("dacs-sealed-bid-context:v1:" || sha256(JCS(SealedBidCommitmentContext)) || salt)`
binding the exact `jobId`, `listingRef` (including `contentHash`), `phaseIndex`,
CF-2 `bidderClaim`, `channelId`, `bid`, and raw decoded salt (SAC-11). The
frozen historical `dacs-sealed-bid:v1:` commitment is not accepted for a
complete-profile record and its released bytes remain unchanged. Demand
controls cover absent and explicit `"demand"` mode plus buyer/seller direction;
procurement retains its inverse role direction. The independent evaluator
derives exact closed record shapes, record authority, deadlines, listing
currency, bidder eligibility, CD-1 price ordering, the SE-5 tie-break, receipt
contents, and agreement closure from the signed inputs.
`listing.pricingCurrency` and the matching
`authenticatedInvocation.pricingCurrency` are this fixture's authenticated
verifier projection of the listing-derived currency. They are not a new
`PricingSpec` wire member, a full signed reserve-free Listing fixture, or a
native listing-resolution claim.

An independent Node.js evaluator separately executes 59 named controls from the
82-case corpus and reproduces the exact candidate-set
root, receipt content hash, demand/mode/role checks, reveal-deadline boundary,
non-USD filtering, exact record-shape refusal, exact arbitrary-length ordering,
inclusive reserve result, context-bound commitment recomputation, early-reveal
refusal, and winner for the selected controls,
providing a second-runtime byte check rather than two calls through the Python
oracle.

Attack cases cover an omitted better reveal, a valid but stale signed set,
missing proof, finalized fork conflict, unavailable winning record or bidder
key, unavailable binding definition or selection-receipt anchor, authenticated
definition/id/version/key substitution, a signed lying winner, receipt-reference
substitution, agreement-price mismatch, invalid/late/wrong-address reveals,
proof-count disagreement, non-finite/exponent/non-string amounts, malformed
PriceTerm shapes, noncanonical decimal strings, fully re-signed cross-job,
cross-listing and cross-phase artifacts, canonical binding-version rejection,
literal record-version checks, and signed extra/missing outer and nested
commit/reveal members. The context-bound commitment adds a copied commitment
opened under another bidder, cross-channel/cross-job/cross-listing/cross-phase
commitment replay, the frozen historical `dacs-sealed-bid:v1:` commitment
refused for a complete-profile record, correctly recomputed records claiming
another bidder's authenticated pairwise channel, unavailable channel authority,
a record signed by a different party than its `bidderClaim`, and a native SR-2
writer that the pinned admission map assigns to another bidder. They also cover
a premature reveal despite every bidder having committed and admission at the
exact inclusive `commitDeadline` boundary. The exact reveal-deadline state
passes while a valid proof one
millisecond earlier rejects. A matching EUR listing succeeds, USD bids are
excluded from it, and a third-currency reserve rejects the listing. Malformed signatures,
prices, or anchor/address
contradictions reject the whole selection; a valid signed reveal that fails to
open its authoritative commit is instead accounted for and excluded. Canonical
zero and negative prices are likewise excluded before selection. Long integer
and fractional controls pin exact lowest/highest ordering and inclusive reserve
floor/ceiling comparison without floating point or context-limited arithmetic.
`first-acceptable` and `rule-ref` are refused
before fetch/execution because the complete profile has no registered
deterministic VM. The fixture's authenticated SR-2 registry resolution binds
the exact definition ref/id/version and derives proof verification, finality,
admission, ordering, conflict, and resource policy from that definition. This
deterministic test adapter exercises the portable SAC-3 contract; it is
explicitly not evidence that Demos currently supplies a production
complete-prefix proof.

Regenerate and execute with:

```sh
python3 scripts/generate_sealed_auction_completeness_vectors.py --write
python3 scripts/generate_sealed_auction_completeness_vectors.py --check
python3 -m unittest tests.test_sealed_auction_completeness_vectors -v
node scripts/evaluate_sealed_auction_fixture.mjs conformance/vectors/security/sealed-auction-completeness-v0.6.json
```

### `canonical-json-v0.1.json` — CORE §B.2 RFC 8785 JCS + CF-1

25 candidate vectors pin exact canonical UTF-8 hex rather than only a generic
accept/reject result. They cover the five fractional values that exposed the
cross-implementation divergence in #270; RFC 8785's 1e-6 notation boundary,
negative zero, positive and negative minimum binary64 values, integral-float
formatting, and a round-to-even sample; both binary64 paths at the inclusive
DACS magnitude limits; and fail-closed handling of over-magnitude, non-finite,
BigInt, and invalid-Unicode inputs.

The Unicode cases discriminate DACS's values-only CF-1 layer from RFC 8785
member-name handling: an NFD string value becomes NFC, an NFD member name stays
as received, NFC and NFD spellings remain distinct members, and member names
sort by UTF-16 code units. Inputs that JSON cannot faithfully carry use the
set's declared `binary64`, `bigint`, or `unicode-code-units` tagged constructor;
an adapter that cannot construct one must report an explicit cross-run
abstention, never a matching rejection. The generic cross-run file records
verdicts rather than canonical bytes, so each adapter MUST compare exact
`canonicalUtf8Hex` before emitting `pass`; byte-level logs may be attached as
additional review evidence.

Regenerate, verify, and execute with:

```sh
python3 scripts/generate_canonical_json_vectors.py --write
python3 scripts/generate_canonical_json_vectors.py --check
python3 -m unittest tests.test_canonical_json_vectors -v
```

### `raw-json-profile-v0.1.json` — CORE §B.2 CF-5

59 raw UTF-8 JSON cases execute the mandatory admission step that precedes
object-model JCS. Unlike ordinary JSON fixtures, each case carries its source as
`rawUtf8Text` or `rawHex`, so duplicate decoded member names, hostile numeric
tokens, trailing data, a BOM, invalid UTF-8, parser extensions, and lone
surrogates cannot disappear while the vector file itself is loaded. A literal
replacement character encoded as valid UTF-8 remains an admitted control, while
the two external entry points refuse decoded text that lacks received-byte
provenance. Boundary cases admit exactly 128 nested array/object containers and
reject depth 129 with `JSON-NESTING-TOO-DEEP`, independent of host recursion
limits.

Positive cases pin the exact later JCS bytes. Negative cases separately name a
`parse` or DACS `profile` refusal and never carry canonical output. The standard
library-tokenizer adapter and a separate hand-written lexer with an explicit
container stack execute every case and must agree on verdict, refusal class,
and accepted value before canonicalisation.
This is raw-input coverage; it complements rather than replaces
`canonical-json-v0.1.json`, which begins from an already constructed value.

Regenerate, verify, and execute with:

```sh
python3 scripts/generate_raw_json_profile_vectors.py --write
python3 scripts/generate_raw_json_profile_vectors.py --check
python3 -m unittest tests.test_raw_json_profile_vectors -v
```

### `ap2-handler-safety-v0.6.json` — §9.5.6 checkout admission + AP2-3/AP2-6/AP2-7

66 candidate vectors execute the DACS-owned AP2 handler boundaries introduced
in DACS-4 v0.6. They pin provider idempotency-key bytes, NFC handling,
job/phase separation, malformed phase refusal, exact compact-JWS transaction-ID
derivation, CheckoutMandate `_sd_alg` selection and SHA-256 fallback, signature-
byte sensitivity, and refusal of malformed or unsupported algorithms. The
composed admission cases require separate verified CheckoutMandate and
PaymentMandate artifacts, enforce the DACS signature profile, and reject a
transaction-ID mismatch before AP2-7 reservation or provider submission. They
also require verifier-owned corrective-profile context bound to the exact
session and authenticated peer identity, validate every member of the closed
participant context before selection, and apply JID-1 plus a valid phase index before
hashing, resolution, metadata construction, reservation, or provider
submission. Missing, duplicate, identity-mismatched, session-mismatched,
unauthenticated, and caller-copied profile authorities all fail closed.

The same set executes first-use binding, immutable operation payload/fingerprint
and exact AP2-6 key continuity, reference-first status reconciliation,
lost-response same-key resubmission, settlement reuse, cross-job/cross-phase
replay refusal, and fail-closed malformed/conflicting-store handling. A recovery
may issue a provider request, but it carries the retained key and operation with
`submitNewPayment: false`; it never creates or counts a second payment. Provider capability, mandate
cryptographic verification, and checkout signature generation remain modeled
inputs: the cases do not claim to introspect a live provider credential, replace
AP2 signature verification, prove a signer's nonce-generation implementation,
or establish crash-safe production durability.
Regenerate, verify, and execute with:

```sh
python3 scripts/generate_ap2_handler_safety_vectors.py --write
python3 scripts/generate_ap2_handler_safety_vectors.py --check
python3 -m unittest tests.test_ap2_handler_safety_vectors -v
```

### `sr2-logical-native-resolution-v0.1.json` — CORE §5 SR2-10..SR2-13

39 candidate vectors make the portable logical-to-native read path executable.
They admit a verified direct `AnchorReceipt` at the calling rule's lifecycle
gate, plus exact authenticated references from a finalized DACS-5 bundle or a
verified registry snapshot only after that named carrier class's checks pass.
They keep bare locators, unregistered or generically authenticated surfaces,
missing class checks, unverified receipts, ordinary catalog/index assertions,
malformed receipt/carrier shapes, missing artifacts, low lifecycle states,
missing artifact authority, and unqualified `not found` results
`indeterminate`. A receipt delivered after its first required gate is a
producer conformance failure. Fractional and unsafe numeric members in the
SR2-5 transaction reference pin canonicalization and fail-closed disposition
behavior without uncaught exceptions. Runtime-controlled nesting depth is
likewise normalized at the deepcopy, canonicalization, and hashing boundaries:
direct unit regressions prove a 1,200-level receipt or storage value returns a
disposition (never a host `RecursionError`/`OverflowError`); depth cases live
in tests rather than the corpus because a committed vector must stay
JSON-serializable by every reader. Transport copies collapse only when their
canonical receipt snapshots are identical; unequal lifecycle snapshots sharing
an SR2-5 tuple remain `indeterminate` without binding-authenticated ordering.
Delivery is then assessed from the earliest finite verified delivery of that
single snapshot, so timely delivery survives later redelivery while all-late
copies fail.

The set also mutates every SR2-5 tuple component and proves that two unequal
otherwise-authorized mappings remain `indeterminate` regardless of arrival
order, `observedAt`, or index visibility. Authoritative absence appears only
through a declared binding policy.

### `registry-bootstrap-v0.1.json` — CORE §5 registry bootstrap

79 candidate vectors exercise the non-recursive recipe/rail index trust root.
The positive chains carry genuine deterministic Ed25519 signatures under
`dacs-registry-bootstrap:v1:` and cover hash-only/key-only first contact,
same-key content updates, two-signature authority rotation, exact
sequence-and-descriptor-hash historical replay, persisted-branch ancestry,
authenticated definition references, closed registry-index shape/kind/version/
revision checks, and SIG-5 preservation plus NFC and fractional-number
canonicalisation of unknown members.

The ratified #338-D1 source contract corrects unreleased
`RegistryIndexSnapshot` v1 entries to numeric versions and adds family-aware
latest selection, derived-NFC identity comparison, fetched-definition equality,
and target-bounded historical traversal. The checked-in 79-vector file has been
regenerated in dependency order: definition bytes and entry hashes, snapshot
hashes, receipt bindings, descriptor signatures and pins, successor references,
and fixture-verifier sidecars. All existing case names and expected outcomes
are preserved, including intentional invalid-input controls. The combined
generator's SR-2 resolution output is unchanged. Local generator determinism
and reference-model outcomes do not establish native proof verification or
integrated full-suite acceptance.
In the reference harness, `definitionQuery` is the non-wire lookup input:
recipe queries are `{id, family, version?}` or `{id, method, version?}` where `family` is
`Recipe.defaultMethod.kind`, while rail queries are `{id, version?}`. Omitting
`version` requests latest; a present version is a positive safe integer.
`definitionChecks` remains modeled output from the definition signature and
semantic verifiers rather than native proof verification.

Every case supplies a closed `expectedRegistryTuple` as independent release
configuration beside `trustPin`; it is not a signed descriptor member or wire
field. The evaluator validates the exact recipe/rail pairing and all four tuple
fields before root classification. `verifiedReceiptEvidence` records successful independent fixture-verifier outputs
bound to the complete evidence reference and SHA-256 of the exact canonical
receipt snapshot. A result for another proof kind or observation cannot authorize
this receipt. The sidecar result and the evidence record keep their required
members but are not exact-key-set constrained: under SIG-5 / §11.1.2 forward
readability, a future minor may add optional members, and the evaluator admits
an extended record exactly when the independent result repeats the complete
extended evidence record and the exact canonical receipt hash. The generator compiles reviewed fixture outcomes into this sidecar;
the evaluator never constructs approval from presented descriptors. These are
modeled verifier outputs, not proof material or a native evidence verifier. The
bounded harness does not claim an SR2-7 ordering primitive.

Negative and indeterminate cases cover missing release pins, descriptor/receipt
tuple substitutions, unavailable or recursive finality evidence, sequence and
registry-tuple changes, key aliases, malformed/cumulative revocations, root and
successor forks including unavailable and invalid competing candidates,
invalid first-contact siblings discarded before fork classification,
invalid-root suppression, post-classification duplicate transport-copy collapse
under valid, invalid, unresolved, and reversed-order combinations, closed snapshot
member shapes, latest rollback and sibling-branch substitution, unrelated
historical descriptors, unsafe JCS numbers,
mutable-address reuse, stale/missing snapshot bytes, definition failures,
cross-domain replay, and discriminator confusion.
Mode and stored-latest context are shape-checked before selection, including in
historical mode; omission means `latest`, while explicit null or unsupported
modes fail. Bootstrap snapshot admission runs the complete receipt predicate
before nested access and then requires an established finalized receipt, exact
descriptor bindings, block metadata, and independently verified non-recursive
evidence.
Public test seeds are included. Regenerate and execute both sets with:

```sh
python3 scripts/generate_sr2_resolution_vectors.py --write
python3 scripts/generate_sr2_resolution_vectors.py --check
python3 -m unittest tests.test_sr2_resolution_vectors -v
```

### `alternative-payment-projection-v0.1.json` — §9.9.1 APR-1..APR-8

45 candidate vectors make the Listing-only `pay-alternative` projection
executable across DACS-1, DACS-3, DACS-4, and DACS-5. Deterministic Ed25519
fixtures sign the Listing, complete DEM/x402/AP2 rail definitions, payee-bound
Agreements, evidence-bound bundles, and prior-payment dispositions. The cases
cover full-reference membership, optional snapshot-selected versions,
same-snapshot registry resolution, supported non-recursive handlers,
array-order independence, original-index projection, exact payout keys, and
concrete evidence/bundle kinds.

Negative and recovery cases reject malformed or repeated choice slots,
concrete payment siblings, same-railId reference substitution, caller-supplied
handler substitution, selected-rail RAV failure, signed in-job switching, and
same-job or fresh-job fallback while prior authorization is open or
indeterminate. Cross-job cases resolve the exact prior Agreement and require a
finalized orchestrator-signed disposition: either an atomic durable closure
before authorization or independently verified cannot-settle evidence. The set
also includes a positive independently recomputed bundle. The executable
effects counter pins zero second-rail wallet authorizations on every
refusal/retry path. A legacy reader refuses the unknown phase, while an
ordinary repeated-payment Listing retains PIPE-5 behaviour. Regenerate and
execute with:

```sh
python3 scripts/generate_alternative_payment_projection_vectors.py --write
python3 scripts/generate_alternative_payment_projection_vectors.py --check
python3 -m unittest tests.test_alternative_payment_projection_vectors -v
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

31 candidate vectors make the PB-2 EVM chain-applicability predicate
executable. Exact safe positive-decimal chain IDs map one-to-one to CAIP-2
`eip155:<chainId>` and cover Ethereum mainnet, Base mainnet, Ethereum Sepolia,
and Base Sepolia. A different numeric chain, a leading-zero or zero spelling,
and the human labels `mainnet`, `testnet`, `sepolia`, and `base` do not
establish tier 2 and leave the signed tier-3 assertion available.

The boundary cases admit `9007199254740991`, keep larger textual `cci-xm`
claims readable but PB-2-inapplicable, and reject an unsafe numeric
`RailDefinition` before either tier 2 or tier 3 can authorize payment.

The address component must be non-empty but is otherwise opaque for chain
selection; optional ClaimReference parameters do not change the derived chain.
An empty or parameter-only address and a non-lowercase `evm` family spelling do
not establish tier 2.

The set also pins three fail-closed boundaries: an exact chain match becomes
tier-2-applicable before SR-1 resolution, so an unavailable or erroneous
linkage cannot downgrade to tier 3; conflicting EVM asset/network chain IDs
fail RD-5, with equal-positive, unequal, zero, and non-integer controls for
`erc20` plus equal-positive and unequal controls for `native-evm`; and an x402
resource rail that exposes no single EIP-155 chain in its pinned definition
cannot gain tier 2 retroactively from a later receipt.
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

### `reputation-authenticated-window-v0.6.json` — DACS-5 v0.6 §10.5 AWT-1..AWT-8

185 candidate vectors pin standalone AWT-v1's business-occurrence clock and
fail-closed boundary. This corpus starts from a disclosed post-reconciliation,
post-RSV authoritative-copy precondition; it does not establish the combined
LAB/CUR/FV admission contract. It covers delayed and early bundle anchoring,
different buyer/seller copy-publication dates, producer and observer clocks,
both inclusive outcome boundaries, unavailable/unsupported/conflicting
occurrence proof, and exact bundle, job, outcome, effective-pipeline, phase,
terminal-evidence, and native-event joins. A completed payment alone does not
prove a multi-phase job, and failed or aborted outcomes cannot inherit payment
or publication time.

Finalized SR-2 receipts remain exact-bundle provenance. Their shared current
and replay lifecycle path enforces CORE §5.1 before replacement authorization:
an established `replaced` predecessor never finalized, its authenticated edge
strictly precedes successor finalization, and the successor carries its own
final receipt. `blockRef.id` is required while `height` and `timestamp` are
optional, matching CORE's optional-height portable receipt; a present `height`
must be a canonical unsigned-decimal string (`"0"` or `[1-9][0-9]*`), so a
sign, plus, whitespace, leading zero, decimal point, or exponent is rejected.
The single normative `demos-bft-final` profile (DEMOS-MAPPING §A.2) declares
inclusion-final semantics and permits the compressed `submitted→finalized` and
`accepted→finalized` edges that CORE allows when valid inclusion is final,
while undeclared profiles and cross-profile/mixed histories are rejected and
finality stays terminal. Ordered replacement chains and
duplicate collapse pass; reversed/equal-order edges, after-finality
transitions, reorg conflicts, cycles, branches, and unorderable snapshots are
non-countable. Malformed nested receipt, occurrence, object-join, transaction,
event, and ordering forms fail closed without raising.

`blockRef.id` is required while `blockRef.height` is optional and, when present,
is the canonical ASCII unsigned-decimal string `"0"` or `[1-9][0-9]*`; id-only
and `"0"`/positive heights pass while signs, whitespace, Unicode digits,
leading zeros, decimal points, exponents, and container/empty forms fail
closed. The declared `demos-bft-final` inclusion-final binding compresses
`submitted`/`accepted` directly to `finalized`; undeclared profiles,
cross-profile histories, and post-finality reorg remain non-countable.

The type-boundary arms require the exclusive
`authenticatedWindowDerivationVersion: "1"` discriminator and
`verified-business-outcome-occurrence` basis. Released derivation shapes never
satisfy a current-profile request. Every one of the five released
discriminators has a current-rejection case and an exact historical object.
The historical positive uses an explicit verified adapter projection bound to
the trusted policy, authority, producer, session, exact profile/commit,
pre-current revision, and `sha256(JCS(exact unsigned derivation object))`.
Independent discriminator, party, lower/upper window, bundleRefs, metrics, and
applicable resolutionContext mutations reject. Era evidence authenticates era,
not metric correctness.

`input` models one authoritative bundle after external reconciliation and RSV,
plus all known anchor and outcome evidence histories. The independent test
evaluator executes the actual `evaluate` → `resolve_current` and replay
countability/membership path. Its exact-object binding-adapter records and
`nativeOrder` are fixture-only projections with trust supplied separately by
the verifier; they are not wire fields, registered authorities, native proof
verification, or a production adapter. The set does not independently execute
two-copy reconciliation, RSV, or the full `tests/dacs5_reference.py` reputation
engine, and remains candidate pending an external cross-run.

### `reputation-participation-admission-v0.7.json` — DACS-5 v0.7 §10.3.2/§10.5 SPA-1..SPA-8

170 candidate vectors exercise the current one-sided-blame and rating consumers.
Both consumers admit only through verifier-owned `trustedContext` outside caller
input, which binds the exact session and authenticated participant identities to
the immutable corrective-profile release pin and complete module tuple
CORE 0.3 / DACS-1 0.8 / DACS-2 0.6 / DACS-3 0.6 / DACS-4 0.8 / DACS-5 0.7. The
caller `currentProfile` boolean and any copied profile object are inert; an
omitted `trustedContext` field fails closed exactly like an explicit `null`, as
do unauthenticated, duplicated, or pin/tuple/session/identity-mismatched
authority, all before blame or rating countability, with dedicated negatives for
each condition in both modes.

Positive participation arms cover source-backed vet, fixed-price, exact signed
RFQ turn/derived responder, exact authenticated pre-cosign Agreement commit, payment, and
delivery obligations. The admission and `TimeoutMarker` carry the same closed
typed obligation, and the separate admission address ends in
`sha256(JCS(exact obligation))`. Signature payload, `AttestationRef.contentHash`,
and receipt `contentHash` all use the same unsigned RFC 8785 JCS artifact hash.

The shared evaluator applies one unsigned-JCS signature and global-unique-roster
gate while preserving each artifact's actual schema: participation remains
closed and ratings permit signed `freeText`/`dimensions`. Re-signed negatives reach semantic checks
for unknown members, duplicate roles/claims, cross-job/Listing substitution,
RFQ message hash/sequence/responder mismatch, commit-proposal mismatch, typed
timeout mismatch, outsider challenge issuance, and invalid phase/action/prefix
bindings. Producer nonce freshness/reuse claims and issuer-role/delegation flags
are inert. The fixture-only challenge adapter authenticates direct counterparty
issuance or, for an in-roster orchestrator, an exact signed `actingFor` relation
to that counterparty; missing delegation is indeterminate and contradictory
delegation rejects. This models CORE SN-1/SN-3 without inventing a global nonce
index or adding a portable admission field.

Admission receipts retain portable CORE `evidence: {kind, value}` wire shape;
its canonical value contains an Ed25519 fixture-adapter signature binding every
receipt field, native order/replacement/root metadata, and the obligor-authorized
writer relation. Because the exact signed `receiptHash` covers `writer`, a
different nonempty delegated native writer remains valid when that trusted
adapter authorizes it for the obligor; it is not required to equal the DACS
signer. `nonce` retains its portable CORE optional-string shape, including no
global nonempty requirement. Non-selected receipts likewise preserve optional
`blockRef.height`/`timestamp`, while the selected finalized participation receipt
still needs `timestamp` for its deadline comparison. Negatives substitute
transaction, writer, nonce, native order, and unsigned artifact hash; provide
marker-only, absent-selected, conflicting-finalized, and illegal-post-finality
histories; and demonstrate that `evidenceValid`, `writerAuthorized`, and
`historyDisposition` booleans authorize nothing. The evaluator collapses
byte-identical snapshots, requires the exact selected receipt in canonical
history, and requires one complete unique authenticated root-to-selected lineage
under CORE lifecycle/native ordering before countability. Incoming-predecessor
positive and missing/disconnected/branched/cyclic/late/final-predecessor
counterexamples prevent selection from treating the final transaction as its
own origin.

The DACS-3 source verifier hashes unknown signed envelope members rather than
stripping or closing them. A source-pinned synthetic pre-cosign Agreement uses
the actual required DACS-3 structure and an exact opposite-party
`AgreementSignature` over the `signatures`-omitted hash. Job, Listing, party
claims/bundle hashes, artifact/commit kind, negotiation pattern, and the fact
that the obligor has not already validly co-signed are checked before the
obligation is admitted. Missing source/key support is indeterminate; malformed,
contradictory, substituted, or invalidly signed source authority rejects.
Fixture cryptography is explicitly dispatched:
Ed25519/raw-key fixtures execute, registered algorithms or key resolution not
modeled here are indeterminate, and unknown/invalid algorithms reject. Signed
list/object malformed forms exercise total failure/indeterminate handling.

`RatingRecord.ratedAt` is checked as a CORE finite safe-magnitude JSON number;
booleans and container/string forms reject, while fractional and negative values
remain compatible because the current contract does not narrow the field to a
nonnegative integer timestamp.

Timeout and rating positives use the explicitly fixture-only
`dacs-test-exact-session-outcome-v1` adapter signature over exact
job/bundle/Listing/roster/phase/obligation projections. Missing, forged,
unsupported, or conflicting outcome proof propagates to excluded,
`currentWindowCountable: false` with no alternate blame. Elapsed deadlines and
publication never establish nonresponse or abort causality. This corpus does
not verify native proof bytes, authoritative absence, two-copy reconciliation,
RSV, or a production outcome adapter; production Demos nonresponse authority is
unavailable and is modeled only by the non-countable arms. The set remains
candidate pending an external cross-run.

### `reputation-settlement-semantics-v0.4.json` — DACS-5 v0.4 §10.5.1 RSV-1..RSV-4

24 candidate vectors for the DACS-4/DACS-5 composition edge under the
structurally distinct settlement-verified derivation types: the selected
authoritative bundle's presented SettlementEvidence must pass independent
semantic authority before the job enters reputation, after two present copies
have agreed on the exact reference multiset. The positive arm admits
one verified completed job and counts the Agreement price once. One-field
adversarial arms reject amount, payer, payee/destination, session, phase, rail,
and finality contradictions. Transaction rejection and authority-indeterminate
arms both exclude the job without fault. A semantically invalid `failed-perm`
bundle pins the symmetric denominator effect. Legacy-agreement arms carry the
full DACS-4 LAA-1..LAA-7 admission input in `laa` and run the shared LAA oracle
against the successful payment rather than trusting a precomputed disposition:
`fail`/`error` rejects, `indeterminate` stays indeterminate, and a historical
`pass` is current-ineligible — excluded from every current numerator,
denominator, rating, volume, `bundleCount`, and `bundleRefs`. An omitted,
malformed, or unknown `laa` input is non-authorizing and rejects the bundle
member, never default-accepting it.

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
the historical RB-6 discovery-only `absent` path. This set predates RSC and
does not establish v0.8 current new-session eligibility: its active/no-binding
`pass` is only the frozen RB discovery result consumed as inert input by the
current profile.

Two multi-surface cases pin RB-6 precedence: a verified marker wins over an
active mirror, while an indeterminate revoked record prevents another active
mirror from manufacturing a clean absence result.

Each entry in `vectors[]` carries `surface`, `markerRead`, optional binding or
signature overrides, and `want` with the exact `RevocationCheck`, session
effect, and failing step. The common `fixtures` block holds the listing context,
signed markers, bindings, and producer-only Demos write inputs. Cross-running
against the offered producer and reader fixtures remains pending.

### `revocation-state-completeness-v0.8.json` — §6.3.4 RSC-1..RSC-10

101 candidate vectors make current non-revocation independently reproducible.
They bind a stable state-line locator and checkpoint into the signed Listing,
verify genuine deterministic Ed25519 signatures on every Listing, state head,
and marker, authenticate the selected head as the latest finalized native value,
replay the checkpoint chain, and recompute compact 256-level sparse-Merkle
append and query proofs byte-for-byte. Head and marker `authority.evidence` is a
signed `(claim, key, validAt)` key-lifecycle attestation verified against each
artifact's finalized inclusion state; omission, wrong container, attacker
substitution, or nested malformation is `indeterminate`, never `absent` or
`revoked`.

Admission is verifier-owned corrective-profile admission (CORE §11.1.2): the
exact release pin and complete module tuple are session- and identity-bound, and
a caller-supplied `currentProfile` boolean or profile copy has no authority.
Missing, mismatched, incomplete, session- or identity-mismatched, or
unauthenticated admission fails closed before any listing interpretation.

Positive controls cover current non-membership in a tree containing another
listing's revocation and a revocation signed after an authenticated key
rotation. Adversarial cases cover a censored tombstone, stale but valid signed
head, two valid children of one head, a higher-known authenticated head that
revokes the target, corrupted non-membership, unavailable latest-state evidence,
cross-tuple replay, unresolved marker, rollback below the Listing checkpoint,
unauthorized and corrupted rotation keys, wrong signer key, wrong signature
algorithm, missing state reference, history gap, missing profile admission,
producer time substituted for current-state authority, omitted or substituted
conflict-observation sets, later conflict-set rewrites and removal transitions,
list- or scalar-valued `blockRef`/authority containers, and a missing, stale, or
hash-mismatched finalized listing receipt. Malformed nested proof containers,
independently re-signed Listings whose `revocationState.anchor` is a list/string/
locator-less object, list- or null-valued authority keys, list-valued
Listing/head/marker signature values, and non-object root inputs are all
non-authorizing `indeterminate`, never an evaluator exception.

The Listing is a signed artifact (there is no bare `authenticated` boolean), and
the authority/current-state dispositions remain projections from the pre-existing
key-lifecycle and substrate-proof validators. The current-state signature binds
the exact Listing content hash, its finalized receipt, and the complete
known-conflicting-head set, so the Listing and its revocation non-membership are
evaluated in one authenticated finalized state. Every historical head receipt is
self-binding: writer, transactionRef, nonce, blockRef, evidence, finalityProfile,
and native ordering are recomputed, so a provenance mutation is `indeterminate`,
never `pass`. The independent evaluator recomputes all corpus signatures, artifact
hashes, receipt bindings, transition roots, current inclusion/non-membership roots,
and exact tuple relations. Missing or conflicting proof is always `indeterminate`;
only verified inclusion returns revoked and only verified current non-membership
permits the session.

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

### `sb3-binding-required-v0.8.json` — §9.5.8 SB-3 required-binding gate

22 candidate vectors pin the DACS-4 v0.8 four-value result after a rail's
authenticated definition declares settlement-side binding. A verified match
continues to the ordinary transfer checks; a verified mismatch fails; missing,
RPC-unavailable, pruned, signature-unavailable, or reorged binding evidence is
non-countable `indeterminate`; malformed, structurally invalid, or unknown-state
evidence is `error` without raising. None of those
non-match paths uses the unbound posture or creates party fault.

The corpus makes an otherwise exact unrelated transfer inert, ignores caller
and unproven-legacy downgrade hints, and makes unavailable authenticated rail
policy itself indeterminate. Controls retain the explicitly weaker SB-1/SB-2
posture only when the signed pinned RailDefinition declares no binding, and
prove that even a satisfied binding does not bypass the remaining transfer
checks. Every outcome also pins DACS-5 final-verification and reputation
eligibility.

Regenerate and execute with:

```sh
python3 scripts/generate_sb3_binding_required_vectors.py --write
python3 scripts/generate_sb3_binding_required_vectors.py --check
python3 -m unittest tests.test_sb3_binding_required_vectors -v
```

### `settlement-event-identity-v0.6.json` — §9.5.8 SB-1 signed projection

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

The set includes batched transfers with distinct keys, missing and malformed
coordinates, a signed-index/ledger mismatch, legacy unambiguous
and ambiguous replay, discriminator stripping, cross-type signature replay,
three independently signed full-address mismatch negatives, and a CF-4 rail
segment positive. Its retained `same-event-second-job-rejected` result records
the historical first-claim behavior only: the top-level `conformanceProfile`
machine-limits current applicability to SB-1 identity projection and same-tuple
idempotency and points collision authority to `sb2-collision-authority-v0.8`.
Regenerate and execute it with:

```bash
python3 scripts/generate_settlement_event_identity_vectors.py --check
python3 -m unittest tests.test_settlement_event_identity_vectors -v
```

### `sb2-settlement-uniqueness-v0.1.json` — historical SB-2 key canonicalisation

These 20 retained candidate vectors established canonical `settlement-tx-id`
formation, malformed-key refusal, and idempotent same-tuple behavior under the
original SB-2 consumer-ledger model (#161, commit `072dc33`). Their historical
`decision`/`effect` values for a cross-tuple collision used first-observed state
and are superseded by DACS-4 v0.8 and `sb2-collision-authority-v0.8.json`; they
MUST NOT be cited as the current collision-authority rule. The reusable key
forms are:

- **evm / x402:** `evm:{chainId}:{txHash}:{logIndex}`
- **solana:** `solana:{cluster}:{signature}:{instructionIndex}`

with SB-1's canonicalisation enforced: `chainId`/`logIndex`/`instructionIndex`
decimal with no leading zeros; `txHash` lower-case hex with no `0x` (so a `0x` or
upper-case re-spelling **collapses to one key** and cannot dodge the consumed
set); `signature` base58 decoding to **exactly 64 bytes**; and a malformed ref
(wrong-length / odd hex / non-64-byte base58 sig / missing coordinates) →
`error`, **never minting a distinct key**.

This set was built off the SN-4 single-use template, scope-inverted to
settlement (cX3po, #159 / #161). The historical `pathos-dacs-ref` and
`mj-deving/dacs-verify` implementations agreed on 6/6 sampled EVM decisions;
that result is provenance for the frozen v0.1 model, not v0.8 conformance.

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

The frozen vectors remain runnable as historical data by feeding each `record`
+ `consumed` to the old adapter and asserting `(decision, effect)`. The
reference run lives in `pathos-dacs-ref`:

```
npx tsx conformance/security-vectors/sb2-settlement-uniqueness/run.mts
# → 20/20 vectors pass
```

### `sb2-collision-authority-v0.8.json` — §9.5.8 SB-2 collision authority

32 candidate group vectors execute the current rule over a complete presented
evidence set. A finalized per-settlement relation must match the canonical
settlement ID, authenticated pinned rail/profile, job, and phase before it can
select that tuple and reject competitors. Authority for one group cannot select
the same tuple in another. Missing/mismatched dimensions, unavailable or pruned
evidence, non-final/reorganised authority, or conflicting purported finality
leave every competitor `indeterminate`. EIP-3009 supplies the exact-phase
positive; current Permit2 and AP2 job-only bindings leave same-job cross-phase
groups unresolved even when a caller appends a phase field. Malformed authority
is `error`; an exact binding to no presented claim rejects all claims.

Producer `observedAt`, evidence-hash order, arrival order, and SR-2 anchor order
are inert. The set proves that a stolen claim anchored first cannot win, later
collision discovery removes a provisional count, outer replacement hints
cannot override finalized settlement authority, and an unregistered atomic
first-claim hint grants nothing. Same-tuple repetition remains idempotent and
different event indices in a batched transaction remain separate settlements.
An independent executable DACS-5 consumer regression also proves that late
unresolved collision discovery removes prior bundle count, fault denominators,
volume, and per-currency transaction count without creating party fault.

Regenerate and execute with:

```sh
python3 scripts/generate_sb2_collision_authority_vectors.py --write
python3 scripts/generate_sb2_collision_authority_vectors.py --check
python3 -m unittest tests.test_sb2_collision_authority_vectors -v
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
- **PB-3 gate separation** — an SB-3 binding result cannot bypass PB-2 and a
  PB-2 destination result cannot bypass SB-3. Under DACS-4 v0.8, an absent or
  unverifiable required x402 job binding is independently `indeterminate` and
  non-countable rather than an unbound fallback.
- **Repeated pay phases** — repeated phases are bound independently by
  `(railId, phaseIndex)`.

Artifact gate failures are ordered for exact-vector reproducibility:
discriminator, reader support, legacy `payoutBindings` ban, commit phase,
signatures, then payee-bound payout coverage.

DACS-3 §8.5 defines the `PayeeBoundAgreementDocument` signature input as
`"dacs-payee-bound-agreement:v1:" || agreement_hash`; the cross-domain vectors
also exercise §B.7/SIG-2 by replaying legacy agreement signatures under the
payee-bound domain and vice versa.

The signed fixtures in this corpus carry the released
`AgreementParty.bundleHash` string spelling, including `sha256:`-prefixed
values. Those bytes and the corpus remain valid. Identity-bound agreement
conformance is additive and lives in `identity-bundle-hash-binding-v0.1.json`;
it does not supersede or reinterpret this corpus.

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

### `legacy-agreement-admission-v0.8.json` — §9.5.1 LAA-1..LAA-7 / §8.6 CA-10

One hundred sixty-six candidate cases execute the governed transition from legacy
`AgreementDocument` payment authority to the payee-bound artifacts
(`PayeeBoundAgreementDocument` and the stronger
`IdentityBoundPayeeAgreementDocument`). They cover fixed-address checkpoint
resolution, steward/domain/address/policy authentication, finalized activation
order, binding-qualified pre-activation absence that covers the authenticated
payment-effect head, the stale-absence race across the activation boundary, a
caller-supplied low `paymentPosition` being inert against that authenticated
head, current-session refusal except for the exact finalized pre-checkpoint
commitment plus signed/anchored payment-reservation transition, and CA-10 commitment-phase selection (a commitment
`pass` carrying zero payment side effects while the later payment re-runs LAA).
The transition vectors derive a `LegacyPaymentReservation` from the real
Agreement, signed Listing phase, authenticated session, pinned signed rail, and
actual `PaymentPhaseInput`. Its unique role-bound buyer/seller signatures plus
distinct orchestrator signature when required, and pre-checkpoint receipt with
an authenticated writer equal to the retained orchestrator bind
the runtime `payeeAddress`, job, session, phase/index, authenticated payer/payee
bundle hashes, authorized paying key, amount, currency, rail, terms hash,
deadline, and idempotency key. The exclusive signed
`LegacyTransitionSettlementEvidence` references the exact reservation without
adding an ignorable field to ordinary `SettlementEvidence`; missing, unknown,
coerced, or substituted transition evidence is non-authorizing. Its full
canonical reservation reference must resolve the exact expected logical address
and receipt, its signer and SR-2 writer must equal the retained orchestrator,
and audit authority must prove the exact reservation idempotency key consumed.
Its phase index is a strict non-boolean non-negative integer, and every
transaction reference must be a valid closed-union `ChainTxRef` member in the
duplicate-free exact success set for the authenticated payment phase.
The stateful ledger rejects altered retained session identities, bundles, keys,
or head before storing any reservation;
substitution, repricing, expired/incomparable time, unavailable authority, and
consumed idempotency all remain side-effect free.

Historical cases require the exact party-signed agreement, agreement-hash
commitment, and settlement-evidence binding to carry finalized receipts on one
authenticated substrate and one exact consensus ordering domain, strictly
before the checkpoint. The settlement-evidence receipt MUST bind the exact
authenticated agreement hash, job, session, and phase of the agreement whose
commitment is being qualified; an authentic receipt for a different agreement,
job, session, or phase is a replay and cannot qualify this agreement's history.
Authenticated absence on another substrate is inert; cross-order-domain scalar
positions are never compared. Backdated `generatedAt` or `observedAt`, a late
presentation/re-anchor, ordinary not-found, non-final receipts, same-position
ambiguity, checkpoint conflict/reorg, and unavailable proof cannot manufacture
current payment authority. Concrete malformed inputs — a non-object agreement
or checkpoint container, a commitment missing a required field, a missing
`agreementBindingMatches` / `agreementHashMatches` / `contentHash` /
`signatureValid`, a non-string receipt position, an unhashable list/dict
operation, artifact, or position, an unknown receipt state, a malformed
same-block native-order flag, a malformed authenticated payment-head position,
and a conflicting checkpoint discriminator — return the four-value `error`
disposition rather than raising, never `fail`, `indeterminate`, or an
uncaught `TypeError`/`AttributeError`. Structural validation precedes every
authorization early return: `operation` must be a scalar member of the closed
LAA operation vocabulary and the agreement must carry a scalar `contentHash`
before any payee-bound / identity-bound / zero-pay / authenticated-absence
branch may authorize, so a payee-bound or identity-bound agreement missing
`contentHash`, and an authenticated-absence branch carrying a malformed
operation, are `error` (never `pass`). The session/hash identity values are
independently verified and non-empty canonical: an empty, whitespace-only, or
leading/trailing-whitespace `agreement.contentHash` or `sessionId` (and any
non-NFC spelling) is malformed and rejected `error` before any payee-bound,
identity-bound, zero-pay, absence, or checkpoint branch may otherwise
authorize, and the `LegacyAgreementLedger` refuses a `commit` / `authorize_payment`
keyed by such an identity. A historical LAA `pass` is
`historical-only` (current-ineligible); an exact post-checkpoint completion is
`transition-only` (payment/audit valid but equally excluded from current
reputation, volume, `bundleCount`, and `bundleRefs`),
never a generic `continue`: it is excluded from current metrics on every bundle
type (`AttestationBundle`, `FaultAttestationBundle`,
`EvidenceBoundFaultAttestationBundle`) and every derivation path (`derive`,
`derive_job_bound`, `derive_settlement_verified`, replay). A bundle whose
successful payment cites a legacy agreement MUST carry the verifier-owned full
LAA input; a missing, malformed, unknown, or caller-only `laaDisposition`
without that full object excludes the bundle from `bundleCount`, `bundleRefs`,
and every metric — never default-eligible. The set carries the
candidate corrective release pin and complete module tuple.

The fake adapter exercises deterministic offline authority fixtures and proves
in-process call ordering and idempotency. It does not claim crash-durable
transactionality, native proof codecs, live-provider reconciliation, or
production conformance.

Regenerate and execute from the repository root:

```sh
python3 scripts/generate_legacy_agreement_admission_vectors.py --write
python3 scripts/generate_legacy_agreement_admission_vectors.py --check
python3 -m unittest tests.test_legacy_agreement_admission_vectors -v
```

### `domain-claim-gcr-v0.4.json` — DACS-1 §6.3.1 DCR-1..DCR-8 / DACS-2 §7.3.10 DGCR-1..DGCR-6

Sixty-three deterministic cases cover canonical `domain:` production,
signature-preserving historical `web2:domain:` reads, semantic deduplication,
presentation-bound control, and authenticated finalized Demos GCR verification.
All bundles are deterministically signed with genuine Ed25519 operations; two
negative cases deliberately corrupt their resulting signatures. Every registration
proof carries a valid deterministic Ed25519 signature.

Cases carrying `producerInput` require an adapter to invoke its public current
DACS-1 domain producer/serializer and compare every emitted ClaimReference plus
the complete unsigned artifact with the signed `artifact.unsigned`. Replaying
the supplied artifact through a reader is not a producer result; an adapter
without the producer boundary records `status: "abstain"` under `CROSS-RUN.md`.
Reader-only cases apply permanent legacy compatibility from the verified
`bundleVersion: "1"` bytes and alias spelling alone. Exact `domain:` spelling
is scheme-selected without any profile sidecar, current production rejects
single and dual legacy-alias emission in claims and `presentedBy`, and mutable
deployment state cannot reclassify retained bytes. Paired signed and
signature-corrupted malformed-host rows require `error` only after successful
signature verification and `fail` before normalization otherwise.

Regenerate and execute from the repository root:

```sh
python3 scripts/generate_domain_gcr_vectors.py --check
python3 -m unittest tests.test_domain_claim_gcr_vectors -v
```

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

### `channel-message-replay-v0.1.json` — frozen historical Demos read arm

These 15 vectors are frozen byte-for-byte as the historical
`LegacyDemosChannelMessage` corpus. They remain executable for explicit
read/import compatibility and MUST NOT be treated as current producer examples.
The historical object has no message discriminator, carries a bare
128-lowercase-hex signature, and signs the **raw 32-byte** digest under
`"dacs-channelmsg:v1:"`. It is selected structurally before crypto and never as
a fallback after current-message failure. Within that historical arm, admission
requires all of:

- **CH-6** — the session's `channelId` MUST NOT be one reused from a prior session
  according to the verifier-owned retained registry; a reused session channel
  → `fail` (the whole session is rejected).
- **channel binding** — `message.channelId == sessionChannelId`; a foreign-channel
  message (a genuine message from another session presented here) → `fail`.
- **signature** — over `UTF8("dacs-channelmsg:v1:") || raw_32_byte_sha256(UTF8(JCS(envelope − signature)))`
  by the independently authenticated channel member key. The retained historical
  `cci:<hex>` spelling is not membership authority. A known algorithm mismatch
  → `fail`; matching authenticated metadata with unavailable key bytes →
  `indeterminate`; an invalid signature → `fail`.
- **monotonic sequence** — strictly greater than the highest already seen in the
  channel (starts at 1, §8.3.3); a duplicate or decreasing `sequence` → `fail`.

A cross-session replay fails **both** ways: keep the old `channelId` → channel-binding
`fail`; rewrite it → the signature (computed over the original `channelId`) breaks.
Malformed artifacts or malformed trusted setup return `error`. The frozen
`ctx` field is retained test metadata, compared against independently reviewed
setup in `tests/channel_message_fixture_authority.py`; it never initializes
state from the presented candidate. The runtime evaluator accepts a previously
issued state capability, not a `ctx` object.

#### Vector schema
| field      | meaning |
|------------|---------|
| `name`     | stable case id |
| `expected` | §7.5.1 verdict (4-value, never collapsed) |
| `message`  | the `LegacyDemosChannelMessage` under test (channelId, sequence, sender, signature, body…) |
| `ctx`      | frozen scenario metadata; compared with separate trusted harness configuration, never state authority |

Signatures are real Ed25519 over the frozen historical scope; member/key
authority and initial state are supplied independently by the harness. Each
fixture is an isolated verifier lifetime. Within a lifetime, a caller-supplied
retained registry preserves identifiers, sequences and terminal status across
issuer facade reconstruction; live and audit registries are distinct. This
in-memory reference does not establish durable restart or distributed-storage
guarantees. Production adapters must retain transactional state for their replay
horizon and demonstrate continuity across restart. The shipped executable oracle is
`python3 -m unittest tests.test_channel_message_vectors`; it replays all 15
persisted cases and pins the complete legacy file SHA-256. The previously cited
external TypeScript runner is not part of this repository and is not the
conformance authority.

### `canonical-channel-message-v0.6.json` — §8.3.3 CH-6..CH-10

55 deterministic cases for the discriminated current
`CanonicalChannelMessage` and its strict historical boundary. The current arm
uses `canonicalChannelMessageVersion: "1"`, a versioned
`ChannelMessageSignature`, SIG-6 unpadded Base64URL, and exactly:

```
UTF8("dacs-canonical-channel-message:v1:")
  || ASCII(lowercase_hex(sha256(UTF8(JCS(message − signature)))))
```

Current-wire sender/signer identities are canonical registered DACS-1
claims: the Ed25519 members carry `key:<64 lowercase hex>` primary-key
references and the non-Ed25519 algorithm fixtures carry `did:` references.
Before issuing current live state, the harness requires verifier-owned exact
release-pin, complete module-tuple, session, and authenticated-participant
admission. The corpus covers missing, partial, wrong-pin, duplicate-participant,
session-mismatch, identity-mismatch, and unauthenticated authority; the frozen
`legacy-import` arm is non-live and exempt. It also distinguishes absent
optional `refs` from malformed explicit `refs: null`.
The historical generic `cci:<64hex>` spelling is unregistered on the current
wire — an otherwise correctly signed message carrying it is refused by
`current-read` while the canonical `key:` spelling of the same key passes —
and it remains readable only through the explicit `legacy-import` arm for
frozen archival bytes.

The caller-selected `operation` is `current-read` or `legacy-import`; it is
trusted harness policy, not a message member or a wire-shape inference. The same
valid frozen legacy bytes reject on `current-read` and pass only on the explicit
`legacy-import` operation.

The corpus covers valid first/next/gapped sequences; positive, tampered,
cross-domain, and wrong-framing examples for Ed25519, ECDSA-secp256k1, and an
authenticated `sr1-root` aggregate signature; duplicate/decreasing,
foreign-channel and reused-channel rejection; unavailable sender authority;
an otherwise-valid outsider signature and a member signature made by the wrong
key against the verifier-owned authenticated member/key capability; CF-3
matching of a parameter-qualified sender and signer to the one member identity;
tampering; padded/standard-Base64/hex value rejection; unknown message and
signature versions; unknown algorithm and algorithm/key confusion; closed
signature-envelope shape and integer/member boundaries;
signer/sender mismatch; SIG-5 unknown-field preservation; current/legacy
cross-domain replay; raw-versus-ASCII-hex framing in both directions; and the
four explicit mixed-wire barriers (discriminator + bare hex, no discriminator
+ current envelope, discriminator + raw-digest signature, and historical shape
+ hex-digest signature). A frozen historical positive also records the exact
Base64URL re-encoding of its raw signature bytes without representing that
re-encoding as a current signature.

Generate/check with
`python3 scripts/generate_channel_message_vectors.py --check`; execute every
current, mixed, and frozen historical verdict with
`python3 -m unittest tests.test_channel_message_vectors`.

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
production or replay authority; `versionsByFamily` supplies the complete numeric
version inventory plus availability. Its greatest numeric member determines the
implicit pin before eligibility; `latestByFamily` is an inert legacy hint. Parameter
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

### `settlement-finality-verification.json` — unallocated #392 FV-1..FV-10

Sixty-seven candidate cases execute consumer-verifiable settlement finality for
block-depth, commitment-level, BFT-final, provider-receipt, HTLC, and
liquidity-tank profiles. The consumer derives the model and strength from the
exact authenticated RailDefinition; the signed `SettlementFinalityRecord` is
always treated as a producer report, never as proof.

The fixture-only proof codec uses raw JCS-encoded transaction, event and header
bodies, Merkle relations, every ancestry link, independently pinned Ed25519
observation/provider authorities, and weighted BFT certificates. Cases cover
network, genesis, transaction/index, proof/root/path, quorum/key, freshness,
provider-byte/attestation, malformed-nested-input and production-codec-unavailable
failures. Provider capture passes only as `provisional-provider-capture`.
HTLC carries four independently verified source-lock/source-claim/
destination-lock/destination-reveal arms and recomputes contract, per-chain
hashlock, preimage, amount and timelock relations from authenticated bytes.
Liquidity-tank verifies coordinator, source and destination arms and exact bridge,
transfer, asset and amount binding.

The same corpus executes the distinct DACS-5 finality-bound bundle and pointer,
all six FV models, non-pass propagation, new/new and new/older authenticated
reconciliation, no weaker fallback, and frozen-reader refusal. The separate
`current-use-reputation-v1.json` corpus composes that consumer with the #391
historical arm. Existing EBFAB and reputation contracts remain unchanged. The
synthetic fixture policy is not a registered live substrate policy; native
production proof-wire support remains unavailable.

Regenerate and execute from the repository root:

```sh
python3 scripts/generate_settlement_finality_verification_vectors.py --write
python3 scripts/generate_settlement_finality_verification_vectors.py --check
python3 -m unittest tests.test_settlement_finality_verification_vectors -v
```

### `current-use-reputation-v1.json` — unallocated #391+#392 LAB-1..LAB-7 / CUR-1..CUR-8

Eight candidate fixtures drive the complete stronger DACS-5 consumer path. Six
compose the finality-bound bundle consumer with every FV model, exact RSV and
applicable SB-3 checks; the provider-receipt case remains classified as
provisional capture. Two retain the complete original requests for the legacy
write-input BundleBinding and deterministic pure-mapping arms.

Every vector embeds the complete executable replay input: the exact request, its
full authenticated dependency closure, the verifier configuration with public
keys, the trusted query context, and the expected outcome. The set hash binds
these complete replay inputs, so each case is independently executable from the
committed JSON alone and any authority, receipt, finality, or
historical-evidence mutation changes the bound payload and yields a non-pass
decision.

The focused executable tests mutate every duplicated historical join, checkpoint
discovery and external trust, BB-6 standing/budget/admission order, role absence,
new/older precedence, required settlement binding, metrics and replay inputs. They
also execute old-reader refusal and malformed-container totality, and the
JSON-only replay corpus tests re-execute the committed bytes and their mutation
boundary directly. Native anchor
and settlement-binding proofs are independently pinned signed synthetic fixtures
for offline testing only; they do not define a production Demos proof codec.

Regenerate and execute from the repository root:

```sh
python3 scripts/generate_current_use_reputation_vectors.py
python3 scripts/generate_current_use_reputation_vectors.py --check
python3 -m unittest tests.test_current_use_reputation_vectors -v
python3 -m unittest tests.test_current_use_replay_corpus -v
```

### `current-use-authenticated-window-v1.json` — CUAW-1..CUAW-6

Fifteen executable fixture-only cases compose all-jobs CUR admission and
reconciliation with independently signed business-outcome occurrence. They
cover all six finality models, both historical mapping arms, a signed two-phase
payment-then-rate session whose payment evidence is inside the query window
while the terminal outcome is outside, retention and mutation of outside-window
replay context, missing proof for one requested job, and fail-closed sealed
selection without independently reproduced SAC-8 authority. Two signed-Listing
`pay-alternative` cases exercise structurally valid projected and wrong-rail
effective pipelines, both refused before outcome-proof lookup because this
bounded reference does not independently reproduce APR-1..APR-4 authority.
It does not implement a positive APR or SAC-8 adapter or a production native
outcome proof codec; those remain separate conformance work and cannot be
inferred from a fixture-only pass.
The bounded CUAW reference also has no positive SPA evidence adapter: it
refuses one-sided fault attribution without SPA authority and leaves ordinary
ratings uncounted without SPA-7. The separate participation corpus exercises
positive admission; this CUAW set does not establish combined positive
CUAW+SPA conformance or production nonresponse authority.

```sh
python3 scripts/generate_current_use_authenticated_window_vectors.py --check
python3 -m unittest tests.test_current_use_authenticated_window_vectors -v
```

### `presence-only-claim-requirement-v0.7.json` — §6.3.3 PCR-1..PCR-6 / §7.7.1

Forty-seven candidate cases make `ClaimRequirement.verificationRequired: false`
executable across DACS-1 matching and DACS-2 composite replay. Every ordinary
bundle and composite record carries a deterministic Ed25519 signature; vectors
that use a real verification result sign it under the independent VerifyResult
domain and supply the independently authenticated signer for each recipe family
through trusted evaluator context. The signature-negative cases cover both a
mutated signature and a valid signature made by an unauthorized replacement
signer while preserving the referenced content hash.

Coverage includes required and `oneOf` presence, expiry and parameter checks,
informational `issuedAt`, optional failing/stale/unavailable `verifiedBy`,
malformed references, invalid presence-only `maxAge`/`recipeVersion`, mixed
presence and verified members, no-synthetic-result enforcement, exact bundle
and requirement hash replay, missing replay input, decision recomputation, and
the authenticated VerifyResult-authority boundary, plus the controlled-key
versus existence-only-LEI selector boundary. Verified parameters use only
authenticated result method/data while presence parameters use signed claim
metadata; one result may satisfy multiple predicates only when its data matches
each. The complete ordered `freshness` + `dealSpecific` projection is bound
before artifact authentication. Signed `generatedAt` reconstructs historical
decisions, while independently retained current time governs reusable results;
distinct session jobs and verifier-issued nonces remain outside reusable
VerifyResult v1 artifacts. Exact-boolean mode selection, canonical DID percent
bytes, safe-integer times, malformed time containers, vacuous empty member
collections, and invalid empty inner `oneOf` groups pin the configuration edges.
The signed bundle and the existing CVR `bundleHash` remain the presence evidence
and binding; the bundle's existing `sessionNonce` conveyance is consumed against
verifier-owned issuance state.

Production acceptance uses independently retained phase-input requirement and complete bundle hashes, an authenticated session-start record, and equality of the phase/session/registry revision pins. It validates required Composite members before resolving the complete ordered reference union. The actual acceptance entrypoint requalifies a historical pass at independently trusted current time and fails closed when the production bundle is unavailable. Historical fixture reconstruction is a separate non-authorizing diagnostic; this pack does not implement signed DACS-5 bundle/recordRef replay admission. Source AttestationRef signer omission and a distinct issuer remain valid under the existing wire shape.

This remains an offline conformance model: it authenticates the committed
VerifyResult bytes, reference hash, registered recipe-family signer, and the
signed source-attestation reference carried by that result. It does not fetch a
live authority, prove durable nonce storage across process restarts, or promote
the referenced source attestation to independently resolved live-provider
evidence.

Regenerate and execute it from the repository root:

```sh
python3 scripts/generate_presence_only_claim_vectors.py --check
python3 -m unittest tests.test_presence_only_claim_vectors -v
```

### `job-id-grammar-v0.1.json` — CORE §B.1 JID-1..JID-4

Forty-seven deterministic cases pin the complete canonical DACS `jobId`
grammar, byte-exact comparison, logical-address insertion, and the DACS-5
bundle-address preimage. Invalid case, alias, overflow, whitespace, Unicode,
type, and length inputs execute through an instrumented gate that must make
zero hash and resolver calls. The buyer, seller, and orchestrator bundle cases
also carry literal address known answers independent of the generator.
Profile-admission cases receive separate verifier-owned context and require it
to bind the exact session and authenticated peer identity to the configured
release pin plus complete module tuple. Missing, duplicate, identity-mismatched,
session-mismatched, or unauthenticated records refuse; caller-supplied matching
objects or copied reference labels do not establish admission.

Regenerate and run with:

```sh
python3 scripts/generate_job_id_grammar_vectors.py --check
python3 -m unittest tests.test_job_id_grammar_vectors -v

```

### `identity-bundle-hash-binding-v0.1.json` — CORE §B.2 IBH-1..IBH-6

These candidate vectors execute the distinct identity-bound agreement paths
without changing any released carrier. Deterministic Ed25519 fixtures include
complete signed Listings, all four signed agreement artifact types, both
commitment-record forms, distinct one-use session-bound IdentityBundle
presentations, signed CVRs with signed VerifyResult material, payment inputs,
terminal EBFABs, and signed prior-payment dispositions. A generalized
fixture-only receipt adapter independently observes commitment, agreement, CVR,
disposition, settlement-evidence, and terminal-bundle dependencies and verifies
native transaction, exact logical/native location, content, writer, nonce,
block ordering, and fixture-finality bindings. Its deterministic cryptography
is not a production-native codec and does not claim Demos or any other
live-substrate consensus verification.
The evaluator verifies cryptography, authenticated production/replay context,
and DACS-2 §7.7.1 aggregation directly; no producer success boolean, asserted
digest, signed `overallDecision` label, or caller role label is proof.

Coverage includes the 4×4 signed phase/artifact matrix, 4×4 cross-domain replay
matrix, closed-PhaseType refusal at all three stage entrypoints, exclusive
discriminator failures, explicit stronger-path downgrade,
presentation signer and distinct verifier-challenge checks (including
consumed-on-failure, bounded lifetime, changed/re-signed reuse, exact retained
admission, and missing-authority refusal), exact CVR reference/job/claim/digest/
requirement/result joins and replayed aggregation, every cross-stage hash
position, payment job/role/key joins, separate-orchestrator binding, mandatory
negotiate→commit ordering, precommit payout coverage, genuine APR projection at
the exact slot, signed/finalized replacement disposition including
closed-cannot-settle evidence, complete EBFAB payment/delivery evidence, and
finalized agreement/CVR/commitment/bundle dependency joins. It also preserves
old and identity-bound sealed-envelope losing-bidder controls, the SE-1
new-session deadline gate over the verifier-trusted session start, and the SE-8
sealed-envelope role-direction assignment (a genuine procurement specimen
assigns the listing publisher as the agreement buyer and the winning bidder as
the agreement seller; a mode marker without the role swap is rejected),
independently authorized fixture-receipt tamper cases, and malformed nested
values that must never escape as language exceptions.

Additional executable regressions preserve non-session Listing publication
without a session nonce across all four agreement types; action-bearing
IdentityBundle companions still require the verifier-issued challenge and exact
authenticated retained admission. Signed wire artifacts alone do not establish
off-chain issuance or one-use retention when that authority is unavailable.
The identity-bound reputation adapter runs these admission checks before
calling the existing DACS-5 metric derivation: a valid control counts one
bundle, while missing or invalid identity proof never invokes the metric
consumer. This is IBH propagation evidence over already verified role-resolution
tags, not a replacement for SR-2/BB-6 resolution or proof of a complete deployed
reputation reader. Historical metric algorithms and derivation types are unchanged.

Historical signed `AgreementDocument` and `PayeeBoundAgreementDocument`
fixtures deliberately retain `sha256:`-prefixed party hashes and verify with
both `CommitmentRecord` and `FinalityCommitmentRecord` without byte rewriting.
The old agreement-reader cases execute a frozen dispatcher modeled from base
`3426faaebc09948d57a3a6d30fd6795df579b68f` because this repository has no
pinned agreement-reader executable. The base DACS-5 reference path is also
executed to prove that unsupported new signed phases are refused before phase
derivation or counting. The focused evaluator executes supported historical
commitment/signature controls; where it lacks a complete historical payment or
terminal stage adapter it returns an explicit non-authorizing `indeterminate`
rather than an unconditional pass or a protocol-invalid judgment. These are
labeled modeled/reference compatibility results, never proof about a deployed
reader. The existing payee-destination corpus remains independently valid and
is not superseded.

Regenerate and execute with:

```sh
python3 scripts/generate_identity_bundle_hash_binding_vectors.py --write
python3 scripts/generate_identity_bundle_hash_binding_vectors.py --check
python3 -m unittest tests.test_identity_bundle_hash_binding_vectors -v
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

The SR2 `method` query and CRQ `recipeDefinitions` projection derive alternative-method
ownership from admitted definition bodies under RA-6. The latter must cover the full
scheme/version inventory; it is not a wire artifact or an unauthenticated alias map.
Legacy CRQ snapshots with no alternatives retain their direct default-method projection.


The current AP2 candidate retains the complete effect-bearing provider request, including mandate, checkout, payee, amount/currency, instrument, destination and metadata, under its operation fingerprint. Same-key recovery dispatches that retained request and refuses changed semantics before provider interaction. Captured recovery must match the operation fingerprint, transaction and retained provider reference. These are local fake-provider controls; mandate cryptographic verification and authenticated status-fetch semantics remain modeled inputs. The entire trusted participant map requires unique identities.

### Complete Recipe fixture follow-up

The generator now constructs a registered `key` / `self-signed` Recipe with
required age, retry and governance fields and a deterministic steward
signature. The signature uses the test harness's `keyId` / `algorithm` / `value`
codec under `dacs-recipe:v1:`; this does not allocate a production signature
wire format or establish live registry-steward authorization. The selector-only
unit projections are not complete wire artifacts.

The renewed bootstrap corpus contains 79 deterministic cases, including three
optional-evidence forward-readability controls. Its dependent hashes,
signatures, references and security-vector index are regenerated, and the
checked-in generator plus integrated reference tests establish byte-identical
reproduction for this fixture profile.
### RSC policy compatibility

The retained `revocation-state-completeness-v0.8.json` corpus records the earlier reference policy; its RSC case outcomes and signed inputs remain unchanged, while trusted profile-admission tuples track the current composed release. `tests/test_rsc_current_admission_v2.py` exercises the unsigned common-state comparison and independent content/native capacity checks, not authentication of those fixture labels. `tests/test_listing_admission_bridge.py` demonstrates that partial checks and caller-supplied new-session or committed-session labels cannot issue a direct capability. The pinned IBH test fixture separately verifies its committed chain before installing a retained historical capability. Full ordered DACS-1 and authenticated committed-session evaluators remain required for general positive admission; historical replay results are not fresh admission authority.
