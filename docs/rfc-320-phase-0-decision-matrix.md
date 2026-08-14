# RFC #320 Phase 0 decision matrix

## Status and scope

- **Review base:** `origin/next` at
  `86c3b3bc64d709bd23dc1ac73f5e7b153ece217c`.
- **Source discussion:** [RFC #320 — Atomic DACS Work: protocol, execution,
  evidence, and recovery][rfc-320].
- **Status:** non-normative review artifact. This document records proposed
  answers, current supporting rules, accepted review corrections, unresolved
  contracts, and required evidence. It does **not** adopt a decision, amend a
  rule, approve a Demos implementation, or promote a conformance vector.
- **Adoption rule:** an Atomic rule becomes normative only through an approved
  Standard change with additive/versioned schemas and discriminators where
  meaning changes, plus the required positive, negative, and boundary vectors.
  Existing artifact, receipt, settlement-identity, and signature discriminators
  must not be reinterpreted in place.

The matrix uses three deliberately separate evidence classes:

1. **Existing invariant** — normative text already present at the review base,
   principally [CORE], [DACS-3], [DACS-4], [DACS-5], and the current
   [Demos mapping].
2. **Proposed Atomic-profile rule** — a direction proposed in
   [the DACS-side disposition][proposed-answers] and refined by review. It is
   not part of the Standard yet.
3. **Demos DACS-binding/evidence requirement** — Demos already provides an
   Atomic Work execution primitive; this class does not request that it be
   rebuilt and does not assert that the named behavior is absent. It identifies
   a node/runtime/SDK property that DACS requires but cannot establish by
   specification text. Demos may answer with already-enforced behavior, a
   DACS-specific binding or configuration, or a missing integration. Every
   answer requires an exact implementation pin, authenticated interfaces, and
   reproducible execution evidence.

For each §A.6 item, the requested Demos response uses one of four review
classifications:

- `EXISTING — PIN/EVIDENCE` — the exact release already enforces it; publish
  the interface, node-produced fixtures where applicable, and repeatable proof;
- `EXISTING — DACS BINDING` — the primitive exists but needs an exact DACS
  mapping, profile, configuration, or SDK surface;
- `NEW — IMPLEMENT` — the pinned release needs node or SDK work; or
- `UNAVAILABLE — PROFILE/FALLBACK` — the profile cannot claim the guarantee and
  must narrow its capability or use the pre-signing fallback.

This classification is review metadata, not a new wire value or capability
field.

“Accepted reviewer correction” below means accepted *within the RFC
discussion* in [the execution-evidence follow-up][accepted-corrections]. It
does not mean steward adoption or Standard approval.

## Current evidence-classifier boundary

Draft PR [#322][pr-322] currently contributes a **52-vector post-verification
evidence classifier** at [exact head][pr-322-current]
`e26e3e4bc873dfc3c34be1a12adef8c2d88ecc67`. Its API is
`classifyVerifiedWorkEvidence(...)` and its positive classification is
`coherent`.

The classifier is proposed, non-normative, and **not a cryptographic proof
verifier**. It performs no signature, Merkle-path, quorum/finality-certificate,
validator-set, or proof-subject verification. It classifies detached
upstream-produced verification-result statuses for structural consistency.
Its 52 cases are useful candidate evidence-classification vectors for parts of
questions 6, 8, 10, and 11; they do not establish the receipt cryptography,
the Demos runtime guarantees, or complete Phase 0 coverage. Exact-head review
approval is expressly limited to that artifact and is not approval of RFC #320,
readiness, merge, or normative promotion.

## Ownership boundary

| Layer | Proposed responsibility |
| --- | --- |
| DACS Standard | Normative Atomic profile meaning; canonical schemas and domains; lifecycle, role, evidence, and recovery rules; implementation-neutral vectors. |
| Demos runtime/node | Consensus execution overlay; cross-Work compare-and-set; fees/nonces; attempt and winner ledger; authenticated receipts, status, lifecycle, state, and absence proofs; crash consistency and resource limits. |
| Demos SDK | Typed construction, signing, submission, status, and proof-verification surfaces over the proven node contract. The reported Node 22 export problem is closed; the DACS-specific API binding and runtime evidence still require an exact release pin. |
| DACS SDK | Version-pinned safe abstraction, orchestration journal, idempotent reconciliation, receipt/evidence verification, and compatibility handling after the Standard and Demos contracts stabilize. |
| Reference integrations | Capability-gated shadow/canary integration and failure injection. They may demonstrate interoperability but do not define Demos consensus behavior or normative DACS meaning. |

The Demos-side response [confirms ownership, the existing Atomic Work
foundation, and reusable work][demos-response], including SR-4
agreement/commitment surfaces and existing nonce/idempotency work. The open
question is not whether the generic primitive exists. It is whether one exact
release binds that primitive to every DACS-specific operation, cross-Work
payment-uniqueness, role-authorization, receipt, proof, and recovery rule below.
The response is not yet that exact runtime pin or reproducible evidence.

## SR-2 resolution boundary from issue #242

The [complete issue #242 discussion][issue-242] remains relevant to every
Atomic `storage-program-put` projection. A verified `AnchorReceipt` proves its
lifecycle and bound tuple; it does not by itself prove that its writer controls
the claimed logical address. A pre-bundle consumer may receive a verified
receipt directly, but it must also verify the artifact-specific role or writer
authority. After bundle publication, it may follow the authenticated transitive
native locator and hash under the applicable binding rules. Missing or invalid
authority discards that candidate and leaves overall resolution
`indeterminate`; it is not repaired by an Indexer result or ordinary `not
found`.

This amendment does not introduce the proposed generic registry-bootstrap
descriptor, a public `jobId`-indexed payment evidence lookup, or a
logical-address-to-StorageProgram-name derivation. Those proposals retain
unresolved key-pinning, writer-authority, rotation, discovery, and conformance
gates. Atomic operation receipts instead expose the actual attempt-sensitive
native output and require the consuming artifact's own authorization checks.

## Decision matrix

### Purchase sequencing

| Question | Proposed answer | Supporting current Standard rules | Accepted reviewer corrections | DACS-decidable? | Demos DACS-binding/evidence required? | Required positive / negative / boundary vectors |
| --- | --- | --- | --- | --- | --- | --- |
| **1. Vet outputs and the “two transactions” claim** | **Proposed Atomic rule:** accept only complete, already-signed Vet artifacts. A Purchase Work may assert an already-finalized, independently resolvable Vet record, or atomically anchor the byte-identical signed artifact after validating its recipe, result, subject, signature, and session binding. It must not perform live XM, Web2, SR-3, or other nondeterministic vetting inside the rollback boundary. “Two transactions” means two successful-path business Works after discovery/negotiation, not a complete terminal lifecycle. Under the current artifact model the conforming first milestone is **two business Works plus an idempotent audit-finalization tail**. Reuse the DACS-3 `AgreementDocument`, existing `commit-agreement` / `commit-payee-bound-agreement` phases, and CCI rather than create a second agreement format. | **Existing:** CORE SR2-9 and DACS-5 ST-11 require every terminal completed-bundle dependency and the bundle itself to be finalized and independently resolvable. DACS-4 FP-1..FP-4 prohibit placeholder receipt values and require final evidence, hashes, signatures, references, and anchors to be regenerated after rail finality. | The successful-path scope must exclude listing/identity publication, live Vet computation, amendments/refunds, failure recovery, and rollout telemetry. Completion cannot be described as the whole lifecycle while receipt-derived DACS-4/DACS-5 material still needs the audit tail. | **Yes**, for allowed Vet forms, validation, lifecycle scope, and reuse of existing DACS artifacts. | **Yes:** first-class atomic storage write/assertion, deterministic validation, rollback, and independently verifiable per-operation output receipts remain unproved. | **Positive:** finalized Vet assertion; byte-identical signed Vet anchoring; two Works followed by audit finalization.<br>**Negative:** live/external Vet operation rejected statically; invalid recipe/result/subject/signature/session binding rolls back all critical effects.<br>**Boundary:** finalized-but-temporarily-unresolvable Vet remains `audit-pending`; maximum artifact/Work size. |
| **2. Atomic co-finality versus commitment-before-payment** | **Proposed Atomic rule:** add a narrow profile-scoped alternative to the sequential rule. Commitment must precede payment in signed operation order; agreement, signatures, listing, payee/amount/asset/job/phase, and deadline checks must pass before payment; deadline checks use the Work’s final consensus timestamp; commitment, payment, slot mutation, and critical writes share one isolated overlay; every critical failure rolls all business effects back; one authenticated BFT-final receipt proves the ordered operations and common finality. Without every condition, use the existing sequential path. | **Existing:** CORE SR2-8 and DACS-3 CA-1 are temporal MUSTs: a finalized agreement-commitment receipt is required before payment or irreversible delivery. DACS-3 §8.5.2 checks 5 and 6 apply deadline/`notAfter`; CA-8 supplies the receipt-derived consensus timestamp and forbids client, observer, RPC, and indexer clocks. | Do not reinterpret CA-1/SR2-8 by “intent.” New Atomic-profile text must state the alternative explicitly. Concurrent revocation/double-settlement invariants move to consensus CAS, not assembly-time preflight. The deadline citation is §8.5.2 checks 5/6; CA-8 is the time source, not the deadline rule. | **Yes**, for the profile-scoped equivalence rule and fallback requirement. | **Yes:** isolated overlay, ordered pre-effect validation, consensus-time evaluation, atomic rollback, and cross-Work CAS need node proof. | **Positive:** valid ordered commitment/payment co-finality.<br>**Negative:** payment ordered first; invalid signature or commercial binding; failure after in-overlay transfer; client-clock substitution.<br>**Boundary:** exact deadline/`notAfter` edge at consensus time; two concurrent Works for the same slot; capability missing forces sequential fallback before Atomic signing/submission. |

### Work identity, authorization, and operation surface

| Question | Proposed answer | Supporting current Standard rules | Accepted reviewer corrections | DACS-decidable? | Demos DACS-binding/evidence required? | Required positive / negative / boundary vectors |
| --- | --- | --- | --- | --- | --- | --- |
| **3. Canonical unsigned Work envelope and `workId`** | **Proposed Atomic rule:** one pure-data, ordered unsigned intent containing version, profile/version, substrate/network, job, expiry, closed role roster, and ordered operations with IDs, kinds, criticality, dependencies, required roles, and complete payloads. `workId` is the domain-separated hash of its exact canonical bytes. Expiry, network/profile/version, roster, operation order, graph, and payloads are inside; authorizations, simulation, receipts, observation time, outer nonce/fee, submitter signature, and native transaction hash are outside. V1 defines operation dependencies but no generic intra-Work output-reference grammar; native outputs are realized and authenticated in receipt leaves after execution. `workId` is the logical intent ID; the native transaction hash identifies a transport attempt. | **Existing:** CORE supplies JCS-based canonicalization, domain separation, safe-integer constraints, and immutable receipt identity, but defines no Atomic Work envelope or `workId`. Current Demos mapping warns that native Storage Program addressing and signer nonce are write-time inputs. | Define `canonical Work bytes ↔ derived workId → transport attempts → winning attempt`. Never hash mutable SDK runtime objects such as a `Set`. Canonicalization must be fork-independent or explicitly fork/profile-pinned. Different bytes under one ID and identical bytes under a different supplied ID must reject or normalize before admission; late attempts cannot execute after a winner. The RFC’s initial JCS proposal and a later byte-level/length-prefixed prototype are alternatives—the Standard must select one exact grammar. | **Yes**, for schema, canonical bytes, domain, derivation, and identity-conflict rules; **joint** for the substrate binding. | **Yes:** Demos must reproduce the digest, enforce the attempt/winner relation, and prove fork-safe behavior across node/SDK versions. | **Positive:** independent implementations produce identical bytes/ID; transport re-envelope preserves ID; one attempt wins.<br>**Negative:** mutate any included field; same ID/different bytes; same bytes/different supplied ID; unordered/mutable-object serialization; self-hash circularity.<br>**Boundary:** fork/profile transition, expiry edge, maximum safe integers, operation insertion-order variance, late competing envelope after inclusion. |
| **4. Operation signature domain and role roster** | **Proposed Atomic rule:** each operation authorization signs a canonical envelope, excluding only its signature value, and binds authorization version/algorithm, `workId`, network, rail, job, phase, operation ID/index/kind, role, and signer. Because `workId` binds the full graph, the authorization transitively binds payload, dependencies, profile, expiry, and roster. Verifier signatures authenticate Vet artifacts but do not authorize payment; payer authorizes transfer; buyer/seller authorize their role-specific writes; orchestrator authority is explicit; submitter/fee payer is transport only. Every role resolves from authenticated DACS claims. | **Existing:** CORE and stage artifacts already require domain-separated signatures and authenticated `ClaimReference`s. DACS-5 requires role-specific bundle signatures and binding authorization. There is no current Atomic operation-authorization envelope, nor a rule making the outer sender a business role. | The initial smaller tuple is insufficient: bind `authorizationVersion` and `algorithm` as well as full network/session/slot/operation context. Moving authorization across a Work, network, session, slot, operation, role, or algorithm must fail. | **Yes**, for envelope, roles, domain, and verifier behavior. | **Yes:** operation-level multi-party authorization, claim resolution, and pre-effect enforcement independent of the transport sender remain unproved in the node/SDK. | **Positive:** required role authorizes the intended operation; one transport account submits independently.<br>**Negative:** mutate every bound field; replay across Work/network/session/slot/operation/role; verifier-as-payer; sender-as-role; missing/duplicate/unknown role.<br>**Boundary:** multi-role same key still needs separate role envelopes; algorithm/version transition; closed-roster validation. |
| **5. Allowed operation families** | **Proposed Atomic rule:** v1 is a closed profile permitting only deterministic Demos-native effects proven to share one overlay: signed artifact assertion/verification, create-only or CAS storage write, native DEM transfer, payment-slot transition, and profile-defined receipt assertion. Critical XM, Web2, L2PS, bridge, HTTP, messaging, or other externally irreversible/nondeterministic operations are rejected statically; they may occur outside the Work without claiming rollback coverage. | **Existing:** the Demos mapping describes SR-4 `DemosWork` WorkSteps for negotiation and several external/substrate capabilities, but it does not declare that generic Work steps or external effects share an atomic business-state overlay. Current DACS rules already require honest capability/finality claims rather than approximated guarantees. | Use existing SR-4 agreement and commitment artifacts, not parallel schemas. The schema must require unique operation IDs, a closed role roster, validated dependencies, no cycles, and no future dependencies. A later output-reference grammar would require an explicit payload-schema and profile revision rather than an unreachable reserved definition. | **Yes**, for the v1 whitelist, graph validity, and meaning of “critical.” | **Yes:** every allowed native family must exist and participate in the same proven overlay; unknown/external kinds must fail before effects. | **Positive:** one case per allowed family and a valid dependency graph.<br>**Negative:** each forbidden external family; unknown kind; duplicate ID; cycle; missing or future dependency; unsupported profile/version.<br>**Boundary:** payload/operation/time/proof-size/fee limits and a failure injected at every critical operation position. |

### Receipts, evidence, and DACS-5

| Question | Proposed answer | Supporting current Standard rules | Accepted reviewer corrections | DACS-decidable? | Demos DACS-binding/evidence required? | Required positive / negative / boundary vectors |
| --- | --- | --- | --- | --- | --- | --- |
| **6. Work receipt to artifact-specific `AnchorReceipt`** | **Proposed Atomic rule:** an authenticated Work receipt binds `workId`, winning transport attempt/tx, network, BFT-final block/time, disposition, ordered operation results, pre/post business roots, payment-slot result, and critical output data. Each storage output includes logical/native address, canonical content hash, native writer, and nonce. An operation inclusion proof projects that leaf into an independently verifiable CORE `AnchorReceipt`. Keep the existing `bft-final` model, but add a new versioned operation-level transaction/settlement reference rather than reinterpret `demos:{txHash}`. RFC-6962-shaped, domain-separated operation leaves/nodes are a candidate construction, not an adopted algorithm. | **Existing:** CORE SR2-4..SR2-6 require authenticated evidence binding logical/native address, content hash, transaction, writer, nonce, block, and finality. The Demos SR-2 mapping treats authenticated inclusion as BFT-final and separates consensus receipt from Indexer visibility. DACS-4 already has `demos` tx references and `bft-final`, but not a Work-operation identity. Current SB-1 requires the full PC-2 address tuple to be independently checked before settlement identity projection. | The consumer-side anchor check and the execution-time slot check are independent controls. A new versioned settlement-identity rule is mandatory. Proof inputs, ordering, domains, odd-leaf behavior, validator/finality evidence, and actual proof bytes must be exact. Detached status labels or client summaries are not authoritative receipts. | **Joint:** DACS can define projection, discriminators, verification result, and proof requirements; exact Demos proof formats require the Demos binding. | **Yes:** authenticated Work/operation receipts, attempt winner, receipt root, finality and validator-set evidence, state proofs, and Indexer-independent serving/reconstruction are not yet proven. | **Positive:** one receipt projects several independently verifiable anchors; complete receipt/finality/state chain without Indexer.<br>**Negative:** tamper operation order/ID/kind/input/output, logical/native address, writer, nonce, content, root/path, block, validator set, quorum, winner, or slot; existing discriminator used with new meaning.<br>**Boundary:** odd and empty Merkle trees if that construction is adopted; missing proof link → `indeterminate`, invalid/contradictory link → reject; receipt available while Indexer lags. |
| **7. Buyer and seller DACS-5 copies with one submitter** | **Proposed Atomic rule:** under the current artifact model, final buyer/seller bundles cannot be safely signed inside the same Completion Work because final evidence references are not known until Completion finality. Produce them in the audit-finalization tail. A later receipt-bound or post-finality audit Work may use distinct role operations carrying each logical address, required `anchoredByRole`, role authorization, existing bundle signatures, and a role-signed `BundleBinding`. The outer submitter is never sufficient anchoring authority. | **Existing:** DACS-4 FP-1..FP-4 require final receipt-derived evidence and transitive bundle re-signing. DACS-5 ST-11 requires the completed bundle itself to be finalized/resolvable. DACS-5 BB-4..BB-8 verify `BundleBinding`, role authorization, resolution, multiplicity, and fail-closed behavior; each side anchors its own copy. Those rules do not define a third-party-transported operation as that role’s anchoring act. | Add an explicit Atomic-profile rule defining what makes the role-authorized operation the anchoring act. `anchoredByRole`, a transport sender, or native writer alone cannot establish it. If Demos cannot enforce and prove per-operation authorizer/writer identity independently of the outer sender, Atomic Completion must fall back. | **Yes**, for anchoring meaning and the mandatory initial audit tail. | **Yes** for any later Work-based role anchoring; **no** new Atomic runtime claim is needed to keep the current post-finality separate-anchor path. | **Positive:** independently authorized buyer/seller copies, correct `anchoredByRole`, binding, address, and canonical convergence.<br>**Negative:** swapped role, outer sender treated as role, missing role authorization/signature/binding, wrong native writer, unequal same-standing copies.<br>**Boundary:** one transport sender for both operations; write-input vs pure mapping; Completion Work alone remains non-terminal. |
| **8. `audit-pending → finalised`** | **Proposed Atomic rule:** Work inclusion alone is insufficient. Verify the finalized Work receipt and every projected anchor, independently resolve native addresses, recompute artifact hashes, verify signatures/session/role bindings and operation proofs, resolve both bundle copies and all dependencies, and only then apply ST-11. Missing/unavailable evidence is `indeterminate`; invalid/contradictory evidence is rejected. A non-paying idempotent audit repair may restore missing bookkeeping, but Purchase payment is never replayed. | **Existing:** DACS-5 ST-11 already defines this gate and states that external Indexer visibility never gates it. CORE SR-2 distinguishes `present`, policy-qualified `absent`, and `indeterminate`; ordinary `not found` is indeterminate. DACS-4 PC-7 preserves rail-final payment while evidence anchoring catches up, and DACS-5 ST-7 supplies bounded substrate pause/resume. | Preserve the independent consumer boundary even if the node slot and receipt say “committed.” A finalized Work claiming an output that cannot be proven/resolved is a substrate/profile failure, not permission to resubmit payment. | **Yes**, for the state machine, verification procedure, and repair restrictions. | **Yes:** authenticated, independently resolvable receipt/proof/output service must work without public Indexer hydration. | **Positive:** all dependencies resolve and verify; idempotent non-paying audit catch-up reaches finality.<br>**Negative:** valid Work plus invalid artifact/proof/role copy; payment replay proposed as repair.<br>**Boundary:** absent proof/artifact/service → `audit-pending`/ST-7; contradictory content → reject; Indexer lag with complete consensus proof still progresses. |

### Rollback, retries, and crash consistency

| Question | Proposed answer | Supporting current Standard rules | Accepted reviewer corrections | DACS-decidable? | Demos DACS-binding/evidence required? | Required positive / negative / boundary vectors |
| --- | --- | --- | --- | --- | --- | --- |
| **9. Fees and nonces on failure** | **Proposed Atomic rule:** business rollback covers Work-transferred balances, payment slot, storage writes, and every profile-declared critical effect. Once an outer transaction is included, its account nonce and fee are consensus/transport effects outside business rollback. Every terminal receipt reports nonce/fee consumption separately from committed/rolled-back business effects. A failed included Work may cost a fee and consume a nonce while moving no payment and creating no artifact. | **Existing:** CORE SR2-7 defines authenticated lifecycle/replacement reconciliation. The Demos mapping documents strict sequential account nonces and warns against deriving follow-on transactions from broadcast acceptance or stale nonce reads. The Standard does not define Atomic Work fee rollback. | Reuse existing nonce sequencing/idempotency work, but do not confuse client auto-nonce with a node execution guarantee. Fee/nonce consumption never authorizes another payment; recovery follows authenticated lifecycle and slot state. | **Joint:** DACS can require the reporting and fail-closed consequences; Demos owns exact native semantics. | **Yes:** exact fee/nonce behavior for admitted, included, failed, expired, stale, future, dropped, and replaced attempts needs a pinned node contract. | **Positive:** included failure reports consumed fee/nonce with unchanged business effects.<br>**Negative:** fee/nonce consumption interpreted as payment or retry authority; hidden business effect after rollback.<br>**Boundary:** pre-admission vs included failure; stale/future nonce; transport timeout; fee exhaustion; replacement attempt. |
| **10. Persistent payment slot and conflict digest** | **Proposed Atomic rule:** a consensus-ledger singleton keyed by the structured `(networkId, railId, jobId, phaseIndex)` tuple. Its conflict digest binds network, slot, agreement/commitment, payer, payee, asset, and amount. Exact replay reconciles the same Work; settlement returns the authoritative receipt; another digest for the slot is rejected; retry after authenticated rollback uses an explicit next generation bound to the failure receipt; indeterminate observation keeps the slot held. The SDK journal coordinates orchestration, but the node slot/work ledger is execution authority. | **Existing:** PC-2 and current SB-1 define and independently verify the complete payment-evidence anchor tuple. SB-2 prevents a consumer from counting one settlement identity across sessions. PC-7 makes post-payment evidence anchoring idempotent. None of these is a consensus execution slot or prevents two distinct Works from paying. | Scope the slot to `networkId`. CAS must apply **across** distinct Works, not only within each Work overlay. Compare a proof-bound structured tuple component-wise and type-strict, never a claimant label or concatenated string. Define canonical bytes/ID → attempts → winner; exactly one attempt/Work may commit effects. | **Joint:** DACS defines identity, conflict, replay, and recovery semantics; Demos owns the singleton ledger, CAS, generations, and winner enforcement. | **Yes:** no current public proof of a global cross-Work payment slot, attempt ledger, or authenticated slot-state proof. | **Positive:** exact replay; post-settlement receipt return; authenticated rollback generation retry; same logical tuple on two networks does not collide.<br>**Negative:** two Work IDs/one slot both commit; changed digest; same proven slot hidden behind alternate labels/encoding; late losing attempt executes.<br>**Boundary:** in-flight reconciliation; proof-bound vs unbound tuple; type/encoding edge; reorg/drop/expiry/replacement with held slot. |
| **11. Authoritative rollback and absence** | **Proposed Atomic rule:** an included failed Work needs a consensus-authenticated rollback receipt binding Work/attempt/block, operation outcomes, rolled-back disposition, payment-slot state, equal pre/post critical-domain roots, and unchanged/non-membership proofs for every possible business output. That receipt proves an included rollback only; it does not prove that another attempt was never included. Pre-admission, dropped, and expired-before-inclusion cases require authenticated lifecycle or finalized absence evidence that proves terminal non-includability. | **Existing:** CORE SR-2 authoritative-absence rules make ordinary `not found`, stale views, transport failure, and unqualified non-observation `indeterminate`. The current Demos mapping expressly declares no authenticated finalized non-membership or independent read-quorum policy, so Demos `not found` cannot establish absence. | Separate included rollback from non-inclusion. Point-in-time non-membership and local-clock expiry are insufficient. Authenticated pre-admission rejection is terminal only if it proves the attempt cannot later enter execution. Invalid proof material rejects before structural/missing-data classification. | **Yes**, for disposition/recovery semantics; **joint** for exact proof bindings. | **Yes:** Demos must define and serve authenticated rollback, lifecycle, membership/non-membership, state-root, and terminality proofs. | **Positive:** included rollback with equal critical roots and unchanged outputs; authenticated terminal pre-admission rejection; authenticated expiry permits replacement.<br>**Negative:** differing roots, committed operation under rolled-back outcome, invalid proof, rollback receipt used as proof another attempt was absent.<br>**Boundary:** broadcast + ordinary `not found`; point-in-time non-membership; missing proof; local-clock expiry; status outage—all remain indeterminate. |
| **12. Crash/restart boundaries and receipt persistence** | **Proposed Atomic rule:** business-state commit and commitment to the authoritative Work receipt must be one consensus transition. Serving storage may be separate only if the receipt is deterministically reconstructible from finalized block/state commitments. Before durable admission, reconcile; during operation execution, no overlay commits; after overlay construction but before consensus, no finalized effect; after consensus but before client observation, recover by `workId` and adopt the winner; service unavailability remains indeterminate and blocks resubmission. | **Existing:** CORE SR2-4..SR2-7 requires authenticated immutable lifecycle snapshots, preserved state under indeterminate observations, and ordered reconciliation. It does not prove atomic node commit/receipt persistence. | The transport-attempt winner relation must survive restart. A conforming profile cannot permit committed business effects with a permanently unrecoverable receipt. | **Joint, runtime-dominant:** DACS can define recovery behavior and the reconstructibility requirement; only Demos can prove the consensus/storage boundary. | **Yes:** atomic commit, durable attempt/slot state, deterministic receipt reconstruction, and restart behavior need failure-injection evidence. | **Positive:** restart after commit reconstructs the same receipt and exact replay adopts it.<br>**Negative:** effects commit without recoverable receipt; replay executes again; partial overlay persists.<br>**Boundary:** crash before admission, between each pair of operations, after overlay/before consensus, after consensus/before serving, and status/receipt-service outage. |
| **13. Failure after Purchase but before Completion** | **Proposed Atomic rule:** two Works are a successful-path optimization, not end-to-end fair exchange. A BFT-final Purchase payment cannot be rewritten as an abort or replayed. Record objective failure and attribution, produce the applicable role-specific `FaultAttestationBundle` copies, use a `SettlementAmendment` for a linked refund/correction, perform refund/recovery as a separately authorized settlement action, and use contractual/DACS-X handling where available. Guaranteed delivery-or-refund needs an escrow/delivery-gated profile. Never silently fall back to legacy payment after an Atomic Work is signed/submitted. | **Existing:** DACS-4 §9.7.1 defines signed, anchored refund/partial-refund/correction amendments linked to successful settlement evidence. DACS-5 defines failure/substrate/timeout handling and `FaultAttestationBundle`; CORE §11.2.1 leaves adjudication to anticipated DACS-X. | Narrow the marketing claim to successful-path execution. Atomic execution supplies no fair-exchange or escrow guarantee and must not create a second payment route during recovery. | **Yes**, for lifecycle, artifacts, fallback prohibition, and separation from an escrow profile. | **No separate blocker** beyond authoritative Purchase finality; any future escrow profile would introduce its own runtime contract. | **Positive:** seller crash/refusal/timeout/failed delivery produces correct failure evidence and separately authorized linked refund.<br>**Negative:** Purchase replay; silent legacy fallback; failed delivery recorded as rolled-back payment; refund without successful source evidence.<br>**Boundary:** crash immediately after Purchase finality; late delivery; disputed attribution; amendment arriving before/after bundle finalization. |

### Evidence provenance and rollout measurement

| Question | Proposed answer | Supporting current Standard rules | Accepted reviewer corrections | DACS-decidable? | Demos DACS-binding/evidence required? | Required positive / negative / boundary vectors |
| --- | --- | --- | --- | --- | --- | --- |
| **14. POC commit `fea395d` and test evidence** | **Proposed answer:** unresolved evidence blocker. Before the POC informs a protocol decision, publish the repository URL, full commit and parent/base SHAs, immutable tree or git bundle, lockfiles and tool versions, exact commands and complete logs, the 21 Atomic fixtures/hashes, the identity of the 798-test suite, and a precise statement that the approximately 10 ms result measured local assembly/signature verification/deterministic execution rather than consensus. | No current Standard invariant turns an inaccessible implementation claim into conformance evidence. The repository’s candidate/golden vector process reinforces the need for pinned, reproducible artifacts but does not validate this missing POC. | Make the consensus-latency dependency explicit. Do not treat later PR #322 classifier evidence as provenance for the separate inaccessible POC. | **No:** this is an implementation-evidence/provenance question, not a semantic decision. | **Separate evidence blocker**, not proof that Demos runtime does or does not implement Atomic Work. | **Positive:** clean checkout reproduces named test counts, fixtures, hashes, and local timing under pinned tools.<br>**Negative:** missing object/base/lock/log; count without suite identity; local timing presented as consensus latency.<br>**Boundary:** environment variance and timing confidence; distinguish simulation, deterministic execution, broadcast, inclusion, and finality. |
| **15. Meaning of the 25-second / 40-second targets** | **Proposed answer:** headline Oracle metric is first byte of Purchase Work submission through DACS-5 ST-11 `finalised` after Completion, including both BFT-final Work receipts, agent execution, receipt verification, independent artifact resolution, and audit finalization. Exclude discovery, negotiation, and precomputed Vet. Report assembly/signing, acknowledgement, Purchase finality, agent execution, Completion finality, audit resolution, and Indexer hydration separately; Indexer hydration is observed but does not gate the headline. Use at least 100 consecutive eligible testnet lifecycles, nearest-rank p50/p95, ≥99% completion, p50 ≤25 s, p95 ≤40 s, and zero duplicate payment, partial critical state, or false finalization. | **Existing:** ST-11 supplies the semantic terminal point and says Indexer visibility never gates it. The Standard currently defines no Atomic performance SLA, sample method, or outage policy. | Outage exclusion must use a predeclared independent rule proving network-wide consensus unavailability, with excluded intervals/evidence published—never job-specific or retrospective manual exclusion. State latency as inclusions × inclusion time plus agent/audit components so consensus dependency is visible. | **Joint/operational:** DACS can define a profile qualification metric; Demos and reference operators must supply network measurements. | **Measurement dependency:** no protocol decision can establish live inclusion latency or availability. | **Positive:** 100-run dataset reproduces nearest-rank results and stage submetrics.<br>**Negative:** Indexer used as success gate; failed/time-out runs removed from denominator; retrospective outage exclusion; local 10 ms substituted for lifecycle latency.<br>**Boundary:** exactly 99% completion, exactly 25/40 s, run spanning a predeclared outage, audit-tail delay, endpoint/network change mid-campaign. |

## Amendment-entry criteria

Before an Atomic-profile draft is treated as implementable, the review record
supports all of the following gates:

1. Preserve the current sequential CA-1/SR2-8 rule and add, rather than infer,
   an explicit profile-scoped co-finality alternative.
2. Pin one canonical unsigned-intent grammar, Work/operation/authorization
   domains, and additive transaction/settlement reference discriminators.
3. Pin the exact Demos node and SDK revisions and the network/fork profile to
   which the binding applies.
4. Obtain reproducible Demos evidence for the isolated overlay, critical-effect
   rollback, global network-scoped slot CAS, attempt/winner ledger, receipt
   reconstruction, fees/nonces, and every crash boundary.
5. Bind exact receipt, finality, validator-set, state-membership,
   non-membership, and lifecycle-proof bytes. A classifier over upstream status
   enums cannot satisfy this gate.
6. Keep ST-11 independent resolution, PC-7 non-paying audit catch-up, and
   fail-closed authoritative-absence behavior intact.
7. Define the DACS-5 anchoring act and retain the audit tail until a separate
   receipt-bound artifact model safely eliminates it.
8. Publish complete implementation-neutral positive, negative, and boundary
   vectors across identity, authorization, graph validation, execution,
   receipts, absence, retries, crash recovery, DACS-4 anchor binding, DACS-5
   role copies, and end-to-end qualification.

## Appendix A — exact Phase 0 questions

The following are quoted from [the Phase 0 review comment][phase-0-questions].
They are distinct from the delivery plan’s earlier ten Demos-confirmation
questions and the issue body’s eleven-item decision checklist.

1. “Are the Buyer/Seller Vet outputs newly written inside the Purchase Work, or
   are they assertions of already-finalized Vet records? What exactly is
   included in the claim that the complete lifecycle drops to two
   transactions?”

2. “Is the intent to change DACS SR2-8 / DACS-3 CA-1 so that atomic co-finality
   of commitment and payment becomes equivalent to ‘finalized commitment before
   payment’? If not, how can payment wait for the finalized commitment receipt
   and the receipt-derived deadline checks inside the same transaction?”

3. “What is the exact canonical unsigned Work envelope and `workId` derivation?
   Which fields, especially signatures, receipts, expiry, chain/profile
   identifiers, and operation ordering, are inside or outside the digest?
   Should there be a separate immutable `intentId` from the native transaction
   hash?”

4. “What is the exact operation-signature domain and role roster? How are
   verifier, buyer, seller, orchestrator, payer, and submitter keys
   distinguished? Does every signature bind the full Work root, operation
   ID/index/type, dependency graph, network, profile version, payload hash,
   expiry, and resolved role?”

5. “Which operation families are allowed in an Atomic DACS profile? Are
   critical XM, Web2, L2PS, or other externally irreversible steps rejected
   statically, since a Demos state overlay cannot roll those effects back?”

6. “How does one Work receipt deterministically derive a complete
   artifact-specific DACS AnchorReceipt for every logical output? What are the
   proof-root algorithm, operation ordering, domain separation, receipt
   version, native address/writer binding, and validator/finality proof?”

7. “In the Completion Work, how do buyer and seller each anchor their own
   DACS-5 copy, with the correct `anchoredByRole` and BundleBinding/discovery
   behavior, when one transaction has one submitter?”

8. “What independent post-inclusion resolution procedure gates
   `audit-pending -> finalised`? If Work inclusion is proven but one operation
   proof, artifact, role copy, or referenced dependency cannot be independently
   resolved, what exact state and recovery path apply?”

9. “What are the failure semantics for fees and nonces? Are fees and the outer
   transaction nonce explicitly outside business-state rollback? If not, what
   are the replay and denial-of-service implications?”

10. “What is the persistent payment-slot state machine and conflict digest? How
    do exact replay, same slot with different payload, dropped/expired/replaced
    transactions, future/stale nonce, and indeterminate observation behave
    without creating a second payment?”

11. “How is rollback or artifact absence proven authoritatively? Is there a
    before/after state-root proof, operation non-membership proof, deterministic
    state diff, or authenticated failure receipt? Ordinary RPC/indexer ‘not
    found’ is not sufficient.”

12. “What are the crash/restart boundaries: before execution, between
    operations, after overlay commit but before receipt persistence, and after
    consensus commit but before the client observes the receipt? Can consensus
    succeed while receipt/status storage fails, and how does replay recover?”

13. “What happens after a successful Purchase Work if the agent crashes,
    refuses, times out, or produces a failed result before Completion? Which
    failed bundle, attribution, refund/amendment, and recovery transactions are
    required? I think the ‘two transactions’ claim should be framed as a
    successful-path target rather than end-to-end fair-exchange atomicity.”

14. “Can you share an immutable tree/diff for POC commit `fea395d`, plus the
    exact test commands and logs? I could not access the referenced
    repository/commit, so the 21/798 test counts and approximately 10 ms local
    timing are not independently reproducible yet.”

15. “What precisely do the 25-second and 40-second targets measure: one
    inclusion, both Work inclusions, agent execution, finality verification, or
    full user-visible lifecycle? What are the sample window, endpoint/network,
    percentile method, and objective outage-exclusion rule?”

## Sources

- [RFC #320 issue baseline][rfc-320].
- [Atomic DACS Demos Work delivery plan, comment 5194366592][delivery-plan].
- [Role alignment and exact 15 Phase 0 questions, comment
  5194367410][phase-0-questions].
- [Proposed DACS-side answers, comment 5194697161][proposed-answers].
- [Demos runtime/node and SDK response, comment 5195210014][demos-response].
- [Execution-evidence and receipt-model lane, comment
  5196976595][execution-evidence].
- [Six required corrections and vector gates, comment
  5203639100][required-corrections].
- [Payment-anchor consumer checks and DACS-5 anchoring question, comment
  5204036235][anchor-review].
- [Discussion acceptance and ownership follow-up, comment
  5206888754][accepted-corrections].
- [Receipt/proof proposal, comment 5207060156][receipt-proposal].
- [Cross-Work slot-CAS correction, comment 5207114349][cross-work-cas].
- [Vector coverage crosswalk, comment 5207480023][vector-crosswalk].
- [Structured slot-key follow-up, comment 5207541904][structured-slot].
- [Proof-bound slot-tuple follow-up, comment 5207843775][proof-bound-slot].
- [Original PR #322 announcement, comment 5208691872][pr-322-announcement].
  Its historical “verifier”/31-vector wording is superseded by the current
  52-vector classifier boundary recorded on [PR #322][pr-322].
- [SR-2 direct-receipt and bootstrap discussion, issue #242][issue-242],
  especially the [artifact-authority correction][issue-242-authority].

[CORE]: ../spec/CORE.md

[DACS-3]: ../spec/DACS-3-NEGOTIATE.md

[DACS-4]: ../spec/DACS-4-SETTLE.md

[DACS-5]: ../spec/DACS-5-VERIFY.md

[Demos mapping]: ../spec/DEMOS-MAPPING.md

[rfc-320]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320

[delivery-plan]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5194366592

[phase-0-questions]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5194367410

[proposed-answers]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5194697161

[demos-response]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5195210014

[execution-evidence]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5196976595

[required-corrections]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5203639100

[anchor-review]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5204036235

[accepted-corrections]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5206888754

[receipt-proposal]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5207060156

[cross-work-cas]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5207114349

[vector-crosswalk]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5207480023

[structured-slot]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5207541904

[proof-bound-slot]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5207843775

[pr-322-announcement]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/320#issuecomment-5208691872

[pr-322]: https://github.com/DACS-Agent-commerce/DACS-Standard/pull/322

[pr-322-current]: https://github.com/DACS-Agent-commerce/DACS-Standard/pull/322#issuecomment-5254850084

[issue-242]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/242

[issue-242-authority]: https://github.com/DACS-Agent-commerce/DACS-Standard/issues/242#issuecomment-5251088143
