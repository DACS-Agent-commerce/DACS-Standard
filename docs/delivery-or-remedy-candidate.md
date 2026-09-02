# Delivery-or-remedy candidate specification

**Status:** pre-normative review candidate for [issue #356](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/356). It does not change DACS conformance, register a rail, or make any deployment available.

**Target:** a future DACS-4 job-escrow lifecycle and DACS-X evaluation module. The first proposed binding is `pay-evm-erc8183`.

**Dependencies:** phase-bound delivery evidence from #333, current exact-profile and JID admission from #343, a self-contained DACS-X vector pack from #99, and #351 only when transcript disclosure is enabled.

The capitalized requirement words in this document are proposed requirements. They become normative only if promoted into the applicable specification modules by a later steward-approved pull request.

## 1. Outcome and boundary

Delivery-or-remedy commerce locks the agreed price before delivery. It releases the locked value only after an agreed evaluator authenticates an acceptable delivery, or returns the locked value through an authenticated rejection or expiry path.

The first profile has:

- one buyer, one seller, and one independent evaluator;
- one fungible token and one funded budget;
- one delivery submission;
- one terminal release, rejection refund, or expiry refund;
- zero provider payout before terminal release;
- zero platform or evaluator fee deducted from escrow;
- no appeal that changes a terminal financial state.

The first profile excludes milestones, partial claims, streaming, fee splitting, evaluator registries, automatic evaluation of arbitrary work, and transcript disclosure.

An evaluator may receive separate compensation under another signed agreement. That payment is not part of the escrowed budget or this profile's terminal disposition.

## 2. Compatibility model

The current DACS pipeline cannot express lock, then delivery, then terminal settlement as one ordinary `pay-*` phase. An ordinary phase returns one `PhaseHandlerResult`, while delivery must occur after funding and before terminal release.

The candidate therefore adds one structurally distinct `job-escrow` phase kind used exactly twice around one existing delivery phase:

```text
commit-delivery-or-remedy-agreement
job-escrow { action: "fund", rail: "pay-evm-erc8183:..." }
deliver-*
job-escrow { action: "terminal", rail: "pay-evm-erc8183:..." }
rate?
```

The two `job-escrow` invocations are one paired lifecycle, not two payments. The fund invocation proves value was locked. The terminal invocation proves release or refund.

An older reader sees unknown agreement and phase discriminators and rejects the Listing before execution. It MUST NOT remove either phase, reinterpret `job-escrow` as an ordinary payment, or execute the delivery outside the pair.

### 2.1 Candidate phase shape

```text
type JobEscrowPhaseStep = {
  kind: "job-escrow"
  parameters: {
    action: "fund" | "terminal"
    rail: string
  }
}
```

- (DRP-1) A delivery-or-remedy pipeline MUST contain exactly two `job-escrow` steps.
- (DRP-2) The first step MUST use `action: "fund"` and the second MUST use `action: "terminal"`.
- (DRP-3) Exactly one supported `deliver-*` step MUST occur between the paired steps.
- (DRP-4) No other payment, delivery, or `pay-alternative` step MAY occur between or alongside the pair.
- (DRP-5) Both steps MUST name the same complete, agreement-selected rail definition.
- (DRP-6) The delivery step MUST NOT begin until finalized evidence proves the exact budget is locked.
- (DRP-7) The terminal step MUST use the exact signed delivery `SettlementEvidence` produced by the intervening step.
- (DRP-8) Neither invocation alone constitutes a second purchase or a second agreement price for DACS-5 volume.

> **Note (non-normative).** A single long-running phase would need a new suspended result state. The paired form preserves the current one-result-per-invocation contract and makes the preterminal delivery hash available without a circular terminal-evidence hash.

## 3. Roles and signed agreement

The existing bilateral `AgreementArtifact` remains the commercial agreement. A distinct three-party overlay adds the evaluator, escrow deployment, deadlines, and disclosure policy without changing the meaning of existing agreement fields.

```text
type DeliveryOrRemedyAgreement = {
  deliveryOrRemedyAgreementVersion: "1"
  jobId: string
  agreementRef: AttestationRef
  agreementHash: string
  railDefinitionRef: AttestationRef
  fundPhaseIndex: number
  deliveryPhaseIndex: number
  terminalPhaseIndex: number
  buyer: EscrowRoleBinding
  seller: EscrowRoleBinding
  evaluator: EscrowEvaluatorBinding
  budgetBaseUnits: string
  submissionCutoffSec: number
  evaluationDeadlineSec: number
  disclosurePolicy: "public-evidence-only" | "explicit-party-supplied"
  evaluationRuleRef: AttestationRef
  signatures: DeliveryOrRemedySignature[]
}

type EscrowRoleBinding = {
  primaryClaim: ClaimReference
  bundleHash: string
  vetRecordRef: AttestationRef
  evmAccountClaim: ClaimReference
}

type EscrowEvaluatorBinding = EscrowRoleBinding & {
  requirement: BundleRequirement
  requirementHash: string
}

type DeliveryOrRemedySignature = {
  role: "buyer" | "seller" | "evaluator"
  party: ClaimReference
  algorithm: "ed25519" | "ecdsa-secp256k1" | "sr1-aggregate"
  value: string
}
```

The canonical form omits `signatures`. Each party signs:

```text
"dacs-delivery-remedy-agreement:v1:" || agreement_overlay_hash
```

`agreement_overlay_hash` is the lowercase hexadecimal SHA-256 digest of the RFC 8785 canonical form after CORE canonicalization.

- (DRA-1) `agreementRef` MUST resolve to the exact finalized bilateral `AgreementArtifact` for `jobId`.
- (DRA-2) `agreementHash` MUST equal the resolved bilateral agreement's recomputed content hash.
- (DRA-3) The buyer, seller, and evaluator MUST each contribute exactly one valid signature over the same overlay hash.
- (DRA-4) Each role's `primaryClaim`, bundle, Vet result, and EVM account claim MUST be independently resolved and verified.
- (DRA-5) Each EVM account claim MUST use the DACS EIP-155 form `cci-xm:evm:<chainId>:<address>` for the selected rail's chain.
- (DRA-6) The evaluator's primary claim MUST differ from both commercial parties under CORE CF-3 identity.
- (DRA-7) The evaluator's controlled EVM account MUST differ from the client and provider accounts.
- (DRA-8) The evaluator's exact `BundleRequirement` MUST hash to `requirementHash` and match the authenticated DACS-2 composite result.
- (DRA-9) The evaluator's Vet result MUST be `pass` and fresh at funding under the bound requirement.
- (DRA-10) `budgetBaseUnits` MUST be the minimal unsigned decimal form of the exact agreement price after conversion using the pinned token decimals.
- (DRA-11) The overlay MUST bind the three ordered phase indexes selected by DRP-1 through DRP-3.
- (DRA-12) The overlay MUST be finalized and independently resolvable before job creation or funding.

The evaluator requirement is deal policy, not a universal arbitrator credential. A live Listing or agreement chooses the credential strength appropriate to the value and subject matter.

## 4. Portable job-escrow lifecycle

The substrate-independent lifecycle is:

| Portable state | Entry evidence | Permitted next state |
|---|---|---|
| `created` | authenticated job-creation evidence bound to the overlay | `funded`, `cancelled` |
| `funded` | exact token and budget locked, zero provider payout | `submitted`, `refunded` |
| `submitted` | exact delivery evidence hash accepted by the escrow | `released`, `refunded` |
| `released` | decision-bound full provider payout | terminal |
| `refunded` | decision-bound or expiry-bound full client refund | terminal |
| `cancelled` | unfunded job closed | terminal, no financial effect |

- (DRL-1) A conforming binding MUST implement every nonterminal and terminal distinction in this table.
- (DRL-2) A binding MAY expose additional native states only when the rail definition maps them deterministically to one portable state.
- (DRL-3) An ambiguous or unavailable native state MUST yield `indeterminate`; it MUST NOT be mapped by guesswork.
- (DRL-4) A terminal native state MUST NOT be reopened or used to authorize another terminal transfer.
- (DRL-5) A refund MUST NOT by itself imply seller fault.
- (DRL-6) A release MUST NOT by itself imply that every non-financial obligation was satisfied.
- (DRL-7) No value MAY reach the seller or its payout receiver before `released`.
- (DRL-8) The selected implementation MUST make DRL-7 true through its immutable capability and authority model.
- (DRL-9) Client policy, SDK omission, hook convention, or event non-observation MUST NOT substitute for DRL-8.

## 5. Job reference and creation binding

```text
type EscrowJobRef = {
  escrowJobRefVersion: "1"
  jobId: string
  deliveryOrRemedyAgreementHash: string
  railDefinitionRef: AttestationRef
  chainId: number
  contractAddress: string
  runtimeBytecodeHash: string
  nativeJobId: string
  creationEvent: EvmEventRef
  signature: ComponentSignature
}

type EvmEventRef = {
  kind: "evm-event"
  chainId: number
  txHash: string
  logIndex: number
}
```

The job reference canonical form omits `signature`. The candidate signing domain is:

```text
"dacs-escrow-job-ref:v1:" || escrow_job_ref_hash
```

- (DRJ-1) `nativeJobId` MUST use the native identifier's minimal canonical spelling.
- (DRJ-2) `creationEvent` MUST resolve to exactly one finalized job-creation event at the pinned contract.
- (DRJ-3) The event's client, provider, evaluator, expiry, and hook fields MUST match the overlay and rail definition.
- (DRJ-4) The native job description MUST equal the byte-exact agreement binding in section 8.1.
- (DRJ-5) `runtimeBytecodeHash` MUST match authenticated code at the finalized creation block and at each later action block.
- (DRJ-6) A proxy binding MUST also resolve the implementation and every authority capable of changing behavior.
- (DRJ-7) A changed, unavailable, or ambiguously resolved code/authority state MUST prevent progression.
- (DRJ-8) A valid signature or creation event MUST NOT repair a mismatch in another field.
- (DRJ-9) The authenticated session orchestrator MUST sign and anchor the job reference through SR-2.

### 5.1 Funding evidence

```text
type EscrowFundingEvidence = {
  escrowFundingEvidenceVersion: "1"
  jobId: string
  deliveryOrRemedyAgreementHash: string
  escrowJobRef: AttestationRef
  fundPhaseIndex: number
  token: string
  amountBaseUnits: string
  fundingEventRefs: EvmEventRef[]
  finality: SettlementFinalityRecord
  observedAt: number
  signature: ComponentSignature
}
```

The canonical form omits `signature`. The signing domain is:

```text
"dacs-escrow-funding-evidence:v1:" || escrow_funding_evidence_hash
```

- (DRF-1) Funding evidence MUST bind the exact overlay, job reference, and `fund` phase index.
- (DRF-2) The native token and amount MUST equal the pinned rail asset and `budgetBaseUnits`.
- (DRF-3) The event set MUST prove the complete budget entered escrow for the exact native job.
- (DRF-4) The resulting native state MUST map to portable state `funded`.
- (DRF-5) The verifier MUST establish that no value reached the provider or payout receiver.
- (DRF-6) Funding evidence MUST meet the rail's exact finality profile before delivery begins.
- (DRF-7) The authenticated session orchestrator MUST sign and anchor the funding evidence through SR-2.

## 6. Evaluation and decision artifacts

Ordinary execution evaluation and contested adjudication have different semantics and remain distinct artifacts.

### 6.1 ExecutionEvaluation

```text
type ExecutionEvaluation = {
  executionEvaluationVersion: "1"
  jobId: string
  evaluationSeq: number
  deliveryOrRemedyAgreementHash: string
  escrowJobRef: AttestationRef
  deliveryEvidenceRef: AttestationRef
  result: "accept" | "reject" | "indeterminate"
  finding: AccountabilityFinding
  subjectEvidenceRefs: AttestationRef[]
  signature: ComponentSignature
}
```

The canonical form omits `signature`. The signing domain is:

```text
"dacs-execution-evaluation:v1:" || execution_evaluation_hash
```

- (DRE-1) The signer MUST be the exact agreement-bound evaluator primary claim.
- (DRE-2) `deliveryEvidenceRef` MUST resolve to the finalized, independently resolvable, signed phase-bound delivery `SettlementEvidence` for the agreed delivery phase.
- (DRE-3) Every subject evidence reference MUST be hash-bound, authenticated, and within the signed disclosure policy.
- (DRE-4) An `indeterminate` evaluation MUST NOT authorize a terminal evaluator transaction.
- (DRE-5) Missing or unavailable evidence MUST remain `indeterminate`; it MUST NOT be converted to rejection or acceptance.
- (DRE-6) The evaluator MUST derive `result` and `finding` under the exact `evaluationRuleRef` bound by the overlay.
- (DRE-7) The evaluation MUST be anchored and independently resolvable before it is used as a decision basis.

### 6.2 EscrowDecision

```text
type EscrowDecision = {
  escrowDecisionVersion: "1"
  jobId: string
  deliveryOrRemedyAgreementHash: string
  escrowJobRef: AttestationRef
  deliveryEvidenceRef?: AttestationRef
  basisRef: {
    kind: "execution-evaluation" | "dispute-outcome"
    ref: AttestationRef
  }
  disposition: "release-to-provider" | "refund-to-client"
  signature: ComponentSignature
}
```

The canonical form omits `signature`. The signing domain is:

```text
"dacs-escrow-decision:v1:" || escrow_decision_hash
```

- (DRD-1) The signer MUST be the exact agreement-bound evaluator primary claim.
- (DRD-2) The basis MUST resolve and authorize the selected disposition under the bound evaluation rule.
- (DRD-3) A release or post-submission refund decision MUST bind the exact delivery evidence.
- (DRD-4) The decision MUST be signed, anchored, finalized, and independently resolvable before the terminal transaction is submitted.
- (DRD-5) `release-to-provider` MUST map only to the native full-release action.
- (DRD-6) `refund-to-client` MUST map only to the native evaluator-rejection action.
- (DRD-7) Expiry recovery MUST NOT manufacture an `EscrowDecision` or evaluator signature.
- (DRD-8) A decision already observed in a terminal job MUST NOT authorize any other job or transaction.
- (DRD-9) A pre-submission refund decision MUST omit `deliveryEvidenceRef` and use a `DisputeOutcome` basis.
- (DRD-10) Authenticated substrate evidence MUST order the decision's finality before the terminal transaction.

### 6.3 DisputeOutcome

```text
type DisputeOutcome = {
  disputeOutcomeVersion: "1"
  jobId: string
  caseId: string
  revision: number
  deliveryOrRemedyAgreementHash: string
  caseRef: AttestationRef
  subjectBundleRefs: AttestationRef[]
  subjectEvidenceRefs: AttestationRef[]
  finding: AccountabilityFinding
  recommendedDisposition?: "release-to-provider" | "refund-to-client"
  supersedesOutcomeRef?: AttestationRef
  signature: ComponentSignature
}

type AccountabilityFinding = {
  classification:
    | "seller-fulfilled"
    | "seller-fault"
    | "buyer-fault"
    | "evaluator-unavailable"
    | "substrate-failure"
    | "no-fault"
    | "indeterminate"
  faultedParty?: ClaimReference
  rationaleCode: string
}
```

The canonical form omits `signature`. The signing domain is:

```text
"dacs-dispute-outcome:v1:" || dispute_outcome_hash
```

- (DRX-1) A `DisputeOutcome` MUST NOT directly instruct or claim an on-chain transfer.
- (DRX-2) A preterminal outcome MAY support a distinct `EscrowDecision` under DRD-1 through DRD-8.
- (DRX-3) A post-terminal outcome MAY supersede only an accountability finding.
- (DRX-4) A post-terminal outcome MUST NOT replace, replay, reverse, or relabel the observed financial disposition.
- (DRX-5) `faultedParty` MUST be present only for `seller-fault` or `buyer-fault` and MUST equal the applicable agreement party.
- (DRX-6) `evaluator-unavailable`, `substrate-failure`, `no-fault`, and `indeterminate` MUST NOT be projected as buyer or seller fault.

### 6.4 Candidate logical addresses

| Artifact | Logical address |
|---|---|
| `DeliveryOrRemedyAgreement` | `dacsx:delivery-remedy:{jobId}:agreement` |
| `EscrowJobRef` | `dacsx:delivery-remedy:{jobId}:job` |
| `EscrowFundingEvidence` | `dacsx:delivery-remedy:{jobId}:funding` |
| `ExecutionEvaluation` | `dacsx:delivery-remedy:{jobId}:evaluation:{evaluationSeq}` |
| `EscrowDecision` | `dacsx:delivery-remedy:{jobId}:decision` |
| `EscrowTerminalEvidence` | `dacsx:delivery-remedy:{jobId}:terminal` |
| `DisputeOutcome` | `dacsx:dispute:{jobId}:{caseId}:outcome:{revision}` |

- (DRAA-1) `jobId` and `caseId` MUST use the current canonical JID form.
- (DRAA-2) Every numeric segment MUST use minimal unsigned decimal ASCII without a sign or leading zero.
- (DRAA-3) A binding MUST derive the native address from the complete logical address under SR-2.
- (DRAA-4) Agreement, job, funding, decision, and terminal addresses are write-once for one job.
- (DRAA-5) A conflicting write or observation at a write-once address MUST be rejected or reported as `indeterminate` under the binding's authenticated conflict rules.
- (DRAA-6) `evaluationSeq` starts at zero and increments by one with no gap.
- (DRAA-7) A later dispute revision MUST reference the exact prior revision through `supersedesOutcomeRef`.
- (DRAA-8) A consumer MUST NOT select a decision, terminal record, or dispute revision from index order or self-reported time.

## 7. Terminal evidence and DACS-5 projection

```text
type EscrowTerminalEvidence = {
  escrowTerminalEvidenceVersion: "1"
  jobId: string
  deliveryOrRemedyAgreementHash: string
  escrowJobRef: AttestationRef
  fundingEvidenceRef: AttestationRef
  terminalState: "released" | "rejected-refund" | "expired-refund"
  disposition: "release-to-provider" | "refund-to-client"
  decisionRef?: AttestationRef
  deliveryEvidenceRef?: AttestationRef
  token: string
  amountBaseUnits: string
  recipient: string
  terminalEventRefs: EvmEventRef[]
  finality: SettlementFinalityRecord
  observedAt: number
  signature: ComponentSignature
}
```

The canonical form omits `signature`. The signing domain is:

```text
"dacs-escrow-terminal-evidence:v1:" || terminal_evidence_hash
```

- (DRT-1) `released` MUST carry and verify `decisionRef`, its basis, and `deliveryEvidenceRef`.
- (DRT-2) `rejected-refund` MUST carry and verify `decisionRef` and its basis.
- (DRT-3) `expired-refund` MUST omit `decisionRef` and MUST NOT imply an evaluator decision.
- (DRT-4) The terminal event set MUST identify one contract, native job, terminal selector, recipient, token, and amount without ambiguity.
- (DRT-5) A release amount MUST equal the complete funded budget and the recipient MUST equal the seller payout account.
- (DRT-6) A refund amount MUST equal the complete funded budget and the recipient MUST equal the client account.
- (DRT-7) Zero-fee policy and zero preterminal payout MUST be verified from immutable capabilities and authenticated state or events.
- (DRT-8) A terminal event MUST meet the rail's exact finality profile before the evidence can establish a financial disposition.
- (DRT-9) Unavailable otherwise-consistent chain evidence MUST yield `indeterminate`, not a retry on another rail.
- (DRT-10) The phase orchestrator signs terminal evidence, but its signature MUST NOT substitute for chain, evaluator, or agreement verification.
- (DRT-11) `fundingEvidenceRef` MUST resolve to the exact finalized funding record for this job and budget.
- (DRT-12) A post-submission refund MUST carry `deliveryEvidenceRef`; a pre-submission refund MUST omit it.

DACS-5 projection keeps money and accountability separate:

| Terminal evidence | Finding | Commercial projection |
|---|---|---|
| `released` | `seller-fulfilled` | completed delivery and settled value |
| `rejected-refund` | `seller-fault` | failed-counterparty for the seller-facing record |
| `rejected-refund` | `buyer-fault` | buyer-fault annotation; refund does not erase the finding |
| `expired-refund` | `seller-fault` | seller-fault only when authenticated deadlines and state show the seller failed to submit |
| `expired-refund` | `evaluator-unavailable` | refund plus evaluator-unavailability annotation |
| `expired-refund` | `substrate-failure` | failed-substrate, no buyer/seller fault |
| any refund | `no-fault` | refund with no reputation penalty |
| any terminal state | `indeterminate` | financial fact may stand; no invented fault |

The promoted DACS-5 text must define the exact perspective mapping and metric treatment. Until it does, implementations may display these findings but must not include them in conforming v0.1 reputation derivation.

## 8. Candidate `pay-evm-erc8183` binding

The first binding composes the canonical ERC-8183 interface at [`ethereum/ERCs@a078cab`](https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-8183.md). It narrows, rather than inherits, optional ERC behavior.

### 8.1 Exact field mapping

Let `H` be a 64-character lowercase hexadecimal DACS content hash. Let `decode_hex_32(H)` decode those 64 ASCII hex digits to the corresponding 32 bytes.

| ERC field | Exact DACS value |
|---|---|
| `description` | UTF-8/ASCII bytes of `dacs-delivery-remedy:v1:` followed by the `DeliveryOrRemedyAgreement` content hash |
| `deliverable` | `decode_hex_32(contentHash(delivery SettlementEvidence))` |
| `reason` on `complete` or evaluator `reject` | `decode_hex_32(contentHash(EscrowDecision))` |

- (DREB-1) A producer MUST use the exact mapping in this table.
- (DREB-2) A verifier MUST independently recompute every source content hash before decoding it.
- (DREB-3) The content-hash text MUST be exactly 64 lowercase hexadecimal characters.
- (DREB-4) A producer or verifier MUST NOT hash the hexadecimal text, add a `sha256:` prefix, truncate, pad, or reinterpret byte order.
- (DREB-5) `bytes32(0)` MUST NOT be used for the delivery or evaluator reason in this profile.
- (DREB-6) A syntactically valid field with the wrong bytes MUST be rejected as a binding mismatch.

Example:

```text
content hash:  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
bytes32 value: 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

### 8.2 Account and deadline mapping

- (DREB-7) ERC `client` MUST equal the address in the buyer's controlled EVM account claim.
- (DREB-8) ERC `provider` MUST equal the address in the seller's controlled EVM account claim.
- (DREB-9) ERC `evaluator` MUST equal the address in the evaluator's controlled EVM account claim.
- (DREB-10) The payout receiver MUST equal the agreement-bound seller payout account.
- (DREB-11) The native budget and payment token MUST equal the agreement price and pinned rail asset.
- (DREB-12) ERC `expiredAt` MUST equal `submissionCutoffSec`.
- (DREB-13) `evaluationDeadlineSec` MUST equal `submissionCutoffSec + evaluationGracePeriodSec` for a binding that grants a fixed post-expiry grace period.
- (DREB-14) `evaluationDeadlineSec - submissionCutoffSec` MUST be positive and no shorter than the pinned `minimumEvaluationWindowSec`.
- (DREB-15) A submitted job's recovery path MUST become callable no later than the bound evaluation deadline.

No universal duration is declared here. Each registered rail revision pins `minimumEvaluationWindowSec`, `evaluationGracePeriodSec`, and the exact native deadline mapping.

### 8.3 Direct evaluator transaction model

- (DREB-16) The first profile MUST set the native evaluator to the evaluator-controlled account directly.
- (DREB-17) An EOA MAY be used when the agreement-bound DACS control proof resolves that address.
- (DREB-18) An EIP-1271 account MAY be used only when the applicable DACS signature/control verifier supports its exact chain and code.
- (DREB-19) A relayer MUST NOT become the evaluator merely because it submits a transaction.
- (DREB-20) A generic evaluator adapter MUST NOT be used in the first profile.

### 8.4 Deployment eligibility

A rail definition must pin at least:

```text
type ERC8183ProfileParameters = {
  canonicalErcRevision: string
  implementationRevision: string
  chainId: number
  contractAddress: string
  runtimeBytecodeHash: string
  implementationAddress?: string
  implementationRuntimeBytecodeHash?: string
  paymentToken: string
  paymentTokenRuntimeBytecodeHash: string
  tokenDecimals: number
  finalityBlocks: number
  minimumEvaluationWindowSec: number
  evaluationGracePeriodSec: number
  decisionOrderingProfile: string
  platformFeeBP: 0
  evaluatorFeeBP: 0
  capabilityProfile: "dacs-delivery-gate-v1"
}
```

- (DRC-1) The selected contract MUST make preterminal provider payout impossible.
- (DRC-2) The selected contract MUST make platform and evaluator escrow fees immutable at zero.
- (DRC-3) Hooks, pause state, or evaluator absence MUST NOT prevent an eligible expiry recovery call from succeeding.
- (DRC-4) No authority MAY withdraw locked job funds to another recipient.
- (DRC-5) No authority MAY upgrade, detach, or replace logic in a way that weakens DRC-1 through DRC-4.
- (DRC-6) If upgradeability exists syntactically, authenticated finalized state MUST prove the relevant upgrade authority is irreversibly disabled.
- (DRC-7) Hook behavior MUST be absent or immutable and MUST NOT block recovery.
- (DRC-8) The payment token MUST exclude transfer fees, rebasing, callbacks, pause, blacklist, and other behavior that can change exact lock/release/refund accounting.
- (DRC-9) Every action used by the profile MUST emit enough indexed data for event-level job and action identity.
- (DRC-10) A registration proposal MUST provide reproducible source-to-bytecode evidence and independently resolved deployed bytecode.
- (DRC-11) Missing or conflicting deployment evidence MUST leave the rail unregistered and unavailable.
- (DRC-12) The rail MUST define how authenticated evidence orders decision finality before the terminal transaction across the selected substrates.

The current reference implementation at [`erc-8183/base-contracts@142e669`](https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183.sol) is not eligible as published. It exposes UUPS upgrades, administrator pause and emergency withdrawal, mutable fees and hooks, and funded-state claim settlement. Its refund function is pause-gated, and a pending claim can delay a funded-state refund.

This finding does not reject ERC-8183. It means a strict DACS deployment needs a minimal compatible implementation or irreversible authority restrictions that independently prove DRC-1 through DRC-11.

## 9. Verification result and ordering

A verifier returns exactly one of:

```text
"verified" | "rejected" | "indeterminate" | "error"
```

It applies the checks in this order:

1. Parse the selected artifact type and reject unsupported discriminators before action.
2. Validate canonical field encodings and required fields. A malformed input is `error`.
3. Recompute content hashes and verify signatures, signer roles, references, and agreement bindings. An authenticated mismatch is `rejected`.
4. Resolve the pinned rail, code, authority, token, job state, and exact events from authenticated sources.
5. Return `indeterminate` when required external evidence is unavailable but not contradictory.
6. Compare the resolved native facts with the authenticated DACS artifacts. A mismatch is `rejected`.
7. Return `verified` only when every applicable check succeeds.

- (DRV-1) A verifier MUST NOT fall back to a current deployment, registry revision, RPC guess, or caller-supplied field when pinned authority is unavailable.
- (DRV-2) RPC `not found`, timeout, stale state, or inconsistent providers MUST remain `indeterminate` unless authenticated absence is established.
- (DRV-3) A malformed encoding MUST NOT be repaired before hashing or comparison.
- (DRV-4) A signature over internally consistent false fields MUST NOT override independently resolved authority.
- (DRV-5) A retry after `indeterminate` MUST reconcile the original native job and action before submitting any transaction.

## 10. Transcript and evidence disclosure

- (DRQ-1) The first profile MUST use `public-evidence-only` or `explicit-party-supplied` disclosure.
- (DRQ-2) `explicit-party-supplied` means the named party deliberately supplies the exact evidence to the evaluator under the signed policy.
- (DRQ-3) Neither policy authorizes retrieval, decryption, or disclosure of a negotiation transcript.
- (DRQ-4) Encrypted transcript use MUST remain disabled until #351 defines the signed transcript, unanimous member consent, envelope suite, revocation, and SR-2 evidence.
- (DRQ-5) A future transcript-enabled profile MUST use a new disclosure-policy value and a new rail or profile revision.

## 11. Required conformance evidence

Promotion requires full signed artifacts and authenticated native inputs, not expected outputs alone.

### 11.1 Positive cases

1. create, fund, deliver, submit, evaluate, and release the complete budget;
2. create, fund, deliver, submit, evaluate, and refund the complete budget;
3. expiry before submission followed by complete refund;
4. expiry after submission and grace followed by complete refund without an invented evaluator decision;
5. an independently reproduced byte-exact `description`, `deliverable`, and `reason` mapping.

### 11.2 Required rejection cases

1. wrong job, overlay, rail, chain, contract, runtime code, token, budget, decimals, client, provider, evaluator, expiry, payout receiver, or phase index;
2. noncanonical JID or content hash;
3. description prefix, hash-text rehash, byte-order, padding, truncation, or zero-reason mismatch;
4. cross-job delivery, evaluation, decision, terminal-event, or receipt replay;
5. wrong evaluator signer or transaction caller;
6. evaluator collision with buyer, seller, client, or provider;
7. delivery or decision hash substitution;
8. release for a refund decision, or refund for a release decision;
9. nonzero preterminal payout, partial claim, platform fee, or evaluator fee;
10. mutable or changed implementation, hook, authority, or token behavior;
11. ambiguous event identity or mismatched log index;
12. terminal action followed by an attempted monetary replay.

### 11.3 Required indeterminate cases

1. unavailable rail definition or agreement artifact;
2. unavailable or inconsistent authenticated chain state;
3. missing finality evidence;
4. unresolved proxy implementation or authority state;
5. missing delivery/evaluation/decision artifact when no contradictory fact is established;
6. decision and terminal evidence that the pinned ordering profile cannot order across substrates.

Every vector pack must include exact canonical bytes, hashes, signatures, logical addresses, receipts, chain inputs, expected result, and the rule IDs exercised. At least two independent implementations must reproduce the positive bytes and all rejection/indeterminate outcomes before the profile is registered.

## 12. Promotion and ownership gates

### DACS Standard and steward

- obtain one independent approval of the issue #356 decision matrix before steward acceptance;
- split promoted text into the job-escrow lifecycle, ERC-8183 binding, DACS-X artifacts, and DACS-5 projection;
- register every new signature domain and rule ID;
- publish implementation-neutral vectors;
- keep the rail unavailable until deployment evidence and independent reproduction pass.

### Contract and reference implementation contributors

- provide an exact deployment satisfying DRC-1 through DRC-11;
- publish verified source, compiler settings, constructor/initializer inputs, deployed addresses, runtime bytecode hashes, and authority state;
- publish finalized event fixtures for release, rejection, expiry, replay, mismatch, and unavailable-state cases.

### DACS SDK contributors

- implement only after artifact shapes and vector bytes are accepted;
- preserve the four-result verification model and retry reconciliation;
- generate canonical field mappings and reject all alternate encodings;
- never treat a client-side ban on claim functions as contract-level delivery gating.

### Demos runtime contributors

No Demos-native escrow is required for the first EVM binding. A future native binding may implement the same portable lifecycle under a separately evidenced rail definition.

## 13. Reviewer checklist

- [ ] The paired `job-escrow` phase model is implementable without changing existing phase-result semantics.
- [ ] The overlay is structurally distinct and binds buyer, seller, evaluator, deployment, policy, and deadlines.
- [ ] The three ERC field mappings are byte-exact and non-circular.
- [ ] Monetary disposition and accountability finding cannot be conflated.
- [ ] Expiry never invents an evaluator decision or party fault.
- [ ] The contract capability gate rules out every preterminal payout and blocked-recovery path.
- [ ] No current deployment is accidentally presented as registered or available.
- [ ] Transcript use remains outside the profile until #351 is complete.
- [ ] The required vector set is sufficient for a second independent implementation.
