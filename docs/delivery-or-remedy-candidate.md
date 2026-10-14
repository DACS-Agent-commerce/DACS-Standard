# Delivery-or-remedy candidate specification

**Status:** pre-normative review candidate for [issue #356](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/356). It does not change DACS conformance, register a rail, or make any deployment available.

**Target:** a future DACS-4 job-escrow lifecycle and DACS-X evaluation module. The first proposed binding is `pay-evm-erc8183`.

**Checked against:** DACS-Standard `next` at `df7bc202ebdc179a59d61a8221072f33f482b933`. Every CORE, DACS-1 through DACS-5, PROFILE, and DEMOS-MAPPING rule ID cited below means the text at that commit. This includes DACS-4 `DeliveryEvidence` with PDE-1 through PDE-8, consumer-verifiable finality FV-1 through FV-10, CORE JID-1 through JID-4, and CORE IBH-1 through IBH-6.

**External pins:**

- canonical ERC-8183 at [`ethereum/ERCs@a078cab`](https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-8183.md);
- EIP-1271 at [`ethereum/ERCs@a078cab`](https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-1271.md);
- EIP-155 at [`ethereum/EIPs@c1a1eb2`](https://github.com/ethereum/EIPs/blob/c1a1eb21b465c9c42704a8a5743ad0694aedbff7/EIPS/eip-155.md);
- EIP-55 at [`ethereum/EIPs@c1a1eb2`](https://github.com/ethereum/EIPs/blob/c1a1eb21b465c9c42704a8a5743ad0694aedbff7/EIPS/eip-55.md).

**Roadmap gates (non-normative):** the self-contained DACS-X vector pack tracked by #99 and transcript disclosure tracked by #351 are open work items. They are not verdict authority. The pinned revisions above are.

The capitalized requirement words in this document are proposed requirements. They become normative only if promoted into the applicable specification modules by a later steward-approved pull request.

All artifact kinds introduced by this pre-normative candidate use the `dacs-x-` extension-domain form required by CORE SIG-4. Promotion requires explicit domain-registry entries and regenerated review vectors.

- (DRG-1) Candidate signatures MUST NOT be relabelled as signatures under a future registered domain.
- (DRG-2) Each revision of this candidate MUST update the **Checked against** commit and MUST be re-audited against every cited rule at that commit before review. `scripts/validate_candidate_profile.py` MUST pass and its rule-to-case matrix MUST be regenerated in the same change.

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

The candidate therefore proposes two additions to the closed DACS-1 `PhaseType` union: one commit kind and one structurally distinct `job-escrow` kind used exactly twice around one existing delivery phase:

```text
commit-delivery-or-remedy-agreement { agreementPhase: "commit-payee-bound-agreement" | "commit-identity-bound-payee-agreement" }
job-escrow { action: "fund", rail: "evm-erc8183:<chainId>:<asset>" }
deliver-*
job-escrow { action: "terminal", rail: "evm-erc8183:<chainId>:<asset>" }
rate?
```

The two `job-escrow` invocations are one paired lifecycle, not two payments. The fund invocation proves value was locked. The terminal invocation proves release or refund.

An older reader sees unknown agreement and phase discriminators and rejects the Listing before execution; DRP-13 states what it must not do instead.

### 2.1 Candidate phase shapes

```text
type DeliveryOrRemedyCommitPhaseStep = {
  kind: "commit-delivery-or-remedy-agreement"
  parameters: {
    agreementPhase: "commit-payee-bound-agreement" | "commit-identity-bound-payee-agreement"
  }
}

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
- (DRP-4) A delivery-or-remedy pipeline MUST NOT contain any other payment, delivery, or `pay-alternative` step between or alongside the pair; a verifier MUST return `fail` for a pipeline that contains one.
- (DRP-5) Both steps MUST name the same complete, agreement-selected rail definition. A verifier MUST derive the effective profile parameters from that authenticated, content-hash-bound definition; a detached caller or fixture projection MUST NOT override or weaken them.
- (DRP-6) The delivery step MUST NOT begin until finalized evidence proves the exact budget is locked.
- (DRP-7) When delivery was submitted, the terminal step MUST use the exact signed current DACS-4 `DeliveryEvidence` (`deliveryEvidenceVersion: "1"`, signed under `dacs-delivery-evidence:v1:`, anchored at `dacs4:delivery:{jobId}:{phaseIndex}`) produced by the intervening step. Its `phaseIndex` MUST equal the overlay's `deliveryPhaseIndex`, and it MUST satisfy PDE-1 through PDE-8. A historical delivery-shaped `SettlementEvidence` admitted only under PDE-7 MUST NOT satisfy this profile. A pre-submission expiry or evaluator-rejection refund MUST instead omit delivery evidence as required by DRD-9 and DRT-12.
- (DRP-8) Until the DACS-5 projection in section 7 is promoted, job-escrow artifacts MUST NOT be carried as DACS-5 session-bundle settlement members and MUST NOT contribute to DACS-5 volume. After promotion, the pair MUST count as at most one purchase at the agreement price, and only on `released`.
- (DRP-9) The delivery evidence content hash MUST be fixed before the native submission call. The hashed artifact MUST NOT contain or derive any field from the resulting native submission transaction or event. Later authenticated native evidence binds that already-fixed digest to the native job; it is not part of the digest itself.
- (DRP-10) The paired `job-escrow` lifecycle counts as one concrete payment selection for DACS-1 §6.3.4 step 8 and the `acceptedRails` rule referenced by DACS-4 PIPE-1. It remains structurally outside the `pay-*` and `pay-alternative` registries and MUST NOT inherit PIPE-3 through PIPE-5 by implication. PIPE-2 ordering applies unchanged.
- (DRP-11) DACS-4 PIPE-6 applies to the `fund` and `terminal` invocations. The commit phase produces two CORE §5.1 receipts: one for the bilateral agreement commitment and one for the overlay commitment. Before the orchestrator submits any transaction that can lock or move value, it MUST verify that both are `finalized` and match the session's `jobId`.
- (DRP-12) On the ordinary submitted path, the `terminal` invocation MUST NOT execute until the intervening `deliver-*` invocation has returned and the native submission is authenticated. It MAY execute without a returned delivery only after authenticated native time has reached `submissionCutoffSec`, or through the DRD-12 pre-submission rejection path. In either exception, the orchestrator MUST cancel or permanently ignore any late delivery result and MUST NOT submit it to a terminal or refunded native job.
- (DRP-13) An older reader MUST NOT remove either phase, reinterpret `job-escrow` as an ordinary payment, or execute the delivery outside the pair.
- (DRP-14) The commit phase MUST run the existing handler named by `agreementPhase` for the bilateral payout-bearing `AgreementArtifact`, then commit the finalized `DeliveryOrRemedyAgreement` overlay at its section 6.5 address. It MUST return one `PhaseHandlerResult` whose `ok: true` requires both commitments to be `finalized`. Any other `agreementPhase` value MUST yield `error`.
- (DRP-15) Each `job-escrow` invocation MUST apply the gate table in section 2.3. A gate listed as not applicable MUST NOT be cited as satisfied.

> **Note (non-normative).** A single long-running phase would need a new suspended result state. The paired form preserves the current one-result-per-invocation contract and makes the preterminal delivery hash available without a circular terminal-evidence hash.

### 2.2 Rail definition, Listing selection, and dispatch

`RailDefinition.railType` and `phaseHandler` are closed unions in DACS-4, so a job-escrow rail is a distinct signed definition:

```text
type JobEscrowRailDefinition = {
  jobEscrowRailVersion: "1"
  railId: string
  railVersion: number
  supersedes?: AttestationRef
  railType: "evm-erc8183"
  phaseHandler: "job-escrow"
  parameters: ERC8183ProfileParameters
  consumerFinalityProfile: ConsumerFinalityProfile
  availability: string
  signature: ComponentSignature
}
```

The canonical form omits `signature`. The registry steward signs:

```text
"dacs-x-job-escrow-rail:v1:" || job_escrow_rail_hash
```

- (DRR-1) `railId` MUST match `evm-erc8183:<chainId>:<asset>`. `<chainId>` is the bare positive decimal EIP-155 chain ID with no leading zero and equals `parameters.chainId`. `<asset>` is a non-empty token symbol of ASCII uppercase letters and digits. Any other spelling MUST yield `error`.
- (DRR-2) RD-1 through RD-7 apply to a `JobEscrowRailDefinition` with `"dacs-x-job-escrow-rail:v1:"` replacing `"dacs-rail:v1:"`. `phaseHandler` MUST equal `job-escrow` in every version sharing a `railId`.
- (DRR-3) The Listing MUST advertise the rail through an `acceptedRails` `PaymentRailRef` whose `railId` equals both `job-escrow` steps' `parameters.rail`. LRR-1 through LRR-6 apply with `job-escrow` standing in for the concrete `PaymentPhaseType` in LRR-1 and LRR-4, so the resolved `phaseHandler` MUST equal `job-escrow`.
- (DRR-4) The rail MUST carry a complete `consumerFinalityProfile` with `model: "block-depth"`, `settlement.networkId` equal to `eip155:<chainId>`, and `settlement.requiredDepth` equal to `parameters.finalityBlocks`. A rail without one MUST NOT be selectable.
- (DRR-5) An orchestrator MUST apply RAV-R1 through RAV-R5 unchanged when it selects a job-escrow rail.
- (DRR-6) An unsupported `jobEscrowRailVersion`, `railType`, or `phaseHandler` MUST yield `error`; an unavailable definition MUST yield `indeterminate`.

### 2.3 Gates applied to each invocation

| Gate | `fund` | `terminal` |
|---|---|---|
| DACS-4 PIPE-6 | applies (DRP-11) | applies (DRP-11) |
| CORE IBH-1 through IBH-6 | applies when `agreementPhase` is `commit-identity-bound-payee-agreement`; IBH-4 and IBH-5 rerun before the lock | applies under the same condition; IBH-4 and IBH-5 rerun before any evaluator or recovery transaction |
| DACS-4 PB-1 through PB-3 | applies to the single payout binding of DRA-20 before the lock | PB-1 recipient equality applies to the release recipient (DRT-5) |
| DACS-4 PC-1 through PC-6 | not applicable: they define one-invocation `PaymentPhaseInput`, `SettlementEvidence`, and `dacs4:payment:` production. DRF-1 through DRF-8 and DRT-1 through DRT-16 restate the binding, anchoring, and classification duties for this lifecycle | not applicable, as for `fund` |
| DACS-4 PC-7 | applies: native finality and SR-2 anchoring of `EscrowFundingEvidence` are separate gates | applies to `EscrowTerminalEvidence` |
| DACS-4 SB-1 through SB-3 | SB-1 event spelling applies to every `EvmEventRef` (DRW-3); SB-2 collision authority applies to `fundingEventRefs`; this rail declares no SB-3 binding because the native `description` carries the overlay hash (DREB-1) | as for `fund`, over `terminalEventRefs` |
| DACS-4 RD-1 through RD-7 | applies through DRR-2 | applies through DRR-2 |
| DACS-1 LRR-1 through LRR-6 | applies through DRR-3 at Listing time | applies through DRR-3 at Listing time |
| DACS-4 RAV-R1 through RAV-R5 | applies through DRR-5 | RAV-R4 applies at the point of use |

## 3. Roles and signed agreement

The existing bilateral payout-bearing `AgreementArtifact` remains the commercial agreement. A distinct three-party overlay adds the evaluator, escrow deployment, deadlines, evaluation rule, and disclosure policy without changing the meaning of existing agreement fields.

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
  submissionCutoffSec: number          // unix seconds
  evaluationDeadlineSec: number        // unix seconds
  preSubmissionRefundPolicy: "evaluator-rejection"
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
"dacs-x-delivery-remedy-agreement:v1:" || agreement_overlay_hash
```

`agreement_overlay_hash` is the lowercase hexadecimal SHA-256 digest of the RFC 8785 canonical form after CORE canonicalization.

- (DRA-1) `agreementRef` MUST resolve to the exact finalized bilateral `AgreementArtifact` for `jobId`.
- (DRA-2) `agreementHash` MUST equal the resolved bilateral agreement's recomputed content hash.
- (DRA-3) The buyer, seller, and evaluator MUST each contribute exactly one valid signature over the same overlay hash.
- (DRA-4) Each role's `primaryClaim`, bundle, Vet result, and EVM account claim MUST be independently resolved and verified.
- (DRA-5) Each EVM account claim MUST use the DACS EIP-155 form `cci-xm:evm:<chainId>:<address>` for the selected rail's chain, with an address component that satisfies DRW-1.
- (DRA-6) The evaluator's primary claim MUST differ from both commercial parties under CORE CF-3 identity.
- (DRA-7) The evaluator's controlled EVM account MUST differ from the client and provider accounts, compared as DRW-1 20-byte values.
- (DRA-8) The evaluator's exact `BundleRequirement` MUST hash to `requirementHash` and match the authenticated DACS-2 composite result.
- (DRA-9) The evaluator's Vet result MUST be `pass` and fresh at funding under the bound requirement. Freshness MUST be evaluated at `fundingTimeMs = fundingBlockTimestampSec × 1000`, where `fundingBlockTimestampSec` is read from the authenticated inclusion-block header of the exact funding event under DRF-8. That value MUST then be used as `now` in the unchanged DACS-2 VP-C1 window, in milliseconds. `observedAt`, a caller-supplied `fundedAt`, or a local clock MUST NOT establish that time.
- (DRA-10) `budgetBaseUnits` MUST be the minimal unsigned decimal form of the exact agreement price after conversion using the pinned token decimals.
- (DRA-11) The overlay MUST bind the three ordered phase indexes selected by DRP-1 through DRP-3.
- (DRA-12) The overlay MUST be finalized and independently resolvable before job creation or funding.
- (DRA-13) The evaluator signature authenticates only this overlay. It MUST NOT add the evaluator to the bilateral `AgreementArtifact`, make the evaluator a buyer or seller, or add an evaluator signature requirement to the buyer/seller `AttestationBundle`.
- (DRA-14) The native client, provider, evaluator, token, budget, release recipient, pre-submission rejection policy, and applicable deadlines MUST be fixed and authenticated no later than funding. A later mutable replacement MUST prevent progression.
- (DRA-15) `preSubmissionRefundPolicy` MUST be signed before funding and MUST equal `evaluator-rejection` in this profile. A different value is an unsupported profile, not a client-side restriction on the native evaluator.
- (DRA-16) Decisionless expiry remains available regardless of the fixed pre-submission policy. A future `expiry-only` profile MUST select an implementation that immutably disables evaluator rejection while funded; an SDK omission, caller convention, or post-transaction verifier rejection is insufficient.
- (DRA-17) The overlay `buyer` and `seller` bindings MUST equal the resolved `AgreementArtifact.parties` entries for the same role: `primaryClaim` under CORE CF-3 identity, and `bundleHash` and `vetRecordRef` byte-exactly. When the agreement is identity-bound, the IBH-5 join MUST also succeed for each role.
- (DRA-18) Each `DeliveryOrRemedySignature.party` MUST equal its `role`'s `primaryClaim` under CORE CF-3 identity. The three `role` values MUST be distinct.
- (DRA-19) `submissionCutoffSec` and `evaluationDeadlineSec` MUST be non-negative integers no greater than `9007199254740`. `evaluationDeadlineSec × 1000` MUST be less than or equal to the bilateral agreement's `terms.deadline`, which is in unix milliseconds.
- (DRA-20) The bilateral agreement MUST carry exactly one `terms.payoutBindings` entry for the job-escrow pair, keyed `(railId, fundPhaseIndex)`. Its `payeeAddress` is the seller payout account. In this profile it MUST equal, as a DRW-1 20-byte value, the address in the seller's EVM account claim. PB-1 through PB-3 apply to that entry.

The evaluator requirement is deal policy, not a universal arbitrator credential. A live Listing or agreement chooses the credential strength appropriate to the value and subject matter.

### 3.1 Wire encodings

- (DRW-1) An EVM address in a DACS artifact field (`contractAddress`, `implementationAddress`, `paymentToken`, `token`, `recipient`) MUST be `0x` followed by exactly 40 lowercase hexadecimal digits. Any other spelling is malformed and MUST yield `error` without repair. The address component of a `cci-xm:evm:<chainId>:<address>` claim, taken before any `?` parameters, MUST be `0x` followed by exactly 40 hexadecimal digits in all-lowercase, all-uppercase, or valid EIP-55 mixed case; anything else MUST yield `error`. Every comparison MUST decode both operands to 20 bytes and compare the bytes. The zero address MUST yield `fail` for client, provider, evaluator, contract, and token.
- (DRW-2) Every EVM code hash field, namely `runtimeBytecodeHash`, `implementationRuntimeBytecodeHash`, and `paymentTokenRuntimeBytecodeHash`, MUST be keccak-256 of the deployed runtime bytecode. That is the `EXTCODEHASH` value of a non-empty account. It MUST be spelled `0x` followed by 64 lowercase hexadecimal digits.
- (DRW-3) `EvmEventRef` is the DACS-4 `ChainTxRef` `evm-event` arm. `txHash` MUST use its SB-1 canonical spelling; any other spelling MUST yield `error`.
- (DRW-4) `observedAt` MUST be unix milliseconds. Every field whose name ends in `Sec` MUST be unix seconds. A comparison between a seconds value and a milliseconds value MUST first multiply the seconds value by 1000 and MUST yield `error` if the product exceeds `9007199254740991`.

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
- (DRL-7) Value MUST NOT reach the seller or any seller payout destination before `released`.
- (DRL-8) The selected implementation MUST make DRL-7 true through its immutable capability and authority model.
- (DRL-9) Client policy, SDK omission, hook convention, or event non-observation MUST NOT substitute for DRL-8.

### 4.1 ERC-8183 state crosswalk

Native `Rejected` and `Expired` are ambiguous without the prior native status. The crosswalk is therefore keyed on the prior native status, the entrypoint, the contract-authenticated caller (DREB-21), and the authenticated events:

| Prior native status | Entrypoint and caller | Required events | Native status after | Portable state | Terminal state |
|---|---|---|---|---|---|
| none | `createJob` by client | `JobCreated` | `Open` | `created` | — |
| `Open` | `reject` by client | `JobRejected` | `Rejected` | `cancelled` | — |
| `Open` | `fund` by client | `JobFunded` (exact budget) | `Funded` | `funded` | — |
| `Funded` | `submit` by provider, before `submissionCutoffSec` | `JobSubmitted` | `Submitted` | `submitted` | — |
| `Submitted` | `complete` by evaluator | `JobCompleted`, `PaymentReleased` (provider, full budget) | `Completed` | `released` | `released` |
| `Funded` | `reject` by evaluator | `JobRejected`, `Refunded` (client, full budget) | `Rejected` | `refunded` | `rejected-refund`, pre-submission |
| `Submitted` | `reject` by evaluator | `JobRejected`, `Refunded` (client, full budget) | `Rejected` | `refunded` | `rejected-refund`, post-submission |
| `Funded` or `Submitted` | `claimRefund` by any caller, at or after `evaluationDeadlineSec` | `JobExpired`, `Refunded` (client, full budget) | `Expired` | `refunded` | `expired-refund` |

- (DRL-10) A verifier MUST derive the portable state and terminal state only from this table, applied to authenticated evidence for the prior native status, entrypoint, caller, and events.
- (DRL-11) Any other authenticated transition MUST yield `fail`, because it shows that the deployment is not the capability profile it claims. This includes `Open` to `Expired`, a provider cancel of `Open`, and an `Open` to `Submitted` zero-budget submit. It also includes a refund move without the full-budget `Refunded` event and any transition out of a terminal status.
- (DRL-12) If the prior native status, entrypoint, or caller cannot be authenticated, the verifier MUST yield `indeterminate`.

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
"dacs-x-escrow-job-ref:v1:" || escrow_job_ref_hash
```

- (DRJ-1) `nativeJobId` MUST match `"0" | [1-9][0-9]*` and MUST denote an integer in `[0, 2^256 - 1]`. A sign, `0x` prefix, whitespace, leading zero, or out-of-range value MUST yield `error`. The verifier MUST compare its numeric value with the `jobId` topic of the authenticated creation event.
- (DRJ-2) `creationEvent` MUST resolve to exactly one finalized job-creation event at the pinned contract.
- (DRJ-3) The authenticated creation/configuration event set's client, provider, evaluator, submission cutoff, expiry/recovery deadline, and pre-submission rejection policy MUST match the overlay and rail definition. Its `hook` MUST equal the zero address required by DRC-7.
- (DRJ-4) The native job `description` MUST equal the byte-exact agreement binding in section 8.1. The verifier MUST obtain it by ABI-decoding the `createJob` calldata of the creating transaction. That transaction's bytes MUST be proven under FV-5 for the transaction that emitted `creationEvent`. The transaction MUST call `contractAddress` directly with the `createJob` selector. An `eth_call`, `getJob`, or other unauthenticated read MUST NOT establish `description`.
- (DRJ-5) `runtimeBytecodeHash` MUST match, under DRW-2, authenticated code at the finalized creation block and at each later action block.
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
  observedAt: number                   // unix ms
  signature: ComponentSignature
}
```

`SettlementFinalityRecord` is the existing DACS-4 type and retains its exact registered shape (`model`, the model-specific parameter such as `finalityBlocks`, and `finalityObservedAt`). Under FV-1 through FV-10 it is producer testimony only. The EVM event's block number, block hash, block timestamp, inclusion, and confirmation facts are established by FV-1 through FV-10 over `AuthenticatedChainObservation`; they are not unregistered replacement members of `SettlementFinalityRecord`. The same boundary applies to `EscrowTerminalEvidence.finality` below. DACS-4 currently documents `SettlementFinalityRecord` as populated by payment phases only; promotion requires a DACS-4 note extending that comment to `job-escrow` invocations.

The canonical form omits `signature`. The signing domain is:

```text
"dacs-x-escrow-funding-evidence:v1:" || escrow_funding_evidence_hash
```

- (DRF-1) Funding evidence MUST bind the exact overlay, job reference, and `fund` phase index.
- (DRF-2) The native token and amount MUST equal the pinned rail asset and `budgetBaseUnits`.
- (DRF-3) The event set MUST prove the complete budget entered escrow for the exact native job and supply its authenticated block timestamp for DRA-9. Every event reference MUST retain the exact `EvmEventRef` kind and chain binding.
- (DRF-4) The resulting native state MUST map to portable state `funded` under DRL-10.
- (DRF-5) The verifier MUST establish that no value reached the provider or any seller payout destination.
- (DRF-6) Funding evidence MUST meet the rail's exact `consumerFinalityProfile` before delivery begins.
- (DRF-7) The authenticated session orchestrator MUST sign and anchor the funding evidence through SR-2.
- (DRF-8) This profile uses authenticated chain facts for creation, funding, submission, terminal action, code, authority, and block timestamp. Each MUST be established by FV-1 through FV-10 under the rail's `consumerFinalityProfile`, over an `AuthenticatedChainObservation` whose `transactionRef` is the exact `EvmEventRef`. Block time MUST be read from the authenticated inclusion-block header. A single unauthenticated RPC response MUST NOT establish any of these facts.

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
  criterionResults: { criterionId: string; outcome: "satisfied" | "unsatisfied" | "indeterminate" }[]
  result: "accept" | "reject" | "indeterminate"
  finding: AccountabilityFinding
  subjectEvidenceRefs: AttestationRef[]
  signature: ComponentSignature
}
```

The canonical form omits `signature`. The signing domain is:

```text
"dacs-x-execution-evaluation:v1:" || execution_evaluation_hash
```

- (DRE-1) The signer MUST be the exact agreement-bound evaluator primary claim.
- (DRE-2) `deliveryEvidenceRef` MUST resolve to the finalized, independently resolvable, signed current `DeliveryEvidence` for the agreed `deliveryPhaseIndex`, satisfying DRP-7.
- (DRE-3) Every subject evidence reference MUST be hash-bound, authenticated, and within the signed disclosure policy.
- (DRE-4) An `indeterminate` evaluation MUST NOT authorize a terminal evaluator transaction.
- (DRE-5) Missing or unavailable evidence MUST remain `indeterminate`; it MUST NOT be converted to rejection or acceptance.
- (DRE-6) The evaluator MUST derive `result` and `finding` under the exact `evaluationRuleRef` bound by the overlay.
- (DRE-7) The evaluation MUST be anchored and independently resolvable before it is used as a decision basis.

### 6.2 EvaluationRule

The overlay binds the rule by content hash, so the three overlay signatures are its authority. The rule itself carries no separate signature.

```text
type EvaluationRule = {
  evaluationRuleVersion: "1"
  ruleKind: "evaluator-judgement-v1"
  jobId: string
  criteria: { criterionId: string; statement: string }[]
}
```

Result and disposition matrix for `evaluator-judgement-v1`:

| Criterion outcomes | `result` | Permitted `finding.classification` | Permitted `EscrowDecision.disposition` |
|---|---|---|---|
| every criterion `satisfied` | `accept` | `seller-fulfilled` | `release-to-provider` |
| at least one criterion `unsatisfied` | `reject` | `seller-fault`, `buyer-fault`, `no-fault`, `substrate-failure` | `refund-to-client` |
| otherwise | `indeterminate` | `indeterminate`, `evaluator-unavailable` | none (DRE-4) |

- (DRE-8) `evaluationRuleRef` MUST resolve to an `EvaluationRule` whose recomputed content hash matches the reference and whose `jobId` equals the overlay's `jobId`. The rule MUST be anchored at its section 6.5 address and finalized before the overlay is finalized. An unavailable rule MUST yield `indeterminate`, and a hash mismatch MUST yield `fail`.
- (DRE-9) `criteria` MUST be non-empty, and every `criterionId` MUST be unique. An unsupported `evaluationRuleVersion` or `ruleKind` MUST yield `error`.
- (DRE-10) `ExecutionEvaluation.criterionResults` MUST contain exactly one entry per rule criterion, in rule order. `result` and `finding.classification` MUST be the values this matrix permits for those outcomes; any contradiction MUST yield `fail`.

### 6.3 EscrowDecision

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
"dacs-x-escrow-decision:v1:" || escrow_decision_hash
```

- (DRD-1) The signer MUST be the exact agreement-bound evaluator primary claim.
- (DRD-2) The basis MUST resolve and authorize the selected disposition under the section 6.2 matrix of the bound evaluation rule.
- (DRD-3) A release or post-submission refund decision MUST bind the exact delivery evidence.
- (DRD-4) The decision MUST be signed, anchored, finalized, and independently resolvable before the terminal transaction is submitted.
- (DRD-5) `release-to-provider` MUST map only to the native full-release action.
- (DRD-6) `refund-to-client` MUST map only to the native evaluator-rejection action.
- (DRD-7) Expiry recovery MUST NOT manufacture an `EscrowDecision` or evaluator signature.
- (DRD-8) A decision already observed in a terminal job MUST NOT authorize any other job or transaction.
- (DRD-9) A pre-submission refund decision MUST omit `deliveryEvidenceRef` and use a `DisputeOutcome` basis.
- (DRD-10) Authenticated substrate evidence MUST order the decision's finality before the terminal transaction under the rail's `decisionOrderingProfile` (DRC-15).
- (DRD-11) A self-reported decision time, block number, or `decidedAt` extension MUST NOT establish DRD-10. Evidence that places finality after the terminal transaction MUST yield `fail`; evidence that cannot order the two events MUST yield `indeterminate`.
- (DRD-12) A pre-submission evaluator rejection is distinct from expiry. It MUST be authorized by the signed agreement policy and a finalized `DisputeOutcome`, omit delivery evidence, and map only to the native evaluator-rejection action.
- (DRD-13) The selected implementation MUST bind the expected prior native status into the evaluator's `reject` entrypoint and revert when it differs. A pre-submission decision MUST execute only against `Funded`. If a native `submit` lands first, the pre-submission decision cannot execute, and the evaluator MUST issue a new post-submission decision bound to the delivery evidence. A `Submitted` to `Rejected` transition whose decision omits `deliveryEvidenceRef` MUST yield `fail`.

### 6.4 DisputeCase and DisputeOutcome

```text
type DisputeCase = {
  disputeCaseVersion: "1"
  jobId: string
  caseId: string
  deliveryOrRemedyAgreementHash: string
  openedByRole: "buyer" | "seller" | "evaluator"
  subjectEvidenceRefs: AttestationRef[]
  signature: ComponentSignature
}
```

The canonical form omits `signature`. The signing domain is:

```text
"dacs-x-dispute-case:v1:" || dispute_case_hash
```

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
"dacs-x-dispute-outcome:v1:" || dispute_outcome_hash
```

- (DRX-1) A `DisputeOutcome` MUST NOT directly instruct or claim an on-chain transfer.
- (DRX-2) A preterminal outcome MAY support a distinct `EscrowDecision` under DRD-1 through DRD-8.
- (DRX-3) A post-terminal outcome MAY supersede only an accountability finding.
- (DRX-4) A post-terminal outcome MUST NOT replace, replay, reverse, or relabel the observed financial disposition.
- (DRX-5) `faultedParty` MUST be present only for `seller-fault` or `buyer-fault` and MUST equal the applicable agreement party.
- (DRX-6) `evaluator-unavailable`, `substrate-failure`, `no-fault`, and `indeterminate` MUST NOT be projected as buyer or seller fault.
- (DRX-7) `caseRef` MUST resolve to a `DisputeCase` with the same `jobId`, `caseId`, and `deliveryOrRemedyAgreementHash`. Its signer MUST equal, under CORE CF-3 identity, the overlay `primaryClaim` of `openedByRole`, and the `DisputeOutcome` signer MUST be the overlay evaluator.
- (DRX-8) These two artifacts are distinct from the output-only DACS-X `dispute` candidate rows in `conformance/MANIFEST.json`. Those rows cover arbitrator dispute records and reputation reweighting, and this candidate neither supersedes nor retires them. A consumer MUST NOT accept one family's artifact, domain, or discriminator as the other's. Promotion MUST either reconcile the two into one DACS-X dispute module or register both with disjoint domains.

### 6.5 Candidate logical addresses

| Artifact | Logical address |
|---|---|
| `DeliveryOrRemedyAgreement` | `dacs4:job-escrow:{jobId}:agreement` |
| `EvaluationRule` | `dacs4:job-escrow:{jobId}:evaluation-rule` |
| `EscrowJobRef` | `dacs4:job-escrow:{jobId}:job` |
| `EscrowFundingEvidence` | `dacs4:job-escrow:{jobId}:funding` |
| `ExecutionEvaluation` | `dacs4:job-escrow:{jobId}:evaluation:{evaluationSeq}` |
| `EscrowDecision` | `dacs4:job-escrow:{jobId}:decision` |
| `EscrowTerminalEvidence` | `dacs4:job-escrow:{jobId}:terminal` |
| `DisputeCase` | `dacs4:job-escrow:{jobId}:dispute:{caseId}:case` |
| `DisputeOutcome` | `dacs4:job-escrow:{jobId}:dispute:{caseId}:outcome:{revision}` |

- (DRAA-1) `jobId` and `caseId` MUST use the current canonical JID form.
- (DRAA-2) Every numeric segment MUST use minimal unsigned decimal ASCII without a sign or leading zero.
- (DRAA-3) On a substrate whose native address is a pure function of the logical address, a binding MUST derive the native address from the complete logical address. On Demos SR-2, which uses write-input mapping, the producer MUST publish the logical-to-native binding as DEMOS-MAPPING requires, and a consumer MUST resolve through that published binding.
- (DRAA-4) Uniqueness of the agreement, job, funding, decision, and terminal artifacts for one job comes from content-hash-bound references and the native `description`, `deliverable`, and `reason` bytes, not from storage immutability. A producer MUST NOT write a second distinct artifact at one of these addresses and MUST NOT delete or mutate an anchored artifact.
- (DRAA-5) An observed artifact whose recomputed content hash differs from the hash-bound reference MUST yield `fail`. A deleted, unavailable, or not-found artifact MUST yield `indeterminate`.
- (DRAA-6) `evaluationSeq` MUST start at zero and MUST increment by one with no gap.
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
  terminalPhaseIndex: number
  terminalState: "released" | "rejected-refund" | "expired-refund"
  disposition: "release-to-provider" | "refund-to-client"
  decisionRef?: AttestationRef
  deliveryEvidenceRef?: AttestationRef
  token: string
  amountBaseUnits: string
  recipient: string
  terminalEventRefs: EvmEventRef[]
  finality: SettlementFinalityRecord
  observedAt: number                   // unix ms
  signature: ComponentSignature
}
```

The canonical form omits `signature`. The signing domain is:

```text
"dacs-x-escrow-terminal-evidence:v1:" || terminal_evidence_hash
```

- (DRT-1) `released` MUST carry and verify `decisionRef`, its basis, and `deliveryEvidenceRef`.
- (DRT-2) `rejected-refund` MUST carry and verify `decisionRef` and its basis.
- (DRT-3) `expired-refund` MUST omit `decisionRef` and MUST NOT imply an evaluator decision.
- (DRT-4) The terminal event set MUST identify one chain, contract, native job, terminal selector, recipient, token, and amount without ambiguity. Every event reference MUST retain the exact `EvmEventRef` kind and chain binding.
- (DRT-5) A release amount MUST equal the complete funded budget. The recipient MUST equal the DRA-20 seller payout account, which in this profile is ERC `provider`.
- (DRT-6) A refund amount MUST equal the complete funded budget and the recipient MUST equal the client account.
- (DRT-7) Zero-fee policy and zero preterminal payout MUST be verified from immutable capabilities and authenticated state or events.
- (DRT-8) A terminal event MUST meet the rail's exact `consumerFinalityProfile` under DRF-8 before the evidence can establish a financial disposition.
- (DRT-9) Unavailable otherwise-consistent chain evidence MUST yield `indeterminate`, not a retry on another rail.
- (DRT-10) The phase orchestrator signs terminal evidence, but its signature MUST NOT substitute for chain, evaluator, or agreement verification.
- (DRT-11) `fundingEvidenceRef` MUST resolve to the exact finalized funding record for this job and budget.
- (DRT-12) A post-submission refund MUST carry `deliveryEvidenceRef`; a pre-submission refund MUST omit it. A verifier MUST derive the pre/post-submission classification from the DRL-10 prior native status, authenticated under DRF-8; a caller-supplied boolean MUST NOT establish it.
- (DRT-13) An expiry refund without an authenticated accountability finding MUST project no buyer or seller fault. A separate later `DisputeOutcome` MAY establish accountability but MUST NOT relabel or reverse the financial disposition.
- (DRT-14) Any candidate financial/accountability projection MUST be recomputed from the authenticated terminal evidence and finding according to the table below. A contradictory caller-supplied projection MUST yield `fail`. Until the DACS-5 mapping is promoted, this projection remains display-only and MUST NOT enter conforming v0.1 reputation derivation.
- (DRT-15) `terminalPhaseIndex` MUST equal the overlay's `terminalPhaseIndex`.
- (DRT-16) Observing the same terminal native transaction again MUST reproduce the byte-identical `EscrowTerminalEvidence` content hash. A second, distinct terminal evidence record for the same job MUST yield `fail`.

DACS-5 projection keeps money and accountability separate. Each row gives the role-relative DACS-5 `outcome` for the buyer-anchored and seller-anchored copies and the absolute `faultedParty`, consistent with the DACS-5 `(outcome, anchoredByRole)` permissible-value table. The evaluator is not a DACS-5 `SessionParty` role, so evaluator findings are annotations only.

| Terminal evidence | Finding | Buyer-anchored `outcome` | Seller-anchored `outcome` | `faultedParty` |
|---|---|---|---|---|
| `released` | `seller-fulfilled` | `completed` | `completed` | `none` |
| `rejected-refund` | `seller-fault` | `failed-counterparty` | `failed-perm` | `seller` |
| `rejected-refund` | `buyer-fault` | `failed-perm` | `failed-counterparty` | `buyer` |
| `expired-refund` | `seller-fault`, only when authenticated deadlines and state show the seller failed to submit | `failed-counterparty` | `failed-perm` | `seller` |
| `expired-refund` | `evaluator-unavailable` | no fault projection | no fault projection | none; evaluator-unavailability annotation only |
| any refund | `substrate-failure` | `failed-substrate` | `failed-substrate` | `none` |
| any refund | `no-fault` | no fault projection | no fault projection | none; refund annotation only |
| any terminal state | `indeterminate` | no projection | no projection | none; the financial fact may stand |

The promoted DACS-5 text must define the metric treatment of these rows. Until it does, implementations may display these findings but must not include them in conforming v0.1 reputation derivation.

## 8. Candidate `pay-evm-erc8183` binding

The first binding composes the canonical ERC-8183 interface at [`ethereum/ERCs@a078cab`](https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-8183.md). It narrows, rather than inherits, optional ERC behavior.

### 8.1 Exact field mapping

Let `H` be a 64-character lowercase hexadecimal DACS content hash. Let `decode_hex_32(H)` decode those 64 ASCII hex digits to the corresponding 32 bytes.

| ERC field | Exact DACS value |
|---|---|
| `description` | UTF-8/ASCII bytes of `dacs-x-delivery-remedy:v1:` followed by the `DeliveryOrRemedyAgreement` content hash |
| `deliverable` | `decode_hex_32(contentHash(DeliveryEvidence))` for the DRP-7 `DeliveryEvidence` |
| `reason` on `complete` or evaluator `reject` | `decode_hex_32(contentHash(EscrowDecision))` |

- (DREB-1) A producer MUST use the exact mapping in this table.
- (DREB-2) A verifier MUST independently recompute every source content hash before decoding it.
- (DREB-3) The content-hash text MUST be exactly 64 lowercase hexadecimal characters.
- (DREB-4) A producer or verifier MUST NOT hash the hexadecimal text, add a `sha256:` prefix, truncate, pad, or reinterpret byte order.
- (DREB-5) `bytes32(0)` MUST NOT be used for the delivery or evaluator reason in this profile.
- (DREB-6) A syntactically valid field with the wrong bytes MUST yield `fail` as a binding mismatch.

Example:

```text
content hash:  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
bytes32 value: 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

### 8.2 Account and deadline mapping

- (DREB-7) ERC `client` MUST equal the address in the buyer's controlled EVM account claim.
- (DREB-8) ERC `provider` MUST equal the address in the seller's controlled EVM account claim.
- (DREB-9) ERC `evaluator` MUST equal the address in the evaluator's controlled EVM account claim.
- (DREB-10) The canonical ERC-8183 surface pays `provider` on `complete` and has no separate payout receiver. The native release recipient MUST therefore equal ERC `provider` and the DRA-20 seller payout account. An implementation with a separate payout-receiver surface MUST prove from finalized state that the receiver is unset or equal to `provider`, and immutable from funding onward.
- (DREB-11) The native budget and payment token MUST equal the agreement price and pinned rail asset.
- (DREB-12) ERC `expiredAt` MUST equal `evaluationDeadlineSec`. It is the terminal recovery deadline, not the submission cutoff.
- (DREB-13) The selected implementation MUST separately and immutably commit `submissionCutoffSec`. It MUST expose authenticated evidence of that per-job value and reject native `submit` calls at or after it, even while the job remains funded awaiting expiry recovery.
- (DREB-14) `evaluationDeadlineSec - submissionCutoffSec` MUST be positive and no shorter than the pinned `minimumEvaluationWindowSec`.
- (DREB-15) The native expiry-recovery path for either a funded or submitted job MUST become callable at `evaluationDeadlineSec` and MUST NOT become callable before it.

No universal duration is declared here. Each registered rail revision pins `minimumEvaluationWindowSec`, the deadline profile, and the exact native enforcement and mapping.

### 8.3 Direct evaluator transaction model

The native caller of an entrypoint is the account the escrow contract authenticates for that call: `msg.sender` of the call frame entering the escrow contract.

- (DREB-16) The first profile MUST set the native evaluator to the evaluator-controlled account directly.
- (DREB-17) An EOA MAY be used when the agreement-bound DACS control proof resolves that address.
- (DREB-18) An EIP-1271 account MAY be used only when the applicable DACS signature/control verifier supports its exact chain and code.
- (DREB-19) A relayer MUST NOT become the evaluator merely because it submits a transaction.
- (DREB-20) A generic evaluator adapter MUST NOT be used in the first profile.
- (DREB-21) For evaluator-driven `complete` or `reject`, the native caller MUST equal the agreement-bound evaluator account. A verifier MUST establish this from the DRL-10 transition, which an eligible implementation permits only to the stored evaluator, together with DREB-9. A verifier MUST NOT use the actor field of an event, because canonical events may emit the stored evaluator rather than the caller.
- (DREB-22) An outer transaction submitter MAY relay execution for an EIP-1271 or other supported account, but the rail evidence MUST distinguish that submitter from the native caller. For an EOA evaluator, the EOA itself remains the native caller; a relayer address MUST NOT be substituted.
- (DREB-23) An SDK timer, orchestrator refusal, transaction-simulation result, or post-transaction conformance verdict MUST NOT substitute for the native submission-cutoff and expiry enforcement required by DREB-12 through DREB-15.
- (DREB-24) In the first profile, the selected implementation MUST NOT recognize any ERC-2771 trusted forwarder or signature-authorized (`*WithAuthorization`) entrypoint for `createJob`, `fund`, `submit`, `complete`, `reject`, or `claimRefund`. DRC-10 evidence MUST show this.

### 8.4 Deployment eligibility

A rail definition must pin at least:

```text
type ERC8183ProfileParameters = {
  canonicalErcRevision: "ethereum/ERCs@a078cab5cc8e9581c15f76c091ed96eed28f02f7"
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
  hook: "0x0000000000000000000000000000000000000000"
  deadlineProfile: "separate-submission-cutoff-v1"
  decisionOrderingProfile: "anchor-final-before-terminal-v1"
  maxCrossSubstrateSkewMs: number
  platformFeeBP: 0
  evaluatorFeeBP: 0
  capabilityProfile: "dacs-delivery-gate-v1"
}
```

- (DRC-1) The selected contract MUST make preterminal provider payout impossible.
- (DRC-2) The selected contract MUST make platform and evaluator escrow fees immutable at zero.
- (DRC-3) Hooks, pause state, or evaluator absence MUST NOT prevent an eligible expiry recovery call from succeeding.
- (DRC-4) An authority MUST NOT be able to withdraw locked job funds to another recipient.
- (DRC-5) An authority MUST NOT be able to upgrade, detach, or replace logic in a way that weakens DRC-1 through DRC-4.
- (DRC-6) If upgradeability exists syntactically, authenticated finalized state MUST prove the relevant upgrade authority is irreversibly disabled.
- (DRC-7) The per-job native hook MUST be the zero address at creation and at every later action block, and the implementation MUST NOT permit a hook to be attached later.
- (DRC-8) The payment token MUST exclude transfer fees, rebasing, callbacks, pause, blacklist, upgradeability, and other behavior that can change exact lock/release/refund accounting. This excludes pausable, blacklistable, or upgradeable stablecoins such as USDC and USDT, including the USDC assets in the DACS-4 v0.1 rail registry.
- (DRC-9) Every action used by the profile MUST emit enough indexed data for event-level job and action identity.
- (DRC-10) A registration proposal MUST provide reproducible source-to-bytecode evidence and independently resolved deployed bytecode.
- (DRC-11) Missing or conflicting deployment evidence MUST leave the rail unregistered and unavailable.
- (DRC-12) The rail MUST define how authenticated evidence orders decision finality before the terminal transaction across the selected substrates.
- (DRC-13) The selected implementation MUST immutably enforce a separate per-job submission cutoff and terminal recovery deadline with the exact behavior in DREB-12 through DREB-15.
- (DRC-14) A verifier MUST return `error` unless every literal-typed field above has exactly the listed value. `implementationRevision` MUST be `<owner>/<repository>@<40 lowercase hex commit>` and MUST identify the DRC-10 source. `deadlineProfile` `separate-submission-cutoff-v1` means DREB-12 through DREB-15 and DRC-13. `capabilityProfile` `dacs-delivery-gate-v1` means DRC-1 through DRC-13 and DREB-24.
- (DRC-15) `anchor-final-before-terminal-v1` orders the decision before the terminal transaction iff `decisionFinalizedAtMs + maxCrossSubstrateSkewMs < terminalBlockTimestampSec × 1000`. It orders the decision after iff `decisionFinalizedAtMs > terminalBlockTimestampSec × 1000 + maxCrossSubstrateSkewMs`, and otherwise cannot order them. `decisionFinalizedAtMs` is the authenticated unix-millisecond timestamp of the block that finalized the decision's SR-2 anchor. `terminalBlockTimestampSec` comes from the authenticated terminal inclusion-block header under DRF-8. `maxCrossSubstrateSkewMs` MUST be a non-negative safe integer.
- (DRC-16) `finalityBlocks` MUST equal `consumerFinalityProfile.settlement.requiredDepth`, and `chainId` MUST equal the chain ID in both the `railId` and the finality profile's `networkId`.

The canonical ERC-8183 surface has one `expiredAt` value and permits evaluator rejection while `Funded`. The DACS MVP therefore fixes `preSubmissionRefundPolicy` to `evaluator-rejection` and requires a compatible implementation with a separately enforced submission cutoff. It does not claim that canonical `expiredAt` alone can provide both a submission cutoff and a later evaluation window. A future `expiry-only` policy requires a new profile and native enforcement that disables funded-state evaluator rejection.

The current reference implementation at [`erc-8183/base-contracts@142e669`](https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183.sol) is not eligible as published. The divergences checked against that revision are:

- UUPS upgrades, administrator pause, and emergency withdrawal (DRC-4 through DRC-6);
- mutable fees and whitelisted, detachable hooks (DRC-2, DRC-7);
- funded-state claim settlement, a pause-gated `claimRefund`, and a pending claim that delays a funded-state refund (DRC-1, DRC-3);
- a provider-mutable `payoutReceiver` while `Open`, and an `IDisburser.onDisbursement` callback that can revert `complete` (DREB-10, DRC-3);
- a submission cutoff enforced only at `expiredAt`, with a fixed one-hour `EVALUATION_GRACE_PERIOD` delaying refund of a `Submitted` job, rather than a separate per-job cutoff and the DREB-12 through DREB-15 mapping (DRC-13);
- a client or provider reject of an `Open` job, an `Open` to `Expired` refund path, and an `Open` to `Submitted` zero-budget submit (DRL-11);
- no zero-budget funding rejection (DRF-2);
- `*WithAuthorization` signature-authorized entrypoints (DREB-24).

Each divergence is a deployment capability check with a section 11 case. Patching only some of them does not make the implementation eligible.

This finding does not reject ERC-8183. It means a strict DACS deployment needs a minimal compatible implementation or irreversible authority restrictions that independently prove DRC-1 through DRC-16 and DREB-24.

## 9. Verification result and ordering

A verifier returns exactly one value of the DACS four-way disposition (CORE JID-4, DACS-4 FV-10):

```text
"pass" | "fail" | "indeterminate" | "error"
```

It applies the checks in this order:

1. Parse the selected artifact type. An unsupported discriminator or version is `error` (CORE JID-3, CF-5).
2. Validate canonical field encodings and required fields under section 3.1. A malformed input is `error`.
3. Recompute content hashes and verify signatures, signer roles, references, and agreement bindings. An authenticated mismatch is `fail`.
4. Resolve the pinned rail, code, authority, token, native job status, creation calldata, and exact events from authenticated sources under DRF-8.
5. Return `indeterminate` when required external evidence is unavailable but not contradictory.
6. Compare the resolved native facts with the authenticated DACS artifacts. A mismatch is `fail`.
7. Return `pass` only when every applicable check succeeds.

As in FV-10, deterministic `error` and `fail` facts are evaluated before unrelated uncertainty.

- (DRV-1) A verifier MUST NOT fall back to a current deployment, registry revision, RPC guess, or caller-supplied field when pinned authority is unavailable.
- (DRV-2) RPC `not found`, timeout, stale state, or inconsistent providers MUST remain `indeterminate` unless authenticated absence is established.
- (DRV-3) A malformed encoding MUST NOT be repaired before hashing or comparison.
- (DRV-4) A signature over internally consistent false fields MUST NOT override independently resolved authority.
- (DRV-5) A retry after `indeterminate` MUST reconcile the original native job and action before submitting any transaction.
- (DRV-6) Authenticated external evidence that contradicts a signed artifact or claimed native fact MUST yield `fail`.
- (DRV-7) A verifier MUST return `pass` only after every applicable artifact, authority, reference, native-evidence, finality, and ordering check succeeds.

## 10. Transcript and evidence disclosure

- (DRQ-1) The first profile MUST use `public-evidence-only` or `explicit-party-supplied` disclosure.
- (DRQ-2) `explicit-party-supplied` means the named party deliberately supplies the exact evidence to the evaluator under the signed policy.
- (DRQ-3) Neither policy authorizes retrieval, decryption, or disclosure of a negotiation transcript.
- (DRQ-4) Encrypted transcript use MUST remain disabled until #351 defines the signed transcript, unanimous member consent, envelope suite, revocation, and SR-2 evidence.
- (DRQ-5) A future transcript-enabled profile MUST use a new disclosure-policy value and a new rail or profile revision.

## 11. Required conformance evidence

Promotion requires full signed artifacts and authenticated native inputs, not expected outputs alone. Each case below has a stable ID and lists the rules it must exercise. `scripts/validate_candidate_profile.py` checks that every requirement-bearing rule is listed by at least one case and that every listed rule exists. It also regenerates `conformance/candidates/delivery-or-remedy/rule-case-matrix.json` and fails CI when that file is stale. No case has an executable vector yet, so this document cannot leave pre-normative status.

### 11.1 Positive cases

<!-- prose-lint: allow — the P1 rule list is an enumeration, not a sentence -->
- **P1** — create, fund, deliver, submit, evaluate, and release the complete budget. *Rules:* DRP-1, DRP-2, DRP-3, DRP-6, DRP-7, DRP-11, DRP-12, DRP-14, DRP-15, DRA-1, DRA-2, DRA-3, DRA-4, DRA-11, DRA-12, DRA-17, DRA-18, DRA-20, DRL-1, DRL-10, DRJ-2, DRJ-4, DRJ-9, DRF-1, DRF-2, DRF-3, DRF-4, DRF-5, DRF-6, DRF-7, DRF-8, DRE-1, DRE-2, DRE-3, DRE-6, DRE-7, DRE-8, DRE-9, DRE-10, DRD-1, DRD-2, DRD-3, DRD-4, DRD-5, DRD-10, DRAA-1, DRAA-3, DRAA-6, DRT-1, DRT-4, DRT-5, DRT-8, DRT-11, DRT-15, DREB-7, DREB-8, DREB-9, DREB-10, DREB-11, DREB-16, DREB-21, DRV-7, DRQ-1, DRR-1, DRR-2, DRR-3, DRR-4, DRR-5, DRC-14, DRC-15, DRC-16, DRW-1, DRW-2, DRW-3, DRW-4.
- **P2** — create, fund, deliver, submit, evaluate, and refund the complete budget after submission. *Rules:* DRT-2, DRT-6, DRT-12, DRD-6, DRL-5, DRT-14.
- **P3** — expiry before submission followed by a complete refund. *Rules:* DRT-3, DRT-13, DRD-7, DRL-5, DRX-6, DREB-15, DRP-12.
- **P4** — expiry after submission, once authenticated native time reaches `evaluationDeadlineSec`, followed by a complete refund without an invented evaluator decision. *Rules:* DRT-3, DRD-7, DRL-5, DRL-6, DREB-15.
- **P5** — agreement-authorized evaluator rejection before submission using a `DisputeOutcome`, with no delivery reference. *Rules:* DRD-9, DRD-12, DRD-13, DRT-2, DRT-12, DRX-7, DRP-7, DRP-12.
- **P6** — an independently reproduced byte-exact `description`, `deliverable`, and `reason` mapping. *Rules:* DREB-1, DREB-2, DREB-3, DREB-4, DREB-6, DRJ-4.
- **P7** — relayed EIP-1271 execution where the outer submitter differs but the native caller remains the bound evaluator account. *Rules:* DREB-21, DREB-22.
- **P8** — the same terminal transaction observed twice reproduces a byte-identical terminal evidence hash. *Rules:* DRT-16, DRV-5.
- **P9** — Vet freshness exactly at the boundary `fundingTimeMs`, with an explicit `validUntil` and with the `defaultMaxAgeSec` fallback. *Rules:* DRA-9, DRW-4.
- **P10** — a DACS-5 projection recomputed for both anchored copies of each section 7 row. *Rules:* DRT-14, DRX-5, DRX-6, DRT-13.

### 11.2 Required rejection cases

- **R1** — wrong job, overlay, rail, chain, contract, runtime code, token, budget, decimals, client, provider, evaluator, submission cutoff, expiry/recovery deadline, payout account, or phase index. *Rules:* DRA-1, DRA-2, DRA-5, DRA-10, DRA-11, DRA-14, DRA-20, DRJ-2, DRJ-3, DRJ-5, DRF-1, DRF-2, DREB-7, DREB-8, DREB-9, DREB-10, DREB-11, DREB-12, DRT-4, DRT-5, DRT-6, DRT-15, DRP-5, DRC-16, DRV-6.
- **R2** — noncanonical JID, content hash, logical-address numeric segment, or `nativeJobId` (zero, maximum, overflow, hex, sign, whitespace, leading zero). *Rules:* DRAA-1, DRAA-2, DREB-3, DRJ-1, DRV-3.
- **R3** — description prefix, hash-text rehash, byte-order, padding, truncation, or zero-reason mismatch. *Rules:* DREB-1, DREB-4, DREB-5, DREB-6, DRJ-4, DRV-3.
- **R4** — cross-job delivery, evaluation, decision, terminal-event, or receipt replay. *Rules:* DRD-8, DRT-11, DRF-1, DRL-4.
- **R5** — wrong evaluator signer or transaction caller. *Rules:* DRE-1, DRD-1, DREB-21, DRA-3.
- **R6** — evaluator collision with buyer, seller, client, or provider. *Rules:* DRA-6, DRA-7.
- **R7** — delivery or decision hash substitution. *Rules:* DRD-3, DREB-2, DREB-6, DRE-2.
- **R8** — release for a refund decision, or refund for a release decision. *Rules:* DRD-2, DRD-5, DRD-6.
- **R9** — nonzero preterminal payout, partial claim, platform fee, or evaluator fee. *Rules:* DRL-7, DRL-8, DRC-1, DRC-2, DRF-5, DRT-7.
- **R10** — mutable or changed implementation, hook, authority, payout receiver, or token behavior, including a pausable or blacklistable token. *Rules:* DRJ-6, DRJ-7, DRC-3, DRC-4, DRC-5, DRC-6, DRC-7, DRC-8, DREB-10, DRL-9, DRA-14.
- **R11** — ambiguous event identity, mismatched log index, or a noncanonical `txHash`. *Rules:* DRJ-2, DRF-3, DRT-4, DRC-9, DRW-3.
- **R12** — terminal action followed by an attempted monetary replay or a post-terminal outcome that relabels the disposition. *Rules:* DRL-4, DRX-4, DRAA-8, DRT-13.
- **R13** — delivery evidence that contains or derives from the native submission event. *Rules:* DRP-9.
- **R14** — a decision finalized after the terminal action, or a self-reported timestamp used as a substitute for authenticated ordering. *Rules:* DRD-4, DRD-10, DRD-11, DRAA-8, DRC-15.
- **R15** — a relayer presented as the native evaluator caller, an event actor field used as the caller, or a trusted-forwarder or `*WithAuthorization` entrypoint, or a generic evaluator adapter set as the native evaluator. *Rules:* DREB-19, DREB-20, DREB-21, DREB-22, DREB-24.
- **R16** — an evaluator added as a buyer/seller bundle party merely because it signed the overlay. *Rules:* DRA-13.
- **R17** — a native submission accepted at or after `submissionCutoffSec`, expiry recovery accepted before `evaluationDeadlineSec`, a cutoff not separated from the deadline by `minimumEvaluationWindowSec`, or a deadline later than the agreement deadline. *Rules:* DREB-12, DREB-13, DREB-14, DREB-15, DRC-13, DREB-23, DRA-19.
- **R18** — an `expiry-only` pre-submission policy claimed under this profile, or a client-side policy presented as native enforcement. *Rules:* DRA-15, DRA-16, DRL-9, DREB-23.
- **R19** — a byte-valid, re-signed historical delivery-shaped `SettlementEvidence` presented as the delivery evidence, or `DeliveryEvidence` whose `phaseIndex` differs from `deliveryPhaseIndex`. *Rules:* DRP-7, DRE-2, DREB-1.
- **R20** — a pipeline with a second payment, delivery, or `pay-alternative` step, a missing or reordered `job-escrow` step, steps naming different rails, or an unsupported `agreementPhase`. *Rules:* DRP-1, DRP-2, DRP-3, DRP-4, DRP-5, DRP-13, DRP-14.
- **R21** — a malformed `railId`, a `phaseHandler` other than `job-escrow`, a missing `consumerFinalityProfile`, an unresolvable `acceptedRails` entry, or dispatch through the `pay-*` PIPE-3 through PIPE-5 contract. *Rules:* DRR-1, DRR-2, DRR-3, DRR-4, DRR-6, DRC-16, DRP-10.
- **R22** — overlay buyer or seller bindings that differ from the bilateral agreement's parties, a signature whose `party` differs from its role's claim, or duplicate roles. *Rules:* DRA-17, DRA-18, DRA-3, DRA-4.
- **R23** — a pre-submission rejection decision executed after a native `submit` landed, or a `Submitted` to `Rejected` transition whose decision omits delivery evidence. *Rules:* DRD-13, DRT-12.
- **R24** — a native transition outside the section 4.1 crosswalk: `Open` to `Expired`, a provider cancel of `Open`, an `Open` zero-budget submit, or a transition out of a terminal status. *Rules:* DRL-10, DRL-11, DRF-4.
- **R25** — an unsupported rule version or kind, a rule hash mismatch, empty or duplicate criteria, a `result` or `finding` that contradicts the criterion outcomes, or a disposition the matrix forbids. *Rules:* DRE-6, DRE-8, DRE-9, DRE-10, DRD-2.
- **R26** — an `indeterminate` evaluation used to authorize a terminal transaction, or missing evidence converted to rejection or acceptance. *Rules:* DRE-4, DRE-5.
- **R27** — an address with bad EIP-55 checksum, short or long length, non-hex digits, the zero address for a live role, an uppercase DACS artifact address, or a non-keccak code hash. *Rules:* DRW-1, DRW-2, DRA-5, DRA-7, DRV-3.
- **R28** — Vet freshness evaluated one second after expiry, with seconds compared directly to milliseconds, or with `observedAt` or a local clock as `now`. *Rules:* DRA-9, DRA-8, DRW-4.
- **R29** — a `DisputeOutcome` that claims a transfer, has a `caseRef` that does not resolve to a matching `DisputeCase`, carries `faultedParty` on a non-fault finding, or skips a revision. *Rules:* DRX-1, DRX-5, DRX-6, DRX-7, DRAA-7.
- **R30** — an artifact from the existing DACS-X dispute candidate family presented as a `DisputeCase` or `DisputeOutcome`, or the reverse. *Rules:* DRX-8, DRG-1.
- **R31** — a profile field with a value other than the listed literal, a malformed `implementationRevision`, or `finalityBlocks` that differs from the profile depth. *Rules:* DRC-14, DRC-16, DRR-6.
- **R32** — a second distinct terminal evidence record, a mutated anchored artifact, or a second write at a single-artifact address. *Rules:* DRT-16, DRAA-4, DRAA-5, DRT-10.
- **R33** — a terminal transaction whose evidence is signed by the orchestrator but contradicts chain or evaluator facts, or a signature over consistent false fields. *Rules:* DRT-10, DRV-4, DRV-6, DRJ-8.
- **R34** — job-escrow artifacts submitted as DACS-5 bundle settlement members, or as volume contributions, before promotion. *Rules:* DRP-8, DRT-14.
- **R35** — a candidate signature presented under a registered DACS domain, or a transcript-dependent disclosure policy. *Rules:* DRG-1, DRQ-1, DRQ-4, DRQ-5.

### 11.3 Required indeterminate cases

- **I1** — unavailable rail definition, agreement artifact, or evaluation rule. *Rules:* DRA-1, DRV-1, DRC-11, DRE-8, DRR-6.
- **I2** — unavailable or inconsistent authenticated chain state, including an unauthenticated prior native status. *Rules:* DRL-3, DRL-12, DRV-2, DRT-9.
- **I3** — missing finality evidence. *Rules:* DRF-6, DRF-8, DRT-8.
- **I4** — unresolved proxy implementation or authority state. *Rules:* DRJ-6, DRJ-7, DRC-6.
- **I5** — missing delivery, evaluation, or decision artifact when no contradictory fact is established, including a deleted Demos storage program. *Rules:* DRE-5, DRAA-5, DRAA-3.
- **I6** — decision and terminal evidence that the `anchor-final-before-terminal-v1` profile cannot order within `maxCrossSubstrateSkewMs`. *Rules:* DRD-11, DRC-12, DRC-15.
- **I7** — a retry after `indeterminate` that reconciles the original native job before any new transaction. *Rules:* DRV-5, DRT-9.

### 11.4 Process checks

- **Q1** — this document's validator, rule-to-case matrix, and **Checked against** pin are current, and every registration proposal carries reproducible deployment evidence. *Rules:* DRG-2, DRC-10, DRC-11, DRJ-9, DRF-7.

Every vector pack must include exact canonical bytes, hashes, signatures, logical addresses, receipts, chain inputs, expected result, and the rule IDs exercised. At least two independent implementations must reproduce the positive bytes and all rejection/indeterminate outcomes before the profile is registered.

## 12. Promotion and ownership gates

### DACS Standard and steward

- obtain one independent approval of the issue #356 decision matrix before steward acceptance;
- split promoted text into the job-escrow lifecycle, ERC-8183 binding, DACS-X artifacts, and DACS-5 projection;
- extend the DACS-1 `PhaseType` union and register every new signature domain, logical-address family, and rule ID;
- publish implementation-neutral vectors for every section 11 case;
- keep the rail unavailable until deployment evidence and independent reproduction pass.

### Contract and reference implementation contributors

- provide an exact deployment satisfying DRC-1 through DRC-16 and DREB-24;
- publish verified source, compiler settings, constructor/initializer inputs, deployed addresses, runtime bytecode hashes, and authority state;
- publish finalized event fixtures for release, rejection, expiry, replay, mismatch, and unavailable-state cases.

### DACS SDK contributors

- implement only after artifact shapes and vector bytes are accepted;
- preserve the four-way disposition and retry reconciliation;
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
