# Delivery-or-remedy candidate specification

**Status:** pre-normative review candidate for [issue #356](https://github.com/DACS-Agent-commerce/DACS-Standard/issues/356). It does not change DACS conformance, register a rail, or make any deployment available.

**Target:** a future DACS-4 job-escrow lifecycle and DACS-X evaluation module. The first proposed binding is `pay-evm-erc8183`.

**Checked against:** DACS-Standard `next` at `df7bc202ebdc179a59d61a8221072f33f482b933`. Every CORE, DACS-1 through DACS-5, and DEMOS-MAPPING rule ID cited below means the text at that commit. This includes DACS-4 `DeliveryEvidence` with PDE-1 through PDE-8, consumer-verifiable finality FV-1 through FV-10, CORE JID-1 through JID-4, and CORE IBH-1 through IBH-6.

**External pins:**

- canonical ERC-8183 at [`ethereum/ERCs@a078cab`](https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-8183.md);
- EIP-1271 at [`ethereum/ERCs@a078cab`](https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-1271.md);
- EIP-155 at [`ethereum/EIPs@c1a1eb2`](https://github.com/ethereum/EIPs/blob/c1a1eb21b465c9c42704a8a5743ad0694aedbff7/EIPS/eip-155.md);
- EIP-55 at [`ethereum/ERCs@a078cab`](https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-55.md), the full specification text; the `ethereum/EIPs` copy is a redirect stub;
- EIP-1052, which defines `EXTCODEHASH`, at [`ethereum/EIPs@c1a1eb2`](https://github.com/ethereum/EIPs/blob/c1a1eb21b465c9c42704a8a5743ad0694aedbff7/EIPS/eip-1052.md);
- ERC-2771 at [`ethereum/ERCs@a078cab`](https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-2771.md);
- the Solidity ABI specification at [`ethereum/solidity@f401782`](https://github.com/ethereum/solidity/blob/f401782df49be312ea4ef52a2d467cf5183b5906/docs/abi-spec.rst), the v0.8.37 release commit. It defines the canonical ABI types, function selectors, event `topic0` values, and the topic and data layout of logs that DRC-17, DRC-18, and DRC-21 read. In this document keccak-256 is the Ethereum Keccak-256 function that this specification and EIP-1052 use, with the original Keccak padding. It is not FIPS 202 `SHA3-256`: keccak-256 of empty input is the DRW-2 empty-code hash `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`;
- RFC 8785, an immutable RFC Editor publication;
- `@kynesyslabs/demosdk@4.0.16` (npm integrity `sha512-nVhp1uC+tFGzhew9c8XIajTMmELopx7gd0joqqzDd2XyUuFDcqrda51NYqvX5C8+L3Xgnie/mRf7JRqZ7r3tHA==`), the SDK used to check the DEMOS-MAPPING behavior cited by DRAA-3 and DRC-19. The pinned DEMOS-MAPPING text, not this package or a live node, is the verdict authority;
- `kynesyslabs/node` at commit `ac8f45f02fc9c25082ce9b83595c2e3916b49c5a`, the node source that sets the Demos block `content.timestamp` that DRC-19 reads. The secretary sets the round timestamp in [`types/secretaryManager.ts`](https://github.com/kynesyslabs/node/blob/ac8f45f02fc9c25082ce9b83595c2e3916b49c5a/src/libs/consensus/v2/types/secretaryManager.ts#L177). [`PoRBFT.ts`](https://github.com/kynesyslabs/node/blob/ac8f45f02fc9c25082ce9b83595c2e3916b49c5a/src/libs/consensus/v2/PoRBFT.ts#L166) copies it before the block is forged. [`routines/createBlock.ts`](https://github.com/kynesyslabs/node/blob/ac8f45f02fc9c25082ce9b83595c2e3916b49c5a/src/libs/consensus/v2/routines/createBlock.ts#L36) stores it in the block. All three are under `src/libs/consensus/v2/`. Neither DEMOS-MAPPING nor the pinned SDK states a unit for that field.

**Roadmap gates (non-normative):** the self-contained DACS-X vector pack tracked by #99 and transcript disclosure tracked by #351 are open work items. They are not verdict authority. The pinned revisions above are.

The capitalized requirement words in this document are proposed requirements. They become normative only if promoted into the applicable specification modules by a later steward-approved pull request.

All artifact kinds introduced by this pre-normative candidate use the `dacs-x-` extension-domain form required by CORE SIG-4. Promotion requires explicit domain-registry entries and regenerated review vectors.

- (DRG-1) Candidate signatures MUST NOT be relabelled as signatures under a future registered domain.
- (DRG-2) Each revision of this candidate MUST update the **Checked against** commit and MUST be re-audited against every cited rule at that commit before review. `scripts/validate_candidate_profile.py` MUST pass and its rule-to-case matrix MUST be regenerated in the same change.
- (DRG-3) Every registry entry this candidate introduces uses a CORE §B.6 `x-` name: the PhaseTypes `x-commit-delivery-or-remedy-agreement` and `x-job-escrow`, the railType `x-evm-erc8183`, the phaseHandler `x-job-escrow`, the `railId` prefix `x-evm-erc8183:`, and the logical-address family `dacs4:x-job-escrow:`. A conforming reader MUST treat these names as unknown unless out-of-band agreement exists. Promotion MUST assign registered names, and a Listing, agreement, or artifact produced under an `x-` name MUST NOT be read as one produced under the registered name.

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

The candidate therefore proposes two additions to the closed DACS-1 `PhaseType` union: one commit kind and one structurally distinct `x-job-escrow` kind used exactly twice around one existing delivery phase:

```text
x-commit-delivery-or-remedy-agreement { agreementPhase: "commit-payee-bound-agreement" | "commit-identity-bound-payee-agreement" }
x-job-escrow { action: "fund", rail: "x-evm-erc8183:<chainId>:<asset>" }
deliver-*
x-job-escrow { action: "terminal", rail: "x-evm-erc8183:<chainId>:<asset>" }
rate?
```

The two `x-job-escrow` invocations are one paired lifecycle, not two payments. The fund invocation proves value was locked. The terminal invocation proves release or refund.

An older reader sees unknown agreement and phase discriminators and rejects the Listing before execution; DRP-13 states what it must not do instead.

### 2.1 Candidate phase shapes

```text
type DeliveryOrRemedyCommitPhaseStep = {
  kind: "x-commit-delivery-or-remedy-agreement"
  parameters: {
    agreementPhase: "commit-payee-bound-agreement" | "commit-identity-bound-payee-agreement"
  }
}

type JobEscrowPhaseStep = {
  kind: "x-job-escrow"
  parameters: {
    action: "fund" | "terminal"
    rail: string
  }
}
```

- (DRP-1) A delivery-or-remedy pipeline MUST contain exactly two `x-job-escrow` steps.
- (DRP-2) The first step MUST use `action: "fund"` and the second MUST use `action: "terminal"`.
- (DRP-3) Exactly one supported `deliver-*` step MUST occur between the paired steps.
- (DRP-4) A delivery-or-remedy pipeline MUST NOT contain any other payment, delivery, or `pay-alternative` step between or alongside the pair; a verifier MUST return `fail` for a pipeline that contains one.
- (DRP-5) Both steps MUST name the same complete, agreement-selected rail definition. A verifier MUST derive the effective profile parameters from that authenticated, content-hash-bound definition; a detached caller or fixture projection MUST NOT override or weaken them.
- (DRP-6) The delivery step MUST NOT begin until finalized evidence proves the exact budget is locked.
- (DRP-7) When delivery was submitted, the terminal step MUST use the exact signed current DACS-4 `DeliveryEvidence` (`deliveryEvidenceVersion: "1"`, signed under `dacs-delivery-evidence:v1:`, anchored at `dacs4:delivery:{jobId}:{phaseIndex}`) produced by the intervening step. Its `phaseIndex` MUST equal the overlay's `deliveryPhaseIndex`, and it MUST satisfy PDE-1 through PDE-8. Its `outcome` MUST be `success`: a `failure` `DeliveryEvidence` MUST NOT be submitted natively or support a release, and such a job ends only through the DRD-12 pre-submission rejection or expiry recovery. A historical delivery-shaped `SettlementEvidence` admitted only under PDE-7 MUST NOT satisfy this profile. A pre-submission expiry or evaluator-rejection refund MUST instead omit delivery evidence as required by DRD-9 and DRT-12.
- (DRP-8) Until the DACS-5 projection in section 7 is promoted, job-escrow artifacts MUST NOT be carried as DACS-5 session-bundle settlement members and MUST NOT contribute to DACS-5 volume. After promotion, the pair MUST count as at most one purchase at the agreement price, and only on `released`.
- (DRP-9) The delivery evidence content hash MUST be fixed before the native submission call. The hashed artifact MUST NOT contain or derive any field from the resulting native submission transaction or event. Later authenticated native evidence binds that already-fixed digest to the native job; it is not part of the digest itself.
- (DRP-10) The paired `x-job-escrow` lifecycle counts as one concrete payment selection for DACS-1 §6.3.4 step 8 and the `acceptedRails` rule referenced by DACS-4 PIPE-1. It remains structurally outside the `pay-*` and `pay-alternative` registries and MUST NOT inherit PIPE-3 through PIPE-5 by implication. PIPE-2 ordering applies unchanged.
- (DRP-11) DACS-4 PIPE-6 applies to the `fund` and `terminal` invocations. The commit phase produces two CORE §5.1 receipts: one for the bilateral agreement commitment and one for the overlay commitment. Before the orchestrator submits any transaction that can lock or move value, it MUST verify that both are `finalized` and match the session's `jobId`.
- (DRP-12) On the ordinary submitted path, the `terminal` invocation MUST NOT execute until the intervening `deliver-*` invocation has returned and the native submission is authenticated. It MAY execute without a returned delivery only after authenticated native time has reached `submissionCutoffSec`, or through the DRD-12 pre-submission rejection path. In either exception, the orchestrator MUST cancel or permanently ignore any late delivery result and MUST NOT submit it to a terminal or refunded native job.
- (DRP-13) An older reader MUST NOT remove either phase, reinterpret `x-job-escrow` as an ordinary payment, or execute the delivery outside the pair.
- (DRP-14) The commit phase MUST run the existing handler named by `agreementPhase`, with the DRA-20 and DRA-22 extensions, for the bilateral payout-bearing `AgreementArtifact`, then commit the finalized `DeliveryOrRemedyAgreement` overlay at its section 6.5 address. It MUST return one `PhaseHandlerResult` whose `ok: true` requires both commitments to be `finalized`. Any other `agreementPhase` value MUST yield `error`.
- (DRP-15) Each `x-job-escrow` invocation MUST apply the gate table in section 2.3. A gate listed as not applicable MUST NOT be cited as satisfied.
- (DRP-16) A CORE `PhaseHandlerResult` carries one `attestationRef` and one `anchorReceipt`. The commit result's pair MUST describe the overlay commitment, and the `fund` result's pair MUST describe `EscrowFundingEvidence`. Every other receipt this profile requires, including the bilateral agreement receipt for DRP-11 and the `EscrowJobRef` receipt for DRJ-9, MUST be resolved independently at its logical address. A consumer MUST NOT infer such a receipt from a phase result.
- (DRP-17) An `x-job-escrow` invocation that returns `ok: false` MUST set `errorClass` under the DACS-4 PC-4 trigger table and, for the DRA-20 payout binding, under the DACS-4 §9.5.1 PB failure modes. A malformed or incomplete payout binding is `permanent`. A PB-1 destination mismatch, or a PB-2 tier-2 resolution to a different address, is `counterparty`. A PB-2 applicable-but-unresolvable binding is `substrate`. A DRA-21 currency mismatch and every other authenticated binding mismatch are `permanent`; an RPC failure is `transient`; and SR-2 unavailability before native finality is `substrate`.

> **Note (non-normative).** A single long-running phase would need a new suspended result state. The paired form preserves the current one-result-per-invocation contract and makes the preterminal delivery hash available without a circular terminal-evidence hash.

### 2.2 Rail definition, Listing selection, and dispatch

`RailDefinition.railType` and `phaseHandler` are closed unions in DACS-4, so a job-escrow rail is a distinct signed definition. It extends, rather than replaces, the DACS-4 `RailDefinition` envelope: `asset`, `network`, `availability`, and `governance` keep their exact DACS-4 types, narrowed to the arms this binding supports.

```text
type JobEscrowRailDefinition = {
  jobEscrowRailVersion: "1"
  railVersion: number
  railId: string
  railType: "x-evm-erc8183"
  asset: { kind: "erc20"; chainId: number; contract: string; symbol: string; decimals: number }
  network: { kind: "evm"; chainId: number; rpcAttestation: "consensus-backed-proxy" | "evm-rpc" }
  phaseHandler: "x-job-escrow"
  parameters: ERC8183ProfileParameters
  consumerFinalityProfile: ConsumerFinalityProfile
  availability: RailAvailability
  governance: {
    proposedBy: ClaimReference
    acceptedAt: number
    supersedes?: number
    anchoring: "in-code" | "single-signer" | "multisig"
    emergency?: { isEmergency: true; failureObservation: string }
    deprecated?: boolean
    deprecationReason?: string
  }
  signature: ComponentSignature
}
```

The canonical form omits `signature`. The registry steward signs:

```text
"dacs-x-job-escrow-rail:v1:" || job_escrow_rail_hash
```

- (DRR-1) `railId` MUST match `x-evm-erc8183:<chainId>:<asset>`. `<chainId>` is the bare positive decimal EIP-155 chain ID with no leading zero and equals `parameters.chainId`. `<asset>` equals `asset.symbol`, a non-empty token symbol of ASCII uppercase letters and digits. The complete `railId` MUST be at most 64 characters. Any other spelling MUST yield `error`. The uppercase `<asset>` segment follows the DACS-4 §9.4.2 registry rows, such as `evm-erc20:1:USDC`, which the "lowercase ASCII" comment on DACS-4 `RailDefinition.railId` contradicts. For a job-escrow rail the rows govern, and a reader MUST NOT case-fold the `<asset>` segment before validating or comparing it.
- (DRR-2) RD-1 through RD-7 apply to a `JobEscrowRailDefinition` with `"dacs-x-job-escrow-rail:v1:"` replacing `"dacs-rail:v1:"`. The same substitution applies wherever the Standard verifies or reads a rail definition's `"dacs-rail:v1:"` signature: DACS-1 LRR-2 and LRR-3, DACS-4 RAV-R5, and step 3 of the DACS-4 §9.4.3 consumer resolution. A job-escrow definition signed under `"dacs-rail:v1:"` does not verify and MUST yield `fail`. `phaseHandler` MUST equal `x-job-escrow` in every version sharing a `railId`.
- (DRR-3) The Listing MUST advertise the rail through an `acceptedRails` `PaymentRailRef` whose `railId` equals both `x-job-escrow` steps' `parameters.rail`. LRR-1 through LRR-6 apply with `x-job-escrow` standing in for the concrete `PaymentPhaseType` in LRR-1 and LRR-4, so the resolved `phaseHandler` MUST equal `x-job-escrow`. In LRR-3 the schema is `JobEscrowRailDefinition`, and RD-1 through RD-6 apply as DRR-2 adapts them. The DACS-4 v0.1 rail-registry index names no `x-` rail, so the authenticated registry snapshot and index entry that LRR-2 requires MUST come from a snapshot named by the reader's CORE §B.6 out-of-band agreement. That agreement replaces only the choice of snapshot: the snapshot's authentication, the index content-hash match, and LRR-3 through LRR-6 still apply. A reader that supports this profile but holds no such agreed snapshot cannot authenticate the registry authority, which LRR-5 makes `indeterminate`. A reader that does not support this profile, including an older reader, treats the `x-` names as unknown under DRG-3 and MUST NOT resolve the job-escrow rail.
- (DRR-4) The rail MUST carry a complete `consumerFinalityProfile` with `model: "block-depth"`, `settlement.networkId` equal to `eip155:<chainId>`, and `settlement.requiredDepth` equal to `parameters.finalityBlocks`. A rail without one MUST NOT be selectable.
- (DRR-5) An orchestrator MUST apply RAV-R1 through RAV-R5 when it selects a job-escrow rail. Under DRR-2, the authoritative record that RAV-R5 names is the signed, anchored `JobEscrowRailDefinition` pinned at session start, and a `"dacs-rail:v1:"` record MUST NOT supply its `availability`.
- (DRR-6) An unsupported `jobEscrowRailVersion`, `railType`, or `phaseHandler` MUST yield `error`; an unavailable definition MUST yield `indeterminate`.
- (DRR-7) `asset.kind` MUST be `erc20` and `network.kind` MUST be `evm`, which is the RD-5 kind match for this railType. `asset.chainId`, `network.chainId`, and `parameters.chainId` MUST be the same positive JSON safe integer. `asset.contract` MUST equal `parameters.paymentToken` as a DRW-1 20-byte value, and `asset.decimals` MUST equal `parameters.tokenDecimals`. A missing member MUST yield `error`; a mismatch MUST yield `fail`. "Pinned rail asset" in this document means this `asset`.
- (DRR-8) `availability` is the DACS-4 `RailAvailability` union that RAV-R1 through RAV-R5 read, and `governance` is the exact DACS-4 `RailDefinition.governance` member that LRR-2 verifies and LRR-6 reads. A replacement revision MUST name the replaced `railVersion` in `governance.supersedes` under RD-4; this type MUST NOT carry any other supersession member.

### 2.3 Gates applied to each invocation

| Gate | `fund` | `terminal` |
|---|---|---|
| DACS-4 PIPE-6 | applies (DRP-11) | applies (DRP-11) |
| CORE IBH-1 through IBH-6 | applies when `agreementPhase` is `commit-identity-bound-payee-agreement`; IBH-4 and IBH-5 rerun before the lock | applies under the same condition; IBH-4 and IBH-5 rerun before any evaluator or recovery transaction |
| DACS-4 PB-1 through PB-3 | applies to the single payout binding of DRA-20 before the lock, with the PB failure-mode classes in DRP-17 | PB-1 recipient equality applies to the release recipient (DRT-5) |
| DACS-4 PC-1 through PC-6 | not applicable: they define one-invocation `PaymentPhaseInput`, `SettlementEvidence`, and `dacs4:payment:` production. DRF-1 through DRF-8 and DRT-1 through DRT-16 restate the binding and anchoring duties, DRA-21 restates the PC-5 currency-to-asset duty, and DRP-17 restates the PC-4 `errorClass` duty for this lifecycle | not applicable, as for `fund`; DRA-21 and DRP-17 apply |
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
- (DRA-10) `budgetBaseUnits` MUST be the minimal unsigned decimal form of the exact agreement price after conversion using the pinned token decimals. A price that is not an integer number of base units after that conversion MUST yield `fail`.
- (DRA-11) The overlay MUST bind the three ordered phase indexes selected by DRP-1 through DRP-3.
- (DRA-12) The overlay MUST be finalized and independently resolvable before job creation or funding.
- (DRA-13) The evaluator signature authenticates only this overlay. It MUST NOT add the evaluator to the bilateral `AgreementArtifact`, make the evaluator a buyer or seller, or add an evaluator signature requirement to the buyer/seller `AttestationBundle`.
- (DRA-14) The native client, provider, evaluator, token, budget, release recipient, pre-submission rejection policy, and applicable deadlines MUST be fixed and authenticated no later than funding. A later mutable replacement MUST prevent progression.
- (DRA-15) `preSubmissionRefundPolicy` MUST be signed before funding and MUST equal `evaluator-rejection` in this profile. A different value is an unsupported profile, not a client-side restriction on the native evaluator.
- (DRA-16) Decisionless expiry remains available regardless of the fixed pre-submission policy. A future `expiry-only` profile MUST select an implementation that immutably disables evaluator rejection while funded; an SDK omission, caller convention, or post-transaction verifier rejection is insufficient.
- (DRA-17) The overlay `buyer` and `seller` bindings MUST equal the resolved `AgreementArtifact.parties` entries for the same role: `primaryClaim` under CORE CF-3 identity, and `bundleHash` and `vetRecordRef` byte-exactly. When the agreement is identity-bound, the IBH-5 join MUST also succeed for each role.
- (DRA-18) Each `DeliveryOrRemedySignature.party` MUST equal its `role`'s `primaryClaim` under CORE CF-3 identity. The three `role` values MUST be distinct.
- (DRA-19) `submissionCutoffSec` and `evaluationDeadlineSec` MUST be non-negative integers no greater than `9007199254740`. `evaluationDeadlineSec × 1000` MUST be less than or equal to the bilateral agreement's `terms.deadline`, which is in unix milliseconds.
- (DRA-20) The bilateral agreement MUST carry exactly one `terms.payoutBindings` entry for the job-escrow pair, keyed `(railId, fundPhaseIndex)`. Its `payeeAddress` is the seller payout account. In this profile it MUST equal, as a DRW-1 20-byte value, the address in the seller's EVM account claim. PB-1 through PB-3 apply to that entry. This extends the DACS-3 §8.5 effective-pipeline payout coverage, and §8.5.2 check 9, to the `x-job-escrow` pair. The `fund` step at `fundPhaseIndex` is the one covered payment phase, and its entry's `railId` equals that step's `parameters.rail`. The `terminal` step is not covered. A missing or duplicate entry, an entry keyed at `terminalPhaseIndex` or any other index, an entry with another `railId`, or any extra entry MUST yield `fail`.
- (DRA-21) The bilateral agreement's `terms.price.currency` MUST equal the rail's `asset.symbol`, which DRR-1 also binds to the `railId` `<asset>` segment. This is the DACS-4 PC-5 `erc20` mapping. A mismatch MUST yield `fail` before job creation or funding, and a matching token amount MUST NOT repair it.
- (DRA-22) Because DRP-10 counts the pair as a concrete payment selection, the bilateral agreement's `terms.rail` MUST be present and canonically equal to the selected `acceptedRails` `PaymentRailRef` whose `railId` equals both `x-job-escrow` steps' `parameters.rail`. This extends DACS-3 §8.5.2 check 3, which requires `terms.rail` exactly when the pipeline has a concrete `PaymentPhaseType` or `pay-alternative` phase, to the `x-job-escrow` pair. An absent or different `terms.rail` MUST yield `fail`.

The evaluator requirement is deal policy, not a universal arbitrator credential. A live Listing or agreement chooses the credential strength appropriate to the value and subject matter.

### 3.1 Wire encodings

- (DRW-1) An EVM address in a DACS artifact field (`contractAddress`, `implementationAddress`, `paymentToken`, `token`, `recipient`) MUST be `0x` followed by exactly 40 lowercase hexadecimal digits. Any other spelling is malformed and MUST yield `error` without repair. The address component of a `cci-xm:evm:<chainId>:<address>` claim, taken before any `?` parameters, MUST be `0x` followed by exactly 40 hexadecimal digits in all-lowercase, all-uppercase, or valid EIP-55 mixed case; anything else MUST yield `error`. Every comparison MUST decode both operands to 20 bytes and compare the bytes. The zero address MUST yield `fail` for client, provider, evaluator, contract, and token.
- (DRW-2) Every EVM code hash field, namely `runtimeBytecodeHash`, `implementationRuntimeBytecodeHash`, and `paymentTokenRuntimeBytecodeHash`, MUST be keccak-256 of the deployed runtime bytecode. That is the `EXTCODEHASH` value of a non-empty account. It MUST be spelled `0x` followed by 64 lowercase hexadecimal digits. The EIP-1052 empty-code hash `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` and the zero hash MUST yield `fail` in every pinned code-hash field.
- (DRW-3) `EvmEventRef` is the DACS-4 `ChainTxRef` `evm-event` arm. `txHash` MUST use its SB-1 canonical spelling; any other spelling MUST yield `error`.
- (DRW-4) Each time-valued field has exactly one unit, as follows. Unix-second timestamps: `submissionCutoffSec`, `evaluationDeadlineSec`, `fundingBlockTimestampSec`, and `terminalBlockTimestampSec`. Duration in seconds: `minimumEvaluationWindowSec`. Unix-millisecond timestamps: `observedAt`, `finalityObservedAt`, `fundingTimeMs`, and `decisionFinalizedAtMs`. Duration in milliseconds: `maxCrossSubstrateSkewMs`. Every one of these values MUST be a non-negative JSON safe integer, and every seconds value MUST be at most `9007199254740`. A duration MUST NOT be compared with a timestamp as if it were one. A comparison or sum that mixes seconds and milliseconds MUST first multiply each seconds operand by 1000. An operand, product, or sum above `9007199254740991` MUST yield `error`.
- (DRW-5) Where this profile compares two `ClaimReference` values under CORE CF-3 identity and both use the `cci-xm:evm` scheme, it MUST compare their decoded chain IDs and DRW-1 20-byte addresses, not the identifier text. Two case spellings of one EVM account are the same party for DRA-6, DRA-17, DRA-18, and DRX-7.
- (DRW-6) In `EscrowFundingEvidence` and `EscrowTerminalEvidence`, `finality.model` MUST be `block-depth` and `finality.finalityBlocks` MUST equal `parameters.finalityBlocks`. `finality.finalityObservedAt` and `observedAt` MUST both equal 1000 times the authenticated timestamp of the `finalityBlocks`-th confirmation block of the last referenced event, as DACS-4 `SettlementFinalityRecord` defines for `block-depth` and read under DRF-8. A wall-clock or local observation time MUST NOT be used. Any other value MUST yield `fail`.
- (DRW-7) The event references and attestation references in `EscrowFundingEvidence` and `EscrowTerminalEvidence` are derived, not chosen by the producer. `fundingEventRefs` and `terminalEventRefs` MUST each list exactly the section 4.1 "Required events" of the recorded transition, one reference per event, in ascending `logIndex` order. All of them MUST come from the one transaction that made the transition. Every `AttestationRef` member MUST carry the referenced artifact's recomputed `contentHash` and MUST omit `signer`. Its `anchor` MUST be `{kind: "storage-program", locator: L}`, where `L` is the artifact's exact logical address, as in the DACS-4 `deliverableAnchor` and `reservationRef` references. `L` is the section 6.5 address for `escrowJobRef`, `fundingEvidenceRef`, and `decisionRef`, and `dacs4:delivery:{jobId}:{deliveryPhaseIndex}` for `deliveryEvidenceRef` (DRP-7). The reference MUST NOT carry a native address. A consumer resolves `L` under DRAA-3 when it reads the artifact, so the reference does not depend on the native address. A missing, extra, duplicate, or reordered event reference, a native-address locator, any other `kind` or `L`, or any other `AttestationRef` spelling MUST yield `fail`.

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
- (DRL-2) A binding MUST NOT expose an additional native state unless the rail definition's `nativeStatusMap` (DRC-17) maps it to exactly one section 4.1 native status. DRL-10 then derives the portable state from that status and the transition.
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
- (DRJ-3) The authenticated creation event carries the job's client, provider, evaluator, and expiry/recovery deadline, read under DRC-20, and the DRC-21 configuration event carries its submission cutoff and pre-submission rejection policy. Decoded only under the DRC-17 pins, each MUST match the overlay and rail definition. The job's `hook` MUST equal the zero address required by DRC-7.
- (DRJ-4) The native job `description` MUST equal the byte-exact agreement binding in section 8.1. The verifier MUST obtain it by ABI-decoding the `createJob` calldata of the creating transaction. That transaction's bytes MUST be proven under FV-5 for the transaction that emitted `creationEvent`. The transaction MUST call `contractAddress` directly with the `createJob` selector pinned by DRC-17. An `eth_call`, `getJob`, or other unauthenticated read MUST NOT establish `description`.
- (DRJ-5) `runtimeBytecodeHash` MUST match, under DRW-2, authenticated code at the finalized creation block and at each later action block.
- (DRJ-6) A proxy binding MUST also resolve the implementation and every authority capable of changing behavior.
- (DRJ-7) A changed, unavailable, or ambiguously resolved code/authority state MUST prevent progression.
- (DRJ-8) A valid signature or creation event MUST NOT repair a mismatch in another field.
- (DRJ-9) The authenticated session orchestrator MUST sign and anchor the job reference through SR-2.
- (DRJ-10) `EscrowJobRef.chainId`, `contractAddress`, and `runtimeBytecodeHash` MUST equal the rail's `parameters.chainId`, `parameters.contractAddress`, and `parameters.runtimeBytecodeHash`, compared under DRW-1 and DRW-2. A mismatch MUST yield `fail`.
- (DRJ-11) A contract that delegates to an implementation MUST have `implementationAddress` and `implementationRuntimeBytecodeHash` pinned, and the implementation resolved under DRJ-6 at the creation block and at every later action block MUST equal both pins. The payment token's authenticated code at the funding block and at the terminal block MUST hash to `paymentTokenRuntimeBytecodeHash` under DRW-2. A mismatch, or a delegating contract without both pins, MUST yield `fail`; unavailable code MUST yield `indeterminate`.

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

`SettlementFinalityRecord` is the existing DACS-4 type and retains its exact registered shape (`model`, the model-specific parameter such as `finalityBlocks`, and `finalityObservedAt`). Under FV-1 through FV-10 it is producer testimony only. The EVM event's block number, block hash, block timestamp, inclusion, and confirmation facts are established by FV-1 through FV-10 over `AuthenticatedChainObservation`; they are not unregistered replacement members of `SettlementFinalityRecord`. The same boundary applies to `EscrowTerminalEvidence.finality` below. DACS-4 currently documents `SettlementFinalityRecord` as populated by payment phases only; promotion requires a DACS-4 note extending that comment to `x-job-escrow` invocations.

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
  decisionStage: "pre-submission" | "post-submission"
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
- (DRD-2) The basis MUST resolve and authorize the selected disposition: an `execution-evaluation` basis under the section 6.2 matrix of the bound evaluation rule, and a `dispute-outcome` basis under the section 6.4 dispute-outcome table and DRX-9.
- (DRD-3) A release or post-submission refund decision MUST bind the exact delivery evidence.
- (DRD-4) The decision MUST be signed, anchored, finalized, and independently resolvable before the terminal transaction is submitted.
- (DRD-5) `release-to-provider` MUST map only to the native full-release action.
- (DRD-6) `refund-to-client` MUST map only to the native evaluator-rejection action.
- (DRD-7) Expiry recovery MUST NOT manufacture an `EscrowDecision` or evaluator signature.
- (DRD-8) A decision already observed in a terminal job MUST NOT authorize any other job or transaction.
- (DRD-9) A pre-submission refund decision MUST use `decisionStage: "pre-submission"`, omit `deliveryEvidenceRef`, and use a `DisputeOutcome` basis.
- (DRD-10) Authenticated substrate evidence MUST order the decision's finality before the terminal transaction under the rail's `decisionOrderingProfile` (DRC-15).
- (DRD-11) A self-reported decision time, block number, or `decidedAt` extension MUST NOT establish DRD-10. Evidence that places finality after the terminal transaction MUST yield `fail`; evidence that cannot order the two events MUST yield `indeterminate`.
- (DRD-12) A pre-submission evaluator rejection is distinct from expiry. It MUST be authorized by the signed agreement policy and a finalized `DisputeOutcome`, omit delivery evidence, and map only to the native evaluator-rejection action.
- (DRD-13) The selected implementation MUST bind the expected prior native status into the evaluator's `reject` entrypoint and revert when it differs. A pre-submission decision MUST execute only against `Funded`. If a native `submit` lands first, the pre-submission decision cannot execute and authorizes nothing. The evaluator MUST then issue a distinct post-submission decision, bound to the delivery evidence, at the `post-submission` decision address. A `Submitted` to `Rejected` transition whose decision omits `deliveryEvidenceRef` MUST yield `fail`.
- (DRD-14) `decisionStage` MUST be `pre-submission` exactly when the decision omits `deliveryEvidenceRef`; any other combination MUST yield `fail`. A job has at most one decision per stage, each at its own section 6.5 address. The decision that authorizes a terminal transaction is the one whose content hash equals the authenticated native `reason` bytes under section 8.1. Its stage MUST match the DRL-10 prior native status: `pre-submission` for `Funded` and `post-submission` for `Submitted`. A stage mismatch, or a second distinct decision at one stage address, MUST yield `fail`. A `release-to-provider` decision MUST be `post-submission`.

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

Dispute-outcome authorization table, for a `DisputeOutcome` used as an `EscrowDecision` basis:

| `finding.classification` | Permitted `recommendedDisposition` and `EscrowDecision.disposition` |
|---|---|
| `seller-fulfilled` | `release-to-provider`, `post-submission` stage only |
| `seller-fault`, `buyer-fault`, `no-fault`, `substrate-failure` | `refund-to-client` |
| `evaluator-unavailable`, `indeterminate` | none |

- (DRX-9) A `DisputeOutcome` used as an `EscrowDecision` basis MUST carry `recommendedDisposition`. It MUST be finalized before the decision and signed by the overlay evaluator. The basis is exactly the revision whose content hash `basisRef` binds. The evaluator signs both that revision (DRX-7) and the decision (DRD-1), so a verifier MUST NOT require or search for the absence of a later revision. The decision's `disposition` MUST equal `recommendedDisposition`, and that pair MUST be permitted by this table for `finding.classification` and the decision's stage. An absent recommendation, a contradiction, a `basisRef` that does not resolve to that exact signed revision, or a `none` row MUST yield `fail`. A later revision of the same case is accountability evidence under DRX-3 and DRX-4 and MUST NOT change the verdict on a decision bound to an earlier revision.

### 6.5 Candidate logical addresses

| Artifact | Logical address |
|---|---|
| `DeliveryOrRemedyAgreement` | `dacs4:x-job-escrow:{jobId}:agreement` |
| `EvaluationRule` | `dacs4:x-job-escrow:{jobId}:evaluation-rule` |
| `EscrowJobRef` | `dacs4:x-job-escrow:{jobId}:job` |
| `EscrowFundingEvidence` | `dacs4:x-job-escrow:{jobId}:funding` |
| `ExecutionEvaluation` | `dacs4:x-job-escrow:{jobId}:evaluation:{evaluationSeq}` |
| `EscrowDecision` | `dacs4:x-job-escrow:{jobId}:decision:{decisionStage}` |
| `EscrowTerminalEvidence` | `dacs4:x-job-escrow:{jobId}:terminal` |
| `DisputeCase` | `dacs4:x-job-escrow:{jobId}:dispute:{caseId}:case` |
| `DisputeOutcome` | `dacs4:x-job-escrow:{jobId}:dispute:{caseId}:outcome:{revision}` |

- (DRAA-1) `jobId` and `caseId` MUST use the current canonical JID form.
- (DRAA-2) Every numeric segment MUST use minimal unsigned decimal ASCII without a sign or leading zero.
- (DRAA-3) On a substrate whose native address is a pure function of the logical address, a binding MUST derive the native address from the complete logical address. On Demos SR-2, which uses write-input mapping, the producer MUST publish the logical-to-native binding as DEMOS-MAPPING requires, and a consumer MUST resolve through that published binding. The DEMOS-MAPPING text at the **Checked against** commit is the sole authority for this mapping and for its not-found behavior; SDK or node behavior that it does not state MUST NOT change a verdict.
- (DRAA-4) Uniqueness of the agreement, job, funding, per-stage decision, and terminal artifacts for one job comes from content-hash-bound references and the native `description`, `deliverable`, and `reason` bytes, not from storage immutability. A producer MUST NOT write a second distinct artifact at one of these addresses and MUST NOT delete or mutate an anchored artifact. A producer MUST NOT write a second copy at one of these addresses once a write there has a qualifying CORE `AnchorReceipt`, even with byte-identical content. A consumer that holds qualifying receipts for two writes at one of these addresses MUST apply the CORE §5.1 equivocation rule, even when the two copies are byte-identical. It retains both, selects neither, and yields `indeterminate`. A consumer that holds a qualifying receipt for only one write MUST NOT require proof that no other write exists.
- (DRAA-5) An observed artifact whose recomputed content hash differs from the hash-bound reference MUST yield `fail`. A deleted, unavailable, or not-found artifact MUST yield `indeterminate`.
- (DRAA-6) `evaluationSeq` MUST start at zero and MUST increment by one with no gap.
- (DRAA-7) A later dispute revision MUST reference the exact prior revision through `supersedesOutcomeRef`.
- (DRAA-8) A consumer MUST NOT select a decision, terminal record, or dispute revision from index order or self-reported time.
- (DRAA-9) For CORE SR2-10 through SR2-12 delivery of a section 6.5 artifact's `AnchorReceipt`, the entitled participants are the buyer, the seller, the evaluator, and the session orchestrator. The producer MUST deliver the verified receipt, and on a write-input substrate the logical-to-native binding, to each of them. DRP-8 closes SR2-13 resolution through the session bundle until promotion, so a consumer that holds neither the receipt nor a published binding MUST yield `indeterminate`.

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
- (DRT-14) Any candidate financial/accountability projection MUST be recomputed from the authenticated terminal evidence and finding according to the table below. A contradictory caller-supplied projection MUST yield `fail`. A terminal-state and finding pair that the table does not list MUST project no buyer or seller fault and remains an annotation. Until the DACS-5 mapping is promoted, this projection remains display-only and MUST NOT enter conforming v0.1 reputation derivation.
- (DRT-15) `terminalPhaseIndex` MUST equal the overlay's `terminalPhaseIndex`.
- (DRT-16) Observing the same terminal native transaction again, at any later wall-clock time or by another producer, MUST reproduce the byte-identical `EscrowTerminalEvidence` content hash. DRW-6 derives `observedAt` and `finality`, DRW-7 derives the event and attestation references, and the remaining fields are fixed by the overlay, DRL-10, and DRT-1 through DRT-15. A second, distinct terminal evidence record for the same job MUST yield `fail`.

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

The promoted DACS-5 text is where the metric treatment of these rows belongs. Until then, DRT-14 keeps every row display-only.

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
- (DREB-13) The selected implementation MUST separately and immutably commit `submissionCutoffSec`. It MUST expose authenticated evidence of that per-job value through the DRC-21 configuration event and reject native `submit` calls at or after it, even while the job remains funded awaiting expiry recovery.
- (DREB-14) `evaluationDeadlineSec - submissionCutoffSec` MUST be positive and no shorter than the pinned `minimumEvaluationWindowSec`.
- (DREB-15) The native expiry-recovery path for either a funded or submitted job MUST become callable at `evaluationDeadlineSec` and MUST NOT become callable before it.

No universal duration is declared here. Each registered rail revision pins `minimumEvaluationWindowSec`, the deadline profile, and the exact native enforcement and mapping.

### 8.3 Direct evaluator transaction model

The native caller of an entrypoint is the account the escrow contract authenticates for that call: `msg.sender` of the call frame entering the escrow contract.

- (DREB-16) The first profile MUST set the native evaluator to the evaluator-controlled account directly.
- (DREB-17) An EOA MAY be used when the agreement-bound DACS control proof resolves that address.
- (DREB-18) An EIP-1271 account MUST NOT be used unless the applicable DACS signature/control verifier supports its exact chain and code.
- (DREB-19) A relayer MUST NOT become the evaluator merely because it submits a transaction.
- (DREB-20) A generic evaluator adapter MUST NOT be used in the first profile.
- (DREB-21) For evaluator-driven `complete` or `reject`, the native caller MUST equal the agreement-bound evaluator account. A verifier MUST establish this from the DRL-10 transition, which an eligible implementation permits only to the stored evaluator, together with DREB-9. A verifier MUST NOT use the actor field of an event, because canonical events may emit the stored evaluator rather than the caller.
- (DREB-22) An outer transaction submitter MAY relay execution for an EIP-1271 or other supported account, but the rail evidence MUST distinguish that submitter from the native caller. For an EOA evaluator, the EOA itself remains the native caller; a relayer address MUST NOT be substituted.
- (DREB-23) An SDK timer, orchestrator refusal, transaction-simulation result, or post-transaction conformance verdict MUST NOT substitute for the native submission-cutoff and expiry enforcement required by DREB-12 through DREB-15.
- (DREB-24) In the first profile, the selected implementation MUST NOT recognize any ERC-2771 trusted forwarder or signature-authorized (`*WithAuthorization`) entrypoint for `createJob`, `fund`, `submit`, `complete`, `reject`, or `claimRefund`. DRC-10 evidence MUST show this.

### 8.4 Deployment eligibility

A rail definition pins at least the following parameters, under DRC-14 and DRC-17:

```text
type ERC8183ProfileParameters = {
  canonicalErcRevision: "ethereum/ERCs@a078cab5cc8e9581c15f76c091ed96eed28f02f7"
  implementationRevision: string
  entrypoints: AbiFunctionPin[]
  events: AbiEventPin[]
  configurationEvidence: { eventTopic0: string; submissionCutoffInput: number; preSubmissionPolicyInput: number; preSubmissionPolicyValue: string }
  nativeStatusMap: { nativeValue: number; nativeStatus: "Open" | "Funded" | "Submitted" | "Completed" | "Rejected" | "Expired" }[]
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

type AbiFunctionPin = { name: "createJob" | "fund" | "submit" | "complete" | "reject" | "claimRefund"; signature: string; selector: string; inputs: { name: string; type: string }[] }

type AbiEventPin = { name: string; signature: string; topic0: string; inputs: { name: string; type: string; indexed: boolean }[] }
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
- (DRC-15) `anchor-final-before-terminal-v1` orders the decision before the terminal transaction iff `decisionFinalizedAtMs + maxCrossSubstrateSkewMs < terminalBlockTimestampSec × 1000`. It orders the decision after iff `decisionFinalizedAtMs > terminalBlockTimestampSec × 1000 + maxCrossSubstrateSkewMs`, and otherwise cannot order them. `decisionFinalizedAtMs` is the `blockRef.timestamp` of the verified `finalized` CORE `AnchorReceipt` for the decision's SR-2 anchor, in unix milliseconds; DRC-19 fixes its Demos value. `terminalBlockTimestampSec` comes from the authenticated terminal inclusion-block header under DRF-8. `maxCrossSubstrateSkewMs` MUST be a non-negative safe integer.
- (DRC-16) `finalityBlocks` MUST equal `consumerFinalityProfile.settlement.requiredDepth`, and `chainId` MUST equal the chain ID in both the `railId` and the finality profile's `networkId`.
- (DRC-17) `entrypoints` MUST list exactly one entry for each of `createJob`, `fund`, `submit`, `complete`, `reject`, and `claimRefund`. `events` MUST list exactly one entry for each event named in the section 4.1 crosswalk and for the DRC-21 configuration event, and no other event; two entries MUST NOT share a `name` or `topic0`. Each entry's `inputs` MUST be the complete ordered parameter list that the DRC-10 source declares for it: each parameter's `name`, its canonical ABI `type`, and, for an event, whether it is `indexed`. `signature` MUST be the entry's `name` followed by its input types, in order, comma-separated and enclosed in parentheses. `selector` MUST be `0x` followed by 8 lowercase hexadecimal digits equal to the first four bytes of keccak-256 of `signature`. `topic0` MUST be `0x` followed by 64 lowercase hexadecimal digits equal to keccak-256 of `signature`. Every pinned event MUST be non-anonymous with at most three indexed inputs. `nativeStatusMap` MUST map every native status value to exactly one section 4.1 status. A missing, duplicate, or extra entry, `inputs` that do not reproduce `signature`, or a selector or `topic0` that does not derive from its signature MUST yield `error`.
- (DRC-18) A verifier MUST decode calldata, events, and native status only through the DRC-17 pins and the DRC-20 and DRC-21 field bindings. It MUST NOT decode an event that is not a pinned `events` entry. `canonicalErcRevision` pins ERC-8183 semantics and parameter names only, not an ABI. Indexed inputs are read from the log topics after `topic0`, in order, and the other inputs from the ABI-encoded log data, in order. A transaction or event that does not match a pinned selector or `topic0` MUST NOT be decoded under another signature. A log whose topics or data do not fit the pinned layout MUST NOT be decoded under another layout. Where the profile requires that transaction or event, the verifier MUST yield `fail`.
- (DRC-19) When the decision is anchored on Demos, `blockRef.timestamp` MUST be the consensus `content.timestamp` of the block that finalized the anchor, multiplied by 1000. DEMOS-MAPPING and the pinned SDK state no unit for that field. The pinned `kynesyslabs/node` source sets it in whole unix seconds when the consensus round starts, before the block is forged and voted, so the product is a lower bound on the anchor's finality. For that one-second granularity, the DRC-15 comparisons MUST use `maxCrossSubstrateSkewMs + 1000` in place of `maxCrossSubstrateSkewMs`. A rail that admits Demos-anchored decisions MUST set `maxCrossSubstrateSkewMs` no lower than the longest Demos round, from its start to block finality, that its DRC-12 ordering evidence establishes. The writer-chosen `content.timestamp` of the Storage Program transaction MUST NOT establish `decisionFinalizedAtMs`.
- (DRC-20) This rule covers each field that the profile reads from a pinned entrypoint or crosswalk event and that canonical ERC-8183 names at `canonicalErcRevision`. These include `jobId`, `client`, `provider`, `evaluator`, `expiredAt`, `hook`, `description`, `deliverable`, `reason`, and `amount`. Each such field MUST be read from the pinned input of that entry whose `name` equals the canonical parameter name, at that input's position and `indexed` layout. A required field with no input of that name in its entry, or with two, MUST yield `error`.
- (DRC-21) `configurationEvidence.eventTopic0` MUST equal the `topic0` of exactly one pinned `events` entry, which MUST have an input named `jobId` of type `uint256`. `submissionCutoffInput` and `preSubmissionPolicyInput` are distinct zero-based indexes into that entry's `inputs`. Each MUST name an input of an elementary value type that fills one ABI word: `uint<N>`, `int<N>`, `bool`, `address`, or `bytes<N>`. The cutoff input's type MUST be `uint<N>`. `preSubmissionPolicyValue` is the 32-byte ABI word that the policy input carries for `evaluator-rejection`, spelled `0x` followed by 64 lowercase hexadecimal digits. DRJ-3 and DREB-13 MUST read the per-job cutoff and policy only from that event, emitted by `contractAddress` in the transaction that emitted `creationEvent` with the native job's `jobId`, at those inputs. A decoded cutoff other than `submissionCutoffSec`, or a policy word other than `preSubmissionPolicyValue`, MUST yield `fail`. A configuration event, index, or input type that the pinned `events` entries do not contain, or an input type that this rule does not allow, MUST yield `error`.

The canonical ERC-8183 surface has one `expiredAt` value and permits evaluator rejection while `Funded`. The DACS MVP therefore fixes `preSubmissionRefundPolicy` to `evaluator-rejection` and requires a compatible implementation with a separately enforced submission cutoff. It does not claim that canonical `expiredAt` alone can provide both a submission cutoff and a later evaluation window. A future `expiry-only` policy requires a new profile and native enforcement that disables funded-state evaluator rejection.

The current reference implementation at [`erc-8183/base-contracts@142e669`](https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183.sol) is not eligible as published. The divergences checked against that revision are:

- UUPS upgrades, administrator pause, and emergency withdrawal (DRC-4 through DRC-6);
- mutable fees and whitelisted, detachable hooks (DRC-2, DRC-7);
- funded-state claim settlement, a pause-gated `claimRefund`, and a pending claim that delays a funded-state refund (DRC-1, DRC-3);
- a provider-mutable `payoutReceiver` while `Open`, and an `IDisburser.onDisbursement` callback that can revert `complete` and funded-state claims (DREB-10, DRC-1);
- a submission cutoff enforced only at `expiredAt`, with a fixed one-hour `EVALUATION_GRACE_PERIOD` delaying refund of a `Submitted` job, rather than a separate per-job cutoff and the DREB-12 through DREB-15 mapping (DRC-13);
- a provider reject of an `Open` job (the client reject is in the crosswalk), an `Open` to `Expired` refund path, and an `Open` to `Submitted` zero-budget submit (DRL-11);
- no zero-budget funding rejection (DRF-2);
- a `PaymentReleased` event whose payee input is named `recipient`, not the canonical `provider`, so a pin of that source has no `provider` input for DRT-5 and yields `error` (DRC-17, DRC-20);
- `*WithAuthorization` signature-authorized entrypoints in [`contracts/ERC8183WithAuthorization.sol`](https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183WithAuthorization.sol) (DREB-24).

Each divergence is a deployment capability check with a section 11 case. Patching only some of them does not make the implementation eligible.

This finding does not reject ERC-8183. It means a strict DACS deployment needs a minimal compatible implementation or irreversible authority restrictions that independently prove DRC-1 through DRC-21 and DREB-24.

## 9. Verification result and ordering

A verifier returns exactly one value of the DACS four-way disposition (CORE JID-4, DACS-4 FV-10):

```text
"pass" | "fail" | "indeterminate" | "error"
```

It applies the checks in this order:

1. Parse the selected artifact type. An unsupported discriminator or version is `error` (CORE §11.1.2 new-type refusal).
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
- (DRV-8) Each signed artifact of sections 2 through 7 MUST carry exactly the one version member its type lists, with the value `"1"`: `jobEscrowRailVersion`, `deliveryOrRemedyAgreementVersion`, `escrowJobRefVersion`, `escrowFundingEvidenceVersion`, `executionEvaluationVersion`, `escrowDecisionVersion`, `disputeCaseVersion`, `disputeOutcomeVersion`, and `escrowTerminalEvidenceVersion`. A missing or duplicated version member, or any other value, MUST yield `error` under step 1 before any hash or signature check. A `JobEscrowRailDefinition` whose `railType` is not `x-evm-erc8183` MUST also yield `error` under step 1.

## 10. Transcript and evidence disclosure

- (DRQ-1) The first profile MUST use `public-evidence-only` or `explicit-party-supplied` disclosure.
- (DRQ-2) `explicit-party-supplied` means the named party deliberately supplies the exact evidence to the evaluator under the signed policy.
- (DRQ-3) An evaluator, verifier, or party MUST NOT treat either policy as authorizing retrieval, decryption, or disclosure of a negotiation transcript.
- (DRQ-4) Encrypted transcript use MUST remain disabled until #351 defines the signed transcript, unanimous member consent, envelope suite, revocation, and SR-2 evidence.
- (DRQ-5) A future transcript-enabled profile MUST use a new disclosure-policy value and a new rail or profile revision.

## 11. Required conformance evidence

Promotion requires full signed artifacts and authenticated native inputs, not expected outputs alone. Each case below has a stable ID, the expected DACS four-way result for each of its sub-cases, and the rules it exercises.

`scripts/validate_candidate_profile.py` checks that every requirement-bearing rule is listed by at least one rejection or indeterminate case, not only by positive cases. A process case may list only the process rules DRG-2, DRC-10, and DRC-11, and it covers only them. Every listed rule exists. Positive cases expect `pass`, rejection cases expect only `fail` or `error`, and indeterminate cases expect `indeterminate`. The script also regenerates `conformance/candidates/delivery-or-remedy/rule-case-matrix.json` and fails CI when that file is stale. No case has an executable vector yet, so this document cannot leave pre-normative status.

### 11.1 Positive cases

<!-- prose-lint: allow — the P1 rule list is an enumeration, not a sentence -->
- **P1** — create, fund, deliver, submit, evaluate, and release the complete budget. *Expected:* `pass`. *Rules:* DRP-1, DRP-2, DRP-3, DRP-6, DRP-7, DRP-11, DRP-12, DRP-14, DRP-15, DRP-16, DRA-1, DRA-2, DRA-3, DRA-4, DRA-11, DRA-12, DRA-17, DRA-18, DRA-20, DRA-21, DRA-22, DRL-1, DRL-10, DRJ-2, DRJ-4, DRJ-9, DRJ-10, DRJ-11, DRF-1, DRF-2, DRF-3, DRF-4, DRF-5, DRF-6, DRF-7, DRF-8, DRE-1, DRE-2, DRE-3, DRE-6, DRE-7, DRE-8, DRE-9, DRE-10, DRD-1, DRD-2, DRD-3, DRD-4, DRD-5, DRD-10, DRD-14, DRAA-1, DRAA-3, DRAA-6, DRAA-9, DRT-1, DRT-4, DRT-5, DRT-8, DRT-11, DRT-15, DREB-7, DREB-8, DREB-9, DREB-10, DREB-11, DREB-16, DREB-21, DRV-7, DRQ-1, DRR-1, DRR-2, DRR-3, DRR-4, DRR-5, DRR-7, DRR-8, DRC-14, DRC-15, DRC-16, DRC-17, DRC-18, DRC-20, DRC-21, DRW-1, DRW-2, DRW-3, DRW-4, DRW-6, DRW-7.
- **P2** — create, fund, deliver, submit, evaluate, and refund the complete budget after submission. *Expected:* `pass`. *Rules:* DRT-2, DRT-6, DRT-12, DRD-6, DRD-14, DRL-5, DRT-14.
- **P3** — expiry before submission followed by a complete refund. *Expected:* `pass`. *Rules:* DRT-3, DRT-13, DRD-7, DRL-5, DRX-6, DREB-15, DRP-12.
- **P4** — expiry after submission, once authenticated native time reaches `evaluationDeadlineSec`, followed by a complete refund without an invented evaluator decision. *Expected:* `pass`. *Rules:* DRT-3, DRD-7, DRL-5, DRL-6, DREB-15.
- **P5** — agreement-authorized evaluator rejection before submission using a `DisputeOutcome`, with no delivery reference, verified from the exact revision `basisRef` binds on a substrate without authenticated absence and without any search for a later revision. *Expected:* `pass`. *Rules:* DRD-9, DRD-12, DRD-13, DRD-14, DRT-2, DRT-12, DRX-7, DRX-9, DRP-7, DRP-12.
- **P6** — an independently reproduced byte-exact `description`, `deliverable`, and `reason` mapping. *Expected:* `pass`. *Rules:* DREB-1, DREB-2, DREB-3, DREB-4, DREB-6, DRJ-4.
- **P7** — relayed EIP-1271 execution where the outer submitter differs but the native caller remains the bound evaluator account. *Expected:* `pass`. *Rules:* DREB-18, DREB-21, DREB-22.
- **P8** — the same terminal transaction observed twice, at two different wall-clock times and by two independent producers, reproduces a byte-identical terminal evidence hash. *Expected:* `pass`. *Rules:* DRT-16, DRV-5, DRW-6, DRW-7.
- **P9** — Vet freshness exactly at the boundary `fundingTimeMs`, with an explicit `validUntil` and with the `defaultMaxAgeSec` fallback. *Expected:* `pass`. *Rules:* DRA-9, DRW-4.
- **P10** — a DACS-5 projection recomputed for both anchored copies of each section 7 row. *Expected:* `pass`. *Rules:* DRT-14, DRX-5, DRX-6, DRT-13.
- **P11** — a native `submit` that lands before a pre-submission rejection: the unexecuted pre-submission decision authorizes nothing, and a post-submission decision at its own address authorizes the terminal action. *Expected:* `pass`. *Rules:* DRD-13, DRD-14, DRAA-4, DRAA-8.
- **P12** — a Demos-anchored decision ordered before an EVM terminal transaction from the finalizing block's second-granularity consensus timestamp. *Expected:* `pass`. *Rules:* DRC-15, DRC-19, DRD-10, DRW-4.
- **P13** — the funding evidence and the post-submission decision each written once on Demos and resolved through the one published binding by two producers at different wall-clock times. Both emit the same logical-address `fundingEvidenceRef` and `decisionRef` and a byte-identical terminal evidence hash. *Expected:* `pass`. *Rules:* DRW-7, DRAA-3, DRAA-4, DRT-16.

### 11.2 Required rejection cases

- **R1** — wrong job, overlay, rail, chain, contract, runtime code, token, currency, budget, decimals, client, provider, evaluator, submission cutoff, pre-submission rejection policy, expiry/recovery deadline, payout account, or phase index. A price that is not a whole number of token base units. A missing payout binding, a second payout binding, or one keyed at `terminalPhaseIndex`. *Expected:* `fail`. *Rules:* DRA-1, DRA-2, DRA-5, DRA-10, DRA-11, DRA-14, DRA-20, DRA-21, DRJ-2, DRJ-3, DRJ-5, DRJ-10, DRC-21, DRF-1, DRF-2, DREB-7, DREB-8, DREB-9, DREB-10, DREB-11, DREB-12, DRT-4, DRT-5, DRT-6, DRT-15, DRP-5, DRR-7, DRC-16, DRV-6, DRV-7.
- **R2** — noncanonical JID, content hash, logical-address numeric segment, or `nativeJobId` (overflow at 2^256, hex, sign, whitespace, leading zero). *Expected:* `error`. *Rules:* DRAA-1, DRAA-2, DREB-3, DRJ-1, DRV-3.
- **R3** — description prefix, hash-text rehash, byte-order, padding, truncation, or zero-reason mismatch. A `createJob` reached through an intermediary contract instead of a direct call to `contractAddress` with the pinned selector, or a `description` taken from `getJob` or an `eth_call`. *Expected:* `fail`. *Rules:* DREB-1, DREB-4, DREB-5, DREB-6, DRJ-4, DRV-3.
- **R4** — cross-job delivery, evaluation, decision, terminal-event, or receipt replay. *Expected:* `fail`. *Rules:* DRD-8, DRT-11, DRF-1, DRL-4.
- **R5** — wrong evaluator signer or transaction caller. *Expected:* `fail`. *Rules:* DRE-1, DRD-1, DREB-21, DRA-3.
- **R6** — evaluator collision with buyer, seller, client, or provider, including a case-variant spelling of a commercial party's `cci-xm:evm` claim. An evaluator `requirement` whose hash differs from `requirementHash`, or an authenticated DACS-2 composite result that does not meet that requirement. *Expected:* `fail`. *Rules:* DRA-6, DRA-7, DRW-5, DRA-8.
- **R7** — delivery or decision hash substitution. *Expected:* `fail`. *Rules:* DRD-3, DREB-2, DREB-6, DRE-2.
- **R8** — release for a refund decision, or refund for a release decision. *Expected:* `fail`. *Rules:* DRD-2, DRD-5, DRD-6.
- **R9** — nonzero preterminal payout, partial claim, platform fee, or evaluator fee. *Expected:* `fail`. *Rules:* DRL-7, DRL-8, DRC-1, DRC-2, DRF-5, DRT-7.
- **R10** — mutable or changed implementation, hook, authority, payout receiver, or token behavior, including a pausable or blacklistable token. A delegating contract without both implementation pins, or implementation or token code that differs from its pin. *Expected:* `fail`. *Rules:* DRJ-6, DRJ-7, DRJ-11, DRC-3, DRC-4, DRC-5, DRC-6, DRC-7, DRC-8, DREB-10, DRL-9, DRA-14.
- **R11** — ambiguous event identity, mismatched log index, or a noncanonical `txHash`. *Expected:* `fail`; `error` for the noncanonical `txHash`. *Rules:* DRJ-2, DRF-3, DRT-4, DRC-9, DRW-3.
- **R12** — terminal action followed by an attempted monetary replay, or a post-terminal outcome that relabels the disposition or supersedes anything other than the accountability finding. *Expected:* `fail`. *Rules:* DRL-4, DRX-3, DRX-4, DRAA-8, DRT-13.
- **R13** — delivery evidence that contains or derives from the native submission event. *Expected:* `fail`. *Rules:* DRP-9.
- **R14** — a decision finalized after the terminal action, or a self-reported timestamp used as a substitute for authenticated ordering. A Demos decision timed from the transaction's writer-chosen timestamp or with consensus seconds read as milliseconds. *Expected:* `fail`. *Rules:* DRD-4, DRD-10, DRD-11, DRAA-8, DRC-15, DRC-19.
- **R15** — a relayer presented as the native evaluator caller, an event actor field used as the caller, or a trusted-forwarder or `*WithAuthorization` entrypoint. A generic evaluator adapter or any account other than the evaluator-controlled account set as the native evaluator. An EIP-1271 evaluator that the DACS verifier does not support. *Expected:* `fail`. *Rules:* DREB-16, DREB-18, DREB-19, DREB-20, DREB-21, DREB-22, DREB-24.
- **R16** — an evaluator added as a buyer/seller bundle party merely because it signed the overlay. *Expected:* `fail`. *Rules:* DRA-13.
- **R17** — a native submission accepted at or after `submissionCutoffSec`, expiry recovery accepted before `evaluationDeadlineSec`, a cutoff not separated from the deadline by `minimumEvaluationWindowSec`, or a deadline later than the agreement deadline. *Expected:* `fail`. *Rules:* DREB-12, DREB-13, DREB-14, DREB-15, DRC-13, DREB-23, DRA-19.
- **R18** — an `expiry-only` pre-submission policy claimed under this profile, or a client-side policy presented as native enforcement. *Expected:* `error` for the `expiry-only` value; `fail` for the client-side policy. *Rules:* DRA-15, DRA-16, DRL-9, DREB-23.
- **R19** — a byte-valid, re-signed historical delivery-shaped `SettlementEvidence` presented as the delivery evidence, `DeliveryEvidence` whose `phaseIndex` differs from `deliveryPhaseIndex`, or a `failure` `DeliveryEvidence` submitted natively or used for a release. *Expected:* `fail`. *Rules:* DRP-7, DRE-2, DREB-1.
- **R20** — a pipeline with a second payment, delivery, or `pay-alternative` step, a missing or reordered `x-job-escrow` step, steps naming different rails, or an unsupported `agreementPhase`. An older reader that drops either `x-job-escrow` step, runs one as an ordinary payment, or executes the delivery outside the pair. *Expected:* `fail`; `error` for the unsupported `agreementPhase`. *Rules:* DRP-1, DRP-2, DRP-3, DRP-4, DRP-5, DRP-13, DRP-14.
- **R21** — a malformed or overlong `railId`, a `phaseHandler` other than `x-job-escrow`, a missing `consumerFinalityProfile`, an unresolvable `acceptedRails` entry, dispatch through the `pay-*` PIPE-3 through PIPE-5 contract, or an absent or different agreement `terms.rail`. A `railId` whose `<asset>` segment is lowercased, or a `JobEscrowRailDefinition` signed under `"dacs-rail:v1:"` instead of the DRR-2 domain. *Expected:* `error` for the malformed `railId`, including the lowercased `<asset>`, and the unsupported `phaseHandler`; `fail` otherwise. *Rules:* DRR-1, DRR-2, DRR-3, DRR-4, DRR-6, DRC-16, DRP-10, DRA-22.
- **R22** — overlay buyer or seller bindings that differ from the bilateral agreement's parties, a signature whose `party` differs from its role's claim, or duplicate roles. A role whose primary claim, bundle, Vet result, or EVM account claim resolves but fails verification. *Expected:* `fail`. *Rules:* DRA-17, DRA-18, DRA-3, DRA-4.
- **R23** — a pre-submission rejection decision executed after a native `submit` landed, or a `Submitted` to `Rejected` transition whose decision omits delivery evidence. A pre-submission decision that carries `deliveryEvidenceRef` or an `ExecutionEvaluation` basis. A decision whose stage contradicts its delivery reference or the prior native status, or a second distinct decision at one stage address. *Expected:* `fail`. *Rules:* DRD-9, DRD-12, DRD-13, DRD-14, DRT-12.
- **R24** — a native transition outside the section 4.1 crosswalk: `Open` to `Expired`, a provider cancel of `Open`, an `Open` zero-budget submit, or a transition out of a terminal status. A binding that merges two portable states, or a native state absent from `nativeStatusMap`. *Expected:* `fail`. *Rules:* DRL-1, DRL-2, DRL-10, DRL-11, DRF-4.
- **R25** — a rule whose `jobId` differs from the overlay's, or a rule finalized after the overlay. An unsupported rule version or kind, a rule hash mismatch, empty or duplicate criteria, a `result` or `finding` that contradicts the criterion outcomes, or a disposition the matrix forbids. *Expected:* `error` for the unsupported version or kind; `fail` otherwise. *Rules:* DRE-6, DRE-8, DRE-9, DRE-10, DRD-2.
- **R26** — an `indeterminate` evaluation used to authorize a terminal transaction, or an evaluation that converts missing evidence to rejection or acceptance. *Expected:* `fail`. *Rules:* DRE-4, DRE-5.
- **R27** — an address with bad EIP-55 checksum, short or long length, or non-hex digits, the zero address for a live role, or an uppercase DACS artifact address. A code hash that is not keccak-256 of the deployed code, or the empty-code hash. *Expected:* `error` for the malformed spellings; `fail` for the zero address, the wrong code hash, and the empty-code hash. *Rules:* DRW-1, DRW-2, DRA-5, DRA-7, DRV-3.
- **R28** — Vet freshness evaluated one second after expiry, with seconds compared directly to milliseconds, or with `observedAt` or a local clock as `now`. A duration compared as a timestamp, or an operand or sum above the safe bound. *Expected:* `fail`; `error` for the operand or sum above the safe bound. *Rules:* DRA-9, DRW-4.
- **R29** — a `DisputeOutcome` that claims a transfer, has a `caseRef` that does not resolve to a matching `DisputeCase`, carries `faultedParty` on a non-fault finding, or skips a revision. A `faultedParty` that names the agreement party the finding does not fault. *Expected:* `fail`. *Rules:* DRX-1, DRX-5, DRX-6, DRX-7, DRAA-7.
- **R30** — an artifact from the existing DACS-X dispute candidate family presented as a `DisputeCase` or `DisputeOutcome`, or the reverse. *Expected:* `error`. *Rules:* DRX-8, DRG-1.
- **R31** — a profile field with a value other than the listed literal, a malformed `implementationRevision`, or `finalityBlocks` that differs from the profile depth. A missing, duplicate, or extra entrypoint or event pin, including two events with one name, or a missing configuration or status pin. Pin `inputs` that do not reproduce their signature, an event with more than three indexed inputs, or a selector or `topic0` that does not derive from its signature. A `configurationEvidence` event, input index, or input type that the pinned events do not contain, or a required canonical field with no pinned input of that name. A configuration input of a static array, tuple, or `bytes<N>` cutoff type, or a configuration `jobId` that is not `uint256`. A required transaction or event decoded outside the pins, or a log whose topics or data do not fit the pinned `indexed` layout. *Expected:* `error` for the literal, revision, pin, and field-binding defects; `fail` for the depth mismatch, the decode outside the pins, and the layout mismatch. *Rules:* DRC-14, DRC-16, DRC-17, DRC-18, DRC-20, DRC-21, DRR-6.
- **R32** — a second distinct terminal evidence record, a mutated anchored artifact, or a second write of different bytes at a single-artifact address. *Expected:* `fail`. *Rules:* DRT-16, DRAA-4, DRAA-5, DRT-10.
- **R33** — a terminal transaction whose evidence is signed by the orchestrator but contradicts chain or evaluator facts, or a signature over consistent false fields. *Expected:* `fail`. *Rules:* DRT-10, DRV-4, DRV-6, DRJ-8.
- **R34** — job-escrow artifacts submitted as DACS-5 bundle settlement members, or as volume contributions, before promotion. *Expected:* `fail`. *Rules:* DRP-8, DRT-14.
- **R35** — a candidate signature presented under a registered DACS domain, a transcript-dependent disclosure policy, or an `x-` candidate name read as a registered name. Transcript evidence retrieved, decrypted, or disclosed on the authority of `public-evidence-only` or `explicit-party-supplied`. *Expected:* `fail` for the relabelled signature and the transcript evidence; `error` for the disclosure policy and the `x-` name. *Rules:* DRG-1, DRG-3, DRQ-1, DRQ-3, DRQ-4, DRQ-5.
- **R36** — delivery begun before funding finality, or job creation before the overlay is finalized. A lock submitted before both commit receipts are finalized, or with a receipt inferred from a phase result. A terminal action before the delivery returns and before the cutoff, or a late delivery submitted to a refunded job. *Expected:* `fail`. *Rules:* DRP-6, DRP-11, DRP-12, DRP-16, DRA-12.
- **R37** — a `disabled`, `failed`, or `mocked` rail selected, or a not-applicable section 2.3 gate cited as satisfied. An `availability` read from a `"dacs-rail:v1:"` record or any copy other than the pinned job-escrow definition. An `asset` or `network` whose kind, chain, contract, or decimals differ from the parameters. A missing `asset`, `network`, or `governance` member, or a supersession member outside `governance.supersedes`. *Expected:* `fail`; `error` for the missing member. *Rules:* DRR-5, DRP-15, DRR-7, DRR-8.
- **R38** — a refund projected as seller fault without an authenticated finding, or a release projected as satisfying every non-financial obligation. A fault projected for a terminal-state and finding pair that the section 7 table does not list. *Expected:* `fail`. *Rules:* DRL-5, DRL-6, DRT-14.
- **R39** — subject evidence outside the signed disclosure policy or not hash-bound, an evaluation used as a decision basis before it is anchored, or an `evaluationSeq` that does not start at zero, skips, or repeats. *Expected:* `fail`. *Rules:* DRE-3, DRE-7, DRAA-6.
- **R40** — `released` terminal evidence without `decisionRef` or `deliveryEvidenceRef`, `rejected-refund` evidence without `decisionRef`, or `expired-refund` evidence that carries a manufactured decision or evaluator signature. *Expected:* `fail`. *Rules:* DRT-1, DRT-2, DRT-3, DRD-7.
- **R41** — a `dispute-outcome` basis without `recommendedDisposition`, with a recommendation that contradicts the decision or the dispute-outcome table, or with an `evaluator-unavailable` or `indeterminate` finding. A basis whose `basisRef` does not resolve to the exact signed revision it hash-binds, or one authorizing a pre-submission release. *Expected:* `fail`. *Rules:* DRX-9, DRD-2, DRD-14.
- **R42** — an `ok: false` invocation whose `errorClass` contradicts the PC-4 trigger table, such as a currency mismatch classified as `transient`. A PB-1 payout destination mismatch classified `permanent`, or a PB-2 applicable-but-unresolvable binding classified `counterparty`. *Expected:* `fail`. *Rules:* DRP-17, DRA-21, DRA-20.
- **R43** — funding or terminal evidence whose `observedAt` or `finalityObservedAt` is a wall-clock time, whose finality model is not `block-depth`, or whose `finalityBlocks` differs from the rail. Event references that are reordered, incomplete, duplicated, or outside the transition's required events. An `AttestationRef` that carries a `signer`, an anchor `kind` other than `storage-program`, or a native `stor-` address as its locator. An `escrowJobRef`, `fundingEvidenceRef`, or `decisionRef` whose locator is not its section 6.5 address, or a `deliveryEvidenceRef` whose locator is not `dacs4:delivery:{jobId}:{deliveryPhaseIndex}`. *Expected:* `fail`. *Rules:* DRW-6, DRW-7, DRT-16.
- **R44** — a job reference or funding evidence signed by an account other than the authenticated session orchestrator, or whose finalized anchor receipt names a logical address other than its section 6.5 address. *Expected:* `fail`. *Rules:* DRJ-9, DRF-7.
- **R45** — for each of `jobEscrowRailVersion`, `deliveryOrRemedyAgreementVersion`, `escrowJobRefVersion`, `escrowFundingEvidenceVersion`, `executionEvaluationVersion`, `escrowDecisionVersion`, `disputeCaseVersion`, `disputeOutcomeVersion`, and `escrowTerminalEvidenceVersion`, an artifact whose version member is missing, duplicated, or other than `"1"`, with otherwise valid hashes and signatures. A rail definition whose `railType` is not `x-evm-erc8183`. *Expected:* `error`. *Rules:* DRV-8, DRR-6.

### 11.3 Required indeterminate cases

- **I1** — unavailable rail definition, agreement artifact, or evaluation rule. A role's primary claim, bundle, Vet result, or EVM account claim that cannot be resolved. A job-escrow rail read by a supporting reader that holds no registry snapshot named by a CORE §B.6 out-of-band agreement. *Expected:* `indeterminate`. *Rules:* DRA-1, DRV-1, DRC-11, DRE-8, DRR-6, DRA-4, DRR-3.
- **I2** — unavailable or inconsistent authenticated chain state, including an unauthenticated prior native status. *Expected:* `indeterminate`. *Rules:* DRL-3, DRL-12, DRV-2, DRT-9.
- **I3** — missing finality evidence. *Expected:* `indeterminate`. *Rules:* DRF-6, DRF-8, DRT-8.
- **I4** — unresolved proxy implementation, authority state, or pinned implementation or token code. *Expected:* `indeterminate`. *Rules:* DRJ-6, DRJ-7, DRJ-11, DRC-6.
- **I5** — missing job reference, funding evidence, delivery, evaluation, or decision artifact when no contradictory fact is established. This includes a deleted Demos storage program and a consumer that received neither the anchor receipt nor the published binding. *Expected:* `indeterminate`. *Rules:* DRE-5, DRAA-5, DRAA-3, DRAA-9, DRJ-9, DRF-7.
- **I6** — decision and terminal evidence that the `anchor-final-before-terminal-v1` profile cannot order within `maxCrossSubstrateSkewMs`, including the Demos one-second widening. *Expected:* `indeterminate`. *Rules:* DRD-11, DRC-12, DRC-15, DRC-19.
- **I7** — a retry after `indeterminate` that reconciles the original native job before any new transaction. *Expected:* `indeterminate`. *Rules:* DRV-5, DRT-9.
- **I8** — the funding evidence or the post-submission decision written twice on Demos with byte-identical content at two native addresses, and a verifier that holds qualifying receipts for both writes. The verifier retains both, selects neither, and evaluates DRC-15 from neither copy, even when one copy finalized before the terminal transaction and the other after it. *Expected:* `indeterminate`. *Rules:* DRAA-4, DRAA-3, DRC-15.

### 11.4 Process checks

- **Q1** — this document's validator, rule-to-case matrix, and **Checked against** pin are current, and every registration proposal carries reproducible deployment evidence. *Expected:* `pass`. *Rules:* DRG-2, DRC-10, DRC-11.

A vector pack for promotion includes exact canonical bytes, hashes, signatures, logical addresses, receipts, chain inputs, the expected result, and the rule IDs exercised. Registration waits until at least two independent implementations reproduce the positive bytes and every rejection and indeterminate outcome.

## 12. Promotion and ownership gates

### DACS Standard and steward

- obtain one independent approval of the issue #356 decision matrix before steward acceptance;
- split promoted text into the job-escrow lifecycle, ERC-8183 binding, DACS-X artifacts, and DACS-5 projection;
- extend the DACS-1 `PhaseType` union and register every new signature domain, logical-address family, and rule ID;
- publish implementation-neutral vectors for every section 11 case;
- record the unit of the Demos block `content.timestamp` in DEMOS-MAPPING before promoting DRC-19, which until then rests on the pinned `kynesyslabs/node` source;
- regenerate every existing Demos-anchored vector whose `blockRef.timestamp` is not a whole multiple of 1000 before promoting DRC-19;
- amend CORE CF-3, or narrow DRW-5 to the DRA-6 and DRA-7 collision checks, before promoting DRW-5. CF-3 compares the identifier text, so two spellings of one EVM account are one party here but two DACS-5 reputation keys;
- reconcile the "lowercase ASCII" comment on DACS-4 `RailDefinition.railId` with the uppercase asset symbols of its §9.4.2 registry rows, which DRR-1 follows, before registering a job-escrow `railId`;
- keep the rail unavailable until deployment evidence and independent reproduction pass.

### Contract and reference implementation contributors

- provide an exact deployment satisfying DRC-1 through DRC-21 and DREB-24;
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

- [ ] The paired `x-job-escrow` phase model is implementable without changing existing phase-result semantics.
- [ ] The overlay is structurally distinct and binds buyer, seller, evaluator, deployment, policy, and deadlines.
- [ ] The three ERC field mappings are byte-exact and non-circular.
- [ ] Monetary disposition and accountability finding cannot be conflated.
- [ ] Expiry never invents an evaluator decision or party fault.
- [ ] The contract capability gate rules out every preterminal payout and blocked-recovery path.
- [ ] No current deployment is accidentally presented as registered or available.
- [ ] Transcript use remains outside the profile until #351 is complete.
- [ ] The required vector set is sufficient for a second independent implementation.
