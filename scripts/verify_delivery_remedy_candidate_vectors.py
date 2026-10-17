#!/usr/bin/env python3
"""Execute the non-normative delivery-or-remedy candidate fixture pack.

This is deliberately separate from the canonical DACS vector validator.  It
implements the review candidate in ``docs/delivery-or-remedy-candidate.md``
without registering a rail or changing current conformance requirements.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import math
import re
import subprocess
import sys
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Any, Callable, NamedTuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

try:
    from jcs import canonicalize as jcs_canonicalize
except ModuleNotFoundError:  # imported as scripts.verify_* by the unit suite
    from scripts.jcs import canonicalize as jcs_canonicalize


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VECTOR_PACK = (
    ROOT / "conformance/fixtures/delivery-remedy/candidate-vectors-v0.1.json"
)
DEFAULT_DEPLOYMENT_PACK = (
    ROOT / "conformance/fixtures/delivery-remedy/deployment-capabilities-v0.1.json"
)
# The candidate's External pins, which fix the exact text each binding rule
# follows, plus the two further sources this pack reads: the ERC-8183
# reference contract whose divergences the deployment pack checks, and the
# ULID range of a JID (DRAA-1).  A lifecycle pack written against other
# sources is refused before any vector runs.
EXTERNAL_SOURCE_PINS = {
    "canonicalErc8183": "https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-8183.md",
    "eip1271": "https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-1271.md",
    "eip155": "https://github.com/ethereum/EIPs/blob/c1a1eb21b465c9c42704a8a5743ad0694aedbff7/EIPS/eip-155.md",
    "eip55": "https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-55.md",
    "eip1052": "https://github.com/ethereum/EIPs/blob/c1a1eb21b465c9c42704a8a5743ad0694aedbff7/EIPS/eip-1052.md",
    "erc2771": "https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-2771.md",
    "rfc8785": "https://www.rfc-editor.org/rfc/rfc8785",
    "demosSdk": {
        "package": "@kynesyslabs/demosdk",
        "version": "4.0.16",
        "integrity": "sha512-nVhp1uC+tFGzhew9c8XIajTMmELopx7gd0joqqzDd2XyUuFDcqrda51NYqvX5C8+L3Xgnie/mRf7JRqZ7r3tHA==",
    },
    "referenceImplementation": "https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183.sol",
    "ulid": "https://github.com/ulid/spec/blob/d0c7170df4517939e70129b4d6462cc162f2d5bf/README.md",
}
# DRG-2: the DACS-Standard `next` commit the candidate is checked against, and
# the documents whose text this verifier implements.  The pack pins each
# document's SHA-256, so a pack and a checkout whose texts differ are refused.
DACS_CHECKED_AGAINST = "df7bc202ebdc179a59d61a8221072f33f482b933"
PINNED_DOCUMENTS = (
    "docs/delivery-or-remedy-candidate.md",
    "spec/CORE.md",
    "spec/DACS-1-IDENTIFY.md",
    "spec/DACS-2-VET.md",
    "spec/DACS-3-NEGOTIATE.md",
    "spec/DACS-4-SETTLE.md",
    "spec/DACS-5-VERIFY.md",
    "spec/DEMOS-MAPPING.md",
)

# A ULID: 26 Crockford base-32 digits, at most 7ZZZZZZZZZZZZZZZZZZZZZZZZZ
# (ulid/spec, "Overflow Errors when Parsing Base32 Strings").
JID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
BYTES32_RE = re.compile(r"^0x[0-9a-f]{64}$")
# DRW-3: the DACS-4 SB-1 spelling of an EVM transaction hash.
EVM_TX_RE = re.compile(r"^0x[0-9a-f]{64}$")
# DRW-1: an EVM address in a DACS artifact field, and the address component
# of a `cci-xm:evm` claim, which may also be upper-case or EIP-55 mixed case.
EVM_ADDRESS_RE = re.compile(r"0x[0-9a-f]{40}")
CLAIM_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
# DRW-2: an EVM code hash.
CODE_HASH_RE = re.compile(r"0x[0-9a-f]{64}")
ZERO_ADDRESS = "0x" + "00" * 20
ZERO_BYTES32 = "0x" + "00" * 32
# EIP-1052: EXTCODEHASH of an account with no code, keccak-256 of no bytes.
EMPTY_CODE_HASH = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
# Minimal unsigned decimal text: DRJ-1's native job ID, a token amount.
UNSIGNED_DECIMAL_RE = re.compile(r"0|[1-9][0-9]*")
# A CORE CD-1 canonical decimal `PriceTerm.amount`.
CANONICAL_DECIMAL_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?")
# ERC-20 `decimals()` is a uint8.
MAX_TOKEN_DECIMALS = 255
# An ERC-20 amount and an ERC-8183 job ID are uint256 values, so no budget or
# job above 2^256 - 1 (78 decimal digits) exists.
UINT256_MAX_TEXT = str(2 ** 256 - 1)
# CORE §B.2 numeric safe-magnitude constraint: every JSON number is finite and
# at most 2^53 - 1 in magnitude.
SAFE_INTEGER_MAX = 2 ** 53 - 1
# DRW-4: the largest unix-second value; 1000 times it is still a safe integer.
MAX_SECONDS = 9007199254740
# The deepest array/object nesting a lifecycle or a pack file may have.  The
# pack's deepest lifecycle nests 8 levels, and the packs themselves 10.  JCS
# canonicalisation, `json.dumps` and `copy.deepcopy` recurse once or more per
# level, and a lifecycle a few hundred levels deep exhausts CPython's default
# 1,000-frame recursion limit; 64 leaves room for producer extensions and stays
# far inside that limit.
MAX_JSON_DEPTH = 64
TOO_DEEP = f"arrays and objects nest deeper than {MAX_JSON_DEPTH} levels"
# What a malformed value can raise while a check reads it.  Each lifecycle in a
# batch that raises one is its own `error`; the guard audit sets this to ().
MALFORMED_INPUT_ERRORS: tuple[type[Exception], ...] = (
    AttributeError, IndexError, KeyError, TypeError, ValueError, RecursionError,
)

# Each signed type's signing domain: the candidate's `dacs-x-` domains, the
# DACS-3 payee-bound agreement, and DACS-4 `DeliveryEvidence` (PDE-2).
DOMAINS = {
    "bilateralAgreement": "dacs-payee-bound-agreement:v1:",
    "railDefinition": "dacs-x-job-escrow-rail:v1:",
    "agreement": "dacs-x-delivery-remedy-agreement:v1:",
    "job": "dacs-x-escrow-job-ref:v1:",
    "funding": "dacs-x-escrow-funding-evidence:v1:",
    "delivery": "dacs-delivery-evidence:v1:",
    "evaluation": "dacs-x-execution-evaluation:v1:",
    "disputeCase": "dacs-x-dispute-case:v1:",
    "dispute": "dacs-x-dispute-outcome:v1:",
    "decision": "dacs-x-escrow-decision:v1:",
    "terminal": "dacs-x-escrow-terminal-evidence:v1:",
}
# DREB-1: the native `description` prefix of candidate §8.1.
DESCRIPTION_PREFIX = "dacs-x-delivery-remedy:v1:"

# The synthetic fixture resolver and registry steward are verifier-pinned
# trust anchors (DRV-1, DRR-2).  `publicKeys` in a vector covers only DACS
# parties.
FIXTURE_RESOLVER_CLAIM = "did:demos:agent:" + "99" * 32
PINNED_RESOLVER_KEYS = {
    FIXTURE_RESOLVER_CLAIM: "iln7hKoVj-cofK9mAaE1yj8OiplfupJiIg1nFjqhqfA",
}
RESOLVER_DOMAIN = "dacs-x-delivery-remedy-fixture-resolver:v1:"
FIXTURE_STEWARD_CLAIM = "did:demos:agent:" + "98" * 32
PINNED_STEWARD_KEYS = {
    FIXTURE_STEWARD_CLAIM: "GzHKEuDmLJEe7Wq8-7G2IBYBZPnCipaIm5481wc3n4A",
}
RESOLVER_EVIDENCE_FIELDS = {
    "resolverEvidenceVersion",
    "resolver",
    "jobId",
    "railDefinitionHash",
    "chainId",
    "contractAddress",
    "nativeJobId",
    "eventObservationsHash",
    "transactions",
    "priorTerminals",
    "nativeState",
    "deliveryDigestAnchor",
    "decisionAnchor",
    "statuses",
    "signature",
}
# Optional fixture proof-verifier outputs, authenticated by the pinned resolver.
# These summaries are not CORE AnchorReceipt proof bytes. Each describes one
# qualifying finalized write; repeated summaries describe the same receipt.
QUALIFIED_ARTIFACT_WRITE_FIELDS = {
    "logicalAddress", "nativeAddress", "contentHash", "transactionRef", "writer",
    "nonce", "finalizedBlockTimestampSec",
}
# One lifecycle transaction as the resolver authenticated it (DRF-8): its
# entrypoint selector and calldata decoded under the DRC-17 pins, the native
# caller and outer submitter (DREB-21, DREB-22), and the native status before
# and after it (DRL-10).  `priorNativeStatus` is null only for `createJob`.
TRANSACTION_FIELDS = {
    "txHash", "entrypoint", "calldata", "nativeCaller", "outerSubmitter",
    "nativeCallerAccountType", "priorNativeStatus", "nativeStatusAfter",
}
EVALUATOR_ACCOUNT_TYPES = {"eoa", "eip1271"}
# The block in which the exact delivery digest was anchored, or null when the
# resolver has no such evidence (DRP-9).  A synthetic fixture boundary.
DIGEST_ANCHOR_FIELDS = {"deliverable", "blockNumber", "blockTimestampSec"}
# The finalized SR-2 anchor of the decision, or null when unavailable: the
# consensus timestamp of the Demos block that finalized it (DRC-15, DRC-19).
DECISION_ANCHOR_FIELDS = {"substrate", "finalizedBlockTimestampSec"}
# One terminal transaction the resolver observed before this lifecycle's
# terminal event, for this native job or consuming this decision.
PRIOR_TERMINAL_FIELDS = {
    "chainId", "contractAddress", "nativeJobId", "txHash", "logIndex", "decisionHash",
}
# Resolved native job state and immutable capability facts (DREB-13, DREB-15,
# DREB-16, DREB-20, DRL-7, DRT-7), and the code the resolver found at every
# action block (DRJ-5, DRJ-11).  The verifier reads them only from here.
NATIVE_STATE_FIELDS = {
    "submissionCutoffEnforced",
    "expiryRecoveryAtSec",
    "preterminalProviderPayoutBaseUnits",
    "platformFeeBP",
    "evaluatorFeeBP",
    "evaluatorBindingMode",
    "evaluatorAdapter",
    "escrowRuntimeBytecodeHash",
    "paymentTokenRuntimeBytecodeHash",
    "implementationAddress",
}
# DACS-4 `DeliveryEvidence` for a storage-program delivery (PDE-1, PDE-4).  A
# failure outcome adds `reason` and may omit the deliverable members.  The
# `attestationRef` and `credentialDelivery` members belong to the other
# deliver-* kinds, which this pack does not model.
DELIVERY_EVIDENCE_FIELDS = {
    "deliveryEvidenceVersion", "jobId", "phaseIndex", "phase", "outcome",
    "deliverableContentHash", "deliverableAnchor", "observedAt", "signature",
}
DELIVERABLE_FIELDS = {"deliverableContentHash", "deliverableAnchor"}
# The deliver-* kinds DACS-4 defines, and the one this pack models.
DACS4_DELIVERY_KINDS = {
    "deliver-storage-program", "deliver-entitlement", "deliver-attested-payload",
}
MODELLED_DELIVERY_KINDS = {"deliver-storage-program"}
DELIVERY_OUTCOMES = {"success", "failure"}
EVALUATION_RESULTS = {"accept", "reject", "indeterminate"}
CRITERION_OUTCOMES = {"satisfied", "unsatisfied", "indeterminate"}
DECISION_DISPOSITIONS = {"release-to-provider", "refund-to-client"}
DECISION_STAGES = {"pre-submission", "post-submission"}
TERMINAL_STATES = {"released", "rejected-refund", "expired-refund"}
DISPUTE_ROLES = {"buyer", "seller", "evaluator"}
# The pipeline's candidate phase kinds (DRG-3) and the commit phase's
# `agreementPhase` values (DRP-14).  This pack models the payee-bound arm only:
# the identity-bound arm needs the CORE IBH-1 through IBH-6 gates.
COMMIT_PHASE_KIND = "x-commit-delivery-or-remedy-agreement"
ESCROW_PHASE_KIND = "x-job-escrow"
AGREEMENT_PHASES = {"commit-payee-bound-agreement", "commit-identity-bound-payee-agreement"}
MODELLED_AGREEMENT_PHASE = "commit-payee-bound-agreement"
# DACS-3 §8.5: the five agreement discriminators; exactly one is present.
AGREEMENT_DISCRIMINATORS = (
    "agreementVersion", "payeeBoundAgreementVersion", "identityBoundAgreementVersion",
    "identityBoundPayeeAgreementVersion", "sealedSelectionAgreementVersion",
)
BILATERAL_MEMBERS = {
    "payeeBoundAgreementVersion", "jobId", "listingRef", "parties", "terms",
    "derivedFromPattern", "generatedAt", "signatures",
}
AGREEMENT_PARTY_MEMBERS = {"role", "bundleHash", "primaryClaim", "vetRecordRef"}
AGREEMENT_PARTY_ROLES = {"buyer", "seller", "bidder-non-winning"}
AGREEMENT_TERMS_MEMBERS = {"deliverable", "price", "deadline", "payoutBindings"}
PAYOUT_BINDING_MEMBERS = {"railId", "phaseIndex", "payeeAddress"}

# The §11.3 resolver statuses and the rule an `unavailable` outcome reports,
# in reporting priority.  A new status is added here and nowhere else.
UNAVAILABLE_STATUS_RULES = {
    "fundingFinality": "DRF-6",
    "deliveryFinality": "DRE-5",
    "decisionFinality": "DRD-4",
    "terminalFinality": "DRT-9",
    "transitionResolution": "DRL-12",
    "nativeStateResolution": "DRL-3",
    "codeResolution": "DRJ-7",
    "authorityResolution": "DRJ-7",
    "railResolution": "DRC-11",
    "agreementResolution": "DRV-2",
}
EXTERNAL_EVIDENCE_FIELDS = frozenset(UNAVAILABLE_STATUS_RULES)
EXTERNAL_STATES = {"verified", "not-applicable", "unavailable", "contradictory"}
# Each signed candidate artifact's version discriminator, and DACS-4
# `DeliveryEvidence`'s; every one is "1" (candidate §§5-7, PDE-1).  §9 step 1
# rejects any other value before a type-specific read, and step 2 makes a
# missing one malformed.
ARTIFACT_VERSION_FIELDS = {
    "job": "escrowJobRefVersion",
    "funding": "escrowFundingEvidenceVersion",
    "delivery": "deliveryEvidenceVersion",
    "evaluation": "executionEvaluationVersion",
    "disputeCase": "disputeCaseVersion",
    "dispute": "disputeOutcomeVersion",
    "decision": "escrowDecisionVersion",
    "terminal": "escrowTerminalEvidenceVersion",
}
# The members each type requires (candidate §§5-7, DACS-4 `DeliveryEvidence`),
# other than its version discriminator and signature, which have their own
# checks.
REQUIRED_ARTIFACT_MEMBERS = {
    "job": {
        "jobId", "deliveryOrRemedyAgreementHash", "railDefinitionRef", "chainId",
        "contractAddress", "runtimeBytecodeHash", "nativeJobId", "creationEvent",
    },
    "funding": {
        "jobId", "deliveryOrRemedyAgreementHash", "escrowJobRef", "fundPhaseIndex", "token",
        "amountBaseUnits", "fundingEventRefs", "finality", "observedAt",
    },
    "delivery": {"jobId", "phaseIndex", "phase", "outcome", "observedAt"},
    "evaluation": {
        "jobId", "evaluationSeq", "deliveryOrRemedyAgreementHash", "escrowJobRef",
        "deliveryEvidenceRef", "criterionResults", "result", "finding", "subjectEvidenceRefs",
    },
    "disputeCase": {
        "jobId", "caseId", "deliveryOrRemedyAgreementHash", "openedByRole", "subjectEvidenceRefs",
    },
    "dispute": {
        "jobId", "caseId", "revision", "deliveryOrRemedyAgreementHash", "caseRef",
        "subjectBundleRefs", "subjectEvidenceRefs", "finding",
    },
    "decision": {
        "jobId", "deliveryOrRemedyAgreementHash", "escrowJobRef", "decisionStage", "basisRef",
        "disposition",
    },
    "terminal": {
        "jobId", "deliveryOrRemedyAgreementHash", "escrowJobRef", "fundingEvidenceRef",
        "terminalPhaseIndex", "terminalState", "disposition", "token", "amountBaseUnits",
        "recipient", "terminalEventRefs", "finality", "observedAt",
    },
}
OPTIONAL_ARTIFACTS = ("evaluationRule", "delivery", "evaluation", "disputeCase", "dispute", "decision")

# The rail: a signed `JobEscrowRailDefinition` (candidate §2.2) that extends
# the DACS-4 `RailDefinition` envelope.  `consumerFinalityProfile` is optional
# in DACS-4; a rail without one is not selectable (DRR-4).
RAIL_MEMBERS = {
    "jobEscrowRailVersion", "railVersion", "railId", "railType", "asset", "network",
    "phaseHandler", "parameters", "availability", "governance", "signature",
}
RAIL_ID_RE = re.compile(r"x-evm-erc8183:([1-9][0-9]*):([A-Z0-9]+)")
MAX_RAIL_ID_LENGTH = 64
ASSET_MEMBERS = {"kind", "chainId", "contract", "symbol", "decimals"}
NETWORK_MEMBERS = {"kind", "chainId", "rpcAttestation"}
RPC_ATTESTATIONS = {"consensus-backed-proxy", "evm-rpc"}
RAIL_AVAILABILITIES = {"live", "operator_gated", "closed_data", "bilateral", "mocked", "disabled", "failed"}
GOVERNANCE_REQUIRED = {"proposedBy", "acceptedAt", "anchoring"}
GOVERNANCE_OPTIONAL = {"supersedes", "emergency", "deprecated", "deprecationReason"}
GOVERNANCE_ANCHORINGS = {"in-code", "single-signer", "multisig"}
# DRC-14: every literal-typed `ERC8183ProfileParameters` field and its value.
PROFILE_LITERALS = {
    "canonicalErcRevision": "ethereum/ERCs@a078cab5cc8e9581c15f76c091ed96eed28f02f7",
    "hook": ZERO_ADDRESS,
    "deadlineProfile": "separate-submission-cutoff-v1",
    "decisionOrderingProfile": "anchor-final-before-terminal-v1",
    "platformFeeBP": 0,
    "evaluatorFeeBP": 0,
    "capabilityProfile": "dacs-delivery-gate-v1",
}
PROFILE_FIELDS = set(PROFILE_LITERALS) | {
    "implementationRevision", "entrypoints", "events", "configurationEvidence",
    "nativeStatusMap", "chainId", "contractAddress", "runtimeBytecodeHash", "paymentToken",
    "paymentTokenRuntimeBytecodeHash", "tokenDecimals", "finalityBlocks",
    "minimumEvaluationWindowSec", "maxCrossSubstrateSkewMs",
}
OPTIONAL_PROFILE_FIELDS = {"implementationAddress", "implementationRuntimeBytecodeHash"}
IMPLEMENTATION_REVISION_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}")
CAPABILITY_PROFILE = PROFILE_LITERALS["capabilityProfile"]
NATIVE_STATUSES = ("Open", "Funded", "Submitted", "Completed", "Rejected", "Expired")
# The fixture implementation's ABI, which the rail pins through DRC-17 and
# this verifier decodes (DRC-18): each entrypoint's ordered (name, type)
# inputs and each event's ordered (name, type, indexed) inputs.  The events
# have the canonical ERC-8183 parameter names and `indexed` layout, with the
# reference contract's `hook` on `JobCreated`.  What the canonical surface
# lacks, a DREB-13-capable implementation adds: a separate submission cutoff
# in `createJob` and a configuration event that carries it with the
# pre-submission policy word (DRC-21), and the expected prior status in
# `reject` (DRD-13).
FIXTURE_ENTRYPOINTS = {
    "createJob": (
        ("provider", "address"), ("evaluator", "address"), ("expiredAt", "uint256"),
        ("submissionCutoff", "uint256"), ("description", "string"), ("hook", "address"),
    ),
    "fund": (("jobId", "uint256"), ("expectedBudget", "uint256")),
    "submit": (("jobId", "uint256"), ("deliverable", "bytes32")),
    "complete": (("jobId", "uint256"), ("reason", "bytes32")),
    "reject": (("jobId", "uint256"), ("reason", "bytes32"), ("expectedStatus", "uint8")),
    "claimRefund": (("jobId", "uint256"),),
}
FIXTURE_EVENTS = {
    "JobCreated": (
        ("jobId", "uint256", True), ("client", "address", True), ("provider", "address", True),
        ("evaluator", "address", False), ("expiredAt", "uint256", False), ("hook", "address", False),
    ),
    "JobConfigured": (
        ("jobId", "uint256", True), ("submissionCutoff", "uint256", False),
        ("preSubmissionRefundPolicy", "bytes32", False),
    ),
    "JobFunded": (("jobId", "uint256", True), ("client", "address", True), ("amount", "uint256", False)),
    "JobSubmitted": (("jobId", "uint256", True), ("provider", "address", True), ("deliverable", "bytes32", False)),
    "JobCompleted": (("jobId", "uint256", True), ("evaluator", "address", True), ("reason", "bytes32", False)),
    "PaymentReleased": (("jobId", "uint256", True), ("provider", "address", True), ("amount", "uint256", False)),
    "JobRejected": (("jobId", "uint256", True), ("rejector", "address", True), ("reason", "bytes32", False)),
    "Refunded": (("jobId", "uint256", True), ("client", "address", True), ("amount", "uint256", False)),
    "JobExpired": (("jobId", "uint256", True),),
}
CONFIGURATION_EVENT = "JobConfigured"
# DRC-21: the 32-byte word the fixture's policy input carries for
# `evaluator-rejection`, the ASCII text right-padded as a Solidity bytes32
# literal.
PRE_SUBMISSION_POLICY_WORD = "0x" + b"evaluator-rejection".ljust(32, b"\0").hex()


def abi_signature(name: str, inputs: tuple[tuple[Any, ...], ...]) -> str:
    """DRC-17: the entry's name followed by its input types, in order."""
    return f"{name}({','.join(item[1] for item in inputs)})"


# DRC-20: each field this profile reads from a pinned entry and that canonical
# ERC-8183 names.  Each is read from the one input of that name.
CANONICAL_FIELDS = {
    "createJob": ("provider", "evaluator", "expiredAt", "description", "hook"),
    "submit": ("jobId", "deliverable"),
    "complete": ("jobId", "reason"),
    "reject": ("jobId", "reason"),
    "JobCreated": ("jobId", "client", "provider", "evaluator", "expiredAt", "hook"),
    "JobFunded": ("jobId", "client", "amount"),
    "JobSubmitted": ("jobId", "deliverable"),
    "JobCompleted": ("jobId", "reason"),
    "PaymentReleased": ("jobId", "provider", "amount"),
    "JobRejected": ("jobId", "reason"),
    "Refunded": ("jobId", "client", "amount"),
    "JobExpired": ("jobId",),
}
# The canonical Solidity ABI types this verifier admits in a DRC-17 pin: an
# elementary type, optionally as a dynamic or fixed-size array.  `uint` and
# `int` are aliases, not canonical.  Tuple, `fixed`/`ufixed` and `function`
# types are canonical but not admitted, so a pin using one is error/DRC-17.
_ABI_SIZE = "|".join(str(bits) for bits in range(8, 257, 8))
_ABI_BYTES = "|".join(str(size) for size in range(1, 33))
ABI_ELEMENTARY_RE = re.compile(rf"u?int(?:{_ABI_SIZE})|address|bool|bytes(?:{_ABI_BYTES})?|string")
ABI_TYPE_RE = re.compile(rf"(?:{ABI_ELEMENTARY_RE.pattern})(?:\[(?:[1-9][0-9]*)?\])*")
# DRC-21: a type that fills exactly one ABI word.
ABI_WORD_TYPE_RE = re.compile(rf"u?int(?:{_ABI_SIZE})|address|bool|bytes(?:{_ABI_BYTES})")
# Candidate §4.1: the ERC-8183 state crosswalk, keyed on the prior native
# status, the entrypoint, and the caller's role (`any` for `claimRefund`).
# Each row gives the events it requires, the native status after it, and the
# portable and terminal states (DRL-10).  `JobConfigured` is the fixture
# implementation's DRC-17 configuration event, emitted by `createJob`.
CROSSWALK = {
    (None, "createJob", "client"): (("JobCreated", "JobConfigured"), "Open", "created", None),
    ("Open", "reject", "client"): (("JobRejected",), "Rejected", "cancelled", None),
    ("Open", "fund", "client"): (("JobFunded",), "Funded", "funded", None),
    ("Funded", "submit", "provider"): (("JobSubmitted",), "Submitted", "submitted", None),
    ("Submitted", "complete", "evaluator"): (
        ("JobCompleted", "PaymentReleased"), "Completed", "released", "released",
    ),
    ("Funded", "reject", "evaluator"): (
        ("JobRejected", "Refunded"), "Rejected", "refunded", "rejected-refund",
    ),
    ("Submitted", "reject", "evaluator"): (
        ("JobRejected", "Refunded"), "Rejected", "refunded", "rejected-refund",
    ),
    ("Funded", "claimRefund", "any"): (("JobExpired", "Refunded"), "Expired", "refunded", "expired-refund"),
    ("Submitted", "claimRefund", "any"): (
        ("JobExpired", "Refunded"), "Expired", "refunded", "expired-refund",
    ),
}
CROSSWALK_EVENTS = sorted({name for row in CROSSWALK.values() for name in row[0]} - {CONFIGURATION_EVENT})
TERMINAL_ENTRYPOINTS = {
    "released": "complete", "rejected-refund": "reject", "expired-refund": "claimRefund",
}
TERMINAL_EVENTS = {
    "released": ("JobCompleted", "PaymentReleased"),
    "rejected-refund": ("JobRejected", "Refunded"),
    "expired-refund": ("JobExpired", "Refunded"),
}
PORTABLE_STATES = {"created", "funded", "submitted", "released", "refunded", "cancelled"}
PORTABLE_TRANSITIONS = {
    ("created", "funded"),
    ("created", "cancelled"),
    ("funded", "submitted"),
    ("funded", "refunded"),
    ("submitted", "released"),
    ("submitted", "refunded"),
}
DRC_RULES = {f"DRC-{number}" for number in range(1, 14)}
# DACS-2 `AttestationRef` members and anchor kinds.
ATTESTATION_REF_FIELDS = {"anchor", "contentHash", "signer"}
ATTESTATION_ANCHOR_KINDS = {"storage-program", "ipfs", "https"}
EVENT_REF_FIELDS = {"kind", "chainId", "txHash", "logIndex"}
# One resolver-authenticated EVM log (DRF-8): its block, the block at the
# rail's confirmation depth (null until it exists), its `topic0`, and the
# decoded values of the topics after it and of the log data, each in order
# (DRC-18).  Block identities are fixture-chain preimages.
EVENT_INPUT_FIELDS = {
    "eventRef",
    "txHashPreimageUtf8",
    "blockNumber",
    "blockHash",
    "blockHashPreimageUtf8",
    "blockTimestampSec",
    "contractAddress",
    "eventName",
    "topic0",
    "indexedArguments",
    "dataArguments",
    "finalityBlock",
}
BLOCK_FIELDS = {"blockNumber", "blockHash", "blockHashPreimageUtf8", "blockTimestampSec"}
# DACS-1 §6.3.1 ClaimReference grammar: a lower-case scheme (CF-2(a) for any
# hashed or signed reference), and one CORE CF-2(c) canonical parameter: the
# reserved `:`, `?`, `&`, `=` and `%` appear only percent-encoded with
# upper-case hex.
CLAIM_SCHEME_RE = re.compile(r"[a-z][a-z0-9-]*")
CLAIM_PARAMETER_RE = re.compile(r"(?:[^:?&=%]|%[0-9A-F]{2})+=(?:[^:?&=%]|%[0-9A-F]{2})*")
# DACS-1 §6.3.1: the Demos agent DID key is 64 lower-case hex digits, and an
# EVM `cci-xm` identifier is `evm:<chainId>:<address>`.
DEMOS_AGENT_PREFIX = "demos:agent:"
DEMOS_AGENT_KEY_RE = re.compile(r"[0-9a-f]{64}")
EVM_IDENTIFIER_RE = re.compile(r"evm:([1-9][0-9]*):(.*)", re.DOTALL)
# Any spelling of the `evm` family with a numeric chain ID: decimal, signed
# or `0x` hexadecimal.  One that is not EVM_IDENTIFIER_RE is outside the PB-2
# profile.
EVM_SPELLING_RE = re.compile(r"[eE][vV][mM]:[+-]?(?:[0-9]+|0[xX][0-9a-fA-F]+):.*", re.DOTALL)
EVM_ACCOUNT_CLAIM_RE = re.compile(r"cci-xm:evm:([1-9][0-9]*):([^?]*)(?:\?.*)?", re.DOTALL)
# AccountabilityFinding members and its closed classification set (candidate §6.4).
FINDING_FIELDS = {"classification", "faultedParty", "rationaleCode"}
FINDING_CLASSIFICATIONS = {
    "seller-fulfilled", "seller-fault", "buyer-fault", "evaluator-unavailable",
    "substrate-failure", "no-fault", "indeterminate",
}
# Candidate §6.2: the `evaluator-judgement-v1` matrix, from the derived result
# to the findings and the disposition it permits (none for indeterminate).
RULE_KIND = "evaluator-judgement-v1"
EVALUATION_RULE_FIELDS = {"evaluationRuleVersion", "ruleKind", "jobId", "criteria"}
RESULT_FINDINGS = {
    "accept": {"seller-fulfilled"},
    "reject": {"seller-fault", "buyer-fault", "no-fault", "substrate-failure"},
    "indeterminate": {"indeterminate", "evaluator-unavailable"},
}
SETTLEMENT_AUTHORIZATIONS = {
    "accept": "release-to-provider",
    "reject": "refund-to-client",
}
# Candidate §6.4: the dispute-outcome authorization table, from the finding to
# the disposition it permits; a release only at the post-submission stage.
DISPUTE_DISPOSITIONS = {
    "seller-fulfilled": "release-to-provider",
    "seller-fault": "refund-to-client",
    "buyer-fault": "refund-to-client",
    "no-fault": "refund-to-client",
    "substrate-failure": "refund-to-client",
}
# DRT-14: the candidate §7 projection table, (terminal state, finding) to the
# buyer-anchored and seller-anchored DACS-5 outcomes and the faulted party,
# with "any refund" expanded.  A null outcome is "no (fault) projection".  An
# expired-refund seller fault holds only when the seller failed to submit, and
# `indeterminate` projects nothing for any terminal state.  Every other pair
# projects no buyer or seller fault and remains an annotation.
NO_PROJECTION = (None, None, "none")
PROJECTION_TABLE = {
    ("released", "seller-fulfilled"): ("completed", "completed", "none"),
    ("rejected-refund", "seller-fault"): ("failed-counterparty", "failed-perm", "seller"),
    ("rejected-refund", "buyer-fault"): ("failed-perm", "failed-counterparty", "buyer"),
    ("expired-refund", "seller-fault"): ("failed-counterparty", "failed-perm", "seller"),
    ("expired-refund", "evaluator-unavailable"): NO_PROJECTION,
    ("rejected-refund", "substrate-failure"): ("failed-substrate", "failed-substrate", "none"),
    ("expired-refund", "substrate-failure"): ("failed-substrate", "failed-substrate", "none"),
    ("rejected-refund", "no-fault"): NO_PROJECTION,
    ("expired-refund", "no-fault"): NO_PROJECTION,
}
PROJECTION_FIELDS = {
    "buyerAnchoredOutcome", "sellerAnchoredOutcome", "faultedParty",
    "releaseAloneEstablishesNonFinancialCompletion",
}
PROJECTED_OUTCOMES = {None, "completed", "failed-counterparty", "failed-perm", "failed-substrate"}
PROJECTED_FAULTS = {"none", "buyer", "seller"}


def nesting_within(value: Any, limit: int) -> bool:
    """Whether ``value`` nests arrays and objects at most ``limit`` deep, checked iteratively."""
    pending = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        if isinstance(current, (dict, list)):
            if depth > limit:
                return False
            children = current.values() if isinstance(current, dict) else current
            pending.extend((child, depth + 1) for child in children)
    return True


def number_profile_valid(value: Any) -> bool:
    """Whether every number in ``value`` is in the CORE §B.2 JSON number profile."""
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, float) and not (
            math.isfinite(current) and abs(current) <= SAFE_INTEGER_MAX
        ):
            return False
        elif isinstance(current, int) and not isinstance(current, bool) and abs(current) > SAFE_INTEGER_MAX:
            return False
    return True


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def content_hash(value: Any) -> str:
    return hashlib.sha256(jcs_canonicalize(value).encode("utf-8")).hexdigest()


def unsigned_artifact(value: dict[str, Any]) -> dict[str, Any]:
    omitted = "signatures" if "signatures" in value else "signature"
    return {key: item for key, item in value.items() if key != omitted}


def artifact_hash(value: dict[str, Any]) -> str:
    return content_hash(unsigned_artifact(value))


def _blob_at(root: Path, commit: str, path: str) -> bytes | None:
    """The bytes of ``path`` at ``commit`` in the repository at ``root``, or None."""
    try:
        shown = subprocess.run(
            ["git", "-C", str(root), "show", f"{commit}:{path}"], capture_output=True, check=False,
        )
    except OSError:
        return None
    return shown.stdout if shown.returncode == 0 else None


def document_pins(root: Path = ROOT) -> dict[str, str] | None:
    """The SHA-256 of each pinned document, or None when one cannot be read.

    The candidate is read from the checkout at ``root``, so the pack is stale
    once the candidate changes.  The `spec/` documents are read at the
    **Checked against** commit, whose text the candidate cites (DRG-2), so
    a later `spec/` edit that does not re-pin the candidate leaves the pack
    valid.  That read needs the commit in the clone's history.
    """
    pins = {PINNED_DOCUMENTS[0]: hashlib.sha256((root / PINNED_DOCUMENTS[0]).read_bytes()).hexdigest()}
    for path in PINNED_DOCUMENTS[1:]:
        blob = _blob_at(root, DACS_CHECKED_AGAINST, path)
        if blob is None:
            return None
        pins[path] = hashlib.sha256(blob).hexdigest()
    return pins


# Keccak-256 (the pre-SHA-3 padding Ethereum uses), for EIP-55 checksums and
# for the DRC-17 selectors and topics.  `hashlib.sha3_256` pads differently.
_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
# The rotation offset of lane (x, y), indexed [x][y].
_KECCAK_ROTATIONS = (
    (0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56), (27, 20, 39, 8, 14),
)
_LANE_MASK = (1 << 64) - 1


def _keccak_f1600(lanes: list[int]) -> list[int]:
    for constant in _KECCAK_ROUND_CONSTANTS:
        parity = [lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20] for x in range(5)]
        lanes = [
            lanes[i] ^ parity[(i - 1) % 5]
            ^ (((parity[(i + 1) % 5] << 1) | (parity[(i + 1) % 5] >> 63)) & _LANE_MASK)
            for i in range(25)
        ]
        rotated = [0] * 25
        for x in range(5):
            for y in range(5):
                lane, offset = lanes[x + 5 * y], _KECCAK_ROTATIONS[x][y]
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = (
                    (lane << offset) | (lane >> (64 - offset))
                ) & _LANE_MASK
        lanes = [
            rotated[i] ^ (~rotated[(i + 1) % 5 + 5 * (i // 5)] & rotated[(i + 2) % 5 + 5 * (i // 5)])
            for i in range(25)
        ]
        lanes[0] ^= constant
    return lanes


def keccak256(data: bytes) -> bytes:
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(bytes(-len(padded) % rate))
    padded[-1] |= 0x80
    lanes = [0] * 25
    for start in range(0, len(padded), rate):
        for index in range(rate // 8):
            offset = start + 8 * index
            lanes[index] ^= int.from_bytes(padded[offset:offset + 8], "little")
        lanes = _keccak_f1600(lanes)
    return b"".join(lane.to_bytes(8, "little") for lane in lanes[:4])


def selector_of(signature: str) -> str:
    """The 4-byte selector of a Solidity function signature (DRC-17)."""
    return "0x" + keccak256(signature.encode("ascii"))[:4].hex()


def topic_of(signature: str) -> str:
    """The 32-byte `topic0` of a Solidity event signature (DRC-17)."""
    return "0x" + keccak256(signature.encode("ascii")).hex()


# DRC-21: the fixture's configuration event, its cutoff and policy inputs by
# zero-based index, and the policy word for `evaluator-rejection`.
CONFIGURATION_EVIDENCE = {
    "eventTopic0": topic_of(abi_signature(CONFIGURATION_EVENT, FIXTURE_EVENTS[CONFIGURATION_EVENT])),
    "submissionCutoffInput": 1,
    "preSubmissionPolicyInput": 2,
    "preSubmissionPolicyValue": PRE_SUBMISSION_POLICY_WORD,
}


def entrypoint_pins() -> list[dict[str, Any]]:
    """The fixture ABI's DRC-17 `AbiFunctionPin` entries."""
    return [
        {
            "name": name,
            "signature": abi_signature(name, inputs),
            "selector": selector_of(abi_signature(name, inputs)),
            "inputs": [{"name": item[0], "type": item[1]} for item in inputs],
        }
        for name, inputs in FIXTURE_ENTRYPOINTS.items()
    ]


def event_pins() -> list[dict[str, Any]]:
    """The fixture ABI's DRC-17 `AbiEventPin` entries."""
    return [
        {
            "name": name,
            "signature": abi_signature(name, inputs),
            "topic0": topic_of(abi_signature(name, inputs)),
            "inputs": [{"name": item[0], "type": item[1], "indexed": item[2]} for item in inputs],
        }
        for name, inputs in FIXTURE_EVENTS.items()
    ]


def abi_value_valid(abi_type: str, item: Any) -> bool:
    """Whether a resolver-decoded ABI value has its pinned type's spelling.

    Integers are minimal decimal text in range, so a uint256 stays exact;
    addresses and fixed bytes are lower-case hexadecimal.  A type this does
    not decode (an array, a signed integer, dynamic `bytes`) is never valid.
    """
    if not isinstance(abi_type, str) or ABI_ELEMENTARY_RE.fullmatch(abi_type) is None:
        return False
    if abi_type == "address":
        return isinstance(item, str) and EVM_ADDRESS_RE.fullmatch(item) is not None
    if abi_type == "bool":
        return type(item) is bool
    if abi_type == "string":
        return isinstance(item, str)
    if abi_type.startswith("uint"):
        return (
            isinstance(item, str) and UNSIGNED_DECIMAL_RE.fullmatch(item) is not None
            and int(item) < 2 ** int(abi_type[4:])
        )
    if abi_type.startswith("bytes") and abi_type != "bytes":
        return isinstance(item, str) and re.fullmatch(f"0x[0-9a-f]{{{2 * int(abi_type[5:])}}}", item) is not None
    return False


def evm_claim_address_valid(address: Any) -> bool:
    """DRW-1: `0x` and 40 hex digits, all lower-case, all upper-case, or valid EIP-55."""
    if not isinstance(address, str) or CLAIM_ADDRESS_RE.fullmatch(address) is None:
        return False
    digits = address[2:]
    if digits in (digits.lower(), digits.upper()):
        return True
    digest = keccak256(digits.lower().encode("ascii")).hex()
    return all(
        char == (char.upper() if int(digest[index], 16) >= 8 else char.lower())
        for index, char in enumerate(digits)
    )


def base64url_decode(value: Any) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("signature is not unpadded Base64URL")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise ValueError("signature is not canonical Base64URL")
    return raw


def signature_valid(
    artifact: dict[str, Any],
    signature: Any,
    expected_signer: str,
    public_keys: dict[str, Any],
    domain: str,
    signer_field: str = "signer",
) -> bool:
    if not isinstance(signature, dict):
        return False
    if signature.get("algorithm") != "ed25519":
        return False
    if signature.get(signer_field) != expected_signer:
        return False
    public_key = public_keys.get(expected_signer)
    try:
        Ed25519PublicKey.from_public_bytes(base64url_decode(public_key)).verify(
            base64url_decode(signature.get("value")),
            (domain + artifact_hash(artifact)).encode("ascii"),
        )
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _claim_component(text: str) -> str | None:
    """A CF-2(c) parameter component decoded, or None unless only reserved characters are escaped."""
    try:
        decoded = urllib.parse.unquote(text, errors="strict")
    except UnicodeDecodeError:
        return None
    reencoded = "".join(f"%{ord(char):02X}" if char in ":?&=%" else char for char in decoded)
    return decoded if reencoded == text else None


def claim_parameters_canonical(text: str) -> bool:
    """Whether a ClaimReference parameter string is in CORE CF-2(c) form.

    Keys are sorted by their decoded code points, before the reserved
    characters are percent-encoded, and only those characters are escaped.
    """
    pairs = text.split("&")
    if not all(CLAIM_PARAMETER_RE.fullmatch(pair) for pair in pairs):
        return False
    components = [_claim_component(part) for pair in pairs for part in pair.split("=", 1)]
    if None in components:
        return False
    keys = components[::2]
    return keys == sorted(keys)


class Claim(NamedTuple):
    """A canonical ClaimReference and its CORE CF-3 identity.

    ``evm`` is the chain ID and 20-byte address of a `cci-xm:evm` claim in
    the PB-2 profile; two such claims compare by those values (DRW-5).
    """

    scheme: str
    identifier: str
    identity: tuple[Any, ...]
    evm: tuple[int, bytes] | None


def parse_claim(value: Any) -> Claim | None:
    """A ClaimReference in CORE CF-2 canonical byte form, or None.

    DACS-1 §6.3.1 grammar.  A signed artifact embeds the CF-2 form: a
    lower-case scheme, an NFC identifier, and sorted, percent-encoded
    parameters.  Any other spelling is malformed rather than repaired (DRV-3).
    A `did:demos:agent:` key is 64 lower-case hex digits; DACS-1 makes a reader
    reject an upper-case key rather than lowercase it.  A `cci-xm:evm` claim
    with a canonical, safe chain ID has a DRW-1 address component.  Parameters
    never contribute to identity (CF-3).
    """
    if not isinstance(value, str):
        return None
    scheme, separator, rest = value.partition(":")
    identifier, question, parameters = rest.partition("?")
    if not separator or CLAIM_SCHEME_RE.fullmatch(scheme) is None or not identifier:
        return None
    if unicodedata.normalize("NFC", identifier) != identifier:
        return None
    if question and not claim_parameters_canonical(parameters):
        return None
    if scheme == "did" and identifier.startswith(DEMOS_AGENT_PREFIX) and (
        DEMOS_AGENT_KEY_RE.fullmatch(identifier[len(DEMOS_AGENT_PREFIX):]) is None
    ):
        return None
    evm = None
    match = EVM_IDENTIFIER_RE.fullmatch(identifier) if scheme == "cci-xm" else None
    # DACS-1 PB-2: an `evm` family spelt in another case, or a chain ID with
    # a leading zero, a sign or a `0x` prefix (not a bare positive decimal
    # integer), does not conform to the profile, and comparing it as text
    # would let one EVM account pose as two parties (DRW-5).  This profile
    # refuses it.  A non-numeric chain stays a generic claim.
    if scheme == "cci-xm" and match is None and EVM_SPELLING_RE.fullmatch(identifier) is not None:
        return None
    if match is not None and int(match.group(1)) <= SAFE_INTEGER_MAX:
        if not evm_claim_address_valid(match.group(2)):
            return None
        evm = (int(match.group(1)), bytes.fromhex(match.group(2)[2:]))
    identity = (scheme, "evm", *evm) if evm is not None else (scheme, identifier)
    return Claim(scheme, identifier, identity, evm)


def claim_identity(value: Any) -> tuple[Any, ...] | None:
    """A canonical ClaimReference's CORE CF-3 identity (with DRW-5), or None."""
    claim = parse_claim(value)
    return None if claim is None else claim.identity


def attestation_ref_shape_valid(ref: Any) -> bool:
    """Whether ``ref`` is a DACS-2 `AttestationRef` (DACS-2 §8.4).

    `{anchor: {kind, locator}, contentHash, signer?}`: the anchor kind is one
    of the three DACS-2 kinds and the optional signer is a canonical
    ClaimReference.
    """
    if not isinstance(ref, dict) or not {"anchor", "contentHash"} <= set(ref) <= ATTESTATION_REF_FIELDS:
        return False
    anchor = ref["anchor"]
    return (
        isinstance(anchor, dict)
        and set(anchor) == {"kind", "locator"}
        and isinstance(anchor["kind"], str)
        and anchor["kind"] in ATTESTATION_ANCHOR_KINDS
        and isinstance(anchor["locator"], str)
        and bool(anchor["locator"])
        and isinstance(ref["contentHash"], str)
        and HASH_RE.fullmatch(ref["contentHash"]) is not None
        and ("signer" not in ref or parse_claim(ref["signer"]) is not None)
    )


def attestation_ref_valid(ref: Any, artifact: Any) -> bool:
    return (
        attestation_ref_shape_valid(ref)
        and isinstance(artifact, dict)
        and ref["contentHash"] == artifact_hash(artifact)
    )


def logical_address(job_id: str, suffix: str) -> str:
    """A candidate §6.5 logical address in the `dacs4:x-job-escrow:` family."""
    return f"dacs4:x-job-escrow:{job_id}:{suffix}"


def _numeric_segment_noncanonical(locator: str, expected: str) -> bool:
    """Whether ``locator`` differs from ``expected`` only in a numeric segment's spelling (DRAA-2)."""
    given, wanted = locator.split(":"), expected.split(":")
    return locator != expected and len(given) == len(wanted) and all(
        left == right or (
            re.fullmatch(r"[+-]?[0-9]+", left) is not None
            and UNSIGNED_DECIMAL_RE.fullmatch(right) is not None
            and int(left) == int(right)
        )
        for left, right in zip(given, wanted)
    )


def _ref_check(
    ref: Any,
    artifact: Any,
    locator: str | None,
    rule: str,
    label: str,
    signers: tuple[str, ...],
) -> dict[str, str] | None:
    """Resolve one `AttestationRef` to the exact artifact at its logical address.

    A malformed reference is `error` (§9 step 2).  A numeric address segment
    spelled other than as minimal unsigned decimal is `error` too (DRAA-2).
    A reference that names another address or content hash is `fail` under
    ``rule``, and an optional `signer` that is none of the artifact's
    authenticated ``signers`` contradicts it (DRV-6).
    """
    if not attestation_ref_shape_valid(ref):
        return result("error", "DRV-3", f"{label} reference is not a DACS-2 AttestationRef")
    if locator is not None and ref["anchor"]["locator"] != locator:
        if _numeric_segment_noncanonical(ref["anchor"]["locator"], locator):
            return result("error", "DRAA-2", f"{label} reference spells a numeric address segment non-minimally")
        return result("fail", rule, f"{label} reference does not name its logical address")
    if locator is not None and ref["anchor"]["kind"] != "storage-program":
        return result("fail", rule, f"{label} reference is not an SR-2 storage-program anchor")
    if not isinstance(artifact, dict) or ref["contentHash"] != artifact_hash(artifact):
        return result("fail", rule, f"{label} reference does not resolve to the exact artifact")
    if "signer" in ref and claim_identity(ref["signer"]) not in {claim_identity(signer) for signer in signers}:
        return result("fail", "DRV-6", f"{label} reference names a signer other than the artifact's")
    return None


def within_uint256(digits: str) -> bool:
    """Whether minimal unsigned decimal text is at most 2^256 - 1, compared as text."""
    return len(digits) < len(UINT256_MAX_TEXT) or (
        len(digits) == len(UINT256_MAX_TEXT) and digits <= UINT256_MAX_TEXT
    )


def price_base_units(amount: str, decimals: int) -> str | None:
    """Convert a CD-1 amount to token base units (DACS-4 §9.5.2 step 3).

    `amount × 10^decimals` as string-decimal arithmetic, as minimal unsigned
    decimal text: the fraction is padded to `decimals` digits and the leading
    zeros are stripped.  No `int` or float is involved, so an amount of any
    length converts exactly.  None when the amount has more fractional digits
    than the token carries: no whole number of base units equals it (DRA-10).
    """
    whole, _, fraction = amount.partition(".")
    if len(fraction) > decimals:
        return None
    return (whole + fraction.ljust(decimals, "0")).lstrip("0") or "0"


def _is_unix_ms(value: Any) -> bool:
    """DRW-4: a unix-millisecond timestamp is a non-negative JSON safe integer."""
    return type(value) is int and 0 <= value <= SAFE_INTEGER_MAX


def _is_unix_sec(value: Any) -> bool:
    """DRW-4: a unix-second timestamp is a non-negative integer of at most 9007199254740."""
    return type(value) is int and 0 <= value <= MAX_SECONDS


def _amount_valid(value: Any) -> bool:
    return isinstance(value, str) and UNSIGNED_DECIMAL_RE.fullmatch(value) is not None and within_uint256(value)


# Rule labels for `error`.  Candidate §9 step 2 makes a malformed input
# `error`; DRV-3, the malformed-encoding rule, forbids repairing it, so those
# results cite DRV-3, or the §3.1 wire rule (DRW-1 to DRW-4) the encoding
# breaks.  §9 step 1 makes an unsupported discriminator `error`; where the
# candidate names the rule (DRR-6 for the rail, DRE-9 for the evaluation rule,
# DRP-14 for the commit phase, DRC-14 for a profile literal) the result cites
# it, and the other discriminators (phase kind, artifact, overlay,
# resolver-evidence or manifest version, implementation ABI) keep the fixture
# label DRV-2, pending a named §9 step-1 rule in #371.  Otherwise DRV-2 is
# unavailable RPC data, which stays `indeterminate`.
def result(verdict: str, rule: str, detail: str) -> dict[str, str]:
    return {"result": verdict, "rule": rule, "detail": detail}


class TerminalRecord(NamedTuple):
    """One terminal transaction: its native job, its event, and its decision.

    ``position`` is the terminal event's authenticated canonical position on
    its chain: (block number, block-scoped log index).  An EVM log index
    counts logs across the whole block, so it already orders transactions
    within a block.  A resolver-attested earlier terminal has no position:
    the resolver attests that it precedes this lifecycle's terminal.
    ``attested`` holds the identities (native job, event, decision) of the
    earlier terminals in this terminal's resolver-attested history.
    ``evidence`` is the content hash of the `EscrowTerminalEvidence`; a
    resolver-attested earlier terminal has none.
    """

    job: tuple[Any, Any, Any]
    event: tuple[Any, Any, Any]
    decision: str | None
    position: tuple[int, int] | None = None
    attested: tuple[tuple[Any, Any, Any], ...] = ()
    evidence: str | None = None


def terminal_conflict(prior: TerminalRecord, current: TerminalRecord) -> tuple[str, str] | None:
    """Return the rule and detail when two terminal records cannot both hold.

    The same terminal presented again is not a conflict, but every
    observation of it reproduces one evidence hash (DRT-16).  A decision
    authorizes one terminal transaction (DRD-8); a native job reaches one
    terminal state (DRL-4); one terminal event settles one native job (DRT-4).
    """
    if prior[:3] == current[:3]:
        if None not in (prior.evidence, current.evidence) and prior.evidence != current.evidence:
            return "DRT-16", "a second, distinct terminal evidence record exists for the same terminal"
        return None
    if current.decision is not None and prior.decision == current.decision:
        return "DRD-8", "the decision already authorized another terminal transaction"
    if prior.job == current.job:
        return "DRL-4", "the native job already reached a terminal state through another transaction"
    if prior.event == current.event:
        return "DRT-4", "the terminal event already settled another native job"
    return None


def terminal_precedes(prior: TerminalRecord, current: TerminalRecord) -> bool | None:
    """Whether ``prior`` is the earlier terminal by authenticated event position.

    Returns None when the authenticated positions cannot order the two: the
    same position, or events on different chains.  The order in which the
    verifier received the evidence is never consulted.
    """
    if prior.position is None:
        return True
    if prior.event[0] != current.event[0] or prior.position == current.position:
        return None
    return prior.position < current.position


class HeldFinding(NamedTuple):
    """A revisable finding the ledger holds for one lifecycle (see `LifecycleCheck`).

    Two qualifying writes known at one of ``addresses`` replace ``finding``
    with DRAA-4.  ``terminal`` is the lifecycle's recorded terminal, or None.
    ``pending`` is the terminal to record, with ``written`` as the addresses
    its evidence references, once the verdict is DRAA-4 and two writes are
    known at each address in ``blocker``.
    """

    addresses: frozenset[str]
    terminal: TerminalRecord | None
    finding: dict[str, str]
    verdict: dict[str, str]
    pending: TerminalRecord | None = None
    written: frozenset[str] = frozenset()
    blocker: frozenset[str] = frozenset()


class DecisionLedger:
    """Verifier-owned, in-memory set of authenticated terminals this verifier evaluated.

    The ledger belongs to the verifier, not to the evidence producer: a vector
    cannot seed or clear it.  It records every terminal whose lifecycle passed
    every check before the replay comparison that does not select a
    qualifying write copy, and whose finding, if any, rests on no copy that
    can still be selected, whatever the replay comparison decides; a
    lifecycle whose finding rests on such a copy has its terminal recorded
    once a second write makes the copy unselectable.  It
    lists them in canonical position order, so a verdict depends on the
    evidence seen and not on its arrival order.  It also keeps the verdict it
    last issued for each recorded terminal, so that a later evaluation can
    revise it.  It retains each qualifying write summary in a pinned-resolver
    record that is bound to the logical address its lifecycle's terminal
    references (DRAA-4), whatever the verdict of the lifecycle that carried
    it, and the logical addresses each recorded terminal's evidence
    references.  It holds each revisable verdict decided before the replay
    comparison (one that rests on a write copy, or uncertainty at or after
    the write-selection point), by the lifecycle's content hash, so a second
    write at its addresses, or a replay `fail` of its recorded terminal, can
    replace it.  It is not durable and
    does not enforce one use across processes.
    """

    def __init__(self) -> None:
        self._terminals: list[TerminalRecord] = []
        self._issued: dict[TerminalRecord, dict[str, str]] = {}
        self._writes: dict[str, set[bytes]] = {}
        self._addresses: dict[TerminalRecord, frozenset[str]] = {}
        self._held: dict[str, HeldFinding] = {}

    def terminals(self) -> tuple[TerminalRecord, ...]:
        return tuple(sorted(self._terminals, key=lambda item: (
            item.position is None, item.position or (), repr(item[:3]), repr(item.attested),
            item.evidence or "",
        )))

    def record(self, terminal: TerminalRecord, addresses: frozenset[str] = frozenset()) -> None:
        if terminal not in self._terminals:
            self._terminals.append(terminal)
        self._addresses[terminal] = self._addresses.get(terminal, frozenset()) | addresses

    def retain_writes(self, address: str, receipts: list[dict[str, Any]]) -> None:
        """Keep each distinct qualifying write at ``address``; an exact repeat is one write."""
        self._writes.setdefault(address, set()).update(canonical_bytes(receipt) for receipt in receipts)

    def writes_at(self, address: str) -> frozenset[bytes]:
        """The distinct qualifying writes known at ``address``."""
        return frozenset(self._writes.get(address, ()))

    def equivocated_at(self, addresses: frozenset[str]) -> bool:
        """Whether two distinct qualifying writes are known at one of ``addresses``."""
        return any(len(self._writes.get(address, ())) > 1 for address in addresses)

    def equivocated(self, terminal: TerminalRecord) -> bool:
        """Whether two distinct qualifying writes are known at an address ``terminal`` references."""
        return self.equivocated_at(self._addresses.get(terminal, frozenset()))

    def hold(self, lifecycle: str, entry: HeldFinding) -> None:
        """Keep a revisable finding (see `LifecycleCheck`) and the verdict last issued for lifecycle hash ``lifecycle``."""
        self._held[lifecycle] = entry._replace(finding=dict(entry.finding), verdict=dict(entry.verdict))

    def held(self) -> tuple[tuple[str, HeldFinding], ...]:
        return tuple((lifecycle, self._held[lifecycle]) for lifecycle in sorted(self._held))

    def issued(self, terminal: TerminalRecord) -> dict[str, str] | None:
        """The verdict last issued for the lifecycle that recorded ``terminal``."""
        return self._issued.get(terminal)

    def issue(self, terminal: TerminalRecord, verdict: dict[str, str]) -> None:
        self._issued[terminal] = dict(verdict)


def terminal_identity(terminal: TerminalRecord) -> dict[str, Any]:
    """Name a recorded terminal exactly.

    The native job, event, and decision, as a `priorTerminals` entry names
    them, plus the event's block and the attested `priorTerminals` history.
    """
    def entry(job: tuple[Any, ...], event: tuple[Any, ...], decision: Any) -> dict[str, Any]:
        return {
            "chainId": job[0],
            "contractAddress": job[1],
            "nativeJobId": job[2],
            "txHash": event[1],
            "logIndex": event[2],
            "decisionHash": decision,
        }

    return {
        **entry(*terminal[:3]),
        "blockNumber": None if terminal.position is None else terminal.position[0],
        "priorTerminals": [entry(*prior) for prior in terminal.attested],
    }


def apply_operation(value: Any, operation: dict[str, Any]) -> Any:
    path = operation.get("path")
    if not isinstance(path, list):
        raise ValueError("patch path must be an array")
    if not path:
        if operation.get("op") in {"add", "replace"}:
            return copy.deepcopy(operation.get("value"))
        raise ValueError("document root can only be added or replaced")
    parent = value
    for segment in path[:-1]:
        parent = parent[segment]
    leaf = path[-1]
    if operation.get("op") == "remove":
        if isinstance(parent, list):
            parent.pop(leaf)
        else:
            del parent[leaf]
    elif operation.get("op") == "replace":
        parent[leaf] = copy.deepcopy(operation.get("value"))
    elif operation.get("op") == "add":
        if isinstance(parent, list):
            parent.insert(leaf, copy.deepcopy(operation.get("value")))
        else:
            parent[leaf] = copy.deepcopy(operation.get("value"))
    else:
        raise ValueError(f"unsupported patch operation: {operation.get('op')!r}")
    return value


def materialize_vector(pack: dict[str, Any], vector: dict[str, Any]) -> dict[str, Any]:
    fixtures = pack.get("fixtures")
    base = vector.get("base")
    if not isinstance(fixtures, dict) or base not in fixtures:
        raise ValueError(f"unknown vector base: {base!r}")
    value = copy.deepcopy(fixtures[base])
    for operation in vector.get("patch", []):
        value = apply_operation(value, operation)
    return value



def _delivery_expected(value: dict[str, Any]) -> bool:
    """Whether the lifecycle has delivery evidence, supplied or not.

    It has when the record is supplied, or when the signed terminal evidence
    references one and the lifecycle names its native submission event.  A
    referenced record the caller did not supply is then `indeterminate`
    (candidate §9 step 5, §11.3 case I5), not absent.
    """
    artifacts = value["artifacts"]
    return artifacts.get("delivery") is not None or (
        "deliveryEvidenceRef" in artifacts["terminal"] and value.get("deliveryBinding") is not None
    )


def _decision_expected(artifacts: dict[str, Any]) -> bool:
    """Whether the lifecycle has an EscrowDecision, supplied or not.

    It has when the record is supplied, or when a signed evaluator terminal
    references one.  An expiry refund that references a decision
    manufactures it (DRD-7), so that reference does not make one expected.
    """
    terminal = artifacts["terminal"]
    return artifacts.get("decision") is not None or (
        "decisionRef" in terminal and terminal.get("terminalState") != "expired-refund"
    )


def role_accounts(agreement: dict[str, Any]) -> dict[str, str]:
    """Each role's EVM account: the lower-case DRW-1 spelling of its claim's 20 bytes."""
    return {
        role: "0x" + parse_claim(agreement[role]["evmAccountClaim"]).evm[1].hex()
        for role in ("buyer", "seller", "evaluator")
    }


def _pipeline_check(value: dict[str, Any]) -> dict[str, str] | None:
    pipeline = value.get("pipeline")
    artifacts = value["artifacts"]
    agreement = artifacts["agreement"]
    rail = artifacts["railDefinition"]
    if not isinstance(pipeline, list) or not pipeline:
        return result("error", "DRV-3", "pipeline must be a non-empty array")
    if not all(isinstance(step, dict) and isinstance(step.get("kind"), str) for step in pipeline):
        return result("error", "DRV-3", "every pipeline step must have a kind")
    # §9 step 1.  A payment phase is a DRP-4 finding and an unsupported
    # delivery a DRP-3 finding below, not unsupported kinds.  An unprefixed
    # candidate name is not the `x-` name (DRG-3), so it is an unknown kind.
    supported_kinds = {COMMIT_PHASE_KIND, ESCROW_PHASE_KIND, *DACS4_DELIVERY_KINDS, "rate"}
    if any(
        step["kind"] not in supported_kinds and not step["kind"].startswith(("pay-", "deliver-"))
        for step in pipeline
    ):
        return result("error", "DRV-2", "pipeline contains an unsupported phase kind")

    escrow_indexes = [i for i, step in enumerate(pipeline) if step["kind"] == ESCROW_PHASE_KIND]
    if len(escrow_indexes) != 2:
        return result("fail", "DRP-1", "pipeline does not contain exactly two x-job-escrow steps")
    fund_index, terminal_index = escrow_indexes
    fund = pipeline[fund_index]
    terminal = pipeline[terminal_index]
    for step in (fund, terminal):
        if not isinstance(step.get("parameters"), dict):
            return result("error", "DRV-3", "x-job-escrow parameters must be an object")
    # Escrow indexes ascend, so the actions alone fix the fund-then-terminal
    # order.  Both phases' rails are bound to the selected rail later (DRP-5).
    if fund["parameters"].get("action") != "fund" or terminal["parameters"].get("action") != "terminal":
        return result("fail", "DRP-2", "escrow actions are not fund then terminal")

    delivery_indexes = [i for i, step in enumerate(pipeline) if step["kind"].startswith("deliver-")]
    if len(delivery_indexes) != 1 or not (fund_index < delivery_indexes[0] < terminal_index):
        return result("fail", "DRP-3", "exactly one delivery must occur between escrow steps")
    # DRP-3 names the delivery's kind: it must be a supported deliver-* step,
    # and this pack supports only the kind it models.  The signed delivery
    # evidence must name this step's kind (DRE-2), so relabelling the step
    # cannot select other checks.
    if pipeline[delivery_indexes[0]]["kind"] not in MODELLED_DELIVERY_KINDS:
        return result("fail", "DRP-3", "the delivery between escrow steps is not a deliver-* kind this pack supports")
    if any(step["kind"].startswith("pay-") for step in pipeline):
        return result("fail", "DRP-4", "ordinary payment phases cannot accompany the escrow pair")
    commits =[i for i, step in enumerate(pipeline) if step["kind"] == COMMIT_PHASE_KIND]
    if len(commits) != 1 or commits[0] > fund_index:
        return result("fail", "DRP-14", "the pipeline does not commit the agreements once, before funding")
    commit_parameters = pipeline[commits[0]].get("parameters")
    if (
        not isinstance(commit_parameters, dict)
        or set(commit_parameters) != {"agreementPhase"}
        or commit_parameters["agreementPhase"] not in tuple(AGREEMENT_PHASES)
    ):
        return result("error", "DRP-14", "unsupported commit-phase agreementPhase")
    if commit_parameters["agreementPhase"] != MODELLED_AGREEMENT_PHASE:
        return result("error", "DRV-2", "unsupported agreement phase: this pack models the payee-bound commit only")
    if (
        agreement.get("fundPhaseIndex") != fund_index
        or agreement.get("deliveryPhaseIndex") != delivery_indexes[0]
        or agreement.get("terminalPhaseIndex") != terminal_index
    ):
        return result("fail", "DRA-11", "agreement phase indexes do not match the pipeline")
    execution = value.get("executionContext")
    if not isinstance(execution, dict):
        return result("error", "DRV-3", "executionContext must be an object")
    # Both steps naming this rail is checked against the agreement later (DRP-5).
    accepted = execution.get("acceptedRails")
    selected = [
        ref for ref in accepted
        if isinstance(ref, dict) and ref.get("railId") == rail["railId"]
    ] if isinstance(accepted, list) else []
    if len(selected) != 1:
        return result("fail", "DRP-10", "job escrow is not selected through one acceptedRails entry")
    # DRR-3: the PaymentRailRef resolves to the selected rail definition.
    if not set(selected[0]) <= {"railId", "railVersion"} or selected[0].get("railVersion", rail["railVersion"]) != rail["railVersion"]:
        return result("fail", "DRR-3", "the acceptedRails reference does not resolve to the selected rail definition")
    # DRP-11: the commit phase's two receipts, the bilateral agreement's and
    # the overlay's, are finalized for this job before any lock.
    receipts = execution.get("commitmentReceipts")
    if not isinstance(receipts, dict) or receipts != {
        "agreement": {
            "status": "finalized", "jobId": agreement["jobId"],
            "contentHash": artifact_hash(artifacts["bilateralAgreement"]),
        },
        "overlay": {"status": "finalized", "jobId": agreement["jobId"], "contentHash": artifact_hash(agreement)},
    }:
        return result("fail", "DRP-11", "funding is not gated by both finalized commit receipts")
    if execution.get("fundingFinalizedBeforeDelivery") is not True:
        return result("fail", "DRP-6", "delivery began before finalized funding evidence")
    # A boolean or a float is not an integer count, though Python compares
    # `false` and `0.0` equal to 0.
    if type(execution.get("dacs5PurchaseCount")) is not int:
        return result("error", "DRV-3", "dacs5PurchaseCount must be an integer")
    if execution["dacs5PurchaseCount"] != 0:
        return result("fail", "DRP-8", "before promotion the escrow pair contributes no DACS-5 purchase or volume")
    expected_gate = (
        "delivery-returned"
        if _delivery_expected(value)
        else (
            "pre-submission-decision"
            if _decision_expected(artifacts)
            else "submission-cutoff"
        )
    )
    if (
        execution.get("terminalGate") != expected_gate
        or execution.get("lateDeliveryDisabled") is not True
    ):
        return result("fail", "DRP-12", "terminal execution did not satisfy the delivery/cutoff gate")
    return None


def _member_issue(artifacts: dict[str, Any]) -> dict[str, str] | None:
    """§9 step 2: every member a later stage reads has its declared encoding (§3.1)."""
    job, funding, terminal = artifacts["job"], artifacts["funding"], artifacts["terminal"]
    for name in ("funding", "delivery", "terminal"):
        artifact = artifacts.get(name)
        if artifact is not None and not _is_unix_ms(artifact.get("observedAt")):
            return result("error", "DRW-4", f"{name} observedAt is not a unix-millisecond safe integer")
    for name, field in (("funding", "fundPhaseIndex"), ("delivery", "phaseIndex"), ("terminal", "terminalPhaseIndex")):
        artifact = artifacts.get(name)
        if artifact is not None and (type(artifact.get(field)) is not int or artifact[field] < 0):
            return result("error", "DRV-3", f"{name} {field} is not a non-negative integer")
    for artifact, field in ((job, "contractAddress"), (funding, "token"), (terminal, "token"), (terminal, "recipient")):
        address = artifact.get(field)
        if not isinstance(address, str) or EVM_ADDRESS_RE.fullmatch(address) is None:
            return result("error", "DRW-1", f"{field} is not 0x and 40 lower-case hexadecimal digits")
    for artifact, field in ((job, "contractAddress"), (funding, "token"), (terminal, "token")):
        if artifact[field] == ZERO_ADDRESS:
            return result("fail", "DRW-1", f"{field} is the zero address")
    runtime = job.get("runtimeBytecodeHash")
    if not isinstance(runtime, str) or CODE_HASH_RE.fullmatch(runtime) is None:
        return result("error", "DRW-2", "runtimeBytecodeHash is not 0x and 64 lower-case hexadecimal digits")
    if runtime in (EMPTY_CODE_HASH, ZERO_BYTES32):
        return result("fail", "DRW-2", "runtimeBytecodeHash is the empty-code or zero hash")
    # Compared with `==` later, where Python would take 8453.0 for 8453.
    if type(job.get("chainId")) is not int:
        return result("error", "DRV-3", "job chain ID must be an integer")
    if not all(_amount_valid(artifact.get("amountBaseUnits")) for artifact in (funding, terminal)):
        return result("error", "DRV-3", "a token amount is not minimal unsigned decimal text within uint256")
    for name, fields in (
        ("evaluation", ("subjectEvidenceRefs",)),
        ("disputeCase", ("subjectEvidenceRefs",)),
        ("dispute", ("subjectBundleRefs", "subjectEvidenceRefs")),
    ):
        artifact = artifacts.get(name)
        if artifact is not None and any(
            field in artifact and (
                not isinstance(artifact[field], list)
                or not all(attestation_ref_shape_valid(ref) for ref in artifact[field])
            )
            for field in fields
        ):
            return result("error", "DRV-3", f"{name} subject references are not an array of AttestationRefs")
    dispute = artifacts.get("dispute")
    if dispute is not None and "recommendedDisposition" in dispute and (
        dispute["recommendedDisposition"] not in tuple(DECISION_DISPOSITIONS)
    ):
        return result("error", "DRV-3", "recommendedDisposition is outside the closed value set")
    if terminal.get("disposition") not in tuple(DECISION_DISPOSITIONS):
        return result("error", "DRV-3", "terminal disposition is outside the closed value set")
    for name, field in (
        ("terminal", "decisionRef"), ("terminal", "deliveryEvidenceRef"),
        ("decision", "deliveryEvidenceRef"), ("dispute", "supersedesOutcomeRef"),
    ):
        artifact = artifacts.get(name)
        if artifact is not None and field in artifact and not attestation_ref_shape_valid(artifact[field]):
            return result("error", "DRV-3", f"{name} {field} is not a DACS-2 AttestationRef")
    return None


def _artifact_shape_check(artifacts: dict[str, Any]) -> dict[str, str] | None:
    required = {"bilateralAgreement", "railDefinition", "agreement", "job", "funding", "terminal"}
    if not required.issubset(artifacts):
        return result("error", "DRV-3", "required candidate artifacts are missing")
    if not all(isinstance(artifacts[name], dict) for name in required):
        return result("error", "DRV-3", "candidate artifacts must be objects")
    for name in OPTIONAL_ARTIFACTS:
        if artifacts.get(name) is not None and not isinstance(artifacts[name], dict):
            return result("error", "DRV-3", f"{name} must be an object")
    agreement = artifacts["agreement"]
    job_id = agreement.get("jobId")
    if not isinstance(job_id, str) or JID_RE.fullmatch(job_id) is None:
        return result("error", "DRAA-1", "jobId is not canonical JID form")
    if "deliveryOrRemedyAgreementVersion" not in agreement:
        return result("error", "DRV-3", "agreement overlay has no deliveryOrRemedyAgreementVersion discriminator")
    if agreement["deliveryOrRemedyAgreementVersion"] != "1":
        return result("error", "DRV-2", "unsupported agreement overlay version")
    # PDE-1: a historical delivery-shaped SettlementEvidence carries
    # `evidenceVersion`; this profile requires current DeliveryEvidence (DRP-7).
    delivery = artifacts.get("delivery")
    if delivery is not None and "evidenceVersion" in delivery and "deliveryEvidenceVersion" not in delivery:
        return result("fail", "DRP-7", "a historical delivery-shaped SettlementEvidence does not satisfy this profile")
    for name, field in ARTIFACT_VERSION_FIELDS.items():
        artifact = artifacts.get(name)
        if artifact is None:
            continue
        if field not in artifact:
            return result("error", "DRV-3", f"{name} has no {field} discriminator")
        if artifact.get(field) != "1":
            return result("error", "DRV-2", f"unsupported {name} version")
        # §9 step 2.  A missing signature is decided by the signature stage.
        if not REQUIRED_ARTIFACT_MEMBERS[name] <= set(artifact):
            return result("error", "DRV-3", f"{name} is missing a required member")
    # DACS-3 §8.5: exactly one agreement discriminator, and this profile's
    # commit phase selects the payee-bound type.
    bilateral = artifacts["bilateralAgreement"]
    discriminators = [field for field in AGREEMENT_DISCRIMINATORS if field in bilateral]
    if not discriminators:
        return result("error", "DRV-3", "bilateral agreement has no version discriminator")
    if discriminators != ["payeeBoundAgreementVersion"] or bilateral["payeeBoundAgreementVersion"] != "1":
        return result("error", "DRV-2", "unsupported bilateral agreement version")
    # Compared with `==` later, where Python would take `true` for 1.
    if any(
        type(agreement.get(name)) is not int
        for name in ("fundPhaseIndex", "deliveryPhaseIndex", "terminalPhaseIndex")
    ):
        return result("error", "DRV-3", "phase indexes must be integers")
    for name in ("job", "funding", "delivery", "evaluation", "disputeCase", "dispute", "decision", "terminal"):
        artifact = artifacts.get(name)
        if artifact is not None and artifact.get("jobId") != job_id:
            return result("fail", "DRD-8", f"{name} is bound to another job")
    for name in ("disputeCase", "dispute"):
        artifact = artifacts.get(name)
        if artifact is not None and (
            not isinstance(artifact.get("caseId"), str) or JID_RE.fullmatch(artifact["caseId"]) is None
        ):
            return result("error", "DRAA-1", "caseId is not canonical JID form")
    # DRJ-1: minimal unsigned decimal text of a uint256; job 0 is admitted.
    native_job = artifacts["job"].get("nativeJobId")
    if (
        not isinstance(native_job, str)
        or UNSIGNED_DECIMAL_RE.fullmatch(native_job) is None
        or not within_uint256(native_job)
    ):
        return result("error", "DRJ-1", "nativeJobId is not minimal unsigned decimal text within uint256")
    evaluation = artifacts.get("evaluation")
    if evaluation is not None:
        sequence = evaluation.get("evaluationSeq")
        if type(sequence) is not int or sequence < 0:
            return result("error", "DRAA-2", "evaluationSeq is not minimal unsigned integer form")
        elif sequence != 0:
            return result("fail", "DRAA-6", "first evaluation sequence is not zero")
        if evaluation.get("result") not in tuple(EVALUATION_RESULTS):
            return result("error", "DRV-3", "evaluation result is outside the closed value set")
    decision = artifacts.get("decision")
    if decision is not None and decision.get("disposition") not in tuple(DECISION_DISPOSITIONS):
        return result("error", "DRV-3", "decision disposition is outside the closed value set")
    if decision is not None and decision.get("decisionStage") not in tuple(DECISION_STAGES):
        return result("error", "DRV-3", "decision stage is outside the closed value set")
    # Checked here, before any stage uses it as a lookup key: an array or
    # object would otherwise escape the four results as a TypeError.
    terminal_state = artifacts["terminal"].get("terminalState")
    if not isinstance(terminal_state, str) or terminal_state not in TERMINAL_STATES:
        return result("error", "DRV-3", "terminal state is outside the closed value set")
    dispute = artifacts.get("dispute")
    if dispute is not None:
        if type(dispute.get("revision")) is not int or dispute["revision"] < 0:
            return result("error", "DRAA-2", "dispute revision is not minimal unsigned integer form")
        if any(field in dispute for field in ("transfer", "recipient", "amountBaseUnits")):
            return result("fail", "DRX-1", "DisputeOutcome directly claims a transfer")
    case = artifacts.get("disputeCase")
    if case is not None and case.get("openedByRole") not in tuple(DISPUTE_ROLES):
        return result("error", "DRV-3", "dispute case openedByRole is outside the closed value set")
    return _member_issue(artifacts)


def _abi_pin_issue(params: dict[str, Any]) -> dict[str, str] | None:
    """DRC-17 pins, DRC-20 field bindings, and DRC-21 configuration evidence.

    Each pin's `inputs` reproduce its signature, which derives its selector
    or `topic0`; the event set is exactly the crosswalk events and the one
    configuration event.  DRC-18: this verifier decodes the fixture ABI only.
    """
    entrypoints, events = params["entrypoints"], params["events"]
    if not isinstance(entrypoints, list) or not all(
        isinstance(pin, dict) and set(pin) == {"name", "signature", "selector", "inputs"}
        and all(isinstance(pin[field], str) for field in ("name", "signature", "selector"))
        and isinstance(pin["inputs"], list)
        and all(
            isinstance(item, dict) and set(item) == {"name", "type"}
            and all(isinstance(item[field], str) for field in item)
            for item in pin["inputs"]
        )
        for pin in entrypoints
    ):
        return result("error", "DRC-17", "entrypoint pins are malformed")
    if sorted(pin["name"] for pin in entrypoints) != sorted(FIXTURE_ENTRYPOINTS):
        return result("error", "DRC-17", "the entrypoint pins are not one per profile entrypoint")
    if not isinstance(events, list) or not all(
        isinstance(pin, dict) and set(pin) == {"name", "signature", "topic0", "inputs"}
        and all(isinstance(pin[field], str) for field in ("name", "signature", "topic0"))
        and isinstance(pin["inputs"], list)
        and all(
            isinstance(item, dict) and set(item) == {"name", "type", "indexed"}
            and isinstance(item["name"], str) and isinstance(item["type"], str)
            and type(item["indexed"]) is bool
            for item in pin["inputs"]
        )
        for pin in events
    ):
        return result("error", "DRC-17", "event pins are malformed")
    names = [pin["name"] for pin in events]
    if len(names) != len(set(names)) or len({pin["topic0"] for pin in events}) != len(events):
        return result("error", "DRC-17", "two event pins share a name or topic0")
    for pin in (*entrypoints, *events):
        if any(ABI_TYPE_RE.fullmatch(item["type"]) is None for item in pin["inputs"]):
            return result("error", "DRC-17", f"{pin['name']} pins an input type that is not a canonical ABI type this verifier admits")
        if pin["signature"] != abi_signature(pin["name"], tuple((item["name"], item["type"]) for item in pin["inputs"])):
            return result("error", "DRC-17", f"{pin['name']} inputs do not reproduce its signature")
    if any(pin["selector"] != selector_of(pin["signature"]) for pin in entrypoints):
        return result("error", "DRC-17", "an entrypoint selector does not derive from its signature")
    if any(pin["topic0"] != topic_of(pin["signature"]) for pin in events):
        return result("error", "DRC-17", "an event topic0 does not derive from its signature")
    if any(sum(item["indexed"] for item in pin["inputs"]) > 3 for pin in events):
        return result("error", "DRC-17", "an event pin has more than three indexed inputs")
    # DRC-21: the configuration event, and its cutoff and policy inputs.
    configuration = params["configurationEvidence"]
    if not isinstance(configuration, dict) or set(configuration) != set(CONFIGURATION_EVIDENCE):
        return result("error", "DRC-21", "configurationEvidence is not the DRC-21 shape")
    configured = [pin for pin in events if pin["topic0"] == configuration["eventTopic0"]]
    if len(configured) != 1:
        return result("error", "DRC-21", "configurationEvidence names no pinned event")
    inputs = configured[0]["inputs"]
    cutoff, policy = configuration["submissionCutoffInput"], configuration["preSubmissionPolicyInput"]
    if (
        [item["type"] for item in inputs if item["name"] == "jobId"] != ["uint256"]
        or any(type(index) is not int or not 0 <= index < len(inputs) for index in (cutoff, policy))
        or cutoff == policy
    ):
        return result("error", "DRC-21", "the configuration event has no uint256 jobId, or its input indexes are not two of its inputs")
    if (
        ABI_WORD_TYPE_RE.fullmatch(inputs[cutoff]["type"]) is None
        or ABI_WORD_TYPE_RE.fullmatch(inputs[policy]["type"]) is None
        or not inputs[cutoff]["type"].startswith("uint")
    ):
        return result("error", "DRC-21", "a configuration input is not a one-word value type, or the cutoff is not a uint")
    word = configuration["preSubmissionPolicyValue"]
    if not isinstance(word, str) or BYTES32_RE.fullmatch(word) is None:
        return result("error", "DRC-21", "preSubmissionPolicyValue is not a 32-byte ABI word")
    if set(names) != set(CROSSWALK_EVENTS) | {configured[0]["name"]}:
        return result("error", "DRC-17", "the event pins are not exactly the crosswalk events and the configuration event")
    # DRC-20: each canonical field is the one input of its name.
    pins = {pin["name"]: pin for pin in (*entrypoints, *events)}
    for entry, fields in CANONICAL_FIELDS.items():
        names_in_entry = [item["name"] for item in pins.get(entry, {"inputs": []})["inputs"]]
        if any(names_in_entry.count(field) != 1 for field in fields):
            return result("error", "DRC-20", f"{entry} has no single input for a canonical field it carries")
    status_map = params["nativeStatusMap"]
    if (
        not isinstance(status_map, list)
        or not all(
            isinstance(entry, dict) and set(entry) == {"nativeValue", "nativeStatus"}
            and type(entry["nativeValue"]) is int and isinstance(entry["nativeStatus"], str)
            for entry in status_map
        )
        or len({entry["nativeValue"] for entry in status_map}) != len(status_map)
        or sorted(entry["nativeStatus"] for entry in status_map) != sorted(NATIVE_STATUSES)
    ):
        return result("error", "DRC-17", "nativeStatusMap does not map each native value to one crosswalk status")
    # DRC-18: this verifier decodes the fixture implementation's ABI only.
    if (
        sorted(entrypoints, key=lambda pin: pin["name"]) != sorted(entrypoint_pins(), key=lambda pin: pin["name"])
        or sorted(events, key=lambda pin: pin["name"]) != sorted(event_pins(), key=lambda pin: pin["name"])
        or configuration != CONFIGURATION_EVIDENCE
    ):
        return result("error", "DRV-2", "unsupported implementation ABI")
    return None


def _rail_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Authenticate the selected `JobEscrowRailDefinition` (candidate §2.2, §8.4).

    Its discriminators first (DRR-6), then its encodings, the DRC-14 literals
    and the DRC-17 pins, then the registry steward's signature (DRR-2) and
    the bindings between its members (DRR-1, DRR-4, DRR-5, DRR-7, DRC-16).
    """
    rail = value["artifacts"]["railDefinition"]
    if rail.get("jobEscrowRailVersion") != "1":
        return result("error", "DRR-6", "unsupported job-escrow rail version")
    if rail.get("railType") != "x-evm-erc8183":
        return result("error", "DRR-6", "unsupported rail type")
    if rail.get("phaseHandler") != ESCROW_PHASE_KIND:
        return result("error", "DRR-6", "unsupported rail phase handler")
    missing = RAIL_MEMBERS - set(rail)
    if missing & {"asset", "network"}:
        return result("error", "DRR-7", "the rail has no asset or network member")
    if "governance" in missing:
        return result("error", "DRR-8", "the rail has no governance member")
    if missing or not set(rail) <= RAIL_MEMBERS | {"consumerFinalityProfile"}:
        return result("error", "DRV-3", "rail definition members are not the JobEscrowRailDefinition's")
    version = rail["railVersion"]
    if type(version) is not int or not 0 < version <= SAFE_INTEGER_MAX:
        return result("error", "DRV-3", "railVersion is not a positive safe integer")
    params = rail["parameters"]
    if not isinstance(params, dict) or not PROFILE_FIELDS <= set(params) <= PROFILE_FIELDS | OPTIONAL_PROFILE_FIELDS:
        return result("error", "DRV-3", "rail parameters are not ERC8183ProfileParameters")
    # Exact JSON types: Python would take `false` for 0.
    if any(
        type(params[name]) is not type(expected) or params[name] != expected
        for name, expected in PROFILE_LITERALS.items()
    ):
        return result("error", "DRC-14", "a literal-typed profile field has another value")
    revision = params["implementationRevision"]
    if not isinstance(revision, str) or IMPLEMENTATION_REVISION_RE.fullmatch(revision) is None:
        return result("error", "DRC-14", "implementationRevision is not <owner>/<repository>@<commit>")
    pins = _abi_pin_issue(params)
    if pins:
        return pins
    chain_id = params["chainId"]
    if type(chain_id) is not int or not 0 < chain_id <= SAFE_INTEGER_MAX:
        return result("error", "DRV-3", "rail chain ID is not a positive safe integer")
    for field in ("contractAddress", "paymentToken", "implementationAddress"):
        if field in params and (
            not isinstance(params[field], str) or EVM_ADDRESS_RE.fullmatch(params[field]) is None
        ):
            return result("error", "DRW-1", f"rail {field} is not 0x and 40 lower-case hexadecimal digits")
    for field in ("runtimeBytecodeHash", "paymentTokenRuntimeBytecodeHash", "implementationRuntimeBytecodeHash"):
        if field in params and (
            not isinstance(params[field], str) or CODE_HASH_RE.fullmatch(params[field]) is None
        ):
            return result("error", "DRW-2", f"rail {field} is not 0x and 64 lower-case hexadecimal digits")
    decimals = params["tokenDecimals"]
    if type(decimals) is not int or not 0 <= decimals <= MAX_TOKEN_DECIMALS:
        return result("error", "DRV-3", "rail token decimals are not a uint8")
    if type(params["finalityBlocks"]) is not int or params["finalityBlocks"] <= 0:
        return result("error", "DRV-3", "rail finality depth must be a positive integer")
    if type(params["minimumEvaluationWindowSec"]) is not int:
        return result("error", "DREB-14", "minimum evaluation window must be an integer")
    if not _is_unix_ms(params["maxCrossSubstrateSkewMs"]):
        return result("error", "DRC-15", "maxCrossSubstrateSkewMs is not a non-negative safe integer")
    asset, network = rail["asset"], rail["network"]
    if (
        not isinstance(asset, dict) or set(asset) != ASSET_MEMBERS
        or not isinstance(network, dict) or set(network) != NETWORK_MEMBERS
    ):
        return result("error", "DRR-7", "rail asset or network members are not the DACS-4 erc20 and evm arms")
    if not isinstance(asset["contract"], str) or EVM_ADDRESS_RE.fullmatch(asset["contract"]) is None:
        return result("error", "DRW-1", "rail asset contract is not 0x and 40 lower-case hexadecimal digits")
    if network["rpcAttestation"] not in tuple(RPC_ATTESTATIONS) or not isinstance(asset["symbol"], str):
        return result("error", "DRV-3", "rail asset symbol or network attestation is malformed")
    rail_id = rail["railId"]
    match = RAIL_ID_RE.fullmatch(rail_id) if isinstance(rail_id, str) else None
    if match is None or len(rail_id) > MAX_RAIL_ID_LENGTH or int(match.group(1)) != chain_id or match.group(2) != asset["symbol"]:
        return result("error", "DRR-1", "railId is not x-evm-erc8183:<chainId>:<asset symbol> within 64 characters")
    availability = rail["availability"]
    if not isinstance(availability, str) or availability not in RAIL_AVAILABILITIES:
        return result("error", "DRV-3", "rail availability is not a DACS-4 RailAvailability")
    governance = rail["governance"]
    if (
        not isinstance(governance, dict)
        or not GOVERNANCE_REQUIRED <= set(governance) <= GOVERNANCE_REQUIRED | GOVERNANCE_OPTIONAL
        or parse_claim(governance["proposedBy"]) is None
        or not _is_unix_ms(governance["acceptedAt"])
        or governance["anchoring"] not in tuple(GOVERNANCE_ANCHORINGS)
        or ("supersedes" in governance and (
            type(governance["supersedes"]) is not int or not 0 < governance["supersedes"] < version
        ))
    ):
        return result("error", "DRR-8", "rail governance is not the DACS-4 RailDefinition governance member")
    # §9 step 3: the registry steward signs the rail (DRR-2, RD-1).
    signature = rail["signature"]
    signer = signature.get("signer") if isinstance(signature, dict) else None
    if not isinstance(signer, str) or signer not in PINNED_STEWARD_KEYS or not signature_valid(
        rail, signature, signer, PINNED_STEWARD_KEYS, DOMAINS["railDefinition"]
    ):
        return result("fail", "DRR-2", "rail definition is not signed by the pinned registry steward")
    if asset["kind"] != "erc20" or network["kind"] != "evm":
        return result("fail", "DRR-7", "rail asset and network are not the erc20 and evm kinds")
    if (
        type(asset["chainId"]) is not int or type(network["chainId"]) is not int
        or not asset["chainId"] == network["chainId"] == chain_id
    ):
        return result("fail", "DRR-7", "rail asset, network, and parameters name different chains")
    if asset["contract"] != params["paymentToken"] or type(asset["decimals"]) is not int or asset["decimals"] != decimals:
        return result("fail", "DRR-7", "rail asset contract or decimals differ from the parameters")
    if ZERO_ADDRESS in (params["contractAddress"], params["paymentToken"]):
        return result("fail", "DRW-1", "the rail contract or payment token is the zero address")
    if any(params.get(field) in (EMPTY_CODE_HASH, ZERO_BYTES32) for field in (
        "runtimeBytecodeHash", "paymentTokenRuntimeBytecodeHash", "implementationRuntimeBytecodeHash",
    )):
        return result("fail", "DRW-2", "a pinned code hash is the empty-code or zero hash")
    profile = rail.get("consumerFinalityProfile")
    if profile is None:
        return result("fail", "DRR-4", "the rail has no consumerFinalityProfile and is not selectable")
    settlement = profile.get("settlement") if isinstance(profile, dict) else None
    if not isinstance(profile, dict) or profile.get("finalityProfileVersion") != "1" or not isinstance(settlement, dict):
        return result("error", "DRV-3", "consumerFinalityProfile is malformed")
    if profile.get("model") != "block-depth" or settlement.get("kind") != "block-depth":
        return result("fail", "DRR-4", "consumerFinalityProfile is not the block-depth model")
    if (
        settlement.get("networkId") != f"eip155:{chain_id}"
        or type(settlement.get("requiredDepth")) is not int
        or settlement["requiredDepth"] != params["finalityBlocks"]
    ):
        return result("fail", "DRC-16", "the finality profile's network or depth differs from the rail parameters")
    # RAV-R2: a `mocked` rail is selectable only in an explicitly configured
    # non-production mode.  This verifier is that mode and runs only offline
    # fixtures, so it accepts nothing else; a disabled or failed rail is never
    # selectable (DRR-5).
    if availability in ("disabled", "failed"):
        return result("fail", "DRR-5", "a disabled or failed rail is not selectable")
    if availability != "mocked":
        return result("error", "DRV-1", "only an offline mocked fixture rail is accepted")
    return None


def _canonical_record_check(value: dict[str, Any]) -> dict[str, str] | None:
    artifacts = value["artifacts"]
    records = value["canonicalRecords"]
    expected_names = {
        name for name in ("agreement", "delivery", "decision")
        if artifacts.get(name) is not None
    }
    if set(records) != expected_names:
        return result("error", "DRV-3", "canonical record set does not match the lifecycle")
    for name in expected_names:
        record = records.get(name)
        artifact = artifacts[name]
        if not isinstance(record, dict):
            return result("error", "DRV-3", f"{name} canonical record must be an object")
        encoded = jcs_canonicalize(unsigned_artifact(artifact)).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        expected_native = DESCRIPTION_PREFIX + digest if name == "agreement" else "0x" + digest
        if record != {
            "canonicalUtf8Hex": encoded.hex(),
            "contentHash": digest,
            "mappedNativeValue": expected_native,
        }:
            return result("fail", "DREB-2", f"{name} canonical bytes or mapped value are stale")
    return None


def _bilateral_shape_issue(bilateral: dict[str, Any]) -> str | None:
    """§9 step 2 for the DACS-3 `PayeeBoundAgreementDocument` (DACS-3 §8.5)."""
    if not BILATERAL_MEMBERS <= set(bilateral):
        return "bilateral agreement is missing a PayeeBoundAgreementDocument member"
    parties = bilateral["parties"]
    if not isinstance(parties, list) or not all(
        isinstance(party, dict) and AGREEMENT_PARTY_MEMBERS <= set(party)
        and isinstance(party["role"], str) and party["role"] in AGREEMENT_PARTY_ROLES
        and parse_claim(party["primaryClaim"]) is not None
        for party in parties
    ):
        return "bilateral agreement parties are not AgreementParty entries"
    terms = bilateral["terms"]
    if not isinstance(terms, dict) or not AGREEMENT_TERMS_MEMBERS <= set(terms):
        return "bilateral agreement terms are missing a member"
    price = terms["price"]
    # A price with DACS-4's optional `unit` is not read: a fixture limitation
    # that fails closed (README, synthetic proof limits), not a candidate rule.
    if (
        not isinstance(price, dict)
        or set(price) != {"amount", "currency"}
        or not isinstance(price["amount"], str)
        or CANONICAL_DECIMAL_RE.fullmatch(price["amount"]) is None
        or not isinstance(price["currency"], str)
    ):
        return "agreement price is not a CD-1 PriceTerm"
    if not _is_unix_ms(terms["deadline"]):
        return "agreement deadline is not a unix-millisecond safe integer"
    bindings = terms["payoutBindings"]
    if not isinstance(bindings, list) or not all(
        isinstance(binding, dict) and set(binding) == PAYOUT_BINDING_MEMBERS
        and isinstance(binding["railId"], str) and type(binding["phaseIndex"]) is int
        and binding["phaseIndex"] >= 0 and isinstance(binding["payeeAddress"], str)
        for binding in bindings
    ):
        return "agreement payout bindings are not PayoutBinding entries"
    if "rail" in terms and not (isinstance(terms["rail"], dict) and isinstance(terms["rail"].get("railId"), str)):
        return "agreement terms.rail is not a PaymentRailRef"
    if not isinstance(bilateral["signatures"], list):
        return "bilateral agreement signatures must be an array"
    return None


def _agreement_check(value: dict[str, Any]) -> dict[str, str] | None:
    artifacts = value["artifacts"]
    agreement = artifacts["agreement"]
    public_keys = value["publicKeys"]
    bilateral = artifacts["bilateralAgreement"]
    rail = artifacts["railDefinition"]
    params = rail["parameters"]

    # §9 step 2: the DACS-3 agreement's and the overlay's encodings.
    issue = _bilateral_shape_issue(bilateral)
    if issue:
        return result("error", "DRV-3", issue)
    role_bindings = {role: agreement.get(role) for role in ("buyer", "seller", "evaluator")}
    if not all(isinstance(binding, dict) for binding in role_bindings.values()):
        return result("error", "DRV-3", "agreement role bindings must be objects")
    claims = {role: binding.get("primaryClaim") for role, binding in role_bindings.items()}
    identities = {role: claim_identity(claim) for role, claim in claims.items()}
    if not all(identity is not None for identity in identities.values()):
        return result("error", "DRV-3", "agreement primary claims must be canonical ClaimReferences")
    for role, binding in role_bindings.items():
        text = binding.get("evmAccountClaim")
        match = EVM_ACCOUNT_CLAIM_RE.fullmatch(text) if isinstance(text, str) else None
        if match is not None and not evm_claim_address_valid(match.group(2)):
            return result(
                "error", "DRW-1",
                f"{role} EVM account address is not 0x and 40 hex digits in one case or valid EIP-55",
            )
        if parse_claim(text) is None:
            return result("error", "DRV-3", f"{role} EVM account claim is not a canonical ClaimReference")
    if not _is_unix_sec(agreement.get("submissionCutoffSec")) or not _is_unix_sec(agreement.get("evaluationDeadlineSec")):
        return result("error", "DRA-19", "submission cutoff and evaluation deadline are not unix seconds within the DRW-4 bound")
    budget = agreement.get("budgetBaseUnits")
    if not isinstance(budget, str) or UNSIGNED_DECIMAL_RE.fullmatch(budget) is None:
        return result("error", "DRA-10", "budgetBaseUnits is not minimal unsigned decimal")
    # Every native amount must equal the budget (DREB-11, DRF-2, DRT-5, DRT-6),
    # so this bounds them too.
    if not within_uint256(budget):
        return result("error", "DRV-3", "budgetBaseUnits exceeds the uint256 range of a token amount")

    # §9 step 3: the bilateral agreement is the exact one both commercial
    # parties signed for this job (DRA-1, DRA-2).
    parties = [party for party in bilateral["parties"] if party["role"] in ("buyer", "seller")]
    by_role = {party["role"]: party for party in parties}
    issue = _ref_check(
        agreement.get("agreementRef"), bilateral, None, "DRA-1", "bilateral agreement",
        tuple(party["primaryClaim"] for party in parties),
    )
    if issue:
        return issue
    if bilateral.get("jobId") != agreement.get("jobId"):
        return result("fail", "DRA-1", "bilateral agreement is for another job")
    signatures = bilateral["signatures"]
    if len(parties) != 2 or set(by_role) != {"buyer", "seller"} or len(signatures) != 2 or not all(
        any(
            signature_valid(bilateral, signature, party["primaryClaim"], public_keys, DOMAINS["bilateralAgreement"], "party")
            for signature in signatures
        )
        for party in parties
    ):
        return result("fail", "DRA-1", "the bilateral agreement is not signed by exactly its buyer and seller")
    if agreement.get("agreementHash") != artifact_hash(bilateral):
        return result("fail", "DRA-2", "bilateral agreement hash mismatch")
    issue = _ref_check(
        agreement.get("railDefinitionRef"), rail, None, "DRP-5", "rail definition",
        (rail["signature"]["signer"],),
    )
    if issue:
        return issue
    # DRA-17: the overlay keeps the bilateral agreement's buyer and seller,
    # matched by CF-3 identity and with byte-exact bundle and Vet bindings.
    for role in ("buyer", "seller"):
        party, binding = by_role[role], role_bindings[role]
        if (
            claim_identity(party["primaryClaim"]) != identities[role]
            or canonical_bytes(party["bundleHash"]) != canonical_bytes(binding.get("bundleHash"))
            or canonical_bytes(party["vetRecordRef"]) != canonical_bytes(binding.get("vetRecordRef"))
        ):
            return result("fail", "DRA-17", f"overlay {role} binding differs from the bilateral agreement's party")
    # DRA-3, DRA-18: one valid signature per role, each by its role's claim.
    signatures = agreement.get("signatures")
    if (
        not isinstance(signatures, list)
        or len(signatures) != 3
        or not all(isinstance(signature, dict) for signature in signatures)
    ):
        return result("fail", "DRA-3", "agreement needs exactly one signature per role")
    roles = [signature.get("role") for signature in signatures]
    if not all(isinstance(role, str) for role in roles) or sorted(roles) != ["buyer", "evaluator", "seller"]:
        return result("fail", "DRA-18", "the overlay signature roles are not buyer, seller, and evaluator once each")
    for signature in signatures:
        role = signature["role"]
        if claim_identity(signature.get("party")) != identities[role]:
            return result("fail", "DRA-18", f"the {role} signature's party is not the {role}'s primary claim")
        if not signature_valid(agreement, signature, signature["party"], public_keys, DOMAINS["agreement"], "party"):
            return result("fail", "DRA-3", f"invalid {role} agreement signature")
    if identities["evaluator"] in {identities["buyer"], identities["seller"]}:
        return result("fail", "DRA-6", "evaluator primary claim collides with a commercial party")
    if value.get("bundleRequiredSigners") != [claims["buyer"], claims["seller"]]:
        return result("fail", "DRA-13", "evaluator overlay signature changed the bilateral bundle parties")
    if agreement.get("preSubmissionRefundPolicy") != "evaluator-rejection":
        return result("error", "DRA-15", "unsupported pre-submission refund policy for this profile")
    if agreement.get("disclosurePolicy") not in ("public-evidence-only", "explicit-party-supplied"):
        return result("error", "DRQ-1", "unsupported evidence-disclosure policy")
    terms = bilateral["terms"]
    if agreement["evaluationDeadlineSec"] * 1000 > terms["deadline"]:
        return result("fail", "DRA-19", "the evaluation deadline is later than the agreement deadline")
    # DRA-22: the agreement's terms.rail is the selected acceptedRails entry.
    selected = next(
        ref for ref in value["executionContext"]["acceptedRails"]
        if isinstance(ref, dict) and ref.get("railId") == rail["railId"]
    )
    if "rail" not in terms or canonical_bytes(terms["rail"]) != canonical_bytes(selected):
        return result("fail", "DRA-22", "the agreement's terms.rail is not the selected acceptedRails reference")
    # DRA-21, DRA-10: the agreed price is in the rail's asset, and the budget
    # is that price converted with the pinned token decimals (DACS-4 §9.5.2
    # steps 2 and 3).
    price = terms["price"]
    if price["currency"] != rail["asset"]["symbol"]:
        return result("fail", "DRA-21", "the agreement price currency is not the rail asset symbol")
    # DACS-4 §9.3: an agreed `PriceTerm.amount` MUST be strictly greater than
    # zero.  CD-1 makes "0" the only spelling of zero, and it has no sign.
    if price["amount"] == "0":
        return result("fail", "DRA-10", "agreement price is not strictly greater than zero")
    # None when the price is not a whole number of token base units, which no
    # budget equals.  Both are otherwise minimal unsigned decimal text, so
    # equal strings are equal amounts.
    base_units = price_base_units(price["amount"], params["tokenDecimals"])
    if base_units != budget:
        return result(
            "fail", "DRA-10",
            "budgetBaseUnits is not the agreement price converted with the pinned token decimals",
        )

    chain_id = params["chainId"]
    accounts: dict[str, bytes] = {}
    for role, binding in role_bindings.items():
        claim = parse_claim(binding["evmAccountClaim"])
        if claim.evm is None or claim.evm[0] != chain_id:
            return result("fail", "DRA-5", f"{role} EVM account claim is not the DACS EIP-155 form for the rail chain")
        accounts[role] = claim.evm[1]
    if bytes(20) in accounts.values():
        return result("fail", "DRW-1", "the zero address cannot be a client, provider, or evaluator")
    if accounts["evaluator"] in {accounts["buyer"], accounts["seller"]}:
        return result("fail", "DRA-7", "evaluator account collides with client or provider")
    # DRA-20: one payout binding, keyed by the escrow rail and fund phase, pays
    # the seller's account.
    bindings = terms["payoutBindings"]
    if len(bindings) != 1 or (bindings[0]["railId"], bindings[0]["phaseIndex"]) != (
        rail["railId"], agreement["fundPhaseIndex"]
    ):
        return result("fail", "DRA-20", "the agreement needs exactly one payout binding keyed by the escrow rail and fund phase")
    payee = bindings[0]["payeeAddress"]
    if not evm_claim_address_valid(payee):
        return result("error", "DRW-1", "the payout binding's payee address is not a DRW-1 EVM address")
    if bytes.fromhex(payee[2:]) != accounts["seller"]:
        return result("fail", "DRA-20", "the payout binding does not pay the seller's EVM account")
    for role, native_field in (("buyer", "client"), ("seller", "provider"), ("evaluator", "evaluator")):
        if value["native"].get(native_field) != "0x" + accounts[role].hex():
            return result("fail", f"DREB-{7 + list(('buyer', 'seller', 'evaluator')).index(role)}", f"native {native_field} mismatch")

    evaluator = role_bindings["evaluator"]
    requirement = evaluator.get("requirement")
    if not isinstance(requirement, dict) or evaluator.get("requirementHash") != content_hash(requirement):
        return result("fail", "DRA-8", "evaluator requirement hash mismatch")
    if value.get("evaluatorVetResult") != "pass":
        return result("fail", "DRA-9", "evaluator Vet result is not pass")
    return None


def _component_signature_check(value: dict[str, Any]) -> dict[str, str] | None:
    artifacts = value["artifacts"]
    claims = {
        role: artifacts["agreement"][role]["primaryClaim"]
        for role in ("buyer", "seller", "evaluator")
    }
    orchestrator = value.get("orchestratorClaim")
    if parse_claim(orchestrator) is None:
        return result("error", "DRV-3", "orchestratorClaim is required")
    case = artifacts.get("disputeCase")
    signers = {
        "job": orchestrator,
        "funding": orchestrator,
        "delivery": orchestrator,
        "evaluation": claims["evaluator"],
        # DRX-7: the opening role's primary claim signs the case.
        "disputeCase": None if case is None else claims[case["openedByRole"]],
        "dispute": claims["evaluator"],
        "decision": claims["evaluator"],
        "terminal": orchestrator,
    }
    rules = {"evaluation": "DRE-1", "decision": "DRD-1", "disputeCase": "DRX-7", "dispute": "DRX-7"}
    for name, signer in signers.items():
        artifact = artifacts.get(name)
        if artifact is None:
            continue
        if not signature_valid(
            artifact, artifact.get("signature"), signer, value["publicKeys"], DOMAINS[name]
        ):
            return result("fail", rules.get(name, "DRV-4"), f"invalid {name} signature")
    return None


def _selected_rail_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Bind the job, pipeline, and native target to the agreement-selected rail."""
    artifacts = value["artifacts"]
    agreement = artifacts["agreement"]
    rail = artifacts["railDefinition"]
    params = rail["parameters"]
    job = artifacts["job"]
    if canonical_bytes(job.get("railDefinitionRef")) != canonical_bytes(agreement.get("railDefinitionRef")):
        return result("fail", "DRP-5", "escrow job does not use the agreement-selected rail")
    if any(
        step["parameters"].get("rail") != rail["railId"]
        for step in value["pipeline"]
        if step["kind"] == ESCROW_PHASE_KIND
    ):
        return result("fail", "DRP-5", "escrow phases do not name the agreement-selected rail")
    # DRJ-10: the job is at the rail's pinned chain, contract, and code.
    if (
        job["chainId"] != params["chainId"]
        or job["contractAddress"] != params["contractAddress"]
        or job["runtimeBytecodeHash"] != params["runtimeBytecodeHash"]
    ):
        return result("fail", "DRJ-10", "escrow job chain, contract, or runtime code differs from the rail's pins")
    if value["native"].get("chainId") != params["chainId"]:
        return result("fail", "DRJ-2", "native chain differs from the selected rail's")
    return None


def _evaluation_rule_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Resolve the overlay's evaluation rule (DRE-8, DRE-9).

    The overlay binds the rule by content hash; it carries no signature of its
    own.  A rule the caller did not supply is decided later as `indeterminate`.
    """
    artifacts = value["artifacts"]
    rule = artifacts.get("evaluationRule")
    if rule is None:
        return None
    if rule.get("evaluationRuleVersion") != "1" or rule.get("ruleKind") != RULE_KIND:
        return result("error", "DRE-9", "unsupported evaluation rule version or kind")
    criteria = rule.get("criteria")
    if set(rule) != EVALUATION_RULE_FIELDS or not isinstance(criteria, list) or not all(
        isinstance(criterion, dict) and set(criterion) == {"criterionId", "statement"}
        and isinstance(criterion["criterionId"], str) and bool(criterion["criterionId"])
        and isinstance(criterion["statement"], str)
        for criterion in criteria
    ):
        return result("error", "DRV-3", "evaluation rule is not an exact EvaluationRule")
    agreement = artifacts["agreement"]
    issue = _ref_check(
        agreement.get("evaluationRuleRef"), rule, logical_address(agreement["jobId"], "evaluation-rule"),
        "DRE-8", "evaluation rule", (),
    )
    if issue:
        return issue
    if rule["jobId"] != agreement["jobId"]:
        return result("fail", "DRE-8", "the evaluation rule is for another job")
    identifiers = [criterion["criterionId"] for criterion in criteria]
    if not identifiers or len(identifiers) != len(set(identifiers)):
        return result("fail", "DRE-9", "evaluation rule criteria are empty or repeat an identifier")
    return None


def _resolver_evidence_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Authenticate the pinned resolver record and its binding to this job."""
    resolver = value.get("resolverEvidence")
    if not isinstance(resolver, dict) or not (
        RESOLVER_EVIDENCE_FIELDS <= set(resolver)
        <= RESOLVER_EVIDENCE_FIELDS | {"qualifiedArtifactWrites"}
    ):
        return result("error", "DRV-3", "resolver evidence shape is not exact")
    if resolver.get("resolverEvidenceVersion") != "1":
        return result("error", "DRV-2", "unsupported resolver evidence version")
    signer = resolver.get("resolver")
    if not isinstance(signer, str) or signer not in PINNED_RESOLVER_KEYS or not signature_valid(
        resolver, resolver.get("signature"), signer, PINNED_RESOLVER_KEYS, RESOLVER_DOMAIN
    ):
        return result("fail", "DRV-1", "resolver evidence is not authenticated by the pinned resolver")
    artifacts = value["artifacts"]
    rail = artifacts["railDefinition"]
    inputs = value.get("reproductionInputs")
    observations = inputs.get("nativeEventInputs") if isinstance(inputs, dict) else None
    if resolver.get("eventObservationsHash") != content_hash(observations):
        return result("fail", "DRV-1", "native event observations are not the resolver-authenticated set")
    if (
        resolver.get("jobId") != artifacts["agreement"].get("jobId")
        or resolver.get("railDefinitionHash") != artifact_hash(rail)
        or resolver.get("chainId") != rail["parameters"]["chainId"]
        or resolver.get("contractAddress") != rail["parameters"]["contractAddress"]
        or resolver.get("nativeJobId") != artifacts["job"].get("nativeJobId")
    ):
        return result("fail", "DRV-6", "resolver evidence describes another job, rail, or contract")
    transactions = resolver.get("transactions")
    if not isinstance(transactions, list) or not transactions or not all(
        _transaction_valid(item) for item in transactions
    ):
        return result("error", "DRV-3", "resolver transaction records are malformed")
    history = resolver.get("priorTerminals")
    if not isinstance(history, list) or not all(_prior_terminal_valid(item) for item in history):
        return result("error", "DRV-3", "resolver terminal history is malformed")
    if not _native_state_valid(resolver.get("nativeState")):
        return result("error", "DRV-3", "resolver native state is malformed")
    if not _digest_anchor_valid(resolver.get("deliveryDigestAnchor")):
        return result("error", "DRV-3", "resolver delivery-digest anchor is malformed")
    if not _decision_anchor_valid(resolver.get("decisionAnchor")):
        return result("error", "DRV-3", "resolver decision anchor is malformed")
    statuses = resolver.get("statuses")
    if not isinstance(statuses, dict) or set(statuses) != EXTERNAL_EVIDENCE_FIELDS:
        return result("error", "DRV-3", "resolver status set is incomplete")
    if any(not isinstance(state, str) or state not in EXTERNAL_STATES for state in statuses.values()):
        return result("error", "DRV-3", "unknown resolver status")
    return None


def _qualified_artifact_write_valid(write: Any) -> bool:
    return (
        isinstance(write, dict)
        and set(write) == QUALIFIED_ARTIFACT_WRITE_FIELDS
        and all(isinstance(write[name], str) and write[name] for name in (
            "logicalAddress", "nativeAddress", "contentHash", "writer", "nonce",
        ))
        and HASH_RE.fullmatch(write["contentHash"]) is not None
        and isinstance(write["transactionRef"], dict)
        and set(write["transactionRef"]) == {"kind", "value"}
        and all(isinstance(item, str) and item for item in write["transactionRef"].values())
        and _is_unix_sec(write["finalizedBlockTimestampSec"])
    )


def _write_addresses(terminal: dict[str, Any]) -> frozenset[str]:
    """The logical addresses of the funding and decision artifacts the terminal evidence references."""
    references = (terminal.get("fundingEvidenceRef"), terminal.get("decisionRef"))
    return frozenset(
        reference["anchor"]["locator"] for reference in references
        if isinstance(reference, dict) and isinstance(reference.get("anchor"), dict)
        and isinstance(reference["anchor"].get("locator"), str)
    )


def _equivocation() -> dict[str, str]:
    """The one DRAA-4 finding, for one lifecycle's writes and for writes from several."""
    return result("indeterminate", "DRAA-4", "two qualifying writes at one logical address; retain both and select neither")


def _write_reference(terminal: dict[str, Any], name: str) -> Any:
    return terminal.get(f"{name}EvidenceRef" if name == "funding" else "decisionRef")


def _resolver_signed(resolver: dict[str, Any]) -> bool:
    """Whether ``resolver`` is an exact version-1 record the pinned resolver signed."""
    signer = resolver.get("resolver")
    return (
        RESOLVER_EVIDENCE_FIELDS <= set(resolver) <= RESOLVER_EVIDENCE_FIELDS | {"qualifiedArtifactWrites"}
        and resolver.get("resolverEvidenceVersion") == "1"
        and isinstance(signer, str) and signer in PINNED_RESOLVER_KEYS
        and signature_valid(resolver, resolver.get("signature"), signer, PINNED_RESOLVER_KEYS, RESOLVER_DOMAIN)
    )


def _retain_qualified_writes(value: Any, ledger: DecisionLedger) -> None:
    """Retain this input's qualifying write summaries before any lifecycle is judged (DRAA-4).

    The pinned resolver's signature is the summaries' authority, so they are
    retained whatever this lifecycle's other checks decide.  Each summary is
    retained on its own when it is well formed and names the logical address
    the terminal references for its artifact: a malformed or misaddressed
    sibling decides this lifecycle's finding, not whether the others exist.
    """
    resolver = value.get("resolverEvidence") if isinstance(value, dict) else None
    if not isinstance(resolver, dict) or not isinstance(resolver.get("qualifiedArtifactWrites"), dict):
        return
    artifacts = value.get("artifacts")
    terminal = artifacts.get("terminal") if isinstance(artifacts, dict) else None
    if not isinstance(terminal, dict) or not nesting_within(value, MAX_JSON_DEPTH) or not number_profile_valid(value):
        return
    if not _resolver_signed(resolver):
        return
    for name, receipts in resolver["qualifiedArtifactWrites"].items():
        reference = _write_reference(terminal, name) if name in ("funding", "decision") else None
        if not isinstance(receipts, list) or not attestation_ref_shape_valid(reference):
            continue
        bound = [
            receipt for receipt in receipts
            if _qualified_artifact_write_valid(receipt) and receipt["logicalAddress"] == reference["anchor"]["locator"]
        ]
        if bound:
            ledger.retain_writes(reference["anchor"]["locator"], bound)


def _artifact_write_check(value: dict[str, Any]) -> dict[str, str] | None:
    """The qualified write summaries are well formed and name the referenced logical addresses.

    Qualification is a synthetic resolver assertion, not a native SR-2 proof.
    Omitting this optional input preserves the pack's existing proof boundary.
    `_retain_qualified_writes` has already retained every summary that
    qualifies, including the bound siblings of one this check rejects.
    """
    resolver = value["resolverEvidence"]
    if "qualifiedArtifactWrites" not in resolver:
        return None
    writes = resolver["qualifiedArtifactWrites"]
    if not isinstance(writes, dict) or not writes or not set(writes) <= {"funding", "decision"} or any(
        not isinstance(receipts, list) or not receipts
        or not all(_qualified_artifact_write_valid(receipt) for receipt in receipts)
        for receipts in writes.values()
    ):
        return result("error", "DRV-3", "qualified artifact write summaries are malformed")
    terminal = value["artifacts"]["terminal"]
    for name, receipts in writes.items():
        reference = _write_reference(terminal, name)
        if reference is None or any(
            receipt["logicalAddress"] != reference["anchor"]["locator"] for receipt in receipts
        ):
            return result("fail", "DRV-6", "qualified writes describe another logical address")
    return None


def _write_selection_check(
    value: dict[str, Any], ledger: DecisionLedger | None = None, select: bool = True
) -> dict[str, str] | None:
    """DRAA-4: with two qualifying writes known, retain both and select neither, before DRC-15.

    The writes known at an address are this lifecycle's own and every write
    ``ledger`` retained from any input, so two writes carried by different
    lifecycles, in one batch or in successive calls, are the same
    equivocation as two carried by one.  Only with one write known is it
    selected and checked against the reference and the decision anchor.
    With ``select`` off nothing here is decided (see `_checked_lifecycle`).
    """
    if not select:
        return None
    terminal = value["artifacts"]["terminal"]
    writes = value["resolverEvidence"].get("qualifiedArtifactWrites", {})
    for address in sorted(_write_addresses(terminal)):
        # The write identity includes native address, transaction, writer and
        # nonce, not just contentHash. Unequal immutable snapshots also cannot
        # be selected. An exact repeat of one receipt is not a second write.
        known = set(ledger.writes_at(address) if ledger is not None else ())
        known.update(
            canonical_bytes(receipt) for receipts in writes.values() for receipt in receipts
            if receipt["logicalAddress"] == address
        )
        if len(known) > 1:
            return _equivocation()
    resolver = value["resolverEvidence"]
    for name, receipts in writes.items():
        reference = _write_reference(terminal, name)
        receipt = receipts[0]
        if receipt["contentHash"] != reference["contentHash"]:
            return result("fail", "DRV-6", "qualified write does not bind the referenced artifact")
        if name == "decision" and resolver["decisionAnchor"] != {
            "substrate": "demos",
            "finalizedBlockTimestampSec": receipt["finalizedBlockTimestampSec"],
        }:
            return result("fail", "DRV-6", "decision ordering does not use the sole qualifying write")
    return None


def _transaction_valid(item: Any) -> bool:
    if not isinstance(item, dict) or set(item) != TRANSACTION_FIELDS:
        return False
    prior = item["priorNativeStatus"]
    return (
        isinstance(item["txHash"], str)
        and EVM_TX_RE.fullmatch(item["txHash"]) is not None
        and isinstance(item["entrypoint"], str)
        and re.fullmatch(r"0x[0-9a-f]{8}", item["entrypoint"]) is not None
        and isinstance(item["calldata"], dict)
        and all(
            isinstance(item[name], str) and EVM_ADDRESS_RE.fullmatch(item[name]) is not None
            for name in ("nativeCaller", "outerSubmitter")
        )
        and isinstance(item["nativeCallerAccountType"], str)
        and (prior is None or type(prior) is int)
        and type(item["nativeStatusAfter"]) is int
    )


def _prior_terminal_valid(item: Any) -> bool:
    if not isinstance(item, dict) or set(item) != PRIOR_TERMINAL_FIELDS:
        return False
    decision_hash = item["decisionHash"]
    return (
        type(item["chainId"]) is int
        and isinstance(item["contractAddress"], str)
        and EVM_ADDRESS_RE.fullmatch(item["contractAddress"]) is not None
        and isinstance(item["nativeJobId"], str)
        and UNSIGNED_DECIMAL_RE.fullmatch(item["nativeJobId"]) is not None
        and isinstance(item["txHash"], str)
        and EVM_TX_RE.fullmatch(item["txHash"]) is not None
        and type(item["logIndex"]) is int
        and item["logIndex"] >= 0
        and (
            decision_hash is None
            or (isinstance(decision_hash, str) and HASH_RE.fullmatch(decision_hash) is not None)
        )
    )


def _native_state_valid(state: Any) -> bool:
    if not isinstance(state, dict) or set(state) != NATIVE_STATE_FIELDS:
        return False
    adapter = state["evaluatorAdapter"]
    implementation = state["implementationAddress"]
    payout = state["preterminalProviderPayoutBaseUnits"]
    return (
        type(state["submissionCutoffEnforced"]) is bool
        and _is_unix_sec(state["expiryRecoveryAtSec"])
        and _amount_valid(payout)
        and all(
            type(state[name]) is int and state[name] >= 0
            for name in ("platformFeeBP", "evaluatorFeeBP")
        )
        and isinstance(state["evaluatorBindingMode"], str)
        and all(
            item is None or (isinstance(item, str) and EVM_ADDRESS_RE.fullmatch(item) is not None)
            for item in (adapter, implementation)
        )
        and all(
            isinstance(state[name], str) and CODE_HASH_RE.fullmatch(state[name]) is not None
            for name in ("escrowRuntimeBytecodeHash", "paymentTokenRuntimeBytecodeHash")
        )
    )


def _digest_anchor_valid(anchor: Any) -> bool:
    if anchor is None:
        return True
    return (
        isinstance(anchor, dict)
        and set(anchor) == DIGEST_ANCHOR_FIELDS
        and isinstance(anchor["deliverable"], str)
        and BYTES32_RE.fullmatch(anchor["deliverable"]) is not None
        and type(anchor["blockNumber"]) is int
        and anchor["blockNumber"] >= 0
        and _is_unix_sec(anchor["blockTimestampSec"])
    )


def _decision_anchor_valid(anchor: Any) -> bool:
    if anchor is None:
        return True
    return (
        isinstance(anchor, dict)
        and set(anchor) == DECISION_ANCHOR_FIELDS
        and anchor["substrate"] == "demos"
        and _is_unix_sec(anchor["finalizedBlockTimestampSec"])
    )


def _finding_check(value: dict[str, Any]) -> dict[str, str] | None:
    agreement = value["artifacts"]["agreement"]
    parties = {
        "seller-fault": agreement["seller"]["primaryClaim"],
        "buyer-fault": agreement["buyer"]["primaryClaim"],
    }
    for name in ("evaluation", "dispute"):
        artifact = value["artifacts"].get(name)
        if artifact is None:
            continue
        finding = artifact.get("finding")
        if not isinstance(finding, dict):
            return result("error", "DRV-3", f"{name} finding must be an object")
        classification = finding.get("classification")
        if (
            not {"classification", "rationaleCode"} <= set(finding) <= FINDING_FIELDS
            or not isinstance(classification, str)
            or classification not in FINDING_CLASSIFICATIONS
            or not isinstance(finding["rationaleCode"], str)
            or not finding["rationaleCode"]
            or ("faultedParty" in finding and parse_claim(finding["faultedParty"]) is None)
        ):
            return result("error", "DRV-3", f"{name} finding is not an exact AccountabilityFinding")
        # DRX-5: `faultedParty` is present only for a party fault, and names
        # that agreement party under CF-3 identity.
        if classification in parties:
            if claim_identity(finding.get("faultedParty")) != claim_identity(parties[classification]):
                return result("fail", "DRX-5", "faultedParty does not match the classified agreement party")
        elif "faultedParty" in finding:
            return result("fail", "DRX-6", "non-party-fault finding names a faulted party")
    return None


def _evaluation_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Re-derive the evaluation's result and finding under the bound rule (DRE-6, DRE-10).

    The candidate §6.2 matrix for `evaluator-judgement-v1`: every criterion
    satisfied is `accept`, any unsatisfied is `reject`, otherwise
    `indeterminate`, and each result permits its own findings.
    """
    artifacts = value["artifacts"]
    evaluation, rule = artifacts.get("evaluation"), artifacts.get("evaluationRule")
    if evaluation is None or rule is None:
        return None
    outcomes = evaluation.get("criterionResults")
    if not isinstance(outcomes, list) or not all(
        isinstance(item, dict) and set(item) == {"criterionId", "outcome"}
        and isinstance(item["criterionId"], str)
        and isinstance(item["outcome"], str) and item["outcome"] in CRITERION_OUTCOMES
        for item in outcomes
    ):
        return result("error", "DRV-3", "criterion results are not exact {criterionId, outcome} entries")
    if [item["criterionId"] for item in outcomes] != [criterion["criterionId"] for criterion in rule["criteria"]]:
        return result("fail", "DRE-10", "criterion results are not one per rule criterion, in rule order")
    observed = {item["outcome"] for item in outcomes}
    derived = "accept" if observed == {"satisfied"} else "reject" if "unsatisfied" in observed else "indeterminate"
    if evaluation["result"] != derived:
        return result("fail", "DRE-10", "the evaluation result contradicts its criterion outcomes")
    if evaluation["finding"]["classification"] not in RESULT_FINDINGS[derived]:
        return result("fail", "DRE-10", "the finding is not one the rule matrix permits for the result")
    return None


def _reference_check(value: dict[str, Any]) -> dict[str, str] | None:
    a = value["artifacts"]
    agreement = a["agreement"]
    job_id = agreement["jobId"]
    evaluator = agreement["evaluator"]["primaryClaim"]
    orchestrator = value["orchestratorClaim"]
    agreement_hash = artifact_hash(agreement)
    for name in ("job", "funding", "evaluation", "disputeCase", "dispute", "decision", "terminal"):
        artifact = a.get(name)
        if artifact is not None and artifact.get("deliveryOrRemedyAgreementHash") != agreement_hash:
            # Funding binds the exact overlay (DRF-1), and a dispute case the
            # outcome's (DRX-7); for every other artifact a valid signature
            # cannot override the overlay (DRV-4).
            return result(
                "fail", {"funding": "DRF-1", "disputeCase": "DRX-7"}.get(name, "DRV-4"),
                f"{name} binds another agreement overlay",
            )
    job_locator = logical_address(job_id, "job")
    # DRW-7: the funding and terminal evidence references are derived, so
    # every producer writes the same bytes: no `signer`, and a
    # storage-program anchor at a logical address, never a native one.  The
    # exact address and content hash are each reference's own check below.
    terminal = a["terminal"]
    derived = [
        ("funding escrow job", a["funding"].get("escrowJobRef")),
        ("terminal escrow job", terminal.get("escrowJobRef")),
        ("terminal funding evidence", terminal.get("fundingEvidenceRef")),
        ("terminal decision", terminal.get("decisionRef")),
        ("terminal delivery evidence", terminal.get("deliveryEvidenceRef")),
    ]
    for label, ref_value in derived:
        if not attestation_ref_shape_valid(ref_value):
            continue
        if "signer" in ref_value:
            return result("fail", "DRW-7", f"{label} reference carries a signer")
        if ref_value["anchor"]["kind"] != "storage-program":
            return result("fail", "DRW-7", f"{label} reference is not a storage-program anchor")
        # A Demos native address is `stor-` and 40 hex digits (DEMOS-MAPPING).
        if ref_value["anchor"]["locator"].startswith("stor-"):
            return result("fail", "DRW-7", f"{label} reference names a native address, not a logical one")
    for name, rule in (("funding", "DRF-1"), ("terminal", "DRT-4"), ("evaluation", "DRD-8"), ("decision", "DRD-8")):
        artifact = a.get(name)
        if artifact is not None:
            issue = _ref_check(artifact.get("escrowJobRef"), a["job"], job_locator, rule, f"{name} escrow job", (orchestrator,))
            if issue:
                return issue
    issue = _ref_check(
        a["terminal"].get("fundingEvidenceRef"), a["funding"], logical_address(job_id, "funding"),
        "DRT-11", "terminal funding evidence", (orchestrator,),
    )
    if issue:
        return issue
    if a.get("delivery") is not None:
        delivery_ref = a.get("deliveryRef")
        # PDE-2: DeliveryEvidence is anchored at dacs4:delivery:{jobId}:{phaseIndex}.
        issue = _ref_check(
            delivery_ref, a["delivery"], f"dacs4:delivery:{job_id}:{agreement['deliveryPhaseIndex']}",
            "DRE-2", "delivery evidence", (orchestrator,),
        )
        if issue:
            return issue
        delivery_issue = _delivery_evidence_check(value)
        if delivery_issue:
            return delivery_issue
        for name in ("evaluation", "decision"):
            artifact = a.get(name)
            if artifact is not None and canonical_bytes(artifact.get("deliveryEvidenceRef")) != canonical_bytes(delivery_ref):
                return result("fail", "DRD-3", f"{name} does not bind the exact delivery")
        if canonical_bytes(a["terminal"].get("deliveryEvidenceRef")) != canonical_bytes(delivery_ref):
            return result("fail", "DRT-12", "terminal delivery reference mismatch")
    elif a.get("decision") is not None and not _delivery_expected(value):
        # Without delivery there is nothing to release (DRD-3), and only a
        # DisputeOutcome can authorize the pre-submission refund (DRD-9).
        # Delivery evidence that is referenced but not supplied is decided
        # later as `indeterminate`.
        decision = a["decision"]
        basis = decision.get("basisRef")
        if decision.get("disposition") == "release-to-provider":
            return result("fail", "DRD-3", "a release decision has no delivery evidence to bind")
        elif not isinstance(basis, dict) or basis.get("kind") != "dispute-outcome":
            return result("fail", "DRD-9", "a decision without delivery evidence must rest on a DisputeOutcome")
    # A decision that a signed terminal references but the caller did not
    # supply is decided later as `indeterminate`; with no such reference, a
    # basis that no decision rests on is rejected.
    decision = a.get("decision")
    unsupplied_decision = decision is None and _decision_expected(a)
    if a.get("evaluation") is not None:
        evaluation = a["evaluation"]
        issue = _ref_check(
            a.get("evaluationRef"), evaluation,
            logical_address(job_id, f"evaluation:{evaluation['evaluationSeq']}"),
            "DRD-2", "evaluation", (evaluator,),
        )
        if issue:
            return issue
        if not unsupplied_decision and (decision is None or canonical_bytes(decision.get("basisRef")) != canonical_bytes({
            "kind": "execution-evaluation", "ref": a["evaluationRef"]
        })):
            return result("fail", "DRD-2", "decision basis does not resolve to the evaluation")
    elif a.get("dispute") is not None:
        dispute = a["dispute"]
        issue = _ref_check(
            a.get("disputeRef"), dispute,
            logical_address(job_id, f"dispute:{dispute['caseId']}:outcome:{dispute['revision']}"),
            "DRD-2", "DisputeOutcome", (evaluator,),
        )
        if issue:
            return issue
        if not unsupplied_decision and (decision is None or canonical_bytes(decision.get("basisRef")) != canonical_bytes({
            "kind": "dispute-outcome", "ref": a["disputeRef"]
        })):
            return result("fail", "DRD-2", "decision basis does not resolve to the dispute outcome")
        case = a.get("disputeCase")
        if case is not None:
            # DRX-7: the case at its own address, for the same case.
            issue = _ref_check(
                dispute.get("caseRef"), case, logical_address(job_id, f"dispute:{dispute['caseId']}:case"),
                "DRX-7", "dispute case", (agreement[case["openedByRole"]]["primaryClaim"],),
            )
            if issue:
                return issue
            if case["caseId"] != dispute["caseId"]:
                return result("fail", "DRX-7", "the dispute case is another case's")
    if decision is not None:
        # DRD-14: each decision stage has its own address.
        issue = _ref_check(
            a.get("decisionRef"), decision,
            logical_address(job_id, f"decision:{decision['decisionStage']}"),
            "DRD-4", "decision", (evaluator,),
        )
        if issue:
            return issue
        if canonical_bytes(a["terminal"].get("decisionRef")) != canonical_bytes(a["decisionRef"]):
            # DRT-1 for a release, DRT-2 for an evaluator refund.
            rule = "DRT-1" if a["terminal"]["terminalState"] == "released" else "DRT-2"
            return result("fail", rule, "terminal decision reference mismatch")
    return None


def _delivery_evidence_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Require the signed current DACS-4 `DeliveryEvidence` of the agreed delivery phase (DRP-7, DRE-2).

    PDE-2: its `jobId`, `phaseIndex`, and `phase` are the session job, the
    overlay's `deliveryPhaseIndex`, and that step's kind.  PDE-4: a success
    anchors the deliverable at `dacs4:deliverable:{jobId}:{phaseIndex}`.
    DRP-7: only a `success` may be submitted natively or support a release.
    """
    a = value["artifacts"]
    delivery = a["delivery"]
    agreement = a["agreement"]
    outcome = delivery.get("outcome")
    failed = outcome == "failure"
    members = DELIVERY_EVIDENCE_FIELDS | {"reason"} if failed else DELIVERY_EVIDENCE_FIELDS
    required = members - DELIVERABLE_FIELDS if failed else members
    content = delivery.get("deliverableContentHash")
    anchor = delivery.get("deliverableAnchor")
    if (
        not required <= set(delivery) <= members
        or not isinstance(outcome, str)
        or outcome not in DELIVERY_OUTCOMES
        or (failed and not (isinstance(delivery["reason"], str) and delivery["reason"]))
        or not isinstance(delivery["phase"], str)
        or ("deliverableContentHash" in delivery and not (
            isinstance(content, str) and HASH_RE.fullmatch(content) is not None
        ))
        or ("deliverableAnchor" in delivery and not (
            isinstance(anchor, dict)
            and set(anchor) == {"kind", "locator"}
            and all(isinstance(anchor[name], str) and anchor[name] for name in ("kind", "locator"))
        ))
    ):
        return result("error", "DRV-3", "delivery evidence is not an exact DACS-4 DeliveryEvidence")
    phase_index = agreement["deliveryPhaseIndex"]
    if delivery["phaseIndex"] != phase_index:
        return result("fail", "DRP-7", "delivery evidence is for another phase index than the overlay's delivery phase")
    if delivery["phase"] != value["pipeline"][phase_index]["kind"]:
        return result("fail", "DRE-2", "delivery evidence phase is not the agreed delivery step")
    if failed:
        return result("fail", "DRP-7", "a failure DeliveryEvidence cannot be submitted natively or support a release")
    if anchor != {"kind": "storage-program", "locator": f"dacs4:deliverable:{agreement['jobId']}:{phase_index}"}:
        return result("fail", "DRE-2", "deliverable anchor is not this phase's PDE-3 storage-program address")
    return None


def _subject_evidence_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Resolve every evaluation subject reference to authenticated evidence (DRE-3, DRE-5).

    A subject resolves when its locator names a lifecycle evidence record that
    this verifier has authenticated: the escrow job, the funding evidence, or
    the delivery evidence.  Both first-profile disclosure policies admit those
    published records.  Any other subject would need public resolution or an
    explicit-party supply proof (DRQ-2) that the fixture does not model, so it
    stays `indeterminate`.
    """
    a = value["artifacts"]
    evaluation = a.get("evaluation")
    # Each source reference was resolved exactly by an earlier stage.
    published = {
        ref_value["anchor"]["locator"]: (ref_value["anchor"]["kind"], artifact)
        for ref_value, artifact in (
            (a["funding"]["escrowJobRef"], a["job"]),
            (a["terminal"]["fundingEvidenceRef"], a["funding"]),
            (a.get("deliveryRef"), a.get("delivery")),
        )
        if artifact is not None
    }
    # An optional `signer` on any subject reference to one of those records
    # names that record's authenticated signer (DRV-6).
    for name in ("evaluation", "disputeCase", "dispute"):
        for ref_value in (a.get(name) or {}).get("subjectEvidenceRefs", []):
            record = published.get(ref_value["anchor"]["locator"])
            signature = record[1].get("signature") if record is not None else None
            if "signer" in ref_value and isinstance(signature, dict) and (
                claim_identity(ref_value["signer"]) != claim_identity(signature.get("signer"))
            ):
                return result("fail", "DRV-6", f"a {name} subject reference names a signer other than the record's")
    if evaluation is None:
        return None
    unresolved = False
    for ref_value in evaluation["subjectEvidenceRefs"]:
        record = published.get(ref_value["anchor"]["locator"])
        if record is None:
            unresolved = True
        elif ref_value["anchor"]["kind"] != record[0] or ref_value["contentHash"] != artifact_hash(record[1]):
            return result("fail", "DRE-3", "a subject reference contradicts the authenticated record at its locator")
    if unresolved:
        return result(
            "indeterminate", "DRE-5",
            "subject evidence does not resolve to authenticated evidence under the signed disclosure policy",
        )
    return None


def _external_evidence_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Apply resolver outcomes; the record was authenticated by an earlier stage."""
    resolver = value["resolverEvidence"]
    external = resolver["statuses"]
    artifacts = value["artifacts"]
    decision_applicable = artifacts["terminal"].get("terminalState") != "expired-refund"
    applicable = dict.fromkeys(EXTERNAL_EVIDENCE_FIELDS, True)
    applicable.update({
        "deliveryFinality": _delivery_expected(value),
        "decisionFinality": decision_applicable,
    })
    # An applicable status must not be `not-applicable`. An inapplicable one
    # must not vouch for or contradict evidence that does not exist. Its
    # `unavailable` asserts nothing, so it is not a DRV-6 contradiction, and
    # it withholds no required evidence (candidate §9 step 5): DRV-7 counts
    # only applicable checks.
    if any(
        external[name] == "not-applicable" if needed
        else external[name] not in {"not-applicable", "unavailable"}
        for name, needed in applicable.items()
    ) or (not decision_applicable and resolver["decisionAnchor"] is not None):
        # The statuses are the pinned resolver's authenticated output; the
        # applicable set comes from the signed terminal and delivery evidence.
        return result("fail", "DRV-6", "authenticated resolver status applicability contradicts the lifecycle")
    contradictory = sorted(name for name, state in external.items() if state == "contradictory")
    if contradictory:
        return result("fail", "DRV-6", "authenticated evidence contradicts: " + ", ".join(contradictory))
    unavailable = [
        name for name in UNAVAILABLE_STATUS_RULES
        if applicable[name] and external[name] == "unavailable"
    ]
    if unavailable:
        return result(
            "indeterminate",
            UNAVAILABLE_STATUS_RULES[unavailable[0]],
            "required external evidence unavailable: " + ", ".join(sorted(unavailable)),
        )
    return None


def _missing_record_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Keep a referenced record that the caller did not supply `indeterminate`.

    Candidate §9 step 5 and §11.3 cases I1 and I5: a missing evaluation rule,
    delivery, evaluation, decision, or dispute case with no contradictory fact
    established is `indeterminate`, not `fail`.  Earlier stages reject a
    reference that something present contradicts: a released or rejected
    terminal without a decision reference (DRT-1, DRT-2, DRD-2), delivery
    evidence on a lifecycle with no native submission (DRT-12), or a resolver
    record that marks the evidence not applicable (DRV-6).
    """
    a = value["artifacts"]
    if a.get("delivery") is None and _delivery_expected(value):
        return result("indeterminate", "DRE-5", "the delivery evidence the terminal references was not supplied")
    decision = a.get("decision")
    if decision is None and _decision_expected(a):
        return result("indeterminate", "DRD-4", "the decision the terminal references was not supplied")
    basis = decision.get("basisRef") if decision is not None else None
    supplied = {"execution-evaluation": a.get("evaluation"), "dispute-outcome": a.get("dispute")}
    if isinstance(basis, dict) and basis.get("kind") in supplied and supplied[basis["kind"]] is None:
        return result("indeterminate", "DRD-2", "the evaluation or DisputeOutcome the decision rests on was not supplied")
    if a.get("dispute") is not None and a.get("disputeCase") is None:
        return result("indeterminate", "DRX-7", "the dispute case the DisputeOutcome rests on was not supplied")
    if a.get("evaluationRule") is None:
        return result("indeterminate", "DRE-8", "the evaluation rule the overlay binds was not supplied")
    return None


def _delivery_binding_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Check the locator of the native submission event for a delivered lifecycle.

    The binding carries no ordering conclusion.  DRP-9 ordering comes from
    the resolver-authenticated submission observation and digest anchor.
    """
    binding = value.get("deliveryBinding")
    if not _delivery_expected(value):
        if binding is not None or value["resolverEvidence"]["deliveryDigestAnchor"] is not None:
            return result("fail", "DRP-9", "deliveryless path carries a native submission binding or digest anchor")
        return None
    if not isinstance(binding, dict) or set(binding) != {"nativeSubmissionEvent"}:
        return result("error", "DRV-3", "deliveryBinding must name only the native submission event")
    return None


def _event_ref_check(
    ref_value: Any, chain_id: Any, rule: str, label: str
) -> dict[str, str] | None:
    if not isinstance(ref_value, dict) or set(ref_value) != EVENT_REF_FIELDS:
        return result("error", "DRV-3", f"{label} event reference is malformed")
    tx_hash = ref_value.get("txHash")
    log_index = ref_value.get("logIndex")
    if type(log_index) is not int or log_index < 0:
        return result("error", "DRV-3", f"{label} event log index is not a non-negative integer")
    # DRW-3: the DACS-4 SB-1 spelling of `txHash`; any other spelling is
    # malformed and is not repaired.
    if not isinstance(tx_hash, str) or EVM_TX_RE.fullmatch(tx_hash) is None:
        return result("error", "DRW-3", f"{label} event transaction hash is not its SB-1 spelling")
    if ref_value.get("kind") != "evm-event" or ref_value.get("chainId") != chain_id:
        return result("fail", rule, f"{label} event reference is not an evm-event on the rail's chain")
    return None


def _event_identity(ref_value: Any) -> tuple[Any, Any, Any, Any] | None:
    if not isinstance(ref_value, dict):
        return None
    identity = (
        ref_value.get("kind"),
        ref_value.get("chainId"),
        ref_value.get("txHash"),
        ref_value.get("logIndex"),
    )
    # Used as a lookup key, where Python would take `false` for log index 0.
    if not all(isinstance(part, str) or type(part) is int for part in identity):
        return None
    return identity


def block_preimage(chain_id: int, number: int, timestamp_sec: int) -> str:
    """A fixture-chain block identity: a block is its chain, number, and timestamp."""
    return f"fixture-evm:{chain_id}:block:{number}:{timestamp_sec}"


def _block_valid(block: Any) -> bool:
    return (
        isinstance(block, dict)
        and BLOCK_FIELDS <= set(block)
        and type(block["blockNumber"]) is int
        and block["blockNumber"] >= 0
        and _is_unix_sec(block["blockTimestampSec"])
        and isinstance(block["blockHash"], str)
        and EVM_TX_RE.fullmatch(block["blockHash"]) is not None
        and isinstance(block["blockHashPreimageUtf8"], str)
    )


def _block_reproduces(block: dict[str, Any], chain_id: int) -> bool:
    preimage = block_preimage(chain_id, block["blockNumber"], block["blockTimestampSec"])
    return (
        block["blockHashPreimageUtf8"] == preimage
        and block["blockHash"] == "0x" + hashlib.sha256(preimage.encode("utf-8")).hexdigest()
    )


def _abi_values_valid(values: Any, inputs: list[dict[str, Any]]) -> bool:
    """Whether decoded calldata has exactly the pinned entrypoint's inputs, each of its type (DRC-18)."""
    return (
        isinstance(values, dict)
        and len(values) == len(inputs)
        and set(values) == {item["name"] for item in inputs}
        and all(abi_value_valid(item["type"], values[item["name"]]) for item in inputs)
    )


def decoded_log(observation: dict[str, Any], pin: dict[str, Any]) -> dict[str, Any] | None:
    """DRC-18: a log's inputs by name, read through its pinned `indexed` layout.

    Indexed inputs come from the topics after `topic0`, in order, and the
    others from the log data, in order.  None when the log does not fit the
    layout; it is then not decoded under any other.
    """
    topics, data = observation["indexedArguments"], observation["dataArguments"]
    indexed = [item for item in pin["inputs"] if item["indexed"]]
    unindexed = [item for item in pin["inputs"] if not item["indexed"]]
    if not isinstance(topics, list) or not isinstance(data, list) or (len(topics), len(data)) != (len(indexed), len(unindexed)):
        return None
    return {item["name"]: item_value for item, item_value in (*zip(indexed, topics), *zip(unindexed, data))}


def _event_pin(params: dict[str, Any], name: str) -> dict[str, Any]:
    return next(pin for pin in params["events"] if pin["name"] == name)


def _configuration_pin(params: dict[str, Any]) -> dict[str, Any]:
    """The DRC-21 configuration event's pin."""
    topic = params["configurationEvidence"]["eventTopic0"]
    return next(pin for pin in params["events"] if pin["topic0"] == topic)


def _native_event_input_check(
    value: dict[str, Any],
) -> tuple[dict[tuple[Any, Any, Any, Any], dict[str, Any]], dict[str, str] | None]:
    """Match the resolver's observations to the lifecycle's event references (DRF-8, DRC-18).

    Each signed event reference, the bound submission event of a delivered
    lifecycle, and the creation transaction's DRC-17 configuration event need
    exactly one observation, decoded under the rail's pinned `topic0`.  Event
    time, finality, and arguments are then read from those observations only.
    """
    inputs = value["reproductionInputs"]
    event_inputs = inputs.get("nativeEventInputs")
    if not isinstance(event_inputs, list) or not event_inputs:
        return {}, result("error", "DRV-3", "native event inputs must be a non-empty array")

    artifacts = value["artifacts"]
    params = artifacts["railDefinition"]["parameters"]
    chain_id = params["chainId"]
    funding_refs = artifacts["funding"].get("fundingEventRefs")
    terminal_refs = artifacts["terminal"].get("terminalEventRefs")
    # DRW-7: each list is exactly its transition's required events, in
    # ascending log order, from the one transaction that made it.
    if not isinstance(funding_refs, list) or len(funding_refs) != 1:
        return {}, result("fail", "DRW-7", "the funding event set is not the one JobFunded log")
    terminal_names = TERMINAL_EVENTS[artifacts["terminal"]["terminalState"]]
    if not isinstance(terminal_refs, list) or len(terminal_refs) != len(terminal_names):
        return {}, result("fail", "DRW-7", "the terminal event set is not the crosswalk's two logs")
    delivered = artifacts.get("delivery") is not None
    # (label, reference, event name, reference rule, block rule, depth rule)
    expected: list[tuple[str, Any, Any, str, str, str]] = [
        ("creation", artifacts["job"].get("creationEvent"), "JobCreated", "DRJ-2", "DRJ-2", "DRJ-2"),
        ("funding", funding_refs[0], "JobFunded", "DRF-3", "DRF-8", "DRF-6"),
    ]
    if delivered:
        expected.append((
            "submission", value["deliveryBinding"]["nativeSubmissionEvent"],
            "JobSubmitted", "DRP-9", "DRP-9", "DRP-9",
        ))
    expected += [
        (f"terminal-{index}", terminal_refs[index], name, "DRT-4", "DRT-8", "DRT-8")
        for index, name in enumerate(terminal_names)
    ]
    for label, ref_value, _name, reference_rule, _block_rule, _depth_rule in expected:
        issue = _event_ref_check(ref_value, chain_id, reference_rule, label)
        if issue:
            return {}, issue

    by_identity: dict[tuple[Any, Any, Any, Any], dict[str, Any]] = {}
    for event_input_value in event_inputs:
        if not isinstance(event_input_value, dict) or set(event_input_value) != EVENT_INPUT_FIELDS:
            return {}, result("error", "DRV-3", "native event input is malformed")
        identity = _event_identity(event_input_value["eventRef"])
        if identity is None:
            return {}, result("error", "DRV-3", "native event input identity is malformed")
        by_identity[identity] = event_input_value
    roles = {_event_identity(item[1]): item for item in expected}
    # The one observation no artifact references is the creation
    # transaction's configuration event.
    extra = [identity for identity in by_identity if identity not in roles]
    if (
        len(roles) != len(expected)
        or len(event_inputs) != len(expected) + 1
        or len(by_identity) != len(event_inputs)
        or len(extra) != 1
        or extra[0][2] != artifacts["job"]["creationEvent"]["txHash"]
    ):
        return {}, result("fail", "DRT-4", "native event inputs do not match the referenced event set")
    roles[extra[0]] = (
        "configuration", None, _configuration_pin(params)["name"], "DRJ-3", "DRJ-2", "DRJ-2",
    )

    pins = {pin["name"]: pin for pin in params["events"]}
    finality_blocks = params["finalityBlocks"]
    records: dict[str, dict[str, Any]] = {}
    blocks: dict[int, set[tuple[str, int]]] = {}
    for identity, event_input_value in by_identity.items():
        label, _ref_value, name, reference_rule, block_rule, _depth_rule = roles[identity]
        tx_preimage = event_input_value["txHashPreimageUtf8"]
        finality = event_input_value["finalityBlock"]
        if (
            not isinstance(tx_preimage, str)
            or not _block_valid(event_input_value)
            or not (finality is None or (_block_valid(finality) and set(finality) == BLOCK_FIELDS))
            or not isinstance(event_input_value["contractAddress"], str)
            or not isinstance(event_input_value["eventName"], str)
            or not isinstance(event_input_value["topic0"], str)
        ):
            return {}, result("error", "DRV-3", "native event observation is malformed")
        if event_input_value["eventRef"]["txHash"] != "0x" + hashlib.sha256(tx_preimage.encode("utf-8")).hexdigest():
            return {}, result("fail", reference_rule, "native event transaction preimage does not match")
        if not _block_reproduces(event_input_value, chain_id):
            return {}, result("fail", block_rule, "native event block identity does not reproduce")
        if event_input_value["eventName"] != name:
            # DRW-7: a funding or terminal reference list is in log order.
            rule = "DRW-7" if label == "funding" or label.startswith("terminal-") else "DRT-4"
            return {}, result("fail", rule, "native event names do not match the lifecycle")
        # DRC-18: a required log that does not match its pinned topic0 or
        # indexed layout is not decoded under any other.
        if event_input_value["topic0"] != pins[name]["topic0"]:
            return {}, result("fail", "DRC-18", "a required event does not match its pinned topic0")
        arguments = decoded_log(event_input_value, pins[name])
        if arguments is None:
            return {}, result("fail", "DRC-18", "a required event's topics or data do not fit its pinned layout")
        if not all(abi_value_valid(item["type"], arguments[item["name"]]) for item in pins[name]["inputs"]):
            return {}, result("error", "DRV-3", "decoded event data does not match the pinned event signature")
        if finality is not None:
            if not _block_reproduces(finality, chain_id):
                return {}, result("fail", block_rule, "finality block identity does not reproduce")
            # The Nth confirmation of an event at block n is block n + N - 1
            # (DACS-4 ChainFinalityProfile: confirmations = head - inclusion + 1).
            if finality["blockNumber"] != event_input_value["blockNumber"] + finality_blocks - 1:
                return {}, result("fail", block_rule, "finality block is not at the rail's confirmation depth")
            blocks.setdefault(finality["blockNumber"], set()).add((finality["blockHash"], finality["blockTimestampSec"]))
        blocks.setdefault(event_input_value["blockNumber"], set()).add(
            (event_input_value["blockHash"], event_input_value["blockTimestampSec"])
        )
        records[label] = event_input_value
    # DRF-8: one chain's blocks have one identity per height, and later
    # blocks are later in time.  A block time that contradicts the block
    # order is not authenticated chain time, wherever it appears.
    anchor = value["resolverEvidence"]["deliveryDigestAnchor"]
    if anchor is not None:
        blocks.setdefault(anchor["blockNumber"], set()).add((None, anchor["blockTimestampSec"]))
    heights = sorted(blocks)
    if any(len({timestamp for _hash, timestamp in blocks[height]}) != 1 for height in heights) or any(
        len({block_hash for block_hash, _timestamp in blocks[height]} - {None}) > 1 for height in heights
    ) or any(
        next(iter(blocks[earlier]))[1] >= next(iter(blocks[later]))[1]
        for earlier, later in zip(heights, heights[1:])
    ):
        return {}, result("fail", "DRF-8", "authenticated block times contradict the block order")
    for label, _ref_value, name, _reference_rule, _block_rule, depth_rule in expected:
        if records[label]["finalityBlock"] is None:
            return {}, result(
                "indeterminate", depth_rule,
                f"{name} event has not reached the rail finality depth",
            )
    if records["configuration"]["finalityBlock"] is None:
        return {}, result("indeterminate", "DRJ-2", "the configuration event has not reached the rail finality depth")
    ordered = [records["creation"], records["funding"]]
    if delivered:
        ordered.append(records["submission"])
    ordered.append(records["terminal-0"])
    if any(
        earlier["blockNumber"] >= later["blockNumber"]
        for earlier, later in zip(ordered, ordered[1:])
    ) or records["configuration"]["eventRef"]["txHash"] != records["creation"]["eventRef"]["txHash"] or any(
        records[f"terminal-{index}"]["eventRef"]["txHash"] != records["terminal-0"]["eventRef"]["txHash"]
        for index in range(len(terminal_names))
    ):
        return {}, result("fail", "DRT-4", "native event observations are not one ordered transaction each")

    funded_at = records["funding"]["blockTimestampSec"]
    if value["native"].get("fundedAtSec") != funded_at:
        return {}, result("fail", "DRA-9", "caller funding time differs from the authenticated event block")
    agreement = artifacts["agreement"]
    if (
        artifacts["terminal"]["terminalState"] == "expired-refund"
        and records["terminal-0"]["blockTimestampSec"] < agreement["evaluationDeadlineSec"]
    ):
        return {}, result("fail", "DREB-15", "expiry recovery executed before the evaluation deadline")
    if delivered:
        submitted = records["submission"]
        anchor_issue = _delivery_digest_anchor_check(artifacts["delivery"], anchor, submitted)
        if anchor_issue:
            return {}, anchor_issue
        if submitted["blockTimestampSec"] >= agreement["submissionCutoffSec"]:
            return {}, result("fail", "DREB-13", "native delivery was submitted at or after the cutoff")
    return by_identity, None


def _delivery_digest_anchor_check(
    delivery: dict[str, Any], anchor: Any, submission: dict[str, Any]
) -> dict[str, str] | None:
    """Require authenticated evidence that the delivery digest was fixed before submission (DRP-9).

    The pinned resolver attests the block in which the exact delivery digest
    was anchored.  A digest anchored in an earlier block than the native
    submission cannot contain or derive anything from that submission, whose
    transaction identity commits to the digest.  The verifier does not search
    the delivery for encodings of the submission.  The anchor record is a
    synthetic fixture boundary, not a normative proof shape.
    """
    if anchor is None:
        return result("indeterminate", "DRP-9", "no authenticated evidence fixes the delivery digest before the native submission")
    if anchor["deliverable"] != "0x" + artifact_hash(delivery):
        return result("fail", "DRP-9", "the anchored digest is not this delivery evidence")
    if anchor["blockNumber"] > submission["blockNumber"]:
        return result("fail", "DRP-9", "the delivery digest was fixed only after the native submission")
    if anchor["blockNumber"] == submission["blockNumber"]:
        return result("indeterminate", "DRP-9", "the digest anchor and the native submission share a block and cannot be ordered")
    if delivery["observedAt"] > anchor["blockTimestampSec"] * 1000:
        return result("fail", "DRP-9", "the delivery evidence records a time after its digest was fixed")
    return None


def _transactions_by_label(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The resolver's records of the creation, funding, submission, and terminal transactions."""
    a = value["artifacts"]
    labels = {a["job"]["creationEvent"]["txHash"]: "creation", a["funding"]["fundingEventRefs"][0]["txHash"]: "funding"}
    if value.get("deliveryBinding") is not None:
        labels[value["deliveryBinding"]["nativeSubmissionEvent"]["txHash"]] = "submission"
    labels[a["terminal"]["terminalEventRefs"][0]["txHash"]] = "terminal"
    return {labels[item["txHash"]]: item for item in value["resolverEvidence"]["transactions"] if item["txHash"] in labels}


def _native_transaction_check(
    value: dict[str, Any], observations: dict[tuple[Any, Any, Any, Any], dict[str, Any]],
) -> dict[str, str] | None:
    """Apply the candidate §4.1 crosswalk to the resolver's transaction records (DRL-10, DRL-11).

    Each lifecycle transaction is decoded only through the rail's pinned
    selectors (DRC-18), and its prior native status, entrypoint, caller, and
    emitted logs must form one crosswalk row, each row starting where the
    previous ended.  An evaluator action's caller is read from the
    transaction, never from an event's actor field (DREB-21).
    """
    a = value["artifacts"]
    params = a["railDefinition"]["parameters"]
    transactions = value["resolverEvidence"]["transactions"]
    by_label = _transactions_by_label(value)
    lifecycle = ["creation", "funding", *(["submission"] if a.get("delivery") is not None else []), "terminal"]
    if [item["txHash"] for item in transactions] != [by_label[label]["txHash"] for label in lifecycle if label in by_label] or list(by_label) != lifecycle:
        return result("fail", "DRL-10", "the resolver's transaction records are not the lifecycle's transactions")
    entrypoints = {pin["selector"]: pin["name"] for pin in params["entrypoints"]}
    entrypoint_inputs = {pin["name"]: pin["inputs"] for pin in params["entrypoints"]}
    statuses = {entry["nativeValue"]: entry["nativeStatus"] for entry in params["nativeStatusMap"]}
    accounts = role_accounts(a["agreement"])
    roles = {accounts["buyer"]: "client", accounts["seller"]: "provider", accounts["evaluator"]: "evaluator"}
    logs: dict[str, list[dict[str, Any]]] = {}
    for item in observations.values():
        logs.setdefault(item["eventRef"]["txHash"], []).append(item)
    previous = None
    for label in lifecycle:
        record = by_label[label]
        entrypoint = entrypoints.get(record["entrypoint"])
        if entrypoint is None:
            return result("fail", "DRC-18", "a lifecycle transaction does not call a pinned entrypoint selector")
        if not _abi_values_valid(record["calldata"], entrypoint_inputs[entrypoint]):
            return result("error", "DRV-3", "decoded calldata does not match the pinned entrypoint signature")
        prior = record["priorNativeStatus"]
        if (prior is not None and prior not in statuses) or record["nativeStatusAfter"] not in statuses:
            return result("fail", "DRL-2", "a native status is absent from the rail's nativeStatusMap")
        if label == "terminal" and entrypoint in ("complete", "reject"):
            account_type = record["nativeCallerAccountType"]
            if account_type not in EVALUATOR_ACCOUNT_TYPES:
                return result("error", "DREB-18", "unsupported evaluator account type")
            # DREB-18: this verifier supports no EIP-1271 chain and code.
            if account_type == "eip1271":
                return result("fail", "DREB-18", "this verifier supports no EIP-1271 evaluator account")
            if record["nativeCaller"] != accounts["evaluator"]:
                return result("fail", "DREB-21", "authenticated native caller is not the bound evaluator account")
            if record["outerSubmitter"] != record["nativeCaller"]:
                return result("fail", "DREB-22", "an EOA evaluator cannot have another transaction submitter")
        prior_status = None if prior is None else statuses[prior]
        role = roles.get(record["nativeCaller"])
        row = CROSSWALK.get((prior_status, entrypoint, role)) or CROSSWALK.get((prior_status, entrypoint, "any"))
        # The fixture emits a row's events in its listed order (README
        # "Fixture implementation ABI"); canonical ERC-8183 refunds first.
        emitted = tuple(item["eventName"] for item in sorted(logs.get(record["txHash"], []), key=lambda item: item["eventRef"]["logIndex"]))
        if (
            row is None
            or prior_status != previous
            or emitted != row[0]
            or statuses[record["nativeStatusAfter"]] != row[1]
        ):
            return result("fail", "DRL-11", "an authenticated transition is outside the candidate §4.1 crosswalk")
        # DRD-13: the evaluator's reject binds the expected prior status.
        if entrypoint == "reject" and int(record["calldata"]["expectedStatus"]) != prior:
            return result("fail", "DRD-13", "the reject call does not bind the expected prior native status")
        previous = row[1]
    return None


def _reproduction_input_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Validate every committed preimage needed to reconstruct fixture claims."""
    inputs = value.get("reproductionInputs")
    if not isinstance(inputs, dict):
        return result("error", "DRV-3", "reproductionInputs must be an object")
    required = {
        "publicTestSeedHex",
        "roleBundles",
        "vetRecords",
        "deliveredArtifact",
        "runtimeBytecode",
        "nativeEventInputs",
    }
    if set(inputs) != required:
        return result("error", "DRV-3", "reproduction input set is incomplete")
    pending = [inputs]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            if any("transcript" in str(key).lower() for key in current):
                return result("fail", "DRQ-3", "candidate inputs attempt to disclose transcript material")
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)

    event_inputs, event_issue = _native_event_input_check(value)
    if event_issue:
        return event_issue
    transaction_issue = _native_transaction_check(value, event_inputs)
    if transaction_issue:
        return transaction_issue

    seeds = inputs["publicTestSeedHex"]
    if not isinstance(seeds, dict) or set(seeds) != set(value["publicKeys"]):
        return result("error", "DRV-3", "public test seed set is incomplete")
    for claim, seed_hex in seeds.items():
        try:
            seed = bytes.fromhex(seed_hex)
            derived = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        except (TypeError, ValueError):
            return result("error", "DRV-3", "public test seed is malformed")
        if base64.urlsafe_b64encode(derived).decode("ascii").rstrip("=") != value["publicKeys"][claim]:
            return result("fail", "DRV-4", "public key does not derive from the committed test seed")

    agreement = value["artifacts"]["agreement"]
    bundles = inputs["roleBundles"]
    vet_records = inputs["vetRecords"]
    if not isinstance(bundles, dict) or not isinstance(vet_records, dict):
        return result("error", "DRV-3", "role source inputs must be objects")
    funding_ref = value["artifacts"]["funding"]["fundingEventRefs"][0]
    funded_at = event_inputs[_event_identity(funding_ref)]["blockTimestampSec"]
    for role in ("buyer", "seller", "evaluator"):
        binding = agreement[role]
        bundle = bundles.get(role)
        vet_record = vet_records.get(role)
        if not isinstance(bundle, dict) or binding.get("bundleHash") != artifact_hash(bundle):
            return result("fail", "DRA-4", f"{role} bundle input does not match the overlay")
        if not attestation_ref_valid(binding.get("vetRecordRef"), vet_record):
            return result("fail", "DRA-4", f"{role} Vet record input does not resolve")
        if (
            vet_record.get("subject") != binding.get("primaryClaim")
            or vet_record.get("bundleHash") != binding.get("bundleHash")
            or vet_record.get("result") != "pass"
            or type(vet_record.get("validFromSec")) is not int
            or type(vet_record.get("validUntilSec")) is not int
            or not vet_record["validFromSec"] <= funded_at <= vet_record["validUntilSec"]
        ):
            return result("fail", "DRA-9" if role == "evaluator" else "DRA-4", f"{role} Vet input is not a fresh pass at funding")
    evaluator = agreement["evaluator"]
    if inputs["vetRecords"]["evaluator"].get("requirementHash") != evaluator.get("requirementHash"):
        return result("fail", "DRA-8", "evaluator Vet input used another requirement")

    artifacts = value["artifacts"]
    delivered = inputs["deliveredArtifact"]
    if artifacts.get("delivery") is None:
        if delivered is not None:
            return result("fail", "DRP-7", "deliveryless path contains an unreferenced deliverable input")
    # DV-1: the deliverable content hash is the SHA-256 of the exact
    # delivered cleartext payload.
    elif (
        not isinstance(delivered, dict)
        or set(delivered) != {"payloadUtf8"}
        or not isinstance(delivered["payloadUtf8"], str)
        or artifacts["delivery"]["deliverableContentHash"]
        != hashlib.sha256(delivered["payloadUtf8"].encode("utf-8")).hexdigest()
    ):
        return result("fail", "DRE-2", "delivered payload input does not resolve")

    runtime = inputs["runtimeBytecode"]
    if not isinstance(runtime, dict) or set(runtime) != {"encoding", "value"} or runtime.get("encoding") != "hex":
        return result("error", "DRV-3", "runtime-bytecode input is malformed")
    runtime_value = runtime.get("value")
    if not isinstance(runtime_value, str) or re.fullmatch(r"(?:[0-9a-f]{2})+", runtime_value) is None:
        return result("error", "DRV-3", "runtime-bytecode input must be non-empty lower-case hex")
    # DRW-2: the code hash is keccak-256 of the deployed runtime bytecode.
    if artifacts["job"]["runtimeBytecodeHash"] != "0x" + keccak256(bytes.fromhex(runtime_value)).hex():
        return result("fail", "DRJ-5", "runtime bytecode does not hash to the job's pinned code hash")

    return None


def _native_event_semantics_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Compare the authenticated, pin-decoded logs and calldata with the signed artifacts they settle."""
    inputs = value["reproductionInputs"]["nativeEventInputs"]
    artifacts = value["artifacts"]
    agreement = artifacts["agreement"]
    job = artifacts["job"]
    terminal = artifacts["terminal"]
    params = artifacts["railDefinition"]["parameters"]
    transactions = _transactions_by_label(value)
    # DRC-20: every field is read from the pinned input of its name.
    logs = {item["eventName"]: decoded_log(item, _event_pin(params, item["eventName"])) for item in inputs}
    # DRJ-1: the job's numeric value is the creation event's job topic.
    if int(logs["JobCreated"]["jobId"]) != int(job["nativeJobId"]):
        return result("fail", "DRJ-1", "the creation event's job topic is not the job's native job ID")
    if any(
        item["contractAddress"] != job["contractAddress"]
        or int(logs[item["eventName"]]["jobId"]) != int(job["nativeJobId"])
        for item in inputs
    ):
        return result("fail", "DRT-4", "native event targets another contract or job")
    accounts = role_accounts(agreement)
    created = logs["JobCreated"]
    # DRJ-3: the creation event carries the job's parties, deadline, and
    # hook, each matching the overlay and rail.
    if (
        (created["client"], created["provider"], created["evaluator"])
        != (accounts["buyer"], accounts["seller"], accounts["evaluator"])
        or int(created["expiredAt"]) != agreement["evaluationDeadlineSec"]
        or created["hook"] != params["hook"]
    ):
        return result("fail", "DRJ-3", "the creation event does not match the overlay and rail")
    # DRC-21: the cutoff and policy word are read from the configuration
    # event at the pinned input indexes.
    configuration = params["configurationEvidence"]
    configuration_pin = _configuration_pin(params)
    configured = logs[configuration_pin["name"]]
    cutoff = configured[configuration_pin["inputs"][configuration["submissionCutoffInput"]]["name"]]
    policy = configured[configuration_pin["inputs"][configuration["preSubmissionPolicyInput"]]["name"]]
    if int(cutoff) != agreement["submissionCutoffSec"]:
        return result("fail", "DRC-21", "the configuration event's cutoff is not the signed submissionCutoffSec")
    if policy != configuration["preSubmissionPolicyValue"]:
        return result("fail", "DRC-21", "the configuration event's policy word is not the evaluator-rejection word")
    # DRJ-4: the description is decoded from the creating transaction's
    # createJob calldata, which also carries what the events report.
    calldata = transactions["creation"]["calldata"]
    if calldata["description"] != DESCRIPTION_PREFIX + artifact_hash(agreement):
        return result("fail", "DREB-1", "native job description is not the exact overlay binding")
    if (
        (calldata["provider"], calldata["evaluator"], calldata["hook"], calldata["expiredAt"])
        != (created["provider"], created["evaluator"], created["hook"], created["expiredAt"])
        or calldata["submissionCutoff"] != cutoff
    ):
        return result("fail", "DRV-6", "authenticated createJob calldata contradicts the creation events it emitted")
    if (logs["JobFunded"]["client"], logs["JobFunded"]["amount"]) != (accounts["buyer"], agreement["budgetBaseUnits"]):
        return result("fail", "DRF-3", "funding event does not lock the complete budget from the client")
    if artifacts.get("delivery") is not None:
        digest = "0x" + artifact_hash(artifacts["delivery"])
        # As an EVM transaction hash commits to its calldata, the synthetic
        # submission transaction identity commits to the submitted digest.
        submitted = next(item for item in inputs if item["eventName"] == "JobSubmitted")
        if (
            logs["JobSubmitted"]["deliverable"] != digest
            or transactions["submission"]["calldata"]["deliverable"] != digest
            or not submitted["txHashPreimageUtf8"].endswith(":" + digest)
        ):
            return result("fail", "DRP-9", "the submission event and its transaction do not commit to the delivery digest")
    state_event, transfer_event = TERMINAL_EVENTS[terminal["terminalState"]]
    transfer = logs[transfer_event]
    recipient = transfer["provider"] if transfer_event == "PaymentReleased" else transfer["client"]
    # DRT-4: the transfer log fixes one recipient and amount.
    if (recipient, transfer["amount"]) != (terminal["recipient"], terminal["amountBaseUnits"]):
        return result("fail", "DRT-4", "terminal transfer log does not match the claimed recipient and amount")
    decision = artifacts.get("decision")
    expected_reason = None if decision is None else "0x" + artifact_hash(decision)
    reasons = {logs[state_event].get("reason"), transactions["terminal"]["calldata"].get("reason")}
    if reasons != {expected_reason}:
        if ZERO_BYTES32 in reasons:
            return result("fail", "DREB-5", "zero decision reason is forbidden")
        return result("fail", "DREB-6", "the native reason is not the decision's content hash")
    return None


def _finality_check(
    evidence: dict[str, Any], finality_blocks: int, observation: dict[str, Any], label: str,
) -> dict[str, str] | None:
    """DRW-6: a signed block-depth record of the rail's depth, observed at the confirmation-depth block.

    For block-depth finality, `finalityObservedAt` is the block timestamp of
    the Nth confirmation (DACS-4 §9.5), which the resolver attests with the
    event; `observedAt` is the same chain time, so the record is a function of
    authenticated chain facts.
    """
    finality = evidence.get("finality")
    if not isinstance(finality, dict) or set(finality) != {
        "model", "finalityBlocks", "finalityObservedAt"
    }:
        return result("error", "DRV-3", f"{label} finality is not an exact DACS-4 block-depth record")
    if (
        type(finality.get("finalityBlocks")) is not int
        or finality["finalityBlocks"] <= 0
        or not _is_unix_ms(finality.get("finalityObservedAt"))
    ):
        return result("error", "DRV-3", f"{label} finality record is malformed")
    if finality.get("model") != "block-depth" or finality["finalityBlocks"] != finality_blocks:
        return result("fail", "DRW-6", f"{label} finality does not match the rail profile")
    observed_at = observation["finalityBlock"]["blockTimestampSec"] * 1000
    if finality["finalityObservedAt"] != observed_at:
        return result("fail", "DRW-6", f"{label} finality time is not its confirmation-depth block time")
    if evidence["observedAt"] != observed_at:
        return result("fail", "DRW-6", f"{label} observedAt is not its confirmation-depth block time")
    return None


def _ordering_bound_check(value: dict[str, Any], terminal_sec: int) -> dict[str, str] | None:
    """DRW-4 for the terminal side of the DRC-15 sums, which reads no decision anchor."""
    skew = value["artifacts"]["railDefinition"]["parameters"]["maxCrossSubstrateSkewMs"] + 1000
    if terminal_sec * 1000 + skew > SAFE_INTEGER_MAX:
        return result("error", "DRW-4", "the terminal side of a decision-ordering sum exceeds the safe-integer bound")
    return None


def _decision_ordering_check(value: dict[str, Any], terminal_sec: int) -> dict[str, str] | None:
    """DRC-15 and DRC-19: order the decision's finality before the terminal transaction.

    `decisionFinalizedAtMs` is the consensus timestamp of the Demos block that
    finalized the decision's anchor, in seconds times 1000; for its
    one-second granularity the skew bound widens by 1000 ms.  A self-reported
    time never orders the two (DRD-11).
    """
    bound = _ordering_bound_check(value, terminal_sec)
    if bound:
        return bound
    anchor = value["resolverEvidence"]["decisionAnchor"]
    if anchor is None:
        return result("indeterminate", "DRD-10", "no authenticated decision anchor orders the decision")
    skew = value["artifacts"]["railDefinition"]["parameters"]["maxCrossSubstrateSkewMs"] + 1000
    decided = anchor["finalizedBlockTimestampSec"] * 1000
    terminal = terminal_sec * 1000
    if decided + skew > SAFE_INTEGER_MAX:
        return result("error", "DRW-4", "a decision-ordering sum exceeds the safe-integer bound")
    if decided + skew < terminal:
        return None
    if decided > terminal + skew:
        return result("fail", "DRD-11", "authenticated evidence finalizes the decision after the terminal transaction")
    return result("indeterminate", "DRC-15", "the decision and terminal transaction cannot be ordered within the skew bound")


def _decision_ordering_stage(value: dict[str, Any], select: bool = True) -> dict[str, str] | None:
    """Order a decision terminal's decision before its terminal transaction (DRC-15).

    With ``select`` off only the terminal side's DRW-4 bound is checked: the
    rest reads a decision anchor, which rests on one selected write copy
    (see `_checked_lifecycle`).
    """
    if value["artifacts"].get("decision") is None:
        return None
    terminal = value["artifacts"]["terminal"]
    observed = {
        _event_identity(item["eventRef"]): item
        for item in value["reproductionInputs"]["nativeEventInputs"]
    }[_event_identity(terminal["terminalEventRefs"][0])]
    if not select:
        return _ordering_bound_check(value, observed["blockTimestampSec"])
    return _decision_ordering_check(value, observed["blockTimestampSec"])


def _resolver_ordered_address(value: dict[str, Any], ledger: DecisionLedger | None) -> str | None:
    """The decision address whose resolver anchor DRC-15 reads with no copy carried, or None.

    A lifecycle that carries no decision write orders the decision on the
    pinned resolver's own anchor.  That selects no copy, but rests on the
    one qualifying write at the decision address: once two writes are known
    there, neither is selected and DRC-15 is not evaluated (DRAA-4, I8), so
    this is None then too.
    """
    if value["artifacts"].get("decision") is None or "decision" in value["resolverEvidence"].get(
        "qualifiedArtifactWrites", {}
    ):
        return None
    reference = _write_reference(value["artifacts"]["terminal"], "decision")
    if not attestation_ref_shape_valid(reference):
        return None
    address = reference["anchor"]["locator"]
    if ledger is not None and ledger.equivocated_at(frozenset({address})):
        return None
    return address


def _native_and_terminal_check(value: dict[str, Any]) -> dict[str, str] | None:
    """Compare the native projection, resolved native state, and terminal evidence.

    Decision ordering (DRC-15) and the native event semantics follow as
    their own stages, in this order.
    """
    a = value["artifacts"]
    agreement = a["agreement"]
    rail = a["railDefinition"]
    params = rail["parameters"]
    native = value["native"]
    state = value["resolverEvidence"]["nativeState"]
    terminal = a["terminal"]
    terminal_state = terminal.get("terminalState")
    transactions = _transactions_by_label(value)
    statuses = {entry["nativeValue"]: entry["nativeStatus"] for entry in params["nativeStatusMap"]}
    # DRL-10, DRT-12: the pre/post-submission classification is the terminal
    # transaction's authenticated prior native status.
    submitted = statuses[transactions["terminal"]["priorNativeStatus"]] == "Submitted"
    history = native.get("portableStateHistory")
    if not isinstance(history, list) or not history:
        return result("error", "DRV-3", "portable state history must be a non-empty array")
    expected_history = [
        "created",
        "funded",
        *(["submitted"] if submitted else []),
        "released" if terminal_state == "released" else "refunded",
    ]
    if history != expected_history:
        if any(not isinstance(item, str) or item not in PORTABLE_STATES for item in history):
            return result("fail", "DRL-2", "native state cannot be mapped to one portable state")
        elif any(pair not in PORTABLE_TRANSITIONS for pair in zip(history, history[1:])):
            return result("fail", "DRL-4", "portable state history contains an invalid or reopened transition")
        else:
            return result("fail", "DRL-1", "portable state history does not match the authenticated transitions")
    if value.get("submittedBeforeCutoff") is not submitted:
        return result("fail", "DRT-12", "submission classification contradicts the authenticated prior native status")
    mapping_sources = value["mappingSources"]
    expected_sources = {"agreementHash": artifact_hash(agreement)}
    if a.get("delivery") is not None:
        expected_sources["deliveryHash"] = artifact_hash(a["delivery"])
    if a.get("decision") is not None:
        expected_sources["decisionHash"] = artifact_hash(a["decision"])
    if set(mapping_sources) != set(expected_sources):
        return result("error", "DRV-3", "mapping source set does not match the lifecycle")
    for name, expected_hash in expected_sources.items():
        declared_hash = mapping_sources[name]
        if declared_hash != expected_hash:
            if not isinstance(declared_hash, str) or HASH_RE.fullmatch(declared_hash) is None:
                return result("fail", "DREB-3", f"{name} is not 64 lowercase hexadecimal characters")
            else:
                return result("fail", "DREB-2", f"{name} does not match the recomputed artifact hash")

    accounts = role_accounts(agreement)
    if native.get("contractAddress") != a["job"].get("contractAddress"):
        return result("fail", "DRJ-2", "native contract address mismatch")
    if native.get("runtimeBytecodeHash") != a["job"].get("runtimeBytecodeHash"):
        return result("fail", "DRJ-5", "runtime bytecode hash mismatch")
    # DRJ-5, DRJ-11: the code the resolver found at every action block is the
    # pinned escrow code and payment-token code.  A delegating escrow needs
    # both implementation pins, and the resolver attests no implementation
    # code to compare with them, so it is never verified here.
    if state["escrowRuntimeBytecodeHash"] != a["job"]["runtimeBytecodeHash"]:
        return result("fail", "DRJ-5", "authenticated escrow code differs from the pinned runtime code")
    if state["paymentTokenRuntimeBytecodeHash"] != params["paymentTokenRuntimeBytecodeHash"]:
        return result("fail", "DRJ-11", "authenticated payment-token code differs from its pin")
    if state["implementationAddress"] != params.get("implementationAddress"):
        return result("fail", "DRJ-11", "the escrow delegates to an implementation the rail does not pin")
    if "implementationAddress" in params and "implementationRuntimeBytecodeHash" not in params:
        return result("fail", "DRJ-11", "a delegating escrow needs both implementation pins")
    if state["implementationAddress"] is not None:
        return result("indeterminate", "DRJ-11", "no authenticated implementation code is available to compare with its pin")
    if native.get("payoutReceiver") != accounts["seller"]:
        return result("fail", "DREB-10", "native payout receiver is not the bound seller account")

    cutoff = agreement["submissionCutoffSec"]
    deadline = agreement["evaluationDeadlineSec"]
    # Exact bytes: Python's `==` would take `false` for 0.
    if canonical_bytes(value["profileParameters"]) != canonical_bytes(params):
        return result("fail", "DRP-5", "detached profile projection differs from the authenticated rail")
    minimum = params["minimumEvaluationWindowSec"]
    if minimum <= 0:
        return result("fail", "DREB-14", "evaluation windows must be positive")
    elif deadline - cutoff < minimum:
        return result("fail", "DREB-14", "evaluation window is shorter than the pinned minimum")
    if native.get("submissionCutoffSec") != cutoff or state["submissionCutoffEnforced"] is not True:
        return result("fail", "DREB-13", "native submission cutoff is not separately enforced")
    if native.get("expiredAt") != deadline:
        return result("fail", "DREB-12", "native expiredAt is not the evaluation deadline")
    if state["expiryRecoveryAtSec"] != deadline:
        return result("fail", "DREB-15", "native expiry recovery is not bound to the evaluation deadline")

    if a.get("delivery") is not None:
        expected_deliverable = "0x" + expected_sources["deliveryHash"]
        provided = native.get("deliverable")
        if provided != expected_deliverable:
            if not isinstance(provided, str) or BYTES32_RE.fullmatch(provided) is None:
                return result("error", "DRV-3", "native deliverable is not canonical bytes32 text")
            elif provided == ZERO_BYTES32:
                return result("fail", "DREB-5", "zero deliverable is forbidden")
            else:
                return result("fail", "DREB-4", "deliverable is not the raw decoded content hash")
    elif native.get("deliverable") is not None:
        return result("fail", "DRT-12", "a deliveryless lifecycle cannot carry a native deliverable")

    funding = a["funding"]
    event_inputs = {
        _event_identity(item["eventRef"]): item
        for item in value["reproductionInputs"]["nativeEventInputs"]
    }
    funding_finality = _finality_check(
        funding, params["finalityBlocks"],
        event_inputs[_event_identity(funding["fundingEventRefs"][0])], "funding",
    )
    if funding_finality:
        return funding_finality
    budget = agreement["budgetBaseUnits"]
    token = params["paymentToken"]
    if native.get("amountBaseUnits") != budget or native.get("token") != token:
        return result("fail", "DREB-11", "native token or budget does not match the agreement rail")
    if funding.get("amountBaseUnits") != budget or funding.get("token") != token:
        return result("fail", "DRF-2", "funding token or complete budget mismatch")
    if funding.get("fundPhaseIndex") != agreement.get("fundPhaseIndex"):
        return result("fail", "DRF-1", "funding phase index mismatch")
    if state["preterminalProviderPayoutBaseUnits"] != "0":
        return result("fail", "DRL-7", "provider received value before terminal release")
    if state["platformFeeBP"] != params["platformFeeBP"] or state["evaluatorFeeBP"] != params["evaluatorFeeBP"]:
        return result("fail", "DRT-7", "escrow fee is nonzero")

    decision = a.get("decision")
    evaluation = a.get("evaluation")
    dispute = a.get("dispute")
    action = native.get("terminalAction")
    if terminal.get("amountBaseUnits") != budget or terminal.get("token") != token:
        return result("fail", "DRT-5", "terminal token or amount is not the complete budget")
    if native.get("terminalState") != terminal_state:
        return result("fail", "DRT-4", "native and DACS terminal states diverge")
    if terminal.get("terminalPhaseIndex") != agreement.get("terminalPhaseIndex"):
        return result("fail", "DRT-15", "terminal phase index is not the overlay's")
    terminal_observation = event_inputs[_event_identity(terminal["terminalEventRefs"][0])]
    terminal_finality = _finality_check(terminal, params["finalityBlocks"], terminal_observation, "terminal")
    if terminal_finality:
        return terminal_finality

    projection = value.get("reputationProjection")
    if (
        not isinstance(projection, dict)
        or set(projection) != PROJECTION_FIELDS
        or not all(
            projection[field] is None or (isinstance(projection[field], str) and projection[field] in PROJECTED_OUTCOMES)
            for field in ("buyerAnchoredOutcome", "sellerAnchoredOutcome")
        )
        or not isinstance(projection["faultedParty"], str)
        or projection["faultedParty"] not in PROJECTED_FAULTS
        or type(projection["releaseAloneEstablishesNonFinancialCompletion"]) is not bool
    ):
        return result("error", "DRV-3", "reputation projection is malformed")
    # DRT-14: the projection is recomputed from the authenticated terminal
    # state and finding.  An expiry's seller fault needs the seller not to
    # have submitted; a pair the table does not list projects no fault.
    finding_artifact = evaluation if evaluation is not None else dispute
    classification = finding_artifact["finding"]["classification"] if finding_artifact is not None else None
    if classification is None or (terminal_state == "expired-refund" and classification == "seller-fault" and submitted):
        expected_projection = NO_PROJECTION
    else:
        expected_projection = PROJECTION_TABLE.get((terminal_state, classification), NO_PROJECTION)
    if (
        projection["buyerAnchoredOutcome"], projection["sellerAnchoredOutcome"], projection["faultedParty"]
    ) != expected_projection:
        if decision is None:
            return result("fail", "DRT-13", "decisionless expiry projects a fault no authenticated finding establishes")
        else:
            return result("fail", "DRT-14", "caller projection contradicts the projection table")

    if decision is not None:
        expected_reason = "0x" + expected_sources["decisionHash"]
        provided_reason = native.get("reason")
        if provided_reason != expected_reason:
            if not isinstance(provided_reason, str) or BYTES32_RE.fullmatch(provided_reason) is None:
                return result("error", "DRV-3", "native decision reason is not canonical bytes32 text")
            elif provided_reason == ZERO_BYTES32:
                return result("fail", "DREB-5", "zero decision reason is forbidden")
            else:
                return result("fail", "DREB-4", "reason is not the raw decoded decision hash")
        if state["evaluatorBindingMode"] != "direct":
            return result("fail", "DREB-16", "native evaluator is not bound directly")
        if state["evaluatorAdapter"] is not None:
            return result("fail", "DREB-20", "generic evaluator adapters are outside the profile")
        disposition = decision.get("disposition")
        stage = decision["decisionStage"]
        # DRD-14: the stage matches the delivery reference and the terminal
        # transaction's prior native status, and a release is post-submission.
        if (stage == "pre-submission") != ("deliveryEvidenceRef" not in decision):
            return result("fail", "DRD-14", "the decision stage contradicts its delivery reference")
        # A release binds its delivery (DRD-3), so this also makes every
        # release decision post-submission.
        if stage != ("post-submission" if submitted else "pre-submission"):
            return result("fail", "DRD-14", "the decision stage contradicts the terminal transaction's prior native status")
        if evaluation is not None:
            evaluation_result = evaluation.get("result")
            if evaluation_result == "indeterminate":
                return result("fail", "DRE-4", "indeterminate evaluation cannot authorize a terminal action")
            elif SETTLEMENT_AUTHORIZATIONS.get(evaluation_result) != disposition:
                return result("fail", "DRD-2", "evaluation result does not authorize the decision disposition")
        elif dispute is not None:
            # DRX-9: the current revision recommends exactly the decision's
            # disposition, and the dispute-outcome table permits it for the
            # finding at this stage.
            if "recommendedDisposition" not in dispute:
                return result("fail", "DRX-9", "a DisputeOutcome basis carries no recommended disposition")
            if dispute["recommendedDisposition"] != disposition:
                return result("fail", "DRX-9", "the decision disposition is not the recommended disposition")
            if DISPUTE_DISPOSITIONS.get(classification) != disposition:
                return result("fail", "DRX-9", "the dispute-outcome table does not permit this disposition for the finding")
            if dispute["revision"] != 0 and "supersedesOutcomeRef" not in dispute:
                return result("fail", "DRAA-7", "a later dispute revision does not reference the prior revision")
            if "supersedesOutcomeRef" in dispute:
                return result("indeterminate", "DRAA-7", "prior dispute revisions are not resolved by this pack")
        else:
            # DRD-2: a basis naming neither artifact resolves to nothing.
            return result("fail", "DRD-2", "decision has no authenticated evaluation or dispute basis")
        # The shape stage closed the disposition set to these two values.
        if disposition == "release-to-provider":
            if terminal_state != "released" or action != "complete":
                return result("fail", "DRD-5", "release decision maps to a non-release action")
            if terminal.get("disposition") != disposition or terminal.get("recipient") != accounts["seller"]:
                return result("fail", "DRT-5", "release recipient or disposition mismatch")
            if projection["releaseAloneEstablishesNonFinancialCompletion"]:
                return result(
                    "fail",
                    "DRL-6",
                    "financial release overclaims non-financial completion",
                )
        else:
            if terminal_state != "rejected-refund" or action != "reject":
                return result("fail", "DRD-6", "refund decision maps to a non-rejection action")
            if terminal.get("disposition") != disposition or terminal.get("recipient") != accounts["buyer"]:
                return result("fail", "DRT-6", "refund recipient or disposition mismatch")
    else:
        if terminal_state != "expired-refund" or action != "claimRefund":
            return result("fail", "DRT-3", "decisionless terminal action is not expiry refund")
        if "decisionRef" in terminal or native.get("reason") is not None:
            return result("fail", "DRD-7", "expiry recovery manufactures an evaluator decision")
        if terminal.get("disposition") != "refund-to-client" or terminal.get("recipient") != accounts["buyer"]:
            return result("fail", "DRT-6", "expiry refund recipient mismatch")
        if submitted != ("deliveryEvidenceRef" in terminal):
            return result("fail", "DRT-12", "expiry delivery-reference presence does not match submission state")
    return None


def _attested_terminals(value: dict[str, Any]) -> list[TerminalRecord]:
    """The resolver-attested earlier terminals for this native job or decision."""
    return [
        TerminalRecord(
            job=(item["chainId"], item["contractAddress"], item["nativeJobId"]),
            event=(item["chainId"], item["txHash"], item["logIndex"]),
            decision=item["decisionHash"],
        )
        for item in value["resolverEvidence"]["priorTerminals"]
    ]


def _terminal_record(value: dict[str, Any]) -> TerminalRecord:
    artifacts = value["artifacts"]
    job = artifacts["job"]
    ref_value = artifacts["terminal"]["terminalEventRefs"][0]
    decision = artifacts.get("decision")
    observed = next(
        item for item in value["reproductionInputs"]["nativeEventInputs"]
        if _event_identity(item["eventRef"]) == _event_identity(ref_value)
    )
    return TerminalRecord(
        job=(job["chainId"], job["contractAddress"], job["nativeJobId"]),
        event=(ref_value["chainId"], ref_value["txHash"], ref_value["logIndex"]),
        decision=None if decision is None else artifact_hash(decision),
        position=(observed["blockNumber"], ref_value["logIndex"]),
        attested=tuple(sorted({prior[:3] for prior in _attested_terminals(value)}, key=repr)),
        evidence=artifact_hash(artifacts["terminal"]),
    )


def _terminal_replay_check(
    current: TerminalRecord, ledger: DecisionLedger
) -> dict[str, str] | None:
    """Compare this terminal with every conflicting terminal (DRD-8, DRL-4, DRT-4).

    The pinned resolver attests `priorTerminals` as the complete set of
    earlier terminals for this native job or decision, so a conflict with one
    is rejected.  For a terminal in the verifier's ledger, the earlier of two
    conflicting terminals is chosen by authenticated event position, and the
    later one is rejected.  The pair stays `indeterminate` when the positions
    cannot order it, or when the later terminal's attested history omits the
    earlier one: the resolver's records then contradict each other.  One
    event claimed by two native jobs is ambiguous whichever came first.
    The finding depends only on ``current`` and the ledger's terminals.
    """
    for prior in current.attested:
        conflict = terminal_conflict(TerminalRecord(*prior), current)
        if conflict:
            return result("fail", *conflict)
    undecided = []
    for other in ledger.terminals():
        conflict = terminal_conflict(other, current)
        if conflict is None:
            continue
        # One event claimed by two jobs, or one terminal with two evidence
        # records, is a conflict whichever came first.
        precedes = True if conflict[0] in ("DRT-4", "DRT-16") else terminal_precedes(other, current)
        if precedes is None:
            undecided.append((conflict[0], "authenticated event positions cannot order this terminal against a conflicting terminal"))
        elif not precedes and current[:3] not in other.attested:
            undecided.append((conflict[0], "a later conflicting terminal's attested history omits this terminal"))
        elif precedes:
            return result("fail", *conflict)
    if undecided:
        return result("indeterminate", *undecided[0])
    return None


def _protocol_stages(
    value: dict[str, Any], ledger: DecisionLedger | None = None, select: bool = True,
) -> tuple[tuple[str, Callable[[], dict[str, str] | None]], ...]:
    """Return the section 9 checks in order; the first finding is the result.

    A later gate is added as one more named stage at its place in this order;
    it reads the same authenticated inputs and needs no change to other stages.
    The replay comparison follows these stages, in `evaluate_lifecycles`.
    Only the write-selection stage reads ``ledger``, and no stage writes it.
    ``select`` off removes the checks that select one qualifying write copy:
    the write-selection stage, and decision ordering (DRC-15) apart from
    its terminal-side DRW-4 bound.
    """
    return (
        ("artifact-shape", lambda: _artifact_shape_check(value["artifacts"])),
        ("rail", lambda: _rail_check(value)),
        ("pipeline", lambda: _pipeline_check(value)),
        ("agreement", lambda: _agreement_check(value)),
        ("component-signatures", lambda: _component_signature_check(value)),
        ("selected-rail", lambda: _selected_rail_check(value)),
        ("evaluation-rule", lambda: _evaluation_rule_check(value)),
        ("references", lambda: _reference_check(value)),
        ("resolver-evidence", lambda: _resolver_evidence_check(value)),
        ("artifact-writes", lambda: _artifact_write_check(value)),
        ("write-selection", lambda: _write_selection_check(value, ledger, select)),
        ("finding", lambda: _finding_check(value)),
        ("evaluation", lambda: _evaluation_check(value)),
        ("canonical-records", lambda: _canonical_record_check(value)),
        ("delivery-binding", lambda: _delivery_binding_check(value)),
        ("resolver-statuses", lambda: _external_evidence_check(value)),
        ("missing-records", lambda: _missing_record_check(value)),
        ("reproduction-inputs", lambda: _reproduction_input_check(value)),
        ("native-and-terminal", lambda: _native_and_terminal_check(value)),
        ("decision-ordering", lambda: _decision_ordering_stage(value, select)),
        ("native-event-semantics", lambda: _native_event_semantics_check(value)),
        ("subject-evidence", lambda: _subject_evidence_check(value)),
    )


# The stages whose finding can rest on one selected qualifying write copy.
SELECTING_STAGES = ("write-selection", "decision-ordering")


class LifecycleCheck(NamedTuple):
    """One lifecycle's checks before the replay comparison.

    ``issue`` is the finding, or None.  ``revisable`` is true when the issue
    rests on a selected write copy, or is uncertainty decided at or after the
    write-selection stage: two qualifying writes known later, at one of
    ``addresses`` (None: every address the terminal references), decide
    DRAA-4 instead.  A deterministic `error` or `fail` is never revisable.
    ``records`` is true when every check that does not select a write copy
    passed and no finding rests on a copy that can still be selected: the
    issue is None or DRAA-4.  The lifecycle's terminal then takes part in
    the replay comparison.  ``pending`` is true when every such check passed
    but the issue rests on a copy that can still be selected: the terminal
    is recorded once the issue is revised to DRAA-4 and two writes are known
    at ``blocker`` too, when it names an address.
    """

    issue: dict[str, str] | None
    revisable: bool = False
    records: bool = False
    pending: bool = False
    addresses: frozenset[str] | None = None
    blocker: str | None = None


def _input_check(value: Any) -> dict[str, str] | None:
    """Candidate §9 steps 1 and 2 for one lifecycle, before any stage."""
    if not isinstance(value, dict):
        return result("error", "DRV-3", "vector input must be an object")
    # Candidate §9 step 2 before any stage hashes or compares a number.  The
    # depth bound keeps the recursive hashing from exhausting the stack.
    if not nesting_within(value, MAX_JSON_DEPTH):
        return result("error", "DRV-3", f"input nests deeper than {MAX_JSON_DEPTH} arrays and objects")
    if not number_profile_valid(value):
        return result("error", "DRV-3", "a number is non-finite or outside the CORE §B.2 safe-integer range")
    required = {
        "candidateProfile", "fixtureOnly", "pipeline", "artifacts", "publicKeys",
        "orchestratorClaim", "evaluatorVetResult", "profileParameters", "native",
        "resolverEvidence", "mappingSources", "canonicalRecords", "deliveryBinding",
        "bundleRequiredSigners", "reputationProjection", "submittedBeforeCutoff",
        "reproductionInputs",
        "executionContext",
    }
    if not required.issubset(value):
        return result("error", "DRV-3", "vector input is missing required fields")
    if value.get("candidateProfile") != "delivery-or-remedy-v1" or value.get("fixtureOnly") is not True:
        return result("error", "DRV-1", "only offline candidate-profile fixtures are accepted")
    object_fields = (
        "artifacts", "publicKeys", "profileParameters", "mappingSources",
        "canonicalRecords", "native", "resolverEvidence",
    )
    if not all(isinstance(value.get(field), dict) for field in object_fields):
        return result("error", "DRV-3", "candidate object fields are malformed")
    # Compared with `==` later, where Python would take 8453.0 for 8453.
    if any(
        type(value["native"].get(name)) is not int
        for name in ("chainId", "fundedAtSec", "submissionCutoffSec", "expiredAt")
    ):
        return result("error", "DRV-3", "native chain ID and times must be integers")
    return None


def _checked_lifecycle(value: Any, ledger: DecisionLedger | None = None) -> LifecycleCheck:
    """Apply every check before the replay comparison to one lifecycle.

    The finding depends on ``value`` and on the qualifying writes ``ledger``
    retained.  An `error` or `fail` from a check that selects no write copy
    is decided first, wherever its stage (candidate §9, FV-10): no later
    write changes it, so it is not revisable.  When the first finding comes
    from a check that selects a copy, the remaining checks run with
    selection off; one of them replaces it only with an `error` or `fail`
    (including the malformed-input `error` of a check that raises), and
    otherwise they only decide whether the terminal is recorded.

    Decision ordering on the resolver's own anchor (no decision write
    carried, one or none known) rests on the decision address alone: its
    `error` or `fail` replaces a write-selection finding and is revised
    only by two writes there, and its uncertainty keeps the terminal
    unrecorded until two writes are known there.
    """
    issue = _input_check(value)
    if issue:
        return LifecycleCheck(issue)
    revisable = False
    decided: dict[str, str] | None = None
    addresses: frozenset[str] | None = None
    blocker: str | None = None
    unselected = dict(_protocol_stages(value, ledger, select=False))
    for name, stage in _protocol_stages(value, ledger):
        revisable = revisable or name == "write-selection"
        if decided is not None:
            fixed = unselected[name]()
        else:
            issue = stage()
            fixed = unselected[name]() if issue and name in SELECTING_STAGES else issue
        address = _resolver_ordered_address(value, ledger) if name == "decision-ordering" and not fixed else None
        if address is not None:
            ordered = stage() if decided is not None else issue
            if ordered and ordered["result"] in ("error", "fail"):
                decided, addresses = ordered, frozenset({address})
            elif ordered:
                decided, blocker = decided or ordered, address
        elif decided is None and issue and not fixed:
            decided = issue
        if not fixed:
            continue
        if fixed["result"] in ("error", "fail"):
            return LifecycleCheck(fixed)
        # Uncertainty after a finding that rests on a copy keeps that finding.
        return LifecycleCheck(decided or issue, revisable, addresses=addresses)
    if decided is None or (decided["rule"] == "DRAA-4" and blocker is None):
        return LifecycleCheck(decided, revisable, records=True)
    return LifecycleCheck(decided, revisable, pending=True, addresses=addresses, blocker=blocker)


def _lifecycle_check(value: Any, ledger: DecisionLedger | None = None) -> dict[str, str] | None:
    """The first finding of `_checked_lifecycle`, or None."""
    return _checked_lifecycle(value, ledger).issue


def _contained_lifecycle_check(value: Any, ledger: DecisionLedger | None = None) -> LifecycleCheck:
    """Apply `_checked_lifecycle`, keeping a malformed value that raises its own `error`.

    The shape stages decide every known malformed input first.  This keeps
    any value they miss inside the four results, and keeps it from failing
    the other lifecycles of a batch.
    """
    try:
        return _checked_lifecycle(value, ledger)
    except MALFORMED_INPUT_ERRORS as exc:
        return LifecycleCheck(result("error", "DRV-3", f"malformed input could not be read ({type(exc).__name__})"))


def _settled_verdict(terminal: TerminalRecord, ledger: DecisionLedger) -> dict[str, str]:
    """The verdict for a lifecycle that passed every check, against everything ``ledger`` holds.

    When the ledger holds two distinct qualifying writes at a logical
    address this terminal's evidence references, the artifact there cannot
    be selected (DRAA-4, CORE §5.1), whichever inputs carried the two writes
    and whether or not this one carried either.  A terminal conflict that
    `fail`s rests on no write copy and decides first (candidate §9, FV-10);
    DRAA-4 then comes before an unordered conflict and before `pass`.
    """
    replay = _terminal_replay_check(terminal, ledger)
    if replay and replay["result"] == "fail":
        return replay
    return (
        (_equivocation() if ledger.equivocated(terminal) else None)
        or replay
        or result("pass", "DRV-7", "all applicable candidate checks passed")
    )


def _held_verdict(
    finding: dict[str, str], addresses: frozenset[str], terminal: TerminalRecord | None,
    ledger: DecisionLedger,
) -> dict[str, str]:
    """The verdict for a revisable ``finding`` (see `LifecycleCheck`), against everything ``ledger`` holds.

    As in `_settled_verdict`, a recorded terminal's replay `fail` decides
    first, and two qualifying writes at one of ``addresses`` then replace
    the finding with DRAA-4.
    """
    replay = _terminal_replay_check(terminal, ledger) if terminal is not None else None
    if replay and replay["result"] == "fail":
        return replay
    return _equivocation() if ledger.equivocated_at(addresses) else finding


def _revise_issued(ledger: DecisionLedger) -> list[dict[str, Any]]:
    """Re-judge every verdict issued earlier against the terminals and writes now known.

    A terminal or write recorded later can contradict a verdict already
    issued: the pinned resolver's records for two terminals, or two
    qualifying writes at one logical address, can disagree, and the second
    record may arrive after the first verdict.  Each changed verdict is
    replaced in the ledger and returned as a revision, including one for a
    terminal evaluated again in this call: an earlier verdict may have been
    issued to another lifecycle with the same terminal.  A held verdict
    (see `LifecycleCheck`) is judged again by `_held_verdict`: DRAA-4 once
    two writes are known at an address its finding rests on, or the
    replay `fail` of its recorded terminal; that revision names the
    lifecycle's content hash.  A held finding revised to DRAA-4 records its
    pending terminal, and every verdict is judged again until no terminal
    is added; each revision then gives the verdict issued before this call
    as `previous`.  Recording a terminal or a write only adds
    conflicts, so a revision never upgrades a verdict, except that DRAA-4
    replaces a `pass`, an uncertainty, or a finding that rested on a write
    copy it makes unselectable.  A deterministic `error` or `fail` is never
    revised to DRAA-4.
    """
    issued = [(terminal, ledger.issued(terminal)) for terminal in ledger.terminals()]
    held = [(lifecycle, entry.verdict) for lifecycle, entry in ledger.held()]
    added = True
    while added:
        added = False
        for terminal in ledger.terminals():
            if ledger.issued(terminal) is not None:
                ledger.issue(terminal, _settled_verdict(terminal, ledger))
        for lifecycle, entry in ledger.held():
            revised = _held_verdict(entry.finding, entry.addresses, entry.terminal, ledger)
            if entry.pending is not None and revised["rule"] == "DRAA-4" and all(
                ledger.equivocated_at(frozenset({address})) for address in entry.blocker
            ):
                ledger.record(entry.pending, entry.written)
                entry, added = entry._replace(terminal=entry.pending, pending=None), True
            ledger.hold(lifecycle, entry._replace(verdict=revised))
    revisions = []
    for terminal, previous in issued:
        if previous is not None and ledger.issued(terminal) != previous:
            revisions.append({"terminal": terminal_identity(terminal), "previous": previous, **ledger.issued(terminal)})
    current = dict(ledger.held())
    for lifecycle, previous in held:
        if current[lifecycle].verdict != previous:
            revisions.append({"lifecycle": lifecycle, "previous": previous, **current[lifecycle].verdict})
    return revisions


def evaluate_lifecycles(values: list[Any], ledger: DecisionLedger) -> list[dict[str, Any]]:
    """Evaluate lifecycles together against verifier-owned replay state.

    Every lifecycle that passes the checks before the replay comparison that
    do not select a write copy first records its terminal in ``ledger``,
    whatever that comparison will decide.  Each is then compared with every
    terminal the ledger holds, so the verdicts do not depend on the order of
    ``values``.  Verifying the same terminal again is idempotent.

    A verdict holds for the evidence evaluated so far.  When this call changes
    a verdict the ledger issued in an earlier call, every result it returns
    lists the change under `revises`: the terminal, or for a verdict decided
    before the replay comparison the lifecycle's content hash, its
    `previous` verdict, and the verdict that replaces it.  A revision
    applies to every verdict issued for that terminal or lifecycle that
    equals `previous`.  Applying the revisions to the verdicts already
    issued gives the verdicts of evaluating everything seen so far as one
    set, whatever the arrival order.

    The qualifying writes of every lifecycle in ``values`` are retained
    before any lifecycle is checked, so two writes carried by different
    lifecycles, in one call or in several, are an equivocation as when one
    lifecycle carries both (DRAA-4): no lifecycle referencing that address
    selects either copy, and a verdict that rested on one is revised.  A
    deterministic `error` or `fail`, including a recorded terminal's replay
    `fail`, comes before DRAA-4 and stays as decided (candidate §9, FV-10).
    """
    if not isinstance(ledger, DecisionLedger):
        raise TypeError("evaluate_lifecycles requires a verifier-owned DecisionLedger")
    for value in values:
        try:
            _retain_qualified_writes(value, ledger)
        except MALFORMED_INPUT_ERRORS:
            pass  # `_contained_lifecycle_check` decides this value's `error`.
    checks = [_contained_lifecycle_check(value, ledger) for value in values]
    terminals = [
        _terminal_record(value) if check.records or check.pending else None for value, check in zip(values, checks)
    ]
    for value, check, terminal in zip(values, checks, terminals):
        if check.records:
            ledger.record(terminal, _write_addresses(value["artifacts"]["terminal"]))
    revisions = _revise_issued(ledger)
    verdicts: list[dict[str, Any]] = []
    for value, check, terminal in zip(values, checks, terminals):
        if check.issue is None:
            verdict = _settled_verdict(terminal, ledger)
            ledger.issue(terminal, verdict)
        elif check.revisable and (terminal is not None or check.issue["rule"] != "DRAA-4"):
            written = _write_addresses(value["artifacts"]["terminal"])
            entry = HeldFinding(
                written if check.addresses is None else check.addresses,
                terminal if check.records else None, check.issue, check.issue,
                terminal if check.pending else None, written,
                frozenset() if check.blocker is None else frozenset({check.blocker}),
            )
            verdict = _held_verdict(entry.finding, entry.addresses, entry.terminal, ledger)
            ledger.hold(content_hash(value), entry._replace(verdict=verdict))
        else:
            verdict = check.issue
        verdicts.append({**verdict, "revises": revisions} if revisions else verdict)
    return verdicts


def evaluate_protocol(value: Any, ledger: DecisionLedger) -> dict[str, Any]:
    """Evaluate one lifecycle against the terminals ``ledger`` already holds.

    The verdict uses the evidence known at the time.  With the resolver's
    complete attested history it does not depend on arrival order.  When the
    resolver's records contradict an earlier verdict, the result lists that
    verdict's revision under `revises` (see `evaluate_lifecycles`).
    """
    if not isinstance(ledger, DecisionLedger):
        raise TypeError("evaluate_protocol requires a verifier-owned DecisionLedger")
    return evaluate_lifecycles([value], ledger)[0]


def _status(values: list[Any], predicate) -> str:
    if any(value is None for value in values):
        return "unknown"
    return "pass" if predicate(*values) else "fail"


def deployment_rule_statuses(manifest: Any) -> dict[str, str] | None:
    if not isinstance(manifest, dict):
        return None
    capabilities = manifest.get("capabilities")
    evidence = manifest.get("evidence")
    if not isinstance(capabilities, dict) or not isinstance(evidence, dict):
        return None

    statuses: dict[str, str] = {}
    paths = capabilities.get("preterminalProviderPayoutPaths")
    statuses["DRC-1"] = "unknown" if paths is None else ("pass" if paths == [] else "fail")

    fee_values = [
        capabilities.get("platformFeeBP"), capabilities.get("evaluatorFeeBP"),
        capabilities.get("feeMutationAuthorities"),
    ]
    statuses["DRC-2"] = _status(
        fee_values,
        lambda platform, evaluator, authorities: (
            type(platform) is int and platform == 0
            and type(evaluator) is int and evaluator == 0
            and authorities == []
        ),
    )

    recovery_values = [
        capabilities.get("expiryRecoveryPauseGated"),
        capabilities.get("expiryRecoveryHookGated"),
        capabilities.get("evaluatorCanBlockExpiryRecovery"),
        capabilities.get("pendingClaimCanDelayFundedRecovery"),
    ]
    statuses["DRC-3"] = _status(
        recovery_values,
        lambda *items: all(type(item) is bool and item is False for item in items),
    )

    alternate = capabilities.get("lockedFundAlternateWithdrawalAuthorities")
    statuses["DRC-4"] = "unknown" if alternate is None else ("pass" if alternate == [] else "fail")

    replacement_values = [
        capabilities.get("logicReplacementAuthorities"),
        capabilities.get("hookMutable"),
    ]
    statuses["DRC-5"] = _status(
        replacement_values,
        lambda authorities, mutable: authorities == [] and type(mutable) is bool and mutable is False,
    )

    syntactic = capabilities.get("upgradeableSyntactically")
    if syntactic is None:
        statuses["DRC-6"] = "unknown"
    elif type(syntactic) is bool and syntactic is False:
        statuses["DRC-6"] = "pass"
    elif type(syntactic) is bool:
        disabled = capabilities.get("upgradeAuthorityIrreversiblyDisabled")
        proof = evidence.get("upgradeDisablementAuthenticated")
        statuses["DRC-6"] = _status([disabled, proof], lambda left, right: left is True and right is True)
    else:
        statuses["DRC-6"] = "fail"

    # DRC-7: the per-job hook is the zero address and none can be attached
    # later, so an immutable non-zero hook fails too.
    hook_mode = capabilities.get("hookMode")
    statuses["DRC-7"] = "unknown" if hook_mode is None else (
        "pass" if hook_mode == "absent" else "fail"
    )

    token = capabilities.get("paymentTokenSemantics")
    token_flags = (
        "transferFees", "rebasing", "callbacks", "pause", "blacklist", "upgradeable",
        "externalBalanceMutation",
    )
    if not isinstance(token, dict) or any(token.get(name) is None for name in token_flags) or token.get("independentlyVerified") is None:
        statuses["DRC-8"] = "unknown"
    else:
        statuses["DRC-8"] = "pass" if (
            all(type(token[name]) is bool and token[name] is False for name in token_flags)
            and type(token["independentlyVerified"]) is bool
            and token["independentlyVerified"] is True
        ) else "fail"

    event_complete = capabilities.get("eventIdentityComplete")
    statuses["DRC-9"] = "unknown" if event_complete is None else (
        "pass" if type(event_complete) is bool and event_complete is True else "fail"
    )

    source_values = [
        evidence.get("sourceRevision"), evidence.get("compilerSettingsHash"),
        evidence.get("runtimeBytecodeHash"), evidence.get("independentlyResolvedRuntimeBytecodeHash"),
        evidence.get("sourceToBytecodeReproducible"),
    ]
    statuses["DRC-10"] = _status(
        source_values,
        lambda source, compiler, runtime, resolved, reproducible: (
            isinstance(source, str) and bool(source)
            and isinstance(compiler, str) and HASH_RE.fullmatch(compiler) is not None
            and isinstance(runtime, str) and HASH_RE.fullmatch(runtime) is not None
            and runtime == resolved and type(reproducible) is bool and reproducible is True
        ),
    )

    complete = evidence.get("complete")
    conflict = evidence.get("conflict")
    statuses["DRC-11"] = _status(
        [complete, conflict],
        lambda is_complete, has_conflict: (
            type(is_complete) is bool and is_complete is True
            and type(has_conflict) is bool and has_conflict is False
        ),
    )

    ordering_values = [
        capabilities.get("decisionOrderingProfile"),
        evidence.get("decisionOrderingEvidenceAuthenticated"),
    ]
    statuses["DRC-12"] = _status(
        ordering_values,
        lambda profile, authenticated: (
            isinstance(profile, str) and bool(profile)
            and type(authenticated) is bool and authenticated is True
        ),
    )
    deadline_values = [
        capabilities.get("deadlineProfile"),
        capabilities.get("submissionCutoffEnforced"),
        capabilities.get("expiryRecoveryDeadlineEnforced"),
        evidence.get("deadlineEnforcementAuthenticated"),
    ]
    # A native deadline known to be unenforced already violates DRC-13;
    # unresolved companion facts cannot turn that into "unknown".
    if any(value is False for value in deadline_values[1:3]):
        statuses["DRC-13"] = "fail"
    else:
        statuses["DRC-13"] = _status(
            deadline_values,
            lambda profile, cutoff, recovery, authenticated: (
                profile == "separate-submission-cutoff-v1"
                and type(cutoff) is bool and cutoff is True
                and type(recovery) is bool and recovery is True
                and type(authenticated) is bool and authenticated is True
            ),
        )
    return statuses


def evaluate_deployment(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        return {
            **result("error", "DRV-3", "deployment manifest must be an object"),
            "ruleStatuses": {},
            "registrationEligible": False,
        }
    required = {
        "manifestVersion", "candidateProfile", "fixtureOnly", "registrationStatus",
        "implementation", "capabilities", "evidence",
    }
    if not required.issubset(manifest) or not number_profile_valid(manifest):
        return {
            **result("error", "DRV-3", "malformed deployment manifest"),
            "ruleStatuses": {},
            "registrationEligible": False,
        }
    if manifest.get("manifestVersion") != "1":
        return {
            **result("error", "DRV-2", "unsupported deployment manifest version"),
            "ruleStatuses": {},
            "registrationEligible": False,
        }
    if manifest.get("candidateProfile") != "dacs-delivery-gate-v1":
        return {
            **result("error", "DRV-2", "unsupported deployment capability profile"),
            "ruleStatuses": {},
            "registrationEligible": False,
        }
    if type(manifest.get("fixtureOnly")) is not bool:
        return {
            **result("error", "DRV-3", "fixtureOnly must be boolean"),
            "ruleStatuses": {},
            "registrationEligible": False,
        }
    statuses = deployment_rule_statuses(manifest)
    if statuses is None or set(statuses) != DRC_RULES:
        return {
            **result("error", "DRV-3", "could not derive every DRC rule"),
            "ruleStatuses": {},
            "registrationEligible": False,
        }
    failed = sorted(
        (rule for rule, status in statuses.items() if status == "fail"),
        key=lambda item: int(item.split("-")[1]),
    )
    unknown = sorted(
        (rule for rule, status in statuses.items() if status == "unknown"),
        key=lambda item: int(item.split("-")[1]),
    )
    if failed:
        outcome: dict[str, Any] = result("fail", failed[0], "failed deployment rules: " + ", ".join(failed))
    elif unknown:
        outcome = result("indeterminate", unknown[0], "unresolved deployment rules: " + ", ".join(unknown))
    else:
        outcome = result("pass", "DRC-1..DRC-13", "all candidate deployment capability rules passed")
    outcome["ruleStatuses"] = statuses
    # Capability predicates come from the manifest itself.  Its own
    # fixtureOnly and registrationStatus labels cannot establish eligibility;
    # registration needs independently resolved deployment and registry facts
    # that this evaluator does not have, so it never reports eligibility.
    outcome["registrationEligible"] = False
    return outcome


def _pack_hash(pack: dict[str, Any], fields: tuple[str, ...]) -> str:
    return hashlib.sha256(canonical_bytes({field: pack[field] for field in fields})).hexdigest()


def verify_vector_pack(pack: Any) -> list[str]:
    # Before anything copies or hashes the pack, as `load_json` checks a file.
    if not nesting_within(pack, MAX_JSON_DEPTH):
        return [f"candidate vector pack: {TOO_DEEP}"]
    if not isinstance(pack, dict):
        return ["candidate vector pack must be an object"]
    required = {
        "kind", "status", "spec", "generator", "sourcePins", "hash", "count", "fixtures",
        "vectors", "promotionBlockedRules", "promotionBlockedProofs",
    }
    if not required.issubset(pack):
        return ["candidate vector pack is missing required top-level fields"]
    pins = pack["sourcePins"]
    dacs = pins.get("dacs") if isinstance(pins, dict) else None
    if (
        not isinstance(dacs, dict)
        or set(pins) != {"external", "dacs"}
        or pins["external"] != EXTERNAL_SOURCE_PINS
        or set(dacs) != {"checkedAgainst", "documents"}
        or dacs["checkedAgainst"] != DACS_CHECKED_AGAINST
        or not isinstance(dacs["documents"], dict)
        or set(dacs["documents"]) != set(PINNED_DOCUMENTS)
    ):
        return ["candidate vector pack source pins are not the verifier's"]
    current = document_pins()
    if current is None:
        return [f"cannot read spec/ at the Checked-against commit {DACS_CHECKED_AGAINST[:7]}; fetch full history"]
    changed = [path for path in PINNED_DOCUMENTS if dacs["documents"][path] != current[path]]
    if changed:
        return [
            f"pinned document {path} differs from "
            + ("the checkout" if path == PINNED_DOCUMENTS[0] else f"its text at {DACS_CHECKED_AGAINST[:7]}")
            for path in changed
        ]
    errors: list[str] = []
    vectors = pack.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        return ["candidate vector pack must contain vectors"]
    if pack.get("count") != len(vectors):
        errors.append("candidate vector count is stale")
    if pack.get("hash") != _pack_hash(
        pack, ("fixtures", "vectors", "promotionBlockedRules", "promotionBlockedProofs")
    ):
        errors.append("candidate vector pack hash is stale")
    # `promotionBlockedRules` are not executed at all.  `promotionBlockedProofs`
    # are executed against a synthetic evidence shape whose normative proof
    # shape is still undefined.
    for field in ("promotionBlockedRules", "promotionBlockedProofs"):
        blocked = pack.get(field)
        if not isinstance(blocked, dict) or not all(
            isinstance(rule, str)
            and isinstance(reason, str)
            and bool(reason.strip())
            for rule, reason in blocked.items()
        ):
            errors.append(f"{field} must map rule IDs to non-empty reasons")
    if isinstance(pack["promotionBlockedRules"], dict) and isinstance(pack["promotionBlockedProofs"], dict):
        blocked_rules = set(pack["promotionBlockedRules"]) | set(pack["promotionBlockedProofs"])
        if set(pack["promotionBlockedRules"]) & set(pack["promotionBlockedProofs"]):
            errors.append("a rule cannot be both unexecuted and proof-blocked")
        # A `pass` vector's rules are the rules it proves; a rule whose proof
        # is blocked is never among them.
        claimed = {
            rule
            for vector in vectors
            if isinstance(vector, dict) and vector.get("expected") == "pass" and isinstance(vector.get("rules"), list)
            for rule in vector["rules"]
            if isinstance(rule, str)
        }
        if claimed & blocked_rules:
            errors.append(
                "a pass vector claims a promotion-blocked rule: " + ", ".join(sorted(claimed & blocked_rules))
            )
    names: set[str] = set()
    by_name: dict[str, dict[str, Any]] = {}
    for vector in vectors:
        name = vector.get("name") if isinstance(vector, dict) else None
        if not isinstance(name, str) or not name or name in names:
            errors.append(f"invalid or duplicate candidate vector name: {name!r}")
            continue
        names.add(name)
        by_name[name] = vector
        rules = vector.get("rules")
        if (
            not isinstance(rules, list)
            or not rules
            or any(not isinstance(rule, str) for rule in rules)
            or rules != sorted(set(rules))
        ):
            errors.append(f"{name}: rules must be a non-empty sorted unique list")
        # Each vector is an independent verifier run.  `evaluatedWith` names
        # earlier vectors evaluated together with it, as one set.
        companions = vector.get("evaluatedWith", [])
        if not isinstance(companions, list) or any(
            companion not in by_name or companion == name for companion in companions
        ):
            errors.append(f"{name}: evaluatedWith must name earlier vectors")
            continue
        try:
            observed = evaluate_lifecycles(
                [materialize_vector(pack, by_name[companion]) for companion in companions]
                + [materialize_vector(pack, vector)],
                DecisionLedger(),
            )[-1]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            errors.append(f"{name}: could not materialize: {exc}")
            continue
        if observed.get("result") != vector.get("expected"):
            errors.append(
                f"{name}: expected {vector.get('expected')!r}, got {observed.get('result')!r} "
                f"({observed.get('rule')}: {observed.get('detail')})"
            )
        expected_rule = vector.get("expectedRule")
        if expected_rule is not None and observed.get("rule") != expected_rule:
            errors.append(f"{name}: expected rule {expected_rule}, got {observed.get('rule')}")
    return errors


def verify_deployment_pack(pack: Any) -> list[str]:
    if not nesting_within(pack, MAX_JSON_DEPTH):
        return [f"deployment capability pack: {TOO_DEEP}"]
    if not isinstance(pack, dict):
        return ["deployment capability pack must be an object"]
    required = {"kind", "status", "spec", "sourcePins", "hash", "count", "manifests", "cases"}
    if not required.issubset(pack):
        return ["deployment capability pack is missing required top-level fields"]
    errors: list[str] = []
    cases = pack.get("cases")
    manifests = pack.get("manifests")
    if not isinstance(cases, list) or not cases or not isinstance(manifests, dict):
        return ["deployment capability pack needs manifests and cases"]
    if pack.get("count") != len(cases):
        errors.append("deployment capability case count is stale")
    if pack.get("hash") != _pack_hash(pack, ("manifests", "cases")):
        errors.append("deployment capability pack hash is stale")
    names: set[str] = set()
    for case in cases:
        name = case.get("name") if isinstance(case, dict) else None
        if not isinstance(name, str) or not name or name in names:
            errors.append(f"invalid or duplicate deployment case name: {name!r}")
            continue
        names.add(name)
        rules = case.get("rules")
        if (
            not isinstance(rules, list)
            or any(not isinstance(rule, str) for rule in rules)
            or rules != sorted(set(rules))
        ):
            errors.append(f"{name}: rules must be a sorted unique list")
        base = case.get("base")
        if base not in manifests:
            errors.append(f"{name}: unknown manifest base {base!r}")
            continue
        manifest = copy.deepcopy(manifests[base])
        try:
            for operation in case.get("patch", []):
                manifest = apply_operation(manifest, operation)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            errors.append(f"{name}: could not materialize: {exc}")
            continue
        observed = evaluate_deployment(manifest)
        if observed["result"] != case.get("expected"):
            errors.append(
                f"{name}: expected {case.get('expected')!r}, got {observed['result']!r} "
                f"({observed['rule']}: {observed['detail']})"
            )
        if observed["registrationEligible"] != case.get("registrationEligible", False):
            errors.append(f"{name}: registration eligibility was not fail-closed")
        expected_failed = case.get("expectedFailedRules")
        if expected_failed is not None:
            actual_failed = sorted(
                (rule for rule, status in observed["ruleStatuses"].items() if status == "fail"),
                key=lambda item: int(item.split("-")[1]),
            )
            if actual_failed != expected_failed:
                errors.append(f"{name}: expected failed rules {expected_failed}, got {actual_failed}")
        expected_unknown = case.get("expectedUnknownRules")
        if expected_unknown is not None:
            actual_unknown = sorted(
                (rule for rule, status in observed["ruleStatuses"].items() if status == "unknown"),
                key=lambda item: int(item.split("-")[1]),
            )
            if actual_unknown != expected_unknown:
                errors.append(f"{name}: expected unknown rules {expected_unknown}, got {actual_unknown}")
    return errors


def _parse_safe_int(text: str) -> int:
    number = int(text)
    if abs(number) > SAFE_INTEGER_MAX:
        raise ValueError(f"integer {text} is outside the CORE §B.2 safe-integer range")
    return number


def _reject_constant(text: str) -> Any:
    raise ValueError(f"{text} is not a JSON number (CORE §B.2)")


def load_json(path: Path) -> Any:
    """Parse JSON in the CORE §B.2 number profile: no NaN, no Infinity, no unsafe integer.

    Nesting is bounded by MAX_JSON_DEPTH.  Whether `json.loads` refuses a deep
    text depends on the interpreter (3.12 raises RecursionError; 3.13 and later
    can parse it), so the bound is checked on the parsed value, and both ways
    give the same error.
    """
    text = path.read_text(encoding="utf-8")
    try:
        value = json.loads(text, parse_int=_parse_safe_int, parse_constant=_reject_constant)
    except RecursionError:
        raise ValueError(TOO_DEEP) from None
    if not nesting_within(value, MAX_JSON_DEPTH):
        raise ValueError(TOO_DEEP)
    return value


def _display_path(path: Path) -> str:
    """A relative path as the caller gave it; an absolute one in the checkout, repository-relative."""
    if not path.is_absolute():
        return str(path)
    resolved = path.resolve()
    return str(resolved.relative_to(ROOT)) if resolved.is_relative_to(ROOT) else str(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTOR_PACK)
    parser.add_argument("--deployments", type=Path, default=DEFAULT_DEPLOYMENT_PACK)
    args = parser.parse_args(argv)
    errors: list[str] = []
    packs: list[Any] = []
    for path, verifier in (
        (args.vectors, verify_vector_pack),
        (args.deployments, verify_deployment_pack),
    ):
        try:
            pack = load_json(path)
        except FileNotFoundError:
            errors.append(f"{path}: file not found")
            continue
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"{path}: cannot read: {exc}")
            continue
        except ValueError as exc:  # json.JSONDecodeError, or outside the number or depth profile
            errors.append(f"{path}: invalid JSON: {exc}")
            continue
        packs.append(pack)
        errors.extend(f"{_display_path(path)}: {message}" for message in verifier(pack))
    if errors:
        print("delivery-or-remedy candidate verification failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    vector_pack, deployment_pack = packs
    print(
        "verified delivery-or-remedy candidate packs: "
        f"{vector_pack['count']} lifecycle/mapping case(s), "
        f"{deployment_pack['count']} deployment case(s); no rail registered"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
