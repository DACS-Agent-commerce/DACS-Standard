#!/usr/bin/env python3
"""Generate deterministic non-normative delivery-or-remedy candidate packs."""
from __future__ import annotations

import argparse
import ast
import base64
import copy
import hashlib
import json
import string
import sys
import types
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from jcs import canonicalize as jcs_canonicalize
except ModuleNotFoundError:  # imported as scripts.generate_* by another tool
    from scripts.jcs import canonicalize as jcs_canonicalize
# The fixture implementation's ABI, keccak-256, and the source pins are the
# verifier's: the pack is generated against exactly what it decodes.
try:
    import verify_delivery_remedy_candidate_vectors as verifier
except ModuleNotFoundError:  # imported as scripts.generate_* by another tool
    from scripts import verify_delivery_remedy_candidate_vectors as verifier


ROOT = Path(__file__).resolve().parents[1]
VECTOR_OUTPUT = ROOT / "conformance/fixtures/delivery-remedy/candidate-vectors-v0.1.json"
DEPLOYMENT_OUTPUT = ROOT / "conformance/fixtures/delivery-remedy/deployment-capabilities-v0.1.json"
VERIFIER_PATH = ROOT / "scripts/verify_delivery_remedy_candidate_vectors.py"

JOB_A = "01J8ME0SXKQ4T9V2RC5HJ6WX7D"
JOB_B = "01J8ME0SXKQ4T9V2RC5HJ6WX7E"
CASE_A = "01J8ME0SXKQ4T9V2RC5HJ6WX7F"
# Each base lifecycle is its own job, so the positives never contend for one
# native job's terminal state.
LIFECYCLE_JOBS = {
    "release": JOB_A,
    "rejected-refund": "01J8ME0SXKQ4T9V2RC5HJ6WX7G",
    "pre-submission-rejected-refund": "01J8ME0SXKQ4T9V2RC5HJ6WX7H",
    "expired-pre": "01J8ME0SXKQ4T9V2RC5HJ6WX7J",
    "expired-post": "01J8ME0SXKQ4T9V2RC5HJ6WX7K",
}
# The other positives are further jobs of their own.
SIGNED_REF_JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX7P"
FAULTED_ALIAS_JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX7Q"
CLAIM_PARAMETER_JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX7R"
MIXED_CASE_JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX7S"
ZERO_NATIVE_JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX7T"
UPPER_CASE_JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX7V"
BUYER_FAULT_JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX7W"
SUBSTRATE_FAILURE_JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX7X"
NO_FAULT_REJECTION_JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX7Y"
DISPUTE_RELEASE_JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX7Z"
POST_SUBMISSION_DISPUTE_JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX80"
# A later expiry recovery is another terminal observation, so it is another
# job's: one terminal transaction reproduces one evidence hash (DRT-16).
LATE_RECOVERY_JOB = "01J8ME0SXKQ4T9V2RC5HJ6WX81"
NATIVE_JOB_IDS = {
    JOB_A: "1",
    JOB_B: "2",
    **{
        job_id: str(index)
        for index, job_id in enumerate(list(LIFECYCLE_JOBS.values())[1:], start=3)
    },
    SIGNED_REF_JOB: "10",
    FAULTED_ALIAS_JOB: "11",
    CLAIM_PARAMETER_JOB: "12",
    MIXED_CASE_JOB: "13",
    # DRJ-1 admits job 0.
    ZERO_NATIVE_JOB: "0",
    UPPER_CASE_JOB: "14",
    BUYER_FAULT_JOB: "15",
    SUBSTRATE_FAILURE_JOB: "16",
    NO_FAULT_REJECTION_JOB: "17",
    DISPUTE_RELEASE_JOB: "18",
    POST_SUBMISSION_DISPUTE_JOB: "19",
    LATE_RECOVERY_JOB: "20",
}
BUYER = "did:demos:agent:" + "11" * 32
SELLER = "did:demos:agent:" + "22" * 32
EVALUATOR = "did:demos:agent:" + "33" * 32
ORCHESTRATOR = "did:demos:agent:" + "44" * 32
CLAIMS = {
    "buyer": BUYER,
    "seller": SELLER,
    "evaluator": EVALUATOR,
    "orchestrator": ORCHESTRATOR,
}
SEEDS = {
    role: hashlib.sha256(f"DACS #356 candidate {role} key v1".encode("ascii")).digest()
    for role in CLAIMS
}
KEY_ROLE_BY_CLAIM = {claim: role for role, claim in CLAIMS.items()}
# Further spellings of a party's claim that a vector signs with that party's
# key: CF-3 aliases, and a `cci-xm:evm` primary claim (DRW-5).
ALIAS_KEY_ROLES: dict[str, str] = {}
# Synthetic resolver and registry steward whose public keys the verifier
# pins.  Both are deliberately absent from CLAIMS, so no vector carries their
# keys or seeds.
RESOLVER = "did:demos:agent:" + "99" * 32
RESOLVER_SEED = hashlib.sha256(b"DACS #356 candidate resolver key v1").digest()
RESOLVER_DOMAIN = "dacs-x-delivery-remedy-fixture-resolver:v1:"
STEWARD = "did:demos:agent:" + "98" * 32
STEWARD_SEED = hashlib.sha256(b"DACS #356 candidate rail steward key v1").digest()
CHAIN_ID = 8453
CONTRACT = "0x" + "81" * 20
# An implementation a delegating escrow could name (DRJ-11).
IMPLEMENTATION = "0x" + "c8" * 20
TOKEN = "0x" + "55" * 20
# A synthetic token symbol: DRC-8 excludes the pausable USDC assets.
TOKEN_SYMBOL = "FXT"
RAIL_ID = f"x-evm-erc8183:{CHAIN_ID}:{TOKEN_SYMBOL}"
# The fixture pipeline's layout (DRP-18, DRP-14, DRP-1 through DRP-3): the one
# negotiation step, the commit step immediately after it, then the escrow pair
# around the one delivery.  The negotiation kind matches the bilateral
# agreement's `derivedFromPattern` (DACS-3 §8.5.2 check 7).  Every fixture,
# patch path, and mismatch value below derives from these indexes.
NEGOTIATION_KIND = "negotiate-fixed-price"
NEGOTIATION_STEP_INDEX = 0
COMMIT_STEP_INDEX = 1
FUND_PHASE_INDEX = 2
DELIVERY_PHASE_INDEX = 3
TERMINAL_PHASE_INDEX = 4
ZERO_ADDRESS = "0x" + "00" * 20
BUYER_ACCOUNT = "0x" + "11" * 20
SELLER_ACCOUNT = "0x" + "22" * 20
EVALUATOR_ACCOUNT = "0x" + "33" * 20
RELAYER_ACCOUNT = "0x" + "77" * 20
# The fixture escrow and token runtime code, and their DRW-2 keccak-256 hashes.
RUNTIME_BYTECODE = b"synthetic DACS delivery gate runtime v1"
RUNTIME_HASH = "0x" + verifier.keccak256(RUNTIME_BYTECODE).hex()
TOKEN_RUNTIME_HASH = "0x" + verifier.keccak256(b"synthetic DACS fixture token runtime v1").hex()
# A synthetic `<owner>/<repository>@<commit>`: the fixture implementation has
# no published source (README, synthetic proof limits).
IMPLEMENTATION_REVISION = "dacs-fixtures/delivery-gate@" + hashlib.sha256(
    b"synthetic DACS delivery gate source v1"
).hexdigest()[:40]
GENESIS_HASH = "0x" + hashlib.sha256(f"fixture-evm:{CHAIN_ID}:genesis".encode("ascii")).hexdigest()
FINALITY_BLOCKS = 64
# The fixture chain makes a block every two seconds; the funding block is the
# reference, so every block's time is a function of its height.
BLOCK_SECONDS = 2
FUNDING_BLOCK = 20000000
FUNDING_TIME = 1799990000
CREATION_BLOCK = 19999500
DIGEST_ANCHOR_BLOCK = 20002450
SUBMISSION_BLOCK = 20002500
SUBMISSION_CUTOFF_SEC = 1800000000
EVALUATION_DEADLINE_SEC = 1800007200
AGREEMENT_DEADLINE_MS = 1800010000000
TERMINAL_BLOCKS = {
    "release": 20005500,
    "rejected-refund": 20005500,
    "pre-submission-rejected-refund": 20003500,
    "expired-pre": 20008600,
    "expired-post": 20008600,
}
DELIVERY_OBSERVED_AT_MS = 1799994800000
# The Demos block that finalizes a decision's anchor, this long before the
# terminal transaction's block (DRC-15, DRC-19).
DECISION_LEAD_SEC = 100
MAX_SKEW_MS = 2000
NATIVE_STATUS_VALUES = {status: value for value, status in enumerate(verifier.NATIVE_STATUSES)}

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
DESCRIPTION_PREFIX = "dacs-x-delivery-remedy:v1:"


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


def key(role: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(SEEDS[role])


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def public_key(role: str) -> str:
    return b64u(key(role).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))


def claim_role(claim: str) -> str:
    """The key holder of a fixture claim; parameters do not change the party (CORE CF-3)."""
    base = claim.split("?", 1)[0]
    return KEY_ROLE_BY_CLAIM[base] if base in KEY_ROLE_BY_CLAIM else ALIAS_KEY_ROLES[base]


def component_signature(artifact: dict[str, Any], claim: str, domain: str) -> dict[str, str]:
    role = claim_role(claim)
    return {
        "algorithm": "ed25519",
        "signer": claim,
        "value": b64u(key(role).sign((domain + artifact_hash(artifact)).encode("ascii"))),
    }


def sign_component(artifact: dict[str, Any], claim: str, domain: str) -> dict[str, Any]:
    artifact.pop("signature", None)
    artifact["signature"] = component_signature(artifact, claim, domain)
    return artifact


def sign_overlay(agreement: dict[str, Any]) -> dict[str, Any]:
    agreement.pop("signatures", None)
    signatures = []
    for role in ("buyer", "seller", "evaluator"):
        signature = component_signature(
            agreement, agreement[role]["primaryClaim"], DOMAINS["agreement"]
        )
        signatures.append({"role": role, "party": signature.pop("signer"), **signature})
    agreement["signatures"] = signatures
    return agreement


def sign_bilateral(bilateral: dict[str, Any]) -> dict[str, Any]:
    """Both commercial parties sign the DACS-3 payee-bound agreement (DACS-3 §8.5.1)."""
    bilateral.pop("signatures", None)
    bilateral["signatures"] = [
        {
            "party": party["primaryClaim"],
            "algorithm": "ed25519",
            "value": b64u(key(claim_role(party["primaryClaim"])).sign(
                (DOMAINS["bilateralAgreement"] + artifact_hash(bilateral)).encode("ascii")
            )),
        }
        for party in bilateral["parties"]
        if party.get("role") in ("buyer", "seller")
    ]
    return bilateral


def steward_signature(rail: dict[str, Any], seed: bytes = STEWARD_SEED, signer: str = STEWARD) -> dict[str, str]:
    return {
        "algorithm": "ed25519",
        "signer": signer,
        "value": b64u(Ed25519PrivateKey.from_private_bytes(seed).sign(
            (DOMAINS["railDefinition"] + artifact_hash(rail)).encode("ascii")
        )),
    }


def sign_rail(rail: dict[str, Any]) -> dict[str, Any]:
    """The registry steward signs the rail definition (DRR-2, RD-1)."""
    rail.pop("signature", None)
    rail["signature"] = steward_signature(rail)
    return rail


def resign_resolver(fixture: dict[str, Any], bind: bool = True) -> None:
    """Have the pinned resolver authenticate the fixture's current record.

    With ``bind`` the record is first bound to this fixture's job, rail,
    contract, native job, and observations.
    """
    artifacts = fixture["artifacts"]
    rail = artifacts["railDefinition"]
    resolver = fixture["resolverEvidence"]
    if bind:
        resolver.update({
            "resolverEvidenceVersion": "1",
            "resolver": RESOLVER,
            "jobId": artifacts["agreement"]["jobId"],
            "railDefinitionHash": artifact_hash(rail),
            "chainId": rail["parameters"]["chainId"],
            "contractAddress": rail["parameters"]["contractAddress"],
            "nativeJobId": artifacts["job"]["nativeJobId"],
            "eventObservationsHash": content_hash(
                fixture["reproductionInputs"]["nativeEventInputs"]
            ),
        })
    resolver.pop("signature", None)
    resolver["signature"] = {
        "algorithm": "ed25519",
        "signer": RESOLVER,
        "value": b64u(
            Ed25519PrivateKey.from_private_bytes(RESOLVER_SEED).sign(
                (RESOLVER_DOMAIN + artifact_hash(resolver)).encode("ascii")
            )
        ),
    }


def apply_patch(value: Any, patch: list[dict[str, Any]]) -> Any:
    """Apply the pack's replace/add/remove operations to a fixture copy."""
    value = copy.deepcopy(value)
    for operation in patch:
        parent = value
        for segment in operation["path"][:-1]:
            parent = parent[segment]
        leaf = operation["path"][-1]
        if operation["op"] == "remove":
            del parent[leaf]
        elif operation["op"] == "add" and isinstance(parent, list):
            parent.insert(leaf, copy.deepcopy(operation["value"]))
        else:
            parent[leaf] = copy.deepcopy(operation["value"])
    return value


def resolver_patch(fixture: dict[str, Any], patch: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extend a patch so the pinned resolver authenticates the patched inputs."""
    patched = apply_patch(fixture, patch)
    resign_resolver(patched)
    return patch + [
        {"op": "replace", "path": ["resolverEvidence"], "value": patched["resolverEvidence"]}
    ]


def attestation_ref(locator: str, digest: str, kind: str = "storage-program") -> dict[str, Any]:
    """A DACS-2 `AttestationRef`: the anchor nests its kind and locator."""
    return {"anchor": {"kind": kind, "locator": locator}, "contentHash": digest}


def ref(artifact: dict[str, Any], locator: str) -> dict[str, Any]:
    return attestation_ref(locator, artifact_hash(artifact))


def logical(job_id: str, suffix: str) -> str:
    """A candidate §6.5 logical address."""
    return verifier.logical_address(job_id, suffix)


def event(tx_preimage: str, log_index: int) -> dict[str, Any]:
    return {
        "kind": "evm-event",
        "chainId": CHAIN_ID,
        # DRW-3: the DACS-4 SB-1 canonical spelling, without `0x`.
        "txHash": hashlib.sha256(tx_preimage.encode("ascii")).hexdigest(),
        "logIndex": log_index,
    }


def block_time(number: int) -> int:
    return FUNDING_TIME + BLOCK_SECONDS * (number - FUNDING_BLOCK)


def block(number: int, timestamp_sec: int | None = None) -> dict[str, Any]:
    """A fixture-chain block identity at ``number``."""
    timestamp = block_time(number) if timestamp_sec is None else timestamp_sec
    preimage = verifier.block_preimage(CHAIN_ID, number, timestamp)
    return {
        "blockNumber": number,
        "blockHash": "0x" + hashlib.sha256(preimage.encode("ascii")).hexdigest(),
        "blockHashPreimageUtf8": preimage,
        "blockTimestampSec": timestamp,
    }


def event_input(
    ref_value: dict[str, Any],
    tx_preimage: str,
    job: dict[str, Any],
    block_number: int,
    event_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """One resolver observation, decoded under the fixture ABI's layout, at the rail's finality depth.

    ``arguments`` names every input but the job ID, which is the log's
    first topic.
    """
    inputs = verifier.FIXTURE_EVENTS[event_name]
    values = {"jobId": job["nativeJobId"], **arguments}
    return {
        "eventRef": copy.deepcopy(ref_value),
        "txHashPreimageUtf8": tx_preimage,
        **block(block_number),
        "contractAddress": job["contractAddress"],
        "eventName": event_name,
        "topic0": verifier.topic_of(verifier.abi_signature(event_name, inputs)),
        "indexedArguments": [values[name] for name, _type, indexed in inputs if indexed],
        "dataArguments": [values[name] for name, _type, indexed in inputs if not indexed],
        "finalityBlock": block(block_number + FINALITY_BLOCKS - 1),
    }


def argument_path(event_name: str, name: str) -> list[Any]:
    """Where an observation carries one decoded input: its topic or data position."""
    inputs = verifier.FIXTURE_EVENTS[event_name]
    indexed = inputs[[item[0] for item in inputs].index(name)][2]
    same_layout = [item[0] for item in inputs if item[2] == indexed]
    return ["indexedArguments" if indexed else "dataArguments", same_layout.index(name)]


def policy_word(policy: str) -> str:
    """The configuration event's 32-byte policy word for ``policy`` (DRC-21)."""
    return "0x" + policy.encode("ascii").ljust(32, b"\0").hex()


def finality_time_ms(block_number: int) -> int:
    """DRW-6: 1000 times the time of the event's confirmation-depth block."""
    return block_time(block_number + FINALITY_BLOCKS - 1) * 1000


def finality(block_number: int) -> dict[str, Any]:
    return {
        "model": "block-depth",
        "finalityBlocks": FINALITY_BLOCKS,
        "finalityObservedAt": finality_time_ms(block_number),
    }


def account_of(claim: str) -> str:
    """The lower-case account of a `cci-xm:evm:<chain>:<address>[?parameters]` claim."""
    return claim.split("?", 1)[0].rsplit(":", 1)[1].lower()


def transaction(
    tx_preimage: str,
    entrypoint: str,
    calldata: dict[str, Any],
    caller: str,
    prior: str | None,
    after: str,
) -> dict[str, Any]:
    """The resolver's record of one lifecycle transaction (DRL-10)."""
    return {
        "txHash": event(tx_preimage, 0)["txHash"],
        "entrypoint": verifier.selector_of(verifier.abi_signature(entrypoint, verifier.FIXTURE_ENTRYPOINTS[entrypoint])),
        "calldata": calldata,
        "nativeCaller": caller,
        "outerSubmitter": caller,
        "nativeCallerAccountType": "eoa",
        "priorNativeStatus": None if prior is None else NATIVE_STATUS_VALUES[prior],
        "nativeStatusAfter": NATIVE_STATUS_VALUES[after],
    }


def projection(terminal_state: str, classification: str | None, submitted: bool) -> dict[str, Any]:
    """The candidate §7 projection of a terminal state and finding (DRT-14)."""
    if classification is None or (
        terminal_state == "expired-refund" and classification == "seller-fault" and submitted
    ):
        row = verifier.NO_PROJECTION
    else:
        row = verifier.PROJECTION_TABLE.get((terminal_state, classification), verifier.NO_PROJECTION)
    return {
        "buyerAnchoredOutcome": row[0],
        "sellerAnchoredOutcome": row[1],
        "faultedParty": row[2],
        "releaseAloneEstablishesNonFinancialCompletion": False,
    }


def rail_body() -> dict[str, Any]:
    """The fixture `JobEscrowRailDefinition` before the steward signs it (candidate §2.2, §8.4)."""
    return {
        "jobEscrowRailVersion": "1",
        "railVersion": 1,
        "railId": RAIL_ID,
        "railType": "x-evm-erc8183",
        "asset": {"kind": "erc20", "chainId": CHAIN_ID, "contract": TOKEN, "symbol": TOKEN_SYMBOL, "decimals": 6},
        "network": {"kind": "evm", "chainId": CHAIN_ID, "rpcAttestation": "evm-rpc"},
        "phaseHandler": "x-job-escrow",
        "parameters": {
            "canonicalErcRevision": "ethereum/ERCs@a078cab5cc8e9581c15f76c091ed96eed28f02f7",
            "implementationRevision": IMPLEMENTATION_REVISION,
            "entrypoints": verifier.entrypoint_pins(),
            "events": verifier.event_pins(),
            "configurationEvidence": dict(verifier.CONFIGURATION_EVIDENCE),
            "nativeStatusMap": [
                {"nativeValue": value, "nativeStatus": status}
                for status, value in NATIVE_STATUS_VALUES.items()
            ],
            "chainId": CHAIN_ID,
            "contractAddress": CONTRACT,
            "runtimeBytecodeHash": RUNTIME_HASH,
            "paymentToken": TOKEN,
            "paymentTokenRuntimeBytecodeHash": TOKEN_RUNTIME_HASH,
            "tokenDecimals": 6,
            "finalityBlocks": FINALITY_BLOCKS,
            "minimumEvaluationWindowSec": 3600,
            "hook": ZERO_ADDRESS,
            "deadlineProfile": "separate-submission-cutoff-v1",
            "decisionOrderingProfile": "anchor-final-before-terminal-v1",
            "maxCrossSubstrateSkewMs": MAX_SKEW_MS,
            "platformFeeBP": 0,
            "evaluatorFeeBP": 0,
            "capabilityProfile": "dacs-delivery-gate-v1",
        },
        "consumerFinalityProfile": {
            "finalityProfileVersion": "1",
            "model": "block-depth",
            "settlement": {
                "kind": "block-depth",
                "networkId": f"eip155:{CHAIN_ID}",
                "genesisHash": GENESIS_HASH,
                "requiredDepth": FINALITY_BLOCKS,
                "observation": {
                    "method": "rpc-quorum",
                    "authorityRefs": [RESOLVER],
                    "threshold": 1,
                    "maxHeadAgeSec": 60,
                },
            },
        },
        "availability": "mocked",
        "governance": {"proposedBy": STEWARD, "acceptedAt": 1799000000000, "anchoring": "single-signer"},
    }


Hooks = dict[str, Callable[[Any], None]]


def noncanonical_b64u(value: str) -> str:
    """Set the zero pad bits of an Ed25519 signature's last Base64URL digit (CORE SIG-6)."""
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
    altered = value[:-1] + alphabet[alphabet.index(value[-1]) | 1]
    assert altered != value and base64.urlsafe_b64decode(altered + "==") == base64.urlsafe_b64decode(value + "==")
    return altered


def make_base(
    lifecycle: str,
    job_id: str | None = None,
    *,
    delivered: bool | None = None,
    basis: str | None = None,
    classification: str | None = None,
    buyer_claim: str = BUYER,
    evaluator_claim: str = EVALUATOR,
    terminal_tx_preimage: str | None = None,
    terminal_offset: int = 0,
    submission_block: int = SUBMISSION_BLOCK,
    submission_tx_preimage: str | None = None,
    hooks: Hooks | None = None,
) -> dict[str, Any]:
    """Build one signed lifecycle whose every binding derives from what it binds.

    A hook edits the named input set, artifact, reference, or finished fixture
    before it is signed or bound, and everything downstream is derived from
    the edited value.  A negative built this way differs from a consistent
    lifecycle only in its hooked edit.  ``terminal_offset`` moves the terminal
    transaction by whole blocks; every block's time follows from its height.
    """
    if lifecycle not in LIFECYCLE_JOBS:
        raise ValueError(lifecycle)
    job_id = LIFECYCLE_JOBS[lifecycle] if job_id is None else job_id
    hooks = hooks or {}

    def hook(name: str, value: Any) -> Any:
        if name in hooks:
            hooks[name](value)
        return value

    if delivered is None:
        delivered = lifecycle not in {"expired-pre", "pre-submission-rejected-refund"}
    if basis is None:
        basis = {
            "release": "evaluation",
            "rejected-refund": "evaluation",
            "pre-submission-rejected-refund": "dispute",
        }.get(lifecycle)
    claims = {"buyer": buyer_claim, "seller": SELLER, "evaluator": evaluator_claim}
    terminal_block = TERMINAL_BLOCKS[lifecycle] + terminal_offset
    terminal_at_sec = block_time(terminal_block)
    pipeline = [
        {"kind": NEGOTIATION_KIND},
        {"kind": "x-commit-delivery-or-remedy-agreement", "parameters": {"agreementPhase": "commit-payee-bound-agreement"}},
        {"kind": "x-job-escrow", "parameters": {"action": "fund", "rail": RAIL_ID}},
        {"kind": "deliver-storage-program"},
        {"kind": "x-job-escrow", "parameters": {"action": "terminal", "rail": RAIL_ID}},
        {"kind": "rate"},
    ]
    rail = sign_rail(hook("rail", rail_body()))
    requirement = {
        "op": "all",
        "of": [
            {"claimType": "demos-agent", "verificationRequired": True},
            {"claimType": "cci-xm", "verificationRequired": True},
        ],
    }
    role_accounts = {
        "buyer": BUYER_ACCOUNT,
        "seller": SELLER_ACCOUNT,
        "evaluator": EVALUATOR_ACCOUNT,
    }
    role_bundles = {
        role: {
            "fixtureRecordVersion": "1",
            "kind": "role-bundle-input",
            "primaryClaim": claims[role],
            "claims": [f"cci-xm:evm:{CHAIN_ID}:{role_accounts[role]}"],
        }
        for role in ("buyer", "seller", "evaluator")
    }
    inputs: dict[str, Any] = {
        "roleBundles": role_bundles,
        "vetRecords": {
            role: {
                "fixtureRecordVersion": "1",
                "kind": "vet-record-input",
                "subject": claims[role],
                "bundleHash": artifact_hash(role_bundles[role]),
                "result": "pass",
                "validFromSec": 1799900000,
                "validUntilSec": 1800010000,
                **(
                    {"requirementHash": content_hash(requirement)}
                    if role == "evaluator"
                    else {}
                ),
            }
            for role in ("buyer", "seller", "evaluator")
        },
        "deliveredArtifact": {"payloadUtf8": f"deliverable:{job_id}"} if delivered else None,
        "runtimeBytecode": {"encoding": "hex", "value": RUNTIME_BYTECODE.hex()},
    }
    hook("inputs", inputs)
    vet_refs = {
        role: ref(inputs["vetRecords"][role], f"fixture:vet:{job_id}:{role}")
        for role in ("buyer", "seller", "evaluator")
    }
    bilateral = sign_bilateral(hook("bilateral", {
        "payeeBoundAgreementVersion": "1",
        "jobId": job_id,
        "listingRef": {
            "listingId": f"fixture-listing-{job_id}",
            "version": 1,
            "contentHash": hashlib.sha256(f"fixture listing for {job_id}".encode("ascii")).hexdigest(),
        },
        "parties": [
            {
                "role": role,
                "bundleHash": artifact_hash(inputs["roleBundles"][role]),
                "primaryClaim": claims[role],
                "vetRecordRef": copy.deepcopy(vet_refs[role]),
            }
            for role in ("buyer", "seller")
        ],
        "terms": {
            "deliverable": {
                "deliverableType": "storage-program",
                "hash": content_hash({"kind": "storage-program"}),
            },
            # 1 FXT at the rail's 6 decimals is the 1000000 base-unit budget (DRA-10).
            "price": {"amount": "1", "currency": TOKEN_SYMBOL},
            "rail": {"railId": RAIL_ID, "railVersion": 1},
            "deadline": AGREEMENT_DEADLINE_MS,
            "payoutBindings": [{"railId": RAIL_ID, "phaseIndex": FUND_PHASE_INDEX, "payeeAddress": SELLER_ACCOUNT}],
        },
        "derivedFromPattern": "fixed-price",
        "generatedAt": 1799980000000,
    }))
    evaluation_rule = hook("evaluationRule", {
        "evaluationRuleVersion": "1",
        "ruleKind": "evaluator-judgement-v1",
        "jobId": job_id,
        "criteria": [
            {
                "criterionId": "deliverable-matches-specification",
                "statement": "The delivered payload matches the agreed deliverable specification.",
            },
            {
                "criterionId": "deliverable-is-complete",
                "statement": "The delivered payload is complete.",
            },
        ],
    })

    agreement = {
        "deliveryOrRemedyAgreementVersion": "1",
        "jobId": job_id,
        "agreementRef": ref(bilateral, f"dacs3:agreement:{job_id}"),
        "agreementHash": artifact_hash(bilateral),
        "railDefinitionRef": ref(rail, f"fixture:rail:{RAIL_ID}:1"),
        "fundPhaseIndex": FUND_PHASE_INDEX,
        "deliveryPhaseIndex": DELIVERY_PHASE_INDEX,
        "terminalPhaseIndex": TERMINAL_PHASE_INDEX,
        **{
            role: {
                "primaryClaim": claims[role],
                "bundleHash": artifact_hash(inputs["roleBundles"][role]),
                "vetRecordRef": copy.deepcopy(vet_refs[role]),
                "evmAccountClaim": f"cci-xm:evm:{CHAIN_ID}:{role_accounts[role]}",
                **(
                    {"requirement": requirement, "requirementHash": content_hash(requirement)}
                    if role == "evaluator"
                    else {}
                ),
            }
            for role in ("buyer", "seller", "evaluator")
        },
        "budgetBaseUnits": "1000000",
        "submissionCutoffSec": SUBMISSION_CUTOFF_SEC,
        "evaluationDeadlineSec": EVALUATION_DEADLINE_SEC,
        "preSubmissionRefundPolicy": "evaluator-rejection",
        "disclosurePolicy": "public-evidence-only",
        "evaluationRuleRef": ref(evaluation_rule, logical(job_id, "evaluation-rule")),
    }
    sign_overlay(hook("agreement", agreement))
    agreement_hash = artifact_hash(agreement)
    accounts = {
        role: account_of(agreement[role]["evmAccountClaim"])
        for role in ("buyer", "seller", "evaluator")
    }
    budget = agreement["budgetBaseUnits"]
    token = rail["parameters"]["paymentToken"]

    creation_preimage = f"{job_id}:create"
    creation_event = event(creation_preimage, 0)
    job = sign_component(hook("job", {
        "escrowJobRefVersion": "1",
        "jobId": job_id,
        "deliveryOrRemedyAgreementHash": agreement_hash,
        "railDefinitionRef": copy.deepcopy(agreement["railDefinitionRef"]),
        "chainId": rail["parameters"]["chainId"],
        "contractAddress": rail["parameters"]["contractAddress"],
        "runtimeBytecodeHash": rail["parameters"]["runtimeBytecodeHash"],
        "nativeJobId": NATIVE_JOB_IDS.get(job_id, "9"),
        "creationEvent": copy.deepcopy(creation_event),
    }), ORCHESTRATOR, DOMAINS["job"])
    job_ref = ref(job, logical(job_id, "job"))
    funding_preimage = f"{job_id}:fund"
    funding_event = event(funding_preimage, 1)
    funding = sign_component(hook("funding", {
        "escrowFundingEvidenceVersion": "1",
        "jobId": job_id,
        "deliveryOrRemedyAgreementHash": agreement_hash,
        "escrowJobRef": copy.deepcopy(job_ref),
        "fundPhaseIndex": agreement["fundPhaseIndex"],
        "token": token,
        "amountBaseUnits": budget,
        "fundingEventRefs": [copy.deepcopy(funding_event)],
        "finality": finality(FUNDING_BLOCK),
        "observedAt": finality_time_ms(FUNDING_BLOCK),
    }), ORCHESTRATOR, DOMAINS["funding"])
    funding_ref = ref(funding, logical(job_id, "funding"))

    artifacts: dict[str, Any] = {
        "bilateralAgreement": bilateral,
        "railDefinition": rail,
        "agreement": agreement,
        "evaluationRule": evaluation_rule,
        "job": job,
        "funding": funding,
    }
    delivery = None
    delivery_ref = None
    if delivered:
        # DACS-4 DeliveryEvidence for the storage-program step (PDE-1, PDE-4).
        delivery = sign_component(hook("delivery", {
            "deliveryEvidenceVersion": "1",
            "jobId": job_id,
            "phaseIndex": agreement["deliveryPhaseIndex"],
            "phase": "deliver-storage-program",
            "outcome": "success",
            "deliverableContentHash": hashlib.sha256(
                inputs["deliveredArtifact"]["payloadUtf8"].encode("utf-8")
            ).hexdigest(),
            "deliverableAnchor": {
                "kind": "storage-program",
                "locator": f"dacs4:deliverable:{job_id}:{agreement['deliveryPhaseIndex']}",
            },
            "observedAt": DELIVERY_OBSERVED_AT_MS,
        }), ORCHESTRATOR, DOMAINS["delivery"])
        delivery_ref = hook("deliveryRef", ref(delivery, f"dacs4:delivery:{job_id}:{agreement['deliveryPhaseIndex']}"))
        artifacts.update({"delivery": delivery, "deliveryRef": delivery_ref})

    released = lifecycle == "release"
    finding_artifact = None
    basis_ref = None
    if basis == "evaluation":
        found = classification or ("seller-fulfilled" if released else "seller-fault")
        evaluation = sign_component(hook("evaluation", {
            "executionEvaluationVersion": "1",
            "jobId": job_id,
            "evaluationSeq": 0,
            "deliveryOrRemedyAgreementHash": agreement_hash,
            "escrowJobRef": copy.deepcopy(job_ref),
            # Without a delivery this names no record: such a decision is
            # refused before it is read (DRD-9).
            "deliveryEvidenceRef": copy.deepcopy(delivery_ref) if delivered else attestation_ref(
                f"dacs4:delivery:{job_id}:{agreement['deliveryPhaseIndex']}", "ab" * 32
            ),
            "criterionResults": [
                {"criterionId": criterion["criterionId"], "outcome": outcome}
                for criterion, outcome in zip(
                    evaluation_rule["criteria"],
                    ["satisfied", "satisfied"] if released else ["unsatisfied", "satisfied"],
                )
            ],
            "result": "accept" if released else "reject",
            "finding": {
                "classification": found,
                **({"faultedParty": SELLER} if found == "seller-fault" else {}),
                **({"faultedParty": claims["buyer"]} if found == "buyer-fault" else {}),
                "rationaleCode": "fixture-criteria-met" if released else "fixture-criterion-unmet",
            },
            "subjectEvidenceRefs": [copy.deepcopy(delivery_ref)] if delivered else [],
        }), claims["evaluator"], DOMAINS["evaluation"])
        evaluation_ref = hook("evaluationRef", ref(evaluation, logical(job_id, f"evaluation:{evaluation.get('evaluationSeq')}")))
        basis_ref = {"kind": "execution-evaluation", "ref": copy.deepcopy(evaluation_ref)}
        artifacts.update({"evaluation": evaluation, "evaluationRef": evaluation_ref})
        finding_artifact = evaluation
    elif basis == "dispute":
        found = classification or ("seller-fulfilled" if released else "no-fault")
        case = sign_component(hook("disputeCase", {
            "disputeCaseVersion": "1",
            "jobId": job_id,
            "caseId": CASE_A,
            "deliveryOrRemedyAgreementHash": agreement_hash,
            "openedByRole": "buyer",
            "subjectEvidenceRefs": [copy.deepcopy(funding_ref)],
        }), claims["buyer"], DOMAINS["disputeCase"])
        dispute = sign_component(hook("dispute", {
            "disputeOutcomeVersion": "1",
            "jobId": job_id,
            "caseId": CASE_A,
            "revision": 0,
            "deliveryOrRemedyAgreementHash": agreement_hash,
            "caseRef": ref(case, logical(job_id, f"dispute:{CASE_A}:case")),
            "subjectBundleRefs": [],
            "subjectEvidenceRefs": [copy.deepcopy(funding_ref)],
            "finding": {
                "classification": found,
                **({"faultedParty": SELLER} if found == "seller-fault" else {}),
                **({"faultedParty": claims["buyer"]} if found == "buyer-fault" else {}),
                "rationaleCode": "fixture-agreement-authorized-rejection",
            },
            "recommendedDisposition": "release-to-provider" if released else "refund-to-client",
        }), claims["evaluator"], DOMAINS["dispute"])
        dispute_ref = hook("disputeRef", ref(
            dispute, logical(job_id, f"dispute:{dispute.get('caseId')}:outcome:{dispute.get('revision')}")
        ))
        basis_ref = {"kind": "dispute-outcome", "ref": copy.deepcopy(dispute_ref)}
        artifacts.update({"disputeCase": case, "dispute": dispute, "disputeRef": dispute_ref})
        finding_artifact = dispute

    decision = None
    decision_ref = None
    if basis_ref is not None:
        decision = sign_component(hook("decision", {
            "escrowDecisionVersion": "1",
            "jobId": job_id,
            "deliveryOrRemedyAgreementHash": agreement_hash,
            "escrowJobRef": copy.deepcopy(job_ref),
            "decisionStage": "post-submission" if delivered else "pre-submission",
            **({"deliveryEvidenceRef": copy.deepcopy(delivery_ref)} if delivered else {}),
            "basisRef": basis_ref,
            "disposition": "release-to-provider" if released else "refund-to-client",
        }), claims["evaluator"], DOMAINS["decision"])
        decision_ref = hook("decisionRef", ref(decision, logical(job_id, f"decision:{decision.get('decisionStage')}")))
        artifacts.update({"decision": decision, "decisionRef": decision_ref})

    if released:
        terminal_state, recipient, action = "released", accounts["seller"], "complete"
    elif lifecycle in {"rejected-refund", "pre-submission-rejected-refund"}:
        terminal_state, recipient, action = "rejected-refund", accounts["buyer"], "reject"
    else:
        terminal_state, recipient, action = "expired-refund", accounts["buyer"], "claimRefund"
    terminal_preimage = terminal_tx_preimage or f"{job_id}:{action}"
    state_name, transfer_name = verifier.TERMINAL_EVENTS[terminal_state]
    terminal_events = [event(terminal_preimage, 2), event(terminal_preimage, 3)]
    terminal_body: dict[str, Any] = {
        "escrowTerminalEvidenceVersion": "1",
        "jobId": job_id,
        "deliveryOrRemedyAgreementHash": agreement_hash,
        "escrowJobRef": copy.deepcopy(job_ref),
        "fundingEvidenceRef": copy.deepcopy(funding_ref),
        "terminalPhaseIndex": agreement["terminalPhaseIndex"],
        "terminalState": terminal_state,
        "disposition": "release-to-provider" if terminal_state == "released" else "refund-to-client",
        "token": token,
        "amountBaseUnits": budget,
        "recipient": recipient,
        "terminalEventRefs": copy.deepcopy(terminal_events),
        "finality": finality(terminal_block),
        "observedAt": finality_time_ms(terminal_block),
    }
    if decision_ref is not None:
        terminal_body["decisionRef"] = copy.deepcopy(decision_ref)
    if delivery_ref is not None:
        terminal_body["deliveryEvidenceRef"] = copy.deepcopy(delivery_ref)
    terminal = sign_component(hook("terminal", terminal_body), ORCHESTRATOR, DOMAINS["terminal"])
    artifacts["terminal"] = terminal

    statuses = {
        "agreementResolution": "verified",
        "railResolution": "verified",
        "codeResolution": "verified",
        "authorityResolution": "verified",
        "fundingFinality": "verified",
        "deliveryFinality": "verified" if delivered else "not-applicable",
        "decisionFinality": "not-applicable" if decision is None else "verified",
        "terminalFinality": "verified",
        "transitionResolution": "verified",
        "nativeStateResolution": "verified",
    }
    mapping_sources = {"agreementHash": agreement_hash}
    if delivery is not None:
        mapping_sources["deliveryHash"] = artifact_hash(delivery)
    if decision is not None:
        mapping_sources["decisionHash"] = artifact_hash(decision)
    reason = None if decision is None else "0x" + artifact_hash(decision)
    deliverable = None if delivery is None else "0x" + artifact_hash(delivery)
    native = {
        "chainId": rail["parameters"]["chainId"],
        "contractAddress": job["contractAddress"],
        "runtimeBytecodeHash": job["runtimeBytecodeHash"],
        "client": accounts["buyer"],
        "provider": accounts["seller"],
        "evaluator": accounts["evaluator"],
        "token": token,
        "payoutReceiver": accounts["seller"],
        "amountBaseUnits": budget,
        "fundedAtSec": block_time(FUNDING_BLOCK),
        "deliverable": deliverable,
        "reason": reason,
        "submissionCutoffSec": agreement["submissionCutoffSec"],
        "expiredAt": agreement["evaluationDeadlineSec"],
        "terminalState": terminal_state,
        "terminalAction": action,
        "portableStateHistory": [
            "created",
            "funded",
            *(["submitted"] if delivered or terminal_state == "released" else []),
            "released" if terminal_state == "released" else "refunded",
        ],
    }
    observations = [
        event_input(
            creation_event, creation_preimage, job, CREATION_BLOCK, "JobCreated",
            {
                "client": accounts["buyer"],
                "provider": accounts["seller"],
                "evaluator": accounts["evaluator"],
                "expiredAt": str(agreement["evaluationDeadlineSec"]),
                "hook": rail["parameters"]["hook"],
            },
        ),
        event_input(
            event(creation_preimage, 1), creation_preimage, job, CREATION_BLOCK, "JobConfigured",
            {
                "submissionCutoff": str(agreement["submissionCutoffSec"]),
                "preSubmissionRefundPolicy": policy_word(agreement["preSubmissionRefundPolicy"]),
            },
        ),
        event_input(
            funding_event, funding_preimage, job, FUNDING_BLOCK, "JobFunded",
            {"client": accounts["buyer"], "amount": budget},
        ),
    ]
    transactions = [
        transaction(creation_preimage, "createJob", {
            "provider": accounts["seller"],
            "evaluator": accounts["evaluator"],
            "expiredAt": str(agreement["evaluationDeadlineSec"]),
            "submissionCutoff": str(agreement["submissionCutoffSec"]),
            "description": DESCRIPTION_PREFIX + agreement_hash,
            "hook": rail["parameters"]["hook"],
        }, accounts["buyer"], None, "Open"),
        transaction(funding_preimage, "fund", {
            "jobId": job["nativeJobId"], "expectedBudget": budget,
        }, accounts["buyer"], "Open", "Funded"),
    ]
    submission_event = None
    if delivered:
        # The transaction identity commits to its deliverable argument.
        submission_preimage = submission_tx_preimage or f"{job_id}:submit:{deliverable}"
        submission_event = event(submission_preimage, 0)
        observations.append(event_input(
            submission_event, submission_preimage, job, submission_block,
            "JobSubmitted", {"provider": accounts["seller"], "deliverable": deliverable},
        ))
        transactions.append(transaction(submission_preimage, "submit", {
            "jobId": job["nativeJobId"], "deliverable": deliverable,
        }, accounts["seller"], "Funded", "Submitted"))
    prior = "Submitted" if delivered else "Funded"
    transfer_arguments = (
        {"provider": terminal["recipient"], "amount": terminal["amountBaseUnits"]}
        if transfer_name == "PaymentReleased"
        else {"client": terminal["recipient"], "amount": terminal["amountBaseUnits"]}
    )
    state_arguments = {
        "JobCompleted": {"evaluator": accounts["evaluator"], "reason": reason},
        "JobRejected": {"rejector": accounts["evaluator"], "reason": reason},
        "JobExpired": {},
    }[state_name]
    observations += [
        event_input(terminal_events[0], terminal_preimage, job, terminal_block, state_name, state_arguments),
        event_input(terminal_events[1], terminal_preimage, job, terminal_block, transfer_name, transfer_arguments),
    ]
    terminal_calldata = {
        "complete": {"jobId": job["nativeJobId"], "reason": reason},
        "reject": {"jobId": job["nativeJobId"], "reason": reason, "expectedStatus": str(NATIVE_STATUS_VALUES[prior])},
        "claimRefund": {"jobId": job["nativeJobId"]},
    }[action]
    transactions.append(transaction(
        terminal_preimage, action, terminal_calldata,
        accounts["evaluator"] if decision is not None else accounts["buyer"],
        prior, {"complete": "Completed", "reject": "Rejected", "claimRefund": "Expired"}[action],
    ))
    finding = None if finding_artifact is None else finding_artifact["finding"]
    found_classification = finding.get("classification") if isinstance(finding, dict) else None
    fixture = {
        "candidateProfile": "delivery-or-remedy-v1",
        "fixtureOnly": True,
        "pipeline": pipeline,
        "executionContext": {
            "acceptedRails": [{"railId": RAIL_ID, "railVersion": 1}],
            "commitmentReceipts": {
                "agreement": {"status": "finalized", "jobId": job_id, "contentHash": artifact_hash(bilateral)},
                "overlay": {"status": "finalized", "jobId": job_id, "contentHash": agreement_hash},
            },
            "fundingFinalizedBeforeDelivery": True,
            "terminalGate": (
                "delivery-returned"
                if delivered
                else (
                    "pre-submission-decision"
                    if decision is not None
                    else "submission-cutoff"
                )
            ),
            "lateDeliveryDisabled": True,
            "dacs5PurchaseCount": 0,
        },
        "artifacts": artifacts,
        "publicKeys": {claim: public_key(role) for role, claim in CLAIMS.items()},
        "orchestratorClaim": ORCHESTRATOR,
        "bundleRequiredSigners": [
            agreement["buyer"]["primaryClaim"], agreement["seller"]["primaryClaim"],
        ],
        "evaluatorVetResult": "pass",
        "profileParameters": copy.deepcopy(rail["parameters"]),
        "mappingSources": mapping_sources,
        "native": native,
        "resolverEvidence": {
            "transactions": transactions,
            "priorTerminals": [],
            "nativeState": {
                "submissionCutoffEnforced": True,
                "expiryRecoveryAtSec": agreement["evaluationDeadlineSec"],
                "preterminalProviderPayoutBaseUnits": "0",
                "platformFeeBP": rail["parameters"]["platformFeeBP"],
                "evaluatorFeeBP": rail["parameters"]["evaluatorFeeBP"],
                "evaluatorBindingMode": "direct",
                "evaluatorAdapter": None,
                "escrowRuntimeBytecodeHash": job["runtimeBytecodeHash"],
                "paymentTokenRuntimeBytecodeHash": rail["parameters"]["paymentTokenRuntimeBytecodeHash"],
                "implementationAddress": None,
            },
            "deliveryDigestAnchor": None if delivery is None else {
                "deliverable": deliverable,
                "blockNumber": DIGEST_ANCHOR_BLOCK,
                "blockTimestampSec": block_time(DIGEST_ANCHOR_BLOCK),
            },
            "decisionAnchor": None if decision is None else {
                "substrate": "demos",
                "finalizedBlockTimestampSec": terminal_at_sec - DECISION_LEAD_SEC,
            },
            "statuses": statuses,
        },
        "deliveryBinding": (
            None
            if submission_event is None
            else {"nativeSubmissionEvent": copy.deepcopy(submission_event)}
        ),
        "reproductionInputs": {
            "publicTestSeedHex": {
                CLAIMS[role]: SEEDS[role].hex() for role in CLAIMS
            },
            **inputs,
            "nativeEventInputs": observations,
        },
        "reputationProjection": projection(terminal_state, found_classification, delivered),
        "submittedBeforeCutoff": delivered,
    }
    hook("fixture", fixture)
    refresh_canonical_records(fixture)
    resign_resolver(fixture)
    return fixture


def refresh_canonical_records(fixture: dict[str, Any]) -> None:
    """Pin the exact canonical bytes that feed each ERC field mapping."""
    records: dict[str, Any] = {}
    for name in ("agreement", "delivery", "decision"):
        artifact = fixture["artifacts"].get(name)
        if artifact is None:
            continue
        digest = artifact_hash(artifact)
        record = {
            "canonicalUtf8Hex": jcs_canonicalize(unsigned_artifact(artifact)).encode("utf-8").hex(),
            "contentHash": digest,
        }
        if name == "agreement":
            record["mappedNativeValue"] = DESCRIPTION_PREFIX + digest
        else:
            record["mappedNativeValue"] = "0x" + digest
        records[name] = record
    fixture["canonicalRecords"] = records


def qualified_artifact_write(
    fixture: dict[str, Any], name: str, copy_index: int = 0,
    finalized_sec: int | None = None,
) -> dict[str, Any]:
    """One synthetic resolver output for a qualifying Demos write (not proof bytes)."""
    terminal = fixture["artifacts"]["terminal"]
    reference = terminal["fundingEvidenceRef" if name == "funding" else "decisionRef"]
    locator = reference["anchor"]["locator"]
    identity = hashlib.sha256(f"{locator}:write:{copy_index}".encode("ascii")).hexdigest()
    if finalized_sec is None:
        finalized_sec = fixture["resolverEvidence"]["decisionAnchor"]["finalizedBlockTimestampSec"]
    return {
        "logicalAddress": locator,
        "nativeAddress": "stor-" + identity,
        "contentHash": reference["contentHash"],
        "transactionRef": {"kind": "demos-transaction", "value": identity},
        "writer": ORCHESTRATOR,
        "nonce": str(copy_index),
        "finalizedBlockTimestampSec": finalized_sec,
    }


def vector(
    name: str,
    base: str,
    expected: str,
    rule: str,
    note: str,
    patch=None,
    rules: list[str] | None = None,
    evaluated_with: list[str] | None = None,
) -> dict[str, Any]:
    value = {
        "name": name,
        "base": base,
        "expected": expected,
        "expectedRule": rule,
        "rules": sorted(set(rules or [rule])),
        "note": note,
        "patch": patch or [],
    }
    if evaluated_with is not None:
        value["evaluatedWith"] = evaluated_with
    return value


def put(*path_and_value: Any) -> Callable[[Any], None]:
    """Return a hook that sets one nested field."""
    *path, value = path_and_value

    def apply(body: Any) -> None:
        target = body
        for segment in path[:-1]:
            target = target[segment]
        target[path[-1]] = copy.deepcopy(value)

    return apply


def drop(*path: Any) -> Callable[[Any], None]:
    """Return a hook that removes one nested field."""

    def apply(body: Any) -> None:
        target = body
        for segment in path[:-1]:
            target = target[segment]
        del target[path[-1]]

    return apply


def each(*hooks_to_apply: Callable[[Any], None]) -> Callable[[Any], None]:
    """Return a hook that applies several hooks in order."""

    def apply(body: Any) -> None:
        for item in hooks_to_apply:
            item(body)

    return apply


def _register_aliases() -> dict[str, str]:
    """Claims that vectors sign with an existing party's key."""
    aliases = {
        # DACS-1: an upper-case Demos agent key is not the buyer's claim respelt.
        "did:demos:agent:" + "11" * 32: "buyer",
        "did:demos:agent:" + "AA" * 32: "buyer",
        "DID:demos:agent:" + "11" * 32: "buyer",
        # DRW-5: one EVM account, two letter cases.
        f"cci-xm:evm:{CHAIN_ID}:0x" + "ab" * 20: "buyer",
        f"cci-xm:evm:{CHAIN_ID}:0x" + "AB" * 20: "buyer",
        # DACS-1 PB-2: spellings outside the profile of that one account.
        f"cci-xm:evm:0{CHAIN_ID}:0x" + "ab" * 20: "buyer",
        f"cci-xm:EVM:{CHAIN_ID}:0x" + "ab" * 20: "buyer",
        f"cci-xm:evm:+{CHAIN_ID}:0x" + "ab" * 20: "buyer",
        f"cci-xm:evm:-{CHAIN_ID}:0x" + "ab" * 20: "buyer",
        f"cci-xm:evm:{CHAIN_ID:#x}:0x" + "ab" * 20: "buyer",
        # DACS-1 §6.3.1: an NFD identifier is not the NFC claim it decomposes.
        "did:web:café.example": "buyer",
    }
    ALIAS_KEY_ROLES.update(aliases)
    return aliases


# EIP-55: the checksum spelling of 0xabab…ab and a spelling that breaks it.
EIP55_ACCOUNT = "0xABaBaBaBABabABabAbAbABAbABabababaBaBABaB"
BAD_CHECKSUM_ACCOUNT = "0x" + "aB" * 20


def build_vector_pack() -> dict[str, Any]:
    _register_aliases()
    substituted = attestation_ref("fixture:substituted", "ab" * 32)
    other_runtime = b"substituted DACS delivery gate runtime"
    unbound_submission = event(f"{JOB_A}:submit", 0)
    # Another job's escrow job, named at this job's job address.
    other_job_ref = attestation_ref(
        logical(JOB_A, "job"), make_base("rejected-refund")["artifacts"]["funding"]["escrowJobRef"]["contentHash"],
    )
    unpublished_subject = attestation_ref("fixture:unpublished-subject", "12" * 32)
    upper_buyer_key = "did:demos:agent:" + "AA" * 32
    scheme_case_buyer = "DID:demos:agent:" + "11" * 32
    evm_buyer = f"cci-xm:evm:{CHAIN_ID}:0x" + "ab" * 20
    evm_buyer_upper = f"cci-xm:evm:{CHAIN_ID}:0x" + "AB" * 20
    evm_buyer_leading_zero = f"cci-xm:evm:0{CHAIN_ID}:0x" + "ab" * 20
    evm_family_upper = f"cci-xm:EVM:{CHAIN_ID}:0x" + "ab" * 20
    evm_chain_plus = f"cci-xm:evm:+{CHAIN_ID}:0x" + "ab" * 20
    evm_chain_minus = f"cci-xm:evm:-{CHAIN_ID}:0x" + "ab" * 20
    evm_chain_hex = f"cci-xm:evm:{CHAIN_ID:#x}:0x" + "ab" * 20
    nfd_claim = "did:web:café.example"

    def with_keys(*claims_and_roles: tuple[str, str]) -> Callable[[Any], None]:
        """A fixture hook that publishes extra claims' keys and seeds."""
        return each(*(
            each(
                put("publicKeys", claim, public_key(role)),
                put("reproductionInputs", "publicTestSeedHex", claim, SEEDS[role].hex()),
            )
            for claim, role in claims_and_roles
        ))

    def evaluation_with(result_value: str, outcomes: list[str], found: dict[str, Any]) -> Callable[[Any], None]:
        return each(
            put("result", result_value),
            put("finding", found),
            lambda body: body.__setitem__("criterionResults", [
                {"criterionId": item["criterionId"], "outcome": outcome}
                for item, outcome in zip(body["criterionResults"], outcomes)
            ]),
        )

    def rail_param(*path_and_value: Any) -> Callable[[Any], None]:
        return put("parameters", *path_and_value)

    def replace_case(fixture: dict[str, Any]) -> None:
        """Re-sign an edited DisputeCase after the outcome's caseRef bound the original."""
        case = {**fixture["artifacts"]["disputeCase"], "subjectEvidenceRefs": []}
        fixture["artifacts"]["disputeCase"] = sign_component(case, BUYER, DOMAINS["disputeCase"])

    fixtures = {
        "release": make_base("release"),
        "rejected-refund": make_base("rejected-refund"),
        "pre-submission-rejected-refund": make_base("pre-submission-rejected-refund"),
        "expired-pre": make_base("expired-pre"),
        "expired-post": make_base("expired-post"),
        # Further positives, each on its own job.
        "native-job-id-zero": make_base("release", ZERO_NATIVE_JOB),
        "rejected-refund-buyer-fault": make_base("rejected-refund", BUYER_FAULT_JOB, classification="buyer-fault"),
        "rejected-refund-substrate-failure": make_base("rejected-refund", SUBSTRATE_FAILURE_JOB, classification="substrate-failure"),
        "rejected-refund-no-fault": make_base("rejected-refund", NO_FAULT_REJECTION_JOB, classification="no-fault"),
        "dispute-release": make_base("release", DISPUTE_RELEASE_JOB, basis="dispute"),
        "post-submission-dispute-refund": make_base("rejected-refund", POST_SUBMISSION_DISPUTE_JOB, basis="dispute"),
        "dreb-15-recovery-after-deadline": make_base("expired-pre", LATE_RECOVERY_JOB, terminal_offset=1),
        "dreb-15-pre-submission-recovery-early": make_base("expired-pre", terminal_offset=-1),
        "dreb-15-post-submission-recovery-early": make_base("expired-post", terminal_offset=-1),
        "native-submission-at-cutoff": make_base(
            "release", submission_block=FUNDING_BLOCK + (SUBMISSION_CUTOFF_SEC - FUNDING_TIME) // BLOCK_SECONDS,
        ),
        "dra-1-bilateral-job": make_base("release", hooks={"bilateral": put("jobId", JOB_B)}),
        "terminal-phase-index-mismatch": make_base("release", hooks={"terminal": put("terminalPhaseIndex", TERMINAL_PHASE_INDEX + 1)}),
        # DRF-8: the signed record and the resolver's confirmation block are
        # altered together; only the block order contradicts them.
        "funding-finality-block-time-jointly-altered": make_base("release", hooks={
            "funding": each(
                put("finality", "finalityObservedAt", 9_000_000_000_000 * 1000),
                put("observedAt", 9_000_000_000_000 * 1000),
            ),
            "fixture": put(
                "reproductionInputs", "nativeEventInputs", 2, "finalityBlock",
                block(FUNDING_BLOCK + FINALITY_BLOCKS - 1, 9_000_000_000_000),
            ),
        }),
        "funding-token-upper-case": make_base("release", hooks={
            "rail": each(rail_param("paymentToken", "0x" + "ab" * 20), put("asset", "contract", "0x" + "ab" * 20)),
            "funding": put("token", "0x" + "AB" * 20),
        }),
        # Pipeline and agreement negatives: the edit is signed and every
        # downstream binding follows it.
        "second-delivery-phase": make_base("release", hooks={
            "agreement": put("terminalPhaseIndex", TERMINAL_PHASE_INDEX + 1),
            "terminal": put("terminalPhaseIndex", TERMINAL_PHASE_INDEX + 1),
            "fixture": lambda fixture: fixture["pipeline"].insert(TERMINAL_PHASE_INDEX, {"kind": "deliver-entitlement"}),
        }),
        "delivery-phase-index-divergence": make_base("release", hooks={"agreement": put("deliveryPhaseIndex", TERMINAL_PHASE_INDEX + 1)}),
        "bilateral-reference-mismatch": make_base("release", hooks={"agreement": put("agreementRef", "contentHash", "01" * 32)}),
        "bilateral-hash-mismatch": make_base("release", hooks={"agreement": put("agreementHash", "02" * 32)}),
        "evaluator-requirement-mismatch": make_base("release", hooks={
            "inputs": put("vetRecords", "evaluator", "requirementHash", "03" * 32),
            "agreement": put("evaluator", "requirementHash", "03" * 32),
        }),
        "evaluator-vet-requirement-mismatch": make_base("release", hooks={
            "inputs": put("vetRecords", "evaluator", "requirementHash", "04" * 32),
        }),
        "evaluator-vet-expired-at-funding": make_base("release", hooks={
            "inputs": put("vetRecords", "evaluator", "validUntilSec", 1799980000),
        }),
        "nonminimal-budget": make_base("release", hooks={
            "agreement": put("budgetBaseUnits", "01000000"),
            "funding": put("amountBaseUnits", "1000000"),
            "terminal": put("amountBaseUnits", "1000000"),
        }),
        # DRA-10, DRA-21: the budget is the agreed price, in the rail asset,
        # converted with the pinned token decimals.
        "dra-10-price-amount": make_base("release", hooks={"bilateral": put("terms", "price", "amount", "2")}),
        "dra-21-price-currency": make_base("release", hooks={"bilateral": put("terms", "price", "currency", "DAI")}),
        "dra-10-token-decimals": make_base("release", hooks={"rail": each(rail_param("tokenDecimals", 18), put("asset", "decimals", 18))}),
        "dra-10-zero-budget": make_base("release", hooks={"agreement": put("budgetBaseUnits", "0")}),
        "dra-10-zero-price": make_base("release", hooks={
            "bilateral": put("terms", "price", "amount", "0"), "agreement": put("budgetBaseUnits", "0"),
        }),
        "dra-10-excess-precision": make_base("release", hooks={"bilateral": put("terms", "price", "amount", "1.0000001")}),
        "rail-reference-mismatch": make_base("release", hooks={"agreement": put("railDefinitionRef", "contentHash", "04" * 32)}),
        "unsupported-disclosure-policy": make_base("release", hooks={"agreement": put("disclosurePolicy", "encrypted-transcript")}),
        "transcript-in-delivered-artifact": make_base("release", hooks={"inputs": put("deliveredArtifact", "transcriptExcerpt", "forbidden")}),
        # DRA-17: the overlay's buyer and seller are the agreement's parties.
        "dra-17-bilateral-parties-swapped": make_base("release", hooks={
            "bilateral": lambda body: body.__setitem__("parties", [
                {**party, "role": {"buyer": "seller", "seller": "buyer"}[party["role"]]}
                for party in body["parties"]
            ]),
        }),
        "dra-17-seller-bundle-differs": make_base("release", hooks={
            "bilateral": put("parties", 1, "bundleHash", "06" * 32),
        }),
        # DRA-19: the evaluation deadline is within the agreement deadline.
        "dra-19-deadline-after-agreement": make_base("release", hooks={
            "bilateral": put("terms", "deadline", EVALUATION_DEADLINE_SEC * 1000 - 1),
        }),
        "dra-19-cutoff-beyond-seconds-bound": make_base("release", hooks={
            "agreement": put("submissionCutoffSec", verifier.MAX_SECONDS + 1),
        }),
        # DRA-20: one payout binding, for the escrow rail and fund phase, paying the seller.
        "dra-20-payee-is-buyer": make_base("release", hooks={
            "bilateral": put("terms", "payoutBindings", 0, "payeeAddress", BUYER_ACCOUNT),
        }),
        "dra-20-payout-phase-index": make_base("release", hooks={
            "bilateral": put("terms", "payoutBindings", 0, "phaseIndex", TERMINAL_PHASE_INDEX),
        }),
        "dra-20-second-payout-binding": make_base("release", hooks={
            "bilateral": lambda body: body["terms"]["payoutBindings"].append(
                {"railId": RAIL_ID, "phaseIndex": TERMINAL_PHASE_INDEX, "payeeAddress": SELLER_ACCOUNT}
            ),
        }),
        "dra-20-payee-malformed": make_base("release", hooks={
            "bilateral": put("terms", "payoutBindings", 0, "payeeAddress", "0x22"),
        }),
        # DRA-22: the agreement's terms.rail is the selected reference.
        "dra-22-terms-rail-absent": make_base("release", hooks={"bilateral": drop("terms", "rail")}),
        "dra-22-terms-rail-other-version": make_base("release", hooks={"bilateral": put("terms", "rail", "railVersion", 2)}),
        # DRA-1: both commercial parties sign the agreement.
        "dra-1-bilateral-seller-unsigned": make_base("release", hooks={
            "fixture": lambda fixture: fixture["artifacts"]["bilateralAgreement"]["signatures"].pop(),
        }),
        # A submission identity that does not commit to its argument can be
        # derived into the delivery it submits.
        "delivery-quotes-native-submission": make_base(
            "release",
            submission_tx_preimage=f"{JOB_A}:submit",
            hooks={"inputs": put(
                "deliveredArtifact", "payloadUtf8",
                f"deliverable:{JOB_A}:quoting:" + hashlib.sha256(
                    unbound_submission["txHash"].encode("ascii")
                ).hexdigest(),
            )},
        ),
        "drp-9-digest-anchor-unavailable": make_base("release", hooks={
            "fixture": put("resolverEvidence", "deliveryDigestAnchor", None),
        }),
        "drp-9-digest-anchor-other-digest": make_base("release", hooks={
            "fixture": put("resolverEvidence", "deliveryDigestAnchor", "deliverable", "0x" + "14" * 32),
        }),
        "drp-9-digest-fixed-after-submission": make_base("release", hooks={
            "fixture": each(
                put("resolverEvidence", "deliveryDigestAnchor", "blockNumber", SUBMISSION_BLOCK + 10),
                put("resolverEvidence", "deliveryDigestAnchor", "blockTimestampSec", block_time(SUBMISSION_BLOCK + 10)),
            ),
        }),
        "drp-9-digest-anchored-in-submission-block": make_base("release", hooks={
            "fixture": each(
                put("resolverEvidence", "deliveryDigestAnchor", "blockNumber", SUBMISSION_BLOCK),
                put("resolverEvidence", "deliveryDigestAnchor", "blockTimestampSec", block_time(SUBMISSION_BLOCK)),
            ),
        }),
        # An anchor block earlier than the submission's, at the same block time.
        "drp-9-digest-anchor-time-equals-submission": make_base("release", hooks={
            "fixture": put("resolverEvidence", "deliveryDigestAnchor", "blockTimestampSec", block_time(SUBMISSION_BLOCK)),
        }),
        "deliveryless-lifecycle-carries-digest-anchor": make_base("expired-pre", hooks={
            "fixture": put("resolverEvidence", "deliveryDigestAnchor", {
                "deliverable": "0x" + "15" * 32, "blockNumber": DIGEST_ANCHOR_BLOCK,
                "blockTimestampSec": block_time(DIGEST_ANCHOR_BLOCK),
            }),
        }),
        "drp-9-delivery-observed-after-submission": make_base("release", hooks={
            "delivery": put("observedAt", block_time(DIGEST_ANCHOR_BLOCK) * 1000 + 1),
        }),
        # DRE-2, DRP-7: the current DeliveryEvidence of the agreed phase.
        "dre-2-delivery-phase-kind": make_base("release", hooks={"delivery": put("phase", "deliver-entitlement")}),
        "drp-7-delivery-phase-index": make_base("release", hooks={"delivery": put("phaseIndex", TERMINAL_PHASE_INDEX)}),
        "drp-7-historical-settlement-evidence": make_base("release", hooks={
            "delivery": each(drop("deliveryEvidenceVersion"), put("evidenceVersion", "1")),
        }),
        # DRP-3: a delivery kind this pack does not model never verifies, even
        # when the step and its signed evidence agree on it.
        "drp-3-attested-payload-delivery": make_base("release", hooks={
            "delivery": each(
                put("phase", "deliver-attested-payload"),
                put("deliverableAnchor", {"kind": "payload-attestation", "locator": "fixture:any-anchor"}),
            ),
            "fixture": put("pipeline", DELIVERY_PHASE_INDEX, {"kind": "deliver-attested-payload"}),
        }),
        "drp-3-entitlement-delivery": make_base("release", hooks={
            "delivery": each(
                put("phase", "deliver-entitlement"),
                put("deliverableAnchor", {"kind": "entitlement", "locator": "fixture:any-anchor"}),
            ),
            "fixture": put("pipeline", DELIVERY_PHASE_INDEX, {"kind": "deliver-entitlement"}),
        }),
        # PDE-3, PDE-4: a storage-program success anchors the deliverable at
        # dacs4:deliverable:{jobId}:{phaseIndex}.  Each control changes one
        # axis and is re-signed and re-bound downstream.
        "dre-2-deliverable-anchor-kind": make_base("release", hooks={
            "delivery": put("deliverableAnchor", "kind", "not-storage-program"),
        }),
        "dre-2-deliverable-anchor-other-job": make_base("release", hooks={
            "delivery": put("deliverableAnchor", "locator", f"dacs4:deliverable:{JOB_B}:{DELIVERY_PHASE_INDEX}"),
        }),
        "dre-2-deliverable-anchor-unindexed": make_base("release", hooks={
            "delivery": put("deliverableAnchor", "locator", f"dacs4:deliverable:{JOB_A}"),
        }),
        "dre-2-deliverable-anchor-native-locator": make_base("release", hooks={
            "delivery": put("deliverableAnchor", "locator", "stor-" + hashlib.sha256(
                b"synthetic native Storage Program for the release deliverable"
            ).hexdigest()[:40]),
        }),
        "drv-3-terminal-state-array": make_base("release", hooks={"terminal": put("terminalState", [])}),
        "drv-3-terminal-state-object": make_base("release", hooks={"terminal": put("terminalState", {})}),
        "drv-3-terminal-state-unknown-string": make_base("release", hooks={"terminal": put("terminalState", "bogus")}),
        "drv-3-delivery-evidence-shape": make_base("release", hooks={"delivery": put("paymentTxRefs", [])}),
        # DRP-7: a failure DeliveryEvidence is never submitted or released against.
        "drp-7-failed-delivery": make_base("rejected-refund", hooks={
            "delivery": each(
                put("outcome", "failure"),
                put("reason", "fixture-output-missing"),
                drop("deliverableContentHash"),
                drop("deliverableAnchor"),
            ),
        }),
        "drv-3-failed-delivery-empty-reason": make_base("rejected-refund", hooks={
            "delivery": each(put("outcome", "failure"), put("reason", "")),
        }),
        "drd-8-evaluation-job-reference": make_base("release", hooks={"evaluation": put("escrowJobRef", other_job_ref)}),
        "drd-8-decision-job-reference": make_base("release", hooks={"decision": put("escrowJobRef", other_job_ref)}),
        "drv-4-job-overlay-hash": make_base("release", hooks={"job": put("deliveryOrRemedyAgreementHash", "05" * 32)}),
        "drf-1-funding-overlay-hash": make_base("release", hooks={"funding": put("deliveryOrRemedyAgreementHash", "05" * 32)}),
        # DRE-3, DRE-5: evaluation subject evidence.
        "dre-5-evaluation-subject-unresolved": make_base("release", hooks={
            "evaluation": put("subjectEvidenceRefs", [unpublished_subject]),
        }),
        "dre-3-evaluation-subject-contradiction": make_base("release", hooks={
            "evaluation": put("subjectEvidenceRefs", [
                attestation_ref(f"dacs4:delivery:{JOB_A}:{DELIVERY_PHASE_INDEX}", "13" * 32),
            ]),
        }),
        # The subject reference names the delivery's locator and hash but
        # another reference kind.
        "dre-3-evaluation-subject-kind": make_base("release", hooks={
            "evaluation": put("subjectEvidenceRefs", [attestation_ref(
                f"dacs4:delivery:{JOB_A}:{DELIVERY_PHASE_INDEX}",
                make_base("release")["artifacts"]["deliveryRef"]["contentHash"],
                "ipfs",
            )]),
        }),
        "drv-3-evaluation-subject-refs": make_base("release", hooks={"evaluation": put("subjectEvidenceRefs", None)}),
        "evaluator-claim-is-buyer": make_base("release", evaluator_claim=BUYER),
        "evaluator-account-is-seller": make_base("release", hooks={
            "agreement": put("evaluator", "evmAccountClaim", f"cci-xm:evm:{CHAIN_ID}:{SELLER_ACCOUNT}"),
        }),
        "evaluator-account-other-chain": make_base("release", hooks={
            "agreement": put("evaluator", "evmAccountClaim", f"cci-xm:evm:10:{EVALUATOR_ACCOUNT}"),
        }),
        "evaluator-account-zero": make_base("release", hooks={
            "agreement": put("evaluator", "evmAccountClaim", f"cci-xm:evm:{CHAIN_ID}:{ZERO_ADDRESS}"),
        }),
        "nonpositive-evaluation-window": make_base("release", hooks={"rail": rail_param("minimumEvaluationWindowSec", 0)}),
        "short-evaluation-window": make_base("release", hooks={"rail": rail_param("minimumEvaluationWindowSec", 8000)}),
        "expiry-only-policy": make_base("release", hooks={"agreement": put("preSubmissionRefundPolicy", "expiry-only")}),
        # Reference and binding negatives.
        "delivery-from-another-job": make_base("release", hooks={"delivery": put("jobId", JOB_B)}),
        "decision-from-another-job": make_base("release", hooks={"decision": put("jobId", JOB_B)}),
        "delivery-reference-mismatch": make_base("release", hooks={"deliveryRef": put("contentHash", "05" * 32)}),
        "evaluation-reference-mismatch": make_base("release", hooks={"evaluationRef": put("contentHash", "06" * 32)}),
        "decision-reference-mismatch": make_base("release", hooks={"decisionRef": put("contentHash", "07" * 32)}),
        "dispute-reference-mismatch": make_base("pre-submission-rejected-refund", hooks={"disputeRef": put("contentHash", "08" * 32)}),
        "decision-delivery-mismatch": make_base("release", hooks={"decision": put("deliveryEvidenceRef", substituted)}),
        "decision-basis-other-evaluation": make_base("release", hooks={"decision": put("basisRef", "ref", substituted)}),
        "decision-basis-other-dispute": make_base("pre-submission-rejected-refund", hooks={"decision": put("basisRef", "ref", substituted)}),
        "pre-submission-decision-with-delivery": make_base("pre-submission-rejected-refund", hooks={"decision": put("deliveryEvidenceRef", substituted)}),
        "release-without-delivery": make_base("release", delivered=False),
        "evaluation-refund-without-delivery": make_base("rejected-refund", delivered=False),
        "dispute-recommends-release": make_base("pre-submission-rejected-refund", hooks={"dispute": put("recommendedDisposition", "release-to-provider")}),
        "dispute-without-recommendation": make_base("pre-submission-rejected-refund", hooks={"dispute": drop("recommendedDisposition")}),
        "dispute-evaluator-unavailable": make_base("pre-submission-rejected-refund", classification="evaluator-unavailable"),
        "dispute-later-revision-unlinked": make_base("pre-submission-rejected-refund", hooks={"dispute": put("revision", 1)}),
        "decision-without-basis-artifact": make_base("release", hooks={
            "fixture": each(drop("artifacts", "evaluation"), drop("artifacts", "evaluationRef")),
        }),
        "terminal-job-reference-mismatch": make_base("release", hooks={"terminal": put("escrowJobRef", other_job_ref)}),
        "terminal-delivery-reference-mismatch": make_base("release", hooks={"terminal": put("deliveryEvidenceRef", substituted)}),
        "terminal-decision-mismatch": make_base("release", hooks={"terminal": put("decisionRef", substituted)}),
        "refund-terminal-decision-mismatch": make_base("rejected-refund", hooks={"terminal": put("decisionRef", substituted)}),
        "terminal-funding-mismatch": make_base("release", hooks={"terminal": put("fundingEvidenceRef", attestation_ref(logical(JOB_A, "funding"), "ab" * 32))}),
        "funding-job-mismatch": make_base("release", hooks={"funding": put("escrowJobRef", other_job_ref)}),
        "funding-token-mismatch": make_base("release", hooks={"funding": put("token", "0x" + "66" * 20)}),
        "funding-phase-index-mismatch": make_base("release", hooks={"funding": put("fundPhaseIndex", FUND_PHASE_INDEX + 1)}),
        # Evaluation, decision, and terminal negatives.  Each evaluation edit
        # keeps the criterion outcomes, result, and finding consistent under
        # the rule matrix (DRE-10), so the disposition check decides.
        "reject-then-release": make_base("release", hooks={"evaluation": evaluation_with(
            "reject", ["unsatisfied", "satisfied"],
            {"classification": "seller-fault", "faultedParty": SELLER, "rationaleCode": "fixture-criterion-unmet"},
        )}),
        "accept-then-refund": make_base("rejected-refund", hooks={"evaluation": evaluation_with(
            "accept", ["satisfied", "satisfied"],
            {"classification": "seller-fulfilled", "rationaleCode": "fixture-criteria-met"},
        )}),
        "indeterminate-evaluation": make_base("release", hooks={"evaluation": evaluation_with(
            "indeterminate", ["indeterminate", "satisfied"],
            {"classification": "indeterminate", "rationaleCode": "fixture-criterion-undecided"},
        )}),
        "drv-3-evaluation-result": make_base("release", hooks={"evaluation": put("result", "deferred")}),
        "drv-3-decision-disposition": make_base("release", hooks={"decision": put("disposition", "partial-release")}),
        "evaluation-sequence-text": make_base("release", hooks={"evaluation": put("evaluationSeq", "0")}),
        "evaluation-sequence-one": make_base("release", hooks={"evaluation": put("evaluationSeq", 1)}),
        "wrong-faulted-party": make_base("rejected-refund", hooks={"evaluation": put("finding", "faultedParty", BUYER)}),
        "nonfault-with-faulted-party": make_base("pre-submission-rejected-refund", hooks={"dispute": put("finding", "faultedParty", SELLER)}),
        "nonfault-with-null-faulted-party": make_base("pre-submission-rejected-refund", hooks={"dispute": put("finding", "faultedParty", None)}),
        "dispute-claims-transfer": make_base("pre-submission-rejected-refund", hooks={"dispute": put("transfer", "refund")}),
        "noncanonical-case-id": make_base("pre-submission-rejected-refund", hooks={"dispute": put("caseId", "case-356")}),
        "dispute-revision-text": make_base("pre-submission-rejected-refund", hooks={"dispute": put("revision", "0")}),
        "partial-release": make_base("release", hooks={"terminal": put("amountBaseUnits", "999999")}),
        "wrong-release-recipient": make_base("release", hooks={"terminal": put("recipient", BUYER_ACCOUNT)}),
        "wrong-refund-recipient": make_base("rejected-refund", hooks={"terminal": put("recipient", SELLER_ACCOUNT)}),
        "expiry-refund-to-seller": make_base("expired-pre", hooks={"terminal": put("recipient", SELLER_ACCOUNT)}),
        "expiry-invented-decision": make_base("expired-pre", hooks={"terminal": put("decisionRef", substituted)}),
        "expiry-invented-delivery": make_base("expired-pre", hooks={"terminal": put("deliveryEvidenceRef", substituted)}),
        # Candidate §9 step 5 and §11.3 case I5: a record the signed artifacts
        # reference but the caller did not supply, with no resolver status
        # changed and nothing present contradicting it.
        "decision-record-not-supplied": make_base("release", hooks={"fixture": each(
            drop("artifacts", "decision"), drop("artifacts", "decisionRef"), drop("mappingSources", "decisionHash"),
        )}),
        "evaluation-and-decision-records-not-supplied": make_base("release", hooks={"fixture": each(
            drop("artifacts", "evaluation"), drop("artifacts", "evaluationRef"),
            drop("artifacts", "decision"), drop("artifacts", "decisionRef"), drop("mappingSources", "decisionHash"),
        )}),
        "pre-submission-decision-record-not-supplied": make_base("pre-submission-rejected-refund", hooks={"fixture": each(
            drop("artifacts", "decision"), drop("artifacts", "decisionRef"), drop("mappingSources", "decisionHash"),
        )}),
        "rejection-evaluation-record-not-supplied": make_base("rejected-refund", hooks={"fixture": each(
            drop("artifacts", "evaluation"), drop("artifacts", "evaluationRef"),
        )}),
        "dispute-outcome-record-not-supplied": make_base("pre-submission-rejected-refund", hooks={"fixture": each(
            drop("artifacts", "dispute"), drop("artifacts", "disputeRef"),
        )}),
        "dispute-case-record-not-supplied": make_base("pre-submission-rejected-refund", hooks={"fixture": drop("artifacts", "disputeCase")}),
        "dispute-case-replaced": make_base("pre-submission-rejected-refund", hooks={"fixture": replace_case}),
        "dispute-case-opened-by-seller": make_base("pre-submission-rejected-refund", hooks={"disputeCase": put("openedByRole", "seller")}),
        "evaluation-rule-not-supplied": make_base("release", hooks={"fixture": drop("artifacts", "evaluationRule")}),
        "delivery-record-not-supplied": make_base("release", hooks={"fixture": each(
            drop("artifacts", "delivery"), drop("artifacts", "deliveryRef"), drop("mappingSources", "deliveryHash"),
        )}),
        "rejection-delivery-record-not-supplied": make_base("rejected-refund", hooks={"fixture": each(
            drop("artifacts", "delivery"), drop("artifacts", "deliveryRef"), drop("mappingSources", "deliveryHash"),
        )}),
        "expiry-delivery-record-not-supplied": make_base("expired-post", hooks={"fixture": each(
            drop("artifacts", "delivery"), drop("artifacts", "deliveryRef"), drop("mappingSources", "deliveryHash"),
        )}),
        # A released terminal that references no decision contradicts the
        # evaluation it would rest on: rejected, not missing.
        "released-terminal-without-decision-reference": make_base("release", hooks={
            "terminal": drop("decisionRef"),
            "fixture": each(
                drop("artifacts", "decision"), drop("artifacts", "decisionRef"), drop("mappingSources", "decisionHash"),
            ),
        }),
        # A decision basis kind outside the candidate's two names neither
        # artifact, so nothing is missing and nothing authorizes the decision.
        "decision-basis-kind-unsupported": make_base("release", hooks={
            "decision": put("basisRef", "kind", "self-assessment"),
            "fixture": each(
                drop("artifacts", "evaluation"), drop("artifacts", "evaluationRef"),
                put("reputationProjection", projection("released", None, True)),
            ),
        }),
        # DRV-3: a boolean where an integer is read is malformed, though
        # Python compares `true` equal to 1 and `false` equal to 0.
        "drv-3-agreement-phase-index-boolean": make_base("release", hooks={
            "agreement": put("fundPhaseIndex", True), "funding": put("fundPhaseIndex", FUND_PHASE_INDEX),
        }),
        "drv-3-funding-phase-index-boolean": make_base("release", hooks={"funding": put("fundPhaseIndex", True)}),
        # Identity, job, and rail negatives.
        "noncanonical-job-id": make_base("release", "job-356"),
        "nonminimal-native-job-id": make_base("release", hooks={"job": put("nativeJobId", "01")}),
        "native-job-id-beyond-uint256": make_base("release", hooks={"job": put("nativeJobId", str(2 ** 256))}),
        "drp-5-job-rail": make_base("release", hooks={
            "job": put("railDefinitionRef", "anchor", "locator", f"fixture:rail:{RAIL_ID}:unselected"),
        }),
        "drj-10-job-contract": make_base("release", hooks={"job": put("contractAddress", "0x" + "82" * 20)}),
        "drj-10-job-runtime": make_base("release", hooks={
            "job": put("runtimeBytecodeHash", "0x" + verifier.keccak256(other_runtime).hex()),
            "inputs": put("runtimeBytecode", {"encoding": "hex", "value": other_runtime.hex()}),
        }),
        "drj-5-escrow-code-changed": make_base("release", hooks={
            "fixture": put("resolverEvidence", "nativeState", "escrowRuntimeBytecodeHash", "0x" + verifier.keccak256(other_runtime).hex()),
        }),
        "drj-11-token-code-changed": make_base("release", hooks={
            "fixture": put("resolverEvidence", "nativeState", "paymentTokenRuntimeBytecodeHash", "0x" + "c7" * 32),
        }),
        "drj-11-unpinned-implementation": make_base("release", hooks={
            "fixture": put("resolverEvidence", "nativeState", "implementationAddress", "0x" + "c8" * 20),
        }),
        # Finality-record and event-set negatives.
        "funding-finality-pending": make_base("release", hooks={
            "fixture": put("reproductionInputs", "nativeEventInputs", 2, "finalityBlock", None),
        }),
        "terminal-finality-pending": make_base("release", hooks={
            "fixture": each(
                put("reproductionInputs", "nativeEventInputs", 4, "finalityBlock", None),
                put("reproductionInputs", "nativeEventInputs", 5, "finalityBlock", None),
            ),
        }),
        "funding-events-empty": make_base("release", hooks={"funding": put("fundingEventRefs", [])}),
        "terminal-events-empty": make_base("release", hooks={"terminal": put("terminalEventRefs", [])}),
        "terminal-events-state-log-only": make_base("release", hooks={"terminal": lambda body: body["terminalEventRefs"].pop()}),
        "terminal-events-extra-log": make_base("release", hooks={"terminal": lambda body: body["terminalEventRefs"].append(
            event(f"{JOB_A}:complete", 4)
        )}),
        "funding-finality-unregistered-member": make_base("release", hooks={"funding": put("finality", "status", "pending")}),
        "funding-finality-depth-below-profile": make_base("release", hooks={"funding": put("finality", "finalityBlocks", 1)}),
        "funding-finality-predates-event": make_base("release", hooks={"funding": put("finality", "finalityObservedAt", (FUNDING_TIME - 1) * 1000)}),
        "funding-observed-at-wall-clock": make_base("release", hooks={"funding": put("observedAt", 1799999999999)}),
        "terminal-finality-unregistered-member": make_base("release", hooks={"terminal": put("finality", "status", "pending")}),
        "terminal-finality-depth-below-profile": make_base("release", hooks={"terminal": put("finality", "finalityBlocks", 1)}),
        "terminal-observed-at-wall-clock": make_base("release", hooks={"terminal": put("observedAt", 1800009999999)}),
        # Replay: one terminal per decision, per native job, and per event.
        "release-second-terminal-transaction": make_base(
            "release", terminal_tx_preimage=f"{JOB_A}:complete:second", terminal_offset=1,
        ),
        "release-earlier-terminal-transaction": make_base(
            "release", terminal_tx_preimage=f"{JOB_A}:complete:earlier", terminal_offset=-1,
        ),
        "release-same-position-terminal-transaction": make_base(
            "release", terminal_tx_preimage=f"{JOB_A}:complete:same-position",
        ),
        "release-job-rejection": make_base("rejected-refund", JOB_A, terminal_offset=1),
        "other-job-reuses-release-terminal-event": make_base("release", JOB_B, terminal_tx_preimage=f"{JOB_A}:complete"),
    }

    def authenticated(fixture_name: str, patch: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return resolver_patch(fixtures[fixture_name], patch)

    def index_of(fixture_name: str, event_name: str) -> int:
        observations = fixtures[fixture_name]["reproductionInputs"]["nativeEventInputs"]
        return next(i for i, item in enumerate(observations) if item["eventName"] == event_name)

    def observation(fixture_name: str, event_name: str, *path: Any, value: Any) -> list[dict[str, Any]]:
        """Replace one observation member; `"arguments", name` names a decoded input."""
        if path[:1] == ("arguments",):
            path = (*argument_path(event_name, path[1]), *path[2:])
        return [{
            "op": "replace",
            "path": ["reproductionInputs", "nativeEventInputs", index_of(fixture_name, event_name), *path],
            "value": value,
        }]

    funded_log = fixtures["release"]["reproductionInputs"]["nativeEventInputs"][index_of("release", "JobFunded")]

    def tx_record(fixture_name: str, position: int, *path: Any, value: Any) -> list[dict[str, Any]]:
        transactions = fixtures[fixture_name]["resolverEvidence"]["transactions"]
        return [{
            "op": "replace",
            "path": ["resolverEvidence", "transactions", position % len(transactions), *path],
            "value": value,
        }]

    def terminal_call(fixture_name: str, field: str, value: Any) -> list[dict[str, Any]]:
        return tx_record(fixture_name, -1, field, value=value)

    def status(name: str, state: str) -> list[dict[str, Any]]:
        return [{"op": "replace", "path": ["resolverEvidence", "statuses", name], "value": state}]

    def native_state(field: str, value: Any) -> list[dict[str, Any]]:
        return [{"op": "replace", "path": ["resolverEvidence", "nativeState", field], "value": value}]

    def decision_anchor(value: Any) -> list[dict[str, Any]]:
        return [{"op": "replace", "path": ["resolverEvidence", "decisionAnchor"], "value": value}]

    def prior_terminal(
        fixture_name: str,
        *,
        tx_preimage: str | None = None,
        native_job_id: str | None = None,
        decision_hash: str | None = None,
    ) -> dict[str, Any]:
        """One resolver-attested earlier terminal, defaulting to the fixture's own."""
        fixture = fixtures[fixture_name]
        job = fixture["artifacts"]["job"]
        ref_value = fixture["artifacts"]["terminal"]["terminalEventRefs"][0]
        return {
            "chainId": job["chainId"],
            "contractAddress": job["contractAddress"],
            "nativeJobId": job["nativeJobId"] if native_job_id is None else native_job_id,
            "txHash": ref_value["txHash"] if tx_preimage is None else event(tx_preimage, 2)["txHash"],
            "logIndex": ref_value["logIndex"],
            "decisionHash": decision_hash,
        }

    def history(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{"op": "replace", "path": ["resolverEvidence", "priorTerminals"], "value": entries}]

    release = fixtures["release"]
    release_hashes = release["mappingSources"]
    release_decision_hash = release_hashes["decisionHash"]
    release_terminal_sec = block_time(TERMINAL_BLOCKS["release"])
    rehash_delivery = hashlib.sha256(release_hashes["deliveryHash"].encode("ascii")).hexdigest()
    rehash_reason = hashlib.sha256(release_decision_hash.encode("ascii")).hexdigest()
    reversed_delivery = bytes.fromhex(release_hashes["deliveryHash"])[::-1].hex()
    shifted_delivery = "00" + release_hashes["deliveryHash"][2:]
    bad_signer = component_signature(release["artifacts"]["evaluation"], BUYER, DOMAINS["evaluation"])
    bad_decision_signer = component_signature(release["artifacts"]["decision"], BUYER, DOMAINS["decision"])
    # DRG-1: the decision signed under the registered-looking domain that the
    # candidate's `dacs-x-` domain would become.
    relabelled_domain_signer = component_signature(
        release["artifacts"]["decision"], EVALUATOR, "dacs-escrow-decision:v1:"
    )
    foreign_resolver_signature = {
        "algorithm": "ed25519",
        "signer": RESOLVER,
        "value": b64u(key("orchestrator").sign(
            (RESOLVER_DOMAIN + artifact_hash(release["resolverEvidence"])).encode("ascii")
        )),
    }
    other_job_resolver = copy.deepcopy(release)
    other_job_resolver["resolverEvidence"]["jobId"] = JOB_B
    resign_resolver(other_job_resolver, bind=False)

    # The rules each positive proves.  None is promotion-blocked: the pack's
    # verifier refuses a pass vector that claims one.
    common_pass_rules = [
        "DRP-1", "DRP-2", "DRP-3", "DRP-4", "DRP-5", "DRP-14", "DRP-18", "DRG-3",
        "DRA-1", "DRA-2", "DRA-3", "DRA-5", "DRA-6", "DRA-7", "DRA-10", "DRA-11", "DRA-13",
        "DRA-15", "DRA-17", "DRA-18", "DRA-19", "DRA-20", "DRA-21", "DRA-22",
        "DRR-1", "DRR-4", "DRR-5", "DRR-6", "DRR-7", "DRR-8",
        "DRC-16", "DRC-17", "DRC-18", "DRC-20", "DRC-21",
        "DRW-1", "DRW-3", "DRW-4", "DRW-7",
        "DRL-1", "DRL-2", "DRL-3", "DRL-4", "DRL-7", "DRL-10", "DRL-11", "DRL-12",
        "DRJ-1", "DRJ-2", "DRJ-3", "DRJ-4", "DRJ-5", "DRJ-7", "DRJ-8", "DRJ-10",
        "DRF-1", "DRF-2", "DRF-3", "DRF-4", "DRF-5", "DRF-6",
        "DRE-9", "DRAA-1", "DRAA-2",
        "DREB-1", "DREB-2", "DREB-3", "DREB-4", "DREB-5", "DREB-6", "DREB-7", "DREB-8",
        "DREB-9", "DREB-10", "DREB-11", "DREB-12", "DREB-13", "DREB-14", "DREB-15", "DREB-23",
        "DRT-4", "DRT-7", "DRT-8", "DRT-10", "DRT-11", "DRT-12", "DRT-14", "DRT-15",
        "DRV-1", "DRV-2", "DRV-3", "DRV-4", "DRV-6", "DRV-7", "DRQ-1", "DRQ-3", "DRQ-4",
    ]
    evaluator_action_rules = [
        "DRD-1", "DRD-2", "DRD-4", "DRD-8", "DRD-10", "DRD-11", "DRD-14", "DRC-15", "DRC-19",
        "DREB-16", "DREB-19", "DREB-20", "DREB-21", "DREB-22",
    ]
    submitted_pass_rules = common_pass_rules + evaluator_action_rules + [
        "DRE-1", "DRE-3", "DRE-4", "DRE-5", "DRE-6", "DRE-10", "DRD-3", "DRAA-6",
    ]
    release_pass_rules = submitted_pass_rules + ["DRD-5", "DRT-1", "DRT-5", "DRL-6"]
    rejection_pass_rules = submitted_pass_rules + ["DRD-6", "DRD-13", "DRT-2", "DRT-6", "DRL-5"]
    pre_submission_pass_rules = common_pass_rules + evaluator_action_rules + [
        "DRA-16", "DRD-6", "DRD-9", "DRD-12", "DRD-13", "DRX-1", "DRX-2", "DRX-5", "DRX-6",
        "DRX-7", "DRX-9", "DRT-2", "DRT-6", "DRL-5",
    ]
    expiry_pass_rules = common_pass_rules + [
        "DRA-16", "DRD-7", "DRL-5", "DRT-3", "DRT-6", "DRT-9", "DRT-13", "DRX-6",
    ]
    dispute_rules = ["DRX-1", "DRX-2", "DRX-5", "DRX-6", "DRX-7", "DRX-9"]

    vectors = [
        # Positive lifecycles.
        vector("release-complete-budget", "release", "pass", "DRV-7", "fund, deliver, evaluate, and release the complete budget (§11.1 P1, P6)", rules=release_pass_rules),
        vector("evaluator-rejection-refund", "rejected-refund", "pass", "DRV-7", "a signed post-submission rejection refunds the complete budget (§11.1 P2)", rules=rejection_pass_rules),
        vector("pre-submission-evaluator-rejection", "pre-submission-rejected-refund", "pass", "DRV-7", "agreement-authorized pre-submission rejection uses a DisputeOutcome and omits delivery evidence (§11.1 P5)", rules=pre_submission_pass_rules),
        vector("expiry-before-submission", "expired-pre", "pass", "DRV-7", "pre-submission expiry refunds without a decision or delivery reference (§11.1 P3)", rules=expiry_pass_rules),
        vector("expiry-after-submission-grace", "expired-post", "pass", "DRV-7", "post-submission expiry refunds at the evaluation deadline without inventing a decision (§11.1 P4)", rules=expiry_pass_rules + ["DRL-6"]),
        vector("dreb-15-recovery-after-deadline", "dreb-15-recovery-after-deadline", "pass", "DRV-7", "DREB-15: expiry recovery after the evaluation deadline remains valid", rules=expiry_pass_rules),
        vector("drd-8-same-terminal-again", "release", "pass", "DRV-7", "DRD-8, DRL-4, DRT-16: verifying the same terminal again reproduces the same evidence and verdict (§11.1 P8)", rules=["DRD-8", "DRL-4", "DRT-16", "DRV-7", "DRW-7"], evaluated_with=["release-complete-budget"]),
        vector("native-job-id-zero", "native-job-id-zero", "pass", "DRV-7", "DRJ-1: native job 0 is minimal unsigned decimal text and names a job", rules=["DRJ-1", "DRV-7"]),
        vector("rejected-refund-buyer-fault", "rejected-refund-buyer-fault", "pass", "DRV-7", "DRT-14: a rejected refund with a buyer-fault finding projects buyer failed-perm, seller failed-counterparty (§11.1 P10)", rules=rejection_pass_rules + ["DRX-5"]),
        vector("rejected-refund-substrate-failure", "rejected-refund-substrate-failure", "pass", "DRV-7", "DRT-14: a rejected refund with a substrate-failure finding projects failed-substrate for both copies (§11.1 P10)", rules=rejection_pass_rules + ["DRX-6"]),
        vector("rejected-refund-no-fault", "rejected-refund-no-fault", "pass", "DRV-7", "DRT-14: a rejected refund with a no-fault finding projects no fault (§11.1 P10)", rules=rejection_pass_rules + ["DRX-6"]),
        vector("dispute-outcome-release", "dispute-release", "pass", "DRV-7", "DRX-9: a seller-fulfilled DisputeOutcome authorizes a post-submission release", rules=release_pass_rules + dispute_rules),
        vector("post-submission-dispute-refund", "post-submission-dispute-refund", "pass", "DRV-7", "DRX-9: a no-fault DisputeOutcome authorizes a post-submission refund", rules=rejection_pass_rules + dispute_rules),
        # DRP: pipeline shape.
        vector("pipeline-missing-terminal", "release", "fail", "DRP-1", "an unpaired escrow phase is rejected", [{"op": "remove", "path": ["pipeline", TERMINAL_PHASE_INDEX]}]),
        vector("pipeline-actions-reversed", "release", "fail", "DRP-2", "escrow phases must be fund then terminal", [{"op": "replace", "path": ["pipeline", FUND_PHASE_INDEX, "parameters", "action"], "value": "terminal"}]),
        vector("pipeline-second-delivery", "second-delivery-phase", "fail", "DRP-3", "only one delivery step may occur between the escrow phases"),
        vector("pipeline-extra-payment", "release", "fail", "DRP-4", "ordinary payment phases cannot accompany the pair", [{"op": "add", "path": ["pipeline", TERMINAL_PHASE_INDEX + 1], "value": {"kind": "pay-x402"}}]),
        vector("pipeline-pay-alternative", "release", "fail", "DRP-4", "a pay-alternative step cannot accompany the pair", [{"op": "add", "path": ["pipeline", TERMINAL_PHASE_INDEX + 1], "value": {"kind": "pay-alternative"}}]),
        vector("pipeline-unsupported-phase-kind", "release", "error", "DRV-2", "an unsupported phase kind is a candidate §9 step-1 discriminator, which no rule names yet; the DRV-2 label is pending #371's named step-1 rule", [{"op": "add", "path": ["pipeline", TERMINAL_PHASE_INDEX + 1], "value": {"kind": "notify"}}]),
        vector("pipeline-unprefixed-escrow-kind", "release", "error", "DRV-2", "DRG-3: `job-escrow` is not the candidate's `x-job-escrow` name, so it is an unknown phase kind", [{"op": "replace", "path": ["pipeline", FUND_PHASE_INDEX, "kind"], "value": "job-escrow"}, {"op": "replace", "path": ["pipeline", TERMINAL_PHASE_INDEX, "kind"], "value": "job-escrow"}], rules=["DRG-3", "DRV-2"]),
        vector("pipeline-commit-phase-missing", "release", "fail", "DRP-14", "the pipeline must commit the agreement and overlay before funding", [{"op": "remove", "path": ["pipeline", COMMIT_STEP_INDEX]}]),
        vector("pipeline-commit-phase-unsupported", "release", "error", "DRP-14", "an agreementPhase outside DRP-14's two values is an error", [{"op": "replace", "path": ["pipeline", COMMIT_STEP_INDEX, "parameters", "agreementPhase"], "value": "commit-agreement"}]),
        vector("pipeline-commit-phase-identity-bound", "release", "error", "DRV-2", "the identity-bound commit needs the IBH gates, which this pack does not model, so it fails closed", [{"op": "replace", "path": ["pipeline", COMMIT_STEP_INDEX, "parameters", "agreementPhase"], "value": "commit-identity-bound-payee-agreement"}], rules=["DRP-14", "DRV-2"]),
        # DRP-18: the commit step is the PS-2 commitment phase, immediately
        # after the one negotiation step, with no DACS-3 commitment kind.
        vector("pipeline-negotiation-missing", "release", "fail", "DRP-18", "PS-1: the pipeline has exactly one negotiate-* step, and the commit step follows it", [{"op": "remove", "path": ["pipeline", NEGOTIATION_STEP_INDEX]}]),
        vector("pipeline-second-negotiation", "release", "fail", "DRP-18", "PS-1: a second negotiate-* step is not one negotiation", [{"op": "add", "path": ["pipeline", TERMINAL_PHASE_INDEX + 1], "value": {"kind": "negotiate-rfq"}}]),
        vector("pipeline-commit-before-negotiation", "release", "fail", "DRP-18", "PS-2: the commit step immediately follows the negotiation, not precedes it", [{"op": "replace", "path": ["pipeline", NEGOTIATION_STEP_INDEX], "value": {"kind": "x-commit-delivery-or-remedy-agreement", "parameters": {"agreementPhase": "commit-payee-bound-agreement"}}}, {"op": "replace", "path": ["pipeline", COMMIT_STEP_INDEX], "value": {"kind": NEGOTIATION_KIND}}]),
        vector("pipeline-second-commit-step", "release", "fail", "DRP-18", "PS-2: the pipeline has one agreement commitment phase, so a second commit step fails", [{"op": "add", "path": ["pipeline", TERMINAL_PHASE_INDEX + 1], "value": {"kind": "x-commit-delivery-or-remedy-agreement", "parameters": {"agreementPhase": "commit-payee-bound-agreement"}}}]),
        vector("pipeline-dacs3-commitment-beside-commit", "release", "fail", "DRP-18", "PS-2: the commit step is the commitment phase, so a DACS-3 commitment kind cannot accompany it", [{"op": "add", "path": ["pipeline", TERMINAL_PHASE_INDEX + 1], "value": {"kind": "commit-payee-bound-agreement"}}]),
        vector("pipeline-complete-sealed-negotiation", "release", "fail", "DRP-18", "PS-2 pairs a complete sealed-envelope negotiation only with commit-selection-bound-agreement, so it cannot precede the payee-bound commit step", [{"op": "replace", "path": ["pipeline", NEGOTIATION_STEP_INDEX, "kind"], "value": "negotiate-sealed-envelope-complete"}]),
        vector("drp-3-attested-payload-delivery-unmodelled", "drp-3-attested-payload-delivery", "fail", "DRP-3", "DRP-3: this pack does not model attested-payload delivery, so a success without a DPA-6 attestationRef never verifies", rules=["DRE-2", "DRP-3"]),
        vector("drp-3-entitlement-delivery-unmodelled", "drp-3-entitlement-delivery", "fail", "DRP-3", "DRP-3: this pack does not model entitlement delivery, so it never verifies", rules=["DRE-2", "DRP-3"]),
        vector("pipeline-unsupported-delivery-kind", "release", "fail", "DRP-3", "DRP-3: the one delivery between the escrow steps must be a supported deliver-* kind", [{"op": "replace", "path": ["pipeline", DELIVERY_PHASE_INDEX, "kind"], "value": "deliver-unsupported"}]),
        vector("pipeline-rail-divergence", "release", "fail", "DRP-5", "both escrow invocations must name the agreement-selected rail", [{"op": "replace", "path": ["pipeline", TERMINAL_PHASE_INDEX, "parameters", "rail"], "value": f"x-evm-erc8183:{CHAIN_ID}:OTHER"}]),
        vector("drp-5-escrow-phase-rails", "release", "fail", "DRP-5", "both escrow phases must name the agreement-selected rail", [{"op": "replace", "path": ["pipeline", FUND_PHASE_INDEX, "parameters", "rail"], "value": f"x-evm-erc8183:{CHAIN_ID}:OTHER"}, {"op": "replace", "path": ["pipeline", TERMINAL_PHASE_INDEX, "parameters", "rail"], "value": f"x-evm-erc8183:{CHAIN_ID}:OTHER"}]),
        vector("pipeline-delivery-before-final-funding", "release", "fail", "DRP-6", "delivery cannot begin before the funding result is finalized", [{"op": "replace", "path": ["executionContext", "fundingFinalizedBeforeDelivery"], "value": False}]),
        vector("drv-3-purchase-count-boolean", "release", "error", "DRV-3", "a boolean purchase count is malformed input, not the count 0", [{"op": "replace", "path": ["executionContext", "dacs5PurchaseCount"], "value": False}], rules=["DRP-8", "DRV-3"]),
        vector("drv-3-purchase-count-float", "release", "error", "DRV-3", "a float purchase count is malformed input, not the integer count 0", [{"op": "replace", "path": ["executionContext", "dacs5PurchaseCount"], "value": 0.0}], rules=["DRP-8", "DRV-3"]),
        vector("dacs5-volume-before-promotion", "release", "fail", "DRP-8", "before the DACS-5 projection is promoted, the pair contributes no purchase or volume (§11.2 R34)", [{"op": "replace", "path": ["executionContext", "dacs5PurchaseCount"], "value": 1}], rules=["DRP-8", "DRT-14"]),
        vector("pipeline-double-counted-purchase", "release", "fail", "DRP-8", "the paired escrow lifecycle never counts as two purchases", [{"op": "replace", "path": ["executionContext", "dacs5PurchaseCount"], "value": 2}]),
        vector("pipeline-escrow-rail-not-accepted", "release", "fail", "DRP-10", "job escrow participates in the acceptedRails selection gate", [{"op": "replace", "path": ["executionContext", "acceptedRails"], "value": []}]),
        vector("drr-3-accepted-rail-other-version", "release", "fail", "DRR-3", "the acceptedRails reference must resolve to the selected rail version", [{"op": "replace", "path": ["executionContext", "acceptedRails", 0, "railVersion"], "value": 2}]),
        vector("pipeline-funding-before-final-commitment", "release", "fail", "DRP-11", "the finalized overlay commitment gates value locking", [{"op": "replace", "path": ["executionContext", "commitmentReceipts", "overlay", "status"], "value": "included"}]),
        vector("pipeline-agreement-commitment-not-final", "release", "fail", "DRP-11", "the finalized bilateral-agreement commitment gates value locking too", [{"op": "replace", "path": ["executionContext", "commitmentReceipts", "agreement", "status"], "value": "included"}]),
        vector("pipeline-terminal-before-delivery-return", "release", "fail", "DRP-12", "terminal execution waits for the delivery return on the ordinary path", [{"op": "replace", "path": ["executionContext", "terminalGate"], "value": "submission-cutoff"}]),
        vector("pipeline-late-delivery-not-disabled", "expired-pre", "fail", "DRP-12", "a cutoff refund permanently disables late delivery submission", [{"op": "replace", "path": ["executionContext", "lateDeliveryDisabled"], "value": False}]),
        vector("pipeline-phase-index-divergence", "delivery-phase-index-divergence", "fail", "DRA-11", "signed indexes must match the phase pair"),
        # DRA, DRQ: the bilateral agreement and the signed overlay.
        vector("bilateral-agreement-reference-mismatch", "bilateral-reference-mismatch", "fail", "DRA-1", "the overlay must resolve the exact bilateral agreement"),
        vector("bilateral-agreement-hash-mismatch", "bilateral-hash-mismatch", "fail", "DRA-2", "the overlay must carry the recomputed bilateral agreement hash"),
        vector("bilateral-agreement-seller-unsigned", "dra-1-bilateral-seller-unsigned", "fail", "DRA-1", "the bilateral agreement both commercial parties signed is the one the overlay binds"),
        vector("overlay-signature-missing", "release", "fail", "DRA-3", "all three overlay signatures are required", [{"op": "remove", "path": ["artifacts", "agreement", "signatures", 2]}]),
        vector("overlay-signature-invalid", "release", "fail", "DRA-3", "each overlay signature must verify under its role's key", [{"op": "replace", "path": ["artifacts", "agreement", "signatures", 2, "value"], "value": release["artifacts"]["agreement"]["signatures"][0]["value"]}]),
        vector("overlay-signature-roles-repeated", "release", "fail", "DRA-18", "the three overlay signature roles are distinct", [{"op": "replace", "path": ["artifacts", "agreement", "signatures", 2, "role"], "value": "buyer"}, {"op": "replace", "path": ["artifacts", "agreement", "signatures", 2, "party"], "value": BUYER}]),
        vector("overlay-signature-party-not-role-claim", "release", "fail", "DRA-18", "each overlay signature's party is its role's primary claim", [{"op": "replace", "path": ["artifacts", "agreement", "signatures", 2, "party"], "value": BUYER}]),
        vector("dra-17-bilateral-parties-swapped", "dra-17-bilateral-parties-swapped", "fail", "DRA-17", "the bilateral agreement's buyer and seller keep their overlay roles"),
        vector("dra-17-seller-bundle-differs", "dra-17-seller-bundle-differs", "fail", "DRA-17", "the overlay's seller binding equals the agreement's seller party byte for byte"),
        vector("dra-19-deadline-after-agreement", "dra-19-deadline-after-agreement", "fail", "DRA-19", "the evaluation deadline cannot fall after the agreement's settle-by deadline"),
        vector("dra-19-cutoff-beyond-seconds-bound", "dra-19-cutoff-beyond-seconds-bound", "error", "DRA-19", "a cutoff above the DRW-4 seconds bound is malformed", rules=["DRA-19", "DRW-4"]),
        vector("dra-20-payee-is-buyer", "dra-20-payee-is-buyer", "fail", "DRA-20", "the escrow payout binding pays the seller's EVM account"),
        vector("dra-20-payout-phase-index", "dra-20-payout-phase-index", "fail", "DRA-20", "the escrow payout binding is keyed by the fund phase"),
        vector("dra-20-second-payout-binding", "dra-20-second-payout-binding", "fail", "DRA-20", "the agreement carries exactly one payout binding, for the escrow pair"),
        vector("dra-20-payee-malformed", "dra-20-payee-malformed", "error", "DRW-1", "a payout address that is not a DRW-1 EVM address is malformed", rules=["DRA-20", "DRW-1"]),
        vector("dra-22-terms-rail-absent", "dra-22-terms-rail-absent", "fail", "DRA-22", "a concrete payment selection needs the agreement's terms.rail"),
        vector("dra-22-terms-rail-other-version", "dra-22-terms-rail-other-version", "fail", "DRA-22", "terms.rail must equal the selected acceptedRails reference"),
        vector("evaluator-requirement-hash-mismatch", "evaluator-requirement-mismatch", "fail", "DRA-8", "the evaluator requirement hash is independently recomputed"),
        vector("evaluator-vet-requirement-mismatch", "evaluator-vet-requirement-mismatch", "fail", "DRA-8", "the evaluator Vet record must use the bound requirement"),
        vector("evaluator-vet-not-fresh-at-funding", "evaluator-vet-expired-at-funding", "fail", "DRA-9", "the evaluator Vet pass must be fresh at the authenticated funding time"),
        vector("nonminimal-budget-base-units", "nonminimal-budget", "error", "DRA-10", "the signed budget uses minimal unsigned decimal text"),
        vector("dra-10-budget-not-agreed-amount", "dra-10-price-amount", "fail", "DRA-10", "the budget is not the agreed 2 FXT converted at the rail's 6 decimals"),
        vector("dra-21-price-currency-not-rail-asset", "dra-21-price-currency", "fail", "DRA-21", "the agreed price currency must be the rail asset symbol"),
        vector("dra-10-budget-uses-other-decimals", "dra-10-token-decimals", "fail", "DRA-10", "the agreed 1 FXT at the rail's pinned 18 decimals is not 1000000 base units"),
        vector("dra-10-zero-budget-for-nonzero-price", "dra-10-zero-budget", "fail", "DRA-10", "a zero budget is not the non-zero agreed price"),
        vector("dra-10-zero-price", "dra-10-zero-price", "fail", "DRA-10", "an agreed price must be strictly greater than zero (DACS-4 §9.3), so a zero price and its zero budget move nothing"),
        vector("dra-10-price-not-whole-base-units", "dra-10-excess-precision", "fail", "DRA-10", "a price with more fractional digits than the rail's 6 token decimals is not a whole number of base units"),
        vector("rail-definition-reference-mismatch", "rail-reference-mismatch", "fail", "DRP-5", "the agreement-selected rail definition must resolve exactly", rules=["DRF-9", "DRP-5"]),
        vector("evaluator-added-as-bundle-party", "release", "fail", "DRA-13", "the evaluator overlay signature does not create a third bundle party", [{"op": "add", "path": ["bundleRequiredSigners", 2], "value": EVALUATOR}]),
        vector("unsupported-disclosure-policy", "unsupported-disclosure-policy", "error", "DRQ-1", "a transcript-dependent disclosure policy is outside the first profile", rules=["DRQ-1", "DRQ-4"]),
        vector("transcript-input-disclosed", "transcript-in-delivered-artifact", "fail", "DRQ-3", "the candidate input pack cannot carry negotiation transcript material", rules=["DRQ-3", "DRQ-4"]),
        vector("evaluator-primary-claim-collision", "evaluator-claim-is-buyer", "fail", "DRA-6", "evaluator and buyer primary claims must differ"),
        vector("evaluator-account-collision", "evaluator-account-is-seller", "fail", "DRA-7", "evaluator and provider accounts must differ"),
        vector("evaluator-wrong-chain", "evaluator-account-other-chain", "fail", "DRA-5", "role accounts are bound to the selected chain"),
        vector("evaluator-account-zero-address", "evaluator-account-zero", "fail", "DRW-1", "the zero address cannot be a live role", rules=["DRA-7", "DRW-1"]),
        vector("evaluator-vet-failure", "release", "fail", "DRA-9", "evaluator must have a fresh pass", [{"op": "replace", "path": ["evaluatorVetResult"], "value": "fail"}]),
        vector("unsupported-expiry-only-policy", "expiry-only-policy", "error", "DRA-15", "an expiry-only pre-submission policy is an unsupported profile under DRA-15 (§11.2 R18)", rules=["DRA-15", "DRA-16"]),
        # DRP-9: delivery and native submission.
        vector("delivery-submission-circularity", "delivery-quotes-native-submission", "fail", "DRP-9", "the native submission transaction identity must commit to the delivery digest it submits"),
        vector("drp-9-digest-anchor-unavailable", "drp-9-digest-anchor-unavailable", "indeterminate", "DRP-9", "without authenticated evidence that the digest was fixed before submission, ordering stays indeterminate"),
        vector("drp-9-digest-anchor-other-digest", "drp-9-digest-anchor-other-digest", "fail", "DRP-9", "the authenticated anchor must fix this delivery evidence's digest"),
        vector("drp-9-digest-fixed-after-submission", "drp-9-digest-fixed-after-submission", "fail", "DRP-9", "a delivery digest fixed only after the native submission may derive from it"),
        vector("drp-9-digest-anchored-in-submission-block", "drp-9-digest-anchored-in-submission-block", "indeterminate", "DRP-9", "an anchor in the submission's own block cannot be ordered before it"),
        vector("drp-9-digest-anchor-time-equals-submission", "drp-9-digest-anchor-time-equals-submission", "fail", "DRF-8", "an anchor block earlier than the submission at the submission's block time contradicts the block order", rules=["DRF-8", "DRP-9"]),
        vector("deliveryless-lifecycle-carries-digest-anchor", "deliveryless-lifecycle-carries-digest-anchor", "fail", "DRP-9", "a lifecycle without delivery has no delivery digest for the resolver to anchor"),
        vector("drp-9-delivery-observed-after-submission", "drp-9-delivery-observed-after-submission", "fail", "DRP-9", "hashed delivery evidence cannot record a time after its digest was fixed"),
        vector("native-submission-at-cutoff", "native-submission-at-cutoff", "fail", "DREB-13", "a native submission accepted at the cutoff shows the implementation did not reject it", rules=["DRC-13", "DREB-13", "DREB-23"]),
        vector("submission-event-deliverable-mismatch", "release", "fail", "DRP-9", "the native submission event must carry the delivery digest", authenticated("release", observation("release", "JobSubmitted", "arguments", "deliverable", value="0x" + rehash_delivery))),
        vector("deliveryless-lifecycle-carries-submission-binding", "expired-pre", "fail", "DRP-9", "a lifecycle without delivery has no native submission to bind", [{"op": "replace", "path": ["deliveryBinding"], "value": {}}]),
        vector("delivery-binding-carries-conclusions", "release", "error", "DRV-3", "the delivery binding names the submission event and nothing else", [{"op": "add", "path": ["deliveryBinding", "status"], "value": "verified"}]),
        # DREB: exact ERC field mapping.  The description is read from the
        # createJob calldata (DRJ-4).
        vector("description-prefix-substitution", "release", "fail", "DREB-1", "the exact `dacs-x-` description prefix is bound; the superseded unprefixed one is not", authenticated("release", tx_record("release", 0, "calldata", "description", value="dacs-delivery-remedy:v1:" + release_hashes["agreementHash"])), rules=["DREB-1", "DRJ-4", "DRG-3"]),
        vector("description-sha256-prefix", "release", "fail", "DREB-1", "a sha256: textual prefix is not inserted", authenticated("release", tx_record("release", 0, "calldata", "description", value=DESCRIPTION_PREFIX + "sha256:" + release_hashes["agreementHash"])), rules=["DREB-1", "DREB-4", "DRJ-4"]),
        vector("uppercase-delivery-hash", "release", "fail", "DREB-3", "declared content hashes are lowercase", [{"op": "replace", "path": ["mappingSources", "deliveryHash"], "value": release_hashes["deliveryHash"].upper()}]),
        vector("prefixed-delivery-hash", "release", "fail", "DREB-3", "declared content hashes have no algorithm prefix", [{"op": "replace", "path": ["mappingSources", "deliveryHash"], "value": "sha256:" + release_hashes["deliveryHash"]}]),
        vector("delivery-hash-text-rehash", "release", "fail", "DREB-4", "deliverable is raw decoded hash bytes, not a text rehash", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + rehash_delivery}]),
        vector("delivery-byte-order-reversal", "release", "fail", "DREB-4", "deliverable byte order is not reinterpreted", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + reversed_delivery}]),
        vector("delivery-padding-truncation", "release", "fail", "DREB-4", "a shifted/padded digest is a binding mismatch", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + shifted_delivery}]),
        vector("zero-deliverable", "release", "fail", "DREB-5", "zero cannot stand in for delivery evidence", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + "00" * 32}]),
        vector("decision-hash-text-rehash", "release", "fail", "DREB-4", "reason is raw decoded decision hash bytes", [{"op": "replace", "path": ["native", "reason"], "value": "0x" + rehash_reason}]),
        vector("zero-decision-reason", "release", "fail", "DREB-5", "zero cannot stand in for an evaluator decision", [{"op": "replace", "path": ["native", "reason"], "value": "0x" + "00" * 32}]),
        vector("native-reason-other-decision", "release", "fail", "DREB-6", "the authenticated complete call and log carry another decision's hash", authenticated("release", tx_record("release", -1, "calldata", "reason", value="0x" + rehash_reason) + observation("release", "JobCompleted", "arguments", "reason", value="0x" + rehash_reason)), rules=["DREB-6", "DRD-14"]),
        vector("malformed-native-reason", "release", "error", "DRV-3", "malformed native reason bytes are not repaired", [{"op": "replace", "path": ["native", "reason"], "value": "0x12"}]),
        vector("decision-hash-substitution", "release", "fail", "DREB-2", "declared decision hash must be independently recomputed", [{"op": "replace", "path": ["mappingSources", "decisionHash"], "value": "99" * 32}]),
        vector("canonical-record-stale", "release", "fail", "DREB-2", "pinned canonical bytes and mapped values are recomputed", [{"op": "replace", "path": ["canonicalRecords", "delivery", "mappedNativeValue"], "value": "0x" + "99" * 32}]),
        vector("native-client-mismatch", "release", "fail", "DREB-7", "native client must equal the buyer-controlled account", [{"op": "replace", "path": ["native", "client"], "value": "0x" + "66" * 20}]),
        vector("native-provider-mismatch", "release", "fail", "DREB-8", "native provider must equal the seller-controlled account", [{"op": "replace", "path": ["native", "provider"], "value": "0x" + "66" * 20}]),
        vector("native-evaluator-mismatch", "release", "fail", "DREB-9", "native evaluator must equal the controlled evaluator account", [{"op": "replace", "path": ["native", "evaluator"], "value": "0x" + "66" * 20}]),
        vector("native-payout-receiver-mismatch", "release", "fail", "DREB-10", "native payout receiver must equal the seller-controlled account", [{"op": "replace", "path": ["native", "payoutReceiver"], "value": BUYER_ACCOUNT}]),
        vector("native-token-mismatch", "release", "fail", "DREB-11", "native token must equal the pinned rail asset", [{"op": "replace", "path": ["native", "token"], "value": "0x" + "66" * 20}]),
        vector("nonpositive-evaluation-window", "nonpositive-evaluation-window", "fail", "DREB-14", "registered rail windows must be positive"),
        vector("evaluation-window-too-short", "short-evaluation-window", "fail", "DREB-14", "the bound evaluation window must meet the rail's pinned minimum"),
        vector("detached-profile-projection-weakened", "release", "fail", "DRP-5", "a detached profile projection cannot weaken the authenticated rail policy", [{"op": "replace", "path": ["profileParameters", "minimumEvaluationWindowSec"], "value": 1}]),
        vector("native-expiry-divergence", "release", "fail", "DREB-12", "native expiredAt must equal the evaluation deadline", [{"op": "replace", "path": ["native", "expiredAt"], "value": EVALUATION_DEADLINE_SEC + 1}]),
        vector("native-submission-cutoff-divergence", "release", "fail", "DREB-13", "the native submission cutoff must equal the signed cutoff", [{"op": "replace", "path": ["native", "submissionCutoffSec"], "value": SUBMISSION_CUTOFF_SEC + 1}]),
        vector("native-submission-cutoff-unenforced", "release", "fail", "DREB-13", "the resolved native state must enforce the submission cutoff", authenticated("release", native_state("submissionCutoffEnforced", False)), rules=["DREB-13", "DREB-23"]),
        vector("native-expiry-recovery-too-early", "release", "fail", "DREB-15", "the resolved expiry recovery time must be the evaluation deadline", authenticated("release", native_state("expiryRecoveryAtSec", SUBMISSION_CUTOFF_SEC))),
        # DREB-16..22: direct evaluator transaction model.
        vector("evaluator-binding-not-direct", "release", "fail", "DREB-16", "the resolved native evaluator must be bound directly", authenticated("release", native_state("evaluatorBindingMode", "adapter"))),
        vector("unsupported-evaluator-account-type", "release", "error", "DREB-18", "only EOA and EIP-1271 evaluator account labels are read", authenticated("release", terminal_call("release", "nativeCallerAccountType", "module"))),
        vector("eip1271-relayed-execution", "release", "fail", "DREB-18", "this verifier supports no EIP-1271 chain and code, so a relayed EIP-1271 evaluator call is refused (§11.2 R15); §11.1 P7 cannot be produced here", authenticated("release", terminal_call("release", "nativeCallerAccountType", "eip1271") + terminal_call("release", "outerSubmitter", RELAYER_ACCOUNT)), rules=["DREB-18", "DREB-22"]),
        vector("evaluator-adapter-substitution", "release", "fail", "DREB-20", "a resolved generic adapter is outside the first profile", authenticated("release", native_state("evaluatorAdapter", RELAYER_ACCOUNT))),
        vector("relayer-substituted-as-native-caller", "release", "fail", "DREB-21", "a relayer cannot replace the agreement-bound evaluator as native caller", authenticated("release", terminal_call("release", "nativeCaller", RELAYER_ACCOUNT) + terminal_call("release", "outerSubmitter", RELAYER_ACCOUNT)), rules=["DREB-19", "DREB-21"]),
        vector("transaction-record-for-another-transaction", "release", "fail", "DRL-10", "the resolver's terminal record must describe the terminal transaction", authenticated("release", terminal_call("release", "txHash", "ee" * 32))),
        vector("resolver-transaction-tx-hash-0x-prefixed", "release", "error", "DRV-3", "a resolver transaction record keeps the SB-1 canonical txHash spelling; the legacy 0x spelling is malformed", authenticated("release", terminal_call("release", "txHash", "0x" + release["artifacts"]["terminal"]["terminalEventRefs"][0]["txHash"])), rules=["DRV-3", "DRW-3"]),
        vector("eoa-relayed-outer-submitter", "release", "fail", "DREB-22", "an EOA evaluator must itself submit the native transaction", authenticated("release", terminal_call("release", "outerSubmitter", RELAYER_ACCOUNT))),
        vector("malformed-outer-submitter", "release", "error", "DRV-3", "the outer submitter is an EVM address", authenticated("release", terminal_call("release", "outerSubmitter", "relayer")), rules=["DREB-22", "DRV-3"]),
        # DRD-8, DRL-4, DRT-4: replay of decisions and terminals.
        vector("cross-job-delivery-replay", "delivery-from-another-job", "fail", "DRD-8", "delivery from another job cannot be replayed"),
        vector("cross-job-decision-replay", "decision-from-another-job", "fail", "DRD-8", "decision from another job cannot be replayed"),
        vector("consumed-decision-replay", "release", "fail", "DRD-8", "DRD-8: a decision the resolver saw consumed by another transaction is one-use", authenticated("release", history([prior_terminal("release", tx_preimage=f"{JOB_A}:complete:earlier", decision_hash=release_decision_hash)]))),
        vector("resolver-history-shows-terminal-job", "rejected-refund", "fail", "DRL-4", "DRL-4: a native job the resolver saw reach a terminal state cannot settle again", authenticated("rejected-refund", history([prior_terminal("rejected-refund", tx_preimage="earlier-terminal", decision_hash=release_decision_hash)]))),
        vector("resolver-history-shows-event-settled-another-job", "release", "fail", "DRT-4", "DRT-4: a terminal event the resolver saw settle another native job is not this job's", authenticated("release", history([prior_terminal("release", native_job_id="2")]))),
        vector("resolver-history-tx-hash-0x-prefixed", "release", "error", "DRV-3", "a resolver-attested earlier terminal keeps the SB-1 canonical txHash spelling; the legacy 0x spelling is malformed", authenticated("release", history([{**prior_terminal("release", native_job_id="2"), "txHash": "0x" + prior_terminal("release")["txHash"]}])), rules=["DRV-3", "DRW-3"]),
        # Terminals evaluated together: the earlier by authenticated event
        # position holds, in any order of evaluation.
        vector("decision-reused-by-another-terminal-transaction", "release-second-terminal-transaction", "fail", "DRD-8", "DRD-8: a decision that authorized an earlier terminal transaction cannot authorize another", evaluated_with=["release-complete-budget"], rules=["DRD-8", "DRT-16"]),
        vector("second-terminal-for-terminal-job", "release-job-rejection", "fail", "DRL-4", "DRL-4: a native job that reached a terminal state earlier cannot settle again", evaluated_with=["release-complete-budget"], rules=["DRL-4", "DRT-16"]),
        vector("terminal-event-settles-another-job", "other-job-reuses-release-terminal-event", "fail", "DRT-4", "DRT-4: one terminal event cannot settle two native jobs", evaluated_with=["release-complete-budget"]),
        vector("drd-8-terminals-share-event-position", "release-same-position-terminal-transaction", "indeterminate", "DRD-8", "DRD-8: conflicting terminals at one authenticated event position cannot be ordered", evaluated_with=["release-complete-budget"]),
        vector("drd-8-earlier-terminal-prevails", "release-earlier-terminal-transaction", "pass", "DRV-7", "DRD-8 and DRL-4: of two conflicting terminals, the earlier by authenticated event position holds when the later one's attested history names it", rules=["DRD-8", "DRL-4", "DRV-7"], evaluated_with=["consumed-decision-replay"]),
        vector("drd-8-later-terminal-history-incomplete", "release-earlier-terminal-transaction", "indeterminate", "DRD-8", "DRD-8: an earlier terminal that a later conflicting terminal's attested history omits cannot be confirmed", evaluated_with=["release-complete-budget"]),
        # DRE, DRD: evaluation and decision.
        vector("wrong-evaluator-signer", "release", "fail", "DRE-1", "commercial parties cannot sign evaluator artifacts", [{"op": "replace", "path": ["artifacts", "evaluation", "signature"], "value": bad_signer}]),
        vector("wrong-decision-signer", "release", "fail", "DRD-1", "only the agreement-bound evaluator may sign the escrow decision", [{"op": "replace", "path": ["artifacts", "decision", "signature"], "value": bad_decision_signer}]),
        vector("decision-signed-under-registered-domain", "release", "fail", "DRD-1", "DRG-1: a candidate signature over a registered-looking domain does not verify under the candidate domain", [{"op": "replace", "path": ["artifacts", "decision", "signature"], "value": relabelled_domain_signer}], rules=["DRD-1", "DRG-1"]),
        vector("delivery-reference-mismatch", "delivery-reference-mismatch", "fail", "DRE-2", "the delivery reference must resolve the signed delivery evidence"),
        vector("dre-2-delivery-phase-kind", "dre-2-delivery-phase-kind", "fail", "DRE-2", "delivery evidence must name the agreed delivery step", rules=["DRE-2", "DRP-7"]),
        vector("drp-7-delivery-phase-index", "drp-7-delivery-phase-index", "fail", "DRP-7", "the DeliveryEvidence phase index is the overlay's delivery phase (§11.2 R19)", rules=["DRE-2", "DRP-7"]),
        vector("drp-7-historical-settlement-evidence", "drp-7-historical-settlement-evidence", "fail", "DRP-7", "a delivery-shaped SettlementEvidence does not satisfy this profile (PDE-1, PDE-7, §11.2 R19)", rules=["DRE-2", "DRP-7"]),
        vector("dre-2-deliverable-anchor-kind", "dre-2-deliverable-anchor-kind", "fail", "DRE-2", "a storage-program delivery anchors a Storage Program, not another anchor kind", rules=["DRE-2", "DRP-7"]),
        vector("dre-2-deliverable-anchor-other-job", "dre-2-deliverable-anchor-other-job", "fail", "DRE-2", "the PDE-3 deliverable address is this job's", rules=["DRE-2", "DRP-7"]),
        vector("dre-2-deliverable-anchor-unindexed", "dre-2-deliverable-anchor-unindexed", "fail", "DRE-2", "PDE-3 phase-indexes the deliverable address", rules=["DRE-2", "DRP-7"]),
        vector("dre-2-deliverable-anchor-native-locator", "dre-2-deliverable-anchor-native-locator", "fail", "DRE-2", "PDE-4 requires the logical phase-indexed address, not a native stor- locator", rules=["DRE-2", "DRP-7"]),
        vector("drv-3-delivery-evidence-shape", "drv-3-delivery-evidence-shape", "error", "DRV-3", "delivery evidence keeps the exact DACS-4 DeliveryEvidence shape", rules=["DRE-2", "DRV-3"]),
        vector("drp-7-failed-delivery", "drp-7-failed-delivery", "fail", "DRP-7", "a failure DeliveryEvidence is never submitted natively or used for a decision (§11.2 R19)", rules=["DRE-2", "DRP-7"]),
        vector("drv-3-failed-delivery-empty-reason", "drv-3-failed-delivery-empty-reason", "error", "DRV-3", "a failed DeliveryEvidence carries a non-empty reason", rules=["DRE-2", "DRV-3"]),
        vector("drd-8-evaluation-job-reference", "drd-8-evaluation-job-reference", "fail", "DRD-8", "the evaluation must reference this escrow job"),
        vector("drd-8-decision-job-reference", "drd-8-decision-job-reference", "fail", "DRD-8", "the decision must reference this escrow job"),
        vector("dre-5-evaluation-subject-unresolved", "dre-5-evaluation-subject-unresolved", "indeterminate", "DRE-5", "subject evidence that does not resolve to authenticated evidence stays indeterminate", rules=["DRE-3", "DRE-5"]),
        vector("dre-3-evaluation-subject-kind", "dre-3-evaluation-subject-kind", "fail", "DRE-3", "a subject reference must name the authenticated record's reference kind, not only its locator and hash"),
        vector("dre-3-evaluation-subject-contradiction", "dre-3-evaluation-subject-contradiction", "fail", "DRE-3", "a subject reference must hash-bind the authenticated record it names"),
        vector("drv-3-evaluation-subject-refs", "drv-3-evaluation-subject-refs", "error", "DRV-3", "evaluation subject references are an array of exact references", rules=["DRE-3", "DRV-3"]),
        vector("evaluation-reference-mismatch", "evaluation-reference-mismatch", "fail", "DRD-2", "the decision basis must resolve to the exact evaluation"),
        vector("decision-delivery-reference-mismatch", "decision-delivery-mismatch", "fail", "DRD-3", "the decision must bind the exact delivery evidence"),
        vector("release-decision-without-delivery", "release-without-delivery", "fail", "DRD-3", "DRD-3: a release decision needs the delivery evidence it releases against"),
        vector("decision-basis-not-the-evaluation", "decision-basis-other-evaluation", "fail", "DRD-2", "the decision basis must resolve to the signed evaluation"),
        vector("decision-basis-not-the-dispute-outcome", "decision-basis-other-dispute", "fail", "DRD-2", "the decision basis must resolve to the signed DisputeOutcome"),
        vector("decision-reference-mismatch", "decision-reference-mismatch", "fail", "DRD-4", "the decision reference must resolve exactly"),
        vector("pre-submission-decision-carries-delivery", "pre-submission-decision-with-delivery", "fail", "DRD-14", "a pre-submission decision omits delivery evidence (§11.2 R23)", rules=["DRD-9", "DRD-14"]),
        vector("refund-without-delivery-needs-dispute-basis", "evaluation-refund-without-delivery", "fail", "DRD-9", "DRD-9: a refund decided before delivery uses a DisputeOutcome basis"),
        vector("dispute-outcome-recommends-other-disposition", "dispute-recommends-release", "fail", "DRX-9", "the decision disposition must be the DisputeOutcome's recommendation"),
        vector("dispute-outcome-without-recommendation", "dispute-without-recommendation", "fail", "DRX-9", "a DisputeOutcome basis carries a recommended disposition (§11.2 R41)"),
        vector("dispute-outcome-evaluator-unavailable", "dispute-evaluator-unavailable", "fail", "DRX-9", "an evaluator-unavailable finding authorizes no disposition (§11.2 R41)", rules=["DRD-2", "DRX-9"]),
        vector("dispute-outcome-revision-unlinked", "dispute-later-revision-unlinked", "fail", "DRAA-7", "a later dispute revision references the exact prior revision (§11.2 R29)"),
        vector("decision-without-authenticated-basis", "decision-without-basis-artifact", "indeterminate", "DRD-2", "an evaluation the decision rests on but the caller did not supply stays indeterminate (candidate §9 step 5, §11.3 I5)"),
        vector("decision-basis-kind-unsupported", "decision-basis-kind-unsupported", "fail", "DRD-2", "a decision basis that is neither an evaluation nor a DisputeOutcome authorizes no terminal action"),
        vector("indeterminate-evaluation-authorizes-terminal", "indeterminate-evaluation", "fail", "DRE-4", "an indeterminate evaluation cannot authorize settlement"),
        vector("reject-evaluation-release-action", "reject-then-release", "fail", "DRD-2", "rejection cannot authorize release"),
        vector("accept-evaluation-refund-action", "accept-then-refund", "fail", "DRD-2", "acceptance cannot authorize refund"),
        vector("drv-3-evaluation-not-object", "release", "error", "DRV-3", "an evaluation that is not an object is malformed input, not another job's", [{"op": "replace", "path": ["artifacts", "evaluation"], "value": 7}]),
        vector("drv-3-agreement-phase-index-boolean", "drv-3-agreement-phase-index-boolean", "error", "DRV-3", "a signed boolean phase index is malformed input, not index 1", rules=["DRA-11", "DRV-3"]),
        vector("drv-3-funding-phase-index-boolean", "drv-3-funding-phase-index-boolean", "error", "DRV-3", "a signed boolean funding phase index is malformed input, not index 1", rules=["DRF-1", "DRV-3"]),
        vector("drv-3-evaluation-result", "drv-3-evaluation-result", "error", "DRV-3", "a signed evaluation result outside the closed set cannot authorize settlement"),
        vector("drv-3-decision-disposition", "drv-3-decision-disposition", "error", "DRV-3", "a signed decision disposition outside the closed set cannot map to a native action"),
        vector("release-decision-native-reject", "release", "fail", "DRD-5", "a release decision maps only to native complete", [{"op": "replace", "path": ["native", "terminalAction"], "value": "reject"}]),
        vector("refund-decision-native-complete", "rejected-refund", "fail", "DRD-6", "a refund decision maps only to native reject", [{"op": "replace", "path": ["native", "terminalAction"], "value": "complete"}]),
        # DRT: terminal evidence.
        vector("partial-terminal-release", "partial-release", "fail", "DRT-5", "terminal release must cover the complete budget"),
        vector("terminal-decision-reference-mismatch", "terminal-decision-mismatch", "fail", "DRT-1", "terminal release must reference the exact decision"),
        vector("refund-terminal-decision-reference-mismatch", "refund-terminal-decision-mismatch", "fail", "DRT-2", "an evaluator refund must reference the exact decision"),
        vector("terminal-funding-reference-mismatch", "terminal-funding-mismatch", "fail", "DRT-11", "terminal evidence must reference the exact finalized funding record"),
        vector("terminal-job-reference-mismatch", "terminal-job-reference-mismatch", "fail", "DRT-4", "terminal evidence must reference the exact escrow job"),
        vector("terminal-delivery-reference-mismatch", "terminal-delivery-reference-mismatch", "fail", "DRT-12", "post-submission terminal evidence must reference the exact delivery"),
        vector("terminal-phase-index-mismatch", "terminal-phase-index-mismatch", "fail", "DRT-15", "terminal evidence carries the overlay's terminal phase index"),
        vector("drv-3-terminal-state-array", "drv-3-terminal-state-array", "error", "DRV-3", "a signed terminal whose terminalState is an array is malformed input"),
        vector("drv-3-terminal-state-object", "drv-3-terminal-state-object", "error", "DRV-3", "a signed terminal whose terminalState is an object is malformed input"),
        vector("drv-3-terminal-state-unknown-string", "drv-3-terminal-state-unknown-string", "error", "DRV-3", "a signed terminal whose terminalState is a string outside the closed value set is malformed input"),
        vector("native-terminal-state-divergence", "release", "fail", "DRT-4", "the native terminal state must equal the signed terminal state", [{"op": "replace", "path": ["native", "terminalState"], "value": "rejected-refund"}]),
        vector("funding-job-reference-mismatch", "funding-job-mismatch", "fail", "DRF-1", "funding evidence must reference the exact escrow job"),
        vector("funding-phase-index-mismatch", "funding-phase-index-mismatch", "fail", "DRF-1", "funding evidence must bind the agreement's fund phase index"),
        vector("funding-token-mismatch", "funding-token-mismatch", "fail", "DRF-2", "funding evidence must bind the pinned token"),
        vector("wrong-release-recipient", "wrong-release-recipient", "fail", "DRT-5", "release goes only to the bound seller payout account"),
        vector("wrong-refund-recipient", "wrong-refund-recipient", "fail", "DRT-6", "refund goes only to the client"),
        vector("expiry-refund-wrong-recipient", "expiry-refund-to-seller", "fail", "DRT-6", "an expiry refund goes only to the client"),
        vector("release-overclaims-nonfinancial-completion", "release", "fail", "DRL-6", "financial release alone cannot establish completion of every non-financial obligation", [{"op": "replace", "path": ["reputationProjection", "releaseAloneEstablishesNonFinancialCompletion"], "value": True}]),
        vector("release-invents-seller-fault", "release", "fail", "DRT-14", "a caller projection cannot contradict the projection table for a seller-fulfilled release", [{"op": "replace", "path": ["reputationProjection", "faultedParty"], "value": "seller"}]),
        vector("rejected-refund-erases-seller-fault", "rejected-refund", "fail", "DRT-14", "a caller projection cannot erase the authenticated seller-fault projection", [{"op": "replace", "path": ["reputationProjection", "sellerAnchoredOutcome"], "value": None}]),
        vector("refund-projected-as-seller-fault", "rejected-refund-no-fault", "fail", "DRT-14", "a no-fault refund is not projected as seller fault (§11.2 R38)", [{"op": "replace", "path": ["reputationProjection", "faultedParty"], "value": "seller"}], rules=["DRL-5", "DRT-14"]),
        vector("nonzero-preterminal-payout", "release", "fail", "DRL-7", "the resolved native state shows no preterminal provider payout", authenticated("release", native_state("preterminalProviderPayoutBaseUnits", "1")), rules=["DRF-5", "DRL-7"]),
        vector("nonzero-platform-fee", "release", "fail", "DRT-7", "the resolved native fees must be the rail's zero fees", authenticated("release", native_state("platformFeeBP", 1))),
        # Finality and event observations.
        vector("creation-finality-pending", "release", "indeterminate", "DRJ-2", "an under-confirmed creation event cannot establish the native job", authenticated("release", observation("release", "JobCreated", "finalityBlock", value=None))),
        vector("funding-finality-pending", "funding-finality-pending", "indeterminate", "DRF-6", "under-confirmed funding-event evidence cannot unlock delivery"),
        vector("submission-finality-pending", "release", "indeterminate", "DRP-9", "an under-confirmed submission event cannot bind the delivery to the native job", authenticated("release", observation("release", "JobSubmitted", "finalityBlock", value=None))),
        vector("funding-events-empty", "funding-events-empty", "fail", "DRW-7", "funding evidence references exactly its transition's one funding event", rules=["DRF-3", "DRW-7"]),
        vector("terminal-finality-pending", "terminal-finality-pending", "indeterminate", "DRT-8", "under-confirmed terminal-event evidence cannot establish disposition"),
        vector("terminal-events-empty", "terminal-events-empty", "fail", "DRW-7", "terminal evidence references exactly the crosswalk's terminal event set", rules=["DRT-4", "DRW-7"]),
        vector("terminal-events-state-log-only", "terminal-events-state-log-only", "fail", "DRW-7", "a release is the JobCompleted and PaymentReleased logs, not the state log alone (candidate section 4.1)", rules=["DRT-4", "DRW-7"]),
        vector("terminal-events-extra-log", "terminal-events-extra-log", "fail", "DRW-7", "the terminal event set is exactly the crosswalk's logs, with no further one", rules=["DRT-4", "DRW-7"]),
        vector("funding-finality-unregistered-member", "funding-finality-unregistered-member", "error", "DRV-3", "a signed funding finality record keeps the exact DACS-4 shape"),
        vector("funding-finality-depth-below-rail-profile", "funding-finality-depth-below-profile", "fail", "DRW-6", "a signed funding finality record must use the rail finality depth", rules=["DRF-6", "DRW-6"]),
        vector("funding-finality-predates-event-block", "funding-finality-predates-event", "fail", "DRW-6", "funding finality is the confirmation-depth block's time, not before it", rules=["DRF-6", "DRW-6"]),
        vector("funding-observed-at-wall-clock", "funding-observed-at-wall-clock", "fail", "DRW-6", "funding observedAt is the confirmation-depth block's time, not a wall clock (§11.2 R43)", rules=["DRT-16", "DRW-6"]),
        vector("terminal-finality-unregistered-member", "terminal-finality-unregistered-member", "error", "DRV-3", "a signed terminal finality record keeps the exact DACS-4 shape"),
        vector("terminal-finality-depth-below-rail-profile", "terminal-finality-depth-below-profile", "fail", "DRW-6", "a signed terminal finality record must use the rail finality depth", rules=["DRT-8", "DRW-6"]),
        vector("terminal-observed-at-wall-clock", "terminal-observed-at-wall-clock", "fail", "DRW-6", "terminal observedAt is the confirmation-depth block's time, so re-observing reproduces the record (§11.2 R43)", rules=["DRT-16", "DRW-6"]),
        vector("portable-state-missing-funded", "release", "fail", "DRL-4", "the portable lifecycle cannot skip the funded state", [{"op": "remove", "path": ["native", "portableStateHistory", 1]}]),
        vector("portable-state-unknown", "release", "fail", "DRL-2", "additional native states require a deterministic portable mapping", [{"op": "replace", "path": ["native", "portableStateHistory", 1], "value": "claim-pending"}]),
        vector("portable-state-reopened", "release", "fail", "DRL-4", "a terminal portable state cannot reopen", [{"op": "add", "path": ["native", "portableStateHistory", 4], "value": "funded"}]),
        vector("portable-state-terminal-mismatch", "release", "fail", "DRL-1", "the portable history must end in the evidenced terminal state", [{"op": "replace", "path": ["native", "portableStateHistory", 3], "value": "refunded"}]),
        vector("portable-state-evidence-unavailable", "release", "indeterminate", "DRL-3", "unavailable native state cannot be guessed", authenticated("release", status("nativeStateResolution", "unavailable"))),
        vector("native-transition-unauthenticated", "release", "indeterminate", "DRL-12", "an unauthenticated prior native status, entrypoint, or caller stays indeterminate (§11.3 I2)", authenticated("release", status("transitionResolution", "unavailable"))),
        vector("native-transition-outside-crosswalk", "release", "fail", "DRL-11", "a complete from Funded skips the submission the crosswalk requires (§11.2 R24)", authenticated("release", tx_record("release", -1, "priorNativeStatus", value=NATIVE_STATUS_VALUES["Funded"]))),
        vector("native-status-not-mapped", "release", "fail", "DRL-2", "a native status absent from nativeStatusMap is not mapped by guesswork (§11.2 R24)", authenticated("release", tx_record("release", -1, "nativeStatusAfter", value=9))),
        vector("native-entrypoint-not-pinned", "release", "fail", "DRC-18", "a transaction whose selector is not pinned is not decoded under another signature", authenticated("release", tx_record("release", -1, "entrypoint", value="0x00000000"))),
        vector("native-event-topic-not-pinned", "release", "fail", "DRC-18", "a required log whose topic0 is not its pinned topic0 is not decoded", authenticated("release", observation("release", "PaymentReleased", "topic0", value="0x" + "00" * 32))),
        vector("reject-without-expected-status", "rejected-refund", "fail", "DRD-13", "the reject call binds the expected prior native status", authenticated("rejected-refund", tx_record("rejected-refund", -1, "calldata", "expectedStatus", value=str(NATIVE_STATUS_VALUES["Funded"]))), rules=["DRC-22", "DRD-13"]),
        vector("expiry-invented-decision", "expiry-invented-decision", "fail", "DRD-7", "expiry cannot manufacture an evaluator decision"),
        vector("expiry-terminal-action-not-recovery", "expired-pre", "fail", "DRT-3", "a decisionless terminal must be the native expiry recovery", [{"op": "replace", "path": ["native", "terminalAction"], "value": "reject"}]),
        vector("pre-submission-expiry-delivery-ref", "expiry-invented-delivery", "fail", "DRT-12", "pre-submission expiry omits delivery evidence"),
        vector("deliveryless-lifecycle-carries-deliverable", "expired-pre", "fail", "DRT-12", "a lifecycle without delivery carries no native deliverable", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x" + "11" * 32}]),
        vector("expiry-invented-seller-fault", "expired-pre", "fail", "DRT-13", "decisionless expiry cannot invent buyer or seller fault", [{"op": "replace", "path": ["reputationProjection", "faultedParty"], "value": "seller"}], rules=["DRL-5", "DRT-13"]),
        # DRX: DisputeCase and DisputeOutcome.
        vector("dispute-outcome-direct-transfer", "dispute-claims-transfer", "fail", "DRX-1", "a DisputeOutcome cannot directly claim an on-chain transfer"),
        vector("dispute-outcome-reference-mismatch", "dispute-reference-mismatch", "fail", "DRD-2", "the DisputeOutcome basis must resolve exactly"),
        vector("dispute-case-mismatch", "dispute-case-replaced", "fail", "DRX-7", "the DisputeOutcome's caseRef must resolve to the signed DisputeCase"),
        vector("dispute-case-signed-by-other-role", "dispute-case-opened-by-seller", "fail", "DRX-7", "the DisputeCase is signed by the primary claim of its opening role"),
        vector("dispute-case-record-not-supplied", "dispute-case-record-not-supplied", "indeterminate", "DRX-7", "a DisputeCase the outcome references but the caller did not supply stays indeterminate"),
        vector("wrong-faulted-party", "wrong-faulted-party", "fail", "DRX-5", "faultedParty must equal the party named by the classification"),
        vector("nonfault-finding-names-party", "nonfault-with-faulted-party", "fail", "DRX-6", "a no-fault finding cannot name a faulted party"),
        vector("nonfault-finding-null-party", "nonfault-with-null-faulted-party", "error", "DRV-3", "a null faultedParty is not a ClaimReference", rules=["DRV-3", "DRX-5"]),
        # Resolver outcomes.
        vector("rail-resolution-unavailable", "release", "indeterminate", "DRC-11", "unavailable rail authority does not become a guessed failure", authenticated("release", status("railResolution", "unavailable")), rules=["DRC-11", "DRF-9"]),
        vector("runtime-code-unavailable", "release", "indeterminate", "DRJ-7", "unresolved code remains indeterminate", authenticated("release", status("codeResolution", "unavailable"))),
        vector("delivery-evidence-unavailable", "release", "indeterminate", "DRE-5", "unavailable delivery evidence remains indeterminate", authenticated("release", status("deliveryFinality", "unavailable"))),
        vector("decision-finality-unavailable", "release", "indeterminate", "DRD-4", "unavailable decision finality cannot authorize the terminal action", authenticated("release", status("decisionFinality", "unavailable"))),
        vector("terminal-finality-unavailable", "release", "indeterminate", "DRT-9", "missing terminal finality evidence remains indeterminate", authenticated("release", status("terminalFinality", "unavailable"))),
        vector("cross-substrate-order-unavailable", "release", "indeterminate", "DRD-10", "no authenticated decision anchor orders the decision before the terminal transaction", authenticated("release", decision_anchor(None))),
        vector("self-reported-time-cannot-order", "release", "indeterminate", "DRD-10", "a self-reported decidedAt value cannot replace authenticated ordering", authenticated("release", [{"op": "add", "path": ["native", "reportedDecidedAt"], "value": 1799999999}, *decision_anchor(None)]), rules=["DRD-10", "DRD-11"]),
        vector("decision-finalized-after-terminal", "release", "fail", "DRD-11", "an anchor finalized after the terminal transaction contradicts DRD-10 (§11.2 R14)", authenticated("release", decision_anchor({"substrate": "demos", "finalizedBlockTimestampSec": release_terminal_sec + 10})), rules=["DRC-15", "DRD-10", "DRD-11"]),
        vector("decision-order-within-skew", "release", "indeterminate", "DRC-15", "a decision anchored within the widened skew of the terminal block cannot be ordered (§11.3 I6)", authenticated("release", decision_anchor({"substrate": "demos", "finalizedBlockTimestampSec": release_terminal_sec - 2})), rules=["DRC-15", "DRC-19", "DRD-11"]),
        vector("decision-order-demos-second-widening", "release", "indeterminate", "DRC-15", "DRC-19: one second inside maxCrossSubstrateSkewMs + 1000 is still unordered", authenticated("release", decision_anchor({"substrate": "demos", "finalizedBlockTimestampSec": release_terminal_sec - 3})), rules=["DRC-15", "DRC-19"]),
        # §11.3 case I5 with every resolver status as for a complete lifecycle.
        vector("decision-record-not-supplied", "decision-record-not-supplied", "indeterminate", "DRD-4", "a decision the signed terminal references but the caller did not supply stays indeterminate", rules=["DRD-4", "DRE-5"]),
        vector("evaluation-and-decision-records-not-supplied", "evaluation-and-decision-records-not-supplied", "indeterminate", "DRD-4", "a missing decision and evaluation without a contradiction stay indeterminate, with no resolver status changed", rules=["DRD-4", "DRE-5"]),
        vector("pre-submission-decision-record-not-supplied", "pre-submission-decision-record-not-supplied", "indeterminate", "DRD-4", "a pre-submission refund's decision that the caller did not supply stays indeterminate", rules=["DRD-4", "DRE-5"]),
        vector("rejection-evaluation-record-not-supplied", "rejection-evaluation-record-not-supplied", "indeterminate", "DRD-2", "a refund decision's evaluation that the caller did not supply stays indeterminate, not a projection contradiction", rules=["DRD-2", "DRE-5"]),
        vector("dispute-outcome-record-not-supplied", "dispute-outcome-record-not-supplied", "indeterminate", "DRD-2", "a pre-submission decision's DisputeOutcome that the caller did not supply stays indeterminate", rules=["DRD-2", "DRE-5"]),
        vector("evaluation-rule-not-supplied", "evaluation-rule-not-supplied", "indeterminate", "DRE-8", "an evaluation rule the overlay binds but the caller did not supply stays indeterminate (§11.3 I1)"),
        vector("delivery-record-not-supplied", "delivery-record-not-supplied", "indeterminate", "DRE-5", "delivery evidence the signed terminal references for an authenticated submission, but that the caller did not supply, stays indeterminate"),
        vector("rejection-delivery-record-not-supplied", "rejection-delivery-record-not-supplied", "indeterminate", "DRE-5", "a post-submission refund's delivery evidence that the caller did not supply stays indeterminate"),
        vector("expiry-delivery-record-not-supplied", "expiry-delivery-record-not-supplied", "indeterminate", "DRE-5", "a post-submission expiry's delivery evidence that the caller did not supply stays indeterminate"),
        vector("released-terminal-without-decision-reference", "released-terminal-without-decision-reference", "fail", "DRD-2", "a released terminal that references no decision contradicts the evaluation; the decision is not merely missing"),
        vector("authenticated-native-contradiction", "release", "fail", "DRV-6", "authenticated contradictory chain evidence rejects", authenticated("release", status("codeResolution", "contradictory"))),
        vector("resolver-status-applicability-mismatch", "release", "fail", "DRV-6", "DRV-6: an authenticated resolver record that marks delivery finality not applicable contradicts the signed delivery evidence", authenticated("release", status("deliveryFinality", "not-applicable"))),
        vector("resolver-status-applicability-verified-without-delivery", "expired-pre", "fail", "DRV-6", "DRV-6: an authenticated resolver record that vouches for delivery finality contradicts a pre-submission expiry that has no delivery", authenticated("expired-pre", status("deliveryFinality", "verified"))),
        vector("resolver-anchors-expiry-decision", "expired-pre", "fail", "DRV-6", "DRV-6: an authenticated decision anchor contradicts an expiry refund that has no decision", authenticated("expired-pre", decision_anchor({"substrate": "demos", "finalizedBlockTimestampSec": EVALUATION_DEADLINE_SEC}))),
        vector("resolver-status-unavailable-without-delivery", "expired-pre", "pass", "DRV-7", "an unavailable delivery-finality status asserts nothing and is not a required check when the lifecycle has no delivery (candidate §9 step 5, DRV-7)", authenticated("expired-pre", status("deliveryFinality", "unavailable")), rules=["DRV-2", "DRV-7"]),
        # DRV-1, DRV-6: the pinned resolver record.
        vector("drv-1-signed-status", "release", "fail", "DRV-1", "DRV-1: a resolver status is evidence only as signed", authenticated("release", status("codeResolution", "unavailable")) + status("codeResolution", "verified")),
        vector("drv-1-signed-observation", "release", "fail", "DRV-1", "DRV-1: an event observation is evidence only as signed", observation("release", "JobCreated", "finalityBlock", value=None)),
        vector("drv-1-signed-transaction-record", "release", "fail", "DRV-1", "DRV-1: a transaction record is evidence only as signed", terminal_call("release", "nativeCallerAccountType", "eip1271")),
        vector("drv-1-signed-history", "release", "fail", "DRV-1", "DRV-1: prior terminal history is evidence only as signed", history([prior_terminal("release", tx_preimage="unrelated-terminal", native_job_id="2")])),
        vector("drv-1-signed-native-state", "release", "fail", "DRV-1", "DRV-1: resolved native state is evidence only as signed", authenticated("release", native_state("evaluatorBindingMode", "adapter")) + native_state("evaluatorBindingMode", "direct")),
        vector("drv-1-resolver-key", "release", "fail", "DRV-1", "DRV-1: the resolver key is pinned by the verifier, not supplied by a vector", [{"op": "add", "path": ["publicKeys", RESOLVER], "value": public_key("orchestrator")}, {"op": "add", "path": ["reproductionInputs", "publicTestSeedHex", RESOLVER], "value": SEEDS["orchestrator"].hex()}, {"op": "replace", "path": ["resolverEvidence", "signature"], "value": foreign_resolver_signature}]),
        vector("resolver-bound-to-another-job", "release", "fail", "DRV-6", "the resolver record must describe this job, rail, and contract", [{"op": "replace", "path": ["resolverEvidence"], "value": other_job_resolver["resolverEvidence"]}]),
        # Reproduction inputs.
        vector("public-test-seed-mismatch", "release", "fail", "DRV-4", "committed public test seeds must derive the published verification keys", [{"op": "replace", "path": ["reproductionInputs", "publicTestSeedHex", BUYER], "value": "00" * 32}]),
        vector("role-bundle-input-mismatch", "release", "fail", "DRA-4", "the committed role bundle must hash to the signed overlay binding", [{"op": "replace", "path": ["reproductionInputs", "roleBundles", "buyer", "primaryClaim"], "value": SELLER}]),
        vector("vet-record-input-mismatch", "release", "fail", "DRA-4", "the committed Vet record must resolve from the signed overlay reference", [{"op": "replace", "path": ["reproductionInputs", "vetRecords", "buyer", "validFromSec"], "value": 1799900001}]),
        vector("evaluation-rule-mismatch", "release", "fail", "DRE-8", "the evaluation rule must resolve from the overlay's reference", [{"op": "replace", "path": ["artifacts", "evaluationRule", "criteria", 0, "statement"], "value": "different statement"}]),
        vector("delivered-artifact-input-mismatch", "release", "fail", "DRE-2", "the delivered payload must hash to the signed delivery evidence's content hash", [{"op": "replace", "path": ["reproductionInputs", "deliveredArtifact", "payloadUtf8"], "value": "substituted"}]),
        vector("deliveryless-lifecycle-carries-artifact-input", "expired-pre", "fail", "DRP-7", "a lifecycle without delivery carries no delivered payload input", [{"op": "replace", "path": ["reproductionInputs", "deliveredArtifact"], "value": {"payloadUtf8": "unreferenced"}}]),
        vector("runtime-bytecode-preimage-mismatch", "release", "fail", "DRJ-5", "the runtime bytecode must hash to the pinned code hash under keccak-256", [{"op": "replace", "path": ["reproductionInputs", "runtimeBytecode", "value"], "value": other_runtime.hex()}], rules=["DRJ-5", "DRW-2"]),
        vector("native-event-transaction-preimage-mismatch", "release", "fail", "DRT-4", "event transaction hashes must reproduce from committed inputs", authenticated("release", observation("release", "JobCompleted", "txHashPreimageUtf8", value="substituted tx"))),
        vector("native-event-kind-substitution", "release", "fail", "DRT-4", "event observations retain the exact EvmEventRef discriminator", authenticated("release", observation("release", "JobCompleted", "eventRef", "kind", value="transaction"))),
        vector("native-event-chain-substitution", "release", "fail", "DRT-4", "event observations retain the selected rail chain", authenticated("release", observation("release", "JobCompleted", "eventRef", "chainId", value=10))),
        vector("native-event-name-substitution", "release", "fail", "DRT-4", "each observation carries its lifecycle event name", authenticated("release", observation("release", "JobCreated", "eventName", value="JobOpened"))),
        vector("native-event-targets-another-job", "release", "fail", "DRT-4", "every observation targets the escrow job's contract and native job", authenticated("release", observation("release", "JobFunded", "arguments", "jobId", value="99"))),
        vector("creation-event-job-topic-mismatch", "release", "fail", "DRJ-1", "the creation event's job topic is numerically the job's nativeJobId", authenticated("release", observation("release", "JobCreated", "arguments", "jobId", value="99"))),
        vector("native-events-out-of-order", "release", "fail", "DRF-8", "authenticated block times follow the block order", authenticated("release", [
            {"op": "replace", "path": ["reproductionInputs", "nativeEventInputs", index_of("release", "JobCompleted"), *path], "value": block_value}
            for path, block_value in (
                (["blockTimestampSec"], block_time(SUBMISSION_BLOCK) - 1),
                (["blockHashPreimageUtf8"], verifier.block_preimage(CHAIN_ID, TERMINAL_BLOCKS["release"], block_time(SUBMISSION_BLOCK) - 1)),
                (["blockHash"], block(TERMINAL_BLOCKS["release"], block_time(SUBMISSION_BLOCK) - 1)["blockHash"]),
            )
        ]), rules=["DRF-8", "DRT-4"]),
        vector("funding-finality-block-time-jointly-altered", "funding-finality-block-time-jointly-altered", "fail", "DRF-8", "a resolver-attested confirmation block far in the future contradicts every later block, even with the signed record altered to match", rules=["DRF-6", "DRF-8"]),
        vector("funding-finality-block-wrong-depth", "release", "fail", "DRF-8", "the funding finality block is the event block plus the rail depth less one", authenticated("release", observation("release", "JobFunded", "finalityBlock", value=block(FUNDING_BLOCK + FINALITY_BLOCKS)))),
        vector("funding-time-caller-substitution", "release", "fail", "DRA-9", "a caller fundedAt value cannot replace the authenticated funding-event block timestamp", [{"op": "replace", "path": ["native", "fundedAtSec"], "value": FUNDING_TIME + 1}]),
        vector("submitted-before-cutoff-claim-substitution", "release", "fail", "DRT-12", "submission classification derives from the authenticated prior native status", [{"op": "replace", "path": ["submittedBeforeCutoff"], "value": False}]),
        vector("creation-event-client-mismatch", "release", "fail", "DRJ-3", "the authenticated creation event's client is the buyer's account", authenticated("release", observation("release", "JobCreated", "arguments", "client", value="0x" + "66" * 20))),
        vector("creation-event-cutoff-mismatch", "release", "fail", "DRC-21", "the authenticated configuration event carries the signed cutoff at its pinned input", authenticated("release", observation("release", "JobConfigured", "arguments", "submissionCutoff", value=str(SUBMISSION_CUTOFF_SEC + 1))), rules=["DRC-21", "DRJ-3", "DREB-13"]),
        vector("creation-event-policy-mismatch", "release", "fail", "DRC-21", "the authenticated configuration event carries the pinned evaluator-rejection policy word", authenticated("release", observation("release", "JobConfigured", "arguments", "preSubmissionRefundPolicy", value=policy_word("expiry-only"))), rules=["DRC-21", "DRJ-3"]),
        vector("event-log-layout-mismatch", "release", "fail", "DRC-18", "a log whose topics and data do not fit the pinned indexed layout is not decoded under another (section 11.2 R31)", authenticated("release", observation("release", "JobFunded", "indexedArguments", value=funded_log["indexedArguments"][:1]) + observation("release", "JobFunded", "dataArguments", value=funded_log["indexedArguments"][1:] + funded_log["dataArguments"]))),
        vector("creation-event-hook-not-zero", "release", "fail", "DRJ-3", "the job's hook is the zero address the rail pins (DRC-7)", authenticated("release", observation("release", "JobCreated", "arguments", "hook", value="0x" + "c4" * 20)), rules=["DRC-7", "DRJ-3"]),
        vector("create-calldata-differs-from-events", "release", "fail", "DRV-6", "the authenticated createJob calldata contradicts the creation events it emitted", authenticated("release", tx_record("release", 0, "calldata", "expiredAt", value=str(EVALUATION_DEADLINE_SEC + 1)))),
        vector("funding-event-amount-mismatch", "release", "fail", "DRF-3", "the authenticated funding event must lock the complete budget", authenticated("release", observation("release", "JobFunded", "arguments", "amount", value="999999"))),
        vector("terminal-event-payload-mismatch", "release", "fail", "DRT-4", "the transfer log must pay the complete budget", authenticated("release", observation("release", "PaymentReleased", "arguments", "amount", value="999999"))),
        # The orchestrator-signed terminal evidence still names the seller; only
        # the authenticated transfer log shows the budget went elsewhere.
        vector("drt-10-orchestrator-signature-not-chain-evidence", "release", "fail", "DRT-4", "a valid orchestrator signature on terminal evidence does not stand in for the chain log it contradicts", authenticated("release", observation("release", "PaymentReleased", "arguments", "provider", value=BUYER_ACCOUNT)), rules=["DRJ-8", "DRT-4", "DRT-10", "DRV-4"]),
        vector("funding-finality-block-preimage-mismatch", "release", "fail", "DRF-8", "the funding block identity must reproduce from committed input", authenticated("release", observation("release", "JobFunded", "blockHashPreimageUtf8", value="substituted block"))),
        vector("funding-block-hash-mismatch", "release", "fail", "DRF-8", "the funding block hash must reproduce from its preimage", authenticated("release", observation("release", "JobFunded", "blockHash", value="0x" + "cd" * 32))),
        # DRJ, DRAA: identifiers, job, and code.
        vector("nonminimal-native-job-id", "nonminimal-native-job-id", "error", "DRJ-1", "native job identifiers use minimal unsigned decimal text"),
        vector("native-job-id-beyond-uint256", "native-job-id-beyond-uint256", "error", "DRJ-1", "a native job identifier at 2^256 overflows uint256"),
        vector("noninteger-evaluation-sequence", "evaluation-sequence-text", "error", "DRAA-2", "numeric address segments must be unsigned integers"),
        vector("first-evaluation-sequence-not-zero", "evaluation-sequence-one", "fail", "DRAA-6", "the first evaluation sequence starts at zero"),
        vector("noncanonical-job-id", "noncanonical-job-id", "error", "DRAA-1", "malformed JID is an input error"),
        vector("noncanonical-case-id", "noncanonical-case-id", "error", "DRAA-1", "malformed DisputeOutcome caseId is an input error"),
        vector("noninteger-dispute-revision", "dispute-revision-text", "error", "DRAA-2", "the dispute revision is an unsigned integer"),
        vector("evaluation-address-segment-nonminimal", "release", "error", "DRAA-2", "the evaluation address's numeric segment is minimal unsigned decimal", [{"op": "replace", "path": ["artifacts", "evaluationRef", "anchor", "locator"], "value": logical(JOB_A, "evaluation:00")}]),
        vector("dispute-address-segment-nonminimal", "pre-submission-rejected-refund", "error", "DRAA-2", "the dispute outcome address's revision segment is minimal unsigned decimal", [{"op": "replace", "path": ["artifacts", "disputeRef", "anchor", "locator"], "value": logical(LIFECYCLE_JOBS["pre-submission-rejected-refund"], f"dispute:{CASE_A}:outcome:00")}]),
        vector("decision-address-of-another-job", "release", "fail", "DRD-4", "the decision reference names this job's decision address", [{"op": "replace", "path": ["artifacts", "decisionRef", "anchor", "locator"], "value": logical(JOB_B, "decision:post-submission")}]),
        vector("decision-address-of-other-stage", "release", "fail", "DRD-4", "each decision stage has its own address (DRD-14)", [{"op": "replace", "path": ["artifacts", "decisionRef", "anchor", "locator"], "value": logical(JOB_A, "decision:pre-submission")}], rules=["DRD-14", "DRD-4"]),
        vector("drp-5-job-rail", "drp-5-job-rail", "fail", "DRP-5", "the signed escrow job must use the agreement-selected rail definition", rules=["DRF-9", "DRP-5"]),
        vector("drj-10-job-contract", "drj-10-job-contract", "fail", "DRJ-10", "the escrow job targets the rail's pinned contract"),
        vector("drj-10-job-runtime", "drj-10-job-runtime", "fail", "DRJ-10", "the escrow job's runtime code is the rail's pinned code"),
        vector("drj-5-escrow-code-changed", "drj-5-escrow-code-changed", "fail", "DRJ-5", "the authenticated escrow code at every action block is the pinned code", rules=["DRJ-5", "DRJ-7"]),
        vector("drj-11-token-code-changed", "drj-11-token-code-changed", "fail", "DRJ-11", "the payment token's authenticated code hashes to its pin (§11.2 R10)", rules=["DRC-8", "DRJ-11"]),
        vector("drj-11-unpinned-implementation", "drj-11-unpinned-implementation", "fail", "DRJ-11", "a delegating escrow needs both implementation pins (§11.2 R10)"),
        vector("drj-11-delegating-without-implementation-hash", "drj-11-delegating-without-implementation-hash", "fail", "DRJ-11", "a pinned implementation address without its code hash is not both pins (section 11.2 R10)"),
        vector("drj-11-delegating-implementation-unverified", "drj-11-delegating-implementation-unverified", "indeterminate", "DRJ-11", "the resolver attests no implementation code, so a delegating escrow stays unverified (section 11.3 I4)", rules=["DRJ-11"]),
        vector("drv-4-job-overlay-hash", "drv-4-job-overlay-hash", "fail", "DRV-4", "a signed escrow job cannot bind another agreement overlay"),
        vector("drf-1-funding-overlay-hash", "drf-1-funding-overlay-hash", "fail", "DRF-1", "funding evidence must bind the exact agreement overlay"),
        vector("dra-1-bilateral-job", "dra-1-bilateral-job", "fail", "DRA-1", "the bilateral agreement must be the one for the overlay's job"),
        vector("native-contract-projection-mismatch", "release", "fail", "DRJ-2", "the native contract projection must be the escrow job's contract", [{"op": "replace", "path": ["native", "contractAddress"], "value": "0x" + "82" * 20}]),
        vector("native-runtime-projection-mismatch", "release", "fail", "DRJ-5", "the native runtime projection must be the escrow job's code", [{"op": "replace", "path": ["native", "runtimeBytecodeHash"], "value": "0x" + "ab" * 32}]),
        vector("malformed-native-bytes32", "release", "error", "DRV-3", "malformed native bytes are not repaired", [{"op": "replace", "path": ["native", "deliverable"], "value": "0x1234"}]),
        vector("unsupported-profile-discriminator", "release", "error", "DRV-1", "unsupported profiles fail before action", [{"op": "replace", "path": ["candidateProfile"], "value": "delivery-or-remedy-v2"}]),
    ]
    vectors += [
        vector("dreb-15-pre-submission-recovery-time", "dreb-15-pre-submission-recovery-early", "fail", "DREB-15", "DREB-15: expiry recovery is not callable before the evaluation deadline"),
        vector("dreb-15-post-submission-recovery-time", "dreb-15-post-submission-recovery-early", "fail", "DREB-15", "DREB-15: a submitted job's expiry recovery is not callable before the evaluation deadline"),
    ]
    # §9 step 1: every artifact's version discriminator.
    versioned = (
        ("job", "escrowJobRefVersion", "release"),
        ("funding", "escrowFundingEvidenceVersion", "release"),
        ("delivery", "deliveryEvidenceVersion", "release"),
        ("evaluation", "executionEvaluationVersion", "release"),
        ("disputeCase", "disputeCaseVersion", "pre-submission-rejected-refund"),
        ("dispute", "disputeOutcomeVersion", "pre-submission-rejected-refund"),
        ("decision", "escrowDecisionVersion", "release"),
        ("terminal", "escrowTerminalEvidenceVersion", "release"),
    )
    # DRV-8 names each version member but the DACS-4 DeliveryEvidence's.
    for name, field, lifecycle in versioned:
        fixtures[f"{name}-version-2"] = make_base(lifecycle, hooks={name: put(field, "2")})
        fixtures[f"{name}-version-missing"] = make_base(lifecycle, hooks={name: drop(field)})
        unsupported, missing = ("DRV-2", "DRV-3") if name == "delivery" else ("DRV-8", "DRV-8")
        vectors += [
            vector(f"{name}-version-unsupported", f"{name}-version-2", "error", unsupported, f"an unsupported {field} fails before action, though signed and bound"),
            vector(f"{name}-version-missing", f"{name}-version-missing", "error", missing, f"a {name} without {field} is malformed"),
        ]
    alias = BUYER + "?role=evaluator"
    other_events = [
        {**pin, "topic0": "0x" + "00" * 32} if pin["name"] == "JobCreated" else pin
        for pin in rail_body()["parameters"]["events"]
    ]
    # The pinned reference's createJob (base-contracts@142e669 ERC8183.sol
    # lines 512-519), which takes no separate submission cutoff.
    reference_signature = "createJob(address,address,uint48,string,address,uint256)"
    reference_inputs = [
        {"name": name, "type": abi_type}
        for name, abi_type in (
            ("provider", "address"), ("evaluator", "address"), ("expiredAt", "uint48"),
            ("description", "string"), ("hook", "address"), ("providerAgentId", "uint256"),
        )
    ]
    provider_set = (("jobId", "uint256", True), ("provider", "address", True))
    provider_set_pin = {
        "name": "ProviderSet",
        "signature": verifier.abi_signature("ProviderSet", provider_set),
        "topic0": verifier.topic_of(verifier.abi_signature("ProviderSet", provider_set)),
        "inputs": [{"name": name, "type": abi_type, "indexed": indexed} for name, abi_type, indexed in provider_set],
    }

    def event_pin_input(event_name: str, index: int, field: str, value: Any) -> Callable[[Any], None]:
        """A rail hook that edits one input of one event pin, leaving its signature as pinned."""
        def apply(body: Any) -> None:
            pin = next(item for item in body["parameters"]["events"] if item["name"] == event_name)
            pin["inputs"][index][field] = value
        return apply

    def entrypoint_type_alias(body: Any) -> None:
        """Spell createJob's `expiredAt` as the alias `uint`, with a signature and selector that agree."""
        pin = body["parameters"]["entrypoints"][0]
        pin["inputs"][2]["type"] = "uint"
        pin["signature"] = verifier.abi_signature(pin["name"], tuple((item["name"], item["type"]) for item in pin["inputs"]))
        pin["selector"] = verifier.selector_of(pin["signature"])

    def configuration_input(index: int, abi_type: str) -> Callable[[Any], None]:
        """A rail hook that re-types one configuration-event input and re-derives its pins."""
        def apply(body: Any) -> None:
            params = body["parameters"]
            pin = next(item for item in params["events"] if item["name"] == verifier.CONFIGURATION_EVENT)
            pin["inputs"][index]["type"] = abi_type
            pin["signature"] = verifier.abi_signature(pin["name"], tuple((item["name"], item["type"]) for item in pin["inputs"]))
            pin["topic0"] = verifier.topic_of(pin["signature"])
            params["configurationEvidence"]["eventTopic0"] = pin["topic0"]
        return apply
    fixtures.update({
        "overlay-version-2": make_base("release", hooks={"agreement": put("deliveryOrRemedyAgreementVersion", "2")}),
        "overlay-version-missing": make_base("release", hooks={"agreement": drop("deliveryOrRemedyAgreementVersion")}),
        "bilateral-version-2": make_base("release", hooks={"bilateral": put("payeeBoundAgreementVersion", "2")}),
        "bilateral-plain-agreement": make_base("release", hooks={"bilateral": each(
            drop("payeeBoundAgreementVersion"), put("agreementVersion", "1"),
        )}),
        # The rail: DRR-6 discriminators, DRC-14 literals, DRC-17 pins.
        "rail-version-2": make_base("release", hooks={"rail": put("jobEscrowRailVersion", "2")}),
        "rail-version-missing": make_base("release", hooks={"rail": drop("jobEscrowRailVersion")}),
        "rail-type-unprefixed": make_base("release", hooks={"rail": put("railType", "evm-erc8183")}),
        "rail-phase-handler-other": make_base("release", hooks={"rail": put("phaseHandler", "pay-evm-erc20")}),
        "rail-capability-profile-other": make_base("release", hooks={"rail": rail_param("capabilityProfile", "other-gate-v9")}),
        "rail-decision-ordering-profile-superseded": make_base("release", hooks={"rail": rail_param(
            "decisionOrderingProfile", "synthetic-single-chain-finalized-before-terminal-v1",
        )}),
        "rail-hook-nonzero": make_base("release", hooks={"rail": rail_param("hook", "0x" + "c4" * 20)}),
        "rail-fee-boolean": make_base("release", hooks={"rail": rail_param("platformFeeBP", False)}),
        "rail-deadline-profile-other": make_base("release", hooks={"rail": rail_param("deadlineProfile", "shared-cutoff-v1")}),
        "rail-implementation-revision-malformed": make_base("release", hooks={"rail": rail_param("implementationRevision", "fixture-only")}),
        "rail-entrypoint-missing": make_base("release", hooks={"rail": lambda body: body["parameters"]["entrypoints"].pop()}),
        "rail-entrypoint-selector-wrong": make_base("release", hooks={"rail": rail_param("entrypoints", 0, "selector", "0x00000000")}),
        "rail-event-missing": make_base("release", hooks={"rail": lambda body: body["parameters"]["events"].pop()}),
        "rail-event-topic-wrong": make_base("release", hooks={"rail": rail_param("events", other_events)}),
        "rail-configuration-event-unpinned": make_base("release", hooks={"rail": rail_param(
            "configurationEvidence", "eventTopic0", verifier.topic_of("JobDeadlinesSet(uint256,uint256)"),
        )}),
        "rail-status-map-incomplete": make_base("release", hooks={"rail": lambda body: body["parameters"]["nativeStatusMap"].pop()}),
        "rail-abi-reference-create-job": make_base("release", hooks={"rail": rail_param("entrypoints", 0, {
            "name": "createJob", "signature": reference_signature, "selector": verifier.selector_of(reference_signature),
            "inputs": reference_inputs,
        })}),
        "rail-id-lower-case-asset": make_base("release", hooks={"rail": put("railId", f"x-evm-erc8183:{CHAIN_ID}:fxt")}),
        "rail-id-other-chain": make_base("release", hooks={"rail": put("railId", f"x-evm-erc8183:1:{TOKEN_SYMBOL}")}),
        "rail-asset-contract-other": make_base("release", hooks={"rail": put("asset", "contract", "0x" + "66" * 20)}),
        "rail-network-chain-other": make_base("release", hooks={"rail": put("network", "chainId", 10)}),
        "rail-asset-missing": make_base("release", hooks={"rail": drop("asset")}),
        "rail-governance-missing": make_base("release", hooks={"rail": drop("governance")}),
        "rail-supersession-member": make_base("release", hooks={"rail": put("governance", "replaces", 0)}),
        "rail-finality-profile-missing": make_base("release", hooks={"rail": drop("consumerFinalityProfile")}),
        "rail-finality-profile-depth": make_base("release", hooks={"rail": put("consumerFinalityProfile", "settlement", "requiredDepth", 12)}),
        "rail-finality-profile-network": make_base("release", hooks={"rail": put("consumerFinalityProfile", "settlement", "networkId", "eip155:1")}),
        "rail-availability-disabled": make_base("release", hooks={"rail": put("availability", "disabled")}),
        "rail-availability-live": make_base("release", hooks={"rail": put("availability", "live")}),
        "rail-skew-negative": make_base("release", hooks={"rail": rail_param("maxCrossSubstrateSkewMs", -1)}),
        "rail-token-code-empty": make_base("release", hooks={"rail": rail_param("paymentTokenRuntimeBytecodeHash", verifier.EMPTY_CODE_HASH)}),
        # DRC-17, DRC-20, DRC-21: inputs, field names, and configuration words.
        "rail-entrypoint-pin-without-inputs": make_base("release", hooks={"rail": lambda body: body["parameters"]["entrypoints"][0].pop("inputs")}),
        "rail-event-inputs-do-not-reproduce-signature": make_base("release", hooks={"rail": event_pin_input("JobCreated", 1, "type", "uint256")}),
        "rail-event-four-indexed-inputs": make_base("release", hooks={"rail": event_pin_input("JobCreated", 3, "indexed", True)}),
        "rail-event-extra-pin": make_base("release", hooks={"rail": lambda body: body["parameters"]["events"].append(provider_set_pin)}),
        "rail-event-pin-repeated": make_base("release", hooks={"rail": lambda body: body["parameters"]["events"].append(copy.deepcopy(body["parameters"]["events"][0]))}),
        "rail-entrypoint-input-type-alias": make_base("release", hooks={"rail": entrypoint_type_alias}),
        "rail-configuration-policy-word-text": make_base("release", hooks={"rail": rail_param("configurationEvidence", "preSubmissionPolicyValue", "evaluator-rejection")}),
        "rail-payment-released-recipient": make_base("release", hooks={"rail": event_pin_input("PaymentReleased", 1, "name", "recipient")}),
        "rail-configuration-cutoff-bytes32": make_base("release", hooks={"rail": configuration_input(1, "bytes32")}),
        "rail-configuration-policy-string": make_base("release", hooks={"rail": configuration_input(2, "string")}),
        "rail-configuration-job-id-uint64": make_base("release", hooks={"rail": configuration_input(0, "uint64")}),
        "rail-configuration-same-input": make_base("release", hooks={"rail": rail_param("configurationEvidence", "preSubmissionPolicyInput", 1)}),
        "rail-configuration-shape-superseded": make_base("release", hooks={"rail": rail_param("configurationEvidence", {
            "event": verifier.CONFIGURATION_EVENT,
            "submissionCutoffField": "submissionCutoff",
            "preSubmissionPolicyField": "preSubmissionRefundPolicy",
        })}),
        # DRW-7: funding and terminal references are derived.
        "funding-job-ref-signer-orchestrator": make_base("release", hooks={"funding": put("escrowJobRef", "signer", ORCHESTRATOR)}),
        "terminal-funding-ref-signer-orchestrator": make_base("release", hooks={"terminal": put("fundingEvidenceRef", "signer", ORCHESTRATOR)}),
        "terminal-job-ref-native-locator": make_base("release", hooks={"terminal": put("escrowJobRef", "anchor", "locator", "stor-" + "ab" * 20)}),
        "terminal-job-ref-ipfs-anchor": make_base("release", hooks={"terminal": put("escrowJobRef", "anchor", "kind", "ipfs")}),
        "terminal-event-refs-reordered": make_base("release", hooks={"terminal": lambda body: body["terminalEventRefs"].reverse()}),
        # DRJ-11: a delegating escrow.
        "drj-11-delegating-without-implementation-hash": make_base("release", hooks={
            "rail": rail_param("implementationAddress", IMPLEMENTATION),
            "fixture": put("resolverEvidence", "nativeState", "implementationAddress", IMPLEMENTATION),
        }),
        "drj-11-delegating-implementation-unverified": make_base("release", hooks={
            "rail": each(rail_param("implementationAddress", IMPLEMENTATION), rail_param("implementationRuntimeBytecodeHash", "0x" + "c9" * 32)),
            "fixture": put("resolverEvidence", "nativeState", "implementationAddress", IMPLEMENTATION),
        }),
        # DACS-2 AttestationRef: the optional signer, and malformed shapes.
        "attestation-ref-with-signer": make_base("release", SIGNED_REF_JOB, hooks={"evaluationRef": put("signer", EVALUATOR)}),
        "attestation-ref-signer-bad-scheme": make_base("release", hooks={"evaluationRef": put("signer", "Bad Scheme:id")}),
        "attestation-ref-signer-unsorted-parameters": make_base("release", hooks={"evaluationRef": put("signer", EVALUATOR + "?b=2&a=1")}),
        "attestation-ref-signer-other-party": make_base("release", hooks={"evaluationRef": put("signer", SELLER)}),
        "evaluation-subject-ref-signer-other-party": make_base("release", hooks={"evaluation": put("subjectEvidenceRefs", 0, "signer", SELLER)}),
        "dispute-case-subject-ref-signer-other-party": make_base("pre-submission-rejected-refund", hooks={"disputeCase": put("subjectEvidenceRefs", 0, "signer", SELLER)}),
        "dispute-subject-ref-signer-other-party": make_base("pre-submission-rejected-refund", hooks={"dispute": put("subjectEvidenceRefs", 0, "signer", SELLER)}),
        "decision-ref-signer-buyer": make_base("release", hooks={"decisionRef": put("signer", BUYER)}),
        "funding-ref-signer-buyer": make_base("release", hooks={"terminal": put("fundingEvidenceRef", "signer", BUYER)}),
        "flat-agreement-reference": make_base("release", hooks={"agreement": put("agreementRef", {
            "kind": "storage-program",
            "locator": f"dacs3:agreement:{JOB_A}",
            "contentHash": release["artifacts"]["agreement"]["agreementRef"]["contentHash"],
        })}),
        "decision-reference-anchor-kind-unregistered": make_base("release", hooks={"terminal": put("decisionRef", "anchor", "kind", "fixture")}),
        # CORE CF-3, DACS-1 §6.3.1, DRW-5: one party in another spelling.
        "evaluator-claim-is-buyer-alias": make_base("release", evaluator_claim=alias, hooks={"fixture": with_keys((alias, "buyer"))}),
        "evaluator-claim-upper-case-key": make_base("release", evaluator_claim=upper_buyer_key, hooks={"fixture": with_keys((upper_buyer_key, "buyer"))}),
        "evaluator-claim-scheme-case-alias": make_base("release", evaluator_claim=scheme_case_buyer, hooks={"fixture": with_keys((scheme_case_buyer, "buyer"))}),
        "evaluator-claim-evm-case-alias": make_base(
            "release", buyer_claim=evm_buyer, evaluator_claim=evm_buyer_upper,
            hooks={"fixture": with_keys((evm_buyer, "buyer"), (evm_buyer_upper, "buyer"))},
        ),
        "evaluator-claim-evm-chain-leading-zero": make_base(
            "release", buyer_claim=evm_buyer, evaluator_claim=evm_buyer_leading_zero,
            hooks={"fixture": with_keys((evm_buyer, "buyer"), (evm_buyer_leading_zero, "buyer"))},
        ),
        "evaluator-claim-evm-family-upper-case": make_base(
            "release", buyer_claim=evm_buyer, evaluator_claim=evm_family_upper,
            hooks={"fixture": with_keys((evm_buyer, "buyer"), (evm_family_upper, "buyer"))},
        ),
        **{
            f"evaluator-claim-evm-chain-{label}": make_base(
                "release", buyer_claim=evm_buyer, evaluator_claim=claim,
                hooks={"fixture": with_keys((evm_buyer, "buyer"), (claim, "buyer"))},
            )
            for label, claim in (("plus-sign", evm_chain_plus), ("minus-sign", evm_chain_minus), ("hex", evm_chain_hex))
        },
        "evaluator-claim-not-nfc": make_base("release", evaluator_claim=nfd_claim, hooks={"fixture": with_keys((nfd_claim, "buyer"))}),
        "faulted-party-with-parameter": make_base("rejected-refund", FAULTED_ALIAS_JOB, hooks={
            "evaluation": put("finding", "faultedParty", SELLER + "?source=fixture"),
        }),
        # DACS-1: unknown claim parameters are ignored; DRW-1: an EVM account
        # claim's address is lower-case, upper-case, or valid EIP-55.
        "account-claim-with-parameter": make_base("release", CLAIM_PARAMETER_JOB, hooks={
            "agreement": put("buyer", "evmAccountClaim", f"cci-xm:evm:{CHAIN_ID}:{BUYER_ACCOUNT}?jurisdiction=US"),
        }),
        "account-claim-mixed-case": make_base("release", MIXED_CASE_JOB, hooks={
            "agreement": put("evaluator", "evmAccountClaim", f"cci-xm:evm:{CHAIN_ID}:{EIP55_ACCOUNT}"),
        }),
        "account-claim-upper-case": make_base("release", UPPER_CASE_JOB, hooks={
            "agreement": put("evaluator", "evmAccountClaim", f"cci-xm:evm:{CHAIN_ID}:0x" + "AB" * 20),
        }),
        "account-claim-bad-checksum": make_base("release", hooks={
            "agreement": put("evaluator", "evmAccountClaim", f"cci-xm:evm:{CHAIN_ID}:{BAD_CHECKSUM_ACCOUNT}"),
        }),
        "account-claim-non-hex-address": make_base("rejected-refund", hooks={
            "agreement": put("seller", "evmAccountClaim", f"cci-xm:evm:{CHAIN_ID}:alice"),
        }),
        "account-claim-short-address": make_base("release", hooks={
            "agreement": put("buyer", "evmAccountClaim", f"cci-xm:evm:{CHAIN_ID}:0x1234"),
        }),
        "account-claim-parameters-unsorted": make_base("release", hooks={
            "agreement": put("buyer", "evmAccountClaim", f"cci-xm:evm:{CHAIN_ID}:{BUYER_ACCOUNT}?b=2&a=1"),
        }),
        "event-reference-tx-hash-upper-case": make_base("release", hooks={"terminal": lambda body: body["terminalEventRefs"][0].__setitem__(
            "txHash", body["terminalEventRefs"][0]["txHash"].upper(),
        )}),
        # The legacy `0x` spelling that SB-1 collapses and a current producer
        # must not emit.
        "event-reference-tx-hash-0x-prefixed": make_base("release", hooks={"terminal": lambda body: body["terminalEventRefs"][0].__setitem__(
            "txHash", "0x" + body["terminalEventRefs"][0]["txHash"],
        )}),
        # ULID upper bound.
        "job-id-above-ulid-range": make_base("release", "8ZZZZZZZZZZZZZZZZZZZZZZZZZ"),
        "case-id-above-ulid-range": make_base("pre-submission-rejected-refund", hooks={"dispute": put("caseId", "8ZZZZZZZZZZZZZZZZZZZZZZZZZ")}),
        # §9 step 2: required members, member types, and closed sets.
        "funding-observed-at-missing": make_base("release", hooks={"funding": drop("observedAt")}),
        "terminal-observed-at-missing": make_base("release", hooks={"terminal": drop("observedAt")}),
        "funding-observed-at-text": make_base("release", hooks={"funding": put("observedAt", "soon")}),
        "terminal-observed-at-negative": make_base("release", hooks={"terminal": put("observedAt", -1)}),
        "dispute-subject-bundle-refs-missing": make_base("pre-submission-rejected-refund", hooks={"dispute": drop("subjectBundleRefs")}),
        "dispute-subject-evidence-refs-missing": make_base("pre-submission-rejected-refund", hooks={"dispute": drop("subjectEvidenceRefs")}),
        "dispute-subject-bundle-refs-number": make_base("pre-submission-rejected-refund", hooks={"dispute": put("subjectBundleRefs", 42)}),
        "finding-rationale-code-missing": make_base("release", hooks={"evaluation": drop("finding", "rationaleCode")}),
        "finding-classification-unknown": make_base("release", hooks={"evaluation": put("finding", "classification", "bogus")}),
        # DRE-8, DRE-9: the bound evaluation rule.
        "rule-kind-always-reject": make_base("release", hooks={"evaluationRule": put("ruleKind", "always-reject-v1")}),
        "rule-version-2": make_base("release", hooks={"evaluationRule": put("evaluationRuleVersion", "2")}),
        "rule-criteria-empty": make_base("release", hooks={"evaluationRule": put("criteria", [])}),
        "rule-criteria-duplicate": make_base("release", hooks={"evaluationRule": put("criteria", 1, "criterionId", "deliverable-matches-specification")}),
        "rule-for-another-job": make_base("release", hooks={"evaluationRule": put("jobId", JOB_B)}),
        "rule-extra-member": make_base("release", hooks={"evaluationRule": put("weights", {})}),
        # DRE-10: the result and finding follow from the criterion outcomes
        # under the rule matrix.
        "release-with-seller-fault-finding": make_base("release", hooks={"evaluation": put("finding", {
            "classification": "seller-fault", "faultedParty": SELLER, "rationaleCode": "fixture-criteria-met",
        })}),
        "release-with-buyer-fault-finding": make_base("release", hooks={"evaluation": put("finding", {
            "classification": "buyer-fault", "faultedParty": BUYER, "rationaleCode": "fixture-criteria-met",
        })}),
        "rejected-refund-with-seller-fulfilled-finding": make_base("rejected-refund", hooks={"evaluation": put("finding", {
            "classification": "seller-fulfilled", "rationaleCode": "fixture-criterion-unmet",
        })}),
        "evaluation-result-contradicts-criteria": make_base("release", hooks={"evaluation": evaluation_with(
            "accept", ["unsatisfied", "satisfied"],
            {"classification": "seller-fault", "faultedParty": SELLER, "rationaleCode": "fixture-criterion-unmet"},
        )}),
        "criterion-results-out-of-order": make_base("release", hooks={"evaluation": lambda body: body["criterionResults"].reverse()}),
        "criterion-results-missing-one": make_base("release", hooks={"evaluation": lambda body: body["criterionResults"].pop()}),
        "criterion-outcome-unknown": make_base("release", hooks={"evaluation": put("criterionResults", 0, "outcome", "maybe")}),
        # DRD-14: decision stages.
        "post-submission-decision-on-funded-job": make_base("pre-submission-rejected-refund", hooks={"decision": each(
            put("decisionStage", "post-submission"), put("deliveryEvidenceRef", substituted),
        )}),
        "pre-submission-decision-after-submit": make_base("rejected-refund", basis="dispute", hooks={"decision": each(
            put("decisionStage", "pre-submission"), drop("deliveryEvidenceRef"),
        )}),
        # DACS-4 block-depth finalityObservedAt is the Nth confirmation's block time.
        "funding-finality-before-confirmation-block": make_base("release", hooks={
            "funding": put("finality", "finalityObservedAt", (FUNDING_TIME + 1) * 1000),
        }),
        "funding-finality-after-confirmation-block": make_base("release", hooks={
            "funding": put("finality", "finalityObservedAt", finality_time_ms(FUNDING_BLOCK) + 2000),
        }),
        "terminal-finality-far-future": make_base("release", hooks={
            "terminal": put("finality", "finalityObservedAt", 9_000_000_000_000_000),
        }),
    })
    resolver_version_2 = copy.deepcopy(release)
    resolver_version_2["resolverEvidence"]["resolverEvidenceVersion"] = "2"
    resign_resolver(resolver_version_2, bind=False)
    rail_value = release["artifacts"]["railDefinition"]
    foreign_rail_signature = steward_signature(rail_value, SEEDS["orchestrator"])
    vectors += [
        vector("agreement-overlay-version-unsupported", "overlay-version-2", "error", "DRV-8", "an unsupported overlay version fails before action, though all three roles signed it"),
        vector("agreement-overlay-version-missing", "overlay-version-missing", "error", "DRV-8", "an overlay without deliveryOrRemedyAgreementVersion fails before action, though all three roles signed it"),
        vector("resolver-evidence-version-unsupported", "release", "error", "DRV-2", "an unsupported resolver evidence version fails before action, though the pinned resolver signed it", [{"op": "replace", "path": ["resolverEvidence"], "value": resolver_version_2["resolverEvidence"]}]),
        vector("bilateral-agreement-version-unsupported", "bilateral-version-2", "error", "DRV-2", "an unsupported payee-bound agreement version fails before action"),
        vector("bilateral-agreement-not-payee-bound", "bilateral-plain-agreement", "error", "DRV-2", "the payee-bound commit selects a PayeeBoundAgreementDocument, not an AgreementDocument"),
        vector("rail-version-unsupported", "rail-version-2", "error", "DRR-6", "an unsupported jobEscrowRailVersion fails before action", rules=["DRR-6", "DRV-8"]),
        vector("rail-version-missing", "rail-version-missing", "error", "DRR-6", "a rail without jobEscrowRailVersion fails before action", rules=["DRR-6", "DRV-8"]),
        vector("rail-type-unprefixed", "rail-type-unprefixed", "error", "DRR-6", "DRG-3: the rail type is x-evm-erc8183; the unprefixed name is unsupported", rules=["DRG-3", "DRR-6", "DRV-8"]),
        vector("rail-phase-handler-other", "rail-phase-handler-other", "error", "DRR-6", "a phaseHandler other than x-job-escrow is unsupported (§11.2 R21)", rules=["DRR-2", "DRR-6"]),
        vector("rail-capability-profile-unsupported", "rail-capability-profile-other", "error", "DRC-14", "the capability profile is a DRC-14 literal"),
        vector("rail-decision-ordering-profile-superseded", "rail-decision-ordering-profile-superseded", "error", "DRC-14", "the decision-ordering profile is the DRC-14 literal anchor-final-before-terminal-v1, not the superseded fixture profile"),
        vector("rail-hook-nonzero", "rail-hook-nonzero", "error", "DRC-14", "the profile hook is the zero-address literal (DRC-7)", rules=["DRC-14", "DRC-7"]),
        vector("rail-fee-boolean", "rail-fee-boolean", "error", "DRC-14", "a boolean fee is not the integer literal 0", rules=["DRC-14", "DRT-7"]),
        vector("unsupported-native-deadline-profile", "rail-deadline-profile-other", "error", "DRC-14", "the deadline profile is the DRC-14 literal separate-submission-cutoff-v1", rules=["DRC-14", "DREB-13"]),
        vector("rail-implementation-revision-malformed", "rail-implementation-revision-malformed", "error", "DRC-14", "implementationRevision is <owner>/<repository>@<40 lower-case hex commit>"),
        vector("rail-entrypoint-missing", "rail-entrypoint-missing", "error", "DRC-17", "the rail pins one entrypoint for each profile entrypoint"),
        vector("rail-entrypoint-selector-wrong", "rail-entrypoint-selector-wrong", "error", "DRC-17", "a selector derives from its signature under keccak-256"),
        vector("rail-event-missing", "rail-event-missing", "error", "DRC-17", "the rail pins every crosswalk event"),
        vector("rail-event-topic-wrong", "rail-event-topic-wrong", "error", "DRC-17", "a topic0 derives from its event signature under keccak-256"),
        vector("rail-configuration-event-unpinned", "rail-configuration-event-unpinned", "error", "DRC-21", "configurationEvidence names a pinned event by its topic0"),
        vector("rail-entrypoint-pin-without-inputs", "rail-entrypoint-pin-without-inputs", "error", "DRC-17", "an AbiFunctionPin carries its ordered inputs"),
        vector("rail-event-inputs-do-not-reproduce-signature", "rail-event-inputs-do-not-reproduce-signature", "error", "DRC-17", "an event pin's inputs reproduce its signature"),
        vector("rail-event-four-indexed-inputs", "rail-event-four-indexed-inputs", "error", "DRC-17", "a pinned event has at most three indexed inputs"),
        vector("rail-event-extra-pin", "rail-event-extra-pin", "error", "DRC-17", "the event pins are exactly the crosswalk events and the configuration event"),
        vector("rail-event-pin-repeated", "rail-event-pin-repeated", "error", "DRC-17", "two event pins never share a name or topic0"),
        vector("rail-entrypoint-input-type-alias", "rail-entrypoint-input-type-alias", "error", "DRC-17", "a pinned input type is the canonical ABI type, so `uint` is not `uint256`"),
        vector("rail-configuration-policy-word-text", "rail-configuration-policy-word-text", "error", "DRC-21", "the policy value is a 32-byte ABI word, not the policy name"),
        vector("rail-payment-released-recipient", "rail-payment-released-recipient", "error", "DRC-20", "the reference implementation's PaymentReleased `recipient` leaves no `provider` input for DRT-5 (section 8.4)", rules=["DRC-17", "DRC-20"]),
        vector("rail-configuration-cutoff-bytes32", "rail-configuration-cutoff-bytes32", "error", "DRC-21", "the configuration cutoff input is a uint"),
        vector("rail-configuration-policy-string", "rail-configuration-policy-string", "error", "DRC-21", "the configuration policy input fills one ABI word"),
        vector("rail-configuration-job-id-uint64", "rail-configuration-job-id-uint64", "error", "DRC-21", "the configuration event's jobId is a uint256"),
        vector("rail-configuration-same-input", "rail-configuration-same-input", "error", "DRC-21", "the cutoff and policy are two distinct inputs"),
        vector("rail-configuration-shape-superseded", "rail-configuration-shape-superseded", "error", "DRC-21", "configurationEvidence names a topic0, two input indexes, and a policy word, not field names"),
        vector("rail-status-map-incomplete", "rail-status-map-incomplete", "error", "DRC-17", "nativeStatusMap maps every native status"),
        vector("rail-abi-reference-create-job", "rail-abi-reference-create-job", "error", "DRV-2", "the reference createJob, with no separate cutoff, is not the fixture implementation this verifier decodes", rules=["DRC-18", "DRV-2"]),
        vector("rail-id-lower-case-asset", "rail-id-lower-case-asset", "error", "DRR-1", "the railId asset segment is the upper-case asset symbol"),
        vector("rail-id-other-chain", "rail-id-other-chain", "error", "DRR-1", "the railId chain segment is the rail's chain"),
        vector("rail-asset-contract-other", "rail-asset-contract-other", "fail", "DRR-7", "the rail asset contract is the pinned payment token"),
        vector("rail-network-chain-other", "rail-network-chain-other", "fail", "DRR-7", "asset, network, and parameters name one chain"),
        vector("rail-asset-missing", "rail-asset-missing", "error", "DRR-7", "a rail without its asset member is malformed (§11.2 R37)"),
        vector("rail-governance-missing", "rail-governance-missing", "error", "DRR-8", "a rail without its governance member is malformed (§11.2 R37)"),
        vector("rail-supersession-member", "rail-supersession-member", "error", "DRR-8", "supersession is named only by governance.supersedes"),
        vector("rail-finality-profile-missing", "rail-finality-profile-missing", "fail", "DRR-4", "a rail without a consumerFinalityProfile is not selectable"),
        vector("rail-finality-profile-depth", "rail-finality-profile-depth", "fail", "DRC-16", "the finality profile's depth is the rail's finalityBlocks"),
        vector("rail-finality-profile-network", "rail-finality-profile-network", "fail", "DRC-16", "the finality profile's network is the rail's chain"),
        vector("rail-availability-disabled", "rail-availability-disabled", "fail", "DRR-5", "a disabled rail is never selectable (RAV-R2)"),
        vector("rail-availability-live", "rail-availability-live", "error", "DRV-1", "this offline fixture verifier accepts only the mocked fixture rail"),
        vector("rail-skew-negative", "rail-skew-negative", "error", "DRC-15", "maxCrossSubstrateSkewMs is a non-negative safe integer"),
        vector("rail-token-code-empty", "rail-token-code-empty", "fail", "DRW-2", "the empty-code hash cannot be a pinned payment-token code hash"),
        vector("rail-signature-not-steward", "release", "fail", "DRR-2", "the rail definition is signed by the pinned registry steward", [{"op": "replace", "path": ["artifacts", "railDefinition", "signature"], "value": foreign_rail_signature}]),
        vector("rail-signature-relabelled", "release", "fail", "DRR-2", "a rail signature under another algorithm label does not verify", [{"op": "replace", "path": ["artifacts", "railDefinition", "signature", "algorithm"], "value": "ecdsa-secp256k1"}]),
        vector("bilateral-signature-relabelled", "release", "fail", "DRA-1", "a bilateral agreement signature under another algorithm label does not verify", [{"op": "replace", "path": ["artifacts", "bilateralAgreement", "signatures", 0, "algorithm"], "value": "ecdsa-secp256k1"}]),
        vector("attestation-ref-with-signer", "attestation-ref-with-signer", "pass", "DRV-7", "a DACS-2 AttestationRef may carry its optional signer, the artifact's own", rules=release_pass_rules),
        vector("attestation-ref-signer-bad-scheme", "attestation-ref-signer-bad-scheme", "error", "DRV-3", "an AttestationRef signer is a canonical ClaimReference: `Bad Scheme` is not a scheme"),
        vector("attestation-ref-signer-unsorted-parameters", "attestation-ref-signer-unsorted-parameters", "error", "DRV-3", "an AttestationRef signer's parameters are in CF-2 order"),
        vector("attestation-ref-signer-other-party", "attestation-ref-signer-other-party", "fail", "DRV-6", "an evaluation reference's signer is the evaluator who signed it"),
        vector("evaluation-subject-ref-signer-other-party", "evaluation-subject-ref-signer-other-party", "fail", "DRV-6", "a subject reference's signer names the delivery evidence's signer", rules=["DRE-3", "DRV-6"]),
        vector("dispute-case-subject-ref-signer-other-party", "dispute-case-subject-ref-signer-other-party", "fail", "DRV-6", "a dispute case's subject reference signer names the funding evidence's signer", rules=["DRX-7", "DRV-6"]),
        vector("dispute-subject-ref-signer-other-party", "dispute-subject-ref-signer-other-party", "fail", "DRV-6", "a dispute outcome's subject reference signer names the funding evidence's signer", rules=["DRX-1", "DRV-6"]),
        vector("decision-ref-signer-buyer", "decision-ref-signer-buyer", "fail", "DRW-7", "the terminal's decision reference carries no signer (section 11.2 R43)", rules=["DRV-6", "DRW-7"]),
        vector("funding-ref-signer-buyer", "funding-ref-signer-buyer", "fail", "DRW-7", "a terminal funding reference carries no signer (section 11.2 R43)"),
        vector("funding-job-ref-signer-orchestrator", "funding-job-ref-signer-orchestrator", "fail", "DRW-7", "a funding evidence reference carries no signer, even the correct one (section 11.2 R43)", rules=["DRT-16", "DRW-7"]),
        vector("terminal-funding-ref-signer-orchestrator", "terminal-funding-ref-signer-orchestrator", "fail", "DRW-7", "a signer would let producers write distinct terminal evidence for one terminal (section 11.2 R43)", rules=["DRT-16", "DRW-7"]),
        vector("terminal-job-ref-native-locator", "terminal-job-ref-native-locator", "fail", "DRW-7", "a terminal reference names its logical address, never a native stor- address (section 11.2 R43)", rules=["DRW-7"]),
        vector("terminal-job-ref-ipfs-anchor", "terminal-job-ref-ipfs-anchor", "fail", "DRW-7", "a terminal reference is a storage-program anchor (section 11.2 R43)"),
        vector("terminal-event-refs-reordered", "terminal-event-refs-reordered", "fail", "DRW-7", "terminal event references are in ascending log order (section 11.2 R43)", rules=["DRT-16", "DRW-7"]),
        vector("flat-agreement-reference", "flat-agreement-reference", "error", "DRV-3", "an agreement reference outside the DACS-2 AttestationRef shape is malformed"),
        vector("decision-reference-anchor-kind-unregistered", "decision-reference-anchor-kind-unregistered", "error", "DRV-3", "a DACS-2 anchor kind is storage-program, ipfs, or https"),
        vector("evaluator-primary-claim-parameter-alias", "evaluator-claim-is-buyer-alias", "fail", "DRA-6", "a parameter does not make the buyer another party under CORE CF-3"),
        vector("evaluator-claim-upper-case-key", "evaluator-claim-upper-case-key", "error", "DRV-3", "DACS-1 §6.3.1: an upper-case Demos agent key is rejected, not lower-cased into an alias"),
        vector("evaluator-claim-scheme-case-alias", "evaluator-claim-scheme-case-alias", "error", "DRV-3", "CF-2(a): a signed overlay embeds the lower-case scheme, so `DID:` is not a canonical alias of the buyer"),
        vector("evaluator-claim-evm-chain-leading-zero", "evaluator-claim-evm-chain-leading-zero", "error", "DRV-3", "DACS-1 PB-2: a leading-zero chain ID is outside the EVM profile, so it cannot respell the buyer's account", rules=["DRA-6", "DRV-3", "DRW-5"]),
        vector("evaluator-claim-evm-family-upper-case", "evaluator-claim-evm-family-upper-case", "error", "DRV-3", "DACS-1 PB-2: the family is the lower-case literal evm", rules=["DRA-6", "DRV-3", "DRW-5"]),
        vector("evaluator-claim-evm-chain-plus-sign", "evaluator-claim-evm-chain-plus-sign", "error", "DRV-3", "DACS-1 PB-2: a signed chain ID is outside the EVM profile, so it cannot respell the buyer's account", rules=["DRA-6", "DRV-3", "DRW-5"]),
        vector("evaluator-claim-evm-chain-minus-sign", "evaluator-claim-evm-chain-minus-sign", "error", "DRV-3", "DACS-1 PB-2: the chain ID is a positive decimal integer, so a negative one is malformed", rules=["DRA-6", "DRV-3", "DRW-5"]),
        vector("evaluator-claim-evm-chain-hex", "evaluator-claim-evm-chain-hex", "error", "DRV-3", "DACS-1 PB-2: the chain ID is decimal, so its 0x hexadecimal spelling cannot respell the buyer's account", rules=["DRA-6", "DRV-3", "DRW-5"]),
        vector("evaluator-claim-not-nfc", "evaluator-claim-not-nfc", "error", "DRV-3", "CF-2: a signed claim embeds an NFC identifier, so an NFD spelling is malformed"),
        vector("evaluator-claim-evm-case-alias", "evaluator-claim-evm-case-alias", "fail", "DRA-6", "DRW-5: two case spellings of one EVM account are one party (§11.2 R6)", rules=["DRA-6", "DRW-5"]),
        vector("faulted-party-with-parameter", "faulted-party-with-parameter", "pass", "DRV-7", "faultedParty matches its agreement party under CORE CF-3 identity", rules=rejection_pass_rules + ["DRX-5"]),
        vector("account-claim-with-parameter", "account-claim-with-parameter", "pass", "DRV-7", "unknown account-claim parameters are ignored, not rejected (DACS-1)", rules=release_pass_rules),
        vector("account-claim-mixed-case-address", "account-claim-mixed-case", "pass", "DRV-7", "a valid EIP-55 mixed-case address names the same EVM account", rules=release_pass_rules),
        vector("account-claim-upper-case-address", "account-claim-upper-case", "pass", "DRV-7", "an all-upper-case address names the same EVM account", rules=release_pass_rules),
        vector("account-claim-bad-checksum", "account-claim-bad-checksum", "error", "DRW-1", "a mixed-case address with an invalid EIP-55 checksum is malformed (§11.2 R27)", rules=["DRA-5", "DRW-1"]),
        vector("account-claim-non-hex-address", "account-claim-non-hex-address", "error", "DRW-1", "an account claim whose address is not 0x and 40 hex digits is malformed, whatever the native evidence says", rules=["DRA-5", "DRW-1"]),
        vector("account-claim-short-address", "account-claim-short-address", "error", "DRW-1", "a short account address is malformed (§11.2 R27)", rules=["DRA-5", "DRW-1"]),
        vector("account-claim-parameters-not-canonical", "account-claim-parameters-unsorted", "error", "DRV-3", "account-claim parameters in a signed overlay keep the CORE CF-2 canonical order", rules=["DRA-5", "DRV-3"]),
        vector("funding-token-upper-case", "funding-token-upper-case", "error", "DRW-1", "an artifact address is 0x and 40 lower-case hex digits (§11.2 R27)"),
        vector("event-reference-tx-hash-upper-case", "event-reference-tx-hash-upper-case", "error", "DRW-3", "an EvmEventRef txHash keeps its SB-1 spelling (§11.2 R11)"),
        vector("event-reference-tx-hash-0x-prefixed", "event-reference-tx-hash-0x-prefixed", "error", "DRW-3", "an EvmEventRef txHash is 64 lower-case hex digits without 0x, its SB-1 canonical spelling (§11.2 R11)"),
        vector("job-id-above-ulid-range", "job-id-above-ulid-range", "error", "DRAA-1", "a ULID above 7ZZZZZZZZZZZZZZZZZZZZZZZZZ is not a canonical JID"),
        vector("case-id-above-ulid-range", "case-id-above-ulid-range", "error", "DRAA-1", "a caseId above the ULID range is not a canonical JID"),
        vector("funding-observed-at-missing", "funding-observed-at-missing", "error", "DRV-3", "funding evidence without observedAt is malformed"),
        vector("terminal-observed-at-missing", "terminal-observed-at-missing", "error", "DRV-3", "terminal evidence without observedAt is malformed"),
        vector("funding-observed-at-text", "funding-observed-at-text", "error", "DRW-4", "observedAt is a unix-millisecond integer, not text"),
        vector("terminal-observed-at-negative", "terminal-observed-at-negative", "error", "DRW-4", "observedAt is a non-negative integer"),
        vector("dispute-subject-bundle-refs-missing", "dispute-subject-bundle-refs-missing", "error", "DRV-3", "a DisputeOutcome without subjectBundleRefs is malformed"),
        vector("dispute-subject-evidence-refs-missing", "dispute-subject-evidence-refs-missing", "error", "DRV-3", "a DisputeOutcome without subjectEvidenceRefs is malformed"),
        vector("dispute-subject-bundle-refs-number", "dispute-subject-bundle-refs-number", "error", "DRV-3", "subjectBundleRefs is an array of AttestationRefs"),
        vector("finding-rationale-code-missing", "finding-rationale-code-missing", "error", "DRV-3", "an AccountabilityFinding without rationaleCode is malformed"),
        vector("finding-classification-unknown", "finding-classification-unknown", "error", "DRV-3", "the finding classification is a closed set"),
        vector("rule-kind-always-reject", "rule-kind-always-reject", "error", "DRE-9", "an unsupported rule kind fails before any result is read (§11.2 R25)"),
        vector("rule-version-unsupported", "rule-version-2", "error", "DRE-9", "an unsupported evaluationRuleVersion fails before any result is read"),
        vector("rule-criteria-empty", "rule-criteria-empty", "fail", "DRE-9", "a rule has at least one criterion"),
        vector("rule-criteria-duplicate", "rule-criteria-duplicate", "fail", "DRE-9", "criterion identifiers are unique"),
        vector("rule-for-another-job", "rule-for-another-job", "fail", "DRE-8", "the rule's jobId is the overlay's"),
        vector("rule-extra-member", "rule-extra-member", "error", "DRV-3", "the rule keeps the exact EvaluationRule shape"),
        vector("release-with-seller-fault-finding", "release-with-seller-fault-finding", "fail", "DRE-10", "an accept result permits only seller-fulfilled (§6.2 matrix)", rules=["DRE-10", "DRE-6"]),
        vector("release-with-buyer-fault-finding", "release-with-buyer-fault-finding", "fail", "DRE-10", "an accept result permits only seller-fulfilled (§6.2 matrix)", rules=["DRE-10", "DRE-6"]),
        vector("rejected-refund-with-seller-fulfilled-finding", "rejected-refund-with-seller-fulfilled-finding", "fail", "DRE-10", "a reject result does not permit seller-fulfilled (§6.2 matrix)", rules=["DRE-10", "DRE-6"]),
        vector("evaluation-result-contradicts-criteria", "evaluation-result-contradicts-criteria", "fail", "DRE-10", "an unsatisfied criterion makes the result reject, not accept", rules=["DRE-10", "DRE-6"]),
        vector("criterion-results-out-of-order", "criterion-results-out-of-order", "fail", "DRE-10", "criterion results follow rule order"),
        vector("criterion-results-missing-one", "criterion-results-missing-one", "fail", "DRE-10", "every rule criterion has a result"),
        vector("criterion-outcome-unknown", "criterion-outcome-unknown", "error", "DRV-3", "a criterion outcome is satisfied, unsatisfied, or indeterminate"),
        vector("post-submission-decision-on-funded-job", "post-submission-decision-on-funded-job", "fail", "DRD-14", "a decision's stage matches the terminal transaction's prior native status: Funded is pre-submission"),
        vector("pre-submission-decision-after-submit", "pre-submission-decision-after-submit", "fail", "DRD-3", "after a native submit, the pre-submission decision authorizes nothing: a Submitted-to-Rejected transition needs the delivery-bound decision (§11.2 R23)", rules=["DRD-13", "DRD-14", "DRD-3"]),
        vector("funding-finality-before-confirmation-block", "funding-finality-before-confirmation-block", "fail", "DRW-6", "funding finality is observed at the confirmation-depth block, not before it", rules=["DRF-6", "DRW-6"]),
        vector("funding-finality-after-confirmation-block", "funding-finality-after-confirmation-block", "fail", "DRW-6", "funding finality is observed at the confirmation-depth block, not after it", rules=["DRF-6", "DRW-6"]),
        vector("terminal-finality-far-future", "terminal-finality-far-future", "fail", "DRW-6", "a far-future terminal finality time is not the confirmation-depth block time", rules=["DRT-8", "DRW-6"]),
    ]
    # Signature fail-open paths: no signature, a null one, or another algorithm
    # label with the Ed25519 value kept never authenticates an artifact.
    signed = (
        ("job", "release", "DRV-4"),
        ("funding", "release", "DRV-4"),
        ("delivery", "release", "DRV-4"),
        ("evaluation", "release", "DRE-1"),
        ("disputeCase", "pre-submission-rejected-refund", "DRX-7"),
        ("dispute", "pre-submission-rejected-refund", "DRX-7"),
        ("decision", "release", "DRD-1"),
        ("terminal", "release", "DRV-4"),
    )
    for name, base, rule in signed:
        path = ["artifacts", name, "signature"]
        vectors += [
            vector(f"{name}-signature-null", base, "fail", rule, f"a {name} with a null signature is unsigned", [{"op": "replace", "path": path, "value": None}]),
            vector(f"{name}-signature-absent", base, "fail", rule, f"a {name} without a signature is unsigned", [{"op": "remove", "path": path}]),
            vector(f"{name}-signature-relabelled", base, "fail", rule, f"a {name} signature labelled with an algorithm the verifier does not verify never authenticates", [{"op": "replace", "path": path + ["algorithm"], "value": "ecdsa-secp256k1"}]),
        ]
    decision_value = release["artifacts"]["decision"]["signature"]["value"]
    resolver_value = release["resolverEvidence"]["signature"]["value"]
    vectors += [
        vector("decision-signature-sr1-aggregate", "release", "fail", "DRD-1", "an sr1-aggregate label never authenticates an Ed25519 decision signature", [{"op": "replace", "path": ["artifacts", "decision", "signature", "algorithm"], "value": "sr1-aggregate"}]),
        vector("resolver-signature-null", "release", "fail", "DRV-1", "an unsigned resolver record is not pinned authority", [{"op": "replace", "path": ["resolverEvidence", "signature"], "value": None}]),
        vector("resolver-signature-relabelled", "release", "fail", "DRV-1", "a resolver signature under another algorithm label is not pinned authority", [{"op": "replace", "path": ["resolverEvidence", "signature", "algorithm"], "value": "ecdsa-secp256k1"}]),
        vector("overlay-signature-relabelled", "release", "fail", "DRA-3", "an overlay signature under another algorithm label does not verify", [{"op": "replace", "path": ["artifacts", "agreement", "signatures", 0, "algorithm"], "value": "ecdsa-secp256k1"}]),
        vector("overlay-signature-entry-not-object", "release", "fail", "DRA-3", "a non-object overlay signature entry is no role's signature", [{"op": "replace", "path": ["artifacts", "agreement", "signatures", 2], "value": None}]),
        vector("decision-signature-noncanonical-base64url", "release", "fail", "DRD-1", "CORE SIG-6: a signature value with non-zero pad bits is not repaired", [{"op": "replace", "path": ["artifacts", "decision", "signature", "value"], "value": noncanonical_b64u(decision_value)}]),
        vector("resolver-signature-noncanonical-base64url", "release", "fail", "DRV-1", "CORE SIG-6: a resolver signature value with non-zero pad bits is not repaired", [{"op": "replace", "path": ["resolverEvidence", "signature", "value"], "value": noncanonical_b64u(resolver_value)}]),
    ]
    # P13 resolves one published write twice. I8 holds two qualifying writes
    # together: byte equality cannot make either eligible for DRC-15.
    single_writes = {name: [qualified_artifact_write(release, name)] for name in ("funding", "decision")}

    def write_patch(writes: Any) -> list[dict[str, Any]]:
        return resolver_patch(release, [{
            "op": "add", "path": ["resolverEvidence", "qualifiedArtifactWrites"], "value": writes,
        }])

    vectors += [
        vector("sr2-single-write-two-producers", "release", "pass", "DRV-7", "P13: both producers resolve one write through one binding and reproduce the same logical references and terminal hash", write_patch(single_writes), rules=["DRW-7", "DRT-16"]),
        vector("sr2-single-write-resolved-again", "release", "pass", "DRV-7", "P13: a later resolution of the same published writes reproduces the same evidence", write_patch(single_writes), rules=["DRW-7", "DRT-16"], evaluated_with=["sr2-single-write-two-producers"]),
        vector("sr2-repeated-receipt-same-write", "release", "pass", "DRV-7", "an exact repeated receipt describes one write, not two", write_patch({name: receipts * 2 for name, receipts in single_writes.items()}), rules=["DRW-7", "DRT-16"]),
    ]
    for name in ("funding", "decision"):
        writes = copy.deepcopy(single_writes)
        writes[name].append(qualified_artifact_write(release, name, 1, release_terminal_sec + 10))
        vectors.append(vector(
            f"sr2-identical-{name}-writes", "release", "indeterminate", "DRAA-4",
            f"I8: two qualifying {name} writes have identical bytes and different native addresses; retain both, select neither, and do not evaluate DRC-15 from either copy",
            write_patch(writes), rules=["DRAA-4"],
        ))
    # Rules no vector executes: each needs evidence or an actor outside this
    # offline pack.  A vector may not tag one.
    promotion_blocked_rules = {
        "DRA-12": "requires authenticated ordering of the overlay's SR-2 finality before job creation; the pack resolves the overlay but has no evidence of when it was finalized",
        "DRA-14": "requires authenticated native evidence of every later mutation of the bound parties, token, budget, recipient, policy, and deadlines; the pack models no later replacement",
        "DRAA-3": "requires the normative SR-2 logical-to-native binding and a conforming resolver",
        "DRAA-5": "requires authenticated conflicting-write evidence from the selected SR-2 binding",
        "DRAA-8": "requires an authenticated resolver that selects by logical address rather than index or reported time",
        "DRAA-9": "requires CORE SR2-10 through SR2-12 receipt delivery to the entitled participants",
        "DRE-7": "requires authenticated evidence that the evaluation was anchored before the decision used it",
        "DREB-17": "requires the agreement-bound DACS control proof for the evaluator's EOA",
        "DRF-7": "requires the session orchestrator to anchor funding evidence through a conforming SR-2 implementation",
        "DRG-2": "is a process rule for the candidate document, which scripts/validate_candidate_profile.py checks",
        "DRJ-6": "requires live proxy, implementation, and mutation-authority resolution for a selected deployment",
        "DRJ-9": "requires the session orchestrator to anchor the job reference through a conforming SR-2 implementation",
        "DRP-13": "concerns an older reader of the candidate phase kinds, which this verifier is not",
        "DRP-15": "requires per-invocation gate evidence for the section 2.3 table",
        "DRP-16": "requires CORE PhaseHandlerResult receipts for the commit and fund invocations",
        "DRP-17": "requires an ok:false invocation and its errorClass",
        "DRQ-2": "requires the explicit-party-supplied evidence shape and deliberate-supply proof to be specified",
        "DRQ-5": "is a future transcript-enabled profile requirement and has no current-profile case",
        "DRV-5": "requires transaction-submission retry orchestration against a live native job",
        "DRX-3": "requires the post-terminal dispute-revision profile, which is outside this first executable pack",
        "DRX-4": "requires a post-terminal dispute revision and authenticated observation of the fixed disposition",
        "DRX-8": "requires artifacts of the output-only DACS-X dispute family to present as this candidate's",
    }
    # Rules executed only against a synthetic evidence shape whose normative
    # proof shape is still undefined.  Negatives may exercise them; no pass
    # vector claims them, and the verifier refuses a pack where one does.
    promotion_blocked_proofs = {
        "DRAA-4": (
            "requires verified CORE AnchorReceipts and native SR-2 write evidence; the pack "
            "checks equivocation only over pinned-resolver summaries of qualifying writes, "
            "not receipt proof bytes or producer write-once enforcement"
        ),
        "DRA-4": (
            "requires authenticated DACS-1 identity bundles and DACS-2 Vet results, and a "
            "control proof for each role's EVM account; the pack binds unsigned fixture "
            "role-bundle and Vet-record inputs by hash only"
        ),
        "DRA-8": (
            "requires an authenticated DACS-2 CompositeVerificationRecord for the evaluator's "
            "BundleRequirement; the pack compares the requirement hash with an unsigned "
            "fixture Vet-record input"
        ),
        "DRA-9": (
            "requires the authenticated DACS-2 composite result and its freshness rule; the "
            "pack reads a pass result and a fixture validFromSec/validUntilSec window from an "
            "unsigned Vet-record input, which is not the DACS-2 record shape"
        ),
        "DRE-2": (
            "requires the DeliveryEvidence and its deliverable to be finalized and "
            "independently resolvable through verified SR-2 receipts (PDE-2, PDE-4); the pack "
            "checks the record's shape, phase, addresses, and hashes but has no receipts"
        ),
        "DRP-7": (
            "requires the PDE-1 through PDE-8 receipts and session authority behind the "
            "DeliveryEvidence; the pack checks the record itself, as for DRE-2"
        ),
        "DRP-9": (
            "requires a normative proof shape showing that the exact delivery digest was "
            "fixed before the native submission; the pack models it with a synthetic "
            "resolver-attested digest anchor"
        ),
        "DRF-9": (
            "requires FV-1 over the registry snapshot and authenticated acceptedRails selection "
            "that DRR-2 and DRR-3 name; the pack checks the job's and the resolved rail's "
            "reference against the overlay's, the steward's RD-1 signature, and the "
            "orchestrator-stated acceptedRails"
        ),
        "DRF-8": (
            "requires FV-1 through FV-10 over an AuthenticatedChainObservation for every chain "
            "fact; the pack reads block, transaction, and log facts from the pinned fixture "
            "resolver and checks their internal consistency"
        ),
        "DRW-6": (
            "requires the confirmation-depth block's timestamp authenticated under FV-1 through "
            "FV-10; the pack's block identity is a fixture preimage the same resolver supplies, "
            "so a consistent shift of every block time is not detected"
        ),
        "DRC-14": (
            "requires implementationRevision to identify the published DRC-10 source; the "
            "fixture implementation has no published source, and the pack checks the "
            "revision's spelling and every literal only"
        ),
        "DRJ-11": (
            "requires authenticated implementation and payment-token code at each action "
            "block; the pack compares the resolver-stated code hashes with the pins and has "
            "no token or implementation bytecode to hash"
        ),
        "DRW-2": (
            "requires every code hash to be keccak-256 of deployed runtime bytecode; the pack "
            "reproduces the escrow code hash from its bytecode but has no payment-token or "
            "implementation bytecode"
        ),
        "DRE-8": (
            "requires the evaluation rule anchored at its section 6.5 address and finalized "
            "before the overlay; the pack resolves the rule by content hash and job and has "
            "no anchor receipts to order"
        ),
        "DRR-2": (
            "requires a registry snapshot for RD-2 through RD-7; the pack verifies the pinned "
            "steward's RD-1 signature only"
        ),
        "DRR-3": (
            "requires LRR-1 through LRR-6 resolution of the signed Listing's acceptedRails; the "
            "pack checks the orchestrator-stated executionContext.acceptedRails"
        ),
        # executionContext values below are orchestrator statements: the
        # vectors check the predicate, not authenticated evidence behind it.
        "DRP-6": (
            "requires authenticated evidence that funding finality preceded the delivery "
            "step; the pack checks the orchestrator-stated "
            "executionContext.fundingFinalizedBeforeDelivery"
        ),
        "DRP-8": (
            "requires authenticated DACS-5 bundle and volume accounting for the escrow pair; "
            "the pack checks the orchestrator-stated executionContext.dacs5PurchaseCount"
        ),
        "DRP-10": (
            "requires authenticated resolution of the signed Listing's acceptedRails "
            "selection of the escrow rail; the pack checks the orchestrator-stated "
            "executionContext.acceptedRails"
        ),
        "DRP-11": (
            "requires the two verified CORE commit receipts; the pack checks the "
            "orchestrator-stated executionContext.commitmentReceipts"
        ),
        "DRP-12": (
            "requires authenticated evidence of the terminal gate and late-delivery "
            "cancellation; the pack checks the orchestrator-stated "
            "executionContext.terminalGate and lateDeliveryDisabled"
        ),
    }
    payload = {
        "fixtures": fixtures,
        "vectors": vectors,
        "promotionBlockedRules": promotion_blocked_rules,
        "promotionBlockedProofs": promotion_blocked_proofs,
    }
    return {
        "kind": "DeliveryRemedyCandidateVectorPack",
        "status": "non-normative-review-fixture",
        "spec": "docs/delivery-or-remedy-candidate.md#11-required-conformance-evidence",
        "generator": "scripts/generate_delivery_remedy_candidate_vectors.py",
        "verifier": "scripts/verify_delivery_remedy_candidate_vectors.py",
        # The candidate's External pins and the DACS text this pack follows
        # (DRG-2): the checked-against commit and each cited document's hash.
        "sourcePins": {
            "external": copy.deepcopy(verifier.EXTERNAL_SOURCE_PINS),
            "dacs": {
                "checkedAgainst": verifier.DACS_CHECKED_AGAINST,
                "documents": verifier.document_pins(ROOT),
            },
        },
        "scope": "offline synthetic evidence only; does not register or make a rail available",
        "hash": hashlib.sha256(canonical_bytes(payload)).hexdigest(),
        "count": len(vectors),
        **payload,
    }


# Negatives whose single defect a second rule also covers by construction.
# With the deciding guard removed, exactly this finding must remain.
FOLLOW_ON_FINDINGS: dict[str, tuple[str, str]] = {
    # An unprefixed escrow kind leaves no x-job-escrow pair.
    "pipeline-unprefixed-escrow-kind": ("fail", "DRP-1"),
    # An agreementPhase outside DRP-14 is not the modelled payee-bound one.
    "pipeline-commit-phase-unsupported": ("error", "DRV-2"),
    # An unmodelled or unsupported delivery's evidence is not the step's.
    "drp-3-attested-payload-delivery-unmodelled": ("fail", "DRE-2"),
    "drp-3-entitlement-delivery-unmodelled": ("fail", "DRE-2"),
    "pipeline-unsupported-delivery-kind": ("fail", "DRE-2"),
    # The other acceptedRails version is not the agreement's terms.rail.
    "drr-3-accepted-rail-other-version": ("fail", "DRA-22"),
    # An overlay delivery index on a non-delivery step names no delivery step.
    "pipeline-phase-index-divergence": ("fail", "DRE-2"),
    # With the fund step after the negotiation and commit steps (DRP-18), a
    # boolean fund index no longer equals the step's index, so the index
    # comparison finds it too.
    "drv-3-agreement-phase-index-boolean": ("fail", "DRA-11"),
    "drv-3-funding-phase-index-boolean": ("fail", "DRF-1"),
    # Overlay signatures: two signatures are not the three distinct roles, and
    # a party relabelled to the buyer is not the evaluator's key.
    "overlay-signature-missing": ("fail", "DRA-18"),
    "overlay-signature-roles-repeated": ("fail", "DRA-3"),
    "overlay-signature-party-not-role-claim": ("fail", "DRA-3"),
    # A cutoff beyond the seconds bound is also after the deadline.
    "dra-19-cutoff-beyond-seconds-bound": ("fail", "DREB-14"),
    # A malformed payee address is not the seller's account either.
    "dra-20-payee-malformed": ("fail", "DRA-20"),
    # Non-minimal budget text is not the converted agreement price either.
    "nonminimal-budget-base-units": ("fail", "DRA-10"),
    # The transcript key makes the payload input more than its payload.
    "transcript-input-disclosed": ("fail", "DRE-2"),
    # A shared evaluator and provider account confuses the callers' roles.
    "evaluator-account-collision": ("fail", "DRL-11"),
    # Without the account-type check the relay itself is refused, and a
    # relayer caller has no crosswalk role.
    "eip1271-relayed-execution": ("fail", "DREB-22"),
    "relayer-substituted-as-native-caller": ("fail", "DRL-11"),
    "malformed-outer-submitter": ("fail", "DREB-22"),
    # The evaluation's subject is that same delivery reference.
    "delivery-reference-mismatch": ("fail", "DRE-3"),
    # A SettlementEvidence has no DeliveryEvidence discriminator.
    "drp-7-historical-settlement-evidence": ("error", "DRV-3"),
    # A failed delivery anchors no deliverable, and an empty reason is still
    # a failure.
    "drp-7-failed-delivery": ("fail", "DRE-2"),
    "drv-3-failed-delivery-empty-reason": ("fail", "DRP-7"),
    # A release with no submission skips the crosswalk's Submitted status.
    "release-decision-without-delivery": ("fail", "DRL-11"),
    # Records not supplied: without the step-5 guard, each later check that
    # needs the record finds the lifecycle inconsistent instead.
    "decision-without-authenticated-basis": ("fail", "DRT-14"),
    "decision-record-not-supplied": ("fail", "DRT-3"),
    "evaluation-and-decision-records-not-supplied": ("fail", "DRT-13"),
    "pre-submission-decision-record-not-supplied": ("fail", "DRT-3"),
    "rejection-evaluation-record-not-supplied": ("fail", "DRT-14"),
    "dispute-outcome-record-not-supplied": ("fail", "DRD-2"),
    "delivery-record-not-supplied": ("fail", "DRT-4"),
    "rejection-delivery-record-not-supplied": ("fail", "DRT-4"),
    "expiry-delivery-record-not-supplied": ("fail", "DRT-4"),
    "released-terminal-without-decision-reference": ("fail", "DRT-3"),
    # An unsupported evaluation result contradicts the criterion outcomes,
    # and an unsupported disposition is none the evaluation authorizes.
    "drv-3-evaluation-result": ("fail", "DRE-10"),
    "drv-3-decision-disposition": ("fail", "DRD-2"),
    # A null faultedParty is still present on a non-fault finding.
    "nonfault-finding-null-party": ("fail", "DRX-6"),
    # A decision finalized after the terminal is also not ordered before it.
    "decision-finalized-after-terminal": ("indeterminate", "DRC-15"),
    # Unsigned resolver edits, read as if signed.
    "drv-1-signed-observation": ("indeterminate", "DRJ-2"),
    "drv-1-signed-transaction-record": ("fail", "DREB-18"),
    # A renamed log is not the event its transaction must emit.
    "native-event-name-substitution": ("fail", "DRL-11"),
    # The creation log's job topic is the job every log must target.
    "creation-event-job-topic-mismatch": ("fail", "DRT-4"),
    # A terminal block moved before the decision's anchor follows it.
    "native-events-out-of-order": ("fail", "DRD-11"),
    # A finality block at another depth has another time than the record's.
    "funding-finality-block-wrong-depth": ("fail", "DRW-6"),
    # A creation log changed alone contradicts the calldata that emitted it.
    "creation-event-cutoff-mismatch": ("fail", "DRV-6"),
    "creation-event-hook-not-zero": ("fail", "DRV-6"),
    # The generator writes the native job ID into every log's job topic.
    "nonminimal-native-job-id": ("error", "DRV-3"),
    "native-job-id-beyond-uint256": ("error", "DRV-3"),
    # The outcome's case and revision are also its addresses' segments.
    "noncanonical-case-id": ("fail", "DRX-7"),
    "case-id-above-ulid-range": ("fail", "DRX-7"),
    "noninteger-dispute-revision": ("fail", "DRAA-7"),
    # A respelt address is no longer the derived logical address, and a
    # decision reference the terminal does not carry is not the terminal's.
    "evaluation-address-segment-nonminimal": ("fail", "DRD-2"),
    "dispute-address-segment-nonminimal": ("fail", "DRD-2"),
    "decision-address-of-another-job": ("fail", "DRT-1"),
    "decision-address-of-other-stage": ("fail", "DRT-1"),
    "decision-reference-anchor-kind-unregistered": ("fail", "DRT-1"),
    # A missing DeliveryEvidence version is not the supported one either.
    # DRV-8 decides the other artifacts' missing and unsupported versions at
    # one guard, so theirs are isolated.
    "delivery-version-missing": ("error", "DRV-2"),
    # A rail with no version member is not a JobEscrowRailDefinition's shape.
    "rail-version-missing": ("error", "DRV-3"),
    # An AgreementDocument has no payee-bound members.
    "bilateral-agreement-not-payee-bound": ("error", "DRV-3"),
    # The rail fee is copied into the resolved native state.
    "rail-fee-boolean": ("error", "DRV-3"),
    # Incomplete or unpinned ABI pins are not the fixture ABI, and a
    # transaction or log outside wrong pins is not decoded.
    "rail-entrypoint-missing": ("error", "DRV-2"),
    "rail-event-missing": ("error", "DRC-20"),
    "rail-entrypoint-selector-wrong": ("error", "DRV-2"),
    "rail-event-topic-wrong": ("error", "DRV-2"),
    "rail-abi-reference-create-job": ("fail", "DRC-18"),
    "rail-event-inputs-do-not-reproduce-signature": ("error", "DRV-2"),
    "rail-event-four-indexed-inputs": ("error", "DRV-2"),
    "rail-event-extra-pin": ("error", "DRV-2"),
    "rail-payment-released-recipient": ("error", "DRV-2"),
    "rail-configuration-cutoff-bytes32": ("error", "DRV-2"),
    "rail-configuration-policy-string": ("error", "DRV-2"),
    "rail-configuration-job-id-uint64": ("error", "DRV-2"),
    "rail-configuration-same-input": ("error", "DRV-2"),
    "rail-event-pin-repeated": ("error", "DRV-2"),
    "rail-entrypoint-input-type-alias": ("error", "DRV-2"),
    "rail-configuration-policy-word-text": ("error", "DRV-2"),
    # Without the policy profile gate, the configuration word differs.
    "unsupported-expiry-only-policy": ("fail", "DRC-21"),
    # A reference signer is also checked against the artifact's signer, a
    # native locator names no logical address, and reordered terminal
    # references meet logs whose topic0 is another event's.
    "decision-ref-signer-buyer": ("fail", "DRV-6"),
    "funding-ref-signer-buyer": ("fail", "DRV-6"),
    "terminal-job-ref-native-locator": ("fail", "DRT-4"),
    "terminal-job-ref-ipfs-anchor": ("fail", "DRT-4"),
    "terminal-event-refs-reordered": ("fail", "DRC-18"),
    # A rail pinning an implementation the escrow does not use, or a
    # delegating escrow without both pins, is a DRJ-11 mismatch either way.
    "drj-11-unpinned-implementation": ("indeterminate", "DRJ-11"),
    "drj-11-delegating-without-implementation-hash": ("indeterminate", "DRJ-11"),
    # A respelt railId is not the one acceptedRails selects.
    "rail-id-lower-case-asset": ("fail", "DRP-10"),
    "rail-id-other-chain": ("fail", "DRP-10"),
    # A rail missing a member is not the JobEscrowRailDefinition shape, a
    # rail without a finality profile has a malformed one, and a disabled
    # rail is not the offline fixture rail either.
    "rail-asset-missing": ("error", "DRV-3"),
    "rail-governance-missing": ("error", "DRV-3"),
    "rail-finality-profile-missing": ("error", "DRV-3"),
    "rail-availability-disabled": ("error", "DRV-1"),
    # A malformed signer is not the artifact's signer either.
    "attestation-ref-signer-bad-scheme": ("fail", "DRV-6"),
    "attestation-ref-signer-unsorted-parameters": ("fail", "DRV-6"),
    # A malformed EVM account claim is not a canonical ClaimReference.
    "account-claim-bad-checksum": ("error", "DRV-3"),
    "account-claim-non-hex-address": ("error", "DRV-3"),
    "account-claim-short-address": ("error", "DRV-3"),
    # An upper-case token is not the rail's lower-case token.
    "funding-token-upper-case": ("fail", "DRF-2"),
    # An upper-case or `0x` txHash names no observed log.
    "event-reference-tx-hash-upper-case": ("fail", "DRT-4"),
    "event-reference-tx-hash-0x-prefixed": ("fail", "DRT-4"),
    # A `0x` resolver record names no terminal transaction.
    "resolver-transaction-tx-hash-0x-prefixed": ("fail", "DRL-10"),
    # A missing or mistyped observedAt is not a unix-millisecond integer, and
    # not the confirmation-depth block's time.
    "funding-observed-at-missing": ("error", "DRW-4"),
    "terminal-observed-at-missing": ("error", "DRW-4"),
    "funding-observed-at-text": ("fail", "DRW-6"),
    "terminal-observed-at-negative": ("fail", "DRW-6"),
    # An unknown classification, an empty rule, and an unknown outcome
    # contradict the rule matrix.
    "finding-classification-unknown": ("fail", "DRE-10"),
    "rule-criteria-empty": ("fail", "DRE-10"),
    "criterion-outcome-unknown": ("fail", "DRE-10"),
    # A pre-submission decision cannot authorize a Submitted job's terminal.
    "pre-submission-decision-after-submit": ("fail", "DRD-14"),
    # The DACS-4 DeliveryEvidence shape includes its signature.
    "delivery-signature-absent": ("error", "DRV-3"),
}
# Structural negatives: their deciding guard is what keeps the verifier from
# reading a structure that the negative removes, so without that guard the
# verifier raises instead of reaching a verdict.  Isolation is not claimed
# for them; the generator fails if one stops raising or another starts.
STRUCTURAL_NEGATIVES: dict[str, str] = {
    "pipeline-missing-terminal": "the pipeline has no terminal escrow step to read",
    "pipeline-commit-phase-missing": "the pipeline has no commit step to read",
    "pipeline-negotiation-missing": "the pipeline has no negotiation step to read",
    "pipeline-escrow-rail-not-accepted": "acceptedRails has no entry for the selected rail to read",
    "overlay-signature-entry-not-object": "the overlay has no signature object for one role",
    "account-claim-parameters-not-canonical": "an unparsed account claim has no address to read",
    "drp-9-digest-anchor-unavailable": "the resolver record has no digest anchor to read",
    "deliveryless-lifecycle-carries-submission-binding": "the submission binding names no event to read",
    "transaction-record-for-another-transaction": "the resolver has no record of the terminal transaction to read",
    "drv-3-evaluation-subject-refs": "the evaluation has no subject reference array to read",
    "drv-3-evaluation-not-object": "an integer evaluation has no discriminator to read",
    "dispute-outcome-without-recommendation": "the DisputeOutcome has no recommendation to read",
    "drv-3-terminal-state-array": "an array terminal state cannot key the terminal-event lookup",
    "drv-3-terminal-state-object": "an object terminal state cannot key the terminal-event lookup",
    "drv-3-terminal-state-unknown-string": "an unknown terminal state names no crosswalk terminal events",
    "funding-events-empty": "the funding evidence has no event to read",
    "terminal-events-empty": "the terminal evidence has no event to read",
    "terminal-events-state-log-only": "the terminal evidence has no transfer log to read",
    "funding-finality-pending": "the funding event has no confirmation-depth block to read",
    "terminal-finality-pending": "the terminal event has no confirmation-depth block to read",
    "native-event-kind-substitution": "the terminal event has no matching observation",
    "native-event-chain-substitution": "the terminal event has no matching observation",
    "native-transition-outside-crosswalk": "no crosswalk row gives the transition's next status",
    "native-status-not-mapped": "an unmapped native status has no crosswalk name",
    "native-entrypoint-not-pinned": "an unpinned selector names no entrypoint",
    "event-log-layout-mismatch": "a log that does not fit its layout has no decoded inputs to read",
    "rail-configuration-event-unpinned": "configurationEvidence names no event whose inputs can be read",
    "rail-configuration-shape-superseded": "configurationEvidence has no eventTopic0 to read",
    "rail-entrypoint-pin-without-inputs": "an entrypoint pin has no inputs to read",
    "cross-substrate-order-unavailable": "the resolver has no decision anchor to read",
    "self-reported-time-cannot-order": "the resolver has no decision anchor to read",
}
# Pack runner and deployment-capability code are outside the lifecycle audit.
# `_contained_lifecycle_check` is the batch's safety net for a malformed value
# that no shape stage decides; the audit disables it, and a unit test drives it.
_UNAUDITED_FUNCTIONS = {
    "_status", "deployment_rule_statuses", "evaluate_deployment", "verify_vector_pack",
    "verify_deployment_pack", "main", "load_json", "_pack_hash", "_contained_lifecycle_check",
}


def _is_finding(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "result"
        and bool(node.args)
        and not (isinstance(node.args[0], ast.Constant) and node.args[0].value == "pass")
    )


class _GuardSwitches(ast.NodeTransformer):
    """Make every non-pass `return result(...)` in the lifecycle verifier switchable."""

    def __init__(self) -> None:
        self.sites: list[str] = []
        self._function: str | None = None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        if node.name in _UNAUDITED_FUNCTIONS:
            return node
        outer, self._function = self._function, node.name
        self.generic_visit(node)
        self._function = outer
        return node

    def visit_Return(self, node: ast.Return) -> ast.AST:
        if self._function is None or node.value is None:
            return node
        parts = node.value.elts if isinstance(node.value, ast.Tuple) else [node.value]
        finding = next((part for part in parts if _is_finding(part)), None)
        if finding is None:
            return node
        self.sites.append(
            f"{self._function}:{node.lineno} "
            f"{ast.unparse(finding.args[0])} {ast.unparse(finding.args[1])}"
        )
        switch = ast.Call(
            func=ast.Name("_guard_fires", ast.Load()),
            args=[ast.Constant(len(self.sites) - 1)],
            keywords=[],
        )
        return ast.copy_location(ast.If(test=switch, body=[node], orelse=[]), node)


class GuardedVerifier:
    """The lifecycle verifier with each guard site switchable, for guard audits."""

    def __init__(self) -> None:
        switches = _GuardSwitches()
        tree = switches.visit(ast.parse(VERIFIER_PATH.read_text(encoding="utf-8")))
        ast.fix_missing_locations(tree)
        self.sites = switches.sites
        self._disabled: int | None = None
        self._fired: list[int] = []
        module = types.ModuleType("guarded_delivery_remedy_verifier")
        module.__file__ = str(VERIFIER_PATH)
        module.__dict__["_guard_fires"] = self._guard_fires
        exec(compile(tree, str(VERIFIER_PATH), "exec"), module.__dict__)
        # A removed guard must surface as the exception it lets through, not
        # as the batch's contained `error`.
        module.MALFORMED_INPUT_ERRORS = ()
        self.module = module

    def _guard_fires(self, site: int) -> bool:
        if site == self._disabled:
            return False
        self._fired.append(site)
        return True

    def run(
        self, value: Any, priors: list[Any] | None = None, disabled: int | None = None
    ) -> tuple[dict[str, str], list[int]]:
        """Evaluate after ``priors`` share a ledger; return the outcome and the guards that fired.

        For ``value`` this is its verdict when evaluated together with
        ``priors``: each prior records its terminal whatever its own verdict.
        """
        self._disabled = disabled
        try:
            ledger = self.module.DecisionLedger()
            for prior in priors or []:
                self.module.evaluate_protocol(copy.deepcopy(prior), ledger)
            self._fired = []
            try:
                outcome = self.module.evaluate_protocol(copy.deepcopy(value), ledger)
            except Exception as exc:  # an unguarded crash, not a guard's finding
                outcome = {"result": "exception", "rule": type(exc).__name__, "detail": str(exc)}
            return outcome, list(self._fired)
        finally:
            self._disabled = None


def negative_isolation_problems(
    pack: dict[str, Any], verifier: GuardedVerifier | None = None
) -> list[str]:
    """Return every negative vector that does not fail only at its intended guard.

    A negative is isolated when, with the guard that decides it removed, the
    verifier returns `pass`: its signatures and bindings are otherwise
    valid.  `FOLLOW_ON_FINDINGS` lists the negatives that reach one exact
    second finding instead, and `STRUCTURAL_NEGATIVES` those that make the
    verifier raise.  Any other outcome, including an exception, is a problem.
    """
    verifier = verifier or GuardedVerifier()
    by_name = {item["name"]: item for item in pack["vectors"]}
    problems = []
    for vector_value in pack["vectors"]:
        name = vector_value["name"]
        if vector_value["expected"] == "pass":
            continue
        value = verifier.module.materialize_vector(pack, vector_value)
        priors = [
            verifier.module.materialize_vector(pack, by_name[prior])
            for prior in vector_value.get("evaluatedWith", [])
        ]
        _outcome, fired = verifier.run(value, priors)
        if not fired:
            problems.append(f"{name}: no guard decides it")
            continue
        deciding = fired[-1]
        isolated, others = verifier.run(value, priors, disabled=deciding)
        without = f"{name}: without {verifier.sites[deciding]},"
        outcome = (isolated["result"], isolated["rule"])
        follow_on = FOLLOW_ON_FINDINGS.get(name)
        if name in STRUCTURAL_NEGATIVES:
            if isolated["result"] != "exception":
                problems.append(f"{without} a listed structural negative reports {outcome[0]}/{outcome[1]}")
        elif isolated["result"] == "exception":
            problems.append(f"{without} the verifier raises {isolated['rule']}: {isolated['detail']}")
        elif follow_on is not None:
            if outcome != follow_on:
                problems.append(f"{without} its listed follow-on finding {follow_on} became {outcome}")
        elif isolated["result"] != "pass":
            reporter = verifier.sites[others[-1]] if others else "an unswitched path"
            problems.append(f"{without} {reporter} reports {outcome[0]}/{outcome[1]}")
    return problems


def synthetic_manifest() -> dict[str, Any]:
    runtime = hashlib.sha256(b"synthetic eligible runtime").hexdigest()
    return {
        "manifestVersion": "1",
        "candidateProfile": "dacs-delivery-gate-v1",
        "fixtureOnly": True,
        "registrationStatus": "not-a-deployment",
        "implementation": {
            "name": "synthetic-drc-control",
            "revision": "fixture-only",
            "chainId": 31337,
            "contractAddress": "0x" + "de" * 20,
        },
        "capabilities": {
            "preterminalProviderPayoutPaths": [],
            "platformFeeBP": 0,
            "evaluatorFeeBP": 0,
            "feeMutationAuthorities": [],
            "expiryRecoveryPauseGated": False,
            "expiryRecoveryHookGated": False,
            "evaluatorCanBlockExpiryRecovery": False,
            "pendingClaimCanDelayFundedRecovery": False,
            "lockedFundAlternateWithdrawalAuthorities": [],
            "logicReplacementAuthorities": [],
            "hookMutable": False,
            "upgradeableSyntactically": False,
            "upgradeAuthorityIrreversiblyDisabled": True,
            "hookMode": "absent",
            "paymentTokenSemantics": {
                "transferFees": False,
                "rebasing": False,
                "callbacks": False,
                "pause": False,
                "blacklist": False,
                "upgradeable": False,
                "externalBalanceMutation": False,
                "independentlyVerified": True,
            },
            "eventIdentityComplete": True,
            "decisionOrderingProfile": "anchor-final-before-terminal-v1",
            "deadlineProfile": "separate-submission-cutoff-v1",
            "submissionCutoffEnforced": True,
            "expiryRecoveryDeadlineEnforced": True,
            "rejectBindsExpectedPriorStatus": True,
            "trustedForwarders": [],
            "authorizationEntrypoints": [],
        },
        "evidence": {
            "sourceRevision": "synthetic-fixture-only",
            "compilerSettingsHash": hashlib.sha256(b"synthetic compiler settings").hexdigest(),
            "runtimeBytecodeHash": runtime,
            "independentlyResolvedRuntimeBytecodeHash": runtime,
            "sourceToBytecodeReproducible": True,
            "upgradeDisablementAuthenticated": True,
            "decisionOrderingEvidenceAuthenticated": True,
            "deadlineEnforcementAuthenticated": True,
            "authorizationPathsFromSource": True,
            "complete": True,
            "conflict": False,
        },
    }


def current_reference_manifest() -> dict[str, Any]:
    return {
        "manifestVersion": "1",
        "candidateProfile": "dacs-delivery-gate-v1",
        "fixtureOnly": False,
        "registrationStatus": "unregistered-ineligible-reference-source",
        "implementation": {
            "name": "erc-8183/base-contracts ERC8183.sol",
            "revision": "142e669c1fd318486a4628395b629f033654dd06",
            "sourcePath": "contracts/ERC8183.sol",
            "deployment": None,
        },
        "capabilities": {
            "preterminalProviderPayoutPaths": ["settleClaim while Funded", "approveClaim while Funded"],
            "platformFeeBP": 0,
            "evaluatorFeeBP": 0,
            "feeMutationAuthorities": ["ADMIN_ROLE:setPlatformFee", "ADMIN_ROLE:setEvaluatorFee"],
            "expiryRecoveryPauseGated": True,
            # claimRefund calls no hook: "Not hookable" (ERC8183.sol lines 861-863).
            "expiryRecoveryHookGated": False,
            "evaluatorCanBlockExpiryRecovery": False,
            "pendingClaimCanDelayFundedRecovery": True,
            "lockedFundAlternateWithdrawalAuthorities": ["ADMIN_ROLE:emergencyWithdraw"],
            "logicReplacementAuthorities": ["DEFAULT_ADMIN_ROLE:_authorizeUpgrade", "ADMIN_ROLE:batchDetachHook"],
            "hookMutable": True,
            "upgradeableSyntactically": True,
            "upgradeAuthorityIrreversiblyDisabled": False,
            "hookMode": "mutable-blocking",
            "paymentTokenSemantics": {
                "transferFees": None,
                "rebasing": None,
                "callbacks": None,
                "pause": None,
                "blacklist": None,
                "upgradeable": None,
                "externalBalanceMutation": None,
                "independentlyVerified": None,
            },
            "eventIdentityComplete": True,
            "decisionOrderingProfile": None,
            "deadlineProfile": None,
            "submissionCutoffEnforced": False,
            # claimRefund on a Submitted job reverts until expiredAt +
            # EVALUATION_GRACE_PERIOD, a one-hour constant (ERC8183.sol lines 78,
            # 869-870), so recovery opens an hour after the DREB-15 deadline; a
            # Funded job with a pending claim reverts with PendingClaimExists
            # (lines 871-872).
            "expiryRecoveryDeadlineEnforced": False,
            # reject(jobId, reason, optParams) accepts a Funded or a Submitted
            # job alike and takes no expected prior status (ERC8183.sol lines
            # 806-831), so a pre-submission rejection can execute after a
            # native submit (DRC-22).
            "rejectBindsExpectedPriorStatus": False,
            # ERC8183.sol inherits no ERC2771Context and declares no
            # *WithAuthorization entrypoint; the ERC8183WithAuthorization.sol
            # extension adds them (deployment case
            # dreb-24-reference-authorization-extension).
            "trustedForwarders": [],
            "authorizationEntrypoints": [],
        },
        "evidence": {
            "sourceRevision": "142e669c1fd318486a4628395b629f033654dd06",
            "compilerSettingsHash": None,
            "runtimeBytecodeHash": None,
            "independentlyResolvedRuntimeBytecodeHash": None,
            "sourceToBytecodeReproducible": None,
            "upgradeDisablementAuthenticated": False,
            "decisionOrderingEvidenceAuthenticated": None,
            "deadlineEnforcementAuthenticated": None,
            "authorizationPathsFromSource": None,
            "complete": False,
            "conflict": None,
        },
        "observedSourceFacts": [
            "UUPSUpgradeable with DEFAULT_ADMIN_ROLE upgrade authorization",
            "ADMIN_ROLE pause, emergencyWithdraw, mutable fees, hook whitelist, and hook detachment",
            "settleClaim and approveClaim can release provider value from Funded",
            "claimRefund is pause-gated and a pending claim can delay Funded recovery",
            "one canonical expiredAt and no separately enforced per-job submission cutoff",
            "claimRefund on a Submitted job reverts with GracePeriodActive until expiredAt + "
            "EVALUATION_GRACE_PERIOD (1 hours) (ERC8183.sol lines 78, 869-870)",
            "claimRefund on a Funded job with a pending claim reverts with PendingClaimExists "
            "(ERC8183.sol lines 871-872)",
            "claimRefund calls no hook (\"Not hookable\", ERC8183.sol lines 861-863)",
            "submit reverts at or after expiredAt (ERC8183.sol line 728)",
            "reject is gated only on Funded or Submitted and takes no expected prior status "
            "(ERC8183.sol lines 806-831)",
            "ERC8183.sol inherits no ERC2771Context; the ERC8183WithAuthorization.sol extension adds a "
            "signature-authorized variant of createJob, fund, submit, complete, and reject "
            "(lines 100, 205, 233, 251, 270)",
        ],
    }


def deployment_case(name: str, base: str, expected: str, rules: list[str], note: str, patch=None, unknown=None, covers=None) -> dict[str, Any]:
    value = {
        "name": name,
        "base": base,
        "expected": expected,
        "registrationEligible": False,
        "expectedFailedRules": rules,
        "rules": sorted(set(covers or rules)),
        "note": note,
        "patch": patch or [],
    }
    if unknown is not None:
        value["expectedUnknownRules"] = unknown
    return value


def build_deployment_pack() -> dict[str, Any]:
    manifests = {
        "synthetic-control": synthetic_manifest(),
        "current-reference-142e669": current_reference_manifest(),
    }
    cases = [
        deployment_case("synthetic-all-rules-control", "synthetic-control", "pass", [], "all DRC rules pass, but a capability evaluation never establishes registration eligibility", covers=["DRL-8", "DRL-9"]),
        deployment_case("drc-11-manifest-labels", "synthetic-control", "pass", [], "eligibility needs independently resolved deployment and registry facts, not manifest labels", [{"op": "replace", "path": ["fixtureOnly"], "value": False}, {"op": "replace", "path": ["registrationStatus"], "value": "listed"}], covers=["DRC-11"]),
        deployment_case("drc-1-preterminal-payout", "synthetic-control", "fail", ["DRC-1"], "a Funded payout path violates delivery gating", [{"op": "replace", "path": ["capabilities", "preterminalProviderPayoutPaths"], "value": ["settleClaim while Funded"]}]),
        deployment_case("drc-2-mutable-fees", "synthetic-control", "fail", ["DRC-2"], "zero defaults do not repair mutable fee authority", [{"op": "replace", "path": ["capabilities", "feeMutationAuthorities"], "value": ["admin:setFee"]}]),
        deployment_case("drc-3-blocked-expiry-recovery", "synthetic-control", "fail", ["DRC-3"], "pause-gated expiry recovery is ineligible", [{"op": "replace", "path": ["capabilities", "expiryRecoveryPauseGated"], "value": True}]),
        deployment_case("drc-4-emergency-withdrawal", "synthetic-control", "fail", ["DRC-4"], "an alternate locked-fund recipient is ineligible", [{"op": "replace", "path": ["capabilities", "lockedFundAlternateWithdrawalAuthorities"], "value": ["admin:withdraw"]}]),
        deployment_case("drc-5-logic-replacement", "synthetic-control", "fail", ["DRC-5"], "mutable logic can weaken core guarantees", [{"op": "replace", "path": ["capabilities", "logicReplacementAuthorities"], "value": ["proxy-admin"]}]),
        deployment_case("drc-6-live-upgrade-authority", "synthetic-control", "fail", ["DRC-6"], "syntactic upgradeability needs irreversible disablement proof", [{"op": "replace", "path": ["capabilities", "upgradeableSyntactically"], "value": True}, {"op": "replace", "path": ["capabilities", "upgradeAuthorityIrreversiblyDisabled"], "value": False}, {"op": "replace", "path": ["evidence", "upgradeDisablementAuthenticated"], "value": False}]),
        deployment_case("drc-7-mutable-blocking-hook", "synthetic-control", "fail", ["DRC-7"], "hooks cannot block recovery or change later", [{"op": "replace", "path": ["capabilities", "hookMode"], "value": "mutable-blocking"}]),
        deployment_case("drc-7-immutable-nonzero-hook", "synthetic-control", "fail", ["DRC-7"], "the per-job hook is the zero address; an immutable non-blocking hook is not absent", [{"op": "replace", "path": ["capabilities", "hookMode"], "value": "immutable-nonblocking"}]),
        deployment_case("drc-8-upgradeable-token", "synthetic-control", "fail", ["DRC-8"], "an upgradeable payment token is excluded, as the pausable USDC assets are", [{"op": "replace", "path": ["capabilities", "paymentTokenSemantics", "upgradeable"], "value": True}]),
        deployment_case("drc-8-fee-on-transfer-token", "synthetic-control", "fail", ["DRC-8"], "token transfer fees break exact accounting", [{"op": "replace", "path": ["capabilities", "paymentTokenSemantics", "transferFees"], "value": True}]),
        deployment_case("drc-9-ambiguous-events", "synthetic-control", "fail", ["DRC-9"], "events must identify the exact job and action", [{"op": "replace", "path": ["capabilities", "eventIdentityComplete"], "value": False}]),
        deployment_case("drc-10-bytecode-mismatch", "synthetic-control", "fail", ["DRC-10"], "independently resolved code must match reproducible output", [{"op": "replace", "path": ["evidence", "independentlyResolvedRuntimeBytecodeHash"], "value": "ab" * 32}]),
        deployment_case("drc-11-conflicting-evidence", "synthetic-control", "fail", ["DRC-11"], "conflicting deployment evidence leaves the rail unavailable", [{"op": "replace", "path": ["evidence", "conflict"], "value": True}]),
        deployment_case("drc-12-unauthenticated-ordering", "synthetic-control", "fail", ["DRC-12"], "decision ordering must be authenticated", [{"op": "replace", "path": ["evidence", "decisionOrderingEvidenceAuthenticated"], "value": False}]),
        deployment_case("drc-13-missing-native-submission-cutoff", "synthetic-control", "fail", ["DRC-13"], "submission and recovery deadlines must be separately enforced", [{"op": "replace", "path": ["capabilities", "submissionCutoffEnforced"], "value": False}]),
        deployment_case("drc-22-reject-without-expected-status", "synthetic-control", "fail", ["DRC-22"], "an evaluator reject gated only on Funded or Submitted can execute a pre-submission rejection after a native submit", [{"op": "replace", "path": ["capabilities", "rejectBindsExpectedPriorStatus"], "value": False}]),
        deployment_case("dreb-24-trusted-forwarder", "synthetic-control", "fail", ["DREB-24"], "an ERC-2771 trusted forwarder lets a relayer act as the native caller", [{"op": "replace", "path": ["capabilities", "trustedForwarders"], "value": ["0x" + "f0" * 20]}]),
        deployment_case("dreb-24-authorization-entrypoint", "synthetic-control", "fail", ["DREB-24"], "a signature-authorized entrypoint lets a relayer act for a profile role", [{"op": "replace", "path": ["capabilities", "authorizationEntrypoints"], "value": ["completeWithAuthorization"]}]),
        deployment_case("dreb-24-absence-not-shown", "synthetic-control", "indeterminate", [], "an absence of forwarders and authorization entrypoints that the DRC-10 evidence does not show is not assumed", [{"op": "replace", "path": ["evidence", "authorizationPathsFromSource"], "value": None}], unknown=["DREB-24"], covers=["DREB-24"]),
        deployment_case("source-to-bytecode-evidence-unavailable", "synthetic-control", "indeterminate", [], "missing source-to-bytecode evidence is not guessed, and without it DREB-24 is not shown", [{"op": "replace", "path": ["evidence", "sourceToBytecodeReproducible"], "value": None}], unknown=["DRC-10", "DREB-24"], covers=["DRC-10", "DREB-24"]),
        deployment_case(
            "current-reference-142e669-ineligible",
            "current-reference-142e669",
            "fail",
            ["DRC-1", "DRC-2", "DRC-3", "DRC-4", "DRC-5", "DRC-6", "DRC-7", "DRC-13", "DRC-22"],
            "the pinned reference source is not a DACS-eligible deployment",
            unknown=["DRC-8", "DRC-10", "DRC-11", "DRC-12", "DREB-24"],
            covers=["DRC-1", "DRC-2", "DRC-3", "DRC-4", "DRC-5", "DRC-6", "DRC-7", "DRC-13", "DRC-22", "DREB-24"],
        ),
        deployment_case(
            "dreb-24-reference-authorization-extension",
            "current-reference-142e669",
            "fail",
            ["DRC-1", "DRC-2", "DRC-3", "DRC-4", "DRC-5", "DRC-6", "DRC-7", "DRC-13", "DRC-22", "DREB-24"],
            "the pinned reference's ERC8183WithAuthorization.sol extension recognizes signature-authorized createJob, fund, submit, complete, and reject",
            [
                {"op": "replace", "path": ["implementation", "sourcePath"], "value": "contracts/ERC8183WithAuthorization.sol"},
                {"op": "replace", "path": ["capabilities", "authorizationEntrypoints"], "value": [
                    f"{action}WithAuthorization" for action in ("createJob", "fund", "submit", "complete", "reject")
                ]},
            ],
            unknown=["DRC-8", "DRC-10", "DRC-11", "DRC-12"],
        ),
        deployment_case("malformed-deployment-manifest", "synthetic-control", "error", [], "malformed capability input fails before eligibility", [{"op": "remove", "path": ["capabilities"]}]),
    ]
    payload = {"manifests": manifests, "cases": cases}
    return {
        "kind": "ERC8183DeploymentCapabilityPack",
        "status": "non-normative-review-fixture",
        "spec": "docs/delivery-or-remedy-candidate.md#84-deployment-eligibility",
        "sourcePins": {
            "canonicalErc": "https://github.com/ethereum/ERCs/blob/a078cab5cc8e9581c15f76c091ed96eed28f02f7/ERCS/erc-8183.md",
            "referenceImplementation": "https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183.sol",
            "referenceAuthorizationExtension": "https://github.com/erc-8183/base-contracts/blob/142e669c1fd318486a4628395b629f033654dd06/contracts/ERC8183WithAuthorization.sol",
        },
        "scope": "capability evidence only; no chain deployment or DACS rail is registered",
        "hash": hashlib.sha256(canonical_bytes(payload)).hexdigest(),
        "count": len(cases),
        **payload,
    }


def rendered(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    vector_pack = build_vector_pack()
    # The spec/ pins need the Checked-against commit in this clone's history:
    # without it there is no pack to write or compare, only null pins.
    if vector_pack["sourcePins"]["dacs"]["documents"] is None:
        print(
            f"ERROR: cannot read spec/ at the Checked-against commit {verifier.DACS_CHECKED_AGAINST[:7]}; fetch full history",
            file=sys.stderr,
        )
        return 1
    outputs = {
        VECTOR_OUTPUT: rendered(vector_pack),
        DEPLOYMENT_OUTPUT: rendered(build_deployment_pack()),
    }
    if args.write or args.check:
        problems = negative_isolation_problems(vector_pack)
        if problems:
            print("ERROR: negative vectors do not fail only at their intended guard:", file=sys.stderr)
            for problem in problems:
                print(f"- {problem}", file=sys.stderr)
            return 1
    if args.write:
        for path, text in outputs.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
        return 0
    if args.check:
        stale = [
            path for path, text in outputs.items()
            if not path.exists() or path.read_text(encoding="utf-8") != text
        ]
        if stale:
            for path in stale:
                print(f"ERROR: {path.relative_to(ROOT)} is stale", file=sys.stderr)
            print("run this script with --write", file=sys.stderr)
            return 1
        print("delivery-or-remedy candidate packs are deterministic and current")
        return 0
    for path, text in outputs.items():
        print(f"# {path.relative_to(ROOT)}")
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
