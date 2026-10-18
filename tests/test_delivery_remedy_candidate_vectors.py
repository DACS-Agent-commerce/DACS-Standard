import contextlib
import copy
import hashlib
import io
import itertools
import json
import random
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from scripts.jcs import canonicalize as jcs_canonicalize
from scripts import generate_delivery_remedy_candidate_vectors as generator
from scripts import verify_delivery_remedy_candidate_vectors as verifier
from scripts.generate_delivery_remedy_candidate_vectors import drop, make_base, put
from scripts.generate_delivery_remedy_candidate_vectors import each as each_hook
from scripts.verify_delivery_remedy_candidate_vectors import (
    DRC_RULES,
    NATIVE_STATE_FIELDS,
    PINNED_RESOLVER_KEYS,
    PINNED_STEWARD_KEYS,
    DecisionLedger,
    TerminalRecord,
    apply_operation,
    artifact_hash,
    canonical_bytes,
    content_hash,
    deployment_rule_statuses,
    evaluate_deployment,
    evaluate_lifecycles,
    evaluate_protocol,
    materialize_vector,
    verify_deployment_pack,
    verify_vector_pack,
)


ROOT = Path(__file__).resolve().parents[1]
VECTOR_PACK = ROOT / "conformance/fixtures/delivery-remedy/candidate-vectors-v0.1.json"
DEPLOYMENT_PACK = ROOT / "conformance/fixtures/delivery-remedy/deployment-capabilities-v0.1.json"
GENERATOR = ROOT / "scripts/generate_delivery_remedy_candidate_vectors.py"
VERIFIER = ROOT / "scripts/verify_delivery_remedy_candidate_vectors.py"
SPEC = ROOT / "docs/delivery-or-remedy-candidate.md"
SETTLE_SPEC = ROOT / "spec/DACS-4-SETTLE.md"
README = ROOT / "conformance/fixtures/delivery-remedy/README.md"


def evaluate(value):
    """Evaluate one independent lifecycle with its own verifier ledger."""
    return evaluate_protocol(value, DecisionLedger())


def finding(value):
    observed = evaluate(value)
    return observed["result"], observed["rule"]


def verdict(observed):
    return observed["result"], observed["rule"]


# A replay revision never moves a verdict to an earlier entry, except that a
# second qualifying write (CORE §5.1) replaces with DRAA-4 a `pass`, an
# uncertainty, or a finding that rested on one selected write copy.  It never
# replaces a deterministic `error` or `fail` (candidate §9, FV-10).  An
# `error` on a copy (the anchor-side DRW-4 bound) can become its pending
# terminal's replay `fail`, never `pass` or plain uncertainty.
REPLAY_VERDICT_RANK = {"pass": 0, "indeterminate": 1, "error": 2, "fail": 3}
EQUIVOCATION = ("indeterminate", "DRAA-4")
COPY_SELECTING_RULES = {"DRV-6", "DRD-10", "DRD-11", "DRC-15", "DRW-4"}


def revision_allowed(revision, current):
    if verdict(revision) == EQUIVOCATION:
        return current[0] in ("pass", "indeterminate") or current[1] in COPY_SELECTING_RULES
    if revision["result"] == "error" or (current[0] == "error" and current[1] not in COPY_SELECTING_RULES):
        return False
    return REPLAY_VERDICT_RANK[revision["result"]] >= REPLAY_VERDICT_RANK[current[0]]


def _signed_by_resolver(edit):
    """Apply ``edit`` to a release fixture and have the pinned resolver sign the result."""
    def build(pack):
        value = copy.deepcopy(pack["fixtures"]["release"])
        edit(value)
        generator.resign_resolver(value)
        return value
    return build


def _release(edit):
    def build(pack):
        value = copy.deepcopy(pack["fixtures"]["release"])
        edit(value)
        return value
    return build


def _hooked(lifecycle="release", **hooks):
    return lambda _pack: make_base(lifecycle, hooks=hooks)


def _overlay(edit):
    """Edit the release overlay unsigned, keeping the orchestrator's commit receipt bound to it."""
    def build(pack):
        value = copy.deepcopy(pack["fixtures"]["release"])
        edit(value["artifacts"]["agreement"])
        value["executionContext"]["commitmentReceipts"]["overlay"]["contentHash"] = artifact_hash(
            value["artifacts"]["agreement"]
        )
        return value
    return build


def _nested(levels):
    """An object nested ``levels`` objects deep, built without recursion."""
    value = {}
    for _ in range(levels - 1):
        value = {"k": value}
    return value


def _creation_after_funding(value):
    """Move the creation logs after the funding block, with consistent block identities."""
    for item in value["reproductionInputs"]["nativeEventInputs"][:2]:
        moved = generator.block(generator.FUNDING_BLOCK + 1)
        item.update(moved)
        item["finalityBlock"] = generator.block(generator.FUNDING_BLOCK + generator.FINALITY_BLOCKS)


def _zero_terminal_reason(value):
    """Zero the reason in the terminal call and its state log (the native projection is unchanged)."""
    value["resolverEvidence"]["transactions"][-1]["calldata"]["reason"] = verifier.ZERO_BYTES32
    for item in value["reproductionInputs"]["nativeEventInputs"]:
        if item["eventName"] == "JobCompleted":
            item["dataArguments"][0] = verifier.ZERO_BYTES32


# Runs the verifier's command line with the pure-Python JSON scanner, whose
# recursion only `sys.setrecursionlimit` bounds, and reports how the parse
# ended.  At the default limit a deep text raises RecursionError, as 3.12's C
# scanner does; at a raised limit it parses, as 3.13's and later ones can.
FORCED_PARSE = """
import json, json.scanner, sys
from scripts import verify_delivery_remedy_candidate_vectors as verifier
json.scanner.make_scanner = json.scanner.py_make_scanner
sys.setrecursionlimit(int(sys.argv[1]))
loads = json.loads
def recording(*args, **kwargs):
    try:
        value = loads(*args, **kwargs)
    except RecursionError:
        print("parse raised RecursionError")
        raise
    print("parse returned")
    return value
json.loads = recording
sys.exit(verifier.main(sys.argv[2:]))
"""


def _without_reproduction_inputs(value):
    value["reproductionInputs"] = []
    value["resolverEvidence"]["eventObservationsHash"] = content_hash(None)
    generator.resign_resolver(value, bind=False)


def _qualified_writes(edit):
    def apply(value):
        value["resolverEvidence"]["qualifiedArtifactWrites"] = {
            name: [generator.qualified_artifact_write(value, name)] for name in ("funding", "decision")
        }
        edit(value["resolverEvidence"]["qualifiedArtifactWrites"])
    return _signed_by_resolver(apply)


def _rail(*path_and_value):
    return put("parameters", *path_and_value)


# Shape guards that no lifecycle vector decides.  Each case reaches exactly
# one guard and pins its full finding, so removing that guard changes the
# outcome of the case.
GUARD_CASES = {
    "qualified-writes-malformed": (_qualified_writes(put("funding", [])), ("error", "DRV-3", "qualified artifact write summaries are malformed")),
    "qualified-write-other-address": (_qualified_writes(put("funding", 0, "logicalAddress", "dacs-x:other-job")), ("fail", "DRV-6", "qualified writes describe another logical address")),
    "qualified-write-other-hash": (_qualified_writes(put("funding", 0, "contentHash", "00" * 32)), ("fail", "DRV-6", "qualified write does not bind the referenced artifact")),
    "qualified-write-other-time": (_qualified_writes(put("decision", 0, "finalizedBlockTimestampSec", 0)), ("fail", "DRV-6", "decision ordering does not use the sole qualifying write")),
    "input-not-an-object": (lambda _pack: [], ("error", "DRV-3", "vector input must be an object")),
    "nesting-too-deep": (_release(put("native", "deep", _nested(verifier.MAX_JSON_DEPTH))), ("error", "DRV-3", f"input nests deeper than {verifier.MAX_JSON_DEPTH} arrays and objects")),
    "number-outside-profile": (_release(put("native", "fundedAtSec", float("nan"))), ("error", "DRV-3", "a number is non-finite or outside the CORE §B.2 safe-integer range")),
    "native-integer-field": (_release(put("native", "fundedAtSec", 1799990000.0)), ("error", "DRV-3", "native chain ID and times must be integers")),
    "input-missing-field": (_release(drop("native")), ("error", "DRV-3", "vector input is missing required fields")),
    "object-field-malformed": (_release(put("native", [])), ("error", "DRV-3", "candidate object fields are malformed")),
    "artifact-missing": (_release(drop("artifacts", "job")), ("error", "DRV-3", "required candidate artifacts are missing")),
    "artifact-not-object": (_release(put("artifacts", "railDefinition", [])), ("error", "DRV-3", "candidate artifacts must be objects")),
    "optional-artifact-not-object": (_release(put("artifacts", "evaluationRule", [])), ("error", "DRV-3", "evaluationRule must be an object")),
    "overlay-version": (_release(put("artifacts", "agreement", "deliveryOrRemedyAgreementVersion", "2")), ("error", "DRV-2", "unsupported agreement overlay version")),
    "overlay-discriminator-missing": (_release(drop("artifacts", "agreement", "deliveryOrRemedyAgreementVersion")), ("error", "DRV-3", "agreement overlay has no deliveryOrRemedyAgreementVersion discriminator")),
    "bilateral-discriminator-missing": (_hooked(bilateral=drop("payeeBoundAgreementVersion")), ("error", "DRV-3", "bilateral agreement has no version discriminator")),
    "decision-stage-unknown": (_hooked(decision=put("decisionStage", "mid-submission")), ("error", "DRV-3", "decision stage is outside the closed value set")),
    "dispute-opener-unknown": (_hooked("pre-submission-rejected-refund", disputeCase=put("openedByRole", "arbiter")), ("error", "DRV-3", "dispute case openedByRole is outside the closed value set")),
    "terminal-phase-index-text": (_hooked(terminal=put("terminalPhaseIndex", "3")), ("error", "DRV-3", "terminal terminalPhaseIndex is not a non-negative integer")),
    "job-contract-zero": (_hooked(job=put("contractAddress", generator.ZERO_ADDRESS)), ("fail", "DRW-1", "contractAddress is the zero address")),
    "job-runtime-hash-bare-hex": (_hooked(job=put("runtimeBytecodeHash", "ab" * 32)), ("error", "DRW-2", "runtimeBytecodeHash is not 0x and 64 lower-case hexadecimal digits")),
    "job-runtime-hash-empty-code": (_hooked(job=put("runtimeBytecodeHash", verifier.EMPTY_CODE_HASH)), ("fail", "DRW-2", "runtimeBytecodeHash is the empty-code or zero hash")),
    "job-chain-id-not-integer": (_hooked(job=put("chainId", 8453.0)), ("error", "DRV-3", "job chain ID must be an integer")),
    "funding-amount-nonminimal": (_hooked(funding=put("amountBaseUnits", "01")), ("error", "DRV-3", "a token amount is not minimal unsigned decimal text within uint256")),
    "recommendation-unknown": (_hooked("pre-submission-rejected-refund", dispute=put("recommendedDisposition", "split")), ("error", "DRV-3", "recommendedDisposition is outside the closed value set")),
    "terminal-disposition-unknown": (_hooked(terminal=put("disposition", "split")), ("error", "DRV-3", "terminal disposition is outside the closed value set")),
    "rail-extra-member": (_hooked(rail=put("fixtureOnly", True)), ("error", "DRV-3", "rail definition members are not the JobEscrowRailDefinition's")),
    "rail-version-boolean": (_hooked(rail=put("railVersion", True)), ("error", "DRV-3", "railVersion is not a positive safe integer")),
    "rail-parameter-missing": (_hooked(rail=drop("parameters", "tokenDecimals")), ("error", "DRV-3", "rail parameters are not ERC8183ProfileParameters")),
    "rail-entrypoint-pins-malformed": (_hooked(rail=_rail("entrypoints", {})), ("error", "DRC-17", "entrypoint pins are malformed")),
    "rail-event-pins-malformed": (_hooked(rail=_rail("events", 0, "topic0", 7)), ("error", "DRC-17", "event pins are malformed")),
    "rail-chain-id-text": (_release(put("artifacts", "railDefinition", "parameters", "chainId", "8453")), ("error", "DRV-3", "rail chain ID is not a positive safe integer")),
    "rail-implementation-address-malformed": (_hooked(rail=_rail("implementationAddress", "none")), ("error", "DRW-1", "rail implementationAddress is not 0x and 40 lower-case hexadecimal digits")),
    "rail-token-code-hash-bare-hex": (_hooked(rail=_rail("paymentTokenRuntimeBytecodeHash", "ab" * 32)), ("error", "DRW-2", "rail paymentTokenRuntimeBytecodeHash is not 0x and 64 lower-case hexadecimal digits")),
    "rail-token-decimals-text": (_hooked(rail=_rail("tokenDecimals", "6")), ("error", "DRV-3", "rail token decimals are not a uint8")),
    "rail-finality-depth": (_hooked(rail=_rail("finalityBlocks", 0)), ("error", "DRV-3", "rail finality depth must be a positive integer")),
    "evaluation-window-type": (_hooked(rail=_rail("minimumEvaluationWindowSec", "3600")), ("error", "DREB-14", "minimum evaluation window must be an integer")),
    "rail-network-extra-member": (_hooked(rail=put("network", "rpcUrl", "https://example.invalid")), ("error", "DRR-7", "rail asset or network members are not the DACS-4 erc20 and evm arms")),
    "rail-asset-contract-upper-case": (_hooked(rail=put("asset", "contract", "0x" + "5A" * 20)), ("error", "DRW-1", "rail asset contract is not 0x and 40 lower-case hexadecimal digits")),
    "rail-network-attestation-unknown": (_hooked(rail=put("network", "rpcAttestation", "trusted")), ("error", "DRV-3", "rail asset symbol or network attestation is malformed")),
    "rail-availability-unknown": (_hooked(rail=put("availability", "beta")), ("error", "DRV-3", "rail availability is not a DACS-4 RailAvailability")),
    "rail-asset-kind": (_hooked(rail=put("asset", "kind", "erc721")), ("fail", "DRR-7", "rail asset and network are not the erc20 and evm kinds")),
    "rail-asset-decimals": (_hooked(rail=put("asset", "decimals", 18)), ("fail", "DRR-7", "rail asset contract or decimals differ from the parameters")),
    "rail-token-zero": (_hooked(
        rail=each_hook(_rail("paymentToken", generator.ZERO_ADDRESS), put("asset", "contract", generator.ZERO_ADDRESS)),
        funding=put("token", generator.TOKEN), terminal=put("token", generator.TOKEN),
    ), ("fail", "DRW-1", "the rail contract or payment token is the zero address")),
    "rail-finality-profile-version": (_hooked(rail=put("consumerFinalityProfile", "finalityProfileVersion", "2")), ("error", "DRV-3", "consumerFinalityProfile is malformed")),
    "rail-finality-profile-model": (_hooked(rail=each_hook(
        put("consumerFinalityProfile", "model", "commitment-level"),
        put("consumerFinalityProfile", "settlement", "kind", "commitment-level"),
    )), ("fail", "DRR-4", "consumerFinalityProfile is not the block-depth model")),
    "pipeline-not-array": (_release(put("pipeline", {})), ("error", "DRV-3", "pipeline must be a non-empty array")),
    "pipeline-step-without-kind": (_release(put("pipeline", 4, {"name": "rate"})), ("error", "DRV-3", "every pipeline step must have a kind")),
    "escrow-parameters-not-object": (_release(put("pipeline", 1, "parameters", [])), ("error", "DRV-3", "x-job-escrow parameters must be an object")),
    "execution-context-not-object": (_release(put("executionContext", [])), ("error", "DRV-3", "executionContext must be an object")),
    "bilateral-member-missing": (_hooked(bilateral=drop("listingRef")), ("error", "DRV-3", "bilateral agreement is missing a PayeeBoundAgreementDocument member")),
    "bilateral-party-malformed": (_hooked(bilateral=put("parties", 0, "role", "observer")), ("error", "DRV-3", "bilateral agreement parties are not AgreementParty entries")),
    "bilateral-terms-member-missing": (_hooked(bilateral=drop("terms", "deadline")), ("error", "DRV-3", "bilateral agreement terms are missing a member")),
    "agreement-price-malformed": (_hooked(bilateral=put("terms", "price", "amount", "1.0")), ("error", "DRV-3", "agreement price is not a CD-1 PriceTerm")),
    "agreement-deadline-text": (_hooked(bilateral=put("terms", "deadline", "soon")), ("error", "DRV-3", "agreement deadline is not a unix-millisecond safe integer")),
    "payout-binding-malformed": (_hooked(bilateral=put("terms", "payoutBindings", 0, "phaseIndex", "1")), ("error", "DRV-3", "agreement payout bindings are not PayoutBinding entries")),
    "terms-rail-malformed": (_hooked(bilateral=put("terms", "rail", "x-evm-erc8183")), ("error", "DRV-3", "agreement terms.rail is not a PaymentRailRef")),
    "bilateral-signatures-not-array": (_release(put("artifacts", "bilateralAgreement", "signatures", {})), ("error", "DRV-3", "bilateral agreement signatures must be an array")),
    "role-binding-not-object": (_overlay(put("buyer", "buyer")), ("error", "DRV-3", "agreement role bindings must be objects")),
    "primary-claim-not-text": (_overlay(put("buyer", "primaryClaim", 7)), ("error", "DRV-3", "agreement primary claims must be canonical ClaimReferences")),
    "primary-claim-without-scheme": (_overlay(put("buyer", "primaryClaim", "buyer")), ("error", "DRV-3", "agreement primary claims must be canonical ClaimReferences")),
    "budget-beyond-uint256": (_hooked(
        bilateral=put("terms", "price", "amount", str(2 ** 256)),
        rail=each_hook(_rail("tokenDecimals", 0), put("asset", "decimals", 0)),
        agreement=put("budgetBaseUnits", str(2 ** 256)),
        funding=put("amountBaseUnits", "1"), terminal=put("amountBaseUnits", "1"),
    ), ("error", "DRV-3", "budgetBaseUnits exceeds the uint256 range of a token amount")),
    "orchestrator-claim-missing": (_release(put("orchestratorClaim", None)), ("error", "DRV-3", "orchestratorClaim is required")),
    "native-chain-mismatch": (_release(put("native", "chainId", 1)), ("fail", "DRJ-2", "native chain differs from the selected rail's")),
    "dispute-case-overlay-hash": (_hooked("pre-submission-rejected-refund", disputeCase=put("deliveryOrRemedyAgreementHash", "05" * 32)), ("fail", "DRX-7", "disputeCase binds another agreement overlay")),
    "dispute-case-other-case": (_hooked("pre-submission-rejected-refund", disputeCase=put("caseId", generator.JOB_B)), ("fail", "DRX-7", "the dispute case is another case's")),
    "resolver-shape": (_release(drop("resolverEvidence", "statuses")), ("error", "DRV-3", "resolver evidence shape is not exact")),
    "resolver-version": (_release(put("resolverEvidence", "resolverEvidenceVersion", "2")), ("error", "DRV-2", "unsupported resolver evidence version")),
    "resolver-transaction-record-shape": (_signed_by_resolver(drop("resolverEvidence", "transactions", 3, "outerSubmitter")), ("error", "DRV-3", "resolver transaction records are malformed")),
    "resolver-history-shape": (_signed_by_resolver(put("resolverEvidence", "priorTerminals", ["earlier"])), ("error", "DRV-3", "resolver terminal history is malformed")),
    "resolver-native-state-shape": (_signed_by_resolver(drop("resolverEvidence", "nativeState", "evaluatorAdapter")), ("error", "DRV-3", "resolver native state is malformed")),
    "resolver-digest-anchor-shape": (_signed_by_resolver(put("resolverEvidence", "deliveryDigestAnchor", "blockNumber", "20002450")), ("error", "DRV-3", "resolver delivery-digest anchor is malformed")),
    "resolver-decision-anchor-shape": (_signed_by_resolver(put("resolverEvidence", "decisionAnchor", "substrate", "ethereum")), ("error", "DRV-3", "resolver decision anchor is malformed")),
    "resolver-status-set": (_signed_by_resolver(drop("resolverEvidence", "statuses", "railResolution")), ("error", "DRV-3", "resolver status set is incomplete")),
    "resolver-status-value": (_signed_by_resolver(put("resolverEvidence", "statuses", "railResolution", "pending")), ("error", "DRV-3", "unknown resolver status")),
    "finding-not-object": (_hooked(evaluation=put("finding", "seller-fulfilled")), ("error", "DRV-3", "evaluation finding must be an object")),
    "canonical-record-set": (_release(drop("canonicalRecords", "delivery")), ("error", "DRV-3", "canonical record set does not match the lifecycle")),
    "canonical-record-not-object": (_release(put("canonicalRecords", "delivery", [])), ("error", "DRV-3", "delivery canonical record must be an object")),
    "reproduction-inputs-not-object": (_release(_without_reproduction_inputs), ("error", "DRV-3", "reproductionInputs must be an object")),
    "reproduction-input-set": (_release(drop("reproductionInputs", "runtimeBytecode")), ("error", "DRV-3", "reproduction input set is incomplete")),
    "observations-empty": (_signed_by_resolver(put("reproductionInputs", "nativeEventInputs", [])), ("error", "DRV-3", "native event inputs must be a non-empty array")),
    "observation-shape": (_signed_by_resolver(drop("reproductionInputs", "nativeEventInputs", 0, "topic0")), ("error", "DRV-3", "native event input is malformed")),
    "observation-field-type": (_signed_by_resolver(put("reproductionInputs", "nativeEventInputs", 0, "blockNumber", "19999500")), ("error", "DRV-3", "native event observation is malformed")),
    "observation-identity-type": (_signed_by_resolver(put("reproductionInputs", "nativeEventInputs", 2, "eventRef", "logIndex", True)), ("error", "DRV-3", "native event input identity is malformed")),
    "observation-data-type": (_signed_by_resolver(put("reproductionInputs", "nativeEventInputs", 0, "dataArguments", 1, 1800007200)), ("error", "DRV-3", "decoded event data does not match the pinned event signature")),
    "finality-block-hash": (_signed_by_resolver(put("reproductionInputs", "nativeEventInputs", 2, "finalityBlock", "blockHash", "0x" + "cd" * 32)), ("fail", "DRF-8", "finality block identity does not reproduce")),
    "configuration-finality-pending": (_signed_by_resolver(put("reproductionInputs", "nativeEventInputs", 1, "finalityBlock", None)), ("indeterminate", "DRJ-2", "the configuration event has not reached the rail finality depth")),
    "creation-after-funding": (_signed_by_resolver(_creation_after_funding), ("fail", "DRT-4", "native event observations are not one ordered transaction each")),
    "evaluation-reference-anchor-kind": (_hooked(evaluationRef=put("anchor", "kind", "https")), ("fail", "DRD-2", "evaluation reference is not an SR-2 storage-program anchor")),
    "event-reference-malformed": (_release(put("deliveryBinding", "nativeSubmissionEvent", "submit")), ("error", "DRV-3", "submission event reference is malformed")),
    "event-log-index-negative": (_hooked(job=put("creationEvent", "logIndex", -1)), ("error", "DRV-3", "creation event log index is not a non-negative integer")),
    "event-reference-not-canonical": (_release(put("deliveryBinding", "nativeSubmissionEvent", "chainId", 10)), ("fail", "DRP-9", "submission event reference is not an evm-event on the rail's chain")),
    "calldata-shape": (_signed_by_resolver(put("resolverEvidence", "transactions", 1, "calldata", "extra", "1")), ("error", "DRV-3", "decoded calldata does not match the pinned entrypoint signature")),
    "seed-set": (_release(drop("reproductionInputs", "publicTestSeedHex", generator.ORCHESTRATOR)), ("error", "DRV-3", "public test seed set is incomplete")),
    "seed-malformed": (_release(put("reproductionInputs", "publicTestSeedHex", generator.BUYER, "zz")), ("error", "DRV-3", "public test seed is malformed")),
    "role-inputs-not-objects": (_release(put("reproductionInputs", "roleBundles", [])), ("error", "DRV-3", "role source inputs must be objects")),
    "runtime-encoding": (_release(put("reproductionInputs", "runtimeBytecode", "encoding", "utf-8")), ("error", "DRV-3", "runtime-bytecode input is malformed")),
    "runtime-value-type": (_release(put("reproductionInputs", "runtimeBytecode", "value", 7)), ("error", "DRV-3", "runtime-bytecode input must be non-empty lower-case hex")),
    "zero-terminal-reason": (_signed_by_resolver(_zero_terminal_reason), ("fail", "DREB-5", "zero decision reason is forbidden")),
    "funding-finality-record-type": (_hooked(funding=put("finality", "finalityBlocks", "64")), ("error", "DRV-3", "funding finality record is malformed")),
    "portable-history-empty": (_release(put("native", "portableStateHistory", [])), ("error", "DRV-3", "portable state history must be a non-empty array")),
    "mapping-source-set": (_release(drop("mappingSources", "deliveryHash")), ("error", "DRV-3", "mapping source set does not match the lifecycle")),
    "reputation-projection-shape": (_release(put("reputationProjection", {})), ("error", "DRV-3", "reputation projection is malformed")),
    "decision-ordering-sum-unsafe": (_hooked(rail=_rail("maxCrossSubstrateSkewMs", verifier.SAFE_INTEGER_MAX - 1000)), ("error", "DRW-4", "the terminal side of a decision-ordering sum exceeds the safe-integer bound")),
    "decision-ordering-anchor-sum-unsafe": (_signed_by_resolver(put("resolverEvidence", "decisionAnchor", "finalizedBlockTimestampSec", verifier.MAX_SECONDS)), ("error", "DRW-4", "a decision-ordering sum exceeds the safe-integer bound")),
    "dispute-prior-revision": (_hooked("pre-submission-rejected-refund", dispute=put("supersedesOutcomeRef", generator.attestation_ref("fixture:earlier-outcome", "ab" * 32))), ("indeterminate", "DRAA-7", "prior dispute revisions are not resolved by this pack")),
}


class DeliveryRemedyCandidateVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector_pack = json.loads(VECTOR_PACK.read_text(encoding="utf-8"))
        cls.deployment_pack = json.loads(DEPLOYMENT_PACK.read_text(encoding="utf-8"))
        cls.vectors = {item["name"]: item for item in cls.vector_pack["vectors"]}
        cls.deployment_cases = {
            item["name"]: item for item in cls.deployment_pack["cases"]
        }

    def _vector(self, name):
        return materialize_vector(self.vector_pack, self.vectors[name])

    def _fixture(self, name):
        return copy.deepcopy(self.vector_pack["fixtures"][name])

    def _observation(self, value, event_name):
        return next(
            item
            for item in value["reproductionInputs"]["nativeEventInputs"]
            if item["eventName"] == event_name
        )

    def _assert_isolated(self, value, agreement=True):
        """The negative keeps every party and resolver signature valid."""
        self.assertIsNone(verifier._component_signature_check(value))
        if agreement:
            self.assertIsNone(verifier._agreement_check(value))
        else:
            overlay = value["artifacts"]["agreement"]
            for signature in overlay["signatures"]:
                self.assertTrue(verifier.signature_valid(
                    overlay, signature, signature["party"], value["publicKeys"],
                    verifier.DOMAINS["agreement"], "party",
                ))
        self.assertIsNone(verifier._resolver_evidence_check(value))

    def _anchored_earlier(self):
        """The release lifecycle with its decision anchored earlier: the same terminal, still a pass."""
        value = self._fixture("release")
        value["resolverEvidence"]["decisionAnchor"]["finalizedBlockTimestampSec"] -= 400
        generator.resign_resolver(value)
        return value

    def test_generated_files_are_current(self):
        result = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_standalone_verifier_accepts_both_packs(self):
        result = subprocess.run(
            [sys.executable, str(VERIFIER)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no rail registered", result.stdout)

    def test_pack_metadata_hashes_and_names_are_exact(self):
        for pack, fields in (
            (
                self.vector_pack,
                ("fixtures", "vectors", "promotionBlockedRules", "promotionBlockedProofs"),
            ),
            (self.deployment_pack, ("manifests", "cases")),
        ):
            with self.subTest(kind=pack["kind"]):
                items = pack[fields[1]]
                self.assertEqual(pack["count"], len(items))
                self.assertEqual(len(items), len({item["name"] for item in items}))
                payload = {field: pack[field] for field in fields}
                self.assertEqual(
                    pack["hash"], hashlib.sha256(canonical_bytes(payload)).hexdigest()
                )

    def test_every_candidate_rule_is_tagged_or_explicitly_promotion_blocked(self):
        spec_rules = set(
            re.findall(
                r"\b(?:DRP|DRA|DRL|DRJ|DRF|DRAA|DREB|DRE|DRD|DRT|DRV|DRQ|DRX|DRC|DRG|DRR|DRW)-\d+\b",
                SPEC.read_text(encoding="utf-8"),
            )
        )
        tagged = {
            rule
            for vector in self.vector_pack["vectors"]
            for rule in vector["rules"]
        }
        tagged.update(
            rule
            for case in self.deployment_pack["cases"]
            for rule in case["rules"]
        )
        blocked = set(self.vector_pack["promotionBlockedRules"])
        self.assertFalse(tagged & blocked)
        self.assertEqual(spec_rules, tagged | blocked)
        self.assertTrue(
            all(self.vector_pack["promotionBlockedRules"][rule] for rule in blocked)
        )
        # A proof-blocked rule is executed only against a synthetic evidence
        # shape: negatives may exercise it, no pass vector proves it.
        proofs = self.vector_pack["promotionBlockedProofs"]
        self.assertEqual(
            set(proofs),
            {
                "DRA-4", "DRA-8", "DRA-9", "DRE-2", "DRF-8", "DRP-6", "DRP-7", "DRP-8", "DRP-9",
                "DRP-10", "DRP-11", "DRP-12", "DRR-2", "DRR-3",
                # The fixture source revision, the token and implementation
                # code, the confirmation-block time, and the rule's anchoring.
                "DRC-14", "DRJ-11", "DRW-2", "DRW-6", "DRE-8", "DRAA-4",
            },
        )
        self.assertLessEqual(set(proofs), tagged)
        self.assertTrue(all(proofs.values()))

    def test_pass_vectors_never_claim_a_promotion_blocked_rule(self):
        """A pass vector's rules are the rules it proves; a blocked rule is never among them."""
        blocked = set(self.vector_pack["promotionBlockedRules"]) | set(self.vector_pack["promotionBlockedProofs"])
        for vector in self.vector_pack["vectors"]:
            if vector["expected"] == "pass":
                with self.subTest(vector=vector["name"]):
                    self.assertFalse(set(vector["rules"]) & blocked)
        # The verifier refuses a pack where one does.
        pack = copy.deepcopy(self.vector_pack)
        claimed = next(vector for vector in pack["vectors"] if vector["name"] == "release-complete-budget")
        claimed["rules"] = sorted(claimed["rules"] + ["DRA-4"])
        pack["hash"] = verifier._pack_hash(pack, ("fixtures", "vectors", "promotionBlockedRules", "promotionBlockedProofs"))
        self.assertIn(
            "a pass vector claims a promotion-blocked rule: DRA-4", verify_vector_pack(pack),
        )

    def test_readme_lists_the_synthetic_proof_limits(self):
        """The coverage statement names every proof-blocked rule and resolver assumption."""
        readme = README.read_text(encoding="utf-8")
        start = readme.index("The separate `promotionBlockedProofs` ledger")
        limits = " ".join(readme[start:readme.index("## Reproduce", start)].split())
        for rule in self.vector_pack["promotionBlockedProofs"]:
            with self.subTest(rule=rule):
                self.assertIn(rule, limits)
        for assumption in (
            "**`priorTerminals` completeness** (DRD-8, DRL-4, DRT-4)",
            "**Block-scoped log index** (DRD-8, DRL-4, DRT-4)",
            "**Fixture chain and resolver** (DRF-8)",
            "**Fixture implementation ABI** (DRC-17, DRC-18, DRC-20, DRC-21, DRJ-3,",
            "**Replay ledger durability**",
            "**`PriceTerm.unit`** (DRA-10)",
            "**Role and Vet records** (DRA-4, DRA-8, DRA-9)",
            "**Payee-bound agreement only** (DRP-14)",
            "**No EIP-1271 support** (DREB-18, DREB-22)",
        ):
            with self.subTest(assumption=assumption):
                self.assertIn(assumption, limits)

    def test_readme_counts_the_listed_isolation_exceptions(self):
        readme = " ".join(README.read_text(encoding="utf-8").split())
        self.assertIn(f"`FOLLOW_ON_FINDINGS` lists {len(generator.FOLLOW_ON_FINDINGS)} negatives", readme)
        self.assertIn(f"`STRUCTURAL_NEGATIVES` lists {len(generator.STRUCTURAL_NEGATIVES)} negatives", readme)
        self.assertIn(f"{self.vector_pack['count']} lifecycle and mapping vectors", readme)

    def test_readme_cites_drv3_for_malformed_input(self):
        """The candidate's malformed-encoding rule is DRV-3; DRV-2 is RPC availability."""
        readme = " ".join(README.read_text(encoding="utf-8").split())
        self.assertIn("reports malformed input (candidate §9 step 2) under DRV-3, the malformed-encoding rule", readme)
        self.assertIn("so those `error` cases keep the fixture label `DRV-2`", readme)
        self.assertIn("is `fail` under DRV-6: the pinned resolver's authenticated record", readme)
        self.assertIn("A value outside the closed value set", readme)
        self.assertNotIn("closed discriminators", readme)
        self.assertIn("The step-1 label is pending #371's named §9 step-1 rule.", readme)
        self.assertIn("so it is `fail` under DRP-3", readme)

    def test_error_results_cite_drv3_unless_the_candidate_names_no_rule(self):
        """Malformed input is DRV-3 or a §3.1 wire rule; DRV-2 is left only where the candidate names no rule."""
        literal_no_rule = {
            "pipeline contains an unsupported phase kind", "unsupported agreement overlay version",
            "unsupported resolver evidence version", "unsupported deployment manifest version",
            "unsupported deployment capability profile", "unsupported bilateral agreement version",
            "unsupported implementation ABI",
            "unsupported agreement phase: this pack models the payee-bound commit only",
        }
        no_rule = literal_no_rule | {
            f"unsupported {name} version" for name in verifier.ARTIFACT_VERSION_FIELDS
        }
        source = VERIFIER.read_text(encoding="utf-8")
        labelled = re.findall(r'result\("error", "DRV-2", "([^"]*)"\)', source)
        self.assertEqual(sorted(labelled), sorted(literal_no_rule))
        self.assertEqual(re.findall(r'result\("error", "DRV-2", f"([^"]*)"\)', source), ["unsupported {name} version"])
        self.assertGreaterEqual(source.count('result("error", "DRV-3", '), 50)
        self.assertNotIn("is not a supported discriminator", source)
        self.assertEqual(source.count('is outside the closed value set")'), 7)
        for vector in self.vector_pack["vectors"]:
            if vector["expected"] == "error":
                with self.subTest(vector=vector["name"]):
                    observed = evaluate(materialize_vector(self.vector_pack, vector))
                    self.assertEqual(observed["rule"], vector["expectedRule"])
                    if observed["rule"] == "DRV-2":
                        self.assertIn(observed["detail"], no_rule)

    def test_step_one_discriminators_keep_the_pending_drv2_label(self):
        """The candidate §9 step-1 cases without a named rule give `error`/DRV-2 end to end, pending #371.

        `manifestVersion: "2"` must reach the unsupported-version branch, not the
        DRV-3 branch for a manifest that is missing a required member.
        """
        def lifecycle(path, new):
            value = make_base("release")
            target = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = new
            return evaluate(value)

        def deployment(field, new):
            manifest = copy.deepcopy(self.deployment_pack["manifests"]["synthetic-control"])
            if new is None:
                del manifest[field]
            else:
                manifest[field] = new
            return evaluate_deployment(manifest)

        notify = make_base("release")
        notify["pipeline"].insert(4, {"kind": "notify"})
        observed = {
            "pipeline contains an unsupported phase kind": evaluate(notify),
            "unsupported agreement overlay version": lifecycle(
                ("artifacts", "agreement", "deliveryOrRemedyAgreementVersion"), "2"),
            "unsupported resolver evidence version": lifecycle(
                ("resolverEvidence", "resolverEvidenceVersion"), "2"),
            "unsupported deployment manifest version": deployment("manifestVersion", "2"),
            "unsupported deployment capability profile": deployment(
                "candidateProfile", "dacs-delivery-gate-v2"),
        }
        for detail, outcome in observed.items():
            with self.subTest(case=detail):
                self.assertEqual(
                    (outcome["result"], outcome["rule"], outcome["detail"]), ("error", "DRV-2", detail))
        missing = deployment("manifestVersion", None)
        self.assertEqual((missing["result"], missing["rule"], missing["detail"]),
                         ("error", "DRV-3", "malformed deployment manifest"))
        # Where the candidate names the step-1 rule, the result cites it.
        for name, rule in (
            ("rail-version-unsupported", "DRR-6"),
            ("rail-type-unprefixed", "DRR-6"),
            ("rail-capability-profile-unsupported", "DRC-14"),
            ("rule-kind-always-reject", "DRE-9"),
            ("pipeline-commit-phase-unsupported", "DRP-14"),
        ):
            with self.subTest(named=name):
                self.assertEqual(finding(self._vector(name)), ("error", rule))

    def test_keccak_and_eip55_reproduce_the_published_vectors(self):
        """Keccak-256 and EIP-55, against known answers; `hashlib.sha3_256` is a different hash."""
        self.assertEqual(verifier.keccak256(b"").hex(), verifier.EMPTY_CODE_HASH[2:])
        self.assertEqual(
            verifier.keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )
        self.assertNotEqual(verifier.keccak256(b"abc").hex(), hashlib.sha3_256(b"abc").hexdigest())
        self.assertEqual(verifier.selector_of("transfer(address,uint256)"), "0xa9059cbb")
        self.assertEqual(
            verifier.topic_of("Transfer(address,address,uint256)"),
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        )
        # The rate is 136 bytes: inputs either side of one block hash apart.
        self.assertEqual(len({verifier.keccak256(bytes(size)) for size in (134, 135, 136, 137)}), 4)
        # EIP-55's own examples, and the spellings this pack uses.
        for address in (
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            generator.EIP55_ACCOUNT, "0x" + "ab" * 20, "0x" + "AB" * 20,
        ):
            with self.subTest(valid=address):
                self.assertTrue(verifier.evm_claim_address_valid(address))
        for address in (
            generator.BAD_CHECKSUM_ACCOUNT, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD", "0X" + "ab" * 20,
            "0x" + "ab" * 19, "0x" + "ab" * 21, "alice", "0x1234", None,
        ):
            with self.subTest(invalid=address):
                self.assertFalse(verifier.evm_claim_address_valid(address))

    def test_claim_references_are_canonical_and_compared_per_scheme(self):
        """CF-2 canonical form, the DACS-1 per-scheme rules, CF-3 identity, and DRW-5."""
        buyer = generator.BUYER
        valid = (
            buyer, buyer + "?role=evaluator", "cci-xm:evm:8453:0x" + "ab" * 20, "key:" + "ab" * 32,
            "cci-xm:evm:8453:" + generator.EIP55_ACCOUNT, "domain:example.com",
            # Readable generic cci-xm claims outside the PB-2 profile.
            "cci-xm:evm:mainnet:alice", "cci-xm:solana:mainnet:abc",
        )
        for claim in valid:
            with self.subTest(valid=claim):
                self.assertIsNotNone(verifier.parse_claim(claim))
        for claim in (
            "DID:demos:agent:" + "11" * 32, "did:demos:agent:" + "AB" * 32, "did:demos:agent:" + "ab" * 31,
            "Bad Scheme:id", "did:demos:agent:" + "11" * 32 + "?b=2&a=1", "did:demos:agent:" + "11" * 32 + "?a=:",
            "cci-xm:evm:8453:alice", "cci-xm:evm:8453:0x1234", "cci-xm:evm:8453:" + generator.BAD_CHECKSUM_ACCOUNT,
            # DACS-1 PB-2: a signed or hexadecimal chain ID is a malformed
            # spelling of the decimal one, not a separate generic claim.
            "cci-xm:evm:+8453:0x" + "ab" * 20, "cci-xm:evm:-8453:0x" + "ab" * 20,
            "cci-xm:evm:0x2105:0x" + "ab" * 20, "cci-xm:evm:0X2105:0x" + "ab" * 20,
            "noscheme", ":x", "x:", 7, None,
        ):
            with self.subTest(invalid=claim):
                self.assertIsNone(verifier.parse_claim(claim))
        identity = verifier.claim_identity
        # Parameters are advisory, and two letter cases of one EVM account
        # are one party (DRW-5).
        self.assertEqual(identity(buyer), identity(buyer + "?role=evaluator"))
        self.assertEqual(identity("cci-xm:evm:8453:0x" + "ab" * 20), identity("cci-xm:evm:8453:0x" + "AB" * 20))
        self.assertEqual(identity("cci-xm:evm:8453:0x" + "ab" * 20), identity("cci-xm:evm:8453:" + generator.EIP55_ACCOUNT))
        self.assertNotEqual(identity("cci-xm:evm:8453:0x" + "ab" * 20), identity("cci-xm:evm:1:0x" + "ab" * 20))
        self.assertNotEqual(identity(buyer), identity(generator.SELLER))
        # DRA-17 matches the bilateral parties by CF-3 identity too: a party
        # claim that differs from the overlay's only by a parameter is the
        # same party.
        claim = buyer + "?source=listing"
        value = make_base("release", hooks={
            "bilateral": put("parties", 0, "primaryClaim", claim),
            "fixture": each_hook(
                put("publicKeys", claim, generator.public_key("buyer")),
                put("reproductionInputs", "publicTestSeedHex", claim, generator.SEEDS["buyer"].hex()),
            ),
        })
        self.assertEqual(value["artifacts"]["bilateralAgreement"]["parties"][0]["role"], "buyer")
        self.assertEqual(finding(value), ("pass", "DRV-7"))
        for name, outcome in (
            ("evaluator-primary-claim-parameter-alias", ("fail", "DRA-6")),
            ("evaluator-claim-upper-case-key", ("error", "DRV-3")),
            ("evaluator-claim-scheme-case-alias", ("error", "DRV-3")),
            ("evaluator-claim-evm-case-alias", ("fail", "DRA-6")),
            ("faulted-party-with-parameter", ("pass", "DRV-7")),
        ):
            with self.subTest(vector=name):
                self.assertEqual(finding(self._vector(name)), outcome)

    def test_evm_account_claims_follow_drw_1(self):
        """DRW-1: a claim's address is one case or valid EIP-55; anything else is `error`, whatever the chain shows."""
        for name, outcome in (
            ("account-claim-with-parameter", ("pass", "DRV-7")),
            ("account-claim-mixed-case-address", ("pass", "DRV-7")),
            ("account-claim-upper-case-address", ("pass", "DRV-7")),
            ("account-claim-bad-checksum", ("error", "DRW-1")),
            ("account-claim-non-hex-address", ("error", "DRW-1")),
            ("account-claim-short-address", ("error", "DRW-1")),
            ("account-claim-parameters-not-canonical", ("error", "DRV-3")),
            ("evaluator-account-zero-address", ("fail", "DRW-1")),
            ("funding-token-upper-case", ("error", "DRW-1")),
            ("event-reference-tx-hash-upper-case", ("error", "DRW-3")),
        ):
            with self.subTest(vector=name):
                self.assertEqual(finding(self._vector(name)), outcome)
        # The mixed-case positive spells a valid EIP-55 checksum.
        claim = self._vector("account-claim-mixed-case-address")["artifacts"]["agreement"]["evaluator"]["evmAccountClaim"]
        self.assertEqual(claim.rsplit(":", 1)[1], generator.EIP55_ACCOUNT)
        # A non-EVM address is refused even when every native account agrees
        # with it.
        for role, lifecycle in (("seller", "release"), ("buyer", "rejected-refund"), ("seller", "rejected-refund")):
            with self.subTest(role=role, lifecycle=lifecycle):
                value = make_base(lifecycle, hooks={"agreement": put(role, "evmAccountClaim", f"cci-xm:evm:{generator.CHAIN_ID}:alice")})
                self.assertEqual(finding(value)[0], "error")

    def test_abi_values_decode_only_their_elementary_type(self):
        """A decoded value has its pinned type's spelling; a type the verifier does not decode is never valid."""
        for abi_type, item in (
            ("uint256", "0"), ("uint8", "255"), ("address", "0x" + "ab" * 20), ("bool", False),
            ("string", "x"), ("bytes32", "0x" + "00" * 32), ("bytes1", "0xff"),
        ):
            with self.subTest(valid=(abi_type, item)):
                self.assertTrue(verifier.abi_value_valid(abi_type, item))
        for abi_type, item in (
            ("uint8", "256"), ("uint256", "01"), ("uint256", 1), ("address", "0x" + "AB" * 20),
            ("bool", "true"), ("bytes32", "0x" + "00" * 31), ("bytes1", "0xFF"),
            # Admitted by ABI_TYPE_RE but not decoded here: no ValueError.
            ("uint256[]", "1"), ("uint256[2]", "1"), ("bytes32[]", "0x" + "00" * 32), ("int256", "1"),
            ("bytes", "0x00"), ("uint", "1"), ("uint7", "1"), ("tuple", "1"), (None, "1"),
        ):
            with self.subTest(invalid=(abi_type, item)):
                self.assertFalse(verifier.abi_value_valid(abi_type, item))

    def test_rail_pins_derive_from_the_fixture_abi(self):
        """DRC-17: each pin's inputs reproduce its signature, which derives its selector or topic0."""
        rail = self._fixture("release")["artifacts"]["railDefinition"]
        params = rail["parameters"]
        for pin in params["entrypoints"]:
            with self.subTest(entrypoint=pin["name"]):
                self.assertEqual(pin["selector"], verifier.selector_of(pin["signature"]))
                types = ",".join(item["type"] for item in pin["inputs"])
                self.assertEqual(pin["signature"], f"{pin['name']}({types})")
        for pin in params["events"]:
            with self.subTest(event=pin["name"]):
                self.assertEqual(pin["topic0"], verifier.topic_of(pin["signature"]))
                types = ",".join(item["type"] for item in pin["inputs"])
                self.assertEqual(pin["signature"], f"{pin['name']}({types})")
                # The canonical ERC-8183 layout: the job ID is the first topic.
                self.assertEqual(pin["inputs"][0], {"name": "jobId", "type": "uint256", "indexed": True})
                self.assertLessEqual(sum(item["indexed"] for item in pin["inputs"]), 3)
        # Exactly the crosswalk events and the one configuration event.
        self.assertEqual(
            sorted(pin["name"] for pin in params["events"]),
            sorted([*verifier.CROSSWALK_EVENTS, verifier.CONFIGURATION_EVENT]),
        )
        self.assertEqual(params["configurationEvidence"], verifier.CONFIGURATION_EVIDENCE)
        configured = verifier._configuration_pin(params)
        self.assertEqual(configured["name"], verifier.CONFIGURATION_EVENT)
        self.assertEqual(configured["inputs"][params["configurationEvidence"]["submissionCutoffInput"]]["type"], "uint256")
        self.assertEqual(
            bytes.fromhex(params["configurationEvidence"]["preSubmissionPolicyValue"][2:]).rstrip(b"\0"),
            b"evaluator-rejection",
        )
        # DRC-20: PaymentReleased pays the canonical `provider` input.
        released = verifier._event_pin(params, "PaymentReleased")
        self.assertEqual([item["name"] for item in released["inputs"]], ["jobId", "provider", "amount"])
        # The DRC-14 literals, and the rail is signed by the pinned steward.
        for field, literal in verifier.PROFILE_LITERALS.items():
            with self.subTest(literal=field):
                self.assertEqual(params[field], literal)
        self.assertEqual(rail["signature"]["signer"], generator.STEWARD)
        self.assertEqual(rail["railId"], f"x-evm-erc8183:{generator.CHAIN_ID}:{rail['asset']['symbol']}")
        for name, outcome in (
            ("rail-entrypoint-selector-wrong", ("error", "DRC-17")),
            ("rail-event-topic-wrong", ("error", "DRC-17")),
            ("rail-abi-reference-create-job", ("error", "DRV-2")),
            ("native-entrypoint-not-pinned", ("fail", "DRC-18")),
            ("native-event-topic-not-pinned", ("fail", "DRC-18")),
            ("rail-signature-not-steward", ("fail", "DRR-2")),
            ("rail-decision-ordering-profile-superseded", ("error", "DRC-14")),
            ("rail-hook-nonzero", ("error", "DRC-14")),
        ):
            with self.subTest(vector=name):
                self.assertEqual(finding(self._vector(name)), outcome)

    def test_spec_tables_are_the_verifiers(self):
        """The §4.1 crosswalk, §6.2 matrix, §6.4 dispute table, and §7 projection are read from the candidate."""
        spec = SPEC.read_text(encoding="utf-8")

        def table(heading):
            """The body rows of the table whose header line starts with ``heading``."""
            rows = []
            for line in spec[spec.index(heading):].splitlines():
                if not line.startswith("|"):
                    break
                rows.append([cell.strip() for cell in line.strip("|").split("|")])
            return rows[2:]

        # §4.1: (prior status, entrypoint, caller) to (events, status after, portable, terminal).
        crosswalk = {}
        for prior, call, events, after, portable, terminal in table("| Prior native status | Entrypoint and caller |"):
            entrypoint, caller = re.fullmatch(r"`(\w+)` by (\w+)(?: caller)?(?:,.*)?", call).groups()
            statuses = [None] if prior == "none" else re.findall(r"`(\w+)`", prior)
            for status in statuses:
                crosswalk[(status, entrypoint, caller)] = (
                    tuple(re.findall(r"`(\w+)`", events)), after.strip("`"), portable.strip("`"),
                    None if terminal == "—" else terminal.split(",")[0].strip("`"),
                )
        implemented = {
            key: (tuple(name for name in row[0] if name != "JobConfigured"), *row[1:])
            for key, row in verifier.CROSSWALK.items()
        }
        self.assertEqual(len(crosswalk), 9)
        self.assertEqual(implemented, crosswalk)
        # §6.2: result to permitted findings and settlement disposition.
        matrix = table("| Criterion outcomes | `result` |")
        self.assertEqual(
            {row[1].strip("`"): set(re.findall(r"`([\w-]+)`", row[2])) for row in matrix},
            verifier.RESULT_FINDINGS,
        )
        self.assertEqual(
            {row[1].strip("`"): row[3].strip("`") for row in matrix if not row[3].startswith("none")},
            verifier.SETTLEMENT_AUTHORIZATIONS,
        )
        # §6.4: finding to the disposition it permits.
        disputes = {}
        for findings, permitted in table("| `finding.classification` | Permitted `recommendedDisposition`"):
            for classification in re.findall(r"`([\w-]+)`", findings):
                if permitted != "none":
                    disputes[classification] = re.findall(r"`([\w-]+)`", permitted)[0]
        self.assertEqual(disputes, verifier.DISPUTE_DISPOSITIONS)
        # §7: (terminal, finding) to (buyer-anchored, seller-anchored, faulted party).
        def outcome(cell):
            return None if cell.startswith("no ") else cell.strip("`")
        projection = {}
        for terminal, found, buyer, seller, faulted in table("| Terminal evidence | Finding |"):
            terminals = (
                ["released", "rejected-refund", "expired-refund"] if terminal == "any terminal state"
                else ["rejected-refund", "expired-refund"] if terminal == "any refund"
                else [terminal.strip("`")]
            )
            classification = re.match(r"`([\w-]+)`", found).group(1)
            party = faulted.split(";")[0].strip().strip("`")
            for state in terminals:
                projection[(state, classification)] = (outcome(buyer), outcome(seller), party)
        indeterminate = {key for key in projection if key[1] == "indeterminate"}
        self.assertEqual({projection[key] for key in indeterminate}, {verifier.NO_PROJECTION})
        self.assertEqual(
            {key: value for key, value in projection.items() if key not in indeterminate},
            verifier.PROJECTION_TABLE,
        )

    def test_deliverable_anchor_is_the_pde3_address(self):
        """PDE-3, PDE-4: the deliverable is anchored at dacs4:deliverable:{jobId}:{phaseIndex}, and nowhere else."""
        release = self._fixture("release")
        delivery = release["artifacts"]["delivery"]
        job = release["artifacts"]["agreement"]["jobId"]
        self.assertEqual(delivery["deliverableAnchor"], {"kind": "storage-program", "locator": f"dacs4:deliverable:{job}:2"})
        self.assertEqual(release["artifacts"]["deliveryRef"]["anchor"]["locator"], f"dacs4:delivery:{job}:2")
        native = "stor-" + hashlib.sha256(b"x").hexdigest()[:40]
        for locator in (
            native, "stor-" + "ab" * 32, f"dacs4:deliverable:{job}", f"dacs4:deliverable:{job}:02",
            f"dacs4:deliverable:{generator.JOB_B}:2", f"dacs4:deliverable:{job}:3",
        ):
            with self.subTest(locator=locator):
                value = make_base("release", hooks={"delivery": put("deliverableAnchor", "locator", locator)})
                self.assertEqual(finding(value), ("fail", "DRE-2"))

    def test_no_finding_reports_a_promotion_blocked_rule(self):
        blocked = set(self.vector_pack["promotionBlockedRules"])
        for vector in self.vector_pack["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertNotIn(vector["expectedRule"], blocked)
        for name, (build, (_result, rule, _detail)) in GUARD_CASES.items():
            with self.subTest(case=name):
                self.assertNotIn(rule, blocked)
        # DRAA-4's write-once rule is not what an overlay-hash binding checks.
        for name, rule in (("drv-4-job-overlay-hash", "DRV-4"), ("drf-1-funding-overlay-hash", "DRF-1")):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), ("fail", rule))

    def test_every_lifecycle_vector_executes_to_its_pinned_result_and_rule(self):
        self.assertEqual(verify_vector_pack(self.vector_pack), [])
        for vector in self.vector_pack["vectors"]:
            with self.subTest(vector=vector["name"]):
                members = [*vector.get("evaluatedWith", []), vector["name"]]
                observed = evaluate_lifecycles(
                    [self._vector(name) for name in members], DecisionLedger()
                )[-1]
                self.assertEqual(observed["result"], vector["expected"])
                self.assertEqual(observed["rule"], vector["expectedRule"])

    def test_single_sr2_write_reproduces_references_without_an_absence_proof(self):
        first = self._vector("sr2-single-write-two-producers")
        second = self._vector("sr2-single-write-resolved-again")
        repeated = self._vector("sr2-repeated-receipt-same-write")
        for value in (first, second, repeated):
            self.assertEqual(finding(value), ("pass", "DRV-7"))
            self.assertEqual(value["artifacts"]["terminal"], first["artifacts"]["terminal"])
        for wall_clock in (0, 2000000000):
            with unittest.mock.patch("time.time", return_value=wall_clock):
                produced = make_base("release")
            self.assertEqual(produced["artifacts"]["terminal"], first["artifacts"]["terminal"])
            for name in ("funding", "decision"):
                self.assertEqual(
                    generator.qualified_artifact_write(produced, name),
                    first["resolverEvidence"]["qualifiedArtifactWrites"][name][0],
                )
        # A resolver summary is not trusted if it is edited without a signature.
        second["resolverEvidence"]["qualifiedArtifactWrites"]["decision"][0]["nonce"] = "changed"
        self.assertEqual(finding(second), ("fail", "DRV-1"))

    def test_identical_sr2_writes_match_core_and_never_reach_decision_ordering(self):
        with unittest.mock.patch.object(sys, "path", [str(ROOT / "scripts"), *sys.path]):
            from scripts import sr2_resolution_reference as core

        for name in ("funding", "decision"):
            value = self._vector(f"sr2-identical-{name}-writes")
            summaries = value["resolverEvidence"]["qualifiedArtifactWrites"][name]
            storage = {}
            carriers = []
            for summary in summaries:
                storage[summary["nativeAddress"]] = verifier.unsigned_artifact(value["artifacts"][name])
                receipt = {key: copy.deepcopy(item) for key, item in summary.items() if key != "finalizedBlockTimestampSec"}
                receipt.update({
                    "receiptVersion": "1", "substrate": "demos", "finalityProfile": "fixture-finalized",
                    "state": "finalized", "observationDisposition": "established",
                    "observedAt": summary["finalizedBlockTimestampSec"] * 1000,
                    "blockRef": {
                        "id": f"fixture-block-{summary['finalizedBlockTimestampSec']}",
                        "timestamp": summary["finalizedBlockTimestampSec"],
                    },
                    "evidence": {"kind": "fixture-resolver", "value": summary["transactionRef"]["value"]},
                })
                carriers.append({"kind": "anchor-receipt", "receipt": receipt, "authorityVerified": True, "receiptEvidenceVerified": True})
            case = {
                "expectedLogicalAddress": summaries[0]["logicalAddress"],
                "expectedContentHash": summaries[0]["contentHash"],
                "minimumState": "finalized", "storage": storage, "carriers": carriers,
            }
            with self.subTest(artifact=name):
                self.assertEqual(core.evaluate_resolution({**case, "carriers": carriers[:1]}), "pass")
                self.assertEqual(core.evaluate_resolution(case), "indeterminate")
                self.assertEqual(len(set(map(canonical_bytes, storage.values()))), 1)
                terminal_sec = self._observation(value, "JobCompleted")["blockTimestampSec"]
                self.assertLess(summaries[0]["finalizedBlockTimestampSec"], terminal_sec)
                self.assertGreater(summaries[1]["finalizedBlockTimestampSec"], terminal_sec)
            # Neither receipt order nor a resolver-selected early/late anchor
            # can authorize choosing a copy and evaluating DRC-15 from it.
            # Two funding writes leave the sole decision write selectable:
            # DRC-15 is evaluated from it (CORE §5.1 is per logical address).
            sole = value["resolverEvidence"]["qualifiedArtifactWrites"]["decision"]
            for ordered in (summaries, list(reversed(summaries))):
                for selected in summaries if name == "decision" else sole:
                    candidate = copy.deepcopy(value)
                    candidate["resolverEvidence"]["qualifiedArtifactWrites"][name] = ordered
                    candidate["resolverEvidence"]["decisionAnchor"]["finalizedBlockTimestampSec"] = selected["finalizedBlockTimestampSec"]
                    generator.resign_resolver(candidate)
                    before = copy.deepcopy(candidate)
                    ledger = DecisionLedger()
                    with unittest.mock.patch.object(
                        verifier, "_decision_ordering_check",
                        side_effect=AssertionError("equivocation must stop before DRC-15") if name == "decision" else verifier._decision_ordering_check,
                    ) as ordering:
                        self.assertEqual(verdict(evaluate_protocol(candidate, ledger)), ("indeterminate", "DRAA-4"))
                    self.assertEqual(ordering.called, name == "funding")
                    self.assertEqual(candidate, before)
                    # Its terminal takes part in the replay comparison, as
                    # when the two writes arrive in separate lifecycles; its
                    # verdict is held by lifecycle, not issued for the terminal.
                    self.assertEqual(list(ledger.terminals()), [verifier._terminal_record(value)])
                    self.assertIsNone(ledger.issued(verifier._terminal_record(value)))
            if name == "funding":
                # An anchor that is not the sole decision write fails there,
                # beside the funding equivocation, and records no terminal.
                for selected in summaries:
                    candidate = copy.deepcopy(value)
                    candidate["resolverEvidence"]["decisionAnchor"]["finalizedBlockTimestampSec"] = selected["finalizedBlockTimestampSec"] + 1
                    generator.resign_resolver(candidate)
                    ledger = DecisionLedger()
                    self.assertEqual(verdict(evaluate_protocol(candidate, ledger)), ("fail", "DRV-6"))
                    self.assertEqual(ledger.terminals(), ())

    def _single_write_copy(self, name, copy_index):
        """P13 with the resolver qualifying only copy ``copy_index`` of the ``name`` write."""
        value = self._vector("sr2-single-write-two-producers")
        value["resolverEvidence"]["qualifiedArtifactWrites"][name] = [
            generator.qualified_artifact_write(value, name, copy_index)
        ]
        generator.resign_resolver(value)
        return value

    def test_sr2_writes_from_different_lifecycles_are_one_equivocation(self):
        """DRAA-4 / CORE §5.1: two qualifying writes are known however they arrive, and never forgotten."""
        conflict = ("indeterminate", "DRAA-4")
        shipped = self._vector("sr2-single-write-two-producers")
        for name in ("funding", "decision"):
            first, second = self._single_write_copy(name, 0), self._single_write_copy(name, 1)
            both = self._vector(f"sr2-identical-{name}-writes")
            with self.subTest(artifact=name):
                self.assertEqual(first, shipped)
                self.assertEqual(finding(second), ("pass", "DRV-7"))
                # One batch, in either order.
                for batch in ([first, second], [second, first]):
                    observed = evaluate_lifecycles([copy.deepcopy(item) for item in batch], DecisionLedger())
                    self.assertEqual([verdict(item) for item in observed], [conflict, conflict])
                # Successive calls: the second write withholds both and
                # revises the pass already issued.
                ledger = DecisionLedger()
                issued = evaluate_protocol(copy.deepcopy(first), ledger)
                self.assertEqual(verdict(issued), ("pass", "DRV-7"))
                later = evaluate_protocol(copy.deepcopy(second), ledger)
                self.assertEqual(verdict(later), conflict)
                self.assertEqual(self._revised(first, issued, later), conflict)
                # Every later lifecycle at that address stays withheld, with
                # its own summary or without one, and nothing is revised again.
                for retry in (
                    first, second, both, self._vector("sr2-single-write-resolved-again"),
                    self._vector("sr2-repeated-receipt-same-write"), self._fixture("release"),
                ):
                    observed = evaluate_protocol(copy.deepcopy(retry), ledger)
                    self.assertEqual(verdict(observed), conflict)
                    self.assertNotIn("revises", observed)
                self.assertEqual([verdict(ledger.issued(item)) for item in ledger.terminals()], [conflict])
                # The conflict first: retained, and its terminal recorded.
                ledger = DecisionLedger()
                self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(both), ledger)), conflict)
                self.assertEqual(list(ledger.terminals()), [verifier._terminal_record(both)])
                for retry in (first, second):
                    self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(retry), ledger)), conflict)
                # An explicit later conflict revises the earlier pass.
                ledger = DecisionLedger()
                issued = evaluate_protocol(copy.deepcopy(first), ledger)
                later = evaluate_protocol(copy.deepcopy(both), ledger)
                self.assertEqual(verdict(later), conflict)
                self.assertEqual(self._revised(first, issued, later), conflict)
                # A summary the pinned resolver did not sign, or one bound to
                # another logical address, is not retained.
                forged = copy.deepcopy(second)
                forged["resolverEvidence"]["qualifiedArtifactWrites"][name][0]["nonce"] = "99"
                elsewhere = copy.deepcopy(second)
                elsewhere["resolverEvidence"]["qualifiedArtifactWrites"][name][0]["logicalAddress"] += "-other"
                generator.resign_resolver(elsewhere)
                for rejected, outcome in ((forged, ("fail", "DRV-1")), (elsewhere, ("fail", "DRV-6"))):
                    ledger = DecisionLedger()
                    self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(rejected), ledger)), outcome)
                    self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(first), ledger)), ("pass", "DRV-7"))
        # The exact same write from several lifecycles is one write.
        repeats = [
            self._vector(item) for item in (
                "sr2-single-write-two-producers", "sr2-single-write-resolved-again",
                "sr2-repeated-receipt-same-write",
            )
        ]
        for order in (repeats, repeats[::-1]):
            observed = evaluate_lifecycles([copy.deepcopy(item) for item in order], DecisionLedger())
            self.assertEqual([verdict(item) for item in observed], [("pass", "DRV-7")] * 3)
            ledger = DecisionLedger()
            for item in order:
                observed = evaluate_protocol(copy.deepcopy(item), ledger)
                self.assertEqual(verdict(observed), ("pass", "DRV-7"))
                self.assertNotIn("revises", observed)

    def _late_decision_copy(self, anchored=True):
        """P13 with the resolver qualifying only I8's late decision copy; ``anchored`` orders the decision on it."""
        late = self._vector("sr2-identical-decision-writes")["resolverEvidence"]["qualifiedArtifactWrites"]["decision"][1]
        value = self._vector("sr2-single-write-two-producers")
        value["resolverEvidence"]["qualifiedArtifactWrites"]["decision"] = [late]
        if anchored:
            value["resolverEvidence"]["decisionAnchor"]["finalizedBlockTimestampSec"] = late["finalizedBlockTimestampSec"]
        generator.resign_resolver(value)
        return value

    def test_a_sole_copy_is_not_selected_once_another_input_carries_the_other_write(self):
        """DRAA-4 / I8: with both writes known, neither DRC-15 nor the anchor check reads either copy."""
        conflict = ("indeterminate", "DRAA-4")
        early = self._vector("sr2-single-write-two-producers")
        unordered = AssertionError("DRC-15 read a copy that cannot be selected")
        for late, own in (
            (self._late_decision_copy(), ("fail", "DRD-11")),
            (self._late_decision_copy(anchored=False), ("fail", "DRV-6")),
        ):
            with self.subTest(own=own):
                self.assertEqual(finding(late), own)
                # One batch, in either order: neither lifecycle orders the decision.
                for batch in ([early, late], [late, early]):
                    with unittest.mock.patch.object(verifier, "_decision_ordering_check", side_effect=unordered):
                        observed = evaluate_lifecycles([copy.deepcopy(item) for item in batch], DecisionLedger())
                    self.assertEqual([verdict(item) for item in observed], [conflict, conflict])
                # The early copy first: the late one is never selected, and
                # the pass already issued is revised.
                ledger = DecisionLedger()
                issued = evaluate_protocol(copy.deepcopy(early), ledger)
                self.assertEqual(verdict(issued), ("pass", "DRV-7"))
                with unittest.mock.patch.object(verifier, "_decision_ordering_check", side_effect=unordered):
                    later = evaluate_protocol(copy.deepcopy(late), ledger)
                self.assertEqual(verdict(later), conflict)
                self.assertEqual(self._revised(early, issued, later), conflict)
                # The late copy first: its finding rested on the sole copy
                # then known, and is revised when the other write arrives.
                ledger = DecisionLedger()
                issued = evaluate_protocol(copy.deepcopy(late), ledger)
                self.assertEqual(verdict(issued), own)
                with unittest.mock.patch.object(verifier, "_decision_ordering_check", side_effect=unordered):
                    later = evaluate_protocol(copy.deepcopy(early), ledger)
                    again = evaluate_protocol(copy.deepcopy(late), ledger)
                self.assertEqual(verdict(later), conflict)
                self.assertEqual(
                    later["revises"],
                    [{"lifecycle": content_hash(late), "previous": issued, **verifier._equivocation()}],
                )
                self.assertEqual(self._revised(late, issued, later), conflict)
                self.assertEqual(verdict(again), conflict)
                self.assertNotIn("revises", again)
        # A finding before the write-selection stage is not revised: the
        # write is still retained, and the verdict rests on no copy.
        detached = self._late_decision_copy()
        detached["resolverEvidence"]["qualifiedArtifactWrites"]["funding"][0]["logicalAddress"] += "-other"
        generator.resign_resolver(detached)
        ledger = DecisionLedger()
        issued = evaluate_protocol(copy.deepcopy(detached), ledger)
        self.assertEqual(verdict(issued), ("fail", "DRV-6"))
        later = evaluate_protocol(copy.deepcopy(early), ledger)
        self.assertEqual(verdict(later), conflict)
        self.assertNotIn("revises", later)

    def test_a_qualifying_write_is_retained_whatever_its_carrier_decides(self):
        """DRAA-4: each pinned-resolver summary bound to its address counts, beside a bad sibling or a failed check."""
        conflict = ("indeterminate", "DRAA-4")
        first = self._vector("sr2-single-write-two-producers")
        # A second funding write beside a decision summary for another address.
        misaddressed = self._single_write_copy("funding", 1)
        misaddressed["resolverEvidence"]["qualifiedArtifactWrites"]["decision"][0]["logicalAddress"] += "-other"
        generator.resign_resolver(misaddressed)
        # Beside a malformed decision summary.
        malformed = self._single_write_copy("funding", 1)
        malformed["resolverEvidence"]["qualifiedArtifactWrites"]["decision"][0]["nonce"] = 7
        generator.resign_resolver(malformed)
        # In a lifecycle that fails a stage before the write checks.
        unsigned = self._single_write_copy("funding", 1)
        unsigned["artifacts"]["evaluation"]["signature"]["value"] = unsigned["artifacts"]["decision"]["signature"]["value"]
        for carrier, own in (
            (misaddressed, ("fail", "DRV-6")), (malformed, ("error", "DRV-3")), (unsigned, ("fail", "DRE-1")),
        ):
            with self.subTest(own=own):
                self.assertEqual(finding(carrier), own)
                observed = evaluate_lifecycles([copy.deepcopy(first), copy.deepcopy(carrier)], DecisionLedger())
                self.assertEqual([verdict(item) for item in observed], [conflict, own])
                observed = evaluate_lifecycles([copy.deepcopy(carrier), copy.deepcopy(first)], DecisionLedger())
                self.assertEqual([verdict(item) for item in observed], [own, conflict])
                ledger = DecisionLedger()
                issued = evaluate_protocol(copy.deepcopy(first), ledger)
                later = evaluate_protocol(copy.deepcopy(carrier), ledger)
                self.assertEqual(verdict(later), own)
                self.assertEqual(self._revised(first, issued, later), conflict)
                ledger = DecisionLedger()
                evaluate_protocol(copy.deepcopy(carrier), ledger)
                self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(first), ledger)), conflict)
        # The misaddressed and malformed summaries themselves are not retained.
        decision = first["resolverEvidence"]["qualifiedArtifactWrites"]["decision"][0]["logicalAddress"]
        for carrier in (misaddressed, malformed):
            ledger = DecisionLedger()
            evaluate_protocol(copy.deepcopy(carrier), ledger)
            self.assertEqual(ledger.writes_at(decision), frozenset())
            self.assertEqual(ledger.writes_at(decision + "-other"), frozenset())
        # A summary the pinned resolver did not sign is never retained, even
        # in a lifecycle that fails before the resolver stage.
        forged = copy.deepcopy(unsigned)
        forged["resolverEvidence"]["qualifiedArtifactWrites"]["funding"][0]["nonce"] = "99"
        ledger = DecisionLedger()
        self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(forged), ledger)), ("fail", "DRE-1"))
        self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(first), ledger)), ("pass", "DRV-7"))

    def test_decision_writes_for_a_decisionless_terminal_are_misaddressed(self):
        """An expiry terminal references no decision, so a decision write summary binds nothing (DRV-6)."""
        write = self._vector("sr2-single-write-two-producers")["resolverEvidence"]["qualifiedArtifactWrites"]["decision"][0]
        expiry = self._fixture("expired-pre")
        expiry["resolverEvidence"]["qualifiedArtifactWrites"] = {"decision": [copy.deepcopy(write)]}
        generator.resign_resolver(expiry)
        ledger = DecisionLedger()
        self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(expiry), ledger)), ("fail", "DRV-6"))
        self.assertEqual(ledger.writes_at(write["logicalAddress"]), frozenset())

    def test_a_summary_without_a_terminal_reference_does_not_stop_retention(self):
        """DRAA-4: a decision summary listed first, for a terminal with no decision, leaves its sibling retained."""
        decision = self._vector("sr2-single-write-two-producers")["resolverEvidence"]["qualifiedArtifactWrites"]["decision"][0]

        def expiry(writes):
            value = self._fixture("expired-pre")
            value["resolverEvidence"]["qualifiedArtifactWrites"] = writes(value)
            generator.resign_resolver(value)
            return value

        first = expiry(lambda value: {"funding": [generator.qualified_artifact_write(value, "funding", 0, 1700000000)]})
        self.assertEqual(finding(first), ("pass", "DRV-7"))
        carrier = expiry(lambda value: {
            "decision": [copy.deepcopy(decision)],
            "funding": [generator.qualified_artifact_write(value, "funding", 1, 1700000000)],
        })
        self.assertEqual(list(carrier["resolverEvidence"]["qualifiedArtifactWrites"]), ["decision", "funding"])
        self.assertNotIn("decisionRef", carrier["artifacts"]["terminal"])
        address = carrier["artifacts"]["terminal"]["fundingEvidenceRef"]["anchor"]["locator"]
        ledger = DecisionLedger()
        self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(carrier), ledger)), ("fail", "DRV-6"))
        self.assertEqual(len(ledger.writes_at(address)), 1)
        self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(first), ledger)), EQUIVOCATION)
        observed = evaluate_lifecycles([copy.deepcopy(carrier), copy.deepcopy(first)], DecisionLedger())
        self.assertEqual([verdict(item) for item in observed], [("fail", "DRV-6"), EQUIVOCATION])

    def test_a_second_write_never_hides_a_deterministic_error_or_fail(self):
        """Candidate §9, FV-10: DRAA-4 replaces no check's or replay comparison's `error` or `fail`."""
        release = self._vector("release-complete-budget")
        for name, companions, vector, own in (
            ("funding", [], "wrong-release-recipient", ("fail", "DRT-5")),
            ("funding", [], "nonzero-platform-fee", ("fail", "DRT-7")),
            ("funding", [], "finding-classification-unknown", ("error", "DRV-3")),
            ("decision", [], "release-with-seller-fault-finding", ("fail", "DRE-10")),
            ("decision", ["release-complete-budget"], "decision-reused-by-another-terminal-transaction", ("fail", "DRD-8")),
            ("funding", ["release-complete-budget"], "second-terminal-for-terminal-job", ("fail", "DRL-4")),
        ):
            values = {
                **{item: self._vector(item) for item in (*companions, vector)},
                "copy-0": self._single_write_copy(name, 0), "copy-1": self._single_write_copy(name, 1),
            }
            members = [*companions, vector]
            with self.subTest(vector=vector):
                self.assertIn(
                    values["copy-0"]["resolverEvidence"]["qualifiedArtifactWrites"][name][0]["logicalAddress"],
                    verifier._write_addresses(values[vector]["artifacts"]["terminal"]),
                )
                alone = evaluate_lifecycles([copy.deepcopy(values[item]) for item in members], DecisionLedger())
                self.assertEqual(verdict(alone[-1]), own)
                joint = None
                for order in ([*members, "copy-0", "copy-1"], ["copy-1", "copy-0", *members[::-1]]):
                    observed = evaluate_lifecycles([copy.deepcopy(values[item]) for item in order], DecisionLedger())
                    verdicts = {item: verdict(outcome) for item, outcome in zip(order, observed)}
                    joint = joint or verdicts
                    self.assertEqual(verdicts, joint)
                self.assertEqual(joint[vector], own)
                # DRAA-4 still replaces a `pass` and an unordered replay conflict.
                self.assertEqual({joint[item] for item in joint if item != vector}, {EQUIVOCATION})
                # One at a time, in any order, the verdicts as revised are the
                # joint ones, and nothing revises the `error` or `fail`.
                for order in (
                    [*members, "copy-0", "copy-1"], ["copy-0", "copy-1", *members],
                    ["copy-0", *members[::-1], "copy-1"],
                ):
                    self.assertEqual(self._streamed(values, order), joint)
                ledger = DecisionLedger()
                outcomes = [evaluate_protocol(copy.deepcopy(values[item]), ledger) for item in (*members, "copy-0", "copy-1")]
                self.assertEqual(verdict(outcomes[len(members) - 1]), own)
                for outcome in outcomes[len(members):]:
                    self.assertNotIn(own, [verdict(revision["previous"]) for revision in outcome.get("revises", [])])
                self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(values[vector]), ledger)), own)
        # One lifecycle carrying both writes and a deterministic `fail`.
        both = self._vector("sr2-identical-funding-writes")["resolverEvidence"]["qualifiedArtifactWrites"]
        for vector, own in (("wrong-release-recipient", ("fail", "DRT-5")), ("nonzero-platform-fee", ("fail", "DRT-7"))):
            value = self._vector(vector)
            value["resolverEvidence"]["qualifiedArtifactWrites"] = copy.deepcopy(both)
            generator.resign_resolver(value)
            with self.subTest(vector=vector, writes="both"):
                self.assertEqual(finding(value), own)

    def test_a_decision_ordered_after_its_terminal_records_no_terminal(self):
        """DRD-11 on the resolver's own anchor keeps its terminal out of replay state; two decision writes make it DRAA-4."""
        release = self._fixture("release")
        terminal = generator.block_time(generator.TERMINAL_BLOCKS["release"])
        widened = (release["artifacts"]["railDefinition"]["parameters"]["maxCrossSubstrateSkewMs"] + 1000) // 1000
        late = copy.deepcopy(release)
        late["resolverEvidence"]["decisionAnchor"]["finalizedBlockTimestampSec"] = terminal + widened + 1
        generator.resign_resolver(late)
        self.assertNotIn("qualifiedArtifactWrites", late["resolverEvidence"])
        second = self._fixture("release-second-terminal-transaction")
        self.assertEqual(finding(late), ("fail", "DRD-11"))
        self.assertEqual(finding(second), ("pass", "DRV-7"))
        recorded = (verifier._terminal_record(copy.deepcopy(second)),)
        for order in ((late, second), (second, late)):
            expected = [("fail", "DRD-11") if item is late else ("pass", "DRV-7") for item in order]
            with self.subTest(late_first=order[0] is late):
                ledger = DecisionLedger()
                observed = evaluate_lifecycles([copy.deepcopy(item) for item in order], ledger)
                self.assertEqual([verdict(item) for item in observed], expected)
                self.assertEqual(ledger.terminals(), recorded)
                ledger = DecisionLedger()
                observed = [evaluate_protocol(copy.deepcopy(item), ledger) for item in order]
                self.assertEqual([verdict(item) for item in observed], expected)
                self.assertNotIn("revises", observed[1])
                self.assertEqual(ledger.terminals(), recorded)
        # The resolver's anchor rests on the one write at the decision
        # address: with two writes known there neither is selected and
        # DRC-15 is not evaluated (DRAA-4, I8), in any order.
        writes = [self._single_write_copy("decision", index) for index in (0, 1)]
        address = writes[0]["resolverEvidence"]["qualifiedArtifactWrites"]["decision"][0]["logicalAddress"]
        self.assertIn(address, verifier._write_addresses(late["artifacts"]["terminal"]))
        values = {"late": late, "copy-0": writes[0], "copy-1": writes[1]}
        joint = dict.fromkeys(values, EQUIVOCATION)
        for order in itertools.permutations(values):
            with self.subTest(order=order):
                with unittest.mock.patch.object(verifier, "_decision_ordering_check", side_effect=AssertionError("DRC-15 read an unselectable anchor")):
                    observed = evaluate_lifecycles([copy.deepcopy(values[item]) for item in order], DecisionLedger())
                self.assertEqual(dict(zip(order, map(verdict, observed))), joint)
                self.assertEqual(self._streamed(values, order), joint)
        # One decision write elsewhere is not a second write: DRD-11 stands.
        for order in ((late, writes[1]), (writes[1], late)):
            observed = evaluate_lifecycles([copy.deepcopy(item) for item in order], DecisionLedger())
            self.assertEqual(verdict(observed[order.index(late)]), ("fail", "DRD-11"))

    def _decision_copy_in_skew_window(self):
        """P13 with the resolver qualifying only a decision copy finalized at the terminal's block time (DRC-15)."""
        terminal = generator.block_time(generator.TERMINAL_BLOCKS["release"])
        value = self._vector("sr2-single-write-two-producers")
        value["resolverEvidence"]["qualifiedArtifactWrites"]["decision"] = [
            generator.qualified_artifact_write(value, "decision", 1, terminal)
        ]
        value["resolverEvidence"]["decisionAnchor"]["finalizedBlockTimestampSec"] = terminal
        generator.resign_resolver(value)
        return value

    def test_a_finding_on_a_selectable_copy_records_its_terminal_only_once_unselectable(self):
        """A finding that rests on the sole copy known keeps its terminal out of replay until a second write (DRAA-4)."""
        second = self._fixture("release-second-terminal-transaction")
        early = self._vector("sr2-single-write-two-producers")
        # A carrier of the early write that fails before the write checks:
        # the write is retained, and its own terminal is not recorded.
        carrier = copy.deepcopy(early)
        carrier["artifacts"]["evaluation"]["signature"]["value"] = carrier["artifacts"]["decision"]["signature"]["value"]
        self.assertEqual(finding(carrier), ("fail", "DRE-1"))
        self.assertEqual(finding(second), ("pass", "DRV-7"))
        for late, own in (
            (self._late_decision_copy(), ("fail", "DRD-11")),
            (self._late_decision_copy(anchored=False), ("fail", "DRV-6")),
            (self._decision_copy_in_skew_window(), ("indeterminate", "DRC-15")),
        ):
            values = {"late": late, "second": second, "early": early, "carrier": carrier}
            with self.subTest(own=own):
                self.assertEqual(finding(late), own)
                # Beside a terminal whose ordering is uncertain, the second
                # use of its decision is neither a replay nor a first use.
                alone = {
                    "late": own,
                    "second": ("indeterminate", "DRD-8") if own[0] == "indeterminate" else ("pass", "DRV-7"),
                }
                for order in (("late", "second"), ("second", "late")):
                    ledger = DecisionLedger()
                    observed = evaluate_lifecycles([copy.deepcopy(values[item]) for item in order], ledger)
                    self.assertEqual(dict(zip(order, map(verdict, observed))), alone)
                    self.assertEqual(ledger.terminals(), (verifier._terminal_record(copy.deepcopy(second)),))
                    ledger = DecisionLedger()
                    for item in order:
                        evaluate_protocol(copy.deepcopy(values[item]), ledger)
                    self.assertEqual(ledger.terminals(), (verifier._terminal_record(copy.deepcopy(second)),))
                    self.assertEqual(self._streamed(values, order), alone)
                # The other write, in any position, makes the copy
                # unselectable; the late terminal then takes part in the
                # replay comparison, and the second terminal fails.
                for other, outcome in (("early", EQUIVOCATION), ("carrier", ("fail", "DRE-1"))):
                    joint = {"late": EQUIVOCATION, "second": ("fail", "DRD-8"), other: outcome}
                    for order in itertools.permutations(joint):
                        with self.subTest(order=order):
                            ledger = DecisionLedger()
                            observed = evaluate_lifecycles([copy.deepcopy(values[item]) for item in order], ledger)
                            self.assertEqual(dict(zip(order, map(verdict, observed))), joint)
                            self.assertEqual(self._streamed(values, order), joint)
                            self.assertIn(verifier._terminal_record(copy.deepcopy(late)), ledger.terminals())

    def _failing_carrier(self, name, copy_index):
        """A lifecycle carrying only copy ``copy_index`` of the ``name`` write that fails DRE-1 before the write checks."""
        value = self._vector("sr2-single-write-two-producers")
        value["resolverEvidence"]["qualifiedArtifactWrites"] = {
            name: [generator.qualified_artifact_write(value, name, copy_index)]
        }
        generator.resign_resolver(value)
        value["artifacts"]["evaluation"]["signature"]["value"] = value["artifacts"]["decision"]["signature"]["value"]
        return value

    def test_a_finding_on_a_copy_stands_beside_another_address_equivocation(self):
        """CORE §5.1, FV-10: two writes at one address leave a sole copy's finding at another standing, and its terminal unrecorded."""
        release = self._fixture("release")
        terminal = generator.block_time(generator.TERMINAL_BLOCKS["release"])
        widened = (release["artifacts"]["railDefinition"]["parameters"]["maxCrossSubstrateSkewMs"] + 1000) // 1000
        resolver_late = copy.deepcopy(release)
        resolver_late["resolverEvidence"]["decisionAnchor"]["finalizedBlockTimestampSec"] = terminal + widened + 1
        generator.resign_resolver(resolver_late)
        unbound_funding = self._vector("sr2-single-write-two-producers")
        unbound_funding["resolverEvidence"]["qualifiedArtifactWrites"]["funding"][0]["contentHash"] = "ab" * 32
        generator.resign_resolver(unbound_funding)
        second = self._fixture("release-second-terminal-transaction")
        carriers = {f"{name}-{index}": self._failing_carrier(name, index) for name in ("funding", "decision") for index in (0, 1)}
        for carrier in carriers.values():
            self.assertEqual(finding(carrier), ("fail", "DRE-1"))
        for label, late, own, other in (
            ("carried late copy", self._late_decision_copy(), ("fail", "DRD-11"), "funding"),
            ("carried unanchored copy", self._late_decision_copy(anchored=False), ("fail", "DRV-6"), "funding"),
            ("carried copy in skew window", self._decision_copy_in_skew_window(), ("indeterminate", "DRC-15"), "funding"),
            ("resolver anchor late", resolver_late, ("fail", "DRD-11"), "funding"),
            ("unbound funding copy", unbound_funding, ("fail", "DRV-6"), "decision"),
        ):
            values = {"late": late, "second": second, **{f"{other}-{index}": carriers[f"{other}-{index}"] for index in (0, 1)}}
            # The copy's own `fail` stands; its uncertainty gives way to
            # DRAA-4 but still keeps the terminal out of replay state.
            joint = {
                "late": own if own[0] == "fail" else EQUIVOCATION, "second": EQUIVOCATION,
                f"{other}-0": ("fail", "DRE-1"), f"{other}-1": ("fail", "DRE-1"),
            }
            with self.subTest(label=label):
                self.assertEqual(finding(late), own)
                for order in itertools.permutations(values):
                    with self.subTest(order=order):
                        ledger = DecisionLedger()
                        observed = evaluate_lifecycles([copy.deepcopy(values[item]) for item in order], ledger)
                        self.assertEqual(dict(zip(order, map(verdict, observed))), joint)
                        self.assertNotIn(verifier._terminal_record(copy.deepcopy(late)), ledger.terminals())
                        self.assertEqual(self._streamed(values, order), joint)
                # The second write at the other address revises the second
                # terminal's verdict and the copy's uncertainty, never its `fail`.
                ledger = DecisionLedger()
                for item in ("late", "second", f"{other}-0"):
                    self.assertNotIn("revises", evaluate_protocol(copy.deepcopy(values[item]), ledger))
                last = evaluate_protocol(copy.deepcopy(values[f"{other}-1"]), ledger)
                self.assertEqual(
                    [verdict(revision["previous"]) for revision in last["revises"]],
                    [("pass", "DRV-7")] if own[0] == "fail" else [("indeterminate", "DRD-8"), own],
                )
                self.assertEqual({verdict(revision) for revision in last["revises"]}, {EQUIVOCATION})

    def test_a_pending_terminal_takes_part_in_the_replay_comparison(self):
        """A terminal whose decision ordering rests on a sole copy still fails replay, and keeps a conflicting terminal undecided."""

        def terminal_sec(value):
            reference = value["artifacts"]["terminal"]["terminalEventRefs"][0]
            return next(
                item["blockTimestampSec"] for item in value["reproductionInputs"]["nativeEventInputs"]
                if verifier._event_identity(item["eventRef"]) == verifier._event_identity(reference)
            )

        def ordered_on(value, finalized, carried=True):
            value = copy.deepcopy(value)
            if carried:
                value["resolverEvidence"]["qualifiedArtifactWrites"] = {
                    "decision": [generator.qualified_artifact_write(value, "decision", 1, finalized)]
                }
            value["resolverEvidence"]["decisionAnchor"]["finalizedBlockTimestampSec"] = finalized
            generator.resign_resolver(value)
            return value

        # The resolver attests the earlier terminal: no ledger is needed.
        for name in (
            "consumed-decision-replay", "resolver-history-shows-terminal-job",
            "resolver-history-shows-event-settled-another-job",
        ):
            shipped = self._vector(name)
            own = (self.vectors[name]["expected"], self.vectors[name]["expectedRule"])
            self.assertEqual(own[0], "fail")
            sec = terminal_sec(shipped)
            widened = (shipped["artifacts"]["railDefinition"]["parameters"]["maxCrossSubstrateSkewMs"] + 1000) // 1000
            for label, value, pending in (
                ("carried copy in skew window", ordered_on(shipped, sec), ("indeterminate", "DRC-15")),
                ("carried late copy", ordered_on(shipped, sec + widened + 1), ("fail", "DRD-11")),
                ("resolver anchor in skew window", ordered_on(shipped, sec, carried=False), ("indeterminate", "DRC-15")),
            ):
                with self.subTest(vector=name, form=label):
                    checked = verifier._checked_lifecycle(copy.deepcopy(value), DecisionLedger())
                    self.assertEqual((verdict(checked.issue), checked.pending), (pending, True))
                    ledger = DecisionLedger()
                    self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(value), ledger)), own)
                    self.assertEqual(ledger.terminals(), ())
        # A conflict with the ledger: the shipped verdicts of the vector and
        # its companion stand in every order, batch and stream.
        for name in ("decision-reused-by-another-terminal-transaction", "second-terminal-for-terminal-job"):
            shipped = self._vector(name)
            companions = self.vectors[name]["evaluatedWith"]
            values = {name: shipped, **{item: self._vector(item) for item in companions}}
            joint = dict(zip(values, map(verdict, evaluate_lifecycles([copy.deepcopy(item) for item in values.values()], DecisionLedger()))))
            self.assertEqual(joint[name], (self.vectors[name]["expected"], self.vectors[name]["expectedRule"]))
            self.assertEqual({joint[item][0] for item in companions}, {"indeterminate"})
            values[name] = ordered_on(shipped, terminal_sec(shipped))
            with self.subTest(vector=name):
                for order in itertools.permutations(values):
                    observed = evaluate_lifecycles([copy.deepcopy(values[item]) for item in order], DecisionLedger())
                    self.assertEqual(dict(zip(order, map(verdict, observed))), joint)
                    self.assertEqual(self._streamed(values, order), joint)

    def test_an_undecided_terminal_still_fails_an_event_or_evidence_conflict(self):
        """DRT-4, DRT-16 fail beside an undecided terminal; DRD-8 stays undecided even when that terminal's own replay fails."""
        release = self._fixture("release")
        inside = copy.deepcopy(release)
        inside["resolverEvidence"]["decisionAnchor"]["finalizedBlockTimestampSec"] = generator.block_time(
            generator.TERMINAL_BLOCKS["release"]
        )
        generator.resign_resolver(inside)
        event = self._fixture("other-job-reuses-release-terminal-event")
        second = self._fixture("release-second-terminal-transaction")
        self.assertEqual(finding(inside), ("indeterminate", "DRC-15"))
        self.assertEqual((finding(event), finding(second)), (("pass", "DRV-7"), ("pass", "DRV-7")))
        values = {"inside": inside, "event": event, "second": second}
        values.update({f"decision-{index}": self._failing_carrier("decision", index) for index in (0, 1)})
        recorded = {verifier._terminal_record(copy.deepcopy(values[item])) for item in ("event", "second")}
        # The decided release fails DRT-4 against the other job's terminal and
        # still takes the decision's first use from the second terminal.
        decided = {"release": release, "event": event, "second": second}
        observed = evaluate_lifecycles([copy.deepcopy(item) for item in decided.values()], DecisionLedger())
        self.assertEqual(
            dict(zip(decided, map(verdict, observed))),
            {"release": ("fail", "DRT-4"), "event": ("fail", "DRT-4"), "second": ("fail", "DRD-8")},
        )
        # Undecided, it fails DRT-4 the same way, and whether the second
        # terminal is the decision's first use is unknown: it would be
        # recorded, whatever its replay comparison decides, once unselectable.
        joint = {"inside": ("fail", "DRT-4"), "event": ("fail", "DRT-4"), "second": ("indeterminate", "DRD-8")}
        for order in itertools.permutations(joint):
            with self.subTest(order=order):
                ledger = DecisionLedger()
                observed = evaluate_lifecycles([copy.deepcopy(values[item]) for item in order], ledger)
                self.assertEqual(dict(zip(order, map(verdict, observed))), joint)
                self.assertEqual(set(ledger.terminals()), recorded)
                self.assertEqual(self._streamed(values, order), joint)
        # Two decision writes make its copy unselectable: it is recorded, and
        # the second terminal fails as beside the decided release.
        joint = {
            "inside": ("fail", "DRT-4"), "event": ("fail", "DRT-4"), "second": ("fail", "DRD-8"),
            "decision-0": ("fail", "DRE-1"), "decision-1": ("fail", "DRE-1"),
        }
        for first, middle, last in itertools.permutations(("inside", "event", "second")):
            for order in (
                ("decision-0", "decision-1", first, middle, last),
                (first, "decision-0", middle, "decision-1", last),
                (first, middle, last, "decision-0", "decision-1"),
            ):
                with self.subTest(order=order):
                    ledger = DecisionLedger()
                    observed = evaluate_lifecycles([copy.deepcopy(values[item]) for item in order], ledger)
                    self.assertEqual(dict(zip(order, map(verdict, observed))), joint)
                    self.assertIn(verifier._terminal_record(copy.deepcopy(inside)), ledger.terminals())
                    self.assertEqual(self._streamed(values, order), joint)
        # The other job's terminal arriving first passes, and is revised to
        # `fail` by the undecided terminal, not to uncertainty.
        with self.subTest(stream="event first"):
            ledger = DecisionLedger()
            self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(event), ledger)), ("pass", "DRV-7"))
            last = evaluate_protocol(copy.deepcopy(inside), ledger)
            self.assertEqual(verdict(last), ("fail", "DRT-4"))
            self.assertEqual(
                [(verdict(item["previous"]), verdict(item)) for item in last["revises"]],
                [(("pass", "DRV-7"), ("fail", "DRT-4"))],
            )
        # A second, distinct evidence record for an undecided terminal fails.
        with self.subTest(conflict="DRT-16"):
            ledger = DecisionLedger()
            self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(inside), ledger)), ("indeterminate", "DRC-15"))
            ((key, entry),) = ledger.held()
            ledger.hold(key, entry._replace(pending=entry.pending._replace(evidence="00" * 32)))
            self.assertEqual(len(ledger.undecided()), 1)
            self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(second), ledger)), ("indeterminate", "DRD-8"))
            self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(release), ledger)), ("fail", "DRT-16"))

    def test_an_error_on_a_copy_gives_way_to_its_terminal_replay_fail(self):
        """The anchor-side DRW-4 `error` rests on the sole decision copy: its pending terminal's replay `fail` decides first."""
        unsafe = GUARD_CASES["decision-ordering-anchor-sum-unsafe"][0](self.vector_pack)
        earlier = self._fixture("release-earlier-terminal-transaction")
        checked = verifier._checked_lifecycle(copy.deepcopy(unsafe), DecisionLedger())
        self.assertEqual((verdict(checked.issue), checked.pending), (("error", "DRW-4"), True))
        self.assertEqual(finding(earlier), ("pass", "DRV-7"))
        values = {"unsafe": unsafe, "earlier": earlier}
        values.update({f"decision-{index}": self._failing_carrier("decision", index) for index in (0, 1)})
        carriers = {"decision-0": ("fail", "DRE-1"), "decision-1": ("fail", "DRE-1")}
        for joint in (
            {"unsafe": ("fail", "DRD-8"), "earlier": ("pass", "DRV-7")},
            {"unsafe": EQUIVOCATION, **carriers},
            {"unsafe": ("fail", "DRD-8"), "earlier": EQUIVOCATION, **carriers},
        ):
            for order in itertools.permutations(joint):
                with self.subTest(order=order):
                    observed = evaluate_lifecycles([copy.deepcopy(values[item]) for item in order], DecisionLedger())
                    self.assertEqual(dict(zip(order, map(verdict, observed))), joint)
                    self.assertEqual(self._streamed(values, order), joint)
        # A stream that issued the `error` first revises it to the replay `fail`.
        ledger = DecisionLedger()
        self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(unsafe), ledger)), ("error", "DRW-4"))
        last = evaluate_protocol(copy.deepcopy(earlier), ledger)
        self.assertEqual(verdict(last), ("pass", "DRV-7"))
        self.assertEqual([(verdict(item["previous"]), verdict(item)) for item in last["revises"]], [(("error", "DRW-4"), ("fail", "DRD-8"))])
        # The oracle never takes a deterministic `error` to `fail`, nor any verdict to `error`.
        self.assertFalse(revision_allowed({"result": "fail", "rule": "DRD-8"}, ("error", "DRV-3")))
        self.assertFalse(revision_allowed({"result": "error", "rule": "DRW-4"}, ("pass", "DRV-7")))

    def test_an_unordered_resolver_anchor_records_its_terminal_only_once_unselectable(self):
        """DRC-15 on the resolver's own anchor keeps its terminal out of replay until two decision writes are known."""
        terminal = generator.block_time(generator.TERMINAL_BLOCKS["release"])
        inside = self._fixture("release")
        inside["resolverEvidence"]["decisionAnchor"]["finalizedBlockTimestampSec"] = terminal
        generator.resign_resolver(inside)
        self.assertNotIn("qualifiedArtifactWrites", inside["resolverEvidence"])
        second = self._fixture("release-second-terminal-transaction")
        own = ("indeterminate", "DRC-15")
        self.assertEqual(finding(inside), own)
        values = {"inside": inside, "second": second}
        # Carriers of each write that fail before the write checks: their
        # writes are retained and their own terminals are not recorded.
        for name in ("funding", "decision"):
            for index in (0, 1):
                carrier = self._single_write_copy(name, index)
                carrier["artifacts"]["evaluation"]["signature"]["value"] = carrier["artifacts"]["decision"]["signature"]["value"]
                self.assertEqual(finding(carrier), ("fail", "DRE-1"))
                values[f"{name}-{index}"] = carrier
        recorded = {verifier._terminal_record(copy.deepcopy(item)) for item in (inside, second)}
        self.assertEqual(len(recorded), 2)
        for writes, records_inside in ((("funding-0", "funding-1"), False), (("decision-0", "decision-1"), True)):
            members = ("inside", "second", *writes)
            joint = None
            for order in itertools.permutations(members):
                with self.subTest(writes=writes, order=order):
                    ledger = DecisionLedger()
                    observed = evaluate_lifecycles([copy.deepcopy(values[item]) for item in order], ledger)
                    verdicts = dict(zip(order, map(verdict, observed)))
                    joint = joint or verdicts
                    self.assertEqual(verdicts, joint)
                    self.assertEqual(self._streamed(values, order), joint)
                    self.assertEqual(
                        verifier._terminal_record(copy.deepcopy(inside)) in ledger.terminals(), records_inside
                    )
            # Two funding writes withhold the verdict, but the decision
            # ordering is still unknown: its terminal fails nothing.
            self.assertEqual(joint["inside"], EQUIVOCATION)
            self.assertEqual(joint["second"] == ("fail", "DRD-8"), records_inside)

    def test_a_terminal_side_ordering_overflow_rests_on_no_copy(self):
        """DRW-4 from the rail skew and the terminal time is an `error` whatever decision writes are known."""
        unsafe = GUARD_CASES["decision-ordering-sum-unsafe"][0](self.vector_pack)
        values = {"unsafe": unsafe}
        for index in (0, 1):
            carried = copy.deepcopy(unsafe)
            carried["resolverEvidence"]["qualifiedArtifactWrites"] = {
                "decision": [generator.qualified_artifact_write(carried, "decision", index)]
            }
            generator.resign_resolver(carried)
            values[f"copy-{index}"] = carried
        joint = dict.fromkeys(values, ("error", "DRW-4"))
        for order in itertools.permutations(values):
            with self.subTest(order=order):
                ledger = DecisionLedger()
                observed = evaluate_lifecycles([copy.deepcopy(values[item]) for item in order], ledger)
                self.assertEqual(dict(zip(order, map(verdict, observed))), joint)
                self.assertEqual(ledger.terminals(), ())
                self.assertEqual(self._streamed(values, order), joint)

    def test_every_negative_fails_only_at_its_intended_guard(self):
        self.assertEqual(generator.negative_isolation_problems(self.vector_pack), [])
        self.assertLessEqual(set(generator.FOLLOW_ON_FINDINGS), set(self.vectors))
        self.assertLessEqual(set(generator.STRUCTURAL_NEGATIVES), set(self.vectors))
        self.assertFalse(set(generator.FOLLOW_ON_FINDINGS) & set(generator.STRUCTURAL_NEGATIVES))
        for name, (result_, rule) in generator.FOLLOW_ON_FINDINGS.items():
            with self.subTest(vector=name):
                self.assertNotEqual(
                    (result_, rule),
                    (self.vectors[name]["expected"], self.vectors[name]["expectedRule"]),
                )

    def test_isolation_audit_counts_a_crash_as_a_failure(self):
        # An exception after the deciding guard is removed is not isolation.
        structural = dict(generator.STRUCTURAL_NEGATIVES)
        name = "pipeline-missing-terminal"
        pack = copy.deepcopy(self.vector_pack)
        pack["vectors"] = [self.vectors[name]]
        try:
            del generator.STRUCTURAL_NEGATIVES[name]
            problems = generator.negative_isolation_problems(pack)
        finally:
            generator.STRUCTURAL_NEGATIVES.clear()
            generator.STRUCTURAL_NEGATIVES.update(structural)
        self.assertEqual(len(problems), 1)
        self.assertIn("the verifier raises", problems[0])
        # A listed structural negative that stops raising is reported too.
        pack["vectors"] = [self.vectors["evaluator-vet-failure"]]
        generator.STRUCTURAL_NEGATIVES["evaluator-vet-failure"] = "control"
        try:
            problems = generator.negative_isolation_problems(pack)
        finally:
            del generator.STRUCTURAL_NEGATIVES["evaluator-vet-failure"]
        self.assertEqual(len(problems), 1)
        self.assertIn("structural negative reports pass", problems[0])

    def test_guard_cases_report_their_exact_finding(self):
        for name, (build, expected) in GUARD_CASES.items():
            with self.subTest(case=name):
                observed = evaluate(build(self.vector_pack))
                self.assertEqual(
                    (observed["result"], observed["rule"], observed["detail"]), expected
                )

    def test_every_verifier_guard_is_killed_by_a_vector_or_a_guard_case(self):
        guarded = generator.GuardedVerifier()
        killed = set()
        for vector in self.vector_pack["vectors"]:
            if vector["expected"] == "pass":
                continue
            value = guarded.module.materialize_vector(self.vector_pack, vector)
            priors = [self._vector(prior) for prior in vector.get("evaluatedWith", [])]
            _outcome, fired = guarded.run(value, priors)
            mutant, _others = guarded.run(value, priors, disabled=fired[-1])
            if (mutant["result"], mutant["rule"]) != (vector["expected"], vector["expectedRule"]):
                killed.add(fired[-1])
        for name, (build, expected) in GUARD_CASES.items():
            value = build(self.vector_pack)
            _outcome, fired = guarded.run(value)
            mutant, _others = guarded.run(value, disabled=fired[-1])
            if (mutant["result"], mutant["rule"], mutant.get("detail")) != expected:
                killed.add(fired[-1])
        self.assertEqual(
            [site for index, site in enumerate(guarded.sites) if index not in killed], []
        )

    def test_positive_mapping_is_byte_exact_not_text_rehashed(self):
        release = self._vector("release-complete-budget")
        artifacts = release["artifacts"]
        create = release["resolverEvidence"]["transactions"][0]
        # DRJ-4: the description is decoded from the createJob calldata.
        self.assertEqual(create["entrypoint"], verifier.selector_of(
            verifier.abi_signature("createJob", verifier.FIXTURE_ENTRYPOINTS["createJob"])
        ))
        self.assertEqual(
            create["calldata"]["description"],
            "dacs-x-delivery-remedy:v1:" + artifact_hash(artifacts["agreement"]),
        )
        params = artifacts["railDefinition"]["parameters"]
        created = verifier.decoded_log(self._observation(release, "JobCreated"), verifier._event_pin(params, "JobCreated"))
        self.assertNotIn("description", created)
        self.assertEqual(
            release["native"]["deliverable"],
            "0x" + artifact_hash(artifacts["delivery"]),
        )
        self.assertEqual(
            release["native"]["reason"],
            "0x" + artifact_hash(artifacts["decision"]),
        )
        completed = verifier.decoded_log(self._observation(release, "JobCompleted"), verifier._event_pin(params, "JobCompleted"))
        self.assertEqual(completed["reason"], release["native"]["reason"])
        self.assertEqual(
            bytes.fromhex(release["canonicalRecords"]["delivery"]["canonicalUtf8Hex"]),
            jcs_canonicalize(
                {key: value for key, value in artifacts["delivery"].items() if key != "signature"}
            ).encode("utf-8"),
        )
        self.assertNotEqual(
            release["native"]["deliverable"][2:],
            hashlib.sha256(artifact_hash(artifacts["delivery"]).encode("ascii")).hexdigest(),
        )
        for name, rule in (
            ("description-prefix-substitution", "DREB-1"),
            ("description-sha256-prefix", "DREB-1"),
            ("native-reason-other-decision", "DREB-6"),
        ):
            with self.subTest(vector=name):
                self.assertEqual(finding(self._vector(name)), ("fail", rule))

    def test_release_refund_and_expiry_terminal_invariants_are_distinct(self):
        release = self._vector("release-complete-budget")
        rejection = self._vector("evaluator-rejection-refund")
        expiry_pre = self._vector("expiry-before-submission")
        expiry_post = self._vector("expiry-after-submission-grace")
        pre_submission_rejection = self._vector("pre-submission-evaluator-rejection")
        self.assertEqual(release["native"]["terminalAction"], "complete")
        self.assertEqual(rejection["native"]["terminalAction"], "reject")
        self.assertEqual(expiry_pre["native"]["terminalAction"], "claimRefund")
        # Candidate §4.1: each terminal is the crosswalk's two logs.
        for value, events in (
            (release, ["JobCompleted", "PaymentReleased"]),
            (rejection, ["JobRejected", "Refunded"]),
            (expiry_pre, ["JobExpired", "Refunded"]),
        ):
            refs = value["artifacts"]["terminal"]["terminalEventRefs"]
            self.assertEqual(len({ref["txHash"] for ref in refs}), 1)
            self.assertEqual([
                item["eventName"] for item in value["reproductionInputs"]["nativeEventInputs"]
                if item["eventRef"] in refs
            ], events)
        self.assertNotIn("decision", expiry_pre["artifacts"])
        self.assertNotIn("decisionRef", expiry_pre["artifacts"]["terminal"])
        self.assertNotIn("deliveryEvidenceRef", expiry_pre["artifacts"]["terminal"])
        self.assertNotIn("decision", expiry_post["artifacts"])
        self.assertIn("deliveryEvidenceRef", expiry_post["artifacts"]["terminal"])
        self.assertNotIn("delivery", pre_submission_rejection["artifacts"])
        self.assertIn("dispute", pre_submission_rejection["artifacts"])
        decision = pre_submission_rejection["artifacts"]["decision"]
        self.assertNotIn("deliveryEvidenceRef", decision)
        self.assertEqual(decision["decisionStage"], "pre-submission")
        self.assertEqual(decision["basisRef"]["kind"], "dispute-outcome")
        self.assertEqual(release["artifacts"]["decision"]["decisionStage"], "post-submission")
        self.assertEqual(
            release["artifacts"]["terminal"]["terminalPhaseIndex"],
            release["artifacts"]["agreement"]["terminalPhaseIndex"],
        )
        # DRT-1 and DRT-2: a release and an evaluator refund each reference
        # the exact decision, each under its own rule.
        for name, rule in (
            ("terminal-decision-reference-mismatch", "DRT-1"),
            ("refund-terminal-decision-reference-mismatch", "DRT-2"),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), ("fail", rule))

    def test_evaluation_and_release_decisions_require_delivery(self):
        # DRD-3: a release needs delivery evidence; DRD-9: without delivery,
        # only a DisputeOutcome basis can authorize the refund.
        for name, rule in (
            ("release-decision-without-delivery", "DRD-3"),
            ("refund-without-delivery-needs-dispute-basis", "DRD-9"),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self.assertNotIn("delivery", value["artifacts"])
                self.assertNotIn(
                    "JobSubmitted",
                    {item["eventName"] for item in value["reproductionInputs"]["nativeEventInputs"]},
                )
                self._assert_isolated(value)
                self.assertEqual(finding(value), ("fail", rule))
        # The deliveryless dispute-based refund remains the one passing shape.
        self.assertEqual(
            finding(self._vector("pre-submission-evaluator-rejection")), ("pass", "DRV-7")
        )

    def test_delivery_evidence_is_current_deliveryevidence_for_the_agreed_phase(self):
        # DACS-4 DeliveryEvidence (PDE-1): its members are the spec type's.
        delivery_type = re.search(
            r"type DeliveryEvidence = \{(.*?)\n\}", SETTLE_SPEC.read_text(encoding="utf-8"), re.S
        ).group(1)
        members = set(re.findall(r"^\s*(\w+)\??:", delivery_type, re.M))
        self.assertLessEqual(verifier.DELIVERY_EVIDENCE_FIELDS | {"reason"}, members)
        self.assertNotIn("evidenceVersion", verifier.DELIVERY_EVIDENCE_FIELDS)
        release = self._vector("release-complete-budget")
        delivery = release["artifacts"]["delivery"]
        self.assertEqual(set(delivery), verifier.DELIVERY_EVIDENCE_FIELDS)
        self.assertEqual(delivery["phaseIndex"], release["artifacts"]["agreement"]["deliveryPhaseIndex"])
        self.assertEqual(
            delivery["deliverableContentHash"],
            hashlib.sha256(release["reproductionInputs"]["deliveredArtifact"]["payloadUtf8"].encode("utf-8")).hexdigest(),
        )
        self.assertEqual(verifier.DOMAINS["delivery"], "dacs-delivery-evidence:v1:")
        for name, outcome in (
            ("dre-2-delivery-phase-kind", ("fail", "DRE-2")),
            ("drp-7-delivery-phase-index", ("fail", "DRP-7")),
            ("drp-7-historical-settlement-evidence", ("fail", "DRP-7")),
            ("drp-7-failed-delivery", ("fail", "DRP-7")),
            ("drv-3-delivery-evidence-shape", ("error", "DRV-3")),
            ("drv-3-failed-delivery-empty-reason", ("error", "DRV-3")),
            ("delivered-artifact-input-mismatch", ("fail", "DRE-2")),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), outcome)
        for edit in (
            put("outcome", "partial"),
            put("reason", "late"),
            put("artifactRef", copy.deepcopy(release["artifacts"]["deliveryRef"])),
            put("deliverableContentHash", "0x" + delivery["deliverableContentHash"]),
            drop("deliverableContentHash"),
            drop("deliverableAnchor"),
            put("deliverableAnchor", {"kind": "storage-program"}),
            put("deliverableAnchor", "locator", ""),
        ):
            with self.subTest(edit=edit):
                self.assertEqual(finding(make_base("release", hooks={"delivery": edit})), ("error", "DRV-3"))
        for edit, outcome in (
            (put("observedAt", "1799994800000"), ("error", "DRW-4")),
            (put("deliveryEvidenceVersion", "2"), ("error", "DRV-2")),
            (put("phaseIndex", -1), ("error", "DRV-3")),
            (each_hook(put("evidenceVersion", "1")), ("error", "DRV-3")),
        ):
            with self.subTest(edit=edit):
                self.assertEqual(finding(make_base("release", hooks={"delivery": edit})), outcome)
        # DRP-7: a failure never passes, whatever it carries.
        failed = each_hook(put("outcome", "failure"), put("reason", "fixture-output-missing"))
        for lifecycle in ("release", "rejected-refund", "expired-post"):
            with self.subTest(failed=lifecycle):
                self.assertEqual(finding(make_base(lifecycle, hooks={"delivery": failed})), ("fail", "DRP-7"))

    def test_records_not_supplied_are_indeterminate_unless_contradicted(self):
        """Candidate §9 step 5 and §11.3 cases I1 and I5, with every resolver status as for a full lifecycle."""
        spec = " ".join(SPEC.read_text(encoding="utf-8").split())
        self.assertIn("**I5** — missing job reference, funding evidence, delivery, evaluation, or decision artifact when no contradictory fact is established", spec)
        for name, outcome in (
            ("decision-record-not-supplied", ("indeterminate", "DRD-4")),
            ("evaluation-and-decision-records-not-supplied", ("indeterminate", "DRD-4")),
            ("pre-submission-decision-record-not-supplied", ("indeterminate", "DRD-4")),
            ("decision-without-authenticated-basis", ("indeterminate", "DRD-2")),
            ("rejection-evaluation-record-not-supplied", ("indeterminate", "DRD-2")),
            ("dispute-outcome-record-not-supplied", ("indeterminate", "DRD-2")),
            ("dispute-case-record-not-supplied", ("indeterminate", "DRX-7")),
            ("evaluation-rule-not-supplied", ("indeterminate", "DRE-8")),
            ("delivery-record-not-supplied", ("indeterminate", "DRE-5")),
            ("rejection-delivery-record-not-supplied", ("indeterminate", "DRE-5")),
            ("expiry-delivery-record-not-supplied", ("indeterminate", "DRE-5")),
            # Something present contradicts the record: still fail.
            ("released-terminal-without-decision-reference", ("fail", "DRD-2")),
            ("decision-basis-kind-unsupported", ("fail", "DRD-2")),
            ("expiry-invented-decision", ("fail", "DRD-7")),
            ("pre-submission-expiry-delivery-ref", ("fail", "DRT-12")),
            ("release-decision-without-delivery", ("fail", "DRD-3")),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self.assertNotIn("unavailable", value["resolverEvidence"]["statuses"].values())
                self._assert_isolated(value)
                self.assertEqual(finding(value), outcome)
        # An authenticated resolver record that says the missing evidence does
        # not exist, or contradicts it, is a contradiction (DRV-6); one that
        # says it is unavailable keeps it indeterminate under its own rule.
        for base, status, state, outcome in (
            ("delivery-record-not-supplied", "deliveryFinality", "not-applicable", ("fail", "DRV-6")),
            ("delivery-record-not-supplied", "deliveryFinality", "contradictory", ("fail", "DRV-6")),
            ("delivery-record-not-supplied", "deliveryFinality", "unavailable", ("indeterminate", "DRE-5")),
            ("decision-record-not-supplied", "decisionFinality", "contradictory", ("fail", "DRV-6")),
            ("decision-record-not-supplied", "decisionFinality", "unavailable", ("indeterminate", "DRD-4")),
        ):
            with self.subTest(base=base, status=status, state=state):
                value = self._fixture(base)
                value["resolverEvidence"]["statuses"][status] = state
                generator.resign_resolver(value)
                self.assertEqual(finding(value), outcome)
        # A delivery the terminal references without a native submission is
        # not missing: the authenticated lifecycle shows none was submitted.
        value = self._fixture("delivery-record-not-supplied")
        value["deliveryBinding"] = None
        self.assertEqual(finding(value)[0], "fail")

    def test_unmodelled_delivery_kinds_never_pass(self):
        """Only storage-program delivery is modelled; no kind label selects which checks run."""
        self.assertEqual(verifier.MODELLED_DELIVERY_KINDS, {"deliver-storage-program"})
        for name in ("drp-3-attested-payload-delivery-unmodelled", "drp-3-entitlement-delivery-unmodelled"):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), ("fail", "DRP-3"))
        kinds = sorted(verifier.DACS4_DELIVERY_KINDS - verifier.MODELLED_DELIVERY_KINDS) + ["deliver-other"]
        anchors = (
            {"kind": "storage-program", "locator": f"dacs4:deliverable:{generator.JOB_A}:2"},
            {"kind": "payload-attestation", "locator": "fixture:any-anchor"},
            None,
        )
        for kind, anchor, lifecycle in itertools.product(kinds, anchors, ("release", "rejected-refund")):
            delivery_edits = [put("phase", kind)]
            delivery_edits.append(drop("deliverableAnchor") if anchor is None else put("deliverableAnchor", anchor))
            for relabel_step in (True, False):
                with self.subTest(kind=kind, anchor=anchor, lifecycle=lifecycle, relabel_step=relabel_step):
                    hooks = {"delivery": each_hook(*delivery_edits)}
                    if relabel_step:
                        hooks["fixture"] = put("pipeline", 2, {"kind": kind})
                    observed = finding(make_base(lifecycle, hooks=hooks))
                    self.assertNotEqual(observed[0], "pass")
                    self.assertIn(observed, {("fail", "DRP-3"), ("fail", "DRE-2"), ("error", "DRV-3"), ("error", "DRV-2")})
        # A deliveryless lifecycle cannot name an unmodelled delivery step either.
        for lifecycle in ("expired-pre", "pre-submission-rejected-refund"):
            with self.subTest(deliveryless=lifecycle):
                value = make_base(lifecycle, hooks={"fixture": put("pipeline", 2, {"kind": "deliver-entitlement"})})
                self.assertEqual(finding(value), ("fail", "DRP-3"))

    def test_every_artifact_describes_the_overlay_job(self):
        for name, rule, agreement in (
            ("drd-8-evaluation-job-reference", "DRD-8", True),
            ("drd-8-decision-job-reference", "DRD-8", True),
            ("dra-1-bilateral-job", "DRA-1", False),
            ("dra-17-bilateral-parties-swapped", "DRA-17", False),
            ("dra-17-seller-bundle-differs", "DRA-17", False),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value, agreement=agreement)
                self.assertEqual(finding(value), ("fail", rule))
        other_job = self._fixture("rejected-refund")["artifacts"]["job"]
        self.assertEqual(
            self._vector("drd-8-evaluation-job-reference")["artifacts"]["evaluation"]["escrowJobRef"]["contentHash"],
            artifact_hash(other_job),
        )

    def test_dre_3_subject_evidence_resolves_to_authenticated_records(self):
        release = self._vector("release-complete-budget")
        self.assertEqual(
            release["artifacts"]["evaluation"]["subjectEvidenceRefs"], [release["artifacts"]["deliveryRef"]]
        )
        for name, outcome in (
            ("dre-5-evaluation-subject-unresolved", ("indeterminate", "DRE-5")),
            ("dre-3-evaluation-subject-contradiction", ("fail", "DRE-3")),
            ("drv-3-evaluation-subject-refs", ("error", "DRV-3")),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), outcome)
        # The published job and funding records resolve as subjects too.
        def subjects(evaluation):
            evaluation["subjectEvidenceRefs"] = [
                copy.deepcopy(evaluation["escrowJobRef"]), copy.deepcopy(evaluation["deliveryEvidenceRef"]),
            ]
        self.assertEqual(finding(make_base("release", hooks={"evaluation": subjects})), ("pass", "DRV-7"))
        for refs in ([{"kind": "storage-program", "locator": "x"}], ["subject"], {}):
            with self.subTest(refs=refs):
                value = make_base("release", hooks={"evaluation": put("subjectEvidenceRefs", refs)})
                self.assertEqual(finding(value), ("error", "DRV-3"))

    def test_drd_8_drl_4_drt_4_terminal_ledger(self):
        release = self._vector("release-complete-budget")
        ledger = DecisionLedger()
        # DRD-8 forbids authorizing another job or transaction, not verifying
        # the same terminal again.
        for _ in range(3):
            self.assertEqual(evaluate_protocol(copy.deepcopy(release), ledger)["result"], "pass")
        self.assertEqual(len(ledger.terminals()), 1)
        self.assertEqual(evaluate_protocol(self._anchored_earlier(), ledger)["result"], "pass")
        # One terminal per decision, per native job, and per terminal event;
        # each of these is later than the release terminal.
        for fixture, rule in (
            ("release-second-terminal-transaction", "DRD-8"),
            ("release-job-rejection", "DRL-4"),
            ("other-job-reuses-release-terminal-event", "DRT-4"),
        ):
            with self.subTest(fixture=fixture):
                alone = self._fixture(fixture)
                self.assertEqual(finding(alone), ("pass", "DRV-7"))
                observed = evaluate_protocol(alone, ledger)
                self.assertEqual((observed["result"], observed["rule"]), ("fail", rule))
        # The ledger holds each authenticated terminal once, whatever its verdict.
        self.assertEqual(len(ledger.terminals()), 4)
        self.assertEqual(len(set(ledger.terminals())), 4)
        # Evidence that fails an earlier stage records nothing.
        fresh = DecisionLedger()
        self.assertEqual(
            evaluate_protocol(self._vector("relayer-substituted-as-native-caller"), fresh)["result"],
            "fail",
        )
        self.assertEqual(fresh.terminals(), ())
        recorded = ledger.terminals()[0]
        self.assertEqual(recorded.position, (generator.TERMINAL_BLOCKS["release"], 2))
        with self.assertRaises(TypeError):
            evaluate_protocol(release, None)

    def test_conflicting_terminals_are_ordered_by_authenticated_position(self):
        release = self._fixture("release")
        # Conflicting terminals whose resolver-attested history names the release.
        def naming_release(name):
            value = self._fixture(name)
            value["resolverEvidence"]["priorTerminals"] = [{
                "chainId": release["artifacts"]["job"]["chainId"],
                "contractAddress": release["artifacts"]["job"]["contractAddress"],
                "nativeJobId": release["artifacts"]["job"]["nativeJobId"],
                "txHash": release["artifacts"]["terminal"]["terminalEventRefs"][0]["txHash"],
                "logIndex": release["artifacts"]["terminal"]["terminalEventRefs"][0]["logIndex"],
                "decisionHash": artifact_hash(release["artifacts"]["decision"]),
            }]
            generator.resign_resolver(value)
            self.assertEqual(finding(value), ("fail", "DRD-8"))
            return value
        attested_later = naming_release("release-second-terminal-transaction")
        # A history cannot order terminals that share an event position.
        attested_same_position = naming_release("release-same-position-terminal-transaction")
        # (other lifecycle, verdict of the release, verdict of the other)
        # when the two are evaluated together.
        pairs = (
            ("history-names-earlier", attested_later, ("pass", "DRV-7"), ("fail", "DRD-8")),
            ("later-decision-reuse", self._fixture("release-second-terminal-transaction"), ("indeterminate", "DRD-8"), ("fail", "DRD-8")),
            ("later-job-terminal", self._fixture("release-job-rejection"), ("indeterminate", "DRL-4"), ("fail", "DRL-4")),
            ("earlier-decision-reuse", self._fixture("release-earlier-terminal-transaction"), ("fail", "DRD-8"), ("indeterminate", "DRD-8")),
            ("same-position", self._fixture("release-same-position-terminal-transaction"), ("indeterminate", "DRD-8"), ("indeterminate", "DRD-8")),
            ("same-position-history-names-release", attested_same_position, ("indeterminate", "DRD-8"), ("fail", "DRD-8")),
            ("shared-event", self._fixture("other-job-reuses-release-terminal-event"), ("fail", "DRT-4"), ("fail", "DRT-4")),
        )
        for label, other, release_outcome, other_outcome in pairs:
            values, expected = [release, other], [release_outcome, other_outcome]
            for order in ((0, 1), (1, 0)):
                with self.subTest(pair=label, order=order):
                    # Evaluated together, the verdicts are the same in either order.
                    joint = evaluate_lifecycles(
                        [copy.deepcopy(values[index]) for index in order], DecisionLedger()
                    )
                    self.assertEqual([verdict(item) for item in joint], [expected[index] for index in order])
                    # One at a time, the second arrival gets its joint verdict
                    # and two conflicting terminals never both pass.  When it
                    # contradicts the first verdict, its result revises that
                    # verdict to the joint one.
                    ledger = DecisionLedger()
                    first, second = (
                        evaluate_protocol(copy.deepcopy(values[index]), ledger) for index in order
                    )
                    self.assertEqual(verdict(second), expected[order[1]])
                    self.assertFalse(first["result"] == second["result"] == "pass")
                    self.assertEqual(self._revised(values[order[0]], first, second), expected[order[0]])
                    self.assertEqual("revises" in second, verdict(first) != expected[order[0]])
                    # With both known, re-evaluation gives the joint verdicts.
                    for index in order:
                        observed = evaluate_protocol(copy.deepcopy(values[index]), ledger)
                        self.assertEqual(verdict(observed), expected[index])
            # When the resolver's records agree, even the first arrival gets
            # its joint verdict, so neither order changes any verdict.
            if label == "history-names-earlier":
                for order in ((0, 1), (1, 0)):
                    ledger = DecisionLedger()
                    for index in order:
                        self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(values[index]), ledger)), expected[index])
        self.assertIsNone(verifier.terminal_precedes(
            TerminalRecord(("c", "a", "1"), (1, "0x1", 2), None, (5, 2)),
            TerminalRecord(("c", "a", "1"), (1, "0x2", 2), None, (5, 2)),
        ))
        self.assertIsNone(verifier.terminal_precedes(
            TerminalRecord(("c", "a", "1"), (1, "0x1", 2), None, (5, 2)),
            TerminalRecord(("c", "a", "1"), (2, "0x2", 2), None, (6, 2)),
        ))
        # A revision names exactly one recorded terminal.
        recorded = TerminalRecord(("c", "a", "1"), ("c", "0x1", 2), "d", (5, 2), ((("c", "a", "1"), ("c", "0x0", 1), "d"),))
        variants = (
            recorded, recorded._replace(job=("c", "a", "2")), recorded._replace(event=("c", "0x2", 2)),
            recorded._replace(decision="e"), recorded._replace(position=(6, 2)), recorded._replace(attested=()),
        )
        identities = {json.dumps(verifier.terminal_identity(item), sort_keys=True) for item in variants}
        self.assertEqual(len(identities), len(variants))

    def test_a_second_distinct_terminal_evidence_record_fails(self):
        """DRT-16: one terminal transaction reproduces one evidence hash; the decision is part of its identity."""
        release = self._fixture("release")
        record = verifier._terminal_record(copy.deepcopy(release))
        self.assertEqual(record.evidence, artifact_hash(release["artifacts"]["terminal"]))
        other = record._replace(evidence="00" * 32)
        self.assertEqual(verifier.terminal_conflict(record, other)[0], "DRT-16")
        self.assertIsNone(verifier.terminal_conflict(record, record))
        # A resolver-attested earlier terminal has no evidence hash to compare.
        self.assertIsNone(verifier.terminal_conflict(record._replace(evidence=None), other))
        # The same job and event with another decision is another terminal.
        self.assertEqual(verifier.terminal_conflict(record, record._replace(decision="11" * 32))[0], "DRL-4")
        # Through the ledger, in either order, the record is `fail`.
        for seeded_first in (True, False):
            with self.subTest(seeded_first=seeded_first):
                ledger = DecisionLedger()
                if seeded_first:
                    ledger.record(other)
                    self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(release), ledger)), ("fail", "DRT-16"))
                else:
                    self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(release), ledger)), ("pass", "DRV-7"))
                    ledger.record(other)
                    self.assertEqual(verdict(evaluate_protocol(copy.deepcopy(release), ledger)), ("fail", "DRT-16"))

    def test_claim_parameters_sort_by_decoded_key(self):
        """CORE CF-2(c): keys sort before percent-encoding, and only reserved characters are escaped."""
        key = "did:demos:agent:" + "ab" * 32
        self.assertIsNotNone(verifier.parse_claim(key + "?0=2&%3F=1"))
        self.assertIsNone(verifier.parse_claim(key + "?%3F=1&0=2"))
        self.assertIsNone(verifier.parse_claim(key + "?%41=1"))
        self.assertIsNone(verifier.parse_claim(key + "?a=%FF"))
        self.assertIsNotNone(verifier.parse_claim(key + "?a=%3A"))

    def test_a_batch_revises_every_earlier_verdict_it_changes(self):
        release = self._fixture("release")
        later = self._fixture("release-second-terminal-transaction")
        # The earlier-anchored release is another lifecycle with the
        # release's terminal; the release itself is evaluated again in the batch.
        for earlier_name, earlier in (
            ("anchored-earlier", self._anchored_earlier()),
            ("release", release),
        ):
            for batch in ([later, release], [release, later]):
                with self.subTest(earlier=earlier_name, batch=[item is release for item in batch]):
                    ledger = DecisionLedger()
                    issued = evaluate_protocol(copy.deepcopy(earlier), ledger)
                    self.assertEqual(verdict(issued), ("pass", "DRV-7"))
                    observed = evaluate_lifecycles([copy.deepcopy(item) for item in batch], ledger)
                    together = evaluate_lifecycles(
                        [copy.deepcopy(item) for item in (earlier, *batch)], DecisionLedger()
                    )
                    # Every result carries the revision, and applying it gives
                    # the verdict of evaluating everything as one set.
                    for item in observed:
                        self.assertEqual(self._revised(earlier, issued, item), verdict(together[0]))
                    self.assertEqual(verdict(together[0]), ("indeterminate", "DRD-8"))
                    self.assertEqual([verdict(item) for item in observed], [verdict(item) for item in together[1:]])

    def test_verdicts_do_not_depend_on_evaluation_order(self):
        vectors = self.vector_pack["vectors"]
        values = {vector["name"]: self._vector(vector["name"]) for vector in vectors}
        # Standalone positives; a vector with `evaluatedWith` is a replay scenario.
        positives = [
            vector["name"] for vector in vectors
            if vector["expected"] == "pass" and "evaluatedWith" not in vector
        ]
        for order in (positives, positives[::-1]):
            ledger = DecisionLedger()
            for _ in range(2):
                for name in order:
                    with self.subTest(order=order[0], vector=name):
                        observed = evaluate_protocol(copy.deepcopy(values[name]), ledger)
                        self.assertEqual(observed["result"], "pass")
                        self.assertNotIn("revises", observed)
        # Each vector set keeps its pinned verdict in every evaluation order.
        for vector in vectors:
            members = [*vector.get("evaluatedWith", []), vector["name"]]
            for order in itertools.permutations(members):
                with self.subTest(vector=vector["name"], order=order):
                    observed = evaluate_lifecycles(
                        [copy.deepcopy(values[name]) for name in order], DecisionLedger()
                    )[order.index(vector["name"])]
                    self.assertEqual(verdict(observed), (vector["expected"], vector["expectedRule"]))
        # The whole pack evaluated as one set: every verdict is the same in
        # any order, and no two conflicting terminals both pass.
        names = list(values)
        baseline = None
        for order in (names, names[::-1], random.Random(372).sample(names, len(names))):
            observed = evaluate_lifecycles([copy.deepcopy(values[name]) for name in order], DecisionLedger())
            verdicts = {name: tuple(item.values()) for name, item in zip(order, observed)}
            baseline = baseline or verdicts
            self.assertEqual(verdicts, baseline)
        self._assert_no_conflicting_pass(values, baseline)
        # One at a time through one ledger, in either order, no two
        # conflicting terminals both pass either, and the verdicts as revised
        # are the verdicts of the whole pack as one set.
        for order in (names, names[::-1]):
            ledger = DecisionLedger()
            streamed = {name: tuple(evaluate_protocol(copy.deepcopy(values[name]), ledger).values()) for name in order}
            self._assert_no_conflicting_pass(values, streamed)
            with self.subTest(streamed=order[0]):
                self.assertEqual(
                    self._streamed(values, order), {name: outcome[:2] for name, outcome in baseline.items()}
                )
        # With every standalone positive already known, each vector without
        # companions keeps its pinned verdict.
        shared = DecisionLedger()
        for name in positives:
            evaluate_protocol(copy.deepcopy(values[name]), shared)
        for vector in vectors:
            if "evaluatedWith" in vector:
                continue
            with self.subTest(shared=vector["name"]):
                observed = evaluate_protocol(copy.deepcopy(values[vector["name"]]), copy.deepcopy(shared))
                self.assertEqual(verdict(observed), (vector["expected"], vector["expectedRule"]))

    def _revised(self, value, issued, *later):
        """The verdict ``issued`` for ``value`` after the revisions in ``later`` results.

        A revision names a terminal or, for a verdict decided before the
        replay comparison, the lifecycle's content hash; it applies to the
        verdicts issued for it that equal its `previous`.
        """
        identity = verifier.terminal_identity(verifier._terminal_record(copy.deepcopy(value)))
        lifecycle = content_hash(value)
        current = verdict(issued)
        for observed in later:
            for revision in observed.get("revises", []):
                if revision.get("lifecycle") == lifecycle or (
                    revision.get("terminal") == identity and verdict(revision["previous"]) == current
                ):
                    self.assertEqual(verdict(revision["previous"]), current)
                    self.assertTrue(revision_allowed(revision, current))
                    current = verdict(revision)
        return current

    def _streamed(self, values, order):
        """Evaluate ``order`` one at a time through one ledger, applying each revision."""
        ledger = DecisionLedger()
        current, issued_for = {}, {}
        for name in order:
            observed = evaluate_protocol(copy.deepcopy(values[name]), ledger)
            current[name] = verdict(observed)
            for revision in observed.get("revises", []):
                key = json.dumps(revision.get("terminal", revision.get("lifecycle")), sort_keys=True)
                revised = [other for other in issued_for.get(key, []) if current[other] == verdict(revision["previous"])]
                self.assertTrue(revised, "a revision names a verdict this ledger issued")
                for other in revised:
                    self.assertTrue(revision_allowed(revision, current[other]))
                    current[other] = verdict(revision)
            if verifier._lifecycle_check(copy.deepcopy(values[name]), ledger) is None:
                terminal = verifier._terminal_record(copy.deepcopy(values[name]))
                key = json.dumps(verifier.terminal_identity(terminal), sort_keys=True)
            else:
                key = json.dumps(content_hash(values[name]))
            issued_for.setdefault(key, []).append(name)
        return current

    def _assert_no_conflicting_pass(self, values, verdicts):
        accepted = {}
        for name, outcome in verdicts.items():
            if outcome[0] == "pass":
                accepted.setdefault(verifier._terminal_record(values[name])[:3], name)
        for left, right in itertools.combinations(accepted, 2):
            with self.subTest(left=accepted[left], right=accepted[right]):
                self.assertIsNone(verifier.terminal_conflict(TerminalRecord(*left), TerminalRecord(*right)))

    def test_resolver_attested_terminal_history_carries_terminal_identity(self):
        for name, rule in (
            ("consumed-decision-replay", "DRD-8"),
            ("resolver-history-shows-terminal-job", "DRL-4"),
            ("resolver-history-shows-event-settled-another-job", "DRT-4"),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), ("fail", rule))
        # An attested entry identical to this terminal is the same transaction.
        release = self._fixture("release")
        terminal = release["artifacts"]["terminal"]
        release["resolverEvidence"]["priorTerminals"] = [{
            "chainId": release["artifacts"]["job"]["chainId"],
            "contractAddress": release["artifacts"]["job"]["contractAddress"],
            "nativeJobId": release["artifacts"]["job"]["nativeJobId"],
            "txHash": terminal["terminalEventRefs"][0]["txHash"],
            "logIndex": terminal["terminalEventRefs"][0]["logIndex"],
            "decisionHash": artifact_hash(release["artifacts"]["decision"]),
        }]
        generator.resign_resolver(release)
        self.assertEqual(finding(release), ("pass", "DRV-7"))

    def test_drp_9_digest_is_fixed_before_the_native_submission(self):
        for name, fixture in self.vector_pack["fixtures"].items():
            with self.subTest(fixture=name):
                binding = fixture["deliveryBinding"]
                anchor = fixture["resolverEvidence"]["deliveryDigestAnchor"]
                # A delivery record the caller did not supply keeps its
                # authenticated native submission (§11.3 case I5).
                if "delivery" in fixture["artifacts"] or name.endswith("delivery-record-not-supplied"):
                    self.assertEqual(set(binding), {"nativeSubmissionEvent"})
                    if name != "drp-9-digest-anchor-unavailable":
                        self.assertEqual(set(anchor), verifier.DIGEST_ANCHOR_FIELDS)
                else:
                    self.assertIsNone(binding)
                    if name != "deliveryless-lifecycle-carries-digest-anchor":
                        self.assertIsNone(anchor)
        for name, outcome in (
            ("delivery-submission-circularity", ("fail", "DRP-9")),
            ("drp-9-digest-anchor-unavailable", ("indeterminate", "DRP-9")),
            ("drp-9-digest-anchor-other-digest", ("fail", "DRP-9")),
            ("drp-9-digest-fixed-after-submission", ("fail", "DRP-9")),
            ("drp-9-digest-anchored-in-submission-block", ("indeterminate", "DRP-9")),
            ("drp-9-digest-anchor-time-equals-submission", ("fail", "DRF-8")),
            ("drp-9-delivery-observed-after-submission", ("fail", "DRP-9")),
            ("deliveryless-lifecycle-carries-digest-anchor", ("fail", "DRP-9")),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), outcome)
        # Payloads derived from the submission, in any encoding, never pass:
        # with a committed submission identity they cannot be computed before
        # the digest is fixed, and a digest fixed later is not anchored before.
        submission = self._observation(self._fixture("release"), "JobSubmitted")
        for derived in (
            hashlib.sha256(submission["eventRef"]["txHash"].encode("ascii")).hexdigest(),
            str(submission["blockNumber"]),
        ):
            with self.subTest(derived=derived):
                value = make_base("release", hooks={
                    "inputs": put("deliveredArtifact", "payloadUtf8", f"deliverable:{generator.JOB_A}:{derived}"),
                    "fixture": put("resolverEvidence", "deliveryDigestAnchor", None),
                })
                self.assertNotEqual(value["deliveryBinding"]["nativeSubmissionEvent"], submission["eventRef"])
                self.assertEqual(finding(value), ("indeterminate", "DRP-9"))
        # An ordering conclusion supplied beside the locator is malformed input.
        labelled = self._fixture("release")
        labelled["deliveryBinding"]["containsNativeSubmissionObservation"] = False
        self.assertEqual(finding(labelled), ("error", "DRV-3"))

    def test_native_capability_facts_come_only_from_the_resolver(self):
        for name, fixture in self.vector_pack["fixtures"].items():
            with self.subTest(fixture=name):
                self.assertFalse(NATIVE_STATE_FIELDS & set(fixture["native"]))
                self.assertNotIn("description", fixture["native"])
                self.assertEqual(
                    set(fixture["resolverEvidence"]["nativeState"]), NATIVE_STATE_FIELDS
                )
        release = self._fixture("release")
        state = release["resolverEvidence"]["nativeState"]
        for field, value in state.items():
            with self.subTest(unsigned=field):
                edited = copy.deepcopy(release)
                edited["resolverEvidence"]["nativeState"][field] = (
                    not value if isinstance(value, bool) else "edited"
                )
                self.assertEqual(finding(edited), ("fail", "DRV-1"))
        # A producer copy of a capability claim has no effect either way.
        producer = copy.deepcopy(release)
        producer["native"].update({
            "submissionCutoffEnforced": False,
            "evaluatorBindingMode": "adapter",
            "preterminalProviderPayoutBaseUnits": "1",
        })
        self.assertEqual(finding(producer), ("pass", "DRV-7"))
        for name, rule in (
            ("native-submission-cutoff-unenforced", "DREB-13"),
            ("native-expiry-recovery-too-early", "DREB-15"),
            ("evaluator-binding-not-direct", "DREB-16"),
            ("evaluator-adapter-substitution", "DREB-20"),
            ("nonzero-preterminal-payout", "DRL-7"),
            ("nonzero-platform-fee", "DRT-7"),
            ("drj-5-escrow-code-changed", "DRJ-5"),
            ("drj-11-token-code-changed", "DRJ-11"),
            ("drj-11-unpinned-implementation", "DRJ-11"),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), ("fail", rule))

    def test_native_description_is_bound_through_the_create_job_calldata(self):
        # An expiry lifecycle presented with a differently signed agreement,
        # but the original native job and resolver record, does not pass.
        original = self._fixture("expired-pre")
        other = make_base(
            "expired-pre",
            hooks={"agreement": put("disclosurePolicy", "explicit-party-supplied")},
        )
        self.assertEqual(finding(other), ("pass", "DRV-7"))
        other["reproductionInputs"]["nativeEventInputs"] = original["reproductionInputs"]["nativeEventInputs"]
        other["resolverEvidence"] = original["resolverEvidence"]
        self._assert_isolated(other)
        self.assertEqual(finding(other), ("fail", "DREB-1"))

    def test_replay_role_mapping_and_ordering_regressions_are_present(self):
        required = {
            "cross-job-delivery-replay": "fail",
            "cross-job-decision-replay": "fail",
            "consumed-decision-replay": "fail",
            "decision-reused-by-another-terminal-transaction": "fail",
            "second-terminal-for-terminal-job": "fail",
            "terminal-event-settles-another-job": "fail",
            "drd-8-same-terminal-again": "pass",
            "evaluator-primary-claim-collision": "fail",
            "evaluator-account-collision": "fail",
            "delivery-hash-text-rehash": "fail",
            "decision-hash-text-rehash": "fail",
            "cross-substrate-order-unavailable": "indeterminate",
            "decision-finalized-after-terminal": "fail",
            "decision-order-within-skew": "indeterminate",
            "delivery-submission-circularity": "fail",
            "evaluator-added-as-bundle-party": "fail",
            "relayer-substituted-as-native-caller": "fail",
        }
        for name, expected in required.items():
            with self.subTest(vector=name):
                self.assertEqual(self.vectors[name]["expected"], expected)

    def test_decision_ordering_follows_drc_15_and_drc_19(self):
        """The decision's Demos anchor, widened by one second, orders it before the terminal block, or not."""
        release = self._fixture("release")
        terminal = generator.block_time(generator.TERMINAL_BLOCKS["release"])
        skew = release["artifacts"]["railDefinition"]["parameters"]["maxCrossSubstrateSkewMs"]
        # Before iff decided + skew + 1000 < terminal (milliseconds).
        widened = (skew + 1000) // 1000
        for offset, outcome in (
            (-(widened + 1), ("pass", "DRV-7")),
            (-widened, ("indeterminate", "DRC-15")),
            (0, ("indeterminate", "DRC-15")),
            (widened, ("indeterminate", "DRC-15")),
            (widened + 1, ("fail", "DRD-11")),
        ):
            with self.subTest(offset=offset):
                value = copy.deepcopy(release)
                value["resolverEvidence"]["decisionAnchor"]["finalizedBlockTimestampSec"] = terminal + offset
                generator.resign_resolver(value)
                self.assertEqual(finding(value), outcome)
        for name, outcome in (
            ("cross-substrate-order-unavailable", ("indeterminate", "DRD-10")),
            ("self-reported-time-cannot-order", ("indeterminate", "DRD-10")),
            ("decision-finalized-after-terminal", ("fail", "DRD-11")),
            ("decision-order-within-skew", ("indeterminate", "DRC-15")),
            ("decision-order-demos-second-widening", ("indeterminate", "DRC-15")),
            ("resolver-anchors-expiry-decision", ("fail", "DRV-6")),
        ):
            with self.subTest(vector=name):
                self.assertEqual(finding(self._vector(name)), outcome)

    def test_relay_never_replaces_the_native_evaluator_caller(self):
        relayed = self._vector("eip1271-relayed-execution")
        call = relayed["resolverEvidence"]["transactions"][-1]
        self.assertEqual(call["nativeCallerAccountType"], "eip1271")
        self.assertEqual(call["nativeCaller"], relayed["native"]["evaluator"])
        self.assertNotEqual(call["outerSubmitter"], call["nativeCaller"])
        # DREB-18: this verifier supports no EIP-1271 chain and code.
        self.assertEqual(finding(relayed), ("fail", "DREB-18"))
        self.assertNotIn("DREB-18", {rule for vector in self.vector_pack["vectors"] if vector["expected"] == "pass" for rule in vector["rules"]})

    def test_fixture_scope_cannot_be_read_as_live_rail_registration(self):
        self.assertEqual(self.vector_pack["status"], "non-normative-review-fixture")
        for fixture in self.vector_pack["fixtures"].values():
            self.assertTrue(fixture["fixtureOnly"])
            rail = fixture["artifacts"]["railDefinition"]
            self.assertIn(rail["availability"], verifier.RAIL_AVAILABILITIES)
            self.assertNotIn("fixtureOnly", rail)
        self.assertEqual(self._fixture("release")["artifacts"]["railDefinition"]["availability"], "mocked")
        for name, outcome in (
            ("rail-availability-live", ("error", "DRV-1")),
            ("rail-availability-disabled", ("fail", "DRR-5")),
        ):
            with self.subTest(vector=name):
                self.assertEqual(finding(self._vector(name)), outcome)

    def test_every_deployment_case_executes_and_registration_stays_false(self):
        self.assertEqual(verify_deployment_pack(self.deployment_pack), [])
        manifests = self.deployment_pack["manifests"]
        for case in self.deployment_pack["cases"]:
            manifest = copy.deepcopy(manifests[case["base"]])
            for operation in case["patch"]:
                manifest = apply_operation(manifest, operation)
            observed = evaluate_deployment(manifest)
            with self.subTest(case=case["name"]):
                self.assertEqual(observed["result"], case["expected"])
                self.assertFalse(observed["registrationEligible"])

    def test_synthetic_control_exercises_all_drc_rules_without_registering(self):
        manifest = self.deployment_pack["manifests"]["synthetic-control"]
        statuses = deployment_rule_statuses(manifest)
        self.assertEqual(set(statuses), DRC_RULES)
        self.assertEqual(set(statuses.values()), {"pass"})
        observed = evaluate_deployment(manifest)
        self.assertEqual(observed["result"], "pass")
        self.assertTrue(manifest["fixtureOnly"])
        self.assertEqual(manifest["registrationStatus"], "not-a-deployment")
        self.assertFalse(observed["registrationEligible"])
        # DRC-7 and DRC-8 as the candidate now states them.
        for capability, value, rule in (
            (("hookMode",), "immutable-nonblocking", "DRC-7"),
            (("paymentTokenSemantics", "upgradeable"), True, "DRC-8"),
        ):
            with self.subTest(rule=rule):
                changed = copy.deepcopy(manifest)
                target = changed["capabilities"]
                for key in capability[:-1]:
                    target = target[key]
                target[capability[-1]] = value
                self.assertEqual(deployment_rule_statuses(changed)[rule], "fail")

    def test_current_reference_is_pinned_ineligible_and_never_available(self):
        manifest = self.deployment_pack["manifests"]["current-reference-142e669"]
        self.assertEqual(
            manifest["implementation"]["revision"],
            "142e669c1fd318486a4628395b629f033654dd06",
        )
        observed = evaluate_deployment(manifest)
        self.assertEqual(observed["result"], "fail")
        # §8.4 states the pinned source has no separately enforced submission
        # cutoff, so the fixture records that fact and DRC-13 fails with DRC-1..7.
        self.assertIs(manifest["capabilities"]["submissionCutoffEnforced"], False)
        # ERC8183.sol lines 78 and 869-872: claimRefund on a Submitted job waits
        # out a one-hour grace period past expiredAt, and a pending claim blocks
        # Funded recovery, so recovery does not open at the DREB-15 deadline.
        self.assertIs(manifest["capabilities"]["expiryRecoveryDeadlineEnforced"], False)
        self.assertEqual(
            [rule for rule in sorted(DRC_RULES, key=lambda item: int(item.split("-")[1])) if observed["ruleStatuses"][rule] == "fail"],
            ["DRC-1", "DRC-2", "DRC-3", "DRC-4", "DRC-5", "DRC-6", "DRC-7", "DRC-13"],
        )
        self.assertEqual(
            [rule for rule in sorted(DRC_RULES, key=lambda item: int(item.split("-")[1])) if observed["ruleStatuses"][rule] == "unknown"],
            ["DRC-8", "DRC-10", "DRC-11", "DRC-12"],
        )
        self.assertFalse(observed["registrationEligible"])

    def test_pinned_reference_states_both_drc13_halves_from_source(self):
        """Either half of DRC-13 alone, as read from the pinned source, fails it."""
        manifest = self.deployment_pack["manifests"]["current-reference-142e669"]
        facts = " ".join(manifest["observedSourceFacts"])
        for citation in ("EVALUATION_GRACE_PERIOD", "lines 78, 869-870", "PendingClaimExists",
                         "lines 871-872"):
            with self.subTest(citation=citation):
                self.assertIn(citation, facts)
        for unresolved in ("submissionCutoffEnforced", "expiryRecoveryDeadlineEnforced"):
            with self.subTest(unresolved=unresolved):
                halved = copy.deepcopy(manifest)
                halved["capabilities"][unresolved] = None
                self.assertEqual(deployment_rule_statuses(halved)["DRC-13"], "fail")

    def test_known_unenforced_native_deadline_fails_drc13_despite_unresolved_companions(self):
        for field in ("submissionCutoffEnforced", "expiryRecoveryDeadlineEnforced"):
            with self.subTest(unenforced=field):
                manifest = copy.deepcopy(self.deployment_pack["manifests"]["synthetic-control"])
                manifest["capabilities"].update({
                    "deadlineProfile": None,
                    "submissionCutoffEnforced": None,
                    "expiryRecoveryDeadlineEnforced": None,
                })
                manifest["evidence"]["deadlineEnforcementAuthenticated"] = None
                self.assertEqual(deployment_rule_statuses(manifest)["DRC-13"], "unknown")
                manifest["capabilities"][field] = False
                self.assertEqual(deployment_rule_statuses(manifest)["DRC-13"], "fail")
                observed = evaluate_deployment(manifest)
                self.assertEqual((observed["result"], observed["rule"]), ("fail", "DRC-13"))

    def test_signed_funding_and_terminal_records_cannot_bypass_finality_or_events(self):
        expected = {
            "creation-finality-pending": ("indeterminate", "DRJ-2"),
            "funding-finality-pending": ("indeterminate", "DRF-6"),
            "submission-finality-pending": ("indeterminate", "DRP-9"),
            "funding-events-empty": ("fail", "DRW-7"),
            "terminal-finality-pending": ("indeterminate", "DRT-8"),
            "terminal-events-empty": ("fail", "DRW-7"),
            "terminal-events-state-log-only": ("fail", "DRW-7"),
            "terminal-events-extra-log": ("fail", "DRW-7"),
            "funding-finality-unregistered-member": ("error", "DRV-3"),
            "funding-finality-depth-below-rail-profile": ("fail", "DRW-6"),
            "funding-finality-predates-event-block": ("fail", "DRW-6"),
            "funding-observed-at-wall-clock": ("fail", "DRW-6"),
            "terminal-finality-unregistered-member": ("error", "DRV-3"),
            "terminal-finality-depth-below-rail-profile": ("fail", "DRW-6"),
            "terminal-observed-at-wall-clock": ("fail", "DRW-6"),
        }
        for name, outcome in expected.items():
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), outcome)

    def test_finality_block_identity_is_bound(self):
        """DRF-8, DRW-6: finality is the confirmation-depth block's time, consistent with every other block."""
        release = self._fixture("release")
        funding = self._observation(release, "JobFunded")
        finality = funding["finalityBlock"]
        self.assertEqual(finality["blockNumber"], funding["blockNumber"] + generator.FINALITY_BLOCKS - 1)
        self.assertEqual(release["artifacts"]["funding"]["observedAt"], finality["blockTimestampSec"] * 1000)
        self.assertEqual(
            release["artifacts"]["funding"]["finality"]["finalityObservedAt"], finality["blockTimestampSec"] * 1000,
        )
        for name, outcome in (
            ("funding-finality-block-time-jointly-altered", ("fail", "DRF-8")),
            ("funding-finality-block-wrong-depth", ("fail", "DRF-8")),
            ("funding-finality-block-preimage-mismatch", ("fail", "DRF-8")),
            ("funding-block-hash-mismatch", ("fail", "DRF-8")),
            ("native-events-out-of-order", ("fail", "DRF-8")),
            ("funding-finality-before-confirmation-block", ("fail", "DRW-6")),
            ("funding-finality-after-confirmation-block", ("fail", "DRW-6")),
            ("terminal-finality-far-future", ("fail", "DRW-6")),
        ):
            with self.subTest(vector=name):
                self.assertEqual(finding(self._vector(name)), outcome)
        # The altered record matches the altered block; only the block order
        # contradicts them.
        altered = self._vector("funding-finality-block-time-jointly-altered")
        block_time = self._observation(altered, "JobFunded")["finalityBlock"]["blockTimestampSec"]
        self.assertEqual(altered["artifacts"]["funding"]["observedAt"], block_time * 1000)
        self.assertLessEqual(block_time, verifier.MAX_SECONDS)

    def test_candidate_domains_and_deadline_profile_match_the_spec(self):
        spec = SPEC.read_text(encoding="utf-8")
        candidate_domains = set(re.findall(r'"(dacs-x-[a-z-]+:v1:)" \|\|', spec))
        self.assertEqual(
            candidate_domains,
            {domain for domain in verifier.DOMAINS.values() if domain.startswith("dacs-x-")},
        )
        self.assertIn('"dacs-payee-bound-agreement:v1:" || agreement_hash', (ROOT / "spec/DACS-3-NEGOTIATE.md").read_text(encoding="utf-8"))
        self.assertEqual(verifier.DOMAINS["bilateralAgreement"], "dacs-payee-bound-agreement:v1:")
        self.assertEqual(generator.DOMAINS, verifier.DOMAINS)
        self.assertIn(f"`{verifier.DESCRIPTION_PREFIX}`", spec)
        release = self._vector("release-complete-budget")
        self.assertEqual(
            release["profileParameters"],
            release["artifacts"]["railDefinition"]["parameters"],
        )
        self.assertEqual(
            release["profileParameters"]["deadlineProfile"],
            "separate-submission-cutoff-v1",
        )
        self.assertEqual(
            release["native"]["expiredAt"],
            release["artifacts"]["agreement"]["evaluationDeadlineSec"],
        )
        self.assertNotEqual(
            release["native"]["expiredAt"],
            release["artifacts"]["agreement"]["submissionCutoffSec"],
        )
        self.assertEqual(
            (self.vectors["unsupported-expiry-only-policy"]["expected"], self.vectors["unsupported-expiry-only-policy"]["expectedRule"]),
            ("error", "DRA-15"),
        )
        # The §6.5 logical addresses.
        job = release["artifacts"]["agreement"]["jobId"]
        self.assertEqual(release["artifacts"]["funding"]["escrowJobRef"]["anchor"]["locator"], f"dacs4:x-job-escrow:{job}:job")
        self.assertEqual(release["artifacts"]["evaluationRef"]["anchor"]["locator"], f"dacs4:x-job-escrow:{job}:evaluation:0")
        self.assertEqual(release["artifacts"]["decisionRef"]["anchor"]["locator"], f"dacs4:x-job-escrow:{job}:decision:post-submission")
        self.assertEqual(release["artifacts"]["agreement"]["evaluationRuleRef"]["anchor"]["locator"], f"dacs4:x-job-escrow:{job}:evaluation-rule")

    def test_finality_time_and_fault_projection_come_from_authenticated_inputs(self):
        release = self._vector("release-complete-budget")
        rejection = self._vector("evaluator-rejection-refund")
        expected_finality_fields = {
            "model", "finalityBlocks", "finalityObservedAt"
        }
        for name in ("funding", "terminal"):
            self.assertEqual(
                set(release["artifacts"][name]["finality"]),
                expected_finality_fields,
            )
            self.assertEqual(
                release["artifacts"][name]["finality"]["model"],
                "block-depth",
            )
            self.assertEqual(
                release["artifacts"][name]["observedAt"],
                release["artifacts"][name]["finality"]["finalityObservedAt"],
            )
        self.assertEqual(
            release["native"]["fundedAtSec"],
            self._observation(release, "JobFunded")["blockTimestampSec"],
        )
        self.assertLess(
            self._observation(release, "JobSubmitted")["blockTimestampSec"],
            release["artifacts"]["agreement"]["submissionCutoffSec"],
        )
        self.assertTrue(release["submittedBeforeCutoff"])
        # DRT-14: the candidate §7 rows, per anchored copy.
        def row(value):
            projection = value["reputationProjection"]
            return projection["buyerAnchoredOutcome"], projection["sellerAnchoredOutcome"], projection["faultedParty"]
        self.assertEqual(row(release), ("completed", "completed", "none"))
        self.assertEqual(row(rejection), ("failed-counterparty", "failed-perm", "seller"))
        self.assertEqual(row(self._vector("rejected-refund-buyer-fault")), ("failed-perm", "failed-counterparty", "buyer"))
        self.assertEqual(row(self._vector("rejected-refund-substrate-failure")), ("failed-substrate", "failed-substrate", "none"))
        for name in ("rejected-refund-no-fault", "expiry-before-submission", "pre-submission-evaluator-rejection"):
            with self.subTest(no_projection=name):
                self.assertEqual(row(self._vector(name)), verifier.NO_PROJECTION)
        # An unlisted pair projects no fault: an expiry's seller fault after a
        # submission is not the listed row.
        self.assertEqual(
            generator.projection("expired-refund", "seller-fault", True),
            {**generator.projection("expired-refund", None, True)},
        )

    def test_reproduction_inputs_are_present_and_load_bearing(self):
        release = self._vector("release-complete-budget")
        inputs = release["reproductionInputs"]
        self.assertEqual(set(inputs["roleBundles"]), {"buyer", "seller", "evaluator"})
        self.assertEqual(set(inputs["vetRecords"]), {"buyer", "seller", "evaluator"})
        self.assertIsNotNone(inputs["deliveredArtifact"])
        # Creation and configuration, funding, submission, and the two terminal logs.
        self.assertEqual(len(inputs["nativeEventInputs"]), 6)
        self.assertEqual(len(release["resolverEvidence"]["transactions"]), 4)
        required = {
            "public-test-seed-mismatch": "DRV-4",
            "role-bundle-input-mismatch": "DRA-4",
            "vet-record-input-mismatch": "DRA-4",
            "evaluation-rule-mismatch": "DRE-8",
            "delivered-artifact-input-mismatch": "DRE-2",
            "runtime-bytecode-preimage-mismatch": "DRJ-5",
            "native-event-transaction-preimage-mismatch": "DRT-4",
            "native-event-kind-substitution": "DRT-4",
            "native-event-chain-substitution": "DRT-4",
            "funding-time-caller-substitution": "DRA-9",
            "submitted-before-cutoff-claim-substitution": "DRT-12",
            "detached-profile-projection-weakened": "DRP-5",
            "release-invents-seller-fault": "DRT-14",
            "rejected-refund-erases-seller-fault": "DRT-14",
            "terminal-event-payload-mismatch": "DRT-4",
            "funding-finality-block-preimage-mismatch": "DRF-8",
            "creation-event-cutoff-mismatch": "DRC-21",
            "create-calldata-differs-from-events": "DRV-6",
        }
        for name, rule in required.items():
            with self.subTest(vector=name):
                vector = self.vectors[name]
                self.assertEqual(vector["expected"], "fail")
                self.assertEqual(vector["expectedRule"], rule)
        # The runtime code hash is keccak-256 of the committed bytes (DRW-2).
        self.assertEqual(
            release["artifacts"]["job"]["runtimeBytecodeHash"],
            "0x" + verifier.keccak256(bytes.fromhex(inputs["runtimeBytecode"]["value"])).hex(),
        )

    def test_drv_1_resolver_and_steward_key_pins(self):
        for pinned, claim, seed in (
            (PINNED_RESOLVER_KEYS, generator.RESOLVER, generator.RESOLVER_SEED),
            (PINNED_STEWARD_KEYS, generator.STEWARD, generator.STEWARD_SEED),
        ):
            derived = generator.b64u(
                generator.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
            )
            self.assertEqual(pinned, {claim: derived})
            for name, fixture in self.vector_pack["fixtures"].items():
                with self.subTest(claim=claim, fixture=name):
                    self.assertNotIn(claim, fixture["publicKeys"])
                    self.assertNotIn(claim, fixture["reproductionInputs"]["publicTestSeedHex"])
                    self.assertNotIn(seed.hex(), json.dumps(fixture))
        foreign = self._vector("drv-1-resolver-key")
        # The vector's own key and seed are valid; only the pin rejects it.
        self.assertIsNone(verifier._reproduction_input_check(foreign))
        self.assertEqual(finding(foreign), ("fail", "DRV-1"))

    def test_drv_1_resolver_record_signature_scope(self):
        # Every status, observation field, transaction record, history, and
        # native state edit after signing is DRV-1.
        for base in ("release", "rejected-refund", "expired-pre", "expired-post"):
            fixture = self._fixture(base)
            self.assertEqual(finding(fixture), ("pass", "DRV-7"))
            for name, state in fixture["resolverEvidence"]["statuses"].items():
                for replacement in sorted(verifier.EXTERNAL_STATES - {state}):
                    with self.subTest(base=base, status=name, value=replacement):
                        mutated = copy.deepcopy(fixture)
                        mutated["resolverEvidence"]["statuses"][name] = replacement
                        self.assertEqual(finding(mutated), ("fail", "DRV-1"))
            for index, item in enumerate(fixture["reproductionInputs"]["nativeEventInputs"]):
                for field in ("blockTimestampSec", "blockNumber"):
                    with self.subTest(base=base, observation=index, field=field):
                        mutated = copy.deepcopy(fixture)
                        mutated["reproductionInputs"]["nativeEventInputs"][index][field] = item[field] + 1
                        self.assertEqual(finding(mutated), ("fail", "DRV-1"))
            for index in range(len(fixture["resolverEvidence"]["transactions"])):
                for field in ("outerSubmitter", "nativeCaller"):
                    with self.subTest(base=base, transaction=index, field=field):
                        mutated = copy.deepcopy(fixture)
                        mutated["resolverEvidence"]["transactions"][index][field] = generator.RELAYER_ACCOUNT
                        self.assertEqual(finding(mutated), ("fail", "DRV-1"))
        for name in (
            "drv-1-signed-status",
            "drv-1-signed-observation",
            "drv-1-signed-transaction-record",
            "drv-1-signed-history",
            "drv-1-signed-native-state",
        ):
            with self.subTest(vector=name):
                self.assertEqual(finding(self._vector(name)), ("fail", "DRV-1"))
        bound = self._vector("resolver-bound-to-another-job")
        self.assertEqual(finding(bound), ("fail", "DRV-6"))

    def test_resolver_signature_is_strict(self):
        release = self._fixture("release")
        for resolver_claim in (["claim"], {"claim": 1}, 7):
            with self.subTest(resolver=resolver_claim):
                mutated = copy.deepcopy(release)
                mutated["resolverEvidence"]["resolver"] = resolver_claim
                self.assertEqual(finding(mutated), ("fail", "DRV-1"))
        renamed = copy.deepcopy(release)
        signature = renamed["resolverEvidence"]["signature"]
        signature["party"] = signature.pop("signer")
        self.assertEqual(finding(renamed), ("fail", "DRV-1"))

    def test_resolver_status_rules_are_complete(self):
        self.assertEqual(
            set(verifier.UNAVAILABLE_STATUS_RULES), set(verifier.EXTERNAL_EVIDENCE_FIELDS)
        )
        for name in verifier.UNAVAILABLE_STATUS_RULES:
            with self.subTest(status=name):
                value = self._fixture("release")
                value["resolverEvidence"]["statuses"][name] = "unavailable"
                generator.resign_resolver(value)
                self.assertEqual(
                    finding(value),
                    ("indeterminate", verifier.UNAVAILABLE_STATUS_RULES[name]),
                )

    def test_resolver_status_applicability_in_both_directions(self):
        """Statuses must match what the signed terminal and delivery evidence make applicable.

        An applicable status may not be `not-applicable`, and an inapplicable
        one may not be `verified` or `contradictory`. An inapplicable
        `unavailable` asserts nothing and withholds no required evidence, so
        the applicable checks decide the verdict (candidate §9 step 5, DRV-7).
        """
        failed, passed = ("fail", "DRV-6"), ("pass", "DRV-7")
        expected = {
            (True, "verified"): passed,
            (True, "not-applicable"): failed,
            (True, "contradictory"): failed,
            (False, "verified"): failed,
            (False, "not-applicable"): passed,
            (False, "unavailable"): passed,
            (False, "contradictory"): failed,
        }
        # base: (delivery applicable, decision applicable)
        for base, (delivery, decision) in {
            "release": (True, True),
            "pre-submission-rejected-refund": (False, True),
            "expired-post": (True, False),
            "expired-pre": (False, False),
        }.items():
            for name, applicable in (
                ("deliveryFinality", delivery),
                ("decisionFinality", decision),
            ):
                for state in sorted(verifier.EXTERNAL_STATES):
                    with self.subTest(base=base, status=name, state=state):
                        value = self._fixture(base)
                        value["resolverEvidence"]["statuses"][name] = state
                        generator.resign_resolver(value)
                        want = expected.get(
                            (applicable, state),
                            ("indeterminate", verifier.UNAVAILABLE_STATUS_RULES[name]),
                        )
                        self.assertEqual(finding(value), want)

    def test_dreb_15_expiry_recovery_time(self):
        for lifecycle in ("expired-pre", "expired-post"):
            deadline = self._fixture(lifecycle)["artifacts"]["agreement"]["evaluationDeadlineSec"]
            for offset, expected in ((-1, ("fail", "DREB-15")), (0, ("pass", "DRV-7")), (1, ("pass", "DRV-7"))):
                with self.subTest(lifecycle=lifecycle, offset=offset):
                    value = make_base(lifecycle, terminal_offset=offset)
                    terminal = value["reproductionInputs"]["nativeEventInputs"][-1]
                    self.assertEqual(terminal["blockTimestampSec"] - deadline, generator.BLOCK_SECONDS * offset)
                    self.assertEqual(finding(value), expected)
                    self.assertEqual(
                        value["resolverEvidence"]["nativeState"]["expiryRecoveryAtSec"], deadline
                    )
        for name in (
            "dreb-15-pre-submission-recovery-time",
            "dreb-15-post-submission-recovery-time",
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), ("fail", "DREB-15"))
        self.assertEqual(self.vectors["dreb-15-recovery-after-deadline"]["expected"], "pass")

    def test_drv_3_closed_evaluation_discriminators(self):
        for evaluation_result in ("deferred", "accepted", "", "ACCEPT", ["accept"]):
            for disposition in ("release-to-provider", "refund-to-client"):
                with self.subTest(result=evaluation_result, disposition=disposition):
                    value = make_base("release", hooks={
                        "evaluation": put("result", evaluation_result),
                        "decision": put("disposition", disposition),
                    })
                    self._assert_isolated(value)
                    self.assertEqual(finding(value), ("error", "DRV-3"))
                    if isinstance(evaluation_result, str):
                        # Behind the discriminator stage, the settlement
                        # mapping itself still refuses any result it does not list.
                        mapped = verifier._native_and_terminal_check(value)
                        self.assertEqual((mapped["result"], mapped["rule"]), ("fail", "DRD-2"))
        self.assertEqual(
            set(verifier.SETTLEMENT_AUTHORIZATIONS), verifier.EVALUATION_RESULTS - {"indeterminate"}
        )

    def test_evaluation_rule_is_executed(self):
        """DRE-6, DRE-8 to DRE-10: the result and finding follow from the bound rule's criteria."""
        release = self._vector("release-complete-budget")
        rule = release["artifacts"]["evaluationRule"]
        self.assertEqual((rule["evaluationRuleVersion"], rule["ruleKind"]), ("1", "evaluator-judgement-v1"))
        self.assertEqual(
            [item["criterionId"] for item in release["artifacts"]["evaluation"]["criterionResults"]],
            [criterion["criterionId"] for criterion in rule["criteria"]],
        )
        for name, outcome in (
            ("rule-kind-always-reject", ("error", "DRE-9")),
            ("rule-version-unsupported", ("error", "DRE-9")),
            ("rule-criteria-empty", ("fail", "DRE-9")),
            ("rule-criteria-duplicate", ("fail", "DRE-9")),
            ("rule-for-another-job", ("fail", "DRE-8")),
            ("evaluation-rule-mismatch", ("fail", "DRE-8")),
            ("evaluation-rule-not-supplied", ("indeterminate", "DRE-8")),
            ("release-with-seller-fault-finding", ("fail", "DRE-10")),
            ("release-with-buyer-fault-finding", ("fail", "DRE-10")),
            ("rejected-refund-with-seller-fulfilled-finding", ("fail", "DRE-10")),
            ("evaluation-result-contradicts-criteria", ("fail", "DRE-10")),
            ("criterion-results-out-of-order", ("fail", "DRE-10")),
            ("criterion-results-missing-one", ("fail", "DRE-10")),
            ("indeterminate-evaluation-authorizes-terminal", ("fail", "DRE-4")),
            ("reject-evaluation-release-action", ("fail", "DRD-2")),
            ("accept-evaluation-refund-action", ("fail", "DRD-2")),
        ):
            with self.subTest(vector=name):
                self.assertEqual(finding(self._vector(name)), outcome)
        # Every outcome combination the matrix permits passes, and only those.
        criteria = [criterion["criterionId"] for criterion in rule["criteria"]]
        for outcomes in itertools.product(sorted(verifier.CRITERION_OUTCOMES), repeat=len(criteria)):
            derived = "accept" if set(outcomes) == {"satisfied"} else "reject" if "unsatisfied" in outcomes else "indeterminate"
            for evaluation_result in sorted(verifier.EVALUATION_RESULTS):
                with self.subTest(outcomes=outcomes, result=evaluation_result):
                    value = make_base("release", hooks={"evaluation": each_hook(
                        put("criterionResults", [
                            {"criterionId": criterion, "outcome": outcome} for criterion, outcome in zip(criteria, outcomes)
                        ]),
                        put("result", evaluation_result),
                    )})
                    observed = verifier._evaluation_check(value)
                    if evaluation_result != derived:
                        self.assertEqual((observed["result"], observed["rule"]), ("fail", "DRE-10"))
                    elif derived != "accept":
                        # A release's seller-fulfilled finding is permitted only for accept.
                        self.assertEqual((observed["result"], observed["rule"]), ("fail", "DRE-10"))
                    else:
                        self.assertIsNone(observed)

    def test_dispute_outcomes_follow_the_dispute_table(self):
        """DRX-7, DRX-9, DRD-14: the case, the recommendation, the table, and the decision stage."""
        for name, outcome in (
            ("pre-submission-evaluator-rejection", ("pass", "DRV-7")),
            ("post-submission-dispute-refund", ("pass", "DRV-7")),
            ("dispute-outcome-release", ("pass", "DRV-7")),
            ("dispute-outcome-recommends-other-disposition", ("fail", "DRX-9")),
            ("dispute-outcome-without-recommendation", ("fail", "DRX-9")),
            ("dispute-outcome-evaluator-unavailable", ("fail", "DRX-9")),
            ("dispute-outcome-revision-unlinked", ("fail", "DRAA-7")),
            ("dispute-case-mismatch", ("fail", "DRX-7")),
            ("dispute-case-signed-by-other-role", ("fail", "DRX-7")),
            ("pre-submission-decision-carries-delivery", ("fail", "DRD-14")),
            ("post-submission-decision-on-funded-job", ("fail", "DRD-14")),
            ("pre-submission-decision-after-submit", ("fail", "DRD-3")),
            ("reject-without-expected-status", ("fail", "DRD-13")),
        ):
            with self.subTest(vector=name):
                self.assertEqual(finding(self._vector(name)), outcome)
        # A seller-fulfilled release is never a pre-submission decision.
        value = make_base("pre-submission-rejected-refund", classification="seller-fulfilled")
        self.assertEqual(finding(value), ("fail", "DRX-9"))

    def test_attestation_ref_signer_is_a_canonical_claim_of_the_artifact_signer(self):
        """DACS-2 `AttestationRef.signer` is a canonical ClaimReference and, when present, the artifact's signer."""
        for name, outcome in (
            ("attestation-ref-with-signer", ("pass", "DRV-7")),
            ("attestation-ref-signer-bad-scheme", ("error", "DRV-3")),
            ("attestation-ref-signer-unsorted-parameters", ("error", "DRV-3")),
            ("attestation-ref-signer-other-party", ("fail", "DRV-6")),
            ("decision-ref-signer-buyer", ("fail", "DRW-7")),
            ("funding-ref-signer-buyer", ("fail", "DRW-7")),
            ("flat-agreement-reference", ("error", "DRV-3")),
            ("decision-reference-anchor-kind-unregistered", ("error", "DRV-3")),
        ):
            with self.subTest(vector=name):
                self.assertEqual(finding(self._vector(name)), outcome)
        # A signer with parameters names the same party (CF-3).
        value = make_base("release", generator.SIGNED_REF_JOB, hooks={"evaluationRef": put("signer", generator.EVALUATOR + "?key=1")})
        self.assertEqual(finding(value), ("pass", "DRV-7"))

    def test_dra_10_budget_is_the_converted_agreement_price(self):
        """DACS-4 §9.5.2 steps 2-3: the currency is the rail asset; amount × 10^decimals is exact."""
        self.assertIn(
            "3. Compute on-chain `amount = amount.amount × 10^rail.asset.decimals` "
            "(string-decimal multiplication, no float).",
            SETTLE_SPEC.read_text(encoding="utf-8"),
        )
        # String arithmetic, so an amount longer than Python's int-string limit
        # (4,300 digits) converts exactly too.
        long_amount = "9" * 4301
        uint256_max = str(2 ** 256 - 1)
        for amount, decimals, expected in (
            ("1", 6, "1000000"), ("0.5", 6, "500000"), ("12.345678", 6, "12345678"),
            ("0", 6, "0"), ("7", 0, "7"), ("1.0000001", 6, None), ("0.1", 0, None),
            ("0.000001", 6, "1"), ("0.05", 18, "5" + "0" * 16), ("0", 0, "0"),
            (long_amount, 0, long_amount), (long_amount, 2, long_amount + "00"),
            ("0." + "0" * 254 + "1", 255, "1"),
        ):
            with self.subTest(amount=amount[:20], decimals=decimals):
                self.assertEqual(verifier.price_base_units(amount, decimals), expected)
        release = self._fixture("release")["artifacts"]
        self.assertEqual(release["bilateralAgreement"]["terms"]["price"], {"amount": "1", "currency": generator.TOKEN_SYMBOL})
        self.assertEqual(
            (release["railDefinition"]["asset"]["symbol"], release["railDefinition"]["parameters"]["tokenDecimals"]),
            (generator.TOKEN_SYMBOL, 6),
        )
        self.assertEqual(release["agreement"]["budgetBaseUnits"], "1000000")

        def decimals(count):
            return each_hook(_rail("tokenDecimals", count), put("asset", "decimals", count))

        def price(amount):
            return put("terms", "price", "amount", amount)

        small_native = {"funding": put("amountBaseUnits", "1"), "terminal": put("amountBaseUnits", "1")}
        cases = {
            "fractional price": ({"bilateral": price("0.5"), "agreement": put("budgetBaseUnits", "500000")}, ("pass", "DRV-7")),
            "18 decimals": ({"rail": decimals(18), "agreement": put("budgetBaseUnits", "1" + "0" * 18)}, ("pass", "DRV-7")),
            "zero price and budget": ({"bilateral": price("0"), "agreement": put("budgetBaseUnits", "0")}, ("fail", "DRA-10")),
            "zero price": ({"bilateral": price("0")}, ("fail", "DRA-10")),
            # An ERC-20 amount is a uint256, so the budget is at most 2^256 - 1;
            # a budget of any greater length is an error, read without an int
            # conversion.
            "budget at the uint256 maximum": ({
                "bilateral": price(uint256_max), "rail": decimals(0),
                "agreement": put("budgetBaseUnits", uint256_max),
            }, ("pass", "DRV-7")),
            "budget at the uint256 maximum, 18 decimals": ({
                "bilateral": price(uint256_max[:-18] + "." + uint256_max[-18:]),
                "rail": decimals(18), "agreement": put("budgetBaseUnits", uint256_max),
            }, ("pass", "DRV-7")),
            "budget one above the uint256 maximum": ({
                "bilateral": price(str(2 ** 256)), "rail": decimals(0),
                "agreement": put("budgetBaseUnits", str(2 ** 256)), **small_native,
            }, ("error", "DRV-3")),
            "4,301-digit price and budget": ({
                "bilateral": price(long_amount), "rail": decimals(0),
                "agreement": put("budgetBaseUnits", long_amount), **small_native,
            }, ("error", "DRV-3")),
            # A price of any length still converts exactly, and a long one
            # matches no budget within the bound.
            "4,301-digit price, budget at the uint256 maximum": ({
                "bilateral": price(long_amount), "rail": decimals(0),
                "agreement": put("budgetBaseUnits", uint256_max),
            }, ("fail", "DRA-10")),
            # DRA-10: a price that is not a whole number of base units is `fail`.
            "excess precision": ({"bilateral": price("1.0000001")}, ("fail", "DRA-10")),
            "excess precision, zero decimals": ({"bilateral": price("1.5"), "rail": decimals(0)}, ("fail", "DRA-10")),
            "excess precision, zero budget": ({"bilateral": price("0.0000001"), "agreement": put("budgetBaseUnits", "0")}, ("fail", "DRA-10")),
            "wrong amount": ({"bilateral": price("2")}, ("fail", "DRA-10")),
            "wrong currency": ({"bilateral": put("terms", "price", "currency", "DAI")}, ("fail", "DRA-21")),
            "wrong decimals": ({"rail": decimals(18)}, ("fail", "DRA-10")),
            "zero budget": ({"agreement": put("budgetBaseUnits", "0")}, ("fail", "DRA-10")),
            "budget one base unit short": ({"agreement": put("budgetBaseUnits", "999999")}, ("fail", "DRA-10")),
            "amount not CD-1": ({"bilateral": price("01")}, ("error", "DRV-3")),
            "amount a number": ({"bilateral": price(1)}, ("error", "DRV-3")),
            "amount with exponent": ({"bilateral": price("1e0")}, ("error", "DRV-3")),
            "currency not text": ({"bilateral": put("terms", "price", "currency", 5)}, ("error", "DRV-3")),
            "price extra member": ({"bilateral": put("terms", "price", "decimals", 6)}, ("error", "DRV-3")),
            # The fixture does not read DACS-4's optional `unit`; it fails
            # closed (README, synthetic proof limits).
            "price unit qualifier": ({"bilateral": put("terms", "price", "unit", "per-call")}, ("error", "DRV-3")),
            "decimals text": ({"rail": _rail("tokenDecimals", "6")}, ("error", "DRV-3")),
            "decimals boolean": ({"rail": _rail("tokenDecimals", True)}, ("error", "DRV-3")),
            "decimals negative": ({"rail": _rail("tokenDecimals", -1)}, ("error", "DRV-3")),
            "decimals beyond uint8": ({"rail": _rail("tokenDecimals", 256)}, ("error", "DRV-3")),
            "symbol missing": ({"rail": drop("asset", "symbol")}, ("error", "DRR-7")),
        }
        for name, (hooks, expected) in cases.items():
            with self.subTest(case=name):
                self.assertEqual(finding(make_base("release", hooks=hooks)), expected)
        # The resolver's pre-terminal provider payout is a native amount the
        # verifier reads without comparing it with the budget.
        for payout, expected in ((uint256_max, ("fail", "DRL-7")), (str(2 ** 256), ("error", "DRV-3"))):
            with self.subTest(payout=payout):
                value = _signed_by_resolver(
                    put("resolverEvidence", "nativeState", "preterminalProviderPayoutBaseUnits", payout)
                )(self.vector_pack)
                self.assertEqual(finding(value), expected)

    def test_malformed_input_stays_in_the_four_results(self):
        """Candidate §9 step 2 and CORE §B.2: malformed input is `error`, one lifecycle at a time."""
        safe = 2 ** 53 - 1
        for number, outcome in (
            (float("nan"), ("error", "DRV-3")), (float("inf"), ("error", "DRV-3")),
            (float("-inf"), ("error", "DRV-3")), (safe + 1, ("error", "DRV-3")),
            (-(safe + 1), ("error", "DRV-3")), (float(safe + 1), ("error", "DRV-3")),
        ):
            for place in (("native", "fundedAtSec"), ("reproductionInputs", "nativeEventInputs", 0, "blockNumber"),
                          ("artifacts", "agreement", "submissionCutoffSec")):
                with self.subTest(number=number, place=place):
                    value = self._fixture("release")
                    target = value
                    for key in place[:-1]:
                        target = target[key]
                    target[place[-1]] = number
                    self.assertEqual(finding(value), outcome)
        # The bound is inclusive for an integer and a float alike.
        for number, in_profile in (
            (safe, True), (-safe, True), (float(safe), True), (-float(safe), True), (0.5, True),
            (safe + 1, False), (float(safe + 1), False), (-float(safe + 1), False),
        ):
            with self.subTest(number=number):
                self.assertIs(verifier.number_profile_valid({"n": [number]}), in_profile)
        # An in-range number is not caught by the profile scan.
        value = self._fixture("release")
        value["native"]["fundedAtSec"] = safe
        self.assertEqual(finding(value), ("fail", "DRA-9"))
        for name, outcome in (
            ("drv-3-evaluation-not-object", ("error", "DRV-3")),
            ("drv-3-purchase-count-boolean", ("error", "DRV-3")),
            ("drv-3-purchase-count-float", ("error", "DRV-3")),
            ("drv-3-agreement-phase-index-boolean", ("error", "DRV-3")),
            ("drv-3-funding-phase-index-boolean", ("error", "DRV-3")),
            ("rail-fee-boolean", ("error", "DRC-14")),
            ("funding-observed-at-text", ("error", "DRW-4")),
            ("terminal-observed-at-negative", ("error", "DRW-4")),
            ("dispute-subject-bundle-refs-number", ("error", "DRV-3")),
            ("nonfault-finding-null-party", ("error", "DRV-3")),
        ):
            with self.subTest(vector=name):
                self.assertEqual(finding(self._vector(name)), outcome)
        # The finding is an exact AccountabilityFinding: a rationale that is
        # not non-empty text, or an extra member, is malformed.
        for edit in (
            put("finding", "rationaleCode", 7),
            put("finding", "rationaleCode", ""),
            put("finding", "note", "x"),
        ):
            with self.subTest(finding=edit):
                observed = evaluate(make_base("release", hooks={"evaluation": edit}))
                self.assertEqual(
                    (observed["result"], observed["rule"], observed["detail"]),
                    ("error", "DRV-3", "evaluation finding is not an exact AccountabilityFinding"),
                )
        for name in ("job", "funding", "delivery", "evaluation", "dispute", "decision", "terminal"):
            for malformed in ([], "x", 7):
                with self.subTest(artifact=name, malformed=malformed):
                    value = self._fixture("release")
                    value["artifacts"][name] = malformed
                    self.assertEqual(finding(value), ("error", "DRV-3"))
        for count in (True, False, 1.0, 0.0, "0", None, [], {}, [0]):
            with self.subTest(dacs5PurchaseCount=count):
                value = self._fixture("release")
                value["executionContext"]["dacs5PurchaseCount"] = count
                self.assertEqual(finding(value), ("error", "DRV-3"))
        for count in (1, 2, -1):
            with self.subTest(dacs5PurchaseCount=count):
                value = self._fixture("release")
                value["executionContext"]["dacs5PurchaseCount"] = count
                self.assertEqual(finding(value), ("fail", "DRP-8"))
        # An integral float or a boolean where an integer is read is
        # malformed, though Python's `==` would take either for the integer.
        # Each edit is signed and bound as built.
        def retyped(kind, *path):
            def apply(body):
                target = body
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = kind(target[path[-1]])
            return apply
        for hook, path in (
            ("fixture", ("native", "chainId")), ("fixture", ("native", "fundedAtSec")),
            ("fixture", ("native", "submissionCutoffSec")), ("fixture", ("native", "expiredAt")),
            ("fixture", ("reproductionInputs", "nativeEventInputs", 0, "blockTimestampSec")),
            ("fixture", ("resolverEvidence", "transactions", 0, "nativeStatusAfter")),
            ("rail", ("railVersion",)), ("job", ("chainId",)), ("agreement", ("submissionCutoffSec",)),
            # An event identity is a lookup key: `false` and `true` would
            # find the logs at index 0 (JobCreated) and 1 (JobConfigured).
            ("fixture", ("reproductionInputs", "nativeEventInputs", 0, "eventRef", "logIndex")),
            ("fixture", ("reproductionInputs", "nativeEventInputs", 1, "eventRef", "logIndex")),
        ):
            for kind, lifecycle in itertools.product((float, bool), ("release", "expired-pre")):
                with self.subTest(lifecycle=lifecycle, hook=hook, path=path, kind=kind.__name__):
                    observed = finding(make_base(lifecycle, hooks={hook: retyped(kind, *path)}))
                    self.assertEqual(observed[0], "error")
        # The rail's addresses are compared for equality later, so a malformed
        # one is refused by shape, signed and bound as built.
        for field, malformed in itertools.chain(
            itertools.product(["paymentToken"], [None, [], {}, True, 1.5, "", "0x" + "AB" * 20, "0x" + "ab" * 19]),
            itertools.product(["contractAddress"], [None, "", "x", "0x" + "81" * 21]),
        ):
            with self.subTest(field=field, malformed=malformed):
                self.assertEqual(
                    finding(make_base("release", hooks={"rail": _rail(field, malformed)}))[0], "error"
                )
        detached = self._fixture("release")
        detached["profileParameters"]["platformFeeBP"] = False
        self.assertEqual(finding(detached), ("fail", "DRP-5"))
        # One malformed lifecycle in a batch is its own `error`; the others keep
        # their verdicts.  The containment covers values no shape stage decides.
        release, expiry = self._fixture("release"), self._fixture("expired-pre")
        nan = self._fixture("rejected-refund")
        nan["native"]["fundedAtSec"] = float("nan")
        batch = evaluate_lifecycles([release, nan, [], expiry], DecisionLedger())
        self.assertEqual([verdict(item) for item in batch], [
            ("pass", "DRV-7"), ("error", "DRV-3"), ("error", "DRV-3"), ("pass", "DRV-7"),
        ])
        original = verifier._checked_lifecycle
        try:
            def raising(value, ledger=None):
                if value.get("raise"):
                    raise KeyError("unread member")
                return original(value, ledger)
            verifier._checked_lifecycle = raising
            batch = evaluate_lifecycles([self._fixture("release"), {"raise": True}], DecisionLedger())
        finally:
            verifier._checked_lifecycle = original
        self.assertEqual(verdict(batch[0]), ("pass", "DRV-7"))
        self.assertEqual(
            (batch[1]["result"], batch[1]["rule"], batch[1]["detail"]),
            ("error", "DRV-3", "malformed input could not be read (KeyError)"),
        )
        # A deployment capability of the wrong type fails its rule, as every
        # other capability predicate does; it never raises.
        for hook_mode in ([], {}, 7, True):
            with self.subTest(hook_mode=hook_mode):
                manifest = copy.deepcopy(self.deployment_pack["manifests"]["synthetic-control"])
                manifest["capabilities"]["hookMode"] = hook_mode
                observed = evaluate_deployment(manifest)
                self.assertEqual((observed["result"], observed["ruleStatuses"]["DRC-7"]), ("fail", "fail"))
                self.assertFalse(observed["registrationEligible"])
        manifest = copy.deepcopy(self.deployment_pack["manifests"]["synthetic-control"])
        manifest["capabilities"]["platformFeeBP"] = float("nan")
        self.assertEqual(evaluate_deployment(manifest)["result"], "error")

    def test_deep_input_stays_in_the_four_results(self):
        """Nesting past MAX_JSON_DEPTH is `error` before any stage hashes; a RecursionError is contained."""
        limit = verifier.MAX_JSON_DEPTH
        self.assertTrue(verifier.nesting_within(_nested(limit), limit))
        self.assertFalse(verifier.nesting_within(_nested(limit + 1), limit))
        self.assertFalse(verifier.nesting_within([[[]]], 2))
        self.assertTrue(verifier.nesting_within({"a": [1, {"b": "c"}]}, 3))
        # The bilateral agreement is three levels down, so an extra member
        # nested `limit - 3` deep is within the bound and is hashed.
        for levels, outcome in (
            (limit - 3, ("fail", "DRP-11")),
            (limit - 2, ("error", "DRV-3")),
            (900, ("error", "DRV-3")),
            (100_000, ("error", "DRV-3")),
        ):
            with self.subTest(levels=levels):
                value = self._fixture("release")
                value["artifacts"]["bilateralAgreement"]["extra"] = _nested(levels)
                self.assertEqual(finding(value), outcome)
        # One deep lifecycle in a batch is its own `error`; the others keep
        # their verdicts.
        deep, deeper = self._fixture("rejected-refund"), self._fixture("release")
        deep["artifacts"]["bilateralAgreement"]["extra"] = _nested(900)
        deeper["reproductionInputs"]["nativeEventInputs"][0]["dataArguments"].append(_nested(100_000))
        batch = evaluate_lifecycles(
            [self._fixture("release"), deep, deeper, self._fixture("expired-pre")], DecisionLedger()
        )
        self.assertEqual([verdict(item) for item in batch], [
            ("pass", "DRV-7"), ("error", "DRV-3"), ("error", "DRV-3"), ("pass", "DRV-7"),
        ])
        # A RecursionError that no bound decides is contained per lifecycle.
        original = verifier._checked_lifecycle
        try:
            def raising(value, ledger=None):
                if value.get("recurse"):
                    raise RecursionError("maximum recursion depth exceeded")
                return original(value, ledger)
            verifier._checked_lifecycle = raising
            batch = evaluate_lifecycles([{"recurse": True}, self._fixture("release")], DecisionLedger())
        finally:
            verifier._checked_lifecycle = original
        self.assertEqual(
            (batch[0]["result"], batch[0]["rule"], batch[0]["detail"]),
            ("error", "DRV-3", "malformed input could not be read (RecursionError)"),
        )
        self.assertEqual(verdict(batch[1]), ("pass", "DRV-7"))

    def test_pack_verifiers_bound_depth_before_hashing(self):
        """Called directly, a pack nested past MAX_JSON_DEPTH is a pack error, not a RecursionError."""
        limit = verifier.MAX_JSON_DEPTH
        too_deep = f"arrays and objects nest deeper than {limit} levels"
        release = self._fixture("release")
        release["artifacts"]["bilateralAgreement"]["extra"] = _nested(900)
        pack = dict(self.vector_pack, fixtures=dict(self.vector_pack["fixtures"], release=release))
        self.assertEqual(verify_vector_pack(pack), [f"candidate vector pack: {too_deep}"])
        manifests = dict(self.deployment_pack["manifests"], deep=_nested(1200))
        self.assertEqual(
            verify_deployment_pack(dict(self.deployment_pack, manifests=manifests)),
            [f"deployment capability pack: {too_deep}"],
        )
        # The bound is inclusive and comes before the shape checks.
        for check, label in ((verify_vector_pack, "candidate vector pack"), (verify_deployment_pack, "deployment capability pack")):
            with self.subTest(pack=label):
                self.assertEqual(check({"deep": _nested(limit)}), [f"{label}: {too_deep}"])
                self.assertEqual(check({"deep": _nested(limit - 1)}), [f"{label} is missing required top-level fields"])

    def test_spec_pins_follow_the_checked_against_commit(self):
        """DRG-2: a spec/ edit that does not re-pin the candidate keeps the pack valid; a candidate edit does not."""
        pins = self.vector_pack["sourcePins"]["dacs"]["documents"]
        original = Path.read_bytes

        def edited(path, target):
            def read(self_path):
                content = original(self_path)
                return content + b"\n" if self_path == verifier.ROOT / target else content
            return read

        with unittest.mock.patch.object(Path, "read_bytes", edited(Path, "spec/CORE.md")):
            self.assertEqual(verifier.document_pins(), pins)
        with unittest.mock.patch.object(Path, "read_bytes", edited(Path, verifier.PINNED_DOCUMENTS[0])):
            changed = verifier.document_pins()
        self.assertEqual(
            [path for path in verifier.PINNED_DOCUMENTS if changed[path] != pins[path]], [verifier.PINNED_DOCUMENTS[0]],
        )
        # Each spec/ pin is that document at the Checked-against commit.
        for path in verifier.PINNED_DOCUMENTS[1:]:
            with self.subTest(path=path):
                shown = subprocess.run(
                    ["git", "-C", str(verifier.ROOT), "show", f"{verifier.DACS_CHECKED_AGAINST}:{path}"],
                    capture_output=True, check=True,
                ).stdout
                self.assertEqual(pins[path], hashlib.sha256(shown).hexdigest())
        # A clone without that commit cannot check the pins.
        with unittest.mock.patch.object(verifier, "_blob_at", return_value=None):
            self.assertEqual(
                verify_vector_pack(self.vector_pack),
                [f"cannot read spec/ at the Checked-against commit {verifier.DACS_CHECKED_AGAINST[:7]}; fetch full history"],
            )

    def test_vector_pack_source_pins_are_the_verifiers(self):
        """A lifecycle pack written against other sources or other DACS text is refused before any vector runs."""
        pins = self.vector_pack["sourcePins"]
        self.assertEqual(pins["external"], verifier.EXTERNAL_SOURCE_PINS)
        self.assertEqual(pins["dacs"]["checkedAgainst"], verifier.DACS_CHECKED_AGAINST)
        self.assertEqual(pins["dacs"]["documents"], verifier.document_pins())
        self.assertIn(f"`{verifier.DACS_CHECKED_AGAINST}`", SPEC.read_text(encoding="utf-8"))
        # The candidate's own External pins name the same sources.
        spec = SPEC.read_text(encoding="utf-8")
        for key in ("canonicalErc8183", "eip1271", "eip155", "eip55", "eip1052", "erc2771"):
            with self.subTest(pin=key):
                self.assertIn(verifier.EXTERNAL_SOURCE_PINS[key], spec)
        self.assertIn(verifier.EXTERNAL_SOURCE_PINS["demosSdk"]["integrity"], spec)
        sdk = dict(verifier.EXTERNAL_SOURCE_PINS["demosSdk"], version="4.0.5")
        for label, changed in (
            ("sdk downgraded", dict(pins, external=dict(verifier.EXTERNAL_SOURCE_PINS, demosSdk=sdk))),
            ("erc unpinned", dict(pins, external={key: value for key, value in verifier.EXTERNAL_SOURCE_PINS.items() if key != "canonicalErc8183"})),
            ("other DACS commit", dict(pins, dacs=dict(pins["dacs"], checkedAgainst="ee499bf" + "0" * 33))),
            ("not an object", None),
        ):
            with self.subTest(pins=label):
                self.assertEqual(
                    verify_vector_pack(dict(self.vector_pack, sourcePins=changed)),
                    ["candidate vector pack source pins are not the verifier's"],
                )
        documents = dict(pins["dacs"]["documents"], **{"docs/delivery-or-remedy-candidate.md": "00" * 32})
        self.assertEqual(
            verify_vector_pack(dict(self.vector_pack, sourcePins=dict(pins, dacs=dict(pins["dacs"], documents=documents)))),
            ["pinned document docs/delivery-or-remedy-candidate.md differs from the checkout"],
        )
        unpinned = {key: value for key, value in self.vector_pack.items() if key != "sourcePins"}
        self.assertEqual(verify_vector_pack(unpinned), ["candidate vector pack is missing required top-level fields"])
        readme = README.read_text(encoding="utf-8")
        self.assertIn(verifier.EXTERNAL_SOURCE_PINS["demosSdk"]["integrity"], readme)

    def test_generator_exit_codes(self):
        """`--check` fails on a stale or missing pack and on an isolation problem; `--write` writes.

        Without the Checked-against commit every mode fails and writes nothing.
        """
        scratch = Path(tempfile.mkdtemp(prefix="drr-gen-"))
        current = {
            "VECTOR_OUTPUT": generator.rendered(self.vector_pack),
            "DEPLOYMENT_OUTPUT": generator.rendered(self.deployment_pack),
        }

        def run(args, problems=(), pack=None):
            patches = {
                "ROOT": scratch,
                "VECTOR_OUTPUT": scratch / "vectors.json",
                "DEPLOYMENT_OUTPUT": scratch / "deployment.json",
                "build_vector_pack": lambda: copy.deepcopy(pack or self.vector_pack),
                "build_deployment_pack": lambda: copy.deepcopy(self.deployment_pack),
                "negative_isolation_problems": lambda _pack: list(problems),
            }
            with contextlib.ExitStack() as stack, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                for name, value in patches.items():
                    stack.enter_context(unittest.mock.patch.object(generator, name, value))
                stack.enter_context(unittest.mock.patch.object(sys, "argv", ["generate", *args]))
                return generator.main(), err.getvalue()

        def reset():
            for name, text in current.items():
                (scratch / ("vectors.json" if name == "VECTOR_OUTPUT" else "deployment.json")).write_text(text, encoding="utf-8")

        try:
            reset()
            self.assertEqual(run(["--check"]), (0, ""))
            (scratch / "vectors.json").write_text(current["VECTOR_OUTPUT"].replace('"count": ', '"count": 1', 1), encoding="utf-8")
            self.assertEqual(run(["--check"]), (1, "ERROR: vectors.json is stale\nrun this script with --write\n"))
            reset()
            (scratch / "deployment.json").unlink()
            self.assertEqual(run(["--check"])[0], 1)
            reset()
            code, err = run(["--check"], problems=["some-vector: not isolated"])
            self.assertEqual(code, 1)
            self.assertIn("- some-vector: not isolated", err)
            # An isolation problem writes nothing.
            (scratch / "vectors.json").unlink()
            self.assertEqual(run(["--write"], problems=["some-vector: not isolated"])[0], 1)
            self.assertFalse((scratch / "vectors.json").exists())
            self.assertEqual(run(["--write"]), (0, ""))
            self.assertEqual((scratch / "vectors.json").read_text(encoding="utf-8"), current["VECTOR_OUTPUT"])
            self.assertEqual(run([]), (0, ""))
            # A clone without the Checked-against commit has no spec/ pins
            # (document_pins is None): every mode says so and writes nothing,
            # rather than calling the pack stale or writing null pins.
            with unittest.mock.patch.object(verifier, "_blob_at", return_value=None):
                self.assertIsNone(verifier.document_pins(verifier.ROOT))
            unpinned = copy.deepcopy(self.vector_pack)
            unpinned["sourcePins"]["dacs"]["documents"] = None
            history = f"ERROR: cannot read spec/ at the Checked-against commit {verifier.DACS_CHECKED_AGAINST[:7]}; fetch full history\n"
            reset()
            for args in (["--write"], ["--check"], []):
                with self.subTest(no_history=args):
                    self.assertEqual(run(args, pack=unpinned), (1, history))
                    self.assertEqual((scratch / "vectors.json").read_text(encoding="utf-8"), current["VECTOR_OUTPUT"])
        finally:
            shutil.rmtree(scratch)

    def test_cli_paths_and_unparseable_packs_are_listed_errors(self):
        """A relative path works; malformed JSON or numbers outside CORE §B.2 are listed, not raised."""
        scratch = Path(tempfile.mkdtemp(prefix="drr-cli-"))
        try:
            good = json.loads(VECTOR_PACK.read_text(encoding="utf-8"))
            stale = dict(good, count=1)
            (scratch / "stale.json").write_text(json.dumps(stale), encoding="utf-8")
            text = VECTOR_PACK.read_text(encoding="utf-8")
            (scratch / "nan.json").write_text(text.replace('"fundedAtSec": 1799990000', '"fundedAtSec": NaN', 1), encoding="utf-8")
            (scratch / "huge.json").write_text(text.replace('"fundedAtSec": 1799990000', '"fundedAtSec": 9007199254740992', 1), encoding="utf-8")
            (scratch / "broken.json").write_text("{", encoding="utf-8")
            # The real pack with one member nested past MAX_JSON_DEPTH, so
            # only the depth bound can refuse it: 100,000 levels, which 3.12's
            # parser refuses and later ones can parse, and 2,000 levels, which
            # every interpreter parses.
            too_deep = f"invalid JSON: arrays and objects nest deeper than {verifier.MAX_JSON_DEPTH} levels"
            for name, levels in (("deep.json", 100_000), ("deep-member.json", 2000)):
                nested = '{"k":' * levels + "0" + "}" * levels
                (scratch / name).write_text(
                    text.replace('"fundedAtSec": 1799990000', f'"deep": {nested}, "fundedAtSec": 1799990000', 1),
                    encoding="utf-8",
                )
            relative = Path("conformance/fixtures/delivery-remedy/candidate-vectors-v0.1.json")
            for args, returncode, needle in (
                (["--vectors", str(relative)], 0, "no rail registered"),
                (["--vectors", str(scratch / "stale.json")], 1, "candidate vector count is stale"),
                (["--vectors", str(scratch / "nan.json")], 1, "invalid JSON: NaN is not a JSON number"),
                (["--vectors", str(scratch / "huge.json")], 1, "invalid JSON: integer 9007199254740992 is outside"),
                (["--vectors", str(scratch / "broken.json")], 1, "invalid JSON"),
                (["--vectors", str(scratch / "deep.json")], 1, f"deep.json: {too_deep}"),
                (["--vectors", str(scratch / "deep-member.json")], 1, f"deep-member.json: {too_deep}"),
                (["--vectors", str(scratch)], 1, "cannot read"),
                (["--vectors", str(scratch / "absent.json")], 1, "file not found"),
            ):
                with self.subTest(args=args):
                    proc = subprocess.run(
                        [sys.executable, str(VERIFIER), *args], cwd=ROOT, capture_output=True, text=True,
                    )
                    self.assertEqual(proc.returncode, returncode, proc.stdout + proc.stderr)
                    self.assertIn(needle, proc.stdout + proc.stderr)
                    self.assertNotIn("Traceback", proc.stderr)
            # The listed error does not depend on whether `json.loads` refuses
            # the deep pack: each parse outcome is forced, whatever this
            # interpreter does natively, and lists the same error.
            deep = scratch / "deep.json"
            listed = {}
            for outcome, command in (
                ("native", [str(VERIFIER)]),
                ("raised RecursionError", ["-c", FORCED_PARSE, "1000"]),
                ("returned", ["-c", FORCED_PARSE, "1000000"]),
            ):
                with self.subTest(parse=outcome):
                    proc = subprocess.run(
                        [sys.executable, *command, "--vectors", str(deep)], cwd=ROOT, capture_output=True, text=True,
                    )
                    listed[outcome] = proc.stderr
                    self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                    if outcome != "native":
                        # The vector pack, then the deployment pack.
                        self.assertEqual(proc.stdout, f"parse {outcome}\nparse returned\n")
            self.assertEqual(listed["raised RecursionError"], listed["returned"], "the listed error depends on the parse")
            self.assertEqual(listed["native"], listed["returned"], "the listed error depends on the interpreter")
            self.assertEqual(
                listed["native"], f"delivery-or-remedy candidate verification failed:\n- {deep}: {too_deep}\n",
            )
            # The bound is inclusive, and checked on the parsed value.
            limit = verifier.MAX_JSON_DEPTH
            bound = scratch / "bound.json"
            bound.write_text("[" * limit + "]" * limit, encoding="utf-8")
            self.assertTrue(verifier.nesting_within(verifier.load_json(bound), limit))
            bound.write_text("[" * (limit + 1) + "]" * (limit + 1), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, f"^arrays and objects nest deeper than {limit} levels$"):
                verifier.load_json(bound)
            # A relative path from another directory is reported as given.
            proc = subprocess.run(
                [sys.executable, str(VERIFIER), "--vectors", "stale.json"], cwd=scratch, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("- stale.json: candidate vector count is stale", proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
        finally:
            shutil.rmtree(scratch)

    def test_drp_5_drj_10_selected_rail(self):
        expected = {
            "drp-5-job-rail": "DRP-5",
            "drj-10-job-contract": "DRJ-10",
            "drj-10-job-runtime": "DRJ-10",
            "drp-5-escrow-phase-rails": "DRP-5",
            "rail-definition-reference-mismatch": "DRP-5",
        }
        for name, rule in expected.items():
            with self.subTest(vector=name):
                value = self._vector(name)
                self.assertIsNone(verifier._component_signature_check(value))
                self.assertEqual(finding(value), ("fail", rule))
        divergent = self._vector("drp-5-job-rail")
        self.assertNotEqual(
            divergent["artifacts"]["job"]["railDefinitionRef"],
            divergent["artifacts"]["agreement"]["railDefinitionRef"],
        )
        rail = divergent["artifacts"]["railDefinition"]
        self.assertEqual(divergent["executionContext"]["acceptedRails"], [{"railId": rail["railId"], "railVersion": rail["railVersion"]}])
        self.assertEqual(divergent["artifacts"]["bilateralAgreement"]["terms"]["rail"], divergent["executionContext"]["acceptedRails"][0])

    def test_dreb_18_21_22_terminal_call_record(self):
        for name, outcome in (
            ("relayer-substituted-as-native-caller", ("fail", "DREB-21")),
            ("transaction-record-for-another-transaction", ("fail", "DRL-10")),
            ("eoa-relayed-outer-submitter", ("fail", "DREB-22")),
            ("unsupported-evaluator-account-type", ("error", "DREB-18")),
            ("eip1271-relayed-execution", ("fail", "DREB-18")),
        ):
            with self.subTest(vector=name):
                value = self._vector(name)
                self._assert_isolated(value)
                self.assertEqual(finding(value), outcome)
        # A malformed submitter is refused by the record's shape, before any
        # caller rule reads it.
        malformed = self._vector("malformed-outer-submitter")
        self.assertEqual(
            verifier._resolver_evidence_check(malformed),
            {"result": "error", "rule": "DRV-3", "detail": "resolver transaction records are malformed"},
        )
        self.assertEqual(finding(malformed), ("error", "DRV-3"))

    def test_drc_11_registration_eligibility_is_never_reported(self):
        for fixture_only in (True, False):
            for status in ("not-a-deployment", "listed", "unregistered-ineligible-reference-source"):
                with self.subTest(fixtureOnly=fixture_only, registrationStatus=status):
                    manifest = copy.deepcopy(self.deployment_pack["manifests"]["synthetic-control"])
                    manifest["fixtureOnly"] = fixture_only
                    manifest["registrationStatus"] = status
                    observed = evaluate_deployment(manifest)
                    self.assertEqual(observed["result"], "pass")
                    self.assertFalse(observed["registrationEligible"])
        case = self.deployment_cases["drc-11-manifest-labels"]
        self.assertFalse(case["registrationEligible"])


if __name__ == "__main__":
    unittest.main()
