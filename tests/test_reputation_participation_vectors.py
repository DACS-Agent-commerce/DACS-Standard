import base64
import copy
import hashlib
import json
import math
import re
import subprocess
import sys
import unittest
from pathlib import Path

import dacs5_reference as R
from scripts.reputation_evidence import (
    ANCHOR_BINDING_FIELDS,
    FIXTURE_MAX_DECODED_BYTES,
    FIXTURE_MAX_ENCODED_BYTES,
    FIXTURE_MAX_MEMBERS_AND_ELEMENTS,
    FIXTURE_MAX_NESTING_DEPTH,
    artifact_hash,
    canonical_receipt_history,
    decode_canonical_object,
    inspect_anchor_receipt,
    jcs_hash,
    lowercase_hash,
    nonempty_string,
    resolve_anchor_history,
    safe_integer,
    transaction_key,
    valid_transaction_ref,
    valid_json_number,
    validate_roster,
    verify_detached_signature_status,
    verify_signed_artifact,
    verify_signed_artifact_status,
)


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "reputation-participation-admission-v0.7.json"
)
GENERATOR = ROOT / "scripts" / "generate_reputation_participation_vectors.py"
SPEC = ROOT / "spec" / "DACS-5-VERIFY.md"
CORE = ROOT / "spec" / "CORE.md"
THREAT_MODEL = ROOT / "spec" / "THREAT-MODEL.md"

PARTICIPATION_DOMAIN = "dacs-participation-admission:v1:"
RATING_DOMAIN = "dacs-rating:v1:"
CHANNEL_DOMAIN = "dacs-channelmsg:v1:"
AGREEMENT_DOMAIN = "dacs-agreement:v1:"
PAYEE_BOUND_AGREEMENT_DOMAIN = "dacs-payee-bound-agreement:v1:"
ANCHOR_ADAPTER_DOMAIN = "dacs-test-participation-anchor-adapter:v1:"
CHALLENGE_ADAPTER_DOMAIN = "dacs-test-participation-challenge-adapter:v1:"
OUTCOME_ADAPTER_DOMAIN = "dacs-test-reputation-outcome-adapter:v1:"
ANCHOR_POLICY = "dacs-test-participation-anchor-v1"
CHALLENGE_POLICY = "dacs-test-session-challenge-v1"
TRUSTED_ADAPTER = "key:4c28551b72b73b7b6cd8eae249bbd55e54de389d1ce0e1c6ee7b3ffc1dfea37d"
OUTCOME_POLICY = {
    "policyId": "dacs-test-exact-session-outcome-v1",
    "adapter": "fixture-only-exact-session-outcome-adapter-v1",
    "trustSource": "conformance-harness-fixture-only",
    "proofProfile": "exact-job-bundle-listing-roster-phase-and-obligation",
    "historyOrder": "native-order-then-sha256-jcs-ascending",
}
FIXTURE_JOB = "01J00000000000000000000000"
FIXTURE_NONCE = "aa" * 32

ADMISSION_FIELDS = {
    "participationAdmissionVersion", "jobId", "listingRef", "parties",
    "completedPrefix", "obligation", "deadline", "deadlinePolicy",
    "deadlineClock", "sessionNonce", "admittedAt",
}
RATING_FIELDS = {
    "ratingVersion", "jobId", "rater", "target", "targetRole", "value", "ratedAt",
}
RATING_OPTIONAL_FIELDS = {"freeText", "dimensions"}
CHANNEL_FIELDS = {"channelId", "sequence", "sender", "sentAt", "type", "body"}
CHALLENGE_FIELDS = {
    "challengeEvidenceVersion", "policyId", "jobId", "issuedBy", "presentedTo", "nonce",
}
CHALLENGE_OPTIONAL_FIELDS = {"actingFor"}
OUTCOME_FIELDS = {
    "outcomeEvidenceVersion", "policyId", "proofKind", "objectHashes", "nativeEvent",
}
OBLIGATION_FIELDS = {
    "obligationVersion", "obligationType", "phaseIndex", "phaseKind",
    "pendingState", "obligorRole", "owedAction", "source",
}
TIMEOUT_FIELDS = {
    "timeoutMarkerVersion", "obligation", "deadline", "deadlinePolicy", "deadlineClock",
}


class ChallengeStore:
    """Verifier-owned mutable fixture state, keyed by exact job and nonce."""

    def __init__(self, records, duration):
        self.records = {}
        self.duration = duration
        for record in records:
            key = (record["jobId"], record["nonce"])
            self.records[key] = copy.deepcopy(record)

    def consume_presented(self, challenge, now):
        if challenge is None:
            return "indeterminate"
        if not isinstance(challenge, dict):
            return "fail"
        job_id = challenge.get("jobId")
        nonce = challenge.get("nonce")
        if not nonempty_string(job_id) or not nonempty_string(nonce):
            return "fail"
        record = self.records.get((job_id, nonce))
        if record is None:
            return "fail"
        if record.get("status") != "issued":
            return "fail"
        issued_at = record.get("issuedAt")
        expires_at = record.get("expiresAt")
        if not (
            safe_integer(now)
            and safe_integer(issued_at)
            and safe_integer(expires_at)
            and safe_integer(self.duration)
            and expires_at == issued_at + self.duration
            and issued_at <= now < expires_at
        ):
            record["status"] = "consumed"
            return "fail"
        # Recognition consumes before signature, admission, or later semantic gates.
        record["status"] = "consumed"
        return "pass"


def fixture_verifier_state():
    return {
        "clock": {"now": 1_500},
        "challengePolicy": {"duration": 1_000},
        "challengeState": [{
            "jobId": FIXTURE_JOB,
            "nonce": FIXTURE_NONCE,
            "issuedAt": 1_000,
            "expiresAt": 2_000,
            "status": "issued",
        }],
        "anchorBinding": {"nonce": "9"},
    }


def admits_spa_current_profile(data, trusted_context):
    """CORE §11.1.2 admission shared by the one-sided and rating SPA consumers.

    The caller `currentProfile` boolean and any copied profile object are inert:
    admission comes only from the verifier-owned `trustedContext`, which must be
    well-formed, uniquely authenticated, and exact on the corrective pin, the
    complete module tuple, the session, and each roster participant identity.
    """
    if not isinstance(data, dict):
        return False
    bundle = data.get("bundle")
    if not isinstance(bundle, dict):
        return False
    job_id = bundle.get("jobId")
    parties = bundle.get("parties")
    if not nonempty_string(job_id) or not isinstance(parties, list):
        return False
    if not R._current_context_shape_valid(trusted_context):
        return False
    if not R.is_exact_corrective_profile(R.AUTHORITATIVE_LOCAL_PROFILE):
        return False
    for party in parties:
        if not isinstance(party, dict):
            return False
        role = party.get("role")
        claim = party.get("primaryClaim")
        if not isinstance(role, str) or not nonempty_string(claim):
            return False
        if R.resolve_current_profile(job_id, role, trusted_context) != claim:
            return False
    return True


def vector_hash(vectors):
    encoded = json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def result(*, admitted=False, blame=False, rating=False):
    return {
        "reputationDisposition": "admitted" if admitted else "excluded",
        "oneSidedBlame": blame,
        "ratingCounted": rating,
        "currentWindowCountable": admitted,
    }


def mapped_obligation(kind):
    if kind == "vet-credentials":
        return "vet-pending", "present-credentials"
    if isinstance(kind, str) and kind.startswith("negotiate-"):
        return "negotiate-pending", "respond-to-negotiation"
    if isinstance(kind, str) and kind.startswith("commit-"):
        return "commit-pending", "co-sign-agreement"
    if isinstance(kind, str) and kind.startswith("pay-") and kind != "pay-alternative":
        return "settle-pending", "authorize-payment"
    if isinstance(kind, str) and kind.startswith("deliver-"):
        return "settle-pending", "deliver"
    return None


def party_maps(parties):
    if not validate_roster(parties):
        return None, None
    role_to_claim = {party["role"]: party["primaryClaim"] for party in parties}
    claim_to_role = {party["primaryClaim"]: party["role"] for party in parties}
    return role_to_claim, claim_to_role


def valid_attestation_ref(value):
    if not isinstance(value, dict) or not {"anchor", "contentHash"} <= set(value) <= {
        "anchor", "contentHash", "signer",
    }:
        return False
    anchor = value.get("anchor")
    return (
        isinstance(anchor, dict)
        and set(anchor) == {"kind", "locator"}
        and anchor.get("kind") in {"storage-program", "ipfs", "https"}
        and nonempty_string(anchor.get("locator"))
        and lowercase_hash(value.get("contentHash"))
        and ("signer" not in value or nonempty_string(value.get("signer")))
    )


def valid_listing_ref(value):
    return (
        isinstance(value, dict)
        and set(value) == {"listingId", "version", "contentHash"}
        and nonempty_string(value.get("listingId"))
        and safe_integer(value.get("version"))
        and value.get("version") > 0
        and lowercase_hash(value.get("contentHash"))
    )


def valid_agreement_terms(value, *, payee_bound):
    if not isinstance(value, dict) or not {"deliverable", "price", "deadline"} <= set(value):
        return False
    if not payee_bound and {"payoutBindings", "priorPaymentDispositionRef"} & set(value):
        return False
    if payee_bound and "payoutBindings" not in value:
        return False
    deliverable = value.get("deliverable")
    if (
        not isinstance(deliverable, dict)
        or not {"deliverableType", "hash"} <= set(deliverable)
        or deliverable.get("deliverableType") not in {
            "storage-program", "entitlement", "attested-payload", "external",
        }
        or not lowercase_hash(deliverable.get("hash"))
        or ("schemaUrl" in deliverable and not nonempty_string(deliverable.get("schemaUrl")))
    ):
        return False
    price = value.get("price")
    if not isinstance(price, dict) or not {"amount", "currency"} <= set(price):
        return False
    amount = price.get("amount")
    if (
        not isinstance(amount, str)
        or amount == "0"
        or re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?", amount) is None
        or not nonempty_string(price.get("currency"))
        or ("unit" in price and not nonempty_string(price.get("unit")))
        or not valid_json_number(value.get("deadline"))
    ):
        return False
    if "meteredQuantity" in value:
        quantity = value.get("meteredQuantity")
        if not (
            isinstance(quantity, dict)
            and {"quantity", "unit"} <= set(quantity)
            and isinstance(quantity.get("quantity"), str)
            and re.fullmatch(r"(?:0|[1-9][0-9]*)", quantity["quantity"]) is not None
            and nonempty_string(quantity.get("unit"))
        ):
            return False
    if "rail" in value:
        rail = value.get("rail")
        if (
            not isinstance(rail, dict)
            or not {"railId"} <= set(rail)
            or not nonempty_string(rail.get("railId"))
            or ("railVersion" in rail and not safe_integer(rail.get("railVersion")))
            or ("parameters" in rail and not isinstance(rail.get("parameters"), dict))
        ):
            return False
    for optional_object in ("priceAnchor", "feeSchedule", "additionalTerms"):
        if optional_object in value and not isinstance(value.get(optional_object), dict):
            return False
    if payee_bound:
        bindings = value.get("payoutBindings")
        if not isinstance(bindings, list):
            return False
        keys = []
        for binding in bindings:
            if not (
                isinstance(binding, dict)
                and {"railId", "phaseIndex", "payeeAddress"} <= set(binding)
                and nonempty_string(binding.get("railId"))
                and safe_integer(binding.get("phaseIndex"))
                and nonempty_string(binding.get("payeeAddress"))
            ):
                return False
            keys.append((binding["railId"], binding["phaseIndex"]))
        if len(keys) != len(set(keys)):
            return False
        if "priorPaymentDispositionRef" in value and not valid_attestation_ref(
            value.get("priorPaymentDispositionRef")
        ):
            return False
    return True


def verify_proposed_agreement(data, admission, role_to_claim):
    proposal = data.get("proposedAgreement")
    if proposal is None:
        return "indeterminate"
    if not isinstance(proposal, dict):
        return "fail"
    obligation = admission["obligation"]
    source = obligation["source"]
    obligor_role = obligation["obligorRole"]
    counterparty_role = {"buyer": "seller", "seller": "buyer"}.get(obligor_role)
    proposer = source.get("proposer")
    if (
        counterparty_role is None
        or proposer != role_to_claim.get(counterparty_role)
        or proposer == role_to_claim.get(obligor_role)
    ):
        return "fail"

    legacy = "agreementVersion" in proposal
    payee_bound = "payeeBoundAgreementVersion" in proposal
    if legacy == payee_bound:
        return "fail"
    phase_kind = obligation.get("phaseKind")
    if (phase_kind == "commit-agreement") != legacy or (
        phase_kind == "commit-payee-bound-agreement"
    ) != payee_bound:
        return "fail"
    version_field = "agreementVersion" if legacy else "payeeBoundAgreementVersion"
    domain = AGREEMENT_DOMAIN if legacy else PAYEE_BOUND_AGREEMENT_DOMAIN
    required = {
        version_field, "jobId", "listingRef", "parties", "terms",
        "derivedFromPattern", "generatedAt", "signatures",
    }
    if not required <= set(proposal) or proposal.get(version_field) != "1":
        return "fail"
    if (
        proposal.get("jobId") != admission.get("jobId")
        or proposal.get("listingRef") != admission.get("listingRef")
        or not valid_listing_ref(proposal.get("listingRef"))
        or not valid_json_number(proposal.get("generatedAt"))
        or not valid_agreement_terms(proposal.get("terms"), payee_bound=payee_bound)
    ):
        return "fail"
    if "derivedFromChannel" in proposal:
        channel = proposal.get("derivedFromChannel")
        if not (
            isinstance(channel, dict)
            and {"subnet", "lastMessageHash"} <= set(channel)
            and nonempty_string(channel.get("subnet"))
            and lowercase_hash(channel.get("lastMessageHash"))
        ):
            return "fail"

    agreement_parties = proposal.get("parties")
    if not isinstance(agreement_parties, list):
        return "fail"
    rows = []
    for party in agreement_parties:
        if not isinstance(party, dict) or not {
            "role", "bundleHash", "primaryClaim", "vetRecordRef",
        } <= set(party):
            return "fail"
        if (
            party.get("role") not in {"buyer", "seller"}
            or not lowercase_hash(party.get("bundleHash"))
            or not nonempty_string(party.get("primaryClaim"))
            or not valid_attestation_ref(party.get("vetRecordRef"))
            or ("encryptionKey" in party and not nonempty_string(party.get("encryptionKey")))
        ):
            return "fail"
        rows.append((party["role"], party["primaryClaim"], party["bundleHash"]))
    expected_rows = {
        (party["role"], party["primaryClaim"], party["bundleHash"])
        for party in admission["parties"]
        if party["role"] in {"buyer", "seller"}
    }
    if len(rows) != 2 or len(set(rows)) != 2 or set(rows) != expected_rows:
        return "fail"

    pipeline = data["listing"].get("effectivePipeline")
    index = obligation.get("phaseIndex")
    pattern_by_phase = {
        "negotiate-fixed-price": "fixed-price",
        "negotiate-rfq": "rfq",
        "negotiate-sealed-envelope": "sealed-envelope",
        "negotiate-sealed-envelope-procurement": "sealed-envelope",
    }
    if not isinstance(pipeline, list) or not isinstance(index, int):
        return "fail"
    patterns = [
        pattern_by_phase[item]
        for item in pipeline[:index]
        if isinstance(item, str) and item in pattern_by_phase
    ]
    if len(patterns) != 1 or proposal.get("derivedFromPattern") != patterns[0]:
        return "fail"

    try:
        digest = artifact_hash(proposal, signature_field="signatures")
    except (TypeError, ValueError, OverflowError):
        return "fail"
    if source.get("proposedAgreementHash") != digest:
        return "fail"
    signatures = proposal.get("signatures")
    if not isinstance(signatures, list):
        return "fail"
    if not signatures:
        return "indeterminate"
    agreement_claims = {row[1] for row in rows}
    statuses = {}
    for signature in signatures:
        party = signature.get("party") if isinstance(signature, dict) else None
        if not nonempty_string(party) or party not in agreement_claims or party in statuses:
            return "fail"
        status = verify_detached_signature_status(
            signature,
            domain=domain,
            digest=digest,
            signer_field="party",
            trusted_signer=party,
        )
        if status == "fail":
            return "fail"
        statuses[party] = status
    obligor = role_to_claim[obligor_role]
    if statuses.get(obligor) == "pass":
        return "fail"
    if statuses.get(obligor) == "indeterminate":
        return "indeterminate"
    return statuses.get(proposer, "indeterminate")


def verify_challenge(data, admission, obligor_claim):
    challenge = data.get("sessionChallengeEvidence")
    if challenge is None:
        return "indeterminate"
    signature_status = verify_signed_artifact_status(
        challenge,
        CHALLENGE_ADAPTER_DOMAIN,
        CHALLENGE_FIELDS,
        CHALLENGE_OPTIONAL_FIELDS,
        trusted_signer=TRUSTED_ADAPTER,
    )
    if signature_status != "pass":
        return signature_status
    role_to_claim, _ = party_maps(admission.get("parties"))
    obligation = admission.get("obligation")
    obligor_role = obligation.get("obligorRole") if isinstance(obligation, dict) else None
    counterparty_role = {"buyer": "seller", "seller": "buyer"}.get(obligor_role)
    if role_to_claim is None or counterparty_role is None:
        return "fail"
    issuer = challenge.get("issuedBy")
    counterparty = role_to_claim.get(counterparty_role)
    orchestrator = role_to_claim.get("orchestrator")
    if not (
        challenge.get("challengeEvidenceVersion") == "1"
        and challenge.get("policyId") == CHALLENGE_POLICY
        and challenge.get("jobId") == admission.get("jobId")
        and challenge.get("presentedTo") == obligor_claim
        and challenge.get("nonce") == admission.get("sessionNonce")
        and nonempty_string(issuer)
    ):
        return "fail"
    if issuer == counterparty:
        acting_for = challenge.get("actingFor")
        return "pass" if "actingFor" not in challenge or acting_for == counterparty else "fail"
    if issuer != orchestrator:
        return "fail"
    if "actingFor" not in challenge:
        return "indeterminate"
    return "pass" if challenge.get("actingFor") == counterparty else "fail"


def valid_channel_envelope_fields(message):
    """Validate known DACS-3 envelope fields without dropping signed extensions."""
    if not isinstance(message.get("channelId"), str) or not valid_json_number(message.get("sentAt")):
        return False
    refs = message.get("refs")
    return "refs" not in message or (
        isinstance(refs, dict)
        and ("repliesTo" not in refs or valid_json_number(refs["repliesTo"]))
    )


def verify_channel_source(data, source, role_to_claim):
    messages = data.get("authenticatedChannelMessages")
    if not isinstance(messages, list) or not messages:
        return "indeterminate"
    matches = []
    for message in messages:
        try:
            if artifact_hash(message) == source.get("messageHash"):
                matches.append(message)
        except (
            AttributeError, MemoryError, OverflowError, RecursionError, TypeError,
            ValueError,
        ):
            # An unrelated, structurally unhashable envelope has no authority
            # over selection of an exact source body.
            continue
    if len(matches) != 1:
        return "fail"
    message = matches[0]
    signature_status = verify_signed_artifact_status(
        message,
        CHANNEL_DOMAIN,
        CHANNEL_FIELDS,
        {"refs"},
        allow_unknown_unsigned_fields=True,
    )
    if signature_status != "pass":
        return signature_status
    if not (
        valid_channel_envelope_fields(message)
        and message.get("channelId") == source.get("channelId")
        and message.get("sequence") == source.get("sequence")
        and message.get("sender") == source.get("sender")
        and safe_integer(message.get("sequence"))
        and message.get("sequence") > 0
        and message["signature"].get("signer") == message.get("sender")
        and isinstance(message.get("type"), str)
        and message.get("type") in {"offer", "counter", "accept", "reject"}
    ):
        return "fail"
    sender = source.get("sender")
    buyer = role_to_claim.get("buyer")
    seller = role_to_claim.get("seller")
    if not nonempty_string(sender) or sender not in {buyer, seller}:
        return "fail"
    expected = seller if sender == buyer else buyer
    return "pass" if source.get("expectedResponder") == expected else "fail"


def verify_obligation(data, admission, bundle, role_to_claim):
    obligation = admission.get("obligation")
    if not isinstance(obligation, dict) or set(obligation) != OBLIGATION_FIELDS:
        return "fail"
    if obligation.get("obligationVersion") != "1":
        return "fail"
    index = obligation.get("phaseIndex")
    kind = obligation.get("phaseKind")
    listing = data.get("listing")
    pipeline = listing.get("effectivePipeline") if isinstance(listing, dict) else None
    if (
        not isinstance(index, int)
        or isinstance(index, bool)
        or not isinstance(kind, str)
        or not isinstance(pipeline, list)
        or index < 0
        or index >= len(pipeline)
        or pipeline[index] != kind
    ):
        return "fail"
    mapping = mapped_obligation(kind)
    if mapping is None or (obligation.get("pendingState"), obligation.get("owedAction")) != mapping:
        return "fail"
    obligor_role = obligation.get("obligorRole")
    if not isinstance(obligor_role, str) or obligor_role not in {"buyer", "seller"}:
        return "fail"
    source = obligation.get("source")
    obligation_type = obligation.get("obligationType")
    if not isinstance(source, dict):
        return "fail"
    if obligation_type == "listing-phase-action":
        if set(source) != {"sourceType", "listingRef", "phaseIndex", "phaseKind"}:
            return "fail"
        if not (
            source.get("sourceType") == "listing-phase"
            and source.get("listingRef") == admission.get("listingRef")
            and source.get("phaseIndex") == index
            and source.get("phaseKind") == kind
            and (kind == "vet-credentials" or kind == "negotiate-fixed-price")
        ):
            return "fail"
    elif obligation_type == "rfq-turn-response":
        if set(source) != {
            "sourceType", "messageHash", "channelId", "sequence", "sender", "expectedResponder",
        }:
            return "fail"
        if source.get("sourceType") != "channel-message" or kind != "negotiate-rfq":
            return "fail"
        source_status = verify_channel_source(data, source, role_to_claim)
        if source_status != "pass":
            return source_status
        if source.get("expectedResponder") != role_to_claim.get(obligation.get("obligorRole")):
            return "fail"
    elif obligation_type == "agreement-co-signature":
        if set(source) != {"sourceType", "proposedAgreementHash", "proposer"}:
            return "fail"
        if not (
            source.get("sourceType") == "agreement-proposal"
            and kind in {"commit-agreement", "commit-payee-bound-agreement"}
        ):
            return "fail"
        proposal_status = verify_proposed_agreement(data, admission, role_to_claim)
        if proposal_status != "pass":
            return proposal_status
    elif obligation_type == "agreement-performance":
        if set(source) != {"sourceType", "agreementRef"}:
            return "fail"
        if not (
            source.get("sourceType") == "agreement-reference"
            and (kind.startswith("pay-") or kind.startswith("deliver-"))
            and source.get("agreementRef") == bundle.get("agreementRef")
        ):
            return "fail"
    else:
        return "fail"
    return "pass"


def projected_prefix(data, admission, bundle):
    obligation = admission["obligation"]
    index = obligation["phaseIndex"]
    pipeline = data["listing"]["effectivePipeline"]
    expected = [
        {"index": position, "kind": kind, "outcome": "ok"}
        for position, kind in enumerate(pipeline[:index])
    ]
    if admission.get("completedPrefix") != expected:
        return False
    summary = bundle.get("phaseSummary")
    if not isinstance(summary, list) or len(summary) != index:
        return False
    projection = []
    for entry in summary:
        if not isinstance(entry, dict):
            return False
        projection.append({
            "index": entry.get("index"),
            "kind": entry.get("kind"),
            "outcome": entry.get("outcome"),
        })
    return projection == expected


def receipt_status(data, admission, signer, anchor_binding):
    evidence = data["participationEvidence"]
    selected = evidence.get("admissionReceipt")
    history = evidence.get("admissionReceiptHistory")
    if selected is None:
        return "indeterminate", None
    obligation = admission["obligation"]
    obligation_digest = jcs_hash(obligation)
    expected_logical = (
        f"dacs5:participation:{admission['jobId']}:"
        f"{obligation['obligorRole']}:{obligation_digest}"
    )
    admission_ref = evidence.get("admissionRef")
    if not isinstance(admission_ref, dict) or set(admission_ref) != {"anchor", "contentHash", "signer"}:
        return "fail", None
    anchor = admission_ref.get("anchor")
    if not isinstance(anchor, dict) or set(anchor) != {"kind", "locator"}:
        return "fail", None
    digest = artifact_hash(admission)
    if not (
        admission_ref.get("contentHash") == digest
        and admission_ref.get("signer") == signer
        and anchor.get("kind") == "storage-program"
        and nonempty_string(anchor.get("locator"))
    ):
        return "fail", None
    if not isinstance(selected, dict):
        return "indeterminate", None
    expected_binding = {
        "substrate": "demos:testnet",
        "logicalAddress": expected_logical,
        "nativeAddress": anchor.get("locator"),
        "contentHash": digest,
    }
    if not isinstance(anchor_binding, dict) or not set(anchor_binding) <= {"nonce"}:
        return "fail", None
    expected_binding.update(copy.deepcopy(anchor_binding))

    def receipt_verifier(item):
        return inspect_anchor_receipt(
            item,
            expected_binding=expected_binding,
            adapter_domain=ANCHOR_ADAPTER_DOMAIN,
            adapter_policy=ANCHOR_POLICY,
            trusted_adapter=TRUSTED_ADAPTER,
            authorized_signer=signer,
        )

    status, resolved, _ = resolve_anchor_history(
        selected,
        history,
        expected_binding=expected_binding,
        receipt_verifier=receipt_verifier,
    )
    if status != "pass":
        return status, None
    block = resolved.get("blockRef")
    if not isinstance(block, dict) or not valid_json_number(block.get("timestamp")):
        return "indeterminate", None
    return "pass", resolved


def outcome_binding_objects(data):
    bundle = data["bundle"]
    objects = {
        "sessionOutcome": {
            "jobId": bundle.get("jobId"),
            "bundleContentHash": bundle.get("contentHash"),
            "outcome": bundle.get("outcome"),
        },
        "listingPipeline": {
            "listingRef": copy.deepcopy(data["listing"].get("listingRef")),
            "effectivePipeline": copy.deepcopy(data["listing"].get("effectivePipeline")),
        },
        "partyRoster": copy.deepcopy(bundle.get("parties")),
        "phaseSummary": copy.deepcopy(bundle.get("phaseSummary")),
    }
    if "timeout" in bundle:
        objects["timeoutMarker"] = copy.deepcopy(bundle["timeout"])
    return objects


def verify_outcome_item(item, data):
    signature_status = verify_signed_artifact_status(
        item,
        OUTCOME_ADAPTER_DOMAIN,
        OUTCOME_FIELDS,
        trusted_signer=TRUSTED_ADAPTER,
    )
    if signature_status != "pass":
        return signature_status
    objects = outcome_binding_objects(data)
    expected_hashes = {key: jcs_hash(value) for key, value in objects.items()}
    event = item.get("nativeEvent")
    timeout = "timeoutMarker" in objects
    event_fields = {
        "kind", "substrate", "transactionRef", "eventIndex", "nativeOrder",
        "timestamp", "jobId", "bundleContentHash", "outcome",
    }
    if timeout:
        event_fields.add("obligationHash")
    bundle = data["bundle"]
    if not (
        item.get("outcomeEvidenceVersion") == "1"
        and item.get("policyId") == OUTCOME_POLICY["policyId"]
        and item.get("proofKind") == ("obligation-nonresponse" if timeout else "completed-session")
        and item.get("objectHashes") == expected_hashes
        and isinstance(event, dict)
        and set(event) == event_fields
        and event.get("kind") == "fixture-only-session-outcome-event"
        and event.get("substrate") == "demos:testnet"
        and valid_transaction_ref(event.get("transactionRef"))
        and nonempty_string(event.get("eventIndex"))
        and safe_integer(event.get("nativeOrder"))
        and safe_integer(event.get("timestamp"))
        and event.get("jobId") == bundle.get("jobId")
        and event.get("bundleContentHash") == bundle.get("contentHash")
        and event.get("outcome") == bundle.get("outcome")
    ):
        return "fail"
    if timeout and event.get("obligationHash") != jcs_hash(bundle["timeout"]["obligation"]):
        return "fail"
    return "pass"


def outcome_status(data):
    if data.get("outcomeTimePolicy") != OUTCOME_POLICY:
        return "indeterminate", None
    items = data.get("knownOutcomeEvidence")
    if not isinstance(items, list) or not items:
        return "indeterminate", None
    if any(verify_outcome_item(item, data) != "pass" for item in items):
        return "indeterminate", None
    unique = {jcs_hash(item): item for item in items}
    history = [
        item for _, item in sorted(
            unique.items(), key=lambda pair: (pair[1]["nativeEvent"]["nativeOrder"], pair[0])
        )
    ]
    positions = {}
    events = set()
    for item in history:
        event = item["nativeEvent"]
        positions.setdefault(event["nativeOrder"], set()).add(jcs_hash(item))
        events.add((
            event["jobId"], event["bundleContentHash"], event["outcome"],
            *transaction_key(event["transactionRef"]), event["eventIndex"],
            event["nativeOrder"], event["timestamp"], event.get("obligationHash"),
        ))
    if any(len(values) > 1 for values in positions.values()) or len(events) != 1:
        return "indeterminate", None
    timestamp = history[0]["nativeEvent"]["timestamp"]
    if not (
        safe_integer(data.get("windowStart"))
        and safe_integer(data.get("windowEnd"))
        and data["windowStart"] <= timestamp <= data["windowEnd"]
    ):
        return "indeterminate", None
    return "pass", history[0]


def evaluate_one_sided(data, *, challenge_store, verifier_now, anchor_binding):
    challenge_state = challenge_store.consume_presented(
        data.get("sessionChallengeEvidence"), verifier_now
    )
    if challenge_state != "pass":
        return challenge_state, result()
    if data.get("absenceDisposition") != "absent":
        return "indeterminate", result()
    listing = data.get("listing")
    if not isinstance(listing, dict) or listing.get("verificationDisposition") != "verified":
        return "indeterminate", result()
    bundle = data.get("bundle")
    if not isinstance(bundle, dict):
        return "fail", result()
    parties = bundle.get("parties")
    role_to_claim, _ = party_maps(parties)
    if role_to_claim is None:
        return "fail", result()
    bundle_type = bundle.get("bundleType")
    faulted_party = bundle.get("faultedParty")
    anchored_by_role = bundle.get("anchoredByRole")
    bundle_outcome = bundle.get("outcome")
    if not (
        isinstance(bundle_type, str)
        and bundle_type in {"FaultAttestationBundle", "EvidenceBoundFaultAttestationBundle"}
        and isinstance(faulted_party, str)
        and faulted_party in {"buyer", "seller"}
        and isinstance(anchored_by_role, str)
        and anchored_by_role in {"buyer", "seller"}
        and isinstance(bundle_outcome, str)
        and bundle_outcome in {"aborted-by-self", "aborted-by-other"}
        and bundle.get("verifiedSignerRoles") == [anchored_by_role]
    ):
        return "fail", result()
    evidence = data.get("participationEvidence")
    timeout = bundle.get("timeout")
    if evidence is None or timeout is None:
        return "indeterminate", result()
    if not isinstance(evidence, dict) or set(evidence) != {
        "admissionRef", "admission", "admissionReceipt", "admissionReceiptHistory",
    }:
        return "fail", result()
    admission = evidence.get("admission")
    signature_status = verify_signed_artifact_status(
        admission, PARTICIPATION_DOMAIN, ADMISSION_FIELDS
    )
    if signature_status != "pass":
        return signature_status, result()
    if admission.get("participationAdmissionVersion") != "1":
        return "fail", result()
    admitted_parties = admission.get("parties")
    admitted_roles, _ = party_maps(admitted_parties)
    if admitted_roles is None or admitted_parties != parties:
        return "fail", result()
    obligation = admission.get("obligation")
    obligor_role = obligation.get("obligorRole") if isinstance(obligation, dict) else None
    if (
        admission.get("jobId") != bundle.get("jobId")
        or admission.get("listingRef") != bundle.get("listingRef")
        or listing.get("listingRef") != bundle.get("listingRef")
        or obligor_role != bundle.get("faultedParty")
    ):
        return "fail", result()
    signer = admission["signature"].get("signer")
    if signer != role_to_claim.get(obligor_role):
        return "fail", result()
    obligation_verdict = verify_obligation(data, admission, bundle, role_to_claim)
    if obligation_verdict != "pass":
        return obligation_verdict, result()
    if not projected_prefix(data, admission, bundle):
        return "fail", result()
    if not isinstance(timeout, dict) or set(timeout) != TIMEOUT_FIELDS:
        return "fail", result()
    if not (
        timeout.get("timeoutMarkerVersion") == "1"
        and timeout.get("obligation") == obligation
        and timeout.get("deadline") == admission.get("deadline")
        and timeout.get("deadlinePolicy") == admission.get("deadlinePolicy")
        and timeout.get("deadlineClock") == admission.get("deadlineClock")
        and admission.get("deadlinePolicy") == "obligor-admitted-absolute-consensus-deadline"
        and admission.get("deadlineClock") == "sr2-finalized-inclusion-timestamp"
        and safe_integer(admission.get("deadline"))
    ):
        return "fail", result()
    challenge_verdict = verify_challenge(data, admission, signer)
    if challenge_verdict != "pass":
        return challenge_verdict, result()
    anchor_verdict, receipt = receipt_status(
        data, admission, signer, anchor_binding
    )
    if anchor_verdict != "pass":
        return anchor_verdict, result()
    if receipt["blockRef"]["timestamp"] >= admission["deadline"]:
        return "fail", result()
    exact_outcome, outcome = outcome_status(data)
    if exact_outcome != "pass":
        return exact_outcome, result()
    event = outcome["nativeEvent"]
    if (
        event.get("substrate") != receipt.get("substrate")
        or event.get("timestamp") < admission["deadline"]
        or outcome.get("proofKind") != "obligation-nonresponse"
    ):
        return "indeterminate", result()
    return "pass", result(admitted=True, blame=True)


def evaluate_rating(data):
    listing = data.get("listing")
    if not isinstance(listing, dict) or listing.get("verificationDisposition") != "verified":
        return "indeterminate", result()
    bundle = data.get("bundle")
    rating = data.get("rating")
    rating_ref = data.get("ratingRef")
    if not isinstance(bundle, dict) or not isinstance(rating_ref, dict):
        return "fail", result()
    role_to_claim, claim_to_role = party_maps(bundle.get("parties"))
    if role_to_claim is None:
        return "fail", result()
    verified_roles = bundle.get("verifiedSignerRoles")
    required_roles = set(role_to_claim)
    fully_signed = (
        isinstance(verified_roles, list)
        and len(verified_roles) == len(required_roles)
        and all(isinstance(role, str) for role in verified_roles)
        and set(verified_roles) == required_roles
    )
    if not (
        bundle.get("outcome") == "completed"
        and fully_signed
        and listing.get("listingRef") == bundle.get("listingRef")
    ):
        return "fail", result()
    signature_status = verify_signed_artifact_status(
        rating, RATING_DOMAIN, RATING_FIELDS, RATING_OPTIONAL_FIELDS
    )
    if signature_status != "pass":
        return signature_status, result()
    if rating.get("ratingVersion") != "1":
        return "fail", result()
    if not valid_json_number(rating.get("ratedAt")):
        return "fail", result()
    rating_refs = bundle.get("ratingRefs")
    if not (
        isinstance(rating_refs, list)
        and set(rating_ref) == {"anchor", "contentHash", "signer"}
        and rating_ref.get("contentHash") == artifact_hash(rating)
        and rating_ref.get("signer") == rating["signature"].get("signer")
        and rating_ref in rating_refs
        and rating.get("jobId") == bundle.get("jobId")
    ):
        return "fail", result()
    rater = rating.get("rater")
    target = rating.get("target")
    if not (
        nonempty_string(rater)
        and nonempty_string(target)
        and rater in claim_to_role
        and target in claim_to_role
        and rater != target
        and rating["signature"].get("signer") == rater
        and rating.get("targetRole") == claim_to_role[target]
    ):
        return "fail", result()
    value = rating.get("value")
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 5:
        return "fail", result()
    free_text = rating.get("freeText")
    if "freeText" in rating and (not isinstance(free_text, str) or len(free_text) > 1000):
        return "fail", result()
    dimensions = rating.get("dimensions")
    if "dimensions" in rating and (
        not isinstance(dimensions, dict)
        or any(
            not (
                (isinstance(score, int) and not isinstance(score, bool))
                or (isinstance(score, float) and math.isfinite(score))
            )
            for score in dimensions.values()
        )
    ):
        return "fail", result()
    pipeline = listing.get("effectivePipeline")
    if not isinstance(pipeline, list) or pipeline.count("rate") != 1:
        return "fail", result()
    index = pipeline.index("rate")
    summary = bundle.get("phaseSummary")
    if not isinstance(summary, list):
        return "fail", result()
    matching = [
        entry for entry in summary
        if isinstance(entry, dict)
        and entry.get("index") == index
        and entry.get("kind") == "rate"
    ]
    if len(matching) != 1 or matching[0].get("outcome") != "ok":
        return "fail", result()
    exact_outcome, outcome = outcome_status(data)
    if exact_outcome != "pass" or outcome.get("proofKind") != "completed-session":
        return exact_outcome, result()
    return "pass", result(admitted=True, rating=True)


def evaluate(vector, *, challenge_store=None, verifier_now=None):
    data = vector.get("input")
    if not isinstance(data, dict):
        return {"expected": "fail", "want": result()}
    trusted_context = vector.get("trustedContext")
    if not admits_spa_current_profile(data, trusted_context):
        return {"expected": "fail", "want": result()}
    if data.get("mode") == "one-sided-blame":
        fixture = vector.get("verifierFixture", fixture_verifier_state())
        if not isinstance(fixture, dict):
            return {"expected": "indeterminate", "want": result()}
        clock = fixture.get("clock")
        challenge_policy = fixture.get("challengePolicy")
        records = fixture.get("challengeState")
        anchor_binding = fixture.get("anchorBinding")
        if (
            not isinstance(clock, dict)
            or not isinstance(challenge_policy, dict)
            or set(challenge_policy) != {"duration"}
            or not isinstance(records, list)
        ):
            return {"expected": "indeterminate", "want": result()}
        if challenge_store is None:
            challenge_store = ChallengeStore(records, challenge_policy["duration"])
        if verifier_now is None:
            verifier_now = clock.get("now")
        verdict, wanted = evaluate_one_sided(
            data,
            challenge_store=challenge_store,
            verifier_now=verifier_now,
            anchor_binding=anchor_binding,
        )
    elif data.get("mode") == "rating":
        verdict, wanted = evaluate_rating(data)
    else:
        verdict, wanted = "fail", result()
    return {"expected": verdict, "want": wanted}


class ReputationParticipationVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.vectors = {item["name"]: item for item in cls.document["vectors"]}

    def test_vector_metadata(self):
        vectors = self.document["vectors"]
        self.assertEqual(self.document["count"], len(vectors))
        self.assertEqual(self.document["hash"], vector_hash(vectors))
        self.assertEqual(len(self.vectors), len(vectors))
        self.assertIn("fixture-only", self.document["inputModel"])
        self.assertIn("no production nonresponse authority", self.document["inputModel"])
        self.assertIn("currentProfile boolean is inert", self.document["inputModel"])
        self.assertIn("actingFor", self.document["challengeAuthorityModel"])
        self.assertIn("source-pinned synthetic Agreement", self.document["agreementSourceAuthorityModel"])
        self.assertIn("independent fixture binding context", self.document["anchorHistoryModel"])
        self.assertIn("consumed before later checks", self.document["challengeAuthorityModel"])
        self.assertIn("verifier-owned trustedContext", self.document["profileAuthorityModel"])
        self.assertIn("immutable corrective-profile pin", self.document["profileAuthorityModel"])
        self.assertIn("complete module tuple", self.document["profileAuthorityModel"])

    def test_independent_reference_evaluator(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    evaluate(vector),
                    {"expected": vector["expected"], "want": vector["want"]},
                )

    def test_generator_is_deterministic(self):
        completed = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_acceptance_attacks_are_explicit(self):
        required = {
            "spa-never-participant-missing-admission",
            "spa-signed-unknown-admission-field",
            "spa-duplicate-buyer-role-resigned",
            "spa-duplicate-primary-claim-resigned",
            "spa-rfq-turn-hash-mismatch",
            "spa-rfq-expected-responder-mismatch",
            "spa-rfq-unrelated-malformed-and-unavailable-sources-ignored",
            "spa-rfq-duplicate-exact-source",
            "spa-commit-proposal-hash-mismatch",
            "spa-timeout-commit-proposal-mismatch",
            "spa-signed-receipt-transaction-substitution",
            "spa-signed-receipt-writer-substitution",
            "spa-signed-receipt-nonce-substitution",
            "spa-signed-receipt-native-order-substitution",
            "spa-marker-only-receipt-history",
            "spa-selected-receipt-not-in-history",
            "spa-conflicting-finalized-receipt-history",
            "spa-producer-nonce-reuse-claim-is-inert",
            "spa-producer-fresh-flag-cannot-authorize",
            "spa-missing-outcome-authority",
            "spa-rating-outcome-authority-unavailable",
            "spa-outsider-issued-challenge",
            "spa-valid-roster-orchestrator-challenge",
            "spa-orchestrator-challenge-missing-delegation",
            "spa-orchestrator-challenge-wrong-party-delegation",
            "spa-unsigned-orchestrator-delegation-is-inert",
            "spa-valid-direct-challenge-with-orchestrator-roster",
            "spa-commit-arbitrary-hash-matching-object",
            "spa-commit-proposal-wrong-job",
            "spa-commit-proposal-wrong-listing",
            "spa-commit-proposal-invalid-signature",
            "spa-commit-proposal-source-unavailable",
            "spa-commit-proposer-substitution",
            "spa-commit-obligor-already-cosigned",
            "spa-valid-forward-agreement-member",
            "spa-valid-adapter-authorized-alternate-writer",
            "spa-valid-nonce-less-portable-receipt",
            "spa-required-receipt-nonce-missing",
            "spa-receipt-nonce-binding-context-mismatch",
            "spa-valid-optional-block-members-in-history",
            "spa-valid-finalized-block-without-height",
            "spa-finalized-receipt-missing-deadline-timestamp",
            "spa-finalized-receipt-missing-block-id",
            "spa-finalized-receipt-malformed-height",
            "spa-resealed-receipt-writer-array",
            "spa-resealed-receipt-writer-object",
            "spa-resealed-receipt-writer-empty",
            "spa-resealed-receipt-nonce-object",
            "spa-resealed-receipt-native-address-array",
            "spa-resealed-receipt-native-address-empty",
            "spa-resealed-receipt-content-not-hash",
            "spa-rating-valid-free-text",
            "spa-rating-valid-dimensions",
            "spa-rating-valid-fractional-rated-at",
            "spa-rating-valid-negative-rated-at",
            "spa-rating-rated-at-string",
            "spa-rating-rated-at-array",
            "spa-rating-rated-at-object",
            "spa-rating-rated-at-boolean",
            "spa-valid-forward-channel-envelope-member",
            "spa-supported-channel-algorithm-unavailable",
            "spa-rating-supported-algorithm-unavailable",
            "spa-valid-incoming-replacement-lineage",
            "spa-missing-replacement-predecessor",
            "spa-branched-replacement-history",
            "spa-cyclic-replacement-history",
            "spa-late-replacement-edge",
            "spa-finalized-predecessor-replaced",
            "spa-roster-role-list-resigned",
            "spa-roster-role-object-resigned",
            "spa-receipt-state-list",
            "spa-receipt-state-object",
            "spa-unissued-verifier-challenge-fails",
            "spa-expired-verifier-challenge-fails",
            "spa-blame-profile-authority-absent",
            "spa-blame-profile-authority-unauthenticated",
            "spa-blame-profile-authority-duplicate",
            "spa-blame-profile-pin-mismatch",
            "spa-blame-profile-tuple-mismatch",
            "spa-blame-profile-session-mismatch",
            "spa-blame-profile-identity-mismatch",
            "spa-blame-caller-currentprofile-only",
            "spa-blame-caller-copied-profile-object-inert",
            "spa-rating-profile-authority-absent",
            "spa-rating-profile-authority-unauthenticated",
            "spa-rating-profile-authority-duplicate",
            "spa-rating-profile-pin-mismatch",
            "spa-rating-profile-tuple-mismatch",
            "spa-rating-profile-session-mismatch",
            "spa-rating-profile-identity-mismatch",
            "spa-rating-caller-currentprofile-only",
            "spa-rating-caller-copied-profile-object-inert",
            "spa-blame-trusted-context-omitted",
            "spa-rating-trusted-context-omitted",
        }
        self.assertLessEqual(required, set(self.vectors))

    def test_resigned_malformed_artifacts_reach_semantic_gates(self):
        for name in (
            "spa-signed-unknown-admission-field",
            "spa-duplicate-buyer-role-resigned",
            "spa-rfq-turn-hash-mismatch",
            "spa-commit-proposal-hash-mismatch",
            "spa-roster-role-list-resigned",
            "spa-roster-role-object-resigned",
        ):
            admission = self.vectors[name]["input"]["participationEvidence"]["admission"]
            with self.subTest(vector=name):
                self.assertTrue(verify_signed_artifact(
                    admission,
                    PARTICIPATION_DOMAIN,
                    set(admission) - {"signature"},
                ))
                self.assertNotEqual(evaluate(self.vectors[name])["expected"], "pass")

    def test_duplicate_role_and_claim_fixtures_preserve_other_authority(self):
        duplicate = self.vectors["spa-duplicate-primary-claim-resigned"]
        self.assertEqual(evaluate(duplicate)["expected"], "fail")
        duplicate_role = self.vectors["spa-duplicate-buyer-role-resigned"]
        parties = duplicate_role["input"]["bundle"]["parties"]
        roles = [party["role"] for party in parties]
        claims = [party["primaryClaim"] for party in parties]
        self.assertIn("buyer", roles)
        self.assertIn("seller", roles)
        self.assertEqual(roles.count("buyer"), 2)
        self.assertEqual(len(claims), len(set(claims)))
        self.assertEqual(evaluate(duplicate_role)["expected"], "fail")

    def test_positive_hashes_signatures_receipts_and_history_are_exact(self):
        for vector in self.document["vectors"]:
            if vector["expected"] != "pass":
                continue
            data = vector["input"]
            with self.subTest(vector=vector["name"]):
                if data["mode"] == "one-sided-blame":
                    evidence = data["participationEvidence"]
                    admission = evidence["admission"]
                    self.assertTrue(verify_signed_artifact(
                        admission, PARTICIPATION_DOMAIN, ADMISSION_FIELDS
                    ))
                    self.assertEqual(evidence["admissionRef"]["contentHash"], artifact_hash(admission))
                    self.assertIn(
                        evidence["admissionReceipt"],
                        canonical_receipt_history(evidence["admissionReceiptHistory"]),
                    )
                else:
                    self.assertTrue(verify_signed_artifact(
                        data["rating"], RATING_DOMAIN, RATING_FIELDS,
                        RATING_OPTIONAL_FIELDS,
                    ))
                    self.assertEqual(data["ratingRef"]["contentHash"], artifact_hash(data["rating"]))

    def test_portable_receipt_wire_and_authenticated_lineage(self):
        vector = self.vectors["spa-valid-incoming-replacement-lineage"]
        evidence = vector["input"]["participationEvidence"]
        for receipt in evidence["admissionReceiptHistory"]:
            with self.subTest(transaction=receipt["transactionRef"]):
                self.assertNotIn("adapterEvidence", receipt)
                self.assertNotIn("nativeOrder", receipt)
                self.assertNotIn("replacementRelation", receipt)
                self.assertEqual(set(receipt["evidence"]), {"kind", "value"})
                adapter_result = decode_canonical_object(receipt["evidence"]["value"])
                self.assertIsInstance(adapter_result, dict)
                self.assertIn("nativeOrder", adapter_result)
                self.assertIn("lineageRootTransactionRef", adapter_result)
        verdict, selected = receipt_status(
            vector["input"],
            evidence["admission"],
            evidence["admission"]["signature"]["signer"],
            vector["verifierFixture"]["anchorBinding"],
        )
        self.assertEqual(verdict, "pass")
        self.assertEqual(selected, evidence["admissionReceipt"])

        for name in (
            "spa-valid-adapter-authorized-alternate-writer",
            "spa-valid-nonce-less-portable-receipt",
            "spa-valid-empty-string-nonce",
            "spa-valid-optional-block-members-in-history",
            "spa-valid-finalized-block-without-height",
        ):
            with self.subTest(compatible_receipt=name):
                data = self.vectors[name]["input"]
                admission = data["participationEvidence"]["admission"]
                self.assertEqual(
                    receipt_status(
                        data,
                        admission,
                        admission["signature"]["signer"],
                        self.vectors[name]["verifierFixture"]["anchorBinding"],
                    )[0],
                    "pass",
                )
        missing_timestamp = self.vectors[
            "spa-finalized-receipt-missing-deadline-timestamp"
        ]["input"]
        missing_admission = missing_timestamp["participationEvidence"]["admission"]
        self.assertEqual(
            receipt_status(
                missing_timestamp,
                missing_admission,
                missing_admission["signature"]["signer"],
                self.vectors[
                    "spa-finalized-receipt-missing-deadline-timestamp"
                ]["verifierFixture"]["anchorBinding"],
            )[0],
            "indeterminate",
        )
        for name in (
            "spa-finalized-receipt-missing-block-id",
            "spa-finalized-receipt-malformed-height",
        ):
            malformed = self.vectors[name]
            malformed_data = malformed["input"]
            malformed_admission = malformed_data["participationEvidence"]["admission"]
            with self.subTest(malformed_block=name):
                self.assertEqual(
                    receipt_status(
                        malformed_data,
                        malformed_admission,
                        malformed_admission["signature"]["signer"],
                        malformed["verifierFixture"]["anchorBinding"],
                    )[0],
                    "indeterminate",
                )

    def test_resealed_malformed_receipt_bindings_fail_schema_before_use(self):
        names = (
            "spa-resealed-receipt-writer-array",
            "spa-resealed-receipt-writer-object",
            "spa-resealed-receipt-writer-empty",
            "spa-resealed-receipt-nonce-object",
            "spa-resealed-receipt-native-address-array",
            "spa-resealed-receipt-native-address-empty",
            "spa-resealed-receipt-content-not-hash",
        )
        for name in names:
            data = self.vectors[name]["input"]
            evidence = data["participationEvidence"]
            receipt = evidence["admissionReceiptHistory"][0]
            expected = {
                field: copy.deepcopy(receipt[field])
                for field in ANCHOR_BINDING_FIELDS
                if field in receipt
            }
            with self.subTest(resealed_binding=name):
                self.assertEqual(
                    inspect_anchor_receipt(
                        receipt,
                        expected_binding=expected,
                        adapter_domain=ANCHOR_ADAPTER_DOMAIN,
                        adapter_policy=ANCHOR_POLICY,
                        trusted_adapter=TRUSTED_ADAPTER,
                        authorized_signer=evidence["admission"]["signature"]["signer"],
                    )[0],
                    "fail",
                )

    def test_pre_cosign_agreement_source_is_authenticated_and_hash_exact(self):
        for name in ("spa-valid-commit-obligation", "spa-valid-forward-agreement-member"):
            data = self.vectors[name]["input"]
            admission = data["participationEvidence"]["admission"]
            role_to_claim, _ = party_maps(admission["parties"])
            proposal = data["proposedAgreement"]
            with self.subTest(valid_proposal=name):
                self.assertEqual(
                    admission["obligation"]["source"]["proposedAgreementHash"],
                    artifact_hash(proposal, signature_field="signatures"),
                )
                self.assertEqual(
                    verify_proposed_agreement(data, admission, role_to_claim), "pass"
                )
        for name in (
            "spa-commit-arbitrary-hash-matching-object",
            "spa-commit-proposal-wrong-job",
            "spa-commit-proposal-wrong-listing",
            "spa-commit-proposal-wrong-pattern",
            "spa-commit-proposal-invalid-signature",
            "spa-commit-proposer-substitution",
            "spa-commit-obligor-already-cosigned",
            "spa-commit-artifact-phase-mismatch",
        ):
            with self.subTest(rejected_proposal=name):
                self.assertEqual(evaluate(self.vectors[name])["expected"], "fail")
        for name in (
            "spa-commit-proposal-algorithm-unavailable",
            "spa-commit-proposal-source-unavailable",
            "spa-commit-proposal-signature-missing",
        ):
            with self.subTest(unavailable_proposal=name):
                self.assertEqual(evaluate(self.vectors[name])["expected"], "indeterminate")

    def test_rated_at_uses_core_number_profile(self):
        for value in (-1, 0, 2_200.5, 2**53 - 1):
            with self.subTest(valid=value):
                self.assertTrue(valid_json_number(value))
        for value in (True, "2200", [], {}, math.nan, math.inf, -(math.inf), 2**53):
            with self.subTest(invalid=repr(value)):
                self.assertFalse(valid_json_number(value))

        base = self.vectors["spa-rating-valid-buyer-to-seller"]
        for value in (math.nan, math.inf, 2**53):
            malformed = copy.deepcopy(base)
            malformed["input"]["rating"]["ratedAt"] = value
            with self.subTest(noncanonical_in_memory=repr(value)):
                self.assertEqual(evaluate(malformed)["expected"], "fail")

    def test_supported_unavailable_and_unknown_algorithms_are_distinct(self):
        for name in (
            "spa-supported-channel-algorithm-unavailable",
            "spa-supported-receipt-algorithm-unavailable",
            "spa-rating-supported-algorithm-unavailable",
            "spa-rating-ed25519-claim-resolution-unavailable",
        ):
            with self.subTest(vector=name):
                self.assertEqual(evaluate(self.vectors[name])["expected"], "indeterminate")
        for name in ("spa-unknown-channel-algorithm", "spa-rating-unknown-algorithm"):
            with self.subTest(vector=name):
                self.assertEqual(evaluate(self.vectors[name])["expected"], "fail")

    def test_decoded_container_variants_are_total(self):
        from scripts import generate_reputation_participation_vectors as g
        for disposition in ([], {}, True, 1, None):
            case = g.resealed_receipts_changed(
                g.one_sided_input(),
                lambda receipt: receipt.update(observationDisposition=disposition),
            )
            with self.subTest(disposition=disposition):
                result = evaluate({
                    "input": case,
                    "trustedContext": g.profile_context(case["bundle"]["parties"]),
                })
                self.assertEqual("indeterminate", result["expected"])
                self.assertFalse(result["want"]["oneSidedBlame"])
                self.assertFalse(result["want"]["currentWindowCountable"])
        for name in (
            "spa-roster-role-list-resigned",
            "spa-roster-role-object-resigned",
            "spa-receipt-state-list",
            "spa-receipt-state-object",
            "spa-rating-target-list",
            "spa-rating-target-object",
            "spa-rating-algorithm-list",
            "spa-rating-algorithm-object",
        ):
            with self.subTest(vector=name):
                self.assertEqual(
                    evaluate(self.vectors[name])["expected"],
                    self.vectors[name]["expected"],
                )
        adapter_fields = {
            "anchorEvidenceVersion", "policyId", "receiptHash", "authorizedSigner",
            "nativeOrder", "lineageRootTransactionRef",
        }
        for name in ("spa-receipt-state-list", "spa-receipt-state-object"):
            receipt = self.vectors[name]["input"]["participationEvidence"][
                "admissionReceiptHistory"
            ][0]
            adapter_result = decode_canonical_object(receipt["evidence"]["value"])
            with self.subTest(signed_malformed_receipt=name):
                self.assertTrue(verify_signed_artifact(
                    adapter_result,
                    ANCHOR_ADAPTER_DOMAIN,
                    adapter_fields,
                    trusted_signer=TRUSTED_ADAPTER,
                ))
                receipt_scope = {
                    key: copy.deepcopy(value)
                    for key, value in receipt.items()
                    if key != "evidence"
                }
                self.assertEqual(adapter_result["receiptHash"], jcs_hash(receipt_scope))

    def test_unknown_nested_signed_agreement_members_remain_compatible(self):
        from scripts import generate_reputation_participation_vectors as g
        base = g.one_sided_input(
            pipeline=["vet-credentials", "negotiate-rfq", "commit-agreement"], phase_index=2
        )
        for location in ("root", "party", "deliverable", "price"):
            def mutate(proposal):
                target = {
                    "root": proposal, "party": proposal["parties"][0],
                    "deliverable": proposal["terms"]["deliverable"],
                    "price": proposal["terms"]["price"],
                }[location]
                target["futureSignedMetadata"] = {"source": "preserved"}
            case = g.proposal_changed(base, mutate)
            context = g.profile_context(case["bundle"]["parties"])
            with self.subTest(location=location):
                self.assertEqual(
                    "pass",
                    evaluate({"input": case, "trustedContext": context})["expected"],
                )
                # Unknown members remain in the signed payload; a later change
                # must still break the exact acknowledged proposal hash.
                case["proposedAgreement"]["futureUnsignedTamper"] = True
                self.assertEqual(
                    "fail",
                    evaluate({"input": case, "trustedContext": context})["expected"],
                )

    def test_challenge_state_is_verifier_owned_expiring_and_single_use(self):
        valid = self.vectors["spa-valid-rfq-turn-obligation"]
        fixture = valid["verifierFixture"]
        store = ChallengeStore(
            fixture["challengeState"], fixture["challengePolicy"]["duration"]
        )
        self.assertEqual(
            evaluate(valid, challenge_store=store)["expected"], "pass"
        )
        self.assertEqual(
            evaluate(valid, challenge_store=store)["expected"], "fail"
        )

        failed = self.vectors["spa-invalid-admission-signature"]
        failed_fixture = failed["verifierFixture"]
        failed_store = ChallengeStore(
            failed_fixture["challengeState"],
            failed_fixture["challengePolicy"]["duration"],
        )
        self.assertEqual(
            evaluate(failed, challenge_store=failed_store)["expected"], "fail"
        )
        failed_challenge = failed["input"]["sessionChallengeEvidence"]
        key = (failed_challenge["jobId"], failed_challenge["nonce"])
        self.assertEqual(failed_store.records[key]["status"], "consumed")
        self.assertEqual(
            evaluate(valid, challenge_store=failed_store)["expected"], "fail"
        )

        self.assertEqual(
            evaluate(self.vectors["spa-unissued-verifier-challenge-fails"])[
                "expected"
            ],
            "fail",
        )
        self.assertEqual(
            evaluate(self.vectors["spa-expired-verifier-challenge-fails"])["expected"],
            "fail",
        )

    def test_semantic_negative_fixtures_keep_outcome_authority_current(self):
        names = (
            "spa-roster-primary-claim-mismatch",
            "spa-duplicate-buyer-role-resigned",
            "spa-duplicate-primary-claim-resigned",
            "spa-obligor-not-faulted-party",
            "spa-timeout-obligation-mismatch",
            "spa-prefix-contradicts-bundle",
            "spa-wrong-deadline",
        )
        for name in names:
            data = self.vectors[name]["input"]
            with self.subTest(vector=name):
                self.assertTrue(data["knownOutcomeEvidence"])
                self.assertTrue(all(
                    verify_outcome_item(item, data) == "pass"
                    for item in data["knownOutcomeEvidence"]
                ))

        roster = self.vectors["spa-roster-primary-claim-mismatch"]
        roster_data = roster["input"]
        roster_admission = roster_data["participationEvidence"]["admission"]
        admitted_roles, _ = party_maps(roster_admission["parties"])
        signer = roster_admission["signature"]["signer"]
        self.assertEqual(verify_challenge(roster_data, roster_admission, signer), "pass")
        self.assertEqual(
            verify_channel_source(
                roster_data, roster_admission["obligation"]["source"], admitted_roles
            ),
            "pass",
        )
        self.assertEqual(
            receipt_status(
                roster_data,
                roster_admission,
                signer,
                roster["verifierFixture"]["anchorBinding"],
            )[0],
            "pass",
        )

        mismatch = self.vectors["spa-obligor-not-faulted-party"]
        mismatch_data = mismatch["input"]
        mismatch_admission = mismatch_data["participationEvidence"]["admission"]
        mismatch_signer = mismatch_admission["signature"]["signer"]
        mismatch_roles, _ = party_maps(mismatch_admission["parties"])
        self.assertEqual(mismatch_admission["obligation"]["obligorRole"], "buyer")
        self.assertEqual(mismatch_signer, mismatch_roles["buyer"])
        self.assertEqual(mismatch_data["bundle"]["faultedParty"], "seller")
        self.assertEqual(
            verify_challenge(mismatch_data, mismatch_admission, mismatch_signer), "pass"
        )

    def test_rfq_selects_exact_unsigned_body_before_signature_status(self):
        self.assertEqual(
            evaluate(
                self.vectors[
                    "spa-rfq-unrelated-malformed-and-unavailable-sources-ignored"
                ]
            )["expected"],
            "pass",
        )
        expectations = {
            "spa-rfq-turn-hash-mismatch": "fail",
            "spa-rfq-source-message-unavailable": "indeterminate",
            "spa-rfq-duplicate-exact-source": "fail",
            "spa-supported-channel-algorithm-unavailable": "indeterminate",
        }
        for name, expected in expectations.items():
            with self.subTest(vector=name):
                self.assertEqual(evaluate(self.vectors[name])["expected"], expected)

    def test_fixture_adapter_decoder_has_local_resource_bounds(self):
        self.assertIsNone(decode_canonical_object("A" * (FIXTURE_MAX_ENCODED_BYTES + 1)))

        oversized = b'{"value":"' + b"a" * FIXTURE_MAX_DECODED_BYTES + b'"}'
        encoded = base64.urlsafe_b64encode(oversized).rstrip(b"=").decode("ascii")
        self.assertIsNone(decode_canonical_object(encoded))

        nested = (
            '{"v":' * (FIXTURE_MAX_NESTING_DEPTH + 1)
            + "0"
            + "}" * (FIXTURE_MAX_NESTING_DEPTH + 1)
        )
        nested_encoded = base64.urlsafe_b64encode(nested.encode()).rstrip(b"=").decode("ascii")
        self.assertIsNone(decode_canonical_object(nested_encoded))

        members = {f"m{index}": index for index in range(FIXTURE_MAX_MEMBERS_AND_ELEMENTS + 1)}
        members_raw = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
        members_encoded = base64.urlsafe_b64encode(members_raw).rstrip(b"=").decode("ascii")
        self.assertIsNone(decode_canonical_object(members_encoded))

    def test_long_replacement_histories_are_iterative_and_deterministic(self):
        from scripts import generate_reputation_participation_vectors as g

        data = g.one_sided_input()
        evidence = data["participationEvidence"]
        admission = evidence["admission"]
        root = "tx-long-000"
        history = [
            g.admission_receipt(
                admission,
                transaction=f"tx-long-{index:03d}",
                replacement_transaction=f"tx-long-{index + 1:03d}",
                native_order=index + 1,
                state="replaced",
                lineage_root_transaction=root,
            )
            for index in range(128)
        ]
        final = g.admission_receipt(
            admission,
            transaction="tx-long-128",
            native_order=129,
            lineage_root_transaction=root,
        )
        evidence["admissionReceipt"] = copy.deepcopy(final)
        evidence["admissionReceiptHistory"] = [*history, final]
        binding = {"nonce": "9"}
        first = receipt_status(data, admission, admission["signature"]["signer"], binding)
        second = receipt_status(data, admission, admission["signature"]["signer"], binding)
        self.assertEqual(first[0], "pass")
        self.assertEqual(first, second)

        cyclic = copy.deepcopy(data)
        cyclic["participationEvidence"]["admissionReceiptHistory"].append(
            g.admission_receipt(
                admission,
                transaction="tx-long-128",
                replacement_transaction=root,
                native_order=130,
                state="replaced",
                lineage_root_transaction=root,
            )
        )
        self.assertEqual(
            receipt_status(
                cyclic, admission, admission["signature"]["signer"], binding
            )[0],
            "indeterminate",
        )

    def test_unavailable_or_conflicting_authority_is_not_current_countable(self):
        for name in (
            "spa-marker-only-receipt-history",
            "spa-conflicting-finalized-receipt-history",
            "spa-missing-outcome-authority",
            "spa-conflicting-outcome-evidence",
            "spa-rating-outcome-authority-unavailable",
            "spa-rating-conflicting-outcome-history",
        ):
            with self.subTest(vector=name):
                evaluated = evaluate(self.vectors[name])
                self.assertEqual(evaluated["expected"], "indeterminate")
                self.assertFalse(evaluated["want"]["currentWindowCountable"])
                self.assertFalse(evaluated["want"]["oneSidedBlame"])

    def test_verifier_owned_profile_admission_gates_both_spa_modes(self):
        positives = (
            "spa-valid-rfq-turn-obligation",
            "spa-valid-roster-orchestrator-challenge",
            "spa-rating-valid-buyer-to-seller",
        )
        for name in positives:
            with self.subTest(positive=name):
                vector = self.vectors[name]
                self.assertIsInstance(vector["trustedContext"], dict)
                self.assertEqual(evaluate(vector)["expected"], "pass")

        negative_expected = {
            "spa-blame-profile-authority-absent": "fail",
            "spa-blame-profile-authority-unauthenticated": "fail",
            "spa-blame-profile-authority-duplicate": "fail",
            "spa-blame-profile-pin-mismatch": "fail",
            "spa-blame-profile-tuple-mismatch": "fail",
            "spa-blame-profile-session-mismatch": "fail",
            "spa-blame-profile-identity-mismatch": "fail",
            "spa-blame-caller-currentprofile-only": "fail",
            "spa-blame-caller-copied-profile-object-inert": "fail",
            "spa-rating-profile-authority-absent": "fail",
            "spa-rating-profile-authority-unauthenticated": "fail",
            "spa-rating-profile-authority-duplicate": "fail",
            "spa-rating-profile-pin-mismatch": "fail",
            "spa-rating-profile-tuple-mismatch": "fail",
            "spa-rating-profile-session-mismatch": "fail",
            "spa-rating-profile-identity-mismatch": "fail",
            "spa-rating-caller-currentprofile-only": "fail",
            "spa-rating-caller-copied-profile-object-inert": "fail",
            "spa-blame-trusted-context-omitted": "fail",
            "spa-rating-trusted-context-omitted": "fail",
        }
        for name, expected in negative_expected.items():
            with self.subTest(negative=name):
                evaluated = evaluate(self.vectors[name])
                self.assertEqual(evaluated["expected"], expected)
                self.assertFalse(evaluated["want"]["currentWindowCountable"])
                self.assertFalse(evaluated["want"]["oneSidedBlame"])
                self.assertFalse(evaluated["want"]["ratingCounted"])

    def test_caller_currentprofile_boolean_and_copied_object_are_inert(self):
        valid = self.vectors["spa-valid-rfq-turn-obligation"]
        context = valid["trustedContext"]
        self.assertTrue(admits_spa_current_profile(valid["input"], context))

        # A caller-supplied boolean cannot substitute for verifier-owned context.
        self.assertFalse(admits_spa_current_profile(valid["input"], None))

        copied = copy.deepcopy(valid["input"])
        copied["localProfile"] = copy.deepcopy(R.AUTHORITATIVE_LOCAL_PROFILE)
        copied["currentProfile"] = True
        self.assertFalse(admits_spa_current_profile(copied, None))

        # The shared reference predicates back the admission gate.
        self.assertTrue(R.is_exact_corrective_profile(R.AUTHORITATIVE_LOCAL_PROFILE))
        self.assertFalse(R.is_exact_corrective_profile({
            "releasePin": "f" * 40,
            "moduleVersions": R.AUTHORITATIVE_MODULE_VERSIONS,
        }))

    def test_omitted_trusted_context_fails_closed_exactly_like_null(self):
        for positive in (
            "spa-valid-rfq-turn-obligation",
            "spa-rating-valid-buyer-to-seller",
        ):
            valid = self.vectors[positive]
            context = valid["trustedContext"]
            with self.subTest(positive=positive):
                self.assertIsInstance(context, dict)
                self.assertEqual(evaluate(valid)["expected"], "pass")

                omitted = copy.deepcopy(valid)
                omitted.pop("trustedContext", None)
                self.assertNotIn("trustedContext", omitted)
                omitted_result = evaluate(omitted)
                self.assertEqual(omitted_result["expected"], "fail")
                self.assertFalse(omitted_result["want"]["currentWindowCountable"])
                self.assertFalse(omitted_result["want"]["oneSidedBlame"])
                self.assertFalse(omitted_result["want"]["ratingCounted"])

                explicit_null = copy.deepcopy(valid)
                explicit_null["trustedContext"] = None
                self.assertEqual(
                    evaluate(explicit_null)["expected"],
                    omitted_result["expected"],
                )

                caller_copy = copy.deepcopy(omitted)
                caller_copy["input"]["localProfile"] = copy.deepcopy(
                    R.AUTHORITATIVE_LOCAL_PROFILE
                )
                caller_copy["input"]["currentProfile"] = True
                caller_result = evaluate(caller_copy)
                self.assertEqual(caller_result["expected"], "fail")
                self.assertFalse(caller_result["want"]["currentWindowCountable"])

                restored = copy.deepcopy(omitted)
                restored["trustedContext"] = context
                self.assertEqual(evaluate(restored)["expected"], "pass")

    def test_spec_and_shared_security_model_pin_repaired_spa(self):
        spec = SPEC.read_text(encoding="utf-8")
        core = CORE.read_text(encoding="utf-8")
        threat = THREAT_MODEL.read_text(encoding="utf-8")
        self.assertIn("**DACS-5 v0.7**", spec)
        self.assertIn("(SPA-1)", spec)
        self.assertIn("(SPA-8)", spec)
        self.assertIn('participationAdmissionVersion: "1"', spec)
        self.assertIn('"dacs-participation-admission:v1:"', core)
        self.assertIn("obligationHash", spec)
        self.assertIn("deadlines and publication do not prove nonresponse", spec.lower())
        self.assertIn("fixture-only", spec)
        self.assertIn("invented participant", threat.lower())
        self.assertIn("corrective-profile admission", spec.lower())
        self.assertIn("CORE §11.1.2", spec)
        self.assertIn("currentProfile", spec)
        self.assertIn("0.3", spec)
        self.assertIn("caller-supplied profile object", spec.lower())


if __name__ == "__main__":
    unittest.main()
