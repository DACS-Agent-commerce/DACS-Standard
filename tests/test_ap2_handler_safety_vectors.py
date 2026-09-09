import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import re
import subprocess
import sys
import threading
import unicodedata
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "ap2-handler-safety-v0.6.json"
SPEC = ROOT / "spec" / "DACS-4-SETTLE.md"
CORE = ROOT / "spec" / "CORE.md"
PLAN = ROOT / "spec" / "CONFORMANCE-PLAN.md"
README = ROOT / "conformance" / "vectors" / "security" / "README.md"
WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"
KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
COMPACT_JWS_RE = re.compile(
    r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\Z"
)
MISSING = object()
HASH_ALGORITHMS = {
    "sha-256": hashlib.sha256,
}
JOB_ID_RE = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}\Z", re.ASCII)
AUTHORITATIVE_RELEASE_PIN = "0000000000000000000000000000000000000001"
AUTHORITATIVE_MODULE_VERSIONS = {
    "core": "0.3",
    "dacs1": "0.7",
    "dacs2": "0.6",
    "dacs3": "0.5",
    "dacs4": "0.7",
    "dacs5": "0.5",
}
AUTHORITATIVE_LOCAL_PROFILE = {
    "releasePin": AUTHORITATIVE_RELEASE_PIN,
    "moduleVersions": AUTHORITATIVE_MODULE_VERSIONS,
}
CURRENT_SESSION_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
CURRENT_PEER_IDENTITY = "did:demos:agent:" + "22" * 32


def trusted_profile_context(
    *,
    session_id=CURRENT_SESSION_ID,
    expected_peer_identity=CURRENT_PEER_IDENTITY,
    participant_identity=None,
    authenticated=True,
    duplicate=False,
):
    participant = {
        "identity": (
            expected_peer_identity
            if participant_identity is None
            else participant_identity
        ),
        "authenticated": authenticated,
        "profile": AUTHORITATIVE_LOCAL_PROFILE,
    }
    participants = [participant]
    if duplicate:
        participants.append(dict(participant))
    return {
        "sessionId": session_id,
        "expectedPeerIdentity": expected_peer_identity,
        "participants": participants,
    }


def trusted_context_for_ap2_case(case):
    """Test harness context; deliberately not derived inside the oracle."""
    name = case["name"]
    if name == "ap2-admission-copied-profile-reference-refuses":
        return None
    if name == "ap2-admission-unauthenticated-profile-refuses":
        return trusted_profile_context(authenticated=False)
    if name == "ap2-admission-duplicate-profile-refuses":
        return trusted_profile_context(duplicate=True)
    if name == "ap2-admission-peer-identity-mismatch-refuses":
        return trusted_profile_context(
            participant_identity="did:demos:agent:" + "33" * 32
        )
    if name == "ap2-admission-session-mismatch-refuses":
        return trusted_profile_context(
            session_id="01ARZ3NDEKTSV4RRFFQ69G5FAW"
        )
    if name == "ap2-admission-noncanonical-job-errors":
        return trusted_profile_context(session_id="cafe\u0301-job")
    if name == "ap2-admission-overflow-job-errors":
        return trusted_profile_context(session_id="8" + CURRENT_SESSION_ID[1:])
    if name == "ap2-composed-cross-job-replay-refuses":
        return trusted_profile_context(session_id="01ARZ3NDEKTSV4RRFFQ69G5FAW")
    return trusted_profile_context()


def authoritative_binding_store_for_ap2_case(case):
    """Handler-owned store fixture; never recovered from checkout input."""
    transaction_id = "rtXpY7wp4o7vknuw0ZaOpynbfydEGvpoFkFUiRFpYJU"
    existing = durable_binding(
        transaction_id, CURRENT_SESSION_ID, 3, "in-flight"
    )
    recovery = durable_binding(
        transaction_id, CURRENT_SESSION_ID, 3, "recovery-pending"
    )
    referenced = durable_binding(
        transaction_id,
        CURRENT_SESSION_ID,
        3,
        "recovery-pending",
        provider_recovery_reference="provider-payment-123",
    )
    settled = durable_binding(
        transaction_id,
        CURRENT_SESSION_ID,
        3,
        "settled",
        provider_recovery_reference="provider-payment-123",
        settlement=fixture_settlement("provider-payment-123"),
    )
    stores = {
        "ap2-composed-same-tuple-inflight-resumes": [existing],
        "ap2-composed-same-tuple-settled-resumes": [settled],
        "ap2-composed-cross-job-replay-refuses": [existing],
        "ap2-composed-cross-phase-replay-refuses": [existing],
        "ap2-composed-duplicate-bindings-refuse": [existing, dict(existing)],
        "ap2-composed-conflicting-bindings-refuse": [
            existing,
            {**existing, "jobId": "01ARZ3NDEKTSV4RRFFQ69G5FAW"},
        ],
        "ap2-composed-caller-store-assertion-cannot-authorize": [existing],
        "ap2-recovery-lost-response-resubmits-same-key": [recovery],
        "ap2-recovery-reference-reconciles-captured": [referenced],
        "ap2-recovery-reference-not-captured-resubmits-same-key": [referenced],
    }
    return stores.get(case["name"], [])


def provider_status_for_ap2_case(case):
    status = case.get("providerStatus")
    if status == "captured":
        return lambda ref: {
            "status": "captured",
            "providerRecoveryReference": ref,
            "settlement": fixture_settlement(ref),
        }
    if status == "not-captured":
        return lambda ref: {
            "status": "not-captured",
            "providerRecoveryReference": ref,
        }
    return None


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def derive_key(job_id, phase_index):
    if not isinstance(job_id, str) or JOB_ID_RE.fullmatch(job_id) is None:
        raise ValueError("jobId must satisfy JID-1")
    if type(phase_index) is not int or phase_index < 0:
        raise ValueError("phaseIndex must be a non-negative integer")
    preimage = (
        b"dacs-ap2-idem:v1:"
        + unicodedata.normalize("NFC", job_id).encode("utf-8")
        + b":"
        + str(phase_index).encode("ascii")
    )
    return hashlib.sha256(preimage).hexdigest()


def derive_transaction_id(checkout_jws, sd_alg=MISSING):
    if (
        not isinstance(checkout_jws, str)
        or not COMPACT_JWS_RE.fullmatch(checkout_jws)
    ):
        raise ValueError("checkoutJws must be an unpadded RFC 7515 compact JWS")
    algorithm = "sha-256" if sd_alg is MISSING else sd_alg
    if not isinstance(algorithm, str) or algorithm not in HASH_ALGORITHMS:
        raise ValueError("_sd_alg is unsupported")
    digest = HASH_ALGORITHMS[algorithm](checkout_jws.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def fixture_provider_request(job_id):
    """Deterministic local provider request; never used as a consumer fallback."""
    return {
        "providerEndpoint": "https://provider.example.invalid/payments",
        "paymentMandate": "fixture-payment-mandate-v1",
        "checkoutId": "checkout-123",
        "payee": "merchant-fixture",
        "amount": "10.00",
        "currency": "USD",
        "instrument": "fixture-instrument-1",
        "metadata": {"dacs_job_id": job_id},
    }


def operation_payload(transaction_id, job_id, phase_index, provider_request):
    """Bind the complete effect-bearing provider request, including metadata."""
    return {
        "transactionId": transaction_id,
        "jobId": job_id,
        "phaseIndex": phase_index,
        "providerRequest": provider_request,
    }


def operation_fingerprint(payload):
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def durable_binding(
    transaction_id,
    job_id,
    phase_index,
    state,
    *,
    provider_recovery_reference=MISSING,
    settlement=MISSING,
    payload=MISSING,
    idempotency_key=MISSING,
    fingerprint=MISSING,
):
    payload = (
        operation_payload(transaction_id, job_id, phase_index, fixture_provider_request(job_id))
        if payload is MISSING
        else payload
    )
    entry = {
        "transactionId": transaction_id,
        "jobId": job_id,
        "phaseIndex": phase_index,
        "state": state,
        "idempotencyKey": (
            derive_key(job_id, phase_index)
            if idempotency_key is MISSING
            else idempotency_key
        ),
        "operationFingerprint": (
            operation_fingerprint(payload)
            if fingerprint is MISSING
            else fingerprint
        ),
        "operationPayload": copy.deepcopy(payload),
    }
    if provider_recovery_reference is not MISSING:
        entry["providerRecoveryReference"] = provider_recovery_reference
    if state == "settled" and settlement is MISSING:
        settlement = {"status": "captured", "transactionId": transaction_id, "operationFingerprint": operation_fingerprint(payload)}
    if settlement is not MISSING:
        entry["settlement"] = copy.deepcopy(settlement)
    return entry


def provider_request_valid(request, job_id):
    if not isinstance(request, dict) or not {
        "providerEndpoint", "paymentMandate", "checkoutId", "payee", "amount",
        "currency", "instrument", "metadata",
    } <= set(request):
        return False
    if any(not isinstance(request.get(field), str) or not request[field] for field in (
        "providerEndpoint", "paymentMandate", "checkoutId", "payee", "amount", "currency", "instrument",
    )):
        return False
    metadata = request.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("dacs_job_id") != job_id:
        return False
    try:
        canonical_json(request)
    except (TypeError, ValueError, UnicodeError):
        return False
    return True


def settlement_matches(settlement, transaction_id, fingerprint, provider_ref=None):
    return (
        isinstance(settlement, dict)
        and settlement.get("status") == "captured"
        and settlement.get("transactionId") == transaction_id
        and settlement.get("operationFingerprint") == fingerprint
        and (provider_ref is None or settlement.get("providerRef") == provider_ref)
    )


def fixture_settlement(provider_ref):
    transaction_id = "rtXpY7wp4o7vknuw0ZaOpynbfydEGvpoFkFUiRFpYJU"
    payload = operation_payload(transaction_id, CURRENT_SESSION_ID, 3, fixture_provider_request(CURRENT_SESSION_ID))
    return {
        "status": "captured", "providerRef": provider_ref,
        "transactionId": transaction_id,
        "operationFingerprint": operation_fingerprint(payload),
    }


def _durable_binding_valid(entry):
    required = {
        "transactionId", "jobId", "phaseIndex", "state", "idempotencyKey",
        "operationFingerprint", "operationPayload",
    }
    optional = {"providerRecoveryReference", "settlement"}
    if not isinstance(entry, dict) or not required <= set(entry) <= required | optional:
        return False
    try:
        recomputed_fingerprint = operation_fingerprint(entry.get("operationPayload"))
        recomputed_key = derive_key(entry.get("jobId"), entry.get("phaseIndex"))
    except (TypeError, ValueError, UnicodeError):
        return False
    if (
        not isinstance(entry.get("transactionId"), str)
        or not entry["transactionId"]
        or not isinstance(entry.get("jobId"), str)
        or JOB_ID_RE.fullmatch(entry["jobId"]) is None
        or type(entry.get("phaseIndex")) is not int
        or entry["phaseIndex"] < 0
        or not isinstance(entry.get("state"), str)
        or entry.get("state") not in {"in-flight", "recovery-pending", "settled"}
        or not isinstance(entry.get("operationPayload"), dict)
        or not isinstance(entry.get("operationFingerprint"), str)
        or not KEY_RE.fullmatch(entry["operationFingerprint"])
        or entry["operationFingerprint"]
        != recomputed_fingerprint
        or not isinstance(entry.get("idempotencyKey"), str)
        or entry["idempotencyKey"] != recomputed_key
        or set(entry["operationPayload"]) != {
            "transactionId", "jobId", "phaseIndex", "providerRequest",
        }
        or any(entry["operationPayload"].get(field) != entry[field]
               for field in ("transactionId", "jobId", "phaseIndex"))
        or not provider_request_valid(entry["operationPayload"].get("providerRequest"), entry["jobId"])
    ):
        return False
    if "providerRecoveryReference" in entry and (
        not isinstance(entry["providerRecoveryReference"], str)
        or not entry["providerRecoveryReference"]
    ):
        return False
    if entry["state"] == "in-flight" and "providerRecoveryReference" in entry:
        return False
    if entry["state"] == "settled":
        return settlement_matches(entry.get("settlement"), entry["transactionId"], entry["operationFingerprint"], entry.get("providerRecoveryReference"))
    return "settlement" not in entry


def evaluate_transaction_binding(transaction_id, job_id, phase_index, prior, provider_request):
    """Classify an atomic durable reservation/recovery decision."""
    if not isinstance(prior, list):
        return "error", "refuse-conflict", False
    for entry in prior:
        if not _durable_binding_valid(entry):
            return "error", "refuse-conflict", False
    matches = [entry for entry in prior if entry["transactionId"] == transaction_id]
    if len(matches) > 1:
        return "error", "refuse-conflict", False
    if not matches:
        if not provider_request_valid(provider_request, job_id):
            return "error", "refuse-conflict", False
        return "pass", "bind-new", True
    bound = matches[0]
    same_tuple = (
        bound["jobId"] == job_id
        and bound["phaseIndex"] == phase_index
    )
    if not same_tuple:
        return "fail", "reject-replay", False
    if not provider_request_valid(provider_request, job_id):
        return "error", "refuse-conflict", False
    expected_payload = operation_payload(transaction_id, job_id, phase_index, provider_request)
    if (
        bound["idempotencyKey"] != derive_key(job_id, phase_index)
        or bound["operationPayload"] != expected_payload
        or bound["operationFingerprint"] != operation_fingerprint(expected_payload)
    ):
        return "error", "refuse-conflict", False
    if bound.get("state") == "settled":
        return "pass", "resume-settlement", False
    if bound.get("state") == "recovery-pending":
        if "providerRecoveryReference" in bound:
            return "pass", "reconcile-reference", False
        return "pass", "resubmit-same-key", False
    if bound.get("state") == "in-flight":
        return "pass", "resubmit-same-key", False
    return "error", "refuse-conflict", False


BINDING_STORE_LOCK = threading.Lock()


def reserve_or_resolve_transaction_binding(transaction_id, job_id, phase_index, store, provider_request):
    """Serialized in-process fixture CAS; production requires a durable atomic store."""
    with BINDING_STORE_LOCK:
        result = evaluate_transaction_binding(transaction_id, job_id, phase_index, store, provider_request)
        if result == ("pass", "bind-new", True):
            store.append(durable_binding(
                transaction_id, job_id, phase_index, "in-flight",
                payload=operation_payload(transaction_id, job_id, phase_index, provider_request),
            ))
        return result


def transition_binding(store, transaction_id, expected_fingerprint, **changes):
    """Atomic state transition that preserves operation/key continuity."""
    if set(changes) - {"state", "providerRecoveryReference", "settlement"}:
        raise ValueError("binding transition malformed: immutable operation fields")
    with BINDING_STORE_LOCK:
        matches = [
            entry for entry in store
            if isinstance(entry, dict)
            and entry.get("transactionId") == transaction_id
        ]
        if len(matches) != 1 or not _durable_binding_valid(matches[0]):
            raise ValueError("binding continuity unavailable")
        entry = matches[0]
        if entry["operationFingerprint"] != expected_fingerprint:
            raise ValueError("binding continuity conflict")
        candidate = copy.deepcopy(entry)
        for key, value in changes.items():
            if value is MISSING:
                candidate.pop(key, None)
            else:
                candidate[key] = copy.deepcopy(value)
        if not _durable_binding_valid(candidate):
            raise ValueError("binding transition malformed")
        entry.clear()
        entry.update(candidate)


def evaluate_signature_policy(case):
    return (
        "pass"
        if case.get("signatureGeneration") == "non-deterministic"
        and case.get("algorithm") != "Ed25519"
        else "fail"
    )


def is_exact_corrective_profile(profile):
    if not isinstance(profile, dict):
        return False
    pin = profile.get("releasePin")
    modules = profile.get("moduleVersions")
    return (
        set(profile) == {"releasePin", "moduleVersions"}
        and
        isinstance(pin, str)
        and pin == AUTHORITATIVE_RELEASE_PIN
        and isinstance(modules, dict)
        and set(modules) == set(AUTHORITATIVE_MODULE_VERSIONS)
        and all(isinstance(value, str) for value in modules.values())
        and modules == AUTHORITATIVE_MODULE_VERSIONS
    )


def admits_current_profile(case, trusted_context):
    if any(
        field in case for field in ("localProfile", "peerProfile", "peerProfileRef")
    ):
        return False
    session_id = case.get("jobId")
    peer_identity = case.get("peerIdentity")
    if not isinstance(session_id, str) or not isinstance(peer_identity, str):
        return False
    if (
        not isinstance(trusted_context, dict)
        or set(trusted_context) != {
            "sessionId", "expectedPeerIdentity", "participants"
        }
    ):
        return False
    if trusted_context.get("sessionId") != session_id:
        return False
    expected_peer_identity = trusted_context.get("expectedPeerIdentity")
    if (
        not isinstance(expected_peer_identity, str)
        or peer_identity != expected_peer_identity
    ):
        return False
    participants = trusted_context.get("participants")
    if not isinstance(participants, list) or not participants:
        return False
    for participant in participants:
        if (
            not isinstance(participant, dict)
            or set(participant) != {"identity", "authenticated", "profile"}
            or not isinstance(participant.get("identity"), str)
            or not participant["identity"]
            or type(participant.get("authenticated")) is not bool
            or not is_exact_corrective_profile(participant.get("profile"))
        ):
            return False
    if len({p["identity"] for p in participants}) != len(participants):
        return False
    matches = [
        participant
        for participant in participants
        if participant["identity"] == expected_peer_identity
    ]
    return (
        len(matches) == 1
        and matches[0].get("authenticated") is True
        and is_exact_corrective_profile(AUTHORITATIVE_LOCAL_PROFILE)
        and is_exact_corrective_profile(matches[0].get("profile"))
    )


def evaluate_checkout_payment_admission(
    case, trusted_context=None, authoritative_binding_store=None,
    provider_submit=None, provider_status=None,
):
    no_effects = {
        "hashCalls": 0,
        "resolverCalls": 0,
        "metadataCalls": 0,
        "bindingStoreCalls": 0,
        "providerStatusCalls": 0,
        "providerRequestCalls": 0,
        "bindingAction": None,
        "operationOrder": [],
        "reserveAp2Binding": False,
        "submitProviderPayment": False,
        "submitNewPayment": False,
        "idempotencyKeys": [],
    }
    if not admits_current_profile(case, trusted_context):
        return "fail", None, no_effects
    job_id = case.get("jobId")
    phase_index = case.get("phaseIndex")
    if not isinstance(job_id, str) or JOB_ID_RE.fullmatch(job_id) is None:
        return "error", None, no_effects
    if type(phase_index) is not int or phase_index < 0:
        return "error", None, no_effects
    if not all(
        case.get(field) is True
        for field in (
            "checkoutMandatePresent",
            "checkoutMandateVerified",
            "paymentMandatePresent",
            "paymentMandateVerified",
        )
    ):
        return "fail", None, no_effects
    if evaluate_signature_policy(case) != "pass":
        return "fail", None, no_effects
    effects = dict(no_effects)
    effects["resolverCalls"] += 1
    try:
        idempotency_key = derive_key(job_id, phase_index)
        effects["hashCalls"] += 1
        transaction_id = derive_transaction_id(
            case.get("checkoutJws"), case.get("_sd_alg", MISSING)
        )
        effects["hashCalls"] += 1
    except ValueError:
        return "error", None, effects
    if case.get("paymentTransactionId") != transaction_id:
        return "fail", transaction_id, effects
    effects["bindingStoreCalls"] += 1
    effects["operationOrder"].append("atomicBindingStoreDecision")
    binding_verdict, binding_action, submit_new = reserve_or_resolve_transaction_binding(
        transaction_id,
        job_id,
        phase_index,
        authoritative_binding_store,
        copy.deepcopy(case.get("providerRequest")),
    )
    effects["bindingAction"] = binding_action
    if binding_verdict != "pass":
        return binding_verdict, transaction_id, effects
    # Dispatch the retained request, never a fresh caller projection.
    retained = next(entry for entry in authoritative_binding_store if entry["transactionId"] == transaction_id)
    payload = copy.deepcopy(retained["operationPayload"])
    fingerprint = retained["operationFingerprint"]
    idempotency_key = retained["idempotencyKey"]
    if binding_action == "resume-settlement":
        return "pass", transaction_id, effects

    if binding_action == "reconcile-reference":
        stored = next(
            entry for entry in authoritative_binding_store
            if entry.get("transactionId") == transaction_id
        )
        provider_ref = stored["providerRecoveryReference"]
        effects["providerStatusCalls"] += 1
        effects["operationOrder"].append("fetchProviderStatus")
        status = provider_status(provider_ref) if provider_status is not None else None
        if not isinstance(status, dict) or status.get("providerRecoveryReference") != provider_ref:
            return "error", transaction_id, effects
        if status.get("status") == "captured" and set(status) == {
            "status", "providerRecoveryReference", "settlement"
        } and settlement_matches(status.get("settlement"), transaction_id, fingerprint, provider_ref):
            transition_binding(
                authoritative_binding_store,
                transaction_id,
                fingerprint,
                state="settled",
                settlement=status["settlement"],
            )
            effects["bindingAction"] = "resume-settlement"
            return "pass", transaction_id, effects
        if status.get("status") == "pending" and set(status) == {
            "status", "providerRecoveryReference"
        }:
            return "pass", transaction_id, effects
        if status.get("status") == "not-captured" and set(status) == {
            "status", "providerRecoveryReference"
        }:
            transition_binding(
                authoritative_binding_store,
                transaction_id,
                fingerprint,
                state="in-flight",
                providerRecoveryReference=MISSING,
            )
            binding_action = "resubmit-same-key"
            effects["bindingAction"] = binding_action
        else:
            return "error", transaction_id, effects

    if binding_action == "bind-new":
        effects["reserveAp2Binding"] = True
        effects["metadataCalls"] += 1
        effects["operationOrder"].append("constructProviderMetadata")
    elif binding_action == "resubmit-same-key":
        transition_binding(
            authoritative_binding_store,
            transaction_id,
            fingerprint,
            state="in-flight",
        )
    else:
        return "error", transaction_id, effects

    effects["submitProviderPayment"] = True
    effects["submitNewPayment"] = submit_new
    effects["providerRequestCalls"] += 1
    effects["idempotencyKeys"].append(idempotency_key)
    effects["operationOrder"].append("submitProviderPayment")
    request = {
        "transactionId": transaction_id,
        "idempotencyKey": idempotency_key,
        "operationFingerprint": fingerprint,
        "operationPayload": copy.deepcopy(payload),
        "submitNewPayment": submit_new,
    }
    if provider_submit is not None:
        try:
            response = provider_submit(request)
        except Exception:
            transition_binding(
                authoritative_binding_store,
                transaction_id,
                fingerprint,
                state="recovery-pending",
            )
            raise
        if response is not None:
            if (
                not isinstance(response, dict)
                or not isinstance(response.get("providerRecoveryReference"), str)
                or not response["providerRecoveryReference"]
                or response.get("status") not in {"pending", "captured"}
            ):
                transition_binding(
                    authoritative_binding_store,
                    transaction_id,
                    fingerprint,
                    state="recovery-pending",
                )
                return "error", transaction_id, effects
            if response["status"] == "captured":
                if (
                    set(response) != {
                        "status", "providerRecoveryReference", "settlement"
                    }
                    or not settlement_matches(response.get("settlement"), transaction_id, fingerprint, response["providerRecoveryReference"])
                ):
                    transition_binding(
                        authoritative_binding_store,
                        transaction_id,
                        fingerprint,
                        state="recovery-pending",
                        providerRecoveryReference=response[
                            "providerRecoveryReference"
                        ],
                    )
                    return "error", transaction_id, effects
                transition_binding(
                    authoritative_binding_store,
                    transaction_id,
                    fingerprint,
                    state="settled",
                    providerRecoveryReference=response["providerRecoveryReference"],
                    settlement=response["settlement"],
                )
            elif set(response) == {"status", "providerRecoveryReference"}:
                transition_binding(
                    authoritative_binding_store,
                    transaction_id,
                    fingerprint,
                    state="recovery-pending",
                    providerRecoveryReference=response["providerRecoveryReference"],
                )
            else:
                transition_binding(
                    authoritative_binding_store,
                    transaction_id,
                    fingerprint,
                    state="recovery-pending",
                    providerRecoveryReference=response[
                        "providerRecoveryReference"
                    ],
                )
                return "error", transaction_id, effects
    return "pass", transaction_id, effects


def evaluate_registration(case):
    eligible = (
        case.get("createCredential") is True
        and case.get("statusOnlyCredential") is True
        and case.get("credentialsDistinct") is True
        and case.get("createCredentialRelayed") is False
    )
    return "pass" if eligible else "fail"


class Ap2HandlerSafetyVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(VECTORS.read_text(encoding="utf-8"))
        cls.cases = {case["name"]: case for case in cls.data["vectors"]}

    def test_vector_hash_count_and_names_are_exact(self):
        vectors = self.data["vectors"]
        self.assertEqual(self.data["count"], len(vectors))
        self.assertEqual(len({case["name"] for case in vectors}), len(vectors))
        self.assertEqual(
            self.data["hash"], hashlib.sha256(canonical_json(vectors)).hexdigest()
        )

    def test_idempotency_keys_recompute_from_raw_inputs(self):
        cases = [case for case in self.data["vectors"] if case["op"] == "derive-idempotency-key"]
        self.assertEqual(len(cases), 7)
        for case in cases:
            with self.subTest(case=case["name"]):
                if case["expected"] == "error":
                    with self.assertRaises(ValueError):
                        derive_key(case["jobId"], case["phaseIndex"])
                    self.assertNotIn("expectedKey", case)
                else:
                    derived = derive_key(case["jobId"], case["phaseIndex"])
                    self.assertRegex(derived, KEY_RE)
                    self.assertEqual(derived, case["expectedKey"])

    def test_jid_gate_and_tuple_separation_are_load_bearing(self):
        base = self.cases["ap2-key-base"]
        phase = self.cases["ap2-key-phase-separation"]
        job = self.cases["ap2-key-job-separation"]
        self.assertNotEqual(base["expectedKey"], phase["expectedKey"])
        self.assertNotEqual(base["expectedKey"], job["expectedKey"])
        for name in (
            "ap2-key-noncanonical-unicode-error",
            "ap2-key-overflow-job-error",
        ):
            case = self.cases[name]
            with self.subTest(case=name), self.assertRaises(ValueError):
                derive_key(case["jobId"], case["phaseIndex"])

    def test_transaction_ids_recompute_from_exact_compact_jws_bytes(self):
        cases = [
            case for case in self.data["vectors"]
            if case["op"] == "derive-transaction-id"
        ]
        self.assertEqual(len(cases), 5)
        for case in cases:
            with self.subTest(case=case["name"]):
                if case["expected"] == "error":
                    with self.assertRaises(ValueError):
                        derive_transaction_id(
                            case["checkoutJws"], case.get("_sd_alg", MISSING)
                        )
                    self.assertNotIn("expectedTransactionId", case)
                else:
                    derived = derive_transaction_id(
                        case["checkoutJws"], case.get("_sd_alg", MISSING)
                    )
                    self.assertEqual(derived, case["expectedTransactionId"])

    def test_digest_selection_and_signature_bytes_are_load_bearing(self):
        default = self.cases["ap2-transaction-id-sha256-default"]
        explicit = self.cases["ap2-transaction-id-sha256-explicit"]
        changed = self.cases["ap2-transaction-id-signature-byte-change"]
        self.assertNotIn("_sd_alg", default)
        self.assertEqual(
            default["expectedTransactionId"],
            "rtXpY7wp4o7vknuw0ZaOpynbfydEGvpoFkFUiRFpYJU",
        )
        self.assertEqual(explicit["_sd_alg"], "sha-256")
        self.assertEqual(
            default["expectedTransactionId"], explicit["expectedTransactionId"]
        )
        default_segments = default["checkoutJws"].split(".")
        changed_segments = changed["checkoutJws"].split(".")
        self.assertEqual(default_segments[:2], changed_segments[:2])
        self.assertNotEqual(default_segments[2], changed_segments[2])
        self.assertEqual(
            changed["differentFromTransactionId"], default["expectedTransactionId"]
        )
        self.assertNotEqual(
            changed["expectedTransactionId"], changed["differentFromTransactionId"]
        )
        self.assertEqual(
            self.cases["ap2-admission-transaction-id-mismatch"]["paymentTransactionId"],
            changed["expectedTransactionId"],
        )

    def test_checkout_payment_admission_precedes_both_side_effects(self):
        cases = [
            case for case in self.data["vectors"]
            if case["op"] == "checkout-payment-admission"
        ]
        self.assertEqual(len(cases), 25)
        for case in cases:
            with self.subTest(case=case["name"]):
                trusted_context = trusted_context_for_ap2_case(case)
                verdict, derived, effects = evaluate_checkout_payment_admission(
                    case,
                    trusted_context,
                    authoritative_binding_store_for_ap2_case(case),
                    provider_status=provider_status_for_ap2_case(case),
                )
                self.assertEqual(verdict, case["expected"])
                for effect in (
                    "hashCalls",
                    "resolverCalls",
                    "metadataCalls",
                    "bindingStoreCalls",
                    "providerStatusCalls",
                    "providerRequestCalls",
                    "bindingAction",
                    "operationOrder",
                    "reserveAp2Binding",
                    "submitProviderPayment",
                    "submitNewPayment",
                    "idempotencyKeys",
                ):
                    self.assertEqual(effects[effect], case["want"][effect], effect)
                if "derivedTransactionId" in case["want"]:
                    self.assertEqual(derived, case["want"]["derivedTransactionId"])
                else:
                    self.assertIsNone(derived)

    def test_profile_and_session_gates_precede_every_modeled_effect(self):
        for name in (
            "ap2-admission-noncanonical-job-errors",
            "ap2-admission-overflow-job-errors",
            "ap2-admission-negative-phase-errors",
            "ap2-admission-unauthenticated-profile-refuses",
            "ap2-admission-caller-profile-refuses",
            "ap2-admission-duplicate-profile-refuses",
            "ap2-admission-peer-identity-mismatch-refuses",
            "ap2-admission-session-mismatch-refuses",
            "ap2-admission-copied-profile-reference-refuses",
        ):
            with self.subTest(case=name):
                case = self.cases[name]
                verdict, derived, effects = evaluate_checkout_payment_admission(
                    case,
                    trusted_context_for_ap2_case(case),
                    authoritative_binding_store_for_ap2_case(case),
                )
                self.assertIn(verdict, {"fail", "error"})
                self.assertIsNone(derived)
                self.assertEqual(
                    effects,
                    {
                        "hashCalls": 0,
                        "resolverCalls": 0,
                        "metadataCalls": 0,
                        "bindingStoreCalls": 0,
                        "providerStatusCalls": 0,
                        "providerRequestCalls": 0,
                        "bindingAction": None,
                        "operationOrder": [],
                        "reserveAp2Binding": False,
                        "submitProviderPayment": False,
                        "submitNewPayment": False,
                        "idempotencyKeys": [],
                    },
                )

    def test_complete_chain_admission_composes_atomic_ap2_7_decision(self):
        for name in (
            "ap2-admission-complete-chain-match",
            "ap2-composed-same-tuple-inflight-resumes",
            "ap2-composed-same-tuple-settled-resumes",
            "ap2-recovery-lost-response-resubmits-same-key",
            "ap2-recovery-reference-reconciles-captured",
            "ap2-recovery-reference-not-captured-resubmits-same-key",
            "ap2-composed-cross-job-replay-refuses",
            "ap2-composed-cross-phase-replay-refuses",
            "ap2-composed-duplicate-bindings-refuse",
            "ap2-composed-conflicting-bindings-refuse",
            "ap2-composed-caller-store-assertion-cannot-authorize",
        ):
            case = self.cases[name]
            with self.subTest(case=name):
                verdict, transaction_id, effects = evaluate_checkout_payment_admission(
                    case,
                    trusted_context_for_ap2_case(case),
                    authoritative_binding_store_for_ap2_case(case),
                    provider_status=provider_status_for_ap2_case(case),
                )
                self.assertEqual(verdict, case["expected"])
                self.assertEqual(transaction_id, case["want"]["derivedTransactionId"])
                self.assertEqual(effects["bindingAction"], case["want"]["bindingAction"])
                self.assertEqual(effects["operationOrder"], case["want"]["operationOrder"])
                self.assertEqual(
                    effects["submitProviderPayment"],
                    case["want"]["submitProviderPayment"],
                )
                if effects["bindingAction"] != "bind-new":
                    self.assertFalse(effects["reserveAp2Binding"])
                    self.assertFalse(effects["submitNewPayment"])
                    self.assertEqual(effects["metadataCalls"], 0)

    def test_inflight_candidate_vectors_dispatch_retained_request(self):
        for name in (
            "ap2-composed-same-tuple-inflight-resumes",
            "ap2-composed-caller-store-assertion-cannot-authorize",
        ):
            case = self.cases[name]
            calls = []

            def provider_submit(request):
                calls.append(copy.deepcopy(request))
                return None

            with self.subTest(case=name):
                store = authoritative_binding_store_for_ap2_case(case)
                verdict, transaction_id, effects = evaluate_checkout_payment_admission(
                    case,
                    trusted_context_for_ap2_case(case),
                    store,
                    provider_submit=provider_submit,
                )
                self.assertEqual(verdict, "pass")
                self.assertEqual(transaction_id, case["want"]["derivedTransactionId"])
                self.assertEqual(effects["bindingAction"], "resubmit-same-key")
                self.assertTrue(effects["submitProviderPayment"])
                self.assertFalse(effects["submitNewPayment"])
                self.assertEqual(effects["idempotencyKeys"], [derive_key(
                    case["jobId"], case["phaseIndex"]
                )])
                self.assertEqual(len(calls), 1)
                self.assertEqual(
                    calls[0]["operationPayload"],
                    store[0]["operationPayload"],
                )

    def test_ap2_context_validates_every_participant_before_selection(self):
        case = self.cases["ap2-admission-complete-chain-match"]
        for mutate in (
            lambda context: context["participants"].append({
                "identity": "unrelated-but-malformed"
            }),
            lambda context: context.__setitem__("callerReset", True),
        ):
            context = trusted_context_for_ap2_case(case)
            mutate(context)
            verdict, derived, effects = evaluate_checkout_payment_admission(
                case, context, []
            )
            self.assertEqual(verdict, "fail")
            self.assertIsNone(derived)
            self.assertEqual(effects["operationOrder"], [])
            self.assertEqual(effects["hashCalls"], 0)
            self.assertEqual(effects["bindingStoreCalls"], 0)
            self.assertEqual(effects["providerRequestCalls"], 0)

    def test_copied_blessed_reference_never_authorizes_ap2_effects(self):
        mutant = dict(self.cases["ap2-admission-caller-profile-refuses"])
        mutant.pop("peerProfile")
        mutant["peerProfileRef"] = "fixture:peer-current"
        verdict, derived, effects = evaluate_checkout_payment_admission(mutant)
        self.assertEqual("fail", verdict)
        self.assertIsNone(derived)
        self.assertEqual(
            effects,
            {
                "hashCalls": 0,
                "resolverCalls": 0,
                "metadataCalls": 0,
                "bindingStoreCalls": 0,
                "providerStatusCalls": 0,
                "providerRequestCalls": 0,
                "bindingAction": None,
                "operationOrder": [],
                "reserveAp2Binding": False,
                "submitProviderPayment": False,
                "submitNewPayment": False,
                "idempotencyKeys": [],
            },
        )

    def test_retry_requires_the_complete_retained_provider_request(self):
        original = self.cases["ap2-admission-complete-chain-match"]
        context = trusted_context_for_ap2_case(original)
        changes = {
            "payee": "different-merchant", "amount": "11.00", "instrument": "other-instrument",
            "paymentMandate": "different-mandate", "checkoutId": "other-checkout",
            "providerEndpoint": "https://other.example.invalid/payments",
            "metadata": {"dacs_job_id": original["jobId"], "dacs_agreement_hash": "1" * 64},
        }
        for field, value in changes.items():
            store = [durable_binding(original["paymentTransactionId"], original["jobId"], original["phaseIndex"], "recovery-pending")]
            before = copy.deepcopy(store)
            changed = copy.deepcopy(original)
            changed["providerRequest"][field] = value
            with self.subTest(field=field):
                verdict, _, effects = evaluate_checkout_payment_admission(changed, context, store)
                self.assertEqual(verdict, "error")
                self.assertEqual(effects["providerRequestCalls"], 0)
                self.assertEqual(effects["providerStatusCalls"], 0)
                self.assertEqual(effects["metadataCalls"], 0)
                self.assertEqual(store, before)

    def test_captured_recovery_requires_matching_operation_and_reference(self):
        case = self.cases["ap2-recovery-reference-reconciles-captured"]
        for field, value in (("transactionId", "other"), ("operationFingerprint", "0" * 64), ("providerRef", "other")):
            store = authoritative_binding_store_for_ap2_case(case)
            before = copy.deepcopy(store)
            settlement = fixture_settlement("provider-payment-123")
            settlement[field] = value
            with self.subTest(field=field):
                verdict, _, effects = evaluate_checkout_payment_admission(
                    case, trusted_context_for_ap2_case(case), store,
                    provider_status=lambda ref: {"status": "captured", "providerRecoveryReference": ref, "settlement": settlement},
                )
                self.assertEqual(verdict, "error")
                self.assertEqual(effects["providerRequestCalls"], 0)
                self.assertEqual(store, before)

    def test_entire_participant_map_requires_unique_identities(self):
        case = self.cases["ap2-admission-complete-chain-match"]
        context = trusted_context_for_ap2_case(case)
        unrelated = copy.deepcopy(context["participants"][0])
        unrelated["identity"] = "did:example:unrelated"
        context["participants"].append(unrelated)
        self.assertTrue(admits_current_profile(case, context))
        context["participants"].append(copy.deepcopy(unrelated))
        verdict, _, effects = evaluate_checkout_payment_admission(case, context, [])
        self.assertEqual(verdict, "fail")
        for field in ("hashCalls", "resolverCalls", "bindingStoreCalls", "providerStatusCalls", "providerRequestCalls", "metadataCalls"):
            self.assertEqual(effects[field], 0)

    def test_inflight_no_response_retry_reuses_retained_operation(self):
        case = self.cases["ap2-admission-complete-chain-match"]
        context = trusted_context_for_ap2_case(case)
        store = []
        calls = []

        def no_response_then_captured(request):
            calls.append(copy.deepcopy(request))
            if len(calls) == 1:
                return None
            provider_ref = "provider-payment-123"
            return {
                "status": "captured",
                "providerRecoveryReference": provider_ref,
                "settlement": fixture_settlement(provider_ref),
            }

        first = evaluate_checkout_payment_admission(
            case, context, store, provider_submit=no_response_then_captured
        )
        self.assertTrue(first[2]["submitProviderPayment"])
        self.assertTrue(first[2]["submitNewPayment"])
        self.assertEqual(store, [durable_binding(
            first[1], case["jobId"], case["phaseIndex"], "in-flight"
        )])
        retry = evaluate_checkout_payment_admission(
            case, context, store, provider_submit=no_response_then_captured
        )
        self.assertEqual(retry[2]["bindingAction"], "resubmit-same-key")
        self.assertTrue(retry[2]["submitProviderPayment"])
        self.assertFalse(retry[2]["submitNewPayment"])
        self.assertFalse(retry[2]["reserveAp2Binding"])
        self.assertEqual(retry[2]["metadataCalls"], 0)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["idempotencyKey"], calls[1]["idempotencyKey"])
        self.assertEqual(calls[0]["operationFingerprint"], calls[1]["operationFingerprint"])
        self.assertEqual(calls[0]["operationPayload"], calls[1]["operationPayload"])
        self.assertTrue(calls[0]["submitNewPayment"])
        self.assertFalse(calls[1]["submitNewPayment"])
        self.assertEqual(store[0]["state"], "settled")
        self.assertEqual(
            store[0]["providerRecoveryReference"], "provider-payment-123"
        )
        self.assertEqual(
            store[0]["settlement"], fixture_settlement("provider-payment-123")
        )

    def test_concurrent_calls_share_one_atomic_reservation(self):
        case = self.cases["ap2-admission-complete-chain-match"]
        context = trusted_context_for_ap2_case(case)
        store = []
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: evaluate_checkout_payment_admission(case, context, store), range(4)))
        self.assertEqual(sum(r[2]["submitNewPayment"] for r in results), 1)
        self.assertEqual(sum(r[2]["submitProviderPayment"] for r in results), 4)
        self.assertEqual(
            {tuple(r[2]["idempotencyKeys"]) for r in results},
            {(derive_key(case["jobId"], case["phaseIndex"]),)},
        )
        self.assertEqual(len(store), 1)

    def test_provider_failure_keeps_reservation_for_recovery(self):
        case = self.cases["ap2-admission-complete-chain-match"]
        context = trusted_context_for_ap2_case(case)
        store = []
        calls = []
        def ambiguous_provider(request):
            self.assertEqual(len(store), 1)
            self.assertEqual(store[0]["transactionId"], request["transactionId"])
            self.assertEqual(store[0]["state"], "in-flight")
            calls.append(copy.deepcopy(request))
            if len(calls) == 1:
                raise RuntimeError("simulated lost provider response")
            return {
                "status": "pending",
                "providerRecoveryReference": "provider-payment-123",
            }
        with self.assertRaisesRegex(RuntimeError, "simulated lost"):
            evaluate_checkout_payment_admission(case, context, store, ambiguous_provider)
        retry = evaluate_checkout_payment_admission(case, context, store, ambiguous_provider)
        self.assertEqual(retry[2]["bindingAction"], "resubmit-same-key")
        self.assertTrue(retry[2]["submitProviderPayment"])
        self.assertFalse(retry[2]["submitNewPayment"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["idempotencyKey"], calls[1]["idempotencyKey"])
        self.assertEqual(calls[0]["operationFingerprint"], calls[1]["operationFingerprint"])
        self.assertEqual(calls[0]["operationPayload"], calls[1]["operationPayload"])
        self.assertEqual(len(store), 1)
        self.assertEqual(store[0]["state"], "recovery-pending")
        self.assertEqual(store[0]["providerRecoveryReference"], "provider-payment-123")

        status_calls = []

        def captured_status(provider_ref):
            status_calls.append(provider_ref)
            return {
                "status": "captured",
                "providerRecoveryReference": provider_ref,
                "settlement": fixture_settlement(provider_ref),
            }

        reconciled = evaluate_checkout_payment_admission(
            case, context, store, provider_status=captured_status
        )
        self.assertEqual(reconciled[2]["bindingAction"], "resume-settlement")
        self.assertEqual(status_calls, ["provider-payment-123"])
        self.assertFalse(reconciled[2]["submitProviderPayment"])
        self.assertEqual(store[0]["state"], "settled")

        reused = evaluate_checkout_payment_admission(
            case,
            context,
            store,
            provider_submit=lambda _request: self.fail("settlement resubmitted"),
            provider_status=lambda _ref: self.fail("settlement re-queried"),
        )
        self.assertEqual(reused[2]["bindingAction"], "resume-settlement")
        self.assertFalse(reused[2]["submitProviderPayment"])

    def test_malformed_provider_result_retains_a_usable_recovery_reference(self):
        case = self.cases["ap2-admission-complete-chain-match"]
        context = trusted_context_for_ap2_case(case)
        store = []
        malformed = evaluate_checkout_payment_admission(
            case,
            context,
            store,
            provider_submit=lambda _request: {
                "status": "captured",
                "providerRecoveryReference": "provider-payment-malformed",
            },
        )
        self.assertEqual(malformed[0], "error")
        self.assertEqual(store[0]["state"], "recovery-pending")
        self.assertEqual(
            store[0]["providerRecoveryReference"],
            "provider-payment-malformed",
        )

        recovered = evaluate_checkout_payment_admission(
            case,
            context,
            store,
            provider_status=lambda ref: {
                "status": "captured",
                "providerRecoveryReference": ref,
                "settlement": fixture_settlement(ref),
            },
        )
        self.assertEqual(recovered[0], "pass")
        self.assertEqual(recovered[2]["bindingAction"], "resume-settlement")
        self.assertFalse(recovered[2]["submitProviderPayment"])

    def test_invalid_atomic_transition_preserves_the_prior_record(self):
        transaction_id = self.cases[
            "ap2-transaction-id-sha256-default"
        ]["expectedTransactionId"]
        store = [durable_binding(
            transaction_id,
            CURRENT_SESSION_ID,
            3,
            "recovery-pending",
        )]
        snapshot = copy.deepcopy(store)
        with self.assertRaisesRegex(ValueError, "transition malformed"):
            transition_binding(
                store,
                transaction_id,
                store[0]["operationFingerprint"],
                state="settled",
            )
        self.assertEqual(store, snapshot)

    def test_new_checkout_cases_cover_positive_negative_and_boundary(self):
        classes = {
            case["caseClass"]
            for case in self.data["vectors"]
            if case["op"] in {"derive-transaction-id", "checkout-payment-admission"}
        }
        self.assertEqual(classes, {"positive", "negative", "boundary"})

    def test_transaction_binding_executes_retry_and_replay_rules(self):
        cases = [case for case in self.data["vectors"] if case["op"] == "transaction-binding"]
        self.assertEqual(len(cases), 22)
        for case in cases:
            with self.subTest(case=case["name"]):
                verdict, action, submit_new = evaluate_transaction_binding(
                    case.get("transactionId"),
                    case.get("jobId"),
                    case.get("phaseIndex"),
                    case.get("priorBindings"),
                    case.get("providerRequest"),
                )
                self.assertEqual(verdict, case["expected"])
                self.assertEqual(action, case["want"]["action"])
                self.assertEqual(submit_new, case["want"]["submitNewPayment"])

    def test_exact_tuple_retries_never_submit_a_second_payment(self):
        for name in (
            "ap2-same-tuple-inflight-resumes",
            "ap2-same-tuple-settled-resumes-evidence",
            "ap2-recovery-pending-without-reference-resubmits-same-key",
            "ap2-recovery-pending-with-reference-reconciles",
        ):
            case = self.cases[name]
            verdict, action, submit_new = evaluate_transaction_binding(
                case["transactionId"],
                case["jobId"],
                case["phaseIndex"],
                case["priorBindings"],
                case["providerRequest"],
            )
            self.assertEqual(verdict, "pass")
            self.assertIn(action, {
                "resume-settlement", "resubmit-same-key",
                "reconcile-reference",
            })
            self.assertFalse(submit_new)

    def test_malformed_binding_store_fails_closed_in_composed_handler(self):
        base = self.cases["ap2-admission-complete-chain-match"]
        malformed = [
            case
            for case in self.data["vectors"]
            if case["op"] == "transaction-binding" and case["expected"] == "error"
        ]
        self.assertGreaterEqual(len(malformed), 10)
        for store_case in malformed:
            with self.subTest(case=store_case["name"]):
                verdict, transaction_id, effects = evaluate_checkout_payment_admission(
                    base,
                    trusted_context_for_ap2_case(base),
                    store_case.get("priorBindings"),
                )
                self.assertEqual(verdict, "error")
                self.assertEqual(
                    transaction_id, base["want"]["derivedTransactionId"]
                )
                self.assertEqual(effects["bindingStoreCalls"], 1)
                self.assertEqual(effects["bindingAction"], "refuse-conflict")
                self.assertEqual(
                    effects["operationOrder"], ["atomicBindingStoreDecision"]
                )
                self.assertEqual(effects["metadataCalls"], 0)
                self.assertFalse(effects["reserveAp2Binding"])
                self.assertFalse(effects["submitProviderPayment"])

    def test_checkout_signature_policy_uses_the_dacs_strict_profile(self):
        cases = [case for case in self.data["vectors"] if case["op"] == "checkout-signature-policy"]
        self.assertEqual(len(cases), 3)
        for case in cases:
            with self.subTest(case=case["name"]):
                self.assertEqual(evaluate_signature_policy(case), case["expected"])

    def test_registration_requires_split_least_privilege_credentials(self):
        cases = [case for case in self.data["vectors"] if case["op"] == "registration-eligibility"]
        self.assertEqual(len(cases), 4)
        for case in cases:
            with self.subTest(case=case["name"]):
                self.assertEqual(evaluate_registration(case), case["expected"])

    def test_generator_check_is_enforced(self):
        result = subprocess.run(
            [sys.executable, "scripts/generate_ap2_handler_safety_vectors.py", "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_spec_registry_plan_readme_and_ci_are_linked(self):
        spec = SPEC.read_text(encoding="utf-8")
        core = CORE.read_text(encoding="utf-8")
        plan = PLAN.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('"dacs-ap2-idem:v1:"', spec)
        self.assertIn('`dacs-ap2-idem:v1:`', core)
        self.assertIn("same `(jobId, phaseIndex)`", spec)
        self.assertIn("DACS profiles the stricter", spec)
        self.assertIn("CheckoutMandate + PaymentMandate", spec)
        self.assertIn("base payload of the SD-JWT carrying the CheckoutMandate", spec)
        self.assertIn("MUST NOT reserve the AP2-7 binding", spec)
        self.assertIn("handler-owned authoritative store", spec)
        self.assertIn("only branch that may create provider metadata", spec)
        self.assertIn("current Demos DAHR binding", spec)
        self.assertIn("handler-owned trusted context", spec)
        self.assertIn("validate every participant record before selecting", spec)
        self.assertIn("duplicate participant records", spec)
        self.assertIn("identity/session mismatch", spec)
        self.assertIn("immutable operation payload", spec)
        self.assertIn("`submitNewPayment: false`", spec)
        self.assertIn("does not claim crash-safe production durability", spec)
        self.assertNotIn("AP2 v0.2's non-deterministic-signature requirement", spec)
        self.assertIn("ap2-handler-safety-v0.6.json", plan)
        self.assertIn("ap2-handler-safety-v0.6.json", readme)
        self.assertIn("generate_ap2_handler_safety_vectors.py --check", workflow)


if __name__ == "__main__":
    unittest.main()
