#!/usr/bin/env python3
"""Generate deterministic DACS-4 LAA-1..LAA-7 / DACS-3 CA-10 vectors.

The expected verdict and declared effects are computed by the single shared
verifier-owned LAA oracle (``tests/dacs5_reference.laa_admission`` /
``laa_want``) rather than hand-asserted per case, so the corpus cannot drift
from the executable reference.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "legacy-agreement-admission-v0.8.json"
)
GOVERNING_SUBSTRATE = "demos-mainnet"
ORDER_DOMAIN = "demos-mainnet:demos-bft-final:genesis-v1"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import dacs5_reference as R  # noqa: E402


def merge(base: dict, changes: dict | None) -> dict:
    value = copy.deepcopy(base)
    for key, item in (changes or {}).items():
        if isinstance(item, dict) and isinstance(value.get(key), dict):
            value[key] = merge(value[key], item)
        else:
            value[key] = copy.deepcopy(item)
    return value


def base_input(*, operation: str = "historical-audit", artifact: str = "legacy") -> dict:
    value = {
        "surface": "dacs4-laa",
        "operation": operation,
        "pipelineHasPayment": True,
        "sessionAuthority": {
            "state": "verified",
            "substrate": GOVERNING_SUBSTRATE,
            "orderDomain": ORDER_DOMAIN,
            "jobId": "job-a",
            "sessionId": "session-a",
            "paymentHeadPosition": "80",
            "payerPrimaryClaim": "did:demos:buyer",
            "payerBundleHash": "buyer-bundle-hash-a",
            "payerAuthorizedKeys": ["key:demos:buyer-paying"],
            "payeePrimaryClaim": "did:demos:seller",
            "payeeBundleHash": "seller-bundle-hash-a",
            "orchestratorPrimaryClaim": "did:demos:orchestrator",
        },
        "agreement": {
            "artifact": artifact,
            "shape": "valid",
            "partySignaturesValid": True,
            "contentHash": "agreement-hash-a",
            "jobId": "job-a",
            "phase": "pay-dem",
            "generatedAt": 10,
            "pbVerified": artifact in R.LAA_PAYEE_BOUND_ARTIFACTS,
            "ibhVerified": artifact in {"identity-bound", "identity-bound-payee"},
            "listingRef": {
                "listingId": "listing-a", "version": 1,
                "contentHash": "listing-hash-a",
            },
            "terms": {
                "price": {"amount": "10.00", "currency": "DEM"},
                "rail": {"railId": "demos-native:DEM", "version": 1},
                "deadline": 2000,
            },
        },
        "checkpoint": {
            "resolution": "verified",
            "discriminator": "legacyAgreementCheckpointVersion:1",
            "shape": "valid",
            "signatureValid": True,
            "signatureDomain": "dacs-legacy-agreement-checkpoint:v1:",
            "stewardAuthorized": True,
            "addressMatches": True,
            "policyMatches": True,
            "receiptState": "finalized",
            "position": "100",
            "authenticatedAbsence": False,
            "absenceCoverPosition": "80",
            "createdAt": 1,
            "substrate": GOVERNING_SUBSTRATE,
            "orderDomain": ORDER_DOMAIN,
        },
        "commitment": {
            "resolution": "verified",
            "shape": "valid",
            "agreementHashMatches": True,
            "signatureValid": True,
            "receiptState": "finalized",
            "position": "80",
            "strictlyBeforeAtSamePosition": None,
            "substrate": GOVERNING_SUBSTRATE,
            "orderDomain": ORDER_DOMAIN,
        },
        "settlementEvidence": {
            "resolution": "verified",
            "shape": "valid",
            "agreementBindingMatches": True,
            "agreementHash": "agreement-hash-a",
            "job": "job-a",
            "session": "session-a",
            "phase": "pay-dem",
            "signatureValid": True,
            "receiptState": "finalized",
            "position": "90",
            "strictlyBeforeAtSamePosition": None,
            "observedAt": 20,
            "substrate": GOVERNING_SUBSTRATE,
            "orderDomain": ORDER_DOMAIN,
        },
        "transitionEvidence": {
            "resolution": "verified",
            "shape": "valid",
            "discriminator": "legacyTransitionEvidenceVersion:1",
            "signatureDomain": "dacs-legacy-transition-evidence:v1:",
            "agreementBindingMatches": True,
            "agreementHash": "agreement-hash-a",
            "job": "job-a",
            "session": "session-a",
            "phase": "pay-dem",
            "phaseIndex": 2,
            "outcome": "success",
            "paymentTxRefs": [{
                "kind": "demos", "txHash": "transition-tx-a", "blockNumber": 42,
            }],
            "paymentAmount": {"amount": "10.00", "currency": "DEM"},
            "settlementFinalityValid": True,
            "reservationRef": {
                "anchor": {
                    "kind": "storage-program",
                    "locator": "dacs4:legacy-payment-reservation:job-a:2",
                },
                "contentHash": "",
            },
            "signature": {
                "signer": "did:demos:orchestrator",
                "algorithm": "ed25519",
                "value": "fixture-transition-evidence-signature",
                "signatureValid": True,
            },
            "receiptWriter": "did:demos:orchestrator",
            "receiptState": "finalized",
            "position": "120",
            "strictlyBeforeAtSamePosition": None,
            "observedAt": 30,
            "substrate": GOVERNING_SUBSTRATE,
            "orderDomain": ORDER_DOMAIN,
        },
        "listingAuthority": {
            "resolution": "verified",
            "signatureValid": True,
            "contentHash": "listing-hash-a",
            "phase": "pay-dem",
            "phaseIndex": 2,
        },
        "railAuthority": {
            "resolution": "verified",
            "signatureValid": True,
            "railId": "demos-native:DEM",
            "version": 1,
            "contentHash": "rail-hash-a",
            "phaseHandler": "pay-dem",
        },
        "presentationPosition": "150",
        "paymentPosition": "150",
        "paymentEffect": {
            "jobId": "job-a",
            "sessionId": "session-a",
            "phase": "pay-dem",
            "phaseIndex": 2,
            "payerPrimaryClaim": "did:demos:buyer",
            "payerBundleHash": "buyer-bundle-hash-a",
            "payingKey": "key:demos:buyer-paying",
            "payeePrimaryClaim": "did:demos:seller",
            "payeeBundleHash": "seller-bundle-hash-a",
            "payeeAddress": "demos1selleraddress",
            "amount": {"amount": "10.00", "currency": "DEM"},
        },
        "reservation": {
            "resolution": "verified",
            "shape": "valid",
            "discriminator": "legacyPaymentReservationVersion:1",
            "signatureDomain": "dacs-legacy-payment-reservation:v1:",
            "signatures": [
                {"role": "buyer", "signer": "did:demos:buyer",
                 "value": "fixture-signature-buyer", "signatureValid": True},
                {"role": "seller", "signer": "did:demos:seller",
                 "value": "fixture-signature-seller", "signatureValid": True},
                {"role": "orchestrator", "signer": "did:demos:orchestrator",
                 "value": "fixture-signature-orchestrator", "signatureValid": True},
            ],
            "addressMatches": True,
            "logicalAddress": "dacs4:legacy-payment-reservation:job-a:2",
            "receiptState": "finalized",
            "position": "85",
            "strictlyBeforeAtSamePosition": None,
            "substrate": GOVERNING_SUBSTRATE,
            "orderDomain": ORDER_DOMAIN,
            "projection": {},
            "contentHash": "",
        },
        "paymentAuthority": {
            "resolution": "verified",
            "clockDomain": ORDER_DOMAIN,
            "authenticatedNowMs": 1500,
            "idempotencyResolution": "unused",
            "idempotencyKey": "",
        },
    }
    for signature in value["reservation"]["signatures"]:
        signature["algorithm"] = "ed25519"
    projection_verdict, projection = R.laa_transition_projection(value)
    if projection_verdict != "pass":
        raise AssertionError(f"base transition projection: {projection_verdict}")
    value["reservation"]["projection"] = projection
    value["reservation"]["contentHash"] = hashlib.sha256(
        json.dumps(
            projection, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    value["paymentAuthority"]["idempotencyKey"] = projection["idempotencyKey"]
    if operation == "transition-audit":
        value["paymentAuthority"]["idempotencyResolution"] = "consumed"
    value["transitionEvidence"]["reservationRef"]["contentHash"] = value["reservation"]["contentHash"]
    return value


def case(
    name: str,
    expected: str,
    note: str,
    *,
    operation: str = "historical-audit",
    artifact: str = "legacy",
    changes: dict | None = None,
    drops: list[tuple[str, str]] | None = None,
    rederive_reservation: bool = False,
) -> dict:
    value = merge(base_input(operation=operation, artifact=artifact), changes)
    signatures = value.get("reservation", {}).get("signatures")
    if isinstance(signatures, list):
        for signature in signatures:
            if isinstance(signature, dict):
                signature.setdefault("algorithm", "ed25519")
    if rederive_reservation:
        projection_verdict, projection = R.laa_transition_projection(value)
        if projection_verdict != "pass":
            raise AssertionError(f"{name}: cannot rederive reservation: {projection_verdict}")
        value["reservation"]["projection"] = projection
        value["reservation"]["contentHash"] = hashlib.sha256(
            json.dumps(
                projection, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        value["paymentAuthority"]["idempotencyKey"] = projection["idempotencyKey"]
        value["transitionEvidence"]["reservationRef"]["contentHash"] = value["reservation"]["contentHash"]
        logical_address = (
            "dacs4:legacy-payment-reservation:"
            f"{projection['jobId']}:{projection['phaseIndex']}"
        )
        value["reservation"]["logicalAddress"] = logical_address
        value["transitionEvidence"]["reservationRef"]["anchor"]["locator"] = logical_address
    for container, key in (drops or []):
        target = value
        for segment in container.split("."):
            target = target.get(segment) if isinstance(target, dict) else None
        if isinstance(target, dict):
            target.pop(key, None)
    verdict = R.laa_admission(value)
    if verdict != expected:
        raise AssertionError(
            f"{name}: shared LAA oracle returns {verdict!r}, declared {expected!r}"
        )
    return {
        "name": name,
        "expected": verdict,
        "note": note,
        "input": value,
        "want": R.laa_want(value),
    }


def vectors() -> list[dict]:
    return [
        case(
            "laa-current-payee-bound-success", "pass",
            "current pay-bearing settlement uses the destination-bound artifact",
            operation="authorize-payment", artifact="payee-bound",
        ),
        case(
            "laa-payee-bound-does-not-fallback-on-checkpoint-outage", "pass",
            "checkpoint uncertainty never forces the safe current artifact onto legacy",
            operation="authorize-payment", artifact="payee-bound",
            changes={"checkpoint": {"resolution": "unavailable"}},
        ),
        case(
            "laa-identity-bound-payee-success", "pass",
            "the stronger identity-bound payee artifact is accepted wherever payee-bound is",
            operation="authorize-payment", artifact="identity-bound-payee",
        ),
        case(
            "laa-identity-bound-non-payee-rejected", "fail",
            "a non-payee identity-bound agreement cannot authorize a current pay-bearing payment",
            operation="authorize-payment", artifact="identity-bound",
        ),
        case(
            "laa-identity-bound-payee-ibh-not-verified", "fail",
            "an identity-bound payee artifact whose identity binding fails does not authorize payment",
            operation="authorize-payment", artifact="identity-bound-payee",
            changes={"agreement": {"ibhVerified": False}},
        ),
        case(
            "laa-ca10-identity-bound-payee-commit", "pass",
            "commit-identity-bound-payee-agreement is available pre-activation without payment side effects",
            operation="commit-pay-bearing", artifact="identity-bound-payee",
            changes={"surface": "dacs3-ca10"},
        ),
        case(
            "laa-zero-pay-legacy-outside-gate", "pass",
            "a pipeline with no payment introduces no runtime payout destination",
            operation="commit-pay-bearing",
            changes={"pipelineHasPayment": False},
        ),
        case(
            "laa-preactivation-authoritative-absence-allows-legacy", "pass",
            "binding-qualified absence covering the payment position proves activation has not occurred",
            operation="authorize-payment",
            changes={"checkpoint": {"resolution": "absent", "authenticatedAbsence": True}},
        ),
        case(
            "laa-stale-absence-across-activation-boundary", "indeterminate",
            "an authenticated absence proven only up to an earlier head does not cover a later payment submission",
            operation="authorize-payment",
            changes={"checkpoint": {"resolution": "absent", "authenticatedAbsence": True, "absenceCoverPosition": "50"}},
        ),
        case(
            "laa-absence-cover-position-malformed", "error",
            "a non-string absence-cover position is a structural error before the payment effect",
            operation="authorize-payment",
            changes={"checkpoint": {"resolution": "absent", "authenticatedAbsence": True, "absenceCoverPosition": 200}},
        ),
        case(
            "laa-caller-lowered-payment-position-cannot-mask-stale-absence", "indeterminate",
            "a caller-supplied low payment position cannot convert a stale absence proof into a pass",
            operation="authorize-payment",
            changes={
                "checkpoint": {"resolution": "absent", "authenticatedAbsence": True, "absenceCoverPosition": "50"},
                "paymentPosition": "40",
            },
        ),
        case(
            "laa-authenticated-head-position-non-string", "error",
            "a non-string authenticated payment-head position is a structural error",
            operation="authorize-payment",
            changes={
                "sessionAuthority": {"paymentHeadPosition": 150},
                "checkpoint": {"resolution": "absent", "authenticatedAbsence": True},
            },
        ),
        case(
            "laa-ca10-preactivation-legacy-commit", "pass",
            "CA-10 permits legacy commitment only under authenticated preactivation absence covering the commit position",
            operation="commit-pay-bearing",
            changes={"surface": "dacs3-ca10", "checkpoint": {"resolution": "absent", "authenticatedAbsence": True}},
        ),
        case(
            "laa-ca10-stale-absence-across-activation-boundary", "indeterminate",
            "CA-10 cannot rely on a stale authenticated absence for a later commit",
            operation="commit-pay-bearing",
            changes={"surface": "dacs3-ca10", "checkpoint": {"resolution": "absent", "authenticatedAbsence": True, "absenceCoverPosition": "50"}},
        ),
        case(
            "laa-fresh-legacy-after-checkpoint", "fail",
            "a current legacy agreement cannot authorize payment after activation",
            operation="authorize-payment",
            changes={"commitment": {"position": "110"}, "settlementEvidence": {"position": "120"}},
        ),
        case(
            "laa-ca10-postactivation-legacy-commit", "fail",
            "CA-10 rejects commit-agreement for a current pay-bearing session",
            operation="commit-pay-bearing", changes={"surface": "dacs3-ca10"},
        ),
        case(
            "laa-backdated-generated-at", "fail",
            "backdating agreement metadata cannot overcome a post-checkpoint commitment",
            operation="authorize-payment",
            changes={"agreement": {"generatedAt": -1000}, "commitment": {"position": "110"}},
        ),
        case(
            "laa-exact-precheckpoint-commitment-transition", "pass",
            "the exact finalized pre-checkpoint commitment and signed reservation may complete one original effect",
            operation="authorize-payment",
            changes={"commitment": {"position": "80"}, "settlementEvidence": {"resolution": "absent"}},
        ),
        case(
            "laa-precheckpoint-payment-reservation", "pass",
            "the exact party- and orchestrator-signed payment effect is reserved before activation",
            operation="reserve-transition-payment",
            changes={
                "checkpoint": {"resolution": "absent", "authenticatedAbsence": True,
                               "absenceCoverPosition": "85"},
            },
        ),
        case(
            "laa-postcheckpoint-payment-reservation", "fail",
            "a reservation cannot be created after activation",
            operation="reserve-transition-payment",
        ),
        case(
            "laa-transition-completion-audit", "pass",
            "a bounded post-checkpoint completion remains auditable but current-profile ineligible",
            operation="transition-audit",
            changes={"transitionEvidence": {"position": "120"}},
        ),
        case(
            "laa-transition-payee-substitution", "fail",
            "the actual rail destination cannot differ from the signed reservation",
            operation="authorize-payment",
            changes={"paymentEffect": {"payeeAddress": "demos1attackeraddress"}},
        ),
        case(
            "laa-transition-job-substitution", "fail",
            "a pre-checkpoint commitment cannot be replayed into another job",
            operation="authorize-payment",
            changes={"paymentEffect": {"jobId": "job-other"}},
        ),
        case(
            "laa-transition-agreement-substitution", "fail",
            "a pre-checkpoint commitment cannot authorize another agreement hash",
            operation="authorize-payment",
            changes={"agreement": {"contentHash": "agreement-hash-other"}},
        ),
        case(
            "laa-transition-amount-substitution", "fail",
            "a pre-checkpoint commitment cannot be repriced",
            operation="authorize-payment",
            changes={"paymentEffect": {"amount": {"amount": "11.00"}}},
        ),
        case(
            "laa-transition-rail-substitution", "fail",
            "a pre-checkpoint commitment cannot select another rail",
            operation="authorize-payment",
            changes={"railAuthority": {"railId": "evm-erc20:1:USDC"}},
        ),
        case(
            "laa-transition-terms-substitution", "fail",
            "a pre-checkpoint commitment cannot alter its signed payment terms",
            operation="authorize-payment",
            changes={"agreement": {"listingRef": {"contentHash": "listing-hash-other"}}},
        ),
        case(
            "laa-transition-cross-session-request", "fail",
            "a pre-checkpoint commitment cannot be replayed into another session",
            operation="authorize-payment",
            changes={"paymentEffect": {"sessionId": "session-other"}},
        ),
        case(
            "laa-transition-cross-phase-request", "fail",
            "a pre-checkpoint commitment cannot be replayed into another phase",
            operation="authorize-payment",
            changes={"paymentEffect": {"phase": "pay-evm-erc20"}},
        ),
        case(
            "laa-transition-reservation-unavailable", "indeterminate",
            "unavailable pre-checkpoint reservation authority cannot authorize payment",
            operation="authorize-payment",
            changes={"reservation": {"resolution": "unavailable"}},
        ),
        case(
            "laa-transition-reservation-signature-invalid", "fail",
            "a reservation without the required valid party signatures cannot authorize payment",
            operation="authorize-payment",
            changes={"reservation": {"signatures": [
                {"role": "buyer", "signer": "did:demos:buyer",
                 "value": "fixture-signature-buyer", "signatureValid": False},
                {"role": "seller", "signer": "did:demos:seller",
                 "value": "fixture-signature-seller", "signatureValid": True},
                {"role": "orchestrator", "signer": "did:demos:orchestrator",
                 "value": "fixture-signature-orchestrator", "signatureValid": True},
            ]}},
        ),
        case(
            "laa-transition-reservation-missing-seller-signature", "fail",
            "the exact authenticated seller must sign the reservation",
            operation="authorize-payment",
            changes={"reservation": {"signatures": [
                {"role": "buyer", "signer": "did:demos:buyer",
                 "value": "fixture-signature-buyer", "signatureValid": True},
                {"role": "orchestrator", "signer": "did:demos:orchestrator",
                 "value": "fixture-signature-orchestrator", "signatureValid": True},
            ]}},
        ),
        case(
            "laa-transition-reservation-duplicate-signer", "fail",
            "one signer cannot occupy two required reservation roles",
            operation="authorize-payment",
            changes={"reservation": {"signatures": [
                {"role": "buyer", "signer": "did:demos:buyer",
                 "value": "fixture-signature-buyer", "signatureValid": True},
                {"role": "seller", "signer": "did:demos:seller",
                 "value": "fixture-signature-seller", "signatureValid": True},
                {"role": "orchestrator", "signer": "did:demos:buyer",
                 "value": "fixture-signature-duplicate", "signatureValid": True},
            ]}},
        ),
        case(
            "laa-transition-reservation-swapped-party-signers", "fail",
            "buyer and seller signature roles bind their authenticated identities",
            operation="authorize-payment",
            changes={"reservation": {"signatures": [
                {"role": "buyer", "signer": "did:demos:seller",
                 "value": "fixture-signature-swapped-buyer", "signatureValid": True},
                {"role": "seller", "signer": "did:demos:buyer",
                 "value": "fixture-signature-swapped-seller", "signatureValid": True},
                {"role": "orchestrator", "signer": "did:demos:orchestrator",
                 "value": "fixture-signature-orchestrator", "signatureValid": True},
            ]}},
        ),
        case(
            "laa-transition-reservation-unauthorized-extra-signer", "fail",
            "an extra unauthenticated signer cannot expand the closed signer set",
            operation="authorize-payment",
            changes={"reservation": {"signatures": [
                {"role": "buyer", "signer": "did:demos:buyer",
                 "value": "fixture-signature-buyer", "signatureValid": True},
                {"role": "seller", "signer": "did:demos:seller",
                 "value": "fixture-signature-seller", "signatureValid": True},
                {"role": "orchestrator", "signer": "did:demos:orchestrator",
                 "value": "fixture-signature-orchestrator", "signatureValid": True},
                {"role": "observer", "signer": "did:demos:attacker",
                 "value": "fixture-signature-attacker", "signatureValid": True},
            ]}},
        ),
        case(
            "laa-transition-reservation-changed-orchestrator", "fail",
            "the reservation binds the verifier-owned authenticated session orchestrator",
            operation="authorize-payment",
            changes={"sessionAuthority": {"orchestratorPrimaryClaim": "did:demos:orchestrator-other"}},
        ),
        case(
            "laa-transition-reservation-orchestrator-coincident", "pass",
            "no third signature is required when the authenticated orchestrator is the buyer",
            operation="authorize-payment",
            changes={
                "sessionAuthority": {"orchestratorPrimaryClaim": "did:demos:buyer"},
                "reservation": {"signatures": [
                    {"role": "buyer", "signer": "did:demos:buyer",
                     "value": "fixture-signature-buyer", "signatureValid": True},
                    {"role": "seller", "signer": "did:demos:seller",
                     "value": "fixture-signature-seller", "signatureValid": True},
                ]},
            },
            rederive_reservation=True,
        ),
        case(
            "laa-transition-attacker-paying-key", "fail",
            "the payer key must be in verifier-owned authenticated payer authority",
            operation="authorize-payment",
            changes={"paymentEffect": {"payingKey": "key:demos:attacker"}},
        ),
        case(
            "laa-transition-payer-bundle-substitution", "fail",
            "the actual payer bundle must match authenticated session authority",
            operation="authorize-payment",
            changes={"paymentEffect": {"payerBundleHash": "buyer-bundle-hash-other"}},
        ),
        case(
            "laa-transition-payee-bundle-substitution", "fail",
            "the actual payee bundle must match authenticated session authority",
            operation="authorize-payment",
            changes={"paymentEffect": {"payeeBundleHash": "seller-bundle-hash-other"}},
        ),
        case(
            "laa-transition-deadline-expired", "fail",
            "an exact transition payment after its signed deadline is refused",
            operation="authorize-payment",
            changes={"paymentAuthority": {"authenticatedNowMs": 2001}},
        ),
        case(
            "laa-transition-deadline-authority-unavailable", "indeterminate",
            "unavailable authenticated deadline authority cannot authorize payment",
            operation="authorize-payment",
            changes={"paymentAuthority": {"resolution": "unavailable"}},
        ),
        case(
            "laa-transition-missing-payment-authority", "indeterminate",
            "missing verifier-owned deadline and idempotency authority cannot authorize payment",
            operation="authorize-payment",
            changes={"paymentAuthority": None},
        ),
        case(
            "laa-transition-clock-domain-incomparable", "indeterminate",
            "a deadline clock outside the authenticated ordering domain is incomparable",
            operation="authorize-payment",
            changes={"paymentAuthority": {"clockDomain": "other:clock"}},
        ),
        case(
            "laa-transition-idempotency-consumed", "fail",
            "a consumed original idempotency key cannot cause another payment",
            operation="authorize-payment",
            changes={"paymentAuthority": {"idempotencyResolution": "consumed"}},
        ),
        case(
            "laa-transition-idempotency-authority-unavailable", "indeterminate",
            "unavailable idempotency authority cannot authorize payment",
            operation="authorize-payment",
            changes={"paymentAuthority": {"idempotencyResolution": "unavailable"}},
        ),
        case(
            "laa-transition-audit-without-checkpoint", "fail",
            "checkpoint absence cannot be relabelled as a transition-era audit",
            operation="transition-audit",
            changes={"checkpoint": {"resolution": "absent", "authenticatedAbsence": True}},
        ),
        case(
            "laa-transition-audit-missing-commitment", "indeterminate",
            "transition audit requires the finalized pre-checkpoint commitment",
            operation="transition-audit",
            changes={"commitment": {"resolution": "unavailable"}},
        ),
        case(
            "laa-transition-audit-missing-settlement", "indeterminate",
            "transition audit requires finalized distinct transition evidence",
            operation="transition-audit",
            changes={"transitionEvidence": {"resolution": "unavailable"}},
        ),
        case(
            "laa-transition-audit-reservation-mismatch", "fail",
            "transition evidence must bind the exact signed reservation reference",
            operation="transition-audit",
            changes={"transitionEvidence": {"reservationRef": {"contentHash": "0" * 64}}},
        ),
        case(
            "laa-transition-audit-reservation-ref-malformed", "error",
            "a scalar reservation reference is malformed, never transition authority",
            operation="transition-audit",
            changes={"transitionEvidence": {"reservationRef": "reservation-a"}},
        ),
        case(
            "laa-transition-audit-reservation-ref-hash-only", "error",
            "a hash without the canonical reservation anchor is not an AttestationRef",
            operation="transition-audit",
            changes={"transitionEvidence": {"reservationRef": {
                "contentHash": "0" * 64,
            }}},
            drops=[("transitionEvidence.reservationRef", "anchor")],
        ),
        case(
            "laa-transition-audit-reservation-ref-foreign-anchor", "fail",
            "a well-formed reference at another logical address cannot bind the reservation",
            operation="transition-audit",
            changes={"transitionEvidence": {"reservationRef": {"anchor": {
                "kind": "storage-program", "locator": "dacs4:legacy-payment-reservation:job-other:2",
            }}}},
        ),
        case(
            "laa-transition-audit-missing-distinct-evidence", "indeterminate",
            "ordinary settlement evidence cannot substitute for missing transition evidence",
            operation="transition-audit",
            changes={"transitionEvidence": None, "settlementEvidence": {"position": "120"}},
        ),
        case(
            "laa-transition-audit-unknown-evidence-type", "error",
            "an unknown transition-evidence discriminator is not interpreted",
            operation="transition-audit",
            changes={"transitionEvidence": {"discriminator": "legacyTransitionEvidenceVersion:99"}},
        ),
        case(
            "laa-transition-audit-ordinary-evidence-coercion", "error",
            "the distinct transition type cannot also claim ordinary SettlementEvidence",
            operation="transition-audit",
            changes={"transitionEvidence": {"evidenceVersion": "1"}},
        ),
        case(
            "laa-transition-audit-evidence-signature-invalid", "fail",
            "transition evidence requires its own valid domain-separated signature",
            operation="transition-audit",
            changes={"transitionEvidence": {"signature": {"signatureValid": False}}},
        ),
        case(
            "laa-transition-audit-evidence-signature-missing", "error",
            "transition evidence without its signature envelope is malformed",
            operation="transition-audit",
            changes={"transitionEvidence": {"signature": None}},
        ),
        case(
            "laa-transition-audit-evidence-wrong-signer", "fail",
            "the transition-evidence signer must be the retained session orchestrator",
            operation="transition-audit",
            changes={"transitionEvidence": {"signature": {"signer": "did:demos:seller"}}},
        ),
        case(
            "laa-transition-audit-evidence-writer-missing", "error",
            "the finalized transition-evidence receipt must authenticate its writer",
            operation="transition-audit",
            drops=[("transitionEvidence", "receiptWriter")],
        ),
        case(
            "laa-transition-audit-evidence-wrong-writer", "fail",
            "the transition-evidence receipt writer must be the retained orchestrator",
            operation="transition-audit",
            changes={"transitionEvidence": {"receiptWriter": "did:demos:seller"}},
        ),
        case(
            "laa-transition-audit-evidence-swapped-signer-writer", "fail",
            "party identities cannot replace the orchestrator as evidence signer/writer",
            operation="transition-audit",
            changes={"transitionEvidence": {
                "signature": {"signer": "did:demos:buyer"},
                "receiptWriter": "did:demos:seller",
            }},
        ),
        case(
            "laa-transition-audit-idempotency-key-missing", "error",
            "transition audit requires the exact consumed reservation idempotency key",
            operation="transition-audit",
            drops=[("paymentAuthority", "idempotencyKey")],
        ),
        case(
            "laa-transition-audit-idempotency-authority-unavailable", "indeterminate",
            "unavailable consumption authority cannot prove a completed transition",
            operation="transition-audit",
            changes={"paymentAuthority": {"idempotencyResolution": "unavailable"}},
        ),
        case(
            "laa-transition-audit-idempotency-wrong-key", "fail",
            "consumption of another key cannot prove this reservation executed",
            operation="transition-audit",
            changes={"paymentAuthority": {"idempotencyKey": "0" * 64}},
        ),
        case(
            "laa-transition-audit-idempotency-unused", "fail",
            "an unused reservation key proves no transition payment completed",
            operation="transition-audit",
            changes={"paymentAuthority": {"idempotencyResolution": "unused"}},
        ),
        case(
            "laa-transition-audit-txrefs-empty-object", "error",
            "an empty object is not a member of the closed ChainTxRef union",
            operation="transition-audit",
            changes={"transitionEvidence": {"paymentTxRefs": [{}]}},
        ),
        case(
            "laa-transition-audit-txrefs-boolean", "error",
            "a boolean is not a member of the closed ChainTxRef union",
            operation="transition-audit",
            changes={"transitionEvidence": {"paymentTxRefs": [True]}},
        ),
        case(
            "laa-transition-audit-txrefs-string", "error",
            "a string is not a member of the closed ChainTxRef union",
            operation="transition-audit",
            changes={"transitionEvidence": {"paymentTxRefs": ["bogus"]}},
        ),
        case(
            "laa-transition-audit-phase-index-boolean-equals-one", "error",
            "boolean true cannot exploit host-language equality with phase index one",
            operation="transition-audit",
            changes={
                "listingAuthority": {"phaseIndex": 1},
                "paymentEffect": {"phaseIndex": 1},
                "transitionEvidence": {"phaseIndex": True},
            },
            rederive_reservation=True,
        ),
        case(
            "laa-transition-audit-phase-index-negative", "error",
            "a negative transition-evidence phase index is malformed",
            operation="transition-audit",
            changes={"transitionEvidence": {"phaseIndex": -1}},
        ),
        case(
            "laa-transition-audit-phase-index-noninteger", "error",
            "a numerically equal floating point phase index is malformed",
            operation="transition-audit",
            changes={"transitionEvidence": {"phaseIndex": 2.0}},
        ),
        case(
            "laa-transition-audit-txrefs-duplicate", "fail",
            "duplicate canonical transaction references are not an exact settlement set",
            operation="transition-audit",
            changes={"transitionEvidence": {"paymentTxRefs": [
                {"kind": "demos", "txHash": "transition-tx-a", "blockNumber": 42},
                {"kind": "demos", "txHash": "transition-tx-a", "blockNumber": 42},
            ]}},
        ),
        case(
            "laa-transition-audit-txrefs-rail-substitution", "fail",
            "a well-formed reference for another rail cannot replace the exact pay-dem set",
            operation="transition-audit",
            changes={"transitionEvidence": {"paymentTxRefs": [{
                "kind": "evm", "chainId": 1, "txHash": "0x01",
            }]}},
        ),
        case(
            "laa-authentic-historical-settlement", "pass",
            "exact commitment and settlement evidence finalized strictly before the checkpoint",
        ),
        case(
            "laa-later-presentation-preserves-historical-era", "pass",
            "presentation after activation does not change verified original anchor order",
            changes={"presentationPosition": "9999"},
        ),
        case(
            "laa-checkpoint-unavailable", "indeterminate",
            "transport failure is not proof that activation has not occurred",
            operation="authorize-payment", changes={"checkpoint": {"resolution": "unavailable"}},
        ),
        case(
            "laa-ordinary-not-found", "indeterminate",
            "unqualified not-found is not binding-qualified authoritative absence",
            operation="authorize-payment", changes={"checkpoint": {"resolution": "absent", "authenticatedAbsence": False}},
        ),
        case(
            "laa-other-substrate-absence-is-inert", "fail",
            "authenticated absence on another substrate cannot evade this session's checkpoint",
            operation="authorize-payment",
            changes={"checkpoint": {"resolution": "absent", "authenticatedAbsence": True, "substrate": "other-mainnet"}},
        ),
        case(
            "laa-conflicting-checkpoints", "indeterminate",
            "multiple authorized checkpoint candidates do not establish an activation order",
            changes={"checkpoint": {"resolution": "conflicting"}},
        ),
        case(
            "laa-checkpoint-reorged", "indeterminate",
            "a reorged checkpoint receipt does not establish activation authority",
            changes={"checkpoint": {"resolution": "reorged"}},
        ),
        case(
            "laa-checkpoint-signature-invalid", "fail",
            "checkpoint must be signed by the authorized steward",
            changes={"checkpoint": {"signatureValid": False}},
        ),
        case(
            "laa-checkpoint-signer-unauthorized", "fail",
            "a valid signature from a non-steward is not checkpoint authority",
            changes={"checkpoint": {"stewardAuthorized": False}},
        ),
        case(
            "laa-checkpoint-address-mismatch", "fail",
            "checkpoint fetched away from its derived fixed address is rejected",
            changes={"checkpoint": {"addressMatches": False}},
        ),
        case(
            "laa-checkpoint-policy-mismatch", "fail",
            "an artifact signed for another transition policy is not this checkpoint",
            changes={"checkpoint": {"policyMatches": False}},
        ),
        case(
            "laa-checkpoint-cross-domain-signature", "fail",
            "a signature under another artifact domain cannot activate the gate",
            changes={"checkpoint": {"signatureDomain": "dacs-agreement:v1:"}},
        ),
        case(
            "laa-checkpoint-malformed", "error",
            "malformed checkpoint bytes are structural error",
            changes={"checkpoint": {"shape": "malformed"}},
        ),
        case(
            "laa-checkpoint-multiple-discriminators", "error",
            "ambiguous checkpoint type is rejected before policy action",
            changes={"checkpoint": {"discriminator": "multiple"}},
        ),
        case(
            "laa-checkpoint-not-finalized", "indeterminate",
            "included-only checkpoint does not yet establish activation",
            changes={"checkpoint": {"receiptState": "included"}},
        ),
        case(
            "laa-checkpoint-substrate-mismatch", "fail",
            "the checkpoint substrate must equal the authenticated session and receipt substrate",
            changes={"checkpoint": {"substrate": "other-mainnet"}},
        ),
        case(
            "laa-checkpoint-cross-order-domain", "indeterminate",
            "a checkpoint from another consensus ordering domain is not position-comparable",
            changes={"checkpoint": {"orderDomain": "demos-mainnet:other-finality:genesis-v1"}},
        ),
        case(
            "laa-missing-commitment-era-proof", "indeterminate",
            "historical audit cannot infer agreement era without commitment authority",
            changes={"commitment": {"resolution": "unavailable"}},
        ),
        case(
            "laa-commitment-hash-mismatch", "fail",
            "a real old commitment for different agreement bytes does not qualify",
            changes={"commitment": {"agreementHashMatches": False}},
        ),
        case(
            "laa-commitment-not-finalized", "indeterminate",
            "non-final commitment history is not era proof",
            changes={"commitment": {"receiptState": "included"}},
        ),
        case(
            "laa-commitment-substrate-mismatch", "fail",
            "a commitment receipt on another substrate cannot be ordered against this checkpoint",
            changes={"commitment": {"substrate": "other-mainnet"}},
        ),
        case(
            "laa-commitment-cross-order-domain", "indeterminate",
            "equal-looking positions from different commitment order domains are incomparable",
            changes={"commitment": {"orderDomain": "demos-mainnet:other-finality:genesis-v1"}},
        ),
        case(
            "laa-missing-settlement-era-proof", "indeterminate",
            "old agreement alone cannot prove payment happened before activation",
            changes={"settlementEvidence": {"resolution": "unavailable"}},
        ),
        case(
            "laa-settlement-binding-mismatch", "fail",
            "settlement evidence for another agreement cannot qualify history",
            changes={"settlementEvidence": {"agreementBindingMatches": False}},
        ),
        case(
            "laa-settlement-not-finalized", "indeterminate",
            "included-only settlement evidence is not historical authority",
            changes={"settlementEvidence": {"receiptState": "included"}},
        ),
        case(
            "laa-settlement-substrate-mismatch", "fail",
            "the DACS SettlementEvidence anchor receipt must share the checkpoint substrate",
            changes={"settlementEvidence": {"substrate": "other-mainnet"}},
        ),
        case(
            "laa-settlement-cross-order-domain", "indeterminate",
            "a settlement-evidence receipt from another ordering domain is incomparable",
            changes={"settlementEvidence": {"orderDomain": "demos-mainnet:other-finality:genesis-v1"}},
        ),
        case(
            "laa-same-position-unorderable", "indeterminate",
            "same block without authenticated transaction order is not strictly earlier",
            changes={"commitment": {"position": "100", "strictlyBeforeAtSamePosition": None}},
        ),
        case(
            "laa-same-position-strict-order", "pass",
            "binding-authenticated same-block transaction order can prove strict precedence",
            changes={
                "commitment": {"position": "100", "strictlyBeforeAtSamePosition": True},
                "settlementEvidence": {"position": "100", "strictlyBeforeAtSamePosition": True},
            },
        ),
        case(
            "laa-backdated-evidence-observed-at", "fail",
            "producer evidence time cannot make a post-checkpoint receipt historical",
            changes={"settlementEvidence": {"position": "101", "observedAt": -5000}},
        ),
        case(
            "laa-deterministic-mismatch-precedes-outage", "fail",
            "bad agreement signature cannot be hidden by checkpoint unavailability",
            operation="authorize-payment",
            changes={"agreement": {"partySignaturesValid": False}, "checkpoint": {"resolution": "unavailable"}},
        ),
        case(
            "laa-malformed-agreement", "error",
            "malformed agreement is an error even when checkpoint proof is unavailable",
            operation="authorize-payment",
            changes={"agreement": {"shape": "malformed"}, "checkpoint": {"resolution": "unavailable"}},
        ),
        case(
            "laa-cross-agreement-replay", "fail",
            "authentic settlement evidence bound to a different agreement cannot qualify this agreement's history",
            changes={"settlementEvidence": {"agreementHash": "agreement-hash-other"}},
        ),
        case(
            "laa-cross-job-replay", "fail",
            "settlement evidence bound to a different job cannot qualify this agreement's history",
            changes={"settlementEvidence": {"job": "job-other"}},
        ),
        case(
            "laa-cross-session-replay", "fail",
            "settlement evidence bound to a different session cannot qualify this agreement's history",
            changes={"settlementEvidence": {"session": "session-other"}},
        ),
        case(
            "laa-cross-phase-replay", "fail",
            "settlement evidence bound to a different phase cannot qualify this agreement's history",
            changes={"settlementEvidence": {"phase": "pay-evm-erc20"}},
        ),
        case(
            "laa-agreement-job-session-mismatch", "fail",
            "an agreement whose jobId does not match the authenticated session jobId cannot qualify",
            changes={"agreement": {"jobId": "job-other"}},
        ),
        case(
            "laa-malformed-agreement-wrong-container", "error",
            "a non-object agreement container is a structural error before field access",
            operation="authorize-payment",
            changes={"agreement": []},
        ),
        case(
            "laa-malformed-checkpoint-wrong-container", "error",
            "a non-object checkpoint container is a structural error before field access",
            operation="authorize-payment",
            changes={"checkpoint": []},
        ),
        case(
            "laa-malformed-commitment-missing-field", "error",
            "a commitment missing a required structural field is a structural error",
            drops=[("commitment", "shape")],
        ),
        case(
            "laa-malformed-settlement-position-scalar", "error",
            "a non-string receipt position is a structural error before ordering",
            changes={"settlementEvidence": {"position": 90}},
        ),
        case(
            "laa-malformed-checkpoint-conflicting-shape", "error",
            "a checkpoint whose discriminator is not the exact literal is a structural error",
            operation="authorize-payment",
            changes={"checkpoint": {"shape": "valid", "discriminator": ["a", "b"]}},
        ),
        case(
            "laa-malformed-agreement-artifact-unhashable", "error",
            "an unhashable agreement artifact is a structural error before membership tests",
            operation="authorize-payment",
            changes={"agreement": {"artifact": ["legacy"]}},
        ),
        case(
            "laa-malformed-settlement-position-unhashable-list", "error",
            "an unhashable list receipt position returns error, never a crash",
            changes={"settlementEvidence": {"position": ["90"]}},
        ),
        case(
            "laa-malformed-settlement-position-unhashable-dict", "error",
            "an unhashable dict receipt position returns error, never a crash",
            changes={"settlementEvidence": {"position": {"block": 90}}},
        ),
        case(
            "laa-malformed-commitment-position-unhashable", "error",
            "an unhashable commitment receipt position returns error, never a crash",
            changes={"commitment": {"position": ["80"]}},
        ),
        case(
            "laa-malformed-settlement-missing-agreement-binding", "error",
            "a settlement-evidence record missing agreementBindingMatches is a structural error, not a fail",
            drops=[("settlementEvidence", "agreementBindingMatches")],
        ),
        case(
            "laa-malformed-commitment-missing-hash-binding", "error",
            "a commitment missing agreementHashMatches is a structural error, not a fail",
            drops=[("commitment", "agreementHashMatches")],
        ),
        case(
            "laa-malformed-operation-unhashable-list", "error",
            "an unhashable list operation returns error, never a TypeError",
            changes={"operation": ["historical-audit"]},
        ),
        case(
            "laa-malformed-operation-unhashable-dict", "error",
            "an unhashable dict operation returns error, never a TypeError",
            changes={"operation": {"kind": "historical-audit"}},
        ),
        case(
            "laa-malformed-agreement-contentHash-missing", "error",
            "a legacy agreement missing contentHash is a structural error, not a hash fail",
            drops=[("agreement", "contentHash")],
        ),
        case(
            "laa-malformed-checkpoint-signatureValid-missing", "error",
            "a checkpoint missing signatureValid is a structural error, not a signature fail",
            drops=[("checkpoint", "signatureValid")],
        ),
        case(
            "laa-malformed-checkpoint-receiptState-nonstring", "error",
            "a non-string checkpoint receiptState is a structural error, not indeterminate",
            changes={"checkpoint": {"receiptState": ["finalized"]}},
        ),
        case(
            "laa-malformed-checkpoint-receiptState-unknown", "error",
            "an unknown checkpoint receiptState spelling is a structural error, not indeterminate",
            changes={"checkpoint": {"receiptState": "bogus"}},
        ),
        case(
            "laa-malformed-commitment-receiptState-missing", "error",
            "a commitment missing receiptState is a structural error, not indeterminate",
            drops=[("commitment", "receiptState")],
        ),
        case(
            "laa-malformed-settlement-receiptState-unknown", "error",
            "an unknown settlement receiptState spelling is a structural error, not indeterminate",
            changes={"settlementEvidence": {"receiptState": "bogus"}},
        ),
        case(
            "laa-malformed-commitment-signatureValid-missing", "error",
            "a commitment missing signatureValid is a structural error, not a signature fail",
            drops=[("commitment", "signatureValid")],
        ),
        case(
            "laa-malformed-settlement-signatureValid-missing", "error",
            "a settlement-evidence record missing signatureValid is a structural error",
            drops=[("settlementEvidence", "signatureValid")],
        ),
        case(
            "laa-malformed-native-order-unhashable", "error",
            "an unhashable same-block native-order flag is a structural error, not a silent fall-through",
            changes={
                "commitment": {"position": "100", "strictlyBeforeAtSamePosition": ["x"]},
                "settlementEvidence": {"position": "100", "strictlyBeforeAtSamePosition": True},
            },
        ),
        case(
            "laa-malformed-payment-head-dict", "error",
            "a non-string authenticated payment-head position is a structural error",
            operation="authorize-payment",
            changes={
                "sessionAuthority": {"paymentHeadPosition": {"block": 150}},
                "checkpoint": {"resolution": "absent", "authenticatedAbsence": True},
            },
        ),
        case(
            "laa-malformed-session-jobId-nonstring", "error",
            "a non-string authenticated session jobId is a structural error",
            changes={"sessionAuthority": {"jobId": ["job-a"]}},
        ),
        case(
            "laa-malformed-settlement-agreementHash-missing", "error",
            "a settlement-evidence record missing agreementHash is a structural error, not a binding fail",
            drops=[("settlementEvidence", "agreementHash")],
        ),
        case(
            "laa-malformed-settlement-job-missing", "error",
            "a settlement-evidence record missing the bound job is a structural error, not a replay fail",
            drops=[("settlementEvidence", "job")],
        ),
        case(
            "laa-malformed-payee-bound-contentHash-missing", "error",
            "a payee-bound agreement missing contentHash is a structural error before the current-payment pass",
            operation="authorize-payment", artifact="payee-bound",
            drops=[("agreement", "contentHash")],
        ),
        case(
            "laa-malformed-identity-bound-contentHash-missing", "error",
            "an identity-bound agreement missing contentHash is a structural error before the artifact branch",
            operation="authorize-payment", artifact="identity-bound",
            drops=[("agreement", "contentHash")],
        ),
        case(
            "laa-absence-with-malformed-operation", "error",
            "an authenticated absence branch cannot authorize before operation is validated as a scalar known value",
            operation="authorize-payment",
            changes={
                "operation": ["authorize-payment"],
                "checkpoint": {"resolution": "absent", "authenticatedAbsence": True},
            },
        ),
        # --- Identity values: empty / whitespace / non-canonical session or hash
        # identity is malformed and rejected before any payee-bound / identity-bound /
        # zero-pay / absence / checkpoint branch may otherwise authorize. ---
        case(
            "laa-payee-bound-empty-content-hash", "error",
            "an empty payee-bound contentHash is malformed identity, rejected before the current-payment pass",
            operation="authorize-payment", artifact="payee-bound",
            changes={"agreement": {"contentHash": ""}},
        ),
        case(
            "laa-payee-bound-whitespace-content-hash", "error",
            "a whitespace-only payee-bound contentHash is malformed identity",
            operation="authorize-payment", artifact="payee-bound",
            changes={"agreement": {"contentHash": "   "}},
        ),
        case(
            "laa-identity-bound-payee-padded-content-hash", "error",
            "a leading/trailing-whitespace identity-bound-payee contentHash is non-canonical",
            operation="authorize-payment", artifact="identity-bound-payee",
            changes={"agreement": {"contentHash": " agreement-hash-a "}},
        ),
        case(
            "laa-zero-pay-legacy-whitespace-content-hash", "error",
            "a whitespace-only contentHash cannot authorize the legacy zero-pay branch",
            operation="commit-pay-bearing",
            changes={"pipelineHasPayment": False, "agreement": {"contentHash": "   "}},
        ),
        case(
            "laa-empty-session-id", "error",
            "an empty authenticated sessionId is malformed identity, rejected before the checkpoint branch",
            changes={"sessionAuthority": {"sessionId": ""}},
        ),
        case(
            "laa-whitespace-session-id", "error",
            "a whitespace-only authenticated sessionId is malformed identity",
            changes={"sessionAuthority": {"sessionId": "   "}},
        ),
        case(
            "laa-padded-session-id", "error",
            "a leading/trailing-whitespace authenticated sessionId is non-canonical",
            changes={"sessionAuthority": {"sessionId": " session-a "}},
        ),
        case(
            "laa-padded-content-hash", "error",
            "a leading/trailing-whitespace agreement contentHash is non-canonical identity",
            changes={"agreement": {"contentHash": " agreement-hash-a "}},
        ),
        # --- Session identity is validated AHEAD of the payee-bound /
        # identity-bound-payee pass, so an empty / blank / padded / non-NFC
        # sessionId can never authorize a current payment on either artifact. ---
        case(
            "laa-payee-bound-empty-session-id", "error",
            "an empty payee-bound sessionId is malformed identity, rejected before the current-payment pass",
            operation="authorize-payment", artifact="payee-bound",
            changes={"sessionAuthority": {"sessionId": ""}},
        ),
        case(
            "laa-payee-bound-whitespace-session-id", "error",
            "a whitespace-only payee-bound sessionId is malformed identity",
            operation="authorize-payment", artifact="payee-bound",
            changes={"sessionAuthority": {"sessionId": "   "}},
        ),
        case(
            "laa-payee-bound-padded-session-id", "error",
            "a leading/trailing-whitespace payee-bound sessionId is non-canonical",
            operation="authorize-payment", artifact="payee-bound",
            changes={"sessionAuthority": {"sessionId": " session-a "}},
        ),
        case(
            "laa-payee-bound-noncanonical-session-id", "error",
            "a non-NFC payee-bound sessionId is malformed identity",
            operation="authorize-payment", artifact="payee-bound",
            changes={"sessionAuthority": {"sessionId": "session-a\u0301"}},
        ),
        case(
            "laa-identity-bound-payee-empty-session-id", "error",
            "an empty identity-bound-payee sessionId is malformed identity, rejected before the pass",
            operation="authorize-payment", artifact="identity-bound-payee",
            changes={"sessionAuthority": {"sessionId": ""}},
        ),
        case(
            "laa-identity-bound-payee-whitespace-session-id", "error",
            "a whitespace-only identity-bound-payee sessionId is malformed identity",
            operation="authorize-payment", artifact="identity-bound-payee",
            changes={"sessionAuthority": {"sessionId": "   "}},
        ),
        case(
            "laa-identity-bound-payee-padded-session-id", "error",
            "a leading/trailing-whitespace identity-bound-payee sessionId is non-canonical",
            operation="authorize-payment", artifact="identity-bound-payee",
            changes={"sessionAuthority": {"sessionId": " session-a "}},
        ),
        case(
            "laa-identity-bound-payee-noncanonical-session-id", "error",
            "a non-NFC identity-bound-payee sessionId is malformed identity",
            operation="authorize-payment", artifact="identity-bound-payee",
            changes={"sessionAuthority": {"sessionId": "session-a\u0301"}},
        ),
    ]


RELEASE_PIN = "0000000000000000000000000000000000000001"
CURRENT_MODULE_TUPLE = {
    "core": "0.3",
    "dacs1": "0.7",
    "dacs2": "0.6",
    "dacs3": "0.6",
    "dacs4": "0.8",
    "dacs5": "0.6",
}


def document() -> dict:
    values = vectors()
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {
        "set": OUTPUT.stem,
        "spec": "DACS-4 v0.8 §9.5.1 LAA-1..LAA-7; DACS-3 v0.6 §8.6 CA-10",
        "tier": "candidate",
        "profile": {
            "releasePin": RELEASE_PIN,
            "moduleVersions": CURRENT_MODULE_TUPLE,
        },
        "description": "Governed legacy-agreement activation, bounded transition completion, and authenticated settlement audit admission.",
        "provenance": {
            "issue": "DACS-Agent-commerce/DACS-Standard#377",
            "generator": "scripts/generate_legacy_agreement_admission_vectors.py",
        },
        "count": len(values),
        "hash": hashlib.sha256(encoded).hexdigest(),
        "vectors": values,
    }


def render() -> bytes:
    return (json.dumps(document(), indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render()
    if args.write:
        OUTPUT.write_bytes(expected)
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if not OUTPUT.exists() or OUTPUT.read_bytes() != expected:
        print(f"ERROR: {OUTPUT.relative_to(ROOT)} is not deterministic/in sync")
        return 1
    print(f"verified {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
