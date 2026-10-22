#!/usr/bin/env python3
"""Deterministic PC-1, AMEND-1 and RTB-1 fixtures with public test keys.

Usage:
  python3 scripts/generate_settlement_contract_vectors.py --write
  python3 scripts/generate_settlement_contract_vectors.py --check
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import settlement_contract_reference as ref

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/fixtures/settlement/payment-input-amendment-v0.1.json"
RAIL_OUTPUT = ROOT / "conformance/fixtures/settlement/rail-authority-time-bound-v0.1.json"

# Public, deterministic test seeds; every derived key is published in the
# fixture. They authorize nothing outside these fixtures.
SEEDS = {
    "network": bytes.fromhex("11" * 32),
    "buyer": bytes.fromhex("22" * 32),
    "seller": bytes.fromhex("33" * 32),
    "orchestrator": bytes.fromhex("44" * 32),
    "payer": bytes.fromhex("55" * 32),
    "steward": bytes.fromhex("77" * 32),
}
CLAIMS = {role: f"did:dacs:test:{role}" for role in SEEDS}
JOB_ID = "01K1DPA0000000000000000000"
RAIL_ID = "demos-native:DEM"
NETWORK_ID = "demos:testnet"
PROOF_PROFILE = "demos-bft-proof/test-1"
VALIDATOR_SET_ID = "test-validator-set-1"
SESSION_STARTED_AT = 1_799_999_800_000
# Verifier-owned native receipt writers (CORE SR2-11): the orchestrator writes
# its payment evidence and the registry steward writes the index and rails.
ORCHESTRATOR_WRITER = "native:orchestrator-writer-1"
REGISTRY_WRITER = "native:registry-steward-writer-1"
OUTSIDER_WRITER = "native:outsider-writer-1"
AGREEMENT_DOMAIN = b"dacs-agreement:v1:"
EVIDENCE_DOMAIN = b"dacs-evidence:v1:"
LEGACY_DOMAIN = b"dacs-legacy-transition-evidence:v1:"
FINALITY_DOMAIN = b"dacs-finality-bound-evidence:v1:"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _key(role: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(SEEDS[role])


PUBLIC_KEYS = {CLAIMS[role]: b64u(_key(role).public_key().public_bytes_raw()) for role in SEEDS}
# A public, deterministic secp256k1 test key for the orchestrator, so the
# registered-but-unimplemented ecdsa-secp256k1 case carries a genuine value.
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ECDSA_PRIVATE_VALUE = (int.from_bytes(hashlib.sha256(b"settlement-contract-orchestrator-ecdsa").digest(), "big")
                       % (SECP256K1_ORDER - 1)) + 1
ECDSA_PUBLIC_KEYS = {CLAIMS["orchestrator"]: ec.derive_private_key(ECDSA_PRIVATE_VALUE, ec.SECP256K1())
                     .public_key().public_bytes(serialization.Encoding.X962,
                                                serialization.PublicFormat.CompressedPoint).hex()}


def retained_state(session=None, *, job_id=JOB_ID, orchestrator=None, steward=None):
    """Independent fixture root's authenticated session/registry snapshot."""
    return sign({
        "jobId": job_id,
        "session": session if session is not None else {
            "startedAt": SESSION_STARTED_AT, "railRegistryVersion": 1},
        "orchestrator": orchestrator or CLAIMS["orchestrator"],
        "writer": ORCHESTRATOR_WRITER,
        "steward": steward or CLAIMS["steward"],
        "registryWriter": REGISTRY_WRITER,
    }, "network", ref.RETAINED_STATE_DOMAIN)


def ecdsa_sign(message: bytes) -> bytes:
    """RFC 6979 secp256k1/SHA-256 with canonical DER and low-S output."""
    digest_bytes = hashlib.sha256(message).digest()
    private_bytes = ECDSA_PRIVATE_VALUE.to_bytes(32, "big")
    reduced = (int.from_bytes(digest_bytes, "big") % SECP256K1_ORDER).to_bytes(32, "big")
    value, key = b"\x01" * 32, b"\x00" * 32
    key = hmac.new(key, value + b"\x00" + private_bytes + reduced, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(key, value + b"\x01" + private_bytes + reduced, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        nonce = int.from_bytes(value, "big")
        if 1 <= nonce < SECP256K1_ORDER:
            break
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()
    r = ec.derive_private_key(nonce, ec.SECP256K1()).public_key().public_numbers().x % SECP256K1_ORDER
    s = (pow(nonce, -1, SECP256K1_ORDER)
         * (int.from_bytes(digest_bytes, "big") + r * ECDSA_PRIVATE_VALUE)) % SECP256K1_ORDER
    return utils.encode_dss_signature(r, min(s, SECP256K1_ORDER - s))


def duplicate_job_id(value: dict) -> str:
    """JSON text of `value` with a leading second `jobId` member (CORE CF-5 refuses it)."""
    return '{"jobId":"01K1DPA0000000000000000009",' + json.dumps(value, ensure_ascii=False)[1:]


def hashed(label: str) -> str:
    """A deterministic placeholder digest for an artifact the fixture does not carry."""
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def sign(value: dict, role: str, domain: bytes) -> dict:
    """A copy carrying `signature` over domain || content hash (CORE §B.7)."""
    out = copy.deepcopy(value)
    digest = ref.content_hash(out)
    out["signature"] = {
        "algorithm": "ed25519", "signer": CLAIMS[role],
        "value": b64u(_key(role).sign(domain + digest.encode("ascii"))),
    }
    return out


def sign_ecdsa(value: dict, domain: bytes) -> dict:
    """A copy carrying the orchestrator's genuine ecdsa-secp256k1 signature."""
    out = copy.deepcopy(value)
    digest = ref.content_hash(out)
    out["signature"] = {
        "algorithm": "ecdsa-secp256k1", "signer": CLAIMS["orchestrator"],
        "value": b64u(ecdsa_sign(domain + digest.encode("ascii"))),
    }
    return out


def native_address(label: str) -> str:
    return "stor-" + ref.sha256_hex(label.encode("utf-8"))[:40]


def anchor_receipt(logical_address: str, content_hash: str, *, label: str, nonce: str,
                   writer: str, block_timestamp: int = 1_799_999_750_000,
                   state: str = "finalized", native: str | None = None,
                   disposition: str = "established") -> dict:
    """An AnchorReceipt whose synthetic proof binds every member but `evidence`.

    `blockRef.timestamp` is CORE SR2-6 consensus time in unix milliseconds.
    """
    receipt = {
        "receiptVersion": "1",
        "substrate": NETWORK_ID,
        "finalityProfile": PROOF_PROFILE,
        "logicalAddress": logical_address,
        "nativeAddress": native or native_address(logical_address),
        "contentHash": content_hash,
        "transactionRef": {"kind": "demos-transaction", "value": f"tx-{label}"},
        "writer": writer,
        "nonce": nonce,
        "state": state,
        "observationDisposition": disposition,
        "observedAt": block_timestamp + 1_000,
        "blockRef": {"id": f"block-{label}-750", "height": "750", "timestamp": block_timestamp},
    }
    if disposition == "indeterminate":
        receipt["preservedReceiptHash"] = hashed(f"preserved-receipt:{label}")
    proof = sign({
        "receipt": receipt,
        "networkId": NETWORK_ID,
        "proofProfile": PROOF_PROFILE,
        "validatorSetId": VALIDATOR_SET_ID,
    }, "network", ref.ANCHOR_TEST_DOMAIN)
    return {**receipt, "evidence": {"kind": ref.ANCHOR_TEST_KIND, "value": b64u(ref.jcs_bytes(proof))}}


def steward_rail(**change) -> dict:
    """The pay-dem RailDefinition, signed by the rail-registry steward (RD-1)."""
    rail = {
        "railVersion": 1, "railId": RAIL_ID, "railType": "demos-native",
        "asset": {"kind": "native-dem", "symbol": "DEM", "decimals": 9},
        "network": {"kind": "demos"}, "phaseHandler": "pay-dem", "parameters": {},
        "availability": "live",
        "governance": {"proposedBy": CLAIMS["steward"], "acceptedAt": 1_799_999_700_000,
                       "anchoring": "single-signer"},
    }
    rail.update(change)
    return sign(rail, "steward", ref.RAIL_DOMAIN)


def ordinary_payment_input() -> dict:
    """A complete ordinary PaymentPhaseInput for one pay-dem invocation."""
    listing_ref = {"listingId": "fixed-price-1", "version": 1,
                   "contentHash": hashed("listing:fixed-price-1")}

    def vet_ref(role):
        return {"anchor": {"kind": "storage-program",
                           "locator": f"dacs2:composite:{JOB_ID}:did%3Adacs%3Atest%3A{role}"},
                "contentHash": hashed("vet:" + role), "signer": CLAIMS["orchestrator"]}

    def party(role, **extra):
        return {"role": role, "bundleHash": hashed("bundle:" + role),
                "primaryClaim": CLAIMS[role], **extra}

    agreement = {
        "agreementVersion": "1", "jobId": JOB_ID, "listingRef": listing_ref,
        "parties": [party("buyer", vetRecordRef=vet_ref("buyer")),
                    party("seller", vetRecordRef=vet_ref("seller"))],
        "terms": {
            "price": {"amount": "10", "currency": "DEM"},
            "rail": {"railId": RAIL_ID},
            "deliverable": {"deliverableType": "storage-program", "hash": hashed("deliverable"),
                            "schemaUrl": "https://dacs.dev/result-v1.json"},
            "deadline": 1_800_000_060_000,
        },
        "derivedFromPattern": "fixed-price",
        "generatedAt": 1_799_999_900_000,
    }
    agreement_hash = ref.sha256_hex(ref.jcs_bytes(agreement))
    agreement["signatures"] = [
        {"party": CLAIMS[role], "algorithm": "ed25519",
         "value": b64u(_key(role).sign(AGREEMENT_DOMAIN + agreement_hash.encode("ascii")))}
        for role in ("buyer", "seller")
    ]
    return {
        "jobId": JOB_ID,
        "agreement": agreement,
        "rail": steward_rail(),
        "payer": {"bundleHash": hashed("bundle:buyer"), "primaryClaim": CLAIMS["buyer"],
                  "payingKey": CLAIMS["payer"]},
        "payee": {"bundleHash": hashed("bundle:seller"), "primaryClaim": CLAIMS["seller"],
                  "payeeAddress": "dem-test-seller"},
        "amount": {"amount": "10", "currency": "DEM"},
        "sessionContext": {
            "jobId": JOB_ID, "listingRef": listing_ref,
            "recipeRegistryVersion": 1, "railRegistryVersion": 1,
            "parties": [party("seller", vetRecordRef=vet_ref("seller")), party("orchestrator"),
                        party("buyer", vetRecordRef=vet_ref("buyer"))],
            "priorPhaseOutputs": {"agreementHash": agreement_hash,
                                  "commitmentHash": hashed("commitment")},
            "startedAt": SESSION_STARTED_AT,
        },
    }


def build_fixture():
    ordinary_input = ordinary_payment_input()
    inputs = []

    def phase(name, binding, value, expected, identity_binding=None):
        # `identityBinding` is the verifier-owned IBH-1..IBH-5 rerun outcome;
        # an identity-bound case without one has no rerun authority.
        inputs.append({"name": name, "ruleRefs": ["PC-1"], "binding": binding,
                       **({"identityBinding": identity_binding} if identity_binding else {}),
                       "input": value, "expected": expected})

    phase("ordinary-input", "ordinary", ordinary_input, "accepted")
    phase("ordinary-keeps-unknown-members", "ordinary",
          {**ordinary_input, "paymentAuthorization": {"opaque": True}}, "accepted")
    # PriceTerm's optional `unit` is a non-empty string when present.
    phase("ordinary-amount-unit", "ordinary",
          {**ordinary_input, "amount": {**ordinary_input["amount"], "unit": "token"}}, "accepted")
    phase("ordinary-amount-unit-empty", "ordinary",
          {**ordinary_input, "amount": {**ordinary_input["amount"], "unit": ""}}, "rejected")
    missing = copy.deepcopy(ordinary_input)
    missing.pop("sessionContext")
    phase("ordinary-context-missing", "ordinary", missing, "rejected")
    for member in ("jobId", "agreement", "rail", "payer", "payee", "amount"):
        missing = copy.deepcopy(ordinary_input)
        missing.pop(member)
        phase("ordinary-missing-" + member, "ordinary", missing, "rejected")
    # A present member of the wrong type fails its arm before any rail call.
    session = ordinary_input["sessionContext"]
    agreement = ordinary_input["agreement"]
    rail = ordinary_input["rail"]

    def session_party(**change):
        return {"sessionContext": {**session, "parties": [
            {**session["parties"][0], **change}, *session["parties"][1:]]}}

    def listing_ref(**change):
        return {"sessionContext": {**session, "listingRef": {**session["listingRef"], **change}}}

    def agreement_with(**change):
        return {"agreement": {**agreement, **change}}

    def agreement_party(**change):
        return agreement_with(parties=[{**agreement["parties"][0], **change}, *agreement["parties"][1:]])

    def agreement_terms(**change):
        return agreement_with(terms={**agreement["terms"], **change})

    def agreement_signature(**change):
        return agreement_with(signatures=[{**agreement["signatures"][0], **change},
                                          *agreement["signatures"][1:]])

    def rail_with(**change):
        return {"rail": {**rail, **change}}

    def rail_without(member):
        return {"rail": {k: v for k, v in rail.items() if k != member}}

    def rail_governance(**change):
        return rail_with(governance={**rail["governance"], **change})

    # A complete pay-dem consumer finality profile (DACS-4 9.4.1, 9.4.3).
    bft_final = {
        "kind": "bft-final", "networkId": NETWORK_ID, "genesisHash": "9a" * 32,
        "validatorSetRef": {"anchor": {"kind": "storage-program",
                                       "locator": "dacs4:validator-set:test-validator-set-1"},
                            "contentHash": "78" * 32},
        "quorumNumerator": 2, "quorumDenominator": 3,
        "observation": {"method": "consensus-backed-proxy",
                        "authorityRefs": [CLAIMS["network"]], "maxHeadAgeSec": 60},
    }
    finality_profile = {"finalityProfileVersion": "1", "model": "bft-final", "settlement": bft_final}

    def rail_finality(**change):
        return rail_with(consumerFinalityProfile={**finality_profile, **change})

    def rail_settlement(**change):
        return rail_finality(settlement={**bft_final, **change})

    # A sealed-selection agreement carries payout bindings and its selection receipt.
    sealed = {
        "sealedSelectionAgreementVersion": "1",
        **{k: v for k, v in agreement.items() if k != "agreementVersion"},
        "derivedFromPattern": "sealed-envelope",
        "selectionReceiptRef": {"anchor": {"kind": "storage-program",
                                           "locator": f"dacs3:selection:{JOB_ID}:1"},
                                "contentHash": "56" * 32},
        "terms": {**agreement["terms"], "payoutBindings": [{
            "railId": rail["railId"], "phaseIndex": 2,
            "payeeAddress": ordinary_input["payee"]["payeeAddress"]}]},
    }
    phase("ordinary-sealed-selection-agreement", "ordinary",
          {**ordinary_input, "agreement": sealed}, "accepted")
    # Nested ordinary members stay open under SIG-5, as top-level ones do.
    phase("ordinary-session-listing-ref-extra-member", "ordinary",
          {**ordinary_input, **listing_ref(note="x")}, "accepted")
    vet = agreement["parties"][0]["vetRecordRef"]
    for label, change in (
        ("ordinary-amount-extra-member", {"amount": {**ordinary_input["amount"], "note": "x"}}),
        ("ordinary-agreement-price-extra-member",
         agreement_terms(price={**agreement["terms"]["price"], "note": "x"})),
        ("ordinary-agreement-vet-record-ref-extra-member",
         agreement_party(vetRecordRef={**vet, "note": "x", "anchor": {**vet["anchor"], "note": "x"}})),
        ("ordinary-payer-extra-member", {"payer": {**ordinary_input["payer"], "note": "x"}}),
        ("ordinary-payee-extra-member", {"payee": {**ordinary_input["payee"], "note": "x"}}),
    ):
        phase(label, "ordinary", {**ordinary_input, **change}, "accepted")
    for label, change in (
        ("ordinary-sealed-selection-agreement-fixed-price",
         {"agreement": {**sealed, "derivedFromPattern": "fixed-price"}}),
        ("ordinary-sealed-selection-agreement-without-receipt-ref",
         {"agreement": {k: v for k, v in sealed.items() if k != "selectionReceiptRef"}}),
        ("ordinary-agreement-job-id-empty", agreement_with(jobId="")),
        ("ordinary-agreement-listing-ref-version-zero",
         agreement_with(listingRef={**agreement["listingRef"], "version": 0})),
        ("ordinary-agreement-parties-empty", agreement_with(parties=[])),
        ("ordinary-agreement-party-role-unknown", agreement_party(role="orchestrator")),
        ("ordinary-agreement-party-bundle-hash-empty", agreement_party(bundleHash="")),
        ("ordinary-agreement-party-claim-malformed", agreement_party(primaryClaim="not a claim")),
        ("ordinary-agreement-terms-without-deadline",
         agreement_with(terms={k: v for k, v in agreement["terms"].items() if k != "deadline"})),
        ("ordinary-agreement-deliverable-string", agreement_terms(deliverable="storage-program")),
        ("ordinary-agreement-deadline-string",
         agreement_terms(deadline=str(agreement["terms"]["deadline"]))),
        ("ordinary-agreement-pattern-unknown", agreement_with(derivedFromPattern="auction")),
        ("ordinary-agreement-generated-at-negative", agreement_with(generatedAt=-1)),
        ("ordinary-agreement-signature-party-malformed", agreement_signature(party="not a claim")),
        ("ordinary-agreement-signature-algorithm-unknown", agreement_signature(algorithm="rsa")),
        ("ordinary-agreement-signature-value-empty", agreement_signature(value="")),
        ("ordinary-rail-id-empty", rail_with(railId="")),
        ("ordinary-rail-id-too-long", rail_with(railId="r" * 65)),
        ("ordinary-rail-network-kind-unknown", rail_with(network={"kind": "bitcoin"})),
        ("ordinary-rail-parameters-array", rail_with(parameters=[])),
        ("ordinary-rail-availability-unknown", rail_with(availability="paused")),
        ("ordinary-rail-without-signature", rail_without("signature")),
        ("ordinary-rail-governance-without-accepted-at",
         rail_with(governance={k: v for k, v in rail["governance"].items() if k != "acceptedAt"})),
        ("ordinary-rail-proposed-by-malformed", rail_governance(proposedBy="not a claim")),
        ("ordinary-rail-accepted-at-string",
         rail_governance(acceptedAt=str(rail["governance"]["acceptedAt"]))),
        ("ordinary-rail-signature-without-algorithm",
         rail_with(signature={k: v for k, v in rail["signature"].items() if k != "algorithm"})),
        ("ordinary-rail-signature-value-empty", rail_with(signature={**rail["signature"], "value": ""})),
        ("ordinary-empty-session-context", {"sessionContext": {}}),
        ("ordinary-session-without-started-at",
         {"sessionContext": {k: v for k, v in session.items() if k != "startedAt"}}),
        ("ordinary-session-parties-not-array", {"sessionContext": {**session, "parties": {}}}),
        ("ordinary-null-payer", {"payer": None}),
        ("ordinary-payer-without-paying-key",
         {"payer": {k: v for k, v in ordinary_input["payer"].items() if k != "payingKey"}}),
        ("ordinary-payee-address-empty", {"payee": {**ordinary_input["payee"], "payeeAddress": ""}}),
        ("ordinary-amount-number", {"amount": 10}),
        ("ordinary-amount-zero", {"amount": {**ordinary_input["amount"], "amount": "0"}}),
        ("ordinary-job-id-number", {"jobId": 1}),
        ("ordinary-rail-string", {"rail": "demos-native:DEM"}),
        ("ordinary-companions-not-array", {"identityBindingCompanions": {}}),
        ("ordinary-session-listing-ref-version-zero", listing_ref(version=0)),
        ("ordinary-session-listing-ref-empty-listing-id", listing_ref(listingId="")),
        ("ordinary-session-party-claim-malformed", session_party(primaryClaim="not a claim")),
        ("ordinary-session-party-not-object",
         {"sessionContext": {**session, "parties": ["buyer", *session["parties"][1:]]}}),
        ("ordinary-session-party-bundle-hash-empty", session_party(bundleHash="")),
        ("ordinary-session-party-role-unknown", session_party(role="payer")),
        # AgreementArtifact and RailDefinition are typed members, not any object.
        ("ordinary-empty-agreement", {"agreement": {}}),
        ("ordinary-empty-rail", {"rail": {}}),
        ("ordinary-agreement-version-2", {"agreement": {**agreement, "agreementVersion": "2"}}),
        *((f"ordinary-{kind}-agreement-without-payout-bindings",
           {"agreement": {**source, selector: "1", "terms": {
               k: v for k, v in source["terms"].items() if k != "payoutBindings"}}})
          for kind, selector, source in (
              ("payee-bound", "payeeBoundAgreementVersion",
               {k: v for k, v in agreement.items() if k != "agreementVersion"}),
              ("identity-bound-payee", "identityBoundPayeeAgreementVersion",
               {k: v for k, v in agreement.items() if k != "agreementVersion"}),
              ("sealed-selection", "sealedSelectionAgreementVersion", sealed))),
        ("ordinary-session-party-vet-record-ref-malformed",
         session_party(vetRecordRef={"contentHash": "00" * 32})),
        ("ordinary-agreement-without-terms",
         {"agreement": {k: v for k, v in agreement.items() if k != "terms"}}),
        ("ordinary-agreement-party-without-vet-record-ref",
         {"agreement": {**agreement, "parties": [
             {k: v for k, v in agreement["parties"][0].items() if k != "vetRecordRef"},
             *agreement["parties"][1:]]}}),
        ("ordinary-agreement-signatures-empty", {"agreement": {**agreement, "signatures": []}}),
        ("ordinary-rail-version-zero", {"rail": {**rail, "railVersion": 0}}),
        ("ordinary-rail-type-unknown", {"rail": {**rail, "railType": "wire"}}),
        ("ordinary-rail-asset-kind-unknown",
         {"rail": {**rail, "asset": {**rail["asset"], "kind": "native-btc"}}}),
        ("ordinary-rail-without-governance",
         {"rail": {k: v for k, v in rail.items() if k != "governance"}}),
    ):
        phase(label, "ordinary", {**ordinary_input, **change}, "rejected")

    # Nested declared types are checked before a rail call.
    for binding, base in (("ordinary", ordinary_input),):
        for label, change in (
            ("rail-native-dem-without-decimals", rail_with(asset={"kind": "native-dem", "symbol": "DEM"})),
            ("rail-native-dem-without-symbol", rail_with(asset={"kind": "native-dem", "decimals": 9})),
            ("rail-native-dem-symbol-eth", rail_with(asset={**rail["asset"], "symbol": "ETH"})),
            ("rail-native-dem-decimals-18", rail_with(asset={**rail["asset"], "decimals": 18})),
            ("rail-erc20-asset-without-contract", rail_with(asset={
                "kind": "erc20", "chainId": 1, "symbol": "USDC", "decimals": 6})),
            ("rail-erc20-asset-kind-only", rail_with(asset={"kind": "erc20"})),
            ("rail-spl-asset-without-mint", rail_with(asset={
                "kind": "spl", "cluster": "mainnet", "symbol": "USDC", "decimals": 6})),
            ("rail-native-evm-chain-id-boolean", rail_with(asset={
                "kind": "native-evm", "chainId": True, "symbol": "ETH", "decimals": 18})),
            ("rail-native-solana-cluster-unknown", rail_with(asset={
                "kind": "native-solana", "cluster": "mainnet-beta", "symbol": "SOL", "decimals": 9})),
            ("rail-fiat-asset-without-provider", rail_with(asset={"kind": "fiat-via-ap2", "isoCurrency": "USD"})),
            ("rail-cross-chain-route-not-object", rail_with(asset={
                "kind": "stablecoin-cross-chain", "canonicalSymbol": "USDC", "routes": [1]})),
            ("rail-cross-chain-route-without-destination", rail_with(asset={
                "kind": "stablecoin-cross-chain", "canonicalSymbol": "USDC", "routes": [{"sourceChainId": 1}]})),
            ("rail-evm-network-without-chain-id", rail_with(network={"kind": "evm", "rpcAttestation": "evm-rpc"})),
            ("rail-evm-network-rpc-attestation-unknown", rail_with(network={
                "kind": "evm", "chainId": 1, "rpcAttestation": "trust-me"})),
            ("rail-solana-network-without-cluster", rail_with(network={"kind": "solana"})),
            ("rail-ap2-network-without-endpoint", rail_with(network={"kind": "ap2-provider"})),
            ("rail-x402-network-without-base-url", rail_with(network={"kind": "x402-resource"})),
            ("rail-cross-chain-network-without-mechanism", rail_with(network={"kind": "cross-chain"})),
            ("rail-cross-chain-network-mechanism-unknown", rail_with(network={"kind": "cross-chain", "mechanism": "bridge"})),
            ("rail-governance-supersedes-string", rail_governance(supersedes="1")),
            ("rail-governance-deprecated-string", rail_governance(deprecated="yes")),
            ("rail-governance-deprecated-without-reason", rail_governance(deprecated=True)),
            ("rail-governance-emergency-without-observation", rail_governance(emergency={"isEmergency": True})),
            ("agreement-deliverable-empty", agreement_terms(deliverable={})),
            ("agreement-deliverable-type-unknown", agreement_terms(deliverable={"deliverableType": "teleport", "hash": "00" * 32})),
            ("agreement-deliverable-hash-malformed", agreement_terms(deliverable={"deliverableType": "external", "hash": "x"})),
            ("agreement-rail-string", agreement_terms(rail="demos-native:DEM")),
            ("agreement-rail-version-string", agreement_terms(rail={"railId": rail["railId"], "railVersion": "1"})),
            # A pay-* agreement names its rail (DACS-3 8.5.2 rule 3).
            ("agreement-without-terms-rail", agreement_with(terms={
                k: v for k, v in agreement["terms"].items() if k != "rail"})),
            # Present declared optionals are typed too.
            ("agreement-party-encryption-key-array", agreement_party(encryptionKey=[])),
            ("agreement-party-encryption-key-empty", agreement_party(encryptionKey="")),
            ("agreement-derived-from-channel-array", agreement_with(derivedFromChannel=[])),
            ("agreement-derived-from-channel-without-last-message-hash",
             agreement_with(derivedFromChannel={"subnet": "subnet-1"})),
            ("agreement-metered-quantity-array", agreement_terms(meteredQuantity=[])),
            ("agreement-metered-quantity-number", agreement_terms(meteredQuantity={"quantity": 3, "unit": "call"})),
            ("agreement-metered-quantity-leading-zero", agreement_terms(meteredQuantity={"quantity": "03", "unit": "call"})),
            ("agreement-metered-quantity-without-unit", agreement_terms(meteredQuantity={"quantity": "3"})),
            ("agreement-additional-terms-array", agreement_terms(additionalTerms=[])),
            ("agreement-additional-terms-null", agreement_terms(additionalTerms=None)),
            ("rail-id-non-ascii", rail_with(railId="démo")),
            ("rail-id-whitespace", rail_with(railId="demos-native: DEM")),
            ("rail-finality-profile-array", rail_with(consumerFinalityProfile=[])),
            ("rail-finality-profile-version-2", rail_finality(finalityProfileVersion="2")),
            ("rail-finality-profile-model-unknown", rail_finality(model="optimistic")),
            ("rail-finality-profile-model-array", rail_finality(model=[])),
            ("rail-finality-profile-model-object", rail_finality(model={})),
            ("rail-finality-profile-capability-unknown", rail_finality(finalityResolutionCapability="v2")),
            ("rail-finality-profile-settlement-kind-mismatch", rail_finality(model="block-depth")),
            ("rail-finality-profile-quorum-string", rail_settlement(quorumNumerator="2")),
            ("rail-finality-profile-validator-set-ref-malformed", rail_settlement(validatorSetRef={})),
            ("rail-finality-profile-authority-refs-empty", rail_settlement(observation={
                **bft_final["observation"], "authorityRefs": []})),
            ("rail-finality-profile-rpc-quorum-without-threshold", rail_settlement(observation={
                **bft_final["observation"], "method": "rpc-quorum"})),
            ("rail-finality-profile-threshold-above-authorities", rail_settlement(observation={
                **bft_final["observation"], "threshold": 2})),
        ):
            phase(binding + "-" + label, binding, {**base, **change}, "rejected")
        # Every declared optional, well formed, is accepted with the input unchanged.
        phase(binding + "-declared-optional-members", binding, {
            **base, **rail_finality(),
            "agreement": {**agreement,
                          "derivedFromChannel": {"subnet": "subnet-1", "lastMessageHash": "ab" * 32},
                          "parties": [{**agreement["parties"][0], "encryptionKey": "x25519:buyer-key"},
                                      *agreement["parties"][1:]],
                          "terms": {**agreement["terms"], "meteredQuantity": {"quantity": "0", "unit": "call"}}},
        }, "accepted")
        for label, entries in (("not-object", [1]), ("empty", [{}]), ("phase-index-string", [{
                "railId": rail["railId"], "payeeAddress": ordinary_input["payee"]["payeeAddress"], "phaseIndex": "2"}])):
            payee_agreement = {"payeeBoundAgreementVersion": "1", **{
                k: v for k, v in agreement.items() if k != "agreementVersion"},
                "terms": {**agreement["terms"], "payoutBindings": entries}}
            phase(f"{binding}-payee-bound-payout-binding-{label}", binding,
                  {**base, "agreement": payee_agreement}, "rejected")
        identity = {"identityBoundAgreementVersion": "1", **{
            k: v for k, v in agreement.items() if k != "agreementVersion"},
            "parties": [{**agreement["parties"][0], "bundleHash": "sha256:ABC"}, *agreement["parties"][1:]]}
        phase(binding + "-agreement-identity-bound-bundle-hash-malformed", binding,
              {**base, "agreement": identity}, "rejected")
    phase("ordinary-session-listing-ref-without-content-hash", "ordinary", {
        **ordinary_input, "sessionContext": {**session, "listingRef": {
            k: v for k, v in session["listingRef"].items() if k != "contentHash"}}}, "rejected")

    # §9.5.1 IdentityBoundPaymentPhaseInput: PC-1 types the companion member
    # as a non-empty array of objects carrying `identityBundle` or
    # `compositeRecord`; the verifier-owned IBH-1..IBH-5 rerun decides their
    # members, so each case declares that rerun's outcome and the companions
    # are placeholders.
    identity_agreement = {"identityBoundAgreementVersion": "1", **{
        k: v for k, v in agreement.items() if k != "agreementVersion"}}
    companions = [{"identityBundle": {"bundleHash": hashed("bundle:" + role)},
                   "compositeRecord": {"subject": CLAIMS[role]}} for role in ("buyer", "seller")]
    identity_input = {**ordinary_input, "agreement": identity_agreement,
                      "identityBindingCompanions": companions}
    without_companions = {k: v for k, v in identity_input.items() if k != "identityBindingCompanions"}
    phase("identity-bound-input", "identity-bound", identity_input, "accepted", "verified")
    # Only a verified rerun reaches the rail; without one nothing is paid.
    phase("identity-bound-ibh-rejected", "identity-bound", identity_input, "rejected", "rejected")
    phase("identity-bound-ibh-indeterminate", "identity-bound", identity_input,
          "indeterminate", "indeterminate")
    phase("identity-bound-ibh-unavailable", "identity-bound", identity_input, "indeterminate")
    # An absent companion member is missing authority (IBH `indeterminate`);
    # an empty or malformed one is a type rejection (IBH `error`).
    phase("identity-bound-companions-missing", "identity-bound", without_companions,
          "indeterminate", "verified")
    phase("identity-bound-companions-empty", "identity-bound",
          {**identity_input, "identityBindingCompanions": []}, "rejected", "verified")
    phase("identity-bound-companion-empty-object", "identity-bound",
          {**identity_input, "identityBindingCompanions": [{}]}, "rejected", "verified")
    phase("identity-bound-companion-without-members", "identity-bound",
          {**identity_input, "identityBindingCompanions": [{"note": "x"}, companions[1]]},
          "rejected", "verified")
    # A companion's own members are the rerun's: one lacking its bundle is
    # IBH `indeterminate`, which PC-1 does not turn into a rejection.
    phase("identity-bound-companion-without-identity-bundle", "identity-bound",
          {**identity_input, "identityBindingCompanions": [
              {"compositeRecord": companions[0]["compositeRecord"]}, companions[1]]},
          "indeterminate", "indeterminate")
    phase("identity-bound-companions-not-array", "identity-bound",
          {**identity_input, "identityBindingCompanions": companions[0]}, "rejected", "verified")
    # The authenticated Listing alone selects the path: an agreement of the
    # other kind contradicts it in either direction.
    phase("identity-bound-listing-ordinary-agreement", "identity-bound",
          {**ordinary_input, "identityBindingCompanions": companions}, "rejected", "verified")
    phase("ordinary-binding-identity-bound-agreement", "ordinary", identity_input, "rejected")
    phase("ordinary-binding-identity-bound-agreement-without-companions", "ordinary",
          without_companions, "rejected")
    # A present companion member is typed on the ordinary path too.
    phase("ordinary-companions-empty", "ordinary",
          {**ordinary_input, "identityBindingCompanions": []}, "rejected")
    phase("ordinary-companion-empty-object", "ordinary",
          {**ordinary_input, "identityBindingCompanions": [{}]}, "rejected")

    ordinary_target = {
        "evidenceVersion": "1", "jobId": JOB_ID, "phase": "pay-dem",
        "outcome": "success", "paymentTxRefs": [{"kind": "demos", "txHash": "ab" * 32, "blockNumber": 750}],
        "paymentAmount": {"amount": "10", "currency": "DEM"},
        "settlementFinality": {"model": "bft-final", "finalityObservedAt": 1_800_000_030_000},
        "observedAt": 1_800_000_030_000,
    }
    # A complete PDE-7 delivery record: it passes its arm and fails only the pay-* rule.
    ordinary_delivery = {
        "evidenceVersion": "1", "jobId": JOB_ID, "phase": "deliver-storage-program",
        "outcome": "success", "deliverableContentHash": "34" * 32,
        "deliverableAnchor": {"kind": "storage-program", "locator": f"dacs4:deliverable:{JOB_ID}"},
        "observedAt": 1_800_000_030_000,
    }
    success_payment = {key: ordinary_target[key] for key in (
        "jobId", "phase", "outcome", "paymentTxRefs", "paymentAmount",
        "settlementFinality", "observedAt",
    )}
    legacy_target = {
        "legacyTransitionEvidenceVersion": "1", **success_payment,
        "sessionId": "session-fixture-1", "agreementHash": "cd" * 32, "phaseIndex": 2,
        "reservationRef": {"anchor": {"kind": "storage-program", "locator":
                           f"dacs4:legacy-payment-reservation:{JOB_ID}:2"},
                           "contentHash": "ef" * 32},
    }
    finality_target = {
        "finalityBoundEvidenceVersion": "1", **success_payment,
        "railDefinitionRef": {"anchor": {"kind": "storage-program", "locator":
                              "dacs4:rail:demos-native%3ADEM:1"},
                              "contentHash": "12" * 32, "railId": RAIL_ID,
                              "railVersion": 1},
    }
    targets = []

    def target_case(name, target, domain, expected, *, edit=None, resolution="finalized",
                    signer="orchestrator", address=None, anchored=None, writer=ORCHESTRATOR_WRITER,
                    native_locator=False, disposition="established", amendment_edit=None,
                    algorithm="ed25519", carriers=None, ref_edit=None, amendment_text=None,
                    artifact_text=None):
        target = sign_ecdsa(target, domain) if algorithm == "ecdsa-secp256k1" else sign(target, signer, domain)
        digest = ref.content_hash(target)
        logical = f"dacs4:payment:{JOB_ID}:fixture-{name}:2"
        # An authentic anchor may bind content other than the reference names,
        # come from another writer, or prove a lifecycle state short of finalized.
        anchor = anchor_receipt(logical, ref.content_hash(anchored) if anchored else digest,
                                label=name, nonce="300", writer=writer, disposition=disposition,
                                state="included" if resolution == "included" else "finalized")
        # The locator is the receipt's logical PC-2 address or its native address.
        locator = anchor["nativeAddress"] if native_locator else logical
        target_ref = {"anchor": {"kind": "storage-program", "locator": locator},
                      "contentHash": digest}
        if ref_edit:
            ref_edit(target_ref)
        amendment = {
            "amendmentVersion": "1", "jobId": JOB_ID,
            "amendsEvidenceRef": target_ref, "amendmentType": "correction",
            "reason": "fixture correction", "observedAt": 1_800_000_040_000,
        }
        amendment = sign(amendment, "seller", ref.AMENDMENT_DOMAIN)
        if amendment_edit:
            amendment_edit(amendment)
        # The resolver lists every carrier it found for the reference's locator.
        resolved = {"artifact": target,
                    "anchorReceipts": [anchor, *(carriers(anchor, logical) if carriers else ())]}
        if artifact_text:
            resolved["artifactText"] = artifact_text(target)
        if resolution == "unavailable":
            resolved = None
        elif resolution == "unanchored":
            resolved.pop("anchorReceipts")
        if edit:
            edit(resolved)
        targets.append({"name": name, "ruleRefs": ["AMEND-1"], "amendment": amendment,
                        **({"amendmentText": amendment_text(amendment)} if amendment_text else {}),
                        "resolved": resolved, "expected": expected,
                        "amendmentAddress": address(digest) if address else
                        f"dacs4:amendment:{JOB_ID}:{digest}:0"})

    for label, base, domain, selector, other in (
        ("ordinary", ordinary_target, EVIDENCE_DOMAIN, "evidenceVersion", LEGACY_DOMAIN),
        ("legacy-transition", legacy_target, LEGACY_DOMAIN, "legacyTransitionEvidenceVersion", EVIDENCE_DOMAIN),
        ("finality-bound", finality_target, FINALITY_DOMAIN, "finalityBoundEvidenceVersion", LEGACY_DOMAIN),
    ):
        target_case(label + "-target", base, domain, "valid")
        # Ordinary SettlementEvidence keeps unknown optional members (CORE
        # SIG-5); the transition and finality-bound arms are closed.
        target_case(label + "-unknown-member", {**base, "futureMember": {"note": "preserve signed bytes"}},
                    domain, "valid" if label == "ordinary" else "violation")
        target_case(label + "-unsupported-version", {**base, selector: "2"}, domain, "violation")
        target_case(label + "-wrong-domain", base, other, "violation")
        target_case(label + "-wrong-job", {**base, "jobId": "01K1DPA0000000000000000009"}, domain, "violation")
        # Every evidence arm is orchestrator-signed; a known seller key is not authority.
        target_case(label + "-seller-signed", base, domain, "violation", signer="seller")
        delivery = ordinary_delivery if label == "ordinary" else {**base, "phase": "deliver-storage-program"}
        target_case(label + "-delivery-target", delivery, domain, "violation")
        for state in ("unavailable", "unanchored", "included"):
            target_case(label + "-" + state, base, domain, "indeterminate", resolution=state)
        for member in ("paymentAmount", "settlementFinality"):
            target_case(f"{label}-success-without-{member}",
                        {k: v for k, v in base.items() if k != member}, domain, "violation")
    target_case("legacy-transition-without-reservation-ref",
                {k: v for k, v in legacy_target.items() if k != "reservationRef"}, LEGACY_DOMAIN, "violation")
    target_case("finality-bound-without-rail-definition-ref",
                {k: v for k, v in finality_target.items() if k != "railDefinitionRef"}, FINALITY_DOMAIN, "violation")
    target_case("ordinary-success-without-payment-tx-refs",
                {k: v for k, v in ordinary_target.items() if k != "paymentTxRefs"}, EVIDENCE_DOMAIN, "violation")
    # The {evidenceHash} amendment-address segment binds the exact target hash.
    signed_hash = ref.sha256_hex(ref.jcs_bytes(sign(ordinary_target, "orchestrator", EVIDENCE_DOMAIN)))
    other_hash = ref.content_hash(finality_target)
    for name, address in (
        ("address-signature-inclusive-hash", lambda _: f"dacs4:amendment:{JOB_ID}:{signed_hash}:0"),
        ("address-other-target-hash", lambda _: f"dacs4:amendment:{JOB_ID}:{other_hash}:0"),
        ("address-wrong-job", lambda digest: f"dacs4:amendment:01K1DPA0000000000000000009:{digest}:0"),
        ("address-noncanonical-index", lambda digest: f"dacs4:amendment:{JOB_ID}:{digest}:01"),
        ("address-wrong-kind", lambda digest: f"dacs4:payment:{JOB_ID}:{digest}:0"),
    ):
        target_case(name, ordinary_target, EVIDENCE_DOMAIN, "violation", address=address)
    target_case("address-later-index", ordinary_target, EVIDENCE_DOMAIN, "valid",
                address=lambda digest: f"dacs4:amendment:{JOB_ID}:{digest}:3")
    target_case("ordinary-projection-phase", {**ordinary_target, "phase": "pay-alternative"},
                EVIDENCE_DOMAIN, "violation")
    target_case("ordinary-malformed-outcome", {**ordinary_target, "outcome": "unknown"},
                EVIDENCE_DOMAIN, "violation")
    no_selector = {k: v for k, v in ordinary_target.items() if k not in ref.EVIDENCE_SELECTORS}
    target_case("no-selector", no_selector, EVIDENCE_DOMAIN, "violation")
    target_case("dual-selectors", {**ordinary_target, "legacyTransitionEvidenceVersion": "1"},
                EVIDENCE_DOMAIN, "violation")
    target_case("unsupported-selector", {**no_selector, "deliveryEvidenceVersion": "1"},
                EVIDENCE_DOMAIN, "violation")
    target_case("all-selectors", {**ordinary_target, **{key: "1" for key in ref.EVIDENCE_SELECTORS}},
                EVIDENCE_DOMAIN, "violation")
    # The authentic anchor binds the reference's hash: other bytes are a
    # substituted resolution, not a wrong target.
    target_case("content-hash-mismatch", ordinary_target, EVIDENCE_DOMAIN, "indeterminate",
                edit=lambda r: r["artifact"].update(observedAt=1_800_000_030_001))
    target_case("anchor-binds-other-content", ordinary_target, EVIDENCE_DOMAIN, "violation",
                anchored=legacy_target)
    # Receipt fields are assertions until its proof binds them (CORE SR2-4): an
    # inauthentic receipt is discarded and the target stays pending.
    target_case("anchor-content-mismatch", ordinary_target, EVIDENCE_DOMAIN, "indeterminate",
                edit=lambda r: r["anchorReceipts"][0].update(contentHash="00" * 32))

    def corrupt_proof(resolved):
        evidence = resolved["anchorReceipts"][0]["evidence"]
        proof = json.loads(ref.b64u_decode(evidence["value"]))
        proof["signature"]["value"] = b64u(b"\0" * 64)
        evidence["value"] = b64u(ref.jcs_bytes(proof))
    target_case("anchor-proof-signature-invalid", ordinary_target, EVIDENCE_DOMAIN,
                "indeterminate", edit=corrupt_proof)
    target_case("anchor-without-evidence", ordinary_target, EVIDENCE_DOMAIN, "indeterminate",
                edit=lambda r: r["anchorReceipts"][0].pop("evidence"))
    target_case("signature-invalid", ordinary_target, EVIDENCE_DOMAIN, "violation",
                edit=lambda r: r["artifact"]["signature"].update(value=b64u(b"\0" * 64)))
    target_case("signature-missing", ordinary_target, EVIDENCE_DOMAIN, "violation",
                edit=lambda r: r["artifact"].pop("signature"))
    # The amendment's own malformation is a violation, not pending authority.
    target_case("amendment-signature-missing", ordinary_target, EVIDENCE_DOMAIN, "violation",
                amendment_edit=lambda a: a.pop("signature"))
    # Registered ComponentSignature algorithms this verifier does not implement
    # leave the decision to a verifier that does; an unregistered one violates.
    # The ecdsa-secp256k1 value is a genuine canonical low-S DER signature, so
    # only the implementation question is open. CORE registers no internal
    # format for sr1-aggregate, so its relabelled value is not malformed.
    target_case("ordinary-target-algorithm-ecdsa-secp256k1", ordinary_target, EVIDENCE_DOMAIN,
                "indeterminate", algorithm="ecdsa-secp256k1")
    for algorithm, expected in (("sr1-aggregate", "indeterminate"), ("rsa", "violation")):
        target_case(f"ordinary-target-algorithm-{algorithm}", ordinary_target, EVIDENCE_DOMAIN,
                    expected, edit=lambda r, a=algorithm: r["artifact"]["signature"].update(algorithm=a))
    # CORE SR2-11: only the orchestrator's writer has authority over the
    # payment address; an outsider's authentic receipt is discarded.
    target_case("ordinary-target-outsider-writer", ordinary_target, EVIDENCE_DOMAIN,
                "indeterminate", writer=OUTSIDER_WRITER)
    target_case("anchor-binds-other-content-outsider-writer", ordinary_target, EVIDENCE_DOMAIN,
                "indeterminate", anchored=legacy_target, writer=OUTSIDER_WRITER)
    # CORE SR2-4: an indeterminate observation cannot establish finality, and
    # its disposition is bound by the proof like every other receipt member.
    target_case("anchor-disposition-edited", ordinary_target, EVIDENCE_DOMAIN, "indeterminate",
                disposition="indeterminate",
                edit=lambda r: r["anchorReceipts"][0].update(observationDisposition="established"))
    target_case("anchor-indeterminate-disposition", ordinary_target, EVIDENCE_DOMAIN,
                "indeterminate", disposition="indeterminate")
    # SEB-3 bundle references carry the native address as their locator.
    target_case("ordinary-target-native-locator", ordinary_target, EVIDENCE_DOMAIN, "valid",
                native_locator=True)
    # CORE §B.2: fractional numbers are admitted, string values are hashed
    # under values-only NFC, and member names keep their exact spelling.
    target_case("ordinary-target-fractional-member", {**ordinary_target, "futureRatio": 0.5},
                EVIDENCE_DOMAIN, "valid")
    target_case("ordinary-target-nfd-value-and-member-name",
                {**ordinary_target, "futureNote": "café", "café": 1}, EVIDENCE_DOMAIN, "valid")
    # A failure record carries its reason; a success record may not.
    target_case("ordinary-failure-target",
                {**{k: v for k, v in ordinary_target.items()
                    if k not in ("paymentAmount", "settlementFinality", "paymentTxRefs")},
                 "outcome": "failure", "reason": "rail refused the transfer"},
                EVIDENCE_DOMAIN, "valid")
    target_case("ordinary-success-with-reason", {**ordinary_target, "reason": "not a failure"},
                EVIDENCE_DOMAIN, "violation")
    # The signed reference keeps unknown members under CORE SIG-5.
    target_case("amendment-reference-extra-member", ordinary_target, EVIDENCE_DOMAIN, "valid",
                ref_edit=lambda r: r.update(future="x", anchor={**r["anchor"], "future": "x"}))
    # CORE §5: every carrier the resolver found counts. Two canonically
    # unequal authorized carriers are an equivocation; an equal copy or an
    # outsider's carrier changes nothing.
    target_case("anchor-equivocation", ordinary_target, EVIDENCE_DOMAIN, "indeterminate",
                carriers=lambda anchor, logical: [anchor_receipt(
                    logical, anchor["contentHash"], label="equivocation-2", nonce="301",
                    writer=ORCHESTRATOR_WRITER, native=native_address(logical + ":second"))])
    target_case("anchor-equivocation-other-content", ordinary_target, EVIDENCE_DOMAIN,
                "indeterminate", carriers=lambda anchor, logical: [anchor_receipt(
                    logical, ref.content_hash(legacy_target), label="equivocation-2", nonce="301",
                    writer=ORCHESTRATOR_WRITER)])
    target_case("anchor-duplicate-carrier", ordinary_target, EVIDENCE_DOMAIN, "valid",
                carriers=lambda anchor, logical: [copy.deepcopy(anchor)])
    target_case("anchor-outsider-second-carrier", ordinary_target, EVIDENCE_DOMAIN, "valid",
                carriers=lambda anchor, logical: [anchor_receipt(
                    logical, ref.content_hash(legacy_target), label="outsider-2", nonce="301",
                    writer=OUTSIDER_WRITER)])
    # CORE CF-5 admits each artifact from its exact received bytes: refused
    # amendment bytes violate, refused target bytes are a substituted resolution.
    target_case("amendment-duplicate-member", ordinary_target, EVIDENCE_DOMAIN, "violation",
                amendment_text=duplicate_job_id)
    target_case("target-duplicate-member", ordinary_target, EVIDENCE_DOMAIN, "indeterminate",
                artifact_text=duplicate_job_id)
    return {"fixtureVersion": "1", "publicKeys": PUBLIC_KEYS, "ecdsaPublicKeys": ECDSA_PUBLIC_KEYS,
            "verifierProfile": {"signatureAlgorithms": ["ed25519"]},
            "orchestrator": CLAIMS["orchestrator"], "orchestratorWriter": ORCHESTRATOR_WRITER,
            "retainedState": retained_state(),
            "inputModel": (
                "Bindings, the orchestrator, its native receipt writer and the finality-proof "
                "pins are verifier-owned. Receipt blockRef.timestamp is CORE SR2-6 consensus "
                "time in unix ms. The verifier implements the verifierProfile signature "
                "algorithms (ed25519); ecdsa-secp256k1 (a genuine signature under the "
                "orchestrator's ecdsaPublicKeys entry) and sr1-aggregate are registered but "
                "not implemented by it, so they are indeterminate here. An identity-bound "
                "case's identityBinding is the verifier-owned IBH-1..IBH-5 rerun outcome over "
                "its placeholder companions; without one the rerun authority is missing. "
                "An amendment or resolved artifact is received as its UTF-8 JSON text "
                "(json.dumps, ensure_ascii false) unless amendmentText or artifactText gives "
                "the exact received text. resolved.anchorReceipts lists every carrier the "
                "resolver found for the reference's locator."),
            "phaseInputs": inputs, "amendmentTargets": targets}


def rail_locator(rail: dict) -> str:
    """The native storage locator a registry index entry gives a definition."""
    return native_address(f"rail-definition:{rail['railId']}:{rail['railVersion']}")


def index_entry(rail: dict, **change) -> dict:
    """A CORE RegistryIndexEntry for a definition (SR2-10 content reference)."""
    return {"id": rail["railId"], "version": rail["railVersion"],
            "anchor": {"kind": "storage-program", "locator": rail_locator(rail)},
            "contentHash": ref.content_hash(rail), **change}


def rail_authority(rail: dict, *, revision: int = 1, index_time: int = 1_799_999_750_000,
                   rail_time: int = 1_799_999_740_000, entries: list | None = None,
                   index_writer: str = REGISTRY_WRITER, rail_writer: str = REGISTRY_WRITER,
                   **index_change) -> dict:
    """The pinned registry index snapshot plus every finalized index and definition receipt.

    The snapshot uses CORE's RegistryIndexSnapshot/RegistryIndexEntry shape,
    with `revision` equal to the session's numeric railRegistryVersion. DACS-4
    defines no canonical rail logical address (RD-2), so the definition receipt
    is matched by its native address to the entry's anchor locator; its
    logicalAddress repeats that locator and is not interpreted. Each binding
    lists every carrier found for it (one here).
    """
    index = {
        "registryIndexVersion": "1", "registryKind": "rail", "revision": revision,
        "entries": entries if entries is not None else [index_entry(rail)],
        **index_change,
    }
    locator = rail_locator(rail)
    return {
        "railRegistryIndex": index,
        "railRegistryIndexReceipts": [anchor_receipt(
            ref.REGISTRY_INDEX_ADDRESS, ref.sha256_hex(ref.jcs_bytes(index)),
            label=f"rail-index-{revision}", nonce="200", block_timestamp=index_time,
            writer=index_writer)],
        "railDefinitionReceipts": [anchor_receipt(
            locator, ref.content_hash(rail), native=locator,
            label=f"rail-definition-{rail['railVersion']}", nonce="201", block_timestamp=rail_time,
            writer=rail_writer)],
    }


def build_rail_fixture():
    """DACS-4 §9.4.3 RTB-1 cases for one existing session's pay-dem rail."""
    session = {"startedAt": SESSION_STARTED_AT, "railRegistryVersion": 1}
    rail_ref = {"railId": RAIL_ID}
    rail = steward_rail()
    cases = []

    def case(name, expected, *, authority=None, rail_value=None, case_session=None, case_ref=None):
        value = rail_value or rail
        cases.append({
            "name": name, "ruleRefs": ["RTB-1"],
            "session": case_session or session, "railRef": case_ref or rail_ref,
            "retainedState": retained_state(case_session or session),
            "rail": value, "authority": authority if authority is not None else rail_authority(value),
            "expected": expected,
        })

    def without(member):
        return {k: v for k, v in rail_authority(rail).items() if k != member}

    case("rail-authority-pinned-before-start", "verified")
    # "No later than": all three authority times equal to the session start.
    at_start = steward_rail(governance={**rail["governance"], "acceptedAt": SESSION_STARTED_AT})
    case("rail-authority-at-session-start", "verified", rail_value=at_start,
         authority=rail_authority(at_start, index_time=SESSION_STARTED_AT, rail_time=SESSION_STARTED_AT))
    case("index-receipt-after-session-start", "rejected",
         authority=rail_authority(rail, index_time=SESSION_STARTED_AT + 1))
    case("definition-receipt-after-session-start", "rejected",
         authority=rail_authority(rail, rail_time=SESSION_STARTED_AT + 1))
    late_accepted = steward_rail(governance={**rail["governance"], "acceptedAt": SESSION_STARTED_AT + 1})
    case("accepted-at-after-session-start", "rejected", rail_value=late_accepted)
    # A later index (and the later definition it lists) informs a new session
    # but cannot rewrite the pinned rail authority of an existing one.
    later = steward_rail(railVersion=2, governance={
        **rail["governance"], "acceptedAt": SESSION_STARTED_AT + 100, "supersedes": 1})
    later_authority = rail_authority(later, revision=2, index_time=SESSION_STARTED_AT + 200,
                                     rail_time=SESSION_STARTED_AT + 150,
                                     entries=[index_entry(rail), index_entry(later)])
    case("later-index-for-existing-session", "rejected", rail_value=later, authority=later_authority)
    case("later-index-for-new-session", "verified", rail_value=later, authority=later_authority,
         case_session={"startedAt": SESSION_STARTED_AT + 1_000, "railRegistryVersion": 2})
    # Even an index finalized before the start is not this session's authority
    # unless it is the snapshot the session pinned.
    other_snapshot = steward_rail(railVersion=2, governance={**rail["governance"], "supersedes": 1})
    case("index-not-session-snapshot", "rejected", rail_value=other_snapshot,
         authority=rail_authority(other_snapshot, revision=2))
    # §9.4.3 step 2: without a pin, the unique greatest listed version is the
    # session's rail; an advertised hint member cannot select another one.
    both = [index_entry(rail), index_entry(other_snapshot)]
    case("unpinned-selects-greatest-version", "verified", rail_value=other_snapshot,
         authority=rail_authority(other_snapshot, entries=both))
    case("unpinned-older-version-rejected", "rejected",
         authority=rail_authority(rail, entries=both))
    case("latest-hint-is-inert", "rejected",
         authority=rail_authority(rail, entries=both, latestVersion=1))
    case("pinned-older-version", "verified", case_ref={"railId": RAIL_ID, "railVersion": 1},
         authority=rail_authority(rail, entries=both))
    case("railref-other-rail-id", "rejected", case_ref={"railId": "evm-erc20:1:USDC"})
    # Two entries for one (id, version) leave the snapshot internally inconsistent.
    case("index-duplicate-version", "indeterminate", authority=rail_authority(
        rail, entries=[index_entry(rail), index_entry(rail, contentHash=hashed("other rail definition"))]))
    case("index-entry-not-object", "rejected", authority=rail_authority(
        rail, entries=[index_entry(rail), "demos-native:DEM"]))
    # A steward-signed definition alone does not resolve a rail.
    usdc = {"railId": "evm-erc20:1:USDC", "railVersion": 1}
    case("definition-without-index-membership", "rejected",
         authority=rail_authority(rail, entries=[{
             "id": usdc["railId"], "version": 1,
             "anchor": {"kind": "storage-program", "locator": rail_locator(usdc)},
             "contentHash": hashed("rail:evm-erc20:1:USDC")}]))
    case("index-missing", "indeterminate", authority=without("railRegistryIndex"))
    case("index-receipt-missing", "indeterminate", authority=without("railRegistryIndexReceipts"))
    case("definition-receipt-missing", "indeterminate", authority=without("railDefinitionReceipts"))
    # CORE SR2-11: receipts by a writer other than the registry's are discarded.
    case("index-receipt-outsider-writer", "indeterminate",
         authority=rail_authority(rail, index_writer=OUTSIDER_WRITER))
    case("definition-receipt-outsider-writer", "indeterminate",
         authority=rail_authority(rail, rail_writer=OUTSIDER_WRITER))
    # An authentic receipt whose proven state is short of finalized.
    unfinalized = rail_authority(rail)
    unfinalized["railDefinitionReceipts"] = [anchor_receipt(
        rail_locator(rail), ref.content_hash(rail), native=rail_locator(rail),
        label="rail-definition-1", nonce="201", block_timestamp=1_799_999_740_000,
        state="included", writer=REGISTRY_WRITER)]
    case("definition-receipt-not-finalized", "indeterminate", authority=unfinalized)
    forged = rail_authority(rail)
    evidence = forged["railRegistryIndexReceipts"][0]["evidence"]
    proof = json.loads(ref.b64u_decode(evidence["value"]))
    proof["signature"]["value"] = b64u(b"\0" * 64)
    evidence["value"] = b64u(ref.jcs_bytes(proof))
    case("index-receipt-proof-invalid", "indeterminate", authority=forged)
    case("index-pins-other-content", "rejected", authority=rail_authority(
        rail, entries=[index_entry(rail, contentHash=hashed("other rail definition"))]))
    other_content = rail_authority(rail)
    other_content["railDefinitionReceipts"] = [anchor_receipt(
        rail_locator(rail), hashed("other rail definition"), native=rail_locator(rail),
        label="rail-definition-1", nonce="201", block_timestamp=1_799_999_740_000,
        writer=REGISTRY_WRITER)]
    case("definition-anchor-binds-other-content", "rejected", authority=other_content)
    bad_signature = copy.deepcopy(rail)
    bad_signature["signature"]["value"] = b64u(b"\0" * 64)
    case("steward-signature-invalid", "rejected", rail_value=bad_signature,
         authority=rail_authority(rail))
    case("agreement-pins-other-version", "rejected", case_ref={"railId": RAIL_ID, "railVersion": 2})
    # CORE RegistryIndexEntry: every registered anchor kind; closed entries
    # with positive versions; a positive JSON-safe revision.
    other_rails = [{"id": f"evm-erc20:1:{symbol}", "version": 1,
                    "anchor": {"kind": kind, "locator": f"{kind}-locator-{symbol}"},
                    "contentHash": hashed(f"rail:{symbol}")}
                   for kind, symbol in (("ipfs", "USDC"), ("https", "USDT"))]
    case("index-lists-ipfs-and-https-entries", "verified",
         authority=rail_authority(rail, entries=[index_entry(rail), *other_rails]))
    case("index-entry-version-zero", "rejected",
         authority=rail_authority(rail, entries=[index_entry(rail), {**other_rails[0], "version": 0}]))
    case("index-entry-extra-member", "rejected",
         authority=rail_authority(rail, entries=[index_entry(rail, note="x")]))
    case("index-entry-anchor-extra-member", "rejected", authority=rail_authority(rail, entries=[
        index_entry(rail, anchor={**index_entry(rail)["anchor"], "note": "x"})]))
    for label, version in (("zero", 0), ("negative", -1)):
        case(f"session-registry-version-{label}", "rejected",
             case_session={**session, "railRegistryVersion": version},
             authority=rail_authority(rail, revision=version))
    case("index-revision-boolean", "rejected", authority=rail_authority(rail, revision=True))
    # RTB-1 also covers PA-3; this verifier does not implement a multisig
    # steward signature (or PA-1 in-code authority), so it verifies neither.
    for anchoring, label in (("multisig", "pa3-multisig"), ("in-code", "pa1-in-code")):
        other = steward_rail(governance={**rail["governance"], "anchoring": anchoring})
        case(f"{label}-rail-not-implemented", "indeterminate", rail_value=other)
    # CORE §5: two canonically unequal authorized carriers for one binding are
    # an equivocation; an equal copy or an outsider's carrier changes nothing.
    for member, label, address, content, native, time in (
            ("railRegistryIndexReceipts", "index", ref.REGISTRY_INDEX_ADDRESS,
             ref.sha256_hex(ref.jcs_bytes(rail_authority(rail)["railRegistryIndex"])),
             None, 1_799_999_750_000),
            ("railDefinitionReceipts", "definition", rail_locator(rail), ref.content_hash(rail),
             rail_locator(rail), 1_799_999_740_000)):
        for name, expected, writer, nonce in (("equivocation", "indeterminate", REGISTRY_WRITER, "202"),
                                              ("outsider-second-carrier", "verified", OUTSIDER_WRITER, "202"),
                                              ("duplicate-carrier", "verified", None, None)):
            authority = rail_authority(rail)
            authority[member].append(copy.deepcopy(authority[member][0]) if writer is None else anchor_receipt(
                address, content, native=native, label=f"rail-{label}-second", nonce=nonce,
                block_timestamp=time, writer=writer))
            case(f"{label}-receipt-{name}", expected, authority=authority)
    return {"fixtureVersion": "1", "publicKeys": PUBLIC_KEYS, "steward": CLAIMS["steward"],
            "registryWriter": REGISTRY_WRITER,
            "inputModel": (
                "The session pins, steward, registry writer and finality-proof pins are "
                "verifier-owned. railRegistryIndex uses CORE's RegistryIndexSnapshot and "
                "RegistryIndexEntry shape as a projection of the DACS-4 numeric snapshot; its "
                "revision is the session's railRegistryVersion. railRegistryIndexReceipts and "
                "railDefinitionReceipts list every carrier found for each binding. The "
                "definition receipt is matched by nativeAddress to the selected entry's anchor "
                "locator. Receipt blockRef.timestamp is CORE SR2-6 consensus time in unix ms. "
                "The verifier implements PA-2 single-signer rails only; PA-1 in-code and PA-3 "
                "multisig rails are indeterminate here."),
            "cases": cases}


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = ((OUTPUT, build_fixture()), (RAIL_OUTPUT, build_rail_fixture()))
    failed = False
    for path, value in outputs:
        data = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        if args.write:
            path.write_text(data)
        elif not path.exists() or path.read_text() != data:
            print(f"FAILED: {path.relative_to(ROOT)} differs from its generator")
            failed = True
    if failed:
        return 1
    print("OK: settlement contract fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
