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
import json
from pathlib import Path

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
AGREEMENT_DOMAIN = b"dacs-agreement:v1:"
EVIDENCE_DOMAIN = b"dacs-evidence:v1:"
LEGACY_DOMAIN = b"dacs-legacy-transition-evidence:v1:"
FINALITY_DOMAIN = b"dacs-finality-bound-evidence:v1:"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _key(role: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(SEEDS[role])


PUBLIC_KEYS = {CLAIMS[role]: b64u(_key(role).public_key().public_bytes_raw()) for role in SEEDS}


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


def anchor_receipt(logical_address: str, content_hash: str, *, label: str, nonce: str,
                   block_timestamp: int = 1_799_999_750_000, state: str = "finalized") -> dict:
    """An AnchorReceipt whose synthetic proof binds its own fields, `state` included."""
    receipt = {
        "receiptVersion": "1",
        "substrate": NETWORK_ID,
        "finalityProfile": PROOF_PROFILE,
        "logicalAddress": logical_address,
        "nativeAddress": "stor-" + ref.sha256_hex(logical_address.encode("utf-8"))[:40],
        "contentHash": content_hash,
        "transactionRef": {"kind": "demos-transaction", "value": f"tx-{label}"},
        "writer": "native:registry-relay-1",
        "nonce": nonce,
        "state": state,
        "observationDisposition": "established",
        "observedAt": block_timestamp + 1_000,
        "blockRef": {"id": f"block-{label}-750", "height": "750", "timestamp": block_timestamp},
    }
    proof = sign({
        "logicalAddress": receipt["logicalAddress"],
        "nativeAddress": receipt["nativeAddress"],
        "contentHash": receipt["contentHash"],
        "transactionRef": receipt["transactionRef"],
        "writer": receipt["writer"],
        "nonce": receipt["nonce"],
        "state": receipt["state"],
        "blockRef": receipt["blockRef"],
        "networkId": NETWORK_ID,
        "proofProfile": PROOF_PROFILE,
        "validatorSetId": VALIDATOR_SET_ID,
    }, "network", ref.ANCHOR_TEST_DOMAIN)
    receipt["evidence"] = {"kind": ref.ANCHOR_TEST_KIND, "value": b64u(ref.jcs_bytes(proof))}
    return receipt


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

    def phase(name, binding, value, expected):
        inputs.append({"name": name, "ruleRefs": ["PC-1"], "binding": binding,
                       "input": value, "expected": expected})

    phase("ordinary-input", "ordinary", ordinary_input, "accepted")
    phase("ordinary-keeps-unknown-members", "ordinary",
          {**ordinary_input, "paymentAuthorization": {"opaque": True}}, "accepted")
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
        ("ordinary-session-party-bundle-hash-uppercase",
         session_party(bundleHash=session["parties"][0]["bundleHash"].upper())),
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
                    signer="orchestrator", address=None, anchored=None):
        target = sign(target, signer, domain)
        digest = ref.content_hash(target)
        locator = f"dacs4:payment:{JOB_ID}:fixture-{name}:2"
        target_ref = {"anchor": {"kind": "storage-program", "locator": locator},
                      "contentHash": digest}
        # An authentic anchor may bind content other than the reference names,
        # or an authentic lifecycle state short of finalized.
        anchor = anchor_receipt(locator, ref.content_hash(anchored) if anchored else digest,
                                label=name, nonce="300",
                                state="included" if resolution == "included" else "finalized")
        amendment = sign({
            "amendmentVersion": "1", "jobId": JOB_ID,
            "amendsEvidenceRef": target_ref, "amendmentType": "correction",
            "reason": "fixture correction", "observedAt": 1_800_000_040_000,
        }, "seller", ref.AMENDMENT_DOMAIN)
        resolved = {"artifact": target, "anchorReceipt": anchor}
        if resolution == "unavailable":
            resolved = None
        elif resolution == "unanchored":
            resolved.pop("anchorReceipt")
        if edit:
            edit(resolved)
        targets.append({"name": name, "ruleRefs": ["AMEND-1"], "amendment": amendment,
                        "resolved": resolved, "expected": expected,
                        "amendmentAddress": address(digest) if address else
                        f"dacs4:amendment:{JOB_ID}:{digest}:0"})

    for label, base, domain, selector, other in (
        ("ordinary", ordinary_target, EVIDENCE_DOMAIN, "evidenceVersion", LEGACY_DOMAIN),
        ("legacy-transition", legacy_target, LEGACY_DOMAIN, "legacyTransitionEvidenceVersion", EVIDENCE_DOMAIN),
        ("finality-bound", finality_target, FINALITY_DOMAIN, "finalityBoundEvidenceVersion", LEGACY_DOMAIN),
    ):
        target_case(label + "-target", base, domain, "valid")
        # Every DACS-4 v0.x arm is closed: an unknown member is a violation.
        target_case(label + "-unknown-member", {**base, "futureMember": {"note": "preserve signed bytes"}},
                    domain, "violation")
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
                edit=lambda r: r["anchorReceipt"].update(contentHash="00" * 32))

    def corrupt_proof(resolved):
        evidence = resolved["anchorReceipt"]["evidence"]
        proof = json.loads(ref.b64u_decode(evidence["value"]))
        proof["signature"]["value"] = b64u(b"\0" * 64)
        evidence["value"] = b64u(ref.jcs_bytes(proof))
    target_case("anchor-proof-signature-invalid", ordinary_target, EVIDENCE_DOMAIN,
                "indeterminate", edit=corrupt_proof)
    target_case("anchor-without-evidence", ordinary_target, EVIDENCE_DOMAIN, "indeterminate",
                edit=lambda r: r["anchorReceipt"].pop("evidence"))
    target_case("signature-invalid", ordinary_target, EVIDENCE_DOMAIN, "violation",
                edit=lambda r: r["artifact"]["signature"].update(value=b64u(b"\0" * 64)))
    target_case("signature-missing", ordinary_target, EVIDENCE_DOMAIN, "violation",
                edit=lambda r: r["artifact"].pop("signature"))
    return {"fixtureVersion": "1", "publicKeys": PUBLIC_KEYS,
            "orchestrator": CLAIMS["orchestrator"],
            "phaseInputs": inputs, "amendmentTargets": targets}


def rail_authority(rail: dict, *, registry_version: int = 1, index_time: int = 1_799_999_750_000,
                   rail_time: int = 1_799_999_740_000, entries: list | None = None) -> dict:
    """The pinned registry index plus its finalized index and definition receipts."""
    address = ref.rail_address(rail)
    index = {
        "registryVersion": registry_version,
        "logicalAddress": ref.REGISTRY_INDEX_ADDRESS,
        "entries": entries if entries is not None else [{
            "railId": rail["railId"], "latestVersion": rail["railVersion"],
            "versions": [{"railVersion": rail["railVersion"], "logicalAddress": address,
                          "contentHash": ref.content_hash(rail)}],
        }],
    }
    return {
        "railRegistryIndex": index,
        "railRegistryIndexReceipt": anchor_receipt(
            ref.REGISTRY_INDEX_ADDRESS, ref.sha256_hex(ref.jcs_bytes(index)),
            label=f"rail-index-{registry_version}", nonce="200", block_timestamp=index_time),
        "railDefinitionReceipt": anchor_receipt(
            address, ref.content_hash(rail),
            label=f"rail-definition-{rail['railVersion']}", nonce="201", block_timestamp=rail_time),
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
    later_authority = rail_authority(later, registry_version=2, index_time=SESSION_STARTED_AT + 200,
                                     rail_time=SESSION_STARTED_AT + 150)
    case("later-index-for-existing-session", "rejected", rail_value=later, authority=later_authority)
    case("later-index-for-new-session", "verified", rail_value=later, authority=later_authority,
         case_session={"startedAt": SESSION_STARTED_AT + 1_000, "railRegistryVersion": 2})
    # Even an index finalized before the start is not this session's authority
    # unless it is the snapshot the session pinned.
    other_snapshot = steward_rail(railVersion=2, governance={**rail["governance"], "supersedes": 1})
    case("index-not-session-snapshot", "rejected", rail_value=other_snapshot,
         authority=rail_authority(other_snapshot, registry_version=2))
    # A steward-signed definition alone does not resolve a rail.
    case("definition-without-index-membership", "rejected",
         authority=rail_authority(rail, entries=[{
             "railId": "evm-erc20:1:USDC", "latestVersion": 1,
             "versions": [{"railVersion": 1, "logicalAddress": "dacs4:rail:evm-erc20%3A1%3AUSDC:1",
                           "contentHash": hashed("rail:evm-erc20:1:USDC")}]}]))
    case("index-missing", "indeterminate", authority=without("railRegistryIndex"))
    case("index-receipt-missing", "indeterminate", authority=without("railRegistryIndexReceipt"))
    case("definition-receipt-missing", "indeterminate", authority=without("railDefinitionReceipt"))
    # An authentic receipt whose proven state is short of finalized.
    unfinalized = rail_authority(rail)
    unfinalized["railDefinitionReceipt"] = anchor_receipt(
        ref.rail_address(rail), ref.content_hash(rail), label="rail-definition-1", nonce="201",
        block_timestamp=1_799_999_740_000, state="included")
    case("definition-receipt-not-finalized", "indeterminate", authority=unfinalized)
    forged = rail_authority(rail)
    evidence = forged["railRegistryIndexReceipt"]["evidence"]
    proof = json.loads(ref.b64u_decode(evidence["value"]))
    proof["signature"]["value"] = b64u(b"\0" * 64)
    evidence["value"] = b64u(ref.jcs_bytes(proof))
    case("index-receipt-proof-invalid", "indeterminate", authority=forged)
    case("index-pins-other-content", "rejected", authority=rail_authority(rail, entries=[{
        "railId": RAIL_ID, "latestVersion": 1,
        "versions": [{"railVersion": 1, "logicalAddress": ref.rail_address(rail),
                      "contentHash": hashed("other rail definition")}]}]))
    other_content = rail_authority(rail)
    other_content["railDefinitionReceipt"] = anchor_receipt(
        ref.rail_address(rail), hashed("other rail definition"),
        label="rail-definition-1", nonce="201", block_timestamp=1_799_999_740_000)
    case("definition-anchor-binds-other-content", "rejected", authority=other_content)
    bad_signature = copy.deepcopy(rail)
    bad_signature["signature"]["value"] = b64u(b"\0" * 64)
    case("steward-signature-invalid", "rejected", rail_value=bad_signature,
         authority=rail_authority(rail))
    case("agreement-pins-other-version", "rejected", case_ref={"railId": RAIL_ID, "railVersion": 2})
    return {"fixtureVersion": "1", "publicKeys": PUBLIC_KEYS, "steward": CLAIMS["steward"],
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
