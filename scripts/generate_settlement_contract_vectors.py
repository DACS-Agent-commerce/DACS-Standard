#!/usr/bin/env python3
"""Deterministic PC-1 and AMEND-1 fixtures using public Atomic test keys."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

import atomic_work_reference as ref
import generate_atomic_work_vectors as atomic

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "conformance/fixtures/settlement/payment-input-amendment-v0.1.json"


def build_fixture():
    purchase = atomic.purchase_intent()
    authority = atomic.authorization_authority(purchase)
    atomic_input = authority["paymentPhaseInput"]
    ordinary_input = copy.deepcopy(atomic_input)
    ordinary_input.pop("atomicSessionContext")
    ordinary_input["sessionContext"] = authority["sessionContextSource"]
    inputs = []

    def phase(name, binding, value, expected):
        inputs.append({"name": name, "ruleRefs": ["PC-1"], "binding": binding,
                       "input": value, "expected": expected})

    phase("ordinary-input", "ordinary", ordinary_input, "accepted")
    phase("atomic-input", "atomic", atomic_input, "accepted")
    phase("ordinary-receives-atomic", "ordinary", atomic_input, "rejected")
    phase("atomic-receives-ordinary", "atomic", ordinary_input, "rejected")
    mixed = {**ordinary_input, "atomicSessionContext": atomic_input["atomicSessionContext"]}
    for binding in ("ordinary", "atomic"):
        phase(binding + "-receives-both-contexts", binding, mixed, "rejected")
    for binding in ("ungated-purchase", "completion", "other-payment"):
        phase(binding + "-uses-ordinary-arm", binding, atomic_input, "rejected")
        phase(binding + "-accepts-ordinary-arm", binding, ordinary_input, "accepted")
    phase("ordinary-keeps-unknown-members", "ordinary",
          {**ordinary_input, "paymentAuthorization": {"opaque": True}}, "accepted")
    phase("atomic-rejects-unknown-member", "atomic",
          {**atomic_input, "paymentAuthorization": {}}, "rejected")
    missing = copy.deepcopy(ordinary_input)
    missing.pop("sessionContext")
    phase("ordinary-context-missing", "ordinary", missing, "rejected")
    for member in atomic_input:
        missing = copy.deepcopy(atomic_input)
        missing.pop(member)
        phase("atomic-missing-" + member, "atomic", missing, "rejected")
    for member in ("jobId", "agreement", "rail", "payer", "payee", "amount"):
        missing = copy.deepcopy(ordinary_input)
        missing.pop(member)
        phase("ordinary-missing-" + member, "ordinary", missing, "rejected")
    # A present member of the wrong type fails its arm before any rail call.
    session = ordinary_input["sessionContext"]
    context = atomic_input["atomicSessionContext"]
    agreement = ordinary_input["agreement"]
    rail = ordinary_input["rail"]

    def session_party(**change):
        return {"sessionContext": {**session, "parties": [
            {**session["parties"][0], **change}, *session["parties"][1:]]}}

    def listing_ref(binding, **change):
        key, value = (("atomicSessionContext", context) if binding == "atomic"
                      else ("sessionContext", session))
        return {key: {**value, "listingRef": {**value["listingRef"], **change}}}

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
        "kind": "bft-final", "networkId": "demos:testnet-atomic", "genesisHash": "9a" * 32,
        "validatorSetRef": {"anchor": {"kind": "storage-program",
                                       "locator": "dacs4:validator-set:test-validator-set-1"},
                            "contentHash": "78" * 32},
        "quorumNumerator": 2, "quorumDenominator": 3,
        "observation": {"method": "consensus-backed-proxy",
                        "authorityRefs": ["did:dacs:test:network"], "maxHeadAgeSec": 60},
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
                                           "locator": f"dacs3:selection:{purchase['jobId']}:1"},
                                "contentHash": "56" * 32},
        "terms": {**agreement["terms"], "payoutBindings": [{
            "railId": rail["railId"], "phaseIndex": 2,
            "payeeAddress": ordinary_input["payee"]["payeeAddress"]}]},
    }
    phase("ordinary-sealed-selection-agreement", "ordinary",
          {**ordinary_input, "agreement": sealed}, "accepted")
    # Nested ordinary members stay open under SIG-5, as top-level ones do.
    phase("ordinary-session-listing-ref-extra-member", "ordinary",
          {**ordinary_input, **listing_ref("ordinary", note="x")}, "accepted")
    for label, binding, base, change in (
        ("ordinary-sealed-selection-agreement-fixed-price", "ordinary", ordinary_input,
         {"agreement": {**sealed, "derivedFromPattern": "fixed-price"}}),
        ("ordinary-sealed-selection-agreement-without-receipt-ref", "ordinary", ordinary_input,
         {"agreement": {k: v for k, v in sealed.items() if k != "selectionReceiptRef"}}),
        ("ordinary-agreement-job-id-empty", "ordinary", ordinary_input, agreement_with(jobId="")),
        ("ordinary-agreement-listing-ref-version-zero", "ordinary", ordinary_input,
         agreement_with(listingRef={**agreement["listingRef"], "version": 0})),
        ("ordinary-agreement-parties-empty", "ordinary", ordinary_input, agreement_with(parties=[])),
        ("ordinary-agreement-party-role-unknown", "ordinary", ordinary_input,
         agreement_party(role="orchestrator")),
        ("ordinary-agreement-party-bundle-hash-empty", "ordinary", ordinary_input,
         agreement_party(bundleHash="")),
        ("ordinary-agreement-party-claim-malformed", "ordinary", ordinary_input,
         agreement_party(primaryClaim="not a claim")),
        ("ordinary-agreement-terms-without-deadline", "ordinary", ordinary_input,
         agreement_with(terms={k: v for k, v in agreement["terms"].items() if k != "deadline"})),
        ("ordinary-agreement-deliverable-string", "ordinary", ordinary_input,
         agreement_terms(deliverable="storage-program")),
        ("ordinary-agreement-deadline-string", "ordinary", ordinary_input,
         agreement_terms(deadline=str(agreement["terms"]["deadline"]))),
        ("ordinary-agreement-pattern-unknown", "ordinary", ordinary_input,
         agreement_with(derivedFromPattern="auction")),
        ("ordinary-agreement-generated-at-negative", "ordinary", ordinary_input,
         agreement_with(generatedAt=-1)),
        ("ordinary-agreement-signature-party-malformed", "ordinary", ordinary_input,
         agreement_signature(party="not a claim")),
        ("ordinary-agreement-signature-algorithm-unknown", "ordinary", ordinary_input,
         agreement_signature(algorithm="rsa")),
        ("ordinary-agreement-signature-value-empty", "ordinary", ordinary_input,
         agreement_signature(value="")),
        ("ordinary-rail-id-empty", "ordinary", ordinary_input, rail_with(railId="")),
        ("ordinary-rail-id-too-long", "ordinary", ordinary_input, rail_with(railId="r" * 65)),
        ("ordinary-rail-network-kind-unknown", "ordinary", ordinary_input,
         rail_with(network={"kind": "bitcoin"})),
        ("ordinary-rail-parameters-array", "ordinary", ordinary_input, rail_with(parameters=[])),
        ("ordinary-rail-availability-unknown", "ordinary", ordinary_input,
         rail_with(availability="paused")),
        ("ordinary-rail-without-signature", "ordinary", ordinary_input, rail_without("signature")),
        ("ordinary-rail-governance-without-accepted-at", "ordinary", ordinary_input,
         rail_with(governance={k: v for k, v in rail["governance"].items() if k != "acceptedAt"})),
        ("ordinary-rail-proposed-by-malformed", "ordinary", ordinary_input,
         rail_governance(proposedBy="not a claim")),
        ("ordinary-rail-accepted-at-string", "ordinary", ordinary_input,
         rail_governance(acceptedAt=str(rail["governance"]["acceptedAt"]))),
        ("ordinary-rail-signature-without-algorithm", "ordinary", ordinary_input,
         rail_with(signature={k: v for k, v in rail["signature"].items() if k != "algorithm"})),
        ("ordinary-rail-signature-value-empty", "ordinary", ordinary_input,
         rail_with(signature={**rail["signature"], "value": ""})),
        ("ordinary-empty-session-context", "ordinary", ordinary_input, {"sessionContext": {}}),
        ("ordinary-session-without-started-at", "ordinary", ordinary_input,
         {"sessionContext": {k: v for k, v in session.items() if k != "startedAt"}}),
        ("ordinary-session-parties-not-array", "ordinary", ordinary_input,
         {"sessionContext": {**session, "parties": {}}}),
        ("ordinary-null-payer", "ordinary", ordinary_input, {"payer": None}),
        ("ordinary-payer-without-paying-key", "ordinary", ordinary_input,
         {"payer": {k: v for k, v in ordinary_input["payer"].items() if k != "payingKey"}}),
        ("ordinary-payee-address-empty", "ordinary", ordinary_input,
         {"payee": {**ordinary_input["payee"], "payeeAddress": ""}}),
        ("ordinary-amount-number", "ordinary", ordinary_input, {"amount": 10}),
        ("ordinary-amount-zero", "ordinary", ordinary_input,
         {"amount": {**ordinary_input["amount"], "amount": "0"}}),
        ("ordinary-job-id-number", "ordinary", ordinary_input, {"jobId": 1}),
        ("ordinary-rail-string", "ordinary", ordinary_input, {"rail": "demos-native:DEM"}),
        ("ordinary-companions-not-array", "ordinary", ordinary_input, {"identityBindingCompanions": {}}),
        ("atomic-null-payer", "atomic", atomic_input, {"payer": None}),
        ("atomic-payer-extra-member", "atomic", atomic_input,
         {"payer": {**atomic_input["payer"], "note": "x"}}),
        ("atomic-paying-key-malformed", "atomic", atomic_input,
         {"payer": {**atomic_input["payer"], "payingKey": "not a claim"}}),
        ("atomic-payee-bundle-hash-uppercase", "atomic", atomic_input,
         {"payee": {**atomic_input["payee"], "bundleHash": atomic_input["payee"]["bundleHash"].upper()}}),
        ("atomic-agreement-null", "atomic", atomic_input, {"agreement": None}),
        ("atomic-context-version-2", "atomic", atomic_input,
         {"atomicSessionContext": {**context, "contextVersion": "2"}}),
        ("atomic-context-parties-reordered", "atomic", atomic_input,
         {"atomicSessionContext": {**context, "parties": context["parties"][::-1]}}),
        ("atomic-context-party-bundle-hash", "atomic", atomic_input,
         {"atomicSessionContext": {**context, "parties": [
             {**context["parties"][0], "bundleHash": atomic_input["payer"]["bundleHash"]},
             *context["parties"][1:]]}}),
        ("atomic-context-started-at-string", "atomic", atomic_input,
         {"atomicSessionContext": {**context, "startedAt": str(context["startedAt"])}}),
        ("atomic-context-listing-ref-extra-member", "atomic", atomic_input,
         listing_ref("atomic", note="x")),
        ("atomic-context-listing-ref-version-zero", "atomic", atomic_input,
         listing_ref("atomic", version=0)),
        ("ordinary-session-listing-ref-version-zero", "ordinary", ordinary_input,
         listing_ref("ordinary", version=0)),
        ("ordinary-session-listing-ref-empty-listing-id", "ordinary", ordinary_input,
         listing_ref("ordinary", listingId="")),
        ("ordinary-session-party-claim-malformed", "ordinary", ordinary_input,
         session_party(primaryClaim="not a claim")),
        ("ordinary-session-party-not-object", "ordinary", ordinary_input,
         {"sessionContext": {**session, "parties": ["buyer", *session["parties"][1:]]}}),
        ("ordinary-session-party-bundle-hash-uppercase", "ordinary", ordinary_input,
         session_party(bundleHash=session["parties"][0]["bundleHash"].upper())),
        ("ordinary-session-party-role-unknown", "ordinary", ordinary_input,
         session_party(role="payer")),
        # AgreementArtifact and RailDefinition are typed members, not any object.
        ("ordinary-empty-agreement", "ordinary", ordinary_input, {"agreement": {}}),
        ("atomic-empty-agreement", "atomic", atomic_input, {"agreement": {}}),
        ("ordinary-empty-rail", "ordinary", ordinary_input, {"rail": {}}),
        ("atomic-empty-rail", "atomic", atomic_input, {"rail": {}}),
        ("atomic-agreement-two-discriminators", "atomic", atomic_input,
         {"agreement": {**agreement, "payeeBoundAgreementVersion": "1"}}),
        ("ordinary-agreement-version-2", "ordinary", ordinary_input,
         {"agreement": {**agreement, "agreementVersion": "2"}}),
        *((f"ordinary-{kind}-agreement-without-payout-bindings", "ordinary", ordinary_input,
           {"agreement": {**source, selector: "1", "terms": {
               k: v for k, v in source["terms"].items() if k != "payoutBindings"}}})
          for kind, selector, source in (
              ("payee-bound", "payeeBoundAgreementVersion",
               {k: v for k, v in agreement.items() if k != "agreementVersion"}),
              ("identity-bound-payee", "identityBoundPayeeAgreementVersion",
               {k: v for k, v in agreement.items() if k != "agreementVersion"}),
              ("sealed-selection", "sealedSelectionAgreementVersion", sealed))),
        ("ordinary-session-party-vet-record-ref-malformed", "ordinary", ordinary_input,
         session_party(vetRecordRef={"contentHash": "00" * 32})),
        ("ordinary-agreement-without-terms", "ordinary", ordinary_input,
         {"agreement": {k: v for k, v in agreement.items() if k != "terms"}}),
        ("atomic-agreement-price-zero", "atomic", atomic_input,
         {"agreement": {**agreement, "terms": {**agreement["terms"], "price": {
             **agreement["terms"]["price"], "amount": "0"}}}}),
        ("ordinary-agreement-party-without-vet-record-ref", "ordinary", ordinary_input,
         {"agreement": {**agreement, "parties": [
             {k: v for k, v in agreement["parties"][0].items() if k != "vetRecordRef"},
             *agreement["parties"][1:]]}}),
        ("ordinary-agreement-signatures-empty", "ordinary", ordinary_input,
         {"agreement": {**agreement, "signatures": []}}),
        ("atomic-rail-phase-handler-alternative", "atomic", atomic_input,
         {"rail": {**rail, "phaseHandler": "pay-alternative"}}),
        ("ordinary-rail-version-zero", "ordinary", ordinary_input, {"rail": {**rail, "railVersion": 0}}),
        ("ordinary-rail-type-unknown", "ordinary", ordinary_input, {"rail": {**rail, "railType": "wire"}}),
        ("ordinary-rail-asset-kind-unknown", "ordinary", ordinary_input,
         {"rail": {**rail, "asset": {**rail["asset"], "kind": "native-btc"}}}),
        ("ordinary-rail-without-governance", "ordinary", ordinary_input,
         {"rail": {k: v for k, v in rail.items() if k != "governance"}}),
        ("atomic-rail-anchoring-unknown", "atomic", atomic_input,
         {"rail": {**rail, "governance": {**rail["governance"], "anchoring": "none"}}}),
    ):
        phase(label, binding, {**base, **change}, "rejected")

    # Nested declared types are checked in both dispatch arms before a rail call.
    for binding, base in (("ordinary", ordinary_input), ("atomic", atomic_input)):
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
    phase("atomic-context-listing-ref-not-object", "atomic", {
        **atomic_input, "atomicSessionContext": {**context, "listingRef": 1}}, "rejected")

    receipt = atomic.final_receipt(purchase)
    atomic_target = atomic.settlement_evidence(purchase, receipt, "payment")
    completion = atomic.completion_intent(receipt)
    atomic_delivery = atomic.settlement_evidence(completion, atomic.final_receipt(completion), "delivery")
    ordinary_target = {
        "evidenceVersion": "1", "jobId": purchase["jobId"], "phase": "pay-dem",
        "outcome": "success", "paymentTxRefs": [{"kind": "demos", "txHash": "ab" * 32, "blockNumber": 750}],
        "paymentAmount": {"amount": "10", "currency": "DEM"},
        "settlementFinality": {"model": "bft-final", "finalityObservedAt": 1_800_000_030_000},
        "observedAt": 1_800_000_030_000,
    }
    # A complete PDE-7 delivery record: it passes its arm and fails only the pay-* rule.
    ordinary_delivery = {
        "evidenceVersion": "1", "jobId": purchase["jobId"], "phase": "deliver-storage-program",
        "outcome": "success", "deliverableContentHash": "34" * 32,
        "deliverableAnchor": {"kind": "storage-program",
                              "locator": f"dacs4:deliverable:{purchase['jobId']}"},
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
                           f"dacs4:legacy-payment-reservation:{purchase['jobId']}:2"},
                           "contentHash": "ef" * 32},
    }
    finality_target = {
        "finalityBoundEvidenceVersion": "1", **success_payment,
        "railDefinitionRef": {"anchor": {"kind": "storage-program", "locator":
                              "dacs4:rail:demos-native%3ADEM:1"},
                              "contentHash": "12" * 32, "railId": "demos-native:DEM",
                              "railVersion": 1},
    }
    targets = []

    def target_case(name, target, domain, expected, *, edit=None, resolution="finalized",
                    signer="orchestrator", address=None, anchored=None):
        target = ref.sign_embedded(target, atomic.CLAIMS[signer], atomic.SEEDS[signer], domain)
        unsigned = {k: v for k, v in target.items() if k != "signature"}
        digest = ref.sha256_hex(ref.jcs_bytes(unsigned))
        locator = f"dacs4:payment:{purchase['jobId']}:fixture-{name}:2"
        target_ref = {"anchor": {"kind": "storage-program", "locator": locator},
                      "contentHash": digest}
        # An authentic anchor may bind content other than the reference names.
        anchor = atomic.registry_anchor_receipt(locator, anchored or unsigned, label=name, nonce="300")
        amendment = ref.sign_embedded({
            "amendmentVersion": "1", "jobId": purchase["jobId"],
            "amendsEvidenceRef": target_ref, "amendmentType": "correction",
            "reason": "fixture correction", "observedAt": 1_800_000_040_000,
        }, atomic.CLAIMS["seller"], atomic.SEEDS["seller"], ref._AMENDMENT_DOMAIN)
        resolved = {"artifact": target, "anchorReceipt": anchor}
        if resolution == "unavailable":
            resolved = None
        elif resolution == "unanchored":
            resolved.pop("anchorReceipt")
        elif resolution == "included":
            anchor["state"] = "included"
        if edit:
            edit(resolved)
        targets.append({"name": name, "ruleRefs": ["AMEND-1"], "amendment": amendment,
                        "resolved": resolved, "expected": expected,
                        "amendmentAddress": address(digest) if address else
                        f"dacs4:amendment:{purchase['jobId']}:{digest}:0"})

    legacy_domain = b"dacs-legacy-transition-evidence:v1:"
    finality_domain = b"dacs-finality-bound-evidence:v1:"
    for label, base, domain, selector, other in (
        ("ordinary", ordinary_target, b"dacs-evidence:v1:", "evidenceVersion", ref.EVIDENCE_DOMAIN),
        ("atomic", atomic_target, ref.EVIDENCE_DOMAIN, "atomicEvidenceVersion", b"dacs-evidence:v1:"),
        ("legacy-transition", legacy_target, legacy_domain, "legacyTransitionEvidenceVersion", b"dacs-evidence:v1:"),
        ("finality-bound", finality_target, finality_domain, "finalityBoundEvidenceVersion", legacy_domain),
    ):
        target_case(label + "-target", base, domain, "valid")
        target_case(label + "-unknown-member", {**base, "futureMember": {"note": "preserve signed bytes"}},
                    domain, "valid" if label == "atomic" else "violation")
        target_case(label + "-unsupported-version", {**base, selector: "2"}, domain, "violation")
        target_case(label + "-wrong-domain", base, other, "violation")
        target_case(label + "-wrong-job", {**base, "jobId": "01K1DPA0000000000000000009"}, domain, "violation")
        # Every evidence arm is orchestrator-signed; a known seller key is not authority.
        target_case(label + "-seller-signed", base, domain, "violation", signer="seller")
        delivery = {"atomic": atomic_delivery, "ordinary": ordinary_delivery}.get(
            label, {**base, "phase": "deliver-storage-program"})
        target_case(label + "-delivery-target", delivery, domain, "violation")
        for state in ("unavailable", "unanchored", "included"):
            target_case(label + "-" + state, base, domain, "indeterminate", resolution=state)
        for member in ("paymentAmount", "settlementFinality"):
            target_case(f"{label}-success-without-{member}",
                        {k: v for k, v in base.items() if k != member}, domain, "violation")
    target_case("legacy-transition-without-reservation-ref",
                {k: v for k, v in legacy_target.items() if k != "reservationRef"}, legacy_domain, "violation")
    target_case("finality-bound-without-rail-definition-ref",
                {k: v for k, v in finality_target.items() if k != "railDefinitionRef"}, finality_domain, "violation")
    target_case("ordinary-success-without-payment-tx-refs",
                {k: v for k, v in ordinary_target.items() if k != "paymentTxRefs"}, b"dacs-evidence:v1:", "violation")
    # The {evidenceHash} amendment-address segment binds the exact target hash.
    job = purchase["jobId"]
    signed_hash = ref.sha256_hex(ref.jcs_bytes(ref.sign_embedded(
        atomic_target, atomic.CLAIMS["orchestrator"], atomic.SEEDS["orchestrator"], ref.EVIDENCE_DOMAIN)))
    other_hash = ref.sha256_hex(ref.jcs_bytes(ordinary_target))
    for name, address in (
        ("address-signature-inclusive-hash", lambda _: f"dacs4:amendment:{job}:{signed_hash}:0"),
        ("address-other-target-hash", lambda _: f"dacs4:amendment:{job}:{other_hash}:0"),
        ("address-wrong-job", lambda digest: f"dacs4:amendment:01K1DPA0000000000000000009:{digest}:0"),
        ("address-noncanonical-index", lambda digest: f"dacs4:amendment:{job}:{digest}:01"),
        ("address-wrong-kind", lambda digest: f"dacs4:payment:{job}:{digest}:0"),
    ):
        target_case(name, atomic_target, ref.EVIDENCE_DOMAIN, "violation", address=address)
    target_case("address-later-index", atomic_target, ref.EVIDENCE_DOMAIN, "valid",
                address=lambda digest: f"dacs4:amendment:{job}:{digest}:3")
    target_case("ordinary-projection-phase", {**ordinary_target, "phase": "pay-alternative"}, b"dacs-evidence:v1:", "violation")
    malformed_atomic = {k: v for k, v in atomic_target.items() if k != "workReceiptRef"}
    target_case("atomic-malformed-member", malformed_atomic, ref.EVIDENCE_DOMAIN, "violation")
    target_case("ordinary-malformed-outcome", {**ordinary_target, "outcome": "unknown"}, b"dacs-evidence:v1:", "violation")
    no_selector = {k: v for k, v in atomic_target.items() if k not in ref.EVIDENCE_SELECTORS}
    target_case("no-selector", no_selector, ref.EVIDENCE_DOMAIN, "violation")
    target_case("dual-selectors", {**atomic_target, "evidenceVersion": "1"}, ref.EVIDENCE_DOMAIN, "violation")
    target_case("unsupported-selector", {**no_selector, "deliveryEvidenceVersion": "1"}, ref.EVIDENCE_DOMAIN, "violation")
    target_case("all-selectors", {**atomic_target, **{key: "1" for key in ref.EVIDENCE_SELECTORS}}, ref.EVIDENCE_DOMAIN, "violation")
    # The authentic anchor binds the reference's hash: other bytes are a
    # substituted resolution, not a wrong target.
    target_case("content-hash-mismatch", atomic_target, ref.EVIDENCE_DOMAIN, "indeterminate",
                edit=lambda r: r["artifact"].update(observedAt=1_800_000_030_001))
    target_case("anchor-binds-other-content", atomic_target, ref.EVIDENCE_DOMAIN, "violation",
                anchored={k: v for k, v in ordinary_target.items()})
    # Receipt fields are assertions until its proof binds them (CORE SR2-4): an
    # inauthentic receipt is discarded and the target stays pending.
    target_case("anchor-content-mismatch", atomic_target, ref.EVIDENCE_DOMAIN, "indeterminate",
                edit=lambda r: r["anchorReceipt"].update(contentHash="00" * 32))

    def corrupt_proof(resolved):
        evidence = resolved["anchorReceipt"]["evidence"]
        proof = json.loads(ref.b64u_decode(evidence["value"]))
        proof["signature"]["value"] = ref.b64u(b"\0" * 64)
        evidence["value"] = ref.b64u(ref.jcs_bytes(proof))
    target_case("anchor-proof-signature-invalid", atomic_target, ref.EVIDENCE_DOMAIN,
                "indeterminate", edit=corrupt_proof)
    target_case("anchor-without-evidence", atomic_target, ref.EVIDENCE_DOMAIN, "indeterminate",
                edit=lambda r: r["anchorReceipt"].pop("evidence"))
    target_case("signature-invalid", atomic_target, ref.EVIDENCE_DOMAIN, "violation",
                edit=lambda r: r["artifact"]["signature"].update(value=ref.b64u(b"\0" * 64)))
    target_case("signature-missing", atomic_target, ref.EVIDENCE_DOMAIN, "violation",
                edit=lambda r: r["artifact"].pop("signature"))
    return {"fixtureVersion": "1", "publicKeys": atomic.PUBLIC_KEYS,
            "orchestrator": atomic.CLAIMS["orchestrator"],
            "phaseInputs": inputs, "amendmentTargets": targets}


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = json.dumps(build_fixture(), ensure_ascii=False, indent=2) + "\n"
    if args.write:
        OUTPUT.write_text(data)
    elif OUTPUT.read_text() != data:
        print("FAILED: settlement contract fixture differs")
        return 1
    print("OK: settlement contract fixture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
