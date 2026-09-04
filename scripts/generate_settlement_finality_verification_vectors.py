#!/usr/bin/env python3
"""Generate deterministic DACS-4 FV-1..FV-10 conformance vectors."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "settlement-finality-verification-v0.8.json"
)


def merge(base: dict, changes: dict | None) -> dict:
    value = copy.deepcopy(base)
    for key, item in (changes or {}).items():
        if isinstance(item, dict) and isinstance(value.get(key), dict):
            value[key] = merge(value[key], item)
        else:
            value[key] = copy.deepcopy(item)
    return value


def chain_profile(model: str = "block-depth") -> dict:
    profile = {
        "kind": model,
        "networkId": "eip155:1",
        "genesisHash": "0xgenesis-mainnet",
        "observation": {
            "method": "rpc-quorum",
            "authorityRefs": ["rpc-a", "rpc-b", "rpc-c"],
            "threshold": 2,
            "maxHeadAgeSec": 60,
        },
    }
    if model == "block-depth":
        profile["requiredDepth"] = 12
    elif model == "commitment-level":
        profile["requiredCommitment"] = "finalized"
    elif model == "bft-final":
        profile.update({
            "validatorSetRef": {"contentHash": "validator-set-v8"},
            "quorumNumerator": 2,
            "quorumDenominator": 3,
        })
    return profile


def chain_observation(profile: dict, label: str) -> dict:
    transaction_hash = hashlib.sha256(f"fv:{label}:transaction".encode()).hexdigest()
    inclusion_block = hashlib.sha256(f"fv:{label}:block:100".encode()).hexdigest()
    head_block = hashlib.sha256(f"fv:{label}:block:111".encode()).hexdigest()
    network_id = profile["networkId"]
    chain_id = network_id.split(":", 1)[1] if network_id.startswith("eip155:") else network_id
    return {
        "networkId": network_id,
        "genesisHash": profile["genesisHash"],
        "transactionRef": {
            "kind": "evm-event",
            "chainId": chain_id,
            "txHash": transaction_hash,
            "logIndex": 0,
        },
        "transactionInclusionProof": {
            "kind": "receipt-merkle-proof",
            "value": f"proof:{label}:transaction",
        },
        "selectedEventProof": {
            "kind": "evm-log-proof",
            "value": f"proof:{label}:event",
        },
        "inclusionBlock": {
            "id": inclusion_block,
            "parentId": hashlib.sha256(f"fv:{label}:block:99".encode()).hexdigest(),
            "position": "100",
        },
        "authenticatedHead": {
            "id": head_block,
            "position": "111",
            "observedAt": 1_900_000_000_000,
        },
        "ancestryProof": [
            {
                "childId": head_block,
                "parentId": inclusion_block,
                "position": "111",
                "header": f"header-chain:{label}:111-to-100",
            }
        ],
        "authorityEvidence": {
            "kind": "rpc-quorum",
            "value": f"quorum:{label}:2-of-3",
            "sourceRefs": copy.deepcopy(profile["observation"]["authorityRefs"]),
        },
    }


def base_input(model: str = "block-depth") -> dict:
    settlement = chain_profile(model if model in {
        "block-depth", "commitment-level", "bft-final"
    } else "block-depth")
    profile = {
        "finalityProfileVersion": "1",
        "model": model,
        "settlement": settlement,
    }
    report = {
        "model": model,
        "finalityBlocks": 12 if model == "block-depth" else None,
        "finalityCommitmentLevel": None,
        "finalityObservedAt": 1_900_000_000_000,
    }
    context = {
        "kind": "chain",
        "shape": "valid",
        "proofKindSupported": True,
        "networkId": settlement["networkId"],
        "genesisHash": settlement["genesisHash"],
        "transactionIncluded": True,
        "selectedEventMatches": True,
        "authority": "verified",
        "canonicalPath": "valid",
        "headAgeSec": 10,
        "inclusionPosition": "100",
        "headPosition": "111",
        "commitment": None,
        "bftCertificateValid": None,
        "bftSignedWeight": None,
        "bftTotalWeight": None,
        "providerCaptured": None,
        "providerBindingMatches": None,
        "compositeStatus": None,
    }
    return {
        "surface": "dacs4-consumer",
        "evidence": {
            "discriminator": "finality-bound",
            "signatureDomainMatches": True,
            "outcome": "success",
            "phase": "pay-evm-erc20",
            "railDefinitionRef": {
                "railId": "evm-erc20:1:USDC",
                "railVersion": 8,
            },
            "settlementFinality": report,
        },
        "rail": {
            "resolution": "verified",
            "referenceMatches": True,
            "agreementMatches": True,
            "phaseMatches": True,
            "profileShape": "valid",
            "profile": profile,
        },
        "context": context,
    }


def model_input(model: str) -> dict:
    value = base_input(model)
    profile = value["rail"]["profile"]
    report = value["evidence"]["settlementFinality"]
    context = value["context"]
    if model == "commitment-level":
        value["evidence"]["phase"] = "pay-solana-spl"
        value["evidence"]["railDefinitionRef"] = {
            "railId": "solana-spl:mainnet:USDC",
            "railVersion": 8,
        }
        profile["settlement"].update({
            "networkId": "solana:mainnet",
            "genesisHash": "solana-mainnet-genesis",
            "requiredCommitment": "finalized",
        })
        report.update({"finalityBlocks": None, "finalityCommitmentLevel": "finalized"})
        context.update({
            "networkId": profile["settlement"]["networkId"],
            "genesisHash": profile["settlement"]["genesisHash"],
            "commitment": "finalized",
        })
    elif model == "bft-final":
        value["evidence"]["phase"] = "pay-dem"
        value["evidence"]["railDefinitionRef"] = {
            "railId": "demos-native:DEM",
            "railVersion": 8,
        }
        profile["settlement"].update({
            "networkId": "demos:mainnet",
            "genesisHash": "demos-mainnet-genesis",
            "quorumNumerator": 2,
            "quorumDenominator": 3,
        })
        report["finalityBlocks"] = None
        context.update({
            "networkId": profile["settlement"]["networkId"],
            "genesisHash": profile["settlement"]["genesisHash"],
            "bftCertificateValid": True,
            "bftSignedWeight": 67,
            "bftTotalWeight": 100,
        })
    elif model == "provider-receipt":
        value["evidence"]["phase"] = "pay-ap2"
        value["evidence"]["railDefinitionRef"] = {
            "railId": "ap2:provider",
            "railVersion": 8,
        }
        value["rail"]["profile"] = {
            "finalityProfileVersion": "1",
            "model": "provider-receipt",
            "providerId": "provider:example",
            "statusEndpointOrigin": "https://payments.example",
            "captureStatuses": ["captured"],
            "sr3Binding": "provider-jws-v1",
            "maxObservationAgeSec": 60,
            "reversibility": "provisional-provider-capture",
        }
        profile = value["rail"]["profile"]
        report["finalityBlocks"] = None
        context.update({
            "kind": "provider",
            "networkId": None,
            "genesisHash": None,
            "providerId": profile["providerId"],
            "endpointOrigin": profile["statusEndpointOrigin"],
            "providerCaptured": True,
            "providerBindingMatches": True,
            "transactionIncluded": None,
            "selectedEventMatches": None,
            "canonicalPath": None,
        })
    elif model == "htlc-reveal":
        value["evidence"]["phase"] = "pay-cross-chain-htlc"
        value["evidence"]["railDefinitionRef"] = {
            "railId": "cross-chain-htlc:USDC",
            "railVersion": 8,
        }
        profile = {
            "finalityProfileVersion": "1",
            "model": "htlc-reveal",
            "source": chain_profile(),
            "destination": merge(chain_profile(), {
                "networkId": "eip155:8453",
                "genesisHash": "0xgenesis-base",
            }),
        }
        value["rail"]["profile"] = profile
        report["finalityBlocks"] = None
        value["context"] = {
            "kind": "htlc",
            "shape": "valid",
            "proofKindSupported": True,
            "sourceLock": chain_observation(profile["source"], "source-lock"),
            "sourceClaim": chain_observation(profile["source"], "source-claim"),
            "destinationLock": chain_observation(
                profile["destination"], "destination-lock"
            ),
            "destinationReveal": chain_observation(
                profile["destination"], "destination-reveal"
            ),
            "relation": {
                "sourceContractMatches": True,
                "destinationContractMatches": True,
                "commonHashlockMatches": True,
                "revealedPreimageMatches": True,
                "amountsMatch": True,
                "timelocksValid": True,
            },
            "authority": "verified",
            "canonicalPath": "valid",
        }
    elif model == "liquidity-tank":
        value["evidence"]["phase"] = "pay-cross-chain-liquidity-tank"
        value["evidence"]["railDefinitionRef"] = {
            "railId": "cross-chain-liquidity-tank:USDC",
            "railVersion": 8,
        }
        profile = {
            "finalityProfileVersion": "1",
            "model": "liquidity-tank",
            "bridgeId": "tank:sepolia-amoy:usdc",
            "coordinator": merge(chain_profile("bft-final"), {
                "networkId": "demos:testnet",
                "genesisHash": "demos-testnet-genesis",
            }),
            "source": merge(chain_profile(), {
                "networkId": "eip155:11155111",
                "genesisHash": "0xgenesis-sepolia",
            }),
            "destination": merge(chain_profile(), {
                "networkId": "eip155:80002",
                "genesisHash": "0xgenesis-amoy",
            }),
        }
        value["rail"]["profile"] = profile
        report["finalityBlocks"] = None
        context.update({"kind": "liquidity-tank", "compositeStatus": "verified"})
    return value


def case(name: str, expected: str, note: str, *, model: str = "block-depth", changes: dict | None = None) -> dict:
    finality_class = None
    if expected == "pass":
        finality_class = (
            "provisional-provider-capture"
            if model == "provider-receipt"
            else "profile-final"
        )
    return {
        "name": name,
        "expected": expected,
        "note": note,
        "input": merge(model_input(model), changes),
        "want": {
            "acceptedAsFinal": expected == "pass",
            "finalityClass": finality_class,
            "producerReportTrustedAsProof": False,
            "dacs5RsvDecision": {
                "pass": "verified",
                "fail": "rejected",
                "indeterminate": "indeterminate",
                "error": "error",
            }[expected],
        },
    }


def vectors() -> list[dict]:
    return [
        case("fv-block-depth-canonical-success", "pass", "exact event is on the authenticated canonical path at required depth"),
        case("fv-x402-canonical-event-success", "pass", "x402 event uses the same canonical EVM finality verifier", changes={"evidence": {"phase": "pay-x402", "railDefinitionRef": {"railId": "x402:default", "railVersion": 8}}}),
        case("fv-solana-finalized-success", "pass", "instruction slot is rooted at the pinned finalized commitment", model="commitment-level"),
        case("fv-demos-bft-final-success", "pass", "Demos inclusion carries a valid active-set certificate above two-thirds signed weight", model="bft-final"),
        case("fv-provider-capture-provisional", "pass", "authenticated provider capture passes but is explicitly provisional", model="provider-receipt"),
        case("fv-htlc-both-legs-success", "pass", "source lock/claim and destination lock/reveal all verify under pinned profiles", model="htlc-reveal"),
        case("fv-liquidity-tank-completed-success", "pass", "source lock, destination release and coordinator completed state all verify", model="liquidity-tank"),
        case("fv-wrong-network", "fail", "authenticated network identity differs from the signed rail profile", changes={"context": {"networkId": "eip155:5"}}),
        case("fv-wrong-genesis", "fail", "same chain label with the wrong genesis is rejected", changes={"context": {"genesisHash": "0xwrong"}}),
        case("fv-wrong-transaction-inclusion", "fail", "inclusion proof does not bind the signed transaction reference", changes={"context": {"transactionIncluded": False}}),
        case("fv-wrong-log-index", "fail", "included receipt does not contain the signed selected event", changes={"context": {"selectedEventMatches": False}}),
        case("fv-insufficient-depth", "fail", "computed canonical depth is below the signed rail requirement", changes={"context": {"headPosition": "110"}}),
        case("fv-fake-confirmation-count", "fail", "producer reports twelve but authenticated path proves only one confirmation", changes={"context": {"headPosition": "100"}}),
        case("fv-producer-selects-weaker-depth", "fail", "producer report cannot lower the profile's depth", changes={"evidence": {"settlementFinality": {"finalityBlocks": 1}}}),
        case("fv-report-model-mismatch", "fail", "producer model must exactly echo the rail-selected model", changes={"evidence": {"settlementFinality": {"model": "provider-receipt", "finalityBlocks": None}}}),
        case("fv-stale-fork", "fail", "valid inclusion on a block proven outside the authenticated canonical path is non-final", changes={"context": {"canonicalPath": "stale-fork"}}),
        case("fv-conflicting-authenticated-heads", "indeterminate", "profile cannot select between conflicting authenticated heads", changes={"context": {"authority": "conflicting"}}),
        case("fv-active-reorganization", "indeterminate", "active reorganization defers finality without manufacturing failure", changes={"context": {"canonicalPath": "reorg"}}),
        case("fv-unresolved-replacement", "indeterminate", "replacement status is reconciled before retry or finality", changes={"context": {"canonicalPath": "replaced"}}),
        case("fv-head-unavailable", "indeterminate", "unavailable authenticated head cannot be replaced by producer values", changes={"context": {"authority": "unavailable"}}),
        case("fv-history-pruned", "indeterminate", "pruned inclusion/ancestry history is not a pass or deterministic mismatch", changes={"context": {"canonicalPath": "pruned"}}),
        case("fv-head-observation-stale", "indeterminate", "authenticated but stale head exceeds the rail freshness bound", changes={"context": {"headAgeSec": 61}}),
        case("fv-solana-commitment-too-weak", "fail", "confirmed cannot satisfy a finalized profile", model="commitment-level", changes={"context": {"commitment": "confirmed"}}),
        case("fv-demos-certificate-invalid", "fail", "invalid BFT certificate cannot establish inclusion finality", model="bft-final", changes={"context": {"bftCertificateValid": False}}),
        case("fv-demos-quorum-insufficient", "fail", "signed validator weight below two-thirds is insufficient", model="bft-final", changes={"context": {"bftSignedWeight": 66}}),
        case("fv-provider-not-captured", "fail", "authenticated non-capture cannot produce payment success", model="provider-receipt", changes={"context": {"providerCaptured": False}}),
        case("fv-provider-binding-mismatch", "fail", "provider response must bind the exact session, amount and currency", model="provider-receipt", changes={"context": {"providerBindingMatches": False}}),
        case("fv-provider-attestation-unavailable", "indeterminate", "unavailable SR-3 provider response remains indeterminate", model="provider-receipt", changes={"context": {"authority": "unavailable"}}),
        case("fv-htlc-source-claim-missing", "indeterminate", "missing source-claim authority leaves an asymmetric HTLC unresolved", model="htlc-reveal", changes={"context": {"sourceClaim": {"authorityEvidence": {"kind": "unavailable", "value": "source-claim-history-unavailable", "sourceRefs": ["rpc-a", "rpc-b", "rpc-c"]}}}}),
        case("fv-htlc-source-lock-missing", "indeterminate", "unavailable source-lock proof cannot be replaced by the other three events", model="htlc-reveal", changes={"context": {"sourceLock": {"authorityEvidence": {"kind": "unavailable", "value": "source-lock-history-unavailable", "sourceRefs": ["rpc-a", "rpc-b", "rpc-c"]}}}}),
        case("fv-htlc-destination-lock-missing", "indeterminate", "unavailable destination-lock proof cannot be replaced by the reveal", model="htlc-reveal", changes={"context": {"destinationLock": {"authorityEvidence": {"kind": "unavailable", "value": "destination-lock-history-unavailable", "sourceRefs": ["rpc-a", "rpc-b", "rpc-c"]}}}}),
        case("fv-htlc-destination-reveal-missing", "indeterminate", "unavailable destination-reveal proof leaves the cross-chain result unresolved", model="htlc-reveal", changes={"context": {"destinationReveal": {"authorityEvidence": {"kind": "unavailable", "value": "destination-reveal-history-unavailable", "sourceRefs": ["rpc-a", "rpc-b", "rpc-c"]}}}}),
        case("fv-htlc-observation-shape-missing", "error", "omitting one of the four required observation arms is a structural impossibility", model="htlc-reveal", changes={"context": {"destinationReveal": None}}),
        case("fv-htlc-destination-reveal-wrong-network", "fail", "the destination reveal must verify on the destination profile's exact network", model="htlc-reveal", changes={"context": {"destinationReveal": {"networkId": "eip155:1"}}}),
        case("fv-htlc-preimage-contradiction", "fail", "proved hashlock/preimage or contract contradiction rejects", model="htlc-reveal", changes={"context": {"relation": {"revealedPreimageMatches": False}}}),
        case("fv-tank-not-completed", "fail", "authenticated coordinator state not completed cannot be final", model="liquidity-tank", changes={"context": {"compositeStatus": "mismatch"}}),
        case("fv-tank-destination-unavailable", "indeterminate", "missing destination release authority leaves tank state unresolved", model="liquidity-tank", changes={"context": {"compositeStatus": "unavailable"}}),
        case("fv-rail-resolution-unavailable", "indeterminate", "missing signed RailDefinition prevents profile selection", changes={"rail": {"resolution": "unavailable"}}),
        case("fv-rail-reference-mismatch", "fail", "resolved rail bytes do not match the signed evidence reference", changes={"rail": {"referenceMatches": False}}),
        case("fv-profile-malformed", "error", "missing conditional profile fields are structural error", changes={"rail": {"profileShape": "malformed"}}),
        case("fv-proof-kind-unsupported", "error", "unknown proof encoding is not normalized or guessed", changes={"context": {"proofKindSupported": False}}),
        case("fv-proof-position-malformed", "error", "non-minimal signed position is rejected before arithmetic", changes={"context": {"headPosition": "+111"}}),
        case("fv-cross-type-domain-replay", "fail", "finality-bound bytes signed under the legacy evidence domain fail", changes={"evidence": {"signatureDomainMatches": False}}),
        case("fv-multiple-discriminators", "error", "both old and new evidence discriminators are structurally ambiguous", changes={"evidence": {"discriminator": "multiple"}}),
        case("fv-legacy-evidence-has-no-current-claim", "fail", "legacy evidence remains historical and is not silently upgraded", changes={"evidence": {"discriminator": "legacy"}}),
        case("fv-deterministic-mismatch-precedes-outage", "fail", "wrong network cannot be hidden behind an unrelated unavailable head", changes={"context": {"networkId": "eip155:5", "authority": "unavailable"}}),
        case("fv-dacs5-rsv-reuses-same-verdict", "fail", "DACS-5 RSV preserves the DACS-4 finality rejection", changes={"surface": "dacs5-rsv", "context": {"headPosition": "100"}}),
    ]


def document() -> dict:
    values = vectors()
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {
        "set": OUTPUT.stem,
        "spec": "DACS-4 v0.8 §9.7.0 FV-1..FV-10; DACS-5 v0.6 §10.4.3/§10.5.1",
        "tier": "candidate",
        "description": "Consumer-verifiable canonical settlement finality across chain, BFT, composite and provider models.",
        "provenance": {
            "issue": "DACS-Agent-commerce/DACS-Standard#382",
            "generator": "scripts/generate_settlement_finality_verification_vectors.py",
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
