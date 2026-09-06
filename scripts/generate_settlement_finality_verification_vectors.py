#!/usr/bin/env python3
"""Generate deterministic cryptographic DACS-4 FV and DACS-5 consumer vectors."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from scripts.jcs import canonicalize
    from scripts.settlement_finality_reference import (
        AGREEMENT_DOMAIN,
        BFT_CERTIFICATE_DOMAIN,
        CHAIN_AUTHORITY_DOMAIN,
        EVIDENCE_DOMAIN,
        FIXTURE_POLICY,
        LEGACY_EVIDENCE_DOMAIN,
        PROVIDER_ATTESTATION_DOMAIN,
        RAIL_DOMAIN,
        artifact_hash,
        hash_value,
    )
except ImportError:
    from jcs import canonicalize
    from settlement_finality_reference import (
        AGREEMENT_DOMAIN,
        BFT_CERTIFICATE_DOMAIN,
        CHAIN_AUTHORITY_DOMAIN,
        EVIDENCE_DOMAIN,
        FIXTURE_POLICY,
        LEGACY_EVIDENCE_DOMAIN,
        PROVIDER_ATTESTATION_DOMAIN,
        RAIL_DOMAIN,
        artifact_hash,
        hash_value,
    )


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "settlement-finality-verification.json"
)
OLD_OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "settlement-finality-verification-v0.8.json"
)
VERIFICATION_TIME = 1_900_000_010_000
OBSERVED_AT = 1_900_000_000_000
FINALITY_BUNDLE_DOMAIN = "dacs-finality-bound-evidence-fault-bundle:v1:"
FINALITY_POINTER_DOMAIN = "dacs-finality-bound-evidence-fault-bundle-pointer:v1:"
LISTING_DOMAIN = "dacs-listing:v1:"
OLD_BUNDLE_DOMAINS = {
    "legacy": "dacs-bundle:v1:",
    "fault": "dacs-fault-bundle:v1:",
    "evidence-bound": "dacs-evidence-bound-fault-bundle:v1:",
}
SEEDS = {
    "steward": "11" * 32,
    "buyer": "22" * 32,
    "seller": "33" * 32,
    "orchestrator": "44" * 32,
    "rpc-a": "51" * 32,
    "rpc-b": "52" * 32,
    "rpc-c": "53" * 32,
    "provider": "61" * 32,
    "validator-a": "71" * 32,
    "validator-b": "72" * 32,
    "validator-c": "73" * 32,
}
CLAIMS = {
    "steward": "did:demos:steward",
    "buyer": "did:demos:buyer",
    "seller": "did:demos:seller",
    "orchestrator": "did:demos:orchestrator",
    "provider": "provider:example",
}
MODEL_PHASE = {
    "block-depth": "pay-evm-erc20",
    "commitment-level": "pay-solana-spl",
    "bft-final": "pay-dem",
    "provider-receipt": "pay-ap2",
    "htlc-reveal": "pay-cross-chain-htlc",
    "liquidity-tank": "pay-cross-chain-liquidity-tank",
}


def canonical_bytes(value) -> bytes:
    return canonicalize(value).encode("utf-8")


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def merge(base: dict, changes: dict | None) -> dict:
    value = copy.deepcopy(base)
    for key, item in (changes or {}).items():
        if isinstance(item, dict) and isinstance(value.get(key), dict):
            value[key] = merge(value[key], item)
        else:
            value[key] = copy.deepcopy(item)
    return value


class FixtureFactory:
    def __init__(self):
        self.keys = {
            name: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
            for name, seed in SEEDS.items()
        }
        validator_set = {
            "validators": [
                {
                    "validatorId": name,
                    "weight": weight,
                    "publicKey": b64u(self.keys[name].public_key().public_bytes_raw()),
                }
                for name, weight in (
                    ("validator-a", 40), ("validator-b", 35), ("validator-c", 25)
                )
            ]
        }
        validator_set_hash = hash_value(validator_set)
        self.validator_set_hash = validator_set_hash
        self.trusted = {
            "policy": FIXTURE_POLICY,
            "verificationTimeMs": VERIFICATION_TIME,
            "stewardKeys": {
                CLAIMS["steward"]: b64u(self.keys["steward"].public_key().public_bytes_raw())
            },
            "partyKeys": {
                CLAIMS[name]: b64u(self.keys[name].public_key().public_bytes_raw())
                for name in ("buyer", "seller", "orchestrator")
            },
            "observationAuthorityKeys": {
                name: b64u(self.keys[name].public_key().public_bytes_raw())
                for name in ("rpc-a", "rpc-b", "rpc-c")
            },
            "providerAuthorityKeys": {
                CLAIMS["provider"]: b64u(self.keys["provider"].public_key().public_bytes_raw())
            },
            "validatorSets": {validator_set_hash: validator_set},
            "providerAttestations": {},
            "sessionAuthorityByJob": {},
        }
        self.controls = {}

    def sign_digest(self, key_name: str, domain: str, digest: str) -> str:
        return b64u(self.keys[key_name].sign((domain + digest).encode("ascii")))

    def reference(self, label: str, content_hash: str) -> dict:
        return {
            "anchor": {
                "kind": "storage-program",
                "locator": "stor-" + hashlib.sha256(label.encode()).hexdigest(),
            },
            "contentHash": content_hash,
        }

    def chain_profile(self, kind="block-depth", *, network="eip155:1", genesis=None) -> dict:
        profile = {
            "kind": kind,
            "networkId": network,
            "genesisHash": genesis or hashlib.sha256(("genesis:" + network).encode()).hexdigest(),
            "observation": {
                "method": "rpc-quorum",
                "authorityRefs": ["rpc-a", "rpc-b", "rpc-c"],
                "threshold": 2,
                "maxHeadAgeSec": 60,
            },
        }
        if kind == "block-depth":
            profile["requiredDepth"] = 12
        elif kind == "commitment-level":
            profile["requiredCommitment"] = "finalized"
        else:
            profile.update({
                "validatorSetRef": self.reference("validator-set", self.validator_set_hash),
                "quorumNumerator": 2,
                "quorumDenominator": 3,
            })
        return profile

    @staticmethod
    def merkle_proof(kind: str, bytes_field: str, body: dict, label: str) -> dict:
        raw = canonical_bytes(body)
        leaf = hashlib.sha256(b"\x00" + raw).hexdigest()
        sibling = hashlib.sha256(("sibling:" + label).encode()).hexdigest()
        root = hashlib.sha256(b"\x01" + bytes.fromhex(leaf) + bytes.fromhex(sibling)).hexdigest()
        return {
            "kind": kind,
            bytes_field: b64u(raw),
            "leafHash": leaf,
            "siblingHash": sibling,
            "leafIndex": 0,
            "root": root,
        }

    def sign_chain_authority(self, observation: dict, signers=("rpc-a", "rpc-b", "rpc-c")) -> None:
        path_ids = [observation["inclusionBlock"]["id"]] + [
            link["childId"] for link in observation["ancestryProof"]
        ]
        head = observation["authenticatedHead"]
        payload = {
            "networkId": observation["networkId"],
            "genesisHash": observation["genesisHash"],
            "headId": head["id"],
            "headPosition": head["position"],
            "observedAt": head["observedAt"],
            "pathDigest": hash_value(path_ids),
        }
        digest = hash_value(payload)
        observation["authorityEvidence"] = {
            "kind": "fixture-threshold-signature-v1",
            "sourceRefs": ["rpc-a", "rpc-b", "rpc-c"],
            "attestations": [
                {
                    "authorityRef": signer,
                    "algorithm": "ed25519",
                    "value": self.sign_digest(signer, CHAIN_AUTHORITY_DOMAIN, digest),
                }
                for signer in signers
            ],
        }

    def chain_observation(
        self,
        profile: dict,
        reference: dict,
        event: dict,
        label: str,
        *,
        head_position: int = 111,
        commitment: str | None = None,
        bft_signers=("validator-a", "validator-b"),
    ) -> dict:
        event_proof = self.merkle_proof(
            "fixture-event-merkle-v1", "eventBytes", event, label + ":event"
        )
        transaction = {
            "networkId": profile["networkId"],
            "genesisHash": profile["genesisHash"],
            "transactionRef": copy.deepcopy(reference),
            "eventsRoot": event_proof["root"],
            "status": "success",
        }
        transaction_proof = self.merkle_proof(
            "fixture-transaction-merkle-v1", "transactionBytes", transaction, label + ":transaction"
        )
        inclusion_position = 100
        parent_id = hashlib.sha256((label + ":block:99").encode()).hexdigest()
        inclusion_header = {
            "networkId": profile["networkId"],
            "genesisHash": profile["genesisHash"],
            "position": str(inclusion_position),
            "parentId": parent_id,
            "transactionsRoot": transaction_proof["root"],
        }
        if commitment is not None and head_position == inclusion_position:
            inclusion_header["commitment"] = commitment
        inclusion_id = hash_value(inclusion_header)
        inclusion = {
            "id": inclusion_id,
            "parentId": parent_id,
            "position": str(inclusion_position),
            "header": b64u(canonical_bytes(inclusion_header)),
        }
        ancestry = []
        previous_id = inclusion_id
        head_header = inclusion_header
        empty_root = hashlib.sha256((label + ":empty-root").encode()).hexdigest()
        for position in range(inclusion_position + 1, head_position + 1):
            header = {
                "networkId": profile["networkId"],
                "genesisHash": profile["genesisHash"],
                "position": str(position),
                "parentId": previous_id,
                "transactionsRoot": empty_root,
            }
            if commitment is not None and position == head_position:
                header["commitment"] = commitment
            child_id = hash_value(header)
            ancestry.append({
                "childId": child_id,
                "parentId": previous_id,
                "position": str(position),
                "header": b64u(canonical_bytes(header)),
            })
            previous_id = child_id
            head_header = header
        observation = {
            "networkId": profile["networkId"],
            "genesisHash": profile["genesisHash"],
            "transactionRef": copy.deepcopy(reference),
            "transactionInclusionProof": transaction_proof,
            "selectedEventProof": event_proof,
            "inclusionBlock": inclusion,
            "authenticatedHead": {
                "id": previous_id,
                "position": str(head_position),
                "observedAt": OBSERVED_AT,
                "header": b64u(canonical_bytes(head_header)),
            },
            "ancestryProof": ancestry,
            "authorityEvidence": None,
        }
        self.sign_chain_authority(observation)
        if profile["kind"] == "bft-final":
            certificate = {
                "kind": "fixture-bft-certificate-v1",
                "validatorSetHash": self.validator_set_hash,
                "blockId": inclusion_id,
                "signatures": [],
            }
            certificate["signatures"] = [
                {
                    "validatorId": signer,
                    "algorithm": "ed25519",
                    "value": self.sign_digest(
                        signer, BFT_CERTIFICATE_DOMAIN, certificate["blockId"]
                    ),
                }
                for signer in bft_signers
            ]
            observation["finalityCertificate"] = certificate
        return observation

    @staticmethod
    def tx_id(label: str) -> str:
        return hashlib.sha256(("tx:" + label).encode()).hexdigest()

    def transaction_ref(self, model: str, label: str) -> dict:
        if model == "block-depth":
            return {"kind": "evm-event", "chainId": 1, "txHash": self.tx_id(label), "logIndex": 0}
        if model == "commitment-level":
            return {
                "kind": "solana-instruction", "cluster": "mainnet",
                "signature": self.tx_id(label), "instructionIndex": 2,
            }
        if model == "bft-final":
            return {"kind": "demos", "txHash": self.tx_id(label), "blockNumber": 100}
        raise ValueError(model)

    @staticmethod
    def common_event(reference: dict, session: dict, *, event_type="transfer") -> dict:
        tx_id = {
            "evm-event": reference.get("txHash"),
            "x402-event": reference.get("settlementTxHash"),
            "solana-instruction": reference.get("signature"),
            "demos": reference.get("txHash"),
            "htlc-lock": reference.get("lockTxHash"),
            "htlc-reveal": reference.get("revealTxHash"),
            "htlc-claim": reference.get("claimTxHash"),
        }[reference["kind"]]
        event_index = reference.get("logIndex", reference.get("instructionIndex", 0))
        return {
            "eventType": event_type,
            "jobId": session["jobId"],
            "phaseIndex": session["phaseIndex"],
            "transactionRef": copy.deepcopy(reference),
            "transactionId": tx_id,
            "eventIndex": event_index,
            "asset": session["asset"],
            "amount": "5",
            "currency": session["asset"],
            "payer": session["payer"],
            "payee": session["payee"],
            "status": "success",
        }

    def agreement(self, job_id: str, rail_id: str, rail_version: int, currency: str) -> dict:
        agreement = {
            "agreementVersion": "1",
            "jobId": job_id,
            "listingRef": {
                "listingId": "listing-finality-fixture",
                "version": 1,
                "contentHash": hashlib.sha256(b"listing-finality-fixture").hexdigest(),
            },
            "parties": [
                {
                    "role": role,
                    "bundleHash": hashlib.sha256((role + ":identity").encode()).hexdigest(),
                    "primaryClaim": CLAIMS[role],
                    "vetRecordRef": self.reference(role + ":vet", hashlib.sha256((role + ":vet-record").encode()).hexdigest()),
                }
                for role in ("buyer", "seller")
            ],
            "terms": {
                "deliverable": {
                    "deliverableType": "entitlement",
                    "hash": hashlib.sha256(b"fixture-deliverable").hexdigest(),
                },
                "price": {"amount": "5", "currency": currency},
                "rail": {"railId": rail_id, "railVersion": rail_version},
                "deadline": 1_900_100_000_000,
            },
            "derivedFromPattern": "fixed-price",
            "generatedAt": 1_899_000_000_000,
            "signatures": [],
        }
        digest = artifact_hash(agreement, "signatures")
        agreement["signatures"] = [
            {
                "party": CLAIMS[role],
                "algorithm": "ed25519",
                "value": self.sign_digest(role, AGREEMENT_DOMAIN, digest),
            }
            for role in ("buyer", "seller")
        ]
        return agreement

    def rail(self, model: str, phase: str, rail_id: str, rail_version: int) -> dict:
        if model == "block-depth":
            profile = {
                "finalityProfileVersion": "1", "model": model,
                "settlement": self.chain_profile(),
            }
            rail_type = "evm-erc20"
            asset = {"kind": "erc20", "chainId": 1, "contract": "0x00000000000000000000000000000000000000cc", "symbol": "USDC", "decimals": 6}
            network = {"kind": "evm", "chainId": 1, "rpcAttestation": "evm-rpc"}
            parameters = {"assetId": "USDC"}
        elif model == "commitment-level":
            profile = {
                "finalityProfileVersion": "1", "model": model,
                "settlement": self.chain_profile("commitment-level", network="solana:mainnet"),
            }
            rail_type = "solana-spl"
            asset = {"kind": "spl", "cluster": "mainnet", "mint": "USDCFixtureMint", "symbol": "USDC", "decimals": 6}
            network = {"kind": "solana", "cluster": "mainnet"}
            parameters = {"assetId": "USDC"}
        elif model == "bft-final":
            profile = {
                "finalityProfileVersion": "1", "model": model,
                "settlement": self.chain_profile("bft-final", network="demos:mainnet"),
            }
            rail_type = "demos-native"
            asset = {"kind": "native-dem", "symbol": "DEM", "decimals": 9}
            network = {"kind": "demos"}
            parameters = {"assetId": "DEM"}
        elif model == "provider-receipt":
            profile = {
                "finalityProfileVersion": "1", "model": model,
                "providerId": CLAIMS["provider"],
                "statusEndpointOrigin": "https://payments.example",
                "captureStatuses": ["captured"],
                "sr3Binding": "provider-jws-v1",
                "maxObservationAgeSec": 60,
                "reversibility": "provisional-provider-capture",
            }
            rail_type = "ap2"
            asset = {"kind": "fiat-via-ap2", "isoCurrency": "USD", "provider": CLAIMS["provider"]}
            network = {"kind": "ap2-provider", "providerEndpoint": "https://payments.example"}
            parameters = {"assetId": "USD"}
        elif model == "htlc-reveal":
            source = self.chain_profile(network="eip155:1")
            destination = self.chain_profile(network="eip155:8453")
            profile = {
                "finalityProfileVersion": "1", "model": model,
                "source": source, "destination": destination,
            }
            rail_type = "cross-chain-htlc"
            asset = {"kind": "stablecoin-cross-chain", "canonicalSymbol": "USDC", "routes": []}
            network = {"kind": "cross-chain", "mechanism": "htlc"}
            parameters = {
                "sourceContract": "0x00000000000000000000000000000000000000a1",
                "destinationContract": "0x00000000000000000000000000000000000000b2",
                "sourceHashAlgorithm": "sha256",
                "destinationHashAlgorithm": "sha3-256",
                "timelockSourceSec": 7200,
                "timelockDestSec": 3600,
                "sourceFinalitySec": 600,
                "safetyWindowSec": 600,
            }
        elif model == "liquidity-tank":
            bridge_id = "tank:sepolia-amoy:usdc"
            profile = {
                "finalityProfileVersion": "1", "model": model, "bridgeId": bridge_id,
                "coordinator": self.chain_profile("bft-final", network="demos:testnet"),
                "source": self.chain_profile(network="eip155:11155111"),
                "destination": self.chain_profile(network="eip155:80002"),
            }
            rail_type = "cross-chain-liquidity-tank"
            asset = {"kind": "stablecoin-cross-chain", "canonicalSymbol": "USDC", "routes": []}
            network = {"kind": "cross-chain", "mechanism": "liquidity-tank"}
            parameters = {"bridgeId": bridge_id, "transferId": "transfer-fixture-392"}
        else:
            raise ValueError(model)
        rail = {
            "railVersion": rail_version,
            "railId": rail_id,
            "railType": rail_type,
            "asset": asset,
            "network": network,
            "phaseHandler": phase,
            "parameters": parameters,
            "consumerFinalityProfile": profile,
            "availability": "mocked",
            "governance": {
                "proposedBy": CLAIMS["steward"],
                "acceptedAt": 1_899_000_000_000,
                "anchoring": "single-signer",
            },
            "signature": {},
        }
        self.resign_rail(rail)
        return rail

    def resign_rail(self, rail: dict, *, key_name="steward", signer=None) -> None:
        signer = signer or CLAIMS[key_name]
        rail["signature"] = {"signer": signer, "algorithm": "ed25519", "value": ""}
        digest = artifact_hash(rail, "signature")
        rail["signature"]["value"] = self.sign_digest(key_name, RAIL_DOMAIN, digest)

    def resign_evidence(self, evidence: dict, *, domain=EVIDENCE_DOMAIN, key_name="orchestrator") -> None:
        evidence["signature"] = {
            "signer": CLAIMS[key_name], "algorithm": "ed25519", "value": "",
        }
        digest = artifact_hash(evidence, "signature")
        evidence["signature"]["value"] = self.sign_digest(key_name, domain, digest)

    def rebind_rail(self, value: dict) -> None:
        self.resign_rail(value["rail"])
        digest = artifact_hash(value["rail"], "signature")
        reference = value["evidence"]["railDefinitionRef"]
        reference["contentHash"] = digest
        reference["railId"] = value["rail"]["railId"]
        reference["railVersion"] = value["rail"]["railVersion"]
        self.resign_evidence(value["evidence"])

    def session(self, model: str, agreement: dict, phase: str, rail_id: str, rail_version: int) -> dict:
        return {
            "jobId": agreement["jobId"],
            "phaseIndex": 0,
            "phaseKind": phase,
            "phaseOrchestrator": CLAIMS["orchestrator"],
            "railId": rail_id,
            "railVersion": rail_version,
            "agreementHash": artifact_hash(agreement, "signatures"),
            "partyClaims": {"buyer": CLAIMS["buyer"], "seller": CLAIMS["seller"]},
            "payer": CLAIMS["buyer"],
            "payee": CLAIMS["seller"],
            "asset": agreement["terms"]["price"]["currency"],
        }

    def provider_context(self, session: dict, reference: dict, *, status="captured", observed_at=OBSERVED_AT) -> tuple[dict, dict]:
        response = {
            "providerRef": reference["providerRef"],
            "endpointOrigin": "https://payments.example",
            "jobId": session["jobId"],
            "phaseIndex": session["phaseIndex"],
            "status": status,
            "amount": "5",
            "currency": session["asset"],
            "payer": session["payer"],
            "payee": session["payee"],
        }
        raw = canonical_bytes(response)
        response_hash = hashlib.sha256(raw).hexdigest()
        attestation = {
            "responseAttestationVersion": "1",
            "providerId": CLAIMS["provider"],
            "sr3Binding": "provider-jws-v1",
            "endpointOrigin": "https://payments.example",
            "providerRef": reference["providerRef"],
            "responseHash": response_hash,
            "observedAt": observed_at,
            "signature": {},
        }
        attestation["signature"] = {
            "signer": CLAIMS["provider"],
            "algorithm": "ed25519",
            "value": self.sign_digest(
                "provider", PROVIDER_ATTESTATION_DOMAIN,
                artifact_hash(attestation, "signature"),
            ),
        }
        attestation_ref = self.reference("provider:" + response_hash, response_hash)
        return {
            "kind": "provider",
            "providerId": CLAIMS["provider"],
            "endpointOrigin": "https://payments.example",
            "providerRef": reference["providerRef"],
            "responseBytes": b64u(raw),
            "responseAttestation": attestation_ref,
        }, attestation

    def model_input(self, model: str) -> dict:
        if model in self.controls:
            return copy.deepcopy(self.controls[model])
        phase = MODEL_PHASE[model]
        job_id = "FV-392-" + model
        rail_id = "fixture:" + model
        rail_version = 1
        currency = {"bft-final": "DEM", "provider-receipt": "USD"}.get(model, "USDC")
        agreement = self.agreement(job_id, rail_id, rail_version, currency)
        session = self.session(model, agreement, phase, rail_id, rail_version)
        self.trusted["sessionAuthorityByJob"][job_id] = copy.deepcopy(session)
        rail = self.rail(model, phase, rail_id, rail_version)
        profile = rail["consumerFinalityProfile"]

        if model in {"block-depth", "commitment-level", "bft-final"}:
            reference = self.transaction_ref(model, model)
            event = self.common_event(reference, session)
            observation = self.chain_observation(
                profile["settlement"], reference, event, model,
                commitment="finalized" if model == "commitment-level" else None,
            )
            payment_refs = [reference]
            context = {"kind": "chain", "observation": observation}
        elif model == "provider-receipt":
            provider_ref = {
                "kind": "ap2",
                "mandateId": hashlib.sha256(b"fixture-mandate").hexdigest(),
                "providerRef": "provider-charge-392",
                "protocolVersion": "1",
            }
            context, attestation = self.provider_context(session, provider_ref)
            provider_ref["receiptAttestation"] = copy.deepcopy(context["responseAttestation"])
            self.trusted["providerAttestations"][attestation["responseHash"]] = attestation
            payment_refs = [provider_ref]
        elif model == "htlc-reveal":
            parameters = rail["parameters"]
            refs = {
                "sourceLock": {
                    "kind": "htlc-lock", "chainId": 1,
                    "contractAddress": parameters["sourceContract"],
                    "lockTxHash": self.tx_id("htlc-source-lock"),
                },
                "sourceClaim": {
                    "kind": "htlc-claim", "chainId": 1,
                    "contractAddress": parameters["sourceContract"],
                    "claimTxHash": self.tx_id("htlc-source-claim"),
                },
                "destinationLock": {
                    "kind": "htlc-lock", "chainId": 8453,
                    "contractAddress": parameters["destinationContract"],
                    "lockTxHash": self.tx_id("htlc-destination-lock"),
                },
                "destinationReveal": {
                    "kind": "htlc-reveal", "chainId": 8453,
                    "contractAddress": parameters["destinationContract"],
                    "revealTxHash": self.tx_id("htlc-destination-reveal"),
                },
            }
            preimage = b"fixture-htlc-preimage-392"
            encoded_preimage = b64u(preimage)
            source_hash = hashlib.sha256(preimage).hexdigest()
            destination_hash = hashlib.sha3_256(preimage).hexdigest()
            source_mined = 1_899_990_000_000
            destination_mined = source_mined + 700_000
            events = {}
            for name, reference in refs.items():
                event = self.common_event(reference, session, event_type=reference["kind"])
                source = name.startswith("source")
                event.update({
                    "contractAddress": parameters["sourceContract"] if source else parameters["destinationContract"],
                    "hashAlgorithm": parameters["sourceHashAlgorithm"] if source else parameters["destinationHashAlgorithm"],
                    "hashlock": source_hash if source else destination_hash,
                })
                if name in {"sourceClaim", "destinationReveal"}:
                    event["preimage"] = encoded_preimage
                if name == "sourceLock":
                    event.update({"minedAt": source_mined, "expiry": source_mined + 7_200_000})
                if name == "destinationLock":
                    event.update({"minedAt": destination_mined, "expiry": destination_mined + 3_600_000})
                events[name] = event
            context = {"kind": "htlc"}
            for name in refs:
                chain_profile = profile["source"] if name.startswith("source") else profile["destination"]
                context[name] = self.chain_observation(
                    chain_profile, refs[name], events[name], "htlc:" + name
                )
            payment_refs = [refs[name] for name in ("sourceLock", "sourceClaim", "destinationLock", "destinationReveal")]
        else:
            bridge_id = profile["bridgeId"]
            composite = {
                "kind": "liquidity-tank",
                "bridgeId": bridge_id,
                "sourceChainId": 11155111,
                "destChainId": 80002,
                "lockTxHash": self.tx_id("tank-source"),
                "releaseTxHash": self.tx_id("tank-destination"),
            }
            refs = {
                "source": {"kind": "evm-event", "chainId": 11155111, "txHash": composite["lockTxHash"], "logIndex": 0},
                "destination": {"kind": "evm-event", "chainId": 80002, "txHash": composite["releaseTxHash"], "logIndex": 0},
                "coordinator": {"kind": "demos", "txHash": hashlib.sha256(("coordinator:" + bridge_id).encode()).hexdigest(), "blockNumber": 100},
            }
            source_event = self.common_event(refs["source"], session, event_type="tank-source-lock")
            source_event.update({"bridgeId": bridge_id, "transferId": rail["parameters"]["transferId"]})
            destination_event = self.common_event(refs["destination"], session, event_type="tank-destination-release")
            destination_event.update({"bridgeId": bridge_id, "transferId": rail["parameters"]["transferId"]})
            coordinator_event = self.common_event(refs["coordinator"], session, event_type="tank-completed")
            coordinator_event.update({
                "bridgeId": bridge_id,
                "transferId": rail["parameters"]["transferId"],
                "sourceEventHash": hash_value(source_event),
                "destinationEventHash": hash_value(destination_event),
            })
            events = {"source": source_event, "destination": destination_event, "coordinator": coordinator_event}
            context = {"kind": "liquidity-tank"}
            for name in ("coordinator", "source", "destination"):
                context[name] = self.chain_observation(
                    profile[name], refs[name], events[name], "tank:" + name
                )
            payment_refs = [composite]

        report = {"model": model, "finalityObservedAt": OBSERVED_AT}
        if model == "block-depth":
            report["finalityBlocks"] = profile["settlement"]["requiredDepth"]
        elif model == "commitment-level":
            report["finalityCommitmentLevel"] = profile["settlement"]["requiredCommitment"]
        rail_digest = artifact_hash(rail, "signature")
        evidence = {
            "finalityBoundEvidenceVersion": "1",
            "jobId": job_id,
            "phase": phase,
            "outcome": "success",
            "paymentTxRefs": payment_refs,
            "paymentAmount": {"amount": "5", "currency": session["asset"]},
            "settlementFinality": report,
            "railDefinitionRef": {
                **self.reference("rail:" + rail_id, rail_digest),
                "railId": rail_id,
                "railVersion": rail_version,
            },
            "observedAt": OBSERVED_AT,
            "signature": {},
        }
        self.resign_evidence(evidence)
        value = {"evidence": evidence, "rail": rail, "agreement": agreement, "context": context}
        self.controls[model] = copy.deepcopy(value)
        return value

    def rebuild_observation_event(self, value: dict, path: tuple[str, ...], mutate) -> None:
        observation = value["context"]
        for segment in path:
            observation = observation[segment]
        encoded = observation["selectedEventProof"]["eventBytes"]
        event = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        mutate(event)
        profile = value["rail"]["consumerFinalityProfile"]
        if value["context"]["kind"] == "chain":
            chain_profile = profile["settlement"]
            ref = value["evidence"]["paymentTxRefs"][0]
            label = "rebuilt:chain"
            commitment = "finalized" if chain_profile["kind"] == "commitment-level" else None
        elif value["context"]["kind"] == "htlc":
            arm = path[-1]
            chain_profile = profile["source"] if arm.startswith("source") else profile["destination"]
            ref = observation["transactionRef"]
            label = "rebuilt:htlc:" + arm
            commitment = None
        else:
            arm = path[-1]
            chain_profile = profile[arm]
            ref = observation["transactionRef"]
            label = "rebuilt:tank:" + arm
            commitment = None
        rebuilt = self.chain_observation(
            chain_profile, ref, event, label, commitment=commitment
        )
        target = value["context"]
        for segment in path[:-1]:
            target = target[segment]
        target[path[-1]] = rebuilt

    def provider_variant(self, *, status="captured", observed_at=OBSERVED_AT) -> tuple[dict, dict]:
        value = self.model_input("provider-receipt")
        ref = value["evidence"]["paymentTxRefs"][0]
        session = self.trusted["sessionAuthorityByJob"][value["evidence"]["jobId"]]
        context, attestation = self.provider_context(session, ref, status=status, observed_at=observed_at)
        ref["receiptAttestation"] = copy.deepcopy(context["responseAttestation"])
        value["context"] = context
        self.resign_evidence(value["evidence"])
        return value, {attestation["responseHash"]: attestation}

    def listing(self, phase: str) -> dict:
        listing = {
            "listingId": "listing-finality-fixture",
            "listingVersion": 1,
            "sellerPrimaryClaim": CLAIMS["seller"],
            "pipeline": [{"kind": phase}],
            "signature": {},
        }
        digest = artifact_hash(listing, "signature")
        listing["signature"] = {
            "signer": CLAIMS["seller"], "algorithm": "ed25519",
            "value": self.sign_digest("seller", LISTING_DOMAIN, digest),
        }
        return listing

    @staticmethod
    def bundle_hash(bundle: dict) -> str:
        return artifact_hash(bundle, ("signatures", "anchoredByRole"))

    def sign_bundle(self, bundle: dict, domain: str) -> None:
        bundle["signatures"] = []
        digest = self.bundle_hash(bundle)
        bundle["signatures"] = [
            {
                "party": CLAIMS[role], "algorithm": "ed25519",
                "value": self.sign_digest(role, domain, digest),
            }
            for role in ("buyer", "seller")
        ]

    def strong_bundle_case(self, model: str) -> dict:
        value = self.model_input(model)
        evidence = value["evidence"]
        phase = evidence["phase"]
        listing = self.listing(phase)
        evidence_digest = artifact_hash(evidence, "signature")
        evidence_ref = self.reference("evidence:" + model, evidence_digest)
        bundle = {
            "finalityBoundEvidenceFaultBundleVersion": "1",
            "jobId": evidence["jobId"],
            "outcome": "completed",
            "faultedParty": "none",
            "anchoredByRole": "buyer",
            "listingRef": {
                "listingId": listing["listingId"],
                "version": listing["listingVersion"],
                "contentHash": artifact_hash(listing, "signature"),
            },
            "parties": [
                {"role": role, "bundleHash": hashlib.sha256((role + ":identity").encode()).hexdigest(), "primaryClaim": CLAIMS[role]}
                for role in ("buyer", "seller")
            ],
            "phaseSummary": [{"index": 0, "kind": phase, "outcome": "ok", "attestationRef": evidence_ref}],
            "vetRecords": [],
            "settlementEvidence": [evidence_ref],
            "recipeRegistryVersion": 1,
            "railRegistryVersion": 1,
            "finalisedAt": OBSERVED_AT,
            "signatures": [],
        }
        self.sign_bundle(bundle, FINALITY_BUNDLE_DOMAIN)
        rail_id = evidence["railDefinitionRef"]["railId"]
        canonical_ref = canonicalize(evidence_ref)
        authority = {
            "listing": listing,
            "referenceValidationByCanonicalRef": {
                canonical_ref: {
                    "record": evidence,
                    "lifecycle": {"state": "finalized", "independentlyResolvable": True},
                }
            },
            "bundleLifecycle": {"state": "finalized", "independentlyResolvable": True},
            "sessionExecutionAuthorityByPhaseKey": {
                "0:" + phase: {
                    "jobId": evidence["jobId"],
                    "phaseIndex": 0,
                    "phaseKind": phase,
                    "phaseOrchestrator": CLAIMS["orchestrator"],
                    "railId": rail_id,
                }
            },
            "verifiedReceiptByCanonicalRef": {
                canonical_ref: {
                    "logicalAddress": "dacs4:payment:%s:%s:0" % (evidence["jobId"], quote(rail_id, safe="-._~")),
                    "nativeAddress": evidence_ref["anchor"]["locator"],
                    "contentHash": evidence_ref["contentHash"],
                    "transaction": "demos:test:" + hashlib.sha256((model + ":anchor").encode()).hexdigest(),
                    "writer": CLAIMS["orchestrator"],
                    "nonce": 0,
                }
            },
            "finalityVerificationByCanonicalRef": {
                canonical_ref: value,
            },
        }
        return {"model": model, "bundle": bundle, "authority": authority}

    def pointer(self, bundle: dict) -> dict:
        pointer = {
            "finalityBoundEvidenceFaultBundleVersion": "1",
            "pointerKind": "extended",
            "fullBundleUrl": "https://example.invalid/finality-bound-bundle.json",
            "fullBundleContentHash": self.bundle_hash(bundle),
            "signature": {},
        }
        digest = artifact_hash(pointer, "signature")
        pointer["signature"] = {
            "signer": CLAIMS["buyer"], "algorithm": "ed25519",
            "value": self.sign_digest("buyer", FINALITY_POINTER_DOMAIN, digest),
        }
        return pointer

    def legacy_evidence_and_authority(self, strong_case: dict) -> tuple[dict, dict, dict]:
        strong = strong_case["authority"]["finalityVerificationByCanonicalRef"]
        value = next(iter(strong.values()))
        old = copy.deepcopy(value["evidence"])
        old.pop("finalityBoundEvidenceVersion")
        old.pop("railDefinitionRef")
        old["evidenceVersion"] = "1"
        self.resign_evidence(old, domain=LEGACY_EVIDENCE_DOMAIN)
        digest = artifact_hash(old, "signature")
        ref = self.reference("legacy-evidence", digest)
        key = canonicalize(ref)
        phase = old["phase"]
        rail_id = value["evidence"]["railDefinitionRef"]["railId"]
        authority = {
            "referenceValidationByCanonicalRef": {
                key: {"record": old, "lifecycle": {"state": "finalized", "independentlyResolvable": True}}
            },
            "verifiedReceiptByCanonicalRef": {
                key: {
                    "logicalAddress": "dacs4:payment:%s:%s:0" % (old["jobId"], quote(rail_id, safe="-._~")),
                    "nativeAddress": ref["anchor"]["locator"],
                    "contentHash": ref["contentHash"],
                    "transaction": "demos:test:legacy-anchor",
                    "writer": CLAIMS["orchestrator"],
                    "nonce": 0,
                }
            },
        }
        return old, ref, authority

    def compatibility_copies(self, strong_case: dict) -> dict:
        strong_bundle = strong_case["bundle"]
        old_record, old_ref, old_authority = self.legacy_evidence_and_authority(strong_case)
        listing = strong_case["authority"]["listing"]
        copies = {"finality-bound": strong_bundle}
        discriminators = {
            "evidence-bound": "evidenceBoundFaultBundleVersion",
            "fault": "faultBundleVersion",
            "legacy": "bundleVersion",
        }
        for kind, discriminator in discriminators.items():
            bundle = copy.deepcopy(strong_bundle)
            bundle.pop("finalityBoundEvidenceFaultBundleVersion")
            bundle[discriminator] = "1"
            bundle["anchoredByRole"] = "seller"
            bundle["settlementEvidence"] = [old_ref]
            bundle["phaseSummary"][0]["attestationRef"] = old_ref
            if kind == "legacy":
                bundle.pop("faultedParty")
            self.sign_bundle(bundle, OLD_BUNDLE_DOMAINS[kind])
            copies[kind] = bundle
        old_authority.update({
            "listing": listing,
            "bundleLifecycle": {"state": "finalized", "independentlyResolvable": True},
            "sessionExecutionAuthorityByPhaseKey": strong_case["authority"]["sessionExecutionAuthorityByPhaseKey"],
        })
        return {"copies": copies, "evidenceBoundAuthority": old_authority}


def case(name: str, expected: str, note: str, value: dict, *, trusted_overrides=None) -> dict:
    finality_class = None
    if expected == "pass":
        finality_class = (
            "provisional-provider-capture"
            if value["rail"]["consumerFinalityProfile"]["model"] == "provider-receipt"
            else "profile-final"
        )
    result = {
        "name": name,
        "expected": expected,
        "note": note,
        "input": value,
        "want": {
            "acceptedAsFinal": expected == "pass",
            "finalityClass": finality_class,
            "producerReportTrustedAsProof": False,
            "dacs5BundleDecision": expected,
        },
    }
    if trusted_overrides:
        result["trustedOverrides"] = trusted_overrides
    return result


def build_vectors(factory: FixtureFactory) -> list[dict]:
    vectors = [
        case("fv-%s-canonical-success" % model, "pass", "all signed artifacts and raw proof relations verify", factory.model_input(model))
        for model in MODEL_PHASE
    ]

    def changed(model, mutation):
        value = factory.model_input(model)
        mutation(value)
        return value

    vectors.extend([
        case("fv-wrong-network", "fail", "observation network differs from the signed profile", changed("block-depth", lambda v: v["context"]["observation"].__setitem__("networkId", "eip155:5"))),
        case("fv-wrong-genesis", "fail", "observation genesis differs from the signed profile", changed("block-depth", lambda v: v["context"]["observation"].__setitem__("genesisHash", "00" * 32))),
        case("fv-signed-transaction-substitution", "fail", "a re-signed evidence reference still must match the authenticated observation", changed("block-depth", lambda v: (v["evidence"]["paymentTxRefs"][0].__setitem__("txHash", "ff" * 32), factory.resign_evidence(v["evidence"])))),
        case("fv-signed-event-index-substitution", "fail", "the selected event index is signature-bound and proof-checked", changed("block-depth", lambda v: (v["evidence"]["paymentTxRefs"][0].__setitem__("logIndex", 1), factory.resign_evidence(v["evidence"])))),
        case("fv-transaction-proof-missing", "indeterminate", "missing raw transaction proof cannot pass", changed("block-depth", lambda v: v["context"]["observation"].__setitem__("transactionInclusionProof", None))),
        case("fv-event-proof-missing", "indeterminate", "missing raw selected-event proof cannot pass", changed("block-depth", lambda v: v["context"]["observation"].__setitem__("selectedEventProof", None))),
        case("fv-event-leaf-substitution", "fail", "raw event bytes must match their Merkle leaf", changed("block-depth", lambda v: v["context"]["observation"]["selectedEventProof"].__setitem__("leafHash", "00" * 32))),
        case("fv-transaction-root-substitution", "fail", "transaction Merkle root must bind the inclusion header", changed("block-depth", lambda v: v["context"]["observation"]["transactionInclusionProof"].__setitem__("root", "00" * 32))),
        case("fv-ancestry-first-link-substitution", "fail", "the first ancestry parent must be the inclusion block", changed("block-depth", lambda v: v["context"]["observation"]["ancestryProof"][0].__setitem__("parentId", "00" * 32))),
        case("fv-ancestry-middle-link-substitution", "fail", "every intermediate ancestry link is verified", changed("block-depth", lambda v: v["context"]["observation"]["ancestryProof"][5].__setitem__("parentId", "00" * 32))),
        case("fv-ancestry-last-link-substitution", "fail", "the final ancestry link must terminate at the authenticated head", changed("block-depth", lambda v: v["context"]["observation"]["ancestryProof"][-1].__setitem__("childId", "00" * 32))),
        case("fv-unverified-extra-ancestry-link", "fail", "an extra unsigned ancestry link cannot increase depth", changed("block-depth", lambda v: v["context"]["observation"]["ancestryProof"].append(copy.deepcopy(v["context"]["observation"]["ancestryProof"][-1])))),
        case("fv-head-authority-missing", "indeterminate", "an unavailable authenticated head cannot be replaced by producer data", changed("block-depth", lambda v: v["context"]["observation"].__setitem__("authorityEvidence", None))),
        case("fv-head-authority-quorum-incomplete", "indeterminate", "one valid RPC authority is below the signed threshold", changed("block-depth", lambda v: v["context"]["observation"]["authorityEvidence"].__setitem__("attestations", v["context"]["observation"]["authorityEvidence"]["attestations"][:1]))),
        case("fv-head-authority-signature-invalid", "fail", "an invalid native observation signature is rejected", changed("block-depth", lambda v: v["context"]["observation"]["authorityEvidence"]["attestations"][0].__setitem__("value", "A" * 86))),
        case("fv-head-authority-key-substitution", "fail", "a producer key cannot replace a pinned observation authority", changed("block-depth", lambda v: v["context"]["observation"]["authorityEvidence"]["attestations"][0].__setitem__("authorityRef", CLAIMS["orchestrator"]))),
        case("fv-verifier-clock-missing", "error", "candidate time cannot replace a missing verifier-local clock", factory.model_input("block-depth"), trusted_overrides={"verificationTimeMs": None}),
        case("fv-head-observation-stale", "indeterminate", "freshness uses the verifier-local clock", factory.model_input("block-depth"), trusted_overrides={"verificationTimeMs": OBSERVED_AT + 61_000}),
        case("fv-head-observation-future", "fail", "future authenticated observation time is rejected", factory.model_input("block-depth"), trusted_overrides={"verificationTimeMs": OBSERVED_AT - 1}),
        case("fv-producer-freshness-substitution", "indeterminate", "a fresh producer report cannot refresh a stale authenticated head", changed("block-depth", lambda v: (v["evidence"]["settlementFinality"].__setitem__("finalityObservedAt", OBSERVED_AT + 61_000), factory.resign_evidence(v["evidence"]))), trusted_overrides={"verificationTimeMs": OBSERVED_AT + 61_000}),
        case("fv-freshness-bound-wrong-type", "error", "nested arithmetic fields are shape-checked", changed("block-depth", lambda v: (v["rail"]["consumerFinalityProfile"]["settlement"]["observation"].__setitem__("maxHeadAgeSec", "60"), factory.rebind_rail(v)))),
        case("fv-evidence-cross-domain-replay", "fail", "legacy evidence domain cannot authenticate the new type", changed("block-depth", lambda v: factory.resign_evidence(v["evidence"], domain=LEGACY_EVIDENCE_DOMAIN))),
        case("fv-evidence-dual-discriminator", "error", "dual evidence discriminators refuse before proof action", changed("block-depth", lambda v: v["evidence"].__setitem__("evidenceVersion", "1"))),
        case("fv-evidence-stripped-discriminator", "error", "stripped finality discriminator cannot satisfy the new consumer", changed("block-depth", lambda v: v["evidence"].pop("finalityBoundEvidenceVersion"))),
        case("fv-evidence-renamed-discriminator", "error", "unknown renamed evidence discriminator is unsupported", changed("block-depth", lambda v: v["evidence"].__setitem__("futureEvidenceVersion", v["evidence"].pop("finalityBoundEvidenceVersion")))),
        case("fv-rail-signature-key-substitution", "fail", "producer cannot substitute the steward rail key", changed("block-depth", lambda v: factory.resign_rail(v["rail"], key_name="orchestrator", signer=CLAIMS["orchestrator"]))),
        case("fv-rail-reference-substitution", "fail", "the exact signed rail hash is evidence-bound", changed("block-depth", lambda v: (v["evidence"]["railDefinitionRef"].__setitem__("contentHash", "00" * 32), factory.resign_evidence(v["evidence"])))),
        case("fv-producer-selects-weaker-depth", "fail", "producer report cannot lower the signed depth", changed("block-depth", lambda v: (v["evidence"]["settlementFinality"].__setitem__("finalityBlocks", 1), factory.resign_evidence(v["evidence"])))),
    ])

    depth_value = factory.model_input("block-depth")
    base_observation = depth_value["context"]["observation"]
    encoded = base_observation["selectedEventProof"]["eventBytes"]
    event = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    depth_value["context"]["observation"] = factory.chain_observation(
        depth_value["rail"]["consumerFinalityProfile"]["settlement"],
        depth_value["evidence"]["paymentTxRefs"][0], event, "insufficient-depth", head_position=110,
    )
    vectors.append(case("fv-insufficient-recomputed-depth", "fail", "authenticated path length, not a scalar summary, determines depth", depth_value))

    wrong_amount = factory.model_input("block-depth")
    factory.rebuild_observation_event(wrong_amount, ("observation",), lambda event: event.__setitem__("amount", "6"))
    vectors.append(case("fv-authenticated-event-economics-mismatch", "fail", "authenticated event amount must match signed agreement and evidence", wrong_amount))

    malformed_event = factory.model_input("block-depth")
    factory.rebuild_observation_event(malformed_event, ("observation",), lambda event: event.__setitem__("bridgeId", "unexpected-bridge"))
    vectors.append(case("fv-authenticated-event-cross-shape-member", "error", "decoded event bodies are closed by authenticated event type", malformed_event))

    weak_commitment = factory.model_input("commitment-level")
    obs = weak_commitment["context"]["observation"]
    encoded = obs["selectedEventProof"]["eventBytes"]
    event = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    weak_commitment["context"]["observation"] = factory.chain_observation(
        weak_commitment["rail"]["consumerFinalityProfile"]["settlement"],
        weak_commitment["evidence"]["paymentTxRefs"][0], event, "weak-commitment", commitment="confirmed",
    )
    vectors.append(case("fv-solana-commitment-too-weak", "fail", "authenticated commitment is below finalized", weak_commitment))

    vectors.extend([
        case("fv-bft-certificate-missing", "indeterminate", "missing BFT certificate cannot pass", changed("bft-final", lambda v: v["context"]["observation"].__setitem__("finalityCertificate", None))),
        case("fv-bft-signature-invalid", "fail", "BFT native proof signature is verified", changed("bft-final", lambda v: v["context"]["observation"]["finalityCertificate"]["signatures"][0].__setitem__("value", "A" * 86))),
        case("fv-bft-quorum-insufficient", "fail", "weighted quorum is recomputed from the pinned validator set", changed("bft-final", lambda v: v["context"]["observation"]["finalityCertificate"].__setitem__("signatures", v["context"]["observation"]["finalityCertificate"]["signatures"][:1]))),
        case("fv-bft-validator-key-substitution", "fail", "unknown validator cannot enter the pinned set", changed("bft-final", lambda v: v["context"]["observation"]["finalityCertificate"]["signatures"][0].__setitem__("validatorId", CLAIMS["orchestrator"]))),
    ])

    provider_not_captured, provider_override = factory.provider_variant(status="declined")
    vectors.extend([
        case("fv-provider-not-captured", "fail", "authenticated exact provider status is not captured", provider_not_captured, trusted_overrides={"providerAttestations": provider_override}),
        case("fv-provider-response-bytes-substitution", "fail", "provider response bytes must match their SR-3 attestation hash", changed("provider-receipt", lambda v: v["context"].__setitem__("responseBytes", b64u(canonical_bytes({"status": "captured"}))))),
        case("fv-provider-attestation-unavailable", "indeterminate", "missing independently resolved SR-3 attestation cannot pass", factory.model_input("provider-receipt"), trusted_overrides={"providerAttestations": None}),
        case("fv-provider-stale", "indeterminate", "provider freshness uses verifier-local time and signed attestation time", factory.model_input("provider-receipt"), trusted_overrides={"verificationTimeMs": OBSERVED_AT + 61_000}),
        case("fv-provider-future", "fail", "future signed provider observation is rejected", factory.model_input("provider-receipt"), trusted_overrides={"verificationTimeMs": OBSERVED_AT - 1}),
        case("fv-provider-origin-not-an-origin", "error", "the signed provider endpoint must be an exact HTTPS origin", changed("provider-receipt", lambda v: (v["rail"]["consumerFinalityProfile"].__setitem__("statusEndpointOrigin", "https://payments.example/status"), factory.rebind_rail(v)))),
        case("fv-provider-reference-substitution", "fail", "providerRef is exact across evidence, response, and attestation", changed("provider-receipt", lambda v: v["context"].__setitem__("providerRef", "provider-charge-other"))),
        case("fv-provider-endpoint-substitution", "fail", "provider endpoint is selected by the signed rail profile", changed("provider-receipt", lambda v: v["context"].__setitem__("endpointOrigin", "https://attacker.example"))),
    ])

    vectors.extend([
        case("fv-htlc-source-lock-missing", "indeterminate", "source lock proof is independently required", changed("htlc-reveal", lambda v: v["context"].__setitem__("sourceLock", None))),
        case("fv-htlc-source-claim-missing", "indeterminate", "source claim proof is independently required", changed("htlc-reveal", lambda v: v["context"].__setitem__("sourceClaim", None))),
        case("fv-htlc-destination-lock-missing", "indeterminate", "destination lock proof is independently required", changed("htlc-reveal", lambda v: v["context"].__setitem__("destinationLock", None))),
        case("fv-htlc-destination-reveal-missing", "indeterminate", "destination reveal proof is independently required", changed("htlc-reveal", lambda v: v["context"].__setitem__("destinationReveal", None))),
        case("fv-htlc-cross-arm-substitution", "fail", "a source observation cannot replace a destination observation", changed("htlc-reveal", lambda v: v["context"].__setitem__("destinationReveal", copy.deepcopy(v["context"]["sourceClaim"])))),
    ])
    htlc_bad_preimage = factory.model_input("htlc-reveal")
    factory.rebuild_observation_event(htlc_bad_preimage, ("destinationReveal",), lambda event: event.__setitem__("preimage", b64u(b"wrong-preimage")))
    vectors.append(case("fv-htlc-preimage-contradiction", "fail", "preimage relation is recomputed from authenticated event bytes", htlc_bad_preimage))
    htlc_bad_contract = factory.model_input("htlc-reveal")
    factory.rebuild_observation_event(htlc_bad_contract, ("destinationLock",), lambda event: event.__setitem__("contractAddress", "0x00000000000000000000000000000000000000ff"))
    vectors.append(case("fv-htlc-contract-contradiction", "fail", "contracts are checked against signed rail parameters", htlc_bad_contract))
    htlc_bad_time = factory.model_input("htlc-reveal")
    factory.rebuild_observation_event(htlc_bad_time, ("destinationLock",), lambda event: event.__setitem__("expiry", event["expiry"] + 4_000_000))
    vectors.append(case("fv-htlc-timelock-contradiction", "fail", "timelock relation is recomputed from authenticated events", htlc_bad_time))

    vectors.extend([
        case("fv-tank-coordinator-missing", "indeterminate", "coordinator state is independently required", changed("liquidity-tank", lambda v: v["context"].__setitem__("coordinator", None))),
        case("fv-tank-source-missing", "indeterminate", "source lock is independently required", changed("liquidity-tank", lambda v: v["context"].__setitem__("source", None))),
        case("fv-tank-destination-missing", "indeterminate", "destination release is independently required", changed("liquidity-tank", lambda v: v["context"].__setitem__("destination", None))),
        case("fv-tank-cross-arm-substitution", "fail", "source and destination proof arms are not interchangeable", changed("liquidity-tank", lambda v: v["context"].__setitem__("destination", copy.deepcopy(v["context"]["source"])))),
    ])
    tank_bad = factory.model_input("liquidity-tank")
    factory.rebuild_observation_event(tank_bad, ("coordinator",), lambda event: event.__setitem__("sourceEventHash", "00" * 32))
    vectors.append(case("fv-tank-coordinator-relation-mismatch", "fail", "coordinator completion binds exact source and destination events", tank_bad))

    vectors.extend([
        case("fv-malformed-head-position", "error", "non-minimal nested positions refuse without arithmetic", changed("block-depth", lambda v: v["context"]["observation"]["authenticatedHead"].__setitem__("position", "+111"))),
        case("fv-malformed-event-index", "error", "boolean event index is not an integer", changed("block-depth", lambda v: (v["evidence"]["paymentTxRefs"][0].__setitem__("logIndex", True), factory.resign_evidence(v["evidence"])))),
        case("fv-malformed-context-kind", "error", "context/profile kind mismatch is structural error", changed("block-depth", lambda v: v["context"].__setitem__("kind", "provider"))),
        case("fv-production-codec-unavailable", "indeterminate", "synthetic vectors never claim a native production codec", factory.model_input("block-depth"), trusted_overrides={"policy": "production-native-unavailable"}),
    ])
    return vectors


def document() -> dict:
    factory = FixtureFactory()
    vectors = build_vectors(factory)
    strong_cases = [factory.strong_bundle_case(model) for model in MODEL_PHASE]
    block_case = next(item for item in strong_cases if item["model"] == "block-depth")
    compatibility = factory.compatibility_copies(block_case)
    pointer = factory.pointer(block_case["bundle"])
    encoded = canonical_bytes(vectors)
    return {
        "set": OUTPUT.stem,
        "spec": "DACS-4 unallocated finality proposal §9.7.0 FV-1..FV-10; DACS-5 typed finality consumer",
        "tier": "candidate",
        "description": "Fixture-only cryptographic finality proofs and typed DACS-5 propagation; no native production proof-wire claim.",
        "provenance": {
            "issue": "DACS-Agent-commerce/DACS-Standard#392",
            "generator": "scripts/generate_settlement_finality_verification_vectors.py",
            "historicalBaseline": "3426faaebc09948d57a3a6d30fd6795df579b68f",
        },
        "fixturePolicyMetadata": {
            "policy": FIXTURE_POLICY,
            "scope": "synthetic-conformance-only",
            "registeredLiveSubstratePolicy": False,
            "privateSeedsAreTestMaterialOnly": True,
            "seeds": SEEDS,
        },
        "trustedFixturePolicy": factory.trusted,
        "count": len(vectors),
        "hash": hashlib.sha256(encoded).hexdigest(),
        "vectors": vectors,
        "dacs5": {
            "bundleDomain": FINALITY_BUNDLE_DOMAIN,
            "pointerDomain": FINALITY_POINTER_DOMAIN,
            "strongBundleCases": strong_cases,
            "compatibility": compatibility,
            "pointer": pointer,
        },
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
        if OLD_OUTPUT.exists():
            OLD_OUTPUT.unlink()
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if OLD_OUTPUT.exists():
        print(f"ERROR: obsolete allocated corpus remains: {OLD_OUTPUT.relative_to(ROOT)}")
        return 1
    if not OUTPUT.exists() or OUTPUT.read_bytes() != expected:
        print(f"ERROR: {OUTPUT.relative_to(ROOT)} is not deterministic/in sync")
        return 1
    print(f"verified {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
