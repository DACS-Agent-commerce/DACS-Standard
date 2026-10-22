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
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

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
        keccak256,
    )
    from scripts.secp256k1_fixture import (
        SECP256K1_ORDER,
        deterministic_ecdsa_signature,
        fixture_private_value,
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
        keccak256,
    )
    from secp256k1_fixture import (
        SECP256K1_ORDER,
        deterministic_ecdsa_signature,
        fixture_private_value,
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
# chain_observation default: an htlc-lock's inclusion header carries its minedAt.
LOCK_EVENT_TIME = object()
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
    # Genuine signers the verifier-local trust input holds no key for.
    "orchestrator-unconfigured": "45" * 32,
    "rpc-d": "54" * 32,
    "rpc-other": "55" * 32,
    "provider-unconfigured": "62" * 32,
    "buyer-unconfigured": "23" * 32,
    "seller-unconfigured": "34" * 32,
}
CLAIMS = {
    "steward": "did:demos:steward",
    "buyer": "did:demos:buyer",
    "seller": "did:demos:seller",
    "orchestrator": "did:demos:orchestrator",
    "orchestrator-unconfigured": "did:demos:orchestrator-unconfigured",
    "provider": "provider:example",
    "provider-unconfigured": "provider:unconfigured",
    "buyer-unconfigured": "did:demos:buyer-unconfigured",
    "seller-unconfigured": "did:demos:seller-unconfigured",
}
# The AP2 wire version the fixtures carry; it is the one version the
# reference implements (AP2_PROTOCOL_VERSIONS).
AP2_PROTOCOL_VERSION = "0.2"
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
            "sr3TransactionFinalityProfile": {
                "sr3Binding": "provider-jws-v1",
                "settlement": self.chain_profile("bft-final", network="demos:mainnet"),
            },
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
        parent_id: str | None = None,
        transaction_mutation=None,
        observed_at: int = OBSERVED_AT,
        block_timestamp=LOCK_EVENT_TIME,
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
        if transaction_mutation is not None:
            # The raw transaction body is still proven, included and signed.
            transaction_mutation(transaction)
        transaction_proof = self.merkle_proof(
            "fixture-transaction-merkle-v1", "transactionBytes", transaction, label + ":transaction"
        )
        inclusion_position = 100
        # A caller-supplied parent places this block on a sibling fork.
        if parent_id is None:
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
        # HTLC-8: the block that includes a lock carries its mined instant,
        # which the lock event records as minedAt.
        if block_timestamp is LOCK_EVENT_TIME:
            block_timestamp = event.get("minedAt") if event.get("eventType") == "htlc-lock" else None
        if block_timestamp is not None:
            inclusion_header["timestamp"] = block_timestamp
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
                "observedAt": observed_at,
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

    @staticmethod
    def base58(value: bytes) -> str:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        number = int.from_bytes(value, "big")
        encoded = ""
        while number:
            number, remainder = divmod(number, 58)
            encoded = alphabet[remainder] + encoded
        return "1" * (len(value) - len(value.lstrip(b"\x00"))) + (encoded or "1")

    @classmethod
    def solana_signature(cls, label: str) -> str:
        return cls.base58(hashlib.sha512(("solana-signature:" + label).encode()).digest())

    def transaction_ref(self, model: str, label: str) -> dict:
        if model == "block-depth":
            return {"kind": "evm-event", "chainId": 1, "txHash": self.tx_id(label), "logIndex": 0}
        if model == "commitment-level":
            return {
                "kind": "solana-instruction", "cluster": "mainnet",
                "signature": self.solana_signature(label), "instructionIndex": 2,
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

    def agreement(
        self, job_id: str, rail_id: str, rail_version: int, currency: str, listing: dict
    ) -> dict:
        agreement = {
            "agreementVersion": "1",
            "jobId": job_id,
            "listingRef": {
                "listingId": listing["listingId"],
                "version": listing["listingVersion"],
                "contentHash": artifact_hash(listing, "signature"),
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
                "sourceHashAlgorithm": "keccak256",
                "destinationHashAlgorithm": "keccak256",
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

    def resign_agreement(self, agreement: dict, *, signers=("buyer", "seller")) -> str:
        """Re-sign every party signature and return the new agreement hash."""
        digest = artifact_hash(agreement, "signatures")
        agreement["signatures"] = [
            {
                "party": CLAIMS[role],
                "algorithm": "ed25519",
                "value": self.sign_digest(role, AGREEMENT_DOMAIN, digest),
            }
            for role in signers
        ]
        return digest

    def resign_rail(self, rail: dict, *, key_name="steward", signer=None) -> None:
        signer = signer or CLAIMS[key_name]
        rail["signature"] = {"signer": signer, "algorithm": "ed25519", "value": ""}
        digest = artifact_hash(rail, "signature")
        rail["signature"]["value"] = self.sign_digest(key_name, RAIL_DOMAIN, digest)

    def sign_ecdsa(self, key_name: str, domain: str, digest: str, *, high_s: bool = False) -> str:
        """A deterministic RFC 6979 low-S DER secp256k1 value over the SIG-1
        bytes; ``high_s`` re-encodes the same (r, n - s), which CORE §B.7
        rejects before any key is consulted."""
        der = deterministic_ecdsa_signature(
            fixture_private_value(("fv-ecdsa:" + key_name).encode()), (domain + digest).encode("ascii")
        )
        if high_s:
            r, s = decode_dss_signature(der)
            der = encode_dss_signature(r, SECP256K1_ORDER - s)
        return b64u(der)

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

    def model_input(self, model: str, *, job_id: str | None = None) -> dict:
        job_id = "FV-392-" + model if job_id is None else job_id
        control_key = (model, job_id)
        if control_key in self.controls:
            return copy.deepcopy(self.controls[control_key])
        phase = MODEL_PHASE[model]
        rail_id = "fixture:" + model
        rail_version = 1
        currency = {"bft-final": "DEM", "provider-receipt": "USD"}.get(model, "USDC")
        listing = self.listing(phase)
        agreement = self.agreement(job_id, rail_id, rail_version, currency, listing)
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
                "protocolVersion": AP2_PROTOCOL_VERSION,
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
            source_hash = keccak256(preimage).hex()
            destination_hash = keccak256(preimage).hex()
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
        self.controls[control_key] = copy.deepcopy(value)
        return value

    def rebuild_observation_event(self, value: dict, path: tuple[str, ...], mutate, *, block_timestamp=LOCK_EVENT_TIME) -> None:
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
            chain_profile, ref, event, label, commitment=commitment,
            block_timestamp=block_timestamp,
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

    def provider_sr3_value(self, *, job_id: str | None = None) -> dict:
        """Build the current Demos DAHR ``ap2-sr3`` provider input, with the
        native ``web2Request`` transaction and its Demos BFT inclusion proof."""
        job_id = "FV-392-ap2-sr3" if job_id is None else job_id
        phase = MODEL_PHASE["provider-receipt"]
        rail_id = "fixture:provider-sr3"
        rail_version = 1
        currency = "USD"
        listing = self.listing(phase)
        agreement = self.agreement(job_id, rail_id, rail_version, currency, listing)
        session = self.session("provider-receipt", agreement, phase, rail_id, rail_version)
        self.trusted["sessionAuthorityByJob"][job_id] = copy.deepcopy(session)
        rail = self.rail("provider-receipt", phase, rail_id, rail_version)

        provider_ref = {
            "kind": "ap2-sr3",
            "mandateId": hashlib.sha256(b"fixture-mandate").hexdigest(),
            "providerRef": "provider-charge-392",
            "protocolVersion": AP2_PROTOCOL_VERSION,
        }
        context, attestation = self.provider_context(session, provider_ref)
        response_hash = attestation["responseHash"]
        status_resource = "https://payments.example/status"
        receipt_attestation = {
            "anchor": {"kind": "https", "locator": status_resource},
            "contentHash": response_hash,
        }
        provider_ref["receiptAttestation"] = copy.deepcopy(receipt_attestation)
        tx_hash = self.tx_id("ap2-sr3-web2-request")
        provider_ref["receiptTransactionRef"] = {"kind": "demos-web2-request", "value": tx_hash}
        context["responseAttestation"] = copy.deepcopy(receipt_attestation)
        self.trusted["providerAttestations"][response_hash] = attestation

        sr3_profile = self.trusted["sr3TransactionFinalityProfile"]["settlement"]
        web2_ref = {"kind": "demos-web2-request", "value": tx_hash}
        web2_event = {
            "eventType": "web2-request",
            "transactionRef": copy.deepcopy(web2_ref),
            "transactionId": tx_hash,
            "requestUrl": status_resource,
            "requestMethod": "GET",
            "responseStatus": 200,
            "responseHash": response_hash,
        }
        observation = self.chain_observation(
            sr3_profile, web2_ref, web2_event, "ap2-sr3:web2-request"
        )
        context["receiptTransactionObservation"] = observation

        report = {"model": "provider-receipt", "finalityObservedAt": OBSERVED_AT}
        rail_digest = artifact_hash(rail, "signature")
        evidence = {
            "finalityBoundEvidenceVersion": "1",
            "jobId": job_id,
            "phase": phase,
            "outcome": "success",
            "paymentTxRefs": [provider_ref],
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
        return {"evidence": evidence, "rail": rail, "agreement": agreement, "context": context}

    def listing(self, phase: str) -> dict:
        listing = {
            "listingId": "listing-finality-fixture",
            "listingVersion": 1,
            "sellerPrimaryClaim": CLAIMS["seller"],
            "pipeline": [
                {"kind": "negotiate-fixed-price"},
                {"kind": "commit-agreement"},
                {"kind": phase},
            ],
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

    def bind_current_laa_authority(self, bundle: dict, authority: dict) -> None:
        """Bind one verifier-owned current-agreement carrier per successful payment."""
        listing = authority["listing"]
        resolutions = authority["referenceValidationByCanonicalRef"]
        receipts = authority["verifiedReceiptByCanonicalRef"]
        executions = authority["sessionExecutionAuthorityByPhaseKey"]
        finality_inputs = authority["finalityVerificationByCanonicalRef"]
        carriers = {}
        for summary in bundle["phaseSummary"]:
            if summary.get("outcome") != "ok" or summary.get("kind") not in MODEL_PHASE.values():
                continue
            evidence_ref = summary.get("attestationRef")
            if not isinstance(evidence_ref, dict):
                continue
            canonical_ref = canonicalize(evidence_ref)
            resolution = resolutions[canonical_ref]
            evidence = resolution["record"]
            if evidence.get("outcome") != "success":
                continue
            phase_key = "%d:%s" % (summary["index"], summary["kind"])
            execution = executions[phase_key]
            receipt = receipts[canonical_ref]
            finality_input = finality_inputs[canonical_ref]
            agreement_hash = artifact_hash(finality_input["agreement"], "signatures")
            session_id = "session-finality-" + hashlib.sha256(
                (evidence["jobId"] + ":" + phase_key).encode()
            ).hexdigest()
            laa = {
                "operation": "authorize-payment",
                "pipelineHasPayment": True,
                "agreement": {
                    "artifact": "payee-bound",
                    "shape": "valid",
                    "partySignaturesValid": True,
                    "contentHash": agreement_hash,
                    "jobId": evidence["jobId"],
                    "phase": evidence["phase"],
                    "listingRef": copy.deepcopy(bundle["listingRef"]),
                    "pbVerified": True,
                },
                "sessionAuthority": {
                    "state": "verified",
                    "jobId": evidence["jobId"],
                    "sessionId": session_id,
                    "orchestratorPrimaryClaim": execution["phaseOrchestrator"],
                },
            }
            resolution.update({
                "agreementHash": agreement_hash,
                "sessionId": session_id,
            })
            carriers[phase_key] = {
                "laa": laa,
                "binding": {
                    "laaContentHash": hashlib.sha256(canonical_bytes(laa)).hexdigest(),
                    "bundleContentHash": self.bundle_hash(bundle),
                    "listingRef": copy.deepcopy(bundle["listingRef"]),
                    "listingContentHash": artifact_hash(listing, "signature"),
                    "agreementContentHash": agreement_hash,
                    "jobId": evidence["jobId"],
                    "sessionId": session_id,
                    "phaseKey": phase_key,
                    "phaseIndex": execution["phaseIndex"],
                    "phase": evidence["phase"],
                    "phaseOrchestrator": execution["phaseOrchestrator"],
                    "evidenceSigner": evidence["signature"]["signer"],
                    "evidenceContentHash": artifact_hash(evidence, "signature"),
                    "evidenceRef": copy.deepcopy(evidence_ref),
                    "evidenceReceiptHash": hashlib.sha256(
                        canonical_bytes(receipt)
                    ).hexdigest(),
                    "receiptWriter": receipt["writer"],
                },
            }
        authority["legacyAgreementAuthorityByPhaseKey"] = carriers

    def bind_legacy_commitment(
        self, bundle: dict, authority: dict, *, agreement_hash: str | None = None
    ) -> dict:
        """Prefix a valid fixed-price legacy commitment and return its bundle ref."""
        listing = authority["listing"]
        agreement = next(iter(
            authority["finalityVerificationByCanonicalRef"].values()
        ))["agreement"]
        prefix = [
            {"kind": "negotiate-fixed-price"},
            {"kind": "commit-agreement"},
        ]
        already_prefixed = (
            len(listing.get("pipeline", [])) >= 2
            and listing["pipeline"][:2] == prefix
        )
        if not already_prefixed:
            listing["pipeline"] = copy.deepcopy(prefix) + listing["pipeline"]
            for summary in bundle["phaseSummary"]:
                summary["index"] += len(prefix)
                ref = summary.get("attestationRef")
                if isinstance(ref, dict):
                    key = canonicalize(ref)
                    receipt = authority["verifiedReceiptByCanonicalRef"].get(key)
                    if isinstance(receipt, dict) and isinstance(
                        receipt.get("logicalAddress"), str
                    ):
                        receipt["logicalAddress"] = (
                            receipt["logicalAddress"].rsplit(":", 1)[0]
                            + ":" + str(summary["index"])
                        )
            bundle["phaseSummary"] = [
                {"index": 0, "kind": "negotiate-fixed-price", "outcome": "ok"},
                {"index": 1, "kind": "commit-agreement", "outcome": "ok"},
                *bundle["phaseSummary"],
            ]
            shifted_execution = {}
            for phase_key, execution in authority[
                "sessionExecutionAuthorityByPhaseKey"
            ].items():
                index_text, phase_kind = phase_key.split(":", 1)
                shifted = copy.deepcopy(execution)
                shifted["phaseIndex"] = int(index_text) + len(prefix)
                shifted_execution[
                    str(shifted["phaseIndex"]) + ":" + phase_kind
                ] = shifted
            authority["sessionExecutionAuthorityByPhaseKey"] = shifted_execution
        listing_digest = artifact_hash(listing, "signature")
        listing["signature"] = {
            "signer": CLAIMS["seller"], "algorithm": "ed25519",
            "value": self.sign_digest("seller", LISTING_DOMAIN, listing_digest),
        }
        listing_ref = {
            "listingId": listing["listingId"],
            "version": listing["listingVersion"],
            "contentHash": listing_digest,
        }
        bundle["listingRef"] = copy.deepcopy(listing_ref)
        agreement["listingRef"] = copy.deepcopy(listing_ref)
        digest = artifact_hash(agreement, "signatures")
        self.trusted["sessionAuthorityByJob"][bundle["jobId"]][
            "agreementHash"
        ] = digest
        agreement["signatures"] = [
            {
                "party": CLAIMS[role], "algorithm": "ed25519",
                "value": self.sign_digest(role, AGREEMENT_DOMAIN, digest),
            }
            for role in ("buyer", "seller")
        ]
        agreement_ref = self.reference(
            "agreement:" + bundle["jobId"], agreement_hash or digest
        )
        bundle["agreementRef"] = copy.deepcopy(agreement_ref)
        authority["agreementSelectionResult"] = {
            "resolution": "verified",
            "agreementRef": copy.deepcopy(agreement_ref),
            "agreementType": "legacy",
            "proofVerified": True,
        }
        self.sign_bundle(bundle, FINALITY_BUNDLE_DOMAIN)
        self.bind_current_laa_authority(bundle, authority)
        return agreement_ref

    def strong_bundle_case(
        self, model: str, *, job_id: str | None = None, value: dict | None = None
    ) -> dict:
        if value is None:
            value = self.model_input(model, job_id=job_id)
        else:
            value = copy.deepcopy(value)
        return self._strong_bundle_case(model, value)

    def strong_bundle_case_sr3(self, *, job_id: str | None = None) -> dict:
        return self._strong_bundle_case("provider-receipt", self.provider_sr3_value(job_id=job_id))

    def _strong_bundle_case(self, model: str, value: dict) -> dict:
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
            "phaseSummary": [
                {"index": 0, "kind": "negotiate-fixed-price", "outcome": "ok"},
                {"index": 1, "kind": "commit-agreement", "outcome": "ok"},
                {"index": 2, "kind": phase, "outcome": "ok", "attestationRef": evidence_ref},
            ],
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
                "2:" + phase: {
                    "jobId": evidence["jobId"],
                    "phaseIndex": 2,
                    "phaseKind": phase,
                    "phaseOrchestrator": CLAIMS["orchestrator"],
                    "railId": rail_id,
                }
            },
            "verifiedReceiptByCanonicalRef": {
                canonical_ref: {
                    "receiptVersion": "1",
                    "substrate": "demos-testnet",
                    "finalityProfile": "demos-bft-final",
                    "logicalAddress": "dacs4:payment:%s:%s:2" % (evidence["jobId"], quote(rail_id, safe="-._~")),
                    "nativeAddress": evidence_ref["anchor"]["locator"],
                    "contentHash": evidence_ref["contentHash"],
                    "transactionRef": {
                        "kind": "demos-transaction",
                        "value": "demos:test:" + hashlib.sha256((model + ":anchor").encode()).hexdigest(),
                    },
                    "writer": CLAIMS["orchestrator"],
                    "nonce": "0",
                    "state": "finalized",
                    "observationDisposition": "established",
                    "observedAt": OBSERVED_AT,
                    "blockRef": {
                        "id": "block-" + hashlib.sha256((model + ":anchor").encode()).hexdigest()[:32],
                        "height": "1000",
                        "timestamp": OBSERVED_AT,
                    },
                    "evidence": {
                        "kind": "fixture-demos-bft-proof",
                        "value": hashlib.sha256((model + ":receipt-proof").encode()).hexdigest(),
                    },
                }
            },
            "finalityVerificationByCanonicalRef": {
                canonical_ref: value,
            },
        }
        agreement = value["agreement"]
        agreement_ref = self.reference(
            "agreement:" + model,
            artifact_hash(agreement, "signatures"),
        )
        bundle["agreementRef"] = copy.deepcopy(agreement_ref)
        authority["agreementSelectionResult"] = {
            "resolution": "verified",
            "agreementRef": copy.deepcopy(agreement_ref),
            "agreementType": "legacy",
            "proofVerified": True,
        }
        self.sign_bundle(bundle, FINALITY_BUNDLE_DOMAIN)
        self.bind_current_laa_authority(bundle, authority)
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
        phase_index = next(
            entry["index"]
            for entry in strong_case["bundle"]["phaseSummary"]
            if entry.get("kind") == phase
        )
        rail_id = value["evidence"]["railDefinitionRef"]["railId"]
        authority = {
            "referenceValidationByCanonicalRef": {
                key: {"record": old, "lifecycle": {"state": "finalized", "independentlyResolvable": True}}
            },
            "verifiedReceiptByCanonicalRef": {
                key: {
                    "logicalAddress": "dacs4:payment:%s:%s:%d" % (
                        old["jobId"], quote(rail_id, safe="-._~"), phase_index,
                    ),
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
            payment_summary = next(
                entry for entry in bundle["phaseSummary"]
                if entry.get("kind") == old_record["phase"]
            )
            payment_summary["attestationRef"] = old_ref
            if kind == "legacy":
                bundle.pop("faultedParty")
            self.sign_bundle(bundle, OLD_BUNDLE_DOMAINS[kind])
            copies[kind] = bundle
        old_authority.update({
            "evidenceReceiptContract": "archival",
            "listing": listing,
            "bundleLifecycle": {"state": "finalized", "independentlyResolvable": True},
            "sessionExecutionAuthorityByPhaseKey": strong_case["authority"]["sessionExecutionAuthorityByPhaseKey"],
        })
        for field in ("additionalCommitPhase", "agreementSelectionResult"):
            if field in strong_case["authority"]:
                old_authority[field] = copy.deepcopy(strong_case["authority"][field])
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
        case("fv-solana-signature-invalid-base58", "error", "Solana instruction signatures use the base58 alphabet", changed("commitment-level", lambda v: (v["evidence"]["paymentTxRefs"][0].__setitem__("signature", "not-base58-0OIl"), factory.resign_evidence(v["evidence"])))),
        case("fv-solana-signature-wrong-width", "error", "Solana instruction signatures decode to exactly 64 bytes", changed("commitment-level", lambda v: (v["evidence"]["paymentTxRefs"][0].__setitem__("signature", factory.base58(b"\x05" * 63)), factory.resign_evidence(v["evidence"])))),
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

    # The sibling block is authentic and includes the signed transaction, but
    # the authenticated head and ancestry are those of the canonical fork.
    stale_fork = factory.model_input("block-depth")
    canonical = stale_fork["context"]["observation"]
    sibling = factory.chain_observation(
        stale_fork["rail"]["consumerFinalityProfile"]["settlement"],
        stale_fork["evidence"]["paymentTxRefs"][0], event, "stale-fork",
        parent_id=canonical["inclusionBlock"]["parentId"],
    )
    for member in ("transactionInclusionProof", "selectedEventProof", "inclusionBlock"):
        canonical[member] = sibling[member]
    vectors.append(case("fv-stale-fork-inclusion", "fail", "an authentic inclusion block on a sibling fork is outside the authenticated canonical path", stale_fork))

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

    def changed_sr3(mutation):
        value = factory.provider_sr3_value()
        mutation(value)
        return value

    vectors.append(case("fv-ap2-sr3-canonical-success", "pass", "current Demos DAHR ap2-sr3 arm authenticates the native web2Request transaction and response commitment", factory.provider_sr3_value()))

    vectors.extend([
        case("fv-ap2-sr3-native-observation-missing", "indeterminate", "a missing SR-3 native transaction observation cannot pass", changed_sr3(lambda v: v["context"].pop("receiptTransactionObservation"))),
        case("fv-ap2-sr3-native-profile-unavailable", "indeterminate", "the independently authenticated SR-3 finality profile is required", factory.provider_sr3_value(), trusted_overrides={"sr3TransactionFinalityProfile": None}),
        case("fv-ap2-sr3-receipt-transaction-ref-substitution", "fail", "the signed receipt transaction hash must match the authenticated native transaction", changed_sr3(lambda v: (v["evidence"]["paymentTxRefs"][0]["receiptTransactionRef"].__setitem__("value", "ff" * 32), factory.resign_evidence(v["evidence"])))),
        case("fv-ap2-sr3-native-transaction-reference-substitution", "fail", "the observed native transaction must bind the signed receipt transaction reference", changed_sr3(lambda v: v["context"]["receiptTransactionObservation"].__setitem__("transactionRef", {"kind": "demos-web2-request", "value": "ff" * 32}))),
        case("fv-ap2-sr3-inclusion-block-substitution", "fail", "the native transaction inclusion block must verify against its header", changed_sr3(lambda v: v["context"]["receiptTransactionObservation"]["inclusionBlock"].__setitem__("id", "00" * 32))),
        case("fv-ap2-sr3-bft-certificate-missing", "indeterminate", "the native transaction finality certificate is independently required", changed_sr3(lambda v: v["context"]["receiptTransactionObservation"].__setitem__("finalityCertificate", None))),
        case("fv-ap2-sr3-malformed-receipt-transaction-ref", "error", "the ap2-sr3 receipt transaction reference is closed over kind and value", changed_sr3(lambda v: (v["evidence"]["paymentTxRefs"][0]["receiptTransactionRef"].__setitem__("value", 12345), factory.resign_evidence(v["evidence"])))),
        case("fv-ap2-sr3-frozen-arm-native-authority-forbidden", "error", "the frozen ap2 arm must not carry SR-3 native transaction authority", changed("provider-receipt", lambda v: v["context"].__setitem__("receiptTransactionObservation", {}))),
        case("fv-ap2-sr3-native-profile-malformed-empty-list", "error", "a malformed trusted SR-3 finality profile is error, not indeterminate", factory.provider_sr3_value(), trusted_overrides={"sr3TransactionFinalityProfile": []}),
        case("fv-ap2-sr3-native-profile-malformed-settlement", "error", "a malformed trusted SR-3 finality settlement profile is error, not indeterminate", factory.provider_sr3_value(), trusted_overrides={"sr3TransactionFinalityProfile": {"settlement": []}}),
        case("fv-ap2-sr3-native-profile-binding-mismatch", "indeterminate", "the native transaction finality profile must be bound to the selected SR-3 binding", factory.provider_sr3_value(), trusted_overrides={"sr3TransactionFinalityProfile": {"sr3Binding": "other-sr3-binding-v1", "settlement": copy.deepcopy(factory.trusted["sr3TransactionFinalityProfile"]["settlement"])}}),
        case("fv-ap2-sr3-malformed-observation-before-profile", "error", "a malformed native transaction observation is error even when the trusted finality profile is missing", changed_sr3(lambda v: v["context"].__setitem__("receiptTransactionObservation", [])), trusted_overrides={"sr3TransactionFinalityProfile": None}),
    ])

    sr3_bad_response = factory.provider_sr3_value()
    sr3_observation = sr3_bad_response["context"]["receiptTransactionObservation"]
    sr3_encoded = sr3_observation["selectedEventProof"]["eventBytes"]
    sr3_event = json.loads(base64.urlsafe_b64decode(sr3_encoded + "=" * (-len(sr3_encoded) % 4)))
    sr3_event["responseHash"] = "00" * 32
    sr3_bad_response["context"]["receiptTransactionObservation"] = factory.chain_observation(
        factory.trusted["sr3TransactionFinalityProfile"]["settlement"],
        sr3_observation["transactionRef"], sr3_event, "ap2-sr3:bad-response",
    )
    vectors.append(case("fv-ap2-sr3-response-hash-contradiction", "fail", "the native transaction must commit the exact provider response hash", sr3_bad_response))

    vectors.extend([
        case("fv-ap2-sr3-missing-authority-malformed-response-bytes", "error", "a malformed provider response is error before an unrelated missing SR-3 native transaction observation", changed_sr3(lambda v: (v["context"].pop("receiptTransactionObservation"), v["context"].__setitem__("responseBytes", "not-base64-json")))),
        case("fv-ap2-sr3-missing-authority-attestation-hash-mismatch", "fail", "a provider response hash mismatch is fail before an unrelated missing SR-3 native transaction observation", changed_sr3(lambda v: (v["context"].pop("receiptTransactionObservation"), v["context"]["responseAttestation"].__setitem__("contentHash", "00" * 32)))),
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
    vectors.extend(build_rejection_vectors(factory))
    vectors.extend(build_guard_isolation_vectors(factory))
    return vectors


def build_rejection_vectors(factory: FixtureFactory) -> list[dict]:
    """One otherwise-valid case per FV rejection guard.

    Each case changes one input and keeps every signed artifact, proof and
    trust input it does not name genuine and consistent, so a verifier that
    ignores the named rule returns a different verdict.
    """
    vectors = []

    def changed(model, mutation):
        value = factory.model_input(model)
        mutation(value)
        return value

    def session_of(value):
        return factory.trusted["sessionAuthorityByJob"][value["evidence"]["jobId"]]

    def session_override(value, **changes):
        return {"sessionAuthorityByJob": {value["evidence"]["jobId"]: changes}}

    def decode(encoded):
        return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))

    # Agreement authority (FV-1): the entry point consumes the signed
    # Agreement that the authenticated session commits.
    def agreement(name, expected, note, mutate, *, commit=True):
        value = factory.model_input("block-depth")
        mutate(value)
        digest = factory.resign_agreement(value["agreement"])
        overrides = session_override(value, agreementHash=digest) if commit else None
        vectors.append(case(name, expected, note, value, trusted_overrides=overrides))

    def other_job(value):
        value["agreement"]["jobId"] = "FV-392-other-job"

    def swap_party_claims(value):
        parties = value["agreement"]["parties"]
        parties[0]["primaryClaim"], parties[1]["primaryClaim"] = (
            parties[1]["primaryClaim"], parties[0]["primaryClaim"]
        )

    def agreement_selects_rail_v2(value):
        value["rail"]["railVersion"] = 2
        factory.rebind_rail(value)
        value["agreement"]["terms"]["rail"]["railVersion"] = 2

    agreement("fv-agreement-member-missing", "error", "a required AgreementDocument member is absent", lambda v: v["agreement"].pop("derivedFromPattern"))
    agreement("fv-agreement-job-mismatch", "fail", "the signed agreement names another job than the authenticated session", other_job)
    agreement("fv-agreement-listing-ref-malformed", "error", "the agreement listingRef version is not an integer", lambda v: v["agreement"]["listingRef"].__setitem__("version", "1"))
    agreement("fv-agreement-party-malformed", "error", "an agreement party lacks its vetRecordRef", lambda v: v["agreement"]["parties"][0].pop("vetRecordRef"))
    agreement("fv-agreement-duplicate-party-role", "error", "both agreement parties claim the buyer role", lambda v: v["agreement"]["parties"][1].__setitem__("role", "buyer"))
    agreement("fv-agreement-parties-differ-from-session", "fail", "the signed buyer and seller claims are reversed against the authenticated session", swap_party_claims)
    agreement("fv-agreement-terms-malformed", "error", "the agreement terms lack a deadline", lambda v: v["agreement"]["terms"].pop("deadline"))
    agreement("fv-agreement-price-noncanonical-decimal", "error", "the agreement price is not a canonical decimal", lambda v: v["agreement"]["terms"]["price"].__setitem__("amount", "5.0"))
    agreement("fv-agreement-rail-differs-from-session", "fail", "the agreement and a re-signed rail select rail version 2; the authenticated session selected version 1", agreement_selects_rail_v2)
    agreement("fv-agreement-hash-not-session-commitment", "fail", "a re-signed agreement whose hash the authenticated session does not commit", lambda v: v["agreement"]["terms"].__setitem__("deadline", v["agreement"]["terms"]["deadline"] + 1), commit=False)

    signed = factory.model_input("block-depth")
    digest = artifact_hash(signed["agreement"], "signatures")
    signed["agreement"]["signatures"][1] = {
        "party": CLAIMS["orchestrator"], "algorithm": "ed25519",
        "value": factory.sign_digest("orchestrator", AGREEMENT_DOMAIN, digest),
    }
    vectors.append(case("fv-agreement-signer-not-session-party", "fail", "a valid agreement signature by a claim that is not a session party", signed))
    forged = factory.model_input("block-depth")
    forged["agreement"]["signatures"][0]["value"] = factory.sign_digest(
        "orchestrator", AGREEMENT_DOMAIN, digest
    )
    vectors.append(case("fv-agreement-signature-invalid", "fail", "the buyer's agreement signature is made by another key", forged))

    # Rail and profile authority (FV-1, FV-2, RD-5).
    def rail(name, expected, note, model, mutate):
        value = factory.model_input(model)
        mutate(value["rail"])
        factory.rebind_rail(value)
        vectors.append(case(name, expected, note, value))

    def asset_and_network_chain(rail_value, chain_id):
        rail_value["asset"]["chainId"] = chain_id
        rail_value["network"]["chainId"] = chain_id

    rail("fv-rail-member-missing", "error", "a steward-signed RailDefinition without availability", "block-depth", lambda r: r.pop("availability"))
    rail("fv-rail-availability-unknown", "error", "a steward-signed rail availability outside the closed set", "block-depth", lambda r: r.__setitem__("availability", "paused"))
    rail("fv-rail-type-unsupported", "error", "a steward-signed rail with an unregistered railType", "block-depth", lambda r: r.__setitem__("railType", "carrier-pigeon"))
    rail("fv-rail-asset-kind-disagrees", "fail", "an evm-erc20 rail whose signed asset kind is spl", "block-depth", lambda r: r["asset"].__setitem__("kind", "spl"))
    rail("fv-rail-asset-chain-id-malformed", "error", "the signed asset chainId is a string", "block-depth", lambda r: r["asset"].__setitem__("chainId", "1"))
    rail("fv-rail-network-chain-id-differs", "fail", "the signed network chainId differs from the asset chainId", "block-depth", lambda r: r["network"].__setitem__("chainId", 5))
    rail("fv-rail-profile-network-differs-from-asset-chain", "fail", "asset and network name chain 5 while the signed finality profile settles on eip155:1", "block-depth", lambda r: asset_and_network_chain(r, 5))
    rail("fv-rail-cluster-differs", "fail", "the signed network cluster differs from the asset cluster", "commitment-level", lambda r: r["network"].__setitem__("cluster", "devnet"))
    rail("fv-rail-provider-differs", "fail", "the signed asset provider differs from the finality profile provider", "provider-receipt", lambda r: r["asset"].__setitem__("provider", "provider:other"))
    rail("fv-rail-provider-endpoint-malformed", "error", "the signed provider endpoint is not a string", "provider-receipt", lambda r: r["network"].__setitem__("providerEndpoint", 443))
    rail("fv-rail-cross-chain-mechanism-differs", "fail", "an HTLC rail whose signed cross-chain mechanism is liquidity-tank", "htlc-reveal", lambda r: r["network"].__setitem__("mechanism", "liquidity-tank"))
    rail("fv-rail-currency-undeclared", "error", "the signed rail asset declares no canonical currency", "block-depth", lambda r: r["asset"].pop("symbol"))
    rail("fv-rail-currency-differs", "fail", "the signed rail asset is USDT while the agreement settles USDC", "block-depth", lambda r: r["asset"].__setitem__("symbol", "USDT"))
    rail("fv-profile-version-unknown", "error", "an unknown finalityProfileVersion", "block-depth", lambda r: r["consumerFinalityProfile"].__setitem__("finalityProfileVersion", "2"))
    rail("fv-profile-capability-unknown", "error", "an unregistered finalityResolutionCapability", "block-depth", lambda r: r["consumerFinalityProfile"].__setitem__("finalityResolutionCapability", "finality-resolution-context-v2"))
    rail("fv-profile-model-unknown", "error", "an unregistered finality model", "block-depth", lambda r: r["consumerFinalityProfile"].__setitem__("model", "probabilistic"))
    rail("fv-profile-settlement-kind-unknown", "error", "an unregistered settlement profile kind", "block-depth", lambda r: r["consumerFinalityProfile"]["settlement"].__setitem__("kind", "longest-chain"))
    rail("fv-profile-required-depth-missing", "error", "a block-depth settlement profile without requiredDepth", "block-depth", lambda r: r["consumerFinalityProfile"]["settlement"].pop("requiredDepth"))
    rail("fv-profile-provider-origin-not-string", "error", "the signed provider status endpoint origin is not a string", "provider-receipt", lambda r: r["consumerFinalityProfile"].__setitem__("statusEndpointOrigin", 443))

    rail("fv-rail-network-chain-id-malformed", "error", "the signed network chainId is zero", "block-depth", lambda r: r["network"].__setitem__("chainId", 0))
    rail("fv-rail-asset-cluster-malformed", "error", "the signed asset cluster is outside mainnet/devnet/testnet", "commitment-level", lambda r: r["asset"].__setitem__("cluster", "mainnet-beta"))
    rail("fv-rail-profile-network-differs-from-cluster", "fail", "asset and network name devnet while the signed finality profile settles on solana:mainnet", "commitment-level", lambda r: (r["asset"].__setitem__("cluster", "devnet"), r["network"].__setitem__("cluster", "devnet")))
    rail("fv-rail-provider-endpoint-not-https", "error", "the signed provider endpoint is not an HTTPS URL", "provider-receipt", lambda r: r["network"].__setitem__("providerEndpoint", "http://payments.example"))

    # An unregistered algorithm, so `error` holds for every verifier. A
    # registered label over these Ed25519 bytes would be a CORE §B.7 encoding
    # `fail` to a verifier that implements that algorithm.
    envelope = factory.model_input("block-depth")
    envelope["rail"]["signature"]["algorithm"] = "ed448"
    vectors.append(case("fv-rail-signature-envelope-malformed", "error", "the rail signature envelope names an algorithm outside the registered set", envelope))

    # DACS-4 §9.4.3: the phase handler selects the required finality model.
    handler = factory.model_input("commitment-level")
    handler["rail"]["phaseHandler"] = "pay-evm-erc20"
    factory.rebind_rail(handler)
    handler["evidence"]["phase"] = "pay-evm-erc20"
    factory.resign_evidence(handler["evidence"])
    vectors.append(case("fv-rail-phase-handler-requires-other-model", "fail", "a steward-signed pay-evm-erc20 rail declares commitment-level finality; that handler requires block-depth", handler, trusted_overrides=session_override(handler, phaseKind="pay-evm-erc20")))

    # Producer report (FV-2): the report echoes the profile and is never proof.
    def report(name, expected, note, model, mutate):
        value = factory.model_input(model)
        mutate(value["evidence"])
        factory.resign_evidence(value["evidence"])
        vectors.append(case(name, expected, note, value))

    report("fv-producer-report-model-mismatch", "fail", "the signed producer report names bft-final for a block-depth profile", "block-depth", lambda e: e["settlementFinality"].__setitem__("model", "bft-final"))
    report("fv-producer-report-commitment-mismatch", "fail", "the signed producer report echoes confirmed for a finalized profile", "commitment-level", lambda e: e["settlementFinality"].__setitem__("finalityCommitmentLevel", "confirmed"))
    report("fv-producer-report-malformed", "error", "the signed producer report lacks finalityObservedAt", "block-depth", lambda e: e["settlementFinality"].pop("finalityObservedAt"))
    report("fv-producer-report-not-object", "error", "the signed settlementFinality member is a string", "block-depth", lambda e: e.__setitem__("settlementFinality", "final"))

    # Evidence and phase authority (FV-1).
    buyer_signed = changed("block-depth", lambda v: factory.resign_evidence(v["evidence"], key_name="buyer"))
    vectors.append(case("fv-evidence-signer-not-phase-orchestrator", "fail", "the evidence is validly signed by the buyer, not the authenticated phase orchestrator", buyer_signed))
    depth = factory.model_input("block-depth")
    vectors.append(case("fv-evidence-phase-differs-from-session", "fail", "the authenticated session runs pay-x402 at this phase; the rail and evidence say pay-evm-erc20", depth, trusted_overrides=session_override(depth, phaseKind="pay-x402")))
    vectors.append(case("fv-session-authority-unavailable", "indeterminate", "no authenticated session authority is configured", depth, trusted_overrides={"sessionAuthorityByJob": None}))
    vectors.append(case("fv-session-authority-malformed", "error", "the trusted session authority carries an unknown member", depth, trusted_overrides=session_override(depth, unexpected=True)))

    # Raw proof admission (FV-3, FV-5).
    def observation(name, expected, note, mutate, *, model="block-depth"):
        vectors.append(case(name, expected, note, changed(model, lambda v: mutate(v["context"]["observation"]))))

    observation("fv-event-proof-codec-unknown", "error", "an unregistered selected-event proof codec", lambda o: o["selectedEventProof"].__setitem__("kind", "fixture-event-merkle-v2"))
    observation("fv-event-proof-malformed", "error", "the selected-event proof lacks its sibling hash", lambda o: o["selectedEventProof"].pop("siblingHash"))
    observation("fv-event-proof-relation-malformed", "error", "the selected-event proof leaf index is outside 0/1", lambda o: o["selectedEventProof"].__setitem__("leafIndex", 2))
    observation("fv-event-bytes-duplicate-key", "error", "the raw event bytes carry a duplicate JSON key", lambda o: o["selectedEventProof"].__setitem__("eventBytes", b64u(b'{"amount":"5","amount":"5"}')))
    observation("fv-observation-member-missing", "error", "the chain observation lacks ancestryProof", lambda o: o.pop("ancestryProof"))
    observation("fv-inclusion-header-bytes-malformed", "error", "the inclusion header bytes are not JSON", lambda o: o["inclusionBlock"].__setitem__("header", "AAAA"))
    observation("fv-inclusion-header-body-malformed", "error", "the inclusion header body lacks its transactions root", lambda o: o["inclusionBlock"].__setitem__("header", b64u(canonical_bytes({key: item for key, item in decode(o["inclusionBlock"]["header"]).items() if key != "transactionsRoot"}))))
    observation("fv-inclusion-block-identity-substitution", "fail", "a substituted inclusion block id is neither the hash of its header nor the parent of the first ancestry link", lambda o: o["inclusionBlock"].__setitem__("id", "00" * 32))
    observation("fv-ancestry-not-array", "error", "ancestryProof is an object", lambda o: o.__setitem__("ancestryProof", {}))
    observation("fv-ancestry-link-malformed", "error", "an ancestry link lacks its header", lambda o: o["ancestryProof"][0].pop("header"))
    observation("fv-ancestry-link-position-noncanonical", "error", "an ancestry link position is not a minimal decimal", lambda o: o["ancestryProof"][0].__setitem__("position", "0101"))
    observation("fv-ancestry-header-bytes-malformed", "error", "an ancestry header is not JSON", lambda o: o["ancestryProof"][0].__setitem__("header", "AAAA"))
    observation("fv-ancestry-header-body-malformed", "error", "an ancestry header body lacks its transactions root", lambda o: o["ancestryProof"][0].__setitem__("header", b64u(canonical_bytes({key: item for key, item in decode(o["ancestryProof"][0]["header"]).items() if key != "transactionsRoot"}))))

    def rebuilt(name, expected, note, *, model="block-depth", reference=None, event_mutation=None, label, **options):
        value = factory.model_input(model)
        ref = copy.deepcopy(value["evidence"]["paymentTxRefs"][0])
        if reference is not None:
            reference(ref)
            value["evidence"]["paymentTxRefs"][0] = ref
            factory.resign_evidence(value["evidence"])
        event = factory.common_event(ref, session_of(value))
        if event_mutation is not None:
            event_mutation(event)
        settlement = value["rail"]["consumerFinalityProfile"]["settlement"]
        if model == "commitment-level":
            options.setdefault("commitment", "finalized")
        value["context"]["observation"] = factory.chain_observation(settlement, ref, event, label, **options)
        vectors.append(case(name, expected, note, value))

    def lock_shaped(event):
        event.update({
            "eventType": "htlc-lock",
            "contractAddress": "0x00000000000000000000000000000000000000a1",
            "hashAlgorithm": "keccak256",
            "hashlock": keccak256(b"fixture-htlc-preimage-392").hex(),
            "expiry": 1_899_997_200_000,
            "minedAt": 1_899_990_000_000,
        })

    rebuilt("fv-transaction-ref-wrong-profile-network", "fail", "the signed and observed EVM reference names chain 5; the signed profile settles on eip155:1", reference=lambda r: r.__setitem__("chainId", 5), label="wrong-profile-network")
    rebuilt("fv-raw-transaction-body-malformed", "error", "the proven raw transaction body lacks its status", label="raw-transaction-malformed", transaction_mutation=lambda t: t.pop("status"))
    rebuilt("fv-raw-transaction-not-successful", "fail", "the signed transaction is included, but its proven raw body has status reverted", label="raw-transaction-reverted", transaction_mutation=lambda t: t.__setitem__("status", "reverted"))
    rebuilt("fv-selected-event-member-malformed", "error", "the proven selected event's phaseIndex is a string", event_mutation=lambda e: e.__setitem__("phaseIndex", "0"), label="event-member-malformed")
    rebuilt("fv-single-chain-non-transfer-event", "fail", "the proven selected event is an HTLC lock, not a transfer", event_mutation=lock_shaped, label="non-transfer-event")
    rebuilt("fv-commitment-unknown", "error", "the authenticated head carries an unregistered commitment", model="commitment-level", label="unknown-commitment", commitment="rooted")

    # The authenticated head is a real header at the same height on another
    # fork; the canonical ancestry still ends at a different block.
    terminus = factory.model_input("block-depth")
    observed = terminus["context"]["observation"]
    encoded = observed["selectedEventProof"]["eventBytes"]
    sibling = factory.chain_observation(
        terminus["rail"]["consumerFinalityProfile"]["settlement"],
        terminus["evidence"]["paymentTxRefs"][0], decode(encoded), "terminus-sibling",
    )
    observed["authenticatedHead"] = sibling["authenticatedHead"]
    factory.sign_chain_authority(observed)
    vectors.append(case("fv-ancestry-terminus-not-authenticated-head", "fail", "the authorities sign a head the canonical ancestry does not reach", terminus))

    # Authenticated head authority (FV-6).
    def authority(name, expected, note, mutate):
        observation(name, expected, note, lambda o: mutate(o["authorityEvidence"]))

    authority("fv-head-authority-sources-differ", "fail", "the authority evidence names two of the profile's three RPC sources", lambda a: a.__setitem__("sourceRefs", ["rpc-a", "rpc-b"]))
    authority("fv-head-authority-codec-unknown", "error", "an unregistered head authority codec", lambda a: a.__setitem__("kind", "fixture-threshold-signature-v2"))
    authority("fv-head-authority-malformed", "error", "the head authority evidence lacks sourceRefs", lambda a: a.pop("sourceRefs"))
    authority("fv-head-authority-attestations-not-array", "error", "the head authority attestations are an object", lambda a: a.__setitem__("attestations", {}))
    authority("fv-head-authority-attestation-malformed", "error", "a head authority attestation lacks its algorithm", lambda a: a["attestations"][0].pop("algorithm"))

    # BFT finality (FV-7).
    def certificate(name, expected, note, mutate):
        observation(name, expected, note, lambda o: mutate(o["finalityCertificate"], o), model="bft-final")

    def certify_head(cert, observed):
        cert["blockId"] = observed["authenticatedHead"]["id"]
        for signature in cert["signatures"]:
            signature["value"] = factory.sign_digest(
                signature["validatorId"], BFT_CERTIFICATE_DOMAIN, cert["blockId"]
            )

    certificate("fv-bft-certificate-wrong-block", "fail", "a quorum genuinely certifies the head block, not the inclusion block", certify_head)
    certificate("fv-bft-certificate-codec-unknown", "error", "an unregistered BFT certificate codec", lambda c, o: c.__setitem__("kind", "fixture-bft-certificate-v2"))
    certificate("fv-bft-certificate-malformed", "error", "the BFT certificate lacks its validator-set hash", lambda c, o: c.pop("validatorSetHash"))
    certificate("fv-bft-signatures-not-array", "error", "the BFT signatures are an object", lambda c, o: c.__setitem__("signatures", {}))
    certificate("fv-bft-signature-malformed", "error", "a BFT signature lacks its algorithm", lambda c, o: c["signatures"][0].pop("algorithm"))
    bft = factory.model_input("bft-final")
    set_hash = bft["rail"]["consumerFinalityProfile"]["settlement"]["validatorSetRef"]["contentHash"]
    altered_set = copy.deepcopy(factory.trusted["validatorSets"][set_hash])
    altered_set["validators"][0]["weight"] = 41
    vectors.append(case("fv-bft-validator-set-unavailable", "indeterminate", "the pinned validator set is not configured", bft, trusted_overrides={"validatorSets": None}))
    vectors.append(case("fv-bft-validator-set-checkpoint-malformed", "error", "the configured validator set does not hash to the pinned checkpoint", bft, trusted_overrides={"validatorSets": {set_hash: altered_set}}))

    # ap2-sr3 native transaction authority (FV-4, FV-9, FV-10).
    def sr3(name, expected, note, mutate=None, *, trusted_overrides=None):
        value = factory.provider_sr3_value()
        if mutate is not None:
            mutate(value["context"]["receiptTransactionObservation"])
        vectors.append(case(name, expected, note, value, trusted_overrides=trusted_overrides))

    def sr3_rebuilt(name, expected, note, label, *, event_mutation=None, transaction_mutation=None):
        value = factory.provider_sr3_value()
        native = value["context"]["receiptTransactionObservation"]
        event = decode(native["selectedEventProof"]["eventBytes"])
        if event_mutation is not None:
            event_mutation(event)
        value["context"]["receiptTransactionObservation"] = factory.chain_observation(
            factory.trusted["sr3TransactionFinalityProfile"]["settlement"],
            native["transactionRef"], event, label,
            transaction_mutation=transaction_mutation,
        )
        vectors.append(case(name, expected, note, value))

    sr3("fv-ap2-sr3-network-differs", "fail", "the native transaction observation names demos:testnet", lambda o: o.__setitem__("networkId", "demos:testnet"))
    sr3_rebuilt("fv-ap2-sr3-raw-transaction-malformed", "error", "the proven native transaction body lacks its status", "ap2-sr3:raw-malformed", transaction_mutation=lambda t: t.pop("status"))
    sr3_rebuilt("fv-ap2-sr3-raw-transaction-not-successful", "fail", "the native web2Request transaction is included with status failed", "ap2-sr3:raw-failed", transaction_mutation=lambda t: t.__setitem__("status", "failed"))
    sr3_rebuilt("fv-ap2-sr3-web2-event-type-unknown", "error", "the proven native event is not a web2-request", "ap2-sr3:event-type", event_mutation=lambda e: e.__setitem__("eventType", "web2-response"))
    sr3_rebuilt("fv-ap2-sr3-web2-event-member-malformed", "error", "the proven web2-request event's response status is zero", "ap2-sr3:event-member", event_mutation=lambda e: e.__setitem__("responseStatus", 0))
    sr3("fv-ap2-sr3-ancestry-incomplete", "fail", "the native ancestry omits its last link", lambda o: o["ancestryProof"].pop())
    sr3("fv-ap2-sr3-ancestry-link-substitution", "fail", "a middle native ancestry link names another parent", lambda o: o["ancestryProof"][5].__setitem__("parentId", "00" * 32))
    sr3("fv-ap2-sr3-ancestry-not-array", "error", "the native ancestryProof is an object", lambda o: o.__setitem__("ancestryProof", {}))
    sr3("fv-ap2-sr3-ancestry-link-malformed", "error", "a native ancestry link lacks its header", lambda o: o["ancestryProof"][0].pop("header"))
    sr3("fv-ap2-sr3-head-authority-signature-invalid", "fail", "a native head authority signature does not verify", lambda o: o["authorityEvidence"]["attestations"][0].__setitem__("value", "A" * 86))
    sr3("fv-ap2-sr3-event-proof-codec-unknown", "error", "an unregistered native event proof codec", lambda o: o["selectedEventProof"].__setitem__("kind", "fixture-event-merkle-v2"))
    sr3("fv-ap2-sr3-transaction-proof-malformed", "error", "the native transaction proof lacks its sibling hash", lambda o: o["transactionInclusionProof"].pop("siblingHash"))
    sr3("fv-ap2-sr3-inclusion-block-malformed", "error", "the native inclusion block id is not a SHA-256 value", lambda o: o["inclusionBlock"].__setitem__("id", "not-a-hash"))
    sr3("fv-ap2-sr3-header-bytes-malformed", "error", "the native inclusion header bytes are not JSON", lambda o: o["inclusionBlock"].__setitem__("header", "AAAA"))
    sr3("fv-ap2-sr3-header-body-malformed", "error", "the native inclusion header body lacks its transactions root", lambda o: o["inclusionBlock"].__setitem__("header", b64u(canonical_bytes({key: item for key, item in decode(o["inclusionBlock"]["header"]).items() if key != "transactionsRoot"}))))
    sr3("fv-ap2-sr3-ancestry-position-noncanonical", "error", "a native ancestry link position is not a minimal decimal", lambda o: o["ancestryProof"][0].__setitem__("position", "0101"))
    sr3("fv-ap2-sr3-ancestry-header-bytes-malformed", "error", "a native ancestry header is not JSON", lambda o: o["ancestryProof"][0].__setitem__("header", "AAAA"))
    sr3("fv-ap2-sr3-ancestry-header-body-malformed", "error", "a native ancestry header body lacks its transactions root", lambda o: o["ancestryProof"][0].__setitem__("header", b64u(canonical_bytes({key: item for key, item in decode(o["ancestryProof"][0]["header"]).items() if key != "transactionsRoot"}))))

    def sr3_sibling_head(native):
        sibling = factory.chain_observation(
            factory.trusted["sr3TransactionFinalityProfile"]["settlement"],
            native["transactionRef"], decode(native["selectedEventProof"]["eventBytes"]),
            "ap2-sr3:terminus-sibling",
        )
        native["authenticatedHead"] = sibling["authenticatedHead"]
        factory.sign_chain_authority(native)

    sr3("fv-ap2-sr3-ancestry-terminus-not-authenticated-head", "fail", "the authorities sign a native head the ancestry does not reach", sr3_sibling_head)
    sr3("fv-ap2-sr3-verifier-clock-malformed", "error", "the verifier-local clock is missing for the native observation", trusted_overrides={"verificationTimeMs": None})
    sr3("fv-ap2-sr3-head-observation-future", "fail", "the native head observation is after the verifier-local clock", trusted_overrides={"verificationTimeMs": OBSERVED_AT - 1})
    sr3("fv-ap2-sr3-head-observation-stale", "indeterminate", "the native head observation is older than its profile allows", trusted_overrides={"verificationTimeMs": OBSERVED_AT + 61_000})

    # Provider capture (FV-4, FV-9): the attestation is independently trusted.
    provider = factory.model_input("provider-receipt")
    response_hash = provider["context"]["responseAttestation"]["contentHash"]
    attestation = factory.trusted["providerAttestations"][response_hash]
    wrong_key = factory.sign_digest(
        "steward", PROVIDER_ATTESTATION_DOMAIN, artifact_hash(attestation, "signature")
    )
    other_reference = copy.deepcopy(attestation)
    other_reference["providerRef"] = "provider-charge-other"
    other_reference["signature"]["value"] = factory.sign_digest(
        "provider", PROVIDER_ATTESTATION_DOMAIN, artifact_hash(other_reference, "signature")
    )
    vectors.extend([
        case("fv-provider-attestation-signature-invalid", "fail", "the trusted response attestation's signature is made by another key", provider, trusted_overrides={"providerAttestations": {response_hash: {"signature": {"value": wrong_key}}}}),
        case("fv-provider-attestation-reference-mismatch", "fail", "the provider genuinely attests this response for another provider reference", provider, trusted_overrides={"providerAttestations": {response_hash: other_reference}}),
        case("fv-provider-attestation-malformed", "error", "the trusted response attestation has an unknown version", provider, trusted_overrides={"providerAttestations": {response_hash: {"responseAttestationVersion": "2"}}}),
        case("fv-provider-attestation-signature-malformed", "error", "the trusted response attestation signature names an unsupported algorithm", provider, trusted_overrides={"providerAttestations": {response_hash: {"signature": {"algorithm": "rsa"}}}}),
        case("fv-provider-attestation-map-malformed", "error", "the trusted provider attestation map is a list", provider, trusted_overrides={"providerAttestations": []}),
        case("fv-provider-verifier-clock-malformed", "error", "the verifier-local clock is missing for provider freshness", provider, trusted_overrides={"verificationTimeMs": None}),
    ])
    economics = factory.model_input("provider-receipt")
    ref = economics["evidence"]["paymentTxRefs"][0]
    session = session_of(economics)
    body = {
        "providerRef": ref["providerRef"], "endpointOrigin": "https://payments.example",
        "jobId": session["jobId"], "phaseIndex": session["phaseIndex"], "status": "captured",
        "amount": "6", "currency": session["asset"], "payer": session["payer"], "payee": session["payee"],
    }
    raw = canonical_bytes(body)
    body_hash = hashlib.sha256(raw).hexdigest()
    attested = copy.deepcopy(attestation)
    attested["responseHash"] = body_hash
    attested["signature"]["value"] = factory.sign_digest(
        "provider", PROVIDER_ATTESTATION_DOMAIN, artifact_hash(attested, "signature")
    )
    economics["context"]["responseBytes"] = b64u(raw)
    economics["context"]["responseAttestation"] = factory.reference("provider:" + body_hash, body_hash)
    ref["receiptAttestation"] = copy.deepcopy(economics["context"]["responseAttestation"])
    factory.resign_evidence(economics["evidence"])
    vectors.append(case("fv-provider-response-economics-mismatch", "fail", "the provider genuinely attests a captured response for amount 6; the agreement settles 5", economics, trusted_overrides={"providerAttestations": {body_hash: attested}}))
    vectors.extend([
        case("fv-provider-context-malformed", "error", "the provider context lacks its providerRef", changed("provider-receipt", lambda v: v["context"].pop("providerRef"))),
        case("fv-provider-evidence-two-references", "error", "the signed provider evidence carries two AP2 references", changed("provider-receipt", lambda v: (v["evidence"]["paymentTxRefs"].append(copy.deepcopy(v["evidence"]["paymentTxRefs"][0])), factory.resign_evidence(v["evidence"])))),
        case("fv-provider-reference-not-ap2", "error", "the signed provider evidence carries an EVM event reference", changed("provider-receipt", lambda v: (v["evidence"].__setitem__("paymentTxRefs", [factory.transaction_ref("block-depth", "provider-as-evm")]), factory.resign_evidence(v["evidence"])))),
        case("fv-provider-reference-x402-not-ap2", "error", "the signed provider evidence carries a well-formed x402 event reference (X402-1 version 1); the AP2 reference-kind check rejects it, and the AP2 protocolVersion check would too", changed("provider-receipt", lambda v: (v["evidence"].__setitem__("paymentTxRefs", [{
            "kind": "x402-event", "httpResource": "https://payments.example/x402", "paymentReceiptHash": "ab" * 32,
            "settlementTxHash": factory.tx_id("provider-as-x402"), "chainId": 1, "logIndex": 0, "protocolVersion": "1",
        }]), factory.resign_evidence(v["evidence"])))),
    ])

    # Composite models (FV-9).
    def htlc_rebuilt(name, expected, note, arm, mutate):
        value = factory.model_input("htlc-reveal")
        factory.rebuild_observation_event(value, (arm,), mutate)
        vectors.append(case(name, expected, note, value))

    def as_lock(event):
        event["eventType"] = "htlc-lock"
        event.pop("preimage")
        event.update({"expiry": 1_899_997_200_000, "minedAt": 1_899_990_000_000})

    htlc_rebuilt("fv-htlc-arm-wrong-event-type", "fail", "the source-claim arm proves a lock-shaped event", "sourceClaim", as_lock)
    htlc_rebuilt("fv-htlc-preimage-encoding-malformed", "error", "the proven source-claim preimage is not Base64URL", "sourceClaim", lambda e: e.__setitem__("preimage", "not base64url!"))
    htlc_rebuilt("fv-htlc-hashlock-not-recomputed", "fail", "the proven source lock commits a hashlock that the revealed preimage does not produce", "sourceLock", lambda e: e.__setitem__("hashlock", "00" * 32))
    rail("fv-htlc-hash-algorithm-unsupported", "error", "the signed HTLC rail selects md5 for the source chain", "htlc-reveal", lambda r: r["parameters"].__setitem__("sourceHashAlgorithm", "md5"))
    rail("fv-htlc-timing-parameters-malformed", "error", "the signed HTLC source timelock is a string", "htlc-reveal", lambda r: r["parameters"].__setitem__("timelockSourceSec", "7200"))
    rail("fv-tank-parameters-malformed", "error", "the signed tank parameters lack the transferId", "liquidity-tank", lambda r: r["parameters"].pop("transferId"))
    vectors.extend([
        case("fv-htlc-context-arm-missing", "error", "the HTLC context lacks its source-claim member", changed("htlc-reveal", lambda v: v["context"].pop("sourceClaim"))),
        case("fv-htlc-duplicate-reference", "error", "the signed HTLC evidence carries the source-lock reference twice", changed("htlc-reveal", lambda v: (v["evidence"]["paymentTxRefs"].append(copy.deepcopy(v["evidence"]["paymentTxRefs"][0])), factory.resign_evidence(v["evidence"])))),
        case("fv-tank-context-arm-missing", "error", "the tank context lacks its destination member", changed("liquidity-tank", lambda v: v["context"].pop("destination"))),
        case("fv-tank-two-composite-references", "error", "the signed tank evidence carries two composite references", changed("liquidity-tank", lambda v: (v["evidence"]["paymentTxRefs"].append(copy.deepcopy(v["evidence"]["paymentTxRefs"][0])), factory.resign_evidence(v["evidence"])))),
    ])

    # Entry point and settlement economics (FV entry, FV-5).
    vectors.extend([
        case("fv-consumer-input-extra-member", "error", "the FV consumer input carries a fifth member", changed("block-depth", lambda v: v.__setitem__("hint", "trust-me"))),
        case("fv-evidence-amount-differs-from-agreement", "fail", "the signed evidence pays 6 while the agreement and the proven event settle 5", changed("block-depth", lambda v: (v["evidence"]["paymentAmount"].__setitem__("amount", "6"), factory.resign_evidence(v["evidence"])))),
        case("fv-single-chain-two-references", "error", "single-chain evidence carries two signed references", changed("block-depth", lambda v: (v["evidence"]["paymentTxRefs"].append(dict(v["evidence"]["paymentTxRefs"][0], logIndex=1)), factory.resign_evidence(v["evidence"])))),
    ])
    return vectors


B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def nonminimal_b64u(value: str) -> str:
    """Respell a 64-byte Base64URL value with a non-zero residual bit.

    86 characters carry 516 bits, so the last character's low four bits are
    unused; a lenient decoder returns the same 64 bytes for both spellings.
    """
    index = B64URL_ALPHABET.index(value[-1])
    if len(value) != 86 or index & 0b1111:
        raise ValueError("expected a canonical 64-byte Base64URL value")
    return value[:-1] + B64URL_ALPHABET[index | 1]


def short_b64u(value: str) -> str:
    """Drop the last byte of a genuine 64-byte signature and re-encode it.

    The result is canonical Base64URL (it passes the SIG-6 wire stage) but
    decodes to 63 bytes, so it fails the Ed25519 algorithm stage (SIG-7
    ``fail``) without any key.
    """
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != 64 or b64u(raw) != value:
        raise ValueError("expected a canonical 64-byte Base64URL value")
    return b64u(raw[:-1])


def build_guard_isolation_vectors(factory: FixtureFactory) -> list[dict]:
    """Cases that isolate an FV guard another guard used to decide.

    Each case changes only bytes no signature covers, verifier-owned trust
    input, or the one artifact it re-signs, so a verifier that omits only
    the named guard returns ``pass``.
    """
    vectors = []
    sr3_settlement = factory.trusted["sr3TransactionFinalityProfile"]["settlement"]

    def decode(encoded):
        return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))

    def changed(model, mutation):
        value = factory.model_input(model)
        mutation(value)
        return value

    def changed_sr3(mutation):
        value = factory.provider_sr3_value()
        mutation(value)
        return value

    def native(value):
        return value["context"]["receiptTransactionObservation"]

    # FV-5 Merkle recomputation: the claimed root still equals the genuine
    # header transactionsRoot (or transaction eventsRoot); only the sibling
    # the leaf hashes with changes.
    def other_sibling(proof):
        proof["siblingHash"] = "11" * 32

    vectors.extend([
        case("fv-transaction-proof-root-not-recomputed", "fail", "the transaction proof keeps the header's transactionsRoot, but its leaf and sibling hash to another root", changed("block-depth", lambda v: other_sibling(v["context"]["observation"]["transactionInclusionProof"]))),
        case("fv-event-proof-root-not-recomputed", "fail", "the event proof keeps the transaction's eventsRoot, but its leaf and sibling hash to another root", changed("block-depth", lambda v: other_sibling(v["context"]["observation"]["selectedEventProof"]))),
        case("fv-ap2-sr3-transaction-proof-root-not-recomputed", "fail", "the native transaction proof keeps the header's transactionsRoot, but its leaf and sibling hash to another root", changed_sr3(lambda v: other_sibling(native(v)["transactionInclusionProof"]))),
        case("fv-ap2-sr3-event-proof-root-not-recomputed", "fail", "the native event proof keeps the transaction's eventsRoot, but its leaf and sibling hash to another root", changed_sr3(lambda v: other_sibling(native(v)["selectedEventProof"]))),
    ])

    # FV-5/FV-6 inclusion-header identity: the genuine inclusion id, parent
    # and position stay (the ancestry and authority attestations cover them);
    # the header bytes commit to another transaction tree whose proof verifies.
    def forge_inclusion_header(observation):
        proof = observation["transactionInclusionProof"]
        proof["siblingHash"] = "22" * 32
        proof["root"] = hashlib.sha256(
            b"\x01" + bytes.fromhex(proof["leafHash"]) + bytes.fromhex(proof["siblingHash"])
        ).hexdigest()
        header = decode(observation["inclusionBlock"]["header"])
        header["transactionsRoot"] = proof["root"]
        observation["inclusionBlock"]["header"] = b64u(canonical_bytes(header))

    vectors.extend([
        case("fv-inclusion-header-bytes-substitution", "fail", "the inclusion header bytes commit to another transaction tree; the genuine id, parent and ancestry remain", changed("block-depth", lambda v: forge_inclusion_header(v["context"]["observation"]))),
        case("fv-ap2-sr3-inclusion-header-bytes-substitution", "fail", "the native inclusion header bytes commit to another transaction tree; the genuine id, parent and ancestry remain", changed_sr3(lambda v: forge_inclusion_header(native(v)))),
    ])

    # FV-8 via FV-9: SR-3 native head freshness, separate from provider freshness.
    def native_head_at(observed_at, label):
        def mutate(value):
            observation = native(value)
            value["context"]["receiptTransactionObservation"] = factory.chain_observation(
                sr3_settlement, observation["transactionRef"],
                decode(observation["selectedEventProof"]["eventBytes"]), label,
                observed_at=observed_at,
            )
        return mutate

    vectors.extend([
        case("fv-ap2-sr3-native-head-stale-provider-fresh", "indeterminate", "the verifier-owned SR-3 profile allows a 30 s native head; at 45 s the head is stale while the 60 s provider attestation is fresh", factory.provider_sr3_value(), trusted_overrides={"sr3TransactionFinalityProfile": {"settlement": {"observation": {"maxHeadAgeSec": 30}}}, "verificationTimeMs": OBSERVED_AT + 45_000}),
        case("fv-ap2-sr3-native-head-future-provider-current", "fail", "the authenticated native head is observed after the verifier-local clock; the provider attestation is not", changed_sr3(native_head_at(VERIFICATION_TIME + 1_000, "ap2-sr3:future-head"))),
    ])

    # CORE SIG-6/SIG-7: a non-minimal Base64URL spelling of a genuine
    # signature fails the wire stage, malformed encoding (error) before any
    # key, on every independently parsed envelope.
    def respell(container, key="value"):
        container[key] = nonminimal_b64u(container[key])

    provider = factory.model_input("provider-receipt")
    response_hash = provider["context"]["responseAttestation"]["contentHash"]
    provider_signature = factory.trusted["providerAttestations"][response_hash]["signature"]["value"]
    vectors.extend([
        case("fv-evidence-signature-nonminimal-base64url", "error", "the evidence signature decodes to the genuine bytes but is not the minimal Base64URL spelling, so it fails the SIG-6 wire stage", changed("block-depth", lambda v: respell(v["evidence"]["signature"]))),
        case("fv-rail-signature-nonminimal-base64url", "error", "the rail steward signature decodes to the genuine bytes but is not the minimal Base64URL spelling, so it fails the SIG-6 wire stage", changed("block-depth", lambda v: respell(v["rail"]["signature"]))),
        case("fv-agreement-signature-nonminimal-base64url", "error", "the buyer's agreement signature decodes to the genuine bytes but is not the minimal Base64URL spelling, so it fails the SIG-6 wire stage", changed("block-depth", lambda v: respell(v["agreement"]["signatures"][0]))),
        case("fv-head-authority-signature-nonminimal-base64url", "error", "a head authority signature decodes to the genuine bytes but is not the minimal Base64URL spelling, so it fails the SIG-6 wire stage", changed("block-depth", lambda v: respell(v["context"]["observation"]["authorityEvidence"]["attestations"][0]))),
        case("fv-bft-signature-nonminimal-base64url", "error", "a BFT certificate signature decodes to the genuine bytes but is not the minimal Base64URL spelling, so it fails the SIG-6 wire stage", changed("bft-final", lambda v: respell(v["context"]["observation"]["finalityCertificate"]["signatures"][0]))),
        case("fv-provider-attestation-signature-nonminimal-base64url", "error", "the trusted provider attestation signature decodes to the genuine bytes but is not the minimal Base64URL spelling, so it fails the SIG-6 wire stage", provider, trusted_overrides={"providerAttestations": {response_hash: {"signature": {"value": nonminimal_b64u(provider_signature)}}}}),
    ])

    # FV-2: unknown or malformed echo values are error, not a mismatch.
    def report(name, note, model, member, item):
        def mutate(value):
            value["evidence"]["settlementFinality"][member] = item
            factory.resign_evidence(value["evidence"])
        vectors.append(case(name, "error", note, changed(model, mutate)))

    report("fv-producer-report-model-unknown", "the signed producer report names an unregistered model", "block-depth", "model", "probabilistic")
    report("fv-producer-report-depth-not-integer", "the signed producer report depth is a string", "block-depth", "finalityBlocks", "12")
    report("fv-producer-report-depth-negative", "the signed producer report depth is negative", "block-depth", "finalityBlocks", -1)
    report("fv-producer-report-commitment-unknown", "the signed producer report names an unregistered commitment", "commitment-level", "finalityCommitmentLevel", "rooted")

    # FV entry: missing trusted authority is indeterminate; malformed is error.
    depth = factory.model_input("block-depth")
    vectors.extend([
        case("fv-trusted-party-keys-unavailable", "indeterminate", "no trusted party key map is configured", depth, trusted_overrides={"partyKeys": None}),
        case("fv-trusted-steward-keys-unavailable", "indeterminate", "no trusted steward key map is configured", depth, trusted_overrides={"stewardKeys": None}),
        case("fv-trusted-observation-authority-keys-unavailable", "indeterminate", "no trusted observation authority key map is configured", depth, trusted_overrides={"observationAuthorityKeys": None}),
        case("fv-trusted-provider-authority-keys-unavailable", "indeterminate", "no trusted provider authority key map is configured", factory.model_input("provider-receipt"), trusted_overrides={"providerAuthorityKeys": None}),
        case("fv-trusted-party-keys-malformed", "error", "the trusted party key map is a list", depth, trusted_overrides={"partyKeys": []}),
        case("fv-trusted-party-key-value-malformed", "error", "a trusted party key is not a 32-byte Base64URL value", depth, trusted_overrides={"partyKeys": {CLAIMS["orchestrator"]: "not-a-key"}}),
        case("fv-trusted-steward-key-value-malformed", "error", "the trusted steward key is not a 32-byte Base64URL value", depth, trusted_overrides={"stewardKeys": {CLAIMS["steward"]: "not-a-key"}}),
        case("fv-trusted-observation-authority-key-value-malformed", "error", "a trusted observation authority key is not a 32-byte Base64URL value", depth, trusted_overrides={"observationAuthorityKeys": {"rpc-a": "not-a-key"}}),
        case("fv-trusted-provider-authority-key-value-malformed", "error", "the trusted provider authority key is not a 32-byte Base64URL value", factory.model_input("provider-receipt"), trusted_overrides={"providerAuthorityKeys": {CLAIMS["provider"]: "not-a-key"}}),
        case("fv-trusted-validator-set-map-malformed", "error", "the trusted validator-set map is a list", factory.model_input("bft-final"), trusted_overrides={"validatorSets": []}),
    ])

    # FV entry: a present map that lacks the key of a signer trusted authority
    # names is missing authority (indeterminate), not a bad signature.
    def unconfigured_orchestrator(value):
        factory.resign_evidence(value["evidence"], key_name="orchestrator-unconfigured")

    unconfigured_session = changed("block-depth", unconfigured_orchestrator)
    unconfigured_authority = {"sessionAuthorityByJob": {unconfigured_session["evidence"]["jobId"]: {"phaseOrchestrator": CLAIMS["orchestrator-unconfigured"]}}}
    vectors.append(case(
        "fv-trusted-party-key-for-orchestrator-absent", "indeterminate",
        "the authenticated phase orchestrator genuinely signs the evidence, but the trusted party key map holds no key for it",
        unconfigured_session, trusted_overrides=unconfigured_authority,
    ))

    # Exercise the Agreement-stage deferral independently of the orchestrator.
    # Each new party really signs; only its verifier-owned key is unavailable.
    for party, other in (("buyer", "seller"), ("seller", "buyer")):
        value = factory.model_input("block-depth")
        claim = CLAIMS[party + "-unconfigured"]
        agreement = value["agreement"]
        for entry in agreement["parties"]:
            if entry["role"] == party:
                entry["primaryClaim"] = claim
        factory.resign_agreement(agreement, signers=tuple(
            role + "-unconfigured" if role == party else role
            for role in ("buyer", "seller")
        ))
        session = copy.deepcopy(factory.trusted["sessionAuthorityByJob"][agreement["jobId"]])
        session["partyClaims"][party] = claim
        session["payer" if party == "buyer" else "payee"] = claim
        session["agreementHash"] = artifact_hash(agreement, "signatures")
        factory.rebuild_observation_event(value, ("observation",), lambda event:
            event.__setitem__("payer" if party == "buyer" else "payee", claim))
        authority = {"sessionAuthorityByJob": {agreement["jobId"]: session}}
        name = "fv-trusted-party-key-for-" + party + "-absent"
        vectors.append(case(name, "indeterminate", "the authenticated session party genuinely signs, but its key is absent from the usable party map", value, trusted_overrides=authority))
        invalid = copy.deepcopy(value)
        signatures = invalid["agreement"]["signatures"]
        signatures[0 if other == "buyer" else 1]["value"] = signatures[0 if party == "buyer" else 1]["value"]
        vectors.append(case(name + "-" + other + "-signature-invalid", "fail", "a missing party key cannot hide the other party's invalid Agreement signature", invalid, trusted_overrides=authority))

    # FV-10: an absent key in one stage is deferred, so a later signature
    # checked against an available key still decides the verdict. Both
    # signatures are outside the hashes they sign, so nothing else changes.
    def unconfigured_and(mutation):
        value = copy.deepcopy(unconfigured_session)
        mutation(value)
        return value

    def buyer_signs_with_seller_value(value):
        signatures = value["agreement"]["signatures"]
        signatures[0]["value"] = signatures[1]["value"]

    vectors.extend([
        case(
            "fv-trusted-party-key-for-orchestrator-absent-agreement-signature-invalid", "fail",
            "the trusted party key map holds no key for the phase orchestrator, and the buyer's agreement signature, checked against the buyer's available key, does not verify",
            unconfigured_and(buyer_signs_with_seller_value), trusted_overrides=unconfigured_authority,
        ),
        case(
            "fv-trusted-party-key-for-orchestrator-absent-rail-signature-invalid", "fail",
            "the trusted party key map holds no key for the phase orchestrator, and the rail signature, checked against the steward's available key, does not verify",
            unconfigured_and(lambda v: v["rail"]["signature"].__setitem__("value", v["agreement"]["signatures"][1]["value"])),
            trusted_overrides=unconfigured_authority,
        ),
    ])

    def pin_authorities(value, pinned, signers):
        value["rail"]["consumerFinalityProfile"]["settlement"]["observation"]["authorityRefs"] = list(pinned)
        factory.rebind_rail(value)
        observation = value["context"]["observation"]
        factory.sign_chain_authority(observation, signers=signers)
        observation["authorityEvidence"]["sourceRefs"] = list(pinned)

    vectors.append(case(
        "fv-trusted-observation-authority-key-absent", "indeterminate",
        "the signed profile pins rpc-d and rpc-d genuinely attests the head, but the trusted observation authority key map holds no key for it; the quorum is incomplete",
        changed("block-depth", lambda v: pin_authorities(v, ("rpc-a", "rpc-b", "rpc-d"), ("rpc-a", "rpc-d"))),
    ))

    def keyless_noncanonical(value):
        pin_authorities(value, ("rpc-a", "rpc-b", "rpc-d"), ("rpc-a", "rpc-b", "rpc-d"))
        attestations = value["context"]["observation"]["authorityEvidence"]["attestations"]
        assert attestations[2]["authorityRef"] == "rpc-d"
        attestations[2]["value"] = "==not base64url=="

    # CORE §B.7 SIG-7: a signature skipped for lack of a key still gets the
    # key-free checks, so the verdict does not depend on the key.
    vectors.append(case(
        "fv-trusted-observation-authority-key-absent-attestation-noncanonical", "error",
        "rpc-a and rpc-b meet the threshold with available keys, and pinned rpc-d, whose key the verifier lacks, presents a value that is not canonical Base64URL",
        changed("block-depth", keyless_noncanonical),
    ))

    def keyless_wrong_length(value):
        pin_authorities(value, ("rpc-a", "rpc-b", "rpc-d"), ("rpc-a", "rpc-b", "rpc-d"))
        attestations = value["context"]["observation"]["authorityEvidence"]["attestations"]
        assert attestations[2]["authorityRef"] == "rpc-d"
        attestations[2]["value"] = short_b64u(attestations[2]["value"])

    vectors.append(case(
        "fv-trusted-observation-authority-key-absent-attestation-wrong-length", "fail",
        "rpc-a and rpc-b meet the threshold with available keys, and pinned rpc-d, whose key the verifier lacks, presents canonical Base64URL that decodes to 63 bytes, which no Ed25519 key verifies",
        changed("block-depth", keyless_wrong_length),
    ))

    def unconfigured_provider(value):
        value["rail"]["consumerFinalityProfile"]["providerId"] = CLAIMS["provider-unconfigured"]
        value["rail"]["asset"]["provider"] = CLAIMS["provider-unconfigured"]
        factory.rebind_rail(value)
        value["context"]["providerId"] = CLAIMS["provider-unconfigured"]

    unconfigured = changed("provider-receipt", unconfigured_provider)
    unconfigured_hash = unconfigured["context"]["responseAttestation"]["contentHash"]
    unconfigured_attestation = copy.deepcopy(factory.trusted["providerAttestations"][unconfigured_hash])
    unconfigured_attestation["providerId"] = CLAIMS["provider-unconfigured"]
    unconfigured_attestation["signature"] = {"signer": CLAIMS["provider-unconfigured"], "algorithm": "ed25519", "value": ""}
    unconfigured_attestation["signature"]["value"] = factory.sign_digest(
        "provider-unconfigured", PROVIDER_ATTESTATION_DOMAIN, artifact_hash(unconfigured_attestation, "signature")
    )
    vectors.append(case(
        "fv-trusted-provider-key-absent", "indeterminate",
        "the signed profile names a provider that genuinely signs the response attestation, but the trusted provider key map holds no key for it",
        unconfigured, trusted_overrides={"providerAttestations": {unconfigured_hash: unconfigured_attestation}},
    ))

    # FV-6: only authorities the signed profile pins count toward the
    # threshold, even when the verifier trusts another authority's key.
    vectors.append(case(
        "fv-head-authority-outside-profile", "fail",
        "rpc-other genuinely attests the head and the verifier holds its key, but the signed profile pins only rpc-a, rpc-b and rpc-c",
        changed("block-depth", lambda v: (
            factory.sign_chain_authority(v["context"]["observation"], signers=("rpc-a", "rpc-other")),
            v["context"]["observation"]["authorityEvidence"].__setitem__("sourceRefs", ["rpc-a", "rpc-b", "rpc-c"]),
        )),
        trusted_overrides={"observationAuthorityKeys": {"rpc-other": b64u(factory.keys["rpc-other"].public_key().public_bytes_raw())}},
    ))

    def pinned_validator_set(name, note, validator_set):
        value = factory.model_input("bft-final")
        set_hash = hash_value(validator_set)
        value["rail"]["consumerFinalityProfile"]["settlement"]["validatorSetRef"] = factory.reference("validator-set:" + name, set_hash)
        factory.rebind_rail(value)
        value["context"]["observation"]["finalityCertificate"]["validatorSetHash"] = set_hash
        vectors.append(case(name, "error", note, value, trusted_overrides={"validatorSets": {set_hash: validator_set}}))

    genuine_set = copy.deepcopy(factory.trusted["validatorSets"][factory.validator_set_hash])
    pinned_validator_set("fv-bft-validator-set-empty", "the steward-pinned trusted validator set has no members", {"validators": []})
    malformed_member = copy.deepcopy(genuine_set)
    malformed_member["validators"][2]["publicKey"] = "not-a-key"
    pinned_validator_set("fv-bft-validator-set-member-malformed", "a non-signing member of the steward-pinned validator set has a malformed key", malformed_member)

    # AP2-2: the ap2-sr3 receiptAttestation names the fetched HTTPS resource.
    def storage_locator(value):
        ref = value["evidence"]["paymentTxRefs"][0]
        locator = factory.reference("ap2-sr3:status", ref["receiptAttestation"]["contentHash"])
        ref["receiptAttestation"] = copy.deepcopy(locator)
        value["context"]["responseAttestation"] = copy.deepcopy(locator)
        observation = native(value)
        event = decode(observation["selectedEventProof"]["eventBytes"])
        event["requestUrl"] = locator["anchor"]["locator"]
        value["context"]["receiptTransactionObservation"] = factory.chain_observation(
            sr3_settlement, observation["transactionRef"], event, "ap2-sr3:storage-locator"
        )
        factory.resign_evidence(value["evidence"])

    vectors.append(case("fv-ap2-sr3-receipt-attestation-locator-not-https", "error", "the signed ap2-sr3 receiptAttestation anchor is a storage-program locator, which the native request also names", changed_sr3(storage_locator)))

    # FV-1 profile shape (DACS-4 §9.4.3): kind equals model; closed method set.
    def rail(name, note, model, mutate):
        value = factory.model_input(model)
        mutate(value["rail"])
        factory.rebind_rail(value)
        vectors.append(case(name, "error", note, value))

    rail("fv-profile-settlement-kind-differs-from-model", "a steward-signed bft-final profile whose settlement kind is block-depth", "bft-final", lambda r: r["consumerFinalityProfile"].__setitem__("settlement", factory.chain_profile("block-depth", network="demos:mainnet")))
    rail("fv-profile-observation-method-unknown", "a steward-signed profile names an unregistered observation method", "block-depth", lambda r: r["consumerFinalityProfile"]["settlement"]["observation"].__setitem__("method", "magic"))

    # HTLC-6 / §9.14: keccak256 is Ethereum's Keccak-256, not FIPS SHA3-256,
    # and FIPS SHA3-256 is not a registered identifier.
    preimage = b"fixture-htlc-preimage-392"
    sha3_hashlock = hashlib.sha3_256(preimage).hexdigest()

    def destination_commits_sha3(value, algorithm, arms=("destinationLock", "destinationReveal")):
        for arm in arms:
            factory.rebuild_observation_event(value, (arm,), lambda event: event.update({"hashAlgorithm": algorithm, "hashlock": sha3_hashlock}))

    keccak_as_sha3 = factory.model_input("htlc-reveal")
    destination_commits_sha3(keccak_as_sha3, "keccak256", ("sourceLock", "sourceClaim", "destinationLock", "destinationReveal"))
    vectors.append(case("fv-htlc-keccak256-hashlock-is-sha3-256", "fail", "every keccak256 lock, claim and reveal commits the FIPS SHA3-256 digest of the preimage", keccak_as_sha3))
    sha3_rail = factory.model_input("htlc-reveal")
    sha3_rail["rail"]["parameters"]["destinationHashAlgorithm"] = "sha3-256"
    factory.rebind_rail(sha3_rail)
    destination_commits_sha3(sha3_rail, "sha3-256")
    vectors.append(case("fv-htlc-hash-algorithm-sha3-256-unregistered", "error", "the signed HTLC rail selects FIPS SHA3-256, which is not a registered hash identifier; the destination events commit it consistently", sha3_rail))
    # HTLC-6: each identifier must be native to its leg chain. EVM computes
    # sha256 natively (precompile 0x02) as well as keccak256, so legs may
    # differ or share sha256.
    def sha256_legs(arms):
        value = factory.model_input("htlc-reveal")
        for field in {"source": ("sourceHashAlgorithm",), "both": ("sourceHashAlgorithm", "destinationHashAlgorithm")}[arms]:
            value["rail"]["parameters"][field] = "sha256"
        factory.rebind_rail(value)
        names = ("sourceLock", "sourceClaim") + (("destinationLock", "destinationReveal") if arms == "both" else ())
        for arm in names:
            factory.rebuild_observation_event(value, (arm,), lambda event: event.update({"hashAlgorithm": "sha256", "hashlock": hashlib.sha256(preimage).hexdigest()}))
        return value

    vectors.append(case("fv-htlc-evm-leg-sha256-hashlock", "pass", "the signed HTLC rail selects sha256 for its eip155:1 source leg and keccak256 for its eip155:8453 destination leg; every event commits its leg's recomputed hashlock", sha256_legs("source")))
    vectors.append(case("fv-htlc-evm-legs-share-sha256-hashlock", "pass", "both EVM legs select sha256, which EVM computes natively; legs MAY share one hash function", sha256_legs("both")))
    # A leg chain the HTLC-6 table lists no native hash for is error, even
    # when its chain reference equals an EVM chainId.
    rail("fv-htlc-leg-chain-without-native-hash", "the signed HTLC rail's destination leg is on cosmos:8453, which the HTLC-6 row lists no native hash for; the evidence names EVM chainId 8453", "htlc-reveal", lambda r: r["consumerFinalityProfile"]["destination"].update({"networkId": "cosmos:8453", "genesisHash": hashlib.sha256(b"genesis:cosmos:8453").hexdigest()}))
    rail("fv-htlc-hash-algorithm-parameter-missing", "the signed HTLC rail omits sourceHashAlgorithm, which the §9.14 row requires", "htlc-reveal", lambda r: r["parameters"].pop("sourceHashAlgorithm"))

    # FV-10: a missing validator-set checkpoint defers only after every check
    # the presented certificate supports alone, on each BFT path.
    def certificate_without_set(name, expected, note, value, path, mutate):
        node = value["context"]
        for segment in path:
            node = node[segment]
        mutate(node["finalityCertificate"]["signatures"], node["finalityCertificate"])
        vectors.append(case(name, expected, note, value, trusted_overrides={"validatorSets": None}))

    def duplicate_signer(signatures, certificate):
        signatures[1] = copy.deepcopy(signatures[0])

    def noncanonical_value(signatures, certificate):
        signatures[0]["value"] = "==not base64url=="

    def unsupported_algorithm(signatures, certificate):
        signatures[0]["algorithm"] = "secp256k1"

    bft_paths = (
        ("fv-bft", lambda: factory.model_input("bft-final"), ("observation",)),
        ("fv-ap2-sr3-bft", factory.provider_sr3_value, ("receiptTransactionObservation",)),
        ("fv-tank-coordinator-bft", lambda: factory.model_input("liquidity-tank"), ("coordinator",)),
    )
    for prefix, build, path in bft_paths:
        certificate_without_set(prefix + "-validator-set-absent-signatures-not-array", "error", "the pinned validator set is not configured and the BFT signatures are an object", build(), path, lambda s, c: c.__setitem__("signatures", {}))
        certificate_without_set(prefix + "-validator-set-absent-signature-noncanonical", "error", "the pinned validator set is not configured and a BFT signature value is not canonical Base64URL", build(), path, noncanonical_value)
    certificate_without_set("fv-bft-validator-set-absent-signature-malformed", "error", "the pinned validator set is not configured and a BFT signature lacks its algorithm", factory.model_input("bft-final"), ("observation",), lambda s, c: s[0].pop("algorithm"))
    certificate_without_set("fv-bft-validator-set-absent-signer-id-not-string", "error", "the pinned validator set is not configured and a BFT signature names its validator by a number", factory.model_input("bft-final"), ("observation",), lambda s, c: s[0].__setitem__("validatorId", 7))
    certificate_without_set("fv-bft-validator-set-absent-duplicate-signer", "fail", "the pinned validator set is not configured and one validator signs twice", factory.model_input("bft-final"), ("observation",), duplicate_signer)
    certificate_without_set("fv-bft-validator-set-absent-algorithm-unsupported", "error", "the pinned validator set is not configured and a BFT signature names secp256k1, outside the ed25519-only certificate algorithm set", factory.model_input("bft-final"), ("observation",), unsupported_algorithm)
    certificate_without_set("fv-bft-validator-set-absent-signatures-empty", "fail", "the pinned validator set is not configured and the certificate carries no signature, which no positive quorum admits", factory.model_input("bft-final"), ("observation",), lambda s, c: s.clear())
    certificate_without_set("fv-bft-validator-set-absent-signature-wrong-length", "fail", "the pinned validator set is not configured and a BFT signature is canonical Base64URL that decodes to 63 bytes, which no Ed25519 key verifies", factory.model_input("bft-final"), ("observation",), lambda s, c: s[0].__setitem__("value", short_b64u(s[0]["value"])))

    # SIG-7: attestation and certificate signatures admit ed25519 alone, so a
    # registered ComponentSignature name is still outside their set (error).
    vectors.append(case("fv-head-authority-attestation-algorithm-outside-set", "error", "a head authority attestation names sr1-aggregate, a ComponentSignature algorithm outside the ed25519-only attestation set", changed("block-depth", lambda v: v["context"]["observation"]["authorityEvidence"]["attestations"][0].__setitem__("algorithm", "sr1-aggregate"))))
    vectors.append(case("fv-bft-signature-algorithm-outside-set", "error", "with the validator set configured, a BFT signature names sr1-aggregate, a ComponentSignature algorithm outside the ed25519-only certificate set", changed("bft-final", lambda v: v["context"]["observation"]["finalityCertificate"]["signatures"][0].__setitem__("algorithm", "sr1-aggregate"))))

    # HTLC-8: the destination lock is mined no earlier than the source lock's
    # mined instant plus the pinned sourceFinalitySec.  Each schedule keeps
    # the HTLC-7 absolute-expiry inequality, so only the epoch check decides.
    def destination_locked_after(offset_ms):
        value = factory.model_input("htlc-reveal")
        parameters = value["rail"]["parameters"]
        source_mined = 1_899_990_000_000
        destination_mined = source_mined + offset_ms
        factory.rebuild_observation_event(value, ("destinationLock",), lambda event: event.update({
            "minedAt": destination_mined,
            "expiry": destination_mined + parameters["timelockDestSec"] * 1000,
        }))
        return value

    finality_ms = 600_000
    vectors.append(case("fv-htlc-destination-lock-before-source-finality", "fail", "the destination lock is mined 1s after the source lock, inside the pinned 600s source-finality interval; 7200s > 3601s + 600s + 600s still holds", destination_locked_after(1_000)))
    vectors.append(case("fv-htlc-destination-lock-one-ms-before-source-finality", "fail", "the destination lock is mined 1ms before the source lock's pinned finality instant", destination_locked_after(finality_ms - 1)))
    vectors.append(case("fv-htlc-destination-lock-at-source-finality", "pass", "the destination lock is mined exactly at the source lock's pinned finality instant", destination_locked_after(finality_ms)))
    rail("fv-htlc-source-finality-parameter-missing", "the signed HTLC rail omits sourceFinalitySec, the pinned bound HTLC-7 and HTLC-8 are evaluated against", "htlc-reveal", lambda r: r["parameters"].pop("sourceFinalitySec"))

    # HTLC-8 timing inputs: the mined instant is the lock's inclusion-header
    # timestamp. Each case rebuilds the destination lock's observation, so
    # its header, proofs and authority signatures are genuine.
    def destination_lock_header(block_timestamp, event_update=None):
        value = factory.model_input("htlc-reveal")
        factory.rebuild_observation_event(
            value, ("destinationLock",), event_update or (lambda event: None),
            block_timestamp=block_timestamp,
        )
        return value

    destination_mined = 1_899_990_000_000 + 700_000
    vectors.append(case("fv-htlc-lock-inclusion-timestamp-missing", "error", "the destination lock's authenticated inclusion header carries no timestamp, so no authenticated mined instant exists; the event's minedAt cannot stand in for it", destination_lock_header(None)))
    vectors.append(case("fv-htlc-lock-inclusion-timestamp-malformed", "error", "the destination lock's inclusion header timestamp is a decimal string, not integer Unix milliseconds", destination_lock_header(str(destination_mined))))
    vectors.append(case("fv-htlc-lock-mined-at-differs-from-inclusion-timestamp", "fail", "the destination lock event claims minedAt exactly at the source lock's pinned finality instant, with a matching expiry, but its inclusion block is timestamped 1s after the source lock", destination_lock_header(1_899_990_001_000, lambda event: event.update({"minedAt": 1_899_990_600_000, "expiry": 1_899_990_600_000 + 3_600_000}))))
    vectors.append(case("fv-htlc-lock-mined-at-not-integer", "error", "the destination lock event's minedAt is a non-integral number; HTLC-8 compares integer Unix milliseconds", destination_lock_header(destination_mined, lambda event: event.update({"minedAt": destination_mined + 0.5}))))

    # SIG-7 on ComponentSignature and AgreementSignature envelopes, whose set
    # admits ecdsa-secp256k1: steps 3-5 decide, never step 1. The fixture's
    # trusted keys are Ed25519, so a keyed signer naming ECDSA is a metadata
    # mismatch (fail). Without the key, a canonical low-S DER value is
    # deferred (indeterminate) and a high-S one can never verify (fail).
    # The signatures are outside the hashes they sign, so nothing else moves.
    def ecdsa_rail(high_s=False):
        def apply(value):
            rail_value = value["rail"]
            rail_value["signature"]["algorithm"] = "ecdsa-secp256k1"
            rail_value["signature"]["value"] = factory.sign_ecdsa("steward", RAIL_DOMAIN, artifact_hash(rail_value, "signature"), high_s=high_s)
        return apply

    def ecdsa_evidence(high_s=False):
        def apply(value):
            evidence = value["evidence"]
            evidence["signature"]["algorithm"] = "ecdsa-secp256k1"
            evidence["signature"]["value"] = factory.sign_ecdsa("orchestrator", EVIDENCE_DOMAIN, artifact_hash(evidence, "signature"), high_s=high_s)
        return apply

    def ecdsa_agreement(high_s=False):
        def apply(value):
            agreement = value["agreement"]
            agreement["signatures"][0]["algorithm"] = "ecdsa-secp256k1"
            agreement["signatures"][0]["value"] = factory.sign_ecdsa("buyer", AGREEMENT_DOMAIN, artifact_hash(agreement, "signatures"), high_s=high_s)
        return apply

    def depth_echo_mismatch(value):
        value["evidence"]["settlementFinality"]["finalityBlocks"] = 13
        factory.resign_evidence(value["evidence"])

    no_steward = {"stewardKeys": None}
    no_party = {"partyKeys": None}
    vectors.extend([
        case("fv-rail-signature-ecdsa-steward-keys-unavailable", "indeterminate", "the rail carries a canonical low-S DER ecdsa-secp256k1 steward signature and no steward key map is configured; a registered algorithm without a key is deferred, not malformed", changed("block-depth", ecdsa_rail()), trusted_overrides=no_steward),
        case("fv-rail-signature-ecdsa-high-s-steward-keys-unavailable", "fail", "with no steward key map, the ecdsa-secp256k1 rail signature is the high-S form of a genuine value, which CORE §B.7 rejects without a key", changed("block-depth", ecdsa_rail(high_s=True)), trusted_overrides=no_steward),
        case("fv-rail-signature-ecdsa-steward-key-ed25519", "fail", "the trusted steward key is Ed25519, and the rail envelope names ecdsa-secp256k1 for that steward (SIG-7 algorithm-metadata mismatch)", changed("block-depth", ecdsa_rail())),
        case("fv-rail-signature-ecdsa-steward-keys-unavailable-depth-echo-mismatch", "fail", "an ECDSA rail signature without a steward key is deferred, so the signed report's depth mismatch still decides", changed("block-depth", lambda v: (ecdsa_rail()(v), depth_echo_mismatch(v))), trusted_overrides=no_steward),
        case("fv-rail-signer-outside-steward-map", "fail", "the rail is genuinely signed by the phase orchestrator, whom the configured steward key map does not hold", changed("block-depth", lambda v: factory.resign_rail(v["rail"], key_name="orchestrator"))),
        case("fv-evidence-signature-ecdsa-party-keys-unavailable", "indeterminate", "the evidence carries a canonical low-S DER ecdsa-secp256k1 orchestrator signature and no party key map is configured", changed("block-depth", ecdsa_evidence()), trusted_overrides=no_party),
        case("fv-evidence-signature-ecdsa-high-s-party-keys-unavailable", "fail", "with no party key map, the ecdsa-secp256k1 evidence signature is the high-S form of a genuine value", changed("block-depth", ecdsa_evidence(high_s=True)), trusted_overrides=no_party),
        case("fv-evidence-signature-ecdsa-orchestrator-key-ed25519", "fail", "the orchestrator's trusted key is Ed25519, and the evidence envelope names ecdsa-secp256k1 for it", changed("block-depth", ecdsa_evidence())),
        case("fv-agreement-signature-ecdsa-party-keys-unavailable", "indeterminate", "the buyer's agreement signature is a canonical low-S DER ecdsa-secp256k1 value and no party key map is configured", changed("block-depth", ecdsa_agreement()), trusted_overrides=no_party),
        case("fv-agreement-signature-ecdsa-high-s-party-keys-unavailable", "fail", "with no party key map, the buyer's ecdsa-secp256k1 agreement signature is the high-S form of a genuine value", changed("block-depth", ecdsa_agreement(high_s=True)), trusted_overrides=no_party),
        case("fv-agreement-signature-ecdsa-buyer-key-ed25519", "fail", "the buyer's trusted key is Ed25519, and the buyer's agreement signature names ecdsa-secp256k1", changed("block-depth", ecdsa_agreement())),
    ])

    # §9.5.6 step 6: the AP2 protocolVersion selects the rules of its era; a
    # version whose rules the verifier does not implement is error.
    def other_ap2_version(value):
        value["evidence"]["paymentTxRefs"][0]["protocolVersion"] = "1"
        factory.resign_evidence(value["evidence"])

    vectors.append(case("fv-ap2-protocol-version-unsupported", "error", "the signed frozen ap2 reference names AP2 protocolVersion 1, whose rules the verifier does not implement", changed("provider-receipt", other_ap2_version)))
    vectors.append(case("fv-ap2-sr3-protocol-version-unsupported", "error", "the signed ap2-sr3 reference names AP2 protocolVersion 1, whose rules the verifier does not implement", changed_sr3(other_ap2_version)))
    # FV-10: preserve deterministic checks across unavailable authority.
    def bad_certificate(value, sr3=False):
        observation = (value["context"]["receiptTransactionObservation"] if sr3
                       else value["context"]["observation"])
        signatures = observation["finalityCertificate"]["signatures"]
        signatures[0]["value"] = signatures[1]["value"]

    for sr3 in (False, True):
        for stale in (False, True):
            for missing_key in (False, True):
                value = factory.provider_sr3_value() if sr3 else factory.model_input("bft-final")
                bad_certificate(value, sr3)
                overrides = {}
                if stale:
                    overrides["verificationTimeMs"] = OBSERVED_AT + 61_000
                if missing_key:
                    overrides["observationAuthorityKeys"] = None
                vectors.append(case(
                    "fv-" + ("ap2-sr3" if sr3 else "bft") + "-bad-certificate"
                    + ("-stale" if stale else "-fresh")
                    + ("-observation-key-absent" if missing_key else ""),
                    "fail", "an available-key BFT signature mismatch takes precedence over staleness and absent observation keys",
                    value, trusted_overrides=overrides,
                ))

    value = factory.provider_sr3_value()
    native(value)["authorityEvidence"]["attestations"][0]["value"] = "==junk=="
    vectors.append(case(
        "fv-ap2-sr3-keyless-attestation-noncanonical", "error",
        "SIG-6 wire-checks a presented SR-3 head signature even without its key; the malformed value is error", value,
        trusted_overrides={"observationAuthorityKeys": None},
    ))
    value = changed("block-depth", lambda v: v["evidence"]["signature"].__setitem__("value", "==junk=="))
    vectors.append(case(
        "fv-keyless-evidence-signature-noncanonical", "error",
        "SIG-6 wire-checks the presented evidence signature independently of party-key availability; the malformed value is error",
        value, trusted_overrides={"partyKeys": None},
    ))
    value = changed("block-depth", lambda v: v["evidence"]["signature"].__setitem__("value", short_b64u(v["evidence"]["signature"]["value"])))
    vectors.append(case(
        "fv-keyless-evidence-signature-wrong-length", "fail",
        "the presented evidence signature is canonical Base64URL that decodes to 63 bytes; SIG-7 makes it fail without the party key",
        value, trusted_overrides={"partyKeys": None},
    ))
    value = unconfigured_and(lambda v: v["evidence"]["signature"].__setitem__("value", "==junk=="))
    vectors.append(case(
        "fv-orchestrator-key-absent-evidence-signature-noncanonical", "error",
        "the session names a keyless orchestrator while the other party keys remain available; a malformed evidence signature encoding is still error",
        value, trusted_overrides=unconfigured_authority,
    ))
    for key_map in ("partyKeys", "stewardKeys"):
        value = changed("block-depth", lambda v: (
            v["evidence"]["settlementFinality"].__setitem__("finalityBlocks", 13),
            factory.resign_evidence(v["evidence"]),
        ))
        vectors.append(case(
            "fv-" + key_map + "-absent-depth-echo-mismatch", "fail",
            "a missing stage key cannot hide the signed report's depth mismatch",
            value, trusted_overrides={key_map: None},
        ))

    for sr3, key_map in ((True, "observationAuthorityKeys"), (False, "providerAuthorityKeys")):
        value = factory.provider_sr3_value() if sr3 else factory.model_input("provider-receipt")
        response_hash = value["context"]["responseAttestation"]["contentHash"]
        attestation = copy.deepcopy(factory.trusted["providerAttestations"][response_hash])
        attestation["providerRef"] = "other-provider-ref"
        vectors.append(case(
            "fv-" + ("ap2-sr3" if sr3 else "provider") + "-key-absent-provider-binding-mismatch", "fail",
            "a missing observation or provider key cannot hide a provider signature or binding mismatch",
            value, trusted_overrides={key_map: None, "providerAttestations": {response_hash: attestation}},
        ))
        if sr3:
            value = copy.deepcopy(value)
            value["context"].pop("receiptTransactionObservation")
            vectors.append(case(
                "fv-ap2-sr3-observation-absent-provider-signature-invalid", "fail",
                "an unavailable SR-3 observation cannot hide a bad available-key provider signature",
                value, trusted_overrides={"providerAttestations": {response_hash: attestation}},
            ))

    # A decoded event remains usable for deterministic cross-arm checks even
    # when its finality authority is unavailable or stale.
    tank_mismatch = factory.model_input("liquidity-tank")
    factory.rebuild_observation_event(
        tank_mismatch, ("coordinator",),
        lambda event: event.__setitem__("sourceEventHash", "00" * 32),
    )
    for label, overrides in (
        ("validator-set-absent", {"validatorSets": None}),
        ("stale", {"verificationTimeMs": OBSERVED_AT + 61_000}),
    ):
        vectors.append(case(
            "fv-tank-relation-mismatch-" + label, "fail",
            "deterministic tank relations take precedence over incomplete finality authority",
            copy.deepcopy(tank_mismatch), trusted_overrides=overrides,
        ))
    value = copy.deepcopy(tank_mismatch)
    value["context"]["coordinator"]["finalityCertificate"] = None
    vectors.append(case(
        "fv-tank-relation-mismatch-certificate-absent", "fail",
        "a missing BFT certificate cannot hide a decoded tank relation mismatch", value,
    ))
    provider_not_captured, _ = factory.provider_variant(status="declined")
    vectors.append(case(
        "fv-provider-attestation-absent-noncapture", "fail",
        "an absent provider attestation cannot hide a proved noncapture in the response bytes",
        copy.deepcopy(provider_not_captured), trusted_overrides={"providerAttestations": None},
    ))
    # FRC-8 closure extends below each observed arm, including references.
    for model, path in (
        ("block-depth", ("observation",)),
        ("block-depth", ("observation", "authenticatedHead")),
        ("block-depth", ("observation", "inclusionBlock")),
        ("block-depth", ("observation", "authorityEvidence")),
        ("block-depth", ("observation", "transactionRef")),
        ("bft-final", ("observation", "finalityCertificate")),
        ("htlc-reveal", ("sourceLock", "transactionRef")),
        ("provider-receipt", ("responseAttestation",)),
        ("provider-receipt", ("responseAttestation", "anchor")),
    ):
        value = factory.model_input(model)
        node = value["context"]
        for part in path:
            node = node[part]
        node["unexpectedMember"] = 1
        vectors.append(case("fv-frc8-extra-member-" + model + "-" + "-".join(path), "error", "an extra member below an observed arm violates FRC-8 closure", value))
    value = factory.provider_sr3_value()
    value["context"]["receiptTransactionObservation"]["transactionRef"]["unexpectedMember"] = 1
    vectors.append(case("fv-frc8-extra-member-sr3-transaction-ref", "error", "the SR-3 native reference is closed at depth", value))
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
            "implementedAP2ProtocolVersions": [AP2_PROTOCOL_VERSION],
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
