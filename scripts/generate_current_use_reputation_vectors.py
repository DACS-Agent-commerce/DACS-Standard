#!/usr/bin/env python3
"""Generate fixture-only current-use reputation inputs.

The native anchor and settlement-binding receipts in this corpus are synthetic,
signed fixtures.  They exercise the verifier boundary offline; they are not a
claim about a production Demos receipt or settlement-proof codec.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT), str(ROOT / "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

try:
    from scripts.generate_settlement_finality_verification_vectors import (
        AGREEMENT_DOMAIN,
        CLAIMS,
        FINALITY_BUNDLE_DOMAIN,
        FixtureFactory,
    )
    from scripts.settlement_finality_reference import artifact_hash
    from tests.dacs5_reference import (
        BINDING_DOMAIN,
        BUNDLE_DOMAIN,
        CURRENT_USE_SYNTHETIC_ANCHOR_PROOF_DOMAIN,
        CURRENT_USE_SYNTHETIC_OUTCOME_PROOF_DOMAIN,
        CURRENT_USE_SYNTHETIC_SETTLEMENT_BINDING_PROOF_DOMAIN,
        LEGACY_BUNDLE_CHECKPOINT_BINDING_DOMAIN,
        LEGACY_BUNDLE_CHECKPOINT_DOMAIN,
        LISTING_DOMAIN,
        RATING_DOMAIN,
        bundle_hash,
        current_use_synthetic_proof_hash,
        _jcs_value_hash,
        legacy_checkpoint_binding_hash,
        legacy_checkpoint_hash,
        legacy_checkpoint_logical_address,
        legacy_logical_address,
        listing_hash,
        logical_address,
        trusted_current_context,
        trusted_query_authority,
        trusted_role_authority,
        trusted_verification_keys,
    )
except ImportError:
    from generate_settlement_finality_verification_vectors import (  # type: ignore
        AGREEMENT_DOMAIN,
        CLAIMS,
        FINALITY_BUNDLE_DOMAIN,
        FixtureFactory,
    )
    from settlement_finality_reference import artifact_hash  # type: ignore
    from dacs5_reference import (  # type: ignore
        BINDING_DOMAIN,
        BUNDLE_DOMAIN,
        CURRENT_USE_SYNTHETIC_ANCHOR_PROOF_DOMAIN,
        CURRENT_USE_SYNTHETIC_OUTCOME_PROOF_DOMAIN,
        CURRENT_USE_SYNTHETIC_SETTLEMENT_BINDING_PROOF_DOMAIN,
        LEGACY_BUNDLE_CHECKPOINT_BINDING_DOMAIN,
        LEGACY_BUNDLE_CHECKPOINT_DOMAIN,
        LISTING_DOMAIN,
        RATING_DOMAIN,
        bundle_hash,
        current_use_synthetic_proof_hash,
        _jcs_value_hash,
        legacy_checkpoint_binding_hash,
        legacy_checkpoint_hash,
        legacy_checkpoint_logical_address,
        legacy_logical_address,
        listing_hash,
        logical_address,
        trusted_current_context,
        trusted_query_authority,
        trusted_role_authority,
        trusted_verification_keys,
    )


OUTPUT = ROOT / "conformance/vectors/security/current-use-reputation-v1.json"
MODELS = (
    "block-depth",
    "commitment-level",
    "bft-final",
    "provider-receipt",
    "htlc-reveal",
    "liquidity-tank",
)
WRITE_SUBSTRATE = "dacs-current-use-synthetic-write-input-v1"
PURE_SUBSTRATE = "dacs-current-use-synthetic-pure-v1"
PURE_PROFILE = "dacs-current-use-synthetic-pure-mapping-v1"
NATIVE_AUTHORITY = "fixture:current-use-native-authority"
OBSERVED_AT = 1_900_000_000_000
COMPUTED_AT = 1_900_000_010_000
HISTORICAL_BINDING_JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
HISTORICAL_PURE_JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
CURRENT_FINALITY_JOB_IDS = {
    "block-depth": "01ARZ3NDEKTSV4RRFFQ69G5FAX",
    "commitment-level": "01ARZ3NDEKTSV4RRFFQ69G5FAY",
    "bft-final": "01ARZ3NDEKTSV4RRFFQ69G5FAZ",
    "provider-receipt": "01ARZ3NDEKTSV4RRFFQ69G5FB0",
    "htlc-reveal": "01ARZ3NDEKTSV4RRFFQ69G5FB1",
    "liquidity-tank": "01ARZ3NDEKTSV4RRFFQ69G5FB2",
}
CURRENT_USE_JOB_IDS = (
    HISTORICAL_BINDING_JOB_ID,
    HISTORICAL_PURE_JOB_ID,
    *(CURRENT_FINALITY_JOB_IDS[model] for model in MODELS),
    "01ARZ3NDEKTSV4RRFFQ69G5FB3",
)
MULTIPHASE_JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FB3"
FIXTURE_QUERY_WINDOW = (0, 2_000_000_000_000)


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def old_hash(value: dict, omitted: str) -> str:
    return hashlib.sha256(canonical({key: item for key, item in value.items() if key != omitted})).hexdigest()


def pure_native(logical: str) -> str:
    return "pure-" + hashlib.sha256(logical.encode("utf-8")).hexdigest()


def reference(label: str, digest: str) -> dict:
    return {
        "anchor": {
            "kind": "storage-program",
            "locator": "stor-" + hashlib.sha256(label.encode("utf-8")).hexdigest(),
        },
        "contentHash": digest,
    }


class CurrentUseFixtureFactory:
    def __init__(self) -> None:
        self.finality = FixtureFactory()
        self.native_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("81" * 32))
        self.dependencies: dict[str, Any] = {
            "bundlesByNativeAddress": {},
            "checkpointsByNativeAddress": {},
            "bundleAuthorityByContentHash": {},
            "settlementBindingProofByCanonicalRef": {},
            "agreementsByCanonicalRef": {},
            "ratingsByCanonicalRef": {},
            "absenceEvidenceByCanonicalRef": {},
            "outcomeTimeEvidenceByJobId": {},
            "anchorReceiptHistoryByJobId": {},
        }
        public_keys = {
            CLAIMS[role]: self.finality.keys[role].public_key().public_bytes_raw()
            for role in ("buyer", "seller", "orchestrator", "steward")
        }
        self.current_keys = trusted_verification_keys(public_keys)
        self.config: dict[str, Any] = {
            "verificationTimeMs": COMPUTED_AT,
            "publicKeys": public_keys,
            "finalityTrust": self.finality.trusted,
            "partyRolesByJob": {},
            "bb6Budget": 8,
            "authorizedStewardBySubstrate": {
                WRITE_SUBSTRATE: CLAIMS["steward"],
                PURE_SUBSTRATE: CLAIMS["steward"],
            },
            "nativeAuthorityBySubstrate": {
                WRITE_SUBSTRATE: NATIVE_AUTHORITY,
                PURE_SUBSTRATE: NATIVE_AUTHORITY,
            },
            "nativeAuthorityKeys": {
                NATIVE_AUTHORITY: self.native_key.public_key().public_bytes_raw(),
            },
            "pureMappingProfileBySubstrate": {PURE_SUBSTRATE: PURE_PROFILE},
            "settlementBindingAuthorityByPhase": {
                "pay-ap2": NATIVE_AUTHORITY,
                "pay-x402": NATIVE_AUTHORITY,
            },
            "settlementBindingAuthorityKeys": {
                NATIVE_AUTHORITY: self.native_key.public_key().public_bytes_raw(),
            },
            "authenticatedAbsenceByJobRole": {},
            "pinnedSyntheticAnchorProofHashBySubject": {},
            "outcomeTimePolicyBySubstrate": {
                WRITE_SUBSTRATE: {"policyId": "fixture-current-outcome-v1", "authority": NATIVE_AUTHORITY},
                PURE_SUBSTRATE: {"policyId": "fixture-current-outcome-v1", "authority": NATIVE_AUTHORITY},
            },
            "outcomeTimeAuthorityKeys": {
                NATIVE_AUTHORITY: self.native_key.public_key().public_bytes_raw(),
            },
            "pinnedOutcomeHistoryHashByJob": {},
            "pinnedAnchorHistoryHashByJob": {},
        }
        self.checkpoints: dict[str, dict] = {}

    def current_authority(
        self, query_party: str, window: tuple[int | float, int | float],
        basis: str = "finalisedAt",
    ) -> dict:
        window_start, window_end = window
        role_map = [
            trusted_role_authority(job_id, role, CLAIMS[role])
            for job_id in CURRENT_USE_JOB_IDS
            for role in ("buyer", "seller")
        ]
        return trusted_current_context(
            role_map,
            query=trusted_query_authority(
                query_party, window_start, window_end, basis
            ),
        )

    def replay_context(self, request: dict, basis: str = "finalisedAt") -> dict:
        """Return the per-case trusted query context and role authority."""
        return trusted_current_context(
            [
                trusted_role_authority(request["jobId"], role, CLAIMS[role])
                for role in ("buyer", "seller")
            ],
            query=trusted_query_authority(
                CLAIMS["buyer"], FIXTURE_QUERY_WINDOW[0], FIXTURE_QUERY_WINDOW[1],
                basis,
            ),
        )

    def replay_keys(self) -> dict:
        """Return the independently authenticated current verification keys."""
        return trusted_verification_keys({
            CLAIMS[role]: self.finality.keys[role].public_key().public_bytes_raw()
            for role in ("buyer", "seller", "orchestrator", "steward")
        })

    def _sign(self, key: Ed25519PrivateKey, domain: str, digest: str) -> str:
        return b64u(key.sign((domain + digest).encode("ascii")))

    def sign_bundle_binding(self, binding: dict, role: str) -> None:
        binding["signature"] = {
            "signer": CLAIMS[role],
            "algorithm": "ed25519",
            "value": self._sign(
                self.finality.keys[role], BINDING_DOMAIN, old_hash(binding, "signature")
            ),
        }

    def _bundle_binding(
        self, bundle: dict, role: str, label: str, logical: str
    ) -> dict:
        job_id = bundle["jobId"]
        binding = {
            "bindingVersion": "1",
            "jobId": job_id,
            "role": role,
            "logicalAddress": logical,
            "nativeAddress": "native-" + hashlib.sha256(label.encode("utf-8")).hexdigest(),
            "bundleContentHash": bundle_hash(bundle),
            "signer": CLAIMS[role],
            "signature": {},
        }
        self.sign_bundle_binding(binding, role)
        return binding

    def bundle_binding(
        self, bundle: dict, role: str, label: str, *, trusted_contexts: dict
    ) -> dict:
        return self._bundle_binding(
            bundle,
            role,
            label,
            logical_address(
                bundle["jobId"], role, trusted_contexts=trusted_contexts
            ),
        )

    def legacy_bundle_binding(self, bundle: dict, role: str, label: str) -> dict:
        return self._bundle_binding(
            bundle,
            role,
            label,
            legacy_logical_address(bundle["jobId"], role),
        )

    def anchor_proof(
        self,
        *,
        purpose: str,
        substrate: str,
        subject_id: str,
        subject_role: str,
        logical: str,
        native: str,
        content_hash: str,
        transaction: str,
        writer: str,
        nonce: int,
        height: int,
        index: int,
        disposition: str = "established",
    ) -> dict:
        proof = {
            "syntheticAnchorProofVersion": "1",
            "purpose": purpose,
            "substrate": substrate,
            "subjectId": subject_id,
            "subjectRole": subject_role,
            "logicalAddress": logical,
            "nativeAddress": native,
            "contentHash": content_hash,
            "transactionRef": transaction,
            "writer": writer,
            "nonce": nonce,
            "position": {"orderDomain": "fixture-ledger-v1", "height": height, "index": index},
            "state": "finalized",
            "observationDisposition": disposition,
            "signature": {},
        }
        proof["signature"] = {
            "signer": NATIVE_AUTHORITY,
            "algorithm": "ed25519",
            "value": self._sign(
                self.native_key,
                CURRENT_USE_SYNTHETIC_ANCHOR_PROOF_DOMAIN,
                current_use_synthetic_proof_hash(proof),
            ),
        }
        pin_key = ":".join((substrate, purpose, subject_id, subject_role, native))
        self.config["pinnedSyntheticAnchorProofHashBySubject"][pin_key] = (
            current_use_synthetic_proof_hash(proof)
        )
        return proof

    def checkpoint(self, substrate: str, *, write_input: bool) -> dict:
        checkpoint = {
            "legacyBundleCheckpointVersion": "1",
            "substrate": substrate,
            "policy": "legacy-attestation-pre-checkpoint-only",
            "createdAt": OBSERVED_AT - 1_000,
            "signature": {},
        }
        checkpoint["signature"] = {
            "signer": CLAIMS["steward"],
            "algorithm": "ed25519",
            "value": self._sign(
                self.finality.keys["steward"], LEGACY_BUNDLE_CHECKPOINT_DOMAIN,
                legacy_checkpoint_hash(checkpoint),
            ),
        }
        digest = legacy_checkpoint_hash(checkpoint)
        logical = legacy_checkpoint_logical_address(substrate)
        native = (
            "native-" + hashlib.sha256(("checkpoint:" + substrate).encode()).hexdigest()
            if write_input else pure_native(logical)
        )
        tx = "fixture-tx-checkpoint-" + hashlib.sha256(substrate.encode()).hexdigest()
        receipt = self.anchor_proof(
            purpose="checkpoint",
            substrate=substrate,
            subject_id=substrate,
            subject_role="steward",
            logical=logical,
            native=native,
            content_hash=digest,
            transaction=tx,
            writer=CLAIMS["steward"],
            nonce=40,
            height=100,
            index=2,
        )
        candidates = []
        if write_input:
            binding = {
                "legacyBundleCheckpointBindingVersion": "1",
                "substrate": substrate,
                "logicalAddress": logical,
                "nativeAddress": native,
                "checkpointContentHash": digest,
                "anchorTx": tx,
                "signer": CLAIMS["steward"],
                "signature": {},
            }
            binding["signature"] = {
                "signer": CLAIMS["steward"],
                "algorithm": "ed25519",
                "value": self._sign(
                    self.finality.keys["steward"],
                    LEGACY_BUNDLE_CHECKPOINT_BINDING_DOMAIN,
                    legacy_checkpoint_binding_hash(binding),
                ),
            }
            candidates = [binding]
        self.dependencies["checkpointsByNativeAddress"][native] = checkpoint
        result = {"checkpoint": checkpoint, "receipt": receipt, "candidates": candidates}
        self.checkpoints[substrate] = result
        return result

    def _historical_listing(self) -> dict:
        listing = {
            "listingId": "listing-historical-nonpayment",
            "listingVersion": 1,
            "sellerPrimaryClaim": CLAIMS["seller"],
            "pipeline": [{"kind": "deliver-storage-program"}],
            "signature": {},
        }
        listing["signature"] = {
            "signer": CLAIMS["seller"],
            "algorithm": "ed25519",
            "value": self._sign(
                self.finality.keys["seller"], LISTING_DOMAIN, listing_hash(listing)
            ),
        }
        return listing

    def _legacy_bundle(self, job_id: str, role: str, listing: dict) -> dict:
        outcome = "aborted-by-other" if role == "buyer" else "aborted-by-self"
        bundle = {
            "bundleVersion": "1",
            "jobId": job_id,
            "outcome": outcome,
            "anchoredByRole": role,
            "listingRef": {
                "listingId": "listing-historical-nonpayment",
                "version": 1,
                "contentHash": listing_hash(listing),
            },
            "parties": [
                {
                    "role": party_role,
                    "bundleHash": hashlib.sha256((job_id + ":" + party_role).encode()).hexdigest(),
                    "primaryClaim": CLAIMS[party_role],
                }
                for party_role in ("buyer", "seller")
            ],
            "phaseSummary": [],
            "vetRecords": [],
            "settlementEvidence": [],
            "recipeRegistryVersion": 1,
            "railRegistryVersion": 1,
            "finalisedAt": OBSERVED_AT - 10_000,
            "signatures": [],
        }
        self.finality.sign_bundle(bundle, BUNDLE_DOMAIN)
        return bundle

    def historical_job(self, job_id: str, *, pure: bool) -> dict:
        substrate = PURE_SUBSTRATE if pure else WRITE_SUBSTRATE
        checkpoint = self.checkpoints.get(substrate) or self.checkpoint(substrate, write_input=not pure)
        self.config["partyRolesByJob"][job_id] = {
            "buyer": CLAIMS["buyer"], "seller": CLAIMS["seller"],
        }
        listing = self._historical_listing()
        current_context = self.current_authority(
            CLAIMS["buyer"], FIXTURE_QUERY_WINDOW
        )
        roles = {}
        for role_index, role in enumerate(("buyer", "seller")):
            bundle = self._legacy_bundle(job_id, role, listing)
            digest = bundle_hash(bundle)
            self.dependencies["bundleAuthorityByContentHash"][digest] = {
                "listing": copy.deepcopy(listing),
            }
            historical_logical = legacy_logical_address(job_id, role)
            if pure:
                historical_native = pure_native(historical_logical)
                original_mapping = {
                    "kind": "pure",
                    "logicalAddress": historical_logical,
                    "nativeAddress": historical_native,
                }
            else:
                original = self.legacy_bundle_binding(
                    bundle, role, job_id + ":historical:" + role
                )
                historical_native = original["nativeAddress"]
                original_mapping = {
                    "kind": "binding",
                    "binding": copy.deepcopy(original),
                    "selectionContext": {
                        "candidateBindings": [copy.deepcopy(original)],
                        "partyMap": {CLAIMS["buyer"]: "buyer", CLAIMS["seller"]: "seller"},
                        "budget": 8,
                    },
                }
            self.dependencies["bundlesByNativeAddress"][historical_native] = bundle
            historical_receipt = self.anchor_proof(
                purpose="historical-bundle",
                substrate=substrate,
                subject_id=job_id,
                subject_role=role,
                logical=historical_logical,
                native=historical_native,
                content_hash=digest,
                transaction="fixture-tx-historical-" + hashlib.sha256((job_id + role).encode()).hexdigest(),
                writer=CLAIMS[role],
                nonce=10 + role_index,
                height=90,
                index=role_index,
            )
            original_mapping.update({
                "anchorTransaction": historical_receipt["transactionRef"],
                "writer": historical_receipt["writer"],
                "nonce": historical_receipt["nonce"],
            })
            era = {
                "bundleContentHash": digest,
                "resolvedJobId": job_id,
                "resolvedRole": role,
                "substrate": substrate,
                "checkpointCandidates": copy.deepcopy(checkpoint["candidates"]),
                "checkpointReceipt": copy.deepcopy(checkpoint["receipt"]),
                "historicalAnchorReceipt": historical_receipt,
                "originalMapping": original_mapping,
            }
            current_logical = logical_address(
                job_id, role, trusted_contexts=current_context
            )
            if pure:
                current_native = pure_native(current_logical)
            else:
                current_binding = self.bundle_binding(
                    bundle,
                    role,
                    job_id + ":current:" + role,
                    trusted_contexts=current_context,
                )
                current_native = current_binding["nativeAddress"]
            self.dependencies["bundlesByNativeAddress"][current_native] = bundle
            current_receipt = self.anchor_proof(
                purpose="current-bundle",
                substrate=substrate,
                subject_id=job_id,
                subject_role=role,
                logical=current_logical,
                native=current_native,
                content_hash=digest,
                transaction="fixture-tx-current-read-" + hashlib.sha256((job_id + role).encode()).hexdigest(),
                writer=CLAIMS[role],
                nonce=30 + role_index,
                height=110,
                index=role_index,
            )
            if pure:
                roles[role] = {
                    "disposition": "present",
                    "mappingKind": "pure",
                    "resolvedAddress": current_native,
                    "anchorReceipt": current_receipt,
                    "legacyEraEvidence": era,
                }
            else:
                roles[role] = {
                    "disposition": "present",
                    "mappingKind": "binding",
                    "selectionContext": {
                        "candidateBindings": [copy.deepcopy(current_binding)],
                        "partyMap": {CLAIMS["buyer"]: "buyer", CLAIMS["seller"]: "seller"},
                        "budget": 8,
                    },
                    "anchorReceiptsByNativeAddress": {current_native: current_receipt},
                    "legacyEraEvidenceByNativeAddress": {current_native: era},
                }
        return {"jobId": job_id, "substrate": substrate, "roles": roles}

    def _rating(self, job_id: str) -> tuple[dict, dict]:
        rating = {
            "ratingVersion": "1",
            "jobId": job_id,
            "rater": CLAIMS["seller"],
            "target": CLAIMS["buyer"],
            "targetRole": "buyer",
            "value": 5,
            "ratedAt": OBSERVED_AT + 1,
            "signature": {},
        }
        digest = artifact_hash(rating, "signature")
        rating["signature"] = {
            "signer": CLAIMS["seller"],
            "algorithm": "ed25519",
            "value": self._sign(self.finality.keys["seller"], RATING_DOMAIN, digest),
        }
        return rating, reference("rating:" + job_id, digest)

    def settlement_binding_proof(self, record: dict, ref_key: str, phase_index: int) -> None:
        proof = {
            "syntheticSettlementBindingProofVersion": "1",
            "jobId": record["jobId"],
            "phaseIndex": phase_index,
            "phase": record["phase"],
            "paymentTxRefsHash": artifact_hash({"paymentTxRefs": record["paymentTxRefs"]}, ()),
            "state": "match",
            "observedAt": OBSERVED_AT,
            "signature": {},
        }
        proof["signature"] = {
            "signer": NATIVE_AUTHORITY,
            "algorithm": "ed25519",
            "value": self._sign(
                self.native_key,
                CURRENT_USE_SYNTHETIC_SETTLEMENT_BINDING_PROOF_DOMAIN,
                current_use_synthetic_proof_hash(proof),
            ),
        }
        self.dependencies["settlementBindingProofByCanonicalRef"][ref_key] = proof

    def current_finality_job(
        self, model: str, index: int, *, job_id: str | None = None,
        extra_rate_phase: bool = False, projected_alternative: bool = False,
    ) -> tuple[dict, dict]:
        actual_job_id = job_id or CURRENT_FINALITY_JOB_IDS[model]
        if model == "provider-receipt":
            case = self.finality.strong_bundle_case_sr3(
                job_id=actual_job_id
            )
        else:
            case = self.finality.strong_bundle_case(
                model, job_id=actual_job_id
            )
        bundle = case["bundle"]
        authority = case["authority"]
        candidate = next(iter(authority["finalityVerificationByCanonicalRef"].values()))
        agreement = candidate["agreement"]
        if projected_alternative:
            listing = authority["listing"]
            selected_rail = copy.deepcopy(agreement["terms"]["rail"])
            alternate_rail = {"railId": "fixture:unselected-apr-rail", "railVersion": 1}
            listing["pipeline"] = [{
                "kind": "pay-alternative",
                "parameters": {"alternatives": [selected_rail, alternate_rail]},
            }]
            listing["acceptedRails"] = [selected_rail, alternate_rail]
            listing["signature"] = {
                "signer": CLAIMS["seller"], "algorithm": "ed25519",
                "value": self._sign(self.finality.keys["seller"], LISTING_DOMAIN,
                                    listing_hash(listing)),
            }
            new_listing_ref = {
                "listingId": listing["listingId"],
                "version": listing["listingVersion"],
                "contentHash": listing_hash(listing),
            }
            bundle["listingRef"] = copy.deepcopy(new_listing_ref)
            agreement["listingRef"] = copy.deepcopy(new_listing_ref)
            agreement_digest = artifact_hash(agreement, "signatures")
            self.finality.trusted["sessionAuthorityByJob"][actual_job_id]["agreementHash"] = agreement_digest
            agreement["signatures"] = [
                {
                    "party": CLAIMS[role], "algorithm": "ed25519",
                    "value": self._sign(self.finality.keys[role], AGREEMENT_DOMAIN,
                                        agreement_digest),
                }
                for role in ("buyer", "seller")
            ]
            authority["effectivePipeline"] = [{
                "kind": candidate["evidence"]["phase"],
                "parameters": {"rail": selected_rail["railId"]},
            }]
        if extra_rate_phase:
            listing = authority["listing"]
            listing["pipeline"].append({"kind": "rate"})
            listing["signature"] = {
                "signer": CLAIMS["seller"], "algorithm": "ed25519",
                "value": self._sign(
                    self.finality.keys["seller"], LISTING_DOMAIN,
                    listing_hash(listing),
                ),
            }
            new_listing_ref = {
                "listingId": listing["listingId"],
                "version": listing["listingVersion"],
                "contentHash": listing_hash(listing),
            }
            bundle["listingRef"] = copy.deepcopy(new_listing_ref)
            agreement["listingRef"] = copy.deepcopy(new_listing_ref)
            digest = artifact_hash(agreement, "signatures")
            self.finality.trusted["sessionAuthorityByJob"][actual_job_id]["agreementHash"] = digest
            agreement["signatures"] = [
                {
                    "party": CLAIMS[role], "algorithm": "ed25519",
                    "value": self._sign(
                        self.finality.keys[role], AGREEMENT_DOMAIN, digest,
                    ),
                }
                for role in ("buyer", "seller")
            ]
            bundle["phaseSummary"].append({"index": 1, "kind": "rate", "outcome": "ok"})
        agreement_digest = artifact_hash(agreement, "signatures")
        agreement_ref = reference(
            "agreement:" + model + (":apr" if projected_alternative else ""),
            agreement_digest,
        )
        bundle["agreementRef"] = agreement_ref
        if model == "block-depth":
            rating, rating_ref = self._rating(bundle["jobId"])
            bundle["ratingRefs"] = [rating_ref]
            self.dependencies["ratingsByCanonicalRef"][canonical(rating_ref).decode("utf-8")] = rating
        self.finality.sign_bundle(bundle, FINALITY_BUNDLE_DOMAIN)
        self.finality.bind_current_laa_authority(bundle, authority)
        digest = bundle_hash(bundle)
        self.dependencies["bundleAuthorityByContentHash"][digest] = authority
        self.dependencies["agreementsByCanonicalRef"][canonical(agreement_ref).decode("utf-8")] = agreement
        self.config["partyRolesByJob"][bundle["jobId"]] = {
            "buyer": CLAIMS["buyer"], "seller": CLAIMS["seller"],
        }
        current_context = (
            trusted_current_context(
                [trusted_role_authority(actual_job_id, role, CLAIMS[role])
                 for role in ("buyer", "seller")],
                query=trusted_query_authority(
                    CLAIMS["buyer"], FIXTURE_QUERY_WINDOW[0],
                    FIXTURE_QUERY_WINDOW[1], "finalisedAt",
                ),
            ) if projected_alternative else self.current_authority(
                CLAIMS["buyer"], FIXTURE_QUERY_WINDOW
            )
        )
        roles = {}
        for role_index, role in enumerate(("buyer", "seller")):
            anchored = copy.deepcopy(bundle)
            anchored["anchoredByRole"] = role
            binding = self.bundle_binding(
                anchored,
                role,
                "current:" + model + ":" + role + (
                    ":" + actual_job_id if extra_rate_phase or projected_alternative else ""
                ),
                trusted_contexts=current_context,
            )
            native = binding["nativeAddress"]
            self.dependencies["bundlesByNativeAddress"][native] = anchored
            receipt = self.anchor_proof(
                purpose="current-bundle",
                substrate=WRITE_SUBSTRATE,
                subject_id=bundle["jobId"],
                subject_role=role,
                logical=binding["logicalAddress"],
                native=native,
                content_hash=digest,
                transaction="fixture-tx-current-" + hashlib.sha256((model + role).encode()).hexdigest(),
                writer=CLAIMS[role],
                nonce=100 + index * 2 + role_index,
                height=200 + index,
                index=role_index,
            )
            roles[role] = {
                "disposition": "present",
                "mappingKind": "binding",
                "selectionContext": {
                    "candidateBindings": [binding],
                    "partyMap": {CLAIMS["buyer"]: "buyer", CLAIMS["seller"]: "seller"},
                    "budget": 8,
                },
                "anchorReceiptsByNativeAddress": {native: receipt},
                "legacyEraEvidenceByNativeAddress": {},
            }
        if model == "provider-receipt":
            ref_key = next(iter(authority["finalityVerificationByCanonicalRef"]))
            self.settlement_binding_proof(candidate["evidence"], ref_key, 0)
        expected_currency = candidate["agreement"]["terms"]["price"]["currency"]
        expected_class = (
            "provisional-provider-capture" if model == "provider-receipt" else "profile-final"
        )
        return (
            {"jobId": bundle["jobId"], "substrate": WRITE_SUBSTRATE, "roles": roles},
            {"model": model, "currency": expected_currency, "finalityClass": expected_class},
        )

    def outcome_time_proof(self, request: dict, *, timestamp: int = OBSERVED_AT + 1000) -> dict:
        """Sign a fixture-only independently observed terminal native event."""
        candidates = []
        for role in ("buyer", "seller"):
            role_request = request["roles"][role]
            native = (
                role_request["selectionContext"]["candidateBindings"][0]["nativeAddress"]
                if role_request["mappingKind"] == "binding"
                else role_request["resolvedAddress"]
            )
            candidates.append(self.dependencies["bundlesByNativeAddress"][native])
        # The fixture's two copies have one type rank; the shared CUR resolver
        # selects the greatest canonical content hash after non-divergence.
        bundle = max(candidates, key=bundle_hash)
        authority = self.dependencies["bundleAuthorityByContentHash"][bundle_hash(bundle)]
        proof = {
            "syntheticOutcomeProofVersion": "1",
            "policyId": "fixture-current-outcome-v1",
            "jobId": bundle["jobId"],
            "bundleContentHash": bundle_hash(bundle),
            "outcome": bundle["outcome"],
            "effectivePipelineHash": _jcs_value_hash(authority["listing"]["pipeline"]),
            "phaseSummaryHash": _jcs_value_hash(bundle["phaseSummary"]),
            "terminalEvidenceHash": _jcs_value_hash(bundle.get("settlementEvidence", [])),
            "nativeEvent": {
                "eventId": "fixture-terminal:" + bundle["jobId"],
                "nativeOrder": 500,
                "timestamp": timestamp,
                "state": "finalized",
            },
            "signature": {},
        }
        proof["signature"] = {
            "signer": NATIVE_AUTHORITY,
            "algorithm": "ed25519",
            "value": self._sign(
                self.native_key, CURRENT_USE_SYNTHETIC_OUTCOME_PROOF_DOMAIN,
                current_use_synthetic_proof_hash(proof),
            ),
        }
        self.dependencies["outcomeTimeEvidenceByJobId"][bundle["jobId"]] = [proof]
        self.config["pinnedOutcomeHistoryHashByJob"][bundle["jobId"]] = _jcs_value_hash([proof])
        selected_role = bundle["anchoredByRole"]
        selected_request = request["roles"][selected_role]
        selected_native = (
            selected_request["selectionContext"]["candidateBindings"][0]["nativeAddress"]
            if selected_request["mappingKind"] == "binding"
            else selected_request["resolvedAddress"]
        )
        selected_anchor = (
            selected_request["anchorReceiptsByNativeAddress"][selected_native]
            if selected_request["mappingKind"] == "binding"
            else selected_request["anchorReceipt"]
        )
        self.dependencies["anchorReceiptHistoryByJobId"][bundle["jobId"]] = [
            copy.deepcopy(selected_anchor)
        ]
        self.config["pinnedAnchorHistoryHashByJob"][bundle["jobId"]] = _jcs_value_hash(
            self.dependencies["anchorReceiptHistoryByJobId"][bundle["jobId"]]
        )
        return proof

    def build(self) -> dict:
        historical = [
            self.historical_job(HISTORICAL_BINDING_JOB_ID, pure=False),
            self.historical_job(HISTORICAL_PURE_JOB_ID, pure=True),
        ]
        current = []
        expectations = []
        for index, model in enumerate(MODELS):
            request, expectation = self.current_finality_job(model, index)
            current.append(request)
            expectations.append(expectation)
        multiphase, _ = self.current_finality_job(
            "block-depth", len(MODELS), job_id=MULTIPHASE_JOB_ID,
            extra_rate_phase=True,
        )
        for request in [*historical, *current, multiphase]:
            self.outcome_time_proof(request)
        return {
            "historicalRequests": historical,
            "currentRequestsByModel": dict(zip(MODELS, current)),
            "multiPhaseRequest": multiphase,
            "expectations": expectations,
            "dependencies": self.dependencies,
            "verifierConfig": self.config,
        }

    def replay_dependencies(self, request: dict, *, include_combined: bool = False) -> dict:
        """Return the per-case authenticated dependency closure."""
        deps = self.dependencies
        closure = {
            "bundlesByNativeAddress": {},
            "checkpointsByNativeAddress": {},
            "bundleAuthorityByContentHash": {},
            "settlementBindingProofByCanonicalRef": {},
            "agreementsByCanonicalRef": {},
            "ratingsByCanonicalRef": {},
            "absenceEvidenceByCanonicalRef": {},
            "outcomeTimeEvidenceByJobId": {},
            "anchorReceiptHistoryByJobId": {},
        }
        native_addresses: list[str] = []
        eras: list[dict] = []
        for role_request in request["roles"].values():
            if role_request.get("mappingKind") == "binding":
                native_addresses.extend(
                    binding["nativeAddress"]
                    for binding in role_request["selectionContext"]["candidateBindings"]
                )
            if "resolvedAddress" in role_request:
                native_addresses.append(role_request["resolvedAddress"])
            eras.extend(
                era for era in (
                    role_request.get("legacyEraEvidenceByNativeAddress") or {}
                ).values() if era
            )
            if "legacyEraEvidence" in role_request:
                eras.append(role_request["legacyEraEvidence"])
        for native in native_addresses:
            bundle = deps["bundlesByNativeAddress"][native]
            closure["bundlesByNativeAddress"][native] = copy.deepcopy(bundle)
            digest = bundle_hash(bundle)
            authority = deps["bundleAuthorityByContentHash"].get(digest)
            if authority is not None:
                closure["bundleAuthorityByContentHash"][digest] = copy.deepcopy(authority)
            agreement_ref = bundle.get("agreementRef")
            if agreement_ref is not None:
                key = canonical(agreement_ref).decode("utf-8")
                if key in deps["agreementsByCanonicalRef"]:
                    closure["agreementsByCanonicalRef"][key] = copy.deepcopy(
                        deps["agreementsByCanonicalRef"][key]
                    )
            for rating_ref in bundle.get("ratingRefs", []):
                key = canonical(rating_ref).decode("utf-8")
                if key in deps["ratingsByCanonicalRef"]:
                    closure["ratingsByCanonicalRef"][key] = copy.deepcopy(
                        deps["ratingsByCanonicalRef"][key]
                    )
            if isinstance(authority, dict):
                for ref_key in authority.get("finalityVerificationByCanonicalRef", {}):
                    if ref_key in deps["settlementBindingProofByCanonicalRef"]:
                        closure["settlementBindingProofByCanonicalRef"][ref_key] = (
                            copy.deepcopy(
                                deps["settlementBindingProofByCanonicalRef"][ref_key]
                            )
                        )
        job_id = request["jobId"]
        if include_combined and job_id in deps["outcomeTimeEvidenceByJobId"]:
            closure["outcomeTimeEvidenceByJobId"][job_id] = copy.deepcopy(
                deps["outcomeTimeEvidenceByJobId"][job_id]
            )
        if include_combined and job_id in deps["anchorReceiptHistoryByJobId"]:
            closure["anchorReceiptHistoryByJobId"][job_id] = copy.deepcopy(
                deps["anchorReceiptHistoryByJobId"][job_id]
            )
        for era in eras:
            for receipt_name in ("checkpointReceipt", "historicalAnchorReceipt"):
                receipt = era[receipt_name]
                checkpoint_native = receipt["nativeAddress"]
                if receipt_name == "checkpointReceipt" and (
                    checkpoint_native in deps["checkpointsByNativeAddress"]
                ):
                    closure["checkpointsByNativeAddress"][checkpoint_native] = (
                        copy.deepcopy(deps["checkpointsByNativeAddress"][checkpoint_native])
                    )
                historical_native = receipt["nativeAddress"]
                if (
                    receipt_name == "historicalAnchorReceipt"
                    and historical_native in deps["bundlesByNativeAddress"]
                ):
                    bundle = deps["bundlesByNativeAddress"][historical_native]
                    closure["bundlesByNativeAddress"][historical_native] = copy.deepcopy(bundle)
                    digest = bundle_hash(bundle)
                    authority = deps["bundleAuthorityByContentHash"].get(digest)
                    if authority is not None:
                        closure["bundleAuthorityByContentHash"][digest] = copy.deepcopy(authority)
        if not include_combined:
            closure.pop("outcomeTimeEvidenceByJobId")
            closure.pop("anchorReceiptHistoryByJobId")
        return closure

    def replay_config(self, request: dict, *, include_combined: bool = False) -> dict:
        """Return the per-case verifier configuration and pinned receipts."""
        config = copy.deepcopy(self.config)
        job_id = request["jobId"]
        config["partyRolesByJob"] = {job_id: copy.deepcopy(self.config["partyRolesByJob"][job_id])}
        receipts = []
        for role_request in request["roles"].values():
            receipts.extend((role_request.get("anchorReceiptsByNativeAddress") or {}).values())
            if "anchorReceipt" in role_request:
                receipts.append(role_request["anchorReceipt"])
            for era in (role_request.get("legacyEraEvidenceByNativeAddress") or {}).values():
                if era:
                    receipts.extend(
                        era.get(receipt_name) for receipt_name in
                        ("checkpointReceipt", "historicalAnchorReceipt")
                    )
            if "legacyEraEvidence" in role_request:
                era = role_request["legacyEraEvidence"]
                receipts.extend(
                    era.get(receipt_name) for receipt_name in
                    ("checkpointReceipt", "historicalAnchorReceipt")
                )
        pins = {}
        for receipt in receipts:
            if not receipt:
                continue
            key = ":".join((
                receipt["substrate"], receipt["purpose"], receipt["subjectId"],
                receipt["subjectRole"], receipt["nativeAddress"],
            ))
            pins[key] = self.config["pinnedSyntheticAnchorProofHashBySubject"][key]
        config["pinnedSyntheticAnchorProofHashBySubject"] = pins
        if include_combined:
            config["pinnedOutcomeHistoryHashByJob"] = {
                job_id: self.config["pinnedOutcomeHistoryHashByJob"][job_id]
            }
            config["pinnedAnchorHistoryHashByJob"] = {
                job_id: self.config["pinnedAnchorHistoryHashByJob"][job_id]
            }
        else:
            for field in (
                "outcomeTimePolicyBySubstrate", "outcomeTimeAuthorityKeys",
                "pinnedOutcomeHistoryHashByJob", "pinnedAnchorHistoryHashByJob",
            ):
                config.pop(field)
            config["finalityTrust"]["sessionAuthorityByJob"].pop(MULTIPHASE_JOB_ID, None)
        return config


def _serializable(value: Any) -> Any:
    if isinstance(value, bytes):
        return b64u(value)
    if isinstance(value, dict):
        return {key: _serializable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serializable(item) for item in value]
    return value


def document() -> dict:
    factory = CurrentUseFixtureFactory()
    fixture = factory.build()
    historical = _serializable(fixture["historicalRequests"])
    expectations = fixture["expectations"]
    replay_inputs = [
        (
            "current-use-" + item["model"],
            _serializable(fixture["currentRequestsByModel"][item["model"]]),
            _serializable(factory.replay_dependencies(
                fixture["currentRequestsByModel"][item["model"]]
            )),
            _serializable(factory.replay_config(
                fixture["currentRequestsByModel"][item["model"]]
            )),
            {
                "name": "current-use-" + item["model"],
                "source": "settlement-finality-verification.json#dacs5.strongBundleCases",
                "model": item["model"],
                "expected": "pass",
                "finalityClass": item["finalityClass"],
                "currency": item["currency"],
            },
            factory.replay_context(fixture["currentRequestsByModel"][item["model"]]),
            _serializable(factory.replay_keys()),
        )
        for item in expectations
    ] + [
        (
            "historical-original-bundle-binding",
            historical[0],
            _serializable(factory.replay_dependencies(
                fixture["historicalRequests"][0]
            )),
            _serializable(factory.replay_config(fixture["historicalRequests"][0])),
            {
                "name": "historical-original-bundle-binding",
                "mappingKind": "binding",
                "expected": "pass",
            },
            factory.replay_context(fixture["historicalRequests"][0]),
            _serializable(factory.replay_keys()),
        ),
        (
            "historical-original-pure-mapping",
            historical[1],
            _serializable(factory.replay_dependencies(
                fixture["historicalRequests"][1]
            )),
            _serializable(factory.replay_config(fixture["historicalRequests"][1])),
            {
                "name": "historical-original-pure-mapping",
                "mappingKind": "pure",
                "expected": "pass",
            },
            factory.replay_context(fixture["historicalRequests"][1]),
            _serializable(factory.replay_keys()),
        ),
    ]
    vectors = []
    for _name, request, dependencies, verifier_config, expected, context, keys in replay_inputs:
        vector = dict(expected)
        vector["replay"] = {
            "request": request,
            "dependencies": dependencies,
            "verifierConfig": verifier_config,
            "trustedContext": context,
            "verificationKeys": keys,
            "query": {
                "party": CLAIMS["buyer"],
                "windowStart": FIXTURE_QUERY_WINDOW[0],
                "windowEnd": FIXTURE_QUERY_WINDOW[1],
                "windowingBasis": "finalisedAt",
            },
        }
        vectors.append(vector)
    return {
        "set": "current-use-reputation-v1",
        "spec": "DACS-5 unallocated current-use candidate §10.4 LAB-1..LAB-7 and §10.5.1 CUR-1..CUR-8",
        "status": "candidate-unallocated-stage-minor",
        "fixturePolicy": (
            "Synthetic signed native proofs for offline conformance only; no production Demos "
            "native cryptographic codec is claimed. Trust roots are verifier configuration."
        ),
        "replayPolicy": (
            "Every vector embeds the complete executable replay input: the exact "
            "request, its full authenticated dependency closure, the verifier "
            "configuration with public keys, the trusted query context, and the "
            "expected outcome. The set hash is computed over these complete replay "
            "inputs; mutating any authority, receipt, finality, or "
            "historical-evidence member of the bound payload yields a non-pass."
        ),
        "count": len(vectors),
        "hash": hashlib.sha256(canonical(vectors)).hexdigest(),
        "vectors": vectors,
    }


def rendered() -> str:
    return json.dumps(document(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
            print(f"stale generated corpus: {OUTPUT}")
            return 1
        print(f"ok: {OUTPUT}")
        return 0
    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
