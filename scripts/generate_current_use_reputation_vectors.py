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
        CLAIMS,
        FINALITY_BUNDLE_DOMAIN,
        FixtureFactory,
    )
    from scripts.settlement_finality_reference import artifact_hash
    from tests.dacs5_reference import (
        BINDING_DOMAIN,
        BUNDLE_DOMAIN,
        CURRENT_USE_SYNTHETIC_ANCHOR_PROOF_DOMAIN,
        CURRENT_USE_SYNTHETIC_SETTLEMENT_BINDING_PROOF_DOMAIN,
        LEGACY_BUNDLE_CHECKPOINT_BINDING_DOMAIN,
        LEGACY_BUNDLE_CHECKPOINT_DOMAIN,
        LISTING_DOMAIN,
        RATING_DOMAIN,
        bundle_hash,
        current_use_synthetic_proof_hash,
        legacy_checkpoint_binding_hash,
        legacy_checkpoint_hash,
        legacy_checkpoint_logical_address,
        listing_hash,
        logical_address,
    )
except ImportError:
    from generate_settlement_finality_verification_vectors import (  # type: ignore
        CLAIMS,
        FINALITY_BUNDLE_DOMAIN,
        FixtureFactory,
    )
    from settlement_finality_reference import artifact_hash  # type: ignore
    from dacs5_reference import (  # type: ignore
        BINDING_DOMAIN,
        BUNDLE_DOMAIN,
        CURRENT_USE_SYNTHETIC_ANCHOR_PROOF_DOMAIN,
        CURRENT_USE_SYNTHETIC_SETTLEMENT_BINDING_PROOF_DOMAIN,
        LEGACY_BUNDLE_CHECKPOINT_BINDING_DOMAIN,
        LEGACY_BUNDLE_CHECKPOINT_DOMAIN,
        LISTING_DOMAIN,
        RATING_DOMAIN,
        bundle_hash,
        current_use_synthetic_proof_hash,
        legacy_checkpoint_binding_hash,
        legacy_checkpoint_hash,
        legacy_checkpoint_logical_address,
        listing_hash,
        logical_address,
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
        }
        public_keys = {
            signer: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            for signer, value in self.finality.trusted["partyKeys"].items()
        }
        public_keys[CLAIMS["steward"]] = self.finality.keys["steward"].public_key().public_bytes_raw()
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
        }
        self.checkpoints: dict[str, dict] = {}

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

    def bundle_binding(self, bundle: dict, role: str, label: str) -> dict:
        job_id = bundle["jobId"]
        binding = {
            "bindingVersion": "1",
            "jobId": job_id,
            "role": role,
            "logicalAddress": logical_address(job_id, role),
            "nativeAddress": "native-" + hashlib.sha256(label.encode("utf-8")).hexdigest(),
            "bundleContentHash": bundle_hash(bundle),
            "signer": CLAIMS[role],
            "signature": {},
        }
        self.sign_bundle_binding(binding, role)
        return binding

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
        roles = {}
        for role_index, role in enumerate(("buyer", "seller")):
            bundle = self._legacy_bundle(job_id, role, listing)
            digest = bundle_hash(bundle)
            self.dependencies["bundleAuthorityByContentHash"][digest] = {
                "listing": copy.deepcopy(listing),
            }
            logical = logical_address(job_id, role)
            if pure:
                native = pure_native(logical)
                original_mapping = {"kind": "pure", "logicalAddress": logical, "nativeAddress": native}
            else:
                original = self.bundle_binding(bundle, role, job_id + ":historical:" + role)
                native = original["nativeAddress"]
                original_mapping = {
                    "kind": "binding",
                    "binding": copy.deepcopy(original),
                    "selectionContext": {
                        "candidateBindings": [copy.deepcopy(original)],
                        "partyMap": {CLAIMS["buyer"]: "buyer", CLAIMS["seller"]: "seller"},
                        "budget": 8,
                    },
                }
            self.dependencies["bundlesByNativeAddress"][native] = bundle
            historical_receipt = self.anchor_proof(
                purpose="historical-bundle",
                substrate=substrate,
                subject_id=job_id,
                subject_role=role,
                logical=logical,
                native=native,
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
            current_receipt = self.anchor_proof(
                purpose="current-bundle",
                substrate=substrate,
                subject_id=job_id,
                subject_role=role,
                logical=logical,
                native=native,
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
                    "resolvedAddress": native,
                    "anchorReceipt": current_receipt,
                    "legacyEraEvidence": era,
                }
            else:
                current_binding = copy.deepcopy(original_mapping["binding"])
                roles[role] = {
                    "disposition": "present",
                    "mappingKind": "binding",
                    "selectionContext": {
                        "candidateBindings": [copy.deepcopy(current_binding)],
                        "partyMap": {CLAIMS["buyer"]: "buyer", CLAIMS["seller"]: "seller"},
                        "budget": 8,
                    },
                    "anchorReceiptsByNativeAddress": {native: current_receipt},
                    "legacyEraEvidenceByNativeAddress": {native: era},
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

    def current_finality_job(self, model: str, index: int) -> tuple[dict, dict]:
        case = self.finality.strong_bundle_case(model)
        bundle = case["bundle"]
        authority = case["authority"]
        candidate = next(iter(authority["finalityVerificationByCanonicalRef"].values()))
        agreement = candidate["agreement"]
        agreement_digest = artifact_hash(agreement, "signatures")
        agreement_ref = reference("agreement:" + model, agreement_digest)
        bundle["agreementRef"] = agreement_ref
        if model == "block-depth":
            rating, rating_ref = self._rating(bundle["jobId"])
            bundle["ratingRefs"] = [rating_ref]
            self.dependencies["ratingsByCanonicalRef"][canonical(rating_ref).decode("utf-8")] = rating
        self.finality.sign_bundle(bundle, FINALITY_BUNDLE_DOMAIN)
        digest = bundle_hash(bundle)
        self.dependencies["bundleAuthorityByContentHash"][digest] = authority
        self.dependencies["agreementsByCanonicalRef"][canonical(agreement_ref).decode("utf-8")] = agreement
        self.config["partyRolesByJob"][bundle["jobId"]] = {
            "buyer": CLAIMS["buyer"], "seller": CLAIMS["seller"],
        }
        roles = {}
        for role_index, role in enumerate(("buyer", "seller")):
            anchored = copy.deepcopy(bundle)
            anchored["anchoredByRole"] = role
            binding = self.bundle_binding(anchored, role, "current:" + model + ":" + role)
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

    def build(self) -> dict:
        historical = [
            self.historical_job("CUR-HIST-BINDING", pure=False),
            self.historical_job("CUR-HIST-PURE", pure=True),
        ]
        current = []
        expectations = []
        for index, model in enumerate(MODELS):
            request, expectation = self.current_finality_job(model, index)
            current.append(request)
            expectations.append(expectation)
        return {
            "historicalRequests": historical,
            "currentRequestsByModel": dict(zip(MODELS, current)),
            "expectations": expectations,
            "dependencies": self.dependencies,
            "verifierConfig": self.config,
        }


def _serializable(value: Any) -> Any:
    if isinstance(value, bytes):
        return b64u(value)
    if isinstance(value, dict):
        return {key: _serializable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serializable(item) for item in value]
    return value


def document() -> dict:
    fixture = CurrentUseFixtureFactory().build()
    historical = _serializable(fixture["historicalRequests"])
    expectations = fixture["expectations"]
    vectors = [
        {
            "name": "current-use-" + item["model"],
            "source": "settlement-finality-verification.json#dacs5.strongBundleCases",
            "model": item["model"],
            "expected": "pass",
            "finalityClass": item["finalityClass"],
            "currency": item["currency"],
        }
        for item in expectations
    ] + [
        {
            "name": "historical-original-bundle-binding",
            "mappingKind": "binding",
            "expected": "pass",
            "request": historical[0],
        },
        {
            "name": "historical-original-pure-mapping",
            "mappingKind": "pure",
            "expected": "pass",
            "request": historical[1],
        },
    ]
    return {
        "set": "current-use-reputation-v1",
        "spec": "DACS-5 unallocated current-use candidate §10.4 LAB-1..LAB-7 and §10.5.1 CUR-1..CUR-8",
        "status": "candidate-unallocated-stage-minor",
        "fixturePolicy": (
            "Synthetic signed native proofs for offline conformance only; no production Demos "
            "native cryptographic codec is claimed. Trust roots are verifier configuration."
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
