#!/usr/bin/env python3
"""Run the dependency-free DACS v0.1 minimum-conformant walkthrough.

The walkthrough intentionally binds to repository fixtures rather than an SDK.
It verifies the current five-stage happy-path artifacts, exposes their canonical
and signing bytes, exercises a fake SR-2 adapter, and runs five deterministic
negative examples.  The emitted trace is byte-pinned for CI.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "spec" / "PROFILE.md"
MANIFEST = ROOT / "conformance" / "MANIFEST.json"
HAPPY_PATH = ROOT / "conformance" / "vectors" / "dacs-v0.1-happy-path.json"
SB2_VECTORS = ROOT / "conformance" / "vectors" / "security" / "sb2-settlement-uniqueness-v0.1.json"
BUYER_BUNDLE = ROOT / "conformance" / "fixtures" / "attestation-bundle-0004.json"
SELLER_BUNDLE = ROOT / "conformance" / "fixtures" / "attestation-bundle-0004-seller.json"
GOLDEN = ROOT / "conformance" / "vectors" / "golden.json"
PINS = ROOT / "conformance" / "walkthrough" / "PINS.json"

STAGES = ["DACS-1", "DACS-2", "DACS-3", "DACS-4", "DACS-5"]
STAGE_LINKS = {
    "DACS-1": {
        "operation": "Identify",
        "rules": ["BP-1", "BP-2", "BP-3", "BP-4", "SIG-1", "SIG-2"],
        "vectorIds": ["sig-roundtrip", "dacs1-siwd-resource-binding"],
    },
    "DACS-2": {
        "operation": "Vet",
        "rules": ["CM-1", "CM-2", "CM-3", "CM-4", "CM-5", "VPC-3"],
        "vectorIds": ["vet-ma3-verified-accept", "cf4-dacs2-composite-address"],
    },
    "DACS-3": {
        "operation": "Negotiate",
        "rules": ["PS-1", "PS-2", "PS-3", "CA-1", "CA-4"],
        "vectorIds": ["neg-band-inclusive", "neg-priceanchor-absent-ok"],
    },
    "DACS-4": {
        "operation": "Settle",
        "rules": ["PC-1", "PC-2", "PC-3", "PC-6", "SB-1", "SB-2"],
        "vectorIds": ["settlement-payment-pass"],
    },
    "DACS-5": {
        "operation": "Verify",
        "rules": ["ST-1", "ST-2", "ST-4", "ST-6", "SIG-1", "SIG-2"],
        "vectorIds": ["bundle-0004-pass", "verify-consume-unified"],
    },
}


def canonical_json(value: Any) -> bytes:
    """Canonical bytes for the integer/string-only repository fixtures."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_hex(path.read_bytes())


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def decode_b64(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(padded, altchars=b"-_")


# Dependency-free Ed25519 verification for the public conformance keys.  These
# affine RFC 8032 formulas are deliberately verification-only: no private key
# material or signing path is part of the walkthrough.
Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, Q - 2, Q)) % Q
I = pow(2, (Q - 1) // 4, Q)


def x_recover(y: int) -> int:
    xx = ((y * y - 1) * pow(D * y * y + 1, Q - 2, Q)) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = (x * I) % Q
    if (x * x - xx) % Q != 0:
        raise ValueError("point is not on the Ed25519 curve")
    return Q - x if x & 1 else x


BASE_Y = (4 * pow(5, Q - 2, Q)) % Q
BASE = (x_recover(BASE_Y), BASE_Y)


def point_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = (D * x1 * x2 * y1 * y2) % Q
    x3 = ((x1 * y2 + x2 * y1) * pow(1 + product, Q - 2, Q)) % Q
    y3 = ((y1 * y2 + x1 * x2) * pow(1 - product, Q - 2, Q)) % Q
    return x3, y3


def scalar_mult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def decode_point(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("Ed25519 point must be 32 bytes")
    raw = int.from_bytes(encoded, "little")
    y = raw & ((1 << 255) - 1)
    if y >= Q:
        raise ValueError("non-canonical Ed25519 point")
    x = x_recover(y)
    if (x & 1) != (raw >> 255):
        x = Q - x
    if (-x * x + y * y - 1 - D * x * x * y * y) % Q != 0:
        raise ValueError("point is not on the Ed25519 curve")
    return x, y


def verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= L:
        return False
    try:
        encoded_r = signature[:32]
        point_r = decode_point(encoded_r)
        point_a = decode_point(public_key)
    except ValueError:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(),
        "little",
    ) % L
    return scalar_mult(BASE, scalar) == point_add(
        point_r,
        scalar_mult(point_a, challenge),
    )


class FakeSubstrate:
    """Small deterministic SR-2/settlement adapter; never calls a live SDK."""

    def __init__(self) -> None:
        self.anchors: dict[str, bytes] = {}
        self.settlement_claims: dict[str, tuple[str, int]] = {}

    def write(self, address: str, value: bytes) -> None:
        prior = self.anchors.get(address)
        if prior is not None and prior != value:
            raise ValueError(f"immutable anchor collision at {address}")
        self.anchors[address] = value

    def read(self, address: str) -> bytes | None:
        return self.anchors.get(address)

    def claim_settlement(self, tx_id: str, job_id: str, phase_index: int) -> str:
        binding = (job_id, phase_index)
        prior = self.settlement_claims.get(tx_id)
        if prior is None:
            self.settlement_claims[tx_id] = binding
            return "count"
        if prior == binding:
            return "already-counted"
        return "reject"


def signing_scope(kind: str, artifact: dict[str, Any]) -> dict[str, Any]:
    omitted = {"signatures"} if "signatures" in artifact else {"signature"}
    if kind == "AttestationBundle":
        omitted.add("anchoredByRole")
    return {key: value for key, value in artifact.items() if key not in omitted}


def signature_entries(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    if "signature" in artifact:
        return [artifact["signature"]]
    return artifact.get("signatures", [])


def key_from_cci(signer: str) -> bytes:
    scheme, identifier = signer.split(":", 1)
    if scheme != "cci" or not re.fullmatch(r"[0-9a-f]{64}", identifier):
        raise ValueError(f"walkthrough cannot resolve fixture signer {signer!r}")
    return bytes.fromhex(identifier)


def verify_signatures(
    artifact: dict[str, Any],
    domain: str,
    artifact_hash: str,
) -> list[dict[str, Any]]:
    payload = (domain + artifact_hash).encode("ascii")
    results = []
    for signature in signature_entries(artifact):
        signer = signature.get("signer") or signature.get("party")
        results.append(
            {
                "signer": signer,
                "algorithm": signature["algorithm"],
                "value": signature["value"],
                "verified": verify_ed25519(
                    key_from_cci(signer),
                    decode_b64(signature["value"]),
                    payload,
                ),
            }
        )
    return results


def verify_identity_presentation(listing: dict[str, Any]) -> dict[str, Any]:
    identity = listing["seller"]["identity"]
    scope = {key: value for key, value in identity.items() if key != "presentation"}
    artifact_hash = sha256_hex(canonical_json(scope))
    signature = identity["presentation"]["signatures"][0]
    signer = signature["ref"]
    payload = ("dacs-bundle-presentation:v1:" + artifact_hash).encode("ascii")
    return {
        "signer": signer,
        "domainSeparator": "dacs-bundle-presentation:v1:",
        "artifactHash": artifact_hash,
        "signaturePayload": payload.decode("ascii"),
        "verified": verify_ed25519(
            key_from_cci(signer),
            decode_b64(signature["signature"]),
            payload,
        ),
    }


def anchor_address(stage: str, artifact_id: str, artifact: dict[str, Any]) -> str:
    if stage == "DACS-5":
        material = artifact["jobId"] + "-bundle-" + artifact["anchoredByRole"]
    else:
        material = f"{artifact.get('jobId', artifact.get('listingId', 'dacs-v0.1'))}:{stage}:{artifact_id}"
    return "stor-" + sha256_hex(material.encode("utf-8"))


def build_stage_trace(
    wrapper: dict[str, Any],
    substrate: FakeSubstrate,
) -> dict[str, Any]:
    stage = wrapper["stage"]
    artifact = wrapper["artifact"]
    canonical = canonical_json(artifact)
    vector_hash = "sha256:" + sha256_hex(canonical)
    if vector_hash != wrapper["contentHash"]:
        raise ValueError(f"{wrapper['id']}: vector content hash drift")

    scope = signing_scope(wrapper["kind"], artifact)
    signing_bytes = canonical_json(scope)
    artifact_hash = sha256_hex(signing_bytes)
    signature_payload = wrapper["domainSeparator"] + artifact_hash
    signatures = verify_signatures(
        artifact,
        wrapper["domainSeparator"],
        artifact_hash,
    )
    if not signatures or not all(item["verified"] for item in signatures):
        raise ValueError(f"{wrapper['id']}: signature verification failed")

    address = anchor_address(stage, wrapper["id"], artifact)
    substrate.write(address, canonical)
    if substrate.read(address) != canonical:
        raise ValueError(f"{wrapper['id']}: fake substrate round-trip failed")

    result = {
        "stage": stage,
        "operation": STAGE_LINKS[stage]["operation"],
        "artifactId": wrapper["id"],
        "kind": wrapper["kind"],
        "rules": STAGE_LINKS[stage]["rules"],
        "vectorIds": STAGE_LINKS[stage]["vectorIds"],
        "artifact": artifact,
        "canonicalBytes": canonical.decode("utf-8"),
        "vectorContentHash": vector_hash,
        "signingCanonicalBytes": signing_bytes.decode("utf-8"),
        "artifactHash": artifact_hash,
        "domainSeparator": wrapper["domainSeparator"],
        "signaturePayload": signature_payload,
        "signatureResults": signatures,
        "attestationRef": {
            "anchor": {"kind": "storage-program", "locator": address},
            "contentHash": artifact_hash,
        },
        "anchorRoundTrip": True,
    }
    if stage == "DACS-1":
        presentation = verify_identity_presentation(artifact)
        if not presentation["verified"]:
            raise ValueError("seller IdentityBundle presentation did not verify")
        result["identityPresentation"] = presentation
    return result


def settlement_tx_id(record: dict[str, Any]) -> str:
    ref = record["settlementRef"]
    if ref["rail"] != "evm":
        raise ValueError("minimum walkthrough expects the EVM SB-2 vector")
    tx_hash = ref["txHash"].removeprefix("0x").lower()
    return f"evm:{ref['chainId']}:{tx_hash}:{ref['logIndex']}"


def malformed_identity_case(listing: dict[str, Any]) -> dict[str, Any]:
    identity = copy.deepcopy(listing["seller"]["identity"])
    identity["claims"] = "not-an-array"
    rejected = not isinstance(identity.get("claims"), list)
    return {
        "id": "malformed-identity",
        "mutation": "IdentityBundle.claims is a string instead of an array",
        "rules": ["BR-1", "VPC-4"],
        "vectorIds": ["vet-counterparty-malformed-attribution"],
        "expected": "reject-counterparty",
        "observed": "reject-counterparty" if rejected else "accepted",
        "passed": rejected,
    }


def outside_policy_case(listing: dict[str, Any], agreement: dict[str, Any]) -> dict[str, Any]:
    candidate = copy.deepcopy(agreement)
    candidate["terms"]["rail"]["railId"] = "evm-erc20:1:UNLISTED"
    accepted = {rail["railId"] for rail in listing["acceptedRails"]}
    rejected = candidate["terms"]["rail"]["railId"] not in accepted
    return {
        "id": "agreement-outside-listing-policy",
        "mutation": "AgreementDocument selects a rail absent from Listing.acceptedRails",
        "rules": ["RFQ-3", "CA-1", "§8.5.2 check 3"],
        "vectorIds": ["neg-rail-reject"],
        "expected": "reject-before-settle",
        "observed": "reject-before-settle" if rejected else "accepted",
        "passed": rejected,
    }


def duplicate_settlement_case(substrate: FakeSubstrate) -> dict[str, Any]:
    vectors = load_json(SB2_VECTORS)["vectors"]
    first = next(item for item in vectors if item["name"] == "first-claim-evm")["record"]
    duplicate = next(
        item for item in vectors if item["name"] == "cross-session-double-count"
    )["record"]
    tx_id = settlement_tx_id(first)
    first_result = substrate.claim_settlement(tx_id, first["jobId"], first["phaseIndex"])
    duplicate_result = substrate.claim_settlement(
        settlement_tx_id(duplicate),
        duplicate["jobId"],
        duplicate["phaseIndex"],
    )
    passed = first_result == "count" and duplicate_result == "reject"
    return {
        "id": "duplicate-settlement-transaction-id",
        "mutation": "one canonical settlement-tx-id is rebound to a second jobId",
        "rules": ["SB-1", "SB-2"],
        "vectorIds": ["sb2-settlement-uniqueness-v0.1#cross-session-double-count"],
        "settlementTxId": tx_id,
        "expected": "reject-later-binding",
        "observed": "reject-later-binding" if passed else duplicate_result,
        "passed": passed,
    }


def delivery_failure_case(stage_traces: list[dict[str, Any]]) -> dict[str, Any]:
    payment = next(item for item in stage_traces if item["stage"] == "DACS-4")
    payment_succeeded = payment["artifact"]["outcome"] == "success" and payment["anchorRoundTrip"]
    deliverable = None
    delivery_ok = isinstance(deliverable, bytes) and bool(deliverable)
    observed = "failed-counterparty" if payment_succeeded and not delivery_ok else "completed"
    return {
        "id": "delivery-failure-after-payment",
        "mutation": "fake deliver adapter returns no deliverable after successful payment",
        "rules": ["PIPE-3", "ST-2"],
        "vectorIds": ["settlement-delivery-missing-deliverable-fail"],
        "paymentRemainsRecorded": payment_succeeded,
        "expected": "failed-counterparty",
        "observed": observed,
        "passed": observed == "failed-counterparty",
    }


def bundle_hash(bundle: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(signing_scope("AttestationBundle", bundle)))


def verify_did_bundle(bundle: dict[str, Any], public_keys: dict[str, bytes]) -> list[dict[str, Any]]:
    digest = bundle_hash(bundle)
    payload = ("dacs-bundle:v1:" + digest).encode("ascii")
    return [
        {
            "signer": signature["party"],
            "verified": verify_ed25519(
                public_keys[signature["party"]],
                decode_b64(signature["value"]),
                payload,
            ),
        }
        for signature in bundle["signatures"]
    ]


def divergent_bundle_case(substrate: FakeSubstrate) -> dict[str, Any]:
    buyer = load_json(BUYER_BUNDLE)
    seller = load_json(SELLER_BUNDLE)
    golden_keys = load_json(GOLDEN)["bundle"]["publicKeys"]
    public_keys = {signer: decode_b64(key) for signer, key in golden_keys.items()}
    buyer_results = verify_did_bundle(buyer, public_keys)
    seller_results = verify_did_bundle(seller, public_keys)
    for bundle in (buyer, seller):
        address = anchor_address("DACS-5", "divergence-case", bundle)
        substrate.write(address, canonical_json(bundle))
    valid = all(item["verified"] for item in buyer_results + seller_results)
    divergent = (
        buyer["jobId"] == seller["jobId"]
        and (
            buyer["outcome"] != seller["outcome"]
            or bundle_hash(buyer) != bundle_hash(seller)
        )
    )
    return {
        "id": "divergent-buyer-seller-bundles",
        "mutation": "independently valid role copies contradict on outcome and phase summary",
        "rules": ["§10.4.3(d)", "§10.5.1 guard (ii)"],
        "vectorIds": ["verify-consume-divergent"],
        "buyerBundleHash": bundle_hash(buyer),
        "sellerBundleHash": bundle_hash(seller),
        "signatureResults": {"buyerCopy": buyer_results, "sellerCopy": seller_results},
        "expected": "divergent-exclude-from-reputation",
        "observed": "divergent-exclude-from-reputation" if valid and divergent else "invalid",
        "passed": valid and divergent,
    }


def parse_profile_versions(profile_text: str) -> dict[str, str]:
    rows = re.findall(r"\| \[([^]]+)\]\([^)]+\) \| ([0-9.]+) \|", profile_text)
    return dict(rows)


def validate_links(manifest: dict[str, Any]) -> None:
    manifest_ids = {case["id"] for case in manifest["cases"]}
    required = {
        vector_id
        for links in STAGE_LINKS.values()
        for vector_id in links["vectorIds"]
    }
    required.update(
        {
            "vet-counterparty-malformed-attribution",
            "neg-rail-reject",
            "settlement-delivery-missing-deliverable-fail",
            "verify-consume-divergent",
        }
    )
    missing = sorted(required - manifest_ids)
    if missing:
        raise ValueError("walkthrough links missing manifest vector IDs: " + ", ".join(missing))

    sb2 = load_json(SB2_VECTORS)
    if not any(item["name"] == "cross-session-double-count" for item in sb2["vectors"]):
        raise ValueError("SB-2 cross-session-double-count vector is missing")


def build_trace() -> dict[str, Any]:
    profile_versions = parse_profile_versions(PROFILE.read_text(encoding="utf-8"))
    manifest = load_json(MANIFEST)
    vector = load_json(HAPPY_PATH)
    if list(profile_versions) != [
        "CORE",
        "DACS-1-IDENTIFY",
        "DACS-2-VET",
        "DACS-3-NEGOTIATE",
        "DACS-4-SETTLE",
        "DACS-5-VERIFY",
    ]:
        raise ValueError("spec/PROFILE.md no longer pins the expected v0.1 document set")
    if set(profile_versions.values()) != {"0.1"}:
        raise ValueError("minimum walkthrough only targets the DACS v0.1 profile")
    if manifest["dacsVersion"] != "0.1" or vector["dacsVersion"] != "0.1":
        raise ValueError("profile, manifest, and lifecycle vector versions disagree")
    validate_links(manifest)

    substrate = FakeSubstrate()
    stages = [build_stage_trace(wrapper, substrate) for wrapper in vector["artifacts"]]
    if [item["stage"] for item in stages] != STAGES:
        raise ValueError("happy-path vector no longer covers the five stages in order")

    listing = stages[0]["artifact"]
    agreement = stages[2]["artifact"]
    negatives = [
        malformed_identity_case(listing),
        outside_policy_case(listing, agreement),
        duplicate_settlement_case(substrate),
        delivery_failure_case(stages),
        divergent_bundle_case(substrate),
    ]
    if not all(case["passed"] for case in negatives):
        raise ValueError("one or more deterministic negative examples did not reject/classify")

    return {
        "walkthroughVersion": "1",
        "status": "non-normative-reference-tooling",
        "profile": {
            "path": "spec/PROFILE.md",
            "dacsVersion": "0.1",
            "documents": profile_versions,
            "sha256": file_sha256(PROFILE),
        },
        "manifest": {
            "path": "conformance/MANIFEST.json",
            "dacsVersion": manifest["dacsVersion"],
            "caseCount": len(manifest["cases"]),
            "sha256": file_sha256(MANIFEST),
        },
        "sourceVector": {
            "path": "conformance/vectors/dacs-v0.1-happy-path.json",
            "vectorId": vector["vectorId"],
            "sha256": file_sha256(HAPPY_PATH),
        },
        "substrate": {
            "adapter": "FakeSubstrate",
            "liveSdkCalls": False,
            "operationalFollowUps": [
                "https://github.com/DACS-Agent-commerce/DACS-Standard/issues/212",
                "https://github.com/DACS-Agent-commerce/DACS-Standard/issues/242",
            ],
        },
        "stages": stages,
        "negativeExamples": negatives,
        "result": {
            "verifies": True,
            "stageCount": len(stages),
            "negativeCount": len(negatives),
            "anchoredObjectCount": len(substrate.anchors),
        },
    }


def computed_pins(trace: dict[str, Any]) -> dict[str, str]:
    return {
        "profileSha256": file_sha256(PROFILE),
        "manifestSha256": file_sha256(MANIFEST),
        "happyPathVectorSha256": file_sha256(HAPPY_PATH),
        "traceSha256": sha256_hex(canonical_json(trace)),
    }


def check_pins(trace: dict[str, Any]) -> None:
    expected = load_json(PINS)
    actual = computed_pins(trace)
    if expected != actual:
        lines = ["lifecycle walkthrough pin drift:"]
        for key in actual:
            if expected.get(key) != actual[key]:
                lines.append(f"- {key}: expected {expected.get(key)!r}, got {actual[key]!r}")
        raise ValueError("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate pins (the default)")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the complete trace (combine with --check to enforce pins)",
    )
    parser.add_argument(
        "--print-pins",
        action="store_true",
        help="print freshly computed pin values for an intentional fixture/profile update",
    )
    args = parser.parse_args(argv)
    try:
        trace = build_trace()
        if args.print_pins:
            print(json.dumps(computed_pins(trace), indent=2, sort_keys=True))
            return 0
        if args.check or not args.json:
            check_pins(trace)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(f"lifecycle walkthrough failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(trace, indent=2, ensure_ascii=False))
    else:
        print(
            "lifecycle walkthrough: PASS "
            f"({trace['result']['stageCount']} stages, "
            f"{trace['result']['negativeCount']} negative examples, "
            f"trace {computed_pins(trace)['traceSha256']})"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
