#!/usr/bin/env python3
"""Regenerate the #308 reference-bearing conformance fixtures.

The shared bundle/settlement fixtures predated the normative DACS-2 §7.5.2
``AttestationRef`` and DACS-4 §9.3 ``ChainTxRef`` shapes. This deterministic
generator:

* rewrites legacy ``{kind,id,contentHash}`` references to
  ``{anchor:{kind,locator},contentHash}``;
* rewrites the fixture transaction references to the applicable §9.3 union arm;
* re-hashes and re-signs every changed SettlementEvidence and DACS-5 bundle with
  the repository's published test seeds; and
* refreshes the pinned hashes in ``conformance/vectors/golden.json``,
  ``conformance/MANIFEST.json``, and the exact-case hash in
  ``artifact-reference-shapes-v0.1.json``.

Usage:
  python3 scripts/generate_artifact_reference_fixtures.py --write
  python3 scripts/generate_artifact_reference_fixtures.py --check
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance" / "MANIFEST.json"
GOLDEN = ROOT / "conformance" / "vectors" / "golden.json"
REFERENCE_CASES = (
    ROOT / "conformance" / "vectors" / "security"
    / "artifact-reference-shapes-v0.1.json"
)
PAYEE_BINDING = (
    ROOT / "conformance" / "vectors" / "security"
    / "payee-destination-binding-v0.1.json"
)
COMMITMENT_AUTHORITY = (
    ROOT / "conformance" / "vectors" / "security"
    / "commitment-anchor-authority-v0.3.json"
)

BUNDLE_FIXTURES = (
    ROOT / "conformance" / "fixtures" / "attestation-bundle-0004.json",
    ROOT / "conformance" / "fixtures" / "attestation-bundle-0004-seller.json",
    ROOT / "conformance" / "fixtures" / "attestation-bundle-htlc9.json",
    ROOT / "conformance" / "fixtures" / "session-bundle-one-sided.json",
    ROOT / "conformance" / "fixtures" / "session-bundles-presence.json",
    ROOT / "conformance" / "fixtures" / "session-bundles-reputation.json",
)
SETTLEMENT_FIXTURES = (
    ROOT / "conformance" / "fixtures" / "settlement-evidence-payment-success.json",
    ROOT / "conformance" / "fixtures" / "settlement-evidence-delivery-success.json",
    ROOT / "conformance" / "fixtures" / "settlement" / "htlc9-asymmetric.json",
)

SEEDS = {
    "buyer": "a1" * 32,
    "seller": "c3" * 32,
    "orchestrator": "e4" * 32,
    "commitment": "22" * 32,
}
ROLE_BY_CLAIM = {
    "did:demos:buyer": "buyer",
    "did:demos:seller": "seller",
    "did:demos:orchestrator": "orchestrator",
}


def canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def canonical_signature_value(value: str) -> str:
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_")
    return b64u(raw)


def keys():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return {
        role: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
        for role, seed in SEEDS.items()
    }


def normalize_attestation_ref(value):
    if not isinstance(value, dict):
        return value
    if (
        "anchor" not in value
        and isinstance(value.get("kind"), str)
        and value["kind"].startswith("dacs-")
        and isinstance(value.get("id"), str)
        and isinstance(value.get("contentHash"), str)
    ):
        out = {
            "anchor": {
                "kind": "storage-program",
                "locator": value["id"],
            },
            "contentHash": value["contentHash"],
        }
        if "signer" in value:
            out["signer"] = value["signer"]
        return out
    return value


def normalize_tx_ref(value):
    if not isinstance(value, dict):
        return value
    kind = value.get("kind")
    if kind in {"settlement", "settlement-fail"} and value.get("rail") == "demos-testnet":
        return {"kind": "demos", "txHash": value["txHash"]}
    if kind == "payment" and value.get("rail") == "polygon-amoy-usdc":
        return {"kind": "evm", "chainId": 80002, "txHash": value["txHash"]}
    if kind == "htlc-reveal" and "rail" in value:
        return {
            "kind": "htlc-reveal",
            "chainId": 80002,
            "contractAddress": "0x0000000000000000000000000000000000000308",
            "revealTxHash": value["txHash"],
        }
    if kind == "source-claim-unclaimed":
        # This describes the absence of a transaction, not a transaction
        # reference. The SettlementEvidence reason carries that state.
        return None
    if kind == "evm" and value.get("role") == "htlc-lock":
        return {
            "kind": "htlc-lock",
            "chainId": value["chainId"],
            "contractAddress": "0x0000000000000000000000000000000000000308",
            "lockTxHash": value["txHash"],
        }
    if kind == "solana":
        # The HTLC-9 prototype needs an explicit reveal semantic for the
        # DACS-X predicate. A generic Solana signature ref cannot express that
        # role, whereas the registered htlc-reveal arm can.
        return {
            "kind": "htlc-reveal",
            "chainId": 80002,
            "contractAddress": "0x0000000000000000000000000000000000000308",
            "revealTxHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        }
    return value


def normalize_tree(value):
    if isinstance(value, list):
        out = []
        for item in value:
            normalized = normalize_tree(item)
            if normalized is not None:
                out.append(normalized)
        return out
    if not isinstance(value, dict):
        return value

    value = normalize_attestation_ref(value)
    if "kind" in value:
        value = normalize_tx_ref(value)
        if value is None:
            return None

    out = {}
    for key, child in value.items():
        if value.get("evidenceVersion") == "1" and key == "phaseIndex":
            continue
        normalized = normalize_tree(child)
        if normalized is not None:
            out[key] = normalized
    return out


def bundle_hash(bundle) -> str:
    unsigned = {
        key: value
        for key, value in bundle.items()
        if key not in {"signatures", "anchoredByRole"}
    }
    return sha256_hex(unsigned)


def evidence_hash(evidence) -> str:
    return sha256_hex({key: value for key, value in evidence.items() if key != "signature"})


def resign_embedded(value, signing_keys) -> None:
    if isinstance(value, dict):
        if value.get("bundleVersion") == "1" or value.get("faultBundleVersion") == "1":
            domain = (
                "dacs-fault-bundle:v1:"
                if value.get("faultBundleVersion") == "1"
                else "dacs-bundle:v1:"
            )
            payload = (domain + bundle_hash(value)).encode("utf-8")
            for signature in value.get("signatures", []):
                role = ROLE_BY_CLAIM[signature["party"]]
                signature["value"] = b64u(signing_keys[role].sign(payload))
        for child in value.values():
            resign_embedded(child, signing_keys)
    elif isinstance(value, list):
        for child in value:
            resign_embedded(child, signing_keys)


def regenerate_bundle_fixture(data, signing_keys):
    out = normalize_tree(copy.deepcopy(data))
    resign_embedded(out, signing_keys)
    return out


def regenerate_settlement_fixture(data, signing_keys):
    out = normalize_tree(copy.deepcopy(data))
    evidence = out.get("evidence")
    if not isinstance(evidence, dict):
        # HTLC-9 is a provisional wrapper with a placeholder signature. It is
        # shape-only and has no deterministic signer key in the fixture.
        return out

    digest = evidence_hash(evidence)
    signer = evidence["signature"]["signer"]
    role = ROLE_BY_CLAIM[signer]
    payload = ("dacs-evidence:v1:" + digest).encode("utf-8")
    evidence["signature"]["value"] = b64u(signing_keys[role].sign(payload))
    out["evidenceHash"] = digest
    if isinstance(out.get("result"), dict):
        result = out["result"]
        if "attestationRef" in result:
            result["attestationRef"]["contentHash"] = digest
        if "txRefs" in result and "paymentTxRefs" in evidence:
            result["txRefs"] = copy.deepcopy(evidence["paymentTxRefs"])
    return out


def encoded(data) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def regenerate_all() -> dict[Path, str]:
    signing_keys = keys()
    outputs: dict[Path, str] = {}
    bundle_hashes: dict[str, str] = {}
    reputation_bundle_hashes: dict[str, str] = {}

    for path in BUNDLE_FIXTURES:
        data = json.loads(path.read_text(encoding="utf-8"))
        regenerated = regenerate_bundle_fixture(data, signing_keys)
        outputs[path] = encoded(regenerated)
        if path.name == "session-bundles-reputation.json":
            reputation_bundle_hashes = {
                bundle["jobId"]: bundle_hash(bundle)
                for bundle in regenerated["bundles"]
            }
        if path.name in {
            "attestation-bundle-0004.json",
            "attestation-bundle-0004-seller.json",
            "attestation-bundle-htlc9.json",
            "session-bundle-one-sided.json",
        }:
            bundle_hashes[path.name] = bundle_hash(regenerated)

    evidence_hashes: dict[str, str] = {}
    for path in SETTLEMENT_FIXTURES:
        data = json.loads(path.read_text(encoding="utf-8"))
        regenerated = regenerate_settlement_fixture(data, signing_keys)
        outputs[path] = encoded(regenerated)
        if isinstance(regenerated.get("evidenceHash"), str):
            evidence_hashes[path.name] = regenerated["evidenceHash"]

    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    golden["bundle"]["bundleHash"] = bundle_hashes["attestation-bundle-0004.json"]
    golden["bundle"]["divergentSeller"]["bundleHash"] = bundle_hashes[
        "attestation-bundle-0004-seller.json"
    ]
    golden["bundle"]["htlc9"]["bundleHash"] = bundle_hashes[
        "attestation-bundle-htlc9.json"
    ]
    golden["bundle"]["htlc9"]["settlementPhase"]["revealTxRef"] = (
        "polygon-amoy:0xreveal9c1a-htlc-reveal"
    )
    for section in ("dispute", "disclosure"):
        golden[section]["bundleRef"]["bundleHash"] = bundle_hashes[
            "attestation-bundle-0004.json"
        ]
        golden[section]["divergentBundleRefs"][0]["bundleHash"] = bundle_hashes[
            "attestation-bundle-0004.json"
        ]
        golden[section]["divergentBundleRefs"][1]["bundleHash"] = bundle_hashes[
            "attestation-bundle-0004-seller.json"
        ]
    golden["dispute"]["htlc9BundleRef"]["bundleHash"] = bundle_hashes[
        "attestation-bundle-htlc9.json"
    ]
    golden["settlement"]["evidenceHash"] = evidence_hashes[
        "settlement-evidence-payment-success.json"
    ]
    golden["settlement"]["deliveryEvidenceHash"] = evidence_hashes[
        "settlement-evidence-delivery-success.json"
    ]
    legacy_refs = golden["verify"]["legacyReputationCandidate"]["bundleRefs"]
    refreshed_refs = []
    for ref in legacy_refs:
        locator = ref.get("id") or ref["anchor"]["locator"]
        refreshed_refs.append({
            "anchor": {
                "kind": "storage-program",
                "locator": locator,
            },
            "contentHash": reputation_bundle_hashes[locator],
        })
    golden["verify"]["legacyReputationCandidate"]["bundleRefs"] = sorted(
        refreshed_refs, key=lambda ref: ref["contentHash"]
    )
    outputs[GOLDEN] = encoded(golden)

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    one_sided_case = next(
        case
        for case in manifest["cases"]
        if case["id"] == "verify-consume-one-sided"
    )
    one_sided_case["want"]["buyerHash"] = bundle_hashes[
        "session-bundle-one-sided.json"
    ]
    outputs[MANIFEST] = encoded(manifest)

    cases = json.loads(REFERENCE_CASES.read_text(encoding="utf-8"))
    cases["count"] = len(cases["vectors"])
    cases["hash"] = sha256_hex(cases["vectors"])
    outputs[REFERENCE_CASES] = encoded(cases)

    payee_binding = json.loads(PAYEE_BINDING.read_text(encoding="utf-8"))
    payee_binding.setdefault("provenance", {})["referenceShapePatch"] = (
        "DACS-Standard #308: upstream f32684f generator with AgreementParty."
        "vetRecordRef upgraded to DACS-2 §7.5.2 AttestationRef; agreement "
        "signatures re-emitted from the generator's published test JWKs and "
        "canonicalized to CORE SIG-6 unpadded Base64URL"
    )

    def canonicalize_signatures(value) -> None:
        if isinstance(value, dict):
            signatures = value.get("signatures")
            if isinstance(signatures, list):
                for signature in signatures:
                    if isinstance(signature, dict) and isinstance(signature.get("value"), str):
                        signature["value"] = canonical_signature_value(signature["value"])
            for child in value.values():
                canonicalize_signatures(child)
        elif isinstance(value, list):
            for child in value:
                canonicalize_signatures(child)

    canonicalize_signatures(payee_binding)
    payee_binding["hash"] = sha256_hex(payee_binding["vectors"])
    outputs[PAYEE_BINDING] = encoded(payee_binding)

    commitment = json.loads(COMMITMENT_AUTHORITY.read_text(encoding="utf-8"))
    source = payee_binding["vectors"][0]
    commitment["agreement"] = copy.deepcopy(source["agreement"])
    commitment["agreementHash"] = source["artifactHash"]
    commitment["commitmentRecord"]["agreementHash"] = source["artifactHash"]
    commitment["commitmentRecordHash"] = sha256_hex(commitment["commitmentRecord"])
    commitment_payload = (
        "dacs-commitment:v1:" + commitment["commitmentRecordHash"]
    ).encode("utf-8")
    commitment["commitmentSignature"]["value"] = b64u(
        signing_keys["commitment"].sign(commitment_payload)
    )
    commitment.setdefault("provenance", {})["referenceShapePatch"] = (
        "DACS-Standard #308: agreement refreshed from the regenerated "
        "payee-destination-binding AgreementDocument"
    )
    commitment["hash"] = sha256_hex(commitment["vectors"])
    outputs[COMMITMENT_AUTHORITY] = encoded(commitment)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()

    outputs = regenerate_all()
    stale = []
    for path, expected in outputs.items():
        current = path.read_text(encoding="utf-8")
        if current != expected:
            stale.append(path)
            if args.write:
                path.write_text(expected, encoding="utf-8")

    if args.check and stale:
        for path in stale:
            print(f"stale: {path.relative_to(ROOT)}", file=sys.stderr)
        return 1
    if args.write:
        print(f"regenerated {len(outputs)} reference-bearing fixture file(s)")
    else:
        print(f"OK — {len(outputs)} reference-bearing fixture file(s) are deterministic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
