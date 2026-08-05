#!/usr/bin/env python3
"""Generate deterministic DCR/DGCR domain compatibility vectors."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "conformance" / "vectors" / "security" / "domain-claim-gcr-v0.4.json"
NOW = 1_800_000_000_000
MAX_AGE_MS = 31_536_000_000


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def account(private: Ed25519PrivateKey) -> str:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def proof_payload(private: Ed25519PrivateKey, host: str, address: str) -> str:
    message = f"dacs-domain:v1:{host}:{address}".encode()
    return "demos:dw2p:ed25519:" + private.sign(message).hex()


def metadata(host: str, private: Ed25519PrivateKey) -> dict:
    address = account(private)
    return {
        "context": "web2.domain",
        "hostname": host,
        "account": address,
        "proofUrl": f"https://{host}/.well-known/demos-cci.txt",
        "sourceTransaction": {
            "txHash": hashlib.sha256(f"gcr:{host}:{address}".encode()).hexdigest(),
            "blockNumber": 424242,
        },
        "recordedAt": NOW - 86_400_000,
    }


def signed_bundle(refs: list[str], md: dict, signer: Ed25519PrivateKey,
                  producer_version: str = "0.6") -> dict:
    unsigned = {
        "bundleVersion": "1",
        "producerDacs1Version": producer_version,
        "subject": "domain compatibility vector",
        "claims": [
            {"ref": ref, "metadata": {"demosGcrDomain": copy.deepcopy(md)}}
            for ref in refs
        ],
        "presentedBy": refs[0],
        "presentedAt": NOW - 1_000,
    }
    canonical = compact(unsigned)
    digest = hashlib.sha256(canonical).digest()
    signed = b"dacs-bundle-presentation:v1:" + digest
    return {
        "unsigned": unsigned,
        "canonicalHex": canonical.hex(),
        "contentHash": digest.hex(),
        "signingPublicKey": account(signer),
        "signature": signer.sign(signed).hex(),
    }


def case(name: str, expected: str, refs: list[str], md: dict, record: dict,
         signer: Ed25519PrivateKey, **extra: object) -> dict:
    producer_version = str(extra.pop("producerDacs1Version", "0.6"))
    registration_proof = str(extra.pop(
        "registrationProofPayload",
        proof_payload(key("dacs-275-domain-owner"), md["hostname"], md["account"]),
    ))
    value = {
        "name": name,
        "expected": expected,
        "artifact": signed_bundle(refs, md, signer, producer_version),
        "authoritativeGcr": copy.deepcopy(record),
        "registrationValidation": {
            "profile": "demos-web2-domain-v1",
            "proofPayload": registration_proof,
        },
        "sourceAvailable": True,
        "validationProfileAvailable": True,
        "requiredMethod": "demos-gcr-domain",
        "evaluatedAt": NOW,
        "recipeDefaultMaxAgeSec": MAX_AGE_MS // 1000,
    }
    value.update(extra)
    return value


def main() -> None:
    owner = key("dacs-275-domain-owner")
    other = key("dacs-275-other-account")
    host = "agent.example"
    md = metadata(host, owner)
    record = copy.deepcopy(md)
    vectors: list[dict] = []

    vectors.append(case("canonical-production", "pass", [f"domain:{host}"], md, record, owner,
                        want={"semanticClaims": [f"domain:{host}"], "freshControl": False}))

    idna_host = "xn--fa-hia.example"
    idna_md = metadata(idna_host, owner)
    vectors.append(case("unicode-idna-production", "pass", [f"domain:{idna_host}"], idna_md,
                        idna_md, owner, unicodeInput="faß.example",
                        want={"semanticClaims": [f"domain:{idna_host}"]}))

    legacy = case("legacy-alias-original-byte-preservation", "pass",
                  [f"web2:domain:{host}"], md, record, owner,
                  producerDacs1Version="0.5",
                  want={"semanticClaims": [f"domain:{host}"], "originalBytesPreserved": True})
    rewritten = copy.deepcopy(legacy["artifact"]["unsigned"])
    rewritten["claims"][0]["ref"] = f"domain:{host}"
    rewritten["presentedBy"] = f"domain:{host}"
    legacy["want"]["rewrittenContentHash"] = hashlib.sha256(compact(rewritten)).hexdigest()
    vectors.append(legacy)

    vectors.append(case("historical-alias-pair-deduplicates", "pass",
                        [f"domain:{host}", f"web2:domain:{host}"], md, record, owner,
                        producerDacs1Version="0.5",
                        want={"semanticClaims": [f"domain:{host}"], "tierGain": False,
                              "oneOfGain": False}))
    vectors.append(case("current-producer-dual-alias-rejected", "fail",
                        [f"domain:{host}", f"web2:domain:{host}"], md, record, owner))

    for name, ref in [
        ("scheme-is-not-a-host", "domain:https://agent.example"),
        ("port-is-not-a-host", "domain:agent.example:443"),
        ("terminal-dot-rejected", "domain:agent.example."),
        ("ip-literal-rejected", "domain:127.0.0.1"),
        ("wildcard-rejected", "domain:*.agent.example"),
        ("underscore-rejected", "domain:_agent.example"),
        ("credentials-rejected", "domain:user@agent.example"),
        ("path-rejected", "domain:agent.example/path"),
        ("query-rejected", "domain:agent.example?x=1"),
        ("fragment-rejected", "domain:agent.example#x"),
        ("surrounding-whitespace-rejected", "domain: agent.example"),
        ("empty-label-rejected", "domain:agent..example"),
        ("leading-hyphen-rejected", "domain:-agent.example"),
    ]:
        vectors.append(case(name, "error", [ref], md, record, owner))

    wrong_host = copy.deepcopy(md)
    wrong_host["hostname"] = "other.example"
    vectors.append(case("host-record-mismatch", "fail", [f"domain:{host}"], wrong_host, record, owner))

    wrong_account = copy.deepcopy(md)
    wrong_account["account"] = account(other)
    vectors.append(case("account-record-mismatch", "fail", [f"domain:{host}"], wrong_account, record, owner))

    vectors.append(case("gcr-unavailable-is-indeterminate", "indeterminate",
                        [f"domain:{host}"], md, record, owner, sourceAvailable=False))
    vectors.append(case("gcr-validation-profile-unavailable-is-indeterminate", "indeterminate",
                        [f"domain:{host}"], md, record, owner,
                        validationProfileAvailable=False))
    wrong_profile = case("different-resolved-validation-profile-fails", "fail",
                         [f"domain:{host}"], md, record, owner)
    wrong_profile["registrationValidation"]["profile"] = "demos-web2-domain-v0"
    vectors.append(wrong_profile)
    vectors.append(case("metadata-preserved-exactly", "pass", [f"domain:{host}"], md, record,
                        owner, want={"metadataEqualsAuthority": True}))
    vectors.append(case("persistent-proof-does-not-satisfy-fresh-control", "fail",
                        [f"domain:{host}"], md, record, owner,
                        requiredMethod="domain-tls-control"))

    expired = copy.deepcopy(md)
    expired["recordedAt"] = NOW - MAX_AGE_MS - 1
    expired_record = copy.deepcopy(expired)
    vectors.append(case("expired-persistent-evidence", "fail", [f"domain:{host}"], expired,
                        expired_record, owner))

    bad_url = copy.deepcopy(md)
    bad_url["proofUrl"] = f"https://{host}/other"
    vectors.append(case("proof-url-mismatch", "fail", [f"domain:{host}"], bad_url, bad_url,
                        owner))

    good_proof = proof_payload(owner, host, account(owner))
    bad_proof = good_proof[:-2] + ("00" if good_proof[-2:] != "00" else "01")
    vectors.append(case("registration-proof-signature-mismatch", "fail",
                        [f"domain:{host}"], md, record, owner,
                        registrationProofPayload=bad_proof))

    bad_source = copy.deepcopy(md)
    bad_source["sourceTransaction"]["txHash"] = "00" * 32
    vectors.append(case("source-transaction-mismatch", "fail", [f"domain:{host}"], bad_source,
                        record, owner))

    vectors.append(case("bundle-account-control-mismatch", "fail", [f"domain:{host}"], md,
                        record, other))

    output = {
        "set": "domain-claim-gcr-v0.4",
        "spec": "DACS-1 §6.3.1 DCR-1..DCR-8; DACS-2 §7.3.10 DGCR-1..DGCR-6",
        "tier": "candidate",
        "description": "Canonical domain production, permanent signature-preserving Demos alias reads, semantic deduplication, and persistent GCR verification with genuine deterministic Ed25519 proofs.",
        "provenance": {
            "issue": "DACS-Agent-commerce/DACS-Standard#275",
            "generator": "scripts/generate_domain_gcr_vectors.py",
        },
        "count": len(vectors),
        "hash": hashlib.sha256(compact(vectors)).hexdigest(),
        "vectors": vectors,
    }
    OUT.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(vectors)} vectors)")


if __name__ == "__main__":
    main()
