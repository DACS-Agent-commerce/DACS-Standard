#!/usr/bin/env python3
"""Generate deterministic DCR/DGCR domain compatibility vectors."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
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
                  claim_metadata: list[dict] | None = None) -> dict:
    metadata_items = claim_metadata or [md for _ in refs]
    if len(metadata_items) != len(refs):
        raise ValueError("claim metadata must align one-to-one with claim refs")
    unsigned = {
        "bundleVersion": "1",
        "subject": "domain compatibility vector",
        "claims": [
            {"ref": ref, "metadata": {"demosGcrDomain": copy.deepcopy(claim_md)}}
            for ref, claim_md in zip(refs, metadata_items)
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
    claim_metadata = extra.pop("claimMetadata", None)
    registration_proof = str(extra.pop(
        "registrationProofPayload",
        proof_payload(key("dacs-275-domain-owner"), md["hostname"], md["account"]),
    ))
    value = {
        "name": name,
        "expected": expected,
        "artifact": signed_bundle(
            refs, md, signer,
            claim_metadata=claim_metadata if isinstance(claim_metadata, list) else None,
        ),
        "authoritativeGcr": copy.deepcopy(record),
        "registrationValidation": {
            "profile": "demos-web2-domain-v1",
            "proofPayload": registration_proof,
        },
        "sourceAvailable": True,
        "sourceAuthentication": {
            "inclusionProofCoversTransaction": True,
            "blockFinalized": True,
        },
        "writerAuthorization": {
            "authenticated": True,
            "writer": md["account"],
            "authorizedAccount": md["account"],
        },
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
                        conformanceOperation="produce-current",
                        want={"semanticClaims": [f"domain:{host}"], "freshControl": False}))

    # DCR-1 exact length boundaries: 63 octets per label and 253 octets for the
    # complete host are admitted; one octet beyond either bound is malformed.
    label_63_host = f"{'a' * 63}.example"
    label_63_md = metadata(label_63_host, owner)
    vectors.append(case(
        "label-length-63-boundary", "pass", [f"domain:{label_63_host}"],
        label_63_md, label_63_md, owner, ruleRefs=["DCR-1"],
        want={"semanticClaims": [f"domain:{label_63_host}"]},
    ))
    vectors.append(case(
        "label-length-64-rejected", "error", [f"domain:{'a' * 64}.example"],
        md, record, owner, ruleRefs=["DCR-1"],
    ))

    host_253 = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
    host_254 = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 62])
    assert len(host_253.encode()) == 253
    assert len(host_254.encode()) == 254
    host_253_md = metadata(host_253, owner)
    vectors.append(case(
        "hostname-length-253-boundary", "pass", [f"domain:{host_253}"],
        host_253_md, host_253_md, owner, ruleRefs=["DCR-1"],
        want={"semanticClaims": [f"domain:{host_253}"]},
    ))
    vectors.append(case(
        "hostname-length-254-rejected", "error", [f"domain:{host_254}"],
        md, record, owner, ruleRefs=["DCR-1"],
    ))

    vectors.append(case(
        "invalid-punycode-a-label-rejected", "error", ["domain:xn--0.example"],
        md, record, owner, ruleRefs=["DCR-1"],
    ))

    numeric_host = "1.2.3.4.5"
    numeric_md = metadata(numeric_host, owner)
    vectors.append(case(
        "all-numeric-non-ip-hostname", "pass", [f"domain:{numeric_host}"],
        numeric_md, numeric_md, owner, ruleRefs=["DCR-2"],
        want={"semanticClaims": [f"domain:{numeric_host}"]},
    ))

    idna_host = "xn--fa-hia.example"
    idna_md = metadata(idna_host, owner)
    vectors.append(case("unicode-idna-production", "pass", [f"domain:{idna_host}"], idna_md,
                        idna_md, owner, unicodeInput="faß.example",
                        want={"semanticClaims": [f"domain:{idna_host}"]}))

    vectors.append(case(
        "current-producer-u-label-rejected", "fail", ["domain:faß.example"],
        idna_md, idna_md, owner, conformanceOperation="produce-current",
        ruleRefs=["DCR-1"],
        want={"semanticClaims": [f"domain:{idna_host}"]},
    ))

    vectors.append(case(
        "current-producer-uppercase-host-rejected", "fail",
        ["domain:Agent.Example"], md, record, owner,
        conformanceOperation="produce-current", ruleRefs=["DCR-1"],
        want={"semanticClaims": [f"domain:{host}"]},
    ))

    for name, ref, expected_host in [
        ("reader-uppercase-domain-rejected-without-profile", "domain:Agent.Example", host),
        ("reader-u-label-domain-rejected-without-profile", "domain:faß.example", idna_host),
    ]:
        expected_md = idna_md if expected_host == idna_host else md
        vectors.append(case(
            name, "fail", [ref], expected_md, expected_md, owner,
            ruleRefs=["DCR-1"],
            want={"semanticClaims": [f"domain:{expected_host}"]},
        ))

    decomposed_input = "e\u0301xample.example"
    decomposed_host = "xn--xample-9ua.example"
    decomposed_md = metadata(decomposed_host, owner)
    vectors.append(case("legacy-decomposed-unicode-nfc-idna-read", "pass",
                        [f"web2:domain:{decomposed_input}"], decomposed_md, decomposed_md,
                        owner, unicodeInput=decomposed_input,
                        want={"semanticClaims": [f"domain:{decomposed_host}"],
                              "originalBytesPreserved": True}))

    vectors.append(case(
        "legacy-mixed-case-ascii-read", "pass", ["web2:domain:Agent.Example"],
        md, record, owner, ruleRefs=["DCR-4"],
        want={"semanticClaims": [f"domain:{host}"], "originalBytesPreserved": True},
    ))

    invalid_legacy = case(
        "legacy-mixed-case-invalid-signature-rejected-before-fold", "fail",
        ["web2:domain:Agent.Example"], md, record, owner,
        ruleRefs=["DCR-4"],
        want={"semanticClaims": []},
    )
    signature = bytearray.fromhex(invalid_legacy["artifact"]["signature"])
    signature[0] ^= 1
    invalid_legacy["artifact"]["signature"] = signature.hex()
    vectors.append(invalid_legacy)

    legacy = case("legacy-alias-original-byte-preservation", "pass",
                  [f"web2:domain:{host}"], md, record, owner,
                  want={"semanticClaims": [f"domain:{host}"], "originalBytesPreserved": True})
    rewritten = copy.deepcopy(legacy["artifact"]["unsigned"])
    rewritten["claims"][0]["ref"] = f"domain:{host}"
    rewritten["presentedBy"] = f"domain:{host}"
    legacy["want"]["rewrittenContentHash"] = hashlib.sha256(compact(rewritten)).hexdigest()
    vectors.append(legacy)

    vectors.append(case("historical-alias-pair-deduplicates", "pass",
                        [f"domain:{host}", f"web2:domain:{host}"], md, record, owner,
                        want={"semanticClaims": [f"domain:{host}"], "tierGain": False,
                              "oneOfGain": False}))

    other_host = "other-agent.example"
    other_md = metadata(other_host, owner)
    vectors.append(case(
        "distinct-hosts-remain-distinct", "pass",
        [f"domain:{host}", f"domain:{other_host}"], md, record, owner,
        claimMetadata=[md, other_md], evaluationScope="semantic-claim-set",
        ruleRefs=["DCR-5"],
        want={"semanticClaims": [f"domain:{host}", f"domain:{other_host}"]},
    ))
    vectors.append(case(
        "current-producer-dual-alias-rejected", "fail",
        [f"domain:{host}", f"web2:domain:{host}"], md, record, owner,
        conformanceOperation="produce-current", ruleRefs=["DCR-5"],
    ))
    vectors.append(case(
        "current-producer-dual-alias-with-mixed-case-rejected", "fail",
        [f"domain:{host}", "web2:domain:Agent.Example"], md, record, owner,
        conformanceOperation="produce-current", ruleRefs=["DCR-5"],
    ))
    vectors.append(case(
        "current-producer-single-legacy-alias-rejected", "fail",
        [f"web2:domain:{host}"], md, record, owner,
        conformanceOperation="produce-current", ruleRefs=["DCR-3"],
    ))
    vectors.append(case(
        "current-producer-single-mixed-case-legacy-alias-rejected", "fail",
        ["web2:domain:Agent.Example"], md, record, owner,
        conformanceOperation="produce-current", ruleRefs=["DCR-3"],
    ))

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
    vectors.append(case(
        "inclusion-proof-does-not-cover-transaction", "indeterminate",
        [f"domain:{host}"], md, record, owner, ruleRefs=["DGCR-1"],
        sourceAuthentication={
            "inclusionProofCoversTransaction": False,
            "blockFinalized": True,
        },
    ))
    vectors.append(case(
        "carrying-block-not-finalized", "indeterminate",
        [f"domain:{host}"], md, record, owner, ruleRefs=["DGCR-1"],
        sourceAuthentication={
            "inclusionProofCoversTransaction": True,
            "blockFinalized": False,
        },
    ))
    vectors.append(case("gcr-validation-profile-unavailable-is-indeterminate", "indeterminate",
                        [f"domain:{host}"], md, record, owner,
                        validationProfileAvailable=False))
    wrong_profile = case("different-resolved-validation-profile-fails", "fail",
                         [f"domain:{host}"], md, record, owner)
    wrong_profile["registrationValidation"]["profile"] = "demos-web2-domain-v0"
    vectors.append(wrong_profile)
    vectors.append(case("metadata-preserved-exactly", "pass", [f"domain:{host}"], md, record,
                        owner, want={"metadataEqualsAuthority": True}))

    node = key("dacs-332-node-writer")
    vectors.append(case(
        "authenticated-node-writer-for-bound-account", "pass",
        [f"domain:{host}"], md, record, owner, ruleRefs=["DGCR-2"],
        writerAuthorization={
            "authenticated": True,
            "writer": account(node),
            "authorizedAccount": md["account"],
        },
    ))
    vectors.append(case(
        "writer-not-authorized-for-bound-account", "fail",
        [f"domain:{host}"], md, record, owner, ruleRefs=["DGCR-2"],
        writerAuthorization={
            "authenticated": True,
            "writer": account(other),
            "authorizedAccount": account(other),
        },
    ))

    wrong_context = copy.deepcopy(md)
    wrong_context["context"] = "web2.other"
    vectors.append(case(
        "wrong-native-context-with-matching-record", "fail",
        [f"domain:{host}"], wrong_context, wrong_context, owner,
        ruleRefs=["DGCR-2"],
    ))
    vectors.append(case("persistent-proof-does-not-satisfy-fresh-control", "fail",
                        [f"domain:{host}"], md, record, owner,
                        requiredMethod="domain-tls-control"))

    expired = copy.deepcopy(md)
    expired["recordedAt"] = NOW - MAX_AGE_MS - 1
    expired_record = copy.deepcopy(expired)
    vectors.append(case("expired-persistent-evidence", "fail", [f"domain:{host}"], expired,
                        expired_record, owner))

    exact_window = case(
        "inclusion-time-window-exact", "pass", [f"domain:{host}"], md, record,
        owner, ruleRefs=["DGCR-4"], evaluatedAt=md["recordedAt"] + MAX_AGE_MS,
        reportedVerifyResult={
            "verifiedAt": md["recordedAt"],
            "fetchedAt": md["recordedAt"] + MAX_AGE_MS,
            "validUntil": md["recordedAt"] + MAX_AGE_MS,
        },
    )
    vectors.append(exact_window)
    vectors.append(case(
        "reissued-verified-at-cannot-refresh", "fail", [f"domain:{host}"], md,
        record, owner, ruleRefs=["DGCR-4"],
        reportedVerifyResult={
            "verifiedAt": md["recordedAt"] + 60_000,
            "fetchedAt": NOW,
            "validUntil": md["recordedAt"] + MAX_AGE_MS,
        },
    ))
    vectors.append(case(
        "valid-until-cannot-exceed-inclusion-window", "fail",
        [f"domain:{host}"], md, record, owner, ruleRefs=["DGCR-4"],
        reportedVerifyResult={
            "verifiedAt": md["recordedAt"],
            "fetchedAt": NOW,
            "validUntil": md["recordedAt"] + MAX_AGE_MS + 1,
        },
    ))

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

    sr1_positive = case(
        "authenticated-sr1-session-binding", "pass", [f"domain:{host}"], md,
        record, other, ruleRefs=["DCR-7"],
    )
    sr1_positive["authenticatedSr1Binding"] = {
        "authenticated": True,
        "account": md["account"],
        "sessionPublicKey": sr1_positive["artifact"]["signingPublicKey"],
        "boundPresentationHash": sr1_positive["artifact"]["contentHash"],
    }
    vectors.append(sr1_positive)

    sr1_unbound = case(
        "sr1-link-without-presentation-binding", "fail", [f"domain:{host}"], md,
        record, other, ruleRefs=["DCR-7"],
    )
    sr1_unbound["authenticatedSr1Binding"] = {
        "authenticated": True,
        "account": md["account"],
        "sessionPublicKey": sr1_unbound["artifact"]["signingPublicKey"],
    }
    vectors.append(sr1_unbound)

    sr1_replay = case(
        "sr1-link-bound-to-different-presentation", "fail",
        [f"domain:{host}"], md, record, other, ruleRefs=["DCR-7"],
    )
    sr1_replay["authenticatedSr1Binding"] = {
        "authenticated": True,
        "account": md["account"],
        "sessionPublicKey": sr1_replay["artifact"]["signingPublicKey"],
        "boundPresentationHash": "00" * 32,
    }
    vectors.append(sr1_replay)

    output = {
        "set": "domain-claim-gcr-v0.4",
        "spec": "DACS-1 §6.3.1 DCR-1..DCR-8; DACS-2 §7.3.10 DGCR-1..DGCR-6",
        "tier": "candidate",
        "description": "Canonical domain production, permanent signature-preserving Demos alias reads, semantic deduplication, and persistent GCR verification with genuine deterministic Ed25519 proofs.",
        "modelNotes": [
            "sourceAuthentication and writerAuthorization are resolved verifier inputs modelling DGCR-1/DGCR-2 substrate evidence; they are not new DACS wire artifacts.",
            "authenticatedSr1Binding models an already-authenticated SR-1 resolver result bound to the exact presentation; it is not a caller assertion.",
            "conformanceOperation=produce-current is a harness operation selecting producer-output conformance; it is not artifact data or a runtime reader input.",
            "Readers apply permanent alias compatibility from the verified bundleVersion and alias spelling alone; mutable deployment/profile state cannot reclassify retained bytes.",
            "evaluationScope=semantic-claim-set isolates DCR-5 identity-set processing before per-claim GCR evaluation.",
        ],
        "provenance": {
            "issue": "DACS-Agent-commerce/DACS-Standard#275",
            "coverageIssue": "DACS-Agent-commerce/DACS-Standard#332",
            "profileBoundaryIssue": "DACS-Agent-commerce/DACS-Standard#347",
            "generator": "scripts/generate_domain_gcr_vectors.py",
        },
        "count": len(vectors),
        "hash": hashlib.sha256(compact(vectors)).hexdigest(),
        "vectors": vectors,
    }
    rendered = json.dumps(output, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv[1:]:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != rendered:
            raise SystemExit(
                f"{OUT.relative_to(ROOT)} is stale; run "
                "python3 scripts/generate_domain_gcr_vectors.py"
            )
        print(f"{OUT.relative_to(ROOT)} is deterministic ({len(vectors)} vectors)")
        return
    OUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(vectors)} vectors)")


if __name__ == "__main__":
    main()
