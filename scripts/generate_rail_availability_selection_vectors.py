#!/usr/bin/env python3
"""Generate the executable DACS-4 rail-availability candidate vectors."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jcs import canonicalize as jcs_canonicalize


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT
    / "conformance"
    / "vectors"
    / "security"
    / "rail-availability-selection-v0.1.json"
)
DOMAIN = "dacs-rail:v1:"
STEWARD_SEED = hashlib.sha256(
    b"DACS rail availability vector steward v1"
).digest()
ATTACKER_SEED = hashlib.sha256(
    b"DACS rail availability vector attacker v1"
).digest()
PRODUCTION_UNSET = object()
STEWARD_CLAIM = "did:demos:agent:" + "11" * 32
ATTACKER_CLAIM = "did:demos:agent:" + "22" * 32


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def public_base64url(key: Ed25519PrivateKey) -> str:
    return base64url(key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))


def unsigned_rail(rail: dict) -> dict:
    """Return the normative RailDefinition signed scope (signature omitted only)."""
    return {key: value for key, value in rail.items() if key != "signature"}


def rail_digest(rail: dict) -> str:
    return hashlib.sha256(
        jcs_canonicalize(unsigned_rail(rail)).encode("utf-8")
    ).hexdigest()


def sign_rail(rail_id: str, availability: str, version: int = 1, *, attacker=False):
    key = Ed25519PrivateKey.from_private_bytes(
        ATTACKER_SEED if attacker else STEWARD_SEED
    )
    rail = {
        "railVersion": version,
        "railId": rail_id,
        "railType": "x402",
        "asset": {
            "kind": "erc20",
            "chainId": 8453,
            "contract": "0x0000000000000000000000000000000000000001",
            "symbol": "USDC",
            "decimals": 6,
        },
        "network": {
            "kind": "x402-resource",
            "resourceBaseUrl": "https://seller.example/pay",
        },
        "phaseHandler": "pay-x402",
        "parameters": {"authorization": "eip-3009"},
        "availability": availability,
        "governance": {
            "proposedBy": STEWARD_CLAIM,
            "acceptedAt": version,
            "anchoring": "single-signer",
            **({"supersedes": version - 1} if version > 1 else {}),
        },
    }
    digest = rail_digest(rail)
    rail["signature"] = {
        "algorithm": "ed25519",
        "signer": ATTACKER_CLAIM if attacker else STEWARD_CLAIM,
        "value": base64url(key.sign((DOMAIN + digest).encode("ascii"))),
    }
    return rail


def context(
    rail: dict,
    *,
    preflight=False,
    session_state="new",
    production=True,
    pinned=True,
    steward=True,
    pinned_digest=None,
    hint=None,
    later_registry_rail=None,
    production_source="local-operator-policy",
    counterparty_production_hint=None,
):
    value = {
        "stewardClaim": STEWARD_CLAIM if steward else None,
        "stewardPublicKey": public_base64url(
            Ed25519PrivateKey.from_private_bytes(STEWARD_SEED)
        ) if steward else None,
        "operatorPreflightOk": preflight,
        "pinnedRailDigest": (
            pinned_digest if pinned_digest is not None
            else rail_digest(rail) if pinned else None
        ),
        "sessionState": session_state,
    }
    if production is not PRODUCTION_UNSET:
        value["operatorContext"] = {
            "source": production_source,
            "production": production,
        }
    if counterparty_production_hint is not None:
        value["counterpartyProductionHint"] = counterparty_production_hint
    if hint is not None:
        value["discoveryAvailabilityHint"] = hint
    if later_registry_rail is not None:
        value["laterRegistryRailDefinition"] = later_registry_rail
    return value


def vector(name, expected, note, rail, **ctx):
    return {
        "name": name,
        "expected": expected,
        "note": note,
        "rail": rail,
        "ctx": context(rail, **ctx),
    }


def build() -> dict:
    live_x402 = sign_rail("x402:default", "live")
    live_old = sign_rail("x402:revision-test", "live", 1)
    disabled = sign_rail("x402:revision-test", "disabled", 2)
    failed = sign_rail("x402:failure-test", "failed")
    mocked = sign_rail("x402:mock-test", "mocked")
    gated = sign_rail("x402:gated-test", "operator_gated")
    closed = sign_rail("x402:closed-test", "closed_data")
    bilateral = sign_rail("x402:bilateral-test", "bilateral")
    live_evm = sign_rail("x402:failure-test", "live")
    vectors = [
        vector("live-signed-pinned", "pass", "live, steward-signed and pinned is selectable", live_x402),
        vector("disabled-signed", "fail", "RAV-R2: disabled cannot start a new session", disabled),
        vector("disabled-signed-non-production", "fail", "RAV-R2: disabled cannot start a non-production session", disabled, production=False),
        vector("disabled-pinned-in-flight", "fail", "RAV-R2: an already-disabled definition is not a lawful in-flight pin", disabled, session_state="in-flight"),
        vector(
            "disabled-after-pin-in-flight",
            "pass",
            "RAV-R2: an in-flight session retains its pinned live definition after a later disabled revision",
            live_old,
            session_state="in-flight",
            later_registry_rail=disabled,
        ),
        vector("failed-signed", "fail", "RAV-R2: failed cannot start a new session", failed),
        vector("failed-signed-non-production", "fail", "RAV-R2: failed cannot start a non-production session", failed, production=False),
        vector("failed-pinned-in-flight", "fail", "RAV-R2: an already-failed definition is not a lawful in-flight pin", failed, session_state="in-flight"),
        vector("mocked-signed", "fail", "RAV-R2: mocked cannot be selected for production", mocked),
        vector("mocked-signed-non-production", "pass", "RAV-R2: mocked remains selectable for development or testing", mocked, production=False),
        vector("mocked-production-context-missing", "error", "production context is required before mocked selection", mocked, production=PRODUCTION_UNSET),
        vector("mocked-production-context-string", "error", "string production context cannot authorize mocked selection", mocked, production="true"),
        vector("mocked-production-context-integer", "error", "integer production context cannot authorize mocked selection", mocked, production=1),
        vector(
            "mocked-production-context-untrusted-source",
            "error",
            "counterparty-controlled context cannot establish non-production mode",
            mocked,
            production=False,
            production_source="counterparty",
        ),
        vector(
            "mocked-counterparty-non-production-override",
            "fail",
            "a counterparty hint cannot override trusted production mode",
            mocked,
            production=True,
            counterparty_production_hint=False,
        ),
        vector("operator_gated-no-preflight", "fail", "RAV-R3: operator_gated requires operator preflight", gated),
        vector("operator_gated-with-preflight", "pass", "RAV-R3: operator_gated with preflight is selectable", gated, preflight=True),
        vector("closed_data-no-preflight", "fail", "RAV-R3: closed_data requires operator preflight", closed),
        vector("bilateral-with-preflight", "pass", "RAV-R3: bilateral with preflight is selectable", bilateral, preflight=True),
        vector("poison-live-bad-signer", "fail", "RAV-R5: attacker-signed live value is not authoritative", sign_rail("x402:failure-test", "live", attacker=True)),
        vector("poison-live-unsigned", "fail", "RAV-R5: unsigned live value is not authoritative", unsigned_rail(live_evm)),
        vector(
            "stale-cached-signed-copy",
            "fail",
            "RAV-R5: a valid stale live definition cannot replace the pinned failed revision",
            live_evm,
            pinned_digest=rail_digest(sign_rail("x402:failure-test", "failed", 2)),
        ),
        vector("steward-key-unresolvable", "indeterminate", "RAV-R5: unavailable steward authority is indeterminate", live_x402, steward=False),
        vector("no-pin-context-signed-live", "indeterminate", "RAV-R5: a signed copy without an authoritative pin is indeterminate", live_x402, pinned=False, hint="live"),
        vector(
            "mirror-live-hint-authoritative-failed",
            "fail",
            "LRR-6/RAV-R5: a live discovery hint cannot override authoritative failed",
            failed,
            hint="live",
        ),
        vector(
            "mirror-failed-hint-authoritative-live",
            "pass",
            "LRR-6/RAV-R5: a failed discovery hint cannot override authoritative live",
            live_evm,
            hint="failed",
        ),
        vector(
            "malformed-rail",
            "error",
            "missing availability and railVersion is malformed",
            {"railId": "x402:default"},
            pinned_digest="00" * 32,
        ),
        vector(
            "unknown-availability-value",
            "error",
            "an unknown availability value is malformed",
            sign_rail("x402:default", "experimental"),
        ),
    ]
    return {
        "set": "rail-availability-selection-v0.1",
        "spec": "DACS-4 §9.4.4 (RAV-R1/R2/R3/R5); DACS-1 §6.3.4 (LRR-6)",
        "gaps": ["#13 rail-availability-poisoning", "#325 executable availability gate"],
        "decisionModel": "§7.5.1 4-value, never collapsed",
        "fixtureProfile": {
            "purpose": "availability decision with complete RailDefinition authentication",
            "signedScope": "complete RailDefinition with only signature omitted; unknown members preserved",
            "canonicalization": "RFC 8785 JCS via scripts/jcs.py",
            "digest": "sha256(canonical complete unsigned RailDefinition)",
            "signature": "RailSignature.algorithm=ed25519; value is unpadded Base64URL Ed25519(dacs-rail:v1: || lowercase-hex digest)",
            "productionContext": "trusted local-operator-policy input; counterparty and discovery hints are non-authoritative",
            "generator": "scripts/generate_rail_availability_selection_vectors.py",
        },
        "hash": hashlib.sha256(canonical_bytes(vectors)).hexdigest(),
        "count": len(vectors),
        "vectors": vectors,
    }


def rendered() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    want = rendered()
    if args.write:
        OUTPUT.write_text(want, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != want:
            print(f"ERROR: {OUTPUT.relative_to(ROOT)} is stale; run this script with --write")
            return 1
        print("rail-availability vectors are deterministic and current")
        return 0
    print(want, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
