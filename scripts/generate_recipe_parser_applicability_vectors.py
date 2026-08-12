#!/usr/bin/env python3
"""Generate DACS-2 v0.5 PRA-1..PRA-5 parser-applicability vectors."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "recipe-parser-applicability-v0.5.json"
)

PARSER_RULES = {
    "format": "json",
    "successJsonPath": "$.verified",
    "dataMap": {"verified": "$.verified"},
}

METHODS = {
    "verifiable-credential": {"kind": "verifiable-credential"},
    "tlsnotary": {
        "kind": "tlsnotary",
        "endpoint": "https://notary.example",
    },
    "zktls": {
        "kind": "zktls",
        "provider": "reclaim",
        "programId": "domain-control-v1",
    },
    "consensus-backed-proxy": {
        "kind": "consensus-backed-proxy",
        "endpoint": {
            "method": "GET",
            "urlTemplate": "https://authority.example/{identifier}",
        },
    },
    "evm-rpc": {
        "kind": "evm-rpc",
        "chainId": 8453,
        "contract": "0x0000000000000000000000000000000000000001",
        "method": "ownerOf",
    },
    "oauth-attested": {
        "kind": "oauth-attested",
        "provider": "github",
        "scopes": ["read:user"],
        "maxTokenAgeSec": 300,
    },
    "domain-tls-control": {
        "kind": "domain-tls-control",
        "challengeType": "http-01",
    },
    "self-signed": {"kind": "self-signed"},
    "demos-gcr-domain": {"kind": "demos-gcr-domain"},
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def recipe(method_kinds: list[str], parser: str = "absent") -> dict:
    methods = [copy.deepcopy(METHODS[kind]) for kind in method_kinds]
    item = {
        "recipeVersion": 1,
        "scheme": "parser-applicability-test",
        "defaultMethod": methods[0],
        "defaultMaxAgeSec": 3600,
        "retryClass": "permanent",
        "availability": "live",
    }
    if len(methods) > 1:
        item["alternatives"] = methods[1:]
    if parser == "valid":
        item["parserRules"] = copy.deepcopy(PARSER_RULES)
    elif parser == "null":
        item["parserRules"] = None
    return item


def case(
    name: str,
    expected: str,
    method_kinds: list[str],
    selected_method: str,
    *,
    parser: str = "absent",
    parser_applied: bool = False,
    method_invoked: bool = True,
    native_result: dict | None = None,
    parser_would_produce: dict | None = None,
    pin_parser_rule: bool = False,
    note: str,
) -> dict:
    item = {
        "name": name,
        "expected": expected,
        "note": note,
        "recipe": recipe(method_kinds, parser),
        "selectedMethod": selected_method,
        "want": {
            "parserApplied": parser_applied,
            "methodInvoked": method_invoked,
        },
    }
    if native_result is not None:
        item["methodNativeResult"] = copy.deepcopy(native_result)
        item["want"].update(copy.deepcopy(native_result))
    if parser_would_produce is not None:
        item["parserWouldProduce"] = copy.deepcopy(parser_would_produce)
    if pin_parser_rule:
        item["want"]["parserRuleHash"] = hashlib.sha256(
            canonical_bytes(item["recipe"]["parserRules"])
        ).hexdigest()
    return item


def build_vectors() -> list[dict]:
    vectors: list[dict] = []
    parser_methods = (
        "verifiable-credential",
        "tlsnotary",
        "zktls",
        "consensus-backed-proxy",
        "evm-rpc",
    )
    native_methods = (
        "oauth-attested",
        "domain-tls-control",
        "self-signed",
        "demos-gcr-domain",
    )

    for method in parser_methods:
        vectors.append(case(
            f"{method}-applies-parser",
            "pass",
            [method],
            method,
            parser="valid",
            parser_applied=True,
            note=f"PRA-1 classifies {method} as parser-consuming",
        ))

    for method in native_methods:
        vectors.append(case(
            f"{method}-is-parser-free",
            "pass",
            [method],
            method,
            note=f"PRA-1 classifies {method} as method-native",
        ))

    vectors.extend([
        case(
            "parser-consuming-recipe-missing-parser",
            "error",
            ["consensus-backed-proxy"],
            "consensus-backed-proxy",
            method_invoked=False,
            note="PRA-2/PRA-5 reject a missing required ParserSpec before invocation",
        ),
        case(
            "native-only-inert-parser-is-ignored",
            "pass",
            ["self-signed"],
            "self-signed",
            parser="valid",
            note="PRA-2 read compatibility ignores parserRules on every signed native-only recipe",
        ),
        case(
            "native-only-divergent-parser-output-is-inert",
            "pass",
            ["self-signed"],
            "self-signed",
            parser="valid",
            native_result={
                "decision": "pass",
                "data": {"source": "native", "verified": True},
            },
            parser_would_produce={
                "decision": "fail",
                "data": {"source": "parser", "verified": False},
            },
            note="PRA-2/PRA-4 preserve the native decision and data even when an inert parser would disagree",
        ),
        case(
            "native-only-null-parser-is-inert",
            "pass",
            ["demos-gcr-domain"],
            "demos-gcr-domain",
            parser="null",
            note="PRA-2 ignores even an invalid or null parserRules value on a native-only read path",
        ),
        case(
            "parser-consuming-null-parser-rejected",
            "error",
            ["consensus-backed-proxy"],
            "consensus-backed-proxy",
            parser="null",
            method_invoked=False,
            note="PRA-2/PRA-5 reject null where a parser-consuming method requires a valid ParserSpec",
        ),
        case(
            "mixed-recipe-parser-selection",
            "pass",
            ["domain-tls-control", "consensus-backed-proxy"],
            "consensus-backed-proxy",
            parser="valid",
            parser_applied=True,
            note="PRA-3 applies the shared ParserSpec when the parsing member is selected",
        ),
        case(
            "mixed-recipe-native-selection-skips-parser",
            "pass",
            ["domain-tls-control", "consensus-backed-proxy"],
            "domain-tls-control",
            parser="valid",
            note="PRA-3/PRA-4 skip parserRules when the native member is selected",
        ),
        case(
            "mixed-recipe-missing-parser",
            "error",
            ["domain-tls-control", "consensus-backed-proxy"],
            "domain-tls-control",
            method_invoked=False,
            note="one parser-consuming alternative makes ParserSpec required for the recipe",
        ),
        case(
            "shared-parser-consensus-proxy-selection",
            "pass",
            ["consensus-backed-proxy", "tlsnotary", "zktls"],
            "consensus-backed-proxy",
            parser="valid",
            parser_applied=True,
            pin_parser_rule=True,
            note="PRA-2 applies one unchanged ParserSpec to the proxy member",
        ),
        case(
            "shared-parser-tlsnotary-selection",
            "pass",
            ["consensus-backed-proxy", "tlsnotary", "zktls"],
            "tlsnotary",
            parser="valid",
            parser_applied=True,
            pin_parser_rule=True,
            note="PRA-2 applies the identical ParserSpec to the TLSNotary member",
        ),
        case(
            "shared-parser-zktls-selection",
            "pass",
            ["consensus-backed-proxy", "tlsnotary", "zktls"],
            "zktls",
            parser="valid",
            parser_applied=True,
            pin_parser_rule=True,
            note="PRA-2 applies the identical ParserSpec to the zkTLS member",
        ),
        case(
            "selected-method-not-declared",
            "error",
            ["self-signed"],
            "domain-tls-control",
            method_invoked=False,
            note="selection must resolve to the recipe default or an explicit alternative",
        ),
    ])

    unknown = case(
        "unclassified-method-rejected",
        "error",
        ["self-signed"],
        "self-signed",
        method_invoked=False,
        note="PRA-1 requires every registered method to have one closed classification",
    )
    unknown["recipe"]["defaultMethod"] = {"kind": "future-unclassified"}
    unknown["selectedMethod"] = "future-unclassified"
    vectors.append(unknown)
    return vectors


def build_document() -> dict:
    vectors = build_vectors()
    return {
        "set": "recipe-parser-applicability-v0.5",
        "spec": "DACS-2 §7.4.1/§7.6 PRA-1..PRA-5 parser applicability",
        "count": len(vectors),
        "hash": hashlib.sha256(canonical_bytes(vectors)).hexdigest(),
        "vectors": vectors,
    }


def encoded() -> str:
    return json.dumps(build_document(), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = encoded()
    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else None
    if args.write:
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return 0
    if current != expected:
        print(f"stale: {OUTPUT.relative_to(ROOT)}")
        return 1
    print(f"OK — {OUTPUT.relative_to(ROOT)} is deterministic")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
