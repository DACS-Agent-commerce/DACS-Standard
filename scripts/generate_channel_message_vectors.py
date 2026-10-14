#!/usr/bin/env python3
"""Generate deterministic DACS-3 CH-6..CH-10 channel-message vectors.

The current DACS wire is deliberately distinct from the historical Demos
message accepted by the frozen ``channel-message-replay-v0.1.json`` corpus.
This generator exercises the current wire and the strict, read-only dispatch
boundary.  It never rewrites the historical corpus.

Current-wire sender/signer identities are canonical registered DACS-1 claims
(``key:<64hex>`` for Ed25519 primary keys, ``did:`` for the ECDSA/SR-1
fixtures).  The generic ``cci:<64hex>`` spelling is a frozen historical form:
it is deliberately absent from the current registry and a current read must
refuse it (DACS-1 registers ``key:``, ``did:``, and specific ``cci-*``
schemes only).
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import jcs  # noqa: E402
from dacs_reference import parse_claim_reference  # noqa: E402


OUTPUT = (
    ROOT / "conformance" / "vectors" / "security"
    / "canonical-channel-message-v0.6.json"
)
LEGACY = (
    ROOT / "conformance" / "vectors" / "security"
    / "channel-message-replay-v0.1.json"
)
LEGACY_VECTOR_HASH = "3f0664c434a6727f7578434cba9ea47b804e0dff12249081c7abdd4fdc03803b"
CURRENT_DOMAIN = b"dacs-canonical-channel-message:v1:"
LEGACY_DOMAIN = b"dacs-channelmsg:v1:"
NOW = 1_900_000_000_000
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def canonical_bytes(value: object) -> bytes:
    return jcs.canonicalize(value).encode("utf-8")


def digest(value: object) -> bytes:
    return hashlib.sha256(canonical_bytes(value)).digest()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(label.encode("utf-8")).digest()
    )


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


ALICE = private_key("dacs-349-alice")
BOB = private_key("dacs-349-bob")
OUTSIDER = private_key("dacs-349-outsider")
SR1_ROOT = private_key("dacs-349-sr1-root")
ECDSA_PRIVATE_VALUE = (
    int.from_bytes(hashlib.sha256(b"dacs-349-ecdsa").digest(), "big")
    % (SECP256K1_ORDER - 1)
) + 1
ECDSA_PRIVATE = ec.derive_private_key(ECDSA_PRIVATE_VALUE, ec.SECP256K1())
# Current-wire sender/signer identities are canonical registered DACS-1
# claims.  The Ed25519 members use the registered self-authenticating key:
# scheme; the non-Ed25519 algorithm fixtures use did: references.  The
# generic cci:<64hex> spelling is not in the current scheme registry.
ALICE_REF = f"key:{public_hex(ALICE)}"
BOB_REF = f"key:{public_hex(BOB)}"
OUTSIDER_REF = f"key:{public_hex(OUTSIDER)}"
ECDSA_REF = "did:example:dacs-349-ecdsa"
SR1_REF = "did:example:dacs-349-sr1-root"
UNRESOLVED_REF = "did:example:unresolved"
# The historical spelling of the Alice fixture key: the frozen corpus era
# carried Ed25519 primary keys as generic cci:<64hex> claims.  It appears in
# the generated corpus only inside explicit legacy-import compatibility
# cases and the current-read refusal regression; the current arm refuses it.
HISTORICAL_ALICE_REF = f"cci:{public_hex(ALICE)}"
CURRENT_RELEASE_PIN = "0d92f6642bdbd96655c8bb9a150b984d6be8bb67"
CURRENT_MODULE_VERSIONS = {
    "core": "0.3", "dacs1": "0.8", "dacs2": "0.6",
    "dacs3": "0.6", "dacs4": "0.8", "dacs5": "0.7",
}
CURRENT_PARTICIPANTS = sorted(
    [ALICE_REF, BOB_REF, ECDSA_REF, SR1_REF, UNRESOLVED_REF],
    key=lambda value: value.encode("utf-8"),
)


def current_ref(value: str) -> str:
    """Validate that a current-wire identity is a registered DACS-1 claim."""

    return parse_claim_reference(value).canonical


# Fail closed at generation time: every current-wire identity must parse
# under the shared current scheme registry (scripts/dacs_reference.py), and
# the historical generic cci:<64hex> spelling must NOT.  Current vectors and
# the current membership authority never carry unregistered claims.
for _current_identity in (
    ALICE_REF, BOB_REF, OUTSIDER_REF, ECDSA_REF, SR1_REF, UNRESOLVED_REF,
):
    current_ref(_current_identity)
try:
    parse_claim_reference(HISTORICAL_ALICE_REF)
except ValueError:
    pass
else:  # pragma: no cover - generation authoring guard
    raise RuntimeError("generic cci: must stay unregistered for current reads")
del _current_identity


def current_payload(unsigned: dict, domain: bytes, framing: str) -> bytes:
    message_hash = digest(unsigned)
    if framing == "hex":
        return domain + message_hash.hex().encode("ascii")
    if framing == "raw":
        return domain + message_hash
    raise ValueError(f"unknown framing {framing}")


def deterministic_ecdsa_signature(payload: bytes) -> bytes:
    """RFC 6979 secp256k1/SHA-256 with canonical DER and low-S output."""

    digest_bytes = hashlib.sha256(payload).digest()
    private_bytes = ECDSA_PRIVATE_VALUE.to_bytes(32, "big")
    reduced_hash = (int.from_bytes(digest_bytes, "big") % SECP256K1_ORDER).to_bytes(32, "big")
    value = b"\x01" * 32
    key = b"\x00" * 32
    key = hmac.new(key, value + b"\x00" + private_bytes + reduced_hash, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(key, value + b"\x01" + private_bytes + reduced_hash, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        nonce = int.from_bytes(value, "big")
        if 1 <= nonce < SECP256K1_ORDER:
            break
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()
    point = ec.derive_private_key(nonce, ec.SECP256K1()).public_key().public_numbers()
    r = point.x % SECP256K1_ORDER
    z = int.from_bytes(digest_bytes, "big")
    s = (pow(nonce, -1, SECP256K1_ORDER) * (z + r * ECDSA_PRIVATE_VALUE)) % SECP256K1_ORDER
    s = min(s, SECP256K1_ORDER - s)
    return utils.encode_dss_signature(r, s)


def unsigned_message(**updates: object) -> dict:
    value = {
        "canonicalChannelMessageVersion": "1",
        "channelId": "channel-349",
        "sequence": 1,
        "sender": ALICE_REF,
        "sentAt": NOW,
        "type": "offer",
        "body": {"currency": "DEM", "price": "10"},
    }
    value.update(copy.deepcopy(updates))
    return value


def sign_current(
    unsigned: dict,
    *,
    key: Ed25519PrivateKey = ALICE,
    signer: str = ALICE_REF,
    signature_version: str = "1",
    algorithm: str = "ed25519",
    domain: bytes = CURRENT_DOMAIN,
    framing: str = "hex",
) -> dict:
    payload = current_payload(unsigned, domain, framing)
    return {
        **copy.deepcopy(unsigned),
        "signature": {
            "signatureVersion": signature_version,
            "signer": signer,
            "algorithm": algorithm,
            "value": b64url(key.sign(payload)),
        },
    }


def sign_current_ecdsa(
    unsigned: dict,
    *,
    domain: bytes = CURRENT_DOMAIN,
    framing: str = "hex",
) -> dict:
    return {
        **copy.deepcopy(unsigned),
        "signature": {
            "signatureVersion": "1",
            "signer": ECDSA_REF,
            "algorithm": "ecdsa-secp256k1",
            "value": b64url(deterministic_ecdsa_signature(current_payload(unsigned, domain, framing))),
        },
    }


def sign_current_sr1(
    unsigned: dict,
    *,
    domain: bytes = CURRENT_DOMAIN,
    framing: str = "hex",
) -> dict:
    return {
        **copy.deepcopy(unsigned),
        "signature": {
            "signatureVersion": "1",
            "signer": SR1_REF,
            "algorithm": "sr1-aggregate",
            "value": b64url(SR1_ROOT.sign(current_payload(unsigned, domain, framing))),
        },
    }


def sign_legacy(
    unsigned: dict,
    *,
    key: Ed25519PrivateKey = ALICE,
    domain: bytes = LEGACY_DOMAIN,
    framing: str = "raw",
) -> dict:
    message_hash = digest(unsigned)
    if framing == "raw":
        payload = domain + message_hash
    elif framing == "hex":
        payload = domain + message_hash.hex().encode("ascii")
    else:  # pragma: no cover - generator authoring guard
        raise ValueError(f"unknown framing {framing}")
    return {**copy.deepcopy(unsigned), "signature": key.sign(payload).hex()}


def context(**updates: object) -> dict:
    value = {
        "sessionChannelId": "channel-349",
        "lastSequence": 0,
        "priorChannelIds": ["channel-100", "channel-200"],
    }
    value.update(copy.deepcopy(updates))
    return value


def profile_admission(session_id: str, **updates: object) -> dict:
    value = {
        "source": "fixture-verifier-owned",
        "authenticated": True,
        "sessionId": session_id,
        "participantIdentities": copy.deepcopy(CURRENT_PARTICIPANTS),
        "releasePin": CURRENT_RELEASE_PIN,
        "moduleVersions": copy.deepcopy(CURRENT_MODULE_VERSIONS),
    }
    value.update(copy.deepcopy(updates))
    return value


def case(name: str, expected: str, message: dict, *, note: str,
         ctx: dict | None = None, operation: str = "current-read",
         omit_profile_admission: bool = False, **extra: object) -> dict:
    selected_context = copy.deepcopy(ctx if ctx is not None else context())
    value = {
        "name": name,
        "expected": expected,
        "operation": operation,
        "note": note,
        "message": copy.deepcopy(message),
        "ctx": selected_context,
    }
    if operation == "current-read" and not omit_profile_admission:
        value["profileAdmission"] = profile_admission(
            selected_context.get("sessionChannelId", "")
        )
    value.update(copy.deepcopy(extra))
    return value


def build_vectors() -> list[dict]:
    valid = sign_current(unsigned_message())
    valid_next = sign_current(unsigned_message(sequence=2))
    valid_gap = sign_current(unsigned_message(sequence=5))

    duplicate = sign_current(unsigned_message(sequence=3))
    foreign = sign_current(unsigned_message(channelId="channel-foreign"))
    reused = sign_current(unsigned_message(channelId="channel-reused"))

    tampered = copy.deepcopy(valid)
    tampered["body"]["price"] = "11"

    unresolved_unsigned = unsigned_message(sender=UNRESOLVED_REF)
    unresolved = sign_current(
        unresolved_unsigned, signer=UNRESOLVED_REF
    )

    outsider_unsigned = unsigned_message(sequence=2, sender=OUTSIDER_REF)
    outsider = sign_current(
        outsider_unsigned,
        key=OUTSIDER,
        signer=OUTSIDER_REF,
    )
    member_wrong_key = sign_current(
        unsigned_message(sequence=2),
        key=BOB,
        signer=ALICE_REF,
    )
    qualified_member = sign_current(
        unsigned_message(sequence=2, sender=f"{ALICE_REF}?role=buyer"),
        signer=f"{ALICE_REF}?role=author",
    )

    padded = copy.deepcopy(valid)
    padded["signature"]["value"] += "=="
    standard_base64 = copy.deepcopy(valid)
    standard_base64["signature"]["value"] = "+" + valid["signature"]["value"][1:]
    hex_value = copy.deepcopy(valid)
    hex_value["signature"]["value"] = base64.urlsafe_b64decode(
        valid["signature"]["value"] + "=="
    ).hex()

    unknown_version = sign_current(
        unsigned_message(), signature_version="2"
    )
    unknown_algorithm = sign_current(
        unsigned_message(), algorithm="rsa-pss"
    )
    algorithm_key_confusion = sign_current(
        unsigned_message(), algorithm="ecdsa-secp256k1"
    )
    signer_mismatch = sign_current(
        unsigned_message(), key=BOB, signer=BOB_REF
    )
    empty_refs = sign_current(unsigned_message(refs={}))
    null_refs = sign_current(unsigned_message(refs=None))
    invalid_replies_to = sign_current(unsigned_message(refs={"repliesTo": True}))
    boolean_sequence = sign_current(unsigned_message(sequence=True))
    empty_channel = sign_current(unsigned_message(channelId=""))
    open_signature_envelope = copy.deepcopy(valid)
    open_signature_envelope["signature"]["keyHint"] = "must-not-be-ignored"

    no_discriminator = copy.deepcopy(valid)
    del no_discriminator["canonicalChannelMessageVersion"]
    discriminator_hex = copy.deepcopy(valid)
    discriminator_hex["signature"] = bytes.fromhex(
        hex_value["signature"]["value"]
    ).hex()
    unknown_discriminator = copy.deepcopy(valid)
    unknown_discriminator["canonicalChannelMessageVersion"] = "2"
    missing_signature = unsigned_message()

    current_raw = sign_current(unsigned_message(), framing="raw")
    current_legacy_domain = sign_current(
        unsigned_message(), domain=LEGACY_DOMAIN, framing="hex"
    )

    # The two synthetic legacy-wire negatives are historical-arm messages:
    # they run on the historical audit channel with the historical spelling
    # of the Alice key, so their failures prove framing/domain confusion and
    # not an unresolvable sender.
    legacy_ctx = context(
        sessionChannelId="chan-session-7",
        priorChannelIds=["chan-session-1", "chan-session-2"],
    )
    legacy_unsigned = {
        "channelId": "chan-session-7",
        "sequence": 1,
        "sender": HISTORICAL_ALICE_REF,
        "sentAt": NOW,
        "type": "offer",
        "body": {"currency": "DEM", "price": "10"},
    }
    legacy_hex_framing = sign_legacy(legacy_unsigned, framing="hex")
    legacy_current_signature = sign_legacy(
        legacy_unsigned, domain=CURRENT_DOMAIN, framing="hex"
    )

    legacy_doc = json.loads(LEGACY.read_text(encoding="utf-8"))
    if legacy_doc.get("hash") != LEGACY_VECTOR_HASH:
        raise RuntimeError("frozen historical channel corpus changed")
    frozen_first = copy.deepcopy(legacy_doc["vectors"][0]["message"])
    frozen_raw = bytes.fromhex(frozen_first["signature"])

    uppercase_legacy = copy.deepcopy(frozen_first)
    uppercase_legacy["signature"] = uppercase_legacy["signature"].upper()

    signed_unknown = unsigned_message(experimentalHint={"future": True})
    current_unknown = sign_current(signed_unknown)
    stripped_unknown = copy.deepcopy(current_unknown)
    del stripped_unknown["experimentalHint"]

    malformed_context = context(lastSequence=True)
    injected_membership_context = context()
    injected_membership_context["authenticatedMembers"] = [{
        "claim": ALICE_REF,
        "algorithm": "ed25519",
        "publicKey": public_hex(BOB),
    }]

    ecdsa_unsigned = unsigned_message(sequence=2, sender=ECDSA_REF)
    ecdsa_valid = sign_current_ecdsa(ecdsa_unsigned)
    ecdsa_tampered = copy.deepcopy(ecdsa_valid)
    ecdsa_tampered["body"]["price"] = "11"
    ecdsa_wrong_domain = sign_current_ecdsa(ecdsa_unsigned, domain=LEGACY_DOMAIN)
    ecdsa_raw_framing = sign_current_ecdsa(ecdsa_unsigned, framing="raw")

    sr1_unsigned = unsigned_message(sequence=3, sender=SR1_REF)
    sr1_valid = sign_current_sr1(sr1_unsigned)
    sr1_tampered = copy.deepcopy(sr1_valid)
    sr1_tampered["body"]["price"] = "11"
    sr1_wrong_domain = sign_current_sr1(sr1_unsigned, domain=LEGACY_DOMAIN)
    sr1_raw_framing = sign_current_sr1(sr1_unsigned, framing="raw")

    # Regression for the scheme-registry boundary: an otherwise well-formed
    # current message whose Ed25519 sender/signer is spelled with the
    # historical generic cci:<64hex> scheme is malformed on current-read —
    # DACS-1 registers key:, did:, and specific cci-* schemes only, and the
    # canonical key:<pubkeyhex> spelling of the same key passes.
    generic_cci_current = sign_current(
        unsigned_message(sender=HISTORICAL_ALICE_REF),
        signer=HISTORICAL_ALICE_REF,
    )

    return [
        case("canonical-valid-first", "pass", valid,
             note="current discriminator, SIG-6 value, hex-digest framing and fresh sequence"),
        case("canonical-valid-next", "pass", valid_next,
             ctx=context(lastSequence=1), note="strictly increasing sequence"),
        case("canonical-valid-sequence-gap", "pass", valid_gap,
             ctx=context(lastSequence=2), note="CH-6 requires monotonicity, not contiguity"),
        case("current-profile-missing-authority", "indeterminate", valid,
             omit_profile_admission=True,
             note="missing verifier-owned exact-profile authority refuses before live state issuance"),
        case("current-profile-partial-module-tuple", "error", valid,
             profileAdmission=profile_admission(
                 "channel-349",
                 moduleVersions={
                     key: value for key, value in CURRENT_MODULE_VERSIONS.items()
                     if key != "dacs5"
                 },
             ),
             note="a partial module tuple is malformed before current channel processing"),
        case("current-profile-wrong-release-pin", "fail", valid,
             profileAdmission=profile_admission("channel-349", releasePin="f" * 40),
             note="an authenticated different release pin refuses the session"),
        case("current-profile-duplicate-participant", "error", valid,
             profileAdmission=profile_admission(
                 "channel-349",
                 participantIdentities=CURRENT_PARTICIPANTS + [ALICE_REF],
             ),
             note="duplicate participant identities make profile authority malformed"),
        case("current-profile-session-mismatch", "fail", valid,
             profileAdmission=profile_admission("channel-other"),
             note="profile authority for a different session cannot issue live state"),
        case("current-profile-identity-mismatch", "fail", valid,
             profileAdmission=profile_admission(
                 "channel-349",
                 participantIdentities=[
                     identity for identity in CURRENT_PARTICIPANTS
                     if identity != BOB_REF
                 ] + [OUTSIDER_REF],
             ),
             note="profile authority must bind the exact authenticated participants"),
        case("current-profile-unauthenticated", "error", valid,
             profileAdmission=profile_admission("channel-349", authenticated=False),
             note="unauthenticated profile material cannot issue live state"),
        case("canonical-duplicate-sequence", "fail", duplicate,
             ctx=context(lastSequence=3), note="duplicate sequence is a replay"),
        case("canonical-decreasing-sequence", "fail", duplicate,
             ctx=context(lastSequence=4), note="decreasing sequence is a replay"),
        case("canonical-foreign-channel", "fail", foreign,
             note="valid signature cannot cross the active channel binding"),
        case("canonical-reused-session-channel", "fail", reused,
             ctx=context(sessionChannelId="channel-reused",
                         priorChannelIds=["channel-reused"]),
             note="CH-6 refuses a reused session channel identifier"),
        case("canonical-unresolved-sender", "indeterminate", unresolved,
             note="well-formed but unavailable signer authority is indeterminate"),
        case("canonical-outsider-valid-signature", "fail", outsider,
             ctx=context(lastSequence=1),
             note="a valid signature cannot admit a sender outside the authenticated fixed member set"),
        case("canonical-member-wrong-key", "fail", member_wrong_key,
             ctx=context(lastSequence=1),
             note="member equality cannot replace verification against the independently bound member key"),
        case("canonical-qualified-member-identity", "pass", qualified_member,
             ctx=context(lastSequence=1),
             note="CF-3 ignores advisory qualifiers when sender, signer and authenticated membership identities are matched"),
        case("canonical-generic-cci-sender-refused", "error", generic_cci_current,
             note="DACS-1 registers key:, did:, and specific cci-* schemes; the historical generic cci spelling of the same key is malformed on current-read while canonical key: passes"),
        case("canonical-tampered-body", "fail", tampered,
             note="message-body mutation breaks the signature"),
        case("canonical-padded-base64url", "error", padded,
             note="SIG-6 rejects padding before cryptographic verification"),
        case("canonical-standard-base64-character", "error", standard_base64,
             note="SIG-6 rejects standard-Base64 alphabet characters"),
        case("canonical-hex-signature-value", "fail", hex_value,
             note="hex characters form a Base64URL spelling but decode to the wrong Ed25519 length"),
        case("canonical-unknown-signature-version", "error", unknown_version,
             note="unknown signature-envelope versions are not retried"),
        case("canonical-unknown-algorithm", "error", unknown_algorithm,
             note="unknown algorithm identifiers are malformed"),
        case("canonical-algorithm-key-confusion", "fail", algorithm_key_confusion,
             note="a CCI Ed25519 key cannot be relabelled as ECDSA"),
        case("canonical-ecdsa-valid", "pass", ecdsa_valid,
             ctx=context(lastSequence=1),
             note="authenticated secp256k1 fixture verifies canonical DER low-S bytes"),
        case("canonical-ecdsa-tampered-body", "fail", ecdsa_tampered,
             ctx=context(lastSequence=1), note="ECDSA covers the complete received message"),
        case("canonical-ecdsa-cross-domain", "fail", ecdsa_wrong_domain,
             ctx=context(lastSequence=1), note="ECDSA cannot authenticate the historical domain"),
        case("canonical-ecdsa-raw-digest-framing", "fail", ecdsa_raw_framing,
             ctx=context(lastSequence=1), note="ECDSA signs ASCII lowercase hex, not raw digest bytes"),
        case("canonical-sr1-aggregate-valid", "pass", sr1_valid,
             ctx=context(lastSequence=2),
             note="authenticated SR-1 root fixture verifies the canonical current payload"),
        case("canonical-sr1-aggregate-tampered-body", "fail", sr1_tampered,
             ctx=context(lastSequence=2), note="SR-1 root signature covers the complete received message"),
        case("canonical-sr1-aggregate-cross-domain", "fail", sr1_wrong_domain,
             ctx=context(lastSequence=2), note="SR-1 root signature cannot authenticate the historical domain"),
        case("canonical-sr1-aggregate-raw-digest-framing", "fail", sr1_raw_framing,
             ctx=context(lastSequence=2), note="SR-1 root signs ASCII lowercase hex, not raw digest bytes"),
        case("canonical-signer-sender-mismatch", "fail", signer_mismatch,
             note="signature.signer must canonically equal sender"),
        case("canonical-empty-refs-object", "pass", empty_refs,
             note="the optional refs object may omit its optional repliesTo member"),
        case("canonical-null-refs", "error", null_refs,
             note="a present refs member must be an object; JSON null is not absence"),
        case("canonical-boolean-replies-to", "error", invalid_replies_to,
             note="repliesTo is a positive integer and excludes JSON booleans"),
        case("canonical-boolean-sequence", "error", boolean_sequence,
             note="sequence is a positive integer and excludes JSON booleans"),
        case("canonical-empty-channel-id", "error", empty_channel,
             note="the active channel binding cannot be empty"),
        case("canonical-open-signature-envelope", "error", open_signature_envelope,
             note="the version-1 signature envelope has an exact member set"),
        case("neither-selector-no-discriminator-current-envelope", "error", no_discriminator,
             note="a current envelope without its discriminator is not legacy"),
        case("mixed-current-discriminator-legacy-signature", "error", discriminator_hex,
             note="the current discriminator selects current parsing before crypto"),
        case("canonical-unknown-message-version", "error", unknown_discriminator,
             note="unknown current message versions do not fall back to legacy"),
        case("canonical-missing-signature", "error", missing_signature,
             note="neither current nor historical structural selector matches"),
        case("mixed-current-raw-digest-framing", "fail", current_raw,
             note="current type signs the ASCII lowercase-hex digest, not raw bytes"),
        case("cross-domain-legacy-to-current", "fail", current_legacy_domain,
             note="the historical domain cannot authenticate a current message"),
        case("mixed-legacy-hex-digest-framing", "fail", legacy_hex_framing,
             ctx=copy.deepcopy(legacy_ctx),
             operation="legacy-import",
             note="historical type signs the raw digest, not ASCII lowercase hex"),
        case("cross-domain-current-to-legacy", "fail", legacy_current_signature,
             ctx=copy.deepcopy(legacy_ctx),
             operation="legacy-import",
             note="the current domain cannot authenticate a historical message"),
        case(
            "legacy-byte-preserving-read-only-import", "pass", frozen_first,
            ctx=copy.deepcopy(legacy_doc["vectors"][0]["ctx"]),
            operation="legacy-import",
            note="the frozen historical bytes verify only on the explicit import arm",
            expectedSignatureBytesBase64Url=b64url(frozen_raw),
        ),
        case("legacy-uppercase-hex-rejected", "error", uppercase_legacy,
            ctx=copy.deepcopy(legacy_doc["vectors"][0]["ctx"]),
             operation="legacy-import",
             note="the historical selector is exact lowercase hex, never auto-detected"),
        case("canonical-preserve-unknown-signed-field", "pass", current_unknown,
             note="SIG-5 includes an unknown field in the signed scope"),
        case("canonical-stripped-unknown-field", "fail", stripped_unknown,
             note="a reader cannot strip an unknown signed field before verification"),
        case("malformed-context-boolean-sequence", "error", valid,
             ctx=malformed_context,
             note="context integers exclude JSON booleans"),
        case("untrusted-context-membership-injection", "error", valid,
             ctx=injected_membership_context,
             note="message-adjacent session input cannot supply or replace authenticated CH-1 authority"),
    ]


def render() -> str:
    vectors = build_vectors()
    document = {
        "set": "canonical-channel-message-v0.6",
        "spec": "DACS-3 §8.3.3 CH-6..CH-10 + CORE §B.7 SIG-2/SIG-5/SIG-6",
        "decisionModel": "§7.5.1 four-value result; trusted operation selection and structural dispatch precede cryptography",
        "authenticatedKeyFixtures": [
            {
                "claim": ECDSA_REF,
                "algorithm": "ecdsa-secp256k1",
                "publicKeyEncoding": "sec1-compressed-lowercase-hex",
                "publicKey": ECDSA_PRIVATE.public_key().public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.CompressedPoint,
                ).hex(),
                "signatureEncoding": "canonical-DER-low-S",
            },
            {
                "claim": SR1_REF,
                "algorithm": "sr1-aggregate",
                "presentation": "sr1-root",
                "publicKeyEncoding": "ed25519-raw-lowercase-hex",
                "publicKey": public_hex(SR1_ROOT),
            },
        ],
        "historicalCorpus": {
            "path": "channel-message-replay-v0.1.json",
            "vectorsHash": LEGACY_VECTOR_HASH,
            "status": "frozen read/import-only; new producers MUST NOT emit",
            "operation": "legacy-import",
        },
        "correctiveProfileFixture": {
            "releasePin": CURRENT_RELEASE_PIN,
            "moduleVersions": CURRENT_MODULE_VERSIONS,
            "authority": "verifier-owned and bound to exact session plus participant identities",
            "legacyImportExempt": True,
        },
        "count": len(vectors),
        "hash": hashlib.sha256(canonical_bytes(vectors)).hexdigest(),
        "vectors": vectors,
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.check and args.write:
        parser.error("choose --check or --write")
    generated = render()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != generated:
            print(
                "ERROR: canonical channel-message vectors are stale; run "
                "python3 scripts/generate_channel_message_vectors.py --write",
                file=sys.stderr,
            )
            return 1
        print("canonical channel-message vectors OK (byte-identical)")
        return 0
    OUTPUT.write_text(generated, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
