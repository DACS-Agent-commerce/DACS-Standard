#!/usr/bin/env python3
"""Generate deterministic known-answer vectors for the HTLC-5 preimage derivation.

DACS-4 §9.5.4 HTLC-5 derives the cross-chain preimage with HKDF (RFC 5869,
SHA-256). This set pins the byte encodings of its inputs and output so two
implementations cannot derive different preimages from the same session:

    IKM  = buyerSalt bytes (HTLC-1: at least 16 bytes)
    salt = the exact ASCII bytes of the JID-1 jobId
    info = the ASCII bytes of the 64-character lowercase hex agreementHash
    L    = 32; the preimage is the 32 output bytes
    hashlock = chain-native hash of those 32 bytes (HTLC-6); sha256 shown here

Dependency-free: HKDF is written out from RFC 5869 with hmac/hashlib and is
checked against the RFC's own test case before any vector is produced.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (
    ROOT / "conformance" / "vectors" / "security" / "htlc-preimage-derivation-v0.1.json"
)
SET = "htlc-preimage-derivation-v0.1"
SPEC = "DACS-4 §9.5.4 HTLC-5 / HTLC-6 preimage derivation byte encodings"
HASH_LEN = hashlib.sha256().digest_size


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 §2.2. An empty salt is a string of HashLen zeros."""
    if not salt:
        salt = bytes(HASH_LEN)
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 §2.3."""
    if length > 255 * HASH_LEN:
        raise ValueError("HKDF output too long")
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def self_check() -> None:
    """RFC 5869 Appendix A, test case 1 (SHA-256). Fails closed if HKDF is wrong."""
    okm = hkdf(
        bytes.fromhex("0b" * 22),
        bytes.fromhex("000102030405060708090a0b0c"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        42,
    )
    want = (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    if okm.hex() != want:
        raise SystemExit("HKDF self-check against RFC 5869 A.1 failed")


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# Synthetic inputs. The salt bytes are a fixed test pattern, not a secret; the
# jobId is a canonical JID-1 ULID; the agreementHash is sha256 of a fixed label,
# standing in for sha256(canonical_JCS(agreement)) (DACS-3 §8.6).
BUYER_SALT_32 = bytes(range(0x10, 0x30))
BUYER_SALT_16 = bytes.fromhex("a1" * 16)
JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
OTHER_JOB_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
AGREEMENT_HASH = hashlib.sha256(b"dacs-4 htlc-5 known-answer agreement").hexdigest()


def derive(buyer_salt: bytes, job_id: str, agreement_hash: str) -> bytes:
    """HTLC-5 as pinned: salt = jobId ASCII, info = lowercase hex ASCII."""
    return hkdf(buyer_salt, job_id.encode("ascii"), agreement_hash.encode("ascii"), 32)


def vector(name, rule, expected, buyer_salt, job_id, agreement_hash, *,
           note, salt_bytes=None, info_bytes=None):
    salt = job_id.encode("ascii") if salt_bytes is None else salt_bytes
    info = agreement_hash.encode("ascii") if info_bytes is None else info_bytes
    preimage = hkdf(buyer_salt, salt, info, 32)
    return {
        "name": name,
        "rule": rule,
        "expected": expected,
        "input": {
            "buyerSaltHex": buyer_salt.hex(),
            "jobId": job_id,
            "agreementHash": agreement_hash,
        },
        "derivation": {
            "ikmHex": buyer_salt.hex(),
            "saltHex": salt.hex(),
            "infoHex": info.hex(),
            "length": 32,
        },
        "want": {
            "preimageHex": preimage.hex(),
            "hashlockSha256Hex": hashlib.sha256(preimage).hexdigest(),
        },
        "note": note,
    }


def document() -> dict:
    self_check()
    canonical = derive(BUYER_SALT_32, JOB_ID, AGREEMENT_HASH)
    vectors = [
        vector(
            "canonical-derivation", "HTLC-5", "pass",
            BUYER_SALT_32, JOB_ID, AGREEMENT_HASH,
            note=(
                "The pinned derivation: IKM = the 32 buyerSalt bytes, salt = the 26 ASCII "
                "bytes of the jobId, info = the 64 ASCII bytes of the lowercase hex "
                "agreementHash, L = 32. want.preimageHex is the preimage; "
                "want.hashlockSha256Hex is its sha256 hashlock (HTLC-6, sha256 chains)."
            ),
        ),
        vector(
            "sixteen-byte-salt-minimum", "HTLC-1 / HTLC-5", "pass",
            BUYER_SALT_16, JOB_ID, AGREEMENT_HASH,
            note="A 16-byte buyerSalt (the HTLC-1 minimum of 128 bits) derives with the same rule.",
        ),
        vector(
            "other-job-id-other-preimage", "HTLC-5", "pass",
            BUYER_SALT_32, OTHER_JOB_ID, AGREEMENT_HASH,
            note=(
                "Same salt and agreementHash, jobId differs in its last character: a "
                "different preimage. Compare with canonical-derivation."
            ),
        ),
        vector(
            "info-as-decoded-bytes-is-wrong", "HTLC-5", "fail",
            BUYER_SALT_32, JOB_ID, AGREEMENT_HASH,
            info_bytes=bytes.fromhex(AGREEMENT_HASH),
            note=(
                "The same inputs with info = the 32 decoded bytes of agreementHash "
                "instead of its 64 hex characters. want shows what that mistake "
                "produces; it MUST NOT equal canonical-derivation's preimage."
            ),
        ),
        vector(
            "uppercase-hex-info-is-wrong", "HTLC-5", "fail",
            BUYER_SALT_32, JOB_ID, AGREEMENT_HASH,
            info_bytes=AGREEMENT_HASH.upper().encode("ascii"),
            note=(
                "info built from an uppercase rendering of agreementHash. The hash is "
                "carried lowercase (CORE §B); any other spelling is a different input."
            ),
        ),
        vector(
            "salt-and-info-swapped-is-wrong", "HTLC-5", "fail",
            BUYER_SALT_32, JOB_ID, AGREEMENT_HASH,
            salt_bytes=AGREEMENT_HASH.encode("ascii"),
            info_bytes=JOB_ID.encode("ascii"),
            note="salt and info exchanged. want shows the result; it MUST NOT be used.",
        ),
    ]
    assert vectors[0]["want"]["preimageHex"] == canonical.hex()
    wrong = {v["want"]["preimageHex"] for v in vectors if v["expected"] == "fail"}
    assert canonical.hex() not in wrong and len(wrong) == 3
    return {
        "set": SET,
        "spec": SPEC,
        "decisionModel": (
            "A pass vector's want.preimageHex is the only preimage an HTLC-5 "
            "implementation may derive from its input; a fail vector's want is the "
            "output of one named encoding mistake and MUST NOT be derived. hashlock "
            "values are sha256(preimage); chains using another hash apply it to the "
            "same 32 bytes (HTLC-6)."
        ),
        "count": len(vectors),
        "hash": hashlib.sha256(canonical_bytes(vectors)).hexdigest(),
        "vectors": vectors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the committed file")
    args = parser.parse_args()
    rendered = json.dumps(document(), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != rendered:
            print("stale generated corpus:", OUTPUT)
            return 1
        print("ok:", OUTPUT)
        return 0
    OUTPUT.write_text(rendered, encoding="utf-8")
    print("wrote:", OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
