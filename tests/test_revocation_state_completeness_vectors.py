import base64
import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    ROOT / "conformance" / "vectors" / "security"
    / "revocation-state-completeness-v0.8.json"
)
GENERATOR = ROOT / "scripts" / "generate_revocation_state_completeness_vectors.py"
SPEC = ROOT / "spec" / "DACS-1-IDENTIFY.md"
CORE = ROOT / "spec" / "CORE.md"
MAPPING = ROOT / "spec" / "DEMOS-MAPPING.md"
HEAD_DOMAIN = "dacs-revocation-state-head:v1:"
MARKER_DOMAIN = "dacs-revocation:v1:"
ZERO_HASH = "00" * 32


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def hash_hex(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def artifact_hash(value):
    return hash_hex({key: item for key, item in value.items() if key != "signature"})


def decode_b64url(value):
    raw = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        raise ValueError("non-canonical base64url")
    return raw


def verify_artifact(value, public_key, domain):
    if not isinstance(value, dict):
        return False
    signature = value.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
        key.verify(
            decode_b64url(signature.get("value", "")),
            (domain + artifact_hash(value)).encode("ascii"),
        )
    except (ValueError, InvalidSignature):
        return False
    return True


def cf4(value):
    encoded = value
    for raw, escaped in (("%", "%25"), (":", "%3A"), ("?", "%3F"), ("&", "%26"), ("=", "%3D")):
        encoded = encoded.replace(raw, escaped)
    return encoded


def empty_hashes():
    result = [hashlib.sha256(b"\x00").digest()]
    for _ in range(256):
        result.append(hashlib.sha256(b"\x01" + result[-1] + result[-1]).digest())
    return result


EMPTY = empty_hashes()


def revoked_leaf(key, revocation_ref):
    ref_hash = hashlib.sha256(canonical_bytes(revocation_ref)).digest()
    return hashlib.sha256(b"\x02" + bytes.fromhex(key) + ref_hash).digest()


def proof_root(key, proof, start):
    if not isinstance(proof, dict) or set(proof) != {"siblings"}:
        return None
    siblings = proof["siblings"]
    if not isinstance(siblings, list):
        return None
    by_height = {}
    prior_height = -1
    for sibling in siblings:
        if not isinstance(sibling, dict) or set(sibling) != {"height", "hash"}:
            return None
        height = sibling["height"]
        value = sibling["hash"]
        if not isinstance(height, int) or isinstance(height, bool) or not prior_height < height < 256:
            return None
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            return None
        raw = bytes.fromhex(value)
        if raw == EMPTY[height]:
            return None
        by_height[height] = raw
        prior_height = height
    index = int(key, 16)
    running = start
    for height in range(256):
        sibling = by_height.get(height, EMPTY[height])
        if (index >> height) & 1:
            running = hashlib.sha256(b"\x01" + sibling + running).digest()
        else:
            running = hashlib.sha256(b"\x01" + running + sibling).digest()
    return running.hex()


def canonical_decimal(value):
    return isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value) is not None


def marker_tuple(marker, seller):
    return {
        "sellerPrimaryClaim": seller,
        "listingId": marker.get("listingId"),
        "listingVersion": marker.get("listingVersion"),
        "listingContentHash": marker.get("listingContentHash"),
    }


def resolve_marker(context, ref, expected_tuple=None):
    candidates = [item for item in context.get("resolvedMarkers", []) if item.get("revocationRef") == ref]
    if len(candidates) != 1:
        return None
    candidate = candidates[0]
    marker = candidate.get("marker")
    authority = candidate.get("authority")
    receipt = candidate.get("receipt")
    if not isinstance(authority, dict) or authority.get("disposition") != "verified":
        return None
    if authority.get("claim") != ref.get("signer"):
        return None
    if not verify_artifact(marker, authority.get("key", ""), MARKER_DOMAIN):
        return None
    if artifact_hash(marker) != ref.get("contentHash"):
        return None
    if marker.get("signature", {}).get("signer") != ref.get("signer"):
        return None
    anchor = ref.get("anchor")
    if not isinstance(receipt, dict) or not isinstance(anchor, dict):
        return None
    if (
        receipt.get("state") != "finalized"
        or receipt.get("observationDisposition") != "established"
        or receipt.get("nativeAddress") != anchor.get("locator")
        or receipt.get("contentHash") != ref.get("contentHash")
    ):
        return None
    resolved_tuple = marker_tuple(marker, ref.get("signer"))
    if expected_tuple is not None and resolved_tuple != expected_tuple:
        return None
    return resolved_tuple


def validate_head_item(item, listing, state_ref):
    if not isinstance(item, dict) or set(item) != {"head", "receipt", "authority"}:
        return None
    head = item["head"]
    receipt = item["receipt"]
    authority = item["authority"]
    if not isinstance(head, dict) or head.get("revocationStateHeadVersion") != "1":
        return None
    if authority.get("disposition") != "verified" or authority.get("claim") != listing["sellerPrimaryClaim"]:
        return None
    if not verify_artifact(head, authority.get("key", ""), HEAD_DOMAIN):
        return None
    if head.get("signature", {}).get("signer") != listing["sellerPrimaryClaim"]:
        return None
    if head.get("sellerPrimaryClaim") != listing["sellerPrimaryClaim"] or head.get("logicalAddress") != state_ref["logicalAddress"]:
        return None
    digest = artifact_hash(head)
    if (
        receipt.get("state") != "finalized"
        or receipt.get("observationDisposition") != "established"
        or receipt.get("logicalAddress") != state_ref["logicalAddress"]
        or receipt.get("nativeAddress") != state_ref["anchor"]["locator"]
        or receipt.get("contentHash") != digest
    ):
        return None
    if not canonical_decimal(head.get("sequence")) or not canonical_decimal(head.get("entryCount")):
        return None
    return head, digest


def validate_transition(head, previous, previous_digest, context):
    sequence = int(head["sequence"])
    if sequence != int(previous["sequence"]) + 1 or head.get("previousHeadHash") != previous_digest:
        return False
    transition = head.get("transition")
    if not isinstance(transition, dict) or set(transition) != {"leafKey", "revocationRef", "priorProof"}:
        return False
    key = transition["leafKey"]
    if not isinstance(key, str) or re.fullmatch(r"[0-9a-f]{64}", key) is None:
        return False
    if proof_root(key, transition["priorProof"], EMPTY[0]) != previous.get("rootHash"):
        return False
    resolved_tuple = resolve_marker(context, transition["revocationRef"])
    if resolved_tuple is None or hash_hex(resolved_tuple) != key:
        return False
    return proof_root(
        key,
        transition["priorProof"],
        revoked_leaf(key, transition["revocationRef"]),
    ) == head.get("rootHash")


def evaluate(data):
    listing = data.get("listing")
    if data.get("currentProfile") is not True or not isinstance(listing, dict):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if listing.get("authenticated") is not True:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    state_ref = listing.get("revocationState")
    if not isinstance(state_ref, dict):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if set(state_ref) != {"revocationStateRefVersion", "logicalAddress", "anchor", "checkpointSequence", "checkpointHeadHash"}:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if state_ref.get("revocationStateRefVersion") != "1" or not canonical_decimal(state_ref.get("checkpointSequence")):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    expected_logical = f"dacs1-revocations:{cf4(listing.get('sellerPrimaryClaim', ''))}"
    if state_ref.get("logicalAddress") != expected_logical:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}

    context = data.get("resolutionContext")
    if not isinstance(context, dict):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    evidence = context.get("currentStateEvidence")
    if (
        not isinstance(evidence, dict)
        or set(evidence) != {"policy", "finalizedStateId", "valueContentHash", "evidence"}
        or evidence.get("policy") != "demos-current-state-v1"
    ):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if evidence.get("evidence", {}).get("value") != "current-proof":
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}

    history = context.get("headHistory")
    if not isinstance(history, list) or not history:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    validated = []
    for item in history:
        value = validate_head_item(item, listing, state_ref)
        if value is None:
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        validated.append(value)
    first, _ = validated[0]
    if first.get("sequence") != "0":
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}

    checkpoints = [
        head for head, digest in validated
        if head.get("sequence") == state_ref.get("checkpointSequence")
        and digest == state_ref.get("checkpointHeadHash")
    ]
    if len(checkpoints) != 1 or int(validated[-1][0]["sequence"]) < int(state_ref["checkpointSequence"]):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}

    for index, (head, digest) in enumerate(validated):
        sequence = int(head["sequence"])
        if int(head["entryCount"]) != sequence:
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        if index == 0 and sequence == 0:
            if head.get("previousHeadHash") != ZERO_HASH or "transition" in head or head.get("rootHash") != EMPTY[256].hex():
                return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
            continue
        if index == 0:
            continue
        previous, previous_digest = validated[index - 1]
        if not validate_transition(head, previous, previous_digest, context):
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}

    current, current_hash = validated[-1]
    head_ref = context.get("headRef")
    head_receipt = context.get("headReceipt")
    if not isinstance(head_ref, dict) or not isinstance(head_receipt, dict):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if (
        head_ref.get("contentHash") != current_hash
        or head_ref.get("anchor") != state_ref.get("anchor")
        or head_ref.get("signer") != listing.get("sellerPrimaryClaim")
    ):
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if evidence.get("valueContentHash") != current_hash or head_receipt != history[-1]["receipt"]:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if context.get("headReceiptHistory") != [item["receipt"] for item in history]:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}

    for conflict in context.get("knownConflictingHeads", []):
        checked = validate_head_item(conflict, listing, state_ref)
        if checked is None:
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        conflicting, conflicting_hash = checked
        for accepted, accepted_hash in validated:
            if (
                conflicting.get("sequence") == accepted.get("sequence")
                and conflicting.get("previousHeadHash") == accepted.get("previousHeadHash")
                and conflicting_hash != accepted_hash
            ):
                predecessor = next(
                    ((head, digest) for head, digest in validated if digest == conflicting.get("previousHeadHash")),
                    None,
                )
                if predecessor is None or not validate_transition(
                    conflicting, predecessor[0], predecessor[1], context
                ):
                    return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
                return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}

    target = {
        "sellerPrimaryClaim": listing.get("sellerPrimaryClaim"),
        "listingId": listing.get("listingId"),
        "listingVersion": listing.get("listingVersion"),
        "listingContentHash": listing.get("listingContentHash"),
    }
    key = hash_hex(target)
    proof = context.get("stateProof")
    if not isinstance(proof, dict) or proof.get("revocationStateProofVersion") != "1":
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    if proof.get("headContentHash") != current_hash or proof.get("leafKey") != key:
        return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
    disposition = proof.get("disposition")
    if disposition == "absent":
        if "revocationRef" in proof or proof_root(key, proof.get("proof"), EMPTY[0]) != current.get("rootHash"):
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        return "pass", {"revocationCheck": "absent", "session": "continue"}
    if disposition == "revoked":
        ref = proof.get("revocationRef")
        if not isinstance(ref, dict) or proof_root(key, proof.get("proof"), revoked_leaf(key, ref)) != current.get("rootHash"):
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        if resolve_marker(context, ref, target) is None:
            return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}
        return "fail", {"revocationCheck": "revoked", "session": "refuse"}
    return "indeterminate", {"revocationCheck": "indeterminate", "session": "refuse"}


class RevocationStateCompletenessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_metadata_and_hash(self):
        vectors = self.document["vectors"]
        encoded = json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()
        self.assertEqual(self.document["count"], len(vectors))
        self.assertEqual(self.document["hash"], hashlib.sha256(encoded).hexdigest())
        self.assertEqual(len({item["name"] for item in vectors}), len(vectors))

    def test_independent_evaluator(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                expected, want = evaluate(vector["input"])
                self.assertEqual((expected, want), (vector["expected"], vector["want"]))

    def test_acceptance_cases_are_explicit(self):
        names = {item["name"] for item in self.document["vectors"]}
        self.assertTrue({
            "rsc-censored-tombstone",
            "rsc-stale-signed-head",
            "rsc-two-equivocated-heads",
            "rsc-invalid-nonmembership",
            "rsc-valid-active-nonmembership",
            "rsc-valid-revocation-inclusion",
        } <= names)

    def test_generator_is_deterministic(self):
        completed = subprocess.run(
            ["python3", str(GENERATOR), "--check"], cwd=ROOT,
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_spec_and_mapping_pin_fail_closed_boundary(self):
        spec = SPEC.read_text(encoding="utf-8")
        core = CORE.read_text(encoding="utf-8")
        mapping = MAPPING.read_text(encoding="utf-8")
        self.assertIn("**DACS-1 v0.8**", spec)
        self.assertIn("(RSC-1)", spec)
        self.assertIn("(RSC-9)", spec)
        self.assertIn('"dacs-revocation-state-head:v1:"', core)
        self.assertIn("cannot produce current RSC `absent`", spec)
        self.assertIn("cannot satisfy DACS-1 RSC-3", mapping)


if __name__ == "__main__":
    unittest.main()
