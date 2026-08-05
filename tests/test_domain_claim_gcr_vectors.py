import hashlib
import ipaddress
import json
import re
import unittest
from pathlib import Path

import idna
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "vectors" / "security" / "domain-claim-gcr-v0.4.json"
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def canonical_host(value):
    if not isinstance(value, str) or value != value.strip() or value.endswith("."):
        raise ValueError("not a hostname")
    if any(c in value for c in ":/@?#*[]"):
        raise ValueError("not a hostname")
    try:
        ascii_host = idna.encode(value, uts46=False, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise ValueError("bad IDNA") from exc
    if len(ascii_host.encode()) > 253:
        raise ValueError("host too long")
    labels = ascii_host.split(".")
    if not labels or any(not LABEL.fullmatch(label) for label in labels):
        raise ValueError("bad label")
    try:
        ipaddress.ip_address(ascii_host)
    except ValueError:
        pass
    else:
        raise ValueError("IP literal")
    return ascii_host


def semantic_ref(ref):
    if ref.startswith("domain:"):
        host = ref[len("domain:"):]
    elif ref.startswith("web2:domain:"):
        host = ref[len("web2:domain:"):]
    else:
        raise ValueError("not a domain reference")
    return "domain:" + canonical_host(host)


def verify_artifact(artifact):
    canonical = compact(artifact["unsigned"])
    if canonical.hex() != artifact["canonicalHex"]:
        return False
    digest = hashlib.sha256(canonical).digest()
    if digest.hex() != artifact["contentHash"]:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(artifact["signingPublicKey"])).verify(
            bytes.fromhex(artifact["signature"]),
            b"dacs-bundle-presentation:v1:" + digest,
        )
    except (ValueError, InvalidSignature):
        return False
    return True


def verify_registration_validation(md, validation):
    if md.get("context") != "web2.domain" or not HEX64.fullmatch(md.get("account", "")):
        return False
    host = canonical_host(md["hostname"])
    if md.get("proofUrl") != f"https://{host}/.well-known/demos-cci.txt":
        return False
    prefix = "demos:dw2p:ed25519:"
    if validation.get("profile") != "demos-web2-domain-v1":
        return False
    payload = validation.get("proofPayload", "")
    if not payload.startswith(prefix) or not HEX128.fullmatch(payload[len(prefix):]):
        return False
    message = f"dacs-domain:v1:{host}:{md['account']}".encode()
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(md["account"])).verify(
            bytes.fromhex(payload[len(prefix):]), message)
    except (ValueError, InvalidSignature):
        return False
    return True


def evaluate(vector):
    artifact = vector["artifact"]
    if not verify_artifact(artifact):
        return "fail", []

    refs = [claim["ref"] for claim in artifact["unsigned"]["claims"]]
    try:
        semantic = list(dict.fromkeys(semantic_ref(ref) for ref in refs))
    except ValueError:
        return "error", []

    has_alias = any(ref.startswith("web2:domain:") for ref in refs)
    if artifact["unsigned"]["producerDacs1Version"] == "0.6" and has_alias:
        return "fail", semantic
    if not vector["sourceAvailable"]:
        return "indeterminate", semantic
    if not vector["validationProfileAvailable"]:
        return "indeterminate", semantic
    if vector["requiredMethod"] != "demos-gcr-domain":
        return "fail", semantic

    md = artifact["unsigned"]["claims"][0]["metadata"]["demosGcrDomain"]
    authority = vector["authoritativeGcr"]
    if md != authority:
        return "fail", semantic
    if semantic != ["domain:" + canonical_host(md["hostname"])]:
        return "fail", semantic
    try:
        proof_ok = verify_registration_validation(md, vector["registrationValidation"])
    except ValueError:
        return "error", semantic
    if not proof_ok:
        return "fail", semantic
    if vector["evaluatedAt"] > md["recordedAt"] + vector["recipeDefaultMaxAgeSec"] * 1000:
        return "fail", semantic
    if artifact["signingPublicKey"] != md["account"]:
        return "fail", semantic
    return "pass", semantic


class DomainClaimGCRVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_declared_hash_and_count(self):
        vectors = self.doc["vectors"]
        self.assertEqual(self.doc["count"], len(vectors))
        self.assertEqual(self.doc["hash"], hashlib.sha256(compact(vectors)).hexdigest())

    def test_every_vector(self):
        for vector in self.doc["vectors"]:
            with self.subTest(vector=vector["name"]):
                verdict, semantic = evaluate(vector)
                self.assertEqual(vector["expected"], verdict)
                if "semanticClaims" in vector.get("want", {}):
                    self.assertEqual(vector["want"]["semanticClaims"], semantic)
                if "unicodeInput" in vector:
                    self.assertEqual(
                        vector["want"]["semanticClaims"],
                        ["domain:" + canonical_host(vector["unicodeInput"])],
                    )

    def test_legacy_signature_is_checked_before_normalization(self):
        vector = next(v for v in self.doc["vectors"]
                      if v["name"] == "legacy-alias-original-byte-preservation")
        artifact = vector["artifact"]
        self.assertTrue(verify_artifact(artifact))
        self.assertNotEqual(artifact["contentHash"], vector["want"]["rewrittenContentHash"])
        rewritten = json.loads(json.dumps(artifact))
        rewritten["unsigned"]["claims"][0]["ref"] = "domain:agent.example"
        rewritten["unsigned"]["presentedBy"] = "domain:agent.example"
        self.assertFalse(verify_artifact(rewritten))

    def test_dedup_cannot_gain_tier_or_oneof(self):
        vector = next(v for v in self.doc["vectors"]
                      if v["name"] == "historical-alias-pair-deduplicates")
        verdict, semantic = evaluate(vector)
        self.assertEqual("pass", verdict)
        self.assertEqual(1, len(semantic))
        self.assertFalse(vector["want"]["tierGain"])
        self.assertFalse(vector["want"]["oneOfGain"])


if __name__ == "__main__":
    unittest.main()
