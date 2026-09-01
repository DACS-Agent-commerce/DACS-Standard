import hashlib
import ipaddress
import json
import re
import unicodedata
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
PROFILE_VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?$"
)


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def canonical_host(value):
    if not isinstance(value, str) or value != value.strip() or value.endswith("."):
        raise ValueError("not a hostname")
    normalized = unicodedata.normalize("NFC", value)
    if any(c in normalized for c in ":/@?#*[]"):
        raise ValueError("not a hostname")
    try:
        ascii_host = idna.encode(normalized, uts46=False, std3_rules=True).decode("ascii").lower()
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


def authenticated_profile_at_least(vector, minimum):
    profile = vector.get("authenticatedProducerProfile")
    if not isinstance(profile, dict):
        raise ValueError("missing authenticated producer profile")
    value = profile.get("dacs1Version")
    match = PROFILE_VERSION.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError("invalid authenticated DACS-1 version")
    actual = tuple(int(part or 0) for part in match.groups())
    return actual >= minimum


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


def presentation_controls_account(vector, artifact, account):
    """DCR-7 control over the already-verified bundle presentation.

    ``authenticatedSr1Binding`` models the output of the substrate's SR-1
    resolver, not a caller assertion.  It must bind the GCR account to both the
    session key that verified this artifact and this exact presentation hash.
    """
    if artifact["signingPublicKey"] == account:
        return True
    binding = vector.get("authenticatedSr1Binding")
    return (
        isinstance(binding, dict)
        and binding.get("authenticated") is True
        and binding.get("account") == account
        and binding.get("sessionPublicKey") == artifact["signingPublicKey"]
        and binding.get("boundPresentationHash") == artifact["contentHash"]
    )


def evaluate(vector):
    artifact = vector["artifact"]
    if not verify_artifact(artifact):
        return "fail", []

    try:
        current_profile = authenticated_profile_at_least(vector, (0, 6, 0))
    except ValueError:
        return "error", []

    refs = [claim["ref"] for claim in artifact["unsigned"]["claims"]]
    try:
        semantic = list(dict.fromkeys(semantic_ref(ref) for ref in refs))
    except ValueError:
        return "error", []

    # DCR-1 exact spelling is selected by the current ``domain:`` scheme, not
    # by a producer-controlled version literal.  DCR-3's legacy-alias emission
    # ban separately uses authenticated release/profile context.
    if any(ref.startswith("domain:") and ref != semantic_ref(ref) for ref in refs):
        return "fail", semantic
    has_alias = any(ref.startswith("web2:domain:") for ref in refs)
    if current_profile and has_alias:
        return "fail", semantic

    # DCR-5 identity-set cases deliberately stop before GCR verification: the
    # vector exercises only whether distinct canonical hosts remain distinct.
    if vector.get("evaluationScope") == "semantic-claim-set":
        return "pass", semantic

    if not vector["sourceAvailable"]:
        return "indeterminate", semantic
    source_auth = vector.get("sourceAuthentication")
    if not isinstance(source_auth, dict):
        return "indeterminate", semantic
    if source_auth.get("inclusionProofCoversTransaction") is not True:
        return "indeterminate", semantic
    if source_auth.get("blockFinalized") is not True:
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

    writer = vector.get("writerAuthorization")
    if not isinstance(writer, dict) or writer.get("authenticated") is not True:
        return "indeterminate", semantic
    if not HEX64.fullmatch(writer.get("writer", "")):
        return "error", semantic
    if not HEX64.fullmatch(writer.get("authorizedAccount", "")):
        return "error", semantic
    if writer["authorizedAccount"] != authority.get("account"):
        return "fail", semantic
    try:
        proof_ok = verify_registration_validation(md, vector["registrationValidation"])
    except ValueError:
        return "error", semantic
    if not proof_ok:
        return "fail", semantic
    verified_at = md["recordedAt"]
    valid_until = verified_at + vector["recipeDefaultMaxAgeSec"] * 1000
    if vector["evaluatedAt"] > valid_until:
        return "fail", semantic

    reported = vector.get("reportedVerifyResult")
    if reported is not None:
        if not isinstance(reported, dict):
            return "error", semantic
        times = [reported.get(k) for k in ("verifiedAt", "fetchedAt", "validUntil")]
        if any(not isinstance(value, int) or isinstance(value, bool) for value in times):
            return "error", semantic
        if reported["verifiedAt"] != verified_at:
            return "fail", semantic
        if reported["fetchedAt"] != vector["evaluatedAt"]:
            return "fail", semantic
        if reported["validUntil"] > valid_until:
            return "fail", semantic

    if not presentation_controls_account(vector, artifact, md["account"]):
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

    def test_issue_332_gap_cases_are_attributed(self):
        expected = {
            "DCR-1": {
                "label-length-63-boundary",
                "label-length-64-rejected",
                "hostname-length-253-boundary",
                "hostname-length-254-rejected",
                "invalid-punycode-a-label-rejected",
                "current-producer-u-label-rejected",
                "current-producer-uppercase-host-rejected",
                "future-profile-uppercase-host-rejected",
                "patch-profile-uppercase-host-rejected",
                "historical-profile-domain-u-label-rejected",
            },
            "DCR-2": {"all-numeric-non-ip-hostname"},
            "DCR-4": {
                "legacy-mixed-case-ascii-read",
                "legacy-mixed-case-invalid-signature-rejected-before-fold",
            },
            "DCR-5": {
                "distinct-hosts-remain-distinct",
                "current-producer-dual-alias-rejected",
                "future-profile-dual-alias-rejected",
            },
            "DCR-7": {
                "authenticated-sr1-session-binding",
                "sr1-link-without-presentation-binding",
                "sr1-link-bound-to-different-presentation",
            },
            "DGCR-1": {
                "inclusion-proof-does-not-cover-transaction",
                "carrying-block-not-finalized",
            },
            "DGCR-2": {
                "authenticated-node-writer-for-bound-account",
                "writer-not-authorized-for-bound-account",
                "wrong-native-context-with-matching-record",
            },
            "DGCR-4": {
                "inclusion-time-window-exact",
                "reissued-verified-at-cannot-refresh",
                "valid-until-cannot-exceed-inclusion-window",
            },
        }
        actual = {rule: set() for rule in expected}
        for vector in self.doc["vectors"]:
            for rule in vector.get("ruleRefs", []):
                if rule in actual:
                    actual[rule].add(vector["name"])
        self.assertEqual(expected, actual)

    def test_current_spelling_is_exact_but_legacy_ascii_case_is_readable(self):
        cases = {v["name"]: v for v in self.doc["vectors"]}
        verdict, semantic = evaluate(cases["legacy-mixed-case-ascii-read"])
        self.assertEqual("pass", verdict)
        self.assertEqual(["domain:agent.example"], semantic)
        for name in (
            "current-producer-u-label-rejected",
            "current-producer-uppercase-host-rejected",
            "future-profile-uppercase-host-rejected",
            "patch-profile-uppercase-host-rejected",
            "historical-profile-domain-u-label-rejected",
        ):
            verdict, _ = evaluate(cases[name])
            self.assertEqual("fail", verdict)

    def test_authenticated_profile_controls_only_alias_emission(self):
        cases = {v["name"]: v for v in self.doc["vectors"]}
        for vector in cases.values():
            self.assertNotIn("producerDacs1Version", vector["artifact"]["unsigned"])
            self.assertIn("dacs1Version", vector["authenticatedProducerProfile"])
        self.assertEqual("pass", evaluate(cases["historical-alias-pair-deduplicates"])[0])
        self.assertEqual("fail", evaluate(cases["current-producer-dual-alias-rejected"])[0])
        self.assertEqual("fail", evaluate(cases["future-profile-dual-alias-rejected"])[0])

    def test_invalid_legacy_signature_stops_before_semantic_fold(self):
        vector = next(
            v for v in self.doc["vectors"]
            if v["name"] == "legacy-mixed-case-invalid-signature-rejected-before-fold"
        )
        self.assertFalse(verify_artifact(vector["artifact"]))
        self.assertEqual(("fail", []), evaluate(vector))

    def test_dcr1_and_dcr2_hostname_boundaries(self):
        cases = {v["name"]: v for v in self.doc["vectors"]}
        for name in ("label-length-63-boundary", "hostname-length-253-boundary"):
            verdict, _ = evaluate(cases[name])
            self.assertEqual("pass", verdict)
        for name in (
            "label-length-64-rejected",
            "hostname-length-254-rejected",
            "invalid-punycode-a-label-rejected",
        ):
            verdict, _ = evaluate(cases[name])
            self.assertEqual("error", verdict)
        verdict, semantic = evaluate(cases["all-numeric-non-ip-hostname"])
        self.assertEqual("pass", verdict)
        self.assertEqual(["domain:1.2.3.4.5"], semantic)

    def test_dcr5_distinct_hosts_do_not_false_merge(self):
        vector = next(v for v in self.doc["vectors"]
                      if v["name"] == "distinct-hosts-remain-distinct")
        verdict, semantic = evaluate(vector)
        self.assertEqual("pass", verdict)
        self.assertEqual(vector["want"]["semanticClaims"], semantic)
        self.assertEqual(2, len(semantic))

    def test_dcr7_sr1_binding_is_presentation_specific(self):
        cases = {v["name"]: v for v in self.doc["vectors"]}
        self.assertEqual("pass", evaluate(cases["authenticated-sr1-session-binding"])[0])
        self.assertEqual("fail", evaluate(cases["sr1-link-without-presentation-binding"])[0])
        self.assertEqual("fail", evaluate(cases["sr1-link-bound-to-different-presentation"])[0])

        broken = json.loads(json.dumps(cases["authenticated-sr1-session-binding"]))
        broken["authenticatedSr1Binding"]["sessionPublicKey"] = "11" * 32
        self.assertEqual("fail", evaluate(broken)[0])

    def test_dgcr1_finality_and_inclusion_are_indeterminate(self):
        cases = {v["name"]: v for v in self.doc["vectors"]}
        self.assertEqual(
            "indeterminate",
            evaluate(cases["inclusion-proof-does-not-cover-transaction"])[0],
        )
        self.assertEqual(
            "indeterminate", evaluate(cases["carrying-block-not-finalized"])[0],
        )

    def test_dgcr2_writer_authorization_is_a_relation(self):
        cases = {v["name"]: v for v in self.doc["vectors"]}
        node_write = cases["authenticated-node-writer-for-bound-account"]
        self.assertNotEqual(
            node_write["writerAuthorization"]["writer"],
            node_write["authoritativeGcr"]["account"],
        )
        self.assertEqual("pass", evaluate(node_write)[0])
        self.assertEqual("fail", evaluate(cases["writer-not-authorized-for-bound-account"])[0])
        self.assertEqual("fail", evaluate(cases["wrong-native-context-with-matching-record"])[0])

    def test_dgcr4_window_is_derived_from_inclusion_time(self):
        cases = {v["name"]: v for v in self.doc["vectors"]}
        exact = cases["inclusion-time-window-exact"]
        reported = exact["reportedVerifyResult"]
        recorded_at = exact["authoritativeGcr"]["recordedAt"]
        self.assertEqual(recorded_at, reported["verifiedAt"])
        self.assertEqual(
            recorded_at + exact["recipeDefaultMaxAgeSec"] * 1000,
            reported["validUntil"],
        )
        self.assertEqual("pass", evaluate(exact)[0])
        self.assertEqual("fail", evaluate(cases["reissued-verified-at-cannot-refresh"])[0])
        self.assertEqual(
            "fail", evaluate(cases["valid-until-cannot-exceed-inclusion-window"])[0],
        )


if __name__ == "__main__":
    unittest.main()
