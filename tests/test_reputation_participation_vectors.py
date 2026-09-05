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
    / "reputation-participation-admission-v0.7.json"
)
GENERATOR = ROOT / "scripts" / "generate_reputation_participation_vectors.py"
SPEC = ROOT / "spec" / "DACS-5-VERIFY.md"
CORE = ROOT / "spec" / "CORE.md"
THREAT_MODEL = ROOT / "spec" / "THREAT-MODEL.md"
PARTICIPATION_DOMAIN = "dacs-participation-admission:v1:"
RATING_DOMAIN = "dacs-rating:v1:"


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def hash_hex(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def verify_component(artifact, domain):
    if not isinstance(artifact, dict):
        return False
    unsigned = dict(artifact)
    signature = unsigned.pop("signature", None)
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
        return False
    signer = signature.get("signer")
    value = signature.get("value")
    if not isinstance(signer, str) or not signer.startswith("key:") or not isinstance(value, str):
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
        if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
            return False
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer[4:]))
        public.verify(raw, (domain + hash_hex(unsigned)).encode("ascii"))
    except (ValueError, InvalidSignature):
        return False
    return True


def vector_hash(vectors):
    encoded = json.dumps(vectors, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def result(*, admitted=False, blame=False, rating=False, external=False):
    return {
        "reputationDisposition": "admitted" if admitted else "excluded",
        "oneSidedBlame": blame,
        "ratingCounted": rating,
        "externalAdmissionConsumed": external,
    }


def mapped_obligation(kind):
    if kind == "vet-credentials":
        return "vet-pending", "present-credentials"
    if isinstance(kind, str) and kind.startswith("negotiate-"):
        return "negotiate-pending", "respond-to-negotiation"
    if isinstance(kind, str) and kind.startswith("commit-"):
        return "commit-pending", "co-sign-agreement"
    if isinstance(kind, str) and kind.startswith("pay-") and kind != "pay-alternative":
        return "settle-pending", "authorize-payment"
    if isinstance(kind, str) and kind.startswith("deliver-"):
        return "settle-pending", "deliver"
    return None


def attributed_fault_role(bundle):
    bundle_type = bundle.get("bundleType")
    if bundle_type in {
        "FaultAttestationBundle", "EvidenceBoundFaultAttestationBundle"
    }:
        role = bundle.get("faultedParty")
        return role if role in {"buyer", "seller"} else None
    if bundle_type != "AttestationBundle" or "faultedParty" in bundle:
        return None
    anchored_role = bundle.get("anchoredByRole")
    if anchored_role not in {"buyer", "seller"}:
        return None
    if bundle.get("outcome") == "aborted-by-self":
        return anchored_role
    if bundle.get("outcome") == "aborted-by-other":
        return "seller" if anchored_role == "buyer" else "buyer"
    return None


def evaluate_one_sided(data):
    if data.get("authoritativeAbsenceValid") is not True:
        return "indeterminate", result()

    bundle = data.get("bundle")
    if not isinstance(bundle, dict):
        return "fail", result()
    faulted_role = attributed_fault_role(bundle)
    signer_roles = bundle.get("verifiedSignerRoles")
    if (
        faulted_role is None
        or not isinstance(signer_roles, list)
        or len(signer_roles) != len(set(signer_roles))
        or any(role not in {"buyer", "seller", "orchestrator"} for role in signer_roles)
    ):
        return "fail", result()

    # Only an absolute bundle's hashed faultedParty can self-admit blame. A
    # legacy role-relative outcome can change meaning when its unsigned
    # anchoredByRole projection changes, so it always follows the SPA path.
    if (
        bundle.get("bundleType") in {
            "FaultAttestationBundle", "EvidenceBoundFaultAttestationBundle"
        }
        and faulted_role in signer_roles
    ):
        if data.get("participationEvidence") is not None:
            return "fail", result()
        return "pass", result(admitted=True, blame=True)

    evidence = data.get("participationEvidence")
    timeout = bundle.get("timeout")
    if evidence is None or timeout is None:
        return "indeterminate", result()
    if not isinstance(evidence, dict) or not isinstance(timeout, dict):
        return "fail", result()

    admission = evidence.get("admission")
    if not isinstance(admission, dict):
        return "fail", result()
    if admission.get("participationAdmissionVersion") != "1":
        return "fail", result()
    if not verify_component(admission, PARTICIPATION_DOMAIN):
        return "fail", result()

    parties = bundle.get("parties")
    admitted_parties = admission.get("parties")
    if not isinstance(parties, list) or admitted_parties != parties:
        return "fail", result()
    canonical = sorted(
        admitted_parties,
        key=lambda item: (item.get("role", ""), item.get("primaryClaim", ""), item.get("bundleHash", "")),
    )
    if admitted_parties != canonical:
        return "fail", result()
    role_entries = [item for item in parties if item.get("role") == admission.get("obligorRole")]
    if len(role_entries) != 1:
        return "fail", result()
    if admission.get("obligorRole") != faulted_role:
        return "fail", result()
    if admission["signature"].get("signer") != role_entries[0].get("primaryClaim"):
        return "fail", result()
    if admission.get("jobId") != bundle.get("jobId"):
        return "fail", result()
    if admission.get("listingRef") != bundle.get("listingRef"):
        return "fail", result()

    listing = data.get("listing")
    if not isinstance(listing, dict) or listing.get("verified") is not True:
        return "indeterminate", result()
    if listing.get("listingRef") != bundle.get("listingRef"):
        return "fail", result()
    pipeline = listing.get("effectivePipeline")
    index = admission.get("phaseIndex")
    if not isinstance(index, int) or isinstance(index, bool) or not isinstance(pipeline, list):
        return "fail", result()
    if index < 0 or index >= len(pipeline):
        return "fail", result()
    kind = admission.get("phaseKind")
    if pipeline[index] != kind:
        return "fail", result()

    expected_prefix = [
        {"index": position, "kind": item, "outcome": "ok"}
        for position, item in enumerate(pipeline[:index])
    ]
    if admission.get("completedPrefix") != expected_prefix:
        return "fail", result()
    phase_summary = bundle.get("phaseSummary")
    if not isinstance(phase_summary, list) or len(phase_summary) != index:
        return "fail", result()
    projected_prefix = []
    for entry in phase_summary:
        if not isinstance(entry, dict):
            return "fail", result()
        projected_prefix.append({
            "index": entry.get("index"),
            "kind": entry.get("kind"),
            "outcome": entry.get("outcome"),
        })
    if projected_prefix != expected_prefix:
        return "fail", result()

    mapping = mapped_obligation(kind)
    if mapping is None:
        return "fail", result()
    pending_state, owed_action = mapping
    if admission.get("pendingState") != pending_state or admission.get("owedAction") != owed_action:
        return "fail", result()
    exact_timeout_fields = (
        "pendingState", "phaseIndex", "phaseKind", "obligorRole",
        "owedAction", "deadline", "deadlinePolicy", "deadlineClock",
    )
    if any(timeout.get(field) != admission.get(field) for field in exact_timeout_fields):
        return "fail", result()
    if admission.get("deadlineClock") != "sr2-finalized-inclusion-timestamp":
        return "fail", result()
    if admission.get("deadlinePolicy") != "obligor-admitted-absolute-consensus-deadline":
        return "fail", result()
    deadline = admission.get("deadline")
    if not isinstance(deadline, int) or isinstance(deadline, bool):
        return "fail", result()

    if kind.startswith("commit-"):
        proposal = admission.get("proposedAgreementHash")
        if not isinstance(proposal, str) or re.fullmatch(r"[0-9a-f]{64}", proposal) is None:
            return "fail", result()
        if "agreementRef" in admission:
            return "fail", result()
    elif kind.startswith("pay-") or kind.startswith("deliver-"):
        if admission.get("agreementRef") != bundle.get("agreementRef") or "proposedAgreementHash" in admission:
            return "fail", result()
    elif "agreementRef" in admission or "proposedAgreementHash" in admission:
        return "fail", result()

    nonce = admission.get("sessionNonce")
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        return "fail", result()
    reused_for = evidence.get("noncePreviouslyUsedFor")
    if reused_for is not None and reused_for != admission.get("jobId"):
        return "fail", result()

    receipt = evidence.get("admissionReceipt")
    history = evidence.get("admissionReceiptHistory")
    if receipt is None:
        return "indeterminate", result()
    if not isinstance(receipt, dict) or not isinstance(history, list) or not history:
        return "indeterminate", result()
    if any(item.get("historyDisposition") == "unorderable" for item in history if isinstance(item, dict)):
        return "indeterminate", result()
    if (
        receipt.get("state") != "finalized"
        or receipt.get("observationDisposition") != "established"
        or receipt.get("evidenceValid") is not True
    ):
        return "indeterminate", result()
    admission_ref = evidence.get("admissionRef")
    if not isinstance(admission_ref, dict):
        return "fail", result()
    if admission_ref.get("contentHash") != hash_hex(admission):
        return "fail", result()
    if admission_ref.get("contentHash") != receipt.get("contentHash"):
        return "fail", result()
    anchor = admission_ref.get("anchor")
    if not isinstance(anchor, dict) or anchor.get("locator") != receipt.get("nativeAddress"):
        return "fail", result()
    expected_address = (
        f"dacs5:participation:{admission.get('jobId')}:{admission.get('obligorRole')}:{index}"
    )
    if receipt.get("logicalAddress") != expected_address or receipt.get("writerAuthorized") is not True:
        return "fail", result()
    block_ref = receipt.get("blockRef")
    if not isinstance(block_ref, dict) or not isinstance(block_ref.get("timestamp"), int):
        return "indeterminate", result()

    window_receipt = bundle.get("windowReceipt")
    if not isinstance(window_receipt, dict):
        return "indeterminate", result()
    if (
        window_receipt.get("state") != "finalized"
        or window_receipt.get("observationDisposition") != "established"
        or window_receipt.get("evidenceValid") is not True
    ):
        return "indeterminate", result()
    window_block = window_receipt.get("blockRef")
    if not isinstance(window_block, dict) or not isinstance(window_block.get("timestamp"), int):
        return "indeterminate", result()
    if receipt.get("substrate") != window_receipt.get("substrate"):
        return "indeterminate", result()
    if block_ref["timestamp"] >= deadline or window_block["timestamp"] < deadline:
        return "fail", result()

    return "pass", result(admitted=True, blame=True, external=True)


def evaluate_rating(data):
    listing = data.get("listing")
    if not isinstance(listing, dict) or listing.get("verified") is not True:
        return "indeterminate", result()
    bundle = data.get("bundle")
    rating = data.get("rating")
    rating_ref = data.get("ratingRef")
    if not isinstance(bundle, dict) or not isinstance(rating, dict) or not isinstance(rating_ref, dict):
        return "fail", result()
    if bundle.get("outcome") != "completed" or bundle.get("fullySigned") is not True:
        return "fail", result()
    if rating.get("ratingVersion") != "1" or not verify_component(rating, RATING_DOMAIN):
        return "fail", result()
    if rating_ref.get("contentHash") != hash_hex(rating):
        return "fail", result()
    if rating_ref.get("signer") != rating["signature"].get("signer"):
        return "fail", result()
    if rating_ref not in bundle.get("ratingRefs", []):
        return "fail", result()
    if rating.get("jobId") != bundle.get("jobId"):
        return "fail", result()
    if listing.get("listingRef") != bundle.get("listingRef"):
        return "fail", result()

    parties = bundle.get("parties")
    if not isinstance(parties, list):
        return "fail", result()
    role_by_claim = {}
    for party in parties:
        role = party.get("role")
        claim = party.get("primaryClaim")
        if role not in {"buyer", "seller"}:
            continue
        if claim in role_by_claim:
            return "fail", result()
        role_by_claim[claim] = role
    rater = rating.get("rater")
    target = rating.get("target")
    if rater not in role_by_claim or target not in role_by_claim or rater == target:
        return "fail", result()
    if rating["signature"].get("signer") != rater:
        return "fail", result()
    if rating.get("targetRole") != role_by_claim[target]:
        return "fail", result()
    value = rating.get("value")
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 5:
        return "fail", result()

    pipeline = listing.get("effectivePipeline")
    if not isinstance(pipeline, list) or pipeline.count("rate") != 1:
        return "fail", result()
    rate_index = pipeline.index("rate")
    matching = [
        entry for entry in bundle.get("phaseSummary", [])
        if entry.get("index") == rate_index and entry.get("kind") == "rate"
    ]
    if len(matching) != 1 or matching[0].get("outcome") != "ok":
        return "fail", result()
    return "pass", result(admitted=True, rating=True)


def evaluate(vector):
    data = vector["input"]
    if data.get("currentProfile") is not True:
        return {"expected": "fail", "want": result()}
    if data.get("mode") == "one-sided-blame":
        verdict, want = evaluate_one_sided(data)
    elif data.get("mode") == "rating":
        verdict, want = evaluate_rating(data)
    else:
        verdict, want = "fail", result()
    return {"expected": verdict, "want": want}


class ReputationParticipationVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_vector_metadata(self):
        vectors = self.document["vectors"]
        self.assertEqual(self.document["count"], len(vectors))
        self.assertEqual(self.document["hash"], vector_hash(vectors))
        names = [vector["name"] for vector in vectors]
        self.assertEqual(len(names), len(set(names)))

    def test_independent_reference_evaluator(self):
        for vector in self.document["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    evaluate(vector),
                    {"expected": vector["expected"], "want": vector["want"]},
                )

    def test_generator_is_deterministic(self):
        completed = subprocess.run(
            ["python3", str(GENERATOR), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_acceptance_attacks_are_explicit(self):
        names = {vector["name"] for vector in self.document["vectors"]}
        required = {
            "spa-never-participant-missing-admission",
            "spa-wrong-job-replay",
            "spa-wrong-obligor-role",
            "spa-wrong-deadline",
            "spa-wrong-action",
            "spa-phase-never-active",
            "spa-legacy-one-sided-blame-requires-external-admission",
            "spa-legacy-reanchored-signer-cannot-self-admit",
            "spa-prefix-projection-allows-authenticated-bundle-evidence",
            "spa-rating-on-abort",
            "spa-rating-non-roster-target",
        }
        self.assertTrue(required <= names)

    def test_positive_artifact_signatures_and_refs_are_recomputed(self):
        for vector in self.document["vectors"]:
            if vector["expected"] != "pass":
                continue
            data = vector["input"]
            with self.subTest(vector=vector["name"]):
                if data["mode"] == "one-sided-blame" and data.get("participationEvidence"):
                    evidence = data["participationEvidence"]
                    admission = evidence["admission"]
                    self.assertTrue(verify_component(admission, PARTICIPATION_DOMAIN))
                    self.assertEqual(evidence["admissionRef"]["contentHash"], hash_hex(admission))
                if data["mode"] == "rating":
                    self.assertTrue(verify_component(data["rating"], RATING_DOMAIN))
                    self.assertEqual(data["ratingRef"]["contentHash"], hash_hex(data["rating"]))

    def test_spec_and_shared_security_model_pin_spa(self):
        spec = SPEC.read_text(encoding="utf-8")
        core = CORE.read_text(encoding="utf-8")
        threat = THREAT_MODEL.read_text(encoding="utf-8")
        self.assertIn("**DACS-5 v0.7**", spec)
        self.assertIn("(SPA-1)", spec)
        self.assertIn("(SPA-8)", spec)
        self.assertIn('participationAdmissionVersion: "1"', spec)
        self.assertIn('"dacs-participation-admission:v1:"', core)
        self.assertIn("absence proves non-publication, not participation", spec)
        self.assertIn("invented participant", threat.lower())


if __name__ == "__main__":
    unittest.main()
