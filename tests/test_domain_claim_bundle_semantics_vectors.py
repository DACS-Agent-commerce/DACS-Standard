"""Bundle-level executable vectors for the canonical domain claim (#275).

Self-contained: RFC-8032 Ed25519 *verification* only (no cryptography import;
the signing seed is public and lives outside this file), plus a deliberately
minimal re-implementation of the DACS-1 evaluation rules this PR adds. Each
matcher branch cites the exact spec clause it implements so drift between the
test and the prose is auditable (Stage-2b divergence control).

Fixture: ``conformance/fixtures/identity/domain-claim-bundle-semantics.json``.
Vectors: V3 original-byte signature/hash preservation; V4 semantic-claim dedup
+ ordered ``oneOf`` consumption; V6 host/account mismatch; V7 unavailable
authority (indeterminate vs error); V8 proof metadata; V9 persistent-not-fresh.
"""
from __future__ import annotations

import base64
import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "conformance" / "fixtures" / "identity" / "domain-claim-bundle-semantics.json"

# --------------------------------------------------------------------------- #
# Self-contained Ed25519 verification (RFC 8032), verify-only. Mirrors the
# approach in tests/test_listing_preserve_unknown_vectors.py.
# --------------------------------------------------------------------------- #
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _x_recover(y):
    xx = ((y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q)) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if (x * x - xx) % _Q != 0:
        raise ValueError("point is not on the Ed25519 curve")
    return _Q - x if x & 1 else x


_BASE_Y = (4 * pow(5, _Q - 2, _Q)) % _Q
_BASE = (_x_recover(_BASE_Y), _BASE_Y)


def _point_add(p, q):
    x1, y1 = p
    x2, y2 = q
    prod = (_D * x1 * x2 * y1 * y2) % _Q
    x3 = ((x1 * y2 + x2 * y1) * pow(1 + prod, _Q - 2, _Q)) % _Q
    y3 = ((y1 * y2 + x1 * x2) * pow(1 - prod, _Q - 2, _Q)) % _Q
    return x3, y3


def _scalar_mult(p, e):
    r = (0, 1)
    a = p
    while e:
        if e & 1:
            r = _point_add(r, a)
        a = _point_add(a, a)
        e >>= 1
    return r


def _decode_point(enc):
    if len(enc) != 32:
        raise ValueError("Ed25519 point must be 32 bytes")
    raw = int.from_bytes(enc, "little")
    y = raw & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("non-canonical Ed25519 point")
    x = _x_recover(y)
    if (x & 1) != (raw >> 255):
        x = _Q - x
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _Q != 0:
        raise ValueError("point is not on the Ed25519 curve")
    return x, y


def verify_ed25519(public_key: bytes, signature: bytes, message: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    try:
        enc_r = signature[:32]
        point_r = _decode_point(enc_r)
        point_a = _decode_point(public_key)
    except ValueError:
        return False
    k = int.from_bytes(hashlib.sha512(enc_r + public_key + message).digest(), "little") % _L
    return _scalar_mult(_BASE, s) == _point_add(point_r, _scalar_mult(point_a, k))


def _b64url(v: str) -> bytes:
    return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def artifact_hash(document: dict, omitted: str) -> str:
    unsigned = {k: v for k, v in document.items() if k != omitted}
    return hashlib.sha256(canonical_json(unsigned)).hexdigest()


# --------------------------------------------------------------------------- #
# Minimal DACS-1 evaluation model (each branch cites its spec clause).
# --------------------------------------------------------------------------- #
def effective_ref(ref: str) -> str:
    """DACS-1 §6.3.2 Layer-2: canonicalise a claim ref into its effective
    reference. A legacy ``web2:domain:<host>`` alias resolves to
    ``domain:<lowercased-host>``; every other ref is its own effective
    reference. (Strict host validity is exercised by the canonicalization
    runner; here we only need the alias→canonical identity map for dedup.)"""
    if ref.startswith("web2:domain:"):
        return "domain:" + ref[len("web2:domain:"):].lower()
    return ref


def semantic_claims(claims: list[dict]) -> dict:
    """DACS-1 §6.3.3 rule 1 (identity equivalence): group claims by canonical
    effective identity — two aliases for one host are ONE semantic claim.
    Rules 2/3 (evidence independent; conflict fails closed): a semantic claim
    is verified iff at least one equivalent claim is verified AND no two
    equivalent claims carry contradictory decisions."""
    groups: dict[str, list[dict]] = {}
    for c in claims:
        groups.setdefault(effective_ref(c["ref"]), []).append(c)
    verified_by_identity: dict[str, bool] = {}
    for ident, members in groups.items():
        decisions = {m.get("decision") for m in members if m.get("verified")}
        any_verified = any(m.get("verified") for m in members)
        conflict = "pass" in decisions and "fail" in decisions  # rule 3, fail-closed
        verified_by_identity[ident] = bool(any_verified) and not conflict
    return {"count": len(groups), "verifiedByIdentity": verified_by_identity}


def evaluate_oneof(claims: list[dict], groups: list[list[str]]) -> dict:
    """DACS-1 §6.3.3 rule 4 (ordered, greedy oneOf consumption): groups are
    evaluated in declared order; a semantic claim is consumed by the FIRST
    group it satisfies and MUST NOT satisfy a later group. A requirement is
    accepted only if every group is satisfied."""
    available = {effective_ref(c["ref"]) for c in claims}  # distinct semantic claims
    satisfied: list[bool] = []
    for group in groups:
        wanted = {effective_ref(r) for r in group}
        hit = next((ident for ident in wanted if ident in available), None)
        if hit is not None:
            available.discard(hit)  # consumed — cannot satisfy a later group
            satisfied.append(True)
        else:
            satisfied.append(False)
    return {"groupSatisfied": satisfied, "accepted": all(satisfied)}


PROOF_PATH = "/.well-known/demos-cci.txt"


def proof_url(identifier: str, proof_path_template: str = PROOF_PATH) -> str:
    """DACS-2 §7.3.10 metadata: derive the proof URL from the identifier and
    the recipe's proofPathTemplate — a derivation, never a presenter value."""
    return f"https://{identifier}{proof_path_template}"


def demos_gcr_verify(
    identifier: str, claim_account: str, gcr_result: dict, session_nonce: object = None
) -> dict:
    """DACS-2 §7.3.10 procedure → §7.5.1 decision values. Consumes the
    consensus-recorded GCR result (no refetch); carries only already-public
    §7.5 metadata. ``session_nonce`` is accepted to model a per-session
    context but is DELIBERATELY UNUSED: the result is persistent
    ownership-and-key evidence (§7.3.10 persistence), so a changing session
    nonce MUST NOT alter the verdict or the result — V9 asserts exactly that
    invariance over a real varying nonce input."""
    del session_nonce  # persistence: the verdict must not depend on it
    avail = gcr_result["availability"]
    if avail == "transport-error":
        return {"decision": "error", "data": None}          # §7.5.1: verifier could not complete
    if avail == "not-found":
        # §7.5.1 indeterminate + DEMOS-MAPPING §A.2: a Demos not-found is
        # authoritative-absence-inconclusive, never fail.
        return {"decision": "indeterminate", "data": None}
    data = {
        "proofUrl": proof_url(identifier),
        "boundAccount": gcr_result["boundAccount"],
        "gcrRecordRef": gcr_result.get("recordRef"),
        "sourceTx": gcr_result["sourceTx"],
    }
    if gcr_result["boundHost"] == identifier and gcr_result["boundAccount"] == claim_account:
        return {"decision": "pass", "data": data}           # §7.5.1: authority confirms
    return {"decision": "fail", "data": data}               # §7.5.1: conclusively contradicts (V6)


def is_fresh(verified_at: int, valid_until: int, now: int) -> bool:
    """DACS-1 §6.3.2 effective-window gate (minimal): fresh iff now <= expiry.
    This is the persistence boundary V9 asserts — the GCR result is accepted
    only inside its effective window, not gated on any per-session challenge."""
    return now <= valid_until and verified_at <= now


def _load() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class DomainClaimBundleSemanticsVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = _load()
        cls.public_keys = {k: _b64url(v) for k, v in cls.data["publicKeys"].items()}

    def test_kind_and_specrefs(self):
        self.assertEqual(self.data["kind"], "DomainClaimBundleSemanticsCases")
        self.assertTrue(all(r.startswith("§") for r in self.data["specRefs"]))

    def _verify_presentation(self, bundle: dict, domain: str) -> tuple[str, bool]:
        bundle_hash = artifact_hash(bundle, "presentation")
        sig_entry = bundle["presentation"]["signatures"][0]
        signer = sig_entry["ref"]
        ok = verify_ed25519(
            self.public_keys[signer],
            base64.b64decode(sig_entry["signature"]),
            (domain + bundle_hash).encode("ascii"),
        )
        return bundle_hash, ok

    def test_v3_original_byte_signature_and_hash_preserved(self):
        sb = self.data["signedBundle"]
        bundle = sb["bundle"]
        domain = sb["bundlePresentationDomain"]
        # Verify over the bytes AS RECEIVED (web2:domain: verbatim in the hash).
        bundle_hash, ok = self._verify_presentation(bundle, domain)
        self.assertEqual(bundle_hash, sb["expectedBundleHash"])
        self.assertTrue(ok, "presentation signature must verify over original bytes")
        # Layer-2 resolution runs on a copy; the signed artifact is NOT rewritten
        # or re-hashed (§6.3.2 rule 3). Recompute over the untouched bundle.
        effective = [effective_ref(c["ref"]) for c in bundle["claims"]]
        self.assertEqual(effective, sb["expectedEffectiveRefs"])
        bundle_hash_2, ok_2 = self._verify_presentation(bundle, domain)
        self.assertEqual(bundle_hash_2, bundle_hash, "resolution must not change the hash")
        self.assertTrue(ok_2, "signature must still verify after resolution")
        # And the raw alias bytes are untouched in the artifact.
        self.assertEqual(bundle["claims"][1]["ref"], "web2:domain:alice.example")

    def test_v3_tamper_breaks_signature(self):
        sb = self.data["signedBundle"]
        tampered = json.loads(json.dumps(sb["bundle"]))
        tampered["claims"][1]["ref"] = "web2:domain:evil.example"
        _, ok = self._verify_presentation(tampered, sb["bundlePresentationDomain"])
        self.assertFalse(ok, "a mutated claim ref must break the presentation signature")

    def test_v4_dedup(self):
        for case in self.data["dedupCases"]:
            with self.subTest(case=case["id"]):
                result = semantic_claims(case["claims"])
                self.assertEqual(result["count"], case["expected"]["semanticClaimCount"])
                self.assertEqual(
                    result["verifiedByIdentity"], case["expected"]["verifiedByIdentity"]
                )

    def test_v4_oneof_consumption(self):
        for case in self.data["oneOfCases"]:
            with self.subTest(case=case["id"]):
                result = evaluate_oneof(case["claims"], case["oneOf"])
                self.assertEqual(result["groupSatisfied"], case["expected"]["groupSatisfied"])
                self.assertEqual(result["accepted"], case["expected"]["accepted"])

    def test_v6_v7_v8_method_results(self):
        for case in self.data["methodCases"]:
            with self.subTest(case=case["id"]):
                res = demos_gcr_verify(case["identifier"], case["claimAccount"], case["gcrResult"])
                exp = case["expected"]
                self.assertEqual(res["decision"], exp["decision"])
                if "dataBoundAccount" in exp:
                    self.assertEqual(res["data"]["boundAccount"], exp["dataBoundAccount"])
                if "dataProofUrl" in exp:
                    self.assertEqual(res["data"]["proofUrl"], exp["dataProofUrl"])
                    # proofUrl is a derivation, not a supplied value.
                    self.assertEqual(
                        res["data"]["proofUrl"],
                        proof_url(case["identifier"], self.data["proofPathTemplate"]),
                    )
                if "dataSourceTx" in exp:
                    self.assertEqual(res["data"]["sourceTx"], exp["dataSourceTx"])

    def test_v9_persistent_not_fresh(self):
        p = self.data["persistenceCases"]
        exp = p["expected"]
        nonce_a, nonce_b = p["sessionNonceA"], p["sessionNonceB"]
        # The two contexts differ ONLY in the session nonce — a real varying
        # input, and it must actually vary (else invariance would be vacuous).
        self.assertNotEqual(nonce_a, nonce_b, "the two session nonces must differ")
        # (ii) Persistence/nonce-invariance: feed the SAME DemosGCRResultRef under
        # two different session nonces; the verdict AND the whole result must be
        # identical (§7.3.10: the GCR record is not a per-session challenge).
        res_a = demos_gcr_verify(p["identifier"], p["claimAccount"], p["gcrResult"], session_nonce=nonce_a)
        res_b = demos_gcr_verify(p["identifier"], p["claimAccount"], p["gcrResult"], session_nonce=nonce_b)
        self.assertEqual(res_a["decision"], "pass")
        self.assertEqual(res_a["decision"], res_b["decision"], "verdict must not depend on the nonce")
        self.assertEqual(res_a, res_b, "the full result must be invariant over the session nonce")
        self.assertEqual(exp["nonceInvariant"], True)
        # (i) No-binding: neither the result nor its data carries a nonce or
        # challenge field (a persistent record has no session binding).
        self.assertFalse(any(k in res_a for k in ("nonce", "challenge")))
        self.assertFalse(any(k in res_a["data"] for k in ("nonce", "challenge")))
        self.assertEqual(exp["hasNonceField"], False)
        # (iii) Accepted only inside the §6.3.2 effective window (persistence is
        # bounded by freshness, not by a per-session challenge).
        fr = p["freshness"]
        self.assertEqual(
            is_fresh(fr["verifiedAt"], fr["validUntil"], p["nowInWindow"]), exp["freshInWindow"]
        )
        self.assertEqual(
            is_fresh(fr["verifiedAt"], fr["validUntil"], p["nowPastWindow"]), exp["freshPastWindow"]
        )


if __name__ == "__main__":
    unittest.main()
