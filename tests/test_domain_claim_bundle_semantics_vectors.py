"""Bundle-level executable vectors for the canonical domain claim (#275).

Self-contained: RFC-8032 Ed25519 *verification* only (no cryptography import;
the signing seed is public and lives outside this file), plus a deliberately
minimal re-implementation of the DACS-1/DACS-2 evaluation rules this PR adds.
Each matcher branch cites the exact spec clause it implements so drift between
the test and the prose is auditable (Stage-2b divergence control).

Fixture: ``conformance/fixtures/identity/domain-claim-bundle-semantics.json``.
Vectors:
  * V3 — original-byte signature/hash preservation across Layer-2 resolution.
  * V4 — semantic-claim deduplication (identity equivalence, evidence
    independent, conflict-fails-closed).
  * demos-gcr-domain over AUTHENTICATED GCR evidence (DACS-2 §7.3.10):
    the ten GE-n binding checks (GE-1..GE-10, GE-10 = record↔transaction
    provenance), the three GF-n freshness rules (GF-1..GF-3: verifiedAt derived
    from evidence.recordedAt + anti-reissue; effective-window bound; recordedAt
    future-dating/positive-window sanity), the CR-1 control binding, the
    unavailability→indeterminate mapping, and the persistent-no-session-nonce
    boundary. SB-1/SB-2/SB-3 substrate hooks are modelled synthetically: the
    concrete Demos wire formats are not yet fixed and bind at the substrate
    profile.
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


PROOF_PATH = "/.well-known/demos-cci.txt"


def proof_url(identifier: str, proof_path_template: str = PROOF_PATH) -> str:
    """DACS-2 §7.3.10 metadata: derive the proof URL from the identifier and
    the recipe's proofPathTemplate. Under the authenticated model this local
    derivation is the CHECK (GE-9), never the source of truth — the authority
    RECORD carries the proof URL and must equal this derivation."""
    return f"https://{identifier}{proof_path_template}"


def record_content_hash(gcr_record: dict) -> str:
    """DACS-2 §7.3.10 GE-8: the recordRef.contentHash MUST be sha256 over the
    RFC-8785-style canonical form of the authenticated gcrRecord."""
    return hashlib.sha256(canonical_json(gcr_record)).hexdigest()


# --------------------------------------------------------------------------- #
# Substrate-binding hooks (SB-1/SB-2/SB-3). These are DELIBERATELY SYNTHETIC:
# the concrete Demos wire representations (inclusion-proof structure + finality
# criterion, transaction-writer recovery + web2.domain write-authorization,
# consensus record-time encoding) are NOT yet fixed and bind at the substrate
# profile. The vectors model them with a minimal well-formed shape so the GE-n
# checks are executable today.
# --------------------------------------------------------------------------- #
def sb1_covers_source_tx(inclusion_proof, source_tx) -> bool:
    """SB-1 (part a): the inclusion proof actually covers ``sourceTx``."""
    if not isinstance(inclusion_proof, dict):
        return False
    return inclusion_proof.get("covers") == source_tx


def sb1_is_final(inclusion_proof, min_confirmations: int) -> bool:
    """SB-1 (part b): the covered transaction meets the substrate finality
    criterion. Modelled synthetically as an explicit finalized flag plus a
    confirmation depth at or above the substrate profile's threshold."""
    if not isinstance(inclusion_proof, dict):
        return False
    return bool(inclusion_proof.get("finalized")) and \
        int(inclusion_proof.get("confirmations", 0)) >= min_confirmations


def sb2_authorizing_account(evidence: dict) -> object:
    """SB-2 (synthetic): the account the substrate's write-authorization RELATION
    determines authorized the web2.domain write, recovered from ``sourceTx`` —
    NOT raw key equality. The concrete Demos realisation is an OPEN QUESTION and
    binds at the substrate profile: for an account-key realisation this equals
    ``txWriter``; for a node/system-key realisation it is the account the node
    acted for (the authenticated instruction's account), which may differ from
    ``txWriter``. Modelled as an explicit ``authorizedAccount`` when the vector
    exercises a node-key write; otherwise it defaults to ``txWriter`` (the
    account-key realisation). GE-5 checks this account against the bound account.
    """
    if "authorizedAccount" in evidence:
        return evidence.get("authorizedAccount")
    return evidence.get("txWriter")


def sb1_written_record_hash(inclusion_proof) -> object:
    """SB-1 (part c, synthetic): the contentHash of the ``web2.domain`` record
    that ``sourceTx`` ACTUALLY wrote, recovered from the authenticated
    transaction on chain — distinct from any presenter-supplied ``gcrRecord``.
    This is the provenance GE-10 relies on. The concrete Demos state-recovery
    format is NOT yet fixed and binds at the substrate profile. Returns the
    written record's hash, or None if provenance cannot be recovered at all
    (GE-10 → indeterminate)."""
    if not isinstance(inclusion_proof, dict):
        return None
    return inclusion_proof.get("writtenRecordHash")


def sb3_recorded_at(evidence) -> object:
    """SB-3: the consensus inclusion/recorded time. Present on a resolved
    record; its concrete epoch/precision is a substrate-profile detail."""
    return evidence.get("recordedAt")


# --------------------------------------------------------------------------- #
# demos-gcr-domain verifier over AUTHENTICATED evidence (DACS-2 §7.3.10).
# Every GE-n binding check is applied explicitly and identifiably so a
# fault-injection can be traced to exactly one rule id. NO caller-asserted
# host/account/tx is trusted: the bound host/account come from the
# authenticated gcrRecord, gated on inclusion + finality + write-authorization.
# --------------------------------------------------------------------------- #
def _indeterminate() -> dict:
    return {"decision": "indeterminate", "data": None}


def _fail() -> dict:
    return {"decision": "fail", "data": None}


def demos_gcr_verify(
    identifier: str,
    claim_account: str,
    evidence: dict,
    recipe: dict,
    min_confirmations: int,
    *,
    session_nonce: object = None,
) -> dict:
    """DACS-2 §7.3.10 procedure → §7.5.1 decision values, derived from
    authenticated evidence. Every GE-n check is unconditional — there is no
    disable path in this verifier; the pin campaign proves each guard by DATA
    CORRUPTION, not by toggling checks off. ``session_nonce`` is accepted to
    model a per-session context but is DELIBERATELY UNUSED: the GCR record is
    persistent ownership-and-key evidence (§7.3.10 persistence), so a changing
    nonce MUST NOT alter the verdict.

    Decision mapping (this method only; the global §7.5.1 taxonomy is unchanged):
      pass          — all GE-n checks hold.
      fail          — authenticated evidence CONCLUSIVELY contradicts (wrong
                      host/account/context/substrate, writer != record account,
                      or tampered/forged record: contentHash or proofUrl).
      indeterminate — authority-side unavailability or unauthenticatable
                      evidence (not-found / transport-error / record-unreadable,
                      missing or unverifiable inclusion proof, not finalized,
                      incomplete evidence). LIST-A: an unreachable authority is
                      an inconclusive ANSWER, not a verifier defect.
      error         — verifier-internal fault only (cannot run the check at all).
    """
    del session_nonce  # persistence: the verdict must not depend on it

    avail = evidence.get("availability")
    if avail in ("not-found", "transport-error", "record-unreadable"):
        # LIST-A / A4: transport/read unavailability is an inconclusive answer,
        # NOT a verifier defect → indeterminate. DEMOS-MAPPING §A.2: a Demos
        # not-found stays indeterminate (authoritative-absence), never fail.
        return _indeterminate()
    if avail != "resolved":
        return _indeterminate()  # unknown/incomplete availability

    rec = evidence.get("gcrRecord")
    if not isinstance(rec, dict) or sb3_recorded_at(evidence) is None:
        return _indeterminate()  # incomplete evidence

    # ---- Ordered GE-n authenticated binding checks (all unconditional) ----- #
    # GE-1 context equals the recipe's gcrContext.
    if evidence.get("context") != recipe.get("gcrContext"):
        return _fail()
    # GE-2 substrate equals the recipe's pinned substrate.
    if evidence.get("substrate") != recipe.get("substrate"):
        return _fail()
    # GE-3 inclusionProof covers sourceTx (SB-1a). Unverifiable → indeterminate.
    if not sb1_covers_source_tx(evidence.get("inclusionProof"), evidence.get("sourceTx")):
        return _indeterminate()
    # GE-4 covered tx meets the substrate finality criterion (SB-1b).
    if not sb1_is_final(evidence.get("inclusionProof"), min_confirmations):
        return _indeterminate()
    # GE-5 the write MUST be authorized by gcrRecord.account under the SB-2
    # write-authorization RELATION (NOT raw txWriter==account equality — see the
    # §7.3.10 open question on node-key vs account-key writes).
    if sb2_authorizing_account(evidence) != rec.get("account"):
        return _fail()
    # GE-6 gcrRecord.account == the claim's asserted account (claimAccount).
    if rec.get("account") != claim_account:
        return _fail()
    # GE-7 gcrRecord.host == identifier.
    if rec.get("host") != identifier:
        return _fail()
    # GE-8 recordRef.contentHash == hash(gcrRecord). SELF-CONSISTENCY of the
    # presented record only (provenance is GE-10).
    record_ref = evidence.get("recordRef") or {}
    if record_ref.get("contentHash") != record_content_hash(rec):
        return _fail()
    # GE-9 gcrRecord.proofUrl == derive(identifier, recipe.proofPathTemplate).
    # LIST-C: the authenticated record CARRIES the proof URL; the local
    # derivation is the CHECK, never the source of truth.
    if rec.get("proofUrl") != proof_url(identifier, recipe.get("proofPathTemplate", PROOF_PATH)):
        return _fail()
    # GE-10 PROVENANCE — the presented gcrRecord MUST be the web2.domain state
    # sourceTx actually wrote, recovered from the authenticated tx (SB-1). This
    # is DISTINCT from GE-8 self-consistency: a record that is internally
    # coherent (GE-1..GE-9 all pass) but is NOT the state the transaction wrote
    # MUST NOT pass. Provenance unrecoverable → indeterminate; a DIFFERENT
    # written record → fail (conclusive contradiction).
    written = sb1_written_record_hash(evidence.get("inclusionProof"))
    if written is None:
        return _indeterminate()  # provenance linkage cannot be established
    if written != record_content_hash(rec):
        return _fail()           # sourceTx authenticated a DIFFERENT record

    data = {
        "proofUrl": rec.get("proofUrl"),          # verified-equal-to-derivation, not merely derived
        "boundAccount": rec.get("account"),        # from the authenticated record
        "gcrRecordRef": evidence.get("recordRef"),
        "sourceTx": evidence.get("sourceTx"),
        "recordedAt": evidence.get("recordedAt"),
    }
    return {"decision": "pass", "data": data}


# --------------------------------------------------------------------------- #
# Freshness (GF-n) — derived from evidence.recordedAt, never presenter-supplied.
# --------------------------------------------------------------------------- #
def derive_effective_window(
    evidence: dict,
    recipe: dict,
    now: int,
    *,
    presented_verified_at: object = None,
    max_age: object = None,
) -> object:
    """DACS-2 §7.3.10 GF-1/GF-2/GF-3. Returns {verifiedAt, validUntil} or None
    (unverified). GF-1: verifiedAt := evidence.recordedAt; a presenter-supplied
    verifiedAt that disagrees with recordedAt makes the claim UNVERIFIED (the
    anti-reissue gate). GF-2: validUntil := verifiedAt + the recipe window
    (defaultMaxAgeSec), tightened only downward by ClaimRequirement.maxAge;
    measured from evidence time. GF-3 recordedAt sanity: a recordedAt in the
    future beyond ``recordedAtSkewToleranceSec`` (relative to the verifier's
    ``now``), or a non-positive derived window, makes the claim UNVERIFIED
    (fail-closed). A separate query/fetch time (queriedAt) MUST NOT extend the
    window and MUST NOT substitute for recordedAt — it is never consulted."""
    recorded_at = evidence.get("recordedAt")
    if recorded_at is None:
        return None  # incomplete evidence
    if presented_verified_at is not None and presented_verified_at != recorded_at:
        return None  # GF-1 anti-reissue: unverified
    verified_at = recorded_at
    # GF-3a: recordedAt MUST NOT be future-dated beyond the skew tolerance.
    tolerance = recipe.get("recordedAtSkewToleranceSec", 0)
    if verified_at > now + tolerance:
        return None
    window = recipe["defaultMaxAgeSec"]
    if max_age is not None:
        window = min(window, max_age)  # tighten downward only
    # GF-3b: the derived window MUST be positive.
    if window <= 0:
        return None
    return {"verifiedAt": verified_at, "validUntil": verified_at + window}


def is_fresh_window(window: dict, now: int, skew_tolerance: int = 0) -> bool:
    """GF-2/GF-3 effective-window gate: fresh iff the window is open at ``now``.
    The lower bound is relaxed by ``skew_tolerance`` so a recordedAt at most that
    far ahead of the verifier's clock (ordinary skew, already bounded by GF-3a)
    counts as in-window rather than not-yet-valid."""
    return (window["verifiedAt"] - skew_tolerance) <= now <= window["validUntil"]


# --------------------------------------------------------------------------- #
# Control binding (CR-1) — DACS-1 §6.3.2 step 6 for a demos-gcr-domain claim.
# The SR-1 linkage is a substrate hook in the same style as SB-1/SB-2/SB-3:
# its concrete Demos wire format is NOT yet fixed and binds at the substrate
# profile. Modelled synthetically as an explicit authenticated linkage.
# --------------------------------------------------------------------------- #
def sr1_authenticated_link(presentation: dict) -> object:
    """SR-1 (substrate hook, synthetic): an authenticated SR-1 linkage / session
    binding proving key possession for a Demos account, BOUND TO THIS
    PRESENTATION. Concrete Demos wire format is NOT yet fixed — binds at the
    substrate profile. Per the §6.3.2 security property the linkage MUST
    demonstrate possession of the private key for the account, cryptographically
    tied to the presentation under evaluation (anti-replay). Modelled
    synthetically: the linkage MUST be ``authenticated`` AND its
    ``boundPresentation`` MUST equal this presentation's ``id`` — so a bearer
    token, a long-lived/ambient session, or an authorization issued for a
    DIFFERENT presentation (``boundPresentation`` absent or mismatched) does NOT
    satisfy it. Returns the linked account iff those hold, else None."""
    link = presentation.get("sr1Link")
    if not isinstance(link, dict) or not link.get("authenticated"):
        return None
    # Presentation binding (anti-replay): the linkage MUST bind THIS presentation.
    if link.get("boundPresentation") is None or link.get("boundPresentation") != presentation.get("id"):
        return None
    return link.get("account")


def controlled_use_permitted(gcr_account: str, presentation: dict) -> bool:
    """DACS-1 §6.3.2 step 6, CR-1 (control binding). Controlled use of a
    demos-gcr-domain claim — serving as the bundle's ``presentedBy`` and having
    reputation key against it — requires the presentation to verify under the
    EXACT ed25519 account bound in the authenticated GCR record
    (``gcrRecord.account``): either directly as the presentation signing key
    (the presentation signature itself binds it), or via an authenticated,
    PRESENTATION-BOUND SR-1 linkage demonstrating key possession for that
    account. A GCR entry proving account A registered a domain does NOT make a
    bundle signed by an unrelated account B a controlled domain claim. The check
    is unconditional — there is no disable path."""
    if presentation.get("signingAccount") == gcr_account:
        return True
    linked = sr1_authenticated_link(presentation)
    return linked is not None and linked == gcr_account


# --------------------------------------------------------------------------- #
# Unified per-vector evaluation used by the case runner and the pin campaign.
# Two gates on distinct axes: ``requirementSatisfied`` (binding + freshness —
# may satisfy a *required* claim) and ``controlled`` (CR-1 — may be presentedBy
# / key reputation). ``accepted`` is the full controlled-use gate.
# --------------------------------------------------------------------------- #
def evaluate_case(case: dict, recipe: dict, min_confirmations: int) -> dict:
    res = demos_gcr_verify(
        case["identifier"], case["claimAccount"], case["evidence"], recipe, min_confirmations
    )
    requirement_satisfied = res["decision"] == "pass"
    fresh = None
    window = None
    controlled = None
    if requirement_satisfied:
        window = derive_effective_window(
            case["evidence"], recipe, case["now"],
            presented_verified_at=case.get("presentedVerifiedAt"),
            max_age=case.get("maxAge"),
        )
        tolerance = recipe.get("recordedAtSkewToleranceSec", 0)
        fresh = window is not None and is_fresh_window(window, case["now"], tolerance)
        requirement_satisfied = requirement_satisfied and fresh
    if requirement_satisfied:
        rec = case["evidence"]["gcrRecord"]
        # Default presenter = the record owner (control axis N/A for pure
        # binding/freshness vectors that carry no explicit presentation).
        presentation = case.get("presentation") or {"signingAccount": rec["account"]}
        controlled = controlled_use_permitted(rec["account"], presentation)
    accepted = requirement_satisfied and bool(controlled)
    return {
        "result": res,
        "requirementSatisfied": requirement_satisfied,
        "controlled": controlled,
        "accepted": accepted,
        "fresh": fresh,
        "window": window,
    }


GCR_RULE_IDS = [
    "GE-1", "GE-2", "GE-3", "GE-4", "GE-5", "GE-6", "GE-7", "GE-8", "GE-9", "GE-10",
    "GF-1", "GF-2", "GF-3", "CR-1",
]


def _load() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class DomainClaimBundleSemanticsVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = _load()
        cls.public_keys = {k: _b64url(v) for k, v in cls.data["publicKeys"].items()}
        cls.recipe = cls.data["recipe"]
        # Finality threshold is a substrate-profile criterion (SB-1), so it lives
        # inside the pinned recipe, not free-standing at fixture top level.
        cls.min_conf = cls.recipe["finalityMinConfirmations"]

    def test_kind_and_specrefs(self):
        self.assertEqual(self.data["kind"], "DomainClaimBundleSemanticsCases")
        self.assertTrue(all(r.startswith("§") for r in self.data["specRefs"]))

    @staticmethod
    def _recipe_tolerance_conforms(recipe: dict) -> bool:
        """DACS-2 §7.3.10 GF-3 Tolerance bound predicate: a recipe conforms iff
        recordedAtSkewToleranceSec <= defaultMaxAgeSec / 100 (<=1% of the window)."""
        return recipe["recordedAtSkewToleranceSec"] <= recipe["defaultMaxAgeSec"] / 100

    def test_recipe_skew_tolerance_within_bound(self):
        """DACS-2 §7.3.10 GF-3 Tolerance bound (normative): a conforming recipe
        MUST set recordedAtSkewToleranceSec <= defaultMaxAgeSec / 100. The
        predicate must genuinely distinguish conforming from violating configs —
        it HOLDS for the shipped recipe and FAILS for an in-memory recipe whose
        tolerance exceeds the ceiling. Static recipe-well-formedness, not a
        per-claim verdict."""
        # HOLDS for the shipped recipe.
        self.assertTrue(
            self._recipe_tolerance_conforms(self.recipe),
            f"shipped recipe non-conforming: recordedAtSkewToleranceSec="
            f"{self.recipe['recordedAtSkewToleranceSec']} exceeds "
            f"defaultMaxAgeSec/100={self.recipe['defaultMaxAgeSec'] / 100}",
        )
        # FAILS for an in-memory copy whose tolerance is one second over the
        # ceiling (written nowhere; proves the predicate has teeth).
        violating = json.loads(json.dumps(self.recipe))
        violating["recordedAtSkewToleranceSec"] = violating["defaultMaxAgeSec"] // 100 + 1
        self.assertFalse(
            self._recipe_tolerance_conforms(violating),
            "predicate failed to reject an over-ceiling tolerance",
        )

    # ---- V3: original-byte signature/hash preservation --------------------- #
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
        bundle_hash, ok = self._verify_presentation(bundle, domain)
        self.assertEqual(bundle_hash, sb["expectedBundleHash"])
        self.assertTrue(ok, "presentation signature must verify over original bytes")
        effective = [effective_ref(c["ref"]) for c in bundle["claims"]]
        self.assertEqual(effective, sb["expectedEffectiveRefs"])
        bundle_hash_2, ok_2 = self._verify_presentation(bundle, domain)
        self.assertEqual(bundle_hash_2, bundle_hash, "resolution must not change the hash")
        self.assertTrue(ok_2, "signature must still verify after resolution")
        self.assertEqual(bundle["claims"][1]["ref"], "web2:domain:alice.example")

    def test_v3_tamper_breaks_signature(self):
        sb = self.data["signedBundle"]
        tampered = json.loads(json.dumps(sb["bundle"]))
        tampered["claims"][1]["ref"] = "web2:domain:evil.example"
        _, ok = self._verify_presentation(tampered, sb["bundlePresentationDomain"])
        self.assertFalse(ok, "a mutated claim ref must break the presentation signature")

    # ---- V4: semantic-claim deduplication ---------------------------------- #
    def test_v4_dedup(self):
        for case in self.data["dedupCases"]:
            with self.subTest(case=case["id"]):
                result = semantic_claims(case["claims"])
                self.assertEqual(result["count"], case["expected"]["semanticClaimCount"])
                self.assertEqual(
                    result["verifiedByIdentity"], case["expected"]["verifiedByIdentity"]
                )

    # ---- demos-gcr-domain over authenticated evidence ---------------------- #
    def test_gcr_authenticated_cases(self):
        for case in self.data["gcrCases"]:
            with self.subTest(case=case["id"]):
                ev = evaluate_case(case, self.recipe, self.min_conf)
                exp = case["expected"]
                self.assertEqual(ev["result"]["decision"], exp["decision"])
                self.assertEqual(ev["accepted"], exp["accepted"])
                if "fresh" in exp:
                    self.assertEqual(ev["fresh"], exp["fresh"])
                if "requirementSatisfied" in exp:
                    self.assertEqual(ev["requirementSatisfied"], exp["requirementSatisfied"])
                if "controlled" in exp:
                    self.assertEqual(ev["controlled"], exp["controlled"])
                data = ev["result"]["data"]
                if "dataProofUrl" in exp:
                    self.assertEqual(data["proofUrl"], exp["dataProofUrl"])
                    # LIST-C: the record carries proofUrl; it must EQUAL the
                    # local derivation (the check), not merely be derived.
                    self.assertEqual(
                        data["proofUrl"],
                        proof_url(case["identifier"], self.recipe["proofPathTemplate"]),
                    )
                    self.assertEqual(data["proofUrl"], case["evidence"]["gcrRecord"]["proofUrl"])
                if "dataBoundAccount" in exp:
                    self.assertEqual(data["boundAccount"], exp["dataBoundAccount"])
                    # bound account comes from the authenticated record.
                    self.assertEqual(data["boundAccount"], case["evidence"]["gcrRecord"]["account"])
                if "dataSourceTx" in exp:
                    self.assertEqual(data["sourceTx"], exp["dataSourceTx"])
                if "dataRecordedAt" in exp:
                    self.assertEqual(data["recordedAt"], exp["dataRecordedAt"])

    def test_gcr_no_caller_asserted_trust(self):
        """The verifier must never read a caller-asserted boundHost/boundAccount/
        sourceTx off the top-level evidence: the bound host/account come from the
        authenticated gcrRecord only. Injecting caller-asserted top-level fields
        that disagree with the record MUST NOT change a pass into anything, and
        MUST NOT rescue a forged record."""
        cases = {c["id"]: c for c in self.data["gcrCases"]}
        valid = json.loads(json.dumps(cases["authenticated-valid"]))
        record_account = valid["evidence"]["gcrRecord"]["account"]
        # Attacker adds caller-asserted top-level fields that would, under the old
        # model, have BEEN the trust source. They must be inert now.
        valid["evidence"]["boundHost"] = "evil.example"
        valid["evidence"]["boundAccount"] = "de" * 32
        ev = evaluate_case(valid, self.recipe, self.min_conf)
        self.assertEqual(ev["result"]["decision"], "pass")
        self.assertEqual(ev["result"]["data"]["boundAccount"], record_account)

    def test_control_binding_cr1(self):
        """DACS-1 §6.3.2 step 6 / CR-1. A GCR record binding account A permits
        controlled use only when the presentation verifies under A (directly or
        via authenticated SR-1). A bundle presented by an unrelated account B
        still SATISFIES a required claim but MUST NOT be controlled (presentedBy
        / reputation keying). Both halves of the negative are asserted."""
        cases = {c["id"]: c for c in self.data["gcrCases"]}
        pos = evaluate_case(cases["control-binding-positive"], self.recipe, self.min_conf)
        self.assertTrue(pos["requirementSatisfied"])
        self.assertTrue(pos["controlled"])
        self.assertTrue(pos["accepted"])
        # NEGATIVE — both halves: requirement STILL satisfied, controlled REFUSED.
        neg = evaluate_case(cases["control-binding-negative"], self.recipe, self.min_conf)
        self.assertTrue(neg["requirementSatisfied"], "the domain claim is still validly verified to account A")
        self.assertFalse(neg["controlled"], "an unrelated presenter B MUST NOT be controlled")
        self.assertFalse(neg["accepted"], "valid-but-uncontrolled: not presentedBy, no reputation keying")
        # SR-1 positive — presenter is B, but an authenticated, PRESENTATION-BOUND
        # SR-1 linkage to A permits control.
        sr1 = evaluate_case(cases["control-binding-sr1-positive"], self.recipe, self.min_conf)
        self.assertTrue(sr1["requirementSatisfied"])
        self.assertTrue(sr1["controlled"])
        self.assertTrue(sr1["accepted"])
        # SR-1 NEGATIVE (i) — authenticated linkage to A but NOT bound to this
        # presentation (bearer/ambient) → controlled REFUSED, requirement still met.
        nb = evaluate_case(cases["sr1-negative-not-bound"], self.recipe, self.min_conf)
        self.assertTrue(nb["requirementSatisfied"])
        self.assertFalse(nb["controlled"], "an SR-1 linkage not bound to this presentation MUST NOT confer control")
        self.assertFalse(nb["accepted"])
        # SR-1 NEGATIVE (ii) — linkage bound to a DIFFERENT presentation (replay) → REFUSED.
        rp = evaluate_case(cases["sr1-negative-replay"], self.recipe, self.min_conf)
        self.assertTrue(rp["requirementSatisfied"])
        self.assertFalse(rp["controlled"], "an SR-1 linkage bound to a different presentation MUST NOT confer control")
        self.assertFalse(rp["accepted"])
        # Data-corruption of the SR-1 positive: strip its presentation binding →
        # controlled must flip to refused (the binding is load-bearing).
        broken = json.loads(json.dumps(cases["control-binding-sr1-positive"]))
        broken["presentation"]["sr1Link"].pop("boundPresentation", None)
        bev = evaluate_case(broken, self.recipe, self.min_conf)
        self.assertTrue(bev["requirementSatisfied"])
        self.assertFalse(bev["controlled"], "removing presentation binding must refuse control")
        self.assertFalse(bev["accepted"])

    def _corrupt_one_field(self, cases: dict, rule: str) -> dict:
        """Return a deep copy of the known-good vector with EXACTLY the one field
        rule ``rule`` binds corrupted. For any corruption that mutates a field
        INSIDE ``gcrRecord``, BOTH hash-derived consistency fields are repaired —
        ``recordRef.contentHash`` (GE-8) AND ``inclusionProof.writtenRecordHash``
        (GE-10) — via ``record_content_hash`` over the corrupted record, so the
        modelled scenario is coherent (the transaction genuinely wrote THAT wrong
        record) and the named rule is the sole catcher. Where a corruption would
        otherwise trip a sibling guard, the co-dependent field is kept internally
        consistent (e.g. GE-6 sets txWriter to the new account so GE-5 passes)."""
        A = self.data["accounts"]["A_keyDerived"]  # noqa: F841 - documents the owner
        B = self.data["accounts"]["B_standalone"]
        Cc = self.data["accounts"]["C_standalone"]
        src = "control-binding-positive" if rule == "CR-1" else "authenticated-valid"
        c = json.loads(json.dumps(cases[src]))
        e = c["evidence"]
        rec = e["gcrRecord"]

        def rehash():
            # Repair BOTH derived fields: the anchored snapshot (GE-8) and the
            # SB-1-recovered written-record hash (GE-10). Teaching this repair
            # only GE-8 was the exact isolation defect this test now guards.
            h = record_content_hash(rec)
            e["recordRef"]["contentHash"] = h
            e["inclusionProof"]["writtenRecordHash"] = h

        if rule == "GE-1":
            e["context"] = "web2.WRONG"
        elif rule == "GE-2":
            e["substrate"] = "demos-WRONG"
        elif rule == "GE-3":
            e["inclusionProof"]["covers"] = "0xUNRELATED"
        elif rule == "GE-4":
            e["inclusionProof"]["finalized"] = False
            e["inclusionProof"]["confirmations"] = 1
        elif rule == "GE-5":
            e["txWriter"] = Cc  # writer != record.account
        elif rule == "GE-6":
            rec["account"] = B
            e["txWriter"] = B   # keep GE-5 (writer==account) passing → GE-6 is sole catcher
            rehash()
        elif rule == "GE-7":
            rec["host"] = "evil.example"  # proofUrl left as derive(identifier) → GE-9 passes
            rehash()
        elif rule == "GE-8":
            e["recordRef"]["contentHash"] = "0" * 64  # the tamper itself — do NOT rehash
        elif rule == "GE-9":
            # Path-only corruption (host stays == identifier so GE-7 still passes,
            # and so the heal can align the recipe's proofPathTemplate — GE-9's
            # only input besides identifier).
            rec["proofUrl"] = "https://alice.example/.well-known/WRONG.txt"
            rehash()
        elif rule == "GE-10":
            # Provenance: the tx wrote a DIFFERENT record than the (coherent,
            # GE-1..GE-9-passing) presented one. Corrupt the SB-1-recovered
            # written-record hash so it no longer matches hash(gcrRecord). NOT a
            # gcrRecord-internal field, so recordRef.contentHash is left correct
            # (GE-8 still passes) → GE-10 is the sole catcher.
            e["inclusionProof"]["writtenRecordHash"] = record_content_hash(
                {"account": A, "host": "other.example",
                 "proofUrl": "https://other.example/.well-known/demos-cci.txt"}
            )
        elif rule == "GF-1":
            c["presentedVerifiedAt"] = e["recordedAt"] + 650000  # disagrees with recordedAt
            c["now"] = e["recordedAt"] + 680000
        elif rule == "GF-2":
            c["now"] = e["recordedAt"] + self.recipe["defaultMaxAgeSec"] + 1  # past the window
        elif rule == "GF-3":
            # recordedAt future-dated beyond the skew tolerance → unverified.
            tol = self.recipe.get("recordedAtSkewToleranceSec", 0)
            e["recordedAt"] = c["now"] + tol + 10000
        elif rule == "CR-1":
            c["presentation"]["signingAccount"] = B  # unrelated presenter
        else:  # pragma: no cover - guard against a new rule with no corruption
            self.fail(f"no corruption defined for rule {rule}")
        return c

    # Fail-class GE rules that carry a HEAL (positive sole-ownership proof).
    # GE-3/GE-4 (indeterminate) and GF-*/CR-1 are excluded: cross-class masking
    # is already excluded by the decision-class assertion, and only fail-class
    # single-guard ownership is provable by "heal exactly one comparison ->
    # accepted".
    HEALABLE_FAIL_GE = ("GE-1", "GE-2", "GE-5", "GE-6", "GE-7", "GE-8", "GE-9", "GE-10")

    def _heal_one_rule(self, rule: str, corrupted: dict) -> tuple:
        """Given a case already corrupted for ``rule`` by _corrupt_one_field,
        return (healed_case, healed_recipe) that makes ONLY that rule's
        comparison pass while leaving the corruption otherwise in place —
        acceptance afterwards is positive proof no sibling guard was firing.
        Heal by DATA/config only (no skip, no guard removal, no verifier
        monkeypatch). HEAL MAP (each verified against the verifier's field reads):

          GE-1  align healed_recipe.gcrContext to the corrupted evidence.context.
                gcrContext is read ONLY by GE-1. (discriminating)
          GE-2  align healed_recipe.substrate to the corrupted evidence.substrate.
                substrate is read ONLY by GE-2. (discriminating)
          GE-5  restore the authorizing account (txWriter, no authorizedAccount)
                to gcrRecord.account. The authorization field is read ONLY by
                GE-5 (via sb2_authorizing_account) -> structurally single-reader,
                so this is a RESTORE-heal, equivalent to the control.
          GE-6  set healed_case.claimAccount to the corrupted gcrRecord.account.
                claimAccount is read ONLY by GE-6 on this path (the default-
                presenter control path keys on gcrRecord.account, not claimAccount).
                (discriminating)
          GE-7  CASCADE: identifier feeds GE-7 AND GE-9's derivation, so align
                healed_case.identifier to the corrupted host, RE-DERIVE
                gcrRecord.proofUrl = proof_url(new identifier, template), and
                RE-REPAIR BOTH hashes (contentHash + writtenRecordHash). If the
                hash-repair chain is incomplete the healed case is rejected by
                GE-10 and this assertion fails — exactly the regression class
                this guards.
          GE-8  restore recordRef.contentHash to hash(gcrRecord). contentHash is
                read ONLY by GE-8 -> single-reader RESTORE-heal.
          GE-9  align healed_recipe.proofPathTemplate so
                proof_url(identifier, template) == the corrupted (path-only)
                proofUrl. proofPathTemplate is read ONLY by GE-9. (discriminating)
          GE-10 set inclusionProof.writtenRecordHash to hash of the PRESENTED
                record (the Step-7c F5 technique). writtenRecordHash is read ONLY
                by GE-10. (discriminating)
        """
        hc = json.loads(json.dumps(corrupted))
        hr = json.loads(json.dumps(self.recipe))
        e = hc["evidence"]
        rec = e["gcrRecord"]

        def rehash():
            h = record_content_hash(rec)
            e["recordRef"]["contentHash"] = h
            e["inclusionProof"]["writtenRecordHash"] = h

        if rule == "GE-1":
            hr["gcrContext"] = e["context"]
        elif rule == "GE-2":
            hr["substrate"] = e["substrate"]
        elif rule == "GE-5":
            e["txWriter"] = rec["account"]
            e.pop("authorizedAccount", None)
        elif rule == "GE-6":
            hc["claimAccount"] = rec["account"]
        elif rule == "GE-7":
            hc["identifier"] = rec["host"]
            rec["proofUrl"] = proof_url(hc["identifier"], hr["proofPathTemplate"])
            rehash()
        elif rule == "GE-8":
            e["recordRef"]["contentHash"] = record_content_hash(rec)
        elif rule == "GE-9":
            prefix = "https://" + hc["identifier"]
            self.assertTrue(rec["proofUrl"].startswith(prefix),
                            "GE-9 heal assumes a path-only corruption (host == identifier)")
            hr["proofPathTemplate"] = rec["proofUrl"][len(prefix):]
        elif rule == "GE-10":
            e["inclusionProof"]["writtenRecordHash"] = record_content_hash(rec)
        else:  # pragma: no cover
            self.fail(f"no heal defined for rule {rule}")
        return hc, hr

    def test_gcr_pin_map_is_complete_and_each_pin_is_solely_owned(self):
        """Prove every GE-/GF-/CR- guard by DATA CORRUPTION — the verifier has no
        disable path, so each guard is exercised by corrupting exactly the one
        field it binds and confirming the case is NOT accepted and its decision
        matches the rule's own class (so no sibling guard caught it first). Also
        asserts pin-map completeness and a CONTROL (the uncorrupted case IS
        accepted — the test cannot pass by rejecting everything)."""
        pins = self.data["gcrGuardPins"]
        cases = {c["id"]: c for c in self.data["gcrCases"]}
        # Completeness + sole-ownership of the MAP: every rule pinned, every pin
        # id a distinct existing vector whose own pinsRule label agrees.
        self.assertEqual(set(pins), set(GCR_RULE_IDS))
        self.assertEqual(len(set(pins.values())), len(pins), "two rules share one pin vector")
        for rule, vid in pins.items():
            self.assertIn(vid, cases, f"pin vector {vid} for {rule} missing from gcrCases")
            self.assertEqual(cases[vid].get("pinsRule"), rule, f"{vid} pinsRule disagrees with the map")
            self.assertFalse(
                evaluate_case(cases[vid], self.recipe, self.min_conf)["accepted"],
                f"pinned vector {vid} must NOT be accepted",
            )
        # CONTROL — the good cases ARE accepted.
        self.assertTrue(evaluate_case(cases["authenticated-valid"], self.recipe, self.min_conf)["accepted"])
        self.assertTrue(evaluate_case(cases["control-binding-positive"], self.recipe, self.min_conf)["accepted"])

        expected_class = {
            "GE-1": "fail", "GE-2": "fail", "GE-3": "indeterminate", "GE-4": "indeterminate",
            "GE-5": "fail", "GE-6": "fail", "GE-7": "fail", "GE-8": "fail", "GE-9": "fail",
            "GE-10": "fail",
            "GF-1": "pass", "GF-2": "pass", "GF-3": "pass", "CR-1": "pass",
        }
        for rule in GCR_RULE_IDS:
            with self.subTest(rule=rule):
                corrupted = self._corrupt_one_field(cases, rule)
                ev = evaluate_case(corrupted, self.recipe, self.min_conf)
                self.assertFalse(ev["accepted"], f"{rule}: corrupting its bound field must block acceptance")
                self.assertEqual(
                    ev["result"]["decision"], expected_class[rule],
                    f"{rule}: wrong decision class — a sibling guard caught it first",
                )
                if rule == "CR-1":
                    # requirement still satisfied; only controlled-use is refused.
                    self.assertTrue(ev["requirementSatisfied"])
                    self.assertFalse(ev["controlled"])
                # HEAL assertion (positive sole-ownership proof) — fail-class GE
                # rules only. Healing exactly this rule's comparison, with the
                # corruption otherwise intact, MUST yield accepted: proof no
                # sibling guard was also firing. Excluded (per B2): GE-3/GE-4
                # (indeterminate class) and GF-*/CR-1 — cross-class masking is
                # already excluded by the decision-class assertion above.
                if rule in self.HEALABLE_FAIL_GE:
                    healed_case, healed_recipe = self._heal_one_rule(rule, corrupted)
                    healed = evaluate_case(healed_case, healed_recipe, self.min_conf)
                    self.assertTrue(
                        healed["accepted"],
                        f"{rule}: healing ONLY its comparison must yield accepted — "
                        f"a sibling guard is still firing (got {healed['result']['decision']})",
                    )

    def test_gcr_persistent_no_session_nonce(self):
        """Persistence (§7.3.10): the GCR record is not a per-session challenge.
        The verdict AND result are invariant over a real varying session nonce,
        the result carries no nonce/challenge field, and acceptance is bounded by
        the derived effective window (fresh in-window, stale past-window)."""
        p = self.data["persistenceCase"]
        exp = p["expected"]
        cases = {c["id"]: c for c in self.data["gcrCases"]}
        base = cases[p["baseVectorId"]]
        nonce_a, nonce_b = p["sessionNonceA"], p["sessionNonceB"]
        self.assertNotEqual(nonce_a, nonce_b, "the two session nonces must differ")
        res_a = demos_gcr_verify(
            base["identifier"], base["claimAccount"], base["evidence"], self.recipe, self.min_conf,
            session_nonce=nonce_a,
        )
        res_b = demos_gcr_verify(
            base["identifier"], base["claimAccount"], base["evidence"], self.recipe, self.min_conf,
            session_nonce=nonce_b,
        )
        self.assertEqual(res_a["decision"], "pass")
        self.assertEqual(res_a["decision"], res_b["decision"], "verdict must not depend on the nonce")
        self.assertEqual(res_a, res_b, "the full result must be invariant over the session nonce")
        self.assertEqual(exp["nonceInvariant"], True)
        self.assertFalse(any(k in res_a for k in ("nonce", "challenge")))
        self.assertFalse(any(k in res_a["data"] for k in ("nonce", "challenge")))
        self.assertEqual(exp["hasNonceField"], False)
        # in-window fresh vs past-window stale, freshness derived from recordedAt.
        in_window = evaluate_case(cases[p["inWindowVectorId"]], self.recipe, self.min_conf)
        past_window = evaluate_case(cases[p["pastWindowVectorId"]], self.recipe, self.min_conf)
        self.assertEqual(in_window["fresh"], exp["freshInWindow"])
        self.assertEqual(past_window["fresh"], exp["freshPastWindow"])
        # the derived window is anchored on recordedAt (never a free-standing literal).
        self.assertEqual(in_window["window"]["verifiedAt"], base["evidence"]["recordedAt"])


if __name__ == "__main__":
    unittest.main()
