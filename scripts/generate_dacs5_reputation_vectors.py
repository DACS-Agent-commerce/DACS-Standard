#!/usr/bin/env python3
"""Deterministic generator for the DACS-5 v0.3 reputation-reconciliation vector sets.

Emits five candidate security-vector sets that exercise the L1–L4 spec surface:

  CONCRETE (real ed25519, embedded synthetic seeds):
    mixed-version-reconciliation-v0.3.json   §10.4.3 mixed-version rule / §10.5.1
    fault-bundle-perspective-pair-v0.3.json  §10.4.3 FaultAttestationBundle-pair / §10.4.1
    outsider-binding-flooding-v0.3.json      §10.4.2 BB-6 authorized-candidate (review-3 #4)
  ABSTRACT (decision-model, placeholder hashes, no crypto):
    unresolved-vs-absent-v0.3.json           §10.4.3(b) / BB-8 / CORE §5 (review-3 #2)
    receipt-rederivation-v0.3.json            §10.5.3 receipt clauses (3)/(4) (review-3 #5)

Seeds are visibly-synthetic repeated-byte patterns (buyer a1.., seller c3.., a
distinct orchestrator 0e.. and outsider f0..) and are disclosed in each concrete
set's header. ed25519 signing is deterministic, so `--write` then `--check` is a
byte-for-byte determinism proof.

Usage:
  python3 scripts/generate_dacs5_reputation_vectors.py --write
  python3 scripts/generate_dacs5_reputation_vectors.py --check
"""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEC = ROOT / "conformance" / "vectors" / "security"

SEEDS = {
    "buyer": "a1" * 32,
    "seller": "c3" * 32,
    "orchestrator": "0e" * 32,   # synthetic (repeated 0e) — distinct-orchestrator party
    "outsider": "f0" * 32,       # synthetic (repeated f0) — non-party attacker
}
CLAIM = {r: f"did:demos:{r}" for r in SEEDS}
ROLE_BY_CLAIM = {c: r for r, c in CLAIM.items()}
BUNDLE_DOMAIN = "dacs-fault-bundle:v1:"
LEGACY_DOMAIN = "dacs-bundle:v1:"
BINDING_DOMAIN = "dacs-bundle-binding:v1:"
FAULT_POINTER_DOMAIN = "dacs-fault-bundle-pointer:v1:"
FINALISED_AT = 1780004000000


# ---- primitives ----
def _keys():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return {r: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for r, s in SEEDS.items()}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sha(*parts):
    return hashlib.sha256(":".join(parts).encode("utf-8")).hexdigest()


def bundle_hash(bundle):
    unsigned = {k: v for k, v in bundle.items() if k not in ("signatures", "anchoredByRole")}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def binding_hash(binding):
    unsigned = {k: v for k, v in binding.items() if k != "signature"}
    return hashlib.sha256(canonical(unsigned)).hexdigest()


def logical_address(job_id, role):
    return "stor-" + hashlib.sha256((job_id + "-bundle-" + role).encode("utf-8")).hexdigest()


def native_address(job_id, role, idx=0):
    return "stor-" + hashlib.sha256(f"native:{job_id}:{role}:{idx}".encode("utf-8")).hexdigest()[:40]


def _parties():
    return [
        {"role": "buyer", "bundleHash": sha("bundle", "buyer"), "primaryClaim": CLAIM["buyer"]},
        {"role": "seller", "bundleHash": sha("bundle", "seller"), "primaryClaim": CLAIM["seller"]},
    ]


def _parties3():
    """Three-party roster (distinct orchestrator) for the E4 implied-fault-SET vectors."""
    return _parties() + [
        {"role": "orchestrator", "bundleHash": sha("bundle", "orchestrator"), "primaryClaim": CLAIM["orchestrator"]},
    ]


def make_fab(keys, job_id, outcome, faulted_party, anchored_by_role, sign_roles,
             phase_kind="deliver-storage-program", phase_outcome="ok", parties=None,
             finalised_at=FINALISED_AT):
    b = {
        "faultBundleVersion": "1",
        "jobId": job_id,
        "outcome": outcome,
        "faultedParty": faulted_party,
        "anchoredByRole": anchored_by_role,
        "listingRef": {"listingId": "listing-" + job_id, "version": 1,
                       "contentHash": sha("listing", job_id)},
        "parties": parties or _parties(),
        "phaseSummary": [{"index": 0, "kind": phase_kind, "outcome": phase_outcome}],
        "vetRecords": [],
        "settlementEvidence": [],
        "recipeRegistryVersion": 1,
        "railRegistryVersion": 1,
        "finalisedAt": finalised_at,
        "signatures": [],
    }
    h = bundle_hash(b)
    payload = (BUNDLE_DOMAIN + h).encode("utf-8")
    b["signatures"] = [
        {"party": CLAIM[r], "algorithm": "ed25519", "value": b64u(keys[r].sign(payload))}
        for r in sign_roles
    ]
    return b


def make_legacy(keys, job_id, outcome, anchored_by_role, sign_roles,
                phase_kind="deliver-storage-program", phase_outcome="ok", parties=None):
    b = {
        "bundleVersion": "1",
        "jobId": job_id,
        "outcome": outcome,
        "anchoredByRole": anchored_by_role,
        "listingRef": {"listingId": "listing-" + job_id, "version": 1,
                       "contentHash": sha("listing", job_id)},
        "parties": parties or _parties(),
        "phaseSummary": [{"index": 0, "kind": phase_kind, "outcome": phase_outcome}],
        "vetRecords": [],
        "settlementEvidence": [],
        "recipeRegistryVersion": 1,
        "railRegistryVersion": 1,
        "finalisedAt": FINALISED_AT,
        "signatures": [],
    }
    h = bundle_hash(b)
    payload = (LEGACY_DOMAIN + h).encode("utf-8")
    b["signatures"] = [
        {"party": CLAIM[r], "algorithm": "ed25519", "value": b64u(keys[r].sign(payload))}
        for r in sign_roles
    ]
    return b


def make_binding(keys, job_id, role, signer_role, native, content_hash, idx=0):
    bd = {
        "bindingVersion": "1",
        "jobId": job_id,
        "role": role,
        "logicalAddress": logical_address(job_id, role),
        "nativeAddress": native,
        "bundleContentHash": content_hash,
        "anchorTx": f"demos-testnet:tx-{native[5:21]}",
        "signer": CLAIM[signer_role],
    }
    bh = binding_hash(bd)
    payload = (BINDING_DOMAIN + bh).encode("utf-8")
    bd["signature"] = {"algorithm": "ed25519", "signer": CLAIM[signer_role],
                       "value": b64u(keys[signer_role].sign(payload))}
    return bd


def make_fab_pointer(keys, signer_role, full_url, full_content_hash):
    """FaultBundleExtendedPointer (E7), signed over dacs-fault-bundle-pointer:v1: || hash."""
    p = {
        "faultBundleVersion": "1",
        "pointerKind": "extended",
        "fullBundleUrl": full_url,
        "fullBundleContentHash": full_content_hash,
    }
    ph = binding_hash(p)   # sha256(canonical(pointer minus signature)) — same excluded-field shape
    payload = (FAULT_POINTER_DOMAIN + ph).encode("utf-8")
    p["signature"] = {"algorithm": "ed25519", "signer": CLAIM[signer_role],
                      "value": b64u(keys[signer_role].sign(payload))}
    return p


def concrete_header(keys, name, spec, gaps, decision, note):
    return {
        "set": name,
        "spec": spec,
        "provenance": {
            "generator": "scripts/generate_dacs5_reputation_vectors.py (deterministic; synthetic disclosed seeds)",
            "canonicalisation": (
                "RFC 8785 JCS over the artifact minus its hash-excluded fields "
                "(FaultAttestationBundle/AttestationBundle: signatures+anchoredByRole; binding: signature); "
                "attestation_bundle_hash = sha256 hex; ed25519 over the CORE §B.7 domain-separated payload "
                "(dacs-fault-bundle:v1: / dacs-bundle:v1: / dacs-bundle-binding:v1: || hash), base64url-unpadded."
            ),
            "note": note,
            "seeds": "synthetic repeated-byte ed25519 seeds; buyer a1.., seller c3.., orchestrator 0e.., outsider f0..",
        },
        "gaps": gaps,
        "decisionModel": decision,
        "publicKeys": {CLAIM[r]: b64u(keys[r].public_key().public_bytes_raw()) for r in SEEDS},
        "seeds": dict(SEEDS),
    }


def finalize(data):
    data["count"] = len(data["vectors"])
    data["hash"] = hashlib.sha256(
        json.dumps(data["vectors"], separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return data


# ---- S1: mixed-version-reconciliation ----
def build_mixed_version(keys):
    j = "MVR"
    d = concrete_header(
        keys, "mixed-version-reconciliation-v0.3",
        "DACS-5 §10.4.3 mixed-version rule + §10.5.1 authoritative selection",
        ["#254 phaseSummary.kind divergence", "#248 FaultAttestationBundle reshape"],
        ("Compare a FaultAttestationBundle copy against a legacy AttestationBundle copy on the common "
         "fault surface: map the legacy role-relative outcome through anchoredByRole (§10.4.1 permissible "
         "set) to an implied absolute fault and read its outcome class; the pair canonically diverges when "
         "the implied absolute fault contradicts the FAB faultedParty, when outcome classes contradict, or "
         "on the shared-index phaseSummary limb. A non-divergent mixed pair is unified with the "
         "FaultAttestationBundle authoritative for derivation (§10.5.1)."),
        ("Concrete FAB + legacy AttestationBundle pairs. The FAB signs under dacs-fault-bundle:v1: and the "
         "legacy copy under dacs-bundle:v1:; verdict pass = unified (usable), fail = divergent (excluded "
         "from reputation)."),
    )
    vectors = []
    # (1) non-divergent: legacy buyer aborted-by-other -> implied fault seller; FAB seller aborted-by-self fP=seller
    v1j = j + "-1"
    fab = make_fab(keys, v1j, "aborted-by-self", "seller", "seller", ["seller"])
    leg = make_legacy(keys, v1j, "aborted-by-other", "buyer", ["buyer"])
    vectors.append({
        "name": "mixed-nondivergent-fab-authoritative",
        "rule": "§10.4.3 mixed-version; §10.5.1",
        "expected": "pass",
        "note": ("legacy buyer copy's aborted-by-other maps through anchoredByRole=buyer to implied fault "
                 "seller, matching the FAB faultedParty=seller and abort class; the pair is unified and the "
                 "FaultAttestationBundle copy is authoritative for derivation."),
        "copies": {"seller": fab, "buyer": leg},
        "want": {"expected": "pass", "convergence": "unified",
                 "authoritativeCopyType": "FaultAttestationBundle",
                 "reputationEffect": "include", "scoredRole": "seller", "scoredOutcome": "aborted-by-self",
                 "reason": "non-divergent mixed pair; authoritative copy for derivation is the FaultAttestationBundle (§10.4.3/§10.5.1)"},
    })
    # (2) implied-fault contradiction: legacy buyer aborted-by-self -> implied fault buyer; FAB fP=seller
    v2j = j + "-2"
    fab2 = make_fab(keys, v2j, "aborted-by-self", "seller", "seller", ["seller"])
    leg2 = make_legacy(keys, v2j, "aborted-by-self", "buyer", ["buyer"])
    vectors.append({
        "name": "mixed-implied-fault-contradiction",
        "rule": "§10.4.3 mixed-version",
        "expected": "fail",
        "note": ("legacy buyer aborted-by-self implies fault buyer; the FAB names faultedParty seller — the "
                 "implied absolute fault contradicts the FAB faultedParty, so the pair canonically diverges."),
        "copies": {"seller": fab2, "buyer": leg2},
        "want": {"expected": "fail", "convergence": "divergent", "authoritativeCopyType": None,
                 "reputationEffect": "exclude",
                 "reason": "implied absolute fault (buyer) contradicts FAB faultedParty (seller); §10.4.3 mixed-version divergence, excluded from ALL metrics"},
    })
    # (3) outcome-class contradiction: FAB completed vs legacy aborted
    v3j = j + "-3"
    fab3 = make_fab(keys, v3j, "completed", "none", "seller", ["buyer", "seller"])
    leg3 = make_legacy(keys, v3j, "aborted-by-self", "buyer", ["buyer"])
    vectors.append({
        "name": "mixed-outcome-class-contradiction",
        "rule": "§10.4.3 mixed-version",
        "expected": "fail",
        "note": ("the FAB copy is completed while the legacy copy is an abort — the outcome classes "
                 "contradict, so the mixed pair canonically diverges regardless of fault."),
        "copies": {"seller": fab3, "buyer": leg3},
        "want": {"expected": "fail", "convergence": "divergent", "authoritativeCopyType": None,
                 "reputationEffect": "exclude",
                 "reason": "outcome classes contradict (completed vs abort); §10.4.3 mixed-version divergence"},
    })
    # (4) phaseSummary shared-index kind mismatch on a mixed pair
    v4j = j + "-4"
    fab4 = make_fab(keys, v4j, "completed", "none", "seller", ["buyer", "seller"], phase_kind="deliver-storage-program")
    leg4 = make_legacy(keys, v4j, "completed", "buyer", ["buyer", "seller"], phase_kind="deliver-attested-payload")
    vectors.append({
        "name": "mixed-phasesummary-kind-mismatch",
        "rule": "§10.4.3 shared-index phaseSummary (#254)",
        "expected": "fail",
        "note": ("both copies agree on outcome and fault, but the shared phaseSummary index names different "
                 "kinds (deliver-storage-program vs deliver-attested-payload); the shared-index phaseSummary "
                 "limb applies to both versions unchanged, so the pair diverges."),
        "copies": {"seller": fab4, "buyer": leg4},
        "want": {"expected": "fail", "convergence": "divergent", "authoritativeCopyType": None,
                 "reputationEffect": "exclude",
                 "reason": "shared-index phaseSummary kind mismatch; §10.4.3 divergence (limb applies to both versions)"},
    })
    # (5) legacy+legacy control: outcome-spelling rule governs
    v5j = j + "-5"
    lega = make_legacy(keys, v5j, "aborted-by-self", "seller", ["seller"])
    legb = make_legacy(keys, v5j, "aborted-by-other", "buyer", ["buyer"])
    vectors.append({
        "name": "legacy-legacy-outcome-spelling-control",
        "rule": "§10.4.3 legacy outcome-spelling",
        "expected": "pass",
        "note": ("regression guard: two legacy AttestationBundle copies whose role-relative outcome spellings "
                 "(aborted-by-self / aborted-by-other) are perspective partners under the legacy rule — "
                 "non-divergent, unified, and the legacy outcome-spelling rule still governs."),
        "copies": {"seller": lega, "buyer": legb},
        "want": {"expected": "pass", "convergence": "unified", "authoritativeCopyType": "AttestationBundle",
                 "reputationEffect": "include", "scoredRole": "seller", "scoredOutcome": "aborted-by-self",
                 "reason": "legacy pair reconciled via perspective_flip; partner spellings are one event, not a contradiction (§10.4.3/§10.5.1)"},
    })
    # (6) legacy+legacy GENUINE divergence: both copies aborted-by-self from opposite roles ->
    #     flip the counterparty copy (buyer's aborted-by-self -> aborted-by-other) contradicts the
    #     seller's aborted-by-self; both parties blame themselves -> canonical divergence -> exclude.
    v6j = j + "-6"
    lega6 = make_legacy(keys, v6j, "aborted-by-self", "seller", ["seller"])
    legb6 = make_legacy(keys, v6j, "aborted-by-self", "buyer", ["buyer"])
    vectors.append({
        "name": "legacy-legacy-genuine-divergence",
        "rule": "§10.4.3 legacy perspective-reconciled",
        "expected": "fail",
        "note": ("two legacy copies each anchoring aborted-by-self from its own role; flipping the "
                 "counterparty copy to the scored perspective yields aborted-by-other, which contradicts the "
                 "scored copy's aborted-by-self. Both parties blame themselves — a genuine contradiction, not "
                 "a perspective partner — so the pair canonically diverges and the jobId is excluded."),
        "copies": {"seller": lega6, "buyer": legb6},
        "want": {"expected": "fail", "convergence": "divergent", "authoritativeCopyType": None,
                 "reputationEffect": "exclude",
                 "reason": "perspective-reconciled outcomes contradict (both blame self); §10.4.3 legacy divergence, excluded"},
    })
    # (7) mixed + distinct ORCHESTRATOR, non-divergent: legacy buyer failed-counterparty implies the
    #     fault SET {seller, orchestrator}; the FAB names faultedParty=orchestrator, a MEMBER of that set,
    #     with the same failure class -> unified, FAB authoritative (E4 set-membership rule).
    v7j = j + "-7"
    fab7 = make_fab(keys, v7j, "failed-counterparty", "orchestrator", "seller", ["buyer", "seller"], parties=_parties3())
    leg7 = make_legacy(keys, v7j, "failed-counterparty", "buyer", ["buyer", "seller"], parties=_parties3())
    vectors.append({
        "name": "mixed-orchestrator-nondivergent",
        "rule": "§10.4.3 mixed-version implied-fault SET (3-party)",
        "expected": "pass",
        "note": ("three-party session with a distinct orchestrator. The legacy buyer copy's "
                 "failed-counterparty implies a non-buyer at fault — the SET {seller, orchestrator}. The FAB "
                 "names faultedParty=orchestrator, a member of that set, same failure class; the pair is "
                 "unified and the FaultAttestationBundle is authoritative. A singular 'implied absolute fault' "
                 "would be undefined here — set membership resolves it."),
        "copies": {"seller": fab7, "buyer": leg7},
        "want": {"expected": "pass", "convergence": "unified", "authoritativeCopyType": "FaultAttestationBundle",
                 "reputationEffect": "include", "impliedFaultSet": ["orchestrator", "seller"], "faultedParty": "orchestrator",
                 "reason": "FAB faultedParty (orchestrator) is a member of the legacy implied-fault set {seller, orchestrator}; non-divergent (§10.4.3 E4)"},
    })
    # (8) mixed + distinct ORCHESTRATOR, divergent: legacy buyer aborted-by-other implies {seller,
    #     orchestrator}; the FAB names faultedParty=buyer, NOT a member of that set -> divergent -> exclude.
    v8j = j + "-8"
    fab8 = make_fab(keys, v8j, "aborted-by-other", "buyer", "seller", ["seller"], parties=_parties3())
    leg8 = make_legacy(keys, v8j, "aborted-by-other", "buyer", ["buyer"], parties=_parties3())
    vectors.append({
        "name": "mixed-orchestrator-divergent",
        "rule": "§10.4.3 mixed-version implied-fault SET (3-party)",
        "expected": "fail",
        "note": ("three-party session. The legacy buyer copy's aborted-by-other implies the fault SET "
                 "{seller, orchestrator}; the FAB names faultedParty=buyer, which is NOT a member of that set. "
                 "Non-membership is a contradiction, so the pair canonically diverges and the jobId is excluded."),
        "copies": {"seller": fab8, "buyer": leg8},
        "want": {"expected": "fail", "convergence": "divergent", "authoritativeCopyType": None,
                 "reputationEffect": "exclude", "impliedFaultSet": ["orchestrator", "seller"], "faultedParty": "buyer",
                 "reason": "FAB faultedParty (buyer) is not a member of the legacy implied-fault set {seller, orchestrator}; §10.4.3 divergence, excluded (E4)"},
    })
    d["vectors"] = vectors
    return finalize(d)


# ---- S2: fault-bundle-perspective-pair ----
def build_perspective_pair(keys):
    j = "FPP"
    d = concrete_header(
        keys, "fault-bundle-perspective-pair-v0.3",
        "DACS-5 §10.4.3 FaultAttestationBundle-pair rule + §10.4.1 permissible set",
        ["#248 FaultAttestationBundle absolute fault attribution"],
        ("A FaultAttestationBundle pair converges when both copies name the same absolute faultedParty and "
         "outcome class, even where the role-relative outcome spellings differ (aborted-by-self vs "
         "aborted-by-other). Diverge when faultedParty or outcome class differs. A copy whose faultedParty "
         "is outside the §10.4.1 permissible set for its (outcome, anchoredByRole) is rejected."),
        ("Concrete FAB pairs signed under dacs-fault-bundle:v1:. Verdict pass = converges/unified, "
         "fail = divergent or a rejected copy. NOTE: the §10.4.1 same-faultedParty identity rule is "
         "exercised by the faultedParty-divergent vector; a separate 'identity-violation' vector would be "
         "duplicative, so this set ships 3 vectors."),
    )
    vectors = []
    # (1) converges: same fault seller, different spellings
    v1j = j + "-1"
    a = make_fab(keys, v1j, "aborted-by-other", "seller", "buyer", ["buyer"])
    b = make_fab(keys, v1j, "aborted-by-self", "seller", "seller", ["seller"])
    vectors.append({
        "name": "fab-pair-converges-same-fault",
        "rule": "§10.4.3 FAB-pair",
        "expected": "pass",
        "note": ("buyer copy reads aborted-by-other, seller copy reads aborted-by-self, both name faultedParty "
                 "seller and the abort class — the pair converges even though canonical forms differ."),
        "copies": {"buyer": a, "seller": b},
        "want": {"expected": "pass", "convergence": "unified", "reputationEffect": "include",
                 "faultedParty": "seller",
                 "reason": "two FAB copies naming the same faultedParty and class do not diverge (§10.4.3)"},
    })
    # (2) faultedParty-divergent: same class, different fP
    v2j = j + "-2"
    a2 = make_fab(keys, v2j, "aborted-by-self", "seller", "seller", ["seller"])
    b2 = make_fab(keys, v2j, "aborted-by-self", "buyer", "buyer", ["buyer"])
    vectors.append({
        "name": "fab-pair-faultedparty-divergent",
        "rule": "§10.4.3 FAB-pair; §10.4.1 identity",
        "expected": "fail",
        "note": ("both copies are aborts but name different absolute faultedParty (seller vs buyer); the "
                 "§10.4.1 same-faultedParty invariant is violated, so the pair canonically diverges."),
        "copies": {"seller": a2, "buyer": b2},
        "want": {"expected": "fail", "convergence": "divergent", "reputationEffect": "exclude",
                 "reason": "paired copies carry non-identical faultedParty (seller vs buyer); §10.4.3 divergence, excluded"},
    })
    # (3) faultedParty outside permissible set -> copy rejected
    v3j = j + "-3"
    bad = make_fab(keys, v3j, "aborted-by-other", "seller", "seller", ["seller"])  # aborted-by-other, R=seller -> permissible=buyer; declared seller
    vectors.append({
        "name": "fab-copy-faultedparty-out-of-set",
        "rule": "§10.4.1 permissible set",
        "expected": "fail",
        "note": ("a single FAB copy declares faultedParty=seller for (outcome=aborted-by-other, "
                 "anchoredByRole=seller); the permissible value is any party role other than seller (buyer), "
                 "so the copy is rejected (§10.4.1)."),
        "copies": {"seller": bad},
        "want": {"expected": "fail", "copyDisposition": "rejected", "reputationEffect": "exclude",
                 "faultedPartyDeclared": "seller", "faultedPartyPermissible": ["buyer"],
                 "reason": "faultedParty outside the §10.4.1 permissible set for (aborted-by-other, seller); copy rejected"},
    })
    d["vectors"] = vectors
    return finalize(d)


# ---- S3: outsider-binding-flooding ----
def build_outsider_flooding(keys):
    j = "OBF"
    d = concrete_header(
        keys, "outsider-binding-flooding-v0.3",
        "DACS-5 §10.4.2 BB-6 authorized-candidate multiplicity + BB-7 side-level exhaustion (round-6 blocker #3)",
        ["#251 read censorship", "round-3 review: BB-6 outsider-triggerable cap",
         "#248 round-6 blocker #3: BB-7 side-level exhaustion (Random)"],
        ("BB-6 keys collapse/precedence/void on the authenticated-and-authorized predicate, not the "
         "observable candidate count: a candidate is authorized only when its signer is the bundle party "
         "holding role. Outsider self-signed bindings are BB-4-valid but unauthorized — pruned pre-fetch "
         "when a co-signed party map is available, inert post-fetch otherwise. BB-7 exhaustion is SIDE-level: "
         "if ANY signer bucket (after the party-map prune) holds more than the N=8 per-signer budget, its "
         "budget exhausts with candidates unfetched and the WHOLE side is indeterminate — overriding any "
         "authorized candidate that resolved, never a void or a fabricated one-sided classification."),
        ("Concrete honest (seller) and outsider (f0..) bindings. The outsider is not a bundle party, so its "
         "self-signed bindings verify (BB-4) but fail authorization (BB-5 check 9). Verdict pass = the honest "
         "copy resolves with no bucket exhausted; indeterminate = a bucket exhausts N=8 (BB-7) or no authorized "
         "binding resolves. PROVENANCE: the round-3 `outsider-flood-nine-plus-one-honest` expectation was "
         "`present`; that contradicted BB-6/BB-7 (a 9-candidate single-signer bucket exhausts N=8 with a "
         "candidate unfetched -> indeterminate) and was CORRECTED per the #248 round-5 review (Random, blocker "
         "3). The expectation was corrected to the rule; the rule was not bent to fit the fixture. "
         "`co-signed-map-prefetch-prunes-outsiders` was also corrected (round-6 rider): its body omitted "
         "the partyMap its name/want claimed, so the prune was pinned metadata; the map is now carried and "
         "the prune executes (five outsiders pruned pre-fetch, only the honest address fetched)."),
    )
    vectors = []
    req = {"jobId": None, "role": "seller"}

    # (1) nine outsider + one honest -> honest resolves, outsiders inert
    v1j = j + "-1"
    hb = make_fab(keys, v1j, "completed", "none", "seller", ["buyer", "seller"])
    hn = native_address(v1j, "seller", 0)
    honest = make_binding(keys, v1j, "seller", "seller", hn, bundle_hash(hb), idx=0)
    outs = [make_binding(keys, v1j, "seller", "outsider", native_address(v1j, "seller", 100 + k),
                         sha("flood", v1j, str(k)), idx=100 + k) for k in range(9)]
    vectors.append({
        "name": "outsider-flood-nine-plus-one-honest",
        "rule": "BB-6 authorization; BB-7 side-level exhaustion",
        "expected": "indeterminate",
        "note": ("nine outsider self-signed bindings for the victim (jobId, seller) under ONE outsider signer, "
                 "plus one honest seller binding, with NO co-signed party map. CORRECTED (#248 round-5 review, "
                 "Random blocker 3): the round-3 expectation `present` contradicted BB-6/BB-7. The outsider "
                 "signer's 9-candidate bucket exhausts the N=8 fetch budget with one candidate still unfetched "
                 "(the ninth outsider cannot be known inert without fetching it), so BB-7 makes the WHOLE side "
                 "indeterminate — overriding the honest copy that resolves. The expectation was corrected to "
                 "the rule; the rule was not bent to fit the fixture. A consumer MAY re-run with a larger "
                 "budget to lift the exhaustion-indeterminate."),
        "request": {"jobId": v1j, "role": "seller"},
        "bindings": [honest] + outs,
        "anchored": {hn: hb},
        "want": {"expected": "indeterminate", "sideDisposition": "indeterminate", "resolvedNativeAddress": None,
                 "outsiderBindings": 9, "authorizedBindings": 1, "void": False,
                 "exhaustedSigners": [CLAIM["outsider"]], "mayRerunWithLargerBudget": True,
                 "reason": "the single outsider signer's 9-candidate bucket exhausts N=8 with a candidate unfetched; BB-7 side-level exhaustion overrides the resolved honest copy -> indeterminate (never absent, never a void)"},
    })
    # (2) co-signed party map available -> pre-fetch prune
    v2j = j + "-2"
    hb2 = make_fab(keys, v2j, "completed", "none", "seller", ["buyer", "seller"])
    hn2 = native_address(v2j, "seller", 0)
    honest2 = make_binding(keys, v2j, "seller", "seller", hn2, bundle_hash(hb2), idx=0)
    outs2 = [make_binding(keys, v2j, "seller", "outsider", native_address(v2j, "seller", 200 + k),
                          sha("flood", v2j, str(k)), idx=200 + k) for k in range(5)]
    vectors.append({
        "name": "co-signed-map-prefetch-prunes-outsiders",
        "rule": "BB-6 co-signed party map",
        "expected": "pass",
        "note": ("a co-signed copy of the same jobId supplies the role→primary-claim party map; the consumer "
                 "prunes the candidate set to the mapped signer (seller) before any fetch, so the five outsider "
                 "bindings are never fetched and only the honest seller nativeAddress is fetched. CORRECTED "
                 "(#248 round-6 rider): the round-6 body omitted the partyMap its name and want claimed, so the "
                 "prune was pinned metadata, not executed; the map is now carried and the prune is executed."),
        "request": {"jobId": v2j, "role": "seller"},
        "bindings": [honest2] + outs2,
        "anchored": {hn2: hb2},
        "partyMap": {CLAIM["seller"]: "seller"},
        "want": {"expected": "pass", "sideDisposition": "present", "resolvedNativeAddress": hn2,
                 "prunedPreFetch": 5, "fetched": 1, "void": False, "exhaustedSigners": [],
                 "reason": "co-signed party map prunes the five outsider candidates to the mapped signer before any fetch (BB-6); only the honest seller address is fetched"},
    })
    # (3) honest self-flood >8, no map -> budget exhaustion -> indeterminate. The honest role-holder's
    #     OWN copies are authorized (it is the party holding role), so the side is indeterminate purely
    #     because its bucket exhausts N=8 — without the exhaustion rule these would resolve `present`.
    v3j = j + "-3"
    hb3 = make_fab(keys, v3j, "completed", "none", "seller", ["buyer", "seller"])
    self_flood_addrs = [native_address(v3j, "seller", 300 + k) for k in range(9)]
    self_floods = [make_binding(keys, v3j, "seller", "seller", self_flood_addrs[k],
                                sha("selfflood", v3j, str(k)), idx=300 + k) for k in range(9)]
    vectors.append({
        "name": "honest-self-flood-budget-exhaustion",
        "rule": "BB-6 fetch budget; BB-7",
        "expected": "indeterminate",
        "note": ("the honest role-holder publishes nine single-signed self-authorized bindings that diverge, "
                 "with no co-signed map to prune; the seller signer's nine-candidate bucket exceeds the N=8 "
                 "fetch budget, so it exhausts with a candidate unfetched and BB-7 makes the side "
                 "indeterminate — never a classification. Now EXECUTED through resolve_bb6 (round-6 blocker 3)."),
        "request": {"jobId": v3j, "role": "seller"},
        "bindings": self_floods,
        "anchored": {a: hb3 for a in self_flood_addrs},
        "want": {"expected": "indeterminate", "sideDisposition": "indeterminate",
                 "authorizedCandidates": 9, "budget": 8, "void": False, "mayRerunWithLargerBudget": True,
                 "exhaustedSigners": [CLAIM["seller"]],
                 "reason": "the seller signer's 9-candidate bucket exhausts N=8 with a candidate unfetched; BB-7 side-level exhaustion -> indeterminate, never a classification — a consumer MAY re-run with a larger budget"},
    })
    # (4) outsider flood with no honest binding -> indeterminate (not absent, not void)
    v4j = j + "-4"
    outs4 = [make_binding(keys, v4j, "seller", "outsider", native_address(v4j, "seller", 400 + k),
                          sha("flood", v4j, str(k)), idx=400 + k) for k in range(6)]
    vectors.append({
        "name": "outsider-flood-no-honest-binding",
        "rule": "BB-6 authorization; BB-7",
        "expected": "indeterminate",
        "note": ("only outsider self-signed bindings exist for the (jobId, seller) side; none is authorized, so "
                 "no authorized binding resolves and the side disposition is indeterminate — neither present "
                 "nor authoritatively absent, and not a void."),
        "request": {"jobId": v4j, "role": "seller"},
        "bindings": outs4,
        "anchored": {},
        "want": {"expected": "indeterminate", "sideDisposition": "indeterminate",
                 "authorizedBindings": 0, "void": False, "absent": False, "exhaustedSigners": [],
                 "reason": "no BB-4-valid authorized binding resolves (bucket of 6 <= N=8, so not an exhaustion); the side is indeterminate — neither present nor authoritatively absent (BB-7), not a void"},
    })
    # (5) WORST-ORDER (round-4 blocker #2): nine outsider hashes ALL sort STRICTLY BELOW the honest
    #     hash — the adversarial ordering the round-3 vector avoided. Under the E6 per-signer budget
    #     (and the MANDATORY derivation-context prune) the honest role-holder's binding is in its own
    #     budget bucket, so the flood cannot starve it: the honest copy still resolves -> present.
    v5j = j + "-5"
    hb5 = make_fab(keys, v5j, "completed", "none", "seller", ["buyer", "seller"])
    hn5 = native_address(v5j, "seller", 0)
    hh5 = bundle_hash(hb5)
    honest5 = make_binding(keys, v5j, "seller", "seller", hn5, hh5, idx=0)
    # outsider hashes 0x0..0x8 — the smallest possible 64-hex values, guaranteed strictly < hh5.
    worst = [make_binding(keys, v5j, "seller", "outsider", native_address(v5j, "seller", 500 + k),
                          "%064x" % k, idx=500 + k) for k in range(9)]
    vectors.append({
        "name": "outsider-flood-worst-order",
        "rule": "BB-6 per-signer budget (E6); round-4 blocker #2",
        "expected": "pass",
        "note": ("nine outsider self-signed bindings whose claimed bundleContentHash values all sort strictly "
                 "below the honest seller binding's hash — the worst-case ordering the round-3 vector did not "
                 "cover. With the E6 per-signer budget the outsiders (one signer) never consume the honest "
                 "signer's allocation, and in a derivation context the mandatory party-map prune drops them "
                 "pre-fetch; the honest copy resolves regardless of hash ordering."),
        "request": {"jobId": v5j, "role": "seller"},
        "bindings": worst + [honest5],
        "anchored": {hn5: hb5},
        "partyMap": {CLAIM["seller"]: "seller"},
        "honestContentHash": hh5,
        "want": {"expected": "pass", "sideDisposition": "present", "resolvedNativeAddress": hn5,
                 "outsiderHashesBelowHonest": 9, "void": False, "exhaustedSigners": [],
                 "reason": "mandatory derivation-context prune drops the outsider bucket pre-fetch, so no bucket exhausts and the authorized role-holder resolves (E6); an outsider's worst-order flood cannot suppress it"},
    })
    # (6) SYBIL flood: eight DISTINCT outsider keys (not one outsider re-signing) plus one honest seller
    #     binding. Even distinct-key sybils each get their OWN per-signer budget bucket and none is
    #     authorized, so they are inert; the honest signer's bucket still resolves -> present.
    v6j = j + "-6"
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sybil_seeds = {"sybil%d" % k: ("d%d" % k) * 32 for k in range(8)}   # visibly synthetic: d0.. .. d7..
    sybil_keys = {name: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s)) for name, s in sybil_seeds.items()}
    sybil_claim = {name: "did:demos:%s" % name for name in sybil_seeds}
    hb6 = make_fab(keys, v6j, "completed", "none", "seller", ["buyer", "seller"])
    hn6 = native_address(v6j, "seller", 0)
    honest6 = make_binding(keys, v6j, "seller", "seller", hn6, bundle_hash(hb6), idx=0)
    sybil_bindings = []
    for k, name in enumerate(sybil_seeds):
        bd = {"bindingVersion": "1", "jobId": v6j, "role": "seller",
              "logicalAddress": logical_address(v6j, "seller"),
              "nativeAddress": native_address(v6j, "seller", 600 + k),
              "bundleContentHash": sha("sybil", v6j, str(k)),
              "anchorTx": "demos-testnet:tx-sybil-%d" % k, "signer": sybil_claim[name]}
        payload = (BINDING_DOMAIN + binding_hash(bd)).encode("utf-8")
        bd["signature"] = {"algorithm": "ed25519", "signer": sybil_claim[name],
                           "value": b64u(sybil_keys[name].sign(payload))}
        sybil_bindings.append(bd)
    vectors.append({
        "name": "outsider-sybil-flood",
        "rule": "BB-6 per-signer budget (E6) — distinct-key sybil",
        "expected": "pass",
        "note": ("eight distinct outsider keypairs (visibly synthetic disclosed seeds d0.. .. d7..) each anchor "
                 "one self-signed binding for the victim (jobId, seller), plus one honest seller binding. Each "
                 "distinct signer gets its own per-signer budget bucket and none is authorized, so all eight "
                 "are inert; the honest signer's bucket resolves the side -> present. A per-(jobId,role) global "
                 "budget would let eight distinct keys crowd out the honest one — the E6 per-signer budget does not."),
        "request": {"jobId": v6j, "role": "seller"},
        "bindings": sybil_bindings + [honest6],
        "anchored": {hn6: hb6},
        "partyMap": {CLAIM["seller"]: "seller"},
        "want": {"expected": "pass", "sideDisposition": "present", "resolvedNativeAddress": hn6,
                 "distinctOutsiderKeys": 8, "void": False, "exhaustedSigners": [],
                 "reason": "the party-map prune drops the eight sybil buckets pre-fetch; each distinct signer would get its own bucket anyway, so none exhausts and the authorized role-holder resolves (E6)"},
    })
    # (7) ARM 1 (xm33 B2 design): worst-order flood with NO co-signed map, every bucket <= 8. Eight
    #     outsider bindings under ONE outsider signer, all bundleContentHash sorting strictly BELOW the
    #     honest hash; one honest seller binding; NO partyMap; anchored = {honest -> the seller bundle}.
    #     The outsider bucket holds exactly 8 (== budget), so it does NOT exhaust; the per-signer budget
    #     keeps the honest seller's own bucket resolvable regardless of the adversarial low-hash ordering.
    #     This is the anchored/no-map worst-order case xm33's arm 1 assumes: present, no exhaustion.
    v7j = j + "-7"
    hb7 = make_fab(keys, v7j, "completed", "none", "seller", ["buyer", "seller"])
    hn7 = native_address(v7j, "seller", 0)
    hh7 = bundle_hash(hb7)
    honest7 = make_binding(keys, v7j, "seller", "seller", hn7, hh7, idx=0)
    # eight outsider hashes 0x0..0x7 — the smallest 64-hex values, guaranteed strictly < hh7; one signer.
    worst_nomap = [make_binding(keys, v7j, "seller", "outsider", native_address(v7j, "seller", 700 + k),
                                "%064x" % k, idx=700 + k) for k in range(8)]
    vectors.append({
        "name": "outsider-flood-worst-order-no-map",
        "rule": "BB-6 per-signer budget (E6), anchored/no-map path; BB-7 (arm 1, xm33 B2)",
        "expected": "pass",
        "note": ("xm33 B2 arm 1: eight outsider self-signed bindings under ONE outsider signer whose "
                 "bundleContentHash values all sort strictly BELOW the honest seller binding's hash, with NO "
                 "co-signed party map (anchored/no-map path). The outsider bucket holds exactly 8 == N, so it "
                 "does not exhaust; the per-signer budget puts the honest seller in its own bucket, so the "
                 "worst-order flood cannot starve it and the honest copy resolves -> present. This makes the "
                 "per-signer budget load-bearing on the anchored-only path (a single global budget would let "
                 "the eight low-hash outsiders crowd out the honest one)."),
        "request": {"jobId": v7j, "role": "seller"},
        "bindings": worst_nomap + [honest7],
        "anchored": {hn7: hb7},
        "honestContentHash": hh7,
        "want": {"expected": "pass", "sideDisposition": "present", "resolvedNativeAddress": hn7,
                 "outsiderHashesBelowHonest": 8, "void": False, "exhaustedSigners": [],
                 "reason": "anchored/no-map path: the outsider bucket holds exactly 8 (no exhaustion) and the per-signer budget isolates the honest seller's bucket, so it resolves despite every outsider hash sorting below it (E6, arm 1)"},
    })
    # (8) CROSS-ROLE INSIDER (round-7 blocker): a FULL co-signed party map names BOTH parties
    #     ({buyer:buyer, seller:seller}). The BUYER — a mapped, authenticated party — signs a binding
    #     that CLAIMS role "seller" (valid buyer signature; correct jobId / logicalAddress / matching
    #     bundleContentHash), ordered ahead of the honest seller binding. Key-membership authorization
    #     (signer in party_map) authorizes it for the SELLER side because the mapped role (buyer) is
    #     discarded; role-match authorization (BB-5 check 9) prunes it — the buyer does not hold seller.
    v8j = j + "-8"
    hb8 = make_fab(keys, v8j, "completed", "none", "seller", ["buyer", "seller"])
    hn8 = native_address(v8j, "seller", 0)
    hh8 = bundle_hash(hb8)
    honest8 = make_binding(keys, v8j, "seller", "seller", hn8, hh8, idx=0)
    insider_native = native_address(v8j, "seller", 800)
    # buyer signs a binding claiming role "seller"; bundleContentHash matches the honest bundle (hh8).
    insider = make_binding(keys, v8j, "seller", "buyer", insider_native, hh8, idx=800)
    vectors.append({
        "name": "cross-role-insider-binding-pruned",
        "rule": "BB-6 role-match authorization (BB-5 check 9); round-7",
        "expected": "pass",
        "note": ("a full co-signed party map names both parties (buyer->buyer, seller->seller). The buyer, a "
                 "mapped and authenticated party, publishes a binding CLAIMING role seller with a valid buyer "
                 "signature and the correct jobId/logicalAddress and a bundleContentHash matching the honest "
                 "seller bundle, ordered ahead of the honest seller binding. Authorizing on key-membership "
                 "(the buyer's signer IS a map key) resolves the insider copy for the seller side because the "
                 "mapped role is discarded; BB-5 check 9 role-match authorization (the buyer's authenticated "
                 "role is buyer, not seller) prunes the insider pre-fetch, and the honest seller binding resolves."),
        "request": {"jobId": v8j, "role": "seller"},
        "bindings": [insider, honest8],
        "anchored": {hn8: hb8},
        "partyMap": {CLAIM["buyer"]: "buyer", CLAIM["seller"]: "seller"},
        "honestContentHash": hh8,
        "insiderNativeAddress": insider_native,
        "want": {"expected": "pass", "sideDisposition": "present", "resolvedNativeAddress": hn8,
                 "void": False, "exhaustedSigners": [], "prunedInsider": insider_native,
                 "reason": "the buyer-signed binding claims role seller but the authenticated party map maps the buyer to buyer, not seller; BB-5 check 9 role-match prunes it pre-fetch and the honest seller binding resolves (never the insider copy)"},
    })
    # ---- SAME-ROLE LADDER (round-7 rider-2): EXECUTED vectors for the BB-6 intra-signer multiplicity
    #      ladder. Under role-match authorization two authorized same-role copies exist only for the SAME
    #      signer (the role holder), so these are same-signer multiplicity cases. WANTS ARE SPEC-DERIVED
    #      from §10.4.2 BB-6 / §10.5.1 (lines 634-644), never from the oracle.
    # L1 collapse: two canonically-EQUAL authorized seller copies (identical §10.4.1 content, distinct
    #      native addresses) -> BB-6 "canonically equal copies collapse to one retrieved copy" -> present.
    v9j = j + "-9"
    hb9 = make_fab(keys, v9j, "completed", "none", "seller", ["buyer", "seller"])
    hh9 = bundle_hash(hb9)
    n9a = native_address(v9j, "seller", 0)
    n9b = native_address(v9j, "seller", 1)
    l1a = make_binding(keys, v9j, "seller", "seller", n9a, hh9, idx=0)
    l1b = make_binding(keys, v9j, "seller", "seller", n9b, hh9, idx=1)  # same content hash -> canonically equal
    l1_resolved = min(n9a, n9b)  # ascending (bundleContentHash, nativeAddress): equal hash -> lower native
    vectors.append({
        "name": "ladder-l1-canonically-equal-collapse",
        "rule": "BB-6 collapse (canonically-equal); round-7 rider-2",
        "expected": "pass",
        "note": "L1: two canonically-equal authorized seller copies (identical §10.4.1 content) collapse to one retrieved copy (BB-6) -> present.",
        "request": {"jobId": v9j, "role": "seller"},
        "bindings": [l1a, l1b],
        "anchored": {n9a: hb9, n9b: hb9},
        "partyMap": {CLAIM["seller"]: "seller"},
        "want": {"expected": "pass", "sideDisposition": "present", "resolvedNativeAddress": l1_resolved,
                 "void": False, "exhaustedSigners": [],
                 "specCitation": "§10.4.2 BB-6: 'canonically equal copies (§10.4.1) collapse to one retrieved copy'",
                 "reason": "canonically-equal authorized same-role copies collapse to one retrieved copy (BB-6) -> present"},
    })
    # L2 precedence: two canonically-UNEQUAL divergent authorized seller copies, one carrying ALL §10.4.1
    #      required signatures (co-signed completed) and one lesser-signed (single-signed abort). BB-6:
    #      "one carrying all §10.4.1 required signatures takes precedence and lesser-signed copies MUST be
    #      discarded" -> present, resolved = the FULLY-SIGNED copy's native (regardless of hash order).
    v10j = j + "-10"
    full_bundle = make_fab(keys, v10j, "completed", "none", "seller", ["buyer", "seller"])   # all required sigs
    lesser_bundle = make_fab(keys, v10j, "aborted-by-self", "seller", "seller", ["seller"])  # single-signed abort (divergent)
    h_full, h_lesser = bundle_hash(full_bundle), bundle_hash(lesser_bundle)
    n_full, n_lesser = native_address(v10j, "seller", 0), native_address(v10j, "seller", 1)
    b_full = make_binding(keys, v10j, "seller", "seller", n_full, h_full, idx=0)
    b_lesser = make_binding(keys, v10j, "seller", "seller", n_lesser, h_lesser, idx=1)
    vectors.append({
        "name": "ladder-l2-full-signature-precedence",
        "rule": "BB-6 full-signature precedence; round-7 rider-2",
        "expected": "pass",
        "note": "L2: divergent authorized seller copies; the co-signed completed copy carries all §10.4.1 required signatures and takes precedence over the single-signed abort (BB-6) -> present, resolved = fully-signed copy.",
        "request": {"jobId": v10j, "role": "seller"},
        "bindings": [b_full, b_lesser],
        "anchored": {n_full: full_bundle, n_lesser: lesser_bundle},
        "partyMap": {CLAIM["seller"]: "seller"},
        "want": {"expected": "pass", "sideDisposition": "present", "resolvedNativeAddress": n_full,
                 "void": False, "exhaustedSigners": [],
                 "fullSignedContentHash": h_full, "lesserSignedContentHash": h_lesser,
                 "specCitation": "§10.4.2 BB-6: 'one carrying all §10.4.1 required signatures takes precedence and lesser-signed copies MUST be discarded'",
                 "reason": "the fully-signed (co-signed completed) copy takes BB-6 precedence over the lesser-signed divergent; resolved = fully-signed native"},
    })
    # L3 equal-standing void: two canonically-UNEQUAL divergent authorized seller copies of EQUAL signature
    #      standing (both single-signed aborts diverging on the absolute faultedParty). BB-6/BB-7: "only
    #      equal signature standing ... MUST NOT select among them and that side's read disposition is
    #      indeterminate" -> indeterminate (never a classification).
    v11j = j + "-11"
    void_a = make_fab(keys, v11j, "aborted-by-self", "seller", "seller", ["seller"])   # faultedParty seller
    void_b = make_fab(keys, v11j, "aborted-by-other", "buyer", "seller", ["seller"])   # faultedParty buyer (divergent)
    hva, hvb = bundle_hash(void_a), bundle_hash(void_b)
    nva, nvb = native_address(v11j, "seller", 0), native_address(v11j, "seller", 1)
    lva = make_binding(keys, v11j, "seller", "seller", nva, hva, idx=0)
    lvb = make_binding(keys, v11j, "seller", "seller", nvb, hvb, idx=1)
    vectors.append({
        "name": "ladder-l3-equal-standing-void",
        "rule": "BB-6 equal-standing void; BB-7; round-7 rider-2",
        "expected": "indeterminate",
        "note": "L3: two equal-standing single-signed authorized seller copies diverge on the absolute faultedParty (seller vs buyer); BB-6 selects neither and the side's read disposition is indeterminate (BB-7).",
        "request": {"jobId": v11j, "role": "seller"},
        "bindings": [lva, lvb],
        "anchored": {nva: void_a, nvb: void_b},
        "partyMap": {CLAIM["seller"]: "seller"},
        "want": {"expected": "indeterminate", "sideDisposition": "indeterminate", "resolvedNativeAddress": None,
                 "void": False, "exhaustedSigners": [],
                 "specCitation": "§10.4.2 BB-6/BB-7: 'only when canonically unequal authorized copies are of equal signature standing ... the consumer MUST NOT select among them and that side's read disposition is indeterminate'",
                 "reason": "equal-standing divergent authorized same-role copies void the side; read disposition indeterminate (BB-6/BB-7), never a classification"},
    })
    # disclose the sybil keypairs so the vector is independently verifiable
    d["seeds"].update(sybil_seeds)
    d["publicKeys"].update({sybil_claim[name]: b64u(sybil_keys[name].public_key().public_bytes_raw())
                            for name in sybil_seeds})
    d["vectors"] = vectors
    return finalize(d)


# ---- S4: unresolved-vs-absent (abstract) ----
PLACEHOLDER = "1" * 64


def build_unresolved_vs_absent():
    d = {
        "set": "unresolved-vs-absent-v0.3",
        "spec": "DACS-5 §10.4.3(b) + §10.4.2 BB-8 + CORE §5 absence-evidence policy",
        "gaps": ["#251 bundle-copy read censorship"],
        "decisionModel": ("The §10.4.3(b) one-sided classification is reachable for a missing side only when a "
                          "BB-4-valid BB-5-consistent binding resolves its native address AND an SR-2 read of "
                          "that address is authoritatively absent under the substrate binding's declared "
                          "absence-evidence policy (CORE §5). Non-discovery of a binding, an ordinary "
                          "unqualified not-found, or a binding with no declared policy is indeterminate — "
                          "never absent."),
    }
    vectors = [
        {
            "name": "no-binding-on-any-surface-is-indeterminate",
            "rule": "BB-8; §10.4.3(b)",
            "expected": "indeterminate",
            "note": "no BB-4-valid binding is discovered on any consulted surface; §10.4.3(b) is unreachable.",
            "scoredRole": "seller",
            "binding": {"resolved": False, "absenceEvidencePolicy": None},
            "reads": {"seller": {"response": "no-binding"}},
            "want": {"readDisposition": "indeterminate", "lookupDisposition": "indeterminate",
                     "oneSidedReachable": False, "reputationEffect": "exclude",
                     "reason": "non-discovery of a binding establishes indeterminate, never absence (BB-8)"},
        },
        {
            "name": "binding-resolves-authoritative-absent-one-sided",
            "rule": "BB-8 gate; CORE §5",
            "expected": "pass",
            "note": ("a BB-4-valid binding resolves the missing side's native address and an SR-2 read is "
                     "authoritatively absent under a declared absence-evidence policy; the §10.4.3(b) one-sided "
                     "classification is reachable."),
            "scoredRole": "seller",
            "binding": {"resolved": True, "nativeAddress": "stor-" + "0" * 40,
                        "absenceEvidencePolicy": {"finalityRule": "finalized-head", "authentication": "signed-response",
                                                  "independence": "distinct-endpoints", "threshold": "2-of-3",
                                                  "freshness": "<=finality", "stateConsistency": "single-view"}},
            "reads": {"seller": {"response": "authoritative-absent", "authenticated": True, "finalizedState": "finalized-head"}},
            "want": {"readDisposition": "absent", "lookupDisposition": "one-sided",
                     "oneSidedReachable": True, "reputationEffect": "include",
                     "reason": "resolved binding plus policy-qualified authoritative absence satisfies the BB-8 gate (§10.4.3(b))"},
        },
        {
            "name": "binding-resolves-ordinary-not-found-is-indeterminate",
            "rule": "CORE §5; BB-8",
            "expected": "indeterminate",
            "note": ("the binding resolves but the SR-2 read is an ordinary unqualified not-found, not an "
                     "authenticated finalized non-membership result; the disposition is indeterminate."),
            "scoredRole": "seller",
            "binding": {"resolved": True, "nativeAddress": "stor-" + "0" * 40,
                        "absenceEvidencePolicy": {"finalityRule": "finalized-head", "authentication": "signed-response",
                                                  "independence": "distinct-endpoints", "threshold": "2-of-3",
                                                  "freshness": "<=finality", "stateConsistency": "single-view"}},
            "reads": {"seller": {"response": "not-found", "authenticated": False, "finalizedState": None}},
            "want": {"readDisposition": "indeterminate", "lookupDisposition": "indeterminate",
                     "oneSidedReachable": False, "reputationEffect": "exclude",
                     "reason": "an ordinary unqualified not-found is indeterminate, not authoritative absence (CORE §5)"},
        },
        {
            "name": "demos-mapping-no-policy-is-indeterminate",
            "rule": "DEMOS-MAPPING authoritative-absence",
            "expected": "indeterminate",
            "note": ("the current Demos Storage Program mapping declares no absence-evidence policy, so any "
                     "not-found has the CORE SR-2 disposition indeterminate, not absent, regardless of the "
                     "read result."),
            "scoredRole": "seller",
            "binding": {"resolved": True, "nativeAddress": "stor-" + "0" * 40, "absenceEvidencePolicy": None},
            "reads": {"seller": {"response": "not-found", "substrate": "demos", "declaredPolicy": False}},
            "want": {"readDisposition": "indeterminate", "lookupDisposition": "indeterminate",
                     "oneSidedReachable": False, "reputationEffect": "exclude",
                     "reason": "the Demos mapping does not declare an absence-evidence policy, so not-found is indeterminate, not absent"},
        },
    ]
    d["vectors"] = vectors
    return finalize(d)


# ---- S5: receipt-rederivation (abstract) ----
RCP_WINDOW = [1780000000000, 1780900000000]


FINALIZED_STATE_REF = "demos-testnet:finalized-1780004000000"


def evidence_hash(ev):
    return hashlib.sha256(canonical(ev)).hexdigest()


def make_absence_evidence(native, kind="non-membership-proof"):
    """AbsenceEvidence (R2): CORE §5 owns policy semantics; DACS-5 defines only the binding relation
    (absenceBinding.nativeAddress == AbsenceEvidence.nativeAddress). Address-cohering, dereferenceable."""
    return {"kind": kind, "nativeAddress": native, "finalizedStateRef": FINALIZED_STATE_REF}


def build_receipt_rederivation(keys):
    """CONCRETE: real signed FaultAttestationBundle content + full resolutionContext. A rederiver
    dereferences bundleRefs, EXECUTES the per-copy validation, and reproduces byte-identical metrics.

    Round-6 blocker #1: the replayable receipt is a DISTINCT type, `ReplayableReputationDerivation`,
    with its own `replayableDerivationVersion: "1"` discriminator (CORE §11.1.2 new-type refusal).
    Round-6 blocker #2: replay now actually AUTHENTICATES every copy — roleEvidence via BB-4/BB-5,
    BB-6 selection reproduced from `bb6Context`, §10.4.3 divergence re-run against the dereferenced
    `counterpartyRef` (authenticated by `counterpartyRoleEvidence`), and the absence address/proof
    relation (`absenceBinding.nativeAddress == AbsenceEvidence.nativeAddress`). Four negative vectors
    (N1-N4) are published receipts that replay REFUSES, one per Random's round-5 mutation class."""
    j = "RCP"
    d = concrete_header(
        keys, "receipt-rederivation-v0.3",
        "DACS-5 §10.5 ReplayableReputationDerivation replay (authenticated per-copy validation) + §10.5.3 (1)-(3); round-6 blockers #1/#2",
        ["round-3 review: receipt rederivation context (#5)", "#248 round-4 blocker #1: replayable receipt",
         "#248 round-6 blocker #1: derivation compatibility split", "#248 round-6 blocker #2: replay actually validates"],
        ("A published ReplayableReputationDerivation carries the replayableDerivationVersion discriminator "
         "(never derivationVersion) and one resolutionContext entry per bundleRefs member. Replay EXECUTES: "
         "roleEvidence BB-4/BB-5 re-verification; BB-6 re-selection from bb6Context (candidateBindings/partyMap/"
         "budget) that MUST reach roleEvidence.binding.nativeAddress; §10.4.3 divergence re-run against the "
         "dereferenced counterpartyRef, whose role is authenticated by counterpartyRoleEvidence; and the "
         "absence relation absenceBinding.nativeAddress == dereferenced AbsenceEvidence.nativeAddress with "
         "absenceEvidenceRef.contentHash == sha256(canonical(AbsenceEvidence)). Any failure => refusal."),
        ("Concrete FAB copies + BundleBindings + AbsenceEvidence objects (disclosed seeds). The pass vector "
         "replays byte-identically through the full validation; N1-N4 are published receipts each carrying one "
         "of Random's round-5 mutations (divergent counterparty, invalid counterparty role binding, misbound "
         "absence evidence, competing same-role BB-6 copy) and MUST be refused; the member-missing + refusal "
         "vectors from round-6 #1 are retained."),
    )
    party = CLAIM["seller"]
    PM = {CLAIM["seller"]: "seller"}   # authenticated role-holder map (MANDATORY in derivation context)

    # --- pass fixture: Job A two-copy present (both completed), Job B one-copy absent (seller abort) ---
    ja, jb = j + "-A", j + "-B"
    a_seller = make_fab(keys, ja, "completed", "none", "seller", ["buyer", "seller"])
    # counterparty copy: distinguished only by an ADVISORY finalisedAt skew (still in-window and
    # NOT a §10.4.3 divergence), so it has a distinct contentHash the counterpartyRef can point at.
    a_buyer = make_fab(keys, ja, "completed", "none", "buyer", ["buyer", "seller"], finalised_at=FINALISED_AT + 1000)
    b_seller = make_fab(keys, jb, "aborted-by-self", "seller", "seller", ["seller"])
    ha_s, ha_b, hb_s = bundle_hash(a_seller), bundle_hash(a_buyer), bundle_hash(b_seller)
    na_a_s, na_a_b = native_address(ja, "seller"), native_address(ja, "buyer")
    na_b_s, na_b_b = native_address(jb, "seller"), native_address(jb, "buyer")
    # roleEvidence: verified BB-4/BB-5 binding for the authoritative copy; counterpartyRoleEvidence:
    # the binding authenticating the counterparty's role (anchoredByRole is unhashed); absenceBinding:
    # the binding resolving the MISSING buyer address, coherent with the AbsenceEvidence object.
    a_seller_binding = make_binding(keys, ja, "seller", "seller", na_a_s, ha_s)
    a_buyer_binding = make_binding(keys, ja, "buyer", "buyer", na_a_b, ha_b)
    b_seller_binding = make_binding(keys, jb, "seller", "seller", na_b_s, hb_s)
    absence_binding = make_binding(keys, jb, "buyer", "buyer", na_b_b, PLACEHOLDER)
    ev_b = make_absence_evidence(na_b_b)
    ev_b_hash = evidence_hash(ev_b)
    bb6_a = {"candidateBindings": [a_seller_binding], "partyMap": PM, "budget": 8}
    bb6_b = {"candidateBindings": [b_seller_binding], "partyMap": PM, "budget": 8}
    tagged = [
        {"bundle": a_seller, "resolvedRole": "seller", "counterpartyDisposition": "present",
         "counterpartyRef": {"kind": "dacs-5-bundle", "id": ja + "-buyer", "contentHash": ha_b},
         "counterpartyRoleEvidence": {"kind": "binding", "binding": a_buyer_binding},
         "roleEvidence": {"kind": "binding", "binding": a_seller_binding},
         "bb6Context": bb6_a},
        {"bundle": b_seller, "resolvedRole": "seller", "counterpartyDisposition": "absent",
         "absenceEvidenceRef": {"kind": "non-membership-proof", "locator": na_b_b, "contentHash": ev_b_hash},
         "absenceBinding": absence_binding,
         "roleEvidence": {"kind": "binding", "binding": b_seller_binding},
         "bb6Context": bb6_b},
    ]
    absence_evidence_map = {ev_b_hash: ev_b}
    vectors = []
    vectors.append({
        "name": "complete-resolution-context-replays-identical",
        "rule": "§10.5 Replay (1)-(4); §10.5.3 (3)",
        "expected": "pass",
        "note": ("two jobIds: a two-copy present jobId (both completed FAB copies) carrying counterpartyRef + "
                 "counterpartyRoleEvidence + bb6Context, and a one-copy absent jobId (seller aborted-by-self) "
                 "carrying a dereferenceable AbsenceEvidence + coherent absenceBinding + bb6Context. Replay "
                 "authenticates every copy AND reproduces byte-identical metrics and bundleCount."),
        "party": party,
        "window": RCP_WINDOW,
        "taggedBundles": tagged,
        "derefBundles": {ha_s: a_seller, ha_b: a_buyer, hb_s: b_seller},
        "absenceEvidence": absence_evidence_map,
        "want": {"conforming": True, "replayByteIdentical": True, "reputationEffect": "include",
                 "bundleCount": 2,
                 "metrics": {"completionRate": 0.5, "counterpartyAdjustedCompletionRate": 0.5, "counterpartyFaultRate": 0.0},
                 "reason": "complete, authenticated resolutionContext replays byte-identical and passes all four replay checks (§10.5 Replay)"},
    })
    # --- fail: present entry missing counterpartyRef (round-4 blocker #1) ---
    vectors.append({
        "name": "receipt-missing-counterparty-ref",
        "rule": "§10.5.3 (3)/(4); E5",
        "expected": "fail",
        "note": ("a published receipt whose two-copy (present) entry omits counterpartyRef; a rederiver cannot "
                 "re-run §10.4.3 divergence or authority selection against the counterparty copy, so the "
                 "receipt is not independently reproducible and is non-conforming."),
        "derivation": {
            "replayableDerivationVersion": "1",
            "bundleRefs": [ha_s],
            "resolutionContext": [
                {"contentHash": ha_s, "resolvedRole": "seller", "counterpartyDisposition": "present",
                 "roleEvidence": {"kind": "address", "resolvedAddress": logical_address(ja, "seller")}},
            ],
            "windowingBasis": "finalisedAt",
        },
        "want": {"conforming": False, "reputationEffect": "exclude",
                 "reason": "present-disposition entry missing counterpartyRef; a rederiver cannot re-run §10.4.3 divergence/authority — non-conforming (E5)"},
    })
    # --- fail: one-copy absent entry missing absenceEvidenceRef ---
    vectors.append({
        "name": "one-copy-without-absence-evidence-must-not-publish",
        "rule": "§10.5.3 E3; §10.5.1 guard (iv)",
        "expected": "fail",
        "note": ("a one-copy jobId whose resolutionContext entry is absent-disposition but lacks a valid "
                 "absenceEvidenceRef MUST NOT be included in a published derivation."),
        "derivation": {
            "replayableDerivationVersion": "1",
            "bundleRefs": [hb_s],
            "resolutionContext": [
                {"contentHash": hb_s, "resolvedRole": "seller", "counterpartyDisposition": "absent",
                 "roleEvidence": {"kind": "address", "resolvedAddress": logical_address(jb, "seller")}},
            ],
            "windowingBasis": "finalisedAt",
        },
        "want": {"conforming": False, "mustNotPublish": True, "reputationEffect": "exclude",
                 "reason": "a one-copy jobId whose entry lacks a valid absenceEvidenceRef MUST NOT be included in a published derivation (§10.5.3/guard (iv))"},
    })
    # --- fail: resolutionContext mis-keyed (fewer entries than bundleRefs) ---
    vectors.append({
        "name": "miskeyed-resolution-context-is-nonconforming",
        "rule": "§10.5.3 (4)",
        "expected": "fail",
        "note": ("the resolutionContext is missing an entry for one bundleRefs member (mis-keyed by "
                 "contentHash); the derivation is not independently reproducible."),
        "derivation": {
            "replayableDerivationVersion": "1",
            "bundleRefs": sorted([ha_s, hb_s]),
            "resolutionContext": [
                {"contentHash": sorted([ha_s, hb_s])[0], "resolvedRole": "seller", "counterpartyDisposition": "present",
                 "counterpartyRef": {"kind": "dacs-5-bundle", "id": ja + "-buyer", "contentHash": ha_b},
                 "roleEvidence": {"kind": "address", "resolvedAddress": logical_address(ja, "seller")}},
            ],
            "windowingBasis": "finalisedAt",
        },
        "want": {"conforming": False, "reputationEffect": "exclude",
                 "reason": "resolutionContext is missing/mis-keyed for a bundleRefs member; not independently reproducible and non-conforming (§10.5.3 (4))"},
    })

    # --- REFUSAL VECTORS (round-6 blocker #1): CORE §11.1.2 new-type refusal on the discriminator.
    # A single well-formed one-copy-absent receipt BODY, cloned three ways, differing only in the
    # discriminator shape. Each MUST be refused before any member check. The body is replay-able
    # (bundleRefs + resolutionContext + derefBundles) so that a mutant which DELETES the refusal
    # gate would proceed and produce a non-None replay, failing the refusal assertion.
    refusal_rc = [
        {"contentHash": hb_s, "resolvedRole": "seller", "counterpartyDisposition": "absent",
         "absenceEvidenceRef": {"kind": "non-membership-proof", "locator": "stor-" + "0" * 40, "contentHash": PLACEHOLDER},
         "absenceBinding": absence_binding,
         "roleEvidence": {"kind": "binding", "binding": b_seller_binding}},
    ]
    refusal_body = {
        "bundleRefs": [hb_s],
        "resolutionContext": refusal_rc,
        "metrics": {"completionRate": 0.0, "counterpartyAdjustedCompletionRate": 0.0, "counterpartyFaultRate": 0.0},
        "bundleCount": 1,
        "windowingBasis": "finalisedAt",
    }
    refusal_deref = {hb_s: b_seller}
    # (a) resolutionContext under the LEGACY derivationVersion "1" — no replay claim exists on the
    #     legacy ReputationDerivation type, so a replay consumer refuses.
    vectors.append({
        "name": "legacy-derivationversion-carrying-resolutioncontext-is-refused",
        "rule": "CORE §11.1.2 new-type refusal; §10.5",
        "expected": "fail",
        "note": ("a published object carries resolutionContext but the legacy derivationVersion \"1\" "
                 "discriminator, not replayableDerivationVersion. The legacy ReputationDerivation makes no "
                 "replay claim, so a replay consumer MUST refuse it as unsupported before any member check."),
        "party": party,
        "window": RCP_WINDOW,
        "derefBundles": refusal_deref,
        "derivation": {"derivationVersion": "1", **refusal_body},
        "want": {"conforming": False, "refused": True, "refusalCategory": "discriminator", "reputationEffect": "exclude",
                 "reason": "object carries legacy derivationVersion, not replayableDerivationVersion \"1\"; refused before member check (CORE §11.1.2)"},
    })
    # (b) a replayable object with the discriminator STRIPPED — no discriminator at all.
    vectors.append({
        "name": "stripped-discriminator-is-refused",
        "rule": "CORE §11.1.2 new-type refusal; §10.5",
        "expected": "fail",
        "note": ("a well-formed replayable receipt body with its replayableDerivationVersion discriminator "
                 "stripped. Stripping the (unsigned) discriminator downgrades the object to a legacy "
                 "derivation making no replay claim; a replay consumer MUST refuse it."),
        "party": party,
        "window": RCP_WINDOW,
        "derefBundles": refusal_deref,
        "derivation": dict(refusal_body),
        "want": {"conforming": False, "refused": True, "refusalCategory": "discriminator", "reputationEffect": "exclude",
                 "reason": "object lacks replayableDerivationVersion \"1\"; refused before member check (CORE §11.1.2)"},
    })
    # (c) an object carrying BOTH discriminators — ambiguous type identity, refused.
    vectors.append({
        "name": "both-discriminators-is-refused",
        "rule": "CORE §11.1.2 new-type refusal; §10.5",
        "expected": "fail",
        "note": ("a published object carries BOTH replayableDerivationVersion \"1\" and the legacy "
                 "derivationVersion \"1\". A ReplayableReputationDerivation MUST NOT carry derivationVersion; "
                 "the ambiguous type identity is refused before any member check."),
        "party": party,
        "window": RCP_WINDOW,
        "derefBundles": refusal_deref,
        "derivation": {"replayableDerivationVersion": "1", "derivationVersion": "1", **refusal_body},
        "want": {"conforming": False, "refused": True, "refusalCategory": "discriminator", "reputationEffect": "exclude",
                 "reason": "object carries both replayableDerivationVersion and derivationVersion; a ReplayableReputationDerivation MUST NOT carry derivationVersion (CORE §11.1.2)"},
    })

    # --- N1-N4 (round-6 blocker #2): each a published receipt that replay REFUSES, one per Random's
    #     round-5 mutation class. All are pre-built ReplayableReputationDerivation objects.
    # N1: the dereferenced counterparty copy canonically diverges (§10.4.3) -> divergence() true.
    a_buyer_div = make_fab(keys, ja, "aborted-by-self", "buyer", "buyer", ["buyer"])
    ha_bdiv = bundle_hash(a_buyer_div)
    na_a_bdiv = native_address(ja, "buyer", 1)
    a_buyer_div_binding = make_binding(keys, ja, "buyer", "buyer", na_a_bdiv, ha_bdiv)
    vectors.append({
        "name": "divergent-counterparty-refused",
        "rule": "§10.5 Replay (3); §10.4.3 (N1)",
        "expected": "fail",
        "note": ("a two-copy present receipt whose dereferenced counterparty copy canonically diverges from "
                 "the authoritative copy (completed vs aborted). Replay re-runs §10.4.3 divergence() against the "
                 "authenticated counterparty and MUST refuse."),
        "party": party,
        "window": RCP_WINDOW,
        "derefBundles": {ha_s: a_seller, ha_bdiv: a_buyer_div},
        "derivation": {
            "replayableDerivationVersion": "1",
            "bundleRefs": [ha_s],
            "resolutionContext": [
                {"contentHash": ha_s, "resolvedRole": "seller",
                 "roleEvidence": {"kind": "binding", "binding": a_seller_binding}, "bb6Context": bb6_a,
                 "counterpartyDisposition": "present",
                 "counterpartyRef": {"kind": "dacs-5-bundle", "id": ja + "-buyer-div", "contentHash": ha_bdiv},
                 "counterpartyRoleEvidence": {"kind": "binding", "binding": a_buyer_div_binding}},
            ],
            "metrics": {"completionRate": 1.0, "counterpartyAdjustedCompletionRate": 1.0, "counterpartyFaultRate": 0.0},
            "bundleCount": 1, "windowingBasis": "finalisedAt",
        },
        "want": {"conforming": False, "refused": True, "refusalCategory": "divergence", "reputationEffect": "exclude",
                 "reason": "dereferenced counterparty copy canonically diverges; §10.4.3 reconciliation refuses the receipt (N1)"},
    })
    # N2: counterpartyRoleEvidence.binding.role is flipped (seller, should be buyer) -> role authentication fails.
    a_buyer_wrongrole_binding = make_binding(keys, ja, "seller", "buyer", na_a_b, ha_b)  # role="seller", signer=buyer
    vectors.append({
        "name": "invalid-counterparty-role-binding-refused",
        "rule": "§10.5 Replay (3) counterparty authentication (N2)",
        "expected": "fail",
        "note": ("a two-copy present receipt whose counterpartyRoleEvidence binding declares the WRONG role "
                 "(seller instead of the counterparty's buyer). anchoredByRole is unhashed, so the receipt must "
                 "carry a role-correct binding; replay MUST refuse the mis-roled one."),
        "party": party,
        "window": RCP_WINDOW,
        "derefBundles": {ha_s: a_seller, ha_b: a_buyer},
        "derivation": {
            "replayableDerivationVersion": "1",
            "bundleRefs": [ha_s],
            "resolutionContext": [
                {"contentHash": ha_s, "resolvedRole": "seller",
                 "roleEvidence": {"kind": "binding", "binding": a_seller_binding}, "bb6Context": bb6_a,
                 "counterpartyDisposition": "present",
                 "counterpartyRef": {"kind": "dacs-5-bundle", "id": ja + "-buyer", "contentHash": ha_b},
                 "counterpartyRoleEvidence": {"kind": "binding", "binding": a_buyer_wrongrole_binding}},
            ],
            "metrics": {"completionRate": 1.0, "counterpartyAdjustedCompletionRate": 1.0, "counterpartyFaultRate": 0.0},
            "bundleCount": 1, "windowingBasis": "finalisedAt",
        },
        "want": {"conforming": False, "refused": True, "refusalCategory": "counterparty-role", "reputationEffect": "exclude",
                 "reason": "counterpartyRoleEvidence.binding.role != the counterparty's role; role authentication fails (N2)"},
    })
    # N3: absenceBinding.nativeAddress != the dereferenced AbsenceEvidence.nativeAddress.
    na_b_b_wrong = native_address(jb, "buyer", 9)
    absence_binding_misbound = make_binding(keys, jb, "buyer", "buyer", na_b_b_wrong, PLACEHOLDER)
    vectors.append({
        "name": "misbound-absence-evidence-refused",
        "rule": "§10.5 Replay (4) absence relation (N3)",
        "expected": "fail",
        "note": ("a one-copy absent receipt whose absenceBinding resolves a DIFFERENT native address than the "
                 "dereferenced AbsenceEvidence.nativeAddress. The absence evidence does not attach to the "
                 "counterparty's actual address, so replay MUST refuse."),
        "party": party,
        "window": RCP_WINDOW,
        "derefBundles": {hb_s: b_seller},
        "absenceEvidence": {ev_b_hash: ev_b},
        "derivation": {
            "replayableDerivationVersion": "1",
            "bundleRefs": [hb_s],
            "resolutionContext": [
                {"contentHash": hb_s, "resolvedRole": "seller",
                 "roleEvidence": {"kind": "binding", "binding": b_seller_binding}, "bb6Context": bb6_b,
                 "counterpartyDisposition": "absent",
                 "absenceEvidenceRef": {"kind": "non-membership-proof", "locator": na_b_b, "contentHash": ev_b_hash},
                 "absenceBinding": absence_binding_misbound},
            ],
            "metrics": {"completionRate": 0.0, "counterpartyAdjustedCompletionRate": 0.0, "counterpartyFaultRate": 0.0},
            "bundleCount": 1, "windowingBasis": "finalisedAt",
        },
        "want": {"conforming": False, "refused": True, "refusalCategory": "absence-relation", "reputationEffect": "exclude",
                 "reason": "absenceBinding.nativeAddress != dereferenced AbsenceEvidence.nativeAddress (N3)"},
    })
    # N4: bb6Context carries a SECOND authorized same-signer candidate whose bundleContentHash sorts BELOW
    #     the authoritative one, so re-running BB-6 re-selects a different nativeAddress. Bucket size 2 (<=8),
    #     no exhaustion — the refusal depends only on deterministic ascending-contentHash selection.
    competitor = make_binding(keys, jb, "seller", "seller", native_address(jb, "seller", 2), "%064x" % 0)
    bb6_n4 = {"candidateBindings": [b_seller_binding, competitor], "partyMap": PM, "budget": 8}
    vectors.append({
        "name": "competing-same-role-copy-changes-bb6-refused",
        "rule": "§10.5 Replay (2) BB-6 reproduction (N4)",
        "expected": "fail",
        "note": ("a one-copy receipt whose bb6Context candidate set contains a SECOND authorized same-signer "
                 "(seller) binding whose bundleContentHash sorts below the authoritative one. Re-running BB-6 "
                 "over the candidate set selects the competitor's nativeAddress, not roleEvidence.binding's, so "
                 "replay MUST refuse. Bucket size 2 (<=8): no budget exhaustion, deterministic selection only."),
        "party": party,
        "window": RCP_WINDOW,
        "derefBundles": {hb_s: b_seller},
        "absenceEvidence": {ev_b_hash: ev_b},
        "derivation": {
            "replayableDerivationVersion": "1",
            "bundleRefs": [hb_s],
            "resolutionContext": [
                {"contentHash": hb_s, "resolvedRole": "seller",
                 "roleEvidence": {"kind": "binding", "binding": b_seller_binding}, "bb6Context": bb6_n4,
                 "counterpartyDisposition": "absent",
                 "absenceEvidenceRef": {"kind": "non-membership-proof", "locator": na_b_b, "contentHash": ev_b_hash},
                 "absenceBinding": absence_binding},
            ],
            "metrics": {"completionRate": 0.0, "counterpartyAdjustedCompletionRate": 0.0, "counterpartyFaultRate": 0.0},
            "bundleCount": 1, "windowingBasis": "finalisedAt",
        },
        "want": {"conforming": False, "refused": True, "refusalCategory": "bb6-reselection", "reputationEffect": "exclude",
                 "competingCandidateBucketSize": 2,
                 "reason": "BB-6 re-selection over bb6Context.candidateBindings yields a different nativeAddress than roleEvidence.binding (N4)"},
    })
    # N5 (round-7 blocker): FORGED bb6Context.partyMap. The map claims the BUYER's authenticated claim
    #     holds role "seller" — contradicting the authoritative bundle roster (the buyer holds "buyer").
    #     The candidate set and every other member is valid, so a replay that consumes the partyMap
    #     WITHOUT authenticating it against the roster resolves BB-6 and replays byte-identically; a replay
    #     that authenticates the partyMap against the roster before any authorization use MUST refuse.
    forged_pm = {CLAIM["seller"]: "seller", CLAIM["buyer"]: "seller"}
    bb6_forged = {"candidateBindings": [b_seller_binding], "partyMap": forged_pm, "budget": 8}
    vectors.append({
        "name": "forged-partymap-unauthenticated-refused",
        "rule": "§10.5 Replay (2) partyMap authentication; BB-6 (round-7 N5)",
        "expected": "fail",
        "note": ("a one-copy absent receipt whose bb6Context.partyMap maps the buyer's claim to role seller, "
                 "contradicting the authenticated bundle roster (the buyer holds buyer). Every member and "
                 "candidate is otherwise valid, so a replay that trusts the partyMap unauthenticated resolves "
                 "BB-6 and reproduces the metrics; a replay that authenticates the partyMap against the roster "
                 "before any authorization use MUST refuse the receipt (round-7)."),
        "party": party,
        "window": RCP_WINDOW,
        "derefBundles": {hb_s: b_seller},
        "absenceEvidence": {ev_b_hash: ev_b},
        "derivation": {
            "replayableDerivationVersion": "1",
            "bundleRefs": [hb_s],
            "resolutionContext": [
                {"contentHash": hb_s, "resolvedRole": "seller",
                 "roleEvidence": {"kind": "binding", "binding": b_seller_binding}, "bb6Context": bb6_forged,
                 "counterpartyDisposition": "absent",
                 "absenceEvidenceRef": {"kind": "non-membership-proof", "locator": na_b_b, "contentHash": ev_b_hash},
                 "absenceBinding": absence_binding},
            ],
            "metrics": {"completionRate": 0.0, "counterpartyAdjustedCompletionRate": 0.0, "counterpartyFaultRate": 0.0},
            "bundleCount": 1, "windowingBasis": "finalisedAt",
        },
        "want": {"conforming": False, "refused": True, "refusalCategory": "partymap-authentication", "reputationEffect": "exclude",
                 "reason": "bb6Context.partyMap maps the buyer's claim to role seller, contradicting the authenticated bundle roster (buyer holds buyer); replay MUST refuse before any authorization use (round-7 N5)"},
    })
    # N6 (round-7 blocker): the bb6Context carries a SECOND candidate binding that is BB-5-invalid for the
    #     requested side — it claims role "buyer" yet is signed by the seller (a valid seller signature over
    #     a buyer-role binding). It sorts ABOVE the honest candidate, so an unfixed replay (which never
    #     re-verifies candidates) still selects the honest address and replays; a replay that re-runs BB-4 +
    #     BB-5 checks 1-5 on EVERY candidate MUST refuse (the candidate's role != the requested seller role).
    bad_candidate = make_binding(keys, jb, "buyer", "seller", native_address(jb, "seller", 5), "f" * 64)
    bb6_badcand = {"candidateBindings": [b_seller_binding, bad_candidate], "partyMap": PM, "budget": 8}
    vectors.append({
        "name": "bad-candidate-binding-in-context-refused",
        "rule": "§10.5 Replay (2) BB-4/BB-5 candidate re-verification; round-7 N6",
        "expected": "fail",
        "note": ("a one-copy absent receipt whose bb6Context candidate set carries a second binding that is "
                 "BB-5-invalid for the requested seller side: it claims role buyer but is signed by the seller "
                 "(the signature verifies over the buyer-role binding). Its bundleContentHash sorts above the "
                 "honest candidate, so an unfixed replay selects the honest address and replays byte-identically "
                 "without ever re-verifying the candidate; a replay that re-runs BB-4 + BB-5 checks 1-5 on EVERY "
                 "carried candidate MUST refuse because the candidate's role != the requested role (round-7 N6)."),
        "party": party,
        "window": RCP_WINDOW,
        "derefBundles": {hb_s: b_seller},
        "absenceEvidence": {ev_b_hash: ev_b},
        "derivation": {
            "replayableDerivationVersion": "1",
            "bundleRefs": [hb_s],
            "resolutionContext": [
                {"contentHash": hb_s, "resolvedRole": "seller",
                 "roleEvidence": {"kind": "binding", "binding": b_seller_binding}, "bb6Context": bb6_badcand,
                 "counterpartyDisposition": "absent",
                 "absenceEvidenceRef": {"kind": "non-membership-proof", "locator": na_b_b, "contentHash": ev_b_hash},
                 "absenceBinding": absence_binding},
            ],
            "metrics": {"completionRate": 0.0, "counterpartyAdjustedCompletionRate": 0.0, "counterpartyFaultRate": 0.0},
            "bundleCount": 1, "windowingBasis": "finalisedAt",
        },
        "want": {"conforming": False, "refused": True, "refusalCategory": "candidate-verification", "reputationEffect": "exclude",
                 "reason": "a bb6Context candidate claims role buyer on the seller side; BB-4/BB-5 re-verification of every candidate refuses the receipt (round-7 N6)"},
    })
    d["vectors"] = vectors
    return finalize(d)


# ---- S6: fab-bundle-extended-pointer (E7 triple-identity) ----
def build_fab_extended_pointer(keys):
    j = "FBEP"
    d = concrete_header(
        keys, "fab-bundle-extended-pointer-v0.3",
        "DACS-5 §10.4.2 extended-pointer FaultAttestationBundle path + §10.4.1 triple-identity (E7)",
        ["#248 FaultAttestationBundle extended-pointer path (round-4 blocker #4)"],
        ("A FaultAttestationBundle too large for the size cap anchors a FaultBundleExtendedPointer "
         "(faultBundleVersion discriminator, dacs-fault-bundle-pointer:v1: domain). BB-5 check 8 and the "
         "§10.4.1 comparison apply to the DEREFERENCED full bundle: binding.bundleContentHash == "
         "pointer.fullBundleContentHash == the recomputed §10.4.1 hash of the dereferenced bundle — three "
         "values, one identity. A signature failure or dereferenced-hash mismatch is rejected content (BB-7), "
         "never absence."),
        ("Concrete FAB + fault-typed pointer + binding. The pointer signs under dacs-fault-bundle-pointer:v1: "
         "and the dereferenced full bundle under dacs-fault-bundle:v1:. Verdict pass = triple-identity holds; "
         "fail = the pointer/binding agree with each other but neither equals the dereferenced bundle's hash "
         "(rejected content — the case a compare-the-pointer's-own-hash shortcut would wrongly accept)."),
    )
    vectors = []
    # (1) valid: binding == pointer == recomputed dereferenced hash
    v1j = j + "-1"
    full1 = make_fab(keys, v1j, "completed", "none", "seller", ["buyer", "seller"])
    h1 = bundle_hash(full1)
    native1 = native_address(v1j, "seller")
    vectors.append({
        "name": "fab-pointer-valid",
        "rule": "§10.4.2 extended-pointer; §10.4.1 triple-identity (E7)",
        "expected": "pass",
        "note": ("the record at the resolved nativeAddress is a FaultBundleExtendedPointer; its "
                 "fullBundleContentHash equals the recomputed §10.4.1 hash of the dereferenced full bundle, "
                 "which equals the binding's bundleContentHash — three values, one identity."),
        "nativeAddress": native1,
        "pointer": make_fab_pointer(keys, "seller", f"https://cdn.example/{v1j}", h1),
        "dereferenced": full1,
        "binding": make_binding(keys, v1j, "seller", "seller", native1, h1),
        "want": {"expected": "pass", "tripleIdentity": True, "reputationEffect": "include",
                 "reason": "binding.bundleContentHash == pointer.fullBundleContentHash == recomputed §10.4.1 hash of the dereferenced bundle"},
    })
    # (2) content-mismatch: pointer and binding agree on a hash that is NOT the dereferenced bundle's.
    #     A faithful predicate recomputes the §10.4.1 hash of the dereferenced bundle and rejects; a
    #     shortcut that compares the pointer's own claimed hash against the binding would wrongly accept.
    v2j = j + "-2"
    full2 = make_fab(keys, v2j, "completed", "none", "seller", ["buyer", "seller"])
    wrong = sha("wrong-content", v2j)   # 64-hex, != bundle_hash(full2)
    native2 = native_address(v2j, "seller")
    vectors.append({
        "name": "fab-pointer-content-mismatch",
        "rule": "§10.4.2 extended-pointer BB-5 check 8 (E7)",
        "expected": "fail",
        "note": ("the pointer's fullBundleContentHash and the binding's bundleContentHash agree with each "
                 "other but neither equals the recomputed §10.4.1 hash of the dereferenced bundle; the "
                 "dereferenced content does not match, so the pointer is rejected content (BB-7), never absence."),
        "nativeAddress": native2,
        "pointer": make_fab_pointer(keys, "seller", f"https://cdn.example/{v2j}", wrong),
        "dereferenced": full2,
        "binding": make_binding(keys, v2j, "seller", "seller", native2, wrong),
        "want": {"expected": "fail", "tripleIdentity": False, "reputationEffect": "exclude",
                 "reason": "pointer.fullBundleContentHash != recomputed §10.4.1 hash of the dereferenced bundle; rejected content (BB-7)"},
    })
    d["vectors"] = vectors
    return finalize(d)


def render(data):
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def all_sets():
    keys = _keys()
    return {
        "mixed-version-reconciliation-v0.3.json": build_mixed_version(keys),
        "fault-bundle-perspective-pair-v0.3.json": build_perspective_pair(keys),
        "outsider-binding-flooding-v0.3.json": build_outsider_flooding(keys),
        "unresolved-vs-absent-v0.3.json": build_unresolved_vs_absent(),
        "receipt-rederivation-v0.3.json": build_receipt_rederivation(keys),
        "fab-bundle-extended-pointer-v0.3.json": build_fab_extended_pointer(keys),
    }


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true")
    g.add_argument("--check", action="store_true")
    args = ap.parse_args()

    sets = all_sets()
    if args.write:
        for fname, data in sets.items():
            (SEC / fname).write_text(render(data), encoding="utf-8")
            print(f"wrote {fname} ({data['count']} vectors)")
        return 0

    mismatched = []
    for fname, data in sets.items():
        want = render(data)
        path = SEC / fname
        if not path.exists() or path.read_text(encoding="utf-8") != want:
            mismatched.append(fname)
    if mismatched:
        print("MISMATCH: " + ", ".join(mismatched) + " (run --write)")
        return 1
    print(f"dacs5 reputation vectors OK — {len(sets)} sets byte-identical to a fresh regeneration")
    return 0


if __name__ == "__main__":
    sys.exit(main())
