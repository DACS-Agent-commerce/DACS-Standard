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


def make_fab(keys, job_id, outcome, faulted_party, anchored_by_role, sign_roles,
             phase_kind="deliver-storage-program", phase_outcome="ok"):
    b = {
        "faultBundleVersion": "1",
        "jobId": job_id,
        "outcome": outcome,
        "faultedParty": faulted_party,
        "anchoredByRole": anchored_by_role,
        "listingRef": {"listingId": "listing-" + job_id, "version": 1,
                       "contentHash": sha("listing", job_id)},
        "parties": _parties(),
        "phaseSummary": [{"index": 0, "kind": phase_kind, "outcome": phase_outcome}],
        "vetRecords": [],
        "settlementEvidence": [],
        "recipeRegistryVersion": 1,
        "railRegistryVersion": 1,
        "finalisedAt": FINALISED_AT,
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
                phase_kind="deliver-storage-program", phase_outcome="ok"):
    b = {
        "bundleVersion": "1",
        "jobId": job_id,
        "outcome": outcome,
        "anchoredByRole": anchored_by_role,
        "listingRef": {"listingId": "listing-" + job_id, "version": 1,
                       "contentHash": sha("listing", job_id)},
        "parties": _parties(),
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
                 "reason": "legacy pair uses the outcome-spelling definition; perspective-partner spellings do not diverge"},
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
        "DACS-5 §10.4.2 BB-6 authorized-candidate multiplicity (round-3 blocker #4)",
        ["#251 read censorship", "round-3 review: BB-6 outsider-triggerable cap"],
        ("BB-6 keys collapse/precedence/void on the authenticated-and-authorized predicate, not the "
         "observable candidate count: a candidate is authorized only when its signer is the bundle party "
         "holding role. Outsider self-signed bindings are BB-4-valid but unauthorized — pruned pre-fetch "
         "when a co-signed party map is available, inert post-fetch otherwise. Budget exhaustion and a side "
         "with no authorized binding are indeterminate (BB-7), never a void or a fabricated one-sided "
         "classification."),
        ("Concrete honest (seller) and outsider (f0..) bindings. The outsider is not a bundle party, so its "
         "self-signed bindings verify (BB-4) but fail authorization (BB-5 check 9). Verdict pass = the honest "
         "copy resolves; indeterminate = budget exhaustion or no authorized binding."),
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
        "rule": "BB-6 authorization",
        "expected": "pass",
        "note": ("the review-3 attack: nine outsider self-signed bindings for the victim (jobId, seller) plus "
                 "one honest seller binding. The outsiders are unauthorized and inert; the honest copy "
                 "resolves and no side is voided."),
        "request": {"jobId": v1j, "role": "seller"},
        "bindings": [honest] + outs,
        "anchored": {hn: hb},
        "want": {"expected": "pass", "sideDisposition": "present", "resolvedNativeAddress": hn,
                 "outsiderBindings": 9, "authorizedBindings": 1, "void": False,
                 "reason": "outsider bindings are BB-4-valid but unauthorized (signer is not the bundle party holding role); they are inert and the honest authorized copy resolves — no void"},
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
                 "prunes the candidate set to the mapped signer (seller) before any fetch, so the outsider "
                 "bindings are never fetched."),
        "request": {"jobId": v2j, "role": "seller"},
        "bindings": [honest2] + outs2,
        "anchored": {hn2: hb2},
        "want": {"expected": "pass", "sideDisposition": "present", "resolvedNativeAddress": hn2,
                 "prunedPreFetch": 5, "fetched": 1, "void": False,
                 "reason": "co-signed party map prunes the candidate set to the mapped signer before any fetch (BB-6); outsiders never fetched"},
    })
    # (3) honest self-flood >8, no map -> budget exhaustion -> indeterminate
    v3j = j + "-3"
    self_floods = [make_binding(keys, v3j, "seller", "seller", native_address(v3j, "seller", 300 + k),
                                sha("selfflood", v3j, str(k)), idx=300 + k) for k in range(9)]
    vectors.append({
        "name": "honest-self-flood-budget-exhaustion",
        "rule": "BB-6 fetch budget; BB-7",
        "expected": "indeterminate",
        "note": ("the honest role-holder publishes nine single-signed self-authorized bindings that diverge, "
                 "with no co-signed map to prune; nine authorized candidates exceed the N=8 fetch budget, so "
                 "the side disposition is indeterminate — never a classification."),
        "request": {"jobId": v3j, "role": "seller"},
        "bindings": self_floods,
        "anchored": {},
        "want": {"expected": "indeterminate", "sideDisposition": "indeterminate",
                 "authorizedCandidates": 9, "budget": 8, "void": False, "mayRerunWithLargerBudget": True,
                 "reason": "budget exhaustion yields the side disposition indeterminate, never a classification — a consumer MAY re-run resolution with a larger budget (BB-6/BB-7)"},
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
                 "authorizedBindings": 0, "void": False, "absent": False,
                 "reason": "no BB-4-valid authorized binding resolves; the side is indeterminate — neither present nor authoritatively absent (BB-7), not a void"},
    })
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
def build_receipt_rederivation():
    d = {
        "set": "receipt-rederivation-v0.3",
        "spec": "DACS-5 §10.5.3 determinism receipt clauses (3)/(4) + §10.5.1 resolutionContext",
        "gaps": ["round-3 review: receipt rederivation context (#5)"],
        "decisionModel": ("A published ReputationDerivation MUST carry exactly one resolutionContext entry per "
                          "bundleRefs member, keyed by contentHash, giving the resolved role and — for every "
                          "one-copy jobId — the counterparty address's absenceEvidenceRef. A rederivation "
                          "supplying each entry as its §10.5.1 input-precondition tag MUST reproduce "
                          "byte-identical metrics and bundleCount; a missing, mis-keyed, or insufficient "
                          "resolutionContext is non-conforming, and a one-copy jobId without a valid "
                          "absenceEvidenceRef MUST NOT be published."),
    }
    vectors = [
        {
            "name": "complete-resolution-context-replays-identical",
            "rule": "§10.5.3 (3)/(4)",
            "expected": "pass",
            "note": ("a derivation whose resolutionContext has one entry per bundleRefs member — including a "
                     "one-copy entry carrying absenceEvidenceRef — replays byte-identical under the recorded "
                     "windowingBasis; conforming."),
            "derivation": {
                "bundleRefs": ["hashA", "hashB"],
                "resolutionContext": [
                    {"contentHash": "hashA", "resolvedRole": "seller", "counterpartyDisposition": "present"},
                    {"contentHash": "hashB", "resolvedRole": "buyer", "counterpartyDisposition": "absent",
                     "absenceEvidenceRef": {"kind": "non-membership-proof", "locator": "stor-" + "0" * 40,
                                            "contentHash": PLACEHOLDER}},
                ],
                "windowingBasis": "sr2-anchor-timestamp",
            },
            "want": {"conforming": True, "replayByteIdentical": True, "reputationEffect": "include",
                     "reason": "resolutionContext has exactly one entry per bundleRefs member keyed by contentHash; replay reproduces byte-identical metrics/bundleCount (§10.5.3 (3)/(4))"},
        },
        {
            "name": "miskeyed-resolution-context-is-nonconforming",
            "rule": "§10.5.3 (4)",
            "expected": "fail",
            "note": ("the resolutionContext is missing an entry for one bundleRefs member (mis-keyed by "
                     "contentHash); the derivation is not independently reproducible."),
            "derivation": {
                "bundleRefs": ["hashA", "hashB"],
                "resolutionContext": [
                    {"contentHash": "hashA", "resolvedRole": "seller", "counterpartyDisposition": "present"},
                ],
                "windowingBasis": "sr2-anchor-timestamp",
            },
            "want": {"conforming": False, "reputationEffect": "exclude",
                     "reason": "resolutionContext is missing/mis-keyed for a bundleRefs member; the derivation is not independently reproducible and is non-conforming (§10.5.3 (4))"},
        },
        {
            "name": "one-copy-without-absence-evidence-must-not-publish",
            "rule": "§10.5.3 E3; §10.5.1 guard (iv)",
            "expected": "fail",
            "note": ("a one-copy jobId whose resolutionContext entry is absent-disposition but lacks a valid "
                     "absenceEvidenceRef MUST NOT be included in a published derivation."),
            "derivation": {
                "bundleRefs": ["hashB"],
                "resolutionContext": [
                    {"contentHash": "hashB", "resolvedRole": "buyer", "counterpartyDisposition": "absent"},
                ],
                "windowingBasis": "sr2-anchor-timestamp",
            },
            "want": {"conforming": False, "mustNotPublish": True, "reputationEffect": "exclude",
                     "reason": "a one-copy jobId whose entry lacks a valid absenceEvidenceRef MUST NOT be included in a published derivation (§10.5.3/guard (iv))"},
        },
    ]
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
        "receipt-rederivation-v0.3.json": build_receipt_rederivation(),
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
