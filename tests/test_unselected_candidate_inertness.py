"""Regression tests: unselected candidates are inert (BB-6/BB-7).

Each case pairs an honest-only control with an honest-plus-unselected variant,
and keeps authenticated conflicts (equal-standing BB-6 divergence, selected
invalid copy) non-passing.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT), str(ROOT / "tests"), str(ROOT / "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

import generate_current_use_reputation_vectors as generator  # noqa: E402
import dacs5_reference as R  # noqa: E402

NON_STRING_FAULTS = ([], {}, 7, None, True)
PARTY_MAP = {generator.CLAIMS["buyer"]: "buyer", generator.CLAIMS["seller"]: "seller"}


class _CurrentUse:
    def __init__(self):
        self.factory = generator.CurrentUseFixtureFactory()
        self.party = generator.CLAIMS["buyer"]
        self.window = generator.FIXTURE_QUERY_WINDOW
        self.keys = self.factory.current_keys
        self.context = self.factory.current_authority(self.party, self.window)
        self.fixture = self.factory.build()
        self.deps = self.fixture["dependencies"]

    def derive(self, request):
        return R.derive_current_use_replayable(
            self.party, [request], *self.window, self.deps, self.fixture["verifierConfig"],
            pubkeys=self.keys, trusted_contexts=self.context)

    def seller_fab_request(self):
        request = self.fixture["currentRequestsByModel"]["block-depth"]
        buyer = request["roles"]["buyer"]["selectionContext"]["candidateBindings"][0]
        strong = self.deps["bundlesByNativeAddress"][buyer["nativeAddress"]]
        authority = self.deps["bundleAuthorityByContentHash"][R.bundle_hash(strong)]
        compat = self.factory.finality.compatibility_copies({"bundle": strong, "authority": authority})
        self.authority = compat["evidenceBoundAuthority"]
        honest = compat["copies"]["fault"]
        request["roles"]["seller"] = {
            "disposition": "present", "mappingKind": "binding",
            "selectionContext": {"candidateBindings": [], "partyMap": dict(PARTY_MAP), "budget": 8},
            "anchorReceiptsByNativeAddress": {}, "legacyEraEvidenceByNativeAddress": {},
        }
        self.add_seller_candidate(request, honest, "honest")
        return request, honest

    def add_seller_candidate(self, request, bundle, label):
        digest = R.bundle_hash(bundle)
        binding = self.factory.bundle_binding(bundle, "seller", "g5:" + label,
                                              trusted_contexts=self.context)
        native = binding["nativeAddress"]
        self.deps["bundlesByNativeAddress"][native] = bundle
        self.deps["bundleAuthorityByContentHash"][digest] = self.authority
        role = request["roles"]["seller"]
        role["selectionContext"]["candidateBindings"].append(binding)
        role["anchorReceiptsByNativeAddress"][native] = self.factory.anchor_proof(
            purpose="current-bundle", substrate=generator.WRITE_SUBSTRATE,
            subject_id=request["jobId"], subject_role="seller", logical=binding["logicalAddress"],
            native=native, content_hash=digest, transaction="g5-" + digest,
            writer=generator.CLAIMS["seller"], nonce=97, height=206, index=1)
        return binding

    def variant(self, honest, fault, signers):
        extra = copy.deepcopy(honest)
        extra["outcome"] = "aborted-by-self"
        extra["faultedParty"] = fault
        extra["finalisedAt"] += 1
        self.factory.finality.sign_bundle(extra, R.FAULT_BUNDLE_DOMAIN)
        extra["signatures"] = [s for s in extra["signatures"]
                               if s["party"] in {generator.CLAIMS[r] for r in signers}]
        return extra


class PostFetchFaultedPartyTotalityTests(unittest.TestCase):
    """Both §10.4.1 membership entry points return (False, reason); they never raise."""

    def test_binding_and_address_entry_points_are_total(self):
        cu = _CurrentUse()
        request, honest = cu.seller_fab_request()
        keys = R._authenticated_current_key_map(cu.keys)
        binding = request["roles"]["seller"]["selectionContext"]["candidateBindings"][0]
        self.assertEqual((True, "ok"), R._post_fetch_valid(honest, binding, keys))
        addr = "pure-g5"
        resolver = lambda _job, _role: addr  # noqa: E731
        self.assertEqual((True, "ok"), R._post_fetch_address_valid(
            honest, addr, "seller", R.bundle_hash(honest), cu.keys,
            expected_jobid=request["jobId"], pure_mapping_resolver=resolver,
            trusted_contexts=cu.context))
        for fault in NON_STRING_FAULTS:
            with self.subTest(faultedParty=fault):
                bad = cu.variant(honest, fault, ("seller",))
                bad_binding = cu.factory.bundle_binding(
                    bad, "seller", "g5:bad:%r" % (fault,), trusted_contexts=cu.context)
                for result in (
                    R._post_fetch_valid(bad, bad_binding, keys),
                    R._post_fetch_legacy_valid(bad, bad_binding, keys),
                    R._post_fetch_address_valid(
                        bad, addr, "seller", R.bundle_hash(bad), cu.keys,
                        expected_jobid=request["jobId"], pure_mapping_resolver=resolver,
                        trusted_contexts=cu.context),
                    R._post_fetch_legacy_address_valid(
                        bad, addr, "seller", R.bundle_hash(bad), keys,
                        expected_jobid=request["jobId"], pure_mapping_resolver=resolver),
                ):
                    self.assertFalse(result[0])
                    self.assertIn("faultedParty", result[1])


class CurrentUseUnselectedCandidateTests(unittest.TestCase):
    def test_honest_only_control_passes(self):
        cu = _CurrentUse()
        request, _ = cu.seller_fab_request()
        self.assertEqual("pass", cu.derive(request)["decision"])

    def test_unselected_invalid_fault_party_is_inert(self):
        for fault in NON_STRING_FAULTS + ("buyer",):
            for signers in (("seller",), ("buyer", "seller")):
                with self.subTest(faultedParty=fault, signers=signers):
                    cu = _CurrentUse()
                    request, honest = cu.seller_fab_request()
                    cu.add_seller_candidate(request, cu.variant(honest, fault, signers), "extra")
                    result = cu.derive(request)
                    self.assertEqual("pass", result["decision"], result["reason"])
                    ref = result["derivation"]["resolutionContext"][0]
                    self.assertNotIn(R.bundle_hash(cu.variant(honest, fault, signers)),
                                     {ref.get("contentHash"),
                                      (ref.get("counterpartyRef") or {}).get("contentHash")})

    def test_authenticated_equal_standing_conflict_stays_non_passing(self):
        cu = _CurrentUse()
        request, honest = cu.seller_fab_request()
        cu.add_seller_candidate(request, cu.variant(honest, "seller", ("buyer", "seller")), "full")
        self.assertEqual("indeterminate", cu.derive(request)["decision"])

    def test_valid_lesser_divergent_copy_loses_precedence(self):
        cu = _CurrentUse()
        request, honest = cu.seller_fab_request()
        cu.add_seller_candidate(request, cu.variant(honest, "seller", ("seller",)), "lesser")
        self.assertEqual("pass", cu.derive(request)["decision"])


class DeriveJobBoundUnselectedCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = json.loads((ROOT / "conformance/fixtures/evidence-bound-fault-bundle-compatibility-v0.4.json")
                          .read_text(encoding="utf-8"))
        cls.data = data
        cls.fab = next(c["copies"]["seller"] for c in data["pairCases"]
                       if c["name"] == "ebfab-fab-older-cannot-erase-seb")
        cls.party = next(p["primaryClaim"] for p in cls.fab["parties"] if p["role"] == "seller")
        cls.job = cls.fab["jobId"]
        cls.window = (cls.fab["finalisedAt"] - 1, cls.fab["finalisedAt"] + 1)
        cls.honest = {"bundle": cls.fab, "selectedByRoleResolution": True, "resolvedJobId": cls.job,
                      "resolvedRole": "seller", "counterpartyDisposition": "absent",
                      "absenceEvidenceRef": {"contentHash": "00" * 32}}

    def derive(self, tags):
        for fn in (R.derive_job_bound, R.derive_legacy_job_bound):
            yield fn.__name__, fn(self.party, tags, *self.window)

    def assertSameAsHonest(self, tags):
        honest = R.derive_job_bound(self.party, [self.honest], *self.window)
        self.assertEqual(1, honest["bundleCount"])
        for name, derivation in self.derive(tags):
            with self.subTest(deriver=name):
                self.assertEqual(honest["bundleCount"], derivation["bundleCount"])
                self.assertEqual(honest["metrics"], derivation["metrics"])
                self.assertEqual(honest["bundleRefs"], derivation["bundleRefs"])

    def test_unselected_candidates_are_inert(self):
        dual = {"faultBundleVersion": "1", "evidenceBoundFaultBundleVersion": "1"}
        bad_version = copy.deepcopy(self.fab)
        bad_version["faultBundleVersion"] = "2"
        bad_version["faultedParty"] = []
        wrong_job = dict(self.fab, jobId=self.job + "-other")
        abort_bad = dict(self.fab, outcome="aborted-by-self", faultedParty=[])
        cp_bad = dict(self.fab, anchoredByRole="buyer", faultedParty=[])
        extras = [
            {"bundle": dual, "selectedByRoleResolution": False},
            {"bundle": dual, "selectedByRoleResolution": False, "resolvedJobId": self.job},
            {"bundle": None, "selectedByRoleResolution": False, "resolvedJobId": self.job},
            {"bundle": bad_version, "selectedByRoleResolution": False, "resolvedJobId": self.job},
            {"bundle": wrong_job, "selectedByRoleResolution": False, "resolvedJobId": self.job},
            {"bundle": abort_bad, "selectedByRoleResolution": False, "resolvedJobId": self.job,
             "resolvedRole": "seller", "counterpartyDisposition": "absent",
             "absenceEvidenceRef": {"contentHash": "00" * 32}},
            {"bundle": cp_bad, "selectedByRoleResolution": False, "resolvedJobId": self.job,
             "resolvedRole": "buyer"},
        ]
        for index, extra in enumerate(extras):
            for order in ("after", "before"):
                with self.subTest(extra=index, order=order):
                    tags = [self.honest, extra] if order == "after" else [extra, self.honest]
                    self.assertSameAsHonest(tags)

    def test_selected_invalid_copy_still_rejects_the_requested_job(self):
        dual = {"faultBundleVersion": "1", "evidenceBoundFaultBundleVersion": "1"}
        cp_bad = dict(self.fab, anchoredByRole="buyer", faultedParty=[])
        for extra in (
            {"bundle": dual, "selectedByRoleResolution": True, "resolvedJobId": self.job},
            {"bundle": dict(self.fab, jobId=self.job + "-other"), "selectedByRoleResolution": True,
             "resolvedJobId": self.job},
            {"bundle": cp_bad, "selectedByRoleResolution": True, "resolvedJobId": self.job,
             "resolvedRole": "buyer"},
        ):
            for name, derivation in self.derive([self.honest, extra]):
                with self.subTest(deriver=name, extra=extra["bundle"] and sorted(extra["bundle"])[:2]):
                    self.assertEqual(0, derivation["bundleCount"])


if __name__ == "__main__":
    unittest.main()
