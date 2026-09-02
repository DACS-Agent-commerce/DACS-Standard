"""Round-14 closure pins for the three findings outstanding at PR #248 head 907901c."""
import copy
import unittest

import dacs5_reference as R
from test_round11_receipt_ingress_vectors import (
    CLAIM,
    FINALISED_AT,
    PUBKEYS,
    _anchor_deref,
    build_present,
)


def _replayable_present(job):
    p = build_present(job)
    entry = p["deriv"]["resolutionContext"][0]
    tag = {"bundle": p["W"]}
    for field in (
        "resolvedRole", "counterpartyDisposition", "counterpartyRef",
        "counterpartyRoleEvidence", "roleEvidence", "bb6Context",
    ):
        tag[field] = copy.deepcopy(entry[field])
    p["deriv"] = R.derive(
        CLAIM["seller"], [tag], FINALISED_AT - 1, FINALISED_AT + 1, "finalisedAt")
    return p


def _replayable_empty():
    return {
        "deriv": R.derive(
            CLAIM["seller"], [], FINALISED_AT - 1, FINALISED_AT + 1, "finalisedAt"),
        "deref": {},
        "anchors": {},
    }


def _validate(p):
    return R.validate_resolution_context(
        p["deriv"], lambda h: p["deref"].get(h), lambda _h: None, PUBKEYS,
        anchor_deref=lambda address: _anchor_deref(p, address))


def _replay(p):
    return R.replay_receipt(
        p["deriv"], lambda h: p["deref"].get(h), CLAIM["seller"],
        FINALISED_AT - 1, FINALISED_AT + 1, pubkeys=PUBKEYS,
        anchor_deref=lambda address: _anchor_deref(p, address))


def _standing_bundle(full):
    parties = [
        {"role": "buyer", "primaryClaim": CLAIM["buyer"]},
        {"role": "seller", "primaryClaim": CLAIM["seller"]},
    ]
    roles = ("buyer", "seller") if full else ("seller",)
    return {"parties": parties, "signatures": [{"party": CLAIM[r]} for r in roles]}


def _candidate(content_hash, native_address):
    return {
        "signer": CLAIM["seller"], "role": "seller",
        "bundleContentHash": content_hash, "nativeAddress": native_address,
    }


class Round14ReviewClosureTests(unittest.TestCase):
    def test_bundle_count_false_refuses_zero_bundle_receipt(self):
        p = _replayable_empty()
        p["deriv"]["bundleCount"] = False
        self.assertEqual(
            R.receipt_required_members_present(p["deriv"]),
            (False, ["bundleCount must be present and an integer"]))
        self.assertEqual(_replay(p), (False, None))

    def test_bundle_count_true_refuses_one_bundle_receipt(self):
        p = _replayable_present("R14-BUNDLE-COUNT-TRUE")
        self.assertEqual(p["deriv"]["bundleCount"], 1)
        p["deriv"]["bundleCount"] = True
        self.assertEqual(
            R.receipt_required_members_present(p["deriv"]),
            (False, ["bundleCount must be present and an integer"]))
        self.assertEqual(_replay(p), (False, None))

    def test_bundle_count_integer_zero_remains_valid(self):
        p = _replayable_empty()
        self.assertIs(type(p["deriv"]["bundleCount"]), int)
        self.assertEqual(p["deriv"]["bundleCount"], 0)
        self.assertEqual(R.receipt_required_members_present(p["deriv"]), (True, []))
        same, replayed = _replay(p)
        self.assertTrue(same)
        self.assertEqual(replayed["bundleCount"], 0)

    def test_bundle_count_integer_one_remains_valid(self):
        p = _replayable_present("R14-BUNDLE-COUNT-ONE")
        self.assertIs(type(p["deriv"]["bundleCount"]), int)
        self.assertEqual(p["deriv"]["bundleCount"], 1)
        self.assertEqual(R.receipt_required_members_present(p["deriv"]), (True, []))
        same, replayed = _replay(p)
        self.assertTrue(same)
        self.assertEqual(replayed["bundleCount"], 1)

    def test_replay_without_exact_anchor_resolver_fails_closed(self):
        p = _replayable_present("R14-ANCHOR-REQUIRED")
        ok, reasons = R.validate_resolution_context(
            p["deriv"], lambda h: p["deref"].get(h), lambda _h: None, PUBKEYS)
        self.assertFalse(ok)
        self.assertTrue(any("authoritative copy not dereferenceable" in reason for reason in reasons))
        self.assertEqual(
            R.replay_receipt(
                p["deriv"], lambda h: p["deref"].get(h), CLAIM["seller"],
                FINALISED_AT - 1, FINALISED_AT + 1, pubkeys=PUBKEYS),
            (False, None))

    def test_windowing_basis_containers_refuse_without_exception(self):
        base = _replayable_present("R14-WINDOW")
        for value in ([], {}):
            with self.subTest(value=value):
                p = copy.deepcopy(base)
                p["deriv"]["windowingBasis"] = value
                ok, reasons = R.receipt_required_members_present(p["deriv"])
                self.assertFalse(ok)
                self.assertTrue(reasons)
                self.assertEqual(_replay(p), (False, None))
                with self.assertRaisesRegex(ValueError, "windowingBasis must be one of"):
                    R.derive(CLAIM["seller"], [], 0, 1, value)

    def test_bb6_full_standing_form_is_independent_of_address_order(self):
        lesser_a = "stor-4"
        lesser_b = "stor-8"
        for full_a in ("stor-0", "stor-9"):
            with self.subTest(full_address=full_a):
                bindings = [
                    _candidate("a" * 64, lesser_a),
                    _candidate("a" * 64, full_a),
                    _candidate("b" * 64, lesser_b),
                ]
                anchored = {
                    lesser_a: _standing_bundle(False),
                    full_a: _standing_bundle(True),
                    lesser_b: _standing_bundle(False),
                }
                result = R.resolve_bb6(
                    bindings, {CLAIM["seller"]: "seller"}, anchored=anchored)
                self.assertEqual(result["disposition"], "present")
                self.assertEqual(result["resolvedNativeAddress"], full_a)

    def test_bb6_equal_form_reports_full_standing_copy(self):
        lesser = _candidate("a" * 64, "stor-0")
        full = _candidate("a" * 64, "stor-9")
        result = R.resolve_bb6(
            [lesser, full], {CLAIM["seller"]: "seller"},
            anchored={"stor-0": _standing_bundle(False), "stor-9": _standing_bundle(True)})
        self.assertEqual(result["disposition"], "present")
        self.assertEqual(result["resolvedNativeAddress"], "stor-9")

    def test_binding_counterparty_anchor_role_is_checked_on_full_replay(self):
        p = _replayable_present("R14-BINDING-ROLE")
        self.assertEqual(_validate(p), (True, []))
        self.assertTrue(_replay(p)[0])

        entry = p["deriv"]["resolutionContext"][0]
        cp_address = entry["counterpartyRoleEvidence"]["binding"]["nativeAddress"]
        original_hash = R.bundle_hash(p["anchors"][cp_address])
        p["anchors"][cp_address]["anchoredByRole"] = "seller"
        self.assertEqual(R.bundle_hash(p["anchors"][cp_address]), original_hash)

        ok, reasons = _validate(p)
        self.assertFalse(ok)
        self.assertTrue(any("anchoredByRole" in reason for reason in reasons))
        self.assertEqual(_replay(p), (False, None))

    def test_binding_counterparty_required_signatures_are_checked(self):
        p = _replayable_present("R14-BINDING-SIGS")
        entry = p["deriv"]["resolutionContext"][0]
        cp_address = entry["counterpartyRoleEvidence"]["binding"]["nativeAddress"]
        p["anchors"][cp_address]["signatures"] = [
            s for s in p["anchors"][cp_address]["signatures"] if s["party"] == CLAIM["seller"]]
        ok, reasons = _validate(p)
        self.assertFalse(ok)
        self.assertTrue(any("required signer" in reason for reason in reasons))

    def test_pure_mapping_evidence_binds_address_and_anchor_role(self):
        p = _replayable_present("R14-ADDRESS-ROLE")
        entry = p["deriv"]["resolutionContext"][0]
        seller_address = R.legacy_logical_address(p["W"]["jobId"], "seller")
        buyer_address = R.legacy_logical_address(p["W"]["jobId"], "buyer")
        entry["roleEvidence"] = {"kind": "address", "resolvedAddress": seller_address}
        entry["counterpartyRoleEvidence"] = {"kind": "address", "resolvedAddress": buyer_address}
        entry.pop("bb6Context")
        p["anchors"][seller_address] = p["W"]
        p["anchors"][buyer_address] = p["cp"]

        self.assertEqual(_validate(p), (True, []))
        self.assertTrue(_replay(p)[0])

        p["anchors"][buyer_address]["anchoredByRole"] = "seller"
        ok, reasons = _validate(p)
        self.assertFalse(ok)
        self.assertTrue(any("anchoredByRole" in reason for reason in reasons))
        self.assertEqual(_replay(p), (False, None))

    def test_pure_mapping_wrong_role_address_refuses(self):
        p = _replayable_present("R14-ADDRESS-MAP")
        entry = p["deriv"]["resolutionContext"][0]
        cp = entry["counterpartyRoleEvidence"]
        wrong = R.legacy_logical_address(p["W"]["jobId"], "seller")
        cp["kind"] = "address"
        cp.pop("binding")
        cp["resolvedAddress"] = wrong
        p["anchors"][wrong] = p["cp"]
        ok, reasons = _validate(p)
        self.assertFalse(ok)
        self.assertTrue(any("resolvedAddress" in reason for reason in reasons))

    def test_pure_mapping_uses_substrate_resolver_not_identity_assumption(self):
        p = _replayable_present("R14-CUSTOM-MAP")
        entry = p["deriv"]["resolutionContext"][0]

        def mapper(job_id, role):
            return "substrate-native:" + R.legacy_logical_address(job_id, role)

        seller_address = mapper(p["W"]["jobId"], "seller")
        buyer_address = mapper(p["W"]["jobId"], "buyer")
        entry["roleEvidence"] = {"kind": "address", "resolvedAddress": seller_address}
        entry["counterpartyRoleEvidence"] = {"kind": "address", "resolvedAddress": buyer_address}
        entry.pop("bb6Context")
        p["anchors"][seller_address] = p["W"]
        p["anchors"][buyer_address] = p["cp"]

        result = R.validate_resolution_context(
            p["deriv"], lambda h: p["deref"].get(h), lambda _h: None, PUBKEYS,
            anchor_deref=lambda address: _anchor_deref(p, address),
            pure_mapping_resolver=mapper)
        self.assertEqual(result, (True, []))


if __name__ == "__main__":
    unittest.main()
