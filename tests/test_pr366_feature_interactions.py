"""PR #366 feature-interaction regressions for the executable Vet reference.

Each test combines features that are otherwise covered one at a time:
production aggregation with an exact-claim ``primaryClaimSelector``,
SN-4 one-use admission across current and historical (non-authorizing)
aggregate use, and the verifier-owned fixture compatibility profile inside
production aggregation.  Every candidate is rebuilt with genuine public test
signatures, receipts and verifier-owned invocation/nonce bindings, so only
the property under test can decide.
"""

import copy
import json
import sys
import unittest
from pathlib import Path


TESTS = Path(__file__).resolve().parent
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import test_dacs1_vet_golden_inputs as vet  # noqa: E402


BASE_AGGREGATE = "vet-oneof-indeterminate-over-fail"
SELECTOR_EVIDENCE_CASE = "vet-ma3-verified-accept"
LEI_REF = "lei:984500ABCDEF12345678"
CCI_LEI_REF = "cci-lei:984500ABCDEF12345678"
PROFILE_ID = "fixture-cci-lei-distinct-scheme-v0.1"
PRESENTER_REF = vet.public_ref(vet.fixture_private_key("presenter"))
ISSUED_AT = 1_899_999_999_000
PASS = {"decision": "pass", "reasons": []}
INVALID = {"decision": "error", "reasons": ["aggregation authority invalid"]}
UNRELATED_REQUIREMENT = {
    "requirementVersion": "1",
    "required": [{"scheme": "lei", "verificationRequired": False}],
}


def case_evaluation(document, name, label="result"):
    case = next(item for item in document["cases"] if item["name"] == name)
    return case, case["evaluations"][label]


def derived_result(document, resolved, *, remove=(), **changes):
    """Re-sign one result with the genuine result authority and register it."""

    source = copy.deepcopy(resolved)
    for key in remove:
        source["artifact"].pop(key, None)
    source["artifact"].update(changes)
    replacement = vet.resign_result(
        source, vet.fixture_private_key("authority"), vet.AUTHORITY_REF
    )
    document["trustedContext"]["authenticatedResultArtifacts"].append({
        "ref": copy.deepcopy(replacement["ref"]),
        "serializedArtifactHash": replacement["serializedArtifactHash"],
    })
    return replacement


def rebuild_aggregate(
    document, evaluation, *, presented_by, claims, requirement, results, decision
):
    """Rebind a production aggregate to a new presentation and commitment set.

    The bundle, composite record and receipt are re-signed/re-anchored, and the
    verifier-owned invocation, bundle challenge and logical receipt address are
    moved to the presented party, so stale bindings cannot reject first.
    """

    changed = copy.deepcopy(evaluation)
    value = changed["input"]
    vet_input = value["authority"]["vetInput"]
    presenter = vet.fixture_private_key("presenter")
    bundle = copy.deepcopy(vet_input["bundleToVet"])
    bundle["presentedBy"] = presented_by
    bundle["claims"] = copy.deepcopy(claims)
    bundle = vet.resign_bundle(bundle, presenter, vet.public_ref(presenter))
    vet_input["bundleToVet"] = bundle
    vet_input["requirement"] = copy.deepcopy(requirement)

    record = value["record"]
    record["evaluatedParty"] = presented_by
    record["bundleHash"] = vet.hash_hex(
        {key: item for key, item in bundle.items() if key != "presentation"}
    )
    record["requirementHash"] = vet.hash_hex(requirement)
    record["freshness"] = []
    record["dealSpecific"] = [copy.deepcopy(item["ref"]) for item in results]
    record["overallDecision"] = decision
    value["resolvedResults"] = copy.deepcopy(results)

    context = document["trustedContext"]
    invocation = context["vetInvocations"][value["authority"]["invocation"]]
    invocation["evaluatedParty"] = presented_by
    invocation["primaryClaim"] = presented_by
    logical = vet.composite_logical_address(record["jobId"], presented_by)
    invocation["recordAnchorBinding"]["logicalAddress"] = logical
    context["authenticatedRecordReceipts"][invocation["recordReceiptId"]][
        "logicalAddress"
    ] = logical
    issuance = next(
        item for item in context["nonceIssuances"]
        if item["challengeId"] == invocation["challengeId"]
    )
    issuance["evaluatedParty"] = presented_by
    changed["input"] = vet.reanchor_composite_input(value, document)
    return changed


def at_trusted_now(document, evaluation, trusted_now):
    moved = copy.deepcopy(document)
    moved["trustedContext"]["vetInvocations"][
        evaluation["input"]["authority"]["invocation"]
    ]["trustedNow"] = trusted_now
    return moved


class Pr366VetInteractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = vet.load_raw_json(vet.FIXTURE.read_bytes())

    def _selector_aggregate(
        self, *, method_pinned=False, member_exclusion=None,
        commit_selector_evidence=True, decision="pass",
        omit_selector_valid_until=False, selector_valid_until=None,
        claim_expires_at=None,
    ):
        """A lei-presented production aggregate whose selector uses R1.

        R1 is the presented claim's own committed vLEI result with a holder
        binding to the presentation signer.  R2 is a refreshed lei proxy pass
        for the same identity that outlives R1.  With ``method_pinned`` the
        only verified member selects the proxy family, so R1 decides only the
        exact-claim selector/control gate.
        """

        document = copy.deepcopy(self.document)
        _, base = case_evaluation(document, BASE_AGGREGATE)
        _, direct = case_evaluation(document, SELECTOR_EVIDENCE_CASE)
        generated_at = base["input"]["record"]["generatedAt"]
        selector_evidence = copy.deepcopy(direct["input"]["resolvedResults"][0])
        if omit_selector_valid_until:
            selector_evidence = derived_result(
                document, selector_evidence, remove=("validUntil",)
            )
        elif selector_valid_until is not None:
            selector_evidence = derived_result(
                document, selector_evidence, validUntil=selector_valid_until
            )
        lei_result = next(
            item for item in base["input"]["resolvedResults"]
            if item["artifact"]["scheme"] == "lei"
        )
        exclusion = "method" if method_pinned else member_exclusion
        member = {"scheme": "lei", "verificationRequired": True}
        if exclusion == "explicit-version":
            recipe = copy.deepcopy(next(
                item for item in document["trustedContext"]["recipeRegistry"]["recipes"]
                if (item["scheme"], item["recipeVersion"])
                == ("lei", selector_evidence["artifact"]["recipeVersion"])
                and item["defaultMethod"]["kind"] == "verifiable-credential"
            ))
            recipe["recipeVersion"] = 3
            vet.resign_recipe(recipe)
            document["trustedContext"]["recipeRegistry"]["recipes"].append(recipe)
            vet.append_recipe_authorities(document["trustedContext"], recipe)
            original_selector = selector_evidence
            source = copy.deepcopy(next(
                item for item in document["trustedContext"][
                    "authenticatedSourceAttestations"
                ]
                if vet.canonical_bytes(item["attestation"])
                == vet.canonical_bytes(original_selector["artifact"]["attestation"])
            ))
            source["recipeVersion"] = 3
            source["attestation"]["anchor"]["locator"] += ":recipe-3"
            source["attestation"]["contentHash"] = vet.hash_hex({
                "fixture": "selector-explicit-version-exclusion",
                "recipeVersion": 3,
            })
            source["resolvedSourceHash"] = source["attestation"]["contentHash"]
            document["trustedContext"]["authenticatedSourceAttestations"].append(source)
            selector_evidence = derived_result(
                document, original_selector,
                recipeVersion=3,
                attestation=copy.deepcopy(source["attestation"]),
                reason="newer exact selector evidence excluded by the member pin",
            )
            refreshed = derived_result(
                document, original_selector,
                reason="explicit-version member control",
                validUntil=generated_at + 360_000,
            )
            member["recipeVersion"] = 2
        elif exclusion == "member-maxAge":
            selector_evidence = derived_result(
                document, selector_evidence,
                verifiedAt=generated_at - 2_000,
                validUntil=generated_at + 500,
            )
            refreshed = derived_result(
                document, selector_evidence,
                verifiedAt=generated_at,
                validUntil=generated_at + 360_000,
                reason="member maxAge control",
            )
            member["maxAge"] = 1
        else:
            refreshed = derived_result(
                document, lei_result,
                decision="pass",
                reason="refreshed proxy pass that outlives the selector evidence",
                validUntil=generated_at + 360_000,
            )
        if exclusion == "method":
            member["parameters"] = {"verificationMethod": "consensus-backed-proxy"}
        presented = {
            "ref": LEI_REF,
            "issuedAt": ISSUED_AT,
            "verifiedBy": copy.deepcopy(selector_evidence["ref"]),
        }
        if claim_expires_at is not None:
            presented["expiresAt"] = claim_expires_at
        evaluation = rebuild_aggregate(
            document,
            base,
            presented_by=LEI_REF,
            claims=[
                presented,
                {"ref": PRESENTER_REF, "issuedAt": ISSUED_AT},
            ],
            requirement={
                "requirementVersion": "1",
                "primaryClaimSelector": "lei",
                "required": [member],
            },
            results=(
                [selector_evidence, refreshed]
                if commit_selector_evidence else [refreshed]
            ),
            decision=decision,
        )
        # Keep both verifier-issued challenges inside their lifetime at every
        # trusted time below, so SN-4 expiry cannot be the rejecting check.
        invocation = document["trustedContext"]["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]
        for issuance in document["trustedContext"]["nonceIssuances"]:
            if issuance["challengeId"] in (
                invocation["challengeId"],
                invocation["verifierIdentityChallengeId"],
            ):
                issuance["expiresAt"] = generated_at + 360_000
        return evaluation, document, selector_evidence, refreshed

    def _key_presence_selector_aggregate(self, *, optional_result):
        """A key selector authorized by exact presence and signature control."""

        document = copy.deepcopy(self.document)
        _, base = case_evaluation(document, BASE_AGGREGATE)
        _, direct = case_evaluation(document, SELECTOR_EVIDENCE_CASE)
        generated_at = base["input"]["record"]["generatedAt"]
        optional = copy.deepcopy(direct["input"]["resolvedResults"][0])
        lei_result = next(
            item for item in base["input"]["resolvedResults"]
            if item["artifact"]["scheme"] == "lei"
        )
        refreshed = derived_result(
            document, lei_result,
            decision="pass",
            reason="current member evidence beside a key presence selector",
            validUntil=generated_at + 360_000,
        )
        key_claim = {"ref": PRESENTER_REF, "issuedAt": ISSUED_AT}
        results = [refreshed]
        if optional_result:
            # PCR-3: a well-shaped optional verifiedBy must not change exact
            # presence.  This committed result is intentionally outside the
            # proxy member and, after its expiry, remains irrelevant to key
            # signature control and the historical presence arm.
            key_claim["verifiedBy"] = copy.deepcopy(optional["ref"])
            results.insert(0, optional)
        evaluation = rebuild_aggregate(
            document,
            base,
            presented_by=PRESENTER_REF,
            claims=[
                key_claim,
                {
                    "ref": LEI_REF,
                    "issuedAt": ISSUED_AT,
                    "verifiedBy": copy.deepcopy(refreshed["ref"]),
                },
            ],
            requirement={
                "requirementVersion": "1",
                "primaryClaimSelector": "key",
                "required": [
                    {"scheme": "key", "verificationRequired": False},
                    {
                        "scheme": "lei",
                        "verificationRequired": True,
                        "parameters": {
                            "verificationMethod": "consensus-backed-proxy"
                        },
                    },
                ],
            },
            results=results,
            decision="pass",
        )
        invocation = document["trustedContext"]["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]
        for issuance in document["trustedContext"]["nonceIssuances"]:
            if issuance["challengeId"] in (
                invocation["challengeId"],
                invocation["verifierIdentityChallengeId"],
            ):
                issuance["expiresAt"] = generated_at + 360_000
        return evaluation, document, optional, refreshed

    @staticmethod
    def _without_selector(evaluation, document):
        changed = copy.deepcopy(evaluation)
        requirement = changed["input"]["authority"]["vetInput"]["requirement"]
        requirement.pop("primaryClaimSelector")
        changed["input"]["record"]["requirementHash"] = vet.hash_hex(requirement)
        changed["input"] = vet.reanchor_composite_input(changed["input"], document)
        return changed

    def test_production_selector_evidence_is_requalified_at_trusted_now(self):
        # DACS-2 §7.7.1: verifiedSelector needs the presented claim's own
        # record-committed passing-and-FRESH verifiedBy; production
        # authorization requalifies exact-owned evidence at trustedNow and
        # "the historical reconstruction alone MUST NOT authorize progression".
        # DACS-1 §6.3.2: a verifiedBy is stale when now > its effective expiry,
        # and a controlled presentedBy needs passing and fresh evidence.
        _, _, selector_evidence, refreshed = self._selector_aggregate(
            method_pinned=True
        )
        selector_expiry = selector_evidence["artifact"]["validUntil"]
        self.assertEqual("verifiable-credential", selector_evidence["artifact"]["method"])
        self.assertEqual(
            PRESENTER_REF,
            selector_evidence["artifact"]["data"]["holderBinding"]["controller"],
        )
        self.assertEqual("consensus-backed-proxy", refreshed["artifact"]["method"])
        self.assertGreater(refreshed["artifact"]["validUntil"], selector_expiry + 1)

        # R1 decides the selector: without its commitment the same signed
        # presentation fails the exact-claim gate while the member still passes.
        uncommitted, document, _, _ = self._selector_aggregate(
            method_pinned=True, commit_selector_evidence=False, decision="fail"
        )
        self.assertEqual(
            {"decision": "fail", "reasons": [
                "primaryClaimSelector is mismatched, uncontrolled, or unauthorized"
            ]},
            vet.execute_once(uncommitted, document),
        )

        # Unpinned control: R1 also participates for the member, so the
        # existing current requalification already refuses it after expiry.
        evaluation, document, _, _ = self._selector_aggregate(method_pinned=False)
        later = at_trusted_now(document, evaluation, selector_expiry + 1)
        self.assertEqual(
            PASS,
            vet.execute_once(
                evaluation, at_trusted_now(document, evaluation, selector_expiry)
            ),
        )
        self.assertEqual(PASS, vet.reconstruct_historical_once(evaluation, later))
        self.assertEqual(INVALID, vet.execute_once(evaluation, later))

        # Target: R1 is selector/control evidence only.  The inclusive boundary
        # and historical reconstruction still pass; current authorization after
        # R1 expires must not.  Reasons are advisory, so only the semantic
        # decision is pinned for the refusal.
        evaluation, document, _, _ = self._selector_aggregate(method_pinned=True)
        later = at_trusted_now(document, evaluation, selector_expiry + 1)
        raw = json.dumps(evaluation, separators=(",", ":")).encode("utf-8")
        self.assertEqual(
            PASS,
            vet.execute_once(
                evaluation, at_trusted_now(document, evaluation, selector_expiry)
            ),
        )
        self.assertEqual(PASS, vet.reconstruct_historical_once(evaluation, later))
        for label, outcome in (
            ("fixture helper", vet.execute_once(evaluation, later)),
            ("external JSON entry", vet.execute_external_once(raw, later)),
        ):
            with self.subTest(entry=label):
                self.assertEqual(
                    "error",
                    outcome["decision"],
                    f"current authorization accepted expired selector evidence: {outcome}",
                )

    def test_selector_evidence_is_current_when_members_exclude_by_version_or_max_age(self):
        # A selector result is member-independent.  Pinning another exact
        # recipe version or applying a tighter member maxAge can make that
        # result non-participating without exempting its own governing window
        # from production requalification.
        for exclusion in ("explicit-version", "member-maxAge"):
            with self.subTest(exclusion=exclusion):
                evaluation, document, selector_evidence, refreshed = (
                    self._selector_aggregate(member_exclusion=exclusion)
                )
                member = evaluation["input"]["authority"]["vetInput"][
                    "requirement"
                ]["required"][0]
                generated_at = evaluation["input"]["record"]["generatedAt"]
                selector = selector_evidence["artifact"]
                control = refreshed["artifact"]
                if exclusion == "explicit-version":
                    self.assertNotEqual(
                        selector["recipeVersion"], member["recipeVersion"]
                    )
                    self.assertEqual(
                        control["recipeVersion"], member["recipeVersion"]
                    )
                    self.assertEqual(selector["method"], control["method"])
                else:
                    max_age_ms = member["maxAge"] * 1_000
                    self.assertGreater(
                        generated_at, selector["verifiedAt"] + max_age_ms
                    )
                    self.assertLessEqual(
                        generated_at, control["verifiedAt"] + max_age_ms
                    )
                    self.assertEqual(
                        (selector["method"], selector["recipeVersion"]),
                        (control["method"], control["recipeVersion"]),
                    )
                expiry = selector["validUntil"]
                at_expiry = at_trusted_now(document, evaluation, expiry)
                after_expiry = at_trusted_now(document, evaluation, expiry + 1)
                self.assertEqual(PASS, vet.execute_once(evaluation, at_expiry))
                self.assertEqual(
                    PASS,
                    vet.reconstruct_historical_once(evaluation, after_expiry),
                )
                self.assertEqual(INVALID, vet.execute_once(evaluation, after_expiry))

    def test_selector_current_window_uses_claim_expiry_and_exact_recipe_default(self):
        _, base = case_evaluation(self.document, BASE_AGGREGATE)
        generated_at = base["input"]["record"]["generatedAt"]

        claim_expiry = generated_at + 500
        evaluation, document, selector_evidence, _ = self._selector_aggregate(
            method_pinned=True, claim_expires_at=claim_expiry
        )
        self.assertGreater(
            selector_evidence["artifact"]["validUntil"], claim_expiry
        )
        self.assertEqual(
            PASS,
            vet.execute_once(
                evaluation, at_trusted_now(document, evaluation, claim_expiry)
            ),
        )
        self.assertEqual(
            INVALID,
            vet.execute_once(
                evaluation, at_trusted_now(document, evaluation, claim_expiry + 1)
            ),
        )

        evaluation, document, selector_evidence, _ = self._selector_aggregate(
            method_pinned=True, omit_selector_valid_until=True
        )
        selector = selector_evidence["artifact"]
        self.assertNotIn("validUntil", selector)
        exact_recipe = next(
            item for item in document["trustedContext"]["recipeRegistry"]["recipes"]
            if (item["scheme"], item["recipeVersion"])
            == (selector["scheme"], selector["recipeVersion"])
            and item["defaultMethod"]["kind"] == selector["method"]
        )
        later_recipe = copy.deepcopy(exact_recipe)
        later_recipe["recipeVersion"] = 3
        later_recipe["defaultMaxAgeSec"] = exact_recipe["defaultMaxAgeSec"] * 2
        vet.resign_recipe(later_recipe)
        document["trustedContext"]["recipeRegistry"]["recipes"].append(later_recipe)
        vet.append_recipe_authorities(document["trustedContext"], later_recipe)
        exact_expiry = (
            selector["verifiedAt"] + exact_recipe["defaultMaxAgeSec"] * 1_000
        )
        self.assertEqual(
            PASS,
            vet.execute_once(
                evaluation, at_trusted_now(document, evaluation, exact_expiry)
            ),
        )
        after_expiry = at_trusted_now(document, evaluation, exact_expiry + 1)
        self.assertEqual(PASS, vet.reconstruct_historical_once(evaluation, after_expiry))
        self.assertEqual(INVALID, vet.execute_once(evaluation, after_expiry))

    def test_key_presence_selector_keeps_control_without_current_result_evidence(self):
        for optional_result in (False, True):
            with self.subTest(optional_stale_result=optional_result):
                evaluation, document, optional, refreshed = (
                    self._key_presence_selector_aggregate(
                        optional_result=optional_result
                    )
                )
                generated_at = evaluation["input"]["record"]["generatedAt"]
                invocation = document["trustedContext"]["vetInvocations"][
                    evaluation["input"]["authority"]["invocation"]
                ]
                trusted_now = (
                    optional["artifact"]["validUntil"] + 1
                    if optional_result else invocation["trustedNow"]
                )
                self.assertLessEqual(trusted_now, refreshed["artifact"]["validUntil"])
                current = at_trusted_now(document, evaluation, trusted_now)
                self.assertEqual(PASS, vet.reconstruct_historical_once(evaluation, current))
                self.assertEqual(PASS, vet.execute_once(evaluation, current))

    def test_non_key_presence_selector_requalifies_result_backed_control(self):
        document = copy.deepcopy(self.document)
        _, base = case_evaluation(document, BASE_AGGREGATE)
        _, direct = case_evaluation(document, SELECTOR_EVIDENCE_CASE)
        generated_at = base["input"]["record"]["generatedAt"]
        selector_evidence = copy.deepcopy(direct["input"]["resolvedResults"][0])
        requirement = {
            "requirementVersion": "1",
            "primaryClaimSelector": "lei",
            "required": [
                {"scheme": "lei", "verificationRequired": False}
            ],
            "oneOf": [[
                {
                    "scheme": "lei",
                    "verificationRequired": True,
                    "parameters": {
                        "verificationMethod": "consensus-backed-proxy"
                    },
                },
                {"scheme": "key", "verificationRequired": False},
            ]],
        }
        evaluation = rebuild_aggregate(
            document,
            base,
            presented_by=LEI_REF,
            claims=[
                {
                    "ref": LEI_REF,
                    "issuedAt": ISSUED_AT,
                    "verifiedBy": copy.deepcopy(selector_evidence["ref"]),
                },
                {"ref": PRESENTER_REF, "issuedAt": ISSUED_AT},
            ],
            requirement=requirement,
            results=[selector_evidence],
            decision="pass",
        )
        invocation = document["trustedContext"]["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]
        for issuance in document["trustedContext"]["nonceIssuances"]:
            if issuance["challengeId"] in (
                invocation["challengeId"],
                invocation["verifierIdentityChallengeId"],
            ):
                issuance["expiresAt"] = generated_at + 360_000
        expiry = selector_evidence["artifact"]["validUntil"]
        self.assertEqual(
            PASS,
            vet.execute_once(
                evaluation, at_trusted_now(document, evaluation, expiry)
            ),
        )
        later = at_trusted_now(document, evaluation, expiry + 1)
        self.assertEqual(PASS, vet.reconstruct_historical_once(evaluation, later))
        # Historical exact presence remains authorized, but an lei claim still
        # needs its independent holder-binding control result to be current.
        self.assertEqual(INVALID, vet.execute_once(evaluation, later))

    def test_existence_only_non_key_presence_remains_uncontrolled_failure(self):
        document = copy.deepcopy(self.document)
        _, base = case_evaluation(document, BASE_AGGREGATE)
        generated_at = base["input"]["record"]["generatedAt"]
        evaluation = rebuild_aggregate(
            document,
            base,
            presented_by=LEI_REF,
            claims=[
                {"ref": LEI_REF, "issuedAt": ISSUED_AT},
                {"ref": PRESENTER_REF, "issuedAt": ISSUED_AT},
            ],
            requirement={
                "requirementVersion": "1",
                "primaryClaimSelector": "lei",
                "required": [
                    {"scheme": "lei", "verificationRequired": False}
                ],
            },
            results=[],
            decision="fail",
        )
        invocation = document["trustedContext"]["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]
        for issuance in document["trustedContext"]["nonceIssuances"]:
            if issuance["challengeId"] in (
                invocation["challengeId"],
                invocation["verifierIdentityChallengeId"],
            ):
                issuance["expiresAt"] = generated_at + 10_000
        expected = {
            "decision": "fail",
            "reasons": [
                "primaryClaimSelector is mismatched, uncontrolled, or unauthorized"
            ],
        }
        self.assertEqual(expected, vet.execute_once(evaluation, document))
        later = at_trusted_now(
            document, evaluation, invocation["trustedNow"] + 1
        )
        self.assertEqual(expected, vet.reconstruct_historical_once(evaluation, later))
        # A historically unauthorized selector stays a signed evaluation fail;
        # the production-current guard must not promote it to authority error.
        self.assertEqual(expected, vet.execute_once(evaluation, later))

    def test_no_selector_still_requires_exact_presenter_control(self):
        document = copy.deepcopy(self.document)
        _, evaluation = case_evaluation(document, SELECTOR_EVIDENCE_CASE)
        evaluation = copy.deepcopy(evaluation)
        evaluation["input"]["requirement"].pop("primaryClaimSelector")
        self.assertIs(True, vet.execute_once(evaluation, document))

        unrelated = copy.deepcopy(self.document)
        _, candidate = case_evaluation(unrelated, SELECTOR_EVIDENCE_CASE)
        candidate = copy.deepcopy(candidate)
        candidate["input"]["requirement"].pop("primaryClaimSelector")
        candidate = vet.rebuild_direct_result(
            candidate,
            unrelated,
            lambda artifact: artifact["data"]["holderBinding"].update(
                controller=vet.public_ref(vet.fixture_private_key("bundle-cosigner"))
            ),
        )
        # The verification-required member still sees a genuine passing result;
        # only its unrelated holder binding fails exact presentedBy control.
        self.assertIs(False, vet.execute_once(candidate, unrelated))

        supporting_document = copy.deepcopy(self.document)
        supporting_case, supporting = case_evaluation(
            supporting_document,
            "vet-control-existence-only-lei-supporting-context",
        )
        self.assertEqual("pass", supporting_case["expectedOutput"])
        self.assertEqual("pass", vet.execute_once(supporting, supporting_document))

        uncontrolled_document = copy.deepcopy(self.document)
        _, uncontrolled = case_evaluation(
            uncontrolled_document,
            "vet-control-existence-only-lei-presentedby-reject",
        )
        uncontrolled = copy.deepcopy(uncontrolled)
        uncontrolled["input"]["requirement"].pop("primaryClaimSelector")
        self.assertEqual("fail", vet.execute_once(uncontrolled, uncontrolled_document))

    def test_no_selector_result_control_is_current_outside_member_predicates(self):
        for exclusion in ("method", "explicit-version", "member-maxAge"):
            with self.subTest(exclusion=exclusion):
                evaluation, document, control_result, member_result = (
                    self._selector_aggregate(
                        method_pinned=exclusion == "method",
                        member_exclusion=(
                            None if exclusion == "method" else exclusion
                        ),
                    )
                )
                evaluation = self._without_selector(evaluation, document)
                expiry = control_result["artifact"]["validUntil"]
                self.assertGreaterEqual(
                    member_result["artifact"]["validUntil"], expiry + 1
                )
                self.assertEqual(
                    PASS,
                    vet.execute_once(
                        evaluation, at_trusted_now(document, evaluation, expiry)
                    ),
                )
                later = at_trusted_now(document, evaluation, expiry + 1)
                self.assertEqual(
                    PASS, vet.reconstruct_historical_once(evaluation, later)
                )
                self.assertEqual(INVALID, vet.execute_once(evaluation, later))

        evaluation, document, control_result, _ = self._selector_aggregate(
            method_pinned=True, omit_selector_valid_until=True
        )
        evaluation = self._without_selector(evaluation, document)
        artifact = control_result["artifact"]
        exact_recipe = next(
            item for item in document["trustedContext"]["recipeRegistry"]["recipes"]
            if (item["scheme"], item["recipeVersion"])
            == (artifact["scheme"], artifact["recipeVersion"])
            and item["defaultMethod"]["kind"] == artifact["method"]
        )
        later_recipe = copy.deepcopy(exact_recipe)
        later_recipe["recipeVersion"] = 3
        later_recipe["defaultMaxAgeSec"] *= 2
        vet.resign_recipe(later_recipe)
        document["trustedContext"]["recipeRegistry"]["recipes"].append(later_recipe)
        vet.append_recipe_authorities(document["trustedContext"], later_recipe)
        exact_expiry = (
            artifact["verifiedAt"] + exact_recipe["defaultMaxAgeSec"] * 1_000
        )
        self.assertEqual(
            PASS,
            vet.execute_once(
                evaluation, at_trusted_now(document, evaluation, exact_expiry)
            ),
        )
        later = at_trusted_now(document, evaluation, exact_expiry + 1)
        self.assertEqual(PASS, vet.reconstruct_historical_once(evaluation, later))
        self.assertEqual(INVALID, vet.execute_once(evaluation, later))

    def test_historically_stale_no_selector_control_remains_semantic_failure(self):
        _, base = case_evaluation(self.document, BASE_AGGREGATE)
        generated_at = base["input"]["record"]["generatedAt"]
        evaluation, document, _, _ = self._selector_aggregate(
            method_pinned=True,
            selector_valid_until=generated_at - 1,
            decision="fail",
        )
        evaluation = self._without_selector(evaluation, document)
        expected = {
            "decision": "fail",
            "reasons": ["presentedBy is uncontrolled"],
        }
        self.assertEqual(expected, vet.reconstruct_historical_once(evaluation, document))
        self.assertEqual(expected, vet.execute_once(evaluation, document))

    def test_production_verifier_identity_requires_exact_expected_key_signature(self):
        document = copy.deepcopy(self.document)
        case, evaluation = case_evaluation(document, BASE_AGGREGATE)
        expected = case["expectedOutput"]
        invocation_id = evaluation["input"]["authority"]["invocation"]
        invocation = document["trustedContext"]["vetInvocations"][invocation_id]
        expected_ref = invocation["expectedVerifier"]
        verifier = vet.fixture_private_key("verifier")
        self.assertEqual(expected_ref, vet.public_ref(verifier))

        def signed_identity(source, key, signer_ref):
            changed = copy.deepcopy(source)
            identity = changed["input"]["authority"]["vetInput"][
                "verifierIdentity"
            ]
            if signer_ref not in {item["ref"] for item in identity["claims"]}:
                identity["claims"].append({"ref": signer_ref, "issuedAt": ISSUED_AT})
            changed["input"]["authority"]["vetInput"]["verifierIdentity"] = (
                vet.resign_bundle(identity, key, signer_ref)
            )
            return changed

        parameterized = expected_ref + "?role=verifier"
        parameterized_control = copy.deepcopy(evaluation)
        identity = parameterized_control["input"]["authority"]["vetInput"][
            "verifierIdentity"
        ]
        identity["claims"][0]["ref"] = parameterized
        parameterized_control = signed_identity(
            parameterized_control, verifier, parameterized
        )
        self.assertEqual(expected, vet.execute_once(parameterized_control, document))
        self.assertEqual(
            expected,
            vet.reconstruct_historical_once(parameterized_control, document),
        )

        cosigner = vet.fixture_private_key("bundle-cosigner")
        cosigner_ref = vet.public_ref(cosigner)
        cosigned_only = signed_identity(evaluation, cosigner, cosigner_ref)
        self.assertEqual(INVALID, vet.execute_once(cosigned_only, document))
        self.assertEqual(
            INVALID, vet.reconstruct_historical_once(cosigned_only, document)
        )

        delegated_document = copy.deepcopy(self.document)
        _, delegated = case_evaluation(delegated_document, BASE_AGGREGATE)
        delegated = copy.deepcopy(delegated)
        delegated_value = delegated["input"]
        delegated_invocation = delegated_document["trustedContext"][
            "vetInvocations"
        ][delegated_value["authority"]["invocation"]]
        phase_ref = delegated_invocation["phaseOrchestrator"]
        phase_key = vet.fixture_private_key("phase-orchestrator")
        self.assertEqual(phase_ref, vet.public_ref(phase_key))
        delegated_invocation["expectedVerifierRole"] = "orchestrator"
        delegated_invocation["expectedVerifier"] = phase_ref
        issuances = {
            item["challengeId"]: item
            for item in delegated_document["trustedContext"]["nonceIssuances"]
        }
        primary_issuance = issuances[delegated_invocation["challengeId"]]
        primary_issuance["expectedVerifier"] = phase_ref
        primary_issuance["issuedBy"] = phase_ref
        verifier_issuance = issuances[
            delegated_invocation["verifierIdentityChallengeId"]
        ]
        verifier_issuance["evaluatedParty"] = phase_ref
        verifier_identity = delegated_value["authority"]["vetInput"][
            "verifierIdentity"
        ]
        verifier_identity["presentedBy"] = phase_ref
        verifier_identity["claims"] = [{"ref": phase_ref, "issuedAt": ISSUED_AT}]
        delegated_value["authority"]["vetInput"]["verifierIdentity"] = (
            vet.resign_bundle(verifier_identity, phase_key, phase_ref)
        )
        delegated["input"] = vet.reanchor_composite_input(
            delegated_value,
            delegated_document,
            signer_name="phase-orchestrator",
        )
        self.assertEqual(expected, vet.execute_once(delegated, delegated_document))
        self.assertEqual(
            expected,
            vet.reconstruct_historical_once(delegated, delegated_document),
        )

        delegated_cosigned = signed_identity(
            delegated, cosigner, cosigner_ref
        )
        self.assertEqual(
            INVALID, vet.execute_once(delegated_cosigned, delegated_document)
        )
        self.assertEqual(
            INVALID,
            vet.reconstruct_historical_once(
                delegated_cosigned, delegated_document
            ),
        )

    def test_one_use_admission_spans_current_and_historical_aggregate_use(self):
        # CORE SN-4: an issued challenge authorizes at most one presentation
        # attempt and is consumed on attempt; DACS-1 §6.3.2: a later stage does
        # not re-accept the consumed nonce.  Non-authorizing reconstruction is
        # neither an exemption nor a probe that leaves the challenge reusable.
        case, evaluation = case_evaluation(self.document, BASE_AGGREGATE)
        expected = case["expectedOutput"]
        document = copy.deepcopy(self.document)
        context = document["trustedContext"]
        recipes = vet.authenticated_recipe_registry(document)
        result_context = vet.authenticated_result_context(document, recipes)
        invocation = context["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]
        challenges = (
            invocation["challengeId"], invocation["verifierIdentityChallengeId"]
        )

        def current(runtime):
            admitted, capability = runtime.admit_synthetic_test_input(evaluation)
            return vet.execute(admitted, document, runtime, capability)

        def historical(runtime):
            admitted, capability = runtime.admit_synthetic_test_input(evaluation)
            return vet.aggregate_output(
                admitted["input"], context, recipes, result_context, runtime,
                input_admission=runtime.derive_input(
                    admitted, capability, admitted["input"]
                ),
                authorize_current=False,
            )

        # Controls: each mode admits once through its own verifier runtime.
        self.assertEqual(expected, current(vet.VetReferenceRuntime(context)))
        self.assertEqual(expected, historical(vet.VetReferenceRuntime(context)))

        for first, second in ((current, historical), (historical, current)):
            with self.subTest(first=first.__name__, then=second.__name__):
                runtime = vet.VetReferenceRuntime(context)
                self.assertEqual(expected, first(runtime))
                for challenge in challenges:
                    self.assertTrue(runtime.nonce_ledger.consumed(challenge))
                self.assertEqual(INVALID, second(runtime))

        # The exact received bytes cannot be admitted twice by one verifier,
        # and a capability minted by another runtime cannot drive (or burn)
        # this runtime's issuer-owned ledger.
        raw = json.dumps(evaluation, separators=(",", ":")).encode("utf-8")
        runtime = vet.VetReferenceRuntime(context)
        admitted, capability = runtime.admit_external_input(raw)
        self.assertEqual(expected, vet.execute(admitted, document, runtime, capability))
        readmitted, recapability = runtime.admit_external_input(raw)
        self.assertEqual(
            INVALID, vet.execute(readmitted, document, runtime, recapability)
        )
        foreign, foreign_capability = vet.VetReferenceRuntime(
            context
        ).admit_external_input(raw)
        fresh = vet.VetReferenceRuntime(context)
        self.assertEqual(
            INVALID, vet.execute(foreign, document, fresh, foreign_capability)
        )
        for challenge in challenges:
            self.assertFalse(fresh.nonce_ledger.consumed(challenge))

    def _profile_aggregate(
        self, *, members, decision, cci_claim=True, profile_binding="bound"
    ):
        """A key-presented aggregate whose bundle may carry an exact cci-lei claim.

        ``profile_binding`` is ``"bound"`` (the verifier-owned invocation binds
        the fixture profile to this exact requirement), ``"other"`` (bound to a
        different requirement) or ``None`` (current-only closed registry).
        """

        document = copy.deepcopy(self.document)
        _, base = case_evaluation(document, BASE_AGGREGATE)
        lei_result = next(
            item for item in base["input"]["resolvedResults"]
            if item["artifact"]["scheme"] == "lei"
        )
        refreshed = derived_result(
            document, lei_result,
            decision="pass", reason="current pass beside a profile-only claim",
        )
        requirement = {"requirementVersion": "1", "required": copy.deepcopy(members)}
        claims = [
            {
                "ref": LEI_REF,
                "issuedAt": ISSUED_AT,
                "verifiedBy": copy.deepcopy(refreshed["ref"]),
            },
            {"ref": PRESENTER_REF, "issuedAt": ISSUED_AT},
        ]
        if cci_claim:
            claims.append({"ref": CCI_LEI_REF})
        evaluation = rebuild_aggregate(
            document,
            base,
            presented_by=PRESENTER_REF,
            claims=claims,
            requirement=requirement,
            results=[refreshed],
            decision=decision,
        )
        invocation = document["trustedContext"]["vetInvocations"][
            evaluation["input"]["authority"]["invocation"]
        ]
        self.assertIsNone(invocation["compatibilityProfile"])
        if profile_binding is not None:
            invocation["compatibilityProfile"] = PROFILE_ID
            invocation["compatibilityRequirementHash"] = vet.hash_hex(
                requirement if profile_binding == "bound" else UNRELATED_REQUIREMENT
            )
        return evaluation, document

    def test_bound_profile_admits_profile_only_presence_claims_in_production_aggregation(self):
        # The fixture-only profile admits cci-lei for exact-scheme presence
        # comparison under its verifier-bound requirement; the closed current
        # registry refuses the same signed bundle; and presence never becomes
        # verification, because no authenticated cci-lei recipe or result exists.
        self.assertEqual(
            ["cci-lei"],
            self.document["trustedContext"]["deferredSchemeCompatibilityProfiles"][
                PROFILE_ID
            ]["registeredSchemes"],
        )
        presence = {"scheme": "cci-lei", "verificationRequired": False}
        verified_lei = {"scheme": "lei", "verificationRequired": True, "recipeVersion": 1}
        absent = {"decision": "fail", "reasons": ["required failing or absent: cci-lei"]}

        evaluation, document = self._profile_aggregate(
            members=[presence, verified_lei], decision="pass"
        )
        raw = json.dumps(evaluation, separators=(",", ":")).encode("utf-8")
        self.assertEqual(PASS, vet.execute_once(evaluation, document))
        self.assertEqual(PASS, vet.reconstruct_historical_once(evaluation, document))
        self.assertEqual(PASS, vet.execute_external_once(raw, document))

        evaluation, document = self._profile_aggregate(
            members=[presence, verified_lei], cci_claim=False, decision="fail"
        )
        self.assertEqual(absent, vet.execute_once(evaluation, document))

        evaluation, document = self._profile_aggregate(
            members=[
                {"scheme": "cci-lei", "verificationRequired": True}, verified_lei,
            ],
            decision="fail",
        )
        self.assertEqual(absent, vet.execute_once(evaluation, document))

        evaluation, document = self._profile_aggregate(
            members=[presence, verified_lei], profile_binding=None, decision="pass"
        )
        self.assertEqual(INVALID, vet.execute_once(evaluation, document))

        evaluation, document = self._profile_aggregate(
            members=[presence, verified_lei], profile_binding="other",
            decision="error",
        )
        self.assertEqual(
            {"decision": "error", "reasons": [
                "requirement is not bound to the compatibility profile"
            ]},
            vet.execute_once(evaluation, document),
        )

    def test_closed_recipe_registry_refuses_a_signed_profile_only_scheme(self):
        # The compatibility profile widens only claim/requirement parsing.  A
        # steward-signed recipe is admitted for a registered scheme but refused
        # for cci-lei, so no authenticated cci-lei recipe family can exist.
        document = copy.deepcopy(self.document)
        base = next(
            recipe
            for recipe in document["trustedContext"]["recipeRegistry"]["recipes"]
            if (recipe["scheme"], recipe["recipeVersion"]) == ("lei", 1)
        )

        def with_recipe(scheme):
            changed = copy.deepcopy(document)
            recipe = copy.deepcopy(base)
            recipe.update(scheme=scheme, recipeVersion=2)
            vet.resign_recipe(recipe)
            changed["trustedContext"]["recipeRegistry"]["recipes"].append(recipe)
            return changed

        self.assertIsNotNone(vet.authenticated_recipe_registry(document))
        self.assertIsNotNone(vet.authenticated_recipe_registry(with_recipe("did")))
        self.assertIsNone(vet.authenticated_recipe_registry(with_recipe("cci-lei")))


if __name__ == "__main__":
    unittest.main()
