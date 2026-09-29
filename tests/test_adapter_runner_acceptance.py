import copy
import unittest

from scripts.validate_adapter_runner_acceptance import PACKET, PacketError, load, validate


class AdapterRunnerAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = load(PACKET)

    def assert_rejected(self, mutator, message):
        changed = copy.deepcopy(self.packet)
        mutator(changed)
        with self.assertRaisesRegex(PacketError, message):
            validate(changed)

    def test_committed_positive_report(self):
        validate(self.packet)

    def test_case_completeness_is_fail_closed(self):
        self.assert_rejected(lambda value: value["observed"]["matrix"].pop(), "20 cases")

    def test_false_independence_is_rejected(self):
        self.assert_rejected(
            lambda value: value["observed"]["matrix"][0].__setitem__("independentImplementations", 2),
            "false independence",
        )

    def test_unsupported_case_cannot_be_scored(self):
        def mutate(value):
            row = next(item for item in value["observed"]["matrix"] if item["id"] == "bigint-native-type")
            row.update(status="SELF-CHECK", participatingAdapters=2, independentImplementations=1)
        self.assert_rejected(mutate, "must fully ABSTAIN")

    def test_unsupported_evidence_binds_two_runs_with_null_outcomes(self):
        def mutate(value):
            row = next(item for item in value["observed"]["matrix"] if item["id"] == "bigint-native-type")
            row["adapters"][1]["runId"] = "run-0"
            row["adapters"][1]["outcome"] = "THROWN"
        self.assert_rejected(mutate, "unsupported evidence|runner identities")

    def test_in_profile_mismatch_must_be_false(self):
        def mutate(value):
            row = next(item for item in value["observed"]["matrix"]
                       if item["id"] == "signing::reject-mismatched-ascii-hex-hash")
            row["adapters"][0]["outcome"] = "true"
        self.assert_rejected(mutate, "observed outcome differs from expected")

    def test_matching_label_cannot_hide_wrong_normal_outcome(self):
        def mutate(value):
            row = next(item for item in value["observed"]["matrix"] if item["id"] == "fraction-one-half")
            row["adapters"][0]["outcome"] = '{"hex":"00"}'
        self.assert_rejected(mutate, "observed outcome differs from expected")

    def test_operation_label_is_bound_to_frozen_descriptor(self):
        self.assert_rejected(
            lambda value: value["observed"]["matrix"][0].__setitem__("operation", "signedScopeHash"),
            "wrong operation mapping",
        )

    def test_expected_value_is_bound_to_frozen_descriptor(self):
        def mutate(value):
            row = next(item for item in value["observed"]["matrix"] if item["id"] == "canonical-base64url-unpadded")
            row["expected"] = row["adapters"][0]["outcome"] = row["adapters"][1]["outcome"] = '"REJECT"'
        self.assert_rejected(mutate, "expected value differs from frozen descriptor")

    def test_runner_patch_and_sources_are_pinned(self):
        self.assert_rejected(
            lambda value: value["coordinates"]["runner"].__setitem__("patchSha256", "0" * 64),
            "wrong runner patch",
        )
        self.assert_rejected(
            lambda value: value["coordinates"]["runner"]["sourceSha256"].popitem(),
            "source pins differ from reviewed bytes",
        )
        self.assert_rejected(
            lambda value: value["coordinates"]["runner"]["sourceSha256"].__setitem__(
                "conformance/shared-suite/adapter-contract.mjs", "0" * 64),
            "source pins differ from reviewed bytes",
        )

    def test_launch_and_protocol_failures_cannot_abstain(self):
        self.assert_rejected(
            lambda value: value["controls"].__setitem__("exportedMalformedProtocolProbe", "ABSTAIN"),
            "must be ERROR",
        )

    def test_mismatch_control_must_equal_matrix_evidence(self):
        self.assert_rejected(
            lambda value: value["controls"]["inProfileCryptoMismatch"].__setitem__("observed", [True, True]),
            "mismatch control contradicts",
        )

    def test_runner_issue_comment_is_exact(self):
        self.assert_rejected(
            lambda value: value["coordinates"]["runner"].__setitem__("issueComment", "https://example.invalid/comment"),
            "wrong runner issue comment",
        )

    def test_metadata_mapping_is_bound_to_descriptor(self):
        self.assert_rejected(
            lambda value: value["adapter"]["wrappedStandard"].__setitem__("revision", "0" * 40),
            "wrapped revision differs",
        )


if __name__ == "__main__":
    unittest.main()
