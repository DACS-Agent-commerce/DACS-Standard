import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.validate_adapter_runner_acceptance import PACKET, PacketError, load, validate


VALIDATOR = PACKET.parents[2] / "scripts" / "validate_adapter_runner_acceptance.py"


class AdapterRunnerAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet = load(PACKET)

    def assert_rejected(self, mutator, message):
        changed = copy.deepcopy(self.packet)
        mutator(changed)
        with self.assertRaisesRegex(PacketError, message):
            validate(changed)

    def run_cli(self, packet=None):
        if packet is None:
            return subprocess.run(
                [sys.executable, str(VALIDATOR)],
                text=True,
                capture_output=True,
                check=False,
            )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packet.json"
            path.write_text(json.dumps(packet), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(VALIDATOR), str(path)],
                text=True,
                capture_output=True,
                check=False,
            )

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

    def test_complete_wrapped_standard_metadata_is_bound_to_descriptor(self):
        mutations = (
            (
                "tree",
                lambda value: value["adapter"]["wrappedStandard"].__setitem__(
                    "tree", "0" * 40
                ),
            ),
            (
                "primitive digest",
                lambda value: value["adapter"]["wrappedStandard"][
                    "primitiveSha256"
                ].__setitem__("scripts/jcs.py", "0" * 64),
            ),
            (
                "missing primitive",
                lambda value: value["adapter"]["wrappedStandard"][
                    "primitiveSha256"
                ].pop("scripts/jcs.py"),
            ),
            (
                "extra primitive",
                lambda value: value["adapter"]["wrappedStandard"][
                    "primitiveSha256"
                ].__setitem__("scripts/extra.py", "0" * 64),
            ),
            (
                "extra wrapped member",
                lambda value: value["adapter"]["wrappedStandard"].__setitem__(
                    "unreviewed", True
                ),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                self.assert_rejected(mutate, "wrapped Standard metadata")

    def test_malformed_packet_sections_are_controlled_packet_errors(self):
        mutations = (
            ("coordinates", lambda value: value.__setitem__("coordinates", None)),
            (
                "standard",
                lambda value: value["coordinates"].__setitem__("standard", []),
            ),
            (
                "runner sources",
                lambda value: value["coordinates"]["runner"].__setitem__(
                    "sourceSha256", None
                ),
            ),
            ("expected", lambda value: value.__setitem__("expected", [])),
            ("observed", lambda value: value.__setitem__("observed", [])),
            (
                "matrix",
                lambda value: value["observed"].__setitem__("matrix", {}),
            ),
            (
                "matrix row",
                lambda value: value["observed"]["matrix"].__setitem__(0, []),
            ),
            (
                "non-hashable case id",
                lambda value: value["observed"]["matrix"][0].__setitem__("id", []),
            ),
            (
                "row adapters",
                lambda value: value["observed"]["matrix"][0].__setitem__(
                    "adapters", None
                ),
            ),
            (
                "adapter row",
                lambda value: value["observed"]["matrix"][0]["adapters"].__setitem__(
                    0, []
                ),
            ),
            ("controls", lambda value: value.__setitem__("controls", [])),
            ("execution", lambda value: value.__setitem__("execution", [])),
            (
                "focused suite",
                lambda value: value["execution"].__setitem__(
                    "contributorFocusedSuite", None
                ),
            ),
            ("runtime", lambda value: value.__setitem__("runtime", [])),
            (
                "python runtime",
                lambda value: value["runtime"].__setitem__("python", []),
            ),
            ("adapter", lambda value: value.__setitem__("adapter", [])),
            (
                "wrapped metadata",
                lambda value: value["adapter"].__setitem__("wrappedStandard", []),
            ),
            (
                "primitive metadata",
                lambda value: value["adapter"]["wrappedStandard"].__setitem__(
                    "primitiveSha256", []
                ),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                changed = copy.deepcopy(self.packet)
                mutate(changed)
                with self.assertRaises(PacketError):
                    validate(changed)

    def test_cli_reports_controlled_failures_without_tracebacks(self):
        positive = self.run_cli()
        self.assertEqual(0, positive.returncode)
        self.assertIn("adapter runner acceptance: PASS", positive.stdout)
        self.assertNotIn("Traceback", positive.stderr)

        mutations = (
            lambda value: value.__setitem__("coordinates", None),
            lambda value: value["observed"]["matrix"][0].__setitem__("id", []),
            lambda value: value["execution"].__setitem__(
                "contributorFocusedSuite", None
            ),
            lambda value: value["adapter"]["wrappedStandard"].__setitem__(
                "primitiveSha256", None
            ),
        )
        for mutate in mutations:
            changed = copy.deepcopy(self.packet)
            mutate(changed)
            completed = self.run_cli(changed)
            self.assertEqual(1, completed.returncode)
            self.assertIn("adapter runner acceptance: FAIL:", completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)
            self.assertNotIn("adapter runner acceptance: PASS", completed.stdout)


if __name__ == "__main__":
    unittest.main()
