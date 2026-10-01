import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import validate_adapter_runner_acceptance as acceptance
from scripts.validate_adapter_runner_acceptance import PACKET, PacketError, load, validate


ROOT = Path(__file__).resolve().parents[1]
FROZEN_DESCRIPTOR = (
    ROOT / "conformance/interop/frozen/dacs-adapter-release-proposal-c799-v1.json"
)
CURRENT_DESCRIPTOR = ROOT / "conformance/interop/dacs-adapter-release-proposal-v1.json"
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

    def test_historical_descriptor_is_frozen_separately_from_current_release(self):
        self.assertEqual(
            hashlib.sha256(FROZEN_DESCRIPTOR.read_bytes()).hexdigest(),
            "723d344e1487361c699cd0750a8567d7e2021cbbcbc1ff90efa39e8a423fecca",
        )
        self.assertNotEqual(
            CURRENT_DESCRIPTOR.read_bytes(), FROZEN_DESCRIPTOR.read_bytes()
        )

    def test_historical_descriptor_ignores_current_checkout_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "checkout"
            subprocess.run(
                ["git", "clone", "--shared", "--no-checkout",
                 str(acceptance.ROOT), str(root)],
                check=True, capture_output=True,
            )
            descriptor = root / acceptance.DESCRIPTOR_PATH
            descriptor.parent.mkdir(parents=True)
            descriptor.write_bytes(b'{"unrelatedCurrentDescriptor":true}\n')
            with patch.object(acceptance, "ROOT", root):
                validate(self.packet)

    def test_unavailable_historical_descriptor_is_a_controlled_cli_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(
                ["git", "init", str(root)], check=True, capture_output=True,
            )
            validator = root / "scripts" / VALIDATOR.name
            validator.parent.mkdir()
            shutil.copyfile(VALIDATOR, validator)
            packet = root / "packet.json"
            packet.write_text(json.dumps(self.packet), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(validator), str(packet)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(1, completed.returncode)
            self.assertIn("frozen descriptor is unavailable", completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)
            self.assertNotIn("adapter runner acceptance: PASS", completed.stdout)

    def test_historical_descriptor_read_checks_digest_and_tool_failures(self):
        with patch.object(acceptance.subprocess, "run", return_value=
                          subprocess.CompletedProcess([], 0, b"{}", b"")):
            with self.assertRaisesRegex(PacketError, "descriptor digest changed"):
                validate(self.packet)
        for error in (FileNotFoundError("git"),
                      subprocess.TimeoutExpired("git", 10)):
            with self.subTest(error=type(error).__name__):
                with patch.object(acceptance.subprocess, "run", side_effect=error):
                    with self.assertRaisesRegex(PacketError, "cannot read frozen descriptor"):
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

    def test_complete_adapter_metadata_is_bound_to_frozen_contract(self):
        mutations = (
            ("name", lambda value: value["adapter"].__setitem__("name", "other-adapter")),
            ("version", lambda value: value["adapter"].__setitem__("version", "2.0")),
            ("observed origin", lambda value: value["adapter"].__setitem__(
                "observedOrigin", "https://example.invalid/repo.git")),
            ("supported families", lambda value: value["adapter"][
                "supportedFamilies"].append("unsupported-family")),
            ("operations", lambda value: value["adapter"]["operations"].append(
                "verifyBundle")),
            ("bounded profile", lambda value: value["adapter"][
                "boundedOperationProfiles"].__setitem__("domainSepVerify", "generic")),
            ("limitations", lambda value: value["adapter"]["limitations"].pop()),
            ("extra member", lambda value: value["adapter"].__setitem__(
                "unreviewed", True)),
            ("missing member", lambda value: value["adapter"].pop("version")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                self.assert_rejected(
                    mutate,
                    "adapter identity differs from packet metadata" if label == "name"
                    else "adapter metadata differs from frozen descriptor and contract",
                )

    def test_packet_limitations_and_claim_fields_are_exact(self):
        mutations = (
            ("missing limitations", lambda value: value.__setitem__("limitations", []),
             "packet limitations differ"),
            ("false limitation", lambda value: value.__setitem__(
                "limitations", ["Independent interoperability established."]),
             "packet limitations differ"),
            ("top-level certification", lambda value: value.__setitem__(
                "certifiedIndependentInterop", True), "packet has missing or unrecognized members"),
            ("summary certification", lambda value: value["observed"]["summary"].__setitem__(
                "CERTIFIED", 20), "observed.summary has missing or unrecognized members"),
            ("row certification", lambda value: value["observed"]["matrix"][0].__setitem__(
                "certified", True), "observed row has missing or unrecognized members"),
            ("run certification", lambda value: value["observed"]["matrix"][0][
                "adapters"][0].__setitem__("certified", True),
             "adapter row has missing or unrecognized members"),
            ("coordinates certification", lambda value: value["coordinates"].__setitem__(
                "certified", True), "coordinates has missing or unrecognized members"),
            ("standard certification", lambda value: value["coordinates"]["standard"].__setitem__(
                "certified", True), "coordinates.standard has missing or unrecognized members"),
            ("runner certification", lambda value: value["coordinates"]["runner"].__setitem__(
                "certified", True), "coordinates.runner has missing or unrecognized members"),
            ("observed certification", lambda value: value["observed"].__setitem__(
                "certified", True), "observed has missing or unrecognized members"),
            ("control certification", lambda value: value["controls"].__setitem__(
                "certified", True), "controls has missing or unrecognized members"),
            ("execution certification", lambda value: value["execution"].__setitem__(
                "certified", True), "execution has missing or unrecognized members"),
            ("focused certification", lambda value: value["execution"][
                "contributorFocusedSuite"].__setitem__("certified", True),
             "execution.contributorFocusedSuite has missing or unrecognized members"),
            ("abstain-row certification", lambda value: next(
                row for row in value["observed"]["matrix"]
                if row["id"] == "bigint-native-type").__setitem__("certified", True),
             "observed row has missing or unrecognized members"),
        )
        for label, mutate, message in mutations:
            with self.subTest(label=label):
                self.assert_rejected(mutate, message)

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
