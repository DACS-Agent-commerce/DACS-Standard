"""DACS-4 §9.5.9 DEM-1/DEM-6 and DEM-7 crash-restart witness.

A storage-backed reference payer handler and payee
(`pay_dem_reference_handler`) take every state input of the corpus oracle's
decisions from what they read back from storage. Each scenario runs one
process per start: the first start is stopped (`os._exit`) on one side of a
transition, then the handler or payee restarts from its storage. The
invariants are what DEM-1, DEM-6 and DEM-7 promise across a crash. Each
mutant, a handler or payee that keeps its state in process memory, journals
late, trusts its saved progress, skips fsync or writes its index without a
conditional write, must break one of them.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import pay_dem_reference_handler as reference  # noqa: E402

generator = reference.generator
SCRIPT = HERE / "pay_dem_reference_handler.py"
PAYER_POINTS = (
    "before-retain", "after-retain", "before-confirm", "after-confirm", "after-confirm-journal",
    "before-broadcast", "after-broadcast", "after-broadcast-journal",
)
PAYEE_POINTS = ("before-admission-write", "after-admission-write", "after-delivery")
JOURNAL = reference.journal_name(generator.JOB_ID, generator.PHASE_INDEX)


def run(command: str, work: Path, boot: str, *options: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), command, "--work", str(work), "--boot", boot, *options],
        capture_output=True, text=True, timeout=120, check=False,
    )


def _options(crash: str | None = None, mutant: str | None = None, *extra: str) -> list[str]:
    return [*(["--crash", crash] if crash else []), *(["--mutant", mutant] if mutant else []), *extra]


def payer_violations(root: Path, mutant: str | None = None, *node: str) -> list[str]:
    """Stop the payer at each point, restart it twice, and check DEM-1/DEM-6."""
    violations = []
    signed = generator.signed()
    for point in PAYER_POINTS:
        work = root / point
        first = run("pay", work, "boot-1", *_options(point, mutant, *node))
        if first.returncode not in (0, reference.CRASH_EXIT):
            violations.append(f"{point}: first start failed: {first.stderr[-400:]}")
            continue
        retained_at_restart = (work / "store" / JOURNAL).exists()
        sent_before_restart = bool(reference.read_lines(work / "egress.jsonl"))
        results = []
        for boot in ("boot-2", "boot-3"):
            again = run("pay", work, boot, *_options(None, mutant, *node))
            if again.returncode != 0:
                violations.append(f"{point}: {boot} failed: {again.stderr[-400:]}")
                break
            results.append(json.loads(again.stdout))
        egress = reference.read_lines(work / "egress.jsonl")
        calls = [entry["call"] for entry in egress]
        if calls.count("confirm") > 1 or calls.count("broadcast") > 1:
            violations.append(f"{point}: second signed effect {calls}")
        after_restart = [entry for entry in egress if entry["boot"] != "boot-1"]
        if after_restart and (retained_at_restart or sent_before_restart):
            violations.append(f"{point}: egress after restart {[entry['call'] for entry in after_restart]}")
        for entry in egress:
            if not entry["retainedAtEgress"] or not reference.same_signed_bytes(signed, entry["transaction"]):
                violations.append(f"{point}: {entry['call']} carried bytes not retained on storage first")
        for result in results:
            if egress and result.get("errorClass") in {"permanent", "transient"}:
                violations.append(f"{point}: {result['errorClass']} after the bytes left")
            if result.get("ok") and "broadcast" not in calls:
                violations.append(f"{point}: success without an executed transfer")
            if result.get("broadcastPermitted") or result.get("replacementPermitted"):
                violations.append(f"{point}: result permits another egress")
    return violations


def fsync_violations(root: Path, mutant: str | None = None) -> list[str]:
    """The journal reaches stable storage, its file and then its directory
    flushed after the rename, before the first egress."""
    events: list[tuple[str, tuple[int, int]]] = []
    real_fsync = os.fsync

    def fsync(fd):
        status = os.fstat(fd)
        events.append(("fsync", (status.st_dev, status.st_ino)))
        return real_fsync(fd)

    handler = reference.payer(root, "boot-1", mutant=mutant)
    store = root / "store"
    journal = store / JOURNAL

    def egress(call):
        status = os.stat(journal) if journal.exists() else None
        events.append(("egress:" + call, (status.st_dev, status.st_ino) if status else (0, 0)))

    handler.node.observer = egress
    with mock.patch.object(reference.os, "fsync", fsync):
        handler.pay(generator.signed())
    first = next((i for i, (kind, _) in enumerate(events) if kind.startswith("egress:")), None)
    if first is None:
        return ["no egress"]
    directory = os.stat(store)
    journal_id = events[first][1]
    before = [identity for kind, identity in events[:first] if kind == "fsync"]
    violations = []
    if journal_id not in before:
        violations.append("journal file not fsynced before the first egress")
    directory_id = (directory.st_dev, directory.st_ino)
    if directory_id not in before or (journal_id in before and before.index(directory_id) < before.index(journal_id)):
        violations.append("journal directory not fsynced after the rename, before the first egress")
    return violations


def cross_phase_violations(root: Path, mutant: str | None = None) -> list[str]:
    """DEM-1: a hash retained for one phase never leaves for another, read
    from the stored journals, also after a restart."""
    violations = []
    for boot, job in (("boot-1", generator.JOB_ID), ("boot-2", generator.OTHER_JOB_ID),
                      ("boot-3", generator.OTHER_JOB_ID)):
        result = run("pay", root, boot, "--job", job, *_options(None, mutant))
        if result.returncode != 0:
            violations.append(f"{boot}: failed: {result.stderr[-400:]}")
    calls = [(entry["call"], entry["boot"]) for entry in reference.read_lines(root / "egress.jsonl")]
    if calls != [("confirm", "boot-1"), ("broadcast", "boot-1")]:
        violations.append(f"one hash sent for two phases: {calls}")
    return violations


def payee_violations(root: Path, mutant: str | None = None) -> list[str]:
    """Stop the payee at each point, restart it, show it the same transfer
    for another job, then for its own again: at most one (jobId,
    phaseIndex) ever receives delivery against the hash, and every delivered
    tuple is in the durable index."""
    violations = []
    for point in PAYEE_POINTS:
        work = root / point
        steps = (("boot-1", generator.JOB_ID, point), ("boot-2", generator.OTHER_JOB_ID, None),
                 ("boot-3", generator.JOB_ID, None))
        for boot, job, crash in steps:
            result = run("deliver", work, boot, "--job", job, *_options(crash, mutant))
            if result.returncode not in (0, reference.CRASH_EXIT):
                violations.append(f"{point}: {boot} failed: {result.stderr[-400:]}")
        delivered = {(entry["jobId"], entry["phaseIndex"]) for entry in reference.read_lines(work / "deliveries.jsonl")}
        if len(delivered) > 1:
            violations.append(f"{point}: one hash delivered for {sorted(delivered)}")
        index = reference.Store(work / "payee-store").read(reference.INDEX) or {"admissions": []}
        indexed = {(admission["jobId"], admission["phaseIndex"]) for admission in index["admissions"]}
        if not delivered <= indexed:
            violations.append(f"{point}: delivered {sorted(delivered - indexed)} without a durable admission")
    return violations


def concurrent_violations(root: Path, mutant: str | None = None) -> list[str]:
    """Two checks for different jobs read the same index snapshot; the
    second write must not succeed on that stale snapshot."""
    first = reference.payee(root, "boot-1", mutant=mutant)
    second = reference.payee(root, "boot-1", mutant=mutant)
    verdicts = {}

    def interleave():
        verdicts["other"] = second.deliver(generator.OTHER_JOB_ID)

    verdicts["own"] = first.deliver(generator.JOB_ID, between=interleave)
    delivered = [verdict for verdict in verdicts.values() if verdict == "pass"]
    return [] if len(delivered) <= 1 else [f"both checks delivered: {verdicts}"]


class PayDemCrashRestartTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_reference_handler_sends_nothing_after_a_restart_at_any_point(self):
        self.assertEqual([], payer_violations(self.root / "reference"))
        # A node that relayed the confirm executes the transfer: the restarted
        # handler settles it by re-reading the retained hash, sending nothing.
        work = self.root / "relayed"
        self.assertEqual(reference.CRASH_EXIT,
                         run("pay", work, "boot-1", "--crash", "after-confirm", "--relays-confirm").returncode)
        resumed = run("pay", work, "boot-2", "--relays-confirm")
        self.assertEqual(0, resumed.returncode, resumed.stderr)
        self.assertEqual("pass", json.loads(resumed.stdout)["expected"])
        self.assertEqual(["boot-1"], [entry["boot"] for entry in reference.read_lines(work / "egress.jsonl")])

    def test_reference_handler_completes_an_uninterrupted_payment(self):
        work = self.root / "clean"
        done = run("pay", work, "boot-1")
        self.assertEqual(0, done.returncode, done.stderr)
        self.assertEqual("pass", json.loads(done.stdout)["expected"])
        self.assertEqual(["confirm", "broadcast"],
                         [entry["call"] for entry in reference.read_lines(work / "egress.jsonl")])

    def test_own_call_outcomes_classify_from_the_stored_journal(self):
        """F1 end to end: a refused or failed call after the bytes left is
        substrate and a restart sends nothing, only re-reads; a short balance
        found before any egress is permanent and nothing leaves. A broadcast
        that failed in transport can still execute, which the re-read finds:
        a permanent result there would have recorded a paid phase as failed."""
        for name, options, cause, first_class, then_class, calls in (
            ("confirm-insufficient-balance", ("--confirm", "insufficient-balance"),
             "confirm:insufficient-balance", "substrate", "substrate", ["confirm"]),
            ("confirm-transport-error", ("--confirm", "transport-error"),
             "confirm:transport-error", "substrate", "substrate", ["confirm"]),
            ("confirm-timeout", ("--confirm", "timeout"), "confirm:timeout", "substrate", "substrate", ["confirm"]),
            ("broadcast-transport-error", ("--broadcast", "transport-error"),
             "broadcast:transport-error", "substrate", None, ["confirm", "broadcast"]),
            ("broadcast-not-valid", ("--broadcast", "refused-not-valid"),
             "broadcast:refused-not-valid", "substrate", "substrate", ["confirm", "broadcast"]),
            ("balance-before-egress", ("--balance", "insufficient"),
             "pre-egress-check:insufficient-balance", "permanent", "permanent", []),
        ):
            with self.subTest(name=name):
                work = self.root / name
                first = run("pay", work, "boot-1", *options)
                self.assertEqual(0, first.returncode, first.stderr)
                result = json.loads(first.stdout)
                self.assertEqual((first_class, cause), (result["errorClass"], result["cause"]))
                self.assertFalse(result["broadcastPermitted"])
                again = run("pay", work, "boot-2", *options)
                self.assertEqual(0, again.returncode, again.stderr)
                self.assertEqual(then_class, json.loads(again.stdout)["errorClass"])
                self.assertEqual(calls, [entry["call"] for entry in reference.read_lines(work / "egress.jsonl")])

    def test_a_hash_retained_for_one_phase_never_leaves_for_another(self):
        self.assertEqual([], cross_phase_violations(self.root / "reference"))
        self.assertTrue(cross_phase_violations(self.root / "no-cross-phase-index", "no-cross-phase-index"))

    def test_journal_is_on_stable_storage_before_the_first_egress(self):
        self.assertEqual([], fsync_violations(self.root / "reference"))
        self.assertTrue(fsync_violations(self.root / "no-fsync", "no-fsync"))

    def test_every_wrong_payer_handler_is_caught(self):
        for mutant in ("process-local-journal", "journal-after-confirm", "restart-from-progress"):
            with self.subTest(mutant=mutant):
                self.assertTrue(payer_violations(self.root / mutant, mutant))

    def test_payee_never_delivers_a_reused_hash_across_a_restart(self):
        self.assertEqual([], payee_violations(self.root / "reference"))
        self.assertTrue(payee_violations(self.root / "process-local-index", "process-local-index"))

    def test_payee_admission_write_is_conditional_on_its_snapshot(self):
        self.assertEqual([], concurrent_violations(self.root / "reference"))
        self.assertTrue(concurrent_violations(self.root / "no-conditional-write", "no-conditional-write"))

    def test_journal_save_never_overwrites_newer_progress(self):
        handler = reference.payer(self.root / "stale", "boot-1")
        handler.store.write(JOURNAL, {
            "boot": "boot-1", "progress": "never-broadcast",
            "retainedTransfer": generator.retained(), "signedTransaction": generator.signed(),
            "confirmResponse": None, "result": None,
        })
        stale = handler.store.read(JOURNAL)
        newer = handler._save(stale, progress="confirm-returned",
                              confirmResponse=generator.validity_response(generator.signed()))
        with self.assertRaises(reference.Conflict):
            handler._save(stale, progress="confirm-sent-interrupted")
        self.assertEqual(newer, handler.store.read(JOURNAL))

    def test_gate_state_comes_from_storage_not_the_caller(self):
        """The reference passes the oracle no caller flag: every state member
        of its gate input is the journal it read back, including the other
        phases that retain the same hash."""
        handler = reference.payer(self.root / "state", "boot-2")
        handler.store.write(JOURNAL, {
            "boot": "boot-1", "progress": "confirm-returned",
            "retainedTransfer": generator.retained(), "signedTransaction": generator.signed(),
            "confirmResponse": generator.validity_response(generator.signed()), "result": None,
        })
        entry = handler.store.read(JOURNAL)
        self.assertEqual({"retentionDurable": True, "restartedSinceRetention": True,
                          "broadcastState": "confirm-returned"}, handler._state(entry))
        self.assertFalse(handler._permits("broadcast-retained", entry))
        self.assertTrue(reference.payer(self.root / "state", "boot-1")._permits("broadcast-retained", entry))
        other = reference.payer(self.root / "state", "boot-1", job_id=generator.OTHER_JOB_ID)
        self.assertEqual([{"jobId": generator.JOB_ID, "phaseIndex": generator.PHASE_INDEX}],
                         other._retained_elsewhere(entry["retainedTransfer"]["txHash"]))


if __name__ == "__main__":
    unittest.main()
