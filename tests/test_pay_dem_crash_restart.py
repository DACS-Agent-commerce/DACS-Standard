"""DACS-4 §9.5.9 DEM-1/DEM-6 and DEM-7 crash-restart witness.

A storage-backed reference payer handler and payee
(`pay_dem_reference_handler`) take every state input of the corpus oracle's
decisions from what they read back from storage. Each scenario runs one
process per start: the first start is stopped (`os._exit`) on one side of a
transition, then the handler or payee restarts from its storage. The
invariants are what DEM-1, DEM-6 and DEM-7 promise across a crash, an
in-process interruption and a concurrent start. Each mutant, a handler or
payee that keeps its state in process memory, journals late or only after a
call returns, trusts its saved progress, skips an fsync, retains a phase's
first transfer without a create-if-absent, locks only its own phase while it
checks the other phases' hashes, takes the network from its binding, trusts
the node's word that a read is authenticated, returns a DEM-4 failure
without journaling it, writes its index without a conditional write, treats
a lost index as empty or delivers on every check, must break one of them.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
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

    store = root / "store"
    journal = store / JOURNAL

    def egress(call):
        status = os.stat(journal) if journal.exists() else None
        events.append(("egress:" + call, (status.st_dev, status.st_ino) if status else (0, 0)))

    with mock.patch.object(reference.os, "fsync", fsync):
        # The store directory is new: the handler creates it in this start.
        handler = reference.payer(root, "boot-1", mutant=mutant)
        handler.node.observer = egress
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
    last_journal = max((i for i, identity in enumerate(before) if identity == journal_id), default=-1)
    if directory_id not in before[last_journal + 1:]:
        violations.append("journal directory not fsynced after the rename, before the first egress")
    parent = os.stat(root)
    if (parent.st_dev, parent.st_ino) not in before:
        violations.append("new journal directory's entry not fsynced in its parent before the first egress")
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
    phaseIndex) ever receives delivery against the hash, no tuple receives
    it twice, and every delivered tuple is in the durable index."""
    violations = []
    for point in PAYEE_POINTS:
        work = root / point
        provisioned = run("provision", work, "boot-0")
        if provisioned.returncode != 0:
            violations.append(f"{point}: provision failed: {provisioned.stderr[-400:]}")
            continue
        steps = (("boot-1", generator.JOB_ID, point), ("boot-2", generator.OTHER_JOB_ID, None),
                 ("boot-3", generator.JOB_ID, None))
        for boot, job, crash in steps:
            result = run("deliver", work, boot, "--job", job, *_options(crash, mutant))
            if result.returncode not in (0, reference.CRASH_EXIT):
                violations.append(f"{point}: {boot} failed: {result.stderr[-400:]}")
        deliveries = reference.read_lines(work / reference.DELIVERIES)
        keys = [reference.delivery_key(entry) for entry in deliveries]
        if len(keys) != len(set(keys)):
            violations.append(f"{point}: one tuple delivered twice")
        delivered = {(entry["jobId"], entry["phaseIndex"]) for entry in deliveries}
        if len(delivered) > 1:
            violations.append(f"{point}: one hash delivered for {sorted(delivered)}")
        index = reference.Store(work / "payee-store").read(reference.INDEX) or {"admissions": []}
        indexed = {(admission["jobId"], admission["phaseIndex"]) for admission in index["admissions"]}
        if not delivered <= indexed:
            violations.append(f"{point}: delivered {sorted(delivered - indexed)} without a durable admission")
    return violations


def index_loss_violations(root: Path, mutant: str | None = None) -> list[str]:
    """Deliver against the transfer, then lose, corrupt or roll back the
    index: a restarted payee shown the same hash for another job, or for its
    own, refuses and delivers nothing. A check never creates the index."""
    violations = []

    def lose(store):
        (store / reference.INDEX).unlink()

    def corrupt(store):
        (store / reference.INDEX).write_bytes(b"{")

    def roll_back(store):
        lose(store)
        run("provision", store.parent, "boot-x")

    for name, damage in (("lost", lose), ("corrupt", corrupt), ("rolled-back", roll_back)):
        work = root / name
        run("provision", work, "boot-0")
        run("deliver", work, "boot-1", "--job", generator.JOB_ID, *_options(None, mutant))
        damage(work / "payee-store")
        for boot, job in (("boot-2", generator.OTHER_JOB_ID), ("boot-3", generator.JOB_ID)):
            again = run("deliver", work, boot, "--job", job, *_options(None, mutant))
            if again.returncode == 0 and json.loads(again.stdout)["verdict"] == "pass":
                violations.append(f"{name}: {boot} delivered for {job} after the index was {name}")
        count = len(reference.read_lines(work / reference.DELIVERIES))
        if count != 1:
            violations.append(f"{name}: {count} deliveries")
    unprovisioned = run("deliver", root / "unprovisioned", "boot-1", "--job", generator.JOB_ID,
                        *_options(None, mutant))
    if unprovisioned.returncode == 0 and json.loads(unprovisioned.stdout)["verdict"] == "pass":
        violations.append("a check created its own index and delivered")
    return violations


def concurrent_payer_violations(root: Path, mutant: str | None = None) -> list[str]:
    """Two starts of one phase, each with its own signed transfer, both find
    no retention: at most one transfer ever leaves for the phase (DEM-1)."""
    first = reference.payer(root, "boot-A", mutant=mutant)
    second = reference.payer(root, "boot-B", mutant=mutant)
    own = generator.signed()
    other = generator.signed(dict(own["content"], timestamp=own["content"]["timestamp"] + 1))
    real_write = first.store.write
    started = []

    def write_after_second_start(name, value):
        # The first start has read "no journal"; the second starts now.
        if not started:
            thread = threading.Thread(target=second.pay, args=(other,), daemon=True)
            started.append(thread)
            thread.start()
            thread.join(timeout=1.0)
        return real_write(name, value)

    first.store.write = write_after_second_start
    first.pay(own)
    started[0].join(timeout=30)
    hashes = {entry["transaction"]["hash"] for entry in reference.read_lines(root / "egress.jsonl")}
    return [] if len(hashes) <= 1 else [f"{len(hashes)} transfers left for one phase"]


def interrupted_call_violations(root: Path, mutant: str | None = None) -> list[str]:
    """A call carries the bytes, then raises an error the handler does not
    model (a socket timeout); the same start resumes the phase. It sends no
    second call and never stores or returns permanent, even when the node
    relayed the confirm and the payer's balance now shows the transfer's own
    debit (DEM-5, DEM-6)."""
    violations = []
    for call in ("confirm", "broadcast"):
        work = root / call
        handler = reference.payer(work, "boot-1", mutant=mutant, relays_confirm=call == "confirm")
        real = getattr(handler.node, call)
        interrupted = []

        def carry_then_time_out(value, real=real, interrupted=interrupted, node=handler.node):
            reply = real(value)
            if not interrupted:
                interrupted.append(True)
                node.balance = "insufficient"
                raise TimeoutError("read timed out")
            return reply

        setattr(handler.node, call, carry_then_time_out)
        try:
            handler.pay(generator.signed())
        except TimeoutError:
            pass
        result = handler.advance()
        calls = [entry["call"] for entry in reference.read_lines(work / "egress.jsonl")]
        if calls.count(call) > 1:
            violations.append(f"{call}: second signed effect")
        stored = (handler.store.read(handler.journal) or {}).get("result") or {}
        if "permanent" in (result.get("errorClass"), stored.get("errorClass")):
            violations.append(f"{call}: permanent after the bytes left")
    return violations


FAILED = ("--record-status", "failed")
FV5 = ("--fv5", "policy")


def _journal(work: Path) -> dict:
    return reference.Store(work / "store").read(JOURNAL) or {}


def failure_proof_violations(root: Path, mutant: str | None = None) -> list[str]:
    """DEM-4 and DEM-6: an FV-5-authenticated failed record is terminal. The
    result and its proof reach storage in one write before `permanent` is
    returned, a crash on either side of that write leaves either a re-read
    or the stored proof, and once it is stored a later read that serves
    `confirmed` reopens nothing."""
    violations = []
    for point in (None, "before-failure-proof", "after-failure-proof"):
        label = point or "uninterrupted"
        work = root / label
        first = run("pay", work, "boot-1", *_options(point, mutant, *FAILED, *FV5))
        if first.returncode not in (0, reference.CRASH_EXIT):
            violations.append(f"{label}: first start failed: {first.stderr[-400:]}")
            continue
        stored = _journal(work)
        returned = json.loads(first.stdout) if first.returncode == 0 else {}
        if returned.get("errorClass") == "permanent" and (stored.get("result") or {}).get("errorClass") != "permanent":
            violations.append(f"{label}: permanent without its durable failure proof")
        if (stored.get("result") is None) != (stored.get("failureProof") is None):
            violations.append(f"{label}: result and failure proof not written together")
        # A crash before the proof leaves only a re-read; the node still
        # serves the failed record then. Once the proof is stored, the node
        # turns to serve confirmed, and the session stays terminal.
        later = FAILED if point == "before-failure-proof" else ("--record-status", "confirmed")
        again = run("pay", work, "boot-2", *_options(None, mutant, *later, *FV5))
        if again.returncode != 0:
            violations.append(f"{label}: restart failed: {again.stderr[-400:]}")
            continue
        result = json.loads(again.stdout)
        if (result.get("expected"), result.get("errorClass")) != ("fail", "permanent"):
            violations.append(f"{label}: terminal failure reopened as {result.get('expected')}")
        if [entry["boot"] for entry in reference.read_lines(work / "egress.jsonl")] != ["boot-1", "boot-1"]:
            violations.append(f"{label}: egress after the terminal failure")
    return violations


def plain_read_violations(root: Path, mutant: str | None = None) -> list[str]:
    """DEM-4/DEM-5: a pinned node that serves a bound failed record and
    calls its own read authenticated proves nothing; without FV-5 the result
    stays substrate and nothing terminal is stored."""
    done = run("pay", root, "boot-1", *_options(None, mutant, *FAILED, "--node-claims-authentication"))
    if done.returncode != 0:
        return [f"failed: {done.stderr[-400:]}"]
    result, stored = json.loads(done.stdout), _journal(root)
    violations = []
    if result.get("errorClass") != "substrate":
        violations.append(f"plain read classified {result.get('errorClass')}")
    if stored.get("result") is not None or stored.get("failureProof") is not None:
        violations.append("plain read stored a terminal result")
    return violations


def forged_fv5_violations(root: Path, mutant: str | None = None) -> list[str]:
    """DEM-4/FV-5: a result source that answers for a bound failed record
    under the policy's authority names, with signatures no policy key
    verifies, authenticates nothing. The result stays substrate, nothing
    terminal is stored, and a restart still sends nothing."""
    violations = []
    for boot in ("boot-1", "boot-2"):
        done = run("pay", root, boot, *_options(None, mutant, *FAILED, "--fv5", "forged"))
        if done.returncode != 0:
            return violations + [f"{boot}: failed: {done.stderr[-400:]}"]
        result, stored = json.loads(done.stdout), _journal(root)
        if result.get("errorClass") != "substrate":
            violations.append(f"{boot}: forged FV-5 result classified {result.get('errorClass')}")
        if stored.get("result") is not None or stored.get("failureProof") is not None:
            violations.append(f"{boot}: forged FV-5 result stored a terminal result")
    if [entry["boot"] for entry in reference.read_lines(root / "egress.jsonl")] != ["boot-1", "boot-1"]:
        violations.append("egress after a restart")
    return violations


def rail_network_violations(root: Path, mutant: str | None = None) -> list[str]:
    """DEM-1/RAV-R3: the payer's binding is for mainnet only and the rail
    settles on testnet. Nothing may be retained or sent: a handler that
    takes the network from its binding would debit the payer on mainnet for
    a phase whose record can never settle."""
    done = run("pay", root, "boot-1", *_options(None, mutant, "--rail-network", "testnet"))
    if done.returncode != 0:
        return [f"failed: {done.stderr[-400:]}"]
    violations = []
    calls = [entry["call"] for entry in reference.read_lines(root / "egress.jsonl")]
    if calls:
        violations.append(f"egress on a rail the binding does not cover: {calls}")
    result = json.loads(done.stdout)
    if (result.get("ok"), result.get("errorClass"), result.get("signPermitted")) != (False, "substrate", False):
        violations.append(f"result {result}")
    if (root / "store" / JOURNAL).exists():
        violations.append("retained a transfer for a rail the binding does not cover")
    return violations


def simultaneous_cross_phase_violations(root: Path, mutant: str | None = None) -> list[str]:
    """DEM-1: two phases start at once with one signed transaction, and both
    look for the hash before either has retained it. At most one phase ever
    retains it."""
    first = reference.payer(root, "boot-A", mutant=mutant)
    second = reference.payer(root, "boot-B", mutant=mutant, job_id=generator.OTHER_JOB_ID)
    transaction = generator.signed()
    real_write = first.store.write
    started = []

    def write_after_other_phase_starts(name, value):
        # The first phase has found the hash nowhere; the other starts now.
        if not started:
            thread = threading.Thread(target=second.pay, args=(transaction,), daemon=True)
            started.append(thread)
            thread.start()
            thread.join(timeout=1.0)
        return real_write(name, value)

    first.store.write = write_after_other_phase_starts
    first.pay(transaction)
    started[0].join(timeout=30)
    retaining = [journal for journal in reference.stored_journals(root / "store")
                 if journal["retainedTransfer"]["txHash"] == transaction["hash"]]
    return [] if len(retaining) <= 1 else [f"{len(retaining)} phases retain one hash"]


def concurrent_violations(root: Path, mutant: str | None = None) -> list[str]:
    """Two checks for different jobs read the same index snapshot; the
    second write must not succeed on that stale snapshot."""
    first = reference.payee(root, "boot-1", mutant=mutant)
    second = reference.payee(root, "boot-1", mutant=mutant)
    first.provision()
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

    def test_two_phases_starting_at_once_never_both_retain_one_hash(self):
        self.assertEqual([], simultaneous_cross_phase_violations(self.root / "reference"))
        self.assertEqual(["2 phases retain one hash"],
                         simultaneous_cross_phase_violations(self.root / "per-phase", "per-phase-retention-lock"))

    def test_proven_failure_is_journaled_with_its_proof_and_never_reopened(self):
        self.assertEqual([], failure_proof_violations(self.root / "reference"))
        work = self.root / "reference" / "uninterrupted"
        stored = _journal(work)
        self.assertEqual(("fail", "permanent"), (stored["result"]["expected"], stored["result"]["errorClass"]))
        # The proof keeps FV-5's signed execution result itself, not a label.
        self.assertEqual({"classification": "permanent",
                          "authentication": generator.execution_result(generator.record("failed")),
                          "inclusionBlock": generator.BLOCK, "record": generator.record("failed")},
                         stored["failureProof"])
        # The handler that returns permanent without journaling it reopens
        # the session when a later read serves confirmed.
        self.assertIn("uninterrupted: terminal failure reopened as pass",
                      failure_proof_violations(self.root / "late", "failure-not-journaled"))

    def test_a_plain_read_of_a_failed_record_is_never_terminal(self):
        self.assertEqual([], plain_read_violations(self.root / "reference"))
        self.assertEqual(["plain read classified permanent", "plain read stored a terminal result"],
                         plain_read_violations(self.root / "trusting", "node-authenticates-read"))

    def test_a_forged_fv5_result_is_never_terminal(self):
        self.assertEqual([], forged_fv5_violations(self.root / "reference"))
        # The handler that takes a result's signatures on trust ends the
        # phase on the forgery and stores it as its proof.
        self.assertEqual(["boot-1: forged FV-5 result classified permanent",
                          "boot-1: forged FV-5 result stored a terminal result",
                          "boot-2: forged FV-5 result classified permanent",
                          "boot-2: forged FV-5 result stored a terminal result"],
                         forged_fv5_violations(self.root / "unverified", "unverified-fv5-result"))

    def test_a_resume_reuses_only_an_authenticated_failure_proof(self):
        """DEM-4: a stored proof whose FV-5 result no longer verifies (a
        label, a forgery, an edited record, another network) or that no
        longer binds the retained transfer is not reused; the resume
        re-reads, and without FV-5 that re-read stays substrate."""
        failed = generator.record("failed")
        for name, damage in (("plain-read", {"authentication": "rpc-read"}),
                             ("label", {"authentication": "fv5-bft-final"}),
                             ("forged", {"authentication": generator.execution_result(
                                 failed, keys=generator.FORGED_FV5_SIGNERS)}),
                             ("edited-result", {"authentication": dict(
                                 generator.execution_result(failed), record=generator.record("pending"))}),
                             ("other-network", {"authentication": generator.execution_result(
                                 failed, network=generator.OTHER_NETWORK)}),
                             ("other-block", {"inclusionBlock": generator.BLOCK + 1})):
            with self.subTest(name=name):
                work = self.root / name
                self.assertEqual(0, run("pay", work, "boot-1", *FAILED, *FV5).returncode)
                store = reference.Store(work / "store")
                entry = store.read(JOURNAL)
                store.write(JOURNAL, dict(entry, failureProof=dict(entry["failureProof"], **damage)))
                again = run("pay", work, "boot-2", *FAILED)
                self.assertEqual(0, again.returncode, again.stderr)
                self.assertEqual(("indeterminate", "substrate"),
                                 tuple(json.loads(again.stdout)[k] for k in ("expected", "errorClass")))
                self.assertEqual(["confirm", "broadcast"],
                                 [entry["call"] for entry in reference.read_lines(work / "egress.jsonl")])

    def test_binding_is_looked_up_by_the_rail_network(self):
        self.assertEqual([], rail_network_violations(self.root / "reference"))
        self.assertTrue(rail_network_violations(self.root / "circular", "network-from-binding"))
        # The gate input is the rail's network and the stored binding, not a flag.
        handler = reference.payer(self.root / "inputs", "boot-1", rail_network=generator.OTHER_NETWORK)
        self.assertEqual({"railNetwork": generator.OTHER_NETWORK, "demosBinding": [generator.binding_entry()]},
                         handler._binding_input())
        # With an entry for each network, the rail's is the one used.
        both = reference.payer(self.root / "both", "boot-1", rail_network=generator.OTHER_NETWORK,
                               bindings=[generator.binding_entry(), generator.binding_entry(generator.OTHER_NETWORK)])
        self.assertEqual(generator.OTHER_NETWORK, both._applied_authority().network)

    def test_journal_is_on_stable_storage_before_the_first_egress(self):
        self.assertEqual([], fsync_violations(self.root / "reference"))
        self.assertTrue(fsync_violations(self.root / "no-fsync", "no-fsync"))
        self.assertEqual(["new journal directory's entry not fsynced in its parent before the first egress"],
                         fsync_violations(self.root / "no-parent-fsync", "no-parent-fsync"))

    def test_one_phase_retains_one_transfer_under_concurrent_starts(self):
        self.assertEqual([], concurrent_payer_violations(self.root / "reference"))
        self.assertTrue(concurrent_payer_violations(self.root / "blind", "blind-first-retention"))

    def test_an_interrupted_call_is_journaled_as_possibly_sent_before_it_leaves(self):
        self.assertEqual([], interrupted_call_violations(self.root / "reference"))
        self.assertEqual(["confirm: permanent after the bytes left", "broadcast: second signed effect"],
                         interrupted_call_violations(self.root / "late", "progress-after-call"))

    def test_payee_never_delivers_after_its_index_is_lost_or_rolled_back(self):
        self.assertEqual([], index_loss_violations(self.root / "reference"))
        self.assertTrue(index_loss_violations(self.root / "empty", "empty-index-when-missing"))

    def test_every_wrong_payer_handler_is_caught(self):
        for mutant in ("process-local-journal", "journal-after-confirm", "restart-from-progress"):
            with self.subTest(mutant=mutant):
                self.assertTrue(payer_violations(self.root / mutant, mutant))

    def test_payee_never_delivers_a_reused_hash_across_a_restart(self):
        self.assertEqual([], payee_violations(self.root / "reference"))
        self.assertTrue(payee_violations(self.root / "process-local-index", "process-local-index"))

    def test_payee_delivers_an_admitted_tuple_once(self):
        self.assertTrue(any("delivered twice" in violation
                            for violation in payee_violations(self.root / "every", "deliver-every-check")))

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
