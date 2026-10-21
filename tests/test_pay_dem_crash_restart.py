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
without journaling it, takes its caller's start value as its start
identifier, counts its starts in a store that a loss or restore resets,
re-derives an ended phase from a re-read, writes its index without a
conditional write, treats a lost index as empty, delivers on every check,
leaves a new delivery record's directory entry unflushed or trusts an index
entry or delivery record that an interrupted start left unflushed, must
break one of them.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from typing import Callable
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
# Each point between a write and its flush leaves a record a restart can read
# before it is on stable storage.
FLUSH_POINTS = ("before-admission-directory-fsync", "before-delivery-fsync", "before-delivery-directory-fsync")
PAYEE_POINTS = ("before-admission-write", "after-admission-write", *FLUSH_POINTS, "after-delivery")
JOURNAL = reference.journal_name(generator.JOB_ID, generator.PHASE_INDEX)


def run(command: str, work: Path, boot: str, *options: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), command, "--work", str(work), "--boot", boot, *options],
        capture_output=True, text=True, timeout=120, check=False,
    )


def _options(crash: str | None = None, mutant: str | None = None, *extra: str) -> list[str]:
    return [*(["--crash", crash] if crash else []), *(["--mutant", mutant] if mutant else []), *extra]


# The genuine, final, authenticated payment shown to the payee. The payee
# decides on the evidence it is presented and never supplies its own.
GENUINE_READ = generator.found(generator.record("confirmed"), authenticated=True)


def evidence(work: Path) -> list[str]:
    """The `deliver` option that presents GENUINE_READ to a payee in `work`."""
    path = Path(work).parent / "presented-evidence.json"
    path.write_text(json.dumps(GENUINE_READ), encoding="utf-8")
    return ["--evidence", str(path)]


def start_state(work: Path) -> list[Path]:
    """The payer's stored documents other than its journals."""
    return sorted(path for path in (work / "store").glob("*") if path.is_file()
                  and not path.name.startswith(".") and not path.name.endswith(reference.JOURNAL))


def start_state_loss_violations(root: Path, mutant: str | None = None) -> list[str]:
    """DEM-6 across a partial restore: once the first start stops at any
    point, every stored document but the journals is lost, or restored from
    the copy an earlier start left. A restart still sends nothing."""
    def lose(work, older):
        for path in start_state(work):
            path.unlink()

    def roll_back(work, older):
        lose(work, older)
        for name, content in older.items():
            (work / "store" / name).write_bytes(content)

    return [f"{name}: {violation}" for name, damage in (("lost", lose), ("rolled-back", roll_back))
            for violation in payer_violations(root / name, mutant, damage=damage)]


def payer_violations(root: Path, mutant: str | None = None, *node: str,
                     restarts: tuple[str, ...] = ("boot-2", "boot-3"),
                     damage: Callable[[Path, dict[str, bytes]], None] | None = None) -> list[str]:
    """Stop the payer at each point, restart it twice, and check DEM-1/DEM-6.
    `restarts` are the caller's labels for the restarted processes: the same
    label as the first start's is a caller that reuses its value, which the
    handler must not take as its own start identity. With `damage`, an
    earlier start first stops before it retains anything, and once the first
    start stops, `damage` changes the store given a copy of its documents
    other than journals as that earlier start left them. Egress after the
    restart is what the log holds beyond what it held when the first start
    stopped."""
    violations = []
    signed = generator.signed()
    for point in PAYER_POINTS:
        work = root / point
        older = {}
        if damage is not None:
            run("pay", work, "boot-0", *_options("before-retain", mutant, *node))
            older = {path.name: path.read_bytes() for path in start_state(work)}
        first = run("pay", work, "boot-1", *_options(point, mutant, *node))
        if first.returncode not in (0, reference.CRASH_EXIT):
            violations.append(f"{point}: first start failed: {first.stderr[-400:]}")
            continue
        if damage is not None:
            damage(work, older)
        retained_at_restart = (work / "store" / JOURNAL).exists()
        sent_before_restart = len(reference.read_lines(work / "egress.jsonl"))
        results = []
        for boot in restarts:
            again = run("pay", work, boot, *_options(None, mutant, *node))
            if again.returncode != 0:
                violations.append(f"{point}: {boot} failed: {again.stderr[-400:]}")
                break
            results.append(json.loads(again.stdout))
        egress = reference.read_lines(work / "egress.jsonl")
        calls = [entry["call"] for entry in egress]
        if calls.count("confirm") > 1 or calls.count("broadcast") > 1:
            violations.append(f"{point}: second signed effect {calls}")
        after_restart = egress[sent_before_restart:]
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


def fsync_violations(root: Path, mutant: str | None = None, *, existing_store: bool = False) -> list[str]:
    """The journal reaches stable storage, its file and then its directory
    flushed after the rename, before the first egress. With `existing_store`,
    the store directory is one an interrupted start created and stopped
    before flushing its entry in the parent; this start flushes it."""
    events: list[tuple[str, tuple[int, int]]] = []
    if existing_store:
        (root / "store").mkdir(parents=True)
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
        violations.append("journal directory's entry not fsynced in its parent before the first egress")
    return violations


def delivery_fsync_violations(root: Path, mutant: str | None = None) -> list[str]:
    """The first delivery creates its record: the record's file and then the
    directory entry naming it reach stable storage before `deliver` returns,
    so a power loss after the delivery never loses it while the admission
    index, already durable, still holds the admission (DEM-7 once-only)."""
    events: list[tuple[int, int]] = []
    real_fsync = os.fsync

    def fsync(fd):
        status = os.fstat(fd)
        events.append((status.st_dev, status.st_ino))
        return real_fsync(fd)

    work = root / "fresh" / "payee"
    with mock.patch.object(reference.os, "fsync", fsync):
        made = reference.payee(work, "boot-1", mutant=mutant)
        made.provision()
        verdict = made.deliver(generator.JOB_ID, read=GENUINE_READ)
    if verdict != "pass":
        return [f"no delivery: {verdict}"]
    sink, directory = os.stat(work / reference.DELIVERIES), os.stat(work)
    sink_id, directory_id = (sink.st_dev, sink.st_ino), (directory.st_dev, directory.st_ino)
    violations = []
    if sink_id not in events:
        violations.append("delivery record not fsynced before deliver returned")
    last = max((i for i, identity in enumerate(events) if identity == sink_id), default=-1)
    if directory_id not in events[last + 1:]:
        violations.append("new delivery record's directory entry not fsynced before deliver returned")
    return violations


def interrupted_delivery_violations(root: Path, mutant: str | None = None) -> list[str]:
    """DEM-7 once-only across a crash between a write and its flush: the
    first start stops after the admission index's rename and before its
    directory fsync, or after the delivery record's write and before its
    fsync or its directory's. A restart finds a record it can read that a
    power loss could still remove, so it flushes the record before trusting
    it: the index entry before the delivery effect, the delivery record and
    then its directory entry before `deliver` returns, with one delivery."""
    violations = []
    real_fsync = os.fsync
    for point in FLUSH_POINTS:
        work = root / point
        run("provision", work, "boot-0")
        first = run("deliver", work, "boot-1", "--job", generator.JOB_ID, *_options(point, mutant), *evidence(work))
        if first.returncode != reference.CRASH_EXIT:
            violations.append(f"{point}: first start did not stop: {first.stderr[-400:]}")
            continue
        events: list[tuple[int, int]] = []

        def fsync(fd, events=events):
            status = os.fstat(fd)
            events.append((status.st_dev, status.st_ino))
            return real_fsync(fd)

        with mock.patch.object(reference.os, "fsync", fsync):
            verdict = reference.payee(work, "boot-2", mutant=mutant).deliver(generator.JOB_ID, read=GENUINE_READ)
        if verdict != "pass":
            violations.append(f"{point}: restart did not deliver: {verdict}")
            continue
        identity = {name: (status.st_dev, status.st_ino) for name, status in (
            ("index", os.stat(work / "payee-store")), ("sink", os.stat(work / reference.DELIVERIES)),
            ("directory", os.stat(work)))}
        first_sink = events.index(identity["sink"]) if identity["sink"] in events else len(events)
        last_sink = max((i for i, seen in enumerate(events) if seen == identity["sink"]), default=-1)
        if point == "before-admission-directory-fsync" and identity["index"] not in events[:first_sink]:
            violations.append(f"{point}: admission index entry not fsynced before the delivery record")
        if identity["sink"] not in events:
            violations.append(f"{point}: delivery record not fsynced before deliver returned")
        if identity["directory"] not in events[last_sink + 1:]:
            violations.append(f"{point}: delivery record's directory entry not fsynced before deliver returned")
        count = len(reference.read_lines(work / reference.DELIVERIES))
        if count != 1:
            violations.append(f"{point}: {count} deliveries")
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
            result = run("deliver", work, boot, "--job", job, *_options(crash, mutant), *evidence(work))
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
        run("deliver", work, "boot-1", "--job", generator.JOB_ID, *_options(None, mutant), *evidence(work))
        damage(work / "payee-store")
        for boot, job in (("boot-2", generator.OTHER_JOB_ID), ("boot-3", generator.JOB_ID)):
            again = run("deliver", work, boot, "--job", job, *_options(None, mutant), *evidence(work))
            if again.returncode == 0 and json.loads(again.stdout)["verdict"] == "pass":
                violations.append(f"{name}: {boot} delivered for {job} after the index was {name}")
        count = len(reference.read_lines(work / reference.DELIVERIES))
        if count != 1:
            violations.append(f"{name}: {count} deliveries")
    unprovisioned = run("deliver", root / "unprovisioned", "boot-1", "--job", generator.JOB_ID,
                        *_options(None, mutant), *evidence(root / "unprovisioned"))
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
        # turns to serve confirmed for the failed transfer, and the session
        # stays terminal.
        later = FAILED if point == "before-failure-proof" else ("--record-status", "confirmed", "--executed", "failed")
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


def terminal_reopen_violations(root: Path, mutant: str | None = None) -> list[str]:
    """DEM-4/DEM-6: once a phase ends on a proven failure, its stored proof
    stops verifying (here: its FV-5 result is now signed by keys outside the
    payer's policy), and a later re-read serves `confirmed` with the applied
    payment authenticated. The proof is not reused, and the re-read is
    post-terminal: it never returns success or anchors success evidence,
    the stored terminal result and proof stay as written, and nothing is sent."""
    if run("pay", root, "boot-1", *_options(None, mutant, *FAILED, *FV5)).returncode != 0:
        return ["no terminal failure stored"]
    store = reference.Store(root / "store")
    entry = store.read(JOURNAL)
    if (entry or {}).get("failureProof") is None:
        return ["no terminal failure stored"]
    invalid = dict(entry, failureProof=dict(entry["failureProof"], authentication=generator.execution_result(
        generator.record("failed"), keys=generator.FORGED_FV5_SIGNERS)))
    store.write(JOURNAL, invalid)
    again = run("pay", root, "boot-2", *_options(None, mutant, "--record-status", "confirmed",
                                                  "--executed", "confirmed", *FV5))
    if again.returncode != 0:
        return [f"restart failed: {again.stderr[-400:]}"]
    result, violations = json.loads(again.stdout), []
    if result.get("ok") or result.get("expected") == "pass" or result.get("nextAction") == "anchor-success-evidence":
        violations.append(f"terminal failure reopened as {result.get('expected')}")
    if result.get("deliveryAuthorized") or result.get("settlementAccounting"):
        violations.append("post-terminal read authorized delivery or accounting")
    if store.read(JOURNAL) != invalid:
        violations.append("post-terminal read changed the stored session")
    if [entry["boot"] for entry in reference.read_lines(root / "egress.jsonl")] != ["boot-1", "boot-1"]:
        violations.append("egress after the terminal failure")
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


def unproven_failure_violations(root: Path, mutant: str | None = None, *options: str,
                                label: str = "forged FV-5 result") -> list[str]:
    """DEM-4/FV-5: a bound failed record whose proof falls short stays
    substrate, nothing terminal is stored, and a restart still sends
    nothing. By default the result source answers under the policy's
    authority names with signatures no policy key verifies."""
    options = options or ("--fv5", "forged")
    violations = []
    for boot in ("boot-1", "boot-2"):
        done = run("pay", root, boot, *_options(None, mutant, *FAILED, *options))
        if done.returncode != 0:
            return violations + [f"{boot}: failed: {done.stderr[-400:]}"]
        result, stored = json.loads(done.stdout), _journal(root)
        if result.get("errorClass") != "substrate":
            violations.append(f"{boot}: {label} classified {result.get('errorClass')}")
        if stored.get("result") is not None or stored.get("failureProof") is not None:
            violations.append(f"{boot}: {label} stored a terminal result")
    if [entry["boot"] for entry in reference.read_lines(root / "egress.jsonl")] != ["boot-1", "boot-1"]:
        violations.append("egress after a restart")
    return violations


def forged_fv5_violations(root: Path, mutant: str | None = None) -> list[str]:
    return unproven_failure_violations(root, mutant)


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
        verdicts["other"] = second.deliver(generator.OTHER_JOB_ID, read=GENUINE_READ)

    verdicts["own"] = first.deliver(generator.JOB_ID, read=GENUINE_READ, between=interleave)
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

    def test_an_executed_payment_in_a_block_not_yet_final_is_no_success(self):
        """DEM-3 and PC-7: a bound confirmed record with its applied payment,
        in a block no BFT certificate finalizes, is substrate, never ok. The
        re-read after the block is final settles it, sending nothing."""
        work = self.root / "unfinal"
        first = run("pay", work, "boot-1", "--fv5", "unfinalized")
        self.assertEqual(0, first.returncode, first.stderr)
        result = json.loads(first.stdout)
        self.assertEqual(("indeterminate", False, "substrate"), (result["expected"], result["ok"], result["errorClass"]))
        final = run("pay", work, "boot-2")
        self.assertEqual(0, final.returncode, final.stderr)
        self.assertEqual("pass", json.loads(final.stdout)["expected"])
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

    def test_a_crash_around_the_pre_egress_refusal_write_sends_nothing(self):
        """A short balance found before any egress ends the phase permanent.
        A crash before that write leaves a retention with no result, which a
        restart treats as possibly sent and only re-reads (substrate); a crash
        after it leaves the stored refusal. Either way nothing is sent."""
        for point, then_class in (("before-refusal-result", "substrate"), ("after-refusal-result", "permanent")):
            with self.subTest(point=point):
                work = self.root / point
                first = run("pay", work, "boot-1", "--crash", point, "--balance", "insufficient")
                self.assertEqual(reference.CRASH_EXIT, first.returncode, first.stderr)
                for boot in ("boot-2", "boot-1"):
                    again = run("pay", work, boot, "--balance", "sufficient")
                    self.assertEqual(0, again.returncode, again.stderr)
                    self.assertEqual(then_class, json.loads(again.stdout)["errorClass"])
                self.assertEqual([], reference.read_lines(work / "egress.jsonl"))

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
        # The proof keeps both halves as received, not a label: FV-5's
        # signed execution result and FV's bft-final inclusion of the transfer.
        self.assertEqual({"classification": "permanent",
                          "authentication": generator.execution_result(generator.record("failed")),
                          "inclusionProof": generator.INCLUSION_PROOF,
                          "inclusionBlock": generator.BLOCK, "record": generator.record("failed")},
                         stored["failureProof"])
        # The handler that returns permanent without journaling it reopens
        # the session when a later read serves confirmed (unpaid: the
        # applied-payment authority observes the rolled-back apply).
        self.assertIn("uninterrupted: terminal failure reopened as indeterminate",
                      failure_proof_violations(self.root / "late", "failure-not-journaled"))

    def test_a_terminal_failure_never_reopens_when_its_proof_stops_verifying(self):
        self.assertEqual([], terminal_reopen_violations(self.root / "reference"))
        # The handler that re-derives a terminal session from the re-read
        # alone returns success for a phase that ended permanent.
        self.assertEqual(["terminal failure reopened as pass"],
                         terminal_reopen_violations(self.root / "reopening", "terminal-reopens"))

    def test_a_restart_that_reuses_the_callers_start_value_sends_nothing(self):
        """DEM-6: each start has an identifier no earlier start used, which
        the handler mints itself. A restarted process given the same caller
        value as the start that crashed is still a restart: nothing is sent,
        at every point, including the broadcast after `after-confirm-journal`."""
        self.assertEqual([], payer_violations(self.root / "reference", restarts=("boot-1", "boot-1")))
        self.assertIn("after-confirm-journal: egress after restart ['broadcast']",
                      payer_violations(self.root / "caller", "caller-start-id", restarts=("boot-1", "boot-1")))

    def test_a_restart_after_its_start_state_is_lost_or_rolled_back_sends_nothing(self):
        """DEM-6: a start's identifier needs no stored state, so losing every
        stored document but the journals, or restoring an older copy of
        them, never gives a restart an earlier start's identity. The handler
        that counts its starts in its store repeats one and completes the
        crashed start's submission."""
        self.assertEqual([], start_state_loss_violations(self.root / "reference"))
        counting = start_state_loss_violations(self.root / "counter", "counter-reset-when-missing")
        for damage in ("lost", "rolled-back"):
            with self.subTest(damage=damage):
                self.assertIn(f"{damage}: after-confirm-journal: egress after restart ['broadcast']", counting)
                self.assertTrue(any(violation.startswith(f"{damage}: after-retain: egress after restart ['confirm'")
                                    for violation in counting), counting)

    def test_first_delivery_record_is_on_stable_storage_before_deliver_returns(self):
        self.assertEqual([], delivery_fsync_violations(self.root / "reference"))
        self.assertEqual(["new delivery record's directory entry not fsynced before deliver returned"],
                         delivery_fsync_violations(self.root / "no-sink-parent-fsync", "no-sink-parent-fsync"))

    def test_a_record_an_interrupted_start_left_unflushed_is_flushed_before_it_is_trusted(self):
        """DEM-7 once-only: a restart that finds an admission or a delivery
        record an interrupted start never flushed makes it durable before it
        acts on it, so a later power loss cannot drop the record while the
        admission stays and let a further check deliver again. The payee that
        trusts what it finds returns with the record still unflushed (its
        directory entry is flushed with the store's own on start)."""
        self.assertEqual([], interrupted_delivery_violations(self.root / "reference"))
        self.assertEqual(["before-admission-directory-fsync: admission index entry not fsynced before the delivery record",
                          "before-delivery-fsync: delivery record not fsynced before deliver returned",
                          "before-delivery-directory-fsync: delivery record not fsynced before deliver returned"],
                         interrupted_delivery_violations(self.root / "trusting", "trust-unflushed-record"))

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

    def test_a_signed_failure_without_bft_final_inclusion_is_never_terminal(self):
        """DEM-4: a policy-signed failed result for a block no BFT
        certificate finalizes is half a proof. The handler stays substrate
        and stores nothing terminal, before and after a restart; the handler
        that takes the signed result alone ends the phase on it."""
        unfinalized = ("--fv5", "unfinalized")
        label = "unfinalized FV-5 result"
        self.assertEqual([], unproven_failure_violations(self.root / "reference", None, *unfinalized, label=label))
        self.assertEqual([f"{boot}: {label} {what}" for boot in ("boot-1", "boot-2")
                          for what in ("classified permanent", "stored a terminal result")],
                         unproven_failure_violations(self.root / "alone", "fv5-result-alone", *unfinalized, label=label))
        # With its certificate, the same signed failure is terminal for both.
        self.assertEqual([], failure_proof_violations(self.root / "alone-final", "fv5-result-alone"))

    def test_independent_sources_never_follow_the_node(self):
        """The FV-5 source and the applied-payment authority answer from the
        chain state they observe, never from the record a node serves. A
        node serving failed for an executed transfer gets no signed failure,
        so nothing terminal is stored; a node serving confirmed for a failed
        one gets no applied payment, so the phase is never paid."""
        for name, served, executed in (("failed-served-executed", "failed", "confirmed"),
                                       ("confirmed-served-failed", "confirmed", "failed")):
            with self.subTest(name=name):
                work = self.root / name
                done = run("pay", work, "boot-1", "--record-status", served, "--executed", executed, *FV5)
                self.assertEqual(0, done.returncode, done.stderr)
                result = json.loads(done.stdout)
                self.assertEqual(("indeterminate", "substrate", False), (result["expected"], result["errorClass"], result["ok"]))
                stored = _journal(work)
                self.assertIsNone(stored.get("result"))
                self.assertIsNone(stored.get("failureProof"))
        handler = reference.payer(self.root / "sources", "boot-1", fv5="policy", record_status="failed",
                                  executed="confirmed")
        self.assertEqual(generator.record("confirmed"),
                         handler.fv5.result(generator.TX_HASH, generator.NETWORK, generator.block_id(generator.BLOCK))["record"])
        self.assertEqual(generator.APPLIED["payerAfterOs"],
                         handler._applied_authority().attest(generator.record("failed"))["appliedTransfer"]
                         ["committedBalances"]["payerAfterOs"])

    def test_a_resume_reuses_only_an_authenticated_failure_proof(self):
        """DEM-4: a stored proof whose FV-5 result or bft-final inclusion no
        longer verifies (a label, a forgery, an edited record, a result of
        another record, another network, no inclusion, an unfinalized or
        another block) or that no longer binds the retained transfer is not
        reused; the resume re-reads, and without FV-5 that re-read stays
        substrate."""
        failed = generator.record("failed")
        for name, damage in (("plain-read", {"authentication": "rpc-read"}),
                             ("label", {"authentication": "fv5-bft-final"}),
                             ("forged", {"authentication": generator.execution_result(
                                 failed, keys=generator.FORGED_FV5_SIGNERS)}),
                             ("edited-result", {"authentication": dict(
                                 generator.execution_result(failed), record=generator.record("pending"))}),
                             # Policy-signed, so only the record binding refuses it.
                             ("signed-other-record", {"authentication": generator.execution_result(
                                 generator.record("failed", generator.send_content(nonce=str(generator.NONCE + 1))))}),
                             ("other-network", {"authentication": generator.execution_result(
                                 failed, network=generator.OTHER_NETWORK)}),
                             ("no-inclusion", {"inclusionProof": None}),
                             ("unfinalized-inclusion", {"inclusionProof": generator.inclusion_proof(certified=False)}),
                             ("inclusion-of-another-block", {"inclusionProof": generator.FORK_INCLUSION_PROOF}),
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
        # The gate input is the rail's network, its signed profile and the
        # stored binding, not a flag.
        handler = reference.payer(self.root / "inputs", "boot-1", rail_network=generator.OTHER_NETWORK)
        self.assertEqual({"railNetwork": generator.OTHER_NETWORK, "finalityProfile": generator.FINALITY_PROFILE,
                          "demosBinding": [generator.binding_entry()]},
                         handler._binding_input())
        # With an entry for each network, the rail's is the one used.
        both = reference.payer(self.root / "both", "boot-1", rail_network=generator.OTHER_NETWORK,
                               bindings=[generator.binding_entry(), generator.binding_entry(generator.OTHER_NETWORK)])
        self.assertEqual(generator.OTHER_NETWORK, both._applied_authority().network)

    def test_payee_refuses_a_malformed_admission_index_entry(self):
        """An index entry without its (jobId, phaseIndex), or with a malformed
        one, is no history: the genuine payment is `error` and delivers
        nothing, before and after a restart, never a KeyError and never a
        pass because the entry names another hash."""
        other = {"kind": "demos", "txHash": generator.OTHER_TX_HASH, "blockNumber": generator.BLOCK}
        for name, admission in (("missing-job-id", {"phaseIndex": generator.PHASE_INDEX, "txRef": other}),
                                ("phase-index-string", {"jobId": generator.OTHER_JOB_ID, "phaseIndex": "1",
                                                        "txRef": other}),
                                ("missing-tx-ref", {"jobId": generator.OTHER_JOB_ID,
                                                    "phaseIndex": generator.PHASE_INDEX})):
            with self.subTest(entry=name):
                work = self.root / ("malformed-admission-" + name)
                first = reference.payee(work, "boot-1")
                first.provision()
                first.store.write(reference.INDEX, {"revision": 1, "admissions": [admission]})
                self.assertEqual("error", first.deliver(generator.JOB_ID, read=GENUINE_READ))
                restarted = reference.payee(work, "boot-2")
                self.assertEqual("error", restarted.deliver(generator.JOB_ID, read=GENUINE_READ))
                self.assertEqual(set(), restarted.delivered())

    def test_payee_delivers_nothing_against_evidence_that_does_not_pay(self):
        """The payee's entry point decides on the evidence it is given, not
        on a passing proof it builds. Failed,
        no-op, unbound, unpinned, unauthenticated and forged-finality
        evidence each deliver nothing and admit nothing; the genuine payment
        delivers once."""
        corpus = generator.load_vectors((HERE.parent / "conformance/vectors/security/pay-dem-execution-v0.1.json")
                                        .read_text(encoding="utf-8"))
        reads = {vector["name"]: vector["protocolInput"]["recordRead"] for vector in corpus["vectors"]
                 if "recordRead" in vector["protocolInput"]}
        for name in ("consumer-failed-fails", "consumer-confirmed-no-op-apply", "consumer-wrong-hash-authenticated",
                     "consumer-unpinned-node-refused", "delivery-record-unauthenticated",
                     "delivery-bft-final-certificate-forged", "delivery-record-fv5-forged-result"):
            with self.subTest(evidence=name):
                work = self.root / ("evidence-" + name)
                payee = reference.payee(work, "boot-1")
                payee.provision()
                self.assertNotEqual("pass", payee.deliver(generator.JOB_ID, read=reads[name]))
                self.assertEqual(set(), payee.delivered())
                self.assertEqual([], payee.snapshot()["admissions"])
        # No evidence is no payment: the payee never supplies its own. The
        # entry point has no default read (b981129 built a passing one).
        work = self.root / "evidence-omitted"
        payee = reference.payee(work, "boot-1")
        payee.provision()
        with self.assertRaises(TypeError):
            payee.deliver(generator.JOB_ID)
        for omitted in (None, [], "pass"):
            with self.subTest(evidence=omitted):
                self.assertEqual("error", payee.deliver(generator.JOB_ID, read=omitted))
        cli = run("deliver", work, "boot-2", "--job", generator.JOB_ID)
        self.assertEqual(0, cli.returncode, cli.stderr[-400:])
        self.assertEqual({"verdict": "error"}, json.loads(cli.stdout))
        self.assertEqual(set(), payee.delivered())
        self.assertEqual([], payee.snapshot()["admissions"])
        work = self.root / "evidence-genuine"
        payee = reference.payee(work, "boot-1")
        payee.provision()
        self.assertEqual("pass", payee.deliver(generator.JOB_ID, read=reads["delivery-after-all-gates"]))
        self.assertEqual(1, len(payee.delivered()))

    def test_nothing_is_sent_without_every_input_a_final_verdict_needs(self):
        """DEM-3 success needs bft-final trust covering the rail's profile,
        and DEM-4 an FV-5 policy. A binding with the other three members but
        without either used to pass the gate (f2148e4), and so did trust that
        is present but that FV rejects (b981129): a set under the pinned hash
        that is not the pinned set, keys that do not decode or alias one key.
        The payer was debited and every re-read stayed substrate. Now nothing
        is retained or sent."""
        trust, policy = generator.BINDING_TRUST, generator.BINDING_POLICY
        names = generator.FINALITY_PROFILE["observation"]["authorityRefs"]
        pinned = generator.FINALITY_PROFILE["validatorSetRef"]["contentHash"]
        refused = {
            "no-bft-final-trust": generator.binding_entry(bftFinalTrust=generator._OMIT),
            "no-execution-policy": generator.binding_entry(executionResultPolicy=generator._OMIT),
            "trust-without-rail-validator-set": generator.binding_entry(bftFinalTrust=dict(trust, validatorSets={})),
            "trust-for-another-network": generator.binding_entry(bftFinalTrust=dict(trust, **generator.OTHER_NETWORK)),
            "malformed-policy": generator.binding_entry(executionResultPolicy=dict(policy, threshold=0)),
            "policy-for-another-network": generator.binding_entry(
                executionResultPolicy=dict(policy, **generator.OTHER_NETWORK)),
            "validator-set-not-the-pinned-one": generator.binding_entry(
                bftFinalTrust=dict(trust, validatorSets={pinned: {"validators": []}})),
            "observation-keys-do-not-decode": generator.binding_entry(
                bftFinalTrust=dict(trust, observationAuthorityKeys={name: "not-a-key" for name in names})),
            "observation-keys-alias-one-key": generator.binding_entry(
                bftFinalTrust=dict(trust, observationAuthorityKeys={
                    name: trust["observationAuthorityKeys"]["rpc-a"] for name in names})),
        }
        for name, binding in refused.items():
            with self.subTest(binding=name):
                work = self.root / name
                result = reference.payer(work, "boot-1", bindings=[binding]).pay(generator.signed())
                self.assertEqual((False, "substrate", False),
                                 (result.get("ok"), result.get("errorClass"), result.get("signPermitted")))
                egress = work / "egress.jsonl"
                self.assertEqual([], reference.read_lines(egress) if egress.exists() else [])
                self.assertFalse((work / "store" / JOURNAL).exists())
        # The control sends, and its re-read verifies under the trust and
        # policy of the binding entry the gate checked.
        control = self.root / "control"
        handler = reference.payer(control, "boot-1")
        handler.pay(generator.signed())
        self.assertEqual(["confirm", "broadcast"],
                         [entry["call"] for entry in reference.read_lines(control / "egress.jsonl")])
        self.assertEqual((dict(generator.FINALITY_TRUST), generator.FV5_POLICY), handler._trust())

    def test_rereads_verify_under_the_binding_members_never_other_configuration(self):
        """DEM-1: the handler's re-reads verify under the binding members its
        gate checked. With the module's fixture trust and FV-5 policy emptied,
        a genuine payment still settles and a genuine failure is still
        proven, from the binding alone; the classification input carries
        exactly the binding's members. A handler that reads separate
        configuration settles nothing here."""
        entry = generator.binding_entry()
        trust = dict({key: entry["bftFinalTrust"][key] for key in reference.oracle.BFT_FINAL_TRUST},
                     verificationTimeMs=generator.FINALITY_TRUST["verificationTimeMs"])
        policy = {key: entry["executionResultPolicy"][key] for key in reference.oracle.EXECUTION_POLICY}
        empty_policy = dict(generator.FV5_POLICY, threshold=2, authorityKeys={})
        with mock.patch.object(generator, "FINALITY_TRUST", {}), \
                mock.patch.object(generator, "FV5_POLICY", empty_policy):
            paid = reference.payer(self.root / "paid", "boot-1", bindings=[entry], fv5="policy")
            result = paid.pay(generator.signed())
            self.assertEqual((True, None), (result.get("ok"), result.get("errorClass")))
            journal = paid.store.read(paid.journal)
            read = paid._read(journal["retainedTransfer"]["txHash"])
            classified = paid._classify_input(journal, read)
            self.assertEqual((trust, policy), (classified["finalityTrust"], classified["fv5Policy"]))
            again = paid.advance()
            self.assertEqual((True, None), (again.get("ok"), again.get("errorClass")))
            failed = reference.payer(self.root / "failed", "boot-1", bindings=[entry], fv5="policy",
                                     record_status="failed")
            result = failed.pay(generator.signed())
            self.assertEqual((False, "permanent"), (result.get("ok"), result.get("errorClass")))

    def test_journal_is_on_stable_storage_before_the_first_egress(self):
        self.assertEqual([], fsync_violations(self.root / "reference"))
        # A store directory an interrupted start created is flushed in its parent too.
        self.assertEqual([], fsync_violations(self.root / "existing", existing_store=True))
        self.assertTrue(fsync_violations(self.root / "no-fsync", "no-fsync"))
        for name, existing in (("no-parent-fsync", False), ("no-parent-fsync-existing", True)):
            with self.subTest(name=name):
                self.assertEqual(["journal directory's entry not fsynced in its parent before the first egress"],
                                 fsync_violations(self.root / name, "no-parent-fsync", existing_store=existing))

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
            "start": handler.start, "progress": "never-broadcast",
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
        phases that retain the same hash. Its start identifier is drawn fresh
        for each start, never the caller's value and never from stored state:
        a handler constructed later is a new start, even with the same caller
        value, and only the start that wrote the journal may complete its
        submission."""
        writer = reference.payer(self.root / "state", "boot-1")
        writer.store.write(JOURNAL, {
            "start": writer.start, "progress": "confirm-returned",
            "retainedTransfer": generator.retained(), "signedTransaction": generator.signed(),
            "confirmResponse": generator.validity_response(generator.signed()), "result": None,
        })
        entry = writer.store.read(JOURNAL)
        self.assertTrue(writer._permits("broadcast-retained", entry))
        for boot in ("boot-2", "boot-1"):
            with self.subTest(boot=boot):
                restarted = reference.payer(self.root / "state", boot)
                self.assertNotEqual(writer.start, restarted.start)
                self.assertEqual({"retentionDurable": True, "restartedSinceRetention": True,
                                  "broadcastState": "confirm-returned"}, restarted._state(entry))
                self.assertFalse(restarted._permits("broadcast-retained", entry))
        # No stored document but the journal decides a start's identity.
        self.assertEqual([], start_state(self.root / "state"))
        self.assertEqual(32, len(writer.start))
        # A journal that names no start, such as one an earlier handler wrote
        # with the caller's value, reads as another start's: nothing leaves.
        legacy = {key: value for key, value in entry.items() if key != "start"}
        legacy["boot"] = "boot-1"
        self.assertTrue(writer._state(legacy)["restartedSinceRetention"])
        self.assertFalse(writer._permits("broadcast-retained", legacy))
        other = reference.payer(self.root / "state", "boot-1", job_id=generator.OTHER_JOB_ID)
        self.assertEqual([{"jobId": generator.JOB_ID, "phaseIndex": generator.PHASE_INDEX}],
                         other._retained_elsewhere(entry["retainedTransfer"]["txHash"]))


if __name__ == "__main__":
    unittest.main()
