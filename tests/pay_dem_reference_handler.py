"""A storage-backed reference of the DACS-4 §9.5.9 pay-dem payer journal
(DEM-1, DEM-5, DEM-6) and the payee's DEM-7 admission index.

Every decision is the corpus oracle's own (`test_pay_dem_execution_vectors`):
`broadcast-gate`, `classify-egress-outcome`, `classify-execution` and
`admit-for-delivery`. Their state inputs (`retentionDurable`,
`restartedSinceRetention`, `broadcastState`, `signedTransaction`, the
presented history and `admissionIndex`) are derived from what this module
reads back from storage, never from process-local state.
`test_pay_dem_crash_restart` stops it on both sides of every transition and
restarts it from storage. Each `--mutant` is a wrong handler or payee that
the harness must catch.

`retentionDurable` is the one state input not read back: it is `True`
because `Store.write` returns only once the journal, its directory and every
directory it created are fsynced, which `test_pay_dem_crash_restart`
witnesses by the order of fsync calls before the first egress.

Run as a script, one process per start:
    pay_dem_reference_handler.py pay --work DIR --boot ID [--job JOB] [--crash POINT] [--mutant M]
    pay_dem_reference_handler.py provision --work DIR --boot ID
    pay_dem_reference_handler.py deliver --work DIR --boot ID --job JOB [--crash POINT] [--mutant M]
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "scripts"))

import test_pay_dem_execution_vectors as oracle  # noqa: E402

generator = oracle.generator

CRASH_EXIT = 70
JOURNAL = "pay-dem-journal.json"
INDEX = "admission-index.json"
DELIVERIES = "deliveries.jsonl"
PAYER_MUTANTS = ("process-local-journal", "journal-after-confirm", "restart-from-progress", "no-fsync",
                 "no-cross-phase-index", "no-parent-fsync", "blind-first-retention", "progress-after-call")
PAYEE_MUTANTS = ("process-local-index", "no-conditional-write", "empty-index-when-missing",
                 "deliver-every-check")
NO_GUARD_REMOVED = frozenset()


class Crashed(Exception):
    """An in-process stop at a crash point."""


class CallFailed(Exception):
    def __init__(self, outcome: str):
        super().__init__(outcome)
        self.outcome = outcome


class Conflict(Exception):
    """The admission index changed after the snapshot a write was based on."""


def _fsync_directory(path: Path) -> None:
    directory = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class Store:
    """One JSON document per name. A write goes to a temporary file that is
    flushed and fsynced, is renamed over the name, and then the directory is
    fsynced, so the document survives a crash at any later step. A directory
    the store creates is fsynced in its parent before the store is used, so a
    new store's own entry survives too. Member order is kept, so stored
    signed bytes read back unchanged."""

    def __init__(self, root: Path, *, fsync: bool = True, parent_fsync: bool = True):
        self.root = Path(root)
        self.fsync = fsync
        missing = []
        path = self.root.absolute()
        while not path.exists():
            missing.append(path)
            path = path.parent
        for path in reversed(missing):
            path.mkdir(exist_ok=True)
            if fsync and parent_fsync:
                # fsync(2): flushing a file does not flush the entry naming it.
                _fsync_directory(path.parent)

    def write(self, name: str, value: Any) -> None:
        temporary = self.root / f".{name}.tmp"
        with open(temporary, "wb") as handle:
            handle.write(json.dumps(value).encode("utf-8"))
            handle.flush()
            if self.fsync:
                os.fsync(handle.fileno())
        os.replace(temporary, self.root / name)
        if self.fsync:
            _fsync_directory(self.root)

    def read(self, name: str) -> Any:
        try:
            return json.loads((self.root / name).read_bytes())
        except FileNotFoundError:
            return None

    def locked(self, name: str):
        """An exclusive lock for a read-compare-write of `name`."""
        return _Lock(self.root / f".{name}.lock")

    def journals(self) -> list[dict[str, Any]]:
        return stored_journals(self.root)


class MemoryStore(Store):
    """The wrong store: process-local, lost at every restart."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.documents: dict[str, str] = {}

    def write(self, name: str, value: Any) -> None:
        self.documents[name] = json.dumps(value)

    def read(self, name: str) -> Any:
        return json.loads(self.documents[name]) if name in self.documents else None

    def locked(self, name: str):
        return _Lock(None)

    def journals(self) -> list[dict[str, Any]]:
        return [json.loads(value) for name, value in sorted(self.documents.items()) if name.endswith(JOURNAL)]


class _Lock:
    def __init__(self, path: Path | None):
        self.path = path
        self.handle = None

    def __enter__(self):
        if self.path is not None:
            self.handle = open(self.path, "a")
            fcntl.flock(self.handle, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_):
        if self.handle is not None:
            fcntl.flock(self.handle, fcntl.LOCK_UN)
            self.handle.close()


def _append(path: Path, entry: dict[str, Any]) -> None:
    """An effect outside the handler: it has happened once this returns."""
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def same_signed_bytes(retained: Any, carried: Any) -> bool:
    """The carried transaction's content, hash and signature serialize
    exactly as the retained signed transaction's (member order included)."""
    return (
        isinstance(retained, dict) and isinstance(carried, dict)
        and all(key in carried and json.dumps(carried[key]) == json.dumps(retained.get(key))
                for key in ("content", "hash", "signature"))
    )


def journal_name(job_id: str, phase_index: int) -> str:
    """One journal per authenticated (jobId, phaseIndex)."""
    return f"{job_id}-{phase_index}-{JOURNAL}"


def stored_journals(store_dir: Path) -> list[dict[str, Any]]:
    return [json.loads(path.read_bytes()) for path in sorted(Path(store_dir).glob("*-" + JOURNAL))]


def read_lines(path: Path) -> list[dict[str, Any]]:
    try:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except FileNotFoundError:
        return []


class Node:
    """The pinned node as the handler reaches it. `confirm` and `broadcast`
    log the bytes they carried before replying, so the network holds them
    even if the handler stops before it sees the reply; each logged egress
    also records whether the handler's stored journal already held exactly
    those signed bytes. A broadcast executes the embedded transaction; with
    `relays_confirm`, a node that received the confirm submits it too."""

    def __init__(self, work: Path, boot: str, *, confirm: str = "valid", broadcast: str = "accepted",
                 balance: str = "sufficient", relays_confirm: bool = False):
        self.work = Path(work)
        self.log = self.work / "egress.jsonl"
        self.boot = boot
        self.outcomes = {"confirm": confirm, "broadcast": broadcast}
        self.balance = balance
        self.relays_confirm = relays_confirm
        self.observer: Callable[[str], None] | None = None

    def _egress(self, call: str, transaction: dict[str, Any] | None) -> None:
        if self.observer is not None:
            self.observer(call)
        retained = any(same_signed_bytes(stored.get("signedTransaction"), transaction)
                       for stored in stored_journals(self.work / "store"))
        _append(self.log, {"call": call, "boot": self.boot, "transaction": transaction, "retainedAtEgress": retained})

    def check_balance(self) -> str:
        return self.balance

    def confirm(self, transaction: dict[str, Any]) -> dict[str, Any]:
        self._egress("confirm", transaction)
        if self.outcomes["confirm"] != "valid":
            raise CallFailed(self.outcomes["confirm"])
        return generator.validity_response(transaction)

    def broadcast(self, response: dict[str, Any]) -> None:
        self._egress("broadcast", response["response"]["data"]["transaction"])
        if self.outcomes["broadcast"] != "accepted":
            raise CallFailed(self.outcomes["broadcast"])

    def read(self, tx_hash: str) -> dict[str, Any]:
        """getTxByHash: the executed record once a submission reached the
        chain. A broadcast that failed in transport may still have arrived;
        one the node refused did not execute."""
        executing = {"broadcast", "confirm"} if self.relays_confirm else {"broadcast"}
        if self.outcomes["broadcast"] in oracle.CALL_REFUSALS:
            executing.discard("broadcast")
        if any(entry["call"] in executing for entry in read_lines(self.log)):
            return generator.found(generator.record("confirmed"), authenticated=True)
        return dict(generator.NOT_FOUND)


class PayerHandler:
    """The payer's pay-dem handler for one phase, from signed transfer to its
    PC-4 result. The journal holds the retained transfer, the signed
    transaction itself, the start (`boot`) that wrote it, its progress, the
    confirm's validity response and any terminal result."""

    def __init__(self, store: Store, node: Node, boot: str, *, crash_at: str | None = None,
                 mutant: str | None = None, exit_on_crash: bool = False,
                 job_id: str = generator.JOB_ID, phase_index: int = generator.PHASE_INDEX):
        self.store, self.node, self.boot = store, node, boot
        self.crash_at, self.mutant, self.exit_on_crash = crash_at, mutant, exit_on_crash
        self.job_id, self.phase_index = job_id, phase_index
        self.journal = journal_name(job_id, phase_index)

    def _crash(self, point: str) -> None:
        if point == self.crash_at:
            if self.exit_on_crash:
                os._exit(CRASH_EXIT)
            raise Crashed(point)

    def _save(self, entry: dict[str, Any], **changes: Any) -> dict[str, Any]:
        """Write the journal only over the state `entry` was read as, so a
        slow or failed path never overwrites newer progress or a result."""
        with self.store.locked(self.journal):
            current = self.store.read(self.journal)
            if current is not None and (current["progress"], current.get("result")) != (
                entry["progress"], entry.get("result")
            ):
                raise Conflict(current["progress"])
            self.store.write(self.journal, dict(entry, **changes))
        return self.store.read(self.journal)

    def _retained_elsewhere(self, tx_hash: str) -> list[dict[str, Any]]:
        """The phases whose stored journal already retains this hash."""
        if self.mutant == "no-cross-phase-index":
            # The wrong handler sees only the phase in front of it.
            return []
        return [
            {"jobId": other["retainedTransfer"]["jobId"], "phaseIndex": other["retainedTransfer"]["phaseIndex"]}
            for other in self.store.journals()
            if other["retainedTransfer"]["txHash"] == tx_hash
            and (other["retainedTransfer"]["jobId"], other["retainedTransfer"]["phaseIndex"])
            != (self.job_id, self.phase_index)
        ]

    def _state(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Gate state derived from the journal as read back from storage."""
        restarted = entry["boot"] != self.boot
        if self.mutant == "restart-from-progress":
            # The wrong handler trusts the progress it saved and never asks
            # whether a start has fallen since the retention.
            restarted = False
        return {
            "retentionDurable": True,
            "restartedSinceRetention": restarted,
            "broadcastState": entry["progress"],
        }

    def _permits(self, request: str, entry: dict[str, Any]) -> bool:
        confirm_response = entry.get("confirmResponse") if request != "confirm-retained" else None
        protocol_input = {
            "phase": generator.phase(jobId=self.job_id, phaseIndex=self.phase_index),
            "pinnedNodeConfigured": True,
            "appliedPaymentAuthorityConfigured": True,
            "gasFeeSeparationUnscheduled": True,
            "signedTransaction": entry["signedTransaction"],
            "retainedTransfer": entry["retainedTransfer"],
            "hashRetainedForOtherPhases": self._retained_elsewhere(entry["retainedTransfer"]["txHash"]),
            **self._state(entry),
            "confirmResponse": confirm_response,
            "request": request,
            "validityResponse": confirm_response,
        }
        return oracle.broadcast_gate(protocol_input, NO_GUARD_REMOVED)[0] == "pass"

    def _outcome(self, call: str, outcome: str, at_call: dict[str, Any]) -> dict[str, Any]:
        expected, want = oracle.egress_outcome(
            {**self._state(at_call), "call": call, "outcome": outcome}, NO_GUARD_REMOVED,
        )
        result = {"expected": expected, **want}
        if want["errorClass"] == "permanent":
            self._save(self.store.read(self.journal), result=result)
        return result

    def _classify(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Re-read the retained hash: the only step after a possible egress."""
        read = self.node.read(entry["retainedTransfer"]["txHash"])
        seen = read["state"] == "found"
        expected, want = oracle.classify({
            "network": generator.NETWORK,
            "retainedTransfer": entry["retainedTransfer"],
            "statusIndex": "included" if seen else "unknown",
            "inclusionObservation": generator.INCLUDED_AT_BLOCK if seen else None,
            "recordRead": read,
        }, NO_GUARD_REMOVED)
        return {"expected": expected, **want}

    def pay(self, transaction: dict[str, Any]) -> dict[str, Any]:
        """Retain `transaction` as the phase's one transfer unless a start
        already retained one. The retention is a create-if-absent under the
        journal lock: a start that finds a retention continues it and never
        retains or sends another transfer for the phase (DEM-1)."""
        if self.mutant == "blind-first-retention":
            # The wrong handler reads "no journal", then writes it unlocked.
            refused = self._retain(transaction) if self.store.read(self.journal) is None else None
        else:
            with self.store.locked(self.journal):
                refused = self._retain(transaction) if self.store.read(self.journal) is None else None
        return self.advance() if refused is None else refused

    def _retain(self, transaction: dict[str, Any]) -> dict[str, Any] | None:
        if self._retained_elsewhere(transaction["hash"]):
            # DEM-1: a hash retained for another phase is never retained
            # or sent for this one; nothing leaves for this phase.
            return {"expected": "fail", "broadcastPermitted": False, "cause": "hash-retained-for-another-phase"}
        entry = {
            "boot": self.boot,
            "progress": "never-broadcast",
            "retainedTransfer": generator.retained(jobId=self.job_id, phaseIndex=self.phase_index,
                                                   txHash=transaction["hash"]),
            "signedTransaction": transaction,
            "confirmResponse": None,
            "result": None,
        }
        if self.mutant == "journal-after-confirm":
            # The wrong handler journals only once confirm has returned.
            self._crash("before-confirm")
            response = self.node.confirm(transaction)
            self._crash("after-confirm")
            entry.update(progress="confirm-returned", confirmResponse=response)
        self._crash("before-retain")
        self.store.write(self.journal, entry)
        self._crash("after-retain")
        return None

    def _sending(self, entry: dict[str, Any], progress: str) -> dict[str, Any]:
        """Write ahead: the journal reads as possibly sent before the call, so
        an interruption of any kind, not only a returned failure, leaves the
        call recorded as one that may have carried the bytes (DEM-6)."""
        if self.mutant == "progress-after-call":
            return entry
        return self._save(entry, progress=progress)

    def advance(self) -> dict[str, Any]:
        """Continue the phase from what the journal holds. After a restart
        the gate refuses every call, so only the re-read remains."""
        entry = self.store.read(self.journal)
        if entry is None:
            return {"expected": None, "nothingRetained": True}
        if entry.get("result") is not None:
            # A terminal session is never reopened.
            return entry["result"]
        if entry["progress"] == "never-broadcast":
            if not self._permits("confirm-retained", entry):
                return self._classify(entry)
            if self.node.check_balance() != "sufficient":
                return self._outcome("pre-egress-check", "insufficient-balance", entry)
            entry = self._sending(entry, "confirm-sent-interrupted")
            self._crash("before-confirm")
            try:
                response = self.node.confirm(entry["signedTransaction"])
            except CallFailed as failure:
                if entry["progress"] == "never-broadcast":
                    self._save(entry, progress="confirm-sent-interrupted")
                return self._outcome("confirm", failure.outcome, entry)
            self._crash("after-confirm")
            entry = self._save(entry, progress="confirm-returned", confirmResponse=response)
            self._crash("after-confirm-journal")
        if entry["progress"] == "confirm-returned":
            if not self._permits("broadcast-retained", entry):
                if entry["boot"] == self.boot:
                    self._save(entry, progress="maybe-broadcast")
                    return self._outcome("broadcast", "refused-by-dem1", entry)
                return self._classify(entry)
            entry = self._sending(entry, "maybe-broadcast")
            self._crash("before-broadcast")
            try:
                self.node.broadcast(entry["confirmResponse"])
            except CallFailed as failure:
                if entry["progress"] == "confirm-returned":
                    self._save(entry, progress="maybe-broadcast")
                return self._outcome("broadcast", failure.outcome, entry)
            self._crash("after-broadcast")
            if entry["progress"] == "confirm-returned":
                entry = self._save(entry, progress="maybe-broadcast")
            self._crash("after-broadcast-journal")
        return self._classify(entry)


class Payee:
    """The payee's delivery check for the default transfer. Its history is
    the snapshot of its admission index; it adds an admission with a write
    conditional on that snapshot's revision before it delivers. The index is
    created empty once, by `provision`; a check never creates it. A missing
    or malformed index, or one that lacks a tuple already delivered, is no
    snapshot, so the check is `error` and nothing is delivered. Delivery is
    idempotent on `(txHash, jobId, phaseIndex)`: a repeated check for an
    admitted tuple returns `pass` and delivers nothing again."""

    def __init__(self, store: Store, work: Path, boot: str, *, crash_at: str | None = None,
                 mutant: str | None = None, exit_on_crash: bool = False):
        self.store, self.work, self.boot = store, Path(work), boot
        self.crash_at, self.mutant, self.exit_on_crash = crash_at, mutant, exit_on_crash
        self.sink = self.work / DELIVERIES

    def _crash(self, point: str) -> None:
        if point == self.crash_at:
            if self.exit_on_crash:
                os._exit(CRASH_EXIT)
            raise Crashed(point)

    def provision(self) -> None:
        """Create the empty index, once, before the payee's first check."""
        with self.store.locked(INDEX):
            if self.store.read(INDEX) is None:
                self.store.write(INDEX, {"revision": 0, "admissions": []})

    def delivered(self) -> set[tuple[str, str, int]]:
        return {delivery_key(entry) for entry in read_lines(self.sink)}

    def snapshot(self) -> dict[str, Any] | None:
        """The index as read for this check, or None when it cannot be one."""
        try:
            index = self.store.read(INDEX)
        except ValueError:
            return None
        if index is None and self.mutant == "empty-index-when-missing":
            # The wrong payee treats a lost index as an empty history.
            return {"revision": 0, "admissions": []}
        if not (isinstance(index, dict) and set(index) == {"revision", "admissions"}
                and isinstance(index["revision"], int) and not isinstance(index["revision"], bool)
                and isinstance(index["admissions"], list) and all(
                    isinstance(admission, dict) and isinstance(admission.get("txRef"), dict)
                    for admission in index["admissions"])):
            return None
        indexed = {delivery_key({"txHash": admission["txRef"].get("txHash"), **admission})
                   for admission in index["admissions"]}
        if self.mutant != "empty-index-when-missing" and not self.delivered() <= indexed:
            # Rolled back or replaced: it no longer holds a delivered tuple.
            return None
        return index

    def check(self, job_id: str, phase_index: int, snapshot: dict[str, Any] | None) -> str:
        protocol_input = generator.deliver("delivery", "pass", "DEM-7", [], "")["protocolInput"]
        protocol_input["phase"] = generator.phase(jobId=job_id, phaseIndex=phase_index)
        protocol_input["consumerAdmissions"] = [] if snapshot is None else snapshot["admissions"]
        protocol_input["admissionIndex"] = snapshot
        return oracle.admit_for_delivery(protocol_input, NO_GUARD_REMOVED)[0]

    def _commit(self, based_on: dict[str, Any], admission: dict[str, Any]) -> None:
        with self.store.locked(INDEX):
            current = self.snapshot()
            if current is None:
                raise Conflict(None)
            if current["revision"] != based_on["revision"] and self.mutant != "no-conditional-write":
                raise Conflict(current["revision"])
            self.store.write(INDEX, {"revision": current["revision"] + 1,
                                     "admissions": current["admissions"] + [admission]})

    def _deliver_once(self, key: tuple[str, str, int]) -> None:
        """The delivery effect, idempotent on its key: under the sink's lock
        it happens only when no earlier delivery carries the key."""
        with _Lock(self.work / f".{DELIVERIES}.lock"):
            if self.mutant == "deliver-every-check" or key not in self.delivered():
                _append(self.sink, {"txHash": key[0], "jobId": key[1], "phaseIndex": key[2], "boot": self.boot})

    def deliver(self, job_id: str, phase_index: int = generator.PHASE_INDEX, *,
                between: Callable[[], None] | None = None) -> str:
        while True:
            snapshot = self.snapshot()
            verdict = self.check(job_id, phase_index, snapshot)
            if verdict != "pass":
                return verdict
            admission = generator._admission({"jobId": job_id, "phaseIndex": phase_index})
            if admission not in snapshot["admissions"]:
                if between is not None:
                    between, run = None, between
                    run()
                self._crash("before-admission-write")
                try:
                    self._commit(snapshot, admission)
                except Conflict:
                    continue
                self._crash("after-admission-write")
            self._deliver_once((admission["txRef"]["txHash"], job_id, phase_index))
            self._crash("after-delivery")
            return "pass"


def delivery_key(entry: dict[str, Any]) -> tuple[str, str, int]:
    return (entry.get("txHash"), entry.get("jobId"), entry.get("phaseIndex"))


def payer(work: Path, boot: str, *, crash_at=None, mutant=None, exit_on_crash=False,
          job_id: str = generator.JOB_ID, **node) -> PayerHandler:
    store_dir = Path(work) / "store"
    store = (MemoryStore(store_dir) if mutant == "process-local-journal"
             else Store(store_dir, fsync=mutant != "no-fsync", parent_fsync=mutant != "no-parent-fsync"))
    return PayerHandler(store, Node(work, boot, **node), boot, crash_at=crash_at, mutant=mutant,
                        exit_on_crash=exit_on_crash, job_id=job_id)


def payee(work: Path, boot: str, *, crash_at=None, mutant=None, exit_on_crash=False) -> Payee:
    store_dir = Path(work) / "payee-store"
    if mutant == "process-local-index":
        # The wrong payee keeps its index in memory, provisioned at each start.
        made = Payee(MemoryStore(store_dir), work, boot, crash_at=crash_at, mutant=mutant,
                     exit_on_crash=exit_on_crash)
        made.provision()
        return made
    return Payee(Store(store_dir), work, boot, crash_at=crash_at, mutant=mutant, exit_on_crash=exit_on_crash)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("pay", "provision", "deliver"))
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--boot", required=True)
    parser.add_argument("--crash")
    parser.add_argument("--mutant", choices=PAYER_MUTANTS + PAYEE_MUTANTS)
    parser.add_argument("--job")
    parser.add_argument("--confirm", default="valid")
    parser.add_argument("--broadcast", default="accepted")
    parser.add_argument("--balance", default="sufficient")
    parser.add_argument("--relays-confirm", action="store_true")
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    if args.command == "pay":
        handler = payer(args.work, args.boot, crash_at=args.crash, mutant=args.mutant, exit_on_crash=True,
                        job_id=args.job or generator.JOB_ID, confirm=args.confirm, broadcast=args.broadcast,
                        balance=args.balance, relays_confirm=args.relays_confirm)
        result = handler.pay(generator.signed())
    elif args.command == "provision":
        payee(args.work, args.boot).provision()
        result = {"provisioned": True}
    else:
        result = {"verdict": payee(args.work, args.boot, crash_at=args.crash, mutant=args.mutant,
                                   exit_on_crash=True).deliver(args.job)}
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
