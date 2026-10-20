"""A storage-backed reference of the DACS-4 §9.5.9 pay-dem payer journal
(DEM-1, DEM-5, DEM-6) and the payee's DEM-7 admission index.

Every decision is the corpus oracle's own (`test_pay_dem_execution_vectors`):
`pre-sign-gate`, `broadcast-gate`, `classify-egress-outcome`,
`classify-execution`, `resume-phase` and `admit-for-delivery`. Their state
inputs (`retentionDurable`, `restartedSinceRetention`, `broadcastState`,
`signedTransaction`, the presented history, `admissionIndex` and a DEM-4
failure proof) are derived from what this module reads back from storage,
never from process-local state. The binding inputs are the rail's pinned
network and the payer's per-network binding configuration. A re-read's
applied-payment authority, FV-5 result and bft-final inclusion come from
their own sources, never from the node that served the record. DEM-4's
authentication is both halves: FV's bft-final inclusion observation of the
transaction and FV-5's signed execution result for the block it names, which
the oracle verifies against the rail's signed profile and the payer's own
trust; a DEM-4 proof stores both verbatim, and a resume verifies both again.
`test_pay_dem_crash_restart` stops it on both sides of every transition and
restarts it from storage. Each `--mutant` is a wrong handler or payee that
the harness must catch.

`retentionDurable` is the one state input not read back: it is `True`
because `Store.write` returns only once the journal, its directory and every
directory it created are fsynced, which `test_pay_dem_crash_restart`
witnesses by the order of fsync calls before the first egress. A delivery
record reaches stable storage the same way, file and then directory entry,
before `deliver` returns. A record a decision trusts is flushed before it is
trusted, since an interrupted start can leave one that a restart can read but
a power loss can still remove: `Store.read` fsyncs the document's directory,
the payee fsyncs an existing delivery record and its directory entry before
it counts as delivered, and `durable_directories` flushes the entry of the
deepest directory that already exists.

Whether a start has fallen since the retention compares the start recorded
in the journal with this start's identifier: 128 random bits the handler
draws for each start, which no loss or rollback of its store can make it
repeat; `--boot` only labels a process's egress, so a restarted process that
repeats it is still a restart (DEM-6). A stored terminal failure is never
reopened: when its proof no longer verifies, the re-read is post-terminal and
never returns success.

Run as a script, one process per start:
    pay_dem_reference_handler.py pay --work DIR --boot ID [--job JOB] [--crash POINT] [--mutant M]
        [--record-status S] [--node-claims-authentication] [--fv5 SOURCE] [--executed S] [--rail-network N]
    pay_dem_reference_handler.py provision --work DIR --boot ID
    pay_dem_reference_handler.py deliver --work DIR --boot ID --job JOB [--crash POINT] [--mutant M]
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import secrets
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
# Only the wrong handler that counts its starts keeps this document.
STARTS = "starts.json"
# One lock for every phase's retention, so the create-if-absent and the
# cross-phase hash check are one step for the whole store.
RETENTION_LOCK = "retention"
PAYER_MUTANTS = ("process-local-journal", "journal-after-confirm", "restart-from-progress", "no-fsync",
                 "no-cross-phase-index", "no-parent-fsync", "blind-first-retention", "progress-after-call",
                 "network-from-binding", "node-authenticates-read", "failure-not-journaled",
                 "per-phase-retention-lock", "unverified-fv5-result", "fv5-result-alone",
                 "caller-start-id", "terminal-reopens", "counter-reset-when-missing")
PAYEE_MUTANTS = ("process-local-index", "no-conditional-write", "empty-index-when-missing",
                 "deliver-every-check", "no-sink-parent-fsync", "trust-unflushed-record")
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


def durable_directories(root: Path, *, parent_fsync: bool = True) -> None:
    """Create `root` and each missing ancestor, fsyncing each new directory's
    parent, so every entry on the path survives a crash. The deepest
    directory that already exists can be the last one an interrupted start
    created before it fsynced the parent, so that entry is flushed first."""
    missing = []
    path = Path(root).absolute()
    while not path.exists():
        missing.append(path)
        path = path.parent
    if parent_fsync:
        _fsync_directory(path.parent)
    for path in reversed(missing):
        path.mkdir(exist_ok=True)
        if parent_fsync:
            # fsync(2): flushing a file does not flush the entry naming it.
            _fsync_directory(path.parent)


class Store:
    """One JSON document per name. A write goes to a temporary file that is
    flushed and fsynced, is renamed over the name, and then the directory is
    fsynced, so the document survives a crash at any later step. A directory
    the store creates is fsynced in its parent before the store is used, so a
    new store's own entry survives too. A read fsyncs the directory before
    the document is returned: a start that stopped between the rename and the
    directory fsync leaves a document a later start can read but a power loss
    can still remove. Member order is kept, so stored signed bytes read back
    unchanged."""

    def __init__(self, root: Path, *, fsync: bool = True, parent_fsync: bool = True, flush_reads: bool = True):
        self.root = Path(root)
        self.fsync = fsync
        self.flush_reads = flush_reads
        durable_directories(self.root, parent_fsync=fsync and parent_fsync)

    def write(self, name: str, value: Any, *, between: Callable[[], None] | None = None) -> None:
        """`between` runs after the rename and before the directory fsync."""
        temporary = self.root / f".{name}.tmp"
        with open(temporary, "wb") as handle:
            handle.write(json.dumps(value).encode("utf-8"))
            handle.flush()
            if self.fsync:
                os.fsync(handle.fileno())
        os.replace(temporary, self.root / name)
        if between is not None:
            between()
        if self.fsync:
            _fsync_directory(self.root)

    def read(self, name: str) -> Any:
        try:
            stored = (self.root / name).read_bytes()
        except FileNotFoundError:
            return None
        if self.fsync and self.flush_reads:
            # The file was fsynced before its rename; this makes the rename
            # that named it durable before anything acts on it.
            _fsync_directory(self.root)
        return json.loads(stored)

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

    def write(self, name: str, value: Any, **_: Any) -> None:
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


def _append(path: Path, entry: dict[str, Any], *, parent_fsync: bool = True,
            crash: Callable[[str], None] | None = None) -> None:
    """An effect outside the handler: it has happened once this returns. The
    line is fsynced, and then the directory that names the file, after every
    append, as `Store` does for its documents. `crash` is called before each
    fsync with `fsync` or `directory-fsync`."""
    durable_directories(path.parent, parent_fsync=parent_fsync)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
        handle.flush()
        if crash is not None:
            crash("fsync")
        os.fsync(handle.fileno())
    if crash is not None:
        crash("directory-fsync")
    if parent_fsync:
        _fsync_directory(path.parent)


def flush_existing(path: Path) -> None:
    """Put a file that an interrupted start may have left unflushed, and the
    directory entry naming it, on stable storage; nothing when it is absent."""
    try:
        handle = os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        return
    try:
        os.fsync(handle)
    finally:
        os.close(handle)
    _fsync_directory(path.parent)


def counted_start(store: Store) -> str:
    """The wrong start identifier: a counter in the store, which reads a lost
    counter as zero and a restored older copy as its older count, so an
    earlier start's identifier comes back."""
    with store.locked(STARTS):
        number = (store.read(STARTS) or {"starts": 0})["starts"] + 1
        store.write(STARTS, {"starts": number})
    return f"start-{number}"


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
    `relays_confirm`, a node that received the confirm submits it too. The
    executed record's status is `record_status`; a node that
    `claims_authentication` adds its own FV-5 flag and applied-payment claims
    to the plain read, which the handler never takes from it."""

    def __init__(self, work: Path, boot: str, *, confirm: str = "valid", broadcast: str = "accepted",
                 balance: str = "sufficient", relays_confirm: bool = False, record_status: str = "confirmed",
                 claims_authentication: bool = False):
        self.work = Path(work)
        self.log = self.work / "egress.jsonl"
        self.boot = boot
        self.outcomes = {"confirm": confirm, "broadcast": broadcast}
        self.balance = balance
        self.relays_confirm = relays_confirm
        self.record_status = record_status
        self.claims_authentication = claims_authentication
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
        """getTxByHash, a plain RPC read: the executed record once a
        submission reached the chain. A broadcast that failed in transport
        may still have arrived; one the node refused did not execute."""
        executing = {"broadcast", "confirm"} if self.relays_confirm else {"broadcast"}
        if self.outcomes["broadcast"] in oracle.CALL_REFUSALS:
            executing.discard("broadcast")
        if any(entry["call"] in executing for entry in read_lines(self.log)):
            if self.claims_authentication:
                return dict(generator.found(generator.record(self.record_status)), authenticated=True)
            return {"state": "found", "record": generator.record(self.record_status)}
        return dict(generator.NOT_FOUND)


class AppliedAuthority:
    """The applied-payment authority the payer's binding configures for one
    network (DEMOS-MAPPING §A.2), a source separate from any node: it
    authenticates the committed balance change of the transaction's apply,
    from the executed status it observed itself (`executed`, the scenario's
    state), which a failed apply rolls back, whatever any node serves."""

    def __init__(self, network: dict[str, str], executed: str = "confirmed"):
        self.network, self.executed = dict(network), executed

    def attest(self, record: dict[str, Any]) -> dict[str, Any]:
        state = generator.APPLIED if self.executed == "confirmed" else generator.ROLLED_BACK
        read = generator.found(record, state=state, network=self.network)
        return {"appliedTransferAuthenticated": read["appliedTransferAuthenticated"],
                "appliedTransfer": read["appliedTransfer"]}


FV5_SOURCES = ("none", "policy", "forged", "unfinalized")
RECORD_STATUSES = ("confirmed", "failed")


class Fv5Authority:
    """The independent sources a DEM-4 proof reads for the rail's network;
    never the node that served the record. FV-5's execution-result source
    answers with a signed result for the record it observed itself
    (`observes`, the scenario's executed status, whatever any node serves)
    at the observed inclusion block, and FV's `bft-final` source with the
    transaction's inclusion observation. `policy` signs with the authorities
    the payer's FV-5 policy trusts; `forged` signs under the same authority
    names with other keys; `unfinalized` signs with the policy's keys for a
    block no BFT certificate finalizes. The handler never takes their word:
    the oracle verifies both against the payer's own trust."""

    def __init__(self, source: str = "none", observes: str = "confirmed"):
        if source not in FV5_SOURCES or observes not in RECORD_STATUSES:
            raise ValueError((source, observes))
        self.source, self.observes = source, observes

    def result(self, tx_hash: str, network: dict[str, str], block: str) -> dict[str, Any] | None:
        if self.source == "none" or tx_hash != generator.TX_HASH:
            return None
        keys = generator.FORGED_FV5_SIGNERS if self.source == "forged" else generator.FV5_SIGNERS
        return generator.execution_result(generator.record(self.observes), network=network, block=block, keys=keys)

    def inclusion(self, tx_hash: str, network: dict[str, str]) -> dict[str, Any] | None:
        """FV's bft-final source is separate from FV-5's result source: it
        answers without one, since every final verdict (success included)
        needs the inclusion. `unfinalized` serves a block no certificate
        finalizes."""
        if tx_hash != generator.TX_HASH:
            return None
        return generator.inclusion_proof(network=network, certified=self.source != "unfinalized")


def binding_network(entry: dict[str, Any]) -> dict[str, str]:
    return {key: entry[key] for key in ("networkId", "genesisHash")}


class PayerHandler:
    """The payer's pay-dem handler for one phase, from signed transfer to its
    PC-4 result. The journal holds the retained transfer, the signed
    transaction itself, the start that wrote it, its progress, the confirm's
    validity response, any terminal result and, with a DEM-4 result, its
    failure proof. Each handler is one start: its identifier is 128 random
    bits drawn for the start, which needs no stored state, so no loss or
    rollback of the store repeats it; it is never taken from the caller,
    whose `boot` only labels its egress.

    `rail_network` is the pinned RailDefinition's
    `consumerFinalityProfile.settlement` network; `bindings` is the payer's
    Demos binding configuration, one entry per network. The gates find the
    entry for the rail's network themselves, and the re-read takes the
    applied-payment authority that entry configures and the FV-5 result and
    bft-final inclusion from their own sources, never from the node's reply.
    `fv5_policy` is the FV-5 execution-result policy the payer trusts
    (authority keys and threshold), and `finality_trust` its validator set,
    observation authorities and clock, from its configuration, never from a
    source or a node; `finality_profile` is the rail's signed settlement
    profile."""

    def __init__(self, store: Store, node: Node, boot: str, *, crash_at: str | None = None,
                 mutant: str | None = None, exit_on_crash: bool = False,
                 job_id: str = generator.JOB_ID, phase_index: int = generator.PHASE_INDEX,
                 rail_network: dict[str, str] = generator.NETWORK,
                 bindings: list[dict[str, Any]] | None = None, fv5: Fv5Authority | None = None,
                 fv5_policy: dict[str, Any] = generator.FV5_POLICY,
                 finality_profile: dict[str, Any] = generator.FINALITY_PROFILE,
                 finality_trust: dict[str, Any] = generator.FINALITY_TRUST):
        self.store, self.node, self.boot = store, node, boot
        self.crash_at, self.mutant, self.exit_on_crash = crash_at, mutant, exit_on_crash
        # DEM-6: an identifier no earlier start used, whatever happened to the
        # store. The wrong handlers take the caller's value, which a restarted
        # process can repeat, or count starts in the store, which a lost or
        # restored counter repeats.
        if mutant == "caller-start-id":
            self.start = boot
        elif mutant == "counter-reset-when-missing":
            self.start = counted_start(store)
        else:
            self.start = secrets.token_hex(16)
        self.job_id, self.phase_index = job_id, phase_index
        self.journal = journal_name(job_id, phase_index)
        self.bindings = [generator.binding_entry()] if bindings is None else bindings
        self.rail_network = dict(rail_network)
        if mutant == "network-from-binding" and self.bindings:
            # The wrong handler keeps one binding and takes the phase's
            # network from it, whatever network the rail settles on.
            self.rail_network = binding_network(self.bindings[0])
        self.fv5 = Fv5Authority() if fv5 is None else fv5
        self.fv5_policy = fv5_policy
        self.finality = {"finalityProfile": finality_profile, "finalityTrust": finality_trust}
        # The wrong handlers take a result's signatures on trust, take the
        # signed result alone for DEM-4 without its bft-final inclusion,
        # (the earlier draft) take a flag for FV-5 and store a label as its
        # proof, or re-derive an ended session from a re-read alone.
        self.off = {"unverified-fv5-result": frozenset({"fv5-result-signed"}),
                    "fv5-result-alone": frozenset({"failure-requires-bft-final-inclusion"}),
                    "node-authenticates-read": frozenset({"fv5-authentication-is-a-signed-result"}),
                    "terminal-reopens": frozenset({"terminal-never-reopens"}),
                    }.get(mutant, NO_GUARD_REMOVED)

    def _binding_input(self) -> dict[str, Any]:
        return {"railNetwork": self.rail_network, "demosBinding": self.bindings}

    def _applied_authority(self) -> AppliedAuthority | None:
        """The authority the binding entry for the rail's network configures;
        it observes the same chain state as the FV-5 source, never the node."""
        for entry in self.bindings:
            if binding_network(entry) == self.rail_network and isinstance(entry.get("appliedPaymentAuthority"), dict):
                return AppliedAuthority(binding_network(entry["appliedPaymentAuthority"]), self.fv5.observes)
        return None

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
        """Gate state derived from the journal as read back from storage. A
        journal that names no start (one written before starts were minted)
        reads as written by another start."""
        restarted = entry.get("start") != self.start
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
            **self._binding_input(),
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
            self._crash("before-refusal-result")
            self._save(self.store.read(self.journal), result=result)
            self._crash("after-refusal-result")
        return result

    def _read(self, tx_hash: str) -> dict[str, Any]:
        """The re-read as the handler composes it: only the node's plain
        record and status, the build attestation its binding holds for that
        node, the applied-payment authority, the FV-5 source's signed result
        for the record it observed at the observed inclusion block, and FV's
        bft-final inclusion of the transaction, all of which the oracle
        verifies. Whatever the node says about its own authentication is
        dropped."""
        served = self.node.read(tx_hash)
        if self.mutant == "node-authenticates-read":
            # The wrong handler trusts the node's word for FV-5 and payment.
            return served
        if served.get("state") != "found":
            return {"state": served.get("state")}
        record = served.get("record")
        read = {"state": "found", "nodeBuild": dict(generator.PINNED_BUILD), "record": record}
        authority = self._applied_authority()
        if authority is not None and isinstance(record, dict):
            read.update(authority.attest(record))
        result = self.fv5.result(tx_hash, self.rail_network, generator.INCLUDED_AT_BLOCK["blockId"])
        if result is not None:
            read["executionResult"] = result
        inclusion = self.fv5.inclusion(tx_hash, self.rail_network)
        if inclusion is not None:
            read["inclusionProof"] = inclusion
        return read

    def _classify_input(self, entry: dict[str, Any], read: dict[str, Any]) -> dict[str, Any]:
        seen = read["state"] == "found"
        return {
            "railNetwork": self.rail_network,
            **self.finality,
            "fv5Policy": self.fv5_policy,
            "retainedTransfer": entry["retainedTransfer"],
            "statusIndex": "included" if seen else "unknown",
            "inclusionObservation": generator.INCLUDED_AT_BLOCK if seen else None,
            "recordRead": read,
        }

    def _classify(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Re-read the retained hash: the only step after a possible egress.
        A DEM-4 failure is terminal: its record, FV-5's signed execution
        result and FV's bft-final inclusion observation exactly as received,
        its classification and inclusion block are journaled with the result
        in one conditional write before `permanent` is returned. Success is
        never cached: each read re-derives it from the chain and the
        authority."""
        read = self._read(entry["retainedTransfer"]["txHash"])
        protocol_input = self._classify_input(entry, read)
        expected, want = oracle.classify(protocol_input, self.off)
        result = {"expected": expected, **want}
        if expected == "fail" and self.mutant != "failure-not-journaled":
            proof = {
                "classification": "permanent",
                # Only the flag-trusting wrong handler reaches here without one.
                "authentication": read.get("executionResult", "fv5-bft-final"),
                "inclusionProof": read.get("inclusionProof"),
                "inclusionBlock": protocol_input["inclusionObservation"]["blockNumber"],
                "record": read["record"],
            }
            self._crash("before-failure-proof")
            self._save(entry, result=result, failureProof=proof)
            self._crash("after-failure-proof")
        return result

    def _resume(self, entry: dict[str, Any]) -> dict[str, Any]:
        """DEM-4/DEM-6: a terminal failure is never reopened. Its retained
        proof is reused only while its stored FV-5 result and bft-final
        inclusion still verify against the payer's own trust, name one block
        and still bind the retained transfer; otherwise the retained hash is
        re-read, a post-terminal read that changes no session state: it
        writes nothing, and the oracle never makes it a success."""
        read = self._read(entry["retainedTransfer"]["txHash"])
        expected, want = oracle.resume(
            dict(self._classify_input(entry, read), retainedFailureProof=entry["failureProof"]), self.off,
        )
        return {"expected": expected, **want}

    def pay(self, transaction: dict[str, Any]) -> dict[str, Any]:
        """Retain `transaction` as the phase's one transfer unless a start
        already retained one. The retention is a create-if-absent under the
        store-wide retention lock, which also covers the check that no other
        phase retains the hash: a start that finds a retention continues it
        and never retains or sends another transfer for the phase, and two
        phases never both retain one hash (DEM-1). With nothing retained, the
        DEM-1 binding check runs first and a refusal sends nothing."""
        if self.mutant == "blind-first-retention":
            # The wrong handler reads "no journal", then writes it unlocked.
            refused = self._retain(transaction) if self.store.read(self.journal) is None else None
        else:
            lock = self.journal if self.mutant == "per-phase-retention-lock" else RETENTION_LOCK
            with self.store.locked(lock):
                refused = self._retain(transaction) if self.store.read(self.journal) is None else None
        return self.advance() if refused is None else refused

    def _retain(self, transaction: dict[str, Any]) -> dict[str, Any] | None:
        expected, want = oracle.pre_sign_gate(
            {"phase": generator.phase(jobId=self.job_id, phaseIndex=self.phase_index), **self._binding_input()},
            NO_GUARD_REMOVED,
        )
        if expected != "pass":
            # DEM-1/RAV-R4: no binding for the rail's network; nothing is
            # retained or sent, and a later start checks again.
            return {"expected": expected, **want}
        if self._retained_elsewhere(transaction["hash"]):
            # DEM-1: a hash retained for another phase is never retained
            # or sent for this one; nothing leaves for this phase.
            return {"expected": "fail", "broadcastPermitted": False, "cause": "hash-retained-for-another-phase"}
        entry = {
            "start": self.start,
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
            # A terminal session is never reopened: a refusal before any
            # egress stands, and a DEM-4 failure stands on its proof.
            return entry["result"] if entry.get("failureProof") is None else self._resume(entry)
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
                if entry.get("start") == self.start:
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
                                     "admissions": current["admissions"] + [admission]},
                             between=lambda: self._crash("before-admission-directory-fsync"))

    def _deliver_once(self, key: tuple[str, str, int]) -> None:
        """The delivery effect, idempotent on its key: under the sink's lock
        it happens only when no earlier delivery carries the key. An earlier
        record counts only once it is on stable storage: a start that stopped
        before fsyncing it or its directory entry leaves one this check can
        read but a power loss can remove, while the admission stays durable."""
        with _Lock(self.work / f".{DELIVERIES}.lock"):
            if self.mutant != "trust-unflushed-record":
                flush_existing(self.sink)
            if self.mutant == "deliver-every-check" or key not in self.delivered():
                # The wrong payee leaves the new record's directory entry unflushed.
                _append(self.sink, {"txHash": key[0], "jobId": key[1], "phaseIndex": key[2], "boot": self.boot},
                        parent_fsync=self.mutant != "no-sink-parent-fsync",
                        crash=lambda step: self._crash(f"before-delivery-{step}"))

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


RAIL_NETWORKS = {"mainnet": generator.NETWORK, "testnet": generator.OTHER_NETWORK}


def payer(work: Path, boot: str, *, crash_at=None, mutant=None, exit_on_crash=False,
          job_id: str = generator.JOB_ID, rail_network: dict[str, str] = generator.NETWORK,
          bindings: list[dict[str, Any]] | None = None, fv5: str = "none", executed: str | None = None,
          **node) -> PayerHandler:
    """`executed` is the scenario's executed status of the transfer, which
    the independent sources observe; by default the status the node serves
    at this start, so a scenario with a lying or stale node sets it."""
    executed = node.get("record_status", "confirmed") if executed is None else executed
    store_dir = Path(work) / "store"
    store = (MemoryStore(store_dir) if mutant == "process-local-journal"
             else Store(store_dir, fsync=mutant != "no-fsync", parent_fsync=mutant != "no-parent-fsync"))
    return PayerHandler(store, Node(work, boot, **node), boot, crash_at=crash_at, mutant=mutant,
                        exit_on_crash=exit_on_crash, job_id=job_id, rail_network=rail_network,
                        bindings=bindings, fv5=Fv5Authority(fv5, executed))


def payee(work: Path, boot: str, *, crash_at=None, mutant=None, exit_on_crash=False) -> Payee:
    store_dir = Path(work) / "payee-store"
    if mutant == "process-local-index":
        # The wrong payee keeps its index in memory, provisioned at each start.
        made = Payee(MemoryStore(store_dir), work, boot, crash_at=crash_at, mutant=mutant,
                     exit_on_crash=exit_on_crash)
        made.provision()
        return made
    # The wrong payee trusts an index entry or delivery record as it finds it.
    store = Store(store_dir, flush_reads=mutant != "trust-unflushed-record")
    return Payee(store, work, boot, crash_at=crash_at, mutant=mutant, exit_on_crash=exit_on_crash)


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
    parser.add_argument("--record-status", choices=RECORD_STATUSES, default="confirmed")
    parser.add_argument("--node-claims-authentication", action="store_true")
    parser.add_argument("--fv5", choices=FV5_SOURCES, default="none")
    # The transfer's executed status that the independent FV-5 source and
    # applied-payment authority observe: scenario state, never the record a
    # node serves. By default the node serves the truth at this start.
    parser.add_argument("--executed", choices=RECORD_STATUSES)
    parser.add_argument("--rail-network", choices=tuple(RAIL_NETWORKS), default="mainnet")
    args = parser.parse_args()
    durable_directories(args.work)
    if args.command == "pay":
        handler = payer(args.work, args.boot, crash_at=args.crash, mutant=args.mutant, exit_on_crash=True,
                        job_id=args.job or generator.JOB_ID, confirm=args.confirm, broadcast=args.broadcast,
                        balance=args.balance, relays_confirm=args.relays_confirm,
                        record_status=args.record_status, claims_authentication=args.node_claims_authentication,
                        fv5=args.fv5, executed=args.executed, rail_network=RAIL_NETWORKS[args.rail_network])
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
