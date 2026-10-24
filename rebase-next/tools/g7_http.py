#!/usr/bin/env python3
"""Bounded real secured HTTP/process controls for one selected G7 adapter.

Uses the ordinary client without retries. A transport proxy discards one request
or completed response; it does not inject a database commit acknowledgement fault.
Run each adapter in a fresh --out directory. FoundationDB namespaces are derived
by the CLI from the fresh absolute store location, never from a shared fixed name.
"""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import platform
import shlex
import threading
import time
from urllib.parse import urlsplit
import uuid

import client
from capacity import snapshot
from harness import Backend, expect_error, latency, require, write_private


TABLES = {"native_kv", "public_records", "reader_records", "authority",
          "operations", "local_runtime", "effect_executions", "effect_due",
          "effect_facts", "effect_inbox", "effect_runtime"}


def digest(value):
    return hashlib.sha256(client._bytes(value)).hexdigest()


def write_result(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


@contextmanager
def discard_once(backend, boundary):
    """A single intentional transport failure; status requests pass normally."""
    upstream = urlsplit(backend.url)
    observation = {"boundary": boundary, "discarded": 0, "upstream_status": None}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(20)

        def log_message(self, *_args):
            pass  # Never log credentials, requests or complete table images.

        def do_POST(self):
            length = int(self.headers["Content-Length"])
            require(0 < length <= client.MAX_REQUEST_BYTES, "Proxy request limit")
            body = self.rfile.read(length)
            mutation = client.loads(body).get("method") == "records.mutate"
            with lock:
                discard = mutation and observation["discarded"] == 0
                if discard:
                    observation["discarded"] += 1
            if discard and boundary == "before_forward":
                self.close_connection = True
                return
            connection = http.client.HTTPConnection(upstream.hostname, upstream.port, timeout=20)
            try:
                connection.request("POST", upstream.path, body, headers={
                    "Authorization": self.headers["Authorization"],
                    "Content-Type": "application/json"})
                response = connection.getresponse()
                data = response.read(client.MAX_RESPONSE_BYTES + 1)
                require(len(data) <= client.MAX_RESPONSE_BYTES, "Proxy response limit")
                if discard:
                    observation["upstream_status"] = response.status
                    self.close_connection = True
                    return
                self.send_response(response.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            finally:
                connection.close()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/rpc", observation
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def run(backend, rounds, clients):
    backend.start()
    model = backend.call("model.describe", {})["model"]
    session = backend.call("session.describe", {})
    expect_error("unauthenticated", lambda: client.call(
        backend.url, "invalid-token", "session.describe", {}))
    namespace = uuid.uuid4()
    identity = lambda label: str(uuid.uuid5(namespace, label))
    root, moment = identity("account"), identity("moment")
    accepted, rejected, race_results = [], [], []

    def create(label, contract, fields):
        return {"op": "create", "id": identity(label), "contract": contract, "fields": fields}

    def plan(label, commands):
        return backend.plan({"model": model, "commands": commands, "returning": []}, label)

    def submit(saved):
        result = client.execute(backend.url, backend.token, saved)
        require(result["status"] == "committed", "Mutation did not commit")
        accepted.append((saved, result))
        return result

    def root_sum(owner):
        return backend.call("roots.read", {"model": model, "owner": owner,
            "slot": 2, "read": {"kind": "summary"}})["value"]["sum"]

    seed = plan("seed", [create("account", 4, {"native_unit": 1}),
        create("credit", 8, {"account": root, "at": "0", "amount": "10"}),
        create("moment", 7, {"at": "0"})])
    submit(seed)
    require(root_sum(root) == "10", "Initial independent root arithmetic differs")

    # One semantic rejection must preserve every table and leave no receipt.
    invalid = plan("invalid-debit", [create("invalid", 8,
        {"account": root, "at": "1", "amount": "-11"})])
    before = snapshot(backend, "rollback-before")
    expect_error("invariant", lambda: client.execute(backend.url, backend.token, invalid))
    after = snapshot(backend, "rollback-after")
    require(before == after, "Rejected debit changed complete application tables")
    rejected.append(invalid)

    def race(label, plans, allowed):
        barrier = threading.Barrier(len(plans))

        def attempt(saved):
            barrier.wait(timeout=20)
            started = time.perf_counter()
            try:
                response = client.execute(backend.url, backend.token, saved)
                outcome = response["status"]
            except client.RpcError as error:
                outcome, response = error.kind, None
            return saved, outcome, response, (time.perf_counter() - started) * 1000

        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=len(plans)) as pool:
            outcomes = list(pool.map(attempt, plans))
        elapsed = time.perf_counter() - started
        counts = Counter(item[1] for item in outcomes)
        require(counts["committed"] == 1 and set(counts) <= {"committed", *allowed},
                f"Unexpected {label} outcomes: {dict(counts)}")
        for saved, outcome, response, _ in outcomes:
            (accepted if outcome == "committed" else rejected).append(
                (saved, response) if outcome == "committed" else saved)
        race_results.append({"name": label, "clients": len(plans), "attempts": len(plans),
            "outcomes": dict(counts), "latency": latency([item[3] for item in outcomes]),
            "elapsed_seconds": round(elapsed, 6), "attempts_per_second": round(len(plans) / elapsed, 3),
            "operation_ids": [item[0]["request"]["operation_id"] for item in outcomes]})
        return outcomes

    for number in range(rounds):
        version = backend.call("records.get", {"model": model, "id": moment})["version"]
        contenders = [plan(f"cas-{number}-{i}", [{"op": "update", "id": moment,
            "if_version": version, "set": {"at": str(number * clients + i + 1)}, "unset": []}])
            for i in range(clients)]
        outcomes = race(f"same-record-cas-{number}", contenders,
                        {"stale_version", "transaction_conflict"})
        winning = next(item[0]["request"]["commands"][0]["set"]["at"]
                       for item in outcomes if item[1] == "committed")
        require(backend.call("records.get", {"model": model, "id": moment})["input"]["at"] == winning,
                "CAS value does not match its sole winning operation")

        # Distinct source IDs compete on one business root, without record CAS.
        # HTTP barriers synchronize submission, never the database interleaving.
        owner = identity(f"root-{number}")
        submit(plan(f"root-seed-{number}", [create(f"root-{number}", 4, {"native_unit": 1}),
            create(f"root-credit-{number}", 8, {"account": owner, "at": "0", "amount": "10"})]))
        debits = [plan(f"root-debit-{number}-{i}", [create(f"debit-{number}-{i}", 8,
            {"account": owner, "at": "1", "amount": "-8"})]) for i in range(clients)]
        race(f"same-root-invariant-{number}", debits, {"invariant", "transaction_conflict"})
        require(root_sum(owner) == "2", "Same-root race violated the independent balance oracle")

    transport = []
    for boundary in ("before_forward", "after_response"):
        with discard_once(backend, boundary) as (url, observation):
            saved = client.prepare(url, backend.token, {"model": model, "commands": [
                create("transport-" + boundary, 7, {"at": "0"})], "returning": []})
            client.save_plan(backend.directory / f"transport-{boundary}.plan.json", saved)
            original = client._bytes(saved)
            expect_error("outcome_unknown", lambda: client.execute(url, backend.token, saved))
            status = client.execute(url, backend.token, saved, status=True)
            expected = "committed" if boundary == "after_response" else "not_observed"
            require(observation["discarded"] == 1 and status["status"] == expected,
                    f"Same-ID reconciliation disagrees at {boundary}")
            if expected == "committed":
                replay = client.execute(url, backend.token, saved)
                require(replay["replayed"] and replay["result"] == status["result"],
                        "Original lost-response operation did not replay exactly")
            require(client._bytes(saved) == original, "Reconciliation altered original ID or context")
            transport.append({**observation, "client_outcome": "outcome_unknown",
                "reconciled_status": status["status"], "operation_id": saved["request"]["operation_id"],
                "replacement_operation_id": None, "original_plan_unchanged": True})

    def receipts():
        for saved, response in accepted:
            status = client.execute(backend.url, backend.token, saved, status=True)
            require(status["result"] == response["result"], "Original receipt result differs")
            replay = client.execute(backend.url, backend.token, saved)
            require(replay["replayed"] and replay["result"] == response["result"], "Replay applied a new operation")
        for saved in rejected:
            require(client.execute(backend.url, backend.token, saved, status=True)["status"] == "not_observed",
                    "Rejected attempt retained a receipt")

    receipts()
    stable = snapshot(backend, "acknowledged-before-crash")
    require(stable["complete"] and set(stable["tables"]) == TABLES, "Unexpected complete table inventory")
    backend.crash()  # SIGKILL after acknowledged commits; no disk/power-loss claim.
    backend.start()
    receipts()
    reopened = snapshot(backend, "after-process-restart")
    require(stable == reopened, "Process restart or receipt replay changed complete tables")
    backend.stop()
    integrity = backend.cli("check", backend.store)
    original_store = backend.store
    restored = backend.directory / "restored-store"
    backend.cli("restore", backend.directory / "after-process-restart.backup.json", restored)
    require(backend.cli("check", restored) == integrity, "Restored integrity differs")
    backend.store = restored
    try:
        backend.start()
        receipts()
        restored_image = snapshot(backend, "restored-image")
        require(restored_image == stable, "Fresh-destination restore changed complete tables")
        backend.stop()
        backend.cli("receipts", "archive", restored, backend.directory / "archived-receipts.json")
        backend.start()
        expect_error("operation_expired", lambda: client.execute(backend.url, backend.token, seed))
        expect_error("operation_expired", lambda: client.execute(backend.url, backend.token, seed, status=True))
        require(root_sum(root) == "10", "Receipt archive changed business root")
        backend.stop()
        archived = backend.cli("check", restored)
        require(archived["receipts"] == 0 and archived["revision"] == integrity["revision"],
                "Archive changed revision or retained receipts")
        reset = backend.cli("reset", restored, "--expect-store", session["store"])
        empty = backend.cli("check", restored)
        require(reset["store"] != session["store"] and empty["records"] == 0 and empty["receipts"] == 0,
                "Reset did not change identity and clear state")
    finally:
        backend.stop()
        backend.store = original_store

    race_counts = Counter()
    for result in race_results:
        race_counts.update(result["outcomes"])
    return {"status": "passed", "model": model, "automatic_retries": False,
        "secured_identity": True, "complete_rollback": True, "races": race_results,
        "race_outcomes": dict(race_counts),
        "request_response_faults": transport, "accepted_ordinary_operations": len(accepted),
        "rejected_ordinary_operations": len(rejected), "integrity": integrity,
        "process_restart": {"signal": "SIGKILL after acknowledged commits", "all_tables_equal": True,
            "table_count": len(TABLES), "image_sha256": digest(stable), "same_id_status_replay": True},
        "lifecycle": {"fresh_restore_all_tables_equal": True, "archive_original_context_expired": True,
            "reset_identity_changed": True, "reset_integrity": empty},
        "measurement_scope": "Client wall time includes session checks; fresh plan preparation excluded. "
            "Submission barrier does not force transaction overlap. This local setup establishes no production capacity.",
        "remaining_fault_gaps": ["No storage-native commit acknowledgement injection through ordinary RPC.",
            "No database-server, replicated-node, disk or power-loss fault is injected.",
            "Before-forward absence is an intentional unsent mutation, not a native uncertain commit abort.",
            "Global revision/receipt keys may cause conservative conflicts; no disjoint-root scale claim.",
            "Effect facts/inbox/application and transaction-size/lifetime boundaries belong to native controls."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--backend", required=True, choices=("redb", "foundationdb", "surrealkv"))
    parser.add_argument("--cluster-file", type=Path)
    parser.add_argument("--out", required=True, type=Path, help="New private output directory")
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--clients", type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.rounds <= 16 or not 2 <= args.clients <= 8:
        parser.error("rounds must be 1-16 and clients 2-8")
    if args.cluster_file and args.backend != "foundationdb":
        parser.error("--cluster-file requires --backend foundationdb")
    binary = args.binary.resolve(strict=True)
    args.out = args.out.resolve()
    args.out.mkdir(mode=0o700)  # Refuse any existing namespace/directory.
    prefix = [str(binary), "--backend", args.backend]
    if args.cluster_file:
        prefix += ["--cluster-file", str(args.cluster_file.resolve(strict=True))]
    wrapper = args.out / "selected-backend"
    write_private(wrapper, ("#!/bin/sh\nexec " + shlex.join(prefix) + ' "$@"\n').encode())
    wrapper.chmod(0o700)
    backend = None
    started = time.perf_counter()
    try:
        backend = Backend(wrapper, args.out / "backend", model="calculation")
        result = run(backend, args.rounds, args.clients)
        with binary.open("rb") as executable:
            binary_sha256 = hashlib.file_digest(executable, "sha256").hexdigest()
        result.update(backend=args.backend, binary_sha256=binary_sha256,
            python=platform.python_version(), rounds=args.rounds, clients=args.clients,
            server_config={"max_inflight": 16, "request_timeout_seconds": 15},
            elapsed_seconds=round(time.perf_counter() - started, 3))
        write_result(args.out / "result.json", result)
        print(json.dumps({"status": "passed", "backend": args.backend, "result": str(args.out / "result.json")}))
    except BaseException as error:
        write_result(args.out / "result.json", {"status": "failed", "backend": args.backend,
            "error": type(error).__name__, "message": str(error)})
        raise
    finally:
        if backend is not None:
            backend.stop()


if __name__ == "__main__":
    main()
