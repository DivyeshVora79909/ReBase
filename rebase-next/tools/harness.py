#!/usr/bin/env python3
"""Exercise a real backend in an owned directory using only its public API."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import threading
import time
import uuid

import client

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def write_private(path, data):
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def command(*args):
    result = subprocess.run([str(a) for a in args], capture_output=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f"Command {args[0]} failed: {result.stderr.decode(errors='replace')}")
    return result.stdout


class Backend:
    """Harness-owned process and files; no client session or authority cache."""

    def __init__(self, binary, directory, model="calculation"):
        self.binary = Path(binary).resolve()
        self.selector = ["--model", model]
        self.directory = Path(directory).resolve()
        self.directory.mkdir(mode=0o700)
        self.store = self.directory / "app.redb"
        self.config_path = self.directory / "server.json"
        self.process = None
        self.log = None
        self.tenant, self.actor = str(uuid.uuid4()), str(uuid.uuid4())
        self.private = self.directory / "issuer-private.pem"
        write_private(self.private, command("openssl", "genpkey", "-algorithm", "ED25519"))
        public = command("openssl", "pkey", "-in", self.private, "-pubout").decode()
        self.config = {"listen": "127.0.0.1:0", "identity": {
            "issuer": "rebase-harness", "audience": "rebase-next",
            "public_keys": {"harness": public}, "max_token_seconds": 600},
            "max_inflight": 16, "request_timeout_seconds": 15}
        write_private(self.config_path, client._bytes(self.config))
        self.cli("init", self.store, "--tenant", self.tenant, "--actor", self.actor)
        request = self.directory / "token-request.json"
        write_private(request, client._bytes({"tenant": self.tenant, "actor": self.actor,
                                             "epoch": 0, "ttl": 600, "key_id": "harness"}))
        self.token = command(self.binary, "auth", "issue", self.config_path, request, self.private).decode().strip()
        self.token_path = self.directory / "token.txt"
        write_private(self.token_path, (self.token + "\n").encode())

    def cli(self, *args):
        return client.loads(command(self.binary, *self.selector, *args))

    def start(self):
        require(self.process is None, "Server already running")
        log_path = self.directory / "server.log"
        offset = log_path.stat().st_size if log_path.exists() else 0
        self.log = log_path.open("ab")
        self.process = subprocess.Popen([str(self.binary), *self.selector, "serve", str(self.store), "--config", str(self.config_path)],
                                        stdout=self.log, stderr=self.log)
        for _ in range(400):
            require(self.process.poll() is None, "Server exited during startup; inspect server.log")
            with log_path.open("rb") as log:
                log.seek(offset)
                match = re.search(rb"listening on (127\.0\.0\.1:\d+)", log.read())
            if match:
                address = match.group(1).decode()
                self.url = f"http://{address}/rpc"
                self.config["listen"] = address  # Retain the endpoint across restart.
                self.config_path.write_bytes(client._bytes(self.config))
                self.call("session.describe", {})
                return
            time.sleep(0.025)
        raise RuntimeError("Server did not become ready")

    def stop(self):
        if self.process is None:
            return
        try:
            self.process.terminate()
            try:
                code = self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
                raise RuntimeError("Graceful shutdown timed out")
            require(code == 0, f"Server exited with {code}")
        finally:
            self.process = None
            self.log.close()

    def crash(self):
        require(self.process is not None, "No owned server to terminate")
        self.process.kill()
        self.process.wait(timeout=5)
        self.process = None
        self.log.close()

    def call(self, method, params):
        return client.call(self.url, self.token, method, params)

    def plan(self, draft, label):
        result = client.prepare(self.url, self.token, draft)
        client.save_plan(self.directory / f"{label}.plan.json", result)
        return result


def expect_error(kind, action):
    try:
        action()
    except client.ClientError as error:
        require(error.kind == kind, f"Expected {kind}, received {error.kind}")
    else:
        raise RuntimeError(f"Expected rejection: {kind}")


def publications(backend, model, ids, slot):
    return {name: backend.call("roots.read", {"model": model, "owner": ids[name], "slot": slot,
                                             "read": {"kind": "summary"}})["value"]["sum"]
            for name in ("A", "Left", "Right", "Final")}


def workflow(backend):
    backend.start()
    public = backend.call("model.describe", {})
    model = public["model"]
    account = next(c for c in public["contracts"] if c["name"] == "Account")
    slot = next(root["slot"] for root in account["roots"] if root["name"] == "history")
    require("fixtures" not in public and all(c["code"] not in (11, 12) for c in public["contracts"]), "Private model data exposed")
    namespace = str(uuid.uuid4())
    draft = backend.cli("fixture", "plan", "causal-diamond", "--namespace", namespace)
    require(draft == backend.cli("fixture", "plan", "causal-diamond", "--namespace", namespace), "Fixture plan was not repeatable")
    ids = draft["fixture"]["ids"]
    require(all(identity == str(uuid.uuid5(uuid.UUID(namespace), f"causal-diamond/{label}"))
                for label, identity in ids.items()), "UUIDv5 identities disagree with independent Python binding")
    seed = backend.plan(draft, "seed")
    require(backend.token not in json.dumps(seed), "Saved plan contains bearer token")
    seeded = client.execute(backend.url, backend.token, seed)
    require(seeded["status"] == "committed" and seeded["result"]["revision"] == "1", "Fixture seed failed")
    initial = {"A": "30", "Left": "60", "Right": "90", "Final": "150"}
    moved = {"A": "20", "Left": "40", "Right": "60", "Final": "100"}
    require(publications(backend, model, ids, slot) == initial, "Initial independent arithmetic mismatch")
    require(draft["fixture"]["expected"] == {"initial": initial, "after_move": moved}, "Authored fixture expectations changed")
    changes = []
    for label, at in (("MP", "20"), ("MQ", "10")):
        record = backend.call("records.get", {"model": model, "id": ids[label]})
        changes.append({"op": "update", "id": record["id"], "if_version": record["version"], "set": {"at": at}, "unset": []})
    move = backend.plan({"model": model, "commands": changes, "returning": [ids["P"], ids["Q"], ids["J"]]}, "move")
    applied = client.execute(backend.url, backend.token, move)
    require(applied["status"] == "committed", "Atomic move failed")
    require(publications(backend, model, ids, slot) == moved, "Moved independent arithmetic mismatch")
    stale = backend.plan({"model": model, "commands": changes, "returning": []}, "stale")
    expect_error("stale_version", lambda: client.execute(backend.url, backend.token, stale))
    bad = json.loads(json.dumps(seed))
    bad["target"]["store"] = str(uuid.uuid4())
    expect_error("target_mismatch", lambda: client.execute(backend.url, backend.token, bad))
    expect_error("target_mismatch", lambda: client.execute(backend.url + "-other", backend.token, seed))
    expect_error("model_mismatch", lambda: client.prepare(backend.url, backend.token, {**draft, "model": "other"}))
    other = backend.cli("fixture", "plan", "causal-diamond", "--namespace", str(uuid.uuid4()))
    require(set(ids.values()).isdisjoint(other["fixture"]["ids"].values()), "Separate fixture namespaces overlap")
    other_plan = backend.plan(other, "other-seed")
    client.execute(backend.url, backend.token, other_plan)
    require(publications(backend, model, other["fixture"]["ids"], slot) == initial, "Second fixture wrong")
    require(publications(backend, model, ids, slot) == moved, "Second fixture changed first")
    backend.stop()
    before = backend.cli("check", backend.store)
    require(before["status"] == "valid" and before["revision"] == "3" and before["receipts"] == 3, "Unexpected state after failed requests")
    backend.start()
    replay = client.execute(backend.url, backend.token, client.read_json(backend.directory / "seed.plan.json"))
    require(replay["replayed"] is True and replay["result"]["revision"] == "1"
            and replay["result"]["operation_id"] == seed["request"]["operation_id"]
            and all(r["record"] is None for r in replay["result"]["records"]),
            "Replay must retain the receipt and suppress outdated record projections")
    require(client.execute(backend.url, backend.token, move, status=True)["result"] == applied["result"], "Saved status failed after restart")
    require(publications(backend, model, ids, slot) == moved, "Restart or replay changed arithmetic")
    # Exercise the actual client executable against the same saved plan.
    cli_status = client.loads(command(sys.executable, ROOT / "tools/client.py", "--url", backend.url,
                                     "--token-file", backend.token_path, "status", backend.directory / "move.plan.json"))
    require(cli_status["result"] == applied["result"], "Client CLI status mismatch")
    backend.stop()
    archive = backend.directory / "receipt-window.json"
    backend.cli("receipts", "archive", backend.store, archive)
    backend.start()
    original = json.dumps(seed, sort_keys=True)
    expect_error("operation_expired", lambda: client.execute(backend.url, backend.token, seed))
    expect_error("operation_expired", lambda: client.execute(backend.url, backend.token, seed, status=True))
    require(json.dumps(seed, sort_keys=True) == original, "Expired plan was mutated")
    require(publications(backend, model, ids, slot) == moved, "Archive/rejection changed arithmetic")
    backend.stop()
    final = backend.cli("check", backend.store)
    require(final["revision"] == "3" and final["receipts"] == 0, "Archive or expired replay changed state")
    return {"model": model, "initial": initial, "after_move": moved, "fixture_instances": 2,
            "committed_operations": 3, "rejections": 6, "restart_replay": True,
            "archive_fence": True, "integrity": final}


def scan(backend, model):
    """A bounded complete scan for this fixed, quiescent acceptance population."""
    cursor, records = None, []
    for _ in range(9):
        page = backend.call("records.page", {"model": model,
            "query": {"path": "records.by_id", "contract": None, "equals": None},
            "limit": 16, "visit_budget": 128, "cursor": cursor})
        records.extend(page["records"])
        if page["exhausted"]:
            require(page["cursor"] is None, "Exhausted scan retained a cursor")
            return records
        require(page["cursor"] is not None and page["cursor"] != cursor, "Scan made no progress")
        cursor = page["cursor"]
    raise RuntimeError("Scan exceeded the supported population budget")


def latency(values):
    ordered = sorted(values)
    return {"count": len(ordered), "p50_ms": round(ordered[math.ceil(len(ordered) * .5) - 1], 3),
            "p95_ms": round(ordered[math.ceil(len(ordered) * .95) - 1], 3), "max_ms": round(ordered[-1], 3)}


def process_usage(pid):
    path = Path(f"/proc/{pid}/status")
    if not path.exists():
        return {"available": False}
    fields = {}
    for line in path.read_text().splitlines():
        key, _, value = line.partition(":")
        if key in ("VmRSS", "VmHWM", "Threads"):
            fields[key] = int(value.split()[0])
    return {"available": True, "rss_kib": fields["VmRSS"], "peak_rss_kib": fields["VmHWM"],
            "threads": fields["Threads"], "open_fds": len(list(Path(f"/proc/{pid}/fd").iterdir()))}


def workload(backend, writes, readers):
    backend.start()
    catalog = backend.call("model.describe", {})
    model = catalog["model"]
    contracts = {c["name"]: c for c in catalog["contracts"]}
    slot = next(r["slot"] for r in contracts["Account"]["roots"] if r["name"] == "history")
    seed = client.read_json(backend.directory / "seed.plan.json")
    ids = seed["fixture"]["ids"]
    population = scan(backend, model)
    limit = catalog["capabilities"]["limits"]["public_records"]
    require(limit == 64 and len(population) == 28, "Unexpected supported population contract")
    extra_ids = [str(uuid.uuid4()) for _ in range(limit - len(population))]
    fill = backend.plan({"model": model, "commands": [
        {"op": "create", "id": identity, "contract": contracts["Moment"]["code"], "fields": {"at": "0"}}
        for identity in extra_ids], "returning": []}, "fill")
    with ThreadPoolExecutor(max_workers=8) as pool:
        duplicates = list(pool.map(lambda _: client.execute(backend.url, backend.token, fill), range(8)))
    require(sum(not r["replayed"] for r in duplicates) == 1
            and all(r["result"]["revision"] == "4" for r in duplicates), "Duplicate receipt applied more than once")
    expected_ids = sorted([r["id"] for r in population] + extra_ids)
    full = scan(backend, model)
    require([r["id"] for r in full] == expected_ids, "Complete public pagination lost, duplicated or reordered sources")
    overflow = backend.plan({"model": model, "commands": [{"op": "create", "id": str(uuid.uuid4()),
        "contract": contracts["Moment"]["code"], "fields": {"at": "0"}}], "returning": []}, "overflow")
    expect_error("state_limit", lambda: client.execute(backend.url, backend.token, overflow))
    require(client.execute(backend.url, backend.token, overflow, status=True)["status"] == "not_observed", "Rejected overflow left a receipt")
    require(scan(backend, model) == full, "Rejected overflow changed public state")

    contender_version = next(r["version"] for r in full if r["id"] == extra_ids[0])
    contenders = [backend.plan({"model": model, "commands": [{"op": "update", "id": extra_ids[0],
        "if_version": contender_version, "set": {"at": str(i)}, "unset": []}], "returning": [extra_ids[0]]}, f"contender-{i}")
        for i in range(1, 9)]
    def contend(plan):
        try:
            return client.execute(backend.url, backend.token, plan)["status"]
        except client.RpcError as error:
            return error.kind
    with ThreadPoolExecutor(max_workers=8) as pool:
        races = list(pool.map(contend, contenders))
    require(races.count("committed") == 1 and races.count("stale_version") == 7, f"Unexpected compare-and-set results: {races}")
    cursor_request = {"model": model, "query": {"path": "records.by_id", "contract": None, "equals": None},
                      "limit": 1, "visit_budget": 1, "cursor": None}
    old_cursor = backend.call("records.page", cursor_request)["cursor"]
    search = {"model": model, "query": {"path": "records.by_id", "contract": contracts["Moment"]["code"],
              "equals": {"field": "at", "value": "-123"}}, "visit_budget": 1, "cursor": None}
    uncertain = backend.call("records.exists", search)
    require(uncertain["answer"] == "unknown", "An exhausted visit budget asserted absence")
    finished = backend.call("records.exists", {**search, "cursor": uncertain["cursor"], "visit_budget": 128})
    require(finished["answer"] == "no", "Exhausted existence search did not prove absence")

    versions = {label: backend.call("records.get", {"model": model, "id": ids[label]})["version"] for label in ("MP", "MQ")}
    barrier = threading.Barrier(readers + 1)
    done = threading.Event()
    def read_stream(_):
        barrier.wait(timeout=10)
        times, overlapping = [], 0
        for _ in range(writes * 2):
            begin = time.perf_counter()
            value = backend.call("roots.read", {"model": model, "owner": ids["Final"], "slot": slot, "read": {"kind": "summary"}})
            times.append((time.perf_counter() - begin) * 1000)
            require(value["value"]["sum"] in ("100", "150"), "Concurrent snapshot observed unsettled arithmetic")
            overlapping += not done.is_set()
        return times, overlapping
    elapsed = time.perf_counter()
    write_times = []
    with ThreadPoolExecutor(max_workers=readers) as pool:
        futures = [pool.submit(read_stream, i) for i in range(readers)]
        barrier.wait(timeout=10)
        try:
            for i in range(writes):
                times = ("10", "20") if i % 2 == 0 else ("20", "10")
                draft = {"model": model, "commands": [
                    {"op": "update", "id": ids[label], "if_version": versions[label], "set": {"at": at}, "unset": []}
                    for label, at in zip(("MP", "MQ"), times)], "returning": [ids["MP"], ids["MQ"]]}
                last = backend.plan(draft, f"write-{i:04}")
                begin = time.perf_counter()
                last_result = client.execute(backend.url, backend.token, last)
                write_times.append((time.perf_counter() - begin) * 1000)
                require(last_result["result"]["revision"] == str(6 + i), "Write/replay/rejection revision mismatch")
                for label, returned in zip(("MP", "MQ"), last_result["result"]["records"]):
                    require(returned["record"] is not None, "Current authored result hidden from its owner")
                    versions[label] = returned["record"]["version"]
        finally:
            done.set()
        completed = [future.result() for future in futures]
    elapsed = time.perf_counter() - elapsed
    usage = process_usage(backend.process.pid)
    read_times = [timing for times, _ in completed for timing in times]
    require(sum(count for _, count in completed) > 0, "No reader overlapped the writer")
    expect_error("query_changed", lambda: backend.call("records.page", {**cursor_request, "cursor": old_cursor}))
    expected = seed["fixture"]["expected"]["initial" if writes % 2 else "after_move"]
    require(publications(backend, model, ids, slot) == expected, "Final arithmetic after workload")
    require([r["id"] for r in scan(backend, model)] == expected_ids, "Workload changed source inventory")
    backend.crash()  # SIGKILL after acknowledged durable commits, not a power-loss claim.
    backend.start()
    require(publications(backend, model, ids, slot) == expected, "Acknowledged state lost across process crash")
    require(client.execute(backend.url, backend.token, last, status=True)["result"] == last_result["result"], "Receipt lost across crash")
    replay = client.execute(backend.url, backend.token, last)
    require(replay["replayed"] and replay["result"] == last_result["result"], "Post-crash replay changed the outcome")
    backend.stop()
    final = backend.cli("check", backend.store)
    require(final["status"] == "valid" and final["revision"] == str(writes + 5)
            and final["records"] == 74 and final["receipts"] == writes + 2, "Final complete integrity/count mismatch")
    backup, restored = backend.directory / "final-backup.json", backend.directory / "restored.redb"
    backend.cli("backup", backend.store, backup)
    backend.cli("restore", backup, restored)
    require(backend.cli("check", restored) == final, "Verified restore differs from original")
    original_store = backend.store
    backend.store = restored
    try:
        backend.start()
        require(publications(backend, model, ids, slot) == expected, "Restored service publication mismatch")
        require(client.execute(backend.url, backend.token, last, status=True)["result"] == last_result["result"], "Restored receipt mismatch")
    finally:
        backend.stop()
        backend.store = original_store
    return {"public_records": limit, "private_outputs": 10, "population_overflow_rejected": True,
            "duplicate_requests": 8, "duplicate_commits": 1, "concurrent_contenders": 8, "contender_commits": 1,
            "writes": writes, "readers": readers, "read_results": len(read_times),
            "reads_overlapping_writer": sum(count for _, count in completed),
            "read_latency": latency(read_times), "mutation_latency": latency(write_times),
            "timing_scope": "client wall time; mutation includes destination session check; plan preparation/fsync excluded from latency but included in elapsed",
            "elapsed_seconds": round(elapsed, 3), "process": usage,
            "store_bytes": backend.store.stat().st_size, "backup_bytes": backup.stat().st_size,
            "graceful_restart": True, "acknowledged_process_crash_recovery": True, "verified_restore_service": True,
            "final_publications": expected, "integrity": final}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path, help="New directory for owned store, private credentials and evidence")
    parser.add_argument("--writes", type=int, default=128, help="0 for workflow only; otherwise 1-512 measured atomic moves")
    parser.add_argument("--readers", type=int, default=4, help="1-8 concurrent read streams")
    args = parser.parse_args()
    if not 0 <= args.writes <= 512 or not 1 <= args.readers <= 8:
        parser.error("writes must be 0-512 and readers 1-8")
    backend = Backend(args.binary, args.out)
    started = time.monotonic()
    try:
        report = {"status": "passed", "version": backend.cli("version"), "workflow": workflow(backend)}
        if args.writes:
            report["workload"] = workload(backend, args.writes, args.readers)
        report["host"] = {"system": platform.system(), "machine": platform.machine(), "kernel": platform.release(),
                          "logical_cpus": os.cpu_count(), "python": platform.python_version()}
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        write_private(backend.directory / "result.json", client._bytes(report) + b"\n")
        print(json.dumps(report, indent=2))
    finally:
        backend.stop()


if __name__ == "__main__":
    main()
