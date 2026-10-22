#!/usr/bin/env python3
"""Exercise a real backend in an owned directory using only its public API."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
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

    def __init__(self, binary, directory):
        self.binary = Path(binary).resolve()
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
        return client.loads(command(self.binary, *args))

    def start(self):
        require(self.process is None, "Server already running")
        log_path = self.directory / "server.log"
        offset = log_path.stat().st_size if log_path.exists() else 0
        self.log = log_path.open("ab")
        self.process = subprocess.Popen([str(self.binary), "serve", str(self.store), "--config", str(self.config_path)],
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path, help="New directory for owned store, private credentials and evidence")
    args = parser.parse_args()
    backend = Backend(args.binary, args.out)
    started = time.monotonic()
    try:
        report = {"status": "passed", "workflow": workflow(backend), "elapsed_seconds": round(time.monotonic() - started, 3)}
        write_private(backend.directory / "result.json", client._bytes(report) + b"\n")
        print(json.dumps(report, indent=2))
    finally:
        backend.stop()


if __name__ == "__main__":
    main()
