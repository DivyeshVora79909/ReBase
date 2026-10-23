#!/usr/bin/env python3
"""G5c signed ingress and prestart-snapshot recovery against an independent journal."""
import argparse
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import client
from effects_worker import Journal, status_revision, wait
from harness import Backend, expect_error, require, write_private


def request(url, body=None, headers=None):
    req = urllib.request.Request(url, data=body, headers=headers or {})
    try:
        response = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response)


def headers(secret, event, raw, timestamp=None):
    timestamp = str(timestamp if timestamp is not None else time.time_ns() // 1_000_000)
    signed = f"fake-account-1\n{event}\n{timestamp}\n".encode() + raw
    return {"Content-Type": "application/json", "x-fake-account": "fake-account-1",
            "x-fake-event": event, "x-fake-timestamp": timestamp,
            "x-fake-signature": hmac.new(secret, signed, hashlib.sha256).hexdigest()}


def webhook(backend, secret, event, raw, expected=200, **changes):
    signed = headers(secret, event, raw, changes.pop("timestamp", None))
    signed.update(changes)
    status, result = request(backend.url.replace("/rpc", "/effects/fake"), raw, signed)
    require(status == expected, f"Webhook returned {status}, expected {expected}: {result}")
    return result


def journal_outcome(provider, execution):
    status, result = request(provider.endpoint + f"/executions/{execution}/1")
    require(status == 200, "Independent provider observation unavailable")
    return result


def event_body(execution, outcome):
    return client._bytes({"execution_id": execution, "outcome": outcome})


def configure(backend, provider, probes, secret_file, mode):
    backend.config["effects"] = {"endpoint": provider.endpoint, "mode": mode,
        "probe_directory": str(probes), "ingress_secret_file": str(secret_file)}
    backend.config_path.write_bytes(client._bytes(backend.config))


def slow_body(backend):
    target = urllib.parse.urlsplit(backend.url)
    started = time.monotonic()
    with socket.create_connection((target.hostname, target.port), timeout=5) as connection:
        connection.sendall((f"POST /effects/fake HTTP/1.1\r\nHost: {target.netloc}\r\n"
            "Content-Type: application/json\r\nContent-Length: 8192\r\n\r\nx").encode())
        reply = connection.recv(4096)
    require(reply.startswith(b"HTTP/1.1 408 "), "Webhook raw-body deadline did not reject")
    return round(time.monotonic() - started, 3)


def discard_ack(backend, secret, event, raw):
    target = urllib.parse.urlsplit(backend.url)
    connection = http.client.HTTPConnection(target.hostname, target.port, timeout=10)
    try:
        connection.request("POST", "/effects/fake", raw, headers(secret, event, raw))
        reply = connection.getresponse()
        require(reply.status == 200, "Initial durable webhook was rejected")
        # Deliberately discard the ACK body. The retry must recognize durable
        # identity rather than publish another row or rely on a client receipt.
    finally:
        connection.close()


def observed_tables(backup):
    return json.loads(backup.read_bytes())["payload"]["tables"]


def failed_cli(backend, *args, message):
    result = subprocess.run([str(backend.binary), *backend.selector, *map(str, args)],
                            capture_output=True, timeout=15)
    require(result.returncode != 0 and message.encode() in result.stderr,
            f"Expected CLI rejection: {args[0]}: {result.stderr.decode(errors='replace')}")


def run(binary, destination):
    destination.mkdir(mode=0o700)
    secret = os.urandom(32)
    secret_file = destination / "webhook.secret"
    write_private(secret_file, secret)
    provider = Journal(destination / "provider")
    backend = Backend(binary, destination / "backend", model="effect-demo")
    restored_backend = None
    probes = destination / "probes"
    probes.mkdir()
    configure(backend, provider, probes, secret_file, "delivery")
    cases, operations = [], []
    started = time.monotonic()

    def record(name, **evidence):
        cases.append({"name": name, **evidence})
        (destination / "partial-cases.json").write_text(json.dumps(cases, indent=2) + "\n")

    def mutate(owner, model, label, commands):
        plan = owner.plan({"model": model, "commands": commands, "returning": []}, label)
        result = client.execute(owner.url, owner.token, plan)
        require(result["status"] == "committed", "Domain mutation failed")
        operations.append({"name": label, "commands": len(commands)})
        return result, plan

    try:
        backend.start()
        model = backend.call("model.describe", {})["model"]
        account, source = str(uuid.uuid4()), str(uuid.uuid4())

        def status(execution):
            return backend.call("effects.status", {"model": model, "execution_id": execution})

        def balance():
            return int(backend.call("records.get", {"model": model, "id": account})["input"]["balance"])

        def update(value):
            row = backend.call("records.get", {"model": model, "id": account})
            return {"op": "update", "id": account, "if_version": row["version"], "set": {"balance": str(value)}, "unset": []}

        def waiting_execution(label, source, value):
            (probes / "before_start.hold").touch()
            result, plan = mutate(backend, model, label, [update(value), {"op": "create", "id": source,
                "contract": 205, "fields": {"account": account, "units": "3", "execute_at": None, "not_after": None}}])
            execution = result["result"]["executions"][0]["execution_id"]
            provider.mode(execution, "waiting")
            (probes / f"{execution}.after_fact.hold").touch()
            (probes / "before_start.hold").unlink()
            wait(lambda: (probes / f"{execution}.after_fact.json").exists(), "provider waiting fact")
            require(status(execution)["phase"] == "waiting", "Provider acceptance was not durable")
            waiting = journal_outcome(provider, execution)
            provider.mode(execution, "success")
            success = journal_outcome(provider, execution)
            # Further lookups are inconclusive, so this workflow's success must
            # arrive through the signed inbox. Journal acceptance remains real.
            provider.mode(execution, "empty")
            return execution, waiting, success, plan

        mutate(backend, model, "account", [{"op": "create", "id": account,
            "contract": 101, "fields": {"balance": "12"}}])
        first, waiting, success, old_plan = waiting_execution("webhook-intent", source, 12)
        success_raw, waiting_raw = event_body(first, success), event_body(first, waiting)
        first_event, older_event = str(uuid.UUID(int=1)), str(uuid.UUID(int=2))
        webhook(backend, secret, first_event, success_raw, expected=401, **{"x-fake-signature": "0" * 64})
        webhook(backend, secret, first_event, success_raw, expected=401,
                timestamp=time.time_ns() // 1_000_000 - 600_000)
        webhook(backend, secret, first_event, success_raw, expected=401, **{"x-fake-account": "other-account"})
        webhook(backend, secret, first_event, b"{} {}", expected=400)
        invalid = {**success, "units": "4"}
        webhook(backend, secret, first_event, event_body(first, invalid), expected=400)
        webhook(backend, secret, first_event, b" " * 8193, expected=413)
        deadline = slow_body(backend)
        record("signature-skew-binding-and-body-limits", raw_limit=8192, body_deadline_seconds=deadline)

        (probes / "inbox.abort").touch()
        webhook(backend, secret, first_event, success_raw, expected=503)
        (probes / "inbox.abort").unlink()
        # This ACK cannot be a duplicate of the failed insertion.
        require(webhook(backend, secret, first_event, success_raw)["duplicate"] is False,
                "Failed inbox publication left a durable row")
        webhook(backend, secret, first_event, success_raw + b" ", expected=409)
        unknown = str(uuid.uuid4())
        webhook(backend, secret, str(uuid.uuid4()), event_body(unknown, {**success, "execution_id": unknown}), expected=404)
        discard_event = str(uuid.UUID(int=3))
        discard_ack(backend, secret, discard_event, success_raw)
        require(webhook(backend, secret, discard_event, success_raw)["duplicate"] is True,
                "Discarded ACK retry created another event")
        webhook(backend, secret, older_event, waiting_raw)
        require(status(first)["phase"] == "waiting" and balance() == 12, "Inbox bypassed fact consumption")
        record("commit-before-ack-conflict-and-failed-storage", failed_write_status=503,
               conflicting_identity_status=409, unknown_execution_status=404, discarded_ack_duplicate=True)

        backend.crash()
        (probes / f"{first}.after_fact.hold").unlink()
        configure(backend, provider, probes, secret_file, "reconcile")
        backend.start()
        require(webhook(backend, secret, first_event, success_raw)["duplicate"] is True, "Restart lost durable deduplication")
        wait(lambda: status(first)["application"] == "applied", "inbox after process loss")
        require(balance() == 9 and status(first)["phase"] == "succeeded", "Out-of-order event regressed success")
        counts = provider.counts(first)
        require(counts["submissions"] == counts["accepted"] == 1, "Inbox replay resubmitted remotely")
        record("process-loss-after-inbox-and-out-of-order-consumption", process_kills=1, balance="9", **counts)

        backend.stop()
        configure(backend, provider, probes, secret_file, "delivery")
        backend.start()
        blocked, pending, succeeded, _ = waiting_execution("blocked-webhook-intent", str(uuid.uuid4()), 2)
        blocked_event = str(uuid.uuid4())
        webhook(backend, secret, blocked_event, event_body(blocked, succeeded))
        (probes / f"{blocked}.after_fact.hold").unlink()
        wait(lambda: status(blocked)["application"] == "blocked", "blocked inbox application")
        revision = int(status(blocked)["revision"])
        webhook(backend, secret, str(uuid.uuid4()), event_body(blocked, pending))
        wait(lambda: int(status(blocked)["revision"]) > revision, "older pending event consumption")
        require(status(blocked)["diagnostic"] == "invariant" and balance() == 2, "Older event erased blocked diagnostic")
        mutate(backend, model, "repair-blocked-account", [update(5)])
        backend.stop()
        backend.cli("effects", "retry", backend.store, blocked, "--if-revision", status_revision(backend, blocked))
        configure(backend, provider, probes, secret_file, "reconcile")
        backend.start()
        wait(lambda: status(blocked)["application"] == "applied", "repaired application")
        require(balance() == 2, "Repaired result applied more than once")
        counts = provider.counts(blocked)
        require(counts["submissions"] == counts["accepted"] == 1, "Repair caused another submission")
        record("delayed-event-preserves-blocked-repair", final_balance="2", **counts)

        backend.stop()
        clean = backend.cli("check", backend.store)
        require(clean["effects"]["inbox_pending"] == clean["effects"]["unresolved"] == 0, "Clean boundary still has pending work")
        clean_backup = destination / "clean-before-capacity.json"
        backend.cli("backup", backend.store, clean_backup)
        configure(backend, provider, probes, secret_file, "disabled")
        backend.start()
        for _ in range(256 - clean["effects"]["inbox"]):
            webhook(backend, secret, str(uuid.uuid4()), waiting_raw)
        webhook(backend, secret, str(uuid.uuid4()), waiting_raw, expected=503)
        require(webhook(backend, secret, first_event, success_raw)["duplicate"] is True, "Full capacity rejected a durable duplicate")
        backend.stop()
        full = backend.cli("check", backend.store)
        require(full["effects"]["inbox"] == 256, "HTTP inbox capacity was not real")
        failed_cli(backend, "reset", backend.store, "--expect-store", full["store"], message="unresolved external work")
        full_backup = destination / "full-inbox.backup.json"
        backed = backend.cli("backup", backend.store, full_backup)
        restored = backend.cli("restore", full_backup, destination / "full-inbox-restored.redb")
        require(restored["integrity"]["effects"]["inbox_pending"] == full["effects"]["inbox_pending"], "Full inbox restore lost work")
        archive = destination / "archive.json"
        backend.cli("receipts", "archive", backend.store, archive)
        after_archive = destination / "after-archive.json"
        backend.cli("backup", backend.store, after_archive)
        before_tables, after_tables = observed_tables(archive), observed_tables(after_archive)
        for table in ("effect_runtime", "effect_inbox", "effect_executions", "effect_facts", "effect_due"):
            require(before_tables[table] == after_tables[table], f"Archiving erased {table}")
        record("full-inbox-retry-backup-archive-and-reset-guard", inbox=256,
               pending=full["effects"]["inbox_pending"], backup_bytes=backed["bytes"], overflow_status=503)

        # The separate original process accepts only after this backup. The
        # future second request has never reached the independent provider.
        restored_backend = Backend(binary, destination / "restore-backend", model="effect-demo")
        restore_probes = destination / "restore-probes"
        restore_probes.mkdir()
        configure(restored_backend, provider, restore_probes, secret_file, "disabled")
        restored_backend.start()
        owner = restored_backend
        restored_account = str(uuid.uuid4())
        now = time.time_ns() // 1_000_000
        result, _ = mutate(owner, model, "prestart-seed", [
            {"op": "create", "id": restored_account, "contract": 101, "fields": {"balance": "12"}},
            {"op": "create", "id": str(uuid.uuid4()), "contract": 205, "fields": {"account": restored_account, "units": "3", "execute_at": None, "not_after": None}},
            {"op": "create", "id": str(uuid.uuid4()), "contract": 205, "fields": {"account": restored_account, "units": "3", "execute_at": str(now + 60_000), "not_after": str(now + 120_000)}}])
        due, empty = [row["execution_id"] for row in result["result"]["executions"]]
        owner.stop()
        prestart = destination / "prestart.backup.json"
        owner.cli("backup", owner.store, prestart)
        frozen = [json.loads(bytes.fromhex(row["value"])) for row in observed_tables(prestart)["effect_executions"]]
        require(all(row["started"] is None and row["attempts"] == 0 for row in frozen), "Backup followed provider start")
        require(provider.counts(due)["submissions"] == 0, "Provider was called before backup")
        (restore_probes / f"{due}.after_fact.hold").touch()
        configure(owner, provider, restore_probes, secret_file, "delivery")
        owner.start()
        wait(lambda: (restore_probes / f"{due}.after_fact.json").exists(), "original provider acceptance")
        require(provider.counts(due)["submissions"] == provider.counts(due)["accepted"] == 1, "Original remote acceptance differs")
        owner.stop()
        (restore_probes / f"{due}.after_fact.hold").unlink()
        old_store = owner.store
        owner.store = owner.directory / "predating-restored.redb"
        owner.cli("restore", prestart, owner.store)
        failed_cli(owner, "serve", owner.store, "--config", owner.config_path, message="worker activation unavailable")
        configure(owner, provider, restore_probes, secret_file, "reconcile")
        owner.start()

        def restored_status(execution):
            return owner.call("effects.status", {"model": model, "execution_id": execution})

        wait(lambda: restored_status(due)["application"] == "applied", "predating restore reconciliation")
        wait(lambda: restored_status(empty)["phase"] == "uncertain", "empty lookup quarantine")
        require(owner.call("records.get", {"model": model, "id": restored_account})["input"]["balance"] == "9", "Restored result applied twice or not at all")
        for execution in (due, empty):
            require(restored_status(execution)["attempts"] == 0, "Restored worker charged a submission")
        require(restored_status(empty)["quarantined"], "Empty lookup removed quarantine")
        blocked_plan = owner.plan({"model": model, "commands": [{"op": "create", "id": str(uuid.uuid4()),
            "contract": 205, "fields": {"account": restored_account, "units": "3", "execute_at": None, "not_after": None}}], "returning": []}, "quarantine-rejection")
        expect_error("invalid_input", lambda: client.execute(owner.url, owner.token, blocked_plan))
        owner.stop()
        counts, empty_counts = provider.counts(due), provider.counts(empty)
        require(counts["submissions"] == counts["accepted"] == 1 and counts["observations"] >= 1, "Restored copy resubmitted")
        require(empty_counts["submissions"] == empty_counts["accepted"] == 0 and empty_counts["observations"] >= 1, "Empty lookup authorized execution")
        restored_check = owner.cli("check", owner.store)
        failed_cli(owner, "reset", owner.store, "--expect-store", restored_check["store"], message="unresolved external work")
        record("backup-before-start-then-independent-acceptance", balance="9", original_store=str(old_store.relative_to(destination)), **counts)
        record("empty-lookup-remains-quarantined", **empty_counts)

        # A clean terminal snapshot can reset after the old writer has stopped;
        # consumed retained events are evidence, not a permanent reset blocker.
        backend.store = backend.directory / "clean-reset.redb"
        backend.cli("restore", clean_backup, backend.store)
        identity = backend.cli("check", backend.store)["store"]
        reset = backend.cli("reset", backend.store, "--expect-store", identity)
        require(reset["store"] != identity, "Reset retained the old store identity")
        old_token = backend.token
        token_request = backend.directory / "epoch-one.json"
        write_private(token_request, client._bytes({"tenant": backend.tenant, "actor": backend.actor,
            "epoch": 1, "ttl": 600, "key_id": "harness"}))
        issued = subprocess.run([str(binary), "auth", "issue", str(backend.config_path), str(token_request), str(backend.private)], capture_output=True, timeout=10, check=True)
        backend.token = issued.stdout.decode().strip()
        backend.start()
        expect_error("target_mismatch", lambda: client.execute(backend.url, backend.token, old_plan))
        try:
            client.call(backend.url, old_token, "session.describe", {})
        except client.ClientError:
            pass
        else:
            raise RuntimeError("Reset accepted the old credential epoch")
        mutate(backend, model, "source-reuse-after-reset", [
            {"op": "create", "id": account, "contract": 101, "fields": {"balance": "12"}},
            {"op": "create", "id": source, "contract": 205, "fields": {"account": account, "units": "3", "execute_at": None, "not_after": None}}])
        webhook(backend, secret, first_event, success_raw, expected=404)
        backend.stop()
        reset_check = backend.cli("check", backend.store)
        require(reset_check["effects"]["inbox"] == 0 and reset_check["effects"]["retained"] == 1, "Old webhook attached to a reused source")
        record("clean-reset-rejects-old-context-credential-and-webhook", old_webhook_status=404, source_reused=True)
        return {"status": "passed", "model": model, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "duration_seconds": round(time.monotonic() - started, 3), "cases": cases, "operations": operations,
            "full_inbox_integrity": full, "restored_integrity": restored_check, "reset_integrity": reset_check,
            "provider_journal": "provider/journal.sqlite", "process_kills": 1}
    finally:
        for directory in (probes, destination / "restore-probes", provider.directory):
            if directory.exists():
                for hold in directory.glob("*.hold"):
                    hold.unlink()
        backend.stop()
        if restored_backend is not None:
            restored_backend.stop()
        provider.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.binary.resolve(), args.out.resolve())
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "cases": len(result["cases"]), "duration_seconds": result["duration_seconds"]}))


if __name__ == "__main__":
    main()
