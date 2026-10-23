#!/usr/bin/env python3
"""G5b real-process acceptance with a separate, durable fake-provider journal."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

import client
from harness import Backend, expect_error, require


def wait(check, label, seconds=15):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = check()
        if result:
            return result
        time.sleep(0.025)
    raise RuntimeError(f"Timed out at {label}")


class Journal:
    def __init__(self, directory):
        self.directory = directory
        directory.mkdir(mode=0o700)
        self.modes = {}
        self.log = (directory / "provider.log").open("wb")
        self.process = subprocess.Popen([sys.executable, "-B", str(Path(__file__).with_name("fake_provider.py")),
                                         "--directory", str(directory)], stdout=self.log, stderr=self.log)
        wait(lambda: (directory / "ready.json").exists(), "independent provider startup")
        self.endpoint = json.loads((directory / "ready.json").read_bytes())["endpoint"]

    def mode(self, execution, mode):
        self.modes[execution] = mode
        temporary = self.directory / "modes.tmp"
        temporary.write_text(json.dumps(self.modes))
        temporary.replace(self.directory / "modes.json")

    def counts(self, execution):
        with sqlite3.connect(self.directory / "journal.sqlite") as db:
            calls = dict(db.execute("SELECT method,count(*) FROM calls WHERE execution=? GROUP BY method", (execution,)))
            accepted = db.execute("SELECT coalesce(sum(accepted),0) FROM executions WHERE execution=?", (execution,)).fetchone()[0]
        return {"submissions": calls.get("POST", 0), "observations": calls.get("GET", 0), "accepted": accepted}

    def hold(self, execution):
        (self.directory / f"{execution}.response.hold").touch()

    def release(self, execution):
        (self.directory / f"{execution}.response.hold").unlink(missing_ok=True)

    def accepted(self, execution):
        return (self.directory / f"{execution}.accepted.json").exists()

    def stop(self):
        self.process.terminate()
        self.process.wait(timeout=5)
        self.log.close()

    def check_contract(self):
        execution = str(uuid.uuid4())
        payload = {"execution_id": execution, "account": "fake-account-1", "action": 1,
                   "request": {"account": str(uuid.uuid4()), "units": "3", "execute_at": None, "not_after": None}}

        def call(identity, body=None):
            request = urllib.request.Request(self.endpoint + f"/executions/{identity}/1",
                data=json.dumps(body).encode() if body else None, headers={"Content-Type": "application/json"})
            try:
                response = urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.status, json.load(response)

        first = call(execution, payload)
        require(first[0] == 200 and first[1]["phase"] == "succeeded", "Fake acceptance failed")
        require(call(execution, payload) == first and self.counts(execution)["accepted"] == 1, "Fake idempotency failed")
        payload["request"]["units"] = "4"
        require(call(execution, payload)[0] == 409, "Fake content conflict accepted")
        require(call(execution) == first and call(str(uuid.uuid4()))[0] == 404, "Fake lookup semantics differ")
        return {"execution": execution, "duplicate_same_result": True, "changed_content_rejected": True,
                "empty_lookup": "inconclusive", **self.counts(execution)}


def run(binary, destination):
    destination.mkdir(mode=0o700)
    provider = Journal(destination / "provider")
    backend = Backend(binary, destination / "backend", model="effect-demo")
    probes = destination / "probes"
    probes.mkdir()
    backend.config["effects"] = {"endpoint": provider.endpoint, "mode": "delivery", "probe_directory": str(probes)}
    backend.config_path.write_bytes(client._bytes(backend.config))
    cases, operations = [], []
    account = str(uuid.uuid4())
    started_at = time.monotonic()
    try:
        backend.start()
        provider_contract = provider.check_contract()
        model = backend.call("model.describe", {})["model"]

        def hold(point, execution=None):
            (probes / (f"{execution}.{point}.hold" if execution else f"{point}.hold")).touch()

        def release(point, execution=None):
            (probes / (f"{execution}.{point}.hold" if execution else f"{point}.hold")).unlink(missing_ok=True)

        def boundary(point, execution):
            return wait(lambda: (probes / f"{execution}.{point}.json").exists(), f"{execution}: {point}")

        def status(execution):
            return backend.call("effects.status", {"model": model, "execution_id": execution})

        def balance():
            return int(backend.call("records.get", {"model": model, "id": account})["input"]["balance"])

        def update(value):
            target = backend.call("records.get", {"model": model, "id": account})
            return {"op": "update", "id": account, "if_version": target["version"], "set": {"balance": str(value)}, "unset": []}

        def mutate(label, commands, error=None):
            plan = backend.plan({"model": model, "commands": commands, "returning": []}, label)
            if error:
                expect_error(error, lambda: client.execute(backend.url, backend.token, plan))
                require(client.execute(backend.url, backend.token, plan, status=True)["status"] == "not_observed", "Rejected receipt exists")
                result = None
            else:
                result = client.execute(backend.url, backend.token, plan)
                replay = client.execute(backend.url, backend.token, plan)
                require(replay["replayed"] and replay["result"] == result["result"], "Execution replay differs")
            operations.append({"name": label, "commands": len(commands), "result": error or "committed"})
            return result

        def create(label, value=12, mode="success", point="before_start"):
            hold("before_start")
            dispatch = {"op": "create", "id": str(uuid.uuid4()), "contract": 205,
                        "fields": {"account": account, "units": "3", "execute_at": str(time.time_ns() // 1_000_000 - 1000), "not_after": None}}
            result = mutate(label, [update(value), dispatch])
            execution = result["result"]["executions"][0]["execution_id"]
            provider.mode(execution, mode)
            hold("before_start", execution)
            release("before_start")
            boundary("before_start", execution)
            if point != "before_start":
                hold(point, execution)
                release("before_start", execution)
                boundary(point, execution)
            return execution

        def applied(execution, expected):
            result = wait(lambda: (s if (s := status(execution))["application"] == "applied" else None), "durable application")
            require(balance() == expected and result["phase"] == "succeeded", "Independent balance differs")
            return result

        def record(name, execution, submissions, accepted=1, observations=None, **extra):
            counts = provider.counts(execution)
            require(counts["submissions"] == submissions and counts["accepted"] == accepted, f"Provider journal differs: {name}: {counts}")
            if observations is not None:
                require(counts["observations"] >= observations, f"Missing reconciliation: {name}")
            cases.append({"name": name, "execution": execution, **counts, **extra})
            (destination / "partial-cases.json").write_text(json.dumps(cases, indent=2) + "\n")

        mutate("account", [{"op": "create", "id": account, "contract": 101, "fields": {"balance": "12"}}])
        mutate("negative-balance", [update(-1)], "invariant")
        require(balance() == 12, "Rejected domain write changed balance")
        literal = create("literal-atomic-intent", 10)
        require(balance() == 10 and status(literal)["phase"] == "ready" and provider.counts(literal)["submissions"] == 0,
                "Business state and frozen intent were not observable before delivery")
        release("before_start", literal)
        applied(literal, 7)
        record("literal-12-10-7", literal, 1)

        blocked = create("blocked-application", point="after_start")
        mutate("spend-before-provider-result", [update(2)])
        release("after_start", blocked)
        wait(lambda: status(blocked)["application"] == "blocked", "blocked domain application")
        require(balance() == 2 and status(blocked)["outcome"]["phase"] == "succeeded", "Provider fact rolled back with domain rejection")
        mutate("authorized-repair", [update(5)])
        backend.stop()
        current = backend.cli("check", backend.store)
        require(current["effects"]["blocked"] == 1, "Missing durable blocked application")
        retry = backend.cli("effects", "retry", backend.store, blocked, "--if-revision", status_revision(backend, blocked))
        require(retry["application"] == "pending", "Retry changed remote state")
        backend.start()
        applied(blocked, 2)
        record("blocked-repair-apply-once", blocked, 1, repaired_balance="5", final_balance="2")

        waiting = create("waiting", mode="waiting")
        release("before_start", waiting)
        wait(lambda: status(waiting)["phase"] == "waiting", "typed pending acceptance")
        require(balance() == 12, "Pending acceptance changed domain balance")
        provider.mode(waiting, "success")
        applied(waiting, 9)
        record("waiting-then-success", waiting, 1, observations=1)

        retry = create("definitive-rejection", mode="reject_once")
        release("before_start", retry)
        applied(retry, 9)
        record("definitive-nonacceptance-retry", retry, 2)

        lost = create("lost-response", mode="lost_response")
        release("before_start", lost)
        applied(lost, 9)
        record("lost-response-reconciles", lost, 1, observations=1)

        rejected = create("permanent-rejection", mode="failed")
        release("before_start", rejected)
        wait(lambda: status(rejected)["phase"] == "failed", "permanent provider rejection")
        require(balance() == 12, "Provider rejection changed domain state")
        record("permanent-provider-rejection", rejected, 1, accepted=0)

        cancelled = create("cancel-before-start")
        cancel_effect(backend, model, cancelled, status(cancelled)["revision"])
        release("before_start", cancelled)
        require(status(cancelled)["phase"] == "cancelled", "Prestart cancellation was not terminal")
        record("cancel-before-start", cancelled, 0, accepted=0)

        cancelled_after = create("cancel-after-remote-acceptance", mode="pause_response")
        provider.hold(cancelled_after)
        release("before_start", cancelled_after)
        wait(lambda: provider.accepted(cancelled_after), "independent remote acceptance")
        cancel_effect(backend, model, cancelled_after, status(cancelled_after)["revision"])
        require(status(cancelled_after)["phase"] == "uncertain", "Cancellation claimed remote nonexecution")
        provider.release(cancelled_after)
        applied(cancelled_after, 9)
        record("cancelled-completion-reconciles", cancelled_after, 1, observations=1)

        for point in ("before_start", "after_start", "after_provider", "after_fact"):
            execution = create("crash-" + point, point=point)
            if point == "after_fact":
                require(status(execution)["application"] == "pending" and balance() == 12, "Fact boundary also applied domain state")
            backend.crash()
            release(point, execution)
            backend.start()
            if point == "after_start":
                wait(lambda: provider.counts(execution)["observations"] >= 1, "empty reconciliation after started crash")
                require(status(execution)["phase"] == "uncertain" and balance() == 12, "Started crash authorized blind resend")
                record("crash-" + point, execution, 0, accepted=0, observations=1)
            else:
                result = applied(execution, 9)
                if point == "before_start":
                    require(result["attempts"] == 2, "Lost prestart claim was not charged")
                record("crash-" + point, execution, 1, observations=1 if point == "after_provider" else None)

        # Three due rows, exactly two transport calls admitted before a response
        # completes. This uses deterministic holds, not probabilistic racing.
        hold("before_start")
        commands = [update(100)] + [{"op": "create", "id": str(uuid.uuid4()), "contract": 205,
                    "fields": {"account": account, "units": "3", "execute_at": None, "not_after": None}} for _ in range(3)]
        result = mutate("three-due-calls", commands)
        executions = [e["execution_id"] for e in result["result"]["executions"]]
        for execution in executions:
            provider.mode(execution, "pause_response")
            provider.hold(execution)
        release("before_start")
        wait(lambda: sum(provider.counts(e)["submissions"] for e in executions) == 2, "two owned HTTP calls", seconds=4)
        require(sum(provider.counts(e)["submissions"] for e in executions) == 2, "Third call escaped concurrency bound")
        for execution in executions:
            provider.release(execution)
        wait(lambda: all(status(e)["application"] == "applied" for e in executions), "three due applications")
        require(balance() == 91, "Concurrent result applications lost an update")
        for execution in executions:
            record("bounded-concurrent-call", execution, 1)

        timeout = create("transport-timeout", mode="pause_response")
        provider.hold(timeout)
        release("before_start", timeout)
        wait(lambda: provider.accepted(timeout), "acceptance before transport timeout")
        # The call future owns its slot until the five-second deadline fires;
        # provider execution can outlive that local deadline.
        applied(timeout, 9)
        provider.release(timeout)
        record("transport-deadline-reconciles", timeout, 1, observations=1)

        backend.stop()
        checked = backend.cli("check", backend.store)
        require(checked["effects"]["unresolved"] == 1 and checked["effects"]["uncertain"] == 1,
                "Started-but-unobserved work was lost")
        backup = destination / "worker.backup.json"
        backend.cli("backup", backend.store, backup)
        restored = destination / "restored.redb"
        restored_result = backend.cli("restore", backup, restored)
        require(restored_result["integrity"]["effects"]["quarantined"], "Restore lost quarantine")
        rejected = subprocess.run([str(binary), "--model", "effect-demo", "serve", str(restored), "--config", str(backend.config_path)],
                                  capture_output=True, timeout=10)
        require(rejected.returncode != 0 and b"worker activation unavailable" in rejected.stderr,
                "G5b restored store admitted a dispatcher")
        return {"status": "passed", "model": model, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "duration_seconds": round(time.monotonic() - started_at, 3), "operations": operations,
                "cases": cases, "integrity": checked, "real_process_crash_boundaries": 4,
                "provider_contract": provider_contract,
                "independent_provider_journal": "provider/journal.sqlite", "restored_dispatch_rejected": True}
    finally:
        # Release only harness-owned barriers so graceful cleanup stays bounded.
        for path in probes.glob("*.hold"):
            path.unlink()
        for path in provider.directory.glob("*.hold"):
            path.unlink()
        backend.stop()
        provider.stop()


def cancel_effect(backend, model, execution, revision):
    context = backend.call("session.describe", {})["operation_context"]
    request = {"model": model, "context": context, "operation_id": str(uuid.uuid4()),
               "execution_id": execution, "if_revision": revision}
    result = backend.call("effects.cancel", request)
    replay = backend.call("effects.cancel", request)
    require(replay["replayed"] and replay["result"] == result["result"], "Cancellation replay differs")


def status_revision(backend, execution):
    # The CLI RPC uses the same ordinary status path with filesystem authority.
    request = {"jsonrpc": "2.0", "id": "offline-status", "method": "effects.status", "params": {
        "model": backend.cli("version")["model"], "execution_id": execution}}
    result = subprocess.run([str(backend.binary), *backend.selector, "rpc", str(backend.store)],
                            input=client._bytes(request) + b"\n", capture_output=True, timeout=10)
    require(result.returncode == 0, "Offline status failed")
    return json.loads(result.stdout)["result"]["revision"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.binary.resolve(), args.out.resolve())
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
