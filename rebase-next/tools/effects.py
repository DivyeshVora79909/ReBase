#!/usr/bin/env python3
"""G5a authenticated atomic-intent workflow. Provider dispatch remains disabled."""
import argparse
import hashlib
import json
from pathlib import Path
import uuid

import client
from capacity import restricted_actor, snapshot
from harness import Backend, expect_error, require, write_private


def run(binary, destination):
    backend = Backend(binary, destination, model="effect-demo")
    operations = []
    try:
        backend.start()
        catalog = backend.call("model.describe", {})
        model = catalog["model"]
        require(catalog["api"] == "rebase-local-api-2" and
                catalog["capabilities"]["effects"]["dispatch_enabled"] is False, "G5a catalog identity")
        token = restricted_actor(backend, model)
        actor = client.call(backend.url, token, "session.describe", {})["actor"]

        def grants(read=True, update=True):
            graph = backend.call("access.describe", {"model": model})
            principal = next(p for p in graph["graph"]["principals"] if p["id"] == actor)
            principal["grants"]["contracts"] = {
                "101": ["create", "delete"] + (["read"] if read else []) + (["update"] if update else []),
                "205": ["create", "read", "update", "delete"]}
            backend.call("access.replace", {"model": model, "if_revision": graph["revision"], "graph": graph["graph"]})

        def call(method, params, credential=None):
            return client.call(backend.url, credential or token, method, params)

        def mutate(label, commands, error=None):
            plan = client.prepare(backend.url, token, {"model": model, "commands": commands, "returning": []})
            client.save_plan(backend.directory / f"{label}.plan.json", plan)
            if error:
                before = snapshot(backend, f"{label}-before")
                expect_error(error, lambda: client.execute(backend.url, token, plan))
                require(snapshot(backend, f"{label}-after") == before, f"Rollback differs: {label}")
                require(client.execute(backend.url, token, plan, status=True)["status"] == "not_observed", "Rejected receipt exists")
                result = None
            else:
                result = client.execute(backend.url, token, plan)
                replay = client.execute(backend.url, token, plan)
                require(replay["replayed"] and replay["result"] == result["result"], "Replay differs")
            operations.append({"name": label, "commands": len(commands), "result": error or "committed"})
            return plan, result

        def get(identity):
            return backend.call("records.get", {"model": model, "id": identity})

        def update(identity, fields):
            return {"op": "update", "id": identity, "if_version": get(identity)["version"], "set": fields, "unset": []}

        def status(execution, credential=None):
            return call("effects.status", {"model": model, "execution_id": execution}, credential)

        grants()
        fixture = backend.cli("fixture", "plan", "atomic-intent", "--namespace", uuid.UUID(int=20261025))
        account, dispatch = (fixture["fixture"]["ids"][name] for name in ("Account", "Dispatch"))
        create_dispatch = fixture["commands"][1]
        mutate("account", [fixture["commands"][0]])
        require(get(account)["input"]["balance"] == "12", "Literal initial balance")
        mutate("rejected-domain", [update(account, {"balance": "-1"}), create_dispatch], "invariant")
        plan, result = mutate("atomic-intent", [update(account, {"balance": "10"}), create_dispatch])
        execution = result["result"]["executions"][0]["execution_id"]
        ready = status(execution)
        require(get(account)["input"]["balance"] == "10" and ready["phase"] == "ready", "Literal atomic intent")
        require(ready["request"] == create_dispatch["fields"] and execution not in (account, dispatch), "Frozen execution identity/request")
        require(ready["created_at"] == ready["execute_at"] and int(ready["not_after"]) - int(ready["created_at"]) == 60000,
                "Frozen default schedule")
        require(ready["provider_key"] == execution + "/1" and ready["dispatch_enabled"] is False, "Disabled stable provider identity")

        context = call("session.describe", {})["operation_context"]
        cancel = {"model": model, "context": context, "operation_id": str(uuid.uuid4()), "execution_id": execution, "if_revision": "1"}
        write_private(backend.directory / "cancel.params.json", client._bytes(cancel))
        before = snapshot(backend, "replay-conflicts-before")
        conflict = json.loads(json.dumps(plan))
        conflict["request"]["commands"][1]["fields"]["units"] = "4"
        expect_error("operation_conflict", lambda: client.execute(backend.url, token, conflict))
        expect_error("operation_conflict", lambda: call("effects.cancel", dict(cancel, operation_id=plan["request"]["operation_id"])))
        expect_error("stale_version", lambda: call("effects.cancel", dict(cancel, if_revision="0")))
        require(snapshot(backend, "replay-conflicts-after") == before, "Rejected conflicts changed complete state")

        grants(update=False)
        denied = dict(create_dispatch, id=str(uuid.uuid4()))
        mutate("missing-update", [denied], "forbidden")
        expect_error("forbidden", lambda: call("effects.cancel", cancel))
        grants(read=False)
        require(status(execution) is None, "Status ignored target Read")
        require("executions" not in client.execute(backend.url, token, plan)["result"], "Receipt disclosed unreadable target")
        require(call("effects.cancel", cancel)["result"] is None, "Fresh cancellation disclosed unreadable target")
        require(call("effects.cancel", cancel)["result"] is None, "Cancellation replay disclosed unreadable target")
        require(call("operations.status", {k: cancel[k] for k in ("model", "context", "operation_id")})["result"] is None,
                "Cancellation receipt status disclosed unreadable target")
        grants()
        require(call("effects.cancel", cancel)["result"]["phase"] == "cancelled", "Restored reader lost cancellation receipt")
        require(status(execution)["phase"] == "cancelled", "Cancellation was not durable")
        mutate("delete-source", [{"op": "delete", "id": dispatch, "if_version": get(dispatch)["version"]}])
        mutate("pinned-target", [{"op": "delete", "id": account, "if_version": get(account)["version"]}], "unavailable_reference")
        reused_plan, reused = mutate("reuse-source", [create_dispatch])
        second = reused["result"]["executions"][0]["execution_id"]
        require(second != execution and status(execution)["phase"] == "cancelled" and status(second)["phase"] == "ready", "Source reuse replaced execution evidence")
        require(get(account)["input"]["balance"] == "10", "G5a performed an external-result application")

        backend.crash()
        backend.start()
        require(status(second)["phase"] == "ready" and status(execution)["phase"] == "cancelled", "Crash recovery lost intent")
        require(client.execute(backend.url, token, reused_plan)["result"] == reused["result"], "Crash replay differs")
        before = snapshot(backend, "recovery")
        require(len(before["tables"]) == 11, "Incomplete effect inventory")
        backend.stop()
        checked = backend.cli("check", backend.store)
        require(checked["effects"]["retained"] == 2 and checked["effects"]["unresolved"] == 1 and checked["effects"]["reserved_facts"] == 1, "Reconstructed effect counts")
        backup = backend.directory / "recovery.backup.json"
        restored = backend.directory / "restored.redb"
        restored_result = backend.cli("restore", backup, restored)
        require(restored_result["integrity"]["effects"]["quarantined"] and
                not restored_result["integrity"]["effects"]["dispatch_enabled"], "Restored dispatch was enabled")
        backend.store = restored
        backend.start()
        require(status(second)["phase"] == "ready" and status(second)["dispatch_enabled"] is False, "Restored intent changed or ran")
        require(client.execute(backend.url, token, reused_plan)["result"] == reused["result"], "Restored replay differs")
        after = snapshot(backend, "restored-state")
        for table, rows in before["tables"].items():
            if table != "effect_runtime":
                require(after["tables"][table] == rows, f"Restore changed {table}")
        runtime = lambda state: json.loads(bytes.fromhex(state["tables"]["effect_runtime"][0]["value"]))
        require(runtime(before)["activation"] != runtime(after)["activation"], "Restore retained old activation")
        backend.stop()
        archive = backend.directory / "receipt-archive.json"
        backend.cli("receipts", "archive", backend.store, archive)
        backend.start()
        expect_error("operation_expired", lambda: client.execute(backend.url, token, reused_plan))
        expect_error("operation_expired", lambda: call("effects.cancel", cancel))
        require(status(second)["phase"] == "ready" and status(execution)["phase"] == "cancelled", "Archiving erased effect evidence")
        return {"status": "passed", "model": model, "api": catalog["api"], "operations": operations,
                "literal": {"initial_balance": "12", "committed_balance": "10", "requested_units": "3", "provider_dispatch": False},
                "effect_states": ["cancelled", "ready"], "shared_operation_namespace": True,
                "current_target_disclosure": True, "whole_table_rollback": True,
                "crash_recovery": True, "restore_quarantine": True, "archive_preserves_effects": True,
                "integrity": checked, "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest()}
    finally:
        backend.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    result = run(args.binary.resolve(), args.out)
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
