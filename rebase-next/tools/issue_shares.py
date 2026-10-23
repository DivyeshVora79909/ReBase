#!/usr/bin/env python3
"""G4d-a focused HTTP acceptance: source-derived shares, authority and recovery."""
import argparse
import hashlib
import json
from pathlib import Path
import uuid

import client
from capacity import restricted_actor, snapshot, work_for
from harness import Backend, expect_error, require
from invoicing import expected, propose, scan, verify


def ratio(n, d=1):
    return {"numerator": str(n), "denominator": str(d)}


def run(binary, destination):
    backend = Backend(binary, destination, model="invoicing")
    facts, operations, measurements = {}, [], {}
    latest = None
    try:
        backend.start()
        model = backend.call("model.describe", {})["model"]
        reader = restricted_actor(backend, model)
        actor = client.call(backend.url, reader, "session.describe", {})["actor"]

        def grants(issue_read, share_read):
            access = backend.call("access.describe", {"model": model})
            principal = next(p for p in access["graph"]["principals"] if p["id"] == actor)
            principal["grants"]["contracts"] = {
                "101": ["read", "create"],
                "211": (["read"] if issue_read else []) + ["create", "update"],
                "821": (["read"] if share_read else []) + ["create", "update", "delete"]}
            backend.call("access.replace", {"model": model, "if_revision": access["revision"], "graph": access["graph"]})

        grants(True, True)
        namespace = uuid.UUID(int=20261024)
        draft = backend.cli("fixture", "plan", "issue-share", "--namespace", namespace)
        ids = draft["fixture"]["ids"]
        issue, share, invoice = (ids[k] for k in ("Issue", "Share", "Invoice"))
        require(draft == backend.cli("fixture", "plan", "issue-share", "--namespace", namespace), "Deterministic fixture")

        def mutate(label, commands, error=None, token=None, returning=None):
            nonlocal facts, latest
            token = token or backend.token
            plan = client.prepare(backend.url, token, {"model": model, "commands": commands, "returning": returning or []})
            client.save_plan(backend.directory / f"{label}.plan.json", plan)
            if error:
                before = snapshot(backend, f"{label}-before")
                expect_error(error, lambda: client.execute(backend.url, token, plan))
                require(snapshot(backend, f"{label}-after") == before, "Complete rollback differs")
                require(client.execute(backend.url, token, plan, status=True)["status"] == "not_observed", "Rejected receipt exists")
                outcome = None
            else:
                proposed = propose(facts, commands)
                expected(proposed)
                outcome = client.execute(backend.url, token, plan)
                require(outcome["status"] == "committed", "Mutation did not commit")
                facts = proposed
                verify(backend, model, facts)
                replay = client.execute(backend.url, token, plan)
                require(replay["replayed"] and replay["result"] == outcome["result"], "Exact replay differs")
                measurements[label] = work_for(backend, plan["request"]["operation_id"])
                if token == backend.token:
                    latest = (plan, outcome)
            operations.append({"name": label, "commands": len(commands), "result": error or "committed"})
            return plan, outcome

        def update(identity, fields):
            record = backend.call("records.get", {"model": model, "id": identity})
            return {"op": "update", "id": identity, "if_version": record["version"], "set": fields, "unset": []}

        def create(label, code, fields):
            return {"op": "create", "id": str(uuid.uuid5(namespace, label)), "contract": code, "fields": fields}

        def get(identity, token=None):
            return client.call(backend.url, token or backend.token, "records.get", {"model": model, "id": identity})

        mutate("fixture", draft["commands"], token=reader, returning=[issue, share])
        require(get(share)["derived"] == {"basis_minor": "15002", "amount_minor": "5001"}, "Literal initial share")
        mutate("parent-only", [update(issue, {"quantity": ratio(2)})])
        require(get(share)["derived"] == {"basis_minor": "20002", "amount_minor": "6667"}, "Fresh parent publication")
        require(measurements["parent-only"]["causal_evaluations"] == 2, "One parent and one consumer")
        mutate("inexact-share", [update(share, {"rounding": "exact"})], "inexact")
        second = create("second-issue", 211, {"invoice": invoice, "at": "0", "quantity": ratio(1), "unit_price_minor": "600", "rounding": "half_even"})
        mutate("second-parent", [second], token=reader)
        other = second["id"]
        mutate("retarget", [update(share, {"issue": other})])
        unchanged = get(share)
        mutate("detached-parent", [update(issue, {"quantity": ratio(3)})])
        require(get(share) == unchanged and measurements["detached-parent"]["causal_evaluations"] == 1, "Detached parent selected old consumer")
        mutate("bounded-fanout", [create(f"extra-share-{n}", 821, {"issue": other, "ratio": ratio(1, 3), "rounding": "half_even"}) for n in range(7)])
        mutate("eight-consumers", [update(other, {"unit_price_minor": "901"})])
        require(measurements["eight-consumers"]["causal_evaluations"] == 9, "Parent plus eight declared consumers")

        # Materialized record policy: unchanged reference recalculation and
        # existing publication visibility are governed by the share's access.
        require(get(issue, reader) is not None and get(share, reader) is not None, "Initial parent/share visibility")
        grants(False, True)
        require(get(issue, reader) is None and get(other, reader) is None, "Issue read was not revoked")
        require(get(share, reader) == get(share), "Parent read revocation redacted materialized share")
        mutate("denied-new-reference", [create("denied-share", 821, {"issue": other, "ratio": ratio(1, 3), "rounding": "half_even"})], "forbidden", token=reader)
        mutate("denied-retarget", [update(share, {"issue": issue})], "forbidden", token=reader)
        receipt, accepted = mutate("unchanged-reference", [update(share, {"rounding": "floor"})], token=reader, returning=[share])
        require(accepted["result"]["records"][0]["record"] is not None, "Share receipt initially unavailable")
        grants(False, False)
        require(get(share, reader) is None, "Share read was not revoked")
        page = client.call(backend.url, reader, "records.page", {"model": model, "query": {"path": "records.by_id", "contract": None, "equals": None}, "limit": 32, "visit_budget": 128, "cursor": None})
        require(page["exhausted"] and all(r["contract"] != 821 for r in page["records"]), "Denied share exposed by page")
        redacted = client.execute(backend.url, reader, receipt)
        require(redacted["replayed"] and redacted["result"]["records"][0]["record"] is None, "Replay disclosed revoked share")

        before = scan(backend, model)
        backend.stop()
        integrity = backend.cli("check", backend.store)
        backup = backend.directory / "verified-backup.json"
        backend.cli("backup", backend.store, backup)
        backend.start()
        require(scan(backend, model) == before, "Reopen changed publications")
        require(client.execute(backend.url, backend.token, latest[0])["result"] == latest[1]["result"], "Reopen replay")
        backend.crash()
        backend.start()
        require(scan(backend, model) == before, "Crash recovery changed publications")
        backend.stop()
        restored = backend.directory / "restored.redb"
        backend.cli("restore", backup, restored)
        backend.store = restored
        backend.start()
        verify(backend, model, facts)
        require(scan(backend, model) == before, "Restore changed publications")
        require(client.execute(backend.url, backend.token, latest[0])["result"] == latest[1]["result"], "Restore replay")
        require(get(share, reader) is None, "Restore lost current share authority")
        return {"status": "passed", "model": model, "operations": operations,
                "measurements": measurements, "public_sources": len(facts), "integrity": integrity,
                "literal": {"initial": {"basis_minor": "15002", "amount_minor": "5001"}, "parent_edit": {"basis_minor": "20002", "amount_minor": "6667"}},
                "logical_bytewise_rollback": True, "materialized_record_authority": True,
                "reopen": True, "crash_recovery": True, "restore": True,
                "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest()}
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
    print(json.dumps({k: v for k, v in result.items() if k not in ("measurements", "operations")}, indent=2))


if __name__ == "__main__":
    main()
