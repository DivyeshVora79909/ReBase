#!/usr/bin/env python3
"""G4d-c: authored latest selection, complete search dependencies and recovery."""
import argparse
import hashlib
import json
from pathlib import Path
import time
import uuid

import client
from capacity import restricted_actor, snapshot, work_for
from harness import Backend, expect_error, require
from invoicing import propose
from observation_reports import expected, verify


def oracle_controls():
    parent, other, a, b, reader = (str(uuid.UUID(int=n)) for n in (10, 11, 20, 21, 30))
    facts = {parent: {"contract": 101, "fields": {"unit": 7}},
             other: {"contract": 101, "fields": {"unit": 7}},
             reader: {"contract": 419, "fields": {"instrument": parent, "at": "10", "unit": 7}}}

    def check(identity=None, at=None, value=None):
        selection = None if identity is None else {
            "identity": identity, "member_slot": 17, "time": str(at), "unit": 7, "value": str(value)}
        require(expected(facts)[1][reader] == {"selection": selection}, "Literal selection oracle")

    check()
    for identity in (b, a):
        facts[identity] = {"contract": 211, "fields": {
            "instrument": parent, "at": "10", "unit": 7, "value": "12"}}
    check(b, 10, 12)
    facts[a]["fields"]["value"] = "99"
    check(b, 10, 12)
    facts[reader]["fields"]["at"] = "9"
    check()
    facts[a]["fields"]["at"] = str(-(2**63))
    facts[reader]["fields"]["at"] = str(-(2**63))
    check(a, -(2**63), 99)
    facts[b]["fields"]["at"] = str(2**63 - 1)
    facts[reader]["fields"]["at"] = str(2**63 - 1)
    check(b, 2**63 - 1, 12)
    facts[reader]["fields"]["instrument"] = other
    check()
    return 7


def run(binary, destination):
    started = time.monotonic()
    controls = oracle_controls()
    backend = Backend(binary, destination, model="measurement")
    facts, operations, measurements = {}, [], {}
    last_owner = None
    namespace = uuid.UUID(int=20261026)
    try:
        backend.start()
        model = backend.call("model.describe", {})["model"]
        token = restricted_actor(backend, model)
        actor = client.call(backend.url, token, "session.describe", {})["actor"]

        def grants(parent_read, selection_read):
            access = backend.call("access.describe", {"model": model})
            principal = next(p for p in access["graph"]["principals"] if p["id"] == actor)
            principal["grants"]["contracts"] = {
                "101": (["read"] if parent_read else []) + ["create", "update"],
                "211": ["read", "create", "update", "delete"],
                "307": ["read", "create", "update", "delete"],
                "419": (["read"] if selection_read else []) + ["create", "update", "delete"]}
            backend.call("access.replace", {"model": model, "if_revision": access["revision"],
                         "graph": access["graph"]})

        def get(identity, credential=None):
            return client.call(backend.url, credential or backend.token, "records.get",
                               {"model": model, "id": identity})

        def update(identity, fields):
            return {"op": "update", "id": identity, "if_version": get(identity)["version"],
                    "set": fields, "unset": []}

        def create(label, contract, fields):
            return {"op": "create", "id": str(uuid.uuid5(namespace, label)),
                    "contract": contract, "fields": fields}

        def delete(identity):
            return {"op": "delete", "id": identity, "if_version": get(identity)["version"]}

        def mutate(label, commands, error=None, credential=None, returning=None):
            nonlocal facts, last_owner
            credential = credential or backend.token
            plan = client.prepare(backend.url, credential, {"model": model,
                                  "commands": commands, "returning": returning or []})
            client.save_plan(backend.directory / f"{label}.plan.json", plan)
            if error:
                before = snapshot(backend, f"{label}-before")
                expect_error(error, lambda: client.execute(backend.url, credential, plan))
                require(snapshot(backend, f"{label}-after") == before, "Complete rollback differs")
                require(client.execute(backend.url, credential, plan, status=True)["status"]
                        == "not_observed", "Rejected receipt exists")
                result = None
            else:
                proposed = propose(facts, commands)
                expected(proposed)
                result = client.execute(backend.url, credential, plan)
                require(result["status"] == "committed", "Mutation did not commit")
                facts = proposed
                verify(backend, model, facts)
                replay = client.execute(backend.url, credential, plan)
                require(replay["replayed"] and replay["result"] == result["result"], "Replay differs")
                measurements[label] = work_for(backend, plan["request"]["operation_id"])
                if credential == backend.token:
                    last_owner = (plan, result)
            operations.append({"name": label, "commands": len(commands), "result": error or "committed"})
            return plan, result

        grants(True, True)
        draft = backend.cli("fixture", "plan", "latest-observation", "--namespace", namespace)
        ids = draft["fixture"]["ids"]
        instrument, other, reader, report = (ids[name] for name in ("instrument", "other", "latest", "report"))
        loser, winner = sorted((ids["tie_a"], ids["tie_b"]), key=lambda value: uuid.UUID(value).int)
        mutate("fixture", draft["commands"], credential=token, returning=[reader, report])
        require(get(reader)["derived"]["selection"] == draft["fixture"]["expected"]["selection"],
                "Fixture complete-key winner")
        require(get(report)["derived"] == draft["fixture"]["expected"]["report"], "Existing report fixture")
        mutate("isolate-report", [update(report, {"range": {"lower": None, "upper": {"excluded": "1"}}})])
        unchanged = get(reader)
        mutate("nonwinner-value", [update(loser, {"value": "13"})])
        require(get(reader) == unchanged and measurements["nonwinner-value"]["causal_evaluations"] == 1,
                "Nonwinner edit must evaluate and retain the unchanged materialization")
        mutate("outside-window", [create("late", 211, {
            "instrument": instrument, "at": "11", "unit": 7, "value": "99"})])
        require(get(reader) == unchanged and measurements["outside-window"]["causal_evaluations"] == 0,
                "Outside search window selected a consumer")
        same = create("same-value-winner", 211, {
            "instrument": instrument, "at": "10", "unit": 7, "value": "12"})
        same["id"] = str(uuid.UUID(int=2**128 - 2))
        mutate("same-value-winner", [same])
        selected = get(reader)["derived"]["selection"]
        require(selected["identity"] == same["id"] and selected["value"] == "12"
                and get(reader)["version"] != unchanged["version"], "Same payload lost changed identity")
        mutate("winner-rekey", [update(same["id"], {"at": "11"})])
        require(get(reader)["derived"]["selection"]["identity"] == winner, "Rekey failed to replace winner")
        mutate("retarget-empty", [update(reader, {"instrument": other})])
        require(get(reader)["derived"] == {"selection": None}, "Empty retarget invented a value")
        mutate("unit-only-empty-parent", [update(other, {"unit": 8})], "invariant")
        first = create("first", 211, {"instrument": other, "at": "5", "unit": 7, "value": "12"})
        mutate("first-candidate", [first])
        require(get(reader)["derived"]["selection"]["identity"] == first["id"]
                and measurements["first-candidate"]["causal_evaluations"] == 1,
                "Absent selection lost its entire search dependency")
        extras = [create(f"selector-{n}", 419, {"instrument": other, "at": "10", "unit": 7}) for n in range(7)]
        sibling = create("sibling", 419, {"instrument": instrument, "at": "10", "unit": 7})
        mutate("seven-more-and-other-root", [*extras, sibling])
        mutate("eight-selected", [update(first["id"], {"at": "6"})])
        require(measurements["eight-selected"]["causal_evaluations"] == 8, "Eight selected consumers")
        mutate("retire-extra-selectors", [delete(row["id"]) for row in extras])
        unchanged = get(sibling["id"])
        mutate("move-between-roots", [update(first["id"], {"instrument": instrument, "at": "9"})])
        require(get(reader)["derived"] == {"selection": None} and get(sibling["id"]) == unchanged
                and measurements["move-between-roots"]["causal_evaluations"] == 2,
                "Old and new root dependencies must both evaluate")
        mutate("delete-winner", [delete(winner)])
        require(get(sibling["id"])["derived"]["selection"]["identity"] == loser, "Winner deletion fallback")
        mutate("delete-next-winner", [delete(loser)])
        require(get(sibling["id"])["derived"]["selection"]["identity"] == first["id"], "Next winner fallback")
        mutate("retarget-and-unit-repair", [
            update(sibling["id"], {"instrument": other, "unit": 8}),
            update(reader, {"unit": 8}),
            update(first["id"], {"instrument": other, "unit": 8}),
            update(other, {"unit": 8})])
        mutate("parent-first-unit-repair", [update(other, {"unit": 7}), update(first["id"], {"unit": 7}),
                                           update(reader, {"unit": 7}), update(sibling["id"], {"unit": 7})])
        mutate("rollback-after-member-change", [update(first["id"], {"at": "8", "value": "-9"}),
                                               update(reader, {"unit": 8})], "invariant")
        mutate("delete-last-and-retarget-sibling", [delete(first["id"]),
                                                   update(sibling["id"], {"instrument": instrument, "at": "11"})])
        require(get(reader)["derived"] == {"selection": None}
                and get(sibling["id"])["derived"]["selection"]["identity"] == same["id"],
                "Final absent and present native selections")

        grants(False, True)
        require(get(other, token) is None and get(reader, token) == get(reader), "Materialized selection Read policy")
        mutate("denied-new-reference", [create("denied", 419, {"instrument": other, "at": "10", "unit": 7})],
               "forbidden", credential=token)
        mutate("denied-retarget", [update(reader, {"instrument": instrument})], "forbidden", credential=token)
        receipt, accepted = mutate("unchanged-reference", [update(reader, {"at": "9"})], credential=token, returning=[reader])
        require(accepted["result"]["records"][0]["record"] is not None, "Selection receipt initially hidden")
        grants(False, False)
        require(get(reader, token) is None and get(sibling["id"], token) is None, "Selection Read was not revoked")
        page = client.call(backend.url, token, "records.page", {"model": model,
            "query": {"path": "records.by_id", "contract": None, "equals": None}, "limit": 32, "visit_budget": 128, "cursor": None})
        require(page["exhausted"] and all(row["contract"] != 419 for row in page["records"]), "Denied selection page disclosure")
        require(client.execute(backend.url, token, receipt)["result"]["records"][0]["record"] is None, "Revoked replay disclosure")

        before = verify(backend, model, facts)
        backend.stop()
        integrity = backend.cli("check", backend.store)
        view = backend.cli("inspect", backend.store)
        require(len(view["queries"]) == 3 and not view["roles"] and len(view["roots"]) == 2,
                "Consumer query/root/output inventory")
        backup = backend.directory / "verified-backup.json"
        backend.cli("backup", backend.store, backup)
        backend.start()
        require(verify(backend, model, facts) == before, "Reopen changed selection/report")
        require(client.execute(backend.url, backend.token, last_owner[0])["result"] == last_owner[1]["result"], "Reopen replay differs")
        backend.crash()
        backend.start()
        require(verify(backend, model, facts) == before, "Crash recovery changed selection/report")
        backend.stop()
        restored = backend.directory / "restored.redb"
        backend.cli("restore", backup, restored)
        backend.store = restored
        backend.start()
        require(verify(backend, model, facts) == before, "Restore changed selection/report")
        require(client.execute(backend.url, token, receipt)["result"]["records"][0]["record"] is None, "Restore lost selection authority")
        return {"status": "passed", "model": model, "operations": operations, "measurements": measurements,
                "public_sources": len(facts), "queries": 3, "private_outputs": 0, "oracle_controls": controls,
                "integrity": integrity, "complete_table_rollback": True, "reopen": True, "replay": True,
                "crash_recovery": True, "restore": True, "materialized_selection_authority": True,
                "duration_seconds": round(time.monotonic() - started, 3),
                "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest()}
    finally:
        backend.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--oracle-only", action="store_true")
    args = parser.parse_args()
    if args.oracle_only:
        print(json.dumps({"status": "passed", "oracle_controls": oracle_controls()}))
        return
    if args.binary is None or args.out is None:
        parser.error("--binary and --out are required for the HTTP workflow")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    result = run(args.binary.resolve(), args.out)
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
