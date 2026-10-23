#!/usr/bin/env python3
"""G4d-b: literal authored statistics, selective reactions, authority and recovery."""
import argparse
import hashlib
import json
from pathlib import Path
import time
import uuid

import client
from capacity import restricted_actor, snapshot, work_for
from harness import Backend, expect_error, require
from invoicing import propose, scan


def contains(at, window):
    for side in ("lower", "upper"):
        bound = window[side]
        if bound is None:
            continue
        kind, text = next(iter(bound.items()))
        value = int(text)
        require(kind in ("included", "excluded") and -(2**63) <= value < 2**63,
                "Exact source time bound")
        if side == "lower" and (at < value or (at == value and kind == "excluded")):
            return False
        if side == "upper" and (at > value or (at == value and kind == "excluded")):
            return False
    return True


def report(values, unit, threshold):
    return {"count": len(values), "min": str(min(values)) if values else None,
            "max": str(max(values)) if values else None, "unit": unit,
            "at_least_threshold": bool(values) and all(v >= threshold for v in values)}


def expected(facts):
    """Expectations come only from retained complete authored inputs."""
    require(len(facts) <= 64, "Measurement source bound")
    roots = {key: [] for key, row in facts.items() if row["contract"] == 101}
    for row in facts.values():
        fields = row["fields"]
        require(1 <= fields["unit"] <= 65535, "Unit code bound")
        if row["contract"] == 101:
            continue
        require(row["contract"] in (211, 307), "Known measurement contract")
        instrument = fields["instrument"]
        require(instrument in roots and facts[instrument]["fields"]["unit"] == fields["unit"],
                "Authored parent dimension")
        if row["contract"] == 211:
            at, value = int(fields["at"]), int(fields["value"])
            require(-(2**63) <= at < 2**63 and abs(value) <= 10**12, "Observation bounds")
            roots[instrument].append((at, value))
        else:
            require(abs(int(fields["threshold"])) <= 10**12, "Threshold bound")
    derived = {}
    for key, row in facts.items():
        fields = row["fields"]
        derived[key] = None
        if row["contract"] == 307:
            values = [value for at, value in roots[fields["instrument"]] if contains(at, fields["range"])]
            derived[key] = report(values, fields["unit"], int(fields["threshold"]))
    return roots, derived


def verify(backend, model, facts):
    roots, derived = expected(facts)
    records = scan(backend, model)
    require(records.keys() == facts.keys(), "Complete authored inventory")
    for identity, source in facts.items():
        record = records[identity]
        require(record["contract"] == source["contract"] and record["input"] == source["fields"],
                "Authored fields differ")
        require(record["derived"] == derived[identity], f"Source-derived report differs: {identity}")
    for instrument, events in roots.items():
        values = [value for _, value in events]
        summary = {"count": len(values), "sum": str(sum(values)),
                   "min": str(min(values)) if values else None, "max": str(max(values)) if values else None,
                   "unit": facts[instrument]["fields"]["unit"] if values else None}
        require(backend.call("roots.read", {"model": model, "owner": instrument, "slot": 7,
                "read": {"kind": "summary"}})["value"] == summary, "Literal root summary differs")
    return records


def oracle_controls():
    events = [(0, 5), (10, 12), (20, -2)]
    cases = [
        (None, None, [5, 12, -2]),
        (None, {"excluded": "0"}, []),
        (None, {"included": "0"}, [5]),
        ({"included": "0"}, {"excluded": "20"}, [5, 12]),
        ({"excluded": "0"}, {"included": "20"}, [12, -2]),
        ({"included": "10"}, {"included": "10"}, [12]),
        ({"included": "10"}, {"excluded": "10"}, []),
        ({"included": "21"}, None, []),
        ({"included": str(-(2**63))}, {"included": str(2**63 - 1)}, [5, 12, -2]),
    ]
    for lower, upper, values in cases:
        require([v for at, v in events if contains(at, {"lower": lower, "upper": upper})] == values,
                "Literal oracle bound control")
    require(report([], 7, -1) == {"count": 0, "min": None, "max": None, "unit": 7,
            "at_least_threshold": False}, "Empty does not invent a minimum")
    require(report([5, 12], 7, 5)["at_least_threshold"], "Threshold equality")
    require(not report([5, 12, -2], 7, 5)["at_least_threshold"], "Negative observation")
    return len(cases) + 3


def run(binary, destination):
    started = time.monotonic()
    controls = oracle_controls()
    backend = Backend(binary, destination, model="measurement")
    facts, operations, measurements = {}, [], {}
    latest = None
    namespace = uuid.UUID(int=20261025)
    try:
        backend.start()
        model = backend.call("model.describe", {})["model"]
        token = restricted_actor(backend, model)
        actor = client.call(backend.url, token, "session.describe", {})["actor"]

        def grants(parent_read, report_read):
            access = backend.call("access.describe", {"model": model})
            principal = next(p for p in access["graph"]["principals"] if p["id"] == actor)
            principal["grants"]["contracts"] = {
                "101": (["read"] if parent_read else []) + ["create", "update"],
                "211": ["read", "create", "update", "delete"],
                "307": (["read"] if report_read else []) + ["create", "update", "delete"]}
            backend.call("access.replace", {"model": model, "if_revision": access["revision"], "graph": access["graph"]})

        def get(identity, credential=None):
            return client.call(backend.url, credential or backend.token, "records.get", {"model": model, "id": identity})

        def update(identity, fields):
            return {"op": "update", "id": identity, "if_version": get(identity)["version"], "set": fields, "unset": []}

        def create(label, code, fields):
            return {"op": "create", "id": str(uuid.uuid5(namespace, label)), "contract": code, "fields": fields}

        def mutate(label, commands, error=None, credential=None, returning=None):
            nonlocal facts, latest
            credential = credential or backend.token
            plan = client.prepare(backend.url, credential, {"model": model, "commands": commands, "returning": returning or []})
            client.save_plan(backend.directory / f"{label}.plan.json", plan)
            if error:
                before = snapshot(backend, f"{label}-before")
                expect_error(error, lambda: client.execute(backend.url, credential, plan))
                require(snapshot(backend, f"{label}-after") == before, "Complete rollback differs")
                require(client.execute(backend.url, credential, plan, status=True)["status"] == "not_observed", "Rejected receipt exists")
                result = None
            else:
                proposed = propose(facts, commands)
                expected(proposed)
                result = client.execute(backend.url, credential, plan)
                require(result["status"] == "committed", "Mutation did not commit")
                facts = proposed
                verify(backend, model, facts)
                replay = client.execute(backend.url, credential, plan)
                require(replay["replayed"] and replay["result"] == result["result"], "Immediate replay differs")
                measurements[label] = work_for(backend, plan["request"]["operation_id"])
                if credential == backend.token:
                    latest = (plan, result)
            operations.append({"name": label, "commands": len(commands), "result": error or "committed"})
            return plan, result

        grants(True, True)
        draft = backend.cli("fixture", "plan", "observation-report", "--namespace", namespace)
        ids = draft["fixture"]["ids"]
        instrument, other, a, b, c, reader = (ids[name] for name in ("instrument", "other", "a", "b", "c", "report"))
        mutate("fixture", draft["commands"], credential=token, returning=[reader])
        require(get(reader)["derived"] == report([5, 12], 7, 5), "Initial literal report")
        mutate("move-into-window", [update(c, {"at": "15"})])
        require(get(reader)["derived"] == report([5, 12, -2], 7, 5), "Moved literal report")
        require(measurements["move-into-window"]["causal_evaluations"] == 1, "One report selected")
        mutate("move-out-of-window", [update(c, {"at": "20"})])
        unchanged = get(reader)
        mutate("outside-window", [update(c, {"value": "-9"})])
        require(get(reader) == unchanged and measurements["outside-window"]["causal_evaluations"] == 0, "Outside change selected report")
        mutate("equal-result-rekey", [update(b, {"at": "11"})])
        require(get(reader) == unchanged and measurements["equal-result-rekey"]["causal_evaluations"] == 1, "Equal result lost its dependency")
        mutate("empty-window", [update(reader, {"range": {"lower": {"included": "10"}, "upper": {"excluded": "10"}}, "threshold": "-1"})])
        require(get(reader)["derived"] == report([], 7, -1), "Empty negative-threshold report")
        window = {"lower": {"included": "0"}, "upper": {"excluded": "20"}}
        mutate("restore-window", [update(reader, {"range": window, "threshold": "5"})])
        mutate("seven-more-reports", [create(f"report-{n}", 307, {"instrument": instrument, "range": window, "unit": 7, "threshold": "5"}) for n in range(7)])
        mutate("eight-selected", [update(a, {"value": "6"})])
        require(measurements["eight-selected"]["causal_evaluations"] == 8, "Eight report fanout")
        mutate("retarget-to-empty", [update(reader, {"instrument": other})])
        require(get(reader)["derived"] == report([], 7, 5), "Retargeted empty report")
        mutate("unit-only-empty-parent", [update(other, {"unit": 8})], "invariant")
        detached = get(reader)
        mutate("detached-root", [update(a, {"value": "7"})])
        require(get(reader) == detached and measurements["detached-root"]["causal_evaluations"] == 7, "Detached consumer selected")
        first = create("first-in-empty-root", 211, {"instrument": other, "at": "0", "unit": 7, "value": "5"})
        mutate("first-candidate", [first])
        require(get(reader)["derived"] == report([5], 7, 5), "First member failed to wake empty query")
        for unit, parent_first in ((8, True), (7, False)):
            commands = [update(other, {"unit": unit}), update(first["id"], {"unit": unit}), update(reader, {"unit": unit})]
            mutate(f"unit-repair-{unit}", commands if parent_first else list(reversed(commands)))
        mutate("rollback-after-member-change", [update(first["id"], {"value": "-10"}), update(reader, {"unit": 8})], "invariant")
        mutate("delete-last-member", [{"op": "delete", "id": first["id"], "if_version": get(first["id"])["version"]}])
        require(get(reader)["derived"] == report([], 7, 5), "All members deleted")

        grants(False, True)
        require(get(other, token) is None and get(reader, token) == get(reader), "Materialized report authority")
        mutate("denied-new-reference", [create("denied-report", 307, {"instrument": other, "range": window, "unit": 7, "threshold": "5"})], "forbidden", credential=token)
        mutate("denied-retarget", [update(reader, {"instrument": instrument})], "forbidden", credential=token)
        receipt, accepted = mutate("unchanged-reference", [update(reader, {"threshold": "6"})], credential=token, returning=[reader])
        require(accepted["result"]["records"][0]["record"] is not None, "Report receipt initially hidden")
        grants(False, False)
        require(get(reader, token) is None, "Report read was not revoked")
        page = client.call(backend.url, token, "records.page", {"model": model,
            "query": {"path": "records.by_id", "contract": None, "equals": None}, "limit": 32, "visit_budget": 128, "cursor": None})
        require(page["exhausted"] and all(row["contract"] != 307 for row in page["records"]), "Denied report page disclosure")
        require(client.execute(backend.url, token, receipt)["result"]["records"][0]["record"] is None, "Revoked replay disclosure")

        before = verify(backend, model, facts)
        backend.stop()
        integrity = backend.cli("check", backend.store)
        view = backend.cli("inspect", backend.store)
        require(len(view["queries"]) == 8 and not view["roles"] and len(view["roots"]) == 2,
                "Report query/root/output inventory")
        backup = backend.directory / "verified-backup.json"
        backend.cli("backup", backend.store, backup)
        backend.start()
        require(verify(backend, model, facts) == before, "Reopen changed reports")
        require(client.execute(backend.url, backend.token, latest[0])["result"] == latest[1]["result"], "Reopen replay differs")
        backend.crash()
        backend.start()
        require(verify(backend, model, facts) == before, "Crash recovery changed reports")
        backend.stop()
        restored = backend.directory / "restored.redb"
        backend.cli("restore", backup, restored)
        backend.store = restored
        backend.start()
        require(verify(backend, model, facts) == before, "Restore changed reports")
        require(client.execute(backend.url, token, receipt)["result"]["records"][0]["record"] is None, "Restore lost report authority")
        return {"status": "passed", "model": model, "operations": operations, "measurements": measurements,
                "public_sources": len(facts), "queries": 8, "private_outputs": 0, "oracle_controls": controls,
                "integrity": integrity, "complete_table_rollback": True, "reopen": True, "replay": True,
                "crash_recovery": True, "restore": True, "materialized_report_authority": True,
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
    print(json.dumps({key: value for key, value in result.items() if key not in ("operations", "measurements")}, indent=2))


if __name__ == "__main__":
    main()
