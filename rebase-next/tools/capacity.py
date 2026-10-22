#!/usr/bin/env python3
"""G2 equipment population probe: real HTTP, source arithmetic, operator counters."""

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import platform
import time
import uuid

import client
from harness import Backend, require, process_usage


def identity(number):
    return str(uuid.UUID(int=number))


def scan(backend, model, limit):
    records, cursor = [], None
    for _ in range(limit // 32 + 2):
        page = backend.call("records.page", {"model": model,
            "query": {"path": "records.by_id", "contract": None, "equals": None},
            "limit": 32, "visit_budget": 128, "cursor": cursor})
        records.extend(page["records"])
        if page["exhausted"]:
            require([r["id"] for r in records] == sorted({r["id"] for r in records}),
                    "Public page order/identity mismatch")
            return records
        require(page["cursor"] and page["cursor"] != cursor, "Page made no progress")
        cursor = page["cursor"]
    raise RuntimeError("Incomplete population observation")


def equipment_expected(facts):
    """A source scan. No native queries, private outputs, or scheduler are used."""
    events, derived = defaultdict(list), {}
    for value in facts.values():
        if value["contract"] == 205:
            f = value["fields"]
            events[f["pool"]].append((int(f["at"]), int(f["quantity"])))
    reservations = sorted((int(v["fields"]["starts"]), key, v["fields"])
                          for key, v in facts.items() if v["contract"] == 410)
    for _, key, f in reservations:
        before = sum(q for at, q in events[f["pool"]] if at < int(f["starts"])) if f["active"] else 0
        allocated = min(int(f["requested"]), max(0, before)) if f["active"] else 0
        derived[key] = {"available_before": str(before), "allocated": str(allocated)}
        if f["active"]:
            events[f["pool"]].extend([(int(f["starts"]), -allocated), (int(f["ends"]), allocated)])
    for rows in events.values():
        grouped = defaultdict(int)
        for at, q in rows:
            grouped[at] += q
        balance = 0
        for at in sorted(grouped):
            balance += grouped[at]
            require(balance >= 0, "Authored workload has an invalid complete-time prefix")
    return events, derived


def verify_equipment(backend, model, facts):
    events, expected = equipment_expected(facts)
    observed = {r["id"]: r for r in scan(backend, model, len(facts))}
    require(observed.keys() == facts.keys(), "Public source inventory mismatch")
    for key, source in facts.items():
        record = observed[key]
        require(record["contract"] == source["contract"] and record["input"] == source["fields"],
                f"Authored input mismatch: {key}")
        require(record["derived"] == expected.get(key), f"Independent allocation mismatch: {key}")
    for pool, rows in events.items():
        summary = backend.call("roots.read", {"model": model, "owner": pool, "slot": 7,
                                               "read": {"kind": "summary"}})["value"]
        require(summary["sum"] == str(sum(q for _, q in rows)) and summary["count"] == len(rows),
                "Independent root sum/count mismatch")
    return observed


def work_for(backend, operation):
    rows = [json.loads(line) for line in (backend.directory / "server.log").read_text().splitlines()
            if line.startswith('{"event":"mutation_work"')]
    matching = [row["work"] for row in rows if row["operation_id"] == operation]
    require(len(matching) == 1, "Missing or duplicated committed operator work observation")
    return matching[0]


def apply(backend, model, commands, label):
    plan = backend.plan({"model": model, "commands": commands, "returning": []}, label)
    start = time.perf_counter()
    result = client.execute(backend.url, backend.token, plan)
    elapsed = (time.perf_counter() - start) * 1000
    return plan, result, {"latency_ms": round(elapsed, 3), "work": work_for(backend, plan["request"]["operation_id"])}


def equipment_run(binary, directory, reservations):
    backend = Backend(binary, directory, "equipment")
    facts = {}
    pool, supply, tail, after = (identity(n) for n in range(1, 5))
    def source(key, code, fields):
        facts[key] = {"contract": code, "fields": fields}
        return {"op": "create", "id": key, "contract": code, "fields": fields}
    last_start = 10 + (reservations - 1) * 4
    commands = [source(pool, 101, {"unit": 1}),
        source(supply, 205, {"pool": pool, "at": "0", "quantity": "10"}),
        source(tail, 205, {"pool": pool, "at": str(last_start - 1), "quantity": "1"}),
        source(after, 205, {"pool": pool, "at": str(last_start + 3), "quantity": "1"})]
    commands += [source(identity(100 + i), 410, {"pool": pool, "starts": str(10 + i * 4),
        "ends": str(12 + i * 4), "requested": "20", "active": True}) for i in range(reservations)]
    try:
        backend.start()
        model = backend.call("model.describe", {})["model"]
        for i in range(0, len(commands), 32):
            apply(backend, model, commands[i:i + 32], f"populate-{i}")
        observed = verify_equipment(backend, model, facts)
        measurements = {}
        for label, key, quantity in [("after_all_reads", after, "2"), ("last_read", tail, "2"),
                                      ("full_fanout", supply, "12")]:
            update = {"op": "update", "id": key, "if_version": observed[key]["version"],
                      "set": {"quantity": quantity}, "unset": []}
            _, _, measurements[label] = apply(backend, model, [update], label)
            facts[key]["fields"]["quantity"] = quantity
            observed = verify_equipment(backend, model, facts)
        usage = process_usage(backend.process.pid)
        backend.stop()
        integrity = backend.cli("check", backend.store)
        report = {"public_sources": len(facts), "active_reservations": reservations,
                  "measurements": measurements, "integrity": integrity, "process": usage}
        (backend.directory / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        return report
    finally:
        backend.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reservations", type=int, nargs="+", default=[16, 24])
    args = parser.parse_args()
    require(all(n > 0 for n in args.reservations), "Positive reservation counts required")
    args.out.mkdir(mode=0o700)
    report = {"status": "passed", "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              "host": {"system": platform.system(), "machine": platform.machine(), "kernel": platform.release()},
              "runs": []}
    for n in args.reservations:
        report["runs"].append(equipment_run(args.binary, args.out / f"equipment-{n}", n))
        (args.out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"Equipment: {n} reservations verified", flush=True)


if __name__ == "__main__":
    main()
