#!/usr/bin/env python3
"""G2 population acceptance: real HTTP, independent arithmetic and bounded work."""

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import platform
import time
import uuid

import client
from harness import Backend, command, expect_error, require, process_usage, write_private

MUTATION_TIMING = ("Client wall time for client.execute through the committed or rejected response, "
                   "including destination session check; excludes plan preparation and rollback verification")
AUTHORITY_TIMING = "Client wall time for access.replace response; excludes verification and reopen"


def identity(number):
    return str(uuid.UUID(int=number))


def scan(backend, model, limit):
    records, cursor = [], None
    for _ in range(limit // 32 + 2):
        page = backend.call("records.page", {"model": model,
            "query": {"path": "records.by_id", "contract": None, "equals": None},
            "limit": 32, "visit_budget": 128, "cursor": cursor})
        records.extend(page["records"])
        require(len(page["records"]) <= 32, "Page exceeded the preserved return bound")
        if page["exhausted"]:
            require(page["cursor"] is None, "Exhausted scan retained a cursor")
            require([r["id"] for r in records] == sorted({r["id"] for r in records}),
                    "Public page order/identity mismatch")
            return records
        require(page["cursor"] and page["cursor"] != cursor, "Page made no progress")
        cursor = page["cursor"]
    raise RuntimeError("Incomplete population observation")


def equipment_expected(facts):
    """A source scan. No native queries, private outputs, or scheduler are used."""
    events, derived = defaultdict(list), {}
    for key, value in facts.items():
        if value["contract"] == 101:
            events[key]  # Include a temporarily empty retarget destination.
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


def verify_sources(backend, model, facts, expected):
    observed = {r["id"]: r for r in scan(backend, model, len(facts))}
    require(observed.keys() == facts.keys(), "Public source inventory mismatch")
    for key, source in facts.items():
        record = observed[key]
        require(record["contract"] == source["contract"] and record["input"] == source["fields"],
                f"Authored input mismatch: {key}")
        require(record["derived"] == expected.get(key), f"Independent allocation mismatch: {key}")
    return observed


def verify_equipment(backend, model, facts):
    events, expected = equipment_expected(facts)
    observed = verify_sources(backend, model, facts, expected)
    for pool, rows in events.items():
        summary = backend.call("roots.read", {"model": model, "owner": pool, "slot": 7,
                                               "read": {"kind": "summary"}})["value"]
        require(summary["sum"] == str(sum(q for _, q in rows)) and summary["count"] == len(rows),
                "Independent root sum/count mismatch")
        for at in (10, max((int(v["fields"]["starts"]) for v in facts.values()
                            if v["contract"] == 410), default=10)):
            prefix = backend.call("roots.read", {"model": model, "owner": pool, "slot": 7,
                "read": {"kind": "before", "at": str(at)}})["value"]
            require(prefix["sum"] == str(sum(q for time, q in rows if time < at)),
                    "Independent strict prefix mismatch")
    return observed


def calculation_expected(facts):
    """Literal authored posting formula and quote predecessor scan."""
    derived, sums, counts = {}, defaultdict(int), defaultdict(int)
    curves = defaultdict(list)
    for value in facts.values():
        if value["contract"] == 3:
            f = value["fields"]
            curves[f["curve"]].append((int(f["at"]), int(f["rate"])))
    for key, value in facts.items():
        if value["contract"] != 6:
            continue
        f = value["fields"]
        quotes = [(at, rate) for at, rate in curves[f["curve"]] if at <= int(f["at"])]
        rate = max(quotes)[1] if quotes else 1
        native = int(f["units"]) * int(facts[f["rule"]]["fields"]["c"])
        reporting = native * rate
        derived[key] = {"native_minor": str(native), "reporting_minor": str(reporting)}
        for root, amount in (((f["account"], 2), native), ((f["subsidiary"], 3), reporting)):
            sums[root] += amount
            counts[root] += 1
    return derived, sums, counts


def verify_calculation(backend, model, facts):
    expected, sums, counts = calculation_expected(facts)
    observed = verify_sources(backend, model, facts, expected)
    for (owner, slot), amount in sums.items():
        summary = backend.call("roots.read", {"model": model, "owner": owner, "slot": slot,
                                               "read": {"kind": "summary"}})["value"]
        require(summary["sum"] == str(amount) and summary["count"] == counts[(owner, slot)],
                "Independent calculation publication mismatch")
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
    return plan, result, {"latency_ms": round(elapsed, 3), "timing_scope": MUTATION_TIMING,
                         "work": work_for(backend, plan["request"]["operation_id"])}


def snapshot(backend, label):
    """A stopped, complete logical byte observation, including all receipts/indexes."""
    backend.stop()
    path = backend.directory / f"{label}.backup.json"
    backend.cli("backup", backend.store, path)
    value = json.loads(path.read_text())
    require(value["payload"]["complete"], "Incomplete rollback observation")
    backend.start()
    return value["payload"]


def retained_roles(path):
    """Exact persisted role/reservation bytes, from existing complete backups."""
    rows = json.loads(path.read_text())["payload"]["tables"]["native_kv"]
    # Native point-key tags 8/9 are Role/Reserved; the source oracle never
    # derives amounts from them. Equality tests identity reuse across lifecycle.
    return {row["key"]: row["value"] for row in rows if row["key"][:2] in ("08", "09")}


def check_selective(measurement, candidates, field="causal_candidates"):
    work = measurement["work"]
    require(work[field] == candidates, f"Expected {candidates} selected producers: {work}")
    require(work["selector_visits"] <= 256 and work["key_loads"] <= 256,
            f"Selective edit exceeded fixed visits/loaded-key bounds: {work}")


def check_fanout(measurement, producers, reads=1, emits=2):
    work = measurement["work"]
    bound = 16 * producers * (1 + reads + emits)
    require(work["work_units"] <= 200000, "Committed outside the fixed engine budget")
    require(work["dependency_checks"] + work["dependency_edges"] <= bound,
            "Scheduler checks/edges exceeded linear resolved-shape bound")


def update_command(key, observed, fields):
    return {"op": "update", "id": key, "if_version": observed[key]["version"],
            "set": fields, "unset": []}


def edit(backend, model, facts, observed, key, fields, label):
    plan, result, measurement = apply(backend, model, [update_command(key, observed, fields)], label)
    require(result["status"] == "committed", "Mutation did not commit")
    facts[key]["fields"].update(fields)
    return plan, result, measurement


def fanout(backend, model, facts, observed, key, fields, producers):
    """One trial per population. A finite work limit is an accepted measured outcome."""
    before = snapshot(backend, "before-full-fanout")
    plan = backend.plan({"model": model, "commands": [update_command(key, observed, fields)],
                         "returning": []}, "full-fanout")
    begin = time.perf_counter()
    try:
        result = client.execute(backend.url, backend.token, plan)
    except client.RpcError as error:
        elapsed = round((time.perf_counter() - begin) * 1000, 3)
        require(error.kind == "work_limit", f"Unexpected fanout rejection: {error.kind}")
        require(client.execute(backend.url, backend.token, plan, status=True)["status"] == "not_observed",
                "Rejected fanout published a receipt")
        require(snapshot(backend, "after-full-fanout") == before,
                "Work-limit rejection changed logical application-table bytes")
        return {"status": "work_limit", "affected_producers": producers,
                "logical_bytewise_rollback": True, "receipt_absent": True,
                "latency_ms": elapsed, "timing_scope": MUTATION_TIMING}, None, None
    measurement = {"status": "committed", "affected_producers": producers,
                   "latency_ms": round((time.perf_counter() - begin) * 1000, 3),
                   "timing_scope": MUTATION_TIMING,
                   "work": work_for(backend, plan["request"]["operation_id"])}
    check_fanout(measurement, producers)
    facts[key]["fields"].update(fields)
    return measurement, plan, result


def restricted_actor(backend, model):
    """Install a real current principal with no grants before population grows."""
    access = backend.call("access.describe", {"model": model})
    actor = str(uuid.uuid4())
    access["graph"]["principals"].append({"id": actor, "kind": "user",
        "parents": [backend.tenant], "active": True, "credential_epoch": 0,
        "grants": {"admin": False, "contracts": {}}})
    backend.call("access.replace", {"model": model, "if_revision": access["revision"],
                                     "graph": access["graph"]})
    request = backend.directory / "restricted-token-request.json"
    write_private(request, client._bytes({"tenant": backend.tenant, "actor": actor,
        "epoch": 0, "ttl": 600, "key_id": "harness"}))
    return command(backend.binary, "auth", "issue", backend.config_path,
                   request, backend.private).decode().strip()


def authority_lifecycle(backend, model, restricted):
    """A real post-population graph edit, with the same finite transaction budget."""
    session = client.call(backend.url, restricted, "session.describe", {})
    records = scan(backend, model, 4096)
    require(len(records) == 4096, "Authority trial requires the accepted full population")
    access = backend.call("access.describe", {"model": model})
    principal = next(p for p in access["graph"]["principals"] if p["id"] == session["actor"])
    require(principal["active"], "Revocation control requires an initially valid credential")
    principal["active"] = False
    principal["credential_epoch"] += 1
    before = snapshot(backend, "before-authority")
    started = time.perf_counter()
    try:
        outcome = backend.call("access.replace", {"model": model, "if_revision": access["revision"],
                                                  "graph": access["graph"]})
    except client.RpcError as error:
        elapsed = round((time.perf_counter() - started) * 1000, 3)
        require(error.kind == "work_limit", f"Unexpected graph-edit rejection: {error.kind}")
        require(snapshot(backend, "after-authority") == before,
                "Over-budget graph edit changed logical table bytes")
        require(client.call(backend.url, restricted, "session.describe", {}) == session,
                "Rejected graph edit changed current credential authority")
        result = {"status": "work_limit", "logical_bytewise_rollback": True,
                  "old_token_remains_valid": True, "latency_ms": elapsed}
    else:
        elapsed = round((time.perf_counter() - started) * 1000, 3)
        require(outcome["changed"] and int(outcome["revision"]) == int(access["revision"]) + 1,
                "Graph replacement did not commit precisely one revision")
        expect_error("forbidden", lambda: client.call(backend.url, restricted, "session.describe", {}))
        require(backend.call("access.describe", {"model": model})["graph"] == access["graph"],
                "Committed graph differs from requested revocation")
        result = {"status": "committed", "disabled": True, "credential_epoch_incremented": True,
                  "old_token_rejected": True, "old_token_error_kind": "forbidden", "latency_ms": elapsed}
    backend.stop()
    result["integrity"] = backend.cli("check", backend.store)
    require(result["integrity"]["status"] == "valid", "Authority trial left invalid inventory")
    backend.start()
    require(scan(backend, model, 4096) == records, "Authority edit changed public source state")
    if result["status"] == "committed":
        expect_error("forbidden", lambda: client.call(backend.url, restricted, "session.describe", {}))
        require(backend.call("access.describe", {"model": model})["graph"] == access["graph"],
                "Reopen lost the committed graph")
    else:
        require(client.call(backend.url, restricted, "session.describe", {}) == session,
                "Reopen changed the rejected graph's credentials")
    result["reopen_verified"] = True
    result["timing_scope"] = AUTHORITY_TIMING
    return result


def authority_run(binary, original, directory, selector):
    """Restore an accepted backup into an owned trial, leaving accepted stores untouched."""
    original = Path(original).resolve()
    backend = Backend.__new__(Backend)
    backend.binary, backend.selector = Path(binary).resolve(), ["--model", selector]
    backend.directory = Path(directory).resolve()
    backend.directory.mkdir(mode=0o700)
    backend.store, backend.config_path = backend.directory / "app.redb", backend.directory / "server.json"
    backend.process, backend.log = None, None
    backend.config = json.loads((original / "server.json").read_text())
    backend.config["listen"] = "127.0.0.1:0"
    write_private(backend.config_path, client._bytes(backend.config))
    backend.private = original / "issuer-private.pem"
    for label, source in (("admin", "token-request.json"), ("restricted", "restricted-token-request.json")):
        request = json.loads((original / source).read_text())
        path = backend.directory / f"{label}-token-request.json"
        write_private(path, client._bytes(request))
        token = command(backend.binary, "auth", "issue", backend.config_path, path, backend.private).decode().strip()
        if label == "admin":
            backend.token, backend.tenant, backend.actor = token, request["tenant"], request["actor"]
        else:
            restricted = token
    backup = original / "final.backup.json"
    backend.cli("restore", backup, backend.store)
    try:
        backend.start()
        model = backend.call("model.describe", {})["model"]
        report = {"model": selector, "public_sources": 4096,
                  "source_backup_sha256": hashlib.sha256(backup.read_bytes()).hexdigest(),
                  "authority_lifecycle": authority_lifecycle(backend, model, restricted)}
        (backend.directory / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        return report
    finally:
        backend.stop()


def rejections(backend, model, facts, observed, key, invalid_fields, restricted):
    before = snapshot(backend, "before-rejections")
    update = update_command(key, observed, invalid_fields)
    plans = []
    for label, kind, mutation in (("invariant", "invariant", update),
        ("stale", "stale_version", {**update, "if_version": "0"})):
        plan = backend.plan({"model": model, "commands": [mutation], "returning": []}, label)
        expect_error(kind, lambda: client.execute(backend.url, backend.token, plan))
        plans.append(plan)
    unauthorized = client.prepare(backend.url, restricted,
        {"model": model, "commands": [update], "returning": []})
    expect_error("forbidden", lambda: client.execute(backend.url, restricted, unauthorized))
    require(client.execute(backend.url, restricted, unauthorized, status=True)["status"] == "not_observed",
            "Unauthorized mutation published a receipt")
    require(client.call(backend.url, restricted, "records.get", {"model": model, "id": key}) is None,
            "Unprivileged principal observed a private reader partition")
    template = plans[0]["request"]
    for label, changes in (("commands", {"commands": [
            {"op": "create", "id": identity(100000 + i), "contract": 7,
             "fields": {"at": "0"}} for i in range(65)]}),
        ("returning", {"returning": [identity(i + 1) for i in range(33)]})):
        request = {**template, **changes, "operation_id": str(uuid.uuid4())}
        expect_error("invalid_input", lambda: backend.call("records.mutate", request))
    if len(facts) == 4096:
        code, fields = (101, {"unit": 1}) if backend.selector[-1] == "equipment" else (7, {"at": "0"})
        overflow = backend.plan({"model": model, "commands": [{"op": "create", "id": identity(99999),
            "contract": code, "fields": fields}], "returning": []}, "overflow")
        expect_error("state_limit", lambda: client.execute(backend.url, backend.token, overflow))
        plans.append(overflow)
    for plan in plans:
        require(client.execute(backend.url, backend.token, plan, status=True)["status"] == "not_observed",
                "Rejected request left a success receipt")
    require(snapshot(backend, "after-rejections") == before,
            "Rejection changed logical table bytes, revisions, indexes or receipts")
    return {"invariant": True, "stale_version": True, "authorization": True,
            "commands_65": True, "returning_33": True, "overflow": len(facts) == 4096,
            "logical_bytewise_rollback": True}


def recover(backend, model, facts, verify, plan, result):
    usage = process_usage(backend.process.pid)
    backend.stop()
    backend.start()
    verify(backend, model, facts)
    require(client.execute(backend.url, backend.token, plan, status=True)["result"] == result["result"],
            "Restart lost a committed receipt")
    replay = client.execute(backend.url, backend.token, plan)
    require(replay["replayed"] and replay["result"] == result["result"], "Restart replay changed outcome")
    backend.crash()
    backend.start()
    verify(backend, model, facts)
    require(client.execute(backend.url, backend.token, plan, status=True)["result"] == result["result"],
            "Acknowledged receipt lost after process crash")
    backend.stop()
    integrity = backend.cli("check", backend.store)
    require(integrity["status"] == "valid" and integrity["receipts"] <= 1024,
            "Integrity/receipt envelope failed")
    backup, restored = backend.directory / "final.backup.json", backend.directory / "restored.redb"
    backend.cli("backup", backend.store, backup)
    if backend.selector[-1] == "equipment":
        require(retained_roles(backend.directory / "before-full-fanout.backup.json") == retained_roles(backup),
                "Retarget/deactivation/reactivation changed retained role identities")
    backend.cli("restore", backup, restored)
    require(backend.cli("check", restored) == integrity, "Verified restore integrity differs")
    original = backend.store
    backend.store = restored
    try:
        backend.start()
        verify(backend, model, facts)
        require(client.execute(backend.url, backend.token, plan, status=True)["result"] == result["result"],
                "Restored receipt differs")
    finally:
        backend.stop()
        backend.store = original
    return {"integrity": integrity, "process": usage, "graceful_restart": True,
            "acknowledged_process_crash": True, "replay": True, "verified_restore_service": True,
            "backup_bytes": backup.stat().st_size, "store_bytes": backend.store.stat().st_size,
            "role_identity_reuse": backend.selector[-1] == "equipment"}


def populate(backend, commands, acceptance=True):
    backend.start()
    catalog = backend.call("model.describe", {})
    limits, model = catalog["capabilities"]["limits"], catalog["model"]
    require(limits["commands"] == 64 and limits["returning"] == 32 and limits["receipts"] == 1024,
            "G2 must preserve separate command/result/receipt limits")
    if acceptance:
        require((limits["public_records"], limits["outputs"], limits["reservations"])
                == (4096, 8192, 16384), "Binary does not publish the G2 population envelope")
    require(limits["public_records"] >= len(commands), "Binary does not support requested population")
    restricted = restricted_actor(backend, model)
    for i in range(0, len(commands), 32):
        apply(backend, model, commands[i:i + 32], f"populate-{i}")
    return model, restricted


def equipment_run(binary, directory, reservations, acceptance=True):
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
        model, restricted = populate(backend, commands, acceptance)
        observed = verify_equipment(backend, model, facts)
        measurements = {}
        for label, key, fields, count in (("after_all_reads", after, {"quantity": "2"}, 0),
                                         ("last_read", tail, {"quantity": "2"}, 1)):
            plan, result, measurements[label] = edit(backend, model, facts, observed, key, fields, label)
            if acceptance:
                check_selective(measurements[label], count)
            observed = verify_equipment(backend, model, facts)
        if reservations >= 128:
            fields = {"at": str(10 + (reservations - 128) * 4 - 1)}
            plan, result, measurements["fanout_128"] = edit(backend, model, facts, observed, tail, fields, "fanout-128")
            require(measurements["fanout_128"]["work"]["causal_candidates"] == 128,
                    "128-producer acceptance did not select precisely 128")
            check_fanout(measurements["fanout_128"], 128)
            observed = verify_equipment(backend, model, facts)
        measurements["full_fanout"], committed, outcome = fanout(
            backend, model, facts, observed, supply, {"quantity": "12"}, reservations)
        if committed:
            plan, result = committed, outcome
        observed = verify_equipment(backend, model, facts)
        last = identity(100 + reservations - 1)
        failures = rejections(backend, model, facts, observed, last,
                              {"starts": str(last_start - 4)}, restricted)
        # Reuse one public slot to add a new root, then move an existing producer
        # onto its empty history and back. Public population never exceeds target.
        saved = dict(facts[after]["fields"])
        _, _, measurements["remove_after"] = apply(backend, model, [{"op": "delete", "id": after,
            "if_version": observed[after]["version"]}], "remove-after")
        del facts[after]
        apply(backend, model, [source(after, 101, {"unit": 1})], "retarget-pool")
        observed = verify_equipment(backend, model, facts)
        for label, fields in (("retarget_empty", {"pool": after}), ("deactivate", {"active": False}),
                              ("reactivate", {"active": True}), ("retarget_back", {"pool": pool})):
            plan, result, measurements[label] = edit(backend, model, facts, observed, last, fields, label)
            observed = verify_equipment(backend, model, facts)
        apply(backend, model, [{"op": "delete", "id": after,
            "if_version": observed[after]["version"]}], "remove-retarget-pool")
        del facts[after]
        plan, result, _ = apply(backend, model, [source(after, 205, saved)], "restore-after")
        report = {"model": "equipment", "public_sources": len(facts), "active_reservations": reservations,
                  "measurements": measurements, "rejections": failures,
                  **recover(backend, model, facts, verify_equipment, plan, result)}
        (backend.directory / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        return report
    finally:
        backend.stop()


def calculation_run(binary, directory, population):
    backend = Backend(binary, directory, "calculation")
    facts = {}
    def source(key, code, fields):
        facts[key] = {"contract": code, "fields": fields}
        return {"op": "create", "id": key, "contract": code, "fields": fields}
    rule, curve, other, account, subsidiary, first, tail, after = (identity(n) for n in range(1, 9))
    subscribers = population - 8
    last_at = 10 + (subscribers - 1) * 4
    commands = [source(rule, 1, {"c": "3"}),
        source(curve, 2, {"native_unit": 1, "reporting_unit": 2}),
        source(other, 2, {"native_unit": 1, "reporting_unit": 2}),
        source(account, 4, {"native_unit": 1}), source(subsidiary, 5, {"reporting_unit": 2}),
        source(first, 3, {"curve": curve, "at": "0", "rate": "2"}),
        source(tail, 3, {"curve": curve, "at": str(last_at), "rate": "3"}),
        source(after, 3, {"curve": curve, "at": str(last_at + 1), "rate": "4"})]
    commands += [source(identity(100 + i), 6, {"units": str(1 + i % 7), "at": str(10 + i * 4),
        "rule": rule, "curve": curve, "account": account, "subsidiary": subsidiary})
        for i in range(subscribers)]
    try:
        model, restricted = populate(backend, commands)
        observed = verify_calculation(backend, model, facts)
        measurements = {}
        for label, key, fields, count in (("after_all_reads", after, {"rate": "5"}, 0),
            ("last_read", tail, {"rate": "4"}, 1)):
            plan, result, measurements[label] = edit(backend, model, facts, observed, key, fields, label)
            check_selective(measurements[label], count, "candidates")
            observed = verify_calculation(backend, model, facts)
        # Moving a quote changes both its old and new successor intervals.
        if subscribers >= 128:
            plan, result, measurements["quote_interval_128"] = edit(backend, model, facts, observed, tail,
                {"at": str(10 + (subscribers - 128) * 4)}, "quote-interval-128")
            require(measurements["quote_interval_128"]["work"]["candidates"] == 128,
                    "Quote old/new successor interval did not select 128 subscribers")
            observed = verify_calculation(backend, model, facts)
        measurements["full_fanout"], committed, outcome = fanout(
            backend, model, facts, observed, rule, {"c": "4"}, subscribers)
        if committed:
            plan, result = committed, outcome
        observed = verify_calculation(backend, model, facts)
        key = identity(100 + subscribers - 1)
        failures = rejections(backend, model, facts, observed, key, {"units": "-1000", "at": "-5"}, restricted)
        for label, fields in (("retarget_fallback", {"curve": other}), ("retarget_back", {"curve": curve}),
                              ("before_first_quote", {"at": "-1"}), ("inclusive_quote", {"at": "0"})):
            plan, result, measurements[label] = edit(backend, model, facts, observed, key, fields, label)
            observed = verify_calculation(backend, model, facts)
        report = {"model": "calculation", "public_sources": len(facts), "active_subscribers": subscribers,
                  "measurements": measurements, "rejections": failures,
                  **recover(backend, model, facts, verify_calculation, plan, result)}
        (backend.directory / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        return report
    finally:
        backend.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--populations", type=int, nargs="+", default=[64, 256, 1024, 4096])
    parser.add_argument("--models", choices=["equipment", "calculation"], nargs="+",
                        default=["equipment", "calculation"])
    parser.add_argument("--reservations", type=int, nargs="+", help="Equipment-only historical baseline counts")
    parser.add_argument("--authority-from", type=Path,
                        help="Separate authority trials restored from this accepted suite's 4096-source backups")
    args = parser.parse_args()
    require(all(12 <= n <= 4096 for n in args.populations), "Populations must be 12..4096")
    require(args.reservations is None or all(2 <= n <= 4092 for n in args.reservations),
            "Reservation counts must be 2..4092")
    args.out.mkdir(mode=0o700)
    started = time.perf_counter()
    report = {"status": "running", "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "host": {"system": platform.system(), "machine": platform.machine(), "kernel": platform.release()},
              "engine_work_budget": 200000, "timing_scope": MUTATION_TIMING, "runs": []}
    if args.authority_from:
        report["scope"] = "Separate restored 4096-source authority trials; original population runs are unchanged"
        report["timing_scope"] = AUTHORITY_TIMING
        for model in args.models:
            run = authority_run(args.binary, args.authority_from / f"{model}-4096",
                                args.out / f"{model}-4096", model)
            report["runs"].append(run)
            print(f"{model}: 4096-source authority edit {run['authority_lifecycle']['status']}", flush=True)
        report["elapsed_seconds"] = round(time.perf_counter() - started, 3)
        report["status"] = "passed"
        (args.out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        return
    workloads = [("equipment", n + 4) for n in args.reservations] if args.reservations else [
        (model, population) for population in args.populations for model in args.models]
    for model, population in workloads:
        directory = args.out / f"{model}-{population}"
        run = equipment_run(args.binary, directory, population - 4, acceptance=not args.reservations) if model == "equipment" else calculation_run(args.binary, directory, population)
        report["runs"].append(run)
        report["elapsed_seconds"] = round(time.perf_counter() - started, 3)
        (args.out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"{model}: {population} public sources verified; full fanout {run['measurements']['full_fanout']['status']}", flush=True)
    report["status"] = "passed"
    report["fanout_boundary"] = {
        model: {"largest_observed_commit": max((count
                for r in report["runs"] if r["model"] == model
                for count in ([r["measurements"]["full_fanout"]["affected_producers"]]
                    if r["measurements"]["full_fanout"]["status"] == "committed" else [])
                    + ([128] if "fanout_128" in r["measurements"] or "quote_interval_128" in r["measurements"] else [])), default=None),
                "smallest_observed_work_limit": min((r["measurements"]["full_fanout"]["affected_producers"]
                for r in report["runs"] if r["model"] == model and r["measurements"]["full_fanout"]["status"] == "work_limit"), default=None)}
        for model in sorted({r["model"] for r in report["runs"]})}
    report["fanout_boundary_scope"] = "Observed brackets for these authored workloads; no exact capacity cutoff or universal cascade capacity claimed"
    (args.out / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
