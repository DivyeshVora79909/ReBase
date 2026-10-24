"""Ordinary, bounded workload functions over Backend and the public client.

The source-only workshop oracles own the expected calculations. These functions
own disposable targets and saved intents, not another calculation/retry engine.
"""
from collections import Counter
from copy import deepcopy
import csv
import hashlib
import math
import os
from pathlib import Path
import random
import shlex
import shutil
import subprocess
import threading
import time
import uuid

import client
from capacity import scan
from g7_http import TABLES
from g8_observe import DEFAULT_BUDGETS, Incomplete, JsonlWriter, check_artifacts, check_resources, host_limits, read_jsonl, sample, validate_budgets
from harness import Backend, backup_image, check_archive, command, expect_error, require, write_private
from verify_oracles import OracleError, evaluate, stage
from verify_runtime import digest, equal, write_json

ROOT = Path(__file__).resolve().parents[1]
FLOORS = {"create": 100, "update": 100, "delete": 100, "read": 500,
          "replay": 10, "noop": 10, "invalid": 10, "stale": 10}
SMOKE_FLOORS = {"create": 3, "update": 3, "delete": 3, "read": 10,
                "replay": 1, "noop": 1, "invalid": 1, "stale": 1}


def profile(*, smoke=False, **overrides):
    """Explicit supported equipment shape. Unknown/unbounded inputs reject."""
    value = {"scenario": "equipment", "seed": 8042, "identity_pool": 64,
             "duration_seconds": 300.0, "warmup_seconds": 30.0, "cooldown_seconds": 30.0,
             "sample_seconds": 1.0, "mutation_rate": 2.0, "reader_rate": 1.0,
             "readers": 2, "max_pending": 8, "max_new_operations": 800,
             "receipt_reserve": 32, "floors": dict(FLOORS), "budgets": dict(DEFAULT_BUDGETS)}
    if smoke:
        value.update(duration_seconds=8.0, warmup_seconds=1.0, cooldown_seconds=2.0,
                     sample_seconds=0.25, mutation_rate=4.0, reader_rate=4.0,
                     max_new_operations=64, floors=dict(SMOKE_FLOORS))
    unknown = overrides.keys() - value.keys()
    if unknown:
        raise ValueError("Unknown profile fields: " + ", ".join(sorted(unknown)))
    value.update(deepcopy(overrides))
    validate_budgets(value["budgets"])
    if value["scenario"] != "equipment":
        raise ValueError("Duration profiles use the compiled equipment scenario")
    for name in ("duration_seconds", "sample_seconds", "mutation_rate", "reader_rate"):
        number = value[name]
        if isinstance(number, bool) or not isinstance(number, (int, float)) or not math.isfinite(number) or number <= 0:
            raise ValueError(f"{name} must be finite and positive")
    for name in ("warmup_seconds", "cooldown_seconds"):
        number = value[name]
        if isinstance(number, bool) or not isinstance(number, (int, float)) or not math.isfinite(number) or number < 0:
            raise ValueError(f"{name} must be finite and nonnegative")
    for name, lower, upper in (("identity_pool", 8, 64), ("readers", 1, 2), ("max_pending", 3, 8),
                               ("max_new_operations", 1, 800), ("receipt_reserve", 1, 128), ("seed", 0, 2**32-1)):
        number = value[name]
        if type(number) is not int or not lower <= number <= upper:
            raise ValueError(f"{name} must be an integer in [{lower}, {upper}]")
    if value["sample_seconds"] > value["budgets"]["sample_gap_seconds"]:
        raise ValueError("Sampling cadence exceeds the declared gap budget")
    if value["max_pending"] < value["readers"] + 1:
        raise ValueError("Pending budget cannot hold the writer and readers")
    floors = value["floors"]
    if not isinstance(floors, dict) or floors.keys() != FLOORS.keys() or any(type(n) is not int or n < 1 for n in floors.values()):
        raise ValueError("All eight action coverage floors must be positive integers")
    if len({floors[k] for k in ("create", "update", "delete")}) != 1 or floors["stale"] > floors["update"]:
        raise ValueError("CRUD floors must form complete cycles with stale edits after updates")
    if any(floors[k] > floors["create"] for k in ("replay", "noop", "invalid")):
        raise ValueError("Replay/no-op/invalid floors cannot exceed the planned cycle count")
    slots = math.ceil(value["duration_seconds"] * value["mutation_rate"])
    required = sum(n for k, n in floors.items() if k != "read")
    if slots < required or slots > value["max_new_operations"]:
        raise ValueError("Duration/rate cannot cover actions within the new-operation budget")
    if math.floor(value["duration_seconds"] * value["reader_rate"]) * value["readers"] < floors["read"]:
        raise ValueError("Duration/reader rate cannot achieve the read floor")
    warmup_slots = math.ceil(value["warmup_seconds"] * value["mutation_rate"]) + 1
    if 1 + warmup_slots + value["max_new_operations"] + value["receipt_reserve"] > 1024:
        raise ValueError("Fixture/warmup/measurement/reserve exceed the 1,024 receipt epoch")
    if math.ceil((value["duration_seconds"] + value["warmup_seconds"] + value["cooldown_seconds"]) / value["sample_seconds"]) > 10000:
        raise ValueError("Profile exceeds the bounded 10,000 sample inventory")
    value["label"] = "default-300-second" if all(value[k] == profile_default(k) for k in (
        "duration_seconds", "warmup_seconds", "cooldown_seconds", "mutation_rate", "readers")) and floors == FLOORS else "custom-short-smoke" if value["duration_seconds"] < 300 else "custom-duration"
    value["receipt_preflight"] = {"fixture": 1, "warmup_max": warmup_slots,
        "measurement_max": value["max_new_operations"], "reserve": value["receipt_reserve"]}
    return value


def profile_default(key):
    return {"duration_seconds": 300.0, "warmup_seconds": 30.0, "cooldown_seconds": 30.0,
            "mutation_rate": 2.0, "readers": 2}[key]


def preflight(binary, backend="redb", cluster_file=None):
    binary = Path(binary).resolve(strict=True)
    if not os.access(binary, os.X_OK):
        raise ValueError("Binary is not executable")
    if backend not in ("redb", "surrealkv", "foundationdb"):
        raise ValueError("Unsupported backend")
    if (backend == "foundationdb") != (cluster_file is not None):
        raise ValueError("FoundationDB requires an explicit cluster file; embedded backends reject it")
    if not shutil.which("openssl"):
        raise ValueError("OpenSSL is required for the owned issuer")
    prefix = [str(binary), "--backend", backend]
    if cluster_file is not None:
        prefix += ["--cluster-file", str(Path(cluster_file).resolve(strict=True))]
    try:
        identity = client.loads(command(*prefix, "--model", "equipment", "version"))
        catalog = client.loads(command(*prefix, "--model", "equipment", "model", "public"))
    except RuntimeError as error:
        raise ValueError("Backend/native-library preflight failed: " + str(error)) from error
    equal("preflight.catalog", identity["model"], catalog["model"])
    baseline_path = ROOT / "research/evidence/2026-10-25-g76-storage-conformance.json"
    baseline = client.loads(baseline_path.read_bytes())
    mismatches = [name for name, expected in baseline["source_sha256"].items()
                  if not (ROOT / name).is_file() or digest(ROOT / name) != expected]
    core = [name for name in mismatches if name.startswith("src/") or name in ("Cargo.toml", "Cargo.lock")]
    if core:
        raise ValueError("G7 core evidence cannot be reused for changed sources: " + ", ".join(core))
    return {"prefix": prefix, "backend": backend, "binary_sha256": digest(binary),
        "model": identity, "catalog": catalog, "g7_evidence_sha256": digest(baseline_path),
        "g7_matching_fingerprints": len(baseline["source_sha256"]) - len(mismatches),
        "changed_tools": mismatches, "core_unchanged": True, "host": host_limits()}


def prepare(binary, directory, *, backend="redb", cluster_file=None, settings=None):
    """Prepare a disposable target with literal equipment facts, before timing."""
    settings = settings or profile(smoke=True)
    inspected = preflight(binary, backend, cluster_file)
    directory = Path(directory).resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    wrapper = directory / "selected-backend"
    write_private(wrapper, ("#!/bin/sh\nexec " + shlex.join(inspected["prefix"]) + ' "$@"\n').encode())
    wrapper.chmod(0o700)
    owned = None
    try:
        owned = Backend(wrapper, directory / "backend", model="equipment")
        owned.start()
        model = owned.call("model.describe", {})["model"]
        namespace = uuid.uuid5(uuid.NAMESPACE_URL, "rebase-g8/" + str(settings["seed"]))
        ids = [str(uuid.uuid5(namespace, str(i))) for i in range(settings["identity_pool"])]
        p, q, d, e, a, b = ids[:6]
        commands = [
            {"op": "create", "id": p, "contract": 101, "fields": {"unit": 7}},
            {"op": "create", "id": q, "contract": 101, "fields": {"unit": 7}},
            {"op": "create", "id": d, "contract": 205, "fields": {"pool": p, "at": "0", "quantity": "10"}},
            {"op": "create", "id": e, "contract": 205, "fields": {"pool": q, "at": "0", "quantity": "6"}},
            {"op": "create", "id": a, "contract": 410, "fields": reservation(p, 10, 30, 8)},
            {"op": "create", "id": b, "contract": 410, "fields": reservation(p, 20, 40, 7)}]
        saved = client.prepare(owned.url, owned.token, {"model": model, "commands": commands, "returning": []})
        client.save_plan(directory / "fixture.plan.json", saved)
        response = client.execute(owned.url, owned.token, saved)
        equal("fixture.status", "committed", response["status"])
        facts = stage({}, commands)
        state = {"backend": owned, "directory": directory, "profile": settings, "preflight": inspected,
            "model": model, "ids": ids, "facts": facts, "reserved": {a, b}, "receipts": 1,
            "last": (saved, response), "fixture": (saved, response), "cycle": 0, "active": None,
            "renewed_at": time.monotonic(), "auth_renewals": 0, "lock": threading.Lock()}
        observed = check_sources(state)
        equal("fixture.literal.A", {"available_before": "10", "allocated": "8"}, observed[a]["derived"])
        equal("fixture.literal.B", {"available_before": "2", "allocated": "2"}, observed[b]["derived"])
        write_json(directory / "profile.json", {**settings, "preflight": inspected})
        write_json(directory / "initial-facts.json", facts)
        return state
    except BaseException:
        if owned is not None:
            owned.stop()
        raise


def reservation(pool, start, end, amount):
    return {"pool": pool, "starts": str(start), "ends": str(end), "requested": str(amount), "active": True}


def check_sources(state):
    """Independent inputs, quantities, strict prefixes and complete-time roots."""
    backend, facts, model = state["backend"], state["facts"], state["model"]
    expected = evaluate("equipment", facts)
    rows = {row["id"]: row for row in scan(backend, model, len(facts))}
    equal("public.inventory", sorted(facts), sorted(rows))
    for identity, source in facts.items():
        equal("public.input", source["fields"], rows[identity]["input"])
        equal("public.contract", source["contract"], rows[identity]["contract"])
        equal("public.derived", expected["derived"].get(identity), rows[identity]["derived"])
    for root in expected["roots"]:
        summary = backend.call("roots.read", {"model": model, "owner": root["owner"], "slot": root["slot"],
            "read": {"kind": "summary"}})["value"]
        for key, value in root["summary"].items():
            equal("root." + key, value, summary[key])
    return rows


def logical(state):
    with state["lock"]:
        facts = state["facts"]
        active = sum(1 for row in facts.values() if row["contract"] == 410 and row["fields"]["active"])
        return {"public_sources": len(facts), "active_outputs": active * 2,
                "retained_roles": len(state["reserved"]) * 2, "receipt_slots": state["receipts"]}


def renew_auth(state):
    if time.monotonic() - state["renewed_at"] < 240:
        return
    backend = state["backend"]
    token = command(backend.binary, "auth", "issue", backend.config_path,
                    backend.directory / "token-request.json", backend.private).decode().strip()
    backend.token = token
    backend.token_path.write_text(token + "\n")
    state["renewed_at"] = time.monotonic()
    state["auth_renewals"] += 1


def scheduled_actions(floors, rng):
    """Guarantee every floor first; then seeded mixing in complete CRUD cycles."""
    for i in range(floors["create"]):
        yield "create"
        yield "update"
        if i < floors["stale"]:
            yield "stale"
        yield "delete"
        for action in ("replay", "noop", "invalid"):
            if i < floors[action]:
                yield action
    while True:
        yield "create"
        yield "update"
        if rng.random() < .15:
            yield "stale"
        yield "delete"
        if rng.random() < .2:
            yield rng.choice(("replay", "noop", "invalid"))


def perform(state, action, rng, trace, *, phase="measurement"):
    backend, model, ids = state["backend"], state["model"], state["ids"]
    renew_auth(state)
    started = time.monotonic()
    commands, proposal, rejected = None, None, None
    if action == "replay":
        saved, original = state["last"]
        response = client.execute(backend.url, backend.token, saved)
        require(response["replayed"], "Replay applied a new intent")
        equal("replay.result", original["result"], response["result"])
        item = {"action": action, "phase": phase, "plan": saved, "expected": "replayed",
                "response": response, "kind": "replayed", "http_status": 200}
    else:
        if action == "invalid":
            commands = [{"op": "create", "id": ids[-1], "contract": 410,
                         "fields": reservation(ids[0], 10, 15, 3)}]
        elif action == "create":
            require(state["active"] is None, "CRUD cycle is not drained")
            i = state["cycle"] % (len(ids) - 6)
            identity = ids[i + 6]
            commands = [{"op": "create", "id": identity, "contract": 410,
                         "fields": reservation(ids[rng.randrange(2)], 50+i*10, 55+i*10, rng.randrange(1, 7))}]
        else:
            identity = ids[2] if action == "noop" else state["active"]
            require(identity is not None, "An active CRUD source is required")
            record = backend.call("records.get", {"model": model, "id": identity})
            if action == "delete":
                commands = [{"op": "delete", "id": identity, "if_version": record["version"]}]
            else:
                fields = {"quantity": "10"} if action == "noop" else {
                    "pool": ids[rng.randrange(2)], "requested": str(rng.randrange(1, 7)),
                    "ends": str(int(record["input"]["starts"]) + rng.randrange(3, 9))}
                commands = [{"op": "update", "id": identity,
                    "if_version": state["stale_version"] if action == "stale" else record["version"],
                    "set": fields, "unset": []}]
                if action == "update":
                    # Force a changed field so that the actual previous token becomes stale.
                    commands[0]["set"]["requested"] = str(int(record["input"]["requested"]) + 1)
                    state["stale_version"] = record["version"]
        if action == "stale":
            rejected = "stale_version"
        else:
            try:
                proposal = stage(state["facts"], commands)
                evaluate("equipment", proposal)
            except OracleError as error:
                rejected = error.kind
            equal("action.oracle", "invariant" if action == "invalid" else None, rejected)
        saved = client.prepare(backend.url, backend.token, {"model": model, "commands": commands, "returning": []})
        # A complete private trace is the saved-intent artifact; flush before submitting.
        trace.write({"event": "intent", "phase": phase, "action": action, "plan": saved,
                     "expected": rejected or "committed"})
        if rejected:
            try:
                client.execute(backend.url, backend.token, saved)
            except client.ClientError as error:
                equal("rejection.kind", rejected, error.kind)
                http_status = error.http_status
            else:
                raise RuntimeError("Expected rejection: " + rejected)
            equal("rejection.receipt", "not_observed", client.execute(backend.url, backend.token, saved, status=True)["status"])
            response, kind = None, rejected
        else:
            response = client.execute(backend.url, backend.token, saved)
            equal("mutation.status", "committed", response["status"])
            with state["lock"]:
                state["facts"] = proposal
                state["receipts"] += 1
                if action == "create":
                    state["active"] = commands[0]["id"]
                    state["reserved"].add(state["active"])
                elif action == "delete":
                    state["active"] = None
                    state["cycle"] += 1
            state["last"] = saved, response
            kind = "committed"
        item = {"action": action, "phase": phase, "plan": saved, "expected": rejected or "committed",
                "response": response, "kind": kind, "http_status": http_status if rejected else 200}
    item.update(event="outcome", latency_ms=(time.monotonic()-started)*1000)
    trace.write(item)
    return item


def offline(state, label):
    """Outside the continuous PID epoch: complete thirteen-table observation."""
    backend = state["backend"]
    backend.stop()
    integrity = backend.cli("check", backend.store)
    image = backup_image(backend, label)
    require(set(image["tables"]) == TABLES and image["complete"], "Missing complete thirteen-table image")
    inventory = logical(state)
    equal("integrity.native_records", inventory["public_sources"] + inventory["active_outputs"], integrity["records"])
    equal("integrity.receipts", state["receipts"], integrity["receipts"])
    inspector = backend.cli("inspect", backend.store)
    equal("integrity.retained_roles", len(state["reserved"])*2, len(inspector["roles"]))
    write_json(state["directory"] / (label + ".inspect.json"), inspector)
    return {"status": "passed", "integrity": integrity, "table_count": len(TABLES),
            "image_sha256": hashlib.sha256(client._bytes(image)).hexdigest(),
            "logical": logical(state)}


def rollback_control(state, label):
    backend = state["backend"]
    backend.stop()
    before = backup_image(backend, label + "-before")
    backend.start()
    bad = {"op": "create", "id": state["ids"][-1], "contract": 410,
           "fields": reservation(state["ids"][0], 10, 15, 3)}
    plan = backend.plan({"model": state["model"], "commands": [bad], "returning": []}, label)
    expect_error("invariant", lambda: client.execute(backend.url, backend.token, plan))
    equal("rollback.receipt", "not_observed", client.execute(backend.url, backend.token, plan, status=True)["status"])
    backend.stop()
    after = backup_image(backend, label + "-after")
    equal("rollback.complete_image", hashlib.sha256(client._bytes(before)).hexdigest(),
          hashlib.sha256(client._bytes(after)).hexdigest())
    backend.start()
    return {"status": "passed", "table_count": len(TABLES), "unchanged": True}


def physical_paths(state, database_paths=()):
    return tuple(database_paths) if state["preflight"]["backend"] == "foundationdb" else (state["backend"].store,)


def engine_observation(backend, max_bytes):
    """Consume existing operator work events once, retaining only counters."""
    log = backend.directory / "server.log"
    if log.stat().st_size > max_bytes:
        raise Incomplete("Operator log exceeded its evidence budget")
    total, peaks, count = Counter(), Counter(), 0
    with log.open() as source:
        for line in source:
            if line.startswith('{"event":"mutation_work"'):
                row = client.loads(line)
                count += 1
                for key, number in row["work"].items():
                    if type(number) is int:
                        total[key] += number
                        peaks[key] = max(peaks[key], number)
    return {"status": "passed" if count else "incomplete", "committed_events": count,
            "totals": dict(total), "peaks": dict(peaks),
            "scope": "Existing native counters; no unprovided counter is represented as zero"}


def trace_outcomes(path, budgets):
    """Require the complete saved-intent/outcome pairing, retaining one intent."""
    pending, count = None, 0
    for item in read_jsonl(path, budgets["trace_bytes"], 20000):
        event = item.get("event")
        if event == "intent":
            if pending is not None:
                raise Incomplete("An original submitted intent has no outcome")
            pending = item
        elif event == "outcome":
            if item.get("action") != "replay":
                if pending is None or pending.get("plan") != item.get("plan"):
                    raise Incomplete("Outcome does not match the retained original intent")
                pending = None
            count += 1
            yield item
        else:
            raise Incomplete("Unknown or missing trace event")
    if pending is not None or not count:
        raise Incomplete("Trace is missing required submitted outcomes")


def reconcile_trace(state, path):
    """At drain, resolve each submitted original intent using its saved context."""
    backend, count = state["backend"], 0
    for item in trace_outcomes(path, state["profile"]["budgets"]):
        saved = item["plan"]
        status = client.execute(backend.url, backend.token, saved, status=True)
        if item["kind"] in ("committed", "replayed"):
            equal("drain.receipt", item["response"]["result"], status["result"])
        else:
            equal("drain.absence_after_completion", "not_observed", status["status"])
        count += 1
    return {"status": "passed", "resolved": count, "unresolved": 0,
            "original_contexts_preserved": True, "replacement_submissions": 0}


def run(state, *, database_pid=None, database_paths=()):
    """One uninterrupted paced PID epoch, with bounded readers and sampling."""
    settings, backend = state["profile"], state["backend"]
    rng = random.Random(settings["seed"])
    directory, stop = state["directory"], threading.Event()
    lock = threading.Lock()
    phase = {"name": "warmup", "begin": time.monotonic()}
    coverage, kinds, http, latencies = Counter(), Counter(), Counter(), []
    read_counts = Counter()
    failures = []
    trace_path, samples_path = directory / "trace.jsonl", directory / "samples.jsonl"
    trace = JsonlWriter(trace_path, settings["budgets"]["trace_bytes"])
    samples = JsonlWriter(samples_path, settings["budgets"]["samples_bytes"])
    read_trace = JsonlWriter(directory / "reads.jsonl", settings["budgets"]["trace_bytes"])
    pid = backend.process.pid
    threads = []
    started = time.monotonic()

    def reader():
        next_at = time.monotonic()
        while not stop.is_set():
            try:
                t = time.monotonic()
                summary = backend.call("roots.read", {"model": state["model"], "owner": state["ids"][0],
                    "slot": 7, "read": {"kind": "summary"}})["value"]
                # Every valid reservation consumes/releases equally: delivery is always ten.
                equal("reader.literal.sum", "10", summary["sum"])
                with lock:
                    name = phase["name"]
                    read_counts[name] += 1
                    read_trace.write({"phase": name, "method": "roots.read", "sum": summary["sum"],
                        "count": summary["count"], "http_status": 200, "latency_ms": (time.monotonic()-t)*1000})
            except BaseException as error:
                with lock:
                    failures.append(error)
                stop.set()
                return
            next_at += 1/settings["reader_rate"]
            stop.wait(max(0, next_at-time.monotonic()))

    def observer():
        next_at = time.monotonic()
        while not stop.is_set():
            try:
                observed = sample(pid, os.getpid(), database_pid, physical_paths(state, database_paths),
                                  phase["name"], logical(state))
                observed["window"] = ("tail" if time.monotonic()-phase["begin"] >= settings["duration_seconds"]*2/3
                                      else "steady") if phase["name"] == "measurement" else phase["name"]
                samples.write(observed)
            except BaseException as error:
                with lock:
                    failures.append(error)
                stop.set()
                return
            next_at += settings["sample_seconds"]
            stop.wait(max(0, next_at-time.monotonic()))

    try:
        for target in [observer] + [reader]*settings["readers"]:
            thread = threading.Thread(target=target, daemon=False)
            thread.start()
            threads.append(thread)
        markers = []
        for name, duration in (("warmup", settings["warmup_seconds"]), ("measurement", settings["duration_seconds"]),
                               ("cooldown", settings["cooldown_seconds"])):
            with lock:
                phase["name"] = name
                phase["begin"] = time.monotonic()
            begin = time.monotonic()
            markers.append({"phase": name, "start_seconds": begin-started, "duration_requested": duration, "pid": pid})
            if name == "cooldown":
                stop.wait(duration)
            else:
                floors = settings["floors"] if name == "measurement" else SMOKE_FLOORS
                actions = scheduled_actions(floors, rng)
                # A warmup that ends inside a CRUD cycle is explicitly completed before measurement.
                if state["active"] is not None:
                    perform(state, "delete", rng, trace, phase="maintenance")
                index = 0
                while time.monotonic() < begin + duration and not stop.is_set():
                    if name == "measurement" and index >= settings["max_new_operations"]:
                        raise Incomplete("Measurement operation budget exhausted before duration")
                    item = perform(state, next(actions), rng, trace, phase=name)
                    if name == "measurement":
                        coverage[item["action"]] += 1
                        kinds[item["kind"]] += 1
                        http[item["http_status"]] += 1
                        latencies.append(item["latency_ms"])
                    index += 1
                    stop.wait(max(0, begin + index/settings["mutation_rate"] - time.monotonic()))
            markers[-1]["duration_achieved"] = time.monotonic()-begin
            if failures:
                raise failures[0]
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=25)
            require(not thread.is_alive(), "Owned worker did not drain within its client deadline")
        trace.close()
        samples.close()
        read_trace.close()
    coverage["read"] = read_counts["measurement"]
    resources = check_resources(read_jsonl(samples_path, settings["budgets"]["samples_bytes"], 10000),
                                settings["budgets"], require_database=database_pid is not None)
    floor_status = "passed" if all(coverage[k] >= v for k,v in settings["floors"].items()) else "incomplete"
    from harness import latency
    result = {"status": "passed" if resources["status"] == floor_status == "passed" else "failed" if resources["status"] == "failed" else "incomplete",
        "profile": settings, "backend": state["preflight"]["backend"], "preflight": state["preflight"],
        "coverage": {"status": floor_status, "requested": settings["floors"], "achieved": dict(coverage)},
        "work": {"offered": sum(v for k,v in coverage.items() if k != "read"), "submitted": sum(kinds.values()),
                 "completed": sum(kinds.values()), "unresolved": 0, "outcomes": dict(kinds),
                 "http_statuses": dict(http), "reads_by_phase": dict(read_counts), "max_pending_bound": settings["readers"]+1,
                 "mutation_latency": latency(latencies) if latencies else {},
                 "measurement_completions_per_second": sum(kinds.values())/settings["duration_seconds"]},
        "markers": markers, "continuous_application_pid": pid, "resources": resources,
        "measurement_windows": {"steady_seconds": [0, settings["duration_seconds"]*2/3],
                                "tail_seconds": [settings["duration_seconds"]*2/3, settings["duration_seconds"]]},
        "logical": logical(state), "auth_renewals": state["auth_renewals"],
        "trace": {"path": "trace.jsonl", "complete": True, "bytes": trace.bytes, "rows": trace.count},
        "scope": "One finite uninterrupted PID epoch; cooldown compares constant retained inventory; no longer soak claim"}
    write_json(directory / "memory-result.json", result)
    return result


def write_observation_report(state, result):
    directory, budgets = state["directory"], state["profile"]["budgets"]
    fields = ["seconds", "phase", "window", "physical_bytes"] + [name+"_"+field
        for name in ("application", "controller", "database")
        for field in ("pid", "rss_kib", "peak_rss_kib", "cpu_seconds", "open_fds", "threads")]
    with os.fdopen(os.open(directory / "samples.csv", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                   "w", newline="") as output:
        writer = csv.DictWriter(output, fields)
        writer.writeheader()
        for row in read_jsonl(directory / "samples.jsonl", budgets["samples_bytes"], 10000):
            projected = {"seconds": row["monotonic_seconds"], "phase": row["phase"],
                         "window": row.get("window", row["phase"]), "physical_bytes": row["physical_bytes"]}
            for name, observation in row["processes"].items():
                for field in ("pid", "rss_kib", "peak_rss_kib", "cpu_seconds", "open_fds", "threads"):
                    projected[name+"_"+field] = observation.get(field)
            writer.writerow(projected)
            if output.tell() > budgets["samples_bytes"]:
                raise Incomplete("CSV observation byte budget exhausted")
    lines = [f"G8 {result['status']}: {result['backend']}", "",
             f"Measured {state['profile']['duration_seconds']} seconds in application PID {result['continuous_application_pid']}.",
             "Requested / achieved action coverage:"]
    lines += [f"- {name}: {floor} / {result['coverage']['achieved'].get(name, 0)}"
              for name, floor in result["coverage"]["requested"].items()]
    lines += ["", f"Resource status: {result['resources']['status']}; cooldown: {result['resources']['cooldown']['status']}.",
              f"Resolved outcomes: {result['receipts']['resolved']}; unresolved: {result['receipts']['unresolved']}.",
              "Complete thirteen-table integrity checked outside the continuous process window."]
    write_private(directory / "summary.md", ("\n".join(lines)+"\n").encode())


def check(result):
    """Convenience result check, usable independently of the workload runner."""
    require(result.get("status") == "passed", "Required workload observations or coverage did not pass")
    require(result["work"]["unresolved"] == 0, "Unresolved work cannot pass")
    for action, floor in result["coverage"]["requested"].items():
        require(result["coverage"]["achieved"].get(action, 0) >= floor, "Missing action coverage: " + action)
    require(result["resources"]["status"] == "passed", "Resource budgets did not pass")
    return {"status": "passed", "coverage": True, "resolved": True, "resources": True}


def complete_epoch(state, *, database_pid=None, database_paths=()):
    rollback = rollback_control(state, "preflight-rollback")
    result = run(state, database_pid=database_pid, database_paths=database_paths)
    check_sources(state)
    result["receipts"] = reconcile_trace(state, state["directory"] / "trace.jsonl")
    result["engine"] = engine_observation(state["backend"], state["profile"]["budgets"]["trace_bytes"])
    equal("engine.confirmed_event_count", state["receipts"], result["engine"]["committed_events"])
    result["complete_state"] = offline(state, "after-epoch")
    result["rollback"] = rollback
    write_json(state["directory"] / "final-facts.json", state["facts"])
    check(result)
    write_observation_report(state, result)
    result["artifacts"] = check_artifacts(state["directory"], state["profile"]["budgets"])
    require(result["artifacts"]["status"] == "passed", "Required artifacts exceed their declared byte budget")
    write_json(state["directory"] / "result.json", result)
    return result
