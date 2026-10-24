"""Offline G8 checks from bounded raw artifacts and source-only expectations.

Cached success labels do not certify a run. No artifact supplies executable code,
and no server, database driver or Rust codec is invoked by this module.
"""

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

import client
from g7_http import TABLES
from g8_observe import Incomplete, check_artifacts, check_resources, read_jsonl, validate_budgets
from g8_workload import FLOORS, profile, trace_outcomes
from harness import check_archive, opaque_token
from verify_oracles import OracleError, evaluate, stage


JSON_BYTES = 2 * 1024 * 1024
BACKUP_BYTES = 64 * 1024 * 1024
MAX_EPOCH_IDS = 2048


class EvidenceError(ValueError):
    """Readable contradictory observations, rather than unavailable evidence."""


def expect(condition, message):
    if not condition:
        raise EvidenceError(message)


def same(expected, observed, label):
    expect(expected == observed, label + " differs")


def digest(value):
    return hashlib.sha256(client._bytes(value)).hexdigest()


def read_object(path, max_bytes=JSON_BYTES):
    try:
        with Path(path).open("rb") as source:
            data = source.read(max_bytes + 1)
    except OSError as error:
        raise Incomplete("required artifact unavailable: " + Path(path).name) from error
    if len(data) > max_bytes:
        raise Incomplete("required artifact exceeds byte budget: " + Path(path).name)
    try:
        value = client.loads(data)
    except client.ClientError as error:
        raise Incomplete("required artifact is not complete JSON: " + Path(path).name) from error
    expect(isinstance(value, dict), "artifact must contain an object: " + Path(path).name)
    return value


def image(path):
    backup = read_object(path, BACKUP_BYTES)
    payload = backup.get("payload")
    expect(isinstance(payload, dict) and payload.get("complete") is True, "backup is not a complete application image")
    same("rebase-backup-1", backup.get("format"), "backup envelope format")
    same("rebase-authorized-observation-1", payload.get("format"), "complete observation format")
    tables = payload.get("tables")
    expect(isinstance(tables, dict) and set(tables) == TABLES, "backup must contain all thirteen application tables")
    for name, rows in tables.items():
        expect(isinstance(rows, list), "backup table rows are missing")
        expect(len(rows) <= 81920, "backup table exceeds the bounded observation inventory")
        keys = set()
        for row in rows:
            expect(isinstance(row, dict) and isinstance(row.get("key"), str), "backup row key is missing")
            expect(row["key"] not in keys, "backup contains a repeated table key")
            keys.add(row["key"])
    return payload


def failure(error):
    status = "incomplete" if isinstance(error, Incomplete) else "failed"
    message = str(error) if isinstance(error, (Incomplete, EvidenceError)) else "invalid or missing required artifact fields"
    return {"status": status, "required": True, "reason": message, "type": type(error).__name__}


def aggregate(obligations):
    if any(row["status"] == "failed" for row in obligations.values()):
        return "failed"
    if any(row.get("required", True) and row["status"] != "passed" for row in obligations.values()):
        return "incomplete"
    return "passed"


def profile_inputs(directory, result):
    recorded = read_object(directory / "profile.json")
    allowed = set(profile()) - {"label", "receipt_preflight"}
    expect(set(recorded) <= allowed | {"label", "receipt_preflight", "preflight"}, "unknown recorded profile fields")
    settings = profile(**{key: value for key, value in recorded.items() if key in allowed})
    for name in allowed | {"label", "receipt_preflight"}:
        same(settings[name], recorded.get(name), "recorded profile " + name)
        same(settings[name], result["profile"].get(name), "result profile " + name)
    validate_budgets(settings["budgets"])
    expect(result.get("backend") in ("redb", "surrealkv", "foundationdb"), "unknown backend")
    same(result["backend"], recorded["preflight"]["backend"], "profile backend")
    return settings


def initial_state(directory, settings):
    fixture = read_object(directory / "fixture.plan.json")
    client._plan(fixture)
    initial = read_object(directory / "initial-facts.json")
    same(stage({}, fixture["request"]["commands"]), initial, "fixture source facts")
    evaluate("equipment", initial)
    expect(0 < len(initial) <= settings["identity_pool"], "fixture identity inventory is invalid")
    roots = [command["id"] for command in fixture["request"]["commands"] if command.get("contract") == 101]
    expect(roots, "equipment fixture has no reader pool")
    state = {"facts": initial, "versions": {}, "target": fixture["target"],
             "context": fixture["request"]["context"], "seen": {fixture["request"]["operation_id"]: digest(fixture)},
             "last": (fixture, None), "receipts": 1, "commits": 1, "root": roots[0],
             "identities": set(initial), "reader_values": set(), "reader_counts": set(),
             "projection_checks": 0, "missing_projections": 0, "stale_checks": 0, "missing_stale": 0}
    remember_root(state)
    return state


def remember_root(state):
    expectation = evaluate("equipment", state["facts"])
    root = next(row for row in expectation["roots"] if row["owner"] == state["root"])
    state["reader_values"].add(root["summary"]["sum"])
    state["reader_counts"].add(root["summary"]["count"])


def consume_trace(path, budgets, state, identity_limit, *, new_epoch=False, only_crud=False):
    """Check one sequential writer trace without retaining its complete history."""
    previous_context = state["context"]
    if new_epoch:
        state["context"], state["seen"], state["receipts"] = None, {}, 0
    counts, phases, kinds, http, total, committed = Counter(), Counter(), Counter(), Counter(), 0, 0
    for row in trace_outcomes(path, budgets):
        action, kind, phase = row.get("action"), row.get("kind"), row.get("phase")
        expect(action in FLOORS and action != "read", "trace action is not part of the declared workload")
        if only_crud:
            expect(action in ("create", "update", "delete") and kind == "committed", "receipt fill/resume contains a non-CRUD outcome")
        if kind == "outcome_unknown":
            raise Incomplete("an original trace outcome remains unknown")
        authored = {"replay": "replayed", "invalid": "invariant", "stale": "stale_version"}.get(action, "committed")
        same(authored, kind, "authored action outcome")
        same(authored, row.get("expected"), "saved expected outcome")
        expect(phase in ("warmup", "measurement", "maintenance", "receipt-fill", "after-archive"), "trace phase is missing")
        saved = row["plan"]
        client._plan(saved)
        same(state["target"], saved["target"], "original operation target")
        request = saved["request"]
        if state["context"] is None:
            expect(request["context"] != previous_context, "post-archive intent retained the expired context")
            state["context"] = request["context"]
        same(state["context"], request["context"], "original epoch context")
        identity = request["operation_id"]
        if action == "replay":
            expect(kind == "replayed" and row["response"].get("replayed") is True, "replay outcome is missing")
            same("committed", row["response"].get("status"), "replayed receipt status")
            expect(state["seen"].get(identity) == digest(saved), "replay replaced or omitted the original intent")
            same(state["last"][0], saved, "replayed original plan")
            if state["last"][1] is not None:
                same(state["last"][1]["result"], row["response"]["result"], "replayed original result")
        else:
            expect(len(request["commands"]) == 1, "the workload action must contain one ordinary command")
            command_kind = "create" if action in ("create", "invalid") else "delete" if action == "delete" else "update"
            same(command_kind, request["commands"][0]["op"], "action command class")
            expect(identity not in state["seen"], "new submission reused an operation ID")
            expect(len(state["seen"]) < MAX_EPOCH_IDS, "trace exceeds the bounded operation identity inventory")
            state["seen"][identity] = digest(saved)
            state["identities"].update(command["id"] for command in request["commands"])
            expect(len(state["identities"]) <= identity_limit, "trace exceeded its source identity pool")
            if kind == "stale_version":
                expect(action == "stale", "unexpected stale outcome outside the deliberate CAS class")
                for command in request["commands"]:
                    current = state["versions"].get(command["id"])
                    if current is None:
                        state["missing_stale"] += 1
                    else:
                        expect(command.get("if_version") != current, "stale edit does not differ from its recorded current token")
                        state["stale_checks"] += 1
            else:
                proposal, rejection = None, None
                try:
                    proposal = stage(state["facts"], request["commands"])
                    expected = evaluate("equipment", proposal)
                except OracleError as error:
                    rejection = error.kind
                if kind == "invariant":
                    expect(action == "invalid" and rejection == "invariant", "deliberate rejection differs from the independent source oracle")
                else:
                    expect(kind == "committed" and rejection is None, "mutation outcome differs from the independent source oracle")
                    expect(row["response"].get("status") == "committed", "committed response is missing")
                    if action == "noop":
                        same(state["facts"], proposal, "no-op source state")
                    elif action == "update":
                        expect(state["facts"] != proposal, "update action did not change a source")
                    publications = row.get("checked_publications")
                    if publications:
                        same(set(proposal), set(publications), "transient public inventory")
                        for source, facts in proposal.items():
                            observed = publications[source]
                            same(facts["fields"], observed["input"], "transient public input")
                            same(expected["derived"].get(source), observed["derived"], "transient source-derived value")
                            opaque_token(observed["version"])
                        for command in request["commands"]:
                            if action == "noop":
                                same(command["if_version"], publications[command["id"]]["version"], "no-op token")
                        state["versions"] = {source: observed["version"] for source, observed in publications.items()}
                        state["projection_checks"] += 1
                    else:
                        state["missing_projections"] += 1
                        state["versions"] = {}
                    state["facts"] = proposal
                    state["receipts"] += 1
                    expect(state["receipts"] <= 1024, "executed receipts exceed the current capacity")
                    state["commits"] += 1
                    committed += 1
                    state["last"] = (saved, row["response"])
                    remember_root(state)
            expect(kind in ("committed", "invariant", "stale_version"), "unsupported or unresolved trace outcome")
        expect(type(row.get("http_status")) is int, "trace HTTP observation is missing")
        expect(row["http_status"] == 200, "duration/receipt trace contains an unexpected HTTP status")
        expect(isinstance(row.get("latency_ms"), (int, float)) and math.isfinite(row["latency_ms"]) and row["latency_ms"] >= 0,
               "trace action latency is missing")
        counts[action] += 1
        phases[phase] += 1
        if phase == "measurement":
            kinds[kind] += 1
            http[str(row["http_status"])] += 1
        total += 1
    return {"status": "passed", "outcomes": total, "committed": committed, "actions": dict(counts),
            "phases": dict(phases), "measurement_kinds": dict(kinds), "measurement_http": dict(http)}


def memory_checks(directory, settings, result):
    state = initial_state(directory, settings)
    trace = consume_trace(directory / "trace.jsonl", settings["budgets"], state, settings["identity_pool"])
    same(state["facts"], read_object(directory / "final-facts.json"), "final source facts")
    measured = Counter()
    for row in trace_outcomes(directory / "trace.jsonl", settings["budgets"]):
        if row["phase"] == "measurement":
            measured[row["action"]] += 1
    reads = Counter()
    for row in read_jsonl(directory / "reads.jsonl", settings["budgets"]["trace_bytes"], 20000):
        expect(row.get("method") == "roots.read" and row.get("http_status") == 200, "read outcome is incomplete")
        expect(row.get("phase") in ("warmup", "measurement", "cooldown"), "read phase is invalid")
        expect(row.get("sum") in state["reader_values"] and row.get("count") in state["reader_counts"],
               "read lies outside the independently reconstructed source trajectories")
        reads[row["phase"]] += 1
    measured["read"] = reads["measurement"]
    for action, floor in settings["floors"].items():
        expect(measured[action] >= floor, "missing raw action coverage: " + action)
    same(settings["floors"], result["coverage"]["requested"], "requested coverage")
    same(dict(measured), result["coverage"]["achieved"], "reported action coverage")
    count = trace["phases"].get("measurement", 0)
    expect(count <= min(settings["max_new_operations"], math.ceil(settings["duration_seconds"] * settings["mutation_rate"])),
           "measurement exceeded its submitted-action budget")
    for field in ("offered", "submitted", "completed"):
        same(count, result["work"][field], "reported measurement " + field)
    same(0, result["work"]["unresolved"], "unresolved measurement work")
    same(dict(reads), result["work"]["reads_by_phase"], "reported read outcomes")
    same(trace["measurement_kinds"], result["work"]["outcomes"], "reported outcome kinds")
    same(trace["measurement_http"], result["work"]["http_statuses"], "reported HTTP statuses")
    same(trace["outcomes"], result["receipts"]["resolved"], "original receipt reconciliation count")
    same(0, result["receipts"]["unresolved"], "unresolved original outcomes")
    same(0, result["receipts"]["replacement_submissions"], "replacement submissions")
    return state, {**trace, "coverage": dict(measured), "reads": dict(reads),
                   "source_facts": len(state["facts"]), "receipts": state["receipts"],
                   "checked_transient_states": state["projection_checks"], "missing_transient_states": state["missing_projections"],
                   "recorded_stale_token_checks": state["stale_checks"], "missing_stale_token_observations": state["missing_stale"]}


def timing_checks(directory, settings, result):
    markers = result["markers"]
    same(["warmup", "measurement", "cooldown"], [row.get("phase") for row in markers], "window markers")
    pid, previous_end = result["continuous_application_pid"], 0
    observations = {}
    for row in read_jsonl(directory / "samples.jsonl", settings["budgets"]["samples_bytes"], 10000):
        phase = row.get("phase")
        expect(phase in ("warmup", "measurement", "cooldown"), "sample phase is missing")
        same(pid, row["processes"]["application"]["pid"], "sample application PID")
        observed = observations.setdefault(phase, {"count": 0, "first": row["monotonic_seconds"], "last": row["monotonic_seconds"]})
        observed["count"] += 1
        observed["last"] = row["monotonic_seconds"]
    for marker, key in zip(markers, ("warmup_seconds", "duration_seconds", "cooldown_seconds")):
        duration = settings[key]
        same(duration, marker["duration_requested"], "requested marker duration")
        same(pid, marker["pid"], "marker application PID")
        expect(isinstance(marker["duration_achieved"], (int, float)) and math.isfinite(marker["duration_achieved"])
               and marker["duration_achieved"] + .001 >= duration, "recorded phase duration was not achieved")
        expect(marker["start_seconds"] >= previous_end - .002, "phase markers overlap or regress")
        previous_end = marker["start_seconds"] + marker["duration_achieved"]
        if duration:
            observed = observations.get(marker["phase"])
            required = max(1, math.floor(duration / settings["sample_seconds"]) - 2)
            if observed is None or observed["count"] < required or observed["last"] - observed["first"] + 2 * settings["budgets"]["sample_gap_seconds"] < duration:
                raise Incomplete("raw samples do not cover the declared " + marker["phase"] + " window")
    return {"status": "passed", "application_pid": pid, "windows": observations}


def complete_memory(directory, result, state):
    observed = image(directory / "backend/after-epoch.backup.json")
    metadata = result["complete_state"]
    same(13, metadata["table_count"], "complete observation table count")
    same(digest(observed), metadata["image_sha256"], "complete observation digest")
    same(len(state["facts"]), len(observed["tables"]["public_records"]), "complete public inventory")
    same(state["receipts"], len(observed["tables"]["operations"]), "complete receipt inventory")
    same(state["receipts"], len(observed["tables"]["receipt_slots"]), "complete receipt-slot inventory")
    same("valid", metadata["integrity"]["status"], "executed native integrity result")
    same(state["receipts"], metadata["integrity"]["receipts"], "executed native receipt count")
    before = image(directory / "backend/preflight-rollback-before.backup.json")
    after = image(directory / "backend/preflight-rollback-after.backup.json")
    same(before, after, "preflight rejection complete image")
    return {"status": "passed", "table_count": 13, "receipt_rows": state["receipts"],
            "image_sha256": digest(observed), "scope": "complete raw table observations and executed native-check identity; native codecs are not reimplemented"}


def check_cycle_images(directory, index):
    """Independent complete-image/slot/archive checks also work without a runner."""
    directory = Path(directory)
    prefix = directory / "backend" / f"cycle-{index}"
    full = image(Path(str(prefix) + "-full.backup.json"))
    before = image(Path(str(prefix) + "-rejection-before.backup.json"))
    rejected = image(Path(str(prefix) + "-rejection-after.backup.json"))
    archived = image(Path(str(prefix) + "-archived.backup.json"))
    saved_archive = image(directory / f"cycle-{index}.archive.json")
    same(full, before, "full/rejection-before image")
    same(before, rejected, "rejected overflow complete image")
    same(rejected, saved_archive, "retained full receipt archive")
    for name in ("operations", "receipt_slots"):
        same(1024, len(full["tables"][name]), "actual full " + name + " rows")
    check_archive(rejected, archived)
    resumed = image(Path(str(prefix) + "-resumed.backup.json"))
    return {"status": "passed", "table_count": 13, "actual_operations": 1024, "actual_receipt_slots": 1024,
            "full_sha256": digest(full), "resumed_sha256": digest(resumed),
            "resumed_receipt_rows": len(resumed["tables"]["operations"]),
            "resumed_slot_rows": len(resumed["tables"]["receipt_slots"])}


def cycle_controls(directory, index, budgets, state):
    expected, events = {"full-replay", "overflow", "expired-replay", "expired-status"}, set()
    last, response = state["last"]
    for row in read_jsonl(directory / f"cycle-{index}.controls.jsonl", budgets["trace_bytes"], 16):
        event = row.get("event")
        expect(event in expected and event not in events, "cycle control is missing, duplicated or unknown")
        events.add(event)
        client._plan(row["plan"])
        if event == "overflow":
            same(state["target"], row["plan"]["target"], "overflow target")
            same(state["context"], row["plan"]["request"]["context"], "overflow original context")
            expect(row["plan"]["request"]["operation_id"] not in state["seen"], "overflow replaced a previous operation ID")
            same("receipt_limit", row["kind"], "overflow outcome")
            same(200, row["http_status"], "overflow HTTP observation")
            same("not_observed", row["status_observation"]["status"], "overflow receipt observation")
        else:
            same(last, row["plan"], "original full-capacity plan")
            if event == "full-replay":
                expect(row["response"].get("replayed") is True, "full-capacity replay was not observed")
                same("committed", row["response"].get("status"), "full-capacity replay status")
                same(response["result"], row["response"]["result"], "full-capacity original result")
            else:
                same("operation_expired", row["kind"], "old-context expiry")
                same(200, row["http_status"], "expiry HTTP observation")
    if events != expected:
        raise Incomplete("cycle controls have an incomplete required suffix")
    return {"status": "passed", "responses": len(events), "original_id_context_preserved": True}


def cycle_checks(directory, settings, result, state):
    pointer = result["receipt_cycles"]
    same("cycles-result.json", pointer.get("path"), "receipt-cycle artifact pointer")
    recorded = read_object(directory / "cycles-result.json")
    entries = recorded["cycles"]
    expect(isinstance(entries, list) and 2 <= len(entries) <= 4, "at least two bounded receipt cycles are required")
    same(len(entries), recorded["cycle_count"], "receipt cycle count")
    same(len(entries), pointer["count"], "composite receipt cycle count")
    results = []
    for index, entry in enumerate(entries):
        same(index, entry["cycle"], "receipt cycle index")
        same(state["receipts"], entry["starting_executed_receipts"], "cycle starting executed receipts")
        start = state["receipts"]
        fill = consume_trace(directory / f"cycle-{index}.trace.jsonl", settings["budgets"], state, settings["identity_pool"], only_crud=True)
        same(1024, state["receipts"], "executed full receipt capacity")
        same(1024-start, fill["committed"], "new executed fill requests")
        same(fill["committed"], entry["new_executed_fill_requests"], "reported executed fill requests")
        same(fill["actions"], entry["fill_coverage"], "reported fill action coverage")
        same(fill["outcomes"], entry["resolved_fill"]["resolved"], "resolved fill originals")
        same(0, entry["resolved_fill"]["unresolved"], "unresolved fill originals")
        resources = check_resources(read_jsonl(directory / f"cycle-{index}.samples.jsonl", settings["budgets"]["samples_bytes"], 10000),
                                    settings["budgets"], require_database=result["backend"] == "foundationdb")
        expect(resources["status"] == "passed", "raw receipt-fill resource budgets did not pass")
        same(entry["fill_application_pid"], resources["obligations"]["continuous_application_pid"]["identity"][0], "receipt fill PID")
        expect(0 < entry["fill_seconds"] <= entry["cycle_seconds"] <= entry["cycle_budget_seconds"] == 300,
               "receipt cycle exceeded its predeclared duration")
        controller = entry["maintenance_controller"]["observation"]
        expect(controller.get("available") is True and max(controller["rss_kib"], controller["peak_rss_kib"]) <= settings["budgets"]["controller_rss_kib"]
               and controller["open_fds"] <= settings["budgets"]["controller_fds"] and controller["threads"] <= settings["budgets"]["controller_threads"],
               "maintenance controller exceeded resource budgets")
        complete = check_cycle_images(directory, index)
        same(complete["full_sha256"], entry["full_integrity"]["image_sha256"], "full-cycle observation digest")
        controls = cycle_controls(directory, index, settings["budgets"], state)
        resumed = consume_trace(directory / f"cycle-{index}.resumed.jsonl", settings["budgets"], state, settings["identity_pool"], new_epoch=True, only_crud=True)
        for action in ("create", "update", "delete"):
            expect(resumed["actions"].get(action, 0) >= 1, "resumed CRUD class was not executed")
        same(resumed["actions"], entry["resumed_crud"], "resumed action coverage")
        same(resumed["outcomes"], entry["resolved_resumed"]["resolved"], "resolved resumed originals")
        same(0, entry["resolved_resumed"]["unresolved"], "unresolved resumed originals")
        same(state["receipts"], complete["resumed_receipt_rows"], "resumed actual receipts")
        same(state["receipts"], complete["resumed_slot_rows"], "resumed actual receipt slots")
        same(complete["resumed_sha256"], entry["final_integrity"]["image_sha256"], "resumed complete image digest")
        same(False, entry["reset_used"], "receipt reset use")
        same(0, entry["unresolved"], "unresolved cycle work")
        results.append({"status": "passed", "cycle": index, "fill_requests": fill["committed"], "resumed_requests": resumed["committed"],
                        "images": complete, "controls": controls, "resources": resources["status"]})
    same(state["commits"], recorded["cumulative_committed_operator_events"], "cumulative executed operator events")
    same(0, recorded["unresolved"], "unresolved lifecycle work")
    same(state["receipts"], recorded["final_logical"]["receipt_slots"], "final lifecycle receipt inventory")
    return {"status": "passed", "cycle_count": len(results), "cycles": results, "cumulative_commits": state["commits"]}


def engine_count(directory, budgets, expected):
    path = directory / "backend/server.log"
    try:
        if path.stat().st_size > budgets["trace_bytes"]:
            raise Incomplete("operator log exceeds the evidence budget")
        count = 0
        with path.open() as source:
            for line in source:
                if line.startswith('{"event":"mutation_work"'):
                    same("mutation_work", client.loads(line)["event"], "operator event")
                    count += 1
    except OSError as error:
        raise Incomplete("operator event log is missing") from error
    same(expected, count, "raw cumulative committed operator events")
    return {"status": "passed", "committed_events": count}


def execution_identities(directory, result, required):
    """Check recorded run-start identities without requiring today's source bytes."""
    profile_preflight = read_object(directory / "profile.json").get("preflight", {})
    result_preflight = result.get("preflight", {})
    expect(isinstance(profile_preflight, dict) and isinstance(result_preflight, dict), "run-start preflight identities are malformed")
    field = "execution_tools_sha256"
    legacy = directory / "run-start-tools.json"
    if field in profile_preflight or field in result_preflight:
        if field not in profile_preflight or field not in result_preflight:
            raise Incomplete("run-start tool identities are missing from profile or result")
        recorded = profile_preflight[field]
        same(recorded, result_preflight[field], "profile/result run-start tool identities")
        artifact = "profile.json and result.json preflight.execution_tools_sha256"
    elif legacy.exists():
        recorded = read_object(legacy)["sha256"]
        artifact = "run-start-tools.json"
    else:
        return {"status": "unsupported", "required": required,
                "reason": "no retained run-start tool identity artifact"}
    expect(isinstance(recorded, dict) and 0 < len(recorded) <= 64 and all(
        isinstance(name, str) and name.startswith("tools/") and name.endswith(".py")
        and "/" not in name[6:] and len(name) <= 128
        and isinstance(value, str) and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
        for name, value in recorded.items()), "run-start tool identities are malformed")
    current, unavailable = {}, []
    for name in sorted(recorded):
        path = Path(__file__).resolve().parent / name[6:]
        try:
            if not path.is_file() or path.stat().st_size > JSON_BYTES:
                unavailable.append(name)
                continue
            with path.open("rb") as source:
                current[name] = hashlib.file_digest(source, "sha256").hexdigest()
        except OSError:
            unavailable.append(name)
    return {"status": "passed", "required": True, "artifact": artifact, "recorded_tools": len(recorded),
            "recorded_tools_sha256": dict(sorted(recorded.items())), "current_tools_sha256": current,
            "current_tools_unavailable": unavailable,
            "scope": "recorded run-start source identities; current fingerprints are separate and historical execution does not imply current-source equality"}


def check_directory(directory):
    """Independently check one memory run and any declared receipt-cycle suffix."""
    directory, obligations = Path(directory).resolve(), {}
    try:
        result = read_object(directory / "result.json")
        settings = profile_inputs(directory, result)
        obligations["inputs"] = {"status": "passed", "required": True}
    except (Incomplete, ValueError, KeyError, TypeError, client.ClientError) as error:
        obligations["inputs"] = failure(error)
        return {"status": aggregate(obligations), "obligations": obligations}
    if result.get("status") != "passed":
        obligations["runtime_result"] = {"status": "failed" if result.get("status") == "failed" else "incomplete", "required": True}
    for name in ("failure.json", "cycles-failure.json"):
        if (directory / name).exists():
            try:
                recorded_failure = read_object(directory / name)
                expect(recorded_failure.get("status") in ("failed", "incomplete"), "retained runtime failure status is invalid")
                obligations[name] = {"status": recorded_failure["status"], "required": True,
                                     "reason": "retained runtime failure requires separate resolution"}
            except (Incomplete, ValueError, KeyError, TypeError) as error:
                obligations[name] = failure(error)
    try:
        resources = check_resources(read_jsonl(directory / "samples.jsonl", settings["budgets"]["samples_bytes"], 10000),
                                    settings["budgets"], require_database=result["backend"] == "foundationdb")
        obligations["resources"] = {"status": resources["status"], "required": True, "recomputed": resources}
    except (Incomplete, ValueError, KeyError, TypeError) as error:
        obligations["resources"] = failure(error)
    try:
        obligations["duration"] = {**timing_checks(directory, settings, result), "required": True}
    except (Incomplete, ValueError, KeyError, TypeError) as error:
        obligations["duration"] = failure(error)
    state = None
    try:
        state, memory = memory_checks(directory, settings, result)
        obligations["memory_outcomes"] = {**memory, "required": True}
        missing = state["missing_projections"]
        obligations["transient_source_values"] = {"status": "unsupported" if missing else "passed",
            "required": settings["duration_seconds"] >= 300, "checked_states": state["projection_checks"], "missing_states": missing,
            "scope": "raw public inputs/derived values checked against source-only arithmetic; older short traces rely on retained runtime source checks"}
        obligations["stale_token_observations"] = {"status": "unsupported" if state["missing_stale"] else "passed", "required": False,
            "observed_relationships": state["stale_checks"], "scope": "recorded current-token inequality only; no invented token or revision sequence"}
        obligations["complete_observations"] = {**complete_memory(directory, result, state), "required": True}
    except (Incomplete, ValueError, KeyError, TypeError, RuntimeError, client.ClientError) as error:
        obligations["memory_outcomes"] = failure(error)
        state = None
    if "receipt_cycles" in result:
        if state is None:
            obligations["receipt_cycles"] = {"status": "incomplete", "required": True, "reason": "source/receipt prefix is incomplete"}
        else:
            try:
                obligations["receipt_cycles"] = {**cycle_checks(directory, settings, result, state), "required": True}
            except (Incomplete, ValueError, KeyError, TypeError, RuntimeError, client.ClientError) as error:
                obligations["receipt_cycles"] = failure(error)
    if state is not None and ("receipt_cycles" not in result or obligations["receipt_cycles"]["status"] == "passed"):
        try:
            obligations["operator_events"] = {**engine_count(directory, settings["budgets"], state["commits"]), "required": True}
        except (Incomplete, ValueError, KeyError, TypeError, client.ClientError) as error:
            obligations["operator_events"] = failure(error)
    elif "receipt_cycles" in result:
        obligations["operator_events"] = {"status": "incomplete", "required": True,
                                             "reason": "complete lifecycle suffix must be checked before cumulative event comparison"}
    try:
        artifacts = check_artifacts(directory, settings["budgets"])
        obligations["artifacts"] = {**artifacts, "required": True}
    except (Incomplete, ValueError, KeyError, TypeError) as error:
        obligations["artifacts"] = failure(error)
    try:
        obligations["run_start_identities"] = execution_identities(directory, result, settings["duration_seconds"] >= 300)
    except (Incomplete, ValueError, KeyError, TypeError) as error:
        obligations["run_start_identities"] = failure(error)
    return {"status": aggregate(obligations), "obligations": obligations,
            "scope": "offline bounded evidence checks; no new runtime, native-codec, outage or distributed acceptance"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    result = check_directory(parser.parse_args().directory)
    print(json.dumps(result, indent=2, sort_keys=True))
    return {"passed": 0, "failed": 1, "incomplete": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
