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


def read_value(path, max_bytes=JSON_BYTES):
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
    return value


def read_object(path, max_bytes=JSON_BYTES):
    value = read_value(path, max_bytes)
    expect(isinstance(value, dict), "artifact must contain an object: " + Path(path).name)
    return value


def read_array(path, max_items):
    value = read_value(path)
    expect(isinstance(value, list), "artifact must contain an array: " + Path(path).name)
    if len(value) > max_items:
        raise Incomplete("artifact array exceeds its bounded inventory: " + Path(path).name)
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


def inspect_source_values(path, selector, facts, target):
    """Compare ordinary inspector JSON with independently reconstructed inputs."""
    observed, expected = read_object(path), evaluate(selector, facts)
    if "codec" not in observed:
        raise Incomplete("required inspector codec observation is missing")
    same("native-slice-kv-7", observed.get("codec"), "inspector codec")
    for field in ("model", "store", "tenant", "actor"):
        same(target[field], observed.get(field), "inspector " + field)
    rows = observed.get("records")
    if not isinstance(rows, list):
        raise Incomplete("required inspector records are missing")
    expect(len(rows) <= 16384, "inspector exceeds the bounded record inventory")
    records = {}
    for row in rows:
        identity, record = row["id"], row["record"]
        expect(identity not in records and isinstance(record, dict), "inspector contains repeated or malformed records")
        records[identity] = record
    codes = (101, 205, 410) if selector == "equipment" else (101, 205, 309)
    public = {identity: record for identity, record in records.items() if record.get("contract") in codes}
    if set(facts) - set(public):
        raise Incomplete("required inspected public sources are missing")
    same(set(facts), set(public), "inspected public source inventory")
    for identity, fact in facts.items():
        record = public[identity]
        if not {"input", "contract", "derived", "version"} <= record.keys():
            raise Incomplete("required public input/derived/version observation is missing")
        same(fact["contract"], record["contract"], "inspected public contract")
        same(fact["fields"], record["input"], "inspected public input")
        same(expected["derived"].get(identity), record["derived"], "inspected source-derived value")
        opaque_token(record["version"])
    actual_roots = {}
    for row in observed["roots"]:
        key = row["root"]["id"], row["root"]["slot"]
        expect(key not in actual_roots, "inspector contains repeated roots")
        value = row["summary"]["value"]
        actual_roots[key] = {"sum": value["sum"], "count": value["count"]}
    same({(row["owner"], row["slot"]): row["summary"] for row in expected["roots"]}, actual_roots,
         "inspected source-derived root values")
    return {"public_sources": len(public), "records": len(records), "roles": len(observed["roles"]),
            "receipt_count": observed["receipt_count"]}, expected


def operation_work(path, budgets, committed):
    """Reuse plain operator counters; never interpret native value bytes."""
    result = {}
    try:
        if path.stat().st_size > budgets["trace_bytes"]:
            raise Incomplete("operator log exceeds the evidence budget")
        with path.open() as source:
            for line in source:
                if line.startswith('{"event":"mutation_work"'):
                    row = client.loads(line)
                    identity = row["operation_id"]
                    expect(identity not in result and isinstance(row.get("work"), dict), "operator work is repeated or missing")
                    expect(len(result) < 1024, "operator counters exceed the bounded receipt inventory")
                    result[identity] = row["work"]
    except OSError as error:
        raise Incomplete("required operator log is unavailable") from error
    if set(committed) - set(result):
        raise Incomplete("required committed-operation work observations are missing")
    same(set(committed), set(result), "committed original operator identities")
    return result


def pressure_trace_checks(directory, settings, budgets):
    """Stream paired originals and stage observations in their recorded order."""
    state = initial_state(directory, {"identity_pool": 4096})
    fixture = read_object(directory / "fixture.plan.json")
    deliveries = {identity for identity, fact in state["facts"].items() if fact["contract"] == 205}
    pools = {identity for identity, fact in state["facts"].items() if fact["contract"] == 101}
    hot_pool = fixture["request"]["commands"][0]["id"]
    pending, stages, outcomes, geometry = {}, {}, {}, {}
    committed = {fixture["request"]["operation_id"]}
    counts, trajectories = Counter(), {}

    def roots():
        current = {row["owner"]: row["summary"] for row in evaluate("equipment", state["facts"])["roots"]}
        for owner, value in current.items():
            allowed = trajectories.setdefault(owner, {"sums": set(), "counts": set()})
            allowed["sums"].update((value["sum"], str(int(value["sum"])+1)))
            allowed["counts"].add(value["count"])
        return current

    roots()
    for row in read_jsonl(directory / "pressure/trace.jsonl", budgets["trace_bytes"], 4*settings["max_requests"]+128):
        event = row.get("event")
        if event == "stage":
            identity = row["stage_id"]
            expect(isinstance(identity, str) and identity not in stages and len(stages) < 8, "pressure stage identity is repeated or unbounded")
            stages[identity] = {"observation": row, "counts": Counter(), "pending": 0, "peak_pending": 0,
                                "pending_mismatches": 0, "unknowns": 0, "drain": None, "roots": roots(), "latencies": [],
                                "original_versions": {}, "committed_sources": Counter()}
            continue
        group = stages.get(row.get("stage_id"))
        if event == "stage_end":
            if group is None or group.get("end") is not None:
                raise Incomplete("raw pressure stage end is missing its unique stage")
            group["end"] = row
            continue
        if event == "offer":
            if group is None:
                raise Incomplete("raw pressure offer has no recorded stage")
            same(group["counts"]["offered"], row["index"], "raw offer index")
            expect(type(row["producer_accepted"]) is bool and type(row["pending"]) is int
                   and 0 <= row["pending"] <= settings["max_pending"], "raw pending/offer observation exceeds its budget")
            group["pending_mismatches"] += row["pending"] != group["pending"]
            group["counts"]["offered"] += 1
            if row["producer_accepted"]:
                expect(row["pending"] < settings["max_pending"], "producer accepted work with a full queue")
                group["pending"] += 1
                group["counts"]["submitted"] += 1
                group["peak_pending"] = max(group["peak_pending"], group["pending"])
            else:
                same(settings["max_pending"], row["pending"], "producer backpressure boundary")
                group["counts"]["producer_backpressure"] += 1
            continue
        if event == "drain":
            if group is None:
                raise Incomplete("raw pressure drain has no recorded stage")
            request, response = row["request"], row["response"]
            same("records.get", request["method"], "sole-permit drain method")
            same(state["target"]["model"], request["params"]["model"], "sole-permit drain model")
            expect(request["params"]["id"] in deliveries and isinstance(response, dict)
                   and {"input", "derived", "version"} <= response.keys(), "authenticated DB drain response is missing")
            expect(group["drain"] is None, "raw pressure stage repeats its successful drain")
            group["pending_mismatches"] += group["pending"] != 0
            group["drain"] = row
            continue
        if event not in ("intent", "outcome", "read"):
            raise Incomplete("unrecognized pressure trace observation")
        if row.get("phase") == "measurement":
            if group is None:
                raise Incomplete("raw pressure completion/intent has no recorded stage")
            same(group["observation"]["pattern"], row.get("pattern"), "raw pressure stage pattern")
        if event == "intent":
            saved = row.get("plan")
            if not isinstance(saved, dict):
                raise Incomplete("pressure intent lost its original plan")
            client._plan(saved)
            identity = saved["request"]["operation_id"]
            expect(identity not in state["seen"] and len(state["seen"]) <= settings["max_new_operations"]
                   and len(pending) < settings["max_pending"], "duplicate or unbounded pressure original inventory")
            same(state["target"], saved["target"], "pressure original target")
            same(state["context"], saved["request"]["context"], "pressure original context")
            if row.get("phase") == "measurement":
                commands = saved["request"]["commands"]
                expect(len(commands) == 1 and commands[0]["op"] == "update" and commands[0]["id"] in deliveries,
                       "pressure measurement is outside its declared delivery edits")
                command = commands[0]
                opaque_token(command["if_version"])
                owner = state["facts"][command["id"]]["fields"]["pool"]
                expect(owner in pools and (row["pattern"] == "independent_business_roots" or owner == hot_pool),
                       "pressure edit changed an undeclared business root")
                same({"quantity": str(int(group["roots"][owner]["sum"])+1)}, command["set"], "declared pressure edit")
                same([], command.get("unset", []), "declared pressure unset")
                previous = group["original_versions"].setdefault(command["id"], command["if_version"])
                same(previous, command["if_version"], "pressure stage original CAS token")
            state["seen"][identity] = digest(saved)
            pending[identity] = row
            if group:
                group["counts"]["intents"] += 1
            continue
        if event == "outcome":
            saved = row.get("plan")
            if not isinstance(saved, dict):
                raise Incomplete("pressure outcome lost its original plan")
            identity = saved["request"]["operation_id"]
            original = pending.pop(identity, None)
            if original is None:
                raise Incomplete("pressure outcome has no original intent")
            same(original["plan"], saved, "pressure paired original plan")
            for field in ("phase", "label", "pattern", "stage_id"):
                same(original.get(field), row.get(field), "pressure paired " + field)
            kind = row.get("kind")
            if kind is None:
                raise Incomplete("pressure outcome classification is missing")
            expect(kind in ("committed", "busy", "stale_version", "transaction_conflict", "transaction_limit", "transaction_aborted", "outcome_unknown"),
                   "pressure mutation classification is invalid")
            status = kind
            if kind == "outcome_unknown":
                if row.get("resolved_status") not in ("committed", "not_observed") or not isinstance(row.get("status_observation"), dict):
                    raise Incomplete("pressure unknown outcome lacks its original status observation")
                same(row["resolved_status"], row["status_observation"].get("status"), "unknown status classification")
                status = row["resolved_status"]
                if group:
                    group["unknowns"] += 1
            response = row.get("response") if kind == "committed" else row.get("status_observation")
            original_result = None
            if status == "committed":
                if not isinstance(response, dict) or response.get("status") != "committed" or not isinstance(response.get("result"), dict):
                    raise Incomplete("committed pressure result is missing")
                if kind == "committed":
                    if "replayed" not in response:
                        raise Incomplete("new pressure intent replay observation is missing")
                    same(False, response.get("replayed"), "new pressure intent replay")
                same(identity, response["result"]["operation_id"], "committed pressure original ID")
                if kind == "outcome_unknown":
                    same(response["result"], row["resolved_result"], "resolved original pressure result")
                original_result = digest(response["result"])
                if group:
                    source = saved["request"]["commands"][0]["id"]
                    group["committed_sources"][source] += 1
                    same(1, group["committed_sources"][source], "prepared pressure source publication count")
                state["facts"] = stage(state["facts"], saved["request"]["commands"])
                expectation = evaluate("equipment", state["facts"])
                committed.add(identity)
                roots()
                label = row.get("label", "")
                if row.get("phase") == "prepare" and label.startswith("cascade-"):
                    level = int(label.removeprefix("cascade-"))
                    owner = state["facts"][saved["request"]["commands"][0]["id"]]["fields"]["pool"]
                    geometry[level] = {"public_sources": len(state["facts"]), "roots": roots(), "operation_id": identity,
                                       "r": sum(dependency["active"] and dependency["pool"] == owner for dependency in expectation["dependencies"])}
            outcomes[identity] = {"plan_sha256": digest(saved), "kind": kind, "status": status,
                                  "result_sha256": original_result, "status_observation": row.get("status_observation")}
        else:
            kind = row.get("kind")
            if group:
                group["counts"]["requests"] += 1
            if kind not in ("read_success", "busy"):
                raise Incomplete("pressure read classification is missing or unresolved")
            request = row.get("request")
            if not isinstance(request, dict):
                raise Incomplete("pressure read request metadata is missing")
            same("roots.read", request["method"], "pressure reader method")
            same(state["target"]["model"], request["params"]["model"], "pressure reader model")
            same(7, request["params"]["slot"], "pressure reader slot")
            owner = request["params"]["owner"]
            expect(owner in pools and (row.get("pattern") == "independent_business_roots" or owner == hot_pool),
                   "pressure reader changed an undeclared business root")
            if kind == "read_success":
                response = row["response"]
                same(owner, response["owner"], "pressure reader response owner")
                same(7, response["slot"], "pressure reader response slot")
                value = response["value"]
                if group:
                    expected = group["roots"][owner]
                    expect(value["sum"] in (expected["sum"], str(int(expected["sum"])+1)) and value["count"] == expected["count"],
                           "pressure read differs from its source-declared trajectory")
                else:
                    expect(value["sum"] in trajectories[owner]["sums"] and value["count"] in trajectories[owner]["counts"],
                           "pressure read differs from reconstructed source values")
        if row.get("phase") == "measurement":
            if type(row.get("http_status")) is not int:
                raise Incomplete("pressure HTTP observation is missing")
            expect(100 <= row["http_status"] <= 599, "pressure HTTP observation is invalid")
            if kind != "outcome_unknown":
                same(429 if kind == "busy" else 200, row["http_status"], "pressure HTTP/classification pairing")
            counts["outcome:" + kind] += 1
            counts["http:" + str(row["http_status"])] += 1
            counts["completed"] += 1
            if group:
                group["counts"]["outcome:" + kind] += 1
                group["counts"]["http:" + str(row["http_status"])] += 1
                group["counts"]["completed"] += 1
                group["counts"]["completions"] += 1
                group["pending"] -= 1
                latency = row.get("queue_and_request_ms", row.get("latency_ms"))
                if not isinstance(latency, (int, float)) or not math.isfinite(latency) or latency < 0:
                    raise Incomplete("pressure latency observation is missing")
                group["latencies"].append(latency)
    if pending or not outcomes:
        raise Incomplete("pressure trace contains missing original outcomes")
    return state, outcomes, committed, stages, geometry, counts


def pressure_stage_checks(result, stages, counts):
    """Check offers, completion counts, queue prefixes, latencies and drains."""
    from harness import latency
    settings = result["profile"]
    reports = result["steps"] + result["bursts"]
    if len(stages) != len(reports) or any(not isinstance(row.get("stage_id"), str) for row in reports):
        raise Incomplete("pressure evidence lacks raw stage attribution")
    same(set(stages), {row["stage_id"] for row in reports}, "raw pressure stage inventory")
    aggregate_counts, total_offered, total_backpressure = Counter(), 0, 0
    for index, report in enumerate(reports):
        group = stages[report["stage_id"]]
        observation, raw = group["observation"], group["counts"]
        same(report["clients"], observation["clients"], "raw stage clients")
        if index < len(result["steps"]):
            for field in ("pattern", "offered_rate"):
                same(report[field], observation[field], "raw stage " + field)
            same(settings["step_seconds"], observation["duration_seconds"], "raw offering duration")
            scheduled = math.ceil(settings["step_seconds"] * report["offered_rate"])
            same(scheduled - raw["offered"], report["counts"].get("not_offered_before_duration", 0), "not-offered count")
            expect(0 <= raw["offered"] <= scheduled, "raw offered work exceeds the declared schedule")
        else:
            same("barrier", observation.get("mode"), "raw barrier mode")
            same("hot_root_submission_barrier", observation["pattern"], "raw barrier pattern")
            same(8, raw["offered"], "raw barrier offers")
        if group["unknowns"]:
            raise Incomplete("raw client completion timing for deferred unknown outcomes is unavailable")
        expect(not group["pending_mismatches"] and group["pending"] == 0, "raw pending queue differs from its completion prefix")
        same(group["peak_pending"], report["peak_pending"], "raw peak pending queue")
        if group["drain"] is None:
            raise Incomplete("pressure stage lacks its successful sole-permit DB drain")
        if observation.get("mode") == "paced":
            ending = group.get("end")
            if not isinstance(ending, dict):
                raise Incomplete("paced pressure stage lacks achieved elapsed-time evidence")
            elapsed = ending.get("offering_elapsed_seconds")
            if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed <= 0:
                raise Incomplete("paced pressure achieved elapsed time is missing or invalid")
            future_drain = ending.get("future_drain_seconds")
            total_drain = ending.get("total_drain_seconds")
            for label, value in (("future drain", future_drain), ("total drain", total_drain)):
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                    raise Incomplete("paced pressure " + label + " timing is missing or invalid")
            expect(future_drain <= settings["drain_seconds"] and total_drain <= settings["drain_seconds"],
                   "paced pressure drain exceeded its declared deadline")
            same(report.get("offering_elapsed_seconds"), elapsed, "reported achieved offering elapsed time")
            for field in ("offered", "submitted", "completed"):
                if field not in report.get("counts", {}):
                    raise Incomplete("pressure stage omits reported " + field + " count")
                same(raw[field], report["counts"][field], "reported actual " + field + " count")
            same(raw["submitted"], raw["intents"] + raw["requests"], "accepted offers and submitted requests")
            same(raw["completed"], raw["completions"], "completed raw responses")
            same(raw["offered"] / elapsed, report.get("offered_per_second"), "achieved offered rate")
            same(raw["submitted"] / elapsed, report.get("submitted_per_second"), "achieved submitted rate")
            same(raw["completed"] / elapsed, report.get("completed_per_second"), "achieved completed rate")
        for field in ("offered", "submitted", "completed", "producer_backpressure"):
            same(raw[field], report["counts"].get(field, 0), "raw stage " + field)
        names = {name for name in raw if name.startswith(("outcome:", "http:"))}
        names.update(name for name in report["counts"] if name.startswith(("outcome:", "http:")))
        for field in names:
            same(raw[field], report["counts"].get(field, 0), "raw stage " + field)
        same(latency(group["latencies"]), report["latency"], "raw stage latency distribution")
        total_offered += raw["offered"]
        total_backpressure += raw["producer_backpressure"]
        aggregate_counts.update({name: value for name, value in raw.items()
                                 if name == "completed" or name.startswith(("outcome:", "http:"))})
    same(dict(counts), dict(aggregate_counts), "aggregate raw pressure outcomes")
    return {"status": "passed", "stages": len(stages), "offered": total_offered,
            "completed": counts["completed"], "producer_backpressure": total_backpressure,
            "scope": "raw offers/completions check the pending queue; active-worker scalars and drain deadlines also use the existing finite-load checker"}


def pressure_receipt_checks(directory, budgets, outcomes, result):
    statuses, replays = set(), 0
    for row in read_jsonl(directory / "pressure/receipt-observations.jsonl", budgets["trace_bytes"], 1024):
        saved, response = row["plan"], row["response"]
        client._plan(saved)
        if not isinstance(response, dict):
            raise Incomplete("pressure receipt response is missing")
        identity = saved["request"]["operation_id"]
        expect(identity in outcomes, "receipt observation changed the original operation ID")
        original = outcomes[identity]
        same(original["plan_sha256"], digest(saved), "receipt original plan/context")
        if row["event"] == "status":
            expect(identity not in statuses, "pressure original status is repeated")
            statuses.add(identity)
            expected = "committed" if original["status"] == "committed" else "not_observed"
            if response.get("status") not in ("committed", "not_observed"):
                raise Incomplete("original pressure status remains unresolved")
            same(expected, response["status"], "original post-drain receipt")
            if expected == "committed":
                same(original["result_sha256"], digest(response["result"]), "original committed receipt result")
            if original["status_observation"] is not None:
                same(original["status_observation"], response, "original unknown status observation")
        elif row["event"] == "replay":
            if identity not in statuses:
                raise Incomplete("pressure replay has no observed original status")
            expect(original["status"] == "committed", "pressure replay has no confirmed original receipt")
            same(True, response["replayed"], "pressure same-ID replay")
            same("committed", response["status"], "pressure replay classification")
            same(original["result_sha256"], digest(response["result"]), "pressure replay result")
            replays += 1
        else:
            raise Incomplete("unknown pressure receipt observation")
    if set(outcomes) != statuses or not replays:
        raise Incomplete("pressure original status/replay observations are missing")
    absent = sum(row["status"] != "committed" for row in outcomes.values())
    for field, expected in (("resolved", len(statuses)), ("absent_after_quiescence", absent), ("unresolved", 0),
                            ("replacement_mutation_submissions", 0), ("original_contexts_preserved", True), ("same_id_replay", True)):
        same(expected, result["receipts"][field], "reported pressure receipt " + field)
    return {"status": "passed", "resolved": len(statuses), "absent_after_drain": absent, "same_id_replays": replays,
            "scope": "complete original plans and raw status/replay responses; no replacement intent or receipt-context refresh"}


def pressure_geometry_checks(result, geometry, work):
    if len(result["geometry"]) != 3 or set(result["profile"]["equipment_reservations"]) != set(geometry):
        raise Incomplete("required equipment cascade/geometry observations are missing")
    same(result["profile"]["equipment_reservations"], [row["added_reservations"] for row in result["geometry"]], "equipment geometry levels")
    same(set(result["profile"]["equipment_reservations"]), set(geometry), "executed equipment cascade levels")
    for row in result["geometry"]:
        observed = geometry[row["added_reservations"]]
        same(row["added_reservations"] + 6, observed["public_sources"], "actual geometry source inventory")
        same(observed["public_sources"], row["public_sources"], "reported geometry sources")
        same({owner: value["count"] for owner, value in observed["roots"].items()},
             {root["owner"]: root["n"] for root in row["relevant_roots"]}, "actual root membership geometry")
        same({"delivery_record": 1, "reservation_source": 0, "private_occurrence": 1,
              "maintained_occurrences_per_active_reservation": 2}, row["actual_memberships"], "declared actual memberships")
        same(work[observed["operation_id"]], row["work"], "raw geometry operation work")
        same(observed["r"], row["r"], "source-derived equipment invalidation closure")
        same(observed["r"], row["work"]["causal_evaluations"], "raw equipment evaluated closure")
    return {"status": "passed", "levels": len(geometry), "scope": "authored public sources, actual root membership counts and raw per-operation counters"}


def pressure_quantity_checks(directory, budgets, recorded):
    prefix = directory / "pressure/quantity"
    steps = read_array(prefix / "steps.json", 16)
    if len(steps) != 8:
        raise Incomplete("required Quantity source observations are missing")
    same(["source", "prepare-1", "cascade-1", "prepare-4", "cascade-4", "prepare-15", "cascade-15", "seventeenth-source"],
         [row.get("name") for row in steps], "executed Quantity trajectory")
    facts, target, context, seen, committed, cascades = {}, None, None, set(), set(), {}
    for row in steps:
        saved = row["plan"]
        client._plan(saved)
        identity = saved["request"]["operation_id"]
        expect(identity not in seen, "Quantity reused an original mutation ID")
        seen.add(identity)
        if target is None:
            target, context = saved["target"], saved["request"]["context"]
        same(target, saved["target"], "Quantity original target")
        same(context, saved["request"]["context"], "Quantity original receipt context")
        same(facts, row["before_facts"], "Quantity raw source prefix")
        proposed = stage(facts, saved["request"]["commands"])
        if row["name"] == "seventeenth-source":
            try:
                evaluate("quantity", proposed)
            except OracleError as error:
                same("state_limit", error.kind, "source-derived Quantity rejection")
            else:
                raise EvidenceError("the Quantity seventeenth source did not cross its declared envelope")
            same("state_limit", row["observed"], "recorded Quantity rejection")
            same("not_observed", row["receipt"], "rejected Quantity receipt")
            before = image(prefix / "seventeenth-source-before.backup.json")
            after = image(prefix / "seventeenth-source-after.backup.json")
            same(before, after, "Quantity quiescent complete rejection image")
            same(len(committed), len(after["tables"]["operations"]), "Quantity unchanged receipt inventory")
        else:
            evaluate("quantity", proposed)
            same("committed", row["observed"], "Quantity recorded outcome")
            response = row["result"]
            same("committed", response["status"], "Quantity mutation classification")
            same(False, response["replayed"], "Quantity new original replay")
            same(identity, response["result"]["operation_id"], "Quantity committed original ID")
            facts = proposed
            committed.add(identity)
            inspect_source_values(prefix / (row["name"] + ".inspect.json"), "quantity", facts, target)
            if row["name"].startswith("cascade-"):
                cascades[int(row["name"].removeprefix("cascade-"))] = {"sources": len(facts), "operation_id": identity, "work": row["work"]}
        same(facts, row["after_facts"], "Quantity raw source suffix")
    work = operation_work(prefix / "server.log", budgets, committed)
    own = read_object(directory / "pressure/quantity-result.json")
    same(own, recorded, "nested Quantity result")
    same(target["model"], recorded["model"], "Quantity model identity")
    same([1, 4, 15], [row["requested_dependents"] for row in recorded["levels"]], "Quantity geometry levels")
    for row in recorded["levels"]:
        actual = cascades[row["requested_dependents"]]
        same(row["requested_dependents"]+1, actual["sources"], "Quantity actual dependent inventory")
        same(actual["sources"], row["public_sources"], "Quantity reported sources")
        same((0, 0, actual["sources"]), (row["n"], row["m"], row["r"]), "Quantity authored geometry and evaluated closure")
        same(work[actual["operation_id"]], row["work"], "raw Quantity cascade work")
        same(row["r"], row["work"]["causal_evaluations"], "raw Quantity evaluated closure")
    same({"kind": "state_limit", "public_sources": 17, "all_tables_unchanged": True, "receipt": "not_observed"},
         recorded["capacity_rejection"], "Quantity capacity rejection")
    return {"status": "passed", "source_snapshots": len(committed), "public_sources": len(facts), "levels": len(cascades), "rejection_table_count": 13}


def pressure_failure(error):
    if isinstance(error, (KeyError, TypeError, IndexError)):
        return failure(Incomplete("required pressure observation fields are missing or unreadable"))
    return failure(error)


def pressure_source_checks(directory, result, state, committed):
    observed, expected = inspect_source_values(directory / "pressure-complete.inspect.json", "equipment", state["facts"], state["target"])
    outputs = sum(len(row["roles"]) for row in expected["dependencies"] if row["active"])
    same(result["model"], state["target"]["model"], "pressure compiled model")
    same(len(committed), observed["receipt_count"], "inspected complete receipt count")
    same(len(state["facts"])+outputs, observed["records"], "inspected public/private inventory")
    same(outputs, observed["roles"], "inspected retained role inventory")
    same({"public_sources": len(state["facts"]), "active_outputs": outputs, "retained_roles": outputs, "receipt_slots": len(committed)},
         result["complete_state"]["logical"], "reported complete logical inventory")
    return {"status": "passed", **observed}


def pressure_complete_checks(directory, result, state, committed):
    complete = image(directory / "backend/pressure-complete.backup.json")
    same(digest(complete), result["complete_state"]["image_sha256"], "complete pressure image")
    same(13, result["complete_state"]["table_count"], "complete pressure table count")
    same(len(state["facts"]), len(complete["tables"]["public_records"]), "complete pressure public inventory")
    for table in ("operations", "receipt_slots"):
        same(len(committed), len(complete["tables"][table]), "complete pressure " + table)
    same("valid", result["complete_state"]["integrity"]["status"], "executed pressure native integrity")
    same(len(committed), result["complete_state"]["integrity"]["receipts"], "executed pressure native receipt count")
    return {"status": "passed", "table_count": 13, "committed_receipts": len(committed)}


def pressure_ingress_checks(result, settings, budgets):
    observed = result["slow_input"]
    same((settings["slow_connections"], settings["slow_connections"], settings["slow_input_seconds"]),
         (observed["opened"], observed["closed"], observed["owned_hold_seconds"]), "bounded partial-input connection observations")
    for phase in ("before", "during"):
        process = observed[phase]
        if not isinstance(process, dict) or process.get("available") is not True:
            raise Incomplete("partial-input process observation is unavailable")
        same(result["application_pid"], process["pid"], "partial-input application PID")
        expect(max(process["rss_kib"], process["peak_rss_kib"]) <= budgets["app_rss_kib"]
               and process["open_fds"] <= budgets["app_fds"] and process["threads"] <= budgets["app_threads"],
               "partial-input application exceeded its resource budget")
    same("passed", observed["recovery"]["status"], "post-close ingress drain")
    expect(observed["recovery"]["elapsed_seconds"] <= settings["drain_seconds"], "post-close ingress drain budget exceeded")
    return {"status": "passed", "owned_partial_connections": observed["opened"],
            "scope": "finite voluntarily closed sockets and raw process snapshots; no general RPC body-read deadline or unbounded ingress protection claim"}


def check_pressure_directory(directory):
    """Check completed finite pressure artifacts without native execution."""
    from g8_pressure import check_overload, default_pressure_profile, pressure_profile
    directory, obligations = Path(directory).resolve(), {}
    try:
        result = read_object(directory / "pressure/pressure-result.json")
        recorded = read_object(directory / "pressure/profile.json")
        fields = set(default_pressure_profile())
        expect(set(recorded) == fields | {"backend", "budgets", "database_observer", "execution_module_sha256"}, "unknown pressure profile fields")
        settings = pressure_profile({name: recorded[name] for name in fields})
        same(settings, result["profile"], "recorded pressure inputs")
        budgets = recorded["budgets"]
        validate_budgets(budgets)
        expect(result["backend"] in ("redb", "surrealkv", "foundationdb"), "unknown pressure backend")
        same(result["backend"], recorded["backend"], "pressure profile backend")
        same(recorded["execution_module_sha256"], result["execution_module_sha256"], "pressure run-start module identity")
        expect(isinstance(result["execution_module_sha256"], str) and len(result["execution_module_sha256"]) == 64
               and all(character in "0123456789abcdef" for character in result["execution_module_sha256"]), "pressure run-start hash is malformed")
        obligations["inputs"] = {"status": "passed", "required": True, "recorded_pressure_module_sha256": result["execution_module_sha256"]}
    except (Incomplete, ValueError, KeyError, TypeError, client.ClientError) as error:
        obligations["inputs"] = pressure_failure(error)
        return {"status": aggregate(obligations), "obligations": obligations}
    if result.get("status") != "passed":
        obligations["runtime_result"] = {"status": "failed" if result.get("status") == "failed" else "incomplete", "required": True}
    for name in ("failure.json", "pressure/failure.json"):
        if (directory / name).exists():
            try:
                retained = read_object(directory / name)
                expect(retained.get("status") in ("failed", "incomplete"), "retained pressure failure status is invalid")
                obligations[name] = {"status": retained["status"], "required": True}
            except (Incomplete, ValueError, KeyError, TypeError) as error:
                obligations[name] = pressure_failure(error)
    try:
        samples = list(read_jsonl(directory / "pressure/samples.jsonl", budgets["samples_bytes"], 10000))
        resources = check_resources(samples, budgets, require_database=result["backend"] == "foundationdb")
        for row in samples:
            same(result["application_pid"], row["processes"]["application"]["pid"], "pressure application PID")
            if result["backend"] == "foundationdb":
                same(recorded["database_observer"]["pid"], row["processes"]["database"]["pid"], "pressure database PID")
        obligations["resources"] = {"status": resources["status"], "required": True, "recomputed": resources}
    except (Incomplete, ValueError, KeyError, TypeError) as error:
        obligations["resources"] = pressure_failure(error)
    state = None
    try:
        state, outcomes, committed, stages, geometry, counts = pressure_trace_checks(directory, settings, budgets)
        obligations["source_trace"] = {"status": "passed", "required": True, "original_outcomes": len(outcomes), "committed": len(committed)}
    except (Incomplete, ValueError, KeyError, TypeError, IndexError, RuntimeError, client.ClientError) as error:
        obligations["source_trace"] = pressure_failure(error)
        state = None
    if state is not None:
        for name, function in (("source_values", lambda: pressure_source_checks(directory, result, state, committed)),
                               ("complete_image", lambda: pressure_complete_checks(directory, result, state, committed)),
                               ("equipment_geometry", lambda: pressure_geometry_checks(result, geometry, operation_work(directory / "backend/server.log", budgets, committed))),
                               ("stages", lambda: pressure_stage_checks(result, stages, counts)),
                               ("original_receipts", lambda: pressure_receipt_checks(directory, budgets, outcomes, result))):
            try:
                obligations[name] = {**function(), "required": True}
            except (Incomplete, ValueError, KeyError, TypeError, IndexError, RuntimeError, client.ClientError) as error:
                obligations[name] = pressure_failure(error)
    else:
        for name in ("source_values", "complete_image", "equipment_geometry", "stages", "original_receipts"):
            obligations[name] = {"status": "incomplete", "required": True, "reason": "raw original/source prefix must be complete before this observation can be checked"}
    try:
        before = image(directory / "backend/pressure-limit-before.backup.json")
        after = image(directory / "backend/pressure-limit-after.backup.json")
        same(before, after, "quiescent pressure command/body rejection tables")
        request = read_object(directory / "pressure/commands-65.request.json")
        fixture = read_object(directory / "fixture.plan.json")
        same(fixture["request"]["model"], request["model"], "over-limit original model")
        same(fixture["request"]["context"], request["context"], "over-limit original receipt context")
        same(65, len(request["commands"]), "actual over-limit command request")
        same(65, result["limits"]["commands"], "recorded command limit")
        same(("invalid_input", "not_observed", 413, client.MAX_REQUEST_BYTES+1),
             (result["limits"]["command_rpc_kind"], result["limits"]["rejected_receipt"],
              result["limits"]["body_http_status"], result["limits"]["body_bytes"]), "recorded command/body rejection")
        obligations["rejection_images"] = {"status": "passed", "required": True, "table_count": 13, "complete_image_sha256": digest(before)}
    except (Incomplete, ValueError, KeyError, TypeError, RuntimeError) as error:
        obligations["rejection_images"] = pressure_failure(error)
    try:
        obligations["finite_ingress"] = {**pressure_ingress_checks(result, settings, budgets), "required": True}
    except (Incomplete, ValueError, KeyError, TypeError, RuntimeError) as error:
        obligations["finite_ingress"] = pressure_failure(error)
    try:
        obligations["quantity_geometry"] = {**pressure_quantity_checks(directory, budgets, result["quantity"]), "required": True}
    except (Incomplete, ValueError, KeyError, TypeError, IndexError, RuntimeError, client.ClientError) as error:
        obligations["quantity_geometry"] = pressure_failure(error)
    try:
        obligations["finite_load"] = {**check_overload(result), "required": True}
    except (Incomplete, ValueError, KeyError, TypeError, RuntimeError) as error:
        obligations["finite_load"] = pressure_failure(error)
    try:
        obligations["artifacts"] = {**check_artifacts(directory, budgets), "required": True}
        obligations["run_start_identities"] = execution_identities(directory, result, True)
    except (Incomplete, ValueError, KeyError, TypeError) as error:
        obligations["artifacts"] = pressure_failure(error)
    obligations["native_permit_proof"] = {"status": "unsupported", "required": False,
        "scope": "matching accepted real-writer/native deadline evidence is supplied by the checkpoint coordinator; raw HTTP pressure alone does not prove native permit retention"}
    return {"status": aggregate(obligations), "obligations": obligations,
            "scope": "bounded saved pressure observations, source arithmetic and complete raw images; native codecs and admission semantics are not reimplemented"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    result = check_directory(parser.parse_args().directory)
    print(json.dumps(result, indent=2, sort_keys=True))
    return {"passed": 0, "failed": 1, "incomplete": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
