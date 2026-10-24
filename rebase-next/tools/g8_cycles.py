"""Executed receipt allocation/archive epochs, separate from PID memory runs."""
from collections import Counter
import hashlib
import os
from pathlib import Path
import random
import threading
import time

import client
from g8_observe import Incomplete, JsonlWriter, check_artifacts, check_resources, process_sample, read_jsonl, sample
from g8_workload import check_sources, engine_observation, logical, offline, perform, physical_paths, publish_result, reconcile_trace
from harness import backup_image, check_archive, expect_error, require
from verify_runtime import equal, write_json


def run_cycles(state, *, cycles=2, database_pid=None, database_paths=()):
    """Reach full capacity through requests, replay/reject, archive and resume.

    No reset or structural receipt fixture is used. Every fill request finishes
    before the next, and original contexts are reconciled before cleanup.
    """
    if type(cycles) is not int or not 2 <= cycles <= 4:
        raise ValueError("Receipt assurance requires two to four executed archive cycles")
    backend, directory, budgets = state["backend"], state["directory"], state["profile"]["budgets"]
    rng, results = random.Random(state["profile"]["seed"] + 1), []
    execution_identity = hashlib.file_digest(open(__file__, "rb"), "sha256").hexdigest()
    cumulative_events = engine_observation(backend, budgets["trace_bytes"])["committed_events"]
    try:
        for index in range(cycles):
            if backend.process is None:
                backend.start()
            start_receipts = state["receipts"]
            require(0 <= start_receipts < 1024, "Archive cycle must have available starting receipt room")
            path = directory / f"cycle-{index}.trace.jsonl"
            samples_path = directory / f"cycle-{index}.samples.jsonl"
            stop, errors = threading.Event(), []
            pid = backend.process.pid
            coverage = Counter()
            started = time.monotonic()
            deadline = started+300

            def check_time():
                if time.monotonic() >= deadline:
                    raise Incomplete("Receipt cycle exceeded its predeclared 300-second budget")

            def observe(writer):
                next_at = time.monotonic()
                while not stop.is_set():
                    try:
                        writer.write(sample(pid, os.getpid(), database_pid, physical_paths(state, database_paths),
                                            "measurement", logical(state)))
                    except BaseException as error:
                        errors.append(error)
                        stop.set()
                        return
                    next_at += .5
                    stop.wait(max(0, next_at - time.monotonic()))

            with JsonlWriter(path, budgets["trace_bytes"]) as trace, JsonlWriter(samples_path, budgets["samples_bytes"]) as samples:
                observer = threading.Thread(target=observe, args=(samples,), daemon=False)
                observer.start()
                try:
                    while state["receipts"] < 1024:
                        check_time()
                        if errors:
                            raise errors[0]
                        action = "create" if state["active"] is None else (
                            "update" if state["last"][0]["request"]["commands"][0]["op"] == "create" else "delete")
                        item = perform(state, action, rng, trace, phase="receipt-fill")
                        equal("fill.commit", "committed", item["kind"])
                        coverage[action] += 1
                    # Give even a very fast fill a comparable absolute-budget sample.
                    stop.wait(max(0, started + .6 - time.monotonic()))
                finally:
                    stop.set()
                    observer.join(timeout=5)
                    require(not observer.is_alive(), "Receipt observer did not drain")
            if errors:
                raise errors[0]
            fill_seconds = time.monotonic()-started
            resources = check_resources(read_jsonl(samples_path, budgets["samples_bytes"], 10000), budgets,
                                        require_database=database_pid is not None)
            require(resources["status"] == "passed", "Receipt fill resource observations did not pass")
            check_sources(state)
            reconciled = reconcile_trace(state, path, deadline=deadline)
            check_time()
            full_plan, full_response = state["last"]
            original_plan = client._bytes(full_plan)
            replay = client.execute(backend.url, backend.token, full_plan)
            require(replay["replayed"], "Full-capacity replay applied a new operation")
            equal("full.replay", full_response["result"], replay["result"])
            equal("full.original_context", original_plan, client._bytes(full_plan))
            controls = JsonlWriter(directory / f"cycle-{index}.controls.jsonl", budgets["trace_bytes"])
            controls.write({"event": "full-replay", "plan": full_plan, "response": replay})
            full = offline(state, f"cycle-{index}-full")
            equal("full.executed_receipts", 1024, full["integrity"]["receipts"])
            equal("full.allocated_slots", 1024, full["logical"]["receipt_slots"])
            before = backup_image(backend, f"cycle-{index}-rejection-before")
            equal("full.actual_receipts", 1024, len(before["tables"]["operations"]))
            equal("full.actual_slots", 1024, len(before["tables"]["receipt_slots"]))
            check_time()
            backend.start()
            identity = state["ids"][2]
            version = backend.call("records.get", {"model": state["model"], "id": identity})["version"]
            overflow = backend.plan({"model": state["model"], "commands": [{"op": "update", "id": identity,
                "if_version": version, "set": {"quantity": "10"}, "unset": []}], "returning": []}, f"cycle-{index}-overflow")
            try:
                client.execute(backend.url, backend.token, overflow)
            except client.ClientError as error:
                equal("overflow.kind", "receipt_limit", error.kind)
                overflow_kind, overflow_http = error.kind, error.http_status
            else:
                raise RuntimeError("Full-capacity new intent did not reject")
            overflow_status = client.execute(backend.url, backend.token, overflow, status=True)
            equal("overflow.no_receipt", "not_observed", overflow_status["status"])
            controls.write({"event": "overflow", "plan": overflow, "kind": overflow_kind,
                            "http_status": overflow_http, "status_observation": overflow_status})
            backend.stop()
            after_reject = backup_image(backend, f"cycle-{index}-rejection-after")
            equal("overflow.quiescent_all_tables", hashlib.sha256(client._bytes(before)).hexdigest(),
                  hashlib.sha256(client._bytes(after_reject)).hexdigest())
            allocated = 1024-start_receipts
            cumulative_events += allocated
            equal("fill.cumulative_operator_events", cumulative_events,
                  engine_observation(backend, budgets["trace_bytes"])["committed_events"])
            archive_path = directory / f"cycle-{index}.archive.json"
            check_time()
            archived = backend.cli("receipts", "archive", backend.store, archive_path)
            equal("archive.status", "archived", archived["status"])
            after_archive = backup_image(backend, f"cycle-{index}-archived")
            check_archive(after_reject, after_archive)
            with state["lock"]:
                state["receipts"] = 0
            backend.start()
            for event, status_read in (("expired-replay", False), ("expired-status", True)):
                try:
                    client.execute(backend.url, backend.token, full_plan, status=status_read)
                except client.ClientError as error:
                    equal("archive.original_expiry", "operation_expired", error.kind)
                    controls.write({"event": event, "plan": full_plan, "kind": error.kind,
                                    "http_status": error.http_status})
                else:
                    raise RuntimeError("Original pre-archive context did not expire")
            controls.close()
            check_time()
            check_sources(state)
            resumed_path = directory / f"cycle-{index}.resumed.jsonl"
            with JsonlWriter(resumed_path, budgets["trace_bytes"]) as resumed_trace:
                # Drain a partial final cycle, then execute an entire new CRUD cycle.
                resumed = Counter()
                if state["active"] is not None:
                    perform(state, "delete", rng, resumed_trace, phase="after-archive")
                    resumed["delete"] += 1
                for action in ("create", "update", "delete"):
                    perform(state, action, rng, resumed_trace, phase="after-archive")
                    resumed[action] += 1
            resolved_after = reconcile_trace(state, resumed_path, deadline=deadline)
            cumulative_events += sum(resumed.values())
            final = offline(state, f"cycle-{index}-resumed")
            equal("resumed.cumulative_operator_events", cumulative_events,
                  engine_observation(backend, budgets["trace_bytes"])["committed_events"])
            controller = process_sample(os.getpid())
            require(controller["available"], "Missing lifecycle controller closeout observation")
            require(max(controller["rss_kib"], controller["peak_rss_kib"]) <= budgets["controller_rss_kib"]
                    and controller["open_fds"] <= budgets["controller_fds"] and controller["threads"] <= budgets["controller_threads"],
                    "Lifecycle controller exceeded its resource budget")
            check_time()
            result = {"status": "passed", "cycle": index, "fill_application_pid": pid,
                "starting_executed_receipts": start_receipts, "new_executed_fill_requests": allocated,
                "full_capacity": 1024, "fill_coverage": dict(coverage), "fill_seconds": fill_seconds,
                "cycle_seconds": time.monotonic()-started, "cycle_budget_seconds": 300,
                "resources": resources, "resolved_fill": reconciled, "full_integrity": full,
                "full_original_id_replay": True, "new_request_rejected": "receipt_limit",
                "quiescent_rejection_all_thirteen_tables_unchanged": True,
                "archive_all_preserved_tables_equal": True, "original_replay_and_status_expired": True,
                "resumed_crud": dict(resumed), "resolved_resumed": resolved_after,
                "final_integrity": final, "reset_used": False, "unresolved": 0,
                "memory_scope": "Separate receipt lifecycle PID epoch; not the continuous 300-second memory window"}
            result["maintenance_controller"] = {"status": "passed", "observation": controller}
            results.append(result)
            write_json(directory / f"cycle-{index}.result.json", result)
        artifacts = check_artifacts(directory, budgets)
        if artifacts["status"] != "passed":
            raise Incomplete("Receipt artifacts exceeded the explicit byte budget")
        result = {"status": "passed", "backend": state["preflight"]["backend"], "cycles": results,
            "cycle_count": len(results), "cumulative_committed_operator_events": cumulative_events,
            "execution_module_sha256": execution_identity,
            "final_logical": logical(state), "artifacts": artifacts, "unresolved": 0,
            "scope": "Real full receipt allocation/archive and resumed CRUD; no reset or synthetic capacity fixture"}
        publish_result(directory / "cycles-result.json", result, directory, budgets)
        return result
    except BaseException as error:
        write_json(directory / "cycles-failure.json", {"status": "incomplete" if isinstance(error, Incomplete) else "failed",
            "type": type(error).__name__, "message": str(error), "completed_cycles": len(results),
            "current_receipts": state["receipts"], "reset_used": False})
        raise
    finally:
        if "controls" in locals():
            controls.close()
        backend.stop()
