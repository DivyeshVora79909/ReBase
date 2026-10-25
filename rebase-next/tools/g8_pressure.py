"""Finite HTTP overload, queue and authored fanout checks for G8.2.

All requests use the existing client and engine. The source-only workshop
oracles own expected values. A separate real-writer native control owns the
permit-retention proof; HTTP submission barriers do not force DB interleaving.
"""
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from copy import deepcopy
import hashlib
import http.client
import math
import os
from pathlib import Path
import socket
import threading
import time
from urllib.parse import urlsplit
import uuid

import client
from capacity import work_for
from g7_http import TABLES
from g8_observe import Incomplete, JsonlWriter, check_resources, process_sample, read_jsonl, sample
from g8_workload import check_sources, database_observer, logical, offline, physical_paths, publish_result, renew_auth, reservation
from harness import backup_image, latency, require, write_private
from verify_oracles import evaluate, stage
from verify_runtime import Scenario, digest, equal, write_json


def default_pressure_profile():
    return {"equipment_reservations": [4, 16, 64], "quantity_dependents": [1, 4, 15],
            "patterns": ["hot_root", "independent_business_roots"],
            "rate_steps": [{"offered_per_second": 2, "clients": 1},
                           {"offered_per_second": 16, "clients": 4},
                           {"offered_per_second": 128, "clients": 8}],
            "step_seconds": 2.0, "barrier_rounds": 2, "max_pending": 8, "max_inflight": 1,
            "client_timeout_seconds": 20.0, "drain_seconds": 20.0,
            "latency_budget_ms": 20000.0, "sample_seconds": .25,
            "slow_connections": 8, "slow_input_seconds": .5,
            "max_requests": 768, "max_new_operations": 512}


def pressure_profile(settings=None):
    expected = default_pressure_profile()
    settings = deepcopy(expected if settings is None else settings)
    if not isinstance(settings, dict) or settings.keys() != expected.keys():
        raise ValueError("pressure profile requires exactly the documented fields")
    if settings["equipment_reservations"] != [4, 16, 64] or settings["quantity_dependents"] != [1, 4, 15]:
        raise ValueError("pressure geometry must use the declared bounded model levels")
    if settings["patterns"] != expected["patterns"] or settings["rate_steps"] != expected["rate_steps"]:
        raise ValueError("pressure uses the fixed business-root and client/rate steps")
    for name in ("step_seconds", "client_timeout_seconds", "drain_seconds", "latency_budget_ms",
                 "sample_seconds", "slow_input_seconds"):
        value = settings[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"{name} must be finite and positive")
    if any(type(settings[name]) is not int for name in ("max_inflight", "max_pending", "slow_connections", "barrier_rounds")) or settings["max_inflight"] != 1 or settings["max_pending"] != 8 or settings["slow_connections"] != 8:
        raise ValueError("pressure uses one native permit and at most eight owned client operations/connections")
    if settings["client_timeout_seconds"] > 20 or settings["drain_seconds"] > 20 or settings["slow_input_seconds"] > 2:
        raise ValueError("pressure deadlines exceed the bounded default")
    if not 1 <= settings["step_seconds"] <= 2 or not .05 <= settings["sample_seconds"] <= 1 or settings["barrier_rounds"] != 2:
        raise ValueError("pressure duration, cadence and barrier count must fit the declared finite profile")
    offered = 2 * sum(math.ceil(step["offered_per_second"] * settings["step_seconds"]) for step in settings["rate_steps"])
    offered += settings["barrier_rounds"] * settings["max_pending"]
    if type(settings["max_requests"]) is not int or not offered <= settings["max_requests"] <= 768:
        raise ValueError("offered request count exceeds the bounded pressure profile")
    if type(settings["max_new_operations"]) is not int or not math.ceil(offered / 2)+8 <= settings["max_new_operations"] <= 512:
        raise ValueError("new intent count exceeds its receipt preflight ceiling")
    return settings


def bounded_step(requests, submit, *, duration, offered_rate, clients, max_pending,
                 drain_seconds=20.0, on_offer=None, on_submit=None, on_complete=None):
    """Pace a lazy producer; at most max_pending tasks ever enter the executor.

    Producer backpressure rejects an offer before allocating/saving an intent.
    Its count is separate from an HTTP admission rejection. All submitted
    futures drain; the thread pool never receives the whole run in advance.
    """
    if not 1 <= clients <= max_pending <= 8 or duration <= 0 or offered_rate <= 0 or not math.isfinite(drain_seconds) or drain_seconds <= 0:
        raise ValueError("bounded clients, pending work, positive rate and duration are required")
    started, pending, counts = time.monotonic(), {}, Counter()
    scheduled = math.ceil(duration * offered_rate)
    peak_pending, latencies, worker_peak, active = 0, [], 0, 0
    worker_lock = threading.Lock()

    def work(item):
        nonlocal active, worker_peak
        with worker_lock:
            active += 1
            worker_peak = max(worker_peak, active)
        try:
            return submit(item)
        finally:
            with worker_lock:
                active -= 1

    def completed(done):
        for future in done:
            item, admitted_at = pending.pop(future)
            outcome = future.result()
            outcome["queue_and_request_ms"] = (time.monotonic()-admitted_at)*1000
            counts["completed"] += 1
            counts["outcome:" + outcome["kind"]] += 1
            if outcome.get("http_status") is not None:
                counts["http:" + str(outcome["http_status"])] += 1
            latencies.append(outcome["queue_and_request_ms"])
            if on_complete:
                on_complete(item, outcome)

    with ThreadPoolExecutor(max_workers=clients) as executor:
        index = 0
        while time.monotonic() < started + duration and index < scheduled:
            done = {future for future in pending if future.done()}
            completed(done)
            now = time.monotonic()
            due = started + index / offered_rate
            if now < due:
                if pending:
                    done, _ = wait(pending, timeout=min(.05, due-now), return_when=FIRST_COMPLETED)
                    completed(done)
                else:
                    threading.Event().wait(min(.05, due-now))
                continue
            counts["offered"] += 1
            index += 1
            accepted = len(pending) < max_pending
            if on_offer:
                on_offer({"index": index-1, "producer_accepted": accepted, "pending": len(pending)})
            if not accepted:
                counts["producer_backpressure"] += 1
                continue
            item = next(requests)
            if on_submit:
                on_submit(item)
            pending[executor.submit(work, item)] = (item, time.monotonic())
            counts["submitted"] += 1
            peak_pending = max(peak_pending, len(pending))
        offering_elapsed = time.monotonic() - started
        drain_started = time.monotonic()
        while pending:
            remaining = drain_started + drain_seconds-time.monotonic()
            if remaining <= 0:
                cancelled = sum(future.cancel() for future in pending)
                error = RuntimeError(f"Pressure future drain exceeded its {drain_seconds:g}-second budget; retained original plans require reconciliation")
                error.drain_report = {"status": "failed", "budget_seconds": drain_seconds,
                    "elapsed_seconds": time.monotonic()-drain_started, "queued_cancelled_before_dispatch": cancelled,
                    "unresolved_client_futures_at_deadline": len(pending)-cancelled,
                    "native_quiescence": "not established by a client deadline",
                    "cleanup": "queued futures cancelled; running bounded client calls join before exit"}
                raise error
            done, _ = wait(pending, timeout=min(.1, remaining), return_when=FIRST_COMPLETED)
            completed(done)
        drain_elapsed = time.monotonic()-drain_started
        if drain_elapsed > drain_seconds:
            error = RuntimeError(f"Pressure future drain took {drain_elapsed:.6f}s and exceeded its {drain_seconds:g}-second budget")
            error.drain_report = {"status": "failed", "budget_seconds": drain_seconds,
                "elapsed_seconds": drain_elapsed, "queued_cancelled_before_dispatch": 0,
                "unresolved_client_futures_at_deadline": 0, "native_quiescence": "not established by client completion"}
            raise error
    counts["not_offered_before_duration"] = scheduled - counts["offered"]
    return {"requested_offers": scheduled, "counts": dict(counts), "peak_pending": peak_pending,
            "peak_active_clients": worker_peak, "clients": clients, "max_pending": max_pending,
            "offered_rate": offered_rate, "offering_seconds": duration,
            "offering_elapsed_seconds": offering_elapsed,
            "elapsed_with_drain_seconds": time.monotonic()-started,
            "drain_started_at": drain_started, "future_drain_seconds": drain_elapsed,
            "drain_budget_seconds": drain_seconds,
            "latency": latency(latencies) if latencies else {}, "unresolved": 0}


def barrier_round(requests, submit, *, drain_seconds=20.0, on_offer=None, on_submit=None, on_complete=None):
    """Exactly eight finite submissions, synchronized before ordinary HTTP calls."""
    if len(requests) != 8 or not math.isfinite(drain_seconds) or drain_seconds <= 0:
        raise ValueError("the pressure submission barrier has exactly eight clients")
    barrier, counts, times = threading.Barrier(8), Counter(), []
    started = time.monotonic()
    def work(request):
        barrier.wait(timeout=10)
        return submit(request)
    with ThreadPoolExecutor(max_workers=8) as executor:
        pending = {}
        for index, request in enumerate(requests):
            if on_offer:
                on_offer({"index": index, "producer_accepted": True, "pending": len(pending)})
            if on_submit:
                on_submit(request)
            pending[executor.submit(work, request)] = request
        drain_started = time.monotonic()
        while pending:
            remaining = drain_started + drain_seconds-time.monotonic()
            if remaining <= 0:
                cancelled = sum(future.cancel() for future in pending)
                error = RuntimeError(f"Pressure barrier drain exceeded its {drain_seconds:g}-second budget; retained original plans require reconciliation")
                error.drain_report = {"status": "failed", "budget_seconds": drain_seconds,
                    "elapsed_seconds": time.monotonic()-drain_started, "queued_cancelled_before_dispatch": cancelled,
                    "unresolved_client_futures_at_deadline": len(pending)-cancelled,
                    "native_quiescence": "not established by a client deadline",
                    "cleanup": "queued futures cancelled; running bounded client calls join before exit"}
                raise error
            done, _ = wait(pending, timeout=min(.1, remaining), return_when=FIRST_COMPLETED)
            for future in done:
                request, outcome = pending.pop(future), future.result()
                counts["outcome:"+outcome["kind"]] += 1
                if outcome.get("http_status") is not None:
                    counts["http:"+str(outcome["http_status"])] += 1
                times.append(outcome["latency_ms"])
                if on_complete:
                    on_complete(request, outcome)
        drain_elapsed = time.monotonic()-drain_started
        if drain_elapsed > drain_seconds:
            error = RuntimeError(f"Pressure barrier drain took {drain_elapsed:.6f}s and exceeded its {drain_seconds:g}-second budget")
            error.drain_report = {"status": "failed", "budget_seconds": drain_seconds,
                "elapsed_seconds": drain_elapsed, "queued_cancelled_before_dispatch": 0,
                "unresolved_client_futures_at_deadline": 0, "native_quiescence": "not established by client completion"}
            raise error
    counts.update(offered=8, submitted=8, completed=8)
    return {"counts": dict(counts), "peak_pending": 8, "peak_active_clients": 8, "clients": 8,
            "max_pending": 8, "latency": latency(times), "elapsed_with_drain_seconds": time.monotonic()-started,
            "offering_elapsed_seconds": drain_started-started,
            "drain_started_at": drain_started, "future_drain_seconds": drain_elapsed,
            "drain_budget_seconds": drain_seconds,
            "unresolved": 0, "scope": "HTTP submission barrier only; no forced native transaction interleaving"}


def request_once(backend, request, timeout):
    started = time.monotonic()
    try:
        response = client.call(backend.url, backend.token, request["method"], request["params"], timeout=timeout)
        kind = response.get("status", "read_success") if request["method"] == "records.mutate" else "read_success"
        outcome = {"kind": kind, "http_status": 200, "response": response}
    except client.ClientError as error:
        outcome = {"kind": error.kind, "http_status": error.http_status, "error_type": type(error).__name__}
    outcome["latency_ms"] = (time.monotonic()-started)*1000
    return outcome


def bound_intent(template, commands):
    """Bind a NEW intent to an explicitly supplied original-target template.

    Only the new UUID and commands vary. The template was prepared with the
    ordinary client before load; no saturated preparation read, context refresh
    or mutation retry occurs in the producer.
    """
    saved = deepcopy(template)
    saved["request"]["operation_id"] = str(uuid.uuid4())
    saved["request"]["commands"] = deepcopy(commands)
    client._plan(saved)
    return saved


def load_requests(state, pattern, templates, records, sums, root_counts):
    index, model, ids = 0, state["model"], state["ids"]
    while True:
        root_index = 0 if pattern == "hot_root" else (index // 2) % 2
        owner, delivery = ids[root_index], ids[root_index + 2]
        if index % 2:
            saved = bound_intent(templates[delivery], [{"op": "update", "id": delivery,
                "if_version": records[delivery]["version"], "set": {"quantity": str(sums[owner]+1)}, "unset": []}])
            yield {"method": "records.mutate", "params": saved["request"], "plan": saved}
        else:
            yield {"method": "roots.read", "params": {"model": model, "owner": owner, "slot": 7,
                "read": {"kind": "summary"}}, "allowed_sums": [str(sums[owner]), str(sums[owner]+1)],
                "expected_count": root_counts[owner]}
        index += 1


def commit_commands(state, commands, label, trace):
    backend = state["backend"]
    proposed = stage(state["facts"], commands)
    evaluate("equipment", proposed)
    saved = client.prepare(backend.url, backend.token, {"model": state["model"], "commands": commands, "returning": []})
    trace.write({"event": "intent", "phase": "prepare", "label": label, "plan": saved})
    response = client.execute(backend.url, backend.token, saved)
    equal("pressure.prepare.status", "committed", response["status"])
    trace.write({"event": "outcome", "phase": "prepare", "label": label, "plan": saved,
                 "kind": "committed", "http_status": 200, "response": response})
    with state["lock"]:
        state["facts"], state["receipts"] = proposed, state["receipts"]+1
        state["reserved"].update(command["id"] for command in commands
                                 if command["op"] == "create" and command["contract"] == 410)
    state["last"] = saved, response
    return saved, response


def equipment_geometry(state, levels, trace, max_log_bytes):
    """Progressively add known valid nonoverlapping trajectories, then cascade."""
    added, reports = 0, []
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, "rebase-g8-pressure-equipment/" + str(state["profile"]["seed"]))
    for number in levels:
        commands = [{"op": "create", "id": str(uuid.uuid5(namespace, str(i))), "contract": 410,
                     "fields": reservation(state["ids"][i % 2], 50+i*4, 52+i*4, 20)}
                    for i in range(added, number)]
        for offset in range(0, len(commands), 32):
            commit_commands(state, commands[offset:offset+32], f"geometry-{number}-{offset}", trace)
        added = number
        before = check_sources(state)
        delivery = state["ids"][2]
        fields = {"quantity": str(int(before[delivery]["input"]["quantity"])+1)}
        saved, _ = commit_commands(state, [{"op": "update", "id": delivery,
            "if_version": before[delivery]["version"], "set": fields, "unset": []}], f"cascade-{number}", trace)
        check_sources(state)
        if (state["backend"].directory / "server.log").stat().st_size > max_log_bytes:
            raise Incomplete("Pressure operator log exhausted its declared budget")
        work = work_for(state["backend"], saved["request"]["operation_id"])
        expectation = evaluate("equipment", state["facts"])
        roots = [{"owner": root["owner"], "n": root["summary"]["count"]} for root in expectation["roots"]]
        reports.append({"status": "passed", "added_reservations": number,
            "public_sources": len(state["facts"]), "relevant_roots": roots,
            "actual_memberships": {"delivery_record": 1, "reservation_source": 0,
                                   "private_occurrence": 1, "maintained_occurrences_per_active_reservation": 2},
            "r": work["causal_evaluations"], "work": work})
    return reports


def quiescent_read(backend, model, identity, budget, *, observations=None, stage_id=None):
    """A successful DB read with the sole permit proves prior native work drained."""
    started, polls = time.monotonic(), 0
    while time.monotonic()-started < budget:
        polls += 1
        try:
            remaining = budget-(time.monotonic()-started)
            if remaining <= 0:
                break
            params = {"model": model, "id": identity}
            response = client.call(backend.url, backend.token, "records.get", params, timeout=min(remaining, 20))
            if time.monotonic()-started > budget:
                break
            if observations is not None:
                observations.write({"event": "drain", "stage_id": stage_id,
                    "request": {"method": "records.get", "params": params}, "response": response})
            return {"status": "passed", "polls": polls, "elapsed_seconds": time.monotonic()-started,
                    "proof": "authenticated DB read admitted with max_inflight=1 after producer/future drain"}
        except client.ClientError as error:
            if error.kind != "busy":
                raise
            threading.Event().wait(.01)
    raise Incomplete("Native pressure work did not drain within its recorded budget")


def reconcile_pressure(state, path, budgets, max_pending=8, max_requests=768, *, observations=None):
    """Stream paired concurrent originals; no successful ID is resubmitted here."""
    pending, seen, resolved, absent = {}, set(), 0, 0
    replay_candidate = None
    for item in read_jsonl(path, budgets["trace_bytes"], max_requests*3):
        if item.get("event") in ("read", "stage", "stage_end", "offer", "drain"):
            continue
        plan = item.get("plan")
        if not isinstance(plan, dict):
            raise Incomplete("Pressure trace is missing an original plan")
        identity = plan["request"]["operation_id"]
        if item["event"] == "intent":
            if identity in seen or len(seen) >= max_requests or len(pending) >= max_pending:
                raise Incomplete("Duplicate or unbounded pressure intent inventory")
            seen.add(identity)
            pending[identity] = plan
            continue
        if item["event"] != "outcome" or pending.pop(identity, None) != plan:
            raise Incomplete("Pressure outcome lost or replaced the original intent")
        status = client.execute(state["backend"].url, state["backend"].token, plan, status=True)
        if observations is not None:
            observations.write({"event": "status", "plan": plan, "response": status})
        if item["kind"] == "committed":
            equal("pressure.original_receipt", item["response"]["result"], status["result"])
            replay_candidate = plan, item["response"]
        elif item["kind"] == "outcome_unknown":
            equal("pressure.unknown.resolved_status", item.get("resolved_status"), status["status"])
            if status["status"] == "committed":
                equal("pressure.unknown.original_result", item.get("resolved_result"), status["result"])
                replay_candidate = plan, {"result": status["result"]}
            else:
                equal("pressure.unknown.absence", "not_observed", status["status"])
                absent += 1
        else:
            equal("pressure.completed_absence", "not_observed", status["status"])
            absent += 1
        resolved += 1
    if pending or not resolved:
        raise Incomplete("Pressure trace retained unresolved original intents")
    if replay_candidate:
        saved, original = replay_candidate
        replay = client.execute(state["backend"].url, state["backend"].token, saved)
        require(replay["replayed"], "Pressure original replay applied again")
        equal("pressure.replay", original["result"], replay["result"])
        if observations is not None:
            observations.write({"event": "replay", "plan": saved, "response": replay})
    return {"status": "passed", "resolved": resolved, "absent_after_quiescence": absent,
            "unresolved": 0, "original_contexts_preserved": True, "replacement_mutation_submissions": 0,
            "same_id_replay": bool(replay_candidate)}


def resolve_unknowns(state, unknown, trace, pattern, *, deadline=None):
    """Only after sole-permit drain: observe each saved original, never resubmit."""
    committed = Counter()
    for request, outcome in unknown:
        try:
            remaining = 40 if deadline is None else deadline-time.monotonic()
            require(remaining > 0, "Pressure unknown reconciliation exceeded the shared drain budget")
            status = client.execute(state["backend"].url, state["backend"].token, request["plan"],
                                    status=True, timeout=min(20, remaining/2))
            outcome["resolved_status"] = status["status"]
            outcome["status_observation"] = status
            if status["status"] == "committed":
                proposed = stage(state["facts"], request["plan"]["request"]["commands"])
                evaluate("equipment", proposed)
                with state["lock"]:
                    state["facts"], state["receipts"] = proposed, state["receipts"]+1
                outcome["resolved_result"] = status["result"]
                committed[request["plan"]["request"]["commands"][0]["id"]] += 1
            else:
                equal("pressure.unknown.after_drain", "not_observed", status["status"])
        finally:
            # Even a failed status observation retains the original unknown
            # classification and plan; required incomplete evidence cannot pass.
            trace.write({"event": "outcome", "phase": "measurement", "pattern": pattern,
                         "plan": request["plan"], **outcome})
    return committed


def slow_input_pressure(backend, model, identity, settings):
    endpoint = urlsplit(backend.url)
    connections, before, during = [], process_sample(backend.process.pid), None
    try:
        for _ in range(settings["slow_connections"]):
            connection = socket.create_connection((endpoint.hostname, endpoint.port), timeout=2)
            connections.append(connection)
            # One incomplete body, never a completed mutation request.
            headers = (f"POST {endpoint.path} HTTP/1.1\r\nHost: {endpoint.hostname}\r\n"
                       f"Authorization: Bearer {backend.token}\r\nContent-Type: application/json\r\n"
                       "Content-Length: 256\r\nConnection: close\r\n\r\n{")
            connection.sendall(headers.encode())
        threading.Event().wait(settings["slow_input_seconds"])
        during = process_sample(backend.process.pid)
        backend.call("records.get", {"model": model, "id": identity})
    finally:
        for connection in connections:
            connection.close()
    recovered = quiescent_read(backend, model, identity, settings["drain_seconds"])
    return {"status": "passed", "opened": len(connections), "closed": len(connections),
        "owned_hold_seconds": settings["slow_input_seconds"], "before": before, "during": during,
        "recovery": recovered, "scope": "eight finite partial-input sockets, voluntarily closed by the controller",
        "server_side_rpc_body_deadline": {"status": "unsupported", "required": False,
                                         "reason": "no general RPC body-read deadline is claimed"}}


def limit_controls(state, directory):
    """Quiescent complete-image comparison around real command/body rejections."""
    backend = state["backend"]
    backend.stop()
    before = backup_image(backend, "pressure-limit-before")
    backend.start()
    session = backend.call("session.describe", {})
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, "g8-pressure-limit")
    request = {"model": state["model"], "context": session["operation_context"], "operation_id": str(uuid.uuid4()),
        "commands": [{"op": "create", "id": str(uuid.uuid5(namespace, str(i))), "contract": 101,
                      "fields": {"unit": 7}} for i in range(65)], "returning": []}
    write_private(directory / "commands-65.request.json", client._bytes(request))
    try:
        client.call(backend.url, backend.token, "records.mutate", request)
    except client.ClientError as error:
        equal("pressure.commands.limit", "invalid_input", error.kind)
        commands_status = error.http_status
    else:
        raise RuntimeError("65 commands did not reject at the existing limit")
    status = backend.call("operations.status", {key: request[key] for key in ("model", "context", "operation_id")})
    equal("pressure.commands.receipt", "not_observed", status["status"])
    endpoint = urlsplit(backend.url)
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=5)
    try:
        connection.request("POST", endpoint.path, b"x"*(client.MAX_REQUEST_BYTES+1), headers={
            "Authorization": "Bearer " + backend.token, "Content-Type": "application/json"})
        response = connection.getresponse()
        body_status = response.status
        response.read(client.MAX_RESPONSE_BYTES+1)
    finally:
        connection.close()
    equal("pressure.body.limit", 413, body_status)
    backend.stop()
    after = backup_image(backend, "pressure-limit-after")
    equal("pressure.limits.complete_tables", hashlib.sha256(client._bytes(before)).hexdigest(),
          hashlib.sha256(client._bytes(after)).hexdigest())
    backend.start()
    return {"status": "passed", "commands": 65, "command_rpc_kind": "invalid_input", "command_http_status": commands_status,
            "body_bytes": client.MAX_REQUEST_BYTES+1, "body_http_status": body_status,
            "rejected_receipt": "not_observed", "all_tables_unchanged": True, "table_count": len(TABLES)}


def quantity_geometry(state, directory, levels):
    """Existing Quantity scenario, real 16-source ceiling and source arithmetic."""
    case = Scenario(state["backend"].binary, directory / "quantity", "quantity", "g8-pressure-quantity")
    reports, added = [], 0
    try:
        source = case.identity("source")
        case.mutate("source", "Prepare literal Source=24.", [case.create("source", 101, {"value": "24"})],
                    "Source publishes its authored exact quantity.", literals={source: {"quantity": "24"}})
        for level in levels:
            commands = []
            scale_count = level if level == 1 else level-1
            while added < scale_count:
                commands.append(case.create("scale-" + str(added), 205, {"parent": source,
                    "factor": {"numerator": "1", "denominator": "2"}, "rounding": "exact"}))
                added += 1
            if level == 4:
                commands.append(case.create("join", 309, {"left": case.identity("scale-0"), "right": case.identity("scale-1")}))
            case.mutate("prepare-" + str(level), f"Prepare {level} dependent publications.", commands,
                        "Known Source/Scale/Join graph, source-only Fraction expectations.")
            next_value = str(int(case.facts[source]["fields"]["value"])*2)
            item = case.mutate("cascade-" + str(level), f"Change Source to {next_value}.",
                [case.update(source, {"value": next_value})], "All declared dependent publications evaluate from ready parents.")
            reports.append({"status": "passed", "requested_dependents": level, "public_sources": len(case.facts),
                "n": 0, "m": 0, "r": item["work"]["causal_evaluations"], "work": item["work"],
                "scope": "Quantity declares no maintained native tree memberships; r is the actual evaluated closure"})
        rejected = case.mutate("seventeenth-source", "Attempt the 17th publication.",
            [case.create("overflow-source", 101, {"value": "1"})], "Existing 16-source compiled envelope.", reject="state_limit")
        result = {"status": "passed", "levels": reports, "model": case.model,
            "capacity_rejection": {"kind": "state_limit", "public_sources": 17,
                "all_tables_unchanged": rejected["complete_rollback"], "receipt": rejected["receipt"]}}
        write_json(directory / "quantity-result.json", result)
        return result
    finally:
        case.close()


def check_overload(result):
    """Independent finite-load acceptance, not a throughput/capacity extrapolation."""
    if result.get("status") == "failed" or result["resources"]["status"] == "failed":
        raise RuntimeError("Required pressure resource budgets failed")
    if result.get("status") != "passed" or result["resources"]["status"] != "passed":
        raise Incomplete("Required pressure observations did not pass")
    if result["receipts"]["unresolved"] or not result["receipts"]["same_id_replay"]:
        raise Incomplete("Pressure outcomes/replay are unresolved")
    steps, busy, reads, commits = result["steps"], 0, 0, 0
    expected = {(pattern, step["offered_per_second"], step["clients"])
                for pattern in result["profile"]["patterns"] for step in result["profile"]["rate_steps"]}
    observed = {(row["pattern"], row["offered_rate"], row["clients"]) for row in steps}
    if expected != observed:
        raise Incomplete("Pressure client/rate/root coverage is incomplete")
    if len(result.get("bursts", [])) != result["profile"]["barrier_rounds"]:
        raise Incomplete("Pressure HTTP barrier coverage is incomplete")
    for row in steps + result["bursts"]:
        counts = row["counts"]
        require(row["peak_pending"] <= result["profile"]["max_pending"], "Executor pending budget exceeded")
        require(row["peak_active_clients"] <= row["clients"], "Producer thread budget exceeded")
        require(counts.get("offered", 0) == counts.get("submitted", 0)+counts.get("producer_backpressure", 0), "Offered pressure work is unaccounted")
        require(counts.get("submitted", 0) == counts.get("completed", 0) and row["unresolved"] == 0, "Submitted pressure work did not drain")
        require(sum(value for name, value in counts.items() if name.startswith("outcome:")) == counts.get("completed", 0),
                "Completed pressure outcomes are unaccounted")
        require(sum(value for name, value in counts.items() if name.startswith("http:")) == counts.get("completed", 0),
                "Completed pressure HTTP observations are unaccounted")
        require(row["latency"].get("max_ms", float("inf")) <= result["profile"]["latency_budget_ms"], "Pressure latency budget exceeded")
        require(row.get("total_drain_seconds", float("inf")) <= result["profile"]["drain_seconds"], "Pressure total drain budget exceeded")
        busy += counts.get("outcome:busy", 0)
        reads += counts.get("outcome:read_success", 0)
        commits += counts.get("outcome:committed", 0) + row.get("resolved_unknown_commits", 0)
    if busy < 1 or reads < 8 or commits < 6:
        raise Incomplete("Finite pressure load did not achieve visible overload/read/write coverage")
    require(result["limits"]["all_tables_unchanged"] and result["complete_state"]["table_count"] == 13,
            "Pressure rejection/integrity tables are incomplete")
    return {"status": "passed", "busy_rejections": busy, "successful_reads": reads, "commits": commits,
            "scope": "declared finite loads; deterministic native permit/timeout proof is separate reused evidence"}


def select_database_observer(state, database_pid=None, database_paths=()):
    """Use the selected cluster and actual directories, including outside Git."""
    if state["preflight"]["backend"] != "foundationdb":
        require(database_pid is None and not database_paths, "Embedded pressure has no separate database process")
        return None
    prefix = state["preflight"]["prefix"]
    if prefix.count("--cluster-file") != 1:
        raise ValueError("FoundationDB pressure requires the selected explicit cluster")
    cluster = Path(prefix[prefix.index("--cluster-file")+1])
    if database_pid is None:
        if database_paths:
            raise ValueError("Explicit database paths require an explicit owned PID")
        import fdb_cluster
        require(cluster.resolve() == fdb_cluster.CLUSTER.resolve(), "Helper observation must match the selected cluster")
        database_pid, database_paths = fdb_cluster.server_pid(), (fdb_cluster.DATA, fdb_cluster.LOG)
    if len(database_paths) != 2:
        raise ValueError("Pressure observation requires exactly the actual data and log paths")
    return database_observer(database_pid, cluster, *database_paths)


def run_overload(state, *, settings=None, database_pid=None, database_paths=()):
    execution_module_sha256 = digest(Path(__file__))
    settings = pressure_profile(settings)
    backend, budgets = state["backend"], state["profile"]["budgets"]
    selected_observer = select_database_observer(state, database_pid, database_paths)
    if selected_observer:
        database_pid = selected_observer["pid"]
        database_paths = (selected_observer["data"], selected_observer["logs"])
    require(len(state["facts"]) == 6 and state["active"] is None, "Pressure requires the compatible six-record prepared fixture")
    require(state["receipts"] + settings["max_new_operations"] + 16 < 1024, "Pressure intents lack receipt-room preflight")
    directory = state["directory"] / "pressure"
    directory.mkdir(mode=0o700)
    write_json(directory / "profile.json", {**settings, "budgets": budgets, "backend": state["preflight"]["backend"],
                                            "database_observer": selected_observer,
                                            "execution_module_sha256": execution_module_sha256})
    original_config, threads, stop, problems = deepcopy(backend.config), [], threading.Event(), []
    trace, samples = None, None
    runtime_started = time.monotonic()
    validation_seconds = 0.0
    try:
        backend.stop()
        backend.config.update(max_inflight=1, request_timeout_seconds=15)
        backend.config_path.write_bytes(client._bytes(backend.config))
        backend.start()
        trace = JsonlWriter(directory / "trace.jsonl", budgets["trace_bytes"])
        geometry = equipment_geometry(state, settings["equipment_reservations"], trace, budgets["trace_bytes"])
        prepare_seconds = time.monotonic()-runtime_started
        pid, phase = backend.process.pid, {"name": "measurement"}
        samples = JsonlWriter(directory / "samples.jsonl", budgets["samples_bytes"])

        def observe():
            next_at = time.monotonic()
            while not stop.is_set():
                try:
                    samples.write(sample(pid, os.getpid(), database_pid, physical_paths(state, database_paths),
                                         phase["name"], logical(state)))
                except BaseException as error:
                    problems.append(error)
                    stop.set()
                    return
                next_at += settings["sample_seconds"]
                stop.wait(max(0, next_at-time.monotonic()))

        observer = threading.Thread(target=observe, daemon=False)
        observer.start()
        threads.append(observer)
        steps, bursts = [], []
        for pattern in settings["patterns"]:
            for requested in settings["rate_steps"]:
                stage_id = f"{pattern}:{requested['offered_per_second']}"
                trace.write({"event": "stage", "stage_id": stage_id, "pattern": pattern,
                    "offered_rate": requested["offered_per_second"], "clients": requested["clients"],
                    "duration_seconds": settings["step_seconds"], "mode": "paced"})
                phase["name"] = "validation"
                validation_started = time.monotonic()
                renew_auth(state)
                records = check_sources(state)
                expectation = evaluate("equipment", state["facts"])
                sums = {root["owner"]: int(root["summary"]["sum"]) for root in expectation["roots"]}
                root_counts = {root["owner"]: root["summary"]["count"] for root in expectation["roots"]}
                templates = {identity: client.prepare(backend.url, backend.token, {"model": state["model"],
                    "commands": [{"op": "update", "id": identity, "if_version": records[identity]["version"],
                                  "set": {"quantity": str(int(records[identity]["input"]["quantity"])+1)}, "unset": []}],
                    "returning": []}) for identity in state["ids"][2:4]}
                unknown, committed_roots = [], Counter()
                validation_seconds += time.monotonic()-validation_started

                def submitted(request):
                    if "plan" in request:
                        trace.write({"event": "intent", "phase": "measurement", "pattern": pattern,
                                     "stage_id": stage_id, "plan": request["plan"]})

                def offered(observation):
                    trace.write({"event": "offer", "stage_id": stage_id, **observation})

                def completed(request, outcome):
                    if "plan" in request:
                        if outcome["kind"] == "outcome_unknown":
                            if len(unknown) >= settings["max_pending"]:
                                raise Incomplete("Unknown pressure outcome inventory exceeded the pending bound")
                            unknown.append((request, outcome))
                        else:
                            trace.write({"event": "outcome", "phase": "measurement", "pattern": pattern,
                                         "stage_id": stage_id, "plan": request["plan"], **outcome})
                        if outcome["kind"] == "committed":
                            require(not outcome["response"]["replayed"], "A newly allocated pressure intent replayed")
                            proposed = stage(state["facts"], request["plan"]["request"]["commands"])
                            evaluate("equipment", proposed)
                            with state["lock"]:
                                state["facts"], state["receipts"] = proposed, state["receipts"]+1
                            committed_roots[request["plan"]["request"]["commands"][0]["id"]] += 1
                        elif outcome["kind"] not in {"busy", "stale_version", "transaction_conflict", "outcome_unknown"}:
                            raise RuntimeError("Unexpected pressure mutation outcome: " + outcome["kind"])
                    else:
                        trace.write({"event": "read", "phase": "measurement", "pattern": pattern,
                            "stage_id": stage_id, "request": {key: request[key] for key in ("method", "params")}, **outcome})
                        if outcome["kind"] == "read_success":
                            value = outcome["response"]["value"]
                            require(value["sum"] in request["allowed_sums"], "Concurrent pressure read is outside source-declared values")
                            equal("pressure.read.members", request["expected_count"], value["count"])
                        elif outcome["kind"] != "busy":
                            raise RuntimeError("Unexpected pressure read outcome: " + outcome["kind"])
                    if outcome["http_status"] is None:
                        raise Incomplete("Pressure response lacks a required HTTP status")

                phase["name"] = "measurement"
                measured = bounded_step(load_requests(state, pattern, templates, records, sums, root_counts),
                    lambda request: request_once(backend, request, settings["client_timeout_seconds"]),
                    duration=settings["step_seconds"], offered_rate=requested["offered_per_second"],
                    clients=requested["clients"], max_pending=settings["max_pending"],
                    drain_seconds=settings["drain_seconds"],
                    on_offer=offered, on_submit=submitted, on_complete=completed)
                measured["stage_id"] = stage_id
                measured["pattern"] = pattern
                measured["offered_per_second"] = measured["counts"]["offered"] / measured["offering_elapsed_seconds"]
                measured["submitted_per_second"] = measured["counts"]["submitted"] / measured["offering_elapsed_seconds"]
                measured["completed_per_second"] = measured["counts"]["completed"] / measured["offering_elapsed_seconds"]
                measured["admitted_completed_http_work"] = measured["counts"]["submitted"] - measured["counts"].get("outcome:busy", 0)
                measured["admitted_native_concurrency_bound"] = 1
                deadline = measured["drain_started_at"] + settings["drain_seconds"]
                remaining = deadline-time.monotonic()
                require(remaining > 0, "Pressure native read exceeded the shared drain budget")
                measured["drain"] = quiescent_read(backend, state["model"], state["ids"][2], remaining,
                                                  observations=trace, stage_id=stage_id)
                resolved = resolve_unknowns(state, unknown, trace, pattern, deadline=deadline)
                measured["total_drain_seconds"] = time.monotonic()-measured["drain_started_at"]
                require(measured["total_drain_seconds"] <= settings["drain_seconds"], "Pressure total drain budget exceeded")
                measured["resolved_unknown_commits"] = sum(resolved.values())
                committed_roots.update(resolved)
                require(all(count <= 1 for count in committed_roots.values()), "Pressure shared-CAS group committed twice for one source")
                trace.write({"event": "stage_end", "stage_id": stage_id,
                    "offering_elapsed_seconds": measured["offering_elapsed_seconds"],
                    "future_drain_seconds": measured["future_drain_seconds"],
                    "total_drain_seconds": measured["total_drain_seconds"]})
                steps.append(measured)
                phase["name"] = "validation"
                validation_started = time.monotonic()
                check_sources(state)
                validation_seconds += time.monotonic()-validation_started
                if problems:
                    raise problems[0]
        for number in range(settings["barrier_rounds"]):
            phase["name"] = "validation"
            validation_started = time.monotonic()
            pattern = "hot_root_submission_barrier"
            stage_id = f"burst:{number}"
            trace.write({"event": "stage", "stage_id": stage_id, "pattern": pattern,
                "offered_rate": None, "clients": 8, "duration_seconds": None, "mode": "barrier"})
            records = check_sources(state)
            delivery = state["ids"][2]
            commands = [{"op": "update", "id": delivery, "if_version": records[delivery]["version"],
                         "set": {"quantity": str(int(records[delivery]["input"]["quantity"])+1)}, "unset": []}]
            template = client.prepare(backend.url, backend.token, {"model": state["model"], "commands": commands, "returning": []})
            requests = [{"method": "records.mutate", "params": saved["request"], "plan": saved}
                        for saved in (bound_intent(template, commands) for _ in range(8))]
            unknown, committed_roots = [], Counter()
            validation_seconds += time.monotonic()-validation_started
            phase["name"] = "measurement"
            observed = barrier_round(requests, lambda request: request_once(backend, request, settings["client_timeout_seconds"]),
                                     drain_seconds=settings["drain_seconds"],
                                     on_offer=offered, on_submit=submitted, on_complete=completed)
            observed["stage_id"] = stage_id
            observed["name"] = "same_record_changed_cascade_" + str(number)
            deadline = observed["drain_started_at"] + settings["drain_seconds"]
            remaining = deadline-time.monotonic()
            require(remaining > 0, "Pressure barrier native read exceeded the shared drain budget")
            observed["drain"] = quiescent_read(backend, state["model"], delivery, remaining,
                                              observations=trace, stage_id=stage_id)
            resolved = resolve_unknowns(state, unknown, trace, pattern, deadline=deadline)
            observed["total_drain_seconds"] = time.monotonic()-observed["drain_started_at"]
            require(observed["total_drain_seconds"] <= settings["drain_seconds"], "Pressure barrier total drain budget exceeded")
            observed["resolved_unknown_commits"] = sum(resolved.values())
            equal("pressure.barrier.one_cas_winner", 1, observed["counts"].get("outcome:committed", 0)+sum(resolved.values()))
            trace.write({"event": "stage_end", "stage_id": stage_id, "mode": "barrier",
                "offering_elapsed_seconds": observed["offering_elapsed_seconds"],
                "future_drain_seconds": observed["future_drain_seconds"],
                "total_drain_seconds": observed["total_drain_seconds"]})
            phase["name"] = "validation"
            validation_started = time.monotonic()
            check_sources(state)
            validation_seconds += time.monotonic()-validation_started
            bursts.append(observed)
        phase["name"] = "slow_input"
        ingress = slow_input_pressure(backend, state["model"], state["ids"][2], settings)
        stop.set()
        for thread in threads:
            thread.join(timeout=5)
            require(not thread.is_alive(), "Pressure observer failed to stop")
        trace.close()
        samples.close()
        maintenance_started = time.monotonic()
        with JsonlWriter(directory / "receipt-observations.jsonl", budgets["trace_bytes"]) as receipt_observations:
            receipts = reconcile_pressure(state, directory / "trace.jsonl", budgets,
                settings["max_pending"], settings["max_requests"], observations=receipt_observations)
        check_sources(state)
        limits = limit_controls(state, directory)
        complete = offline(state, "pressure-complete")
        resources = check_resources(read_jsonl(directory / "samples.jsonl", budgets["samples_bytes"], 10000),
                                    budgets, require_database=database_pid is not None)
        quantity = quantity_geometry(state, directory, settings["quantity_dependents"])
        result = {"status": "passed" if resources["status"] == "passed" else resources["status"],
            "profile": settings, "backend": state["preflight"]["backend"], "model": state["model"],
            "preflight": state["preflight"], "steps": steps, "bursts": bursts, "geometry": geometry,
            "quantity": quantity, "receipts": receipts, "limits": limits, "slow_input": ingress,
            "resources": resources, "complete_state": complete, "application_pid": pid,
            "database_observer": selected_observer,
            "execution_module_sha256": execution_module_sha256,
            "time": {"prepare_seconds": prepare_seconds, "separate_source_validation_seconds": validation_seconds,
                     "offering_seconds": settings["step_seconds"] * len(steps),
                     "maintenance_seconds": time.monotonic()-maintenance_started,
                     "elapsed_seconds": time.monotonic()-runtime_started},
            "native_permit_retention": {"status": "unsupported", "required_for_checkpoint": True,
                "reason": "checkpoint coordinator supplies the matching existing real-writer native deadline control"},
            "scope": "Fixed finite HTTP pressure and authored geometries; independent business roots still share reader/query/capacity coordination"}
        result["checks"] = check_overload(result)
        summary = [f"G8.2 {result['status']}: {result['backend']}", "",
            f"Application PID {pid}; one native permit, at most eight pending submissions/clients.",
            f"Visible HTTP overload rejections: {result['checks']['busy_rejections']}.",
            f"Original outcomes resolved: {receipts['resolved']}; unresolved: 0.",
            "Equipment geometry uses actual root memberships; Quantity has no tree memberships.",
            "Complete thirteen-table integrity and rejected image equality pass after drain.",
            "Native permit/deadline correctness is separate reused evidence; no capacity extrapolation."]
        write_private(directory / "summary.md", ("\n".join(summary)+"\n").encode())
        backend.config = original_config
        backend.config_path.write_bytes(client._bytes(original_config))
        publish_result(directory / "pressure-result.json", result, state["directory"], budgets)
        return result
    except BaseException as error:
        write_json(directory / "failure.json", {"status": "incomplete" if isinstance(error, Incomplete) else "failed",
                                                "type": type(error).__name__, "message": str(error),
                                                "drain": getattr(error, "drain_report", None)})
        raise
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=5)
        if trace is not None:
            trace.close()
        if samples is not None:
            samples.close()
        try:
            backend.stop()
        finally:
            backend.config = original_config
            backend.config_path.write_bytes(client._bytes(original_config))
