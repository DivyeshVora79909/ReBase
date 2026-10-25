"""Owned FoundationDB service interruption with original-intent reconciliation.

This exercises a local database-service outage. It does not intercept a native
commit acknowledgement, fail over replicas, or simulate power loss.
"""

from contextlib import contextmanager, redirect_stdout
import hashlib
import io
import os
from pathlib import Path
import threading
import time

import client
import fdb_cluster
from g8_observe import Incomplete, JsonlWriter, check_artifacts, check_resources, process_sample, read_jsonl, sample
from g8_workload import check_sources, logical, offline, physical_paths, publish_result, renew_auth
from harness import require, write_private
from verify_oracles import evaluate, stage
from verify_runtime import digest, equal, write_json


RECOVERY_SECONDS = 30.0
NATIVE_TIMEOUT_SECONDS = 4.5
DOWN_BEFORE_READ_SECONDS = 5.5


def verify_service(pid, cluster_file, *, proc_root=Path("/proc")):
    """Verify exact owned executable, PID file, cluster, data, logs and endpoint."""
    if type(pid) is not int or pid <= 0:
        raise ValueError("the owned FoundationDB service PID is required")
    if Path(cluster_file).resolve() != fdb_cluster.CLUSTER.resolve():
        raise ValueError("outage requires the exact disposable helper cluster")
    try:
        if fdb_cluster.PIDFILE.read_text().strip() != str(pid):
            raise ValueError("FoundationDB PID file does not match the selected service")
        executable = (proc_root / str(pid) / "exe").resolve(strict=True)
        if executable != fdb_cluster.FDBSERVER.resolve():
            raise ValueError("refusing to signal a different executable")
        arguments = (proc_root / str(pid) / "cmdline").read_bytes().split(b"\0")
        arguments = [argument.decode() for argument in arguments if argument]
    except (OSError, UnicodeError) as error:
        raise ValueError("owned FoundationDB service identity is unavailable") from error
    expected = {"-C": str(fdb_cluster.CLUSTER.resolve()), "-d": str(fdb_cluster.DATA.resolve()),
                "-L": str(fdb_cluster.LOG.resolve()), "-p": f"{fdb_cluster.HOST}:{fdb_cluster.PORT}"}
    for flag, value in expected.items():
        if arguments.count(flag) != 1:
            raise ValueError("FoundationDB ownership argument is missing or duplicated")
        index = arguments.index(flag)
        if index + 1 >= len(arguments) or arguments[index + 1] != value:
            raise ValueError("refusing to signal a different cluster, data, log or endpoint")
    return {"pid": pid, "executable": str(executable), "cluster_file": expected["-C"],
            "data_path": expected["-d"], "log_path": expected["-L"], "endpoint": expected["-p"]}


@contextmanager
def owned_outage(cluster_file):
    """Restore the verified helper service on success and every exception path."""
    pid = fdb_cluster.server_pid()
    owner = verify_service(pid, cluster_file)
    require(fdb_cluster.server_pid() == pid, "Owned service changed before interruption")
    observation = {"ownership": owner, "stop_requested_at": time.monotonic(), "before_pid": pid}
    try:
        with redirect_stdout(io.StringIO()):
            fdb_cluster.stop()
        require(fdb_cluster.server_pid() is None, "Owned service remained alive after stop")
        observation["stopped_at"] = time.monotonic()
        yield observation
    finally:
        observation["restart_requested_at"] = time.monotonic()
        with redirect_stdout(io.StringIO()):
            fdb_cluster.start()
        restored = fdb_cluster.server_pid()
        observation["restored_ownership"] = verify_service(restored, cluster_file)
        observation["restart_returned_at"] = time.monotonic()
        observation["after_pid"] = restored


def observed_call(backend, method, params, *, phase, operation_id=None, timeout=3):
    """One ordinary client call. There are no mutation retries in this function."""
    started = time.monotonic()
    item = {"phase": phase, "method": method, "operation_id": operation_id,
            "started_at": started, "mutation_submissions": int(method == "records.mutate")}
    try:
        response = client.call(backend.url, backend.token, method, params, timeout=timeout)
        item.update(kind=response.get("status", "read_success"), http_status=200, response=response)
    except client.ClientError as error:
        item.update(kind=error.kind, http_status=getattr(error, "http_status", None),
                    error_type=type(error).__name__)
    item["finished_at"] = time.monotonic()
    item["latency_ms"] = (item["finished_at"] - started) * 1000
    return item


def public_call(item):
    result = {key: value for key, value in item.items() if key != "response"}
    if "response" in item:
        result["response_sha256"] = hashlib.sha256(client._bytes(item["response"])).hexdigest()
    return result


def database_resources(samples, budgets, before_pid, after_pid):
    """Check observed live DB lifetimes; intentional downtime is nonapplicable."""
    peaks = {"rss_kib": 0, "peak_rss_kib": 0, "open_fds": 0, "threads": 0}
    lifetimes, stopped, transient = {}, 0, 0
    for row in samples:
        if row.get("database_state") == "intentionally_stopped":
            stopped += 1
            continue
        observed = row["processes"].get("database", {})
        if observed.get("available") is not True:
            transient += 1
            continue
        pid = observed["pid"]
        lifetimes[pid] = lifetimes.get(pid, 0) + 1
        for name in peaks:
            peaks[name] = max(peaks[name], observed[name])
    limits = {"rss_kib": budgets["database_rss_kib"], "open_fds": budgets["database_fds"],
              "threads": budgets["database_threads"]}
    exceeded = max(peaks["rss_kib"], peaks["peak_rss_kib"]) > limits["rss_kib"] or any(
        peaks[name] > limits[name] for name in ("open_fds", "threads"))
    status = "failed" if exceeded else "passed" if before_pid in lifetimes and after_pid in lifetimes else "incomplete"
    return {"status": status, "peaks": peaks, "budgets": limits, "observed_pid_samples": lifetimes,
            "intentional_downtime_samples": stopped, "transient_service_exit_samples": transient,
            "downtime_status": "unsupported", "scope": "absolute live-service budgets in two PID epochs; no continuous database memory trend"}


def _run_outage(state):
    """Interrupt one owned FDB service; keep the application PID alive to recover.

    Embedded adapters return a nonapplicable network-fault result. Complete
    operator observations occur before/after the fault window. The application
    is stopped at return, matching the existing offline workload helpers.
    """
    if state["preflight"]["backend"] != "foundationdb":
        return {"status": "unsupported", "applicable": False,
                "boundary": "database-service network outage",
                "reason": "embedded adapters have no separately owned network service",
                "reused_evidence": "research/evidence/2026-10-25-g76-storage-conformance.json",
                "embedded_process_restore": "accepted G7 evidence; not a network outage pass"}
    prefix = state["preflight"]["prefix"]
    if prefix.count("--cluster-file") != 1:
        raise ValueError("outage requires an explicit single cluster selection")
    cluster_file = Path(prefix[prefix.index("--cluster-file") + 1])
    verify_service(fdb_cluster.server_pid(), cluster_file)
    backend, directory, budgets = state["backend"], state["directory"], state["profile"]["budgets"]
    execution_identity = digest(Path(__file__))
    write_json(directory / "outage-profile.json", {"execution_module_sha256": execution_identity,
        "budgets": budgets, "recovery_seconds": RECOVERY_SECONDS, "native_timeout_seconds": NATIVE_TIMEOUT_SECONDS,
        "http_deadline_seconds": 1, "max_inflight": 1, "maximum_pending_clients": 1})
    renew_auth(state)
    before = offline(state, "outage-before")
    original_config = dict(backend.config)
    backend.config.update(max_inflight=1, request_timeout_seconds=1)
    backend.config_path.write_bytes(client._bytes(backend.config))
    backend.start()
    application_pid = backend.process.pid
    require(backend.process.poll() is None, "Owned application is not alive")
    intent_before = []
    for index, increment in ((2, 2), (3, 1)):
        identity = state["ids"][index]
        row = backend.call("records.get", {"model": state["model"], "id": identity})
        command = {"op": "update", "id": identity, "if_version": row["version"],
                   "set": {"quantity": str(int(state["facts"][identity]["fields"]["quantity"]) + increment)}, "unset": []}
        evaluate("equipment", stage(state["facts"], [command]))
        saved = client.prepare(backend.url, backend.token,
                               {"model": state["model"], "commands": [command], "returning": []})
        client.save_plan(directory / f"outage-{index}.plan.json", saved)
        intent_before.append((saved, hashlib.sha256(client._bytes(saved)).hexdigest()))
    stop, observer_errors = threading.Event(), []
    samples_path, trace_path = directory / "fault-samples.jsonl", directory / "fault-trace.jsonl"
    phase = {"name": "before"}
    outcomes, requests, recovered, service = [], [], None, None

    def observe(writer):
        next_at = time.monotonic()
        while not stop.is_set():
            try:
                observation_started = time.monotonic()
                row = sample(application_pid, os.getpid(), None,
                             physical_paths(state, (fdb_cluster.DATA, fdb_cluster.LOG)), "measurement", logical(state))
                row["fault_phase"] = phase["name"]
                database_pid = fdb_cluster.server_pid()
                row["database_state"] = "running" if database_pid else "intentionally_stopped"
                if database_pid:
                    row["processes"]["database"] = process_sample(database_pid)
                row["observer_ms"] = (time.monotonic() - observation_started) * 1000
                writer.write(row)
            except BaseException as error:
                observer_errors.append(error)
                stop.set()
                return
            next_at += 0.5
            stop.wait(max(0, next_at - time.monotonic()))

    try:
        with JsonlWriter(samples_path, budgets["samples_bytes"]) as samples, JsonlWriter(trace_path, budgets["trace_bytes"]) as trace:
            observer = threading.Thread(target=observe, args=(samples,), daemon=False)
            observer.start()
            try:
                initial_read = observed_call(backend, "records.get", {"model": state["model"], "id": state["ids"][2]}, phase="before")
                require(initial_read["kind"] == "read_success", "Pre-outage authenticated DB read failed")
                requests.append(public_call(initial_read))
                trace.write(initial_read)
                with owned_outage(cluster_file) as service:
                    phase["name"] = "database_down"
                    for saved, _ in intent_before:
                        item = observed_call(backend, "records.mutate", saved["request"], phase="database_down",
                                             operation_id=saved["request"]["operation_id"])
                        require(item["kind"] != "committed",
                                "Mutation unexpectedly succeeded while the database service was stopped")
                        outcomes.append(item)
                        requests.append(public_call(item))
                        trace.write({**item, "plan": saved})
                    # This establishes a finite outage interval, not correctness
                    # inferred from a sleep. A subsequent sole-permit DB read
                    # establishes actual drain after the service is restored.
                    stop.wait(max(0, service["stopped_at"] + DOWN_BEFORE_READ_SECONDS - time.monotonic()))
                    during_read = observed_call(backend, "records.get", {"model": state["model"], "id": state["ids"][2]}, phase="database_down_after_native_deadline")
                    require(during_read["kind"] != "read_success",
                            "Authenticated DB read unexpectedly succeeded while the database service was stopped")
                    requests.append(public_call(during_read))
                    trace.write(during_read)
                phase["name"] = "recovering"
                deadline = service["stop_requested_at"] + RECOVERY_SECONDS
                while time.monotonic() < deadline:
                    require(backend.process.pid == application_pid and backend.process.poll() is None,
                            "Application PID changed during database recovery")
                    item = observed_call(backend, "records.get", {"model": state["model"], "id": state["ids"][2]}, phase="recovering")
                    requests.append(public_call(item))
                    trace.write(item)
                    if item["kind"] == "read_success":
                        recovered = item["finished_at"]
                        break
                    if item["kind"] not in ("busy", "outcome_unknown", "transaction_limit", "transaction_aborted"):
                        raise RuntimeError("Unexpected authenticated recovery classification: " + item["kind"])
                    stop.wait(0.1)
                if recovered is None:
                    raise Incomplete("Same-PID authenticated database recovery exceeded 30 seconds")
                phase["name"] = "recovered"
                reconciled = []
                for (saved, original_digest), item in zip(intent_before, outcomes):
                    equal("fault.original_plan", original_digest, hashlib.sha256(client._bytes(saved)).hexdigest())
                    result = client.call(backend.url, backend.token, "operations.status",
                                         {key: saved["request"][key] for key in ("model", "context", "operation_id")}, timeout=3)
                    kind = result["status"]
                    require(kind in ("committed", "not_observed"), "Original-ID outcome remained unresolved after sole-permit drain")
                    if kind == "committed":
                        require(item["kind"] not in ("busy", "transaction_conflict", "transaction_aborted", "transaction_limit"),
                                "A confirmed rejection unexpectedly retained a receipt")
                        facts = stage(state["facts"], saved["request"]["commands"])
                        evaluate("equipment", facts)
                        with state["lock"]:
                            state["facts"] = facts
                            state["receipts"] += 1
                        state["last"] = (saved, {"status": "committed", "result": result["result"]})
                    elif item["kind"] == "committed":
                        raise RuntimeError("Acknowledged mutation lacks its original receipt after drain")
                    reconciled.append({"operation_id": saved["request"]["operation_id"], "initial_kind": item["kind"],
                                       "outcome_after_drain": kind, "original_plan_sha256": original_digest,
                                       "original_context_preserved": True, "replacement_submissions": 0})
                    trace.write({"phase": "reconciled_after_drain", "plan": saved, "response": result})
                check_sources(state)
                # Give the observer a recovered sample before ending the window.
                stop.wait(0.6)
            finally:
                stop.set()
                observer.join(timeout=5)
                require(not observer.is_alive(), "Owned fault observer did not drain")
        if observer_errors:
            raise observer_errors[0]
        resources = check_resources(read_jsonl(samples_path, budgets["samples_bytes"], 256), budgets)
        database = database_resources(read_jsonl(samples_path, budgets["samples_bytes"], 256), budgets,
                                      service["before_pid"], service["after_pid"])
        after = offline(state, "outage-after")
        # The application is stopped after the complete offline observation;
        # restore its config before counting/publishing the bounded artifacts.
        backend.config.clear()
        backend.config.update(original_config)
        backend.config_path.write_bytes(client._bytes(original_config))
        commits = sum(item["outcome_after_drain"] == "committed" for item in reconciled)
        if commits == 0:
            equal("fault.complete_rejected_image", before["image_sha256"], after["image_sha256"])
        classifications = all(item["kind"] in ("committed", "busy", "outcome_unknown", "transaction_limit", "transaction_aborted", "transaction_conflict") for item in outcomes)
        http_supported = all(item["http_status"] is not None for item in requests)
        elapsed = recovered - service["stop_requested_at"]
        status = "failed" if "failed" in (resources["status"], database["status"]) or not classifications or elapsed > RECOVERY_SECONDS else (
            "passed" if resources["status"] == database["status"] == "passed" and http_supported else "incomplete")
        result = {"status": status, "applicable": True, "backend": "foundationdb",
                  "execution_module_sha256": execution_identity,
                  "preflight": state["preflight"],
                  "boundary": "owned local database-service stop/restart; no native commit-ack isolation",
                  "application_pid": application_pid, "same_application_pid_after_recovery": True,
                  "service": service, "recovery_seconds": elapsed, "recovery_budget_seconds": RECOVERY_SECONDS,
                  "native_timeout_seconds": NATIVE_TIMEOUT_SECONDS, "configured_max_inflight": 1,
                  "configured_http_deadline_seconds": 1, "maximum_pending_client_operations": 1,
                  "mutation_submissions": len(outcomes), "replacement_mutation_submissions": 0,
                  "requests": requests, "outcomes": reconciled, "resolved": len(reconciled), "unresolved": 0,
                  "classification": {"status": "passed" if classifications else "failed"},
                  "http_observation": {"status": "passed" if http_supported else "unsupported",
                                       "reason": None if http_supported else "ordinary client did not expose every actual HTTP error status"},
                  "quiescence": "authenticated DB read admitted with sole permit after all mutation responses; no other producers",
                  "complete_images": {"before": before, "after": after, "unchanged_when_no_commit": commits == 0,
                                      "during": {"status": "unsupported", "reference_before_sha256": before["image_sha256"],
                                                 "reason": "offline service cannot provide a complete image; no partial observation accepted"}},
                  "resources": resources,
                  "database_resources": database,
                  "database_downtime_observation": "intentional absence; database resource observation is nonapplicable while stopped",
                  "artifacts": check_artifacts(directory, budgets),
                  "limitations": ["one local process/coordinator with no replication", "native commit acknowledgement interception unverified",
                                  "replicated failover and disk/power-loss infrastructure unprovided",
                                  "HTTP deadline outcome_unknown does not imply native commit reached"]}
        if result["artifacts"]["status"] == "failed":
            result["status"] = "failed"
        elif result["status"] == "passed" and result["artifacts"]["status"] != "passed":
            result["status"] = "incomplete"
        write_private(directory / "summary.md", ("\n".join([
            f"G8.3 {result['status']}: owned local FoundationDB service outage", "",
            f"Application PID {application_pid} recovered an authenticated DB read after {elapsed:.3f} seconds.",
            f"Original mutations resolved: {len(reconciled)}; replacement submissions: 0; unresolved: 0.",
            "Complete thirteen-table state checked before and after drain.",
            "Native commit-ack isolation, replication and power loss remain unverified.", ""]).encode()))
        publish_result(directory / "outage-result.json", result, directory, budgets)
        return result
    except BaseException as error:
        write_json(directory / "outage-failure.json", {"status": "incomplete" if isinstance(error, Incomplete) else "failed",
                                                      "type": type(error).__name__, "message": str(error),
                                                      "application_pid": application_pid, "submitted": len(outcomes),
                                                      "unresolved": len(outcomes), "outcomes": [public_call(item) for item in outcomes],
                                                      "saved_plan_files": [f"outage-{index}.plan.json" for index in (2, 3)],
                                                      "replacement_submissions": 0})
        raise
    finally:
        stop.set()


def run_outage(state):
    """Run the applicable fault and stop the owned application on every exit."""
    backend = state.get("backend")
    original_config = dict(backend.config) if backend is not None else None
    try:
        return _run_outage(state)
    finally:
        if backend is not None:
            backend.stop()
            backend.config.clear()
            backend.config.update(original_config)
            backend.config_path.write_bytes(client._bytes(backend.config))


def check_outage_directory(directory):
    """Recompute G8.3 obligations from bounded retained artifacts, not labels."""
    from g8_check import (EvidenceError, expect, failure, image, inspect_source_values,
                         read_object, same)

    directory = Path(directory).resolve()
    obligations = {}
    try:
        result = read_object(directory / "outage-result.json")
        profile = read_object(directory / "outage-profile.json")
        recorded_profile = read_object(directory / "profile.json")
        budgets = profile["budgets"]
        from g8_observe import validate_budgets
        validate_budgets(budgets)
        expect(result.get("backend") == "foundationdb" and result.get("applicable") is True,
               "outage report is not an applicable FoundationDB service interruption")
        same("owned local database-service stop/restart; no native commit-ack isolation", result.get("boundary"), "outage boundary")
        same(profile.get("execution_module_sha256"), result.get("execution_module_sha256"), "outage module identity")
        same(recorded_profile["budgets"], budgets, "outage run budgets")
        obligations["inputs"] = {"status": "passed", "required": True}
    except (Incomplete, EvidenceError, ValueError, KeyError, TypeError, client.ClientError) as error:
        return {"status": "incomplete" if isinstance(error, Incomplete) else "failed",
                "obligations": {"inputs": failure(error)}}

    def record(name, work):
        try:
            obligations[name] = {**work(), "required": True}
        except (Incomplete, EvidenceError, ValueError, KeyError, TypeError, IndexError, RuntimeError,
                client.ClientError) as error:
            obligations[name] = failure(Incomplete("required outage evidence fields are missing")
                                        if isinstance(error, KeyError) else error)

    if result.get("status") != "passed":
        obligations["runtime_result"] = {"status": "failed" if result.get("status") == "failed" else "incomplete", "required": True}
    if (directory / "outage-failure.json").exists():
        try:
            retained = read_object(directory / "outage-failure.json")
            status = retained.get("status")
            obligations["retained_failure"] = {"status": status if status in ("failed", "incomplete") else "failed",
                                                "required": True,
                                                "reason": "retained runtime failure requires separate resolution"}
        except (Incomplete, ValueError, KeyError, TypeError) as error:
            obligations["retained_failure"] = failure(error)

    def plans_and_trace():
        plans = [read_object(directory / f"outage-{index}.plan.json") for index in (2, 3)]
        for saved in plans:
            request = saved.get("request")
            expect(isinstance(request, dict) and request.get("model") == recorded_profile["preflight"]["model"]["model"],
                   "original outage plan model is missing or changed")
            expect(isinstance(request.get("context"), str) and isinstance(request.get("operation_id"), str),
                   "original outage plan context or operation ID is missing")
        expect(len({plan["request"]["operation_id"] for plan in plans}) == len(plans),
               "original outage IDs are duplicated")
        trace = list(read_jsonl(directory / "fault-trace.jsonl", budgets["trace_bytes"], 256))
        expect(trace, "outage request trace is empty")
        requests = [row for row in trace if "method" in row]
        expect(requests and requests[0].get("phase") == "before", "pre-outage authenticated DB request is absent")
        down = [row for row in requests if row.get("phase") in ("database_down", "database_down_after_native_deadline")]
        expect(len([row for row in down if row.get("method") == "records.mutate"]) == len(plans),
               "database-down original mutation attempts are missing")
        expect(any(row.get("method") == "records.get" and row.get("phase") == "database_down_after_native_deadline" for row in down),
               "database-down authenticated read is missing")
        for row in down:
            expect(row.get("http_status") is not None and row.get("kind") != "read_success" and row.get("kind") != "committed",
                   "authenticated request succeeded while database service was stopped")
        for saved in plans:
            matching = [row for row in down if row.get("operation_id") == saved["request"]["operation_id"]]
            expect(len(matching) == 1, "original ID does not have exactly one down-phase submission")
            same(saved["request"], matching[0].get("plan", {}).get("request"), "down-phase original request and context")
        reconciled = [row for row in trace if row.get("phase") == "reconciled_after_drain"]
        expect(len(reconciled) == len(plans), "post-drain original-ID reconciliations are incomplete")
        by_id = {row.get("plan", {}).get("request", {}).get("operation_id"): row for row in reconciled}
        for saved in plans:
            identity = saved["request"]["operation_id"]
            row = by_id.get(identity)
            expect(row is not None, "original operation ID was not reconciled")
            same(saved["request"], row["plan"]["request"], "reconciled original request")
            expect(row.get("response", {}).get("status") in ("committed", "not_observed"),
                   "original-ID outcome is unresolved after drain")
        ordered = [row["started_at"] for row in requests if isinstance(row.get("started_at"), (int, float))]
        expect(len(ordered) == len(requests) and ordered == sorted(ordered), "request trace chronology is invalid")
        return plans, trace, by_id

    plan_state = {}
    def check_plans():
        plans, trace, reconciled = plans_and_trace()
        plan_state.update(plans=plans, trace=trace, reconciled=reconciled)
        return {"status": "passed", "required": True, "original_operations": len(plans),
                "reconciled": len(reconciled), "replacement_submissions": result.get("replacement_mutation_submissions")}
    record("original_intents_and_trace", check_plans)

    def check_service():
        service = result["service"]
        expect(result.get("same_application_pid_after_recovery") is True, "application PID continuity is unproven")
        same(service.get("before_pid"), service.get("ownership", {}).get("pid"), "initial service PID")
        same(service.get("after_pid"), service.get("restored_ownership", {}).get("pid"), "restored service PID")
        for field in ("executable", "cluster_file", "data_path", "log_path", "endpoint"):
            same(service["ownership"].get(field), service["restored_ownership"].get(field), "restored service " + field)
        owner = service["ownership"]
        for field in ("executable", "cluster_file", "data_path", "log_path", "endpoint"):
            expect(isinstance(owner.get(field), str) and owner[field], "verified service " + field + " is missing")
        prefix = result["preflight"]["prefix"]
        expect(prefix.count("--cluster-file") == 1, "preflight does not select exactly one disposable cluster")
        same(str(Path(prefix[prefix.index("--cluster-file") + 1]).resolve()), owner["cluster_file"], "owned cluster path")
        expect(Path(owner["executable"]).name == "fdbserver", "owned service executable is not fdbserver")
        expect(service.get("stopped_at", 0) <= service.get("restart_requested_at", -1)
               <= service.get("restart_returned_at", -1), "service outage/restart chronology is invalid")
        expect(result.get("recovery_seconds", RECOVERY_SECONDS + 1) <= RECOVERY_SECONDS,
               "authenticated recovery exceeded its budget")
        expect(any(row.get("phase") == "recovering" and row.get("kind") == "read_success"
                   for row in plan_state.get("trace", [])), "same-PID authenticated recovery read is absent")
        return {"status": "passed", "required": True, "application_pid": result["application_pid"],
                "restored_service_pid": service["after_pid"]}
    record("service_ownership_and_recovery", check_service)

    def check_images_and_sources():
        facts = read_object(directory / "initial-facts.json")
        facts_after = dict(facts)
        commits = 0
        for saved in plan_state["plans"]:
            identity = saved["request"]["operation_id"]
            outcome = plan_state["reconciled"][identity]["response"]
            if outcome["status"] == "committed":
                facts_after = stage(facts_after, saved["request"]["commands"])
                evaluate("equipment", facts_after)
                commits += 1
        before = image(directory / "backend/outage-before.backup.json")
        after = image(directory / "backend/outage-after.backup.json")
        same(result["complete_images"]["before"]["image_sha256"], hashlib.sha256(client._bytes(before)).hexdigest(), "before complete image digest")
        same(result["complete_images"]["after"]["image_sha256"], hashlib.sha256(client._bytes(after)).hexdigest(), "after complete image digest")
        same(13, len(before["tables"]), "before table count")
        same(13, len(after["tables"]), "after table count")
        source_summary, _ = inspect_source_values(directory / "outage-after.inspect.json", "equipment", facts_after,
            {key: plan_state["plans"][0]["target"][key] for key in ("model", "store", "tenant", "actor")})
        probe_id = plan_state["plans"][0]["request"]["commands"][0]["id"]
        probe_fact = facts_after[probe_id]
        probe_expected = evaluate("equipment", facts_after)["derived"].get(probe_id)
        probes = [row for row in plan_state["trace"] if row.get("phase") == "recovering"
                  and row.get("method") == "records.get" and row.get("kind") == "read_success"]
        expect(probes, "post-recovery authenticated DB probe is missing")
        response = probes[-1].get("response", {})
        same(probe_id, response.get("id"), "recovery probe source ID")
        same(probe_fact["contract"], response.get("contract"), "recovery probe contract")
        same(probe_fact["fields"], response.get("input"), "recovery probe input")
        same(probe_expected, response.get("derived"), "recovery probe source-derived value")
        expect(isinstance(response.get("version"), str) and response["version"], "recovery probe version is missing")
        if commits == 0:
            same(before["tables"], after["tables"], "unchanged complete state when all intents were absent")
        expected_receipts = 1 + commits
        for table in ("operations", "receipt_slots"):
            same(1, len(before["tables"][table]), "before-image " + table + " count")
            same(expected_receipts, len(after["tables"][table]), "after-image " + table + " count")
        same(expected_receipts, source_summary["receipt_count"], "independently inspected receipt count")
        for side, image_payload in (("before", before), ("after", after)):
            integrity = result["complete_images"][side]["integrity"]
            same("valid", integrity.get("status"), side + " native integrity status")
            same(len(image_payload["tables"]["operations"]), integrity.get("receipts"), side + " integrity receipt count")
        same(1, len(before["tables"]["operations"]), "before-image receipt count")
        same(1, len(before["tables"]["receipt_slots"]), "before-image receipt slot count")
        return {"status": "passed", "required": True, "tables": len(after["tables"]),
                "committed_originals": commits, "source_values": source_summary,
                "receipt_count": len(after["tables"]["operations"])}
    record("complete_state_and_receipts", check_images_and_sources)

    def check_resources_and_artifacts():
        samples = list(read_jsonl(directory / "fault-samples.jsonl", budgets["samples_bytes"], 10000))
        expect(samples, "required fault resource samples are empty")
        for row in samples:
            same(result["application_pid"], row["processes"]["application"]["pid"], "continuous application PID")
        app_resources = check_resources(samples, budgets, require_database=False)
        database = database_resources(samples, budgets, result["service"]["before_pid"], result["service"]["after_pid"])
        recorded_app = result.get("resources", {})
        same(app_resources["status"], recorded_app.get("status"), "application resource status")
        same(database["status"], result.get("database_resources", {}).get("status"), "database resource status")
        artifacts = check_artifacts(directory, budgets)
        same(artifacts["bytes"], result.get("artifacts", {}).get("bytes"),
             "reported final outage artifact byte count")
        status = "failed" if "failed" in (app_resources["status"], database["status"], artifacts["status"]) else (
            "passed" if app_resources["status"] == database["status"] == artifacts["status"] == "passed" else "incomplete")
        return {"status": status,
                "required": True, "application": app_resources, "database": database, "artifacts": artifacts}
    record("resources_and_artifact_budget", check_resources_and_artifacts)

    final_status = "failed" if any(row["status"] == "failed" for row in obligations.values()) else (
        "incomplete" if any(row.get("required") and row["status"] != "passed" for row in obligations.values()) else "passed")
    return {"status": final_status, "obligations": obligations,
            "scope": "offline recomputation from outage traces, original plans, source oracle, complete images and bounded resources"}
