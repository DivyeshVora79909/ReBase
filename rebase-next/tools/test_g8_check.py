"""Independent small evidence controls, not mocked distributed acceptance."""

from copy import deepcopy
from collections import Counter
import json
from pathlib import Path
import tempfile
import unittest
import uuid

import client
import g8_check as check
from g7_http import TABLES
from g8_pressure import default_pressure_profile
from g8_workload import profile
from harness import latency
from verify_oracles import evaluate, stage


def write(path, value):
    path.write_text(json.dumps(value) + "\n")


def write_rows(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def identity(name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "g8-offline-fixture/" + str(name)))


def backup(facts, receipts, epoch=0):
    tables = {name: [] for name in TABLES}
    tables["public_records"] = [{"key": key, "contract": row["contract"]} for key, row in facts.items()]
    tables["reader_records"] = deepcopy(tables["public_records"])
    tables["operations"] = [{"key": f"{number:032x}", "value": "00"} for number in range(receipts)]
    tables["receipt_slots"] = [{"key": f"{number:04x}", "value": "00"} for number in range(receipts)]
    tables["native_kv"] = [{"key": "00", "value": "00"}]
    header = {"operation_epoch": str(epoch), "store_id": identity("store"), "cursor_key": "private-fixture-value"}
    tables["local_runtime"] = [{"key": "00", "value": client._bytes(header).hex()}]
    return {"format": "rebase-backup-1", "payload": {"format": "rebase-authorized-observation-1", "complete": True, "tables": tables}}


def memory_fixture(root):
    (root / "backend").mkdir()
    floors = {name: 1 for name in check.FLOORS}
    floors["read"] = 2
    settings = profile(smoke=True, duration_seconds=2.0, warmup_seconds=0.0, cooldown_seconds=0.0,
                       floors=floors, readers=1, reader_rate=1.0)
    write(root / "profile.json", {**settings, "preflight": {"backend": "redb"}})
    p, q, d, e, a, b, x, invalid = [identity(name) for name in ("P", "Q", "D", "E", "A", "B", "X", "invalid")]
    reservation = lambda pool, start, end, amount: {"pool": pool, "starts": str(start), "ends": str(end), "requested": str(amount), "active": True}
    fixture_commands = [
        {"op": "create", "id": p, "contract": 101, "fields": {"unit": 7}},
        {"op": "create", "id": q, "contract": 101, "fields": {"unit": 7}},
        {"op": "create", "id": d, "contract": 205, "fields": {"pool": p, "at": "0", "quantity": "10"}},
        {"op": "create", "id": e, "contract": 205, "fields": {"pool": q, "at": "0", "quantity": "6"}},
        {"op": "create", "id": a, "contract": 410, "fields": reservation(p, 10, 30, 8)},
        {"op": "create", "id": b, "contract": 410, "fields": reservation(p, 20, 40, 7)}]
    target = {"url": "http://127.0.0.1:12345/rpc", "model": "model-fixture",
              "store": identity("store"), "tenant": identity("tenant"), "actor": identity("actor")}

    def plan(commands, name):
        return {"format": client.PLAN_FORMAT, "target": target, "request": {"model": target["model"],
            "context": "aa" * 32, "operation_id": identity(name), "commands": commands, "returning": []}}

    fixture = plan(fixture_commands, "fixture-operation")
    write(root / "fixture.plan.json", fixture)
    initial = stage({}, fixture_commands)
    write(root / "initial-facts.json", initial)
    facts, versions = initial, {source: identity("version/initial/" + source) for source in initial}
    rows, outcomes, receipts = [], [], 1
    last, old_a = None, versions[a]

    def add(action, command=None, kind="committed"):
        nonlocal facts, versions, receipts, last
        if action == "replay":
            saved, previous = last
            response = {**previous, "replayed": True}
        else:
            saved = plan([command], action + "-operation")
            response = None
            rows.append({"event": "intent", "phase": "measurement", "action": action, "plan": saved, "expected": kind})
        publications = {}
        if kind == "committed":
            proposed = stage(facts, [command])
            before, after = evaluate("equipment", facts), evaluate("equipment", proposed)
            next_versions = {}
            for source, fact in proposed.items():
                unchanged = source in facts and facts[source] == fact and before["derived"].get(source) == after["derived"].get(source)
                next_versions[source] = versions[source] if unchanged else identity("version/" + action + "/" + source)
                publications[source] = {"input": fact["fields"], "derived": after["derived"].get(source), "version": next_versions[source]}
            facts, versions = proposed, next_versions
            response = {"status": "committed", "replayed": False, "result": {"operation_id": saved["request"]["operation_id"]}}
            receipts += 1
            last = saved, response
        row = {"event": "outcome", "phase": "measurement", "action": action, "expected": kind,
               "plan": saved, "response": response, "kind": kind, "http_status": 200, "latency_ms": 1.0}
        if kind == "committed":
            row["checked_publications"] = publications
        rows.append(row)
        outcomes.append(row)

    add("create", {"op": "create", "id": x, "contract": 205, "fields": {"pool": p, "at": "50", "quantity": "2"}})
    add("update", {"op": "update", "id": a, "if_version": versions[a], "set": {"active": False}, "unset": []})
    add("stale", {"op": "update", "id": a, "if_version": old_a, "set": {"active": True}, "unset": []}, kind="stale_version")
    add("delete", {"op": "delete", "id": x, "if_version": versions[x]})
    add("replay", kind="replayed")
    add("noop", {"op": "update", "id": d, "if_version": versions[d], "set": {"quantity": "10"}, "unset": []})
    add("invalid", {"op": "create", "id": invalid, "contract": 410, "fields": reservation(p, 20, 25, 11)}, kind="invariant")
    write_rows(root / "trace.jsonl", rows)
    write(root / "final-facts.json", facts)
    reads = [{"method": "roots.read", "http_status": 200, "phase": "measurement", "sum": "10", "count": 5, "latency_ms": 1.0}] * 2
    write_rows(root / "reads.jsonl", reads)
    process = {"available": True, "pid": 101, "start_ticks": 1000, "rss_kib": 1000, "peak_rss_kib": 1200,
               "cpu_seconds": 0.1, "open_fds": 3, "threads": 1}
    samples = [{"phase": "measurement", "monotonic_seconds": 100 + number * .25, "observer_ms": 1.0,
                "processes": {"application": process, "controller": {**process, "pid": 102}},
                "physical_bytes": 1024, "logical": {"public_sources": 6, "receipt_slots": receipts}} for number in range(8)]
    write_rows(root / "samples.jsonl", samples)
    full = backup(facts, receipts)
    write(root / "backend/after-epoch.backup.json", full)
    before = backup(initial, 1)
    for suffix in ("before", "after"):
        write(root / f"backend/preflight-rollback-{suffix}.backup.json", before)
    (root / "backend/server.log").write_text('{"event":"mutation_work","work":{"loads":1}}\n' * receipts)
    kinds = dict(Counter(row["kind"] for row in outcomes))
    coverage = dict(floors)
    result = {"status": "passed", "profile": settings, "backend": "redb", "continuous_application_pid": 101,
        "coverage": {"requested": floors, "achieved": coverage}, "resources": {"status": "passed"},
        "work": {"offered": 7, "submitted": 7, "completed": 7, "unresolved": 0,
                 "reads_by_phase": {"measurement": 2}, "outcomes": kinds, "http_statuses": {"200": 7}},
        "receipts": {"resolved": 7, "unresolved": 0, "replacement_submissions": 0},
        "markers": [{"phase": phase, "duration_requested": duration, "duration_achieved": duration,
                     "pid": 101, "start_seconds": start} for phase, duration, start in (("warmup", 0, 0), ("measurement", 2, 0), ("cooldown", 0, 2))],
        "complete_state": {"table_count": 13, "image_sha256": check.digest(full["payload"]), "integrity": {"status": "valid", "receipts": receipts}}}
    write(root / "result.json", result)
    return rows, samples, result, facts


def source_inspector(facts, target, receipts):
    expected = evaluate("equipment", facts)
    records = [{"id": source, "record": {"contract": row["contract"], "input": row["fields"],
        "derived": expected["derived"].get(source), "version": identity("inspected/" + source)}}
        for source, row in facts.items()]
    roles = [identity(f"private/{row['source']}/{role}") for row in expected["dependencies"] if row["active"] for role in row["roles"]]
    records.extend({"id": source, "record": {"contract": 999}} for source in roles)
    return {**{key: target[key] for key in ("model", "store", "tenant", "actor")}, "codec": "native-slice-kv-7",
        "records": records, "roles": roles, "receipt_count": receipts,
        "roots": [{"root": {"id": row["owner"], "slot": row["slot"]}, "summary": {"value": row["summary"]}}
                  for row in expected["roots"]]}


def partial_pressure_fixture(root):
    """One raw stage checks field boundaries without simulating a load matrix."""
    _, samples, memory, _ = memory_fixture(root)
    pressure = root / "pressure"
    pressure.mkdir()
    fixture = check.read_object(root / "fixture.plan.json")
    initial = check.read_object(root / "initial-facts.json")
    pool = fixture["request"]["commands"][0]["id"]
    delivery = fixture["request"]["commands"][2]["id"]
    settings, target = default_pressure_profile(), fixture["target"]
    settings["step_seconds"] = 1.0
    command = {"op": "update", "id": delivery, "if_version": identity("prepared/" + delivery),
               "set": {"quantity": "11"}, "unset": []}
    saved = {"format": client.PLAN_FORMAT, "target": target, "request": {**fixture["request"],
        "operation_id": identity("pressure-operation"), "commands": [command]}}
    response = {"status": "committed", "replayed": False, "result": {"operation_id": saved["request"]["operation_id"]}}
    stage_id = "hot_root:2"
    attribution = {"phase": "measurement", "pattern": "hot_root", "stage_id": stage_id}
    facts = stage(initial, [command])
    rows = [
        {"event": "stage", "stage_id": stage_id, "pattern": "hot_root", "clients": 1, "offered_rate": 2,
         "duration_seconds": 1.0, "mode": "paced"},
        {"event": "offer", "stage_id": stage_id, "index": 0, "pending": 0, "producer_accepted": True},
        {"event": "intent", **attribution, "plan": saved},
        {"event": "offer", "stage_id": stage_id, "index": 1, "pending": 1, "producer_accepted": True},
        {"event": "read", **attribution, "request": {"method": "roots.read", "params": {
            "model": target["model"], "owner": pool, "slot": 7}}, "kind": "busy", "http_status": 429,
         "latency_ms": .5, "queue_and_request_ms": .5},
        {"event": "outcome", **attribution, "plan": saved, "kind": "committed", "http_status": 200,
         "response": response, "latency_ms": 1.5, "queue_and_request_ms": 1.5},
        {"event": "stage_end", "stage_id": stage_id, "offering_elapsed_seconds": 1.0,
         "future_drain_seconds": 0.5, "total_drain_seconds": 0.5},
        {"event": "drain", "stage_id": stage_id, "request": {"method": "records.get", "params": {
            "model": target["model"], "id": delivery}}, "response": {"input": facts[delivery]["fields"],
            "derived": None, "version": identity("drained/" + delivery)}}]
    write_rows(pressure / "trace.jsonl", rows)
    statuses = [{"event": "status", "plan": saved, "response": {"status": "committed", "result": response["result"]}},
                {"event": "replay", "plan": saved, "response": {**response, "replayed": True}}]
    write_rows(pressure / "receipt-observations.jsonl", statuses)
    write_rows(pressure / "samples.jsonl", samples)
    budgets = memory["profile"]["budgets"]
    write(pressure / "profile.json", {**settings, "backend": "redb", "budgets": budgets,
        "database_observer": None, "execution_module_sha256": "a" * 64})
    inspector = source_inspector(facts, target, 2)
    write(root / "pressure-complete.inspect.json", inspector)
    full = backup(facts, 2)
    for label in ("complete", "limit-before", "limit-after"):
        write(root / f"backend/pressure-{label}.backup.json", full)
    write(pressure / "commands-65.request.json", {**saved["request"], "operation_id": identity("over-limit-operation"),
        "commands": [{"op": "create", "id": identity(f"limit-{number}"), "contract": 101, "fields": {"unit": 7}} for number in range(65)]})
    (root / "backend/server.log").write_bytes(b"".join(client._bytes({"event": "mutation_work", "operation_id": original,
        "work": {"causal_evaluations": 2}}) + b"\n" for original in (fixture["request"]["operation_id"], saved["request"]["operation_id"])))
    counts = {"offered": 2, "submitted": 2, "completed": 2, "outcome:busy": 1, "http:429": 1,
              "outcome:committed": 1, "http:200": 1, "not_offered_before_duration": 0}
    result = {"status": "passed", "backend": "redb", "model": target["model"], "profile": settings,
        "execution_module_sha256": "a" * 64, "application_pid": 101, "resources": {"status": "passed"},
        "steps": [{"stage_id": stage_id, "pattern": "hot_root", "offered_rate": 2, "clients": 1,
            "offering_elapsed_seconds": 1.0, "offered_per_second": 2.0, "submitted_per_second": 2.0,
            "completed_per_second": 2.0, "peak_pending": 2, "counts": counts, "latency": latency([.5, 1.5])}], "bursts": [], "geometry": [], "quantity": {},
        "receipts": {"resolved": 1, "absent_after_quiescence": 0, "unresolved": 0, "same_id_replay": True,
            "replacement_mutation_submissions": 0, "original_contexts_preserved": True},
        "limits": {"commands": 65, "command_rpc_kind": "invalid_input", "rejected_receipt": "not_observed",
            "body_http_status": 413, "body_bytes": client.MAX_REQUEST_BYTES+1, "all_tables_unchanged": True},
        "complete_state": {"table_count": 13, "image_sha256": check.digest(full["payload"]),
            "logical": {"public_sources": 6, "active_outputs": 4, "retained_roles": 4, "receipt_slots": 2},
            "integrity": {"status": "valid", "receipts": 2}}}
    write(pressure / "pressure-result.json", result)
    return rows, samples, result, inspector, statuses


class OfflineMemoryControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rows, self.samples, self.result, self.facts = memory_fixture(self.root)

    def test_raw_small_evidence_passes_with_source_calculations(self):
        result = check.check_directory(self.root)
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(result["obligations"]["memory_outcomes"]["checked_transient_states"], 4)
        self.assertEqual(result["obligations"]["stale_token_observations"]["observed_relationships"], 1)

    def test_cached_pass_cannot_hide_bad_raw_rss(self):
        self.samples[2]["processes"]["application"]["rss_kib"] = self.result["profile"]["budgets"]["app_rss_kib"] + 1
        write_rows(self.root / "samples.jsonl", self.samples)
        result = check.check_directory(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["obligations"]["resources"]["status"], "failed")

    def test_retained_runtime_failure_preserves_failed_or_incomplete(self):
        for name in ("failure.json", "cycles-failure.json"):
            for status in ("failed", "incomplete"):
                with self.subTest(artifact=name, status=status):
                    path = self.root / name
                    write(path, {"status": status, "type": "Incomplete" if status == "incomplete" else "RuntimeError"})
                    result = check.check_directory(self.root)
                    self.assertEqual(result["status"], status)
                    self.assertEqual(result["obligations"][name]["status"], status)
                    path.unlink()

    def test_dropped_original_outcome_is_incomplete(self):
        write_rows(self.root / "trace.jsonl", self.rows[:-1])
        result = check.check_directory(self.root)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["obligations"]["memory_outcomes"]["status"], "incomplete")

    def test_raw_coverage_is_required_even_when_cached_counts_pass(self):
        write_rows(self.root / "reads.jsonl", [])
        self.assertEqual(check.check_directory(self.root)["status"], "failed")

    def test_changed_final_authored_facts_fail(self):
        changed = deepcopy(self.facts)
        delivery = next(source for source, row in changed.items() if row["contract"] == 205)
        changed[delivery]["fields"]["quantity"] = "999"
        write(self.root / "final-facts.json", changed)
        self.assertEqual(check.check_directory(self.root)["status"], "failed")

    def test_wrong_transient_allocation_is_detected_before_final_state(self):
        outcome = next(row for row in self.rows if row["event"] == "outcome" and row["kind"] == "committed")
        reservation = next(source for source, row in outcome["checked_publications"].items() if row["derived"])
        outcome["checked_publications"][reservation]["derived"]["allocated"] = "999"
        write_rows(self.root / "trace.jsonl", self.rows)
        self.assertEqual(check.check_directory(self.root)["status"], "failed")

    def test_stale_edit_cannot_be_relabelled_as_a_successful_update(self):
        for row in self.rows:
            if row["action"] == "stale":
                row["kind"] = "committed" if row["event"] == "outcome" else row.get("kind")
        write_rows(self.root / "trace.jsonl", self.rows)
        self.assertEqual(check.check_directory(self.root)["status"], "failed")

    def test_missing_fixture_or_final_private_artifacts_is_incomplete(self):
        for name in ("fixture.plan.json", "final-facts.json"):
            path = self.root / name
            data = path.read_bytes()
            path.unlink()
            self.assertEqual(check.check_directory(self.root)["status"], "incomplete")
            path.write_bytes(data)

    def test_declared_duration_cannot_hide_truncated_samples(self):
        write_rows(self.root / "samples.jsonl", self.samples[:2])
        self.assertEqual(check.check_directory(self.root)["status"], "incomplete")

    def record_tool_identities(self, profile_hashes, result_hashes):
        recorded_profile = json.loads((self.root / "profile.json").read_text())
        recorded_profile["preflight"]["execution_tools_sha256"] = profile_hashes
        self.result["preflight"] = {"execution_tools_sha256": result_hashes}
        write(self.root / "profile.json", recorded_profile)
        write(self.root / "result.json", self.result)

    def test_embedded_run_start_hashes_agree_without_claiming_current_equality(self):
        hashes = {"tools/g8_workload.py": "a" * 64}
        self.record_tool_identities(hashes, deepcopy(hashes))
        result = check.check_directory(self.root)
        self.assertEqual(result["status"], "passed", result)
        identities = result["obligations"]["run_start_identities"]
        self.assertEqual(identities["recorded_tools_sha256"], hashes)
        self.assertNotEqual(identities["current_tools_sha256"], hashes)

    def test_malformed_embedded_run_start_hash_fails(self):
        hashes = {"tools/g8_workload.py": "not-a-sha256"}
        self.record_tool_identities(hashes, deepcopy(hashes))
        result = check.check_directory(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["obligations"]["run_start_identities"]["status"], "failed")

    def test_mismatched_embedded_run_start_hashes_fail(self):
        self.record_tool_identities({"tools/g8_workload.py": "a" * 64}, {"tools/g8_workload.py": "b" * 64})
        result = check.check_directory(self.root)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["obligations"]["run_start_identities"]["status"], "failed")

    def test_missing_embedded_run_start_counterpart_is_incomplete(self):
        self.record_tool_identities({"tools/g8_workload.py": "a" * 64}, {})
        self.result["preflight"].pop("execution_tools_sha256")
        write(self.root / "result.json", self.result)
        result = check.check_directory(self.root)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["obligations"]["run_start_identities"]["status"], "incomplete")

    def test_legacy_run_start_artifact_remains_supported(self):
        hashes = {"tools/g8_workload.py": "a" * 64}
        write(self.root / "run-start-tools.json", {"sha256": hashes})
        result = check.check_directory(self.root)
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(result["obligations"]["run_start_identities"]["recorded_tools_sha256"], hashes)


class OfflineArchiveControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "backend").mkdir()
        self.full = backup({}, 1024)
        self.archived = backup({}, 0, epoch=1)
        for label in ("full", "rejection-before", "rejection-after"):
            write(self.root / f"backend/cycle-0-{label}.backup.json", self.full)
        write(self.root / "cycle-0.archive.json", self.full)
        write(self.root / "backend/cycle-0-archived.backup.json", self.archived)
        write(self.root / "backend/cycle-0-resumed.backup.json", backup({}, 3, epoch=1))

    def test_exact_full_images_archive_and_resumed_inventory_pass(self):
        result = check.check_cycle_images(self.root, 0)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["actual_receipt_slots"], 1024)

    def test_truncated_slot_inventory_is_not_full_capacity(self):
        self.full["payload"]["tables"]["receipt_slots"].pop()
        for label in ("full", "rejection-before", "rejection-after"):
            write(self.root / f"backend/cycle-0-{label}.backup.json", self.full)
        write(self.root / "cycle-0.archive.json", self.full)
        with self.assertRaisesRegex(check.EvidenceError, "actual full receipt_slots"):
            check.check_cycle_images(self.root, 0)

    def test_archive_cannot_change_preserved_native_rows(self):
        self.archived["payload"]["tables"]["native_kv"][0]["value"] = "01"
        write(self.root / "backend/cycle-0-archived.backup.json", self.archived)
        with self.assertRaisesRegex(RuntimeError, "Archive changed native_kv"):
            check.check_cycle_images(self.root, 0)

    def test_incomplete_archive_artifact_does_not_pass(self):
        (self.root / "cycle-0.archive.json").write_text('{"payload":')
        with self.assertRaises(check.Incomplete):
            check.check_cycle_images(self.root, 0)


class OfflinePressureControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rows, self.samples, self.result, self.inspector, self.statuses = partial_pressure_fixture(self.root)

    def test_one_raw_stage_passes_its_checks_without_certifying_the_matrix(self):
        result = check.check_pressure_directory(self.root)
        self.assertEqual(result["status"], "incomplete", result)
        for name in ("inputs", "resources", "source_trace", "source_values", "complete_image", "stages", "original_receipts", "rejection_images"):
            self.assertEqual(result["obligations"][name]["status"], "passed", (name, result))
        self.assertEqual(result["obligations"]["finite_load"]["status"], "incomplete")
        self.assertEqual(result["obligations"]["native_permit_proof"]["status"], "unsupported")

    def test_dropped_raw_pressure_outcome_is_incomplete(self):
        write_rows(self.root / "pressure/trace.jsonl", [row for row in self.rows if row["event"] != "outcome"])
        result = check.check_pressure_directory(self.root)
        self.assertEqual(result["status"], "incomplete", result)
        self.assertEqual(result["obligations"]["source_trace"]["status"], "incomplete")
        self.assertEqual(result["obligations"]["original_receipts"]["status"], "incomplete")

    def test_cached_pressure_pass_cannot_hide_bad_raw_resource_samples(self):
        for process, budget in (("application", "app_rss_kib"), ("controller", "controller_rss_kib")):
            with self.subTest(process=process):
                samples = deepcopy(self.samples)
                samples[2]["processes"][process] = {**samples[2]["processes"][process], "rss_kib": self.result_budgets()[budget] + 1}
                write_rows(self.root / "pressure/samples.jsonl", samples)
                result = check.check_pressure_directory(self.root)
                self.assertEqual(result["status"], "failed", result)
                self.assertEqual(result["obligations"]["resources"]["status"], "failed")

    def result_budgets(self):
        return check.read_object(self.root / "pressure/profile.json")["budgets"]

    def test_wrong_public_input_or_derived_value_fails_independent_pressure_check(self):
        for field in ("input", "derived"):
            with self.subTest(field=field):
                observed = deepcopy(self.inspector)
                if field == "input":
                    record = next(row["record"] for row in observed["records"] if row["record"]["contract"] == 205)
                    record["input"]["quantity"] = "999"
                else:
                    record = next(row["record"] for row in observed["records"] if row["record"]["contract"] == 410)
                    record["derived"]["allocated"] = "999"
                write(self.root / "pressure-complete.inspect.json", observed)
                result = check.check_pressure_directory(self.root)
                self.assertEqual(result["status"], "failed", result)
                self.assertEqual(result["obligations"]["source_values"]["status"], "failed")

    def test_changed_complete_rejection_image_cannot_be_hidden_by_cached_pass(self):
        after = check.read_object(self.root / "backend/pressure-limit-after.backup.json")
        after["payload"]["tables"]["native_kv"][0]["value"] = "01"
        write(self.root / "backend/pressure-limit-after.backup.json", after)
        result = check.check_pressure_directory(self.root)
        self.assertEqual(result["status"], "failed", result)
        self.assertEqual(result["obligations"]["rejection_images"]["status"], "failed")

    def test_receipt_observation_must_preserve_the_original_context(self):
        statuses = deepcopy(self.statuses)
        statuses[0]["plan"]["request"]["context"] = "bb" * 32
        write_rows(self.root / "pressure/receipt-observations.jsonl", statuses)
        result = check.check_pressure_directory(self.root)
        self.assertEqual(result["obligations"]["original_receipts"]["status"], "failed", result)

    def test_pressure_replay_must_return_the_original_result_and_flag(self):
        for corruption in ("result", "replayed"):
            with self.subTest(corruption=corruption):
                statuses = deepcopy(self.statuses)
                if corruption == "result":
                    statuses[-1]["response"]["result"] = {"operation_id": identity("replacement")}
                else:
                    statuses[-1]["response"]["replayed"] = False
                write_rows(self.root / "pressure/receipt-observations.jsonl", statuses)
                result = check.check_pressure_directory(self.root)
                self.assertEqual(result["obligations"]["original_receipts"]["status"], "failed", result)

    def test_missing_raw_status_or_replay_cannot_be_hidden_by_cached_receipt_pass(self):
        for omitted in ("status", "replay"):
            with self.subTest(omitted=omitted):
                write_rows(self.root / "pressure/receipt-observations.jsonl", [row for row in self.statuses if row["event"] != omitted])
                result = check.check_pressure_directory(self.root)
                self.assertEqual(result["obligations"]["original_receipts"]["status"], "incomplete", result)

    def test_raw_queue_prefix_is_required_even_with_a_plausible_cached_peak(self):
        self.rows[3]["pending"] = 0
        write_rows(self.root / "pressure/trace.jsonl", self.rows)
        result = check.check_pressure_directory(self.root)
        self.assertEqual(result["obligations"]["stages"]["status"], "failed", result)

    def test_pressure_rates_are_recomputed_from_raw_counts_and_achieved_elapsed(self):
        result_path = self.root / "pressure/pressure-result.json"
        result = check.read_object(result_path)
        result["steps"][0]["completed_per_second"] = 2000.0
        write(result_path, result)
        checked = check.check_pressure_directory(self.root)
        self.assertEqual(checked["obligations"]["stages"]["status"], "failed", checked)

    def test_missing_achieved_pressure_duration_is_incomplete(self):
        write_rows(self.root / "pressure/trace.jsonl", [row for row in self.rows if row["event"] != "stage_end"])
        result = check.check_pressure_directory(self.root)
        self.assertEqual(result["obligations"]["stages"]["status"], "incomplete", result)

    def test_busy_reader_still_requires_its_declared_method_model_and_root(self):
        for corruption in ("method", "model", "owner"):
            with self.subTest(corruption=corruption):
                rows = deepcopy(self.rows)
                request = rows[4]["request"]
                if corruption == "method":
                    request["method"] = "records.get"
                else:
                    request["params"][corruption] = identity("changed-reader-target")
                write_rows(self.root / "pressure/trace.jsonl", rows)
                result = check.check_pressure_directory(self.root)
                self.assertEqual(result["obligations"]["source_trace"]["status"], "failed", result)

    def test_repeated_success_for_one_prepared_cas_source_fails(self):
        rows = deepcopy(self.rows)
        second = deepcopy(rows[2])
        second["plan"]["request"]["operation_id"] = identity("second-pressure-operation")
        second_outcome = deepcopy(rows[5])
        second_outcome["plan"] = second["plan"]
        second_outcome["response"]["result"]["operation_id"] = second["plan"]["request"]["operation_id"]
        rows[4] = second
        rows.insert(6, second_outcome)
        write_rows(self.root / "pressure/trace.jsonl", rows)
        result = check.check_pressure_directory(self.root)
        self.assertEqual(result["obligations"]["source_trace"]["status"], "failed", result)

    def test_an_original_token_cannot_be_refreshed_within_the_pressure_stage(self):
        rows = deepcopy(self.rows)
        second = deepcopy(rows[2])
        second["plan"]["request"]["operation_id"] = identity("second-pressure-operation")
        second["plan"]["request"]["commands"][0]["if_version"] = identity("refreshed-pressure-version")
        rows[4] = second
        write_rows(self.root / "pressure/trace.jsonl", rows)
        result = check.check_pressure_directory(self.root)
        self.assertEqual(result["obligations"]["source_trace"]["status"], "failed", result)

    def test_missing_raw_operation_work_is_incomplete(self):
        path = self.root / "backend/server.log"
        lines = path.read_bytes().splitlines(keepends=True)
        path.write_bytes(lines[0])
        fixture = check.read_object(self.root / "fixture.plan.json")
        original = self.rows[2]["plan"]["request"]["operation_id"]
        with self.assertRaisesRegex(check.Incomplete, "work observations are missing"):
            check.operation_work(path, self.result_budgets(), {fixture["request"]["operation_id"], original})

    def test_deferred_unknown_completion_timing_remains_incomplete(self):
        outcome = self.rows.pop(5)
        outcome.update(kind="outcome_unknown", http_status=504, resolved_status="committed",
            status_observation={"status": "committed", "result": outcome["response"]["result"]},
            resolved_result=outcome["response"]["result"])
        self.rows.append(outcome)
        write_rows(self.root / "pressure/trace.jsonl", self.rows)
        result = check.check_pressure_directory(self.root)
        self.assertEqual(result["obligations"]["source_trace"]["status"], "passed", result)
        self.assertEqual(result["obligations"]["stages"]["status"], "incomplete")
        self.assertEqual(result["status"], "incomplete", result)


if __name__ == "__main__":
    unittest.main()
