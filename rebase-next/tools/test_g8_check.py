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
from g8_workload import profile
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


if __name__ == "__main__":
    unittest.main()
