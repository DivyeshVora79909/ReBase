"""Ownership/cleanup controls; these mocks are not distributed acceptance."""

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import client
import fdb_cluster
import g8_faults
from g7_http import TABLES
from g8_observe import DEFAULT_BUDGETS, check_artifacts
from verify_oracles import evaluate


class FaultOwnershipChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc = self.root / "proc"
        process = self.proc / "12"
        process.mkdir(parents=True)
        self.server = self.root / "fdbserver"
        self.server.write_bytes(b"owned executable identity fixture")
        (process / "exe").symlink_to(self.server)
        self.cluster, self.data, self.log, self.pidfile = [self.root / name for name in ("fdb.cluster", "data", "log", "server.pid")]
        self.cluster.write_text("owned cluster identity fixture")
        self.data.mkdir()
        self.log.mkdir()
        self.pidfile.write_text("12\n")
        self.arguments = [str(self.server), "-p", "127.0.0.1:4500", "-C", str(self.cluster),
                          "-d", str(self.data), "-L", str(self.log)]
        self.write_arguments(self.arguments)
        stack = self.enterContext(ExitStack())
        for name, value in (("FDBSERVER", self.server), ("CLUSTER", self.cluster), ("DATA", self.data),
                            ("LOG", self.log), ("PIDFILE", self.pidfile)):
            stack.enter_context(patch.object(fdb_cluster, name, value))

    def write_arguments(self, arguments):
        (self.proc / "12" / "cmdline").write_bytes(b"\0".join(value.encode() for value in arguments) + b"\0")

    def verify(self, cluster=None):
        return g8_faults.verify_service(12, cluster or self.cluster, proc_root=self.proc)

    def test_exact_identity_is_required_before_signals(self):
        self.assertEqual(self.verify()["data_path"], str(self.data))
        with self.assertRaisesRegex(ValueError, "exact disposable helper cluster"):
            self.verify(self.root / "different.cluster")

    def test_wrong_pid_executable_and_each_ownership_argument_refuse(self):
        self.pidfile.write_text("99\n")
        with self.assertRaisesRegex(ValueError, "PID file"):
            self.verify()
        self.pidfile.write_text("12\n")
        for flag in ("-C", "-d", "-L", "-p"):
            changed = list(self.arguments)
            changed[changed.index(flag) + 1] = "unowned target"
            self.write_arguments(changed)
            with self.assertRaisesRegex(ValueError, "refusing to signal"):
                self.verify()
        self.write_arguments(self.arguments)
        (self.proc / "12" / "exe").unlink()
        (self.proc / "12" / "exe").symlink_to(self.cluster)
        with self.assertRaisesRegex(ValueError, "different executable"):
            self.verify()

    def test_duplicate_arguments_cannot_hide_a_different_target(self):
        self.write_arguments(self.arguments + ["-C", str(self.cluster)])
        with self.assertRaisesRegex(ValueError, "duplicated"):
            self.verify()

    def test_context_refuses_unverified_service_without_sending_signals(self):
        with patch.object(fdb_cluster, "server_pid", return_value=99), patch.object(fdb_cluster, "stop") as stop, patch.object(fdb_cluster, "start") as start:
            with self.assertRaises(ValueError):
                with g8_faults.owned_outage(self.cluster):
                    self.fail("unowned service entered outage")
            stop.assert_not_called()
            start.assert_not_called()

    def test_exception_after_stop_always_requests_verified_service_restore(self):
        with patch.object(fdb_cluster, "server_pid", side_effect=[12, 12, None, 13]), patch.object(g8_faults, "verify_service", side_effect=[{"pid": 12}, {"pid": 13}]), patch.object(fdb_cluster, "stop") as stop, patch.object(fdb_cluster, "start") as start:
            with self.assertRaisesRegex(RuntimeError, "injected work failure"):
                with g8_faults.owned_outage(self.cluster):
                    raise RuntimeError("injected work failure")
            stop.assert_called_once()
            start.assert_called_once()

    def test_stop_failure_still_runs_restore_cleanup(self):
        with patch.object(fdb_cluster, "server_pid", side_effect=[12, 12, 12]), patch.object(g8_faults, "verify_service", return_value={"pid": 12}), patch.object(fdb_cluster, "stop", side_effect=RuntimeError("stop failed")), patch.object(fdb_cluster, "start") as start:
            with self.assertRaisesRegex(RuntimeError, "stop failed"):
                with g8_faults.owned_outage(self.cluster):
                    self.fail("failed stop entered outage")
            start.assert_called_once()

    def test_embedded_network_case_is_unsupported_and_does_not_start_service(self):
        for backend in ("redb", "surrealkv"):
            with patch.object(fdb_cluster, "start") as start, patch.object(fdb_cluster, "stop") as stop:
                result = g8_faults.run_outage({"preflight": {"backend": backend}})
            self.assertEqual(result["status"], "unsupported")
            self.assertFalse(result["applicable"])
            start.assert_not_called()
            stop.assert_not_called()

    def test_initial_failure_still_stops_application_and_restores_config(self):
        config = {"max_inflight": 16, "request_timeout_seconds": 15}
        original = dict(config)
        backend = SimpleNamespace(config=config, config_path=self.root / "server.json", stop=Mock())
        state = {"preflight": {"backend": "foundationdb"}, "backend": backend}

        def fail(_state):
            config.update(max_inflight=1, request_timeout_seconds=1)
            raise RuntimeError("initial failure")

        with patch.object(g8_faults, "_run_outage", side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, "initial failure"):
                g8_faults.run_outage(state)
        backend.stop.assert_called_once()
        self.assertEqual(config, original)

    def test_nonapplicable_network_case_stops_an_owned_prepared_application(self):
        config = {"max_inflight": 16, "request_timeout_seconds": 15}
        backend = SimpleNamespace(config=config, config_path=self.root / "server.json", stop=Mock())
        result = g8_faults.run_outage({"preflight": {"backend": "redb"}, "backend": backend})
        self.assertEqual(result["status"], "unsupported")
        backend.stop.assert_called_once()

    def test_directory_checker_marks_missing_run_incomplete(self):
        result = g8_faults.check_outage_directory(self.root)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["obligations"]["inputs"]["status"], "incomplete")

    def test_database_resource_evidence_requires_both_pid_epochs(self):
        budgets = {"database_rss_kib": 100, "database_fds": 10, "database_threads": 8}
        samples = [{"database_state": "running", "processes": {"database": {
            "available": True, "pid": pid, "rss_kib": 50, "peak_rss_kib": 60, "open_fds": 4, "threads": 3}}}
            for pid in (12, 13)]
        result = g8_faults.database_resources(samples, budgets, 12, 13)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["observed_pid_samples"], {12: 1, 13: 1})
        missing_epoch = g8_faults.database_resources(samples[:1], budgets, 12, 13)
        self.assertEqual(missing_epoch["status"], "incomplete")

    def test_database_resource_budget_excess_fails(self):
        budgets = {"database_rss_kib": 100, "database_fds": 10, "database_threads": 8}
        samples = [{"database_state": "running", "processes": {"database": {
            "available": True, "pid": pid, "rss_kib": 101, "peak_rss_kib": 101, "open_fds": 4, "threads": 3}}}
            for pid in (12, 13)]
        self.assertEqual(g8_faults.database_resources(samples, budgets, 12, 13)["status"], "failed")

    def test_directory_checker_accepts_complete_raw_fixture(self):
        directory = self.root / "positive"
        (directory / "backend").mkdir(parents=True)
        model, store, tenant, actor = "fixture-model", "fixture-store", "fixture-tenant", "fixture-actor"
        facts = {"pool": {"contract": 101, "fields": {"unit": 7}},
                 "delivery": {"contract": 205, "fields": {"pool": "pool", "at": "0", "quantity": "10"}}}
        expected = evaluate("equipment", facts)
        request_ids = ("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        commands = [
            {"op": "update", "id": "delivery", "if_version": "version-1", "set": {"quantity": value}, "unset": []}
            for value in ("11", "12")]
        plans = []
        for identity, command in zip(request_ids, commands):
            plans.append({"format": "rebase-operation-plan-1", "target": {"model": model, "store": store,
                "tenant": tenant, "actor": actor, "url": "http://127.0.0.1/rpc"}, "request": {
                "model": model, "context": "c" * 64, "operation_id": identity,
                "commands": [command], "returning": []}})
        (directory / "initial-facts.json").write_text(json.dumps(facts))
        for index, plan in zip((2, 3), plans):
            (directory / f"outage-{index}.plan.json").write_text(json.dumps(plan))

        tables = {name: [] for name in TABLES}
        tables["operations"] = [{"key": "operation-key", "value": "encoded-receipt"}]
        tables["receipt_slots"] = [{"key": "slot-key", "value": "operation-key"}]
        payload = {"complete": True, "format": "rebase-authorized-observation-1", "tables": tables}
        envelope = {"format": "rebase-backup-1", "payload": payload}
        for name in ("outage-before", "outage-after"):
            (directory / "backend" / f"{name}.backup.json").write_text(json.dumps(envelope))
        (directory / "backend" / "outage-before.inspect.json").write_text("{}")

        inspector_records = [{"id": identity, "record": {"input": fact["fields"], "contract": fact["contract"],
            "derived": expected["derived"].get(identity), "version": f"00000000-0000-4000-8000-{index:012d}"}}
            for index, (identity, fact) in enumerate(facts.items(), 1)]
        inspector = {"codec": "native-slice-kv-7", "model": model, "store": store, "tenant": tenant,
            "actor": actor, "records": inspector_records, "roles": [], "receipt_count": 1,
            "roots": [{"root": {"id": row["owner"], "slot": row["slot"]},
                       "summary": {"value": row["summary"]}} for row in expected["roots"]]}
        (directory / "outage-after.inspect.json").write_text(json.dumps(inspector))

        trace = [{"phase": "before", "method": "records.get", "kind": "read_success",
            "http_status": 200, "started_at": 0.0, "response": {"id": "delivery", **inspector_records[1]["record"]}}]
        for index, (plan, identity) in enumerate(zip(plans, request_ids)):
            trace.append({"phase": "database_down", "method": "records.mutate", "kind": "outcome_unknown",
                "http_status": 504, "operation_id": identity, "started_at": float(index + 1), "plan": plan})
        trace.append({"phase": "database_down_after_native_deadline", "method": "records.get",
            "kind": "outcome_unknown", "http_status": 504, "started_at": 3.0})
        probe = inspector_records[1]["record"]
        trace.append({"phase": "recovering", "method": "records.get", "kind": "read_success",
            "http_status": 200, "started_at": 4.0, "response": {"id": "delivery", **probe}})
        for plan in plans:
            trace.append({"phase": "reconciled_after_drain", "plan": plan,
                "response": {"status": "not_observed"}})
        (directory / "fault-trace.jsonl").write_text("".join(json.dumps(row) + "\n" for row in trace))

        owner = {"pid": 10, "executable": "/tmp/fdbserver", "cluster_file": "/tmp/disposable.cluster",
            "data_path": "/tmp/disposable-data", "log_path": "/tmp/disposable-log", "endpoint": "127.0.0.1:4500"}
        restored = {**owner, "pid": 11}
        budgets = dict(DEFAULT_BUDGETS)
        def process(pid):
            return {"available": True, "pid": pid, "start_ticks": pid * 10, "rss_kib": 100,
                "peak_rss_kib": 100, "cpu_seconds": 0.1, "open_fds": 4, "threads": 2}
        samples = []
        for index, db_pid in enumerate((10, 11)):
            samples.append({"monotonic_seconds": float(index + 1), "observer_ms": 1.0,
                "phase": "measurement", "physical_bytes": 1000, "logical": {"public_sources": 2},
                "database_state": "running", "processes": {"application": process(20),
                "controller": process(30), "database": process(db_pid)}})
        (directory / "fault-samples.jsonl").write_text("".join(json.dumps(row) + "\n" for row in samples))
        integrity = {"status": "valid", "receipts": 1}
        image_digest = hashlib.sha256(client._bytes(payload)).hexdigest()
        complete = {"status": "passed", "table_count": 13, "image_sha256": image_digest,
            "integrity": integrity, "logical": {}}
        prefix = ["runtime", "--backend", "foundationdb", "--cluster-file", owner["cluster_file"]]
        profile = {"preflight": {"model": {"model": model}, "prefix": prefix}, "budgets": budgets}
        (directory / "profile.json").write_text(json.dumps(profile))
        (directory / "outage-profile.json").write_text(json.dumps({"execution_module_sha256": "a" * 64,
            "budgets": budgets}))
        result = {"status": "passed", "applicable": True, "backend": "foundationdb",
            "boundary": "owned local database-service stop/restart; no native commit-ack isolation",
            "execution_module_sha256": "a" * 64, "preflight": {"prefix": prefix}, "application_pid": 20,
            "same_application_pid_after_recovery": True, "service": {"before_pid": 10, "after_pid": 11,
            "ownership": owner, "restored_ownership": restored, "stopped_at": 1.0,
            "restart_requested_at": 2.0, "restart_returned_at": 2.1}, "recovery_seconds": 3.0,
            "resources": {"status": "passed"}, "database_resources": {"status": "passed"},
            "complete_images": {"before": complete, "after": complete}, "replacement_mutation_submissions": 0,
            "artifacts": {"status": "passed"}}
        result_path = directory / "outage-result.json"
        for _ in range(5):
            result_path.write_text(json.dumps(result))
            result["artifacts"] = check_artifacts(directory, budgets)
            result_path.write_text(json.dumps(result))
            if result["artifacts"] == check_artifacts(directory, budgets):
                break
        else:
            self.fail("fixture final artifact byte count did not stabilize")
        checked = g8_faults.check_outage_directory(directory)
        self.assertEqual(checked["status"], "passed", checked)
        result["artifacts"]["bytes"] += 1
        result_path.write_text(json.dumps(result))
        stale = g8_faults.check_outage_directory(directory)
        self.assertEqual(stale["status"], "failed", stale)


if __name__ == "__main__":
    unittest.main()
