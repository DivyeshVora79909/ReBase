"""Independent producer/pressure acceptance controls; no backend is mocked as proof."""
from copy import deepcopy
import itertools
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

import client
import g8_pressure as pressure
from g8_observe import DEFAULT_BUDGETS, Incomplete


def finite_result():
    profile = pressure.default_pressure_profile()
    steps = [{"pattern": pattern, "offered_rate": step["offered_per_second"], "clients": step["clients"],
              "peak_pending": step["clients"], "peak_active_clients": step["clients"], "unresolved": 0,
              "counts": {"offered": 10, "submitted": 9, "completed": 9, "producer_backpressure": 1,
                         "outcome:busy": 1, "outcome:read_success": 6, "outcome:committed": 1,
                         "outcome:stale_version": 1, "http:429": 1, "http:200": 8},
              "latency": {"max_ms": 10}, "total_drain_seconds": .01}
             for pattern in profile["patterns"] for step in profile["rate_steps"]]
    return {"status": "passed", "profile": profile, "steps": steps, "resources": {"status": "passed"},
            "bursts": [{"peak_pending": 8, "peak_active_clients": 8, "clients": 8, "unresolved": 0,
                        "counts": {"offered": 8, "submitted": 8, "completed": 8, "outcome:busy": 1,
                                   "outcome:stale_version": 6, "outcome:committed": 1, "http:429": 1, "http:200": 7},
                        "latency": {"max_ms": 10}, "total_drain_seconds": .01} for _ in range(2)],
            "receipts": {"unresolved": 0, "same_id_replay": True},
            "limits": {"all_tables_unchanged": True}, "complete_state": {"table_count": 13}}


class PressureControls(unittest.TestCase):
    def test_fixed_profiles_reject_unknown_unbounded_or_impossible_offers(self):
        default = pressure.default_pressure_profile()
        self.assertEqual(pressure.pressure_profile(), default)
        for changes in ({"surprise": 1}, {"max_pending": 1000}, {"step_seconds": float("inf")},
                        {"step_seconds": 300}, {"equipment_reservations": [1000000]}, {"slow_connections": 9}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                pressure.pressure_profile({**default, **changes})

    def test_real_thread_queue_never_enqueues_the_whole_offered_run(self):
        yielded = []
        def items():
            for number in itertools.count():
                yielded.append(number)
                yield number
        def controlled_worker(_item):
            threading.Event().wait(.02)
            return {"kind": "read_success", "http_status": 200}
        result = pressure.bounded_step(items(), controlled_worker, duration=.06, offered_rate=1000,
                                       clients=2, max_pending=3)
        self.assertLessEqual(result["peak_pending"], 3)
        self.assertLessEqual(result["peak_active_clients"], 2)
        self.assertGreater(result["counts"]["producer_backpressure"], 0)
        self.assertEqual(len(yielded), result["counts"]["submitted"])
        self.assertEqual(result["counts"]["submitted"], result["counts"]["completed"])
        self.assertEqual(result["unresolved"], 0)
        self.assertGreater(result["offering_elapsed_seconds"], 0)
        self.assertLessEqual(result["offering_elapsed_seconds"], .06 + .02)

    def test_pending_thread_failure_propagates_after_pool_cleanup(self):
        before = {thread.ident for thread in threading.enumerate()}
        def failing(_item):
            raise RuntimeError("controlled producer failure")
        with self.assertRaisesRegex(RuntimeError, "controlled producer"):
            pressure.bounded_step(itertools.repeat(None), failing, duration=.05, offered_rate=100,
                                  clients=2, max_pending=3)
        self.assertEqual({thread.ident for thread in threading.enumerate()}, before)

    def test_declared_finite_observations_can_be_checked_without_runner(self):
        self.assertEqual(pressure.check_overload(finite_result())["status"], "passed")

    def test_weighted_but_unachieved_overload_does_not_pass(self):
        result = finite_result()
        for row in result["steps"]:
            row["counts"]["outcome:busy"] = 0
            row["counts"]["outcome:stale_version"] += 1
        for row in result["bursts"]:
            row["counts"]["outcome:busy"] = 0
            row["counts"]["outcome:stale_version"] += 1
        with self.assertRaisesRegex(Incomplete, "visible overload"):
            pressure.check_overload(result)

    def test_unaccounted_queues_and_latency_excess_fail(self):
        for field in ("pending", "counts", "latency"):
            result = finite_result()
            if field == "pending":
                result["steps"][0]["peak_pending"] = 9
            elif field == "counts":
                result["steps"][0]["counts"]["completed"] -= 1
            else:
                result["steps"][0]["latency"]["max_ms"] = 20001
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                pressure.check_overload(result)

    def test_new_intent_retains_target_context_and_does_not_change_saved_template(self):
        identity = lambda value: str(uuid.UUID(int=value))
        target = {"url": "http://127.0.0.1:8080/rpc", "model": "m"*64,
                  "store": identity(1), "tenant": identity(2), "actor": identity(3)}
        commands = [{"op": "create", "id": identity(5), "contract": 101, "fields": {"value": "1"}}]
        template = {"format": client.PLAN_FORMAT, "target": target,
                    "request": {"model": "m"*64, "context": "original-context", "operation_id": identity(4),
                                "commands": commands, "returning": []}}
        before = deepcopy(template)
        new = pressure.bound_intent(template, commands)
        self.assertEqual(template, before)
        self.assertEqual(new["target"], template["target"])
        self.assertEqual(new["request"]["context"], template["request"]["context"])
        self.assertNotEqual(new["request"]["operation_id"], template["request"]["operation_id"])

    def test_eight_client_barrier_is_finite_and_all_workers_leave(self):
        before = {thread.ident for thread in threading.enumerate()}
        result = pressure.barrier_round(list(range(8)), lambda _request: {
            "kind": "read_success", "http_status": 200, "latency_ms": .1})
        self.assertEqual(result["counts"]["submitted"], 8)
        self.assertEqual(result["counts"]["completed"], 8)
        self.assertEqual(result["peak_pending"], 8)
        self.assertEqual({thread.ident for thread in threading.enumerate()}, before)

    def test_missing_matrix_or_unresolved_originals_are_incomplete(self):
        for kind in ("matrix", "original", "resource"):
            result = finite_result()
            if kind == "matrix":
                result["steps"].pop()
            elif kind == "original":
                result["receipts"]["unresolved"] = 1
            else:
                result["resources"]["status"] = "incomplete"
            with self.subTest(kind=kind), self.assertRaises(Incomplete):
                pressure.check_overload(result)

    def test_explicit_external_observer_uses_selected_cluster_and_exact_paths(self):
        state = {"preflight": {"backend": "foundationdb", "prefix": ["binary", "--cluster-file", "/external/fdb.cluster"]}}
        expected = {"pid": 123, "data": "/external/data", "logs": "/external/logs"}
        with patch("g8_pressure.database_observer", return_value=expected) as validate:
            observed = pressure.select_database_observer(state, 123, ("/external/data", "/external/logs"))
        self.assertEqual(observed, expected)
        validate.assert_called_once_with(123, Path("/external/fdb.cluster"), "/external/data", "/external/logs")
        for paths in ((), ("/external/data",), ("/external/data", "/external/logs", "/extra")):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                pressure.select_database_observer(state, 123, paths)

    def test_external_paths_cannot_silently_fall_back_to_another_helper(self):
        state = {"preflight": {"backend": "foundationdb", "prefix": ["binary", "--cluster-file", "/external/fdb.cluster"]}}
        with self.assertRaisesRegex(ValueError, "explicit owned PID"):
            pressure.select_database_observer(state, None, ("/external/data", "/external/logs"))
        with self.assertRaisesRegex(RuntimeError, "selected cluster"):
            pressure.select_database_observer(state)

    def test_excess_future_drain_fails_and_cancels_queued_work_before_cleanup(self):
        before = {thread.ident for thread in threading.enumerate()}
        dispatched = []
        def slow_worker(item):
            dispatched.append(item)
            threading.Event().wait(.04)
            return {"kind": "read_success", "http_status": 200}
        with self.assertRaisesRegex(RuntimeError, "future drain exceeded") as error:
            pressure.bounded_step(iter(range(100)), slow_worker, duration=.005, offered_rate=1000,
                                  clients=1, max_pending=3, drain_seconds=.005)
        self.assertEqual(len(dispatched), 1)
        self.assertGreater(error.exception.drain_report["queued_cancelled_before_dispatch"], 0)
        self.assertEqual(error.exception.drain_report["status"], "failed")
        self.assertEqual({thread.ident for thread in threading.enumerate()}, before)

    def test_stage_end_marker_is_skipped_by_original_receipt_reconciler(self):
        identity = lambda value: str(uuid.UUID(int=value))
        plan = {"format": client.PLAN_FORMAT,
            "target": {"url": "http://127.0.0.1:8080/rpc", "model": "m"*64,
                       "store": identity(1), "tenant": identity(2), "actor": identity(3)},
            "request": {"model": "m"*64, "context": "original-context", "operation_id": identity(4),
                        "commands": [{"op": "create", "id": identity(5), "contract": 101,
                                      "fields": {"value": "1"}}], "returning": []}}
        client._plan(plan)
        rows = [
            {"event": "stage", "stage_id": "paced:2"},
            {"event": "stage_end", "stage_id": "paced:2", "offering_elapsed_seconds": 1.0},
            {"event": "intent", "phase": "measurement", "stage_id": "paced:2", "pattern": "hot_root", "plan": plan},
            {"event": "outcome", "phase": "measurement", "stage_id": "paced:2", "pattern": "hot_root",
             "kind": "busy", "http_status": 429, "plan": plan},
        ]
        backend = type("Backend", (), {"url": plan["target"]["url"], "token": "token"})()
        state = {"backend": backend}
        with patch("g8_pressure.read_jsonl", return_value=iter(rows)), \
             patch("client.execute", return_value={"status": "not_observed"}) as execute:
            report = pressure.reconcile_pressure(state, Path("unused"), DEFAULT_BUDGETS)
        self.assertEqual(report["resolved"], 1)
        self.assertEqual(report["absent_after_quiescence"], 1)
        execute.assert_called_once_with(backend.url, backend.token, plan, status=True)

    def test_total_drain_budget_is_independently_checked(self):
        result = finite_result()
        result["steps"][0]["total_drain_seconds"] = 20.001
        with self.assertRaisesRegex(RuntimeError, "total drain budget"):
            pressure.check_overload(result)

    def test_final_report_and_summary_bytes_are_counted_after_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "summary.md").write_text("retained summary\n")
            result = {"status": "passed"}
            path = directory / "result.json"
            pressure.publish_result(path, result, directory, DEFAULT_BUDGETS)
            self.assertEqual(result["artifacts"]["bytes"], sum(p.stat().st_size for p in directory.iterdir()))
            with self.assertRaisesRegex(RuntimeError, "final artifact budget"):
                pressure.publish_result(path, result, directory, {**DEFAULT_BUDGETS, "artifacts_bytes": path.stat().st_size-1})


if __name__ == "__main__":
    unittest.main()
