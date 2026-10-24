"""Independent negative controls for workload evidence/resource acceptance."""

import os
from pathlib import Path
import tempfile
import unittest

import g8_observe as observe


def observations(count=12):
    rows = []
    for number in range(count):
        process = {"available": True, "pid": 101, "start_ticks": 1000, "rss_kib": 1000,
                   "peak_rss_kib": 1200, "cpu_seconds": number / 10, "open_fds": 10, "threads": 2}
        rows.append({"monotonic_seconds": float(number + 1), "observer_ms": 1.0, "phase": "cooldown",
                     "processes": {"application": dict(process), "controller": {**process, "pid": 102}},
                     "physical_bytes": 1024, "logical": {"records": 4, "roles": 4, "slots": 5}})
    return rows


class ResourceChecks(unittest.TestCase):
    def check(self, rows):
        return observe.check_resources(iter(rows), dict(observe.DEFAULT_BUDGETS))

    def test_equal_inventory_windows_pass_without_claiming_a_soak(self):
        result = self.check(observations())
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["cooldown"]["growth_kib"]["application"], 0)
        self.assertEqual(result["obligations"]["database_resources"]["status"], "unsupported")

    def test_short_observation_keeps_absolute_bounds_but_no_trend_verdict(self):
        result = self.check(observations(3))
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["cooldown"]["status"], "unsupported")

    def test_changing_retained_slots_prevents_false_comparable_verdict(self):
        rows = observations()
        rows[-1]["logical"]["slots"] += 1
        self.assertEqual(self.check(rows)["cooldown"]["status"], "unsupported")

    def test_missing_observation_is_incomplete(self):
        rows = observations()
        rows[4]["processes"]["application"]["available"] = False
        result = self.check(rows)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("application", result["obligations"]["observations"]["missing_processes"])
        self.assertEqual(self.check([])["status"], "incomplete")

    def test_peak_hwm_excess_fails_even_when_current_rss_falls(self):
        rows = observations()
        rows[2]["processes"]["application"]["peak_rss_kib"] = observe.DEFAULT_BUDGETS["app_rss_kib"] + 1
        self.assertEqual(self.check(rows)["obligations"]["application_resources"]["status"], "failed")

    def test_injected_excessive_growth_rejects_intended_trend_class(self):
        rows = observations(30)
        for number, row in enumerate(rows):
            row["processes"]["application"]["rss_kib"] += number * 2000
            row["processes"]["application"]["peak_rss_kib"] += number * 2000
        result = self.check(rows)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["obligations"]["application_resources"]["status"], "passed")
        self.assertEqual(result["cooldown"]["status"], "failed")

    def test_sample_gap_and_pid_restart_do_not_pass_continuous_evidence(self):
        rows = observations()
        for row in rows[5:]:
            row["monotonic_seconds"] += 10
            row["processes"]["application"]["start_ticks"] += 1
        result = self.check(rows)
        self.assertEqual(result["obligations"]["sample_gap"]["status"], "failed")
        self.assertEqual(result["obligations"]["continuous_application_pid"]["status"], "failed")

    def test_database_observation_required_only_when_declared(self):
        result = observe.check_resources(observations(), dict(observe.DEFAULT_BUDGETS), require_database=True)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["obligations"]["database_resources"]["status"], "incomplete")

    def test_budgetless_unknown_and_nonfinite_fields_reject(self):
        for budgets in ({}, {**observe.DEFAULT_BUDGETS, "surprise": 1}, {**observe.DEFAULT_BUDGETS, "observer_ms": float("inf")}):
            with self.assertRaises(ValueError):
                observe.check_resources(observations(), budgets)

    def test_physical_and_fd_budgets_fail_their_own_obligations(self):
        rows = observations()
        rows[-1]["physical_bytes"] += observe.DEFAULT_BUDGETS["physical_growth_bytes"] + 1
        rows[-1]["processes"]["controller"]["open_fds"] = observe.DEFAULT_BUDGETS["controller_fds"] + 1
        result = self.check(rows)
        self.assertEqual(result["obligations"]["physical_growth"]["status"], "failed")
        self.assertEqual(result["obligations"]["controller_resources"]["status"], "failed")


class EvidenceChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_private_stream_exhaustion_preserves_complete_prefix_and_fails(self):
        path = self.root / "trace.jsonl"
        with observe.JsonlWriter(path, 20) as writer:
            writer.write({"a": 1})
            with self.assertRaises(observe.Incomplete):
                writer.write({"required_suffix": "larger than remaining budget"})
            self.assertEqual(writer.count, 1)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(observe.read_jsonl(path, 20, 2)), [{"a": 1}])
        with self.assertRaises(FileExistsError):
            observe.JsonlWriter(path, 20)

    def test_truncated_missing_and_oversized_streams_are_incomplete(self):
        path = self.root / "bad.jsonl"
        path.write_bytes(b'{"a":1}')
        with self.assertRaises(observe.Incomplete):
            list(observe.read_jsonl(path, 20, 2))
        path.write_bytes(b'{"a":1}\n{"b":2}\n')
        for byte_limit, row_limit in ((10, 2), (20, 1)):
            with self.assertRaises(observe.Incomplete):
                list(observe.read_jsonl(path, byte_limit, row_limit))
        with self.assertRaises(observe.Incomplete):
            list(observe.read_jsonl(self.root / "missing", 20, 2))

    def test_physical_paths_and_hardlinks_are_counted_once(self):
        directory = self.root / "data"
        directory.mkdir()
        file = directory / "store"
        file.write_bytes(b"0123456789")
        os.link(file, directory / "same-inode")
        result = observe.physical_sample((directory, file, directory))
        self.assertEqual(result["bytes"], 10)
        self.assertEqual(result["files"], 1)
        self.assertFalse(observe.physical_sample((self.root / "absent",))["available"])
        self.assertFalse(observe.physical_sample(())["available"])

    def test_owned_self_process_has_pid_identity_and_cpu(self):
        result = observe.process_sample(os.getpid())
        self.assertTrue(result["available"])
        self.assertEqual(result["pid"], os.getpid())
        self.assertGreater(result["start_ticks"], 0)
        self.assertGreaterEqual(result["cpu_seconds"], 0)
        self.assertGreater(result["open_fds"], 0)


if __name__ == "__main__":
    unittest.main()
