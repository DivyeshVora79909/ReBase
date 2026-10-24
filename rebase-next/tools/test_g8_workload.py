"""Preflight and independently consumable acceptance controls for G8."""
from copy import deepcopy
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

import g8_workload as workload
from g8_observe import Incomplete, JsonlWriter


class ProfileControls(unittest.TestCase):
    def test_default_epoch_has_real_receipt_room_and_coverage(self):
        settings = workload.profile()
        self.assertEqual(settings["label"], "default-300-second")
        self.assertLess(sum(settings["receipt_preflight"].values()), 1024)
        counts = {name: 0 for name in settings["floors"]}
        actions = workload.scheduled_actions(settings["floors"], random.Random(8042))
        for _ in range(340):
            counts[next(actions)] += 1
        for name in counts.keys() - {"read"}:
            self.assertGreaterEqual(counts[name], settings["floors"][name])

    def test_invalid_unknown_unbounded_and_infeasible_shapes_reject(self):
        for change in ({"unknown": 1}, {"mutation_rate": float("inf")}, {"duration_seconds": 1},
                       {"max_pending": 0}, {"identity_pool": 65}, {"readers": 3},
                       {"duration_seconds": 900}, {"warmup_seconds": 300}, {"budgets": {}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                workload.profile(**change)

    def test_zero_weight_is_not_achieved_coverage(self):
        floors = dict(workload.FLOORS, delete=0)
        with self.assertRaises(ValueError):
            workload.profile(floors=floors)

    def test_missing_binary_backend_sdk_preflight_fails_clearly(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary"
            binary.write_text("#!/bin/sh\nexit 1\n")
            binary.chmod(0o700)
            with self.assertRaisesRegex(ValueError, "Unsupported backend"):
                workload.preflight(binary, "missing")
            with self.assertRaisesRegex(ValueError, "explicit cluster"):
                workload.preflight(binary, "foundationdb")
            with self.assertRaisesRegex(ValueError, "Backend/native-library"):
                workload.preflight(binary)
            with patch("g8_workload.shutil.which", return_value=None), self.assertRaisesRegex(ValueError, "OpenSSL"):
                workload.preflight(binary)

    def test_bad_observations_cannot_pass_independent_result_check(self):
        result = {"status": "passed", "work": {"unresolved": 0}, "resources": {"status": "passed"},
                  "coverage": {"requested": dict(workload.SMOKE_FLOORS), "achieved": dict(workload.SMOKE_FLOORS)}}
        self.assertEqual(workload.check(result)["status"], "passed")
        for change in ("unresolved", "resources", "coverage"):
            bad = deepcopy(result)
            if change == "unresolved":
                bad["work"]["unresolved"] = 1
            elif change == "resources":
                bad["resources"]["status"] = "incomplete"
            else:
                del bad["coverage"]["achieved"]["delete"]
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                workload.check(bad)

    def test_missing_original_outcome_cannot_be_silently_discarded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            with JsonlWriter(path, 1024) as output:
                output.write({"event": "intent", "plan": {"request": "original"}})
            with self.assertRaises(Incomplete):
                list(workload.trace_outcomes(path, workload.DEFAULT_BUDGETS))

    def test_replaced_original_plan_cannot_reconcile_as_the_original(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.jsonl"
            with JsonlWriter(path, 1024) as output:
                output.write({"event": "intent", "plan": {"context": "original"}})
                output.write({"event": "outcome", "action": "create", "plan": {"context": "refreshed"}})
            with self.assertRaises(Incomplete):
                list(workload.trace_outcomes(path, workload.DEFAULT_BUDGETS))


if __name__ == "__main__":
    unittest.main()
