"""Pure standard-library controls for bounded trace reduction."""
import unittest
from pathlib import Path
import tempfile
from unittest.mock import patch

from verify_explore import _check_model_compatibility, _failure_class_replay, _profile, explore, minimize
from verify_oracles import evaluate
from verify_runtime import Mismatch, equal


class MinimizeTests(unittest.TestCase):
    def test_reduces_known_comparator_fault_without_changing_failure_class(self):
        trace = [
            {"op": "source", "id": "s", "value": "12"},
            {"op": "source", "id": "unused", "value": "6"},
            {"op": "scale", "id": "left", "parent": "s", "numerator": "1", "denominator": "2"},
            {"op": "irrelevant", "id": "tail"},
        ]

        def injected_comparator(candidate):
            facts = {}
            try:
                for row in candidate:
                    if row["op"] == "source":
                        facts[row["id"]] = {"contract": 101, "fields": {"value": row["value"]}}
                    elif row["op"] == "scale":
                        facts[row["id"]] = {"contract": 205, "fields": {
                            "parent": row["parent"], "factor": {"numerator": row["numerator"],
                            "denominator": row["denominator"]}, "rounding": "exact"}}
                expected = evaluate("quantity", facts)["derived"]["left"]["quantity"]
                # Deliberate comparator defect: expected=6 is incorrectly
                # compared with an injected observation of 5.
                equal("quantity.expected", expected, "5")
            except Mismatch as error:
                return error.kind
            except (KeyError, ValueError):
                return False
            return False

        result = minimize(trace, injected_comparator, budget=64)
        self.assertEqual(result, [trace[0], trace[2]])
        self.assertEqual(injected_comparator(result), "quantity.expected")

    def test_does_not_shrink_to_a_different_failure_class(self):
        trace = ["precondition", "trigger", "other-error"]

        def predicate(candidate):
            if "precondition" in candidate and "trigger" in candidate:
                return "wrong_quantity"
            if "other-error" in candidate:
                return "stale_version"
            return False

        self.assertEqual(minimize(trace, predicate), ["precondition", "trigger"])

    def test_budget_bounds_candidate_replays(self):
        calls = []

        def predicate(candidate):
            calls.append(candidate)
            return "failure" if "keep" in candidate else False

        minimize(["keep", "a", "b", "c", "d"], predicate, budget=3)
        self.assertLessEqual(len(calls), 4)  # Initial classification plus budget.

    def test_initial_nonfailure_is_returned_unchanged(self):
        trace = ["a", "b"]
        result = minimize(trace, lambda _: False)
        self.assertEqual(result, trace)
        self.assertIsNot(result, trace)

    def test_failure_replay_returns_failure_kind_for_minimizer(self):
        class FakeScenario:
            def __init__(self, kind):
                self.kind = kind

            def update(self, identity, fields):
                return {"identity": identity, "fields": fields}

            def mutate(self, *args, **kwargs):
                raise Mismatch(self.kind, "expected", "observed")

            def close(self):
                pass

        action = {"kind": "cycle", "ids": {"target": "old", "parent": "old"}}
        with tempfile.TemporaryDirectory() as directory:
            with patch("verify_explore.Scenario", return_value=FakeScenario("feedback")), \
                    patch("verify_explore._fixture", return_value=({"source": "new"}, {})):
                self.assertEqual(_failure_class_replay("unused", Path(directory), {"source": "old"},
                                                        [action], "feedback"), "feedback")
            with patch("verify_explore.Scenario", return_value=FakeScenario("inexact")), \
                    patch("verify_explore._fixture", return_value=({"source": "new"}, {})):
                self.assertFalse(_failure_class_replay("unused", Path(directory), {"source": "old"},
                                                       [action], "feedback"))

    def test_replay_refuses_an_artifact_for_another_model(self):
        with self.assertRaisesRegex(ValueError, "does not match fresh Quantity model"):
            _check_model_compatibility({"model": "other"}, "quantity-v1")
        _check_model_compatibility({"model": "quantity-v1"}, "quantity-v1")

    def test_explore_cleanup_when_fixture_setup_fails(self):
        class FakeScenario:
            model = "quantity-v1"
            catalog = {"model": "quantity-v1"}
            namespace = "namespace"

            def close(self):
                self.closed = True

        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary"
            binary.write_bytes(b"binary")
            destination = Path(directory) / "run"
            fake = FakeScenario()
            with patch("verify_explore.Scenario", return_value=fake), \
                    patch("verify_explore._fixture", side_effect=RuntimeError("fixture setup failed")):
                with self.assertRaisesRegex(RuntimeError, "fixture setup failed"):
                    explore(binary, destination, seed=1, steps=0)
            self.assertTrue(fake.closed)
            self.assertTrue((destination / "failure.original.json").is_file())

    def test_oracle_failure_does_not_reuse_previous_step_plan(self):
        class FakeScenario:
            model = "quantity-v1"
            catalog = {"model": "quantity-v1"}
            namespace = "namespace"
            steps = [{"name": "Q0", "plan": {"request": {"operation_id": "seed"}}}]

            def close(self):
                pass

            def mutate(self, *args, **kwargs):
                raise Mismatch("oracle.unexpected_rejection", "committed", "inexact")

        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary"
            binary.write_bytes(b"binary")
            destination = Path(directory) / "run"
            with patch("verify_explore.Scenario", return_value=FakeScenario()), \
                    patch("verify_explore._fixture", return_value=({"source": "id"}, {"commands": []})), \
                    patch("verify_explore._action", return_value={"kind": "source_update", "value": "6", "commands": []}), \
                    patch("verify_explore._failure_class_replay", return_value=False):
                with self.assertRaises(Mismatch):
                    explore(binary, destination, seed=1, steps=1)
            import json
            failure = json.loads((destination / "failure.original.json").read_text())
            self.assertNotIn("plan", failure["actions"][0])
            self.assertEqual(failure["exact_plans"], [{"request": {"operation_id": "seed"}}])

    def test_profile_does_not_claim_native_checks_were_run(self):
        profile = _profile(3, 2, None)
        self.assertIn("not executed by this mode", profile["coverage_note"])


if __name__ == "__main__":
    unittest.main()
