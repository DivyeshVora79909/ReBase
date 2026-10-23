"""Source-only negative controls for the walkthrough expectations."""
import unittest
from unittest.mock import Mock, patch

from verify_runtime import Mismatch, Scenario
from verify_oracles import OracleError, evaluate, stage


class WalkOracleTests(unittest.TestCase):
    @staticmethod
    def public_scenario(records):
        scenario = Scenario.__new__(Scenario)
        scenario.selector = "quantity"
        scenario.model = "quantity-model"
        scenario.facts = {"source": {"contract": 101, "fields": {"value": "12"}}}
        scenario.backend = Mock()
        with patch("verify_runtime.scan", return_value=records):
            scenario.public()

    @staticmethod
    def source_record(identity="source", derived=None):
        return {"id": identity, "contract": 101, "input": {"value": "12"},
                "derived": derived if derived is not None else {"quantity": "12"}}

    def test_public_comparison_rejects_wrong_value(self):
        with self.assertRaises(Mismatch) as error:
            self.public_scenario([self.source_record(derived={"quantity": "13"})])
        self.assertEqual(error.exception.kind, "public.derived")

    def test_public_comparison_rejects_missing_and_extra_rows(self):
        with self.subTest("missing"):
            with self.assertRaises(Mismatch) as error:
                self.public_scenario([])
            self.assertEqual(error.exception.kind, "public.inventory")
        with self.subTest("extra"):
            with self.assertRaises(Mismatch) as error:
                self.public_scenario([self.source_record(), self.source_record("unexpected")])
            self.assertEqual(error.exception.kind, "public.inventory")

    def test_quantity_literal_and_exact_rejection(self):
        facts = {
            "s": {"contract": 101, "fields": {"value": "12"}},
            "l": {"contract": 205, "fields": {"parent": "s", "factor": {"numerator": "1", "denominator": "2"}, "rounding": "exact"}},
            "r": {"contract": 205, "fields": {"parent": "s", "factor": {"numerator": "1", "denominator": "3"}, "rounding": "exact"}},
            "j": {"contract": 309, "fields": {"left": "l", "right": "r"}},
        }
        self.assertEqual({key: row["quantity"] for key, row in evaluate("quantity", facts)["derived"].items()},
                         {"s": "12", "l": "6", "r": "4", "j": "10"})
        changed = stage(facts, [{"op": "update", "id": "s", "set": {"value": "13"}}])
        with self.assertRaises(OracleError) as error:
            evaluate("quantity", changed)
        self.assertEqual(error.exception.kind, "inexact")
        self.assertEqual(facts["s"]["fields"]["value"], "12")

    def test_cycle_is_rejected_even_with_zero_factor(self):
        facts = {
            "s": {"contract": 101, "fields": {"value": "12"}},
            "l": {"contract": 205, "fields": {"parent": "s", "factor": {"numerator": "0", "denominator": "1"}, "rounding": "exact"}},
            "j": {"contract": 309, "fields": {"left": "l", "right": "s"}},
        }
        final = stage(facts, [{"op": "update", "id": "l", "set": {"parent": "j"}}])
        with self.assertRaises(OracleError) as error:
            evaluate("quantity", final)
        self.assertEqual(error.exception.kind, "feedback")

    def test_quantity_distinguishes_input_state_and_publication_bounds(self):
        too_many = {str(index): {"contract": 101, "fields": {"value": "0"}}
                    for index in range(17)}
        with self.assertRaises(OracleError) as error:
            evaluate("quantity", too_many)
        self.assertEqual(error.exception.kind, "state_limit")

        source_out_of_range = {"s": {"contract": 101, "fields": {"value": str(10**18 + 1)}}}
        with self.assertRaises(OracleError) as error:
            evaluate("quantity", source_out_of_range)
        self.assertEqual(error.exception.kind, "invalid_input")

        published_out_of_range = {
            "s": {"contract": 101, "fields": {"value": str(10**18)}},
            "l": {"contract": 205, "fields": {"parent": "s", "factor": {"numerator": "2", "denominator": "1"}, "rounding": "exact"}},
        }
        with self.assertRaises(OracleError) as error:
            evaluate("quantity", published_out_of_range)
        self.assertEqual(error.exception.kind, "overflow")

    def test_equipment_complete_time_history_rejects_same_time_overbooking(self):
        facts = {
            "p": {"contract": 101, "fields": {"unit": 7}},
            "d": {"contract": 205, "fields": {"pool": "p", "at": "0", "quantity": "10"}},
            "a": {"contract": 410, "fields": {"pool": "p", "starts": "10", "ends": "30", "requested": "8", "active": True}},
            "b": {"contract": 410, "fields": {"pool": "p", "starts": "20", "ends": "40", "requested": "7", "active": True}},
        }
        with self.assertRaises(OracleError) as error:
            evaluate("equipment", {**facts, "c": {"contract": 410, "fields": {
                "pool": "p", "starts": "10", "ends": "15", "requested": "3", "active": True}}})
        self.assertEqual(error.exception.kind, "invariant")


if __name__ == "__main__":
    unittest.main()
