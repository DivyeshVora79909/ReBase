#!/usr/bin/env python3
"""Literal boundary controls for the capacity probe's independent source oracle."""

import unittest

from capacity import calculation_expected, equipment_expected


def fact(code, **fields):
    return {"contract": code, "fields": fields}


class SourceOracleControls(unittest.TestCase):
    def test_equipment_strict_equal_time_and_cancelled_intervals(self):
        facts = {
            "pool": fact(101, unit=1),
            "delivery": fact(205, pool="pool", at="0", quantity="10"),
            "same_time": fact(205, pool="pool", at="10", quantity="2"),
            "a": fact(410, pool="pool", starts="10", ends="20", requested="8", active=True),
            "b": fact(410, pool="pool", starts="20", ends="30", requested="20", active=True),
            "off": fact(410, pool="pool", starts="40", ends="50", requested="20", active=False),
        }
        events, expected = equipment_expected(facts)
        self.assertEqual(expected, {
            "a": {"available_before": "10", "allocated": "8"},
            "b": {"available_before": "4", "allocated": "4"},
            "off": {"available_before": "0", "allocated": "0"},
        })
        self.assertEqual(sum(quantity for _, quantity in events["pool"]), 12)

    def test_simultaneous_allocations_reject_negative_complete_time_group(self):
        facts = {
            "pool": fact(101, unit=1),
            "supply": fact(205, pool="pool", at="0", quantity="10"),
            "a": fact(410, pool="pool", starts="10", ends="20", requested="8", active=True),
            "b": fact(410, pool="pool", starts="10", ends="30", requested="8", active=True),
        }
        with self.assertRaisesRegex(RuntimeError, "complete-time prefix"):
            equipment_expected(facts)

    def test_quote_fallback_inclusive_successor_and_retarget(self):
        facts = {
            "rule": fact(1, c="3"),
            "early": fact(3, curve="curve", at="0", rate="2"),
            "successor": fact(3, curve="curve", at="10", rate="5"),
        }
        for key, at, curve in (("before", "-1", "curve"), ("equal", "0", "curve"),
                               ("between", "9", "curve"), ("next", "10", "curve"),
                               ("other", "10", "empty")):
            facts[key] = fact(6, rule="rule", curve=curve, account="account",
                              subsidiary="subsidiary", at=at, units="2")
        derived, sums, counts = calculation_expected(facts)
        self.assertEqual(derived, {
            key: {"native_minor": "6", "reporting_minor": amount}
            for key, amount in (("before", "6"), ("equal", "12"), ("between", "12"),
                                ("next", "30"), ("other", "6"))})
        self.assertEqual(dict(sums), {("account", 2): 30, ("subsidiary", 3): 66})
        self.assertEqual(dict(counts), {("account", 2): 5, ("subsidiary", 3): 5})


if __name__ == "__main__":
    unittest.main()
