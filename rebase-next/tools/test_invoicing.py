#!/usr/bin/env python3
"""Literal controls of the independent invoicing source oracle."""
from copy import deepcopy
import unittest

from invoicing import expected


def source(code, **fields):
    return {"contract": code, "fields": fields}


def scenario():
    return {
        "invoice": source(101, currency=1),
        "issue": source(211, invoice="invoice", at="0", quantity={"numerator": "3", "denominator": "2"},
                        unit_price_minor="6670", rounding="half_even"),
        "base": source(401, invoice="invoice", kind="base", rate={"numerator": "1", "denominator": "10"}, rounding="half_even"),
        "net": source(401, invoice="invoice", kind="net", rate={"numerator": "1", "denominator": "20"}, rounding="half_even"),
        "base-tax": source(509, invoice="invoice", rule="base", at="10"),
        "net-tax": source(509, invoice="invoice", rule="net", at="20"),
    }


class SourceOracleTests(unittest.TestCase):
    def test_literal_tax_on_tax_and_later_corrections(self):
        facts = scenario()
        first = expected(facts)
        self.assertEqual(first["derived"]["base-tax"]["delta_minor"], "1000")
        self.assertEqual(first["derived"]["net-tax"]["delta_minor"], "550")
        self.assertEqual(first["summaries"]["invoice", 13]["sum"], "11555")
        facts.update({
            "credit": source(307, invoice="invoice", issue="issue", at="50", amount_minor="2001"),
            "base-correction": source(509, invoice="invoice", rule="base", at="51"),
            "net-correction": source(509, invoice="invoice", rule="net", at="52"),
        })
        corrected = expected(facts)
        self.assertEqual(corrected["derived"]["base-correction"]["delta_minor"], "-200")
        self.assertEqual(corrected["derived"]["net-correction"]["delta_minor"], "-110")
        self.assertEqual(corrected["summaries"]["invoice", 13]["sum"], "9244")

    def test_net_reassessment_excludes_its_own_previous_tax(self):
        facts = scenario()
        facts["net-again"] = source(509, invoice="invoice", rule="net", at="21")
        result = expected(facts)
        self.assertEqual(result["derived"]["net-again"]["basis_minor"], "11005")
        self.assertEqual(result["derived"]["net-again"]["delta_minor"], "0")
        self.assertEqual(result["summaries"]["net", 19]["count"], 2)

    def test_complete_time_credit_floor_and_duplicate_rule_dates_reject(self):
        for amount, at in [("10006", "50"), ("1", "-1")]:
            facts = scenario()
            facts["credit"] = source(307, invoice="invoice", issue="issue", at=at, amount_minor=amount)
            with self.assertRaises(RuntimeError):
                expected(facts)
        facts = scenario()
        facts["duplicate"] = deepcopy(facts["base-tax"])
        with self.assertRaises(RuntimeError):
            expected(facts)

    def test_simultaneous_time_is_excluded_from_every_before_read(self):
        facts = scenario()
        facts["base-tax"]["fields"]["at"] = "0"
        result = expected(facts)
        self.assertEqual(result["derived"]["base-tax"]["basis_minor"], "0")
        self.assertEqual(result["derived"]["base-tax"]["delta_minor"], "0")
        self.assertEqual(result["derived"]["net-tax"]["delta_minor"], "500")


if __name__ == "__main__":
    unittest.main()
