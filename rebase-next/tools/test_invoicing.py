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


def settled_scenario():
    facts = scenario()
    facts.update({
        "treasury": source(601, currency=1, name="Operating cash"),
        "payment": source(701, invoice="invoice", treasury="treasury", at="30", amount_minor="11555"),
    })
    return facts


def refund_scenario():
    facts = settled_scenario()
    facts.update({
        "credit": source(307, invoice="invoice", issue="issue", at="50", amount_minor="2001"),
        "refund": source(809, invoice="invoice", treasury="treasury", payment="payment", at="50", amount_minor="2311"),
        "base-correction": source(509, invoice="invoice", rule="base", at="51"),
        "net-correction": source(509, invoice="invoice", rule="net", at="52"),
    })
    return facts


class SourceOracleTests(unittest.TestCase):
    def test_share_uses_authored_parent_in_any_source_order(self):
        facts = scenario()
        facts["issue"]["fields"]["unit_price_minor"] = "10001"
        share = source(821, issue="issue", ratio={"numerator":"1", "denominator":"3"}, rounding="half_even")
        facts = {"share":share, **facts}
        result = expected(facts)
        self.assertEqual(result["derived"]["share"], {"basis_minor":"15002", "amount_minor":"5001"})
        facts["issue"]["fields"]["quantity"] = {"numerator":"2", "denominator":"1"}
        self.assertEqual(expected(facts)["derived"]["share"], {"basis_minor":"20002", "amount_minor":"6667"})
        facts["share"]["fields"]["ratio"] = {"numerator":"0", "denominator":"1"}
        self.assertEqual(expected(facts)["derived"]["share"], {"basis_minor":"20002", "amount_minor":"0"})
        facts["share"]["fields"]["issue"] = "invoice"
        with self.assertRaises(RuntimeError):
            expected(facts)

    def test_share_inexact_and_outside_ratio_reject(self):
        for numerator, denominator, mode in [("1", "2", "exact"), ("2", "1", "half_even"), ("-1", "1", "half_even")]:
            facts = scenario()
            facts["share"] = source(821, issue="issue", ratio={"numerator":numerator, "denominator":denominator}, rounding=mode)
            with self.assertRaises(RuntimeError):
                expected(facts)

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

    def test_settlement_refund_and_directional_claims_are_distinct(self):
        paid = expected(settled_scenario())
        self.assertEqual(paid["summaries"]["invoice", 23]["sum"], "0")
        reference = expected(refund_scenario())
        for root in (("invoice", 13), ("invoice", 21), ("treasury", 37), ("payment", 41)):
            self.assertEqual(reference["summaries"][root]["sum"], "9244")
        for slot, amount in ((23, "0"), (29, "13866"), (31, "13866")):
            self.assertEqual(reference["summaries"]["invoice", slot]["sum"], amount)
        history = reference["histories"]["invoice", 23]
        for at, amount in ((30, 0), (50, 310), (51, 110), (52, 0)):
            self.assertEqual(sum(value for time, value in history if time <= at), amount)
        # Independent complete-time identity for every authored boundary.
        for at in sorted({time for events in reference["histories"].values() for time, _ in events}):
            totals = {slot: sum(value for time, value in reference["histories"]["invoice", slot] if time <= at)
                      for slot in (13, 21, 23, 29, 31)}
            self.assertEqual(totals[23], totals[13] - totals[21])
            self.assertEqual(totals[23], totals[29] - totals[31])

    def test_credit_without_refund_and_late_refund_reject_historical_balance(self):
        for change in ("missing", "late", "short"):
            facts = refund_scenario()
            if change == "missing":
                del facts["refund"]
            elif change == "late":
                facts["refund"]["fields"]["at"] = "52"
            else:
                facts["refund"]["fields"]["amount_minor"] = "2310"
            with self.assertRaises(RuntimeError):
                expected(facts)

    def test_refund_capacity_is_per_payment_and_complete_timestamp(self):
        facts = settled_scenario()
        facts["payment"]["fields"]["amount_minor"] = "1000"
        facts["another-payment"] = source(701, invoice="invoice", treasury="treasury", at="30", amount_minor="1000")
        facts["refund"] = source(809, invoice="invoice", treasury="treasury", payment="payment", at="31", amount_minor="1001")
        # Overall paid/cash remain positive; the linked payment is overrefunded.
        with self.assertRaises(RuntimeError):
            expected(facts)
        facts["refund"]["fields"].update(amount_minor="1000", at="30")
        self.assertEqual(expected(facts)["summaries"]["payment", 41]["sum"], "0")
        facts["refund"]["fields"]["at"] = "29"
        with self.assertRaises(RuntimeError):
            expected(facts)

    def test_currency_and_refund_parent_agreement(self):
        facts = refund_scenario()
        facts["treasury"]["fields"]["currency"] = 2
        with self.assertRaises(RuntimeError):
            expected(facts)
        facts = refund_scenario()
        facts["other"] = source(601, currency=1, name="Other cash")
        facts["refund"]["fields"]["treasury"] = "other"
        with self.assertRaises(RuntimeError):
            expected(facts)

    def test_assessment_changes_direction_without_netting_claims(self):
        facts = refund_scenario()
        facts["more"] = source(211, invoice="invoice", at="40", quantity={"numerator":"1", "denominator":"1"},
                               unit_price_minor="3000", rounding="exact")
        result = expected(facts)
        self.assertEqual(result["derived"]["base-correction"]["delta_minor"], "100")
        self.assertEqual(result["derived"]["net-correction"]["delta_minor"], "55")
        for slot, amount in ((13, "12709"), (21, "9244"), (23, "3465"), (29, "17021"), (31, "13556")):
            self.assertEqual(result["summaries"]["invoice", slot]["sum"], amount)


if __name__ == "__main__":
    unittest.main()
