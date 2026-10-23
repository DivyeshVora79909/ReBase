#!/usr/bin/env python3
"""Invoicing and settlement acceptance: source-only Fraction arithmetic over HTTP."""

import argparse
from collections import defaultdict
from copy import deepcopy
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import random
import uuid

import client
from capacity import retained_roles, snapshot
from harness import Backend, expect_error, require

MIN, MAX = -(2**127), 2**127 - 1


def checked(value):
    require(MIN <= value <= MAX, "Oracle amount exceeds i128")
    return value


def quantize(value, mode):
    # Independent standard-library operations; no Rust code or float conversion.
    if mode == "half_even":
        result = round(value)
    elif mode == "floor":
        result = math.floor(value)
    elif mode == "ceiling":
        result = math.ceil(value)
    elif mode == "toward_zero":
        result = math.trunc(value)
    elif mode == "half_away_from_zero":
        result = math.floor(abs(value) + Fraction(1, 2)) * (-1 if value < 0 else 1)
    elif mode == "exact":
        require(value.denominator == 1, "Oracle inexact result")
        result = value.numerator
    else:
        raise RuntimeError("Unknown rounding choice")
    return checked(result)


def ratio(value):
    return Fraction(int(value["numerator"]), int(value["denominator"]))


def expected(facts):
    """Derive values and complete-time histories solely from authored facts."""
    histories, derived, dates = defaultdict(list), {}, set()
    assessments = []

    def prefix(owner, slot, at):
        return checked(sum(amount for time, amount in histories[owner, slot] if time < at))

    for identity, record in facts.items():
        code, f = record["contract"], record["fields"]
        derived[identity] = None
        if code == 101:
            for slot in (7, 13, 21, 23, 29, 31):
                histories[identity, slot]
        elif code == 211:
            require(facts[f["invoice"]]["contract"] == 101, "Issue Invoice type")
            amount = quantize(ratio(f["quantity"]) * int(f["unit_price_minor"]), f["rounding"])
            require(amount >= 0, "Negative source issue")
            derived[identity] = {"amount_minor": str(amount)}
            for root in ((f["invoice"], 7), (f["invoice"], 13), (identity, 17),
                         (f["invoice"], 23), (f["invoice"], 29)):
                histories[root].append((int(f["at"]), amount))
        elif code == 307:
            issue = facts[f["issue"]]
            require(issue["contract"] == 211 and issue["fields"]["invoice"] == f["invoice"],
                    "Credit parent disagreement")
            amount = int(f["amount_minor"])
            require(amount > 0, "Credit must be positive")
            for root in ((f["invoice"], 7), (f["invoice"], 13), (f["issue"], 17),
                         (f["invoice"], 23)):
                histories[root].append((int(f["at"]), -amount))
            histories[f["invoice"], 31].append((int(f["at"]), amount))
        elif code == 401:
            require(facts[f["invoice"]]["contract"] == 101, "Rule Invoice type")
            histories[identity, 19]
        elif code == 509:
            rule = facts[f["rule"]]
            require(rule["contract"] == 401 and rule["fields"]["invoice"] == f["invoice"],
                    "Assessment parent disagreement")
            date = (f["rule"], int(f["at"]))
            require(date not in dates, "Duplicate assessment time in a rule")
            dates.add(date)
            assessments.append((int(f["at"]), identity, f))
        elif code == 601:
            histories[identity, 37]
        elif code == 821:
            # Defer shares until every authored Issue has been inspected. The
            # expectation below recomputes its basis from source fields.
            pass
        elif code in (701, 809):
            invoice, treasury = facts[f["invoice"]], facts[f["treasury"]]
            require(invoice["contract"] == 101 and treasury["contract"] == 601
                    and invoice["fields"]["currency"] == treasury["fields"]["currency"],
                    "Settlement currency disagreement")
            amount, at = int(f["amount_minor"]), int(f["at"])
            require(amount > 0, "Settlement amount must be positive")
            if code == 701:
                events = ((f["invoice"], 21, amount), (f["invoice"], 23, -amount),
                          (f["invoice"], 31, amount), (f["treasury"], 37, amount),
                          (identity, 41, amount))
            else:
                payment = facts.get(f["payment"])
                require(payment is not None and payment["contract"] == 701
                        and payment["fields"]["invoice"] == f["invoice"]
                        and payment["fields"]["treasury"] == f["treasury"],
                        "Refund payment disagreement")
                events = ((f["invoice"], 21, -amount), (f["invoice"], 23, amount),
                          (f["invoice"], 29, amount), (f["treasury"], 37, -amount),
                          (f["payment"], 41, -amount))
            for owner, slot, delta in events:
                histories[owner, slot].append((at, delta))
        else:
            raise RuntimeError("Unknown authored contract")

    for identity, record in facts.items():
        if record["contract"] != 821:
            continue
        f = record["fields"]
        parent = facts.get(f["issue"])
        require(parent is not None and parent["contract"] == 211, "Share Issue type")
        share = ratio(f["ratio"])
        require(0 <= share <= 1, "Share ratio bound")
        issue = parent["fields"]
        basis = quantize(ratio(issue["quantity"]) * int(issue["unit_price_minor"]), issue["rounding"])
        derived[identity] = {"basis_minor": str(basis),
                             "amount_minor": str(quantize(basis * share, f["rounding"]))}

    for at, identity, f in sorted(assessments):
        rule = facts[f["rule"]]["fields"]
        prior = prefix(f["rule"], 19, at)
        basis = prefix(f["invoice"], 7 if rule["kind"] == "base" else 13, at)
        if rule["kind"] == "net":
            basis = checked(basis - prior)
        assessed = quantize(basis * ratio(rule["rate"]), rule["rounding"])
        delta = checked(assessed - prior)
        derived[identity] = {"basis_minor": str(basis),
                             "prior_minor": str(prior), "assessed_minor": str(assessed),
                             "delta_minor": str(delta)}
        histories[f["invoice"], 13].append((at, delta))
        histories[f["rule"], 19].append((at, delta))
        histories[f["invoice"], 23].append((at, delta))
        histories[f["invoice"], 29].append((at, max(delta, 0)))
        histories[f["invoice"], 31].append((at, max(-delta, 0)))

    summaries = {}
    for root, events in histories.items():
        grouped = defaultdict(int)
        for at, amount in events:
            grouped[at] += amount
        total, minimum = 0, 0
        for amount in (grouped[at] for at in sorted(grouped)):
            total = checked(total + amount)
            minimum = min(minimum, total)
        require(minimum >= 0, "Negative complete-time source history")
        summaries[root] = {"count": len(events), "sum": str(total), "complete_min": str(minimum),
                           "first": str(min(grouped)) if grouped else None,
                           "last": str(max(grouped)) if grouped else None}
    return {"derived": derived, "histories": histories, "summaries": summaries}


def scan(backend, model):
    records, cursor = [], None
    for _ in range(10):
        page = backend.call("records.page", {"model": model,
            "query": {"path": "records.by_id", "contract": None, "equals": None},
            "limit": 7, "visit_budget": 32, "cursor": cursor})
        records.extend(page["records"])
        if page["exhausted"]:
            require([r["id"] for r in records] == sorted({r["id"] for r in records}),
                    "Public pagination order/uniqueness")
            return {r["id"]: r for r in records}
        require(page["cursor"] and page["cursor"] != cursor, "Pagination made no progress")
        cursor = page["cursor"]
    raise RuntimeError("Incomplete source observation")


def verify(backend, model, facts, *, boundaries=False):
    reference = expected(facts)
    records = scan(backend, model)
    require(records.keys() == facts.keys(), "Complete public source inventory")
    for identity, source in facts.items():
        observed = records[identity]
        require(observed["contract"] == source["contract"] and observed["input"] == source["fields"],
                f"Authored fields changed: {identity}")
        require(observed["derived"] == reference["derived"][identity],
                f"Source-derived calculation differs: {identity}")
    for (owner, slot), value in reference["summaries"].items():
        request = {"model": model, "owner": owner, "slot": slot, "read": {"kind": "summary"}}
        require(backend.call("roots.read", request)["value"] == value,
                f"Source-derived root differs: {owner}/{slot}")
        if boundaries:
            events = reference["histories"][owner, slot]
            times = {t + offset for t, _ in events for offset in (-1, 0, 1)}
            for at in sorted(times):
                request["read"] = {"kind": "before", "at": str(at)}
                observed = backend.call("roots.read", request)["value"]["sum"]
                require(observed == str(sum(q for t, q in events if t < at)),
                        f"Strict time boundary differs: {owner}/{slot}/{at}")
    return records, reference


def propose(facts, commands):
    result = deepcopy(facts)
    for command in commands:
        identity = command["id"]
        if command["op"] == "create":
            result[identity] = {"contract": command["contract"], "fields": deepcopy(command["fields"])}
        elif command["op"] == "update":
            result[identity]["fields"].update(deepcopy(command["set"]))
        elif command["op"] == "delete":
            del result[identity]
        else:
            raise RuntimeError("Unknown source command")
    return result


def run(binary, destination):
    backend = Backend(binary, destination, model="invoicing")
    facts, operations = {}, []
    latest = None
    try:
        backend.start()
        public = backend.call("model.describe", {})
        model = public["model"]
        require({c["code"] for c in public["contracts"]} == {101, 211, 307, 401, 509, 601, 701, 809, 821},
                "Private contracts leaked or public contracts missing")
        namespace = str(uuid.UUID(int=20261022))
        draft = backend.cli("fixture", "plan", "invoice", "--namespace", namespace)
        require(draft == backend.cli("fixture", "plan", "invoice", "--namespace", namespace),
                "Fixture was not deterministic")
        ids = draft["fixture"]["ids"]
        require(all(identity == str(uuid.uuid5(uuid.UUID(namespace), f"invoice/{label}"))
                    for label, identity in ids.items()), "Fixture UUID binding")

        def mutate(label, commands, error=None):
            nonlocal facts, latest
            before, _ = verify(backend, model, facts)
            plan = backend.plan({"model": model, "commands": commands, "returning": []}, label)
            if error:
                if error == "invariant":
                    try:
                        expected(propose(facts, commands))
                    except RuntimeError:
                        pass
                    else:
                        raise RuntimeError(f"Oracle accepted rejected history: {label}")
                raw_before = snapshot(backend, f"{label}-before")
                expect_error(error, lambda: client.execute(backend.url, backend.token, plan))
                require(snapshot(backend, f"{label}-after") == raw_before,
                        f"Rejected mutation changed application table bytes: {label}")
                after, _ = verify(backend, model, facts)
                require(after == before, "Rejected mutation changed source values/versions")
                require(client.execute(backend.url, backend.token, plan, status=True)["status"] == "not_observed",
                        "Rejected mutation retained a receipt")
            else:
                proposed = propose(facts, commands)
                expected(proposed)  # Establish expectations before submitting.
                outcome = client.execute(backend.url, backend.token, plan)
                require(outcome["status"] == "committed", "Mutation did not commit")
                facts = proposed
                verify(backend, model, facts)
                replay = client.execute(backend.url, backend.token, plan)
                require(replay["replayed"] and replay["result"] == outcome["result"], "Replay differs")
                latest = (plan, outcome)
            operations.append({"name": label, "commands": len(commands), "result": error or "committed"})

        def update(identity, fields):
            record = backend.call("records.get", {"model": model, "id": identity})
            return {"op": "update", "id": identity, "if_version": record["version"], "set": fields, "unset": []}

        def create(label, contract, fields):
            return {"op": "create", "id": str(uuid.uuid5(uuid.UUID(namespace), f"trial/{label}")),
                    "contract": contract, "fields": fields}

        def delete(identity):
            record = backend.call("records.get", {"model": model, "id": identity})
            return {"op": "delete", "id": identity, "if_version": record["version"]}

        def trial_id(label):
            return str(uuid.uuid5(uuid.UUID(namespace), f"trial/{label}"))

        mutate("baseline", draft["commands"])
        _, reference = verify(backend, model, facts, boundaries=True)
        require(reference["summaries"][ids["Invoice"], 13]["sum"] == "11555", "Literal baseline")
        mutate("credit-and-reassess", [
            create("Credit", 307, {"invoice": ids["Invoice"], "issue": ids["Issue"], "at": "50", "amount_minor": "2001"}),
            create("BaseCorrection", 509, {"invoice": ids["Invoice"], "rule": ids["BaseRule"], "at": "51"}),
            create("NetCorrection", 509, {"invoice": ids["Invoice"], "rule": ids["NetRule"], "at": "52"}),
        ])
        _, reference = verify(backend, model, facts, boundaries=True)
        require(reference["summaries"][ids["Invoice"], 13]["sum"] == "9244", "Literal corrected total")
        mutate("historical-price", [update(ids["Issue"], {"unit_price_minor": "8000"})])
        mutate("restore-price", [update(ids["Issue"], {"unit_price_minor": "6670"})])
        mutate("parent-rate", [update(ids["BaseRule"], {"rate": {"numerator": "1", "denominator": "5"}})])
        mutate("restore-rate", [update(ids["BaseRule"], {"rate": {"numerator": "1", "denominator": "10"}})])
        mutate("net-rule-kind", [update(ids["BaseRule"], {"kind": "net"})])
        mutate("restore-kind", [update(ids["BaseRule"], {"kind": "base"})])
        mutate("zero-reassessment", [create("Zero", 509, {"invoice": ids["Invoice"], "rule": ids["BaseRule"], "at": "60"})])
        # Bounded valid stress: varied historical credit boundaries, rates,
        # rounding and query topology, with shuffled final-state source updates.
        rng = random.Random(20261022)
        credit_id = str(uuid.uuid5(uuid.UUID(namespace), "trial/Credit"))
        modes = ("half_even", "floor", "ceiling", "toward_zero", "half_away_from_zero")
        for trial in range(40):
            rate = Fraction(rng.randrange(36), 100)
            quantity = rng.choice((Fraction(1), Fraction(3, 2), Fraction(4, 3)))
            commands = [
                update(ids["Issue"], {"unit_price_minor": str(rng.randrange(6000, 10001)),
                    "quantity": {"numerator": str(quantity.numerator), "denominator": str(quantity.denominator)}}),
                update(credit_id, {"at": str(rng.choice((5, 10, 11, 19, 20, 21, 49, 50, 51, 52, 53))),
                    "amount_minor": str(rng.randrange(1, 3001))}),
                update(ids["BaseRule"], {"kind": rng.choice(("base", "net")), "rounding": rng.choice(modes),
                    "rate": {"numerator": str(rate.numerator), "denominator": str(rate.denominator)}}),
            ]
            rng.shuffle(commands)
            mutate(f"source-stress-{trial:02}", commands)
        mutate("restore-literal-scenario", [
            update(ids["Issue"], {"unit_price_minor": "6670", "quantity": {"numerator": "3", "denominator": "2"}}),
            update(credit_id, {"at": "50", "amount_minor": "2001"}),
            update(ids["BaseRule"], {"kind": "base", "rate": {"numerator": "1", "denominator": "10"}, "rounding": "half_even"}),
        ])
        # Re-enter the literal history as explicit paid cash facts. Deleted
        # calculation producers retain reservations, so replacements get new IDs.
        mutate("remove-correction", [delete(trial_id(label))
                                      for label in ("Credit", "BaseCorrection", "NetCorrection", "Zero")])
        treasury, payment, refund = (trial_id(label) for label in ("Treasury", "Payment", "Refund"))
        mutate("fully-paid", [
            create("Treasury", 601, {"currency": 1, "name": "Operating cash"}),
            create("Payment", 701, {"invoice": ids["Invoice"], "treasury": treasury,
                                    "at": "30", "amount_minor": "11555"}),
        ])
        corrections = [
            create("SettledCredit", 307, {"invoice": ids["Invoice"], "issue": ids["Issue"], "at": "50", "amount_minor": "2001"}),
            create("SettledBaseCorrection", 509, {"invoice": ids["Invoice"], "rule": ids["BaseRule"], "at": "51"}),
            create("SettledNetCorrection", 509, {"invoice": ids["Invoice"], "rule": ids["NetRule"], "at": "52"}),
        ]
        refund_command = create("Refund", 809, {"invoice": ids["Invoice"], "treasury": treasury,
                                               "payment": payment, "at": "50", "amount_minor": "2311"})
        mutate("paid-credit-without-refund", corrections, "invariant")
        late = deepcopy(refund_command)
        late["fields"]["at"] = "52"
        mutate("late-refund-final-zero", [late, *corrections], "invariant")
        mutate("credit-refund-reassess", [refund_command, *reversed(corrections)])
        _, settled = verify(backend, model, facts, boundaries=True)
        literal = {"gross": "9244", "paid": "9244", "balance": "0", "receivable": "13866", "payable": "13866"}
        require({name: settled["summaries"][ids["Invoice"], slot]["sum"]
                 for slot, name in ((13, "gross"), (21, "paid"), (23, "balance"), (29, "receivable"), (31, "payable"))}
                == literal, "Literal paid/refunded invoice")
        require(settled["summaries"][treasury, 37]["sum"] == "9244"
                and settled["summaries"][payment, 41]["sum"] == "9244", "Literal cash/refund capacity")
        snapshot(backend, "before-sign-change")
        stable_roles = retained_roles(backend.directory / "before-sign-change.backup.json")
        mutate("positive-reassessment-claims", [create("ExtraIssue", 211, {"invoice": ids["Invoice"], "at": "40",
            "quantity": {"numerator": "1", "denominator": "1"}, "unit_price_minor": "3000", "rounding": "exact"})])
        _, positive = verify(backend, model, facts)
        require(positive["derived"][trial_id("SettledBaseCorrection")]["delta_minor"] == "100"
                and positive["derived"][trial_id("SettledNetCorrection")]["delta_minor"] == "55", "Claim sign reversal")
        snapshot(backend, "positive-claims")
        changed_roles = retained_roles(backend.directory / "positive-claims.backup.json")
        require(all(changed_roles.get(key) == value for key, value in stable_roles.items()), "Sign change churned existing roles")
        mutate("restore-negative-claims", [delete(trial_id("ExtraIssue"))])
        mutate("retired-producer-identity", [create("ExtraIssue", 211, {"invoice": ids["Invoice"], "at": "40",
            "quantity": {"numerator": "1", "denominator": "1"}, "unit_price_minor": "3000", "rounding": "exact"})], "unavailable_reference")
        snapshot(backend, "negative-claims")
        changed_roles = retained_roles(backend.directory / "negative-claims.backup.json")
        require(all(changed_roles.get(key) == value for key, value in stable_roles.items()), "Restored claims churned roles")
        mutate("partial-settlement", [update(payment, {"amount_minor": "10555"})])
        mutate("second-payment", [create("SecondPayment", 701, {"invoice": ids["Invoice"], "treasury": treasury,
                                                               "at": "30", "amount_minor": "1000"})])
        mutate("linked-capacity-despite-positive-cash", [create("TooMuchRefund", 809, {"invoice": ids["Invoice"],
            "treasury": treasury, "payment": trial_id("SecondPayment"), "at": "50", "amount_minor": "1001"})], "invariant")
        mutate("combine-payments", [delete(trial_id("SecondPayment")), update(payment, {"amount_minor": "11555"})])
        mutate("split-same-time-refunds", [
            create("SecondRefund", 809, {"invoice": ids["Invoice"], "treasury": treasury,
                                          "payment": payment, "at": "50", "amount_minor": "1311"}),
            update(refund, {"amount_minor": "1000"}),
        ])
        mutate("combine-refunds", [update(refund, {"amount_minor": "2311"}), delete(trial_id("SecondRefund"))])
        mutate("other-treasuries", [create("OtherCurrency", 601, {"currency": 2, "name": "Other currency"}),
                                     create("OtherCash", 601, {"currency": 1, "name": "Other cash"})])
        mutate("treasury-name", [update(treasury, {"name": "Settlement cash"})])
        mutate("currency-mismatch", [create("WrongCurrencyPayment", 701, {"invoice": ids["Invoice"],
            "treasury": trial_id("OtherCurrency"), "at": "30", "amount_minor": "1"})], "unavailable_reference")
        mutate("refund-parent-mismatch", [create("WrongTreasuryRefund", 809, {"invoice": ids["Invoice"],
            "treasury": trial_id("OtherCash"), "payment": payment, "at": "50", "amount_minor": "1"})], "unavailable_reference")
        mutate("immutable-payment-treasury", [update(payment, {"treasury": trial_id("OtherCash")})], "invalid_input")
        mutate("immutable-refund-payment", [update(refund, {"payment": str(uuid.UUID(int=999))})], "invalid_input")
        mutate("immutable-treasury-currency", [update(treasury, {"currency": 2})], "invalid_input")
        mutate("private-directional-output", [create("Private", 907, {"producer": trial_id("SettledBaseCorrection"),
            "role": 31, "target": ids["Invoice"], "at": "51", "amount": "1"})], "forbidden")
        mutate("delete-refunded-payment", [delete(payment)], "invariant")
        mutate("delete-used-treasury", [delete(treasury)], "unavailable_reference")
        mutate("payment-before-issue", [update(payment, {"at": "-1"})], "invariant")
        mutate("refund-before-payment", [update(refund, {"at": "29"})], "invariant")
        mutate("excess-payment", [update(payment, {"amount_minor": "11556"})], "invariant")
        mutate("insufficient-refund", [update(refund, {"amount_minor": "2310"})], "invariant")
        # Source-only verdicts for bounded edits across cash, price and tax.
        # All non-history constraints are valid, so rejection means invariant.
        settlement_rng = random.Random(20261023)
        settlement_results = {"committed": 0, "invariant": 0}
        for trial in range(24):
            rate = Fraction(settlement_rng.randrange(21), 100)
            commands = [
                update(ids["Issue"], {"unit_price_minor": str(settlement_rng.randrange(6000, 9001))}),
                update(ids["BaseRule"], {"rate": {"numerator": str(rate.numerator), "denominator": str(rate.denominator)}}),
                update(payment, {"at": str(settlement_rng.choice((0, 20, 30, 40))),
                                 "amount_minor": str(settlement_rng.randrange(5000, 15001))}),
                update(refund, {"at": str(settlement_rng.choice((20, 30, 40, 49, 50, 51, 52, 60))),
                                "amount_minor": str(settlement_rng.randrange(500, 8001))}),
            ]
            settlement_rng.shuffle(commands)
            try:
                expected(propose(facts, commands))
                verdict = None
            except RuntimeError:
                verdict = "invariant"
            mutate(f"settlement-stress-{trial:02}", commands, verdict)
            settlement_results[verdict or "committed"] += 1
        require(all(settlement_results.values()), "Seeded settlement edits must cover both outcomes")
        mutate("restore-settled-literal", [
            update(ids["Issue"], {"unit_price_minor": "6670"}),
            update(ids["BaseRule"], {"rate": {"numerator": "1", "denominator": "10"}}),
            update(payment, {"at": "30", "amount_minor": "11555"}),
            update(refund, {"at": "50", "amount_minor": "2311"}),
        ])
        mutate("duplicate-time", [create("Duplicate", 509, {"invoice": ids["Invoice"], "rule": ids["BaseRule"], "at": "10"})], "invariant")
        mutate("overcredit", [create("TooMuch", 307, {"invoice": ids["Invoice"], "issue": ids["Issue"], "at": "65", "amount_minor": "10006"})], "invariant")
        mutate("early-credit", [create("Early", 307, {"invoice": ids["Invoice"], "issue": ids["Issue"], "at": "-1", "amount_minor": "1"})], "invariant")
        mutate("inexact-rule", [update(ids["BaseRule"], {"rounding": "exact"})], "inexact")
        mutate("overflow-price", [update(ids["Issue"], {"unit_price_minor": str(MAX)})], "overflow")
        mutate("missing-rule", [create("Missing", 509, {"invoice": ids["Invoice"], "rule": str(uuid.UUID(int=999)), "at": "70"})], "unavailable_reference")
        mutate("fill-source-envelope", [create(f"Empty-{i}", 101, {"currency": 1}) for i in range(64 - len(facts))])
        mutate("source-overflow", [create("Overflow", 101, {"currency": 1})], "state_limit")
        verify(backend, model, facts)
        before = scan(backend, model)
        backend.stop()
        integrity = backend.cli("check", backend.store)
        backup = backend.directory / "verified-backup.json"
        backend.cli("backup", backend.store, backup)
        backend.start()
        require(scan(backend, model) == before, "Reopening changed sources")
        require(client.execute(backend.url, backend.token, latest[0])["result"] == latest[1]["result"], "Reopen replay")
        backend.crash()
        backend.start()
        verify(backend, model, facts)
        backend.stop()
        restored = backend.directory / "restored.redb"
        backend.cli("restore", backup, restored)
        backend.store = restored
        backend.start()
        verify(backend, model, facts, boundaries=True)
        require(scan(backend, model) == before, "Restore changed sources")
        require(client.execute(backend.url, backend.token, latest[0])["result"] == latest[1]["result"], "Restore replay")
        return {"status": "passed", "model": model, "public_sources": len(facts),
                "baseline_gross": "11555", "corrected_gross": "9244", "operations": operations,
                "stress_seed": 20261022, "stress_batches": 40,
                "settlement": {**literal, "cash": "9244", "refund_capacity": "9244"},
                "settlement_stress_seed": 20261023, "settlement_stress_batches": 24,
                "settlement_stress_results": settlement_results, "stable_directional_roles": True,
                "logical_bytewise_rollback": True,
                "integrity": integrity, "reopen": True, "crash_recovery": True, "restore": True,
                "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest()}
    finally:
        backend.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    report = run(args.binary, args.out)
    (args.out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
