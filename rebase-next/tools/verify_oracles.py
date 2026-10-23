"""Independent workshop expectations from authored facts, lists and fractions.

No engine scheduler, tree cache, prepared authority graph or derived record is an
input to these functions. Small rescans deliberately favor readability.
"""
from copy import deepcopy
from fractions import Fraction
import math

from capacity import equipment_expected
from observation_reports import expected as measurement_expected


class OracleError(ValueError):
    def __init__(self, kind, message):
        self.kind = kind
        super().__init__(message)


def require(condition, kind, message):
    if not condition:
        raise OracleError(kind, message)


REFERENCES = {"pool", "instrument", "parent", "left", "right", "account"}


def stage(facts, commands):
    """Apply input edits in authored order; the caller commits only on success."""
    proposed = deepcopy(facts)
    for command in commands:
        identity, operation = command["id"], command["op"]
        if operation == "create":
            require(identity not in proposed, "already_exists", "Source already exists")
            fields = deepcopy(command["fields"])
            for field in REFERENCES & fields.keys():
                require(fields[field] in proposed, "unavailable_reference", "New parents precede children")
            proposed[identity] = {"contract": command["contract"], "fields": fields}
        elif operation == "update":
            require(identity in proposed, "not_found", "Source to update is absent")
            for field in REFERENCES & command["set"].keys():
                require(command["set"][field] in proposed, "unavailable_reference", "Retarget parent is absent")
            proposed[identity]["fields"].update(deepcopy(command["set"]))
            for field in command.get("unset", []):
                proposed[identity]["fields"].pop(field, None)
        elif operation == "delete":
            require(identity in proposed, "not_found", "Source to delete is absent")
            del proposed[identity]
        else:
            raise OracleError("invalid_request", "Unknown command")
    return proposed


def rounded(value, mode):
    if mode == "exact":
        require(value.denominator == 1, "inexact", "Exact quantity is fractional")
        return value.numerator
    if mode == "half_even":
        return round(value)
    if mode == "half_away_from_zero":
        return math.floor(abs(value) + Fraction(1, 2)) * (-1 if value < 0 else 1)
    if mode == "floor":
        return math.floor(value)
    if mode == "ceiling":
        return math.ceil(value)
    if mode == "toward_zero":
        return math.trunc(value)
    raise OracleError("invalid_request", "Unknown rounding mode")


def quantity(facts):
    require(len(facts) <= 16, "state_limit", "Quantity source limit")
    derived, pending, dependencies = {}, dict(facts), []
    for identity, row in facts.items():
        code, fields = row["contract"], row["fields"]
        require(code in (101, 205, 309), "contract", "Unknown quantity contract")
        parents = [] if code == 101 else ([fields["parent"]] if code == 205 else [fields["left"], fields["right"]])
        for parent in parents:
            require(parent in facts, "unavailable_reference", "Quantity parent missing")
        dependencies.append({"source": identity, "parents": parents,
                             "slots": [] if code == 101 else ([9] if code == 205 else [8, 3])})
    # The complete declared graph is checked before arithmetic, including zero factors.
    order, remaining = [], dict(pending)
    while remaining:
        ready = [row["source"] for row in dependencies if row["source"] in remaining
                 and all(parent not in remaining for parent in row["parents"])]
        require(ready, "feedback", "Final publication graph is cyclic")
        for identity in sorted(ready):
            order.append(identity)
            del remaining[identity]
    for identity in order:
        code, fields = facts[identity]["contract"], facts[identity]["fields"]
        if code == 101:
            value = int(fields["value"])
            require(abs(value) <= 10**18, "invalid_input", "Source quantity bound")
        elif code == 205:
            factor = fields["factor"]
            numerator, denominator = int(factor["numerator"]), int(factor["denominator"])
            require(denominator > 0 and math.gcd(numerator, denominator) == 1,
                    "invalid_request", "Canonical rational required")
            require(-(2**127) <= numerator < 2**127 and denominator < 2**127,
                    "invalid_request", "Rational components exceed i128")
            value = rounded(Fraction(int(derived[fields["parent"]]["quantity"]))
                            * Fraction(numerator, denominator), fields["rounding"])
        else:
            value = int(derived[fields["left"]]["quantity"]) + int(derived[fields["right"]]["quantity"])
        require(abs(value) <= 10**18, "overflow", "Published quantity bound")
        derived[identity] = {"quantity": str(value)}
    return {"derived": derived, "roots": [], "dependencies": dependencies}


def equipment(facts):
    dependencies = []
    for identity, row in facts.items():
        code, fields = row["contract"], row["fields"]
        require(code in (101, 205, 410), "contract", "Public equipment contract required")
        if code == 101:
            require(1 <= fields["unit"] <= 65535, "invariant", "Unit code")
            continue
        parent = facts.get(fields["pool"])
        require(parent and parent["contract"] == 101, "unavailable_reference", "Pool type/existence")
        if code == 205:
            require(int(fields["quantity"]) >= 0, "invariant", "Nonnegative delivery")
        else:
            require(int(fields["starts"]) < int(fields["ends"]) and int(fields["requested"]) >= 0,
                    "invariant", "Reservation interval/request")
            dependencies.append({"source": identity, "pool": fields["pool"], "query_slot": 31,
                "range": {"lower": None, "upper": {"excluded": fields["starts"]}},
                "active": fields["active"], "roles": [11, 29] if fields["active"] else []})
    try:
        events, values = equipment_expected(facts)
    except RuntimeError as error:
        raise OracleError("invariant", str(error)) from error
    return {"derived": {identity: values.get(identity) for identity in facts},
            "roots": [{"owner": owner, "slot": 7,
                       "summary": {"sum": str(sum(value for _, value in rows)), "count": len(rows)}}
                      for owner, rows in sorted(events.items())], "dependencies": dependencies}


def measurement(facts):
    try:
        roots, derived = measurement_expected(facts)
    except (RuntimeError, KeyError) as error:
        raise OracleError("invariant", str(error)) from error
    summaries, dependencies = [], []
    for owner, events in sorted(roots.items()):
        values = [value for _, value in events]
        summaries.append({"owner": owner, "slot": 7, "summary": {
            "count": len(values), "sum": str(sum(values)), "min": str(min(values)) if values else None,
            "max": str(max(values)) if values else None,
            "unit": facts[owner]["fields"]["unit"] if values else None}})
    for identity, row in facts.items():
        fields = row["fields"]
        if row["contract"] in (307, 419):
            dependencies.append({"source": identity, "instrument": fields["instrument"],
                "query_slot": 31 if row["contract"] == 307 else 43,
                "range": fields["range"] if row["contract"] == 307 else {
                    "lower": None, "upper": {"included": fields["at"]}}})
    return {"derived": derived, "roots": summaries, "dependencies": dependencies}


def evaluate(model, facts):
    if model == "equipment":
        return equipment(facts)
    if model == "measurement":
        return measurement(facts)
    if model == "quantity":
        return quantity(facts)
    raise ValueError("No source oracle for " + model)
