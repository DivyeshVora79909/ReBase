#!/usr/bin/env python3
"""Independent G7 schedule specification; never substitutes for backend tests.

The model implements the required protection rule directly: a changed fact
between an attempt's selected snapshot and commit invalidates its decision.
It uses ordinary dictionary images, independent of engine keys and adapters.
"""
from __future__ import annotations

import copy
import hashlib
import json

TABLES = ("records", "indexes", "receipts", "roots", "references", "authority")


class Store:
    def __init__(self):
        self.tables = {name: {} for name in TABLES}
        self.changes = []

    def begin(self):
        return Attempt(self, len(self.changes), copy.deepcopy(self.tables))


class Attempt:
    def __init__(self, store, version, snapshot):
        self.store, self.version, self.snapshot = store, version, snapshot
        self.points, self.ranges, self.writes = set(), [], {}

    def get(self, table, key):
        self.points.add((table, key))
        return self.writes.get((table, key), self.snapshot[table].get(key))

    def scan(self, table, lower, upper):
        self.ranges.append((table, lower, upper))
        rows = self.snapshot[table].copy()
        for (space, key), value in self.writes.items():
            if space == table:
                if value is None:
                    rows.pop(key, None)
                else:
                    rows[key] = value
        return {key: value for key, value in sorted(rows.items()) if lower <= key < upper}

    def put(self, table, key, value):
        # The portable put operation observes its previous value.
        self.get(table, key)
        self.writes[table, key] = value

    def commit(self):
        changed = self.store.changes[self.version:]
        if any(
            (table, key) in self.points
            or any(space == table and lower <= key < upper for space, lower, upper in self.ranges)
            for table, key in changed
        ):
            return "transaction_conflict"
        for (table, key), value in self.writes.items():
            if value is None:
                self.store.tables[table].pop(key, None)
            else:
                self.store.tables[table][key] = value
            self.store.changes.append((table, key))
        return "committed"


def base():
    store = Store()
    initial = store.begin()
    initial.put("records", "parent", "present")
    initial.put("roots", "balance", 10)
    initial.put("authority", "actor", "allowed")
    assert initial.commit() == "committed"
    return store


def stale_rows(attempt):
    for table in TABLES:
        attempt.put(table, "loser-operation", "must-not-publish")


def observation(store, name, outcome, protection):
    tables = copy.deepcopy(store.tables)
    return {"name": name, "expected_outcome": outcome,
            "expected_attempt_receipt": "loser-operation" in tables["receipts"],
            "protection": protection, "expected_complete_tables": tables}


def conflict_case(name, observe, winner, protection):
    store = base()
    first = store.begin()
    observe(first)
    second = store.begin()
    winner(second)
    second.put("receipts", "winner-operation", "committed")
    assert second.commit() == "committed"
    accepted = copy.deepcopy(store.tables)
    stale_rows(first)
    outcome = first.commit()
    assert outcome == "transaction_conflict"
    assert store.tables == accepted
    assert "loser-operation" not in store.tables["receipts"]
    return observation(store, name, outcome, protection)


def run():
    cases = []
    cases.append(conflict_case("absent-uniqueness", lambda t: t.get("records", "absent"),
        lambda t: t.put("records", "absent", "created"), "exact absent key"))
    cases.append(conflict_case("empty-range-insertion", lambda t: t.scan("references", "child/", "child0"),
        lambda t: t.put("references", "child/1", "parent"), "half-open empty reverse range"))
    cases.append(conflict_case("range-deletion", lambda t: t.scan("records", "parent", "parent0"),
        lambda t: t.put("records", "parent", None), "half-open populated range"))
    cases.append(conflict_case("root-invariant", lambda t: t.get("roots", "balance"),
        lambda t: t.put("roots", "balance", 7), "business-root tracked value"))
    cases.append(conflict_case("no-op-guard", lambda t: t.put("roots", "balance", 10),
        lambda t: t.put("roots", "balance", 6), "read protection retained for unchanged writes"))
    cases.append(conflict_case("protected-put", lambda t: t.put("roots", "balance", 11),
        lambda t: t.put("roots", "balance", 12), "put observes prior value"))
    cases.append(conflict_case("reference-target-deletion", lambda t: t.get("records", "parent"),
        lambda t: t.put("records", "parent", None), "exact referenced target"))
    cases.append(conflict_case("authority-revocation", lambda t: t.get("authority", "actor"),
        lambda t: t.put("authority", "actor", "revoked"), "actor scope/credential state"))

    store = base()
    first, second = store.begin(), store.begin()
    first.put("records", "root-a", "a")
    second.put("records", "root-b", "b")
    assert first.commit() == second.commit() == "committed"
    cases.append(observation(store, "disjoint-points", "both_committed", "no shared protected fact"))

    store = base()
    snapshot = store.begin()
    change = store.begin()
    change.put("authority", "actor", "revoked")
    assert change.commit() == "committed"
    assert snapshot.get("authority", "actor") == "allowed"
    cases.append(observation(store, "snapshot-authorized-read", "snapshot_allowed", "selected snapshot authority"))

    store = base()
    prior = copy.deepcopy(store.tables)
    dropped = store.begin()
    stale_rows(dropped)
    assert store.tables == prior
    cases.append(observation(store, "partial-write-abort", "aborted", "one atomic publication"))

    original_id = "original-operation"
    committed = store.begin()
    committed.put("records", "accepted", "result")
    committed.put("receipts", original_id, "result")
    assert committed.commit() == "committed"
    cases.append({"name": "lost-commit-response", "expected_outcome": "outcome_unknown",
        "original_operation_id": original_id, "replacement_operation_id": None,
        "expected_attempt_receipt": True, "expected_complete_tables": copy.deepcopy(store.tables)})
    reconciled = store.begin().get("receipts", original_id)
    assert reconciled == "result"
    cases.append({"name": "same-id-reconciliation", "expected_outcome": "committed",
        "original_operation_id": original_id, "replacement_operation_id": None,
        "expected_attempt_receipt": True, "expected_complete_tables": copy.deepcopy(store.tables)})

    payload = {"status": "passed", "kind": "independent-specification-oracle",
        "scope": "expected dictionary images only; real backend conformance must run separately",
        "table_families": TABLES, "cases": cases}
    payload["oracle_sha256"] = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return payload


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
