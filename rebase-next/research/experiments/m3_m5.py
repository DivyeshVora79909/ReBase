#!/usr/bin/env python3
"""Bounded M3/M5 contract experiment; no runtime, persistence or repository imports.

Five fixed calculation steps at most. Compare a grouped source scan and literal
expectations with every permitted evaluation order. Logical output pairs stand
for reserved UUIDs; the experiment does not implement their allocation.
"""

from copy import deepcopy
from dataclasses import asdict, dataclass, replace
import hashlib
from itertools import permutations
import json


@dataclass(frozen=True)
class Reader:
    account: str
    at: int
    target: int
    post: bool = True


BASE = {"P": Reader("A", 10, 20), "Q": Reader("A", 20, 30)}
# Occurrence: (source, member slot, root, time, exact amount).
SEEDS = [("seed-A", "history", "A", 0, 10), ("seed-B", "history", "B", 0, 4)]
ROOTS = ("A", "B", "left", "right", "final")


def output_shape(facts, feedback=False):
    # Output identity -> (producer, root, time). This consumes authored facts only.
    roles = {
        f"{name}/post": (name, row.account, row.at)
        for name, row in facts.items() if row.post
    }
    roles.update({"L/post": ("L", "left", 40), "R/post": ("R", "right", 40),
                  "J/post": ("J", "final", 40)})
    if feedback:
        roles["J/feedback"] = ("J", "A", 5)
    return roles


def query_shape(facts):
    # Query identity -> (consumer, source root, exclusive time bound, phase).
    queries = {}
    for name, row in facts.items():
        queries[f"{name}/q_before"] = (name, row.account, row.at, "calculate")
        queries[f"{name}/q_guard"] = (name, row.account, row.at, "validate")
    queries.update({"L/q_A": ("L", "A", None, "calculate"),
                    "R/q_A": ("R", "A", None, "calculate"),
                    "J/q_left": ("J", "left", None, "calculate"),
                    "J/q_right": ("J", "right", None, "calculate")})
    return queries


def graph(facts, feedback=False):
    incoming = {name: set() for name in (*facts, "L", "R", "J")}
    for consumer, root, upper, phase in query_shape(facts).values():
        if phase == "validate":
            continue
        for producer, destination, at in output_shape(facts, feedback).values():
            if destination == root and (upper is None or at < upper):
                incoming[consumer].add(producer)
    return incoming


def valid_orders(incoming):
    # At most 5! = 120 candidates. This is enumeration, not a runtime scheduler.
    result = []
    for order in permutations(incoming):
        position = {name: i for i, name in enumerate(order)}
        if all(position[parent] < position[child]
               for child, parents in incoming.items() for parent in parents):
            result.append(order)
    return result


def read(members, root, upper=None):
    return sum(amount for _, _, destination, at, amount in members
               if destination == root and (upper is None or at < upper))


def state(facts, values, query_values, members):
    """Normalize for complete logical comparison; no maintained indexes exist."""
    roots = {}
    for root in ROOTS:
        rows = sorted((m for m in members if m[2] == root), key=lambda m: (m[3], m[0], m[1]))
        balance, minimum = 0, 0
        for at in sorted({m[3] for m in rows}):
            balance += sum(m[4] for m in rows if m[3] == at)
            minimum = min(minimum, balance)
        roots[root] = {"sum": balance, "complete_time_min": minimum, "count": len(rows)}
    return {
        "facts": {name: asdict(row) for name, row in sorted(facts.items())},
        "values": dict(sorted(values.items())),
        "outputs": sorted({m[0] for m in members if m[0] not in ("seed-A", "seed-B")}),
        "members": sorted(members),
        "queries": {name: (*spec, query_values[name])
                    for name, spec in sorted(query_shape(facts).items())},
        "roots": roots,
    }


def evaluate(facts, order, require_ready=True):
    """Candidate fixed-step evaluation with pending contributors kept explicit."""
    incoming, shapes = graph(facts), output_shape(facts)
    members, values, queries, done = list(SEEDS), {}, {}, set()
    for name in order:
        if require_ready:
            assert incoming[name] <= done, f"unsettled inputs for {name}"
        for identity, (consumer, root, upper, phase) in query_shape(facts).items():
            if consumer == name and phase == "calculate":
                queries[identity] = read(members, root, upper)
        if name in facts:
            values[name] = facts[name].target - queries[f"{name}/q_before"]
        elif name in ("L", "R"):
            values[name] = (2 if name == "L" else 3) * queries[f"{name}/q_A"]
        else:
            values[name] = queries["J/q_left"] + queries["J/q_right"]
        for identity, (producer, root, at) in shapes.items():
            if producer == name:
                members.append((identity, "history", root, at, values[name]))
        done.add(name)
    assert done == set(incoming)
    for identity, (_, root, upper, phase) in query_shape(facts).items():
        if phase == "validate":
            queries[identity] = read(members, root, upper)
    return state(facts, values, queries, members)


def source_oracle(facts):
    """Independent arithmetic: group source facts by time, then use 2A/3A/5A.

    Does not consult the candidate graph, schedule, output_shape, stored values,
    or descriptors. Expected query roles come from source declarations, never
    from the candidate's inventory. Shared state() only normalizes comparisons.
    """
    members, values, query_values = list(SEEDS), {}, {}
    for root, seed in (("A", 10), ("B", 4)):
        balance = 0
        readers = {name: row for name, row in facts.items() if row.account == root}
        for at in sorted({0, *(row.at for row in readers.values())}):
            emitted = 0
            for name, row in readers.items():
                if row.at != at:
                    continue
                query_values[f"{name}/q_before"] = balance
                query_values[f"{name}/q_guard"] = balance
                values[name] = row.target - balance
                if row.post:
                    members.append((f"{name}/post", "history", root, at, values[name]))
                    emitted += values[name]
            balance += emitted + (seed if at == 0 else 0)
    a = sum(m[4] for m in members if m[2] == "A")
    values.update(L=2 * a, R=3 * a, J=5 * a)
    query_values.update({"L/q_A": a, "R/q_A": a, "J/q_left": 2 * a, "J/q_right": 3 * a})
    members.extend([("L/post", "history", "left", 40, 2 * a),
                    ("R/post", "history", "right", 40, 3 * a),
                    ("J/post", "history", "final", 40, 5 * a)])
    return state(facts, values, query_values, members)


def compare(actual, expected):
    assert actual == expected, "complete source-derived state differs"


def must_differ(actual, expected):
    try:
        compare(actual, expected)
    except AssertionError:
        return
    raise AssertionError("counterexample escaped the source-derived comparison")


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def identity_control():
    declared = ["z_financial", "a_financial", "later"]
    roles = [("z_financial", 5, 7), ("a_financial", 5, -2), ("later", 8, 3)]

    def financial(items):
        result = []
        for at in sorted({r[1] for r in items}):
            group = [r for r in items if r[1] == at]
            representative = min(group, key=lambda r: declared.index(r[0]))[0]
            result.append((representative, at, sum(r[2] for r in group)))
        return result

    expected = [("z_financial", 5, 5), ("later", 8, 3)]
    assert financial(roles) == expected == financial(list(reversed(roles)))
    queries = {name: (0, 10, 8) for name in ("q_first", "q_second")}
    intervals = {name: (4, 9) for name in ("i_first", "i_second")}
    assert len(queries) == len(intervals) == 2
    assert len(set(queries.values())) == len(set(intervals.values())) == 1
    changed = {**intervals, "i_second": (4, 10)}
    assert changed != intervals and len(changed) == 2
    assert financial([]) == []
    return {"financial": expected, "queries": queries, "intervals": intervals,
            "changed_intervals": changed, "provider_order_independent": True,
            "bound_deduplication_would_lose_slots": True}


def main():
    swapped = {**BASE, "P": replace(BASE["P"], at=20), "Q": replace(BASE["Q"], at=10)}
    moved = {**BASE, "P": replace(BASE["P"], at=30)}
    disabled = {**BASE, "P": replace(BASE["P"], post=False)}
    deleted = {"Q": BASE["Q"]}
    scenarios = [
        ("baseline", BASE, {"P": (10, 10), "Q": (20, 10)}, 30, 4),
        ("swap", swapped, {"P": (30, -10), "Q": (10, 20)}, 20, 4),
        ("move_P_later", moved, {"P": (30, -10), "Q": (10, 20)}, 20, 4),
        ("reparent_P", {**BASE, "P": replace(BASE["P"], account="B")},
         {"P": (4, 16), "Q": (10, 20)}, 30, 20),
        ("disable_P_output", disabled, {"P": (10, 10), "Q": (10, 20)}, 30, 4),
        ("reenable_P_output", {**disabled, "P": replace(disabled["P"], post=True)},
         {"P": (10, 10), "Q": (20, 10)}, 30, 4),
        ("delete_P", deleted, {"Q": (10, 20)}, 30, 4),
        ("same_time", {**BASE, "P": replace(BASE["P"], at=20)},
         {"P": (10, 10), "Q": (10, 20)}, 40, 4),
        ("zero_P_output", {**BASE, "P": replace(BASE["P"], target=10)},
         {"P": (10, 0), "Q": (10, 20)}, 30, 4),
    ]
    report = []
    for name, facts, golden, a, b in scenarios:
        expected = source_oracle(facts)
        assert {r: (expected["queries"][f"{r}/q_before"][-1], expected["values"][r])
                for r in facts} == golden
        assert [expected["roots"][r]["sum"] for r in ROOTS] == [a, b, 2 * a, 3 * a, 5 * a]
        assert all(root["complete_time_min"] >= 0 for root in expected["roots"].values())
        assert len(expected["outputs"]) == 3 + sum(row.post for row in facts.values())
        assert len(expected["members"]) == 5 + sum(row.post for row in facts.values())
        assert len(expected["queries"]) == 4 + 2 * len(facts)
        incoming = graph(facts)
        orders = valid_orders(incoming)
        assert orders, name
        for order in orders:
            compare(evaluate(facts, order), expected)
        report.append({"case": name, "facts": expected["facts"], "prefix_and_delta": golden,
                       "root_totals": {r: expected["roots"][r]["sum"] for r in ROOTS},
                       "edges": sorted((p, c) for c, ps in incoming.items() for p in ps),
                       "valid_orders_checked": len(orders),
                       "output_ids": expected["outputs"],
                       "member_count": len(expected["members"]),
                       "query_ids": sorted(expected["queries"]),
                       "complete_state_sha256": fingerprint(expected)})

    before, after = graph(BASE), graph(swapped)
    assert not valid_orders({name: before[name] | after[name] for name in before})
    wrong = evaluate(swapped, ("P", "Q", "L", "R", "J"), require_ready=False)
    assert wrong["roots"]["A"]["sum"] == 40
    must_differ(wrong, source_oracle(swapped))
    # Keeping Q's old output while evaluating moved P is a separate error.
    stale_q = source_oracle(BASE)["values"]["Q"]
    stale_p_delta = moved["P"].target - (10 + stale_q)
    repaired_q_delta = moved["Q"].target - 10
    stale_total = 10 + stale_p_delta + repaired_q_delta
    assert stale_total == 30 != source_oracle(moved)["roots"]["A"]["sum"]

    # Feedback remains a declared edge when its output formula is 0 * J.value.
    assert not valid_orders(graph(BASE, feedback=True))
    invalid = source_oracle({**BASE, "P": replace(BASE["P"], target=-1)})
    assert invalid["roots"]["A"]["sum"] == 30
    assert invalid["roots"]["A"]["complete_time_min"] == -1
    assert (invalid["values"]["P"], invalid["values"]["Q"]) == (-11, 31)
    for facts in (disabled, deleted):
        # A surviving U -> P/post reference is now unsatisfied: reject, not cascade.
        assert "P/post" in source_oracle(BASE)["outputs"]
        assert "P/post" not in source_oracle(facts)["outputs"]

    expected = source_oracle(BASE)
    corrupt = deepcopy(expected)
    corrupt["queries"] = {k: v for k, v in corrupt["queries"].items() if not k.startswith("P/")}
    must_differ(corrupt, expected)
    corrupt = deepcopy(expected)
    corrupt["outputs"].remove("P/post")
    must_differ(corrupt, expected)

    return {
        "scope": "Fixed-shape exact contract model; not incremental or transactional execution",
        "status": "passed",
        "accepted_source_states": report,
        "valid_orders_checked": sum(row["valid_orders_checked"] for row in report),
        "counterexamples": {
            "old_new_union_falsely_cyclic": True,
            "wrong_order_after_detach": {"wrong_A": 40, "correct_A": 20},
            "unrefreshed_predecessor": {"wrong_A": stale_total, "correct_A": 20},
            "zero_feedback": "final active graph is cyclic",
            "historical_floor": {"final_A": 30, "minimum_A": -1},
            "referenced_output_disable_and_parent_delete": "surviving REJECT reference becomes unsatisfied",
            "missing_complete_P_query_inventory_detected": True,
            "missing_required_output_detected": True,
        },
        "identity_control": identity_control(),
        "baseline_inventory": {key: expected[key] for key in ("outputs", "members", "queries", "roots")},
        "not_exercised": ["incremental discovery", "AVL links or summaries", "UUID allocation",
                          "storage atomicity or conflicts", "authority or RPC", "query-derived shape"],
    }


if __name__ == "__main__":
    print(json.dumps(main(), indent=2, sort_keys=True))
