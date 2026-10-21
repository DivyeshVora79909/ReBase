#!/usr/bin/env python3
"""M6 checker experiment over synthetic typed snapshots, not a tree runtime.

Run with python3 -B research/experiments/m6.py. The unchanged M3/M5 oracle owns
source expectations. All links/caches below are disposable research fixtures.
"""

from copy import deepcopy
from dataclasses import replace
import json

from m3_m5 import BASE, ROOTS, fingerprint, source_oracle


NEG, POS = (-1, 0), (1, 0)
MODEL = "m6-bounded-snapshot-v1"
SECTIONS = ("authored", "derived", "managed", "queries", "roots", "nodes")
NODE_FIELDS = {"id", "owner", "key", "value", "parent", "left", "right",
               "prev", "next", "height", "summary"}
ROOT_FIELDS = {"id", "kind", "root", "first", "last", "height", "summary"}


def exact(actual, expected):
    # In particular, bool/int and float/int equality is not semantic equality.
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(exact(actual[k], v) for k, v in expected.items())
    if isinstance(expected, (tuple, list)):
        return len(actual) == len(expected) and all(exact(a, e) for a, e in zip(actual, expected))
    return actual == expected


def scan(kind, entries):
    """Exact linear oracle over ordered leaves; never combines cached summaries."""
    summary = {"count": len(entries), "first": entries[0]["key"] if entries else None,
               "last": entries[-1]["key"] if entries else None}
    if kind == "interval":
        return {**summary, "max_upper": max((e["value"]["upper"] for e in entries), default=NEG)}
    running, prefixes, groups = 0, [0], []
    for entry in entries:
        running += entry["value"]["amount"]
        prefixes.append(running)
        at = entry["key"][0]
        if groups and groups[-1][0] == at:
            groups[-1] = (at, running)
        else:
            groups.append((at, running))
    completed = [0, *(balance for _, balance in groups)]
    internal = [balance for _, balance in groups[:-1]]
    return {**summary, "sum": running, "record_min": min(prefixes), "record_max": max(prefixes),
            "complete_time_min": min(completed), "complete_time_max": max(completed),
            "internal_min": min(internal) if internal else None,
            "internal_max": max(internal) if internal else None}


def expectations(facts):
    """Source-owned population, independent of every observed snapshot field."""
    model = source_oracle(facts)
    authored = [{"id": r, "contract": "RootOwner", "unit": "minor"} for r in ROOTS]
    authored += [{"id": "seed-A", "contract": "Seed", "account": "A", "at": 0, "amount": 10},
                 {"id": "seed-B", "contract": "Seed", "account": "B", "at": 0, "amount": 4},
                 {"id": "L", "contract": "Branch", "source": "A", "factor": 2, "at": 40},
                 {"id": "R", "contract": "Branch", "source": "A", "factor": 3, "at": 40},
                 {"id": "J", "contract": "Join", "sources": ("left", "right"), "at": 40}]
    authored += [{"id": name, "contract": "Reader", **row} for name, row in model["facts"].items()]
    roots = {(root, slot): kind for root in ROOTS
             for slot, kind in (("history", "financial"), ("subscribers", "interval"))}
    entries, managed, queries = {}, [], []
    for source, slot, root, at, amount in model["members"]:
        identity = (source, slot)
        entries[identity] = {"id": identity, "owner": (root, "history"),
                             "key": (at, source, slot), "value": {"amount": amount}}
        if source in model["outputs"]:
            parent, role = source.split("/")
            managed.append({"id": source, "source": parent, "role": role,
                            "root": root, "at": at, "amount": amount})
    for identity, (reader, root, upper, phase, value) in model["queries"].items():
        field = identity.split("/")[1]
        bound = POS if upper is None else (0, upper)
        queries.append({"id": (reader, field), "source": (root, "history"), "operation": "range",
                        "lower": NEG, "upper": bound, "phase": phase, "channel": "amount",
                        "fallback": 0, "result": value})
        node = (reader, "dep_" + field)
        entries[node] = {"id": node, "owner": (root, "subscribers"),
                         "key": (NEG, *node), "value": {"upper": bound}}
    return {"authored": authored, "derived": [{"id": n, "value": v} for n, v in model["values"].items()],
            "managed": managed, "queries": queries, "roots": roots, "entries": entries, "model": model}


def fixture_tree(root, kind, entries, shape="upper"):
    """Only assemble a finite test image. No insertion, rotation or persistence."""
    ordered = sorted(entries, key=lambda e: e["key"])
    nodes = {}

    def arrange(rows, parent):
        if not rows:
            return None, 0
        mid = 0 if shape == "chain" else (len(rows) - (shape == "lower")) // 2
        entry = deepcopy(rows[mid])
        left, lh = arrange(rows[:mid], entry["id"])
        right, rh = arrange(rows[mid + 1:], entry["id"])
        nodes[entry["id"]] = {**entry, "parent": parent, "left": left, "right": right,
                               "height": 1 + max(lh, rh), "summary": scan(kind, rows)}
        return entry["id"], 1 + max(lh, rh)

    head, height = arrange(ordered, None)
    ids = [e["id"] for e in ordered]
    for i, identity in enumerate(ids):
        nodes[identity].update(prev=ids[i - 1] if i else None,
                               next=ids[i + 1] if i + 1 < len(ids) else None)
    header = {"id": root, "kind": kind, "root": head, "height": height,
              "first": ids[0] if ids else None, "last": ids[-1] if ids else None,
              "summary": scan(kind, ordered)}
    return header, list(nodes.values())


def snapshot(facts, shape="upper"):
    wanted = expectations(facts)
    image = {k: deepcopy(wanted[k]) for k in SECTIONS[:4]}
    image.update(model=MODEL, pending=[], roots=[], nodes=[])
    for root, kind in wanted["roots"].items():
        entries = [e for e in wanted["entries"].values() if e["owner"] == root]
        header, nodes = fixture_tree(root, kind, entries, shape)
        image["roots"].append(header)
        image["nodes"].extend(nodes)
    return image


class Failure(Exception):
    def __init__(self, code, identity):
        super().__init__(f"{code}: {identity}")
        self.code, self.identity = code, identity


def require(condition, code, identity):
    if not condition:
        raise Failure(code, identity)


def verify(facts, image, *, complete, budget=1000):
    """Fail with a named obligation, or return work counts for a complete check."""
    require(complete is True, "INCOMPLETE_SCOPE", "snapshot")
    require(set(image) == {*SECTIONS, "model", "pending"}, "LAYOUT", "snapshot")
    require(image["model"] == MODEL, "MODEL", "snapshot")
    require(exact(image["pending"], []), "PENDING_WORK", "snapshot")
    wanted = expectations(facts)
    counts = {"work_units": 0, "node_visits": 0, "summary_leaf_visits": 0}

    def tick(n):
        counts["work_units"] += n
        require(counts["work_units"] <= budget, "INCOMPLETE_BUDGET", counts["work_units"])

    def index(rows, section):
        require(type(rows) is list, "LAYOUT", section)
        tick(len(rows))
        result = {}
        for row in rows:
            require(type(row) is dict and "id" in row, "LAYOUT", section)
            identity = row["id"]
            valid_id = type(identity) is str or (type(identity) is tuple and len(identity) == 2
                                                and all(type(p) is str for p in identity))
            require(valid_id, "LAYOUT", section)
            require(identity not in result, "DUPLICATE_ID", (section, identity))
            result[identity] = row
        return result

    actual = {name: index(image[name], name) for name in SECTIONS}
    for section, code in (("authored", "SOURCE"), ("derived", "DERIVED"),
                          ("managed", "MANAGED"), ("queries", "QUERY")):
        expected = {r["id"]: r for r in wanted[section]}
        require(actual[section].keys() == expected.keys(), code + "_INVENTORY", section)
        for identity, row in expected.items():
            require(exact(actual[section][identity], row), code + "_VALUE", identity)
    roots, nodes, entries = actual["roots"], actual["nodes"], wanted["entries"]
    require(roots.keys() == wanted["roots"].keys(), "ROOT_INVENTORY", "roots")
    require(nodes.keys() == entries.keys(), "NODE_INVENTORY", "nodes")
    for identity, node in nodes.items():
        require(set(node) == NODE_FIELDS, "LAYOUT", identity)
        payload = {k: node[k] for k in ("id", "owner", "key", "value")}
        require(exact(payload, entries[identity]), "NODE_PAYLOAD", identity)

    visited = set()

    def rescan(kind, ids):
        tick(len(ids))
        counts["summary_leaf_visits"] += len(ids)
        return scan(kind, [entries[i] for i in ids])

    for root, kind in wanted["roots"].items():
        header = roots[root]
        require(set(header) == ROOT_FIELDS and header["kind"] == kind, "LAYOUT", root)
        expected_ids = sorted((i for i, e in entries.items() if e["owner"] == root),
                              key=lambda i: entries[i]["key"])

        def visit(identity, parent, lower, upper):
            if identity is None:
                return 0, []
            tick(1)
            counts["node_visits"] += 1
            require(type(identity) is tuple and all(type(p) is str for p in identity), "LINK", identity)
            require(identity not in visited, "TREE_REVISIT", identity)
            require(identity in nodes, "DANGLING_LINK", identity)
            node = nodes[identity]
            require(node["owner"] == root, "WRONG_ROOT", identity)
            visited.add(identity)
            require(exact(node["parent"], parent), "PARENT", identity)
            key = node["key"]
            require((lower is None or lower < key) and (upper is None or key < upper), "ORDER", identity)
            lh, left = visit(node["left"], identity, lower, key)
            rh, right = visit(node["right"], identity, key, upper)
            require(abs(lh - rh) <= 1, "BALANCE", identity)
            height = 1 + max(lh, rh)
            require(exact(node["height"], height), "HEIGHT", identity)
            sequence = [*left, identity, *right]
            code = "INTERVAL_SUMMARY" if kind == "interval" else "NODE_SUMMARY"
            require(exact(node["summary"], rescan(kind, sequence)), code, identity)
            return height, sequence

        height, sequence = visit(header["root"], None, None, None)
        require(sequence == expected_ids, "REACHABILITY", root)
        require(exact(header["height"], height), "ROOT_HEIGHT", root)
        first, last = (expected_ids[0], expected_ids[-1]) if expected_ids else (None, None)
        require(exact((header["first"], header["last"]), (first, last)), "ROOT_ENDPOINT", root)
        require(exact(header["summary"], rescan(kind, expected_ids)), "ROOT_SUMMARY", root)
        for i, identity in enumerate(expected_ids):
            previous = expected_ids[i - 1] if i else None
            following = expected_ids[i + 1] if i + 1 < len(expected_ids) else None
            require(exact((nodes[identity]["prev"], nodes[identity]["next"]), (previous, following)),
                    "NEIGHBOUR", identity)
    require(visited == nodes.keys(), "REACHABILITY", "all private nodes")
    require(all(wanted["model"]["roots"][r]["complete_time_min"] >= 0 for r in ("A", "B")),
            "INVARIANT", "complete-time account floor")
    require(all(q["result"] >= 0 for q in wanted["queries"] if q["phase"] == "validate"),
            "INVARIANT", "validation prefix")
    return counts


def row(image, section, identity):
    return next(r for r in image[section] if r["id"] == identity)


def rebuild_fixture_root(image, root, shape="upper"):
    # For controls whose broken payload/population still has internally valid caches.
    kind = row(image, "roots", root)["kind"]
    entries = [{k: n[k] for k in ("id", "owner", "key", "value")}
               for n in image["nodes"] if n["owner"] == root]
    header, nodes = fixture_tree(root, kind, entries, shape)
    image["roots"] = [header if h["id"] == root else h for h in image["roots"]]
    image["nodes"] = [n for n in image["nodes"] if n["owner"] != root] + nodes


def main():
    # Independent literals anchor the shared fixture/cache raw scan, including
    # strict type checks and absent versus zero internal boundaries.
    leaves = lambda pairs: [{"key": (at, str(i), "x"), "value": {"amount": amount}}
                            for i, (at, amount) in enumerate(pairs)]
    same_time = scan("financial", leaves([(1, -5), (1, 5)]))
    assert (same_time["sum"], same_time["record_min"], same_time["complete_time_min"],
            same_time["internal_min"]) == (0, -5, 0, None)
    deficit = scan("financial", leaves([(0, 10), (10, -15), (20, 10)]))
    assert (deficit["sum"], deficit["complete_time_min"], deficit["internal_min"]) == (5, -5, -5)
    assert scan("interval", [])["max_upper"] == NEG
    assert not exact(1, True) and not exact(10, 10.0)

    zero = {**BASE, "P": replace(BASE["P"], target=10)}
    disabled = {**BASE, "P": replace(BASE["P"], post=False)}
    positive = []
    for name, facts, shape in (("baseline_upper", BASE, "upper"), ("baseline_lower", BASE, "lower"),
                               ("zero_posting", zero, "upper"), ("disabled_output", disabled, "upper"),
                               ("deleted_reader", {"Q": BASE["Q"]}, "upper")):
        image = snapshot(facts, shape)
        positive.append({"case": name, "counts": {k: len(image[k]) for k in SECTIONS},
                         "work": verify(facts, image, complete=True), "snapshot_sha256": fingerprint(image)})
    assert positive[0]["snapshot_sha256"] != positive[1]["snapshot_sha256"]
    assert positive[0]["counts"] == {"authored": 12, "derived": 5, "managed": 5,
                                      "queries": 8, "roots": 10, "nodes": 15}
    baseline, zero_image, negatives = snapshot(BASE), snapshot(zero), []
    a, reverse_a = ("A", "history"), ("A", "subscribers")
    financial_totals = lambda image: {h["id"][0]: h["summary"]["sum"] for h in image["roots"]
                                      if h["kind"] == "financial"}

    def reject(name, image, code, facts=BASE, original=baseline, **options):
        digest = fingerprint(image)
        try:
            verify(facts, image, complete=options.pop("complete", True), **options)
        except Failure as failure:
            assert failure.code == code, (name, failure.code, code)
            negatives.append({"case": name, "obligation": failure.code, "identity": failure.identity,
                              "result": "incomplete" if code.startswith("INCOMPLETE_") else "invalid",
                              "published_financial_totals_unchanged": financial_totals(image) == financial_totals(original),
                              "snapshot_sha256": digest})
        else:
            raise AssertionError(f"checker accepted {name}")
        assert fingerprint(image) == digest, "verification must not repair or mutate the snapshot"

    bad = deepcopy(baseline)
    bad["queries"] = [q for q in bad["queries"] if q["source"] != a]
    bad["nodes"] = [n for n in bad["nodes"] if n["owner"] != reverse_a]
    rebuild_fixture_root(bad, reverse_a)
    reject("erased_A_query_inventory", bad, "QUERY_INVENTORY")

    bad = deepcopy(baseline)
    bad["roots"] = [h for h in bad["roots"] if h["id"] != ("B", "subscribers")]
    reject("missing_empty_root", bad, "ROOT_INVENTORY")
    bad = deepcopy(baseline)
    bad["nodes"].append(deepcopy(bad["nodes"][0]))
    reject("duplicate_raw_node_identity", bad, "DUPLICATE_ID")
    bad = deepcopy(baseline)
    bad["nodes"].append({**deepcopy(bad["nodes"][0]), "id": ("ghost", "slot")})
    reject("disconnected_extra_node", bad, "NODE_INVENTORY")
    bad = deepcopy(baseline)
    bad["managed"] = [m for m in bad["managed"] if m["id"] != "P/post"]
    reject("missing_required_output", bad, "MANAGED_INVENTORY")
    bad = deepcopy(baseline)
    bad["authored"] = [r for r in bad["authored"] if r["id"] != "P"]
    reject("missing_authored_source", bad, "SOURCE_INVENTORY")

    bad = deepcopy(zero_image)
    bad["nodes"] = [n for n in bad["nodes"] if n["id"] != ("P/post", "history")]
    rebuild_fixture_root(bad, a)
    reject("zero_posting_omitted", bad, "NODE_INVENTORY", facts=zero, original=zero_image)
    bad = deepcopy(baseline)
    row(bad, "queries", ("P", "q_guard"))["phase"] = "calculate"
    reject("query_phase_changed", bad, "QUERY_VALUE")
    bad = deepcopy(zero_image)
    row(bad, "queries", ("P", "q_before"))["upper"] = (0, 11)
    row(bad, "nodes", ("P", "dep_q_before"))["value"]["upper"] = (0, 11)
    rebuild_fixture_root(bad, reverse_a)
    reject("bound_changed_with_equal_answer", bad, "QUERY_VALUE", facts=zero, original=zero_image)
    bad = deepcopy(baseline)
    row(bad, "queries", ("P", "q_before"))["result"] += 1
    reject("stored_query_result_changed", bad, "QUERY_VALUE")
    bad = deepcopy(baseline)
    row(bad, "nodes", ("P/post", "history"))["value"]["amount"] += 1
    row(bad, "nodes", ("Q/post", "history"))["value"]["amount"] -= 1
    rebuild_fixture_root(bad, a)
    reject("opposite_leaf_errors_preserve_total", bad, "NODE_PAYLOAD")

    for name, field, value, code in (
        ("wrong_parent", "parent", None, "PARENT"),
        ("wrong_neighbour", "prev", None, "NEIGHBOUR"),
        ("wrong_cached_height", "height", 2, "HEIGHT"),
    ):
        bad = deepcopy(baseline)
        row(bad, "nodes", ("Q/post", "history"))[field] = value
        reject(name, bad, code)
    for name, left, right, code in (
        ("cycle", ("P/post", "history"), ("Q/post", "history"), "TREE_REVISIT"),
        ("shared_child", ("seed-A", "history"), ("seed-A", "history"), "TREE_REVISIT"),
        ("wrong_BST_order", ("Q/post", "history"), ("seed-A", "history"), "ORDER"),
        ("cross_root_child", ("seed-B", "history"), ("Q/post", "history"), "WRONG_ROOT"),
        ("dangling_child", ("seed-A", "history"), ("ghost", "slot"), "DANGLING_LINK"),
    ):
        bad = deepcopy(baseline)
        row(bad, "nodes", ("P/post", "history")).update(left=left, right=right)
        reject(name, bad, code)
    bad = deepcopy(baseline)
    row(bad, "roots", a).update(root=None, first=None, last=None, height=0, summary=scan("financial", []))
    reject("root_disconnected_from_present_nodes", bad, "REACHABILITY")
    bad = deepcopy(baseline)
    row(bad, "roots", a)["first"] = ("P/post", "history")
    reject("wrong_root_endpoint", bad, "ROOT_ENDPOINT")
    bad = deepcopy(baseline)
    rebuild_fixture_root(bad, a, "chain")
    reject("unbalanced_BST_with_correct_caches", bad, "BALANCE")

    bad = deepcopy(baseline)
    row(bad, "nodes", ("seed-A", "history"))["summary"]["sum"] = 11
    reject("wrong_internal_cache", bad, "NODE_SUMMARY")
    bad = deepcopy(baseline)
    row(bad, "roots", a)["summary"]["complete_time_min"] = -1
    reject("wrong_published_cache", bad, "ROOT_SUMMARY")
    bad = deepcopy(baseline)
    reverse_head = row(bad, "roots", reverse_a)["root"]
    row(bad, "nodes", reverse_head)["summary"]["max_upper"] = (0, 20)
    reject("underestimated_interval_maximum", bad, "INTERVAL_SUMMARY")
    bad = deepcopy(baseline)
    row(bad, "nodes", ("seed-A", "history"))["summary"]["sum"] = 10.0
    reject("floating_cached_integer", bad, "NODE_SUMMARY")
    bad = deepcopy(baseline)
    bad["pending"] = ["P/post"]
    reject("unsettled_snapshot", bad, "PENDING_WORK")
    invalid_facts = {**BASE, "P": replace(BASE["P"], target=-1)}
    reject("valid_structure_but_negative_history", snapshot(invalid_facts), "INVARIANT", facts=invalid_facts)
    reject("partial_observation", deepcopy(baseline), "INCOMPLETE_SCOPE", complete=False)
    reject("budget_exhausted", deepcopy(baseline), "INCOMPLETE_BUDGET",
           budget=positive[0]["work"]["work_units"] - 1)

    return {"status": "passed", "scope": "Synthetic typed-snapshot checker, no runtime or storage",
            "positive_controls": positive, "negative_controls": negatives,
            "literal_scan_controls": {"same_time": same_time, "historical_deficit": deficit},
            "expected_root_ids": sorted(expectations(BASE)["roots"]),
            "baseline_snapshot_sha256": fingerprint(baseline),
            "not_exercised": ["native tree mutations", "storage or snapshot export", "incremental discovery",
                              "latest/next/empty-range slots", "direct reverse routes", "UUID codecs",
                              "permissions, receipts or rollback", "distributed conflict schedules"]}


if __name__ == "__main__":
    print(json.dumps(main(), indent=2, sort_keys=True))
