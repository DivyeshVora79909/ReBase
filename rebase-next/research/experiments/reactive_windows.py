#!/usr/bin/env python3
"""Independent literal G4b source oracle; no engine or writer imports.

Bounds are null (unbounded), {"included": "time"}, or {"excluded": "time"}.
Times and amounts are canonical decimal strings. Window predicates operate on
whole timestamp groups, never on UUID ties. Reversed windows and equal bounds
with either endpoint excluded contain no points. An included singleton does.

`--self-test` runs literal controls and bounded generated vectors. `--emit`
writes request/expected JSONL; `--requests` writes requests only. With no option,
read requests from stdin and write one response per line. `--binary PATH`
compares a native harness implementing this small oracle protocol. A normal run
does not claim native acceptance. The symbolic source vocabulary is intentionally
independent of production records, codecs, AVL routes and graph compression.

State: sources have id/root/at/amount; producers have id/reads/emits. Each read
has slot/root/lower/upper and optional validate. Each emission has role/root/at,
offset, and factor; its amount is offset + factor * sum(calculation read values).
Validation reads consume settled values but never contribute evaluation edges.
Graph edges are literal producer-emission/read pairs, including zero emissions.
Arithmetic is mathematical integer arithmetic; generated values stay in i128.
"""

import argparse
from copy import deepcopy
import json
from pathlib import Path
import random
import re
import subprocess
import sys


TIME_MIN, TIME_MAX = -(2**63), 2**63 - 1
AMOUNT_MIN, AMOUNT_MAX = -(2**127), 2**127 - 1


class Reject(Exception):
    pass


def require(condition):
    if not condition:
        raise Reject("invalid_input")


def exact(value, low=AMOUNT_MIN, high=AMOUNT_MAX):
    require(type(value) is str and re.fullmatch(r"0|-?[1-9][0-9]*", value) is not None)
    result = int(value)
    require(low <= result <= high)
    return result


def bound(value):
    if value is None:
        return None
    require(type(value) is dict and len(value) == 1)
    kind = next(iter(value))
    require(kind in ("included", "excluded"))
    return kind, exact(value[kind], TIME_MIN, TIME_MAX)


def contains(window, at):
    """Literal conjunction, without boundary arithmetic or sentinel keys."""
    lower, upper = bound(window["lower"]), bound(window["upper"])
    left = lower is None or (at >= lower[1] if lower[0] == "included" else at > lower[1])
    right = upper is None or (at <= upper[1] if upper[0] == "included" else at < upper[1])
    return left and right


def label(value):
    require(type(value) is str and bool(value))
    return value


def slot(value):
    require(type(value) is int and 0 < value <= 65535)
    return value


def state(value):
    require(type(value) is dict and set(value) == {"sources", "producers"})
    require(type(value["sources"]) is list and type(value["producers"]) is list)
    identities = []
    for source in value["sources"]:
        require(type(source) is dict and set(source) == {"id", "root", "at", "amount"})
        identities.append(label(source["id"]))
        label(source["root"])
        exact(source["at"], TIME_MIN, TIME_MAX)
        exact(source["amount"])
    for producer in value["producers"]:
        require(type(producer) is dict and set(producer) == {"id", "reads", "emits"})
        identities.append(label(producer["id"]))
        require(type(producer["reads"]) is list and type(producer["emits"]) is list)
        reads, roles = [], []
        for read in producer["reads"]:
            require(type(read) is dict and {"slot", "root", "lower", "upper"} <= set(read)
                    and set(read) <= {"slot", "root", "lower", "upper", "validate"})
            reads.append(slot(read["slot"]))
            label(read["root"])
            bound(read["lower"])
            bound(read["upper"])
            require(type(read.get("validate", False)) is bool)
        for emit in producer["emits"]:
            require(type(emit) is dict and set(emit) == {"role", "root", "at", "offset", "factor"})
            roles.append(slot(emit["role"]))
            label(emit["root"])
            exact(emit["at"], TIME_MIN, TIME_MAX)
            exact(emit["offset"])
            exact(emit["factor"])
        require(len(reads) == len(set(reads)) and len(roles) == len(set(roles)))
    require(len(identities) == len(set(identities)))
    return value


def graph(value):
    """Compare every final emission to every final calculation read."""
    edges = set()
    for upstream in value["producers"]:
        for downstream in value["producers"]:
            for emit in upstream["emits"]:
                for read in downstream["reads"]:
                    if (not read.get("validate", False) and emit["root"] == read["root"]
                            and contains(read, int(emit["at"]))):
                        edges.add((upstream["id"], downstream["id"]))
    return sorted(edges)


def order(value, edges):
    pending = {producer["id"] for producer in value["producers"]}
    result = []
    while pending:
        ready = sorted(node for node in pending
                       if not any(target == node and source in pending for source, target in edges))
        if not ready:
            raise Reject("calculation_cycle")
        chosen = ready[0]
        result.append(chosen)
        pending.remove(chosen)
    return result


def selected(value, impacts):
    return sorted({(producer["id"], read["slot"])
                   for producer in value["producers"] for read in producer["reads"]
                   for root, at in impacts
                   if root == read["root"] and contains(read, at)})


def evaluate(value):
    edges = graph(value)
    sequence = order(value, edges)
    members = [(source["root"], int(source["at"]), int(source["amount"]))
               for source in value["sources"]]
    reads, emissions = [], []
    producers = {producer["id"]: producer for producer in value["producers"]}
    for identity in sequence:
        producer = producers[identity]
        total = 0
        for read in producer["reads"]:
            if not read.get("validate", False):
                amount = sum(amount for root, at, amount in members
                             if root == read["root"] and contains(read, at))
                reads.append([identity, read["slot"], str(amount)])
                total += amount
        for emit in producer["emits"]:
            amount = int(emit["offset"]) + int(emit["factor"]) * total
            emissions.append([identity, emit["role"], str(amount)])
            members.append((emit["root"], int(emit["at"]), amount))
    for producer in value["producers"]:
        for read in producer["reads"]:
            if read.get("validate", False):
                amount = sum(amount for root, at, amount in members
                             if root == read["root"] and contains(read, at))
                reads.append([producer["id"], read["slot"], str(amount)])
    return {"edges": [list(edge) for edge in edges], "order": sequence,
            "reads": sorted(reads), "emissions": sorted(emissions)}


def oracle(request):
    try:
        require(type(request) is dict)
        if request.get("op") == "contains":
            require(set(request) == {"op", "lower", "upper", "at"})
            return {"ok": contains(request, exact(request["at"], TIME_MIN, TIME_MAX))}
        if request.get("op") in ("graph", "evaluate"):
            require(set(request) == {"op", "state"})
            value = state(request["state"])
            if request["op"] == "evaluate":
                return {"ok": evaluate(value)}
            edges = graph(value)
            try:
                sequence = order(value, edges)
            except Reject:
                return {"ok": {"edges": [list(edge) for edge in edges], "cyclic": True}}
            return {"ok": {"edges": [list(edge) for edge in edges], "cyclic": False, "order": sequence}}
        if request.get("op") == "discover":
            require(set(request) == {"op", "old", "new", "impacts"})
            old, new = state(request["old"]), state(request["new"])
            require(type(request["impacts"]) is list)
            impacts = []
            for impact in request["impacts"]:
                require(type(impact) is dict and set(impact) == {"root", "at"})
                impacts.append((label(impact["root"]), exact(impact["at"], TIME_MIN, TIME_MAX)))
            old_reads, new_reads = selected(old, impacts), selected(new, impacts)
            return {"ok": {"old": [list(item) for item in old_reads],
                           "new": [list(item) for item in new_reads],
                           "union": [list(item) for item in sorted(set(old_reads) | set(new_reads))]}}
        raise Reject("invalid_input")
    except Reject as error:
        return {"error": str(error)}


def endpoint(at, included=True):
    return {"included" if included else "excluded": str(at)}


def read(number, root, lower=None, upper=None, validate=False):
    return {"slot": number, "root": root, "lower": lower, "upper": upper, "validate": validate}


def emit(root, at, offset=0, factor=1, role=1):
    return {"role": role, "root": root, "at": str(at), "offset": str(offset), "factor": str(factor)}


def producer(identity, reads=(), emits=()):
    return {"id": identity, "reads": list(reads), "emits": list(emits)}


def movement():
    old = {"sources": [], "producers": [
        producer("x", [read(1, "r", endpoint(100), endpoint(100))], [emit("r", 1, 2)]),
        producer("y", [read(1, "r", endpoint(1), endpoint(1))], [emit("r", 3, 7)])]}
    new = deepcopy(old)
    new["producers"][0]["reads"] = [read(1, "r", endpoint(3), endpoint(3))]
    new["producers"][1]["reads"] = [read(1, "r", endpoint(100), endpoint(100))]
    return old, new


def cases():
    bounds = [None] + [endpoint(at, included) for at in (TIME_MIN, -1, 0, 1, TIME_MAX)
                       for included in (False, True)]
    for lower in bounds:
        for upper in bounds:
            for at in (TIME_MIN, TIME_MIN + 1, -2, -1, 0, 1, 2, TIME_MAX - 1, TIME_MAX):
                yield {"op": "contains", "lower": lower, "upper": upper, "at": str(at)}
    old, new = movement()
    for value in (old, new):
        for operation in ("graph", "evaluate"):
            yield {"op": operation, "state": value}
    cyclic = deepcopy(old)
    cyclic["producers"][0]["reads"] = deepcopy(new["producers"][0]["reads"])
    for operation in ("graph", "evaluate"):
        yield {"op": operation, "state": cyclic}
    disjoint = {"sources": [], "producers": [producer("windows", [
        read(1, "r", endpoint(1), endpoint(2)), read(2, "r", endpoint(9), endpoint(10)),
        read(3, "r", endpoint(9), endpoint(9, False)),
        read(4, "other", None, None), read(5, "r", endpoint(9), endpoint(10))])]}
    yield {"op": "discover", "old": disjoint, "new": disjoint,
           "impacts": [{"root": "r", "at": "1"}, {"root": "r", "at": "9"}]}
    # Duplicate impacts are harmless, but neither distinct impacts nor distinct
    # query identities may collapse. Retargeting unions old and final routes.
    moved = deepcopy(disjoint)
    moved["producers"][0]["reads"][1]["root"] = "other"
    yield {"op": "discover", "old": disjoint, "new": moved,
           "impacts": [{"root": "r", "at": "9"}, {"root": "r", "at": "9"}]}
    yield {"op": "discover", "old": old, "new": new,
           "impacts": [{"root": "r", "at": "1"}, {"root": "r", "at": "3"}]}
    # Precision, complete timestamp groups, zero-emission dependencies and a
    # validation read of one's own publication all have independent meaning.
    huge = 10**30 + 9007199254740993
    diamond = {"sources": [
        {"id": "s1", "root": "input", "at": "0", "amount": str(huge)},
        {"id": "s2", "root": "input", "at": "0", "amount": str(-huge + 11)}],
        "producers": [
            producer("a", [read(1, "input")], [emit("left", 1)]),
            producer("b", [read(1, "input")], [emit("right", 1, factor=2)]),
            producer("c", [read(1, "left"), read(2, "right"),
                            read(3, "answer", validate=True)], [emit("answer", 2)]),
            producer("zero", [], [emit("zero", 3, factor=0)]),
            producer("reader", [read(1, "zero")], [])]}
    yield {"op": "evaluate", "state": diamond}
    precise = deepcopy(diamond)
    precise["sources"] = precise["sources"][:1]
    yield {"op": "evaluate", "state": precise}
    # Finite-window sums contain every same-time source together. Equal closed
    # endpoints select the group; reversed/half-open singleton windows stay as
    # distinct zero-valued reads. Unbounded sums include both i64 extrema.
    groups = {"sources": [
        {"id": "min", "root": "r", "at": str(TIME_MIN), "amount": "19"},
        {"id": "first", "root": "r", "at": "0", "amount": "9007199254740993"},
        {"id": "second", "root": "r", "at": "0", "amount": "-9007199254740990"},
        {"id": "max", "root": "r", "at": str(TIME_MAX), "amount": "23"}],
        "producers": [producer("groups", [
            read(1, "r"), read(2, "r", endpoint(0), endpoint(0)),
            read(3, "r", endpoint(0, False), endpoint(0)),
            read(4, "r", endpoint(1), endpoint(-1)),
            read(5, "r", endpoint(TIME_MIN), endpoint(TIME_MAX, False)),
            read(6, "r", endpoint(TIME_MIN, False), endpoint(TIME_MAX))])]}
    yield {"op": "evaluate", "state": groups}
    # Positive randomized DAGs complement feedback rejection vectors. Every
    # calculation reads strictly earlier timestamps on its root, so graph truth
    # is independent of the producer array's deliberately shuffled order.
    dag_rng = random.Random(20261024)
    for _ in range(32):
        dag = {"sources": [], "producers": []}
        for index in range(6):
            root = dag_rng.choice(("r", "q"))
            dag["sources"].append({"id": f"s{index}", "root": root,
                                   "at": str(index), "amount": str(10**25 + index)})
            dag["producers"].append(producer(f"p{index}", [
                read(1, root, endpoint(dag_rng.randint(-1, index)), endpoint(index, False))],
                [emit(root, index, dag_rng.randint(-5, 5), dag_rng.randint(-2, 2))]))
        dag_rng.shuffle(dag["producers"])
        yield {"op": "evaluate", "state": dag}
    # Bounded deterministic randomized source populations exercise literal
    # pairwise discovery and arbitrary acyclic/cyclic final graphs.
    rng = random.Random(20261023)
    for _ in range(96):
        value = {"sources": [], "producers": []}
        for index in range(5):
            value["sources"].append({"id": f"s{index}", "root": rng.choice(("r", "q")),
                                     "at": str(rng.randint(-3, 3)),
                                     "amount": str(rng.randint(-100, 100) * 10**20 + index)})
            value["producers"].append(producer(f"p{index}", [
                read(1, rng.choice(("r", "q")), rng.choice(bounds), rng.choice(bounds)),
                read(2, "r", rng.choice(bounds), rng.choice(bounds), validate=True)],
                [emit(rng.choice(("r", "q")), rng.randint(-3, 3), rng.randint(-5, 5),
                      rng.randint(-2, 2))]))
        yield {"op": "graph", "state": value}
        yield {"op": "evaluate", "state": value}
        yield {"op": "discover", "old": value, "new": value,
               "impacts": [{"root": "r", "at": str(at)} for at in (-3, 0, 3)]}
    for malformed in ("+1", "01", "-0", "1.0", "1e0", 1, None, str(TIME_MAX + 1)):
        yield {"op": "contains", "lower": None, "upper": None, "at": malformed}
    for malformed in ({}, {"included": "0", "excluded": "1"}, {"before": "0"},
                      {"included": 0}, {"included": str(TIME_MIN - 1)}):
        yield {"op": "contains", "lower": malformed, "upper": None, "at": "0"}


def verify(actual, expected):
    if actual != expected:
        raise AssertionError(f"expected {expected!r}, observed {actual!r}")


def controls():
    literals = 0
    for lower, upper, at, expected in (
        (None, None, TIME_MIN, True), (None, None, TIME_MAX, True),
        (endpoint(0), endpoint(0), 0, True),
        (endpoint(0, False), endpoint(0), 0, False),
        (endpoint(0), endpoint(0, False), 0, False),
        (endpoint(1), endpoint(0), 0, False),
        (endpoint(TIME_MAX, False), None, TIME_MAX, False),
        (None, endpoint(TIME_MIN, False), TIME_MIN, False),
        (endpoint(TIME_MAX), endpoint(TIME_MAX), TIME_MAX, True)):
        verify(oracle({"op": "contains", "lower": lower, "upper": upper, "at": str(at)}),
               {"ok": expected})
        literals += 1
    old, new = movement()
    verify(graph(old), [("x", "y")])
    verify(graph(new), [("y", "x")])
    verify(evaluate(old)["emissions"], [["x", 1, "2"], ["y", 1, "9"]])
    verify(evaluate(new)["emissions"], [["x", 1, "9"], ["y", 1, "7"]])
    try:
        order(new, sorted(set(graph(old)) | set(graph(new))))
    except Reject as error:
        verify(str(error), "calculation_cycle")
    else:
        raise AssertionError("old/new union must be cyclic in this control")
    literals += 5
    vectors = list(cases())
    discovered = next(oracle(request) for request in vectors
                      if request["op"] == "discover" and request["old"]["producers"][0]["id"] == "windows")
    verify(discovered, {"ok": {"old": [["windows", 1], ["windows", 2], ["windows", 5]],
                              "new": [["windows", 1], ["windows", 2], ["windows", 5]],
                              "union": [["windows", 1], ["windows", 2], ["windows", 5]]}})
    literals += 1
    diamond = next(request for request in vectors if request["op"] == "evaluate"
                   and len(request["state"]["producers"]) == 5 and request["state"]["producers"][0]["id"] == "a")
    result = oracle(diamond)["ok"]
    verify(result["emissions"], [["a", 1, "11"], ["b", 1, "22"], ["c", 1, "33"], ["zero", 1, "0"]])
    verify(result["edges"], [["a", "c"], ["b", "c"], ["zero", "reader"]])
    verify([item for item in result["reads"] if item[:2] == ["c", 3]], [["c", 3, "33"]])
    literals += 3
    groups = next(request for request in vectors if request["op"] == "evaluate"
                  and request["state"]["producers"][0]["id"] == "groups")
    verify(oracle(groups)["ok"]["reads"], [
        ["groups", 1, "45"], ["groups", 2, "3"], ["groups", 3, "0"],
        ["groups", 4, "0"], ["groups", 5, "22"], ["groups", 6, "26"]])
    literals += 1
    # These deliberate misobservations model the principal regression classes.
    negatives = [(True, False), (discovered["ok"]["union"], [["windows", 1]]),
                 (result["edges"], [["a", "c"], ["b", "c"]]),
                 (evaluate(new)["emissions"], evaluate(old)["emissions"]),
                 (str(10**30 + 9007199254740993), str(int(float(10**30 + 9007199254740993))))]
    for actual, wrong in negatives:
        try:
            verify(actual, wrong)
        except AssertionError:
            continue
        raise AssertionError("negative control incorrectly accepted")
    # Every successful settled result must respect every literal edge.
    for request in vectors:
        response = oracle(request)
        if request["op"] == "evaluate" and "ok" in response:
            positions = {identity: index for index, identity in enumerate(response["ok"]["order"])}
            require(all(positions[a] < positions[b] for a, b in response["ok"]["edges"]))
    return {"literal_controls": literals, "negative_controls": len(negatives), "cases": len(vectors)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--emit", action="store_true", help="request/expected JSONL vectors")
    action.add_argument("--requests", action="store_true", help="request-only JSONL vectors")
    action.add_argument("--binary", type=Path, help="compare a native oracle-protocol harness")
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps({"format": "rebase-reactive-window-oracle-1", **controls(),
                          "native_verified": False}, sort_keys=True))
    elif args.emit or args.requests or args.binary:
        controls()
        vectors = list(cases())
        if args.binary:
            requests = "".join(json.dumps(request, separators=(",", ":")) + "\n" for request in vectors)
            run = subprocess.run([str(args.binary.resolve())], input=requests, text=True,
                                 capture_output=True, check=True, timeout=60)
            lines = run.stdout.splitlines()
            verify(len(lines), len(vectors))
            for index, (request, line) in enumerate(zip(vectors, lines)):
                try:
                    verify(json.loads(line), oracle(request))
                except (ValueError, AssertionError) as error:
                    raise AssertionError(f"case {index}: {request!r}: {error}") from error
            print(json.dumps({"cases": len(vectors), "native_verified": True}, sort_keys=True))
        else:
            for request in vectors:
                value = request if args.requests else {"request": request, "expected": oracle(request)}
                print(json.dumps(value, separators=(",", ":"), sort_keys=True))
    else:
        for line in sys.stdin:
            try:
                response = oracle(json.loads(line))
            except (ValueError, KeyError, TypeError):
                response = {"error": "invalid_input"}
            print(json.dumps(response, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
