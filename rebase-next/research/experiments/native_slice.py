#!/usr/bin/env python3
"""Independent M1/M2/M4 source oracle and complete native-KV checker.

No Rust calculation, discovery, tree or summary implementation is used here.
Without --actual this checks source cases and deliberately synthetic images.
With --actual it checks snapshots emitted by the native redb harness.
"""

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import uuid

from m6 import Failure, exact, require

ROOT = Path(__file__).resolve().parents[2]
CODEC = "native-slice-kv-1"
FIELDS = {1: ("c",), 2: ("native_unit", "reporting_unit"),
          3: ("curve", "at", "rate"), 4: ("native_unit",),
          5: ("reporting_unit",),
          6: ("units", "at", "rule", "curve", "account", "subsidiary")}
KINDS = {0: "meta", 1: "record", 2: "root", 3: "node", 4: "query",
         5: "incoming", 6: "direct", 7: "subscribers"}
MODEL_FILES = ("Cargo.lock", "Cargo.toml", "rust-toolchain.toml", "src/algebra.rs",
               "src/native_codec.rs", "src/native_slice.rs", "src/plan.rs",
               "src/staging.rs", "src/tree.rs")


class Reject(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def check(condition, code="invalid_input"):
    if not condition:
        raise Reject(code)


def integer(value, low=-(2**127), high=2**127 - 1):
    check(type(value) is str and re.fullmatch(r"0|-?[1-9][0-9]*", value) is not None)
    try:
        result = int(value)
    except ValueError as error:
        raise Reject("invalid_input") from error
    check(low <= result <= high)
    return result


def identity(value):
    try:
        check(type(value) is str and str(uuid.UUID(value)) == value)
    except (ValueError, AttributeError) as error:
        raise Reject("invalid_input") from error
    return value


def address(record, slot):
    return {"id": record, "slot": slot}


def aid(value):
    if value is None:
        return None
    require(type(value) is dict and set(value) == {"id", "slot"}, "LAYOUT", value)
    require(type(value["slot"]) is int and 0 < value["slot"] <= 65535, "LAYOUT", value)
    try:
        identity(value["id"])
    except Reject as error:
        raise Failure("LAYOUT", value) from error
    return value["id"], value["slot"]


def references(code, fields):
    if code == 3:
        return [(fields["curve"], 2, 1)]
    if code == 6:
        return [(fields[name], kind, slot) for name, kind, slot in
                (("rule", 1, 3), ("curve", 2, 4), ("account", 4, 5), ("subsidiary", 5, 6))]
    return []


def validate_input(code, fields):
    check(type(code) is int and code in FIELDS)
    check(type(fields) is dict and set(fields) == set(FIELDS[code]))
    for name, value in fields.items():
        if name in ("c", "rate"):
            integer(value, 1, 1000)
        elif name == "units":
            integer(value, -1000, 1000)
        elif name == "at":
            integer(value, -(2**63), 2**63 - 1)
        elif name.endswith("_unit"):
            check(type(value) is int and 1 <= value <= 65535)
        else:
            identity(value)


def validate_references(facts, code, fields):
    for target, kind, _ in references(code, fields):
        check(target in facts and facts[target]["contract"] == kind, "unavailable_reference")
    if code == 6:
        curve = facts[fields["curve"]]["input"]
        account = facts[fields["account"]]["input"]
        subsidiary = facts[fields["subsidiary"]]["input"]
        check(curve["native_unit"] == account["native_unit"] and
              curve["reporting_unit"] == subsidiary["reporting_unit"], "unavailable_reference")


def ordered(entry):
    key = entry["key"]
    return int(key["at"]), uuid.UUID(key["id"]).bytes, key["slot"]


def scan(kind, entries):
    """Scan source leaves directly, including each complete-time boundary."""
    rows = sorted(entries, key=ordered)
    result = {"count": len(rows), "first": rows[0]["key"]["at"] if rows else None,
              "last": rows[-1]["key"]["at"] if rows else None}
    if kind == "quote":
        return {"kind": kind, "value": result}
    running, prefixes, completed = 0, [0], []
    for i, row in enumerate(rows):
        running += int(row["leaf"]["value"])
        prefixes.append(running)
        if i + 1 == len(rows) or row["key"]["at"] != rows[i + 1]["key"]["at"]:
            completed.append(running)
    internal = completed[:-1]
    result.update(sum=str(running), min_prefix=str(min(prefixes)), max_prefix=str(max(prefixes)),
                  boundary_min=str(min(internal)) if internal else None,
                  boundary_max=str(max(internal)) if internal else None)
    return {"kind": kind, "value": result}


def complete_min(summary):
    value = summary["value"]
    return min(0, int(value["sum"]), int(value["boundary_min"] or "0"))


class State:
    def __init__(self, tenant, actor, model="synthetic-native-model"):
        self.tenant, self.actor, self.model = tenant, actor, model
        self.revision, self.facts, self.records, self.roots = 0, {}, {}, {}
        self.entries, self.rows = {}, {}
        self.derive(None)

    def derive(self, previous):
        """All populations originate in facts, not in observed descriptors."""
        self.rows, self.roots, self.entries, self.records = {}, {}, {}, {}
        counts = [0] * 6
        for rid, fact in self.facts.items():
            code = fact["contract"]
            counts[code - 1] += 1
            self.rows[(5, rid)] = []
            if code == 1:
                self.rows[(6, rid)] = []
            if code in (2, 4, 5):
                slot = {2: 1, 4: 2, 5: 3}[code]
                self.roots[(rid, slot)] = {"kind": "quote" if code == 2 else "financial"}
            if code == 2:
                self.rows[(7, rid, 1)] = []

        def member(rid, slot, root, at, kind, amount):
            self.entries[(rid, slot)] = {"root": address(*root),
                "key": {"at": at, "id": rid, "slot": slot},
                "leaf": {"kind": kind, "value": str(amount)}}

        for rid, fact in sorted(self.facts.items()):
            code, fields = fact["contract"], fact["input"]
            for target, _, slot in references(code, fields):
                self.rows[(5, target)].append(address(rid, slot))
            derived = None
            if code == 3:
                member(rid, 3, (fields["curve"], 1), fields["at"], "quote", fields["rate"])
            if code == 6:
                self.rows[(6, fields["rule"])].append(address(rid, 7))
                self.rows[(7, fields["curve"], 1)].append(address(rid, 1))
                quotes = [(int(q["input"]["at"]), qid, int(q["input"]["rate"]))
                          for qid, q in self.facts.items() if q["contract"] == 3
                          and q["input"]["curve"] == fields["curve"]
                          and int(q["input"]["at"]) <= int(fields["at"])]
                selected = max(quotes) if quotes else None
                rate = selected[2] if selected else 1
                native = int(fields["units"]) * int(self.facts[fields["rule"]]["input"]["c"])
                reporting = native * rate
                derived = {"native_minor": str(native), "reporting_minor": str(reporting)}
                self.rows[(4, rid, 1)] = {"source": address(fields["curve"], 1),
                    "operation": "latest", "phase": "calculate", "channel": "rate",
                    "lower": "negative_infinity", "upper": {"after_time": fields["at"]},
                    "selected": selected[1] if selected else None, "result": str(rate)}
                member(rid, 1, (fields["account"], 2), fields["at"], "financial", native)
                member(rid, 2, (fields["subsidiary"], 3), fields["at"], "financial", reporting)
            value = {"contract": code, "tenant": self.tenant, "owner": self.actor,
                     "reader": self.actor, "version": str(self.revision),
                     "input": deepcopy(fields), "derived": derived}
            old = previous.records.get(rid) if previous else None
            if old and all(value[k] == old[k] for k in value if k != "version"):
                value["version"] = old["version"]
            self.records[rid] = value
            self.rows[(1, rid)] = value
        for key, values in self.rows.items():
            if key[0] in (5, 6, 7):
                values.sort(key=lambda a: (uuid.UUID(a["id"]).bytes, a["slot"]))
        for root, value in self.roots.items():
            entries = {k: e for k, e in self.entries.items() if aid(e["root"]) == root}
            version = self.revision
            if previous and root in previous.roots:
                old_entries = {k: e for k, e in previous.entries.items() if aid(e["root"]) == root}
                if entries == old_entries:
                    version = int(previous.roots[root]["revision"])
            value.update(revision=str(version), summary=scan(value["kind"], entries.values()))
        self.rows[(0,)] = {"model": self.model, "codec": CODEC, "tenant": self.tenant,
                          "actor": self.actor, "revision": str(self.revision), "counts": counts}

    def apply(self, operation):
        check(operation.get("model", "current") == "current", "model_mismatch")
        check(operation.get("codec", CODEC) == CODEC, "model_mismatch")
        check(operation.get("actor", self.actor) == self.actor and
              operation.get("tenant", self.tenant) == self.tenant, "forbidden")
        commands = operation["commands"]
        check(type(commands) is list and 1 <= len(commands) <= 64)
        ids = [identity(c.get("id")) for c in commands]
        check(len(ids) == len(set(ids)))
        candidate = deepcopy(self)
        for command in commands:
            rid, op = command["id"], command.get("op")
            keys = {"create": {"op", "id", "contract", "fields"},
                    "update": {"op", "id", "if_version", "set", "unset"},
                    "delete": {"op", "id", "if_version"}}
            check(op in keys and set(command) == keys[op])
            if op == "create":
                check(rid not in candidate.facts, "already_exists")
                code, fields = command["contract"], deepcopy(command["fields"])
            else:
                check(rid in candidate.facts, "unavailable_reference")
                expected = integer(command["if_version"], 0, 2**64 - 1)
                check(expected == int(self.records[rid]["version"]), "stale_version")
                if op == "delete":
                    del candidate.facts[rid]
                    continue
                code = candidate.facts[rid]["contract"]
                check(type(command["set"]) is dict and exact(command["unset"], []))
                allowed = FIELDS[code] if code in (1, 3, 6) else ()
                check(set(command["set"]) <= set(allowed))
                fields = {**candidate.facts[rid]["input"], **command["set"]}
            validate_input(code, fields)
            validate_references(candidate.facts, code, fields)
            candidate.facts[rid] = {"contract": code, "input": fields}
        counts = [sum(f["contract"] == c for f in candidate.facts.values()) for c in range(1, 7)]
        check(sum(counts) <= 64 and counts[2] <= 16 and counts[5] <= 16, "state_limit")
        quote_times = set()
        for fact in candidate.facts.values():
            code, fields = fact["contract"], fact["input"]
            validate_references(candidate.facts, code, fields)
            if code == 3:
                key = fields["curve"], int(fields["at"])
                check(key not in quote_times, "duplicate_time")
                quote_times.add(key)
        check(self.revision < 2**64 - 1, "revision_exhausted")
        candidate.revision += 1
        candidate.derive(self)
        for root, value in candidate.roots.items():
            if root[1] == 2:
                check(complete_min(value["summary"]) >= 0, "invariant")
        return candidate


def encode_key(key):
    data = bytes([key[0]])
    if len(key) > 1:
        data += uuid.UUID(key[1]).bytes
    if len(key) > 2:
        data += key[2].to_bytes(2, "big")
    return data.hex()


def raw_rows(rows):
    return [{"key": encode_key(k), "value": json.dumps({"type": KINDS[k[0]], "data": v},
              separators=(",", ":")).encode().hex()} for k, v in sorted(rows.items())]


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_FIELD", key)
        result[key] = value
    return result


def decode_rows(raw):
    require(type(raw) is list, "LAYOUT", "raw rows")
    rows = {}
    for row in raw:
        try:
            require(set(row) == {"key", "value"}, "LAYOUT", row)
            key = bytes.fromhex(row["key"])
            require(key and key[0] in KINDS and row["key"] == key.hex(), "KEY", row["key"])
            tag = key[0]
            require(len(key) == (1 if tag == 0 else 19 if tag in (2, 3, 4, 7) else 17), "KEY", key.hex())
            identity_key = (tag,) if tag == 0 else (tag, str(uuid.UUID(bytes=key[1:17])))
            if len(key) == 19:
                slot = int.from_bytes(key[17:], "big")
                require(slot in ((1, 2, 3) if tag in (2, 3) else (1,)), "KEY", key.hex())
                identity_key += (slot,)
            require(identity_key not in rows, "DUPLICATE_ID", identity_key)
            payload = bytes.fromhex(row["value"])
            require(row["value"] == payload.hex(), "VALUE", identity_key)
            value = json.loads(payload, object_pairs_hook=unique_object)
            require(set(value) == {"type", "data"} and value["type"] == KINDS[tag], "VALUE", identity_key)
            rows[identity_key] = value["data"]
        except (ValueError, TypeError, KeyError, UnicodeError) as error:
            raise Failure("DECODE", row) from error
    return rows


def verify(state, raw, *, complete, budget=10000):
    require(complete is True, "INCOMPLETE_SCOPE", "snapshot")
    work = {"rows": len(raw), "nodes": 0, "scanned_leaves": 0}

    def tick(kind, n):
        work[kind] += n
        require(sum(work.values()) <= budget, "INCOMPLETE_BUDGET", work)

    tick("rows", 0)
    rows = decode_rows(raw)
    root_keys = {(2, *r) for r in state.roots}
    node_keys = {(3, *n) for n in state.entries}
    require(rows.keys() == state.rows.keys() | root_keys | node_keys, "INVENTORY", "all KV namespaces")
    for key, expected in state.rows.items():
        require(exact(rows[key], expected), KINDS[key[0]].upper() + "_VALUE", key)
    visited = set()

    def rescan(kind, ids):
        tick("scanned_leaves", len(ids))
        return scan(kind, [state.entries[n] for n in ids])

    for root, expected in state.roots.items():
        header = rows[(2, *root)]
        require(set(header) == {"kind", "head", "first", "last", "height", "summary", "revision"}, "LAYOUT", root)
        require(header["kind"] == expected["kind"] and exact(header["revision"], expected["revision"]), "ROOT_VALUE", root)
        ordered_ids = sorted((n for n, e in state.entries.items() if aid(e["root"]) == root),
                             key=lambda n: ordered(state.entries[n]))

        def visit(link, parent, lower, upper):
            node_id = aid(link)
            if node_id is None:
                return 0, []
            tick("nodes", 1)
            require(node_id not in visited, "TREE_REVISIT", node_id)
            require((3, *node_id) in rows, "DANGLING_LINK", node_id)
            visited.add(node_id)
            node = rows[(3, *node_id)]
            require(set(node) == {"root", "key", "leaf", "parent", "left", "right", "prev", "next", "height", "summary"}, "LAYOUT", node_id)
            require(exact({k: node[k] for k in ("root", "key", "leaf")}, state.entries[node_id]), "NODE_PAYLOAD", node_id)
            require(aid(node["root"]) == root, "WRONG_ROOT", node_id)
            require(aid(node["parent"]) == parent, "PARENT", node_id)
            key = ordered(node)
            require((lower is None or lower < key) and (upper is None or key < upper), "ORDER", node_id)
            lh, left = visit(node["left"], node_id, lower, key)
            rh, right = visit(node["right"], node_id, key, upper)
            require(abs(lh - rh) <= 1, "BALANCE", node_id)
            height = 1 + max(lh, rh)
            require(exact(node["height"], height), "HEIGHT", node_id)
            ids = left + [node_id] + right
            require(exact(node["summary"], rescan(header["kind"], ids)), "NODE_SUMMARY", node_id)
            return height, ids

        height, actual_ids = visit(header["head"], None, None, None)
        require(actual_ids == ordered_ids, "REACHABILITY", root)
        require(exact(header["height"], height), "ROOT_HEIGHT", root)
        require(aid(header["first"]) == (ordered_ids[0] if ordered_ids else None) and
                aid(header["last"]) == (ordered_ids[-1] if ordered_ids else None), "ROOT_ENDPOINT", root)
        require(exact(header["summary"], rescan(header["kind"], ordered_ids)), "ROOT_SUMMARY", root)
        for i, node_id in enumerate(ordered_ids):
            node = rows[(3, *node_id)]
            require(aid(node["prev"]) == (ordered_ids[i - 1] if i else None) and
                    aid(node["next"]) == (ordered_ids[i + 1] if i + 1 < len(ordered_ids) else None), "NEIGHBOUR", node_id)
        if root[1] == 2:
            require(complete_min(expected["summary"]) >= 0, "INVARIANT", root)
    require(visited == state.entries.keys(), "REACHABILITY", "global")
    return work


def synthetic(state, lower=False):
    """Assemble two valid shapes for checker controls; never used as native evidence."""
    rows = deepcopy(state.rows)
    for root, info in state.roots.items():
        ids = sorted((n for n, e in state.entries.items() if aid(e["root"]) == root),
                     key=lambda n: ordered(state.entries[n]))

        def arrange(nodes, parent):
            if not nodes:
                return None, 0
            mid = (len(nodes) - int(lower)) // 2
            current = nodes[mid]
            link = address(*current)
            left, lh = arrange(nodes[:mid], link)
            right, rh = arrange(nodes[mid + 1:], link)
            rows[(3, *current)] = {**deepcopy(state.entries[current]), "parent": parent,
                "left": left, "right": right, "prev": None, "next": None,
                "height": 1 + max(lh, rh),
                "summary": scan(info["kind"], [state.entries[n] for n in nodes])}
            return link, 1 + max(lh, rh)

        head, height = arrange(ids, None)
        for i, node in enumerate(ids):
            rows[(3, *node)].update(prev=address(*ids[i - 1]) if i else None,
                next=address(*ids[i + 1]) if i + 1 < len(ids) else None)
        rows[(2, *root)] = {"kind": info["kind"], "head": head,
            "first": address(*ids[0]) if ids else None, "last": address(*ids[-1]) if ids else None,
            "height": height, "summary": deepcopy(info["summary"]), "revision": info["revision"]}
    return raw_rows(rows)


def literals(state, expected, labels):
    for name, values in expected.get("postings", {}).items():
        actual = state.records[labels[name]]["derived"]
        require([actual["native_minor"], actual["reporting_minor"]] == values, "LITERAL_AMOUNT", name)
    for name, total in expected.get("totals", {}).items():
        rid = labels[name]
        root = next(r for r in state.roots if r[0] == rid)
        require(state.roots[root]["summary"]["value"]["sum"] == total, "LITERAL_TOTAL", name)


def outcome(state, operation):
    try:
        proposed = state.apply(operation)
    except Reject as error:
        return state, "rejected", error.code, False
    expected = operation["expect"]
    if "abort_after" in operation:
        return state, "rejected", "injected_abort", True
    if expected.get("code") == "work_limit":
        require("work_limit" in operation, "FIXTURE", "missing work limit")
        return state, "rejected", "work_limit", True
    return proposed, "committed", None, False


def exercise_cases(fixtures, report=None):
    controls = []
    actual_cases = {c["name"]: c for c in report["cases"]} if report else {}
    if report:
        require(len(actual_cases) == len(report["cases"]) == len(fixtures["cases"]), "CASE_INVENTORY", "cases")
    for case in fixtures["cases"]:
        state = State(fixtures["tenant"], fixtures["actor"], report["model"] if report else "synthetic-native-model")
        base = fixtures["bases"][case["base"]]
        if base:
            state = state.apply({"commands": base})
        actual = actual_cases.get(case["name"])
        previous_raw = None
        if report:
            require(actual is not None and len(actual["operations"]) == len(case["operations"]), "CASE_INVENTORY", case["name"])
            initial = actual["initial"]
            require(initial["tables"] == ["native_kv"], "TABLE_INVENTORY", case["name"])
            verify(state, initial["rows"], complete=initial["complete"])
            previous_raw = initial["rows"]
        for index, operation in enumerate(case["operations"]):
            state, status, code, mechanism = outcome(state, operation)
            expected = operation["expect"]
            require(status == expected["status"] and code == expected.get("code"), "CASE_OUTCOME", (case["name"], index, code))
            literals(state, expected, fixtures["ids"])
            control = {"case": case["name"], "step": index, "status": status, "code": code,
                       "mechanism_requires_runtime": mechanism}
            if report:
                observed = actual["operations"][index]
                require(observed["status"] == status and observed.get("code") == code, "RUNTIME_OUTCOME", control)
                image = observed["after"]
                require(image["tables"] == ["native_kv"], "TABLE_INVENTORY", control)
                control["checker_work"] = verify(state, image["rows"], complete=image["complete"])
                require(observed["old_snapshot_unchanged"] is True, "OLD_SNAPSHOT", control)
                if status == "rejected":
                    require(exact(image["rows"], previous_raw), "ROLLBACK_BYTES", control)
                    require(observed["returned"] is None, "REJECTED_RETURN", control)
                else:
                    require(exact(observed["returned"], {"revision": str(state.revision)}), "COMMIT_RETURN", control)
                if "abort_after" in operation:
                    require(observed["applied_writes"] > 0, "ABORT_NOT_EXERCISED", control)
                if expected.get("staged_min"):
                    require(observed["work"]["staged_patches"] >= expected["staged_min"], "LATE_FAILURE", control)
                previous_raw = image["rows"]
            controls.append(control)
        if report:
            require(actual["reopened_equal"] is True, "REOPEN", case["name"])
    return controls


def corruption_controls(state, labels):
    base = synthetic(state)
    results = []
    for lower in (False, True):
        verify(state, synthetic(state, lower), complete=True)

    def reject(name, mutate, obligation):
        rows = decode_rows(base)
        mutate(rows)
        try:
            verify(state, raw_rows(rows), complete=True)
        except Failure as error:
            require(error.code == obligation, "WRONG_FAILURE", (name, error.code))
            results.append({"case": name, "obligation": error.code})
        else:
            raise AssertionError(name)

    p, a, b, c, d = (labels[n] for n in ("P", "A", "B", "C", "D"))
    reject("erased_subscribers", lambda r: r[(7, c, 1)].clear(), "SUBSCRIBERS_VALUE")
    reject("missing_empty_root", lambda r: r.pop((2, b, 2)), "INVENTORY")
    reject("missing_source", lambda r: r.pop((1, p)), "INVENTORY")
    reject("missing_member", lambda r: r.pop((3, p, 1)), "INVENTORY")
    reject("missing_direct_route", lambda r: r[(6, d)].clear(), "DIRECT_VALUE")
    reject("missing_reference_route", lambda r: r[(5, a)].clear(), "INCOMING_VALUE")
    reject("wrong_selected_quote", lambda r: r[(4, p, 1)].update(selected=None), "QUERY_VALUE")
    reject("wrong_query_bound", lambda r: r[(4, p, 1)].update(upper={"after_time": "16"}), "QUERY_VALUE")
    reject("wrong_summary", lambda r: r[(3, p, 1)]["summary"]["value"].update(sum="9"), "NODE_SUMMARY")
    reject("wrong_scalar_type", lambda r: r[(1, p)]["derived"].update(native_minor=8), "RECORD_VALUE")
    reject("wrong_parent", lambda r: r[(3, p, 1)].update(parent=address(p, 1)), "PARENT")
    reject("wrong_endpoint", lambda r: r[(2, a, 2)].update(first=None), "ROOT_ENDPOINT")
    reject("wrong_neighbour", lambda r: r[(3, p, 1)].update(next=None), "NEIGHBOUR")
    reject("wrong_height", lambda r: r[(3, p, 1)].update(height=True), "HEIGHT")
    q = labels["Q"]
    reject("cycle", lambda r: r[(3, q, 1)].update(left=address(q, 1)), "TREE_REVISIT")
    reject("cross_root_link", lambda r: r[(2, a, 2)].update(head=address(p, 2)), "WRONG_ROOT")
    for name, image, complete, budget, code in (
        ("duplicate_raw_identity", base + [deepcopy(base[0])], True, 10000, "DUPLICATE_ID"),
        ("unknown_namespace", base + [{"key": "ff", "value": "7b7d"}], True, 10000, "KEY"),
        ("partial", base, False, 10000, "INCOMPLETE_SCOPE"),
        ("budget", base, True, 1, "INCOMPLETE_BUDGET")):
        try:
            verify(state, image, complete=complete, budget=budget)
        except Failure as error:
            require(error.code == code, "WRONG_FAILURE", (name, error.code))
            results.append({"case": name, "obligation": code})
        else:
            raise AssertionError(name)
    for name, commands, key, mutation, code in (
        ("lost_zero_member", [{"op": "update", "id": p, "if_version": "1",
          "set": {"units": "0"}, "unset": []}], (3, p, 1), None, "INVENTORY"),
        ("equal_rate_old_selection", [{"op": "create", "id": labels["Z"], "contract": 3,
          "fields": {"curve": c, "at": "12", "rate": "3"}}], (4, p, 1),
          {"selected": labels["X"]}, "QUERY_VALUE")):
        control = state.apply({"commands": commands})
        image = synthetic(control)
        verify(control, image, complete=True)
        rows = decode_rows(image)
        if mutation is None:
            rows.pop(key)
        else:
            rows[key].update(mutation)
        try:
            verify(control, raw_rows(rows), complete=True)
        except Failure as error:
            require(error.code == code, "WRONG_FAILURE", (name, error.code))
            results.append({"case": name, "obligation": code})
        else:
            raise AssertionError(name)
    return results


def model_digest():
    digest = hashlib.sha256(b"rebase-native-slice-model-v1\0")
    for name in sorted(MODEL_FILES):
        for data in (name.encode(), (ROOT / name).read_bytes()):
            digest.update(len(data).to_bytes(8, "big"))
            digest.update(data)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actual", type=Path)
    args = parser.parse_args()
    fixtures = json.loads((ROOT / "research/fixtures/native-slice.json").read_text(), object_pairs_hook=unique_object)
    actual = json.loads(args.actual.read_text(), object_pairs_hook=unique_object) if args.actual else None
    if actual:
        require(actual["model"] == model_digest(), "MODEL", "compiled source fingerprint")
        require(actual["format"] == "native-slice-run-v1", "LAYOUT", "report")
    controls = exercise_cases(fixtures, actual)
    base = State(fixtures["tenant"], fixtures["actor"]).apply({"commands": fixtures["bases"]["baseline"]})
    require(len(base.records) == 9 and len(base.roots) == 4 and len(base.entries) == 6
            and len(base.rows) + len(base.roots) + len(base.entries) == 33, "LITERAL_INVENTORY", "baseline")
    corruptions = corruption_controls(base, fixtures["ids"])
    result = {"status": "passed", "scope": "native redb observations" if actual else "source oracle and synthetic checker controls only",
              "cases": len(fixtures["cases"]), "operations": controls,
              "valid_checker_controls": 4, "corruption_controls": corruptions,
              "baseline_kv_rows": 33, "native_runtime_checked": actual is not None}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
