#!/usr/bin/env python3
"""Independent source oracle and complete native-KV checker.

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
CODEC = "native-slice-kv-2"
FIELDS = {1: ("c",), 2: ("native_unit", "reporting_unit"),
          3: ("curve", "at", "rate"), 4: ("native_unit",),
          5: ("reporting_unit",),
          6: ("units", "at", "rule", "curve", "account", "subsidiary"),
          7: ("at",), 8: ("account", "at", "amount"),
          9: ("account", "moment", "offset", "target", "post"),
          10: ("sources", "factor", "account", "at", "feedback"),
          11: ("output",), 12: ("producer", "role", "account", "at", "amount")}
KINDS = {0: "meta", 1: "record", 2: "root", 3: "node", 4: "query",
         5: "incoming", 6: "direct", 7: "subscribers", 8: "role", 9: "reserved"}



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
    if code == 8:
        return [(fields["account"], 4, 1)]
    if code == 9:
        return [(fields["account"], 4, 1), (fields["moment"], 7, 2)]
    if code == 10:
        return [(r, 4, i + 1) for i, r in enumerate(fields["sources"])] + [(fields["account"], 4, 3)] + ([(fields["feedback"]["account"], 4, 4)] if fields["feedback"] else [])
    if code == 11:
        return [(fields["output"], 12, 1)]
    if code == 12:
        return [(fields["producer"], 0, 1), (fields["account"], 4, 2)]
    return []


def validate_input(code, fields):
    check(type(code) is int and code in FIELDS)
    check(type(fields) is dict and set(fields) == set(FIELDS[code]))
    for name, value in fields.items():
        if name in ("c", "rate"):
            integer(value, 1, 1000)
        elif name in ("units", "amount", "offset", "target"):
            integer(value, -1000, 1000)
        elif name == "at":
            integer(value, -(2**63), 2**63 - 1)
        elif name.endswith("_unit"):
            check(type(value) is int and 1 <= value <= 65535)
        elif name == "factor":
            integer(value, 1, 3)
        elif name == "post":
            check(type(value) is bool)
        elif name == "sources":
            check(type(value) is list and 1 <= len(value) <= 2)
            for source in value: identity(source)
        elif name == "feedback":
            check(value is None or type(value) is dict and set(value) == {"account", "at"})
            if value is not None:
                identity(value["account"])
                integer(value["at"], -(2**63), 2**63 - 1)
        elif name == "role":
            check(type(value) is int and 1 <= value <= 2)
        else:
            identity(value)


def validate_references(facts, code, fields):
    for target, kind, _ in references(code, fields):
        check(target in facts and (facts[target]["contract"] == kind or kind == 0 and facts[target]["contract"] in (9, 10)), "unavailable_reference")
    if code == 6:
        curve = facts[fields["curve"]]["input"]
        account = facts[fields["account"]]["input"]
        subsidiary = facts[fields["subsidiary"]]["input"]
        check(curve["native_unit"] == account["native_unit"] and
              curve["reporting_unit"] == subsidiary["reporting_unit"], "unavailable_reference")
    if code == 10:
        unit = facts[fields["account"]]["input"]["native_unit"]
        for account in fields["sources"] + ([fields["feedback"]["account"]] if fields["feedback"] else []):
            check(facts[account]["input"]["native_unit"] == unit, "unavailable_reference")


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
        self.roles = {}
        self.derive(None)

    def available(self):
        return {**{rid: r for rid, r in self.records.items() if r["contract"] == 12}, **self.facts}

    def derive(self, previous, allocations=()):
        """All populations originate in facts, not in observed descriptors."""
        self.rows, self.roots, self.entries, self.records = {}, {}, {}, {}
        counts = [0] * 12
        for rid, fact in self.facts.items():
            code = fact["contract"]
            counts[code - 1] += 1
            self.rows[(5, rid)] = []
            if code in (1, 7):
                self.rows[(6, rid)] = []
            if code in (2, 4, 5):
                slot = {2: 1, 4: 2, 5: 3}[code]
                self.roots[(rid, slot)] = {"kind": "quote" if code == 2 else "financial"}
            if code == 2:
                self.rows[(7, rid, 1)] = []
            if code == 4:
                self.rows[(7, rid, 2)] = []

        def member(rid, slot, root, at, kind, amount):
            self.entries[(rid, slot)] = {"root": address(*root),
                "key": {"at": at, "id": rid, "slot": slot},
                "leaf": {"kind": kind, "value": str(amount)}}

        derived_values, emits, times = {}, {}, {}
        for rid, fact in sorted(self.facts.items()):
            code, fields = fact["contract"], fact["input"]
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
            if code == 8:
                member(rid, 1, (fields["account"], 2), fields["at"], "financial", fields["amount"])
            if code == 9:
                at = int(self.facts[fields["moment"]]["input"]["at"]) + int(fields["offset"])
                check(-(2**63) <= at < 2**63)
                times[rid] = at
                if fields["post"]: emits[rid, 1] = (fields["account"], at, False)
                self.rows[(6, fields["moment"])].append(address(rid, 6))
                for slot in (1, 2): self.rows[(7, fields["account"], 2)].append(address(rid, slot))
            if code == 10:
                emits[rid, 1] = fields["account"], int(fields["at"]), False
                if fields["feedback"]:
                    f = fields["feedback"]
                    emits[rid, 2] = f["account"], int(f["at"]), True
                for i, source in enumerate(fields["sources"]): self.rows[(7, source, 2)].append(address(rid, i + 1))
            derived_values[rid] = derived

        authored_entries = tuple(self.entries.values())
        values, visiting = {}, set()

        def checked(value):
            check(-(2**127) <= value < 2**127, "overflow")
            return value

        def source_read(account, before=None):
            total = sum(int(e["leaf"]["value"]) for e in authored_entries
                        if aid(e["root"]) == (account, 2) and (before is None or int(e["key"]["at"]) < before))
            for (producer, _), (root, at, zero) in sorted(emits.items()):
                if root == account and (before is None or at < before):
                    amount = calculate(producer)  # Even a zero output retains this dependency.
                    total += 0 if zero else amount
            return checked(total)

        def calculate(rid):
            if rid in values: return values[rid]
            check(rid not in visiting, "feedback")
            visiting.add(rid)
            fact = self.facts[rid]
            code, fields = fact["contract"], fact["input"]
            if code == 9:
                before = source_read(fields["account"], times[rid])
                value = checked(int(fields["target"]) - before)
                derived_values[rid] = {"at": str(times[rid]), "before": str(before), "delta": str(value)}
            else:
                value = checked(int(fields["factor"]) * sum(source_read(r) for r in fields["sources"]))
                derived_values[rid] = {"value": str(value)}
            visiting.remove(rid)
            values[rid] = value
            return value

        for rid, fact in sorted(self.facts.items()):
            if fact["contract"] in (9, 10): calculate(rid)
        pool = iter(allocations)
        for role in sorted(emits):
            if role in self.roles: continue
            for _ in range(8):
                try: allocated = identity(next(pool))
                except StopIteration: raise Reject("allocation_exhausted") from None
                if allocated in self.facts or previous and allocated in previous.records or any(
                        allocated == binding["output"] or allocated == producer for (producer, _), binding in self.roles.items()):
                    continue
                self.roles[role] = {"output": allocated, "retired": False}
                check(len(self.roles) <= 256, "state_limit")
                break
            else: raise Reject("allocation_collision")
        for (producer, _), binding in self.roles.items():
            if producer not in self.facts: binding["retired"] = True

        all_facts = deepcopy(self.facts)
        for (producer, role), (account, at, zero) in sorted(emits.items()):
            rid = self.roles[producer, role]["output"]
            amount = 0 if zero else values[producer]
            all_facts[rid] = {"contract": 12, "input": {"producer": producer, "role": role, "account": account, "at": str(at), "amount": str(amount)}}
            derived_values[rid] = None
            self.rows[(5, rid)] = []
            counts[11] += 1
            member(rid, 1, (account, 2), str(at), "financial", amount)
        check(counts[11] <= 48, "state_limit")
        for rid, fact in sorted(all_facts.items()):
            code, fields = fact["contract"], fact["input"]
            validate_references(all_facts, code, fields)
            for target, _, slot in references(code, fields): self.rows[(5, target)].append(address(rid, slot))
            if code in (9, 10):
                reads = [(fields["account"], times[rid], "calculate"), (fields["account"], times[rid], "validate")] if code == 9 else [(source, None, "calculate") for source in fields["sources"]]
                for i, (source, before, phase) in enumerate(reads):
                    result = source_read(source, before)
                    if phase == "validate": check(result >= 0, "invariant")
                    self.rows[(4, rid, i + 1)] = {"source": address(source, 2), "operation": "sum", "phase": phase,
                        "channel": "amount", "lower": "negative_infinity", "upper": "all" if before is None else {"before_time": str(before)}, "selected": None, "result": str(result)}
            value = {"contract": code, "tenant": self.tenant, "owner": self.actor,
                     "reader": self.actor, "version": str(self.revision),
                     "input": deepcopy(fields), "derived": derived_values[rid]}
            old = previous.records.get(rid) if previous else None
            if old and all(value[k] == old[k] for k in value if k != "version"):
                value["version"] = old["version"]
            self.records[rid] = value
            self.rows[(1, rid)] = value
        for (producer, slot), binding in self.roles.items():
            self.rows[(8, producer, slot)] = deepcopy(binding)
            self.rows[(9, binding["output"])] = address(producer, slot)
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
                          "actor": self.actor, "revision": str(self.revision), "counts": counts, "reserved": len(self.roles)}

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
            old = candidate.available().get(rid)
            if old and (old["contract"] == 12 or old["contract"] == 11 and not operation.get("trusted", False)):
                raise Reject("forbidden")
            if op == "create":
                check(command["contract"] != 12 and (command["contract"] != 11 or operation.get("trusted", False)), "forbidden")
                check(rid not in candidate.facts, "already_exists")
                check(not any(rid == producer or rid == binding["output"] for (producer, _), binding in candidate.roles.items()), "unavailable_reference")
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
                allowed = FIELDS[code] if code in (1, 3, 6, 7, 8, 9, 10) else ()
                check(set(command["set"]) <= set(allowed))
                fields = {**candidate.facts[rid]["input"], **command["set"]}
            validate_input(code, fields)
            validate_references(candidate.available(), code, fields)
            candidate.facts[rid] = {"contract": code, "input": fields}
        counts = [sum(f["contract"] == c for f in candidate.facts.values()) for c in range(1, 12)]
        check(sum(counts) <= 64 and all(counts[i] <= 16 for i in (2, 5, 8, 9)), "state_limit")
        quote_times = set()
        for fact in candidate.facts.values():
            code, fields = fact["contract"], fact["input"]
            if code != 11: validate_references(candidate.facts, code, fields)
            if code == 3:
                key = fields["curve"], int(fields["at"])
                check(key not in quote_times, "duplicate_time")
                quote_times.add(key)
        check(self.revision < 2**64 - 1, "revision_exhausted")
        candidate.revision += 1
        candidate.derive(self, operation.get("allocations", []))
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
            require(len(key) == (1 if tag == 0 else 19 if tag in (2, 3, 4, 7, 8) else 17), "KEY", key.hex())
            identity_key = (tag,) if tag == 0 else (tag, str(uuid.UUID(bytes=key[1:17])))
            if len(key) == 19:
                slot = int.from_bytes(key[17:], "big")
                require(slot in ((1, 2, 3) if tag in (2, 3, 7) else (1, 2)), "KEY", key.hex())
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
    for name, value in expected.get("derived", {}).items():
        require(exact(state.records[labels[name]]["derived"], value), "LITERAL_DERIVED", name)
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
            state = state.apply({"commands": base, "allocations": fixtures.get("base_allocations", {}).get(case["base"], [])})
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
                for kind, value in expected.get("work", {}).items():
                    require(exact(observed["work"].get(kind), value), "WORK_BOUND",
                            (control, kind, observed["work"].get(kind), value))
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


def causal_corruption_controls(fixtures):
    labels = fixtures["ids"]
    state = State(fixtures["tenant"], fixtures["actor"]).apply({
        "commands": fixtures["bases"]["baseline"],
        "allocations": fixtures["base_allocations"]["baseline"]})
    require(len(state.records) == 19 and len(state.entries) == 7
            and len(state.rows) + len(state.roots) + len(state.entries) == 76,
            "LITERAL_INVENTORY", "causal baseline")
    results = []

    def reject(name, source, mutate, obligation):
        image = synthetic(source)
        verify(source, image, complete=True)
        rows = decode_rows(image)
        mutate(rows)
        try:
            verify(source, raw_rows(rows), complete=True)
        except Failure as error:
            require(error.code == obligation, "WRONG_FAILURE", (name, error.code))
            results.append({"case": name, "obligation": error.code})
        else:
            raise AssertionError(name)

    p, output = labels["P"], labels["O_P"]
    reject("missing_output_role", state, lambda r: r.pop((8, p, 1)), "INVENTORY")
    reject("missing_reverse_reservation", state, lambda r: r.pop((9, output)), "INVENTORY")
    reject("missing_private_record", state, lambda r: r.pop((1, output)), "INVENTORY")
    reject("missing_private_member", state, lambda r: r.pop((3, output, 1)), "INVENTORY")
    reject("redirected_role_identity", state,
           lambda r: r[(8, p, 1)].update(output=labels["O_Q"]), "ROLE_VALUE")
    reject("redirected_reverse_identity", state,
           lambda r: r[(9, output)].update(id=labels["Q"]), "RESERVED_VALUE")
    reject("wrong_output_producer", state,
           lambda r: r[(1, output)]["input"].update(producer=labels["Q"]), "RECORD_VALUE")
    reject("conflated_validation_query", state,
           lambda r: r[(4, p, 2)].update(phase="calculate"), "QUERY_VALUE")
    disabled = state.apply({"commands": [{"op": "update", "id": p, "if_version": "1",
        "set": {"post": False}, "unset": []}]})
    reject("lost_inactive_reservation", disabled, lambda r: r.pop((9, output)), "INVENTORY")
    retired = state.apply({"commands": [{"op": "delete", "id": p, "if_version": "1"}]})
    reject("lost_retired_role", retired, lambda r: r.pop((8, p, 1)), "INVENTORY")
    reject("reactivated_retired_role", retired,
           lambda r: r[(8, p, 1)].update(retired=False), "ROLE_VALUE")
    zero = state.apply({"commands": [{"op": "update", "id": p, "if_version": "1",
        "set": {"target": "10"}, "unset": []}]})
    reject("lost_zero_output", zero, lambda r: r.pop((1, output)), "INVENTORY")
    return results


def model_digest():
    # Explicit data/behavior contract, independent of build/dependency bytes.
    # Release evidence still fingerprints every executed source separately.
    return hashlib.sha256(b"rebase-calculation-contract-1").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actual", type=Path)
    parser.add_argument("--fixtures", type=Path, default=ROOT / "research/fixtures/native-slice.json")
    args = parser.parse_args()
    fixtures = json.loads(args.fixtures.read_text(), object_pairs_hook=unique_object)
    actual = json.loads(args.actual.read_text(), object_pairs_hook=unique_object) if args.actual else None
    if actual:
        require(actual["model"] == model_digest(), "MODEL", "declared behavior contract")
        require(actual["format"] == "native-slice-run-v1", "LAYOUT", "report")
    controls = exercise_cases(fixtures, actual)
    original_fixtures = json.loads((ROOT / "research/fixtures/native-slice.json").read_text(), object_pairs_hook=unique_object)
    base = State(original_fixtures["tenant"], original_fixtures["actor"]).apply({"commands": original_fixtures["bases"]["baseline"]})
    require(len(base.records) == 9 and len(base.roots) == 4 and len(base.entries) == 6
            and len(base.rows) + len(base.roots) + len(base.entries) == 35, "LITERAL_INVENTORY", "baseline")
    corruptions = corruption_controls(base, original_fixtures["ids"])
    causal_fixtures = json.loads((ROOT / "research/fixtures/causal-slice.json").read_text(), object_pairs_hook=unique_object)
    causal_corruptions = causal_corruption_controls(causal_fixtures)
    result = {"status": "passed", "scope": "native redb observations" if actual else "source oracle and synthetic checker controls only",
              "cases": len(fixtures["cases"]), "operations": controls,
              "valid_checker_controls": 4, "corruption_controls": corruptions,
              "causal_corruption_controls": causal_corruptions,
              "baseline_kv_rows": 35, "native_runtime_checked": actual is not None}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
