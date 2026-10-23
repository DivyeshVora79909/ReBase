#!/usr/bin/env python3
"""G4c: independent dimensioned source scans against the real authenticated API."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import client  # noqa: E402
from capacity import restricted_actor, snapshot  # noqa: E402
from harness import Backend, expect_error, require  # noqa: E402

LIMIT = 10**12


def summary(events):
    """Literal arithmetic over authored observations; no maintained cache input."""
    values = [value for _, unit, value in events]
    units = {unit for _, unit, _ in events}
    require(len(units) <= 1, "Mixed source dimensions")
    return {"count": len(values), "sum": str(sum(values)),
            "min": str(min(values)) if values else None,
            "max": str(max(values)) if values else None,
            "unit": next(iter(units)) if units else None}


def expected(facts):
    require(len(facts) <= 64, "Source population bound")
    roots = {identity: [] for identity, r in facts.items() if r["contract"] == 101}
    for identity, record in facts.items():
        f = record["fields"]
        require(1 <= f["unit"] <= 65535, "Source unit bound")
        if record["contract"] == 101:
            continue
        require(record["contract"] == 211, "Unknown source contract")
        require(f["instrument"] in roots, "Missing source instrument")
        require(facts[f["instrument"]]["fields"]["unit"] == f["unit"],
                "Source observation and instrument dimensions differ")
        require(-(2**63) <= int(f["at"]) < 2**63, "Source time bound")
        require(-LIMIT <= int(f["value"]) <= LIMIT, "Source value bound")
        roots[f["instrument"]].append((int(f["at"]), f["unit"], int(f["value"])))
    return roots


def contains(at, window):
    for name in ("lower", "upper"):
        bound = window[name]
        if bound is None:
            continue
        kind, text = next(iter(bound.items()))
        value = int(text)
        if name == "lower" and (at < value or (at == value and kind == "excluded")):
            return False
        if name == "upper" and (at > value or (at == value and kind == "excluded")):
            return False
    return True


def scan(backend, model):
    records, cursor = {}, None
    for _ in range(12):
        page = backend.call("records.page", {"model": model,
            "query": {"path": "records.by_id", "contract": None, "equals": None},
            "limit": 7, "visit_budget": 32, "cursor": cursor})
        for record in page["records"]:
            require(record["id"] not in records, "Repeated source identity")
            records[record["id"]] = record
        if page["exhausted"]:
            return records
        require(page["cursor"] and page["cursor"] != cursor, "Source pagination progress")
        cursor = page["cursor"]
    raise RuntimeError("Incomplete public source scan")


def verify(backend, model, facts, windows=False):
    roots = expected(facts)
    records = scan(backend, model)
    require(records.keys() == facts.keys(), "Complete source inventory")
    for identity, record in records.items():
        require(record["contract"] == facts[identity]["contract"]
                and record["input"] == facts[identity]["fields"] and record["derived"] is None,
                "Authored source or empty derived value differs")
    for owner, events in roots.items():
        request = {"model": model, "owner": owner, "slot": 7, "read": {"kind": "summary"}}
        require(backend.call("roots.read", request)["value"] == summary(events),
                "Literal source statistics differ from root")
        if not windows:
            continue
        times = sorted({-(2**63), 2**63-1, 0, 10, *(at for at, _, _ in events)})
        for at in times:
            request["read"] = {"kind": "before", "at": str(at)}
            require(backend.call("roots.read", request)["value"]
                    == summary([event for event in events if event[0] < at]), "Strict-before source scan")
        ranges = [{"lower": None, "upper": None},
                  {"lower": {"included": "10"}, "upper": {"included": "10"}},
                  {"lower": {"excluded": "10"}, "upper": {"included": "10"}},
                  {"lower": {"included": "10"}, "upper": {"excluded": "0"}},
                  {"lower": {"included": "-9223372036854775808"},
                   "upper": {"included": "9223372036854775807"}}]
        for at in times:
            ranges.extend({"lower": {lower: str(at)}, "upper": {upper: str(at)}}
                          for lower in ("included", "excluded") for upper in ("included", "excluded"))
        for window in ranges:
            request["read"] = {"kind": "range", "range": window}
            require(backend.call("roots.read", request)["value"]
                    == summary([event for event in events if contains(event[0], window)]),
                    "Inclusive/exclusive literal window differs")
    return records


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


def corrupt_restore_controls(backend, backup):
    """Rehash complete backups so native validation, not a stale digest, rejects."""
    original = json.loads(backup.read_text())
    controls = ("index-code", "key-variant", "leaf-variant", "summary-variant", "span", "cache")
    for label in controls:
        image = deepcopy(original)
        for row in image["payload"]["tables"]["native_kv"]:
            if not row["key"].startswith("03"):  # Native membership node.
                continue
            value = json.loads(bytes.fromhex(row["value"]))
            node = value["data"]
            if label == "index-code":
                node["kind"] = 999
            elif label == "key-variant":
                node["key"]["value"] = {"quote": "0"}
            elif label == "leaf-variant":
                node["leaf"] = {"kind": "financial", "value": "1"}
            elif label == "summary-variant":
                node["summary"] = {"kind": "quote", "value": {"count": 1}}
            elif label == "span":
                node["span"]["first"] = str(int(node["span"]["first"]) + 1)
            else:
                # A leaf's value and cached singleton agree internally but now
                # contradict the authored public source. Checker's source scan
                # must reject even though native local bounds still hold.
                leaf_value = int(node["leaf"]["value"])
                next_value = leaf_value + 1 if leaf_value < LIMIT else leaf_value - 1
                delta = next_value - leaf_value
                node["leaf"]["value"] = str(next_value)
                node["summary"]["sum"] = str(int(node["summary"]["sum"]) + delta)
                if node["summary"]["count"] == 1:
                    node["summary"]["min"] = node["summary"]["max"] = str(next_value)
            row["value"] = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode().hex()
            break
        else:
            raise RuntimeError("Corruption fixture lacks native member")
        payload = json.dumps(image["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        image["sha256"] = hashlib.sha256(payload).hexdigest()
        source, destination = (backend.directory / f"bad-{label}.json", backend.directory / f"bad-{label}.redb")
        source.write_text(json.dumps(image, sort_keys=True, separators=(",", ":")))
        result = subprocess.run([str(backend.binary), "--model", "measurement", "restore", str(source), str(destination)],
                                capture_output=True, timeout=60)
        require(result.returncode != 0 and not destination.exists(), "Corrupt restore published a store")
        require(b"checksum" not in result.stderr.lower(), "Corruption rejected only by backup checksum")
    return list(controls)


def run(binary, destination):
    backend = Backend(binary, destination, model="measurement")
    facts, operations = {}, []
    latest = None
    try:
        backend.start()
        public = backend.call("model.describe", {})
        model = public["model"]
        require({c["code"] for c in public["contracts"]} == {101, 211}, "Measurement public contracts")
        restricted = restricted_actor(backend, model)
        namespace = uuid.UUID(int=20261023)
        draft = backend.cli("fixture", "plan", "measurements", "--namespace", namespace)
        require(draft == backend.cli("fixture", "plan", "measurements", "--namespace", namespace), "Repeatable fixture")
        ids = draft["fixture"]["ids"]
        require(all(identity == str(uuid.uuid5(namespace, f"measurements/{label}")) for label, identity in ids.items()), "Independent fixture identities")

        def mutate(label, commands, error=None):
            nonlocal facts, latest
            before = verify(backend, model, facts)
            plan = backend.plan({"model": model, "commands": commands, "returning": []}, label)
            if error:
                if error == "invariant":
                    try:
                        expected(propose(facts, commands))
                    except RuntimeError:
                        pass
                    else:
                        raise RuntimeError("Source oracle accepted invalid dimension")
                raw = snapshot(backend, f"{label}-before")
                expect_error(error, lambda: client.execute(backend.url, backend.token, plan))
                require(snapshot(backend, f"{label}-after") == raw, "Rejected batch changed complete logical bytes")
                require(verify(backend, model, facts) == before, "Rejected batch changed record versions")
                require(client.execute(backend.url, backend.token, plan, status=True)["status"] == "not_observed", "Rejected receipt retained")
            else:
                proposed = propose(facts, commands)
                expected(proposed)
                outcome = client.execute(backend.url, backend.token, plan)
                require(outcome["status"] == "committed", "Mutation did not commit")
                facts = proposed
                verify(backend, model, facts)
                replay = client.execute(backend.url, backend.token, plan)
                require(replay["replayed"] and replay["result"] == outcome["result"], "Exact replay")
                latest = plan, outcome
            operations.append({"name": label, "commands": len(commands), "result": error or "committed"})

        def update(identity, fields):
            record = backend.call("records.get", {"model": model, "id": identity})
            return {"op": "update", "id": identity, "if_version": record["version"], "set": fields, "unset": []}

        def create(label, code, fields):
            return {"op": "create", "id": str(uuid.uuid5(namespace, f"trial/{label}")), "contract": code, "fields": fields}

        def delete(identity):
            record = backend.call("records.get", {"model": model, "id": identity})
            return {"op": "delete", "id": identity, "if_version": record["version"]}

        mutate("fixture", draft["commands"])
        verify(backend, model, facts, windows=True)
        mutate("mixed-dimension", [update(ids["b"], {"unit": 8})], "invariant")
        mutate("owner-dimension", [update(ids["instrument"], {"unit": 8})], "invariant")
        for unit, parent_first in ((8, True), (7, False)):
            parent = update(ids["instrument"], {"unit": unit})
            children = [update(ids[name], {"unit": unit}) for name in ("a", "b", "c")]
            mutate(f"unit-repair-parent-{parent_first}", [parent, *children] if parent_first else [*children, parent])
        mutate("extreme-time-and-value", [update(ids["a"], {"at": str(-(2**63)), "value": str(-LIMIT)}),
                                           update(ids["c"], {"at": str(2**63-1), "value": str(LIMIT)})])
        verify(backend, model, facts, windows=True)
        mutate("compatible-root-move", [update(ids["b"], {"instrument": ids["other"]})])
        mutate("revalue", [update(ids["b"], {"value": "-19", "at": "-1"})])
        mutate("value-overflow", [update(ids["b"], {"value": str(LIMIT+1)})], "invalid_input")
        mutate("missing-instrument", [update(ids["b"], {"instrument": str(uuid.UUID(int=999))})], "unavailable_reference")
        mutate("delete-referenced-instrument", [delete(ids["other"])], "unavailable_reference")
        mutate("delete-to-empty", [delete(ids["a"]), delete(ids["c"])])
        mutate("empty-owner-unit", [update(ids["instrument"], {"unit": 9})])
        mutate("incompatible-root-move", [update(ids["b"], {"instrument": ids["instrument"]})], "invariant")
        mutate("move-and-unit-repair", [update(ids["b"], {"instrument": ids["instrument"], "unit": 9})])
        rng = random.Random(20261023)
        for trial in range(16):
            mutate(f"source-stress-{trial:02}", [update(ids["b"], {"value": str(rng.randint(-LIMIT, LIMIT)),
                "at": str(rng.choice((-10, -1, 0, 0, 10, 10, 50)))})])
        remaining = 64-len(facts)
        mutate("fill-source-envelope", [create(f"extra-{n}", 211, {"instrument": ids["instrument"],
            "at": str(n//3), "unit": 9, "value": str((n-30)*123)}) for n in range(remaining)])
        mutate("source-overflow", [create("too-many", 101, {"unit": 9})], "state_limit")
        verify(backend, model, facts, windows=True)

        raw = snapshot(backend, "authority-before")
        root_request = {"model": model, "owner": ids["instrument"], "slot": 7,
                        "read": {"kind": "range", "range": {"lower": None, "upper": None}}}
        expect_error("not_found", lambda: client.call(backend.url, restricted, "roots.read", root_request))
        unauthorized = client.prepare(backend.url, restricted, {"model": model,
            "commands": [update(ids["b"], {"value": "3"})], "returning": []})
        expect_error("forbidden", lambda: client.execute(backend.url, restricted, unauthorized))
        require(client.execute(backend.url, restricted, unauthorized, status=True)["status"] == "not_observed", "Authority failure receipt")
        require(snapshot(backend, "authority-after") == raw, "Authority failure changed logical bytes")
        backend.stop()
        integrity = backend.cli("check", backend.store)
        backup = backend.directory / "verified-backup.json"
        backend.cli("backup", backend.store, backup)
        controls = corrupt_restore_controls(backend, backup)
        backend.start()
        verify(backend, model, facts)
        require(client.execute(backend.url, backend.token, latest[0])["result"] == latest[1]["result"], "Reopen replay")
        backend.crash()
        backend.start()
        verify(backend, model, facts)
        require(client.execute(backend.url, backend.token, latest[0], status=True)["result"] == latest[1]["result"], "Crash receipt")
        backend.stop()
        restored = backend.directory / "restored.redb"
        backend.cli("restore", backup, restored)
        backend.store = restored
        backend.start()
        verify(backend, model, facts, windows=True)
        require(client.execute(backend.url, backend.token, latest[0])["result"] == latest[1]["result"], "Restore replay")
        expect_error("not_found", lambda: client.call(backend.url, restricted, "roots.read", root_request))
        return {"status": "passed", "model": model, "public_sources": len(facts), "operations": operations,
                "stress_seed": 20261023, "stress_batches": 16, "logical_bytewise_rollback": True,
                "authenticated_windows": True, "authority_failure": True, "reopen": True,
                "crash_recovery": True, "verified_restore": True, "corrupt_restore_controls": controls,
                "integrity": integrity, "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest()}
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
