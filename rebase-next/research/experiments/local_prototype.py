#!/usr/bin/env python3
"""Independent source, public-index and receipt checks of the real local adapter.

Private output expectations come from explicit allocator inputs in the unchanged
causal fixture, never from the observed role map. Native structure/value checking
reuses the source oracle. No Rust settlement or maintained index drives expected
record values, versions, public membership or returned receipt projections.
"""

import argparse
from copy import deepcopy
import hashlib
import hmac
import json
from pathlib import Path
import uuid

from native_slice import ROOT, State, Reject, identity, model_digest, unique_object, verify
from m6 import Failure, exact, require


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def prepared_identity(catalog):
    core = model_digest()
    require(catalog["core_identity"] == core, "CORE_IDENTITY", "compiled native sources")
    declarations = {str(c["code"]): {k: v for k, v in c.items()
        if k not in ("schema_source", "behavior_source")} for c in catalog["contracts"]}
    require(set(declarations) == {str(c) for c in range(1, 13)}, "CODEBOOK", "all contracts")
    digest = hashlib.sha256(b"rebase-next-local-model-v1\0")
    require(catalog["name"] == "rebase-next-local"
            and catalog["behavior_contract"] == "rebase-calculation-contract-5",
            "BEHAVIOR_IDENTITY", "compiled calculation model")
    for data in (b"rebase-next-local", b"rebase-calculation-contract-5", core.encode(), canonical(declarations)):
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def payload(row):
    data = bytes.fromhex(row["value"])
    require(row["value"] == data.hex(), "HEX", "canonical value bytes")
    return json.loads(data, object_pairs_hook=unique_object)


def operation_context(state, header):
    return hmac.new(bytes.fromhex(header["cursor_key"]), b"rebase-operation-context-1\0"
        + uuid.UUID(header["store_id"]).bytes + int(header["operation_epoch"]).to_bytes(8,"big")
        + uuid.UUID(state.tenant).bytes + uuid.UUID(state.actor).bytes + state.model.encode(),hashlib.sha256).hexdigest()


def returned(state, request):
    records = []
    for rid in request["returning"]:
        r = state.records.get(rid)
        record = {"id": rid, **{k: r[k] for k in ("contract", "version", "input", "derived")}} if r and r["contract"] <= 10 else None
        records.append({"id": rid, "record": record})
    return {"operation_id": request["operation_id"], "revision": str(state.revision), "records": records}


def receipt(state, request):
    digest = hashlib.sha256(b"rebase-local-operation-v1\0" + uuid.UUID(state.tenant).bytes
        + uuid.UUID(state.actor).bytes + canonical(request)).hexdigest()
    return {"context":request["context"], "model": state.model, "tenant": state.tenant, "actor": state.actor,
            "request_hash": digest, "result": returned(state, request)}


def check_snapshot(state, observed, receipts, initial_header):
    require(observed["format"] == "rebase-local-observation-1" and observed["complete"] is True,
            "INCOMPLETE_SCOPE", "local snapshot")
    tables = observed["tables"]
    require(set(tables) == {"native_kv", "public_records", "operations", "local_runtime"},
            "TABLE_INVENTORY", "all local tables")
    work = verify(state, tables["native_kv"], complete=True)
    public = [{"key": uuid.UUID(rid).hex, "contract": r["contract"]}
              for rid, r in sorted(state.records.items()) if r["contract"] <= 10]
    require(exact(tables["public_records"], public), "PUBLIC_INDEX", "complete public identity path")
    rows = tables["operations"]
    require(len(rows) == len(receipts) and [row["key"] for row in rows] == sorted(uuid.UUID(rid).hex for rid in receipts),
            "RECEIPT_INVENTORY", "exact receipt keys")
    for row in rows:
        rid = str(uuid.UUID(hex=row["key"]))
        require(exact(payload(row), receipts[rid]), "RECEIPT_VALUE", rid)
    rows = tables["local_runtime"]
    require(len(rows) == 1 and rows[0]["key"] == b"header".hex(), "LOCAL_HEADER", "header key")
    header = payload(rows[0])
    require(exact(header, {**initial_header, "receipts": len(receipts)}), "LOCAL_HEADER", "scope and receipt count")
    return work


def controls(state, image, receipts, header):
    results = []

    def reject(name, mutate, code):
        broken = deepcopy(image)
        mutate(broken)
        try:
            check_snapshot(state, broken, receipts, header)
        except Failure as error:
            require(error.code == code, "WRONG_FAILURE", (name, error.code))
            results.append({"case": name, "obligation": code})
        else:
            raise AssertionError(name)

    reject("missing_public_identity", lambda o: o["tables"]["public_records"].pop(), "PUBLIC_INDEX")
    reject("private_identity_in_public_path", lambda o: o["tables"]["public_records"].append(
        {"key": uuid.UUID(next(r for r, v in state.records.items() if v["contract"] == 12)).hex, "contract": 12}), "PUBLIC_INDEX")
    reject("missing_receipt", lambda o: o["tables"]["operations"].clear(), "RECEIPT_INVENTORY")

    def damage_receipt(o):
        row = o["tables"]["operations"][0]
        value = payload(row)
        value["result"]["records"][0]["record"]["version"] = "999"
        row["value"] = canonical(value).hex()
    reject("receipt_returns_wrong_version", damage_receipt, "RECEIPT_VALUE")

    def damage_header(o):
        row = o["tables"]["local_runtime"][0]
        value = payload(row)
        value["receipts"] += 1
        row["value"] = canonical(value).hex()
    reject("receipt_counter_drift", damage_header, "LOCAL_HEADER")
    reject("unobserved_extra_table", lambda o: o["tables"].update(hidden=[]), "TABLE_INVENTORY")
    reject("partial_observation", lambda o: o.update(complete=False), "INCOMPLETE_SCOPE")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actual", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.actual.read_text(), object_pairs_hook=unique_object)
    fixtures = json.loads((ROOT / "research/fixtures/causal-slice.json").read_text(), object_pairs_hook=unique_object)
    require(report["format"] == "rebase-local-adapter-run-1", "LAYOUT", "local report")
    require(report["model"] == report["developer_catalog"]["model"] == prepared_identity(report["developer_catalog"]),
            "MODEL", "resolved declarations and compiled behavior")
    selected = {"swap", "disable_reenable", "delete_and_new_lifetime", "noncyclic_zero_output",
                "historical_floor_after_settlement", "delete_account_and_move_whole_causal_role",
                "public_output_create_forbidden", "coincident_query_slots", "allocation_retries"}
    actual_cases = {c["name"]: c for c in report["cases"]}
    require(set(actual_cases) == selected and len(report["cases"]) == len(selected), "CASE_INVENTORY", "local adapter cases")
    results = []
    negative_controls = None
    for fixture in fixtures["cases"]:
        if fixture["name"] not in selected:
            continue
        actual = actual_cases[fixture["name"]]
        base = fixtures["bases"][fixture["base"]]
        state = State(fixtures["tenant"], fixtures["actor"], report["model"]).apply({
            "commands": base, "allocations": fixtures["base_allocations"].get(fixture["base"], [])})
        header = payload(actual["initial"]["tables"]["local_runtime"][0])
        context = operation_context(state,header)
        base_request = {"context":context, "model": state.model, "operation_id": str(uuid.UUID(int=5000)),
                        "commands": base, "returning": [c["id"] for c in base]}
        require(exact(actual["base_request"], base_request), "REQUEST", "base")
        receipts = {base_request["operation_id"]: receipt(state, base_request)}
        require(exact(actual["base_result"], {"status": "committed", "replayed": False, "result": returned(state, base_request)}), "RESULT", "base")
        header = payload(actual["initial"]["tables"]["local_runtime"][0])
        require(set(header) == {"format", "store_id", "cursor_key", "receipts", "operation_epoch"} and header["format"] == "rebase-store-5", "LOCAL_HEADER", "initializer")
        identity(header["store_id"])
        require(len(header["cursor_key"]) == 64 and bytes.fromhex(header["cursor_key"]).hex() == header["cursor_key"], "LOCAL_HEADER", "signing key")
        header = {k: v for k, v in header.items() if k != "receipts"}
        check_snapshot(state, actual["initial"], receipts, header)
        if negative_controls is None:
            negative_controls = controls(state, actual["initial"], receipts, header)
        previous = actual["initial"]
        require(len(actual["operations"]) == len(fixture["operations"]), "CASE_INVENTORY", fixture["name"])
        for index, (operation, observed) in enumerate(zip(fixture["operations"], actual["operations"])):
            request = {"context":context, "model": state.model, "operation_id": str(uuid.UUID(int=5001+index)),
                       "commands": operation["commands"], "returning": [fixtures["ids"][n] for n in ("P", "Q", "J", "A")]}
            require(exact(observed["request"], request), "REQUEST", (fixture["name"], index))
            try:
                proposed = state.apply(operation)
                status, code = "committed", None
            except Reject as error:
                status, code = "rejected", error.code
            require(status == operation["expect"]["status"] == observed["status"]
                    and code == operation["expect"].get("code") == observed.get("code"), "OUTCOME", (fixture["name"], index))
            if status == "committed":
                state = proposed
                receipts[request["operation_id"]] = receipt(state, request)
                result = returned(state, request)
                require(exact(observed["returned"], {"status": status, "replayed": False, "result": result}), "RESULT", "confirmed settled projection")
                require(exact(observed["replay"], {"status": status, "replayed": True, "result": result})
                        and observed["replay_unchanged"] is True, "REPLAY", "same content")
                require(observed["conflict_code"] == "operation_conflict" and observed["conflict_unchanged"] is True, "REPLAY", "different content")
                require(exact(observed["receipt"], {"status": status, "result": result}), "STATUS", "committed")
            else:
                require(observed["returned"] is None and exact(observed["after"], previous), "ROLLBACK", "all four application tables")
                require(exact(observed["receipt"], {"status": "not_observed"}), "STATUS", "rejected attempt")
            check_snapshot(state, observed["after"], receipts, header)
            previous = observed["after"]
            results.append({"case": fixture["name"], "step": index, "status": status, "code": code})
        require(actual["reopened_equal"] is True, "REOPEN", fixture["name"])
    print(json.dumps({"status": "passed", "scope": "real local adapter, complete native/public/receipt/runtime inventories",
        "cases": len(selected), "operations": results, "controls": negative_controls,
        "model": report["model"], "allocation_expectations": "explicit fixture sequence, independent of native role maps"}, indent=2))


if __name__ == "__main__":
    main()
