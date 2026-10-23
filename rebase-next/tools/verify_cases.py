"""Literal workshop stories. Each function uses ordinary public commands."""
from copy import deepcopy
import json
import uuid

from verify_runtime import Scenario, equal


def allocation(before, amount):
    return {"available_before": str(before), "allocated": str(amount)}


def equipment(binary, directory):
    case = Scenario(binary, directory, "equipment", "equipment")
    try:
        pool, other, delivery, a, b = [case.identity(x) for x in ("pool", "other", "delivery", "A", "B")]
        reservation = lambda p, start, end, amount: {
            "pool": p, "starts": str(start), "ends": str(end), "requested": str(amount), "active": True}
        case.mutate("E0", "Deliver 10 units; A requests 8 at [10,30), B requests 7 at [20,40).", [
            case.create("pool", 101, {"unit": 7}), case.create("other", 101, {"unit": 7}),
            case.create("delivery", 205, {"pool": pool, "at": "0", "quantity": "10"}),
            case.create("other-delivery", 205, {"pool": other, "at": "0", "quantity": "6"}),
            case.create("A", 410, reservation(pool, 10, 30, 8)),
            case.create("B", 410, reservation(pool, 20, 40, 7))],
            "Reservation query 31 reads Pool root 7 strictly before starts; roles 11/29 consume/release.",
            literals={a: allocation(10, 8), b: allocation(2, 2)})
        case.mutate("delivery-12", "Increase delivery to 12: A=8, B=4.", [case.update(delivery, {"quantity": "12"})],
                    "Both chronological consumers depend on the changed earlier delivery.",
                    literals={a: allocation(12, 8), b: allocation(4, 4)})
        case.mutate("early-release", "Move A's end to 15: B can now allocate 7.", [case.update(a, {"ends": "15"})],
                    "A's release moves into B's strict prefix; old and final points both invalidate.",
                    literals={a: allocation(12, 8), b: allocation(12, 7)})
        for active in (False, True):
            case.mutate("reactivate-A" if active else "disable-A", "Activate A." if active else "Disable A.",
                        [case.update(a, {"active": active})],
                        "Occurrences disappear/reappear; retained (producer,role) identities stay stable.",
                        literals={a: allocation(12, 8) if active else allocation(0, 0), b: allocation(12, 7)})
        case.mutate("second-pool", "Move A to a separate pool with six delivered units.", [case.update(a, {"pool": other})],
                    "Validate the original and final roots; A=6 and B=7.",
                    literals={a: allocation(6, 6), b: allocation(12, 7)})
        case.mutate("E0-end-20", "Reset E0 and release A exactly at B's start 20.", [
            case.update(delivery, {"quantity": "10"}), case.update(a, {"pool": pool, "ends": "20"})],
            "The release at 20 is outside the strict prefix: B still gets 2.",
            literals={a: allocation(10, 8), b: allocation(2, 2)})
        case.mutate("end-19", "Move that release to 19.", [case.update(a, {"ends": "19"})],
                    "19 is before B's start: B gets 7.", literals={b: allocation(10, 7)})
        case.mutate("reset-E0", "Restore the named E0 baseline before testing rejection.", [case.update(a, {"ends": "30"})],
                    "A=8, B=2; all later branches start here.", literals={a: allocation(10, 8), b: allocation(2, 2)})
        c_command = case.create("C", 410, reservation(pool, 10, 15, 3))
        case.mutate("same-time-negative", "C also requests 3 at [10,15).", [c_command],
                    "A and C read the same old prefix; their total makes the complete-time history negative at 10.",
                    reject="invariant")
        for parent_first in (False, True):
            if parent_first:
                c_command = case.create("C-parent-first", 410, reservation(pool, 10, 15, 3))
            commands = [case.update(delivery, {"quantity": "12"}), deepcopy(c_command)]
            if not parent_first:
                commands.reverse()
            case.mutate("joint-repair-" + str(parent_first).lower(), "Add C and raise delivery to 12 atomically.", commands,
                        "Validation runs after final settlement in either valid command order.",
                        literals={a: allocation(12, 8), c_command["id"]: allocation(12, 3), b: allocation(4, 4)})
            case.mutate("reset-after-repair-" + str(parent_first).lower(), "Restore E0 after this independent order trial.",
                        [case.delete(c_command["id"]), case.update(delivery, {"quantity": "10"})],
                        "Delete the extra source and restore delivery; retired role identities remain reserved.")
        zero = case.create("zero", 410, reservation(pool, 25, 27, 1))
        item = case.mutate("zero-allocation", "Request one unit while the pool has zero available units.", [zero],
                          "Zero allocation keeps its query and both required private output identities.",
                          literals={zero["id"]: allocation(0, 0)})
        equal("zero.query_count", 3, len(item["internal"]["queries"]))
        return case.finish()
    finally:
        case.close()


def window(lower, upper):
    return {"lower": {"included": str(lower)}, "upper": {"excluded": str(upper)}}


def measurement(binary, directory):
    case = Scenario(binary, directory, "measurement", "sensors")
    try:
        instrument, other, report, selector = [case.identity(x) for x in ("instrument", "other", "report", "selector")]
        ids = [case.identity("o" + str(at)) for at in (0, 10, 20)]
        commands = [case.create("instrument", 101, {"unit": 7}), case.create("other", 101, {"unit": 7})]
        commands += [case.create("o" + str(at), 211, {"instrument": instrument, "at": str(at), "value": str(value), "unit": 7})
                     for at, value in ((0, 5), (10, 12), (20, -2))]
        commands += [case.create("report", 307, {"instrument": instrument, "unit": 7, "range": window(0, 20), "threshold": "5"}),
                     case.create("selector", 419, {"instrument": instrument, "unit": 7, "at": "10"})]
        case.mutate("M0", "Observe (0,5), (10,12), (20,-2); report [0,20) and select at 10.", commands,
                    "ObservationReport query 31 has exact bounds; LatestObservation query 43 includes all (-infinity,10].",
                    literals={report: {"count": 2, "min": "5", "max": "12", "unit": 7, "at_least_threshold": True}})
        raw = case.backend.call("roots.read", {"model": case.model, "owner": instrument, "slot": 7,
            "read": {"kind": "range", "range": window(0, 20)}})["value"]
        equal("M0.range_sum", "17", raw["sum"])
        case.steps[-1]["range_read"] = {"expected_sum": "17", "observed": raw, "full_root_sum": "15"}
        unchanged = case.get(selector)
        case.mutate("move-20-to-15", "Move the last observation into the report window.", [case.update(ids[2], {"at": "15"})],
                    "Report count=3/min=-2/max=12/false; selector's different search window retains its winner.",
                    literals={report: {"count": 3, "min": "-2", "max": "12", "unit": 7, "at_least_threshold": False}})
        equal("selector.outside_window_version", unchanged, case.get(selector))
        case.mutate("empty-report", "Change the report to [10,10).", [case.update(report, {"range": window(10, 10)})],
                    "Empty publishes its unit, absent extrema and false; its query registration remains.",
                    literals={report: {"count": 0, "min": None, "max": None, "unit": 7, "at_least_threshold": False}})
        case.mutate("absent-selector", "Select before the first observation.", [case.update(selector, {"at": "-1"})],
                    "Absence still depends on all eligible earlier points.", literals={selector: {"selection": None}})
        first = case.create("first-eligible", 211, {"instrument": instrument, "at": "-2", "unit": 7, "value": "9"})
        case.mutate("first-eligible", "Insert the first eligible point into the absent selector's window.", [first],
                    "The absent registration discovers the new member and now selects it.")
        case.mutate("restore-selector-10", "Return the selector to M0's at=10.", [case.update(selector, {"at": "10"})],
                    "The authored observation at 10 wins again.")
        tie = case.create("greater-tie", 211, {"instrument": instrument, "at": "10", "unit": 7, "value": "12"})
        tie["id"] = str(uuid.UUID(int=2**128 - 2))
        old = case.get(selector)
        case.mutate("identity-tie", "Insert equal time/payload with a greater UUID.", [tie],
                    "The maximum complete (time,UUID,member-slot) changes winner identity despite equal payload.")
        equal("tie.winner", tie["id"], case.get(selector)["derived"]["selection"]["identity"])
        if old["version"] == case.get(selector)["version"]:
            raise AssertionError("Changed selection identity retained an old version")
        old = case.get(selector)
        case.mutate("nonwinner", "Edit an eligible nonwinner's payload.", [case.update(ids[0], {"value": "6"})],
                    "The selector may evaluate; unchanged materialization preserves its record version.")
        equal("nonwinner.version", old, case.get(selector))
        case.mutate("move-and-retarget", "Move a member and both consumers to the second instrument.", [
            case.update(tie["id"], {"instrument": other}), case.update(selector, {"instrument": other}),
            case.update(report, {"instrument": other, "range": window(0, 20)})],
            "Compare old/final root memberships and remove stale consumer routes.")
        case.mutate("wrong-unit", "Change only the instrument dimension.", [case.update(other, {"unit": 8})],
                    "The final mixed instrument/member/report/selector dimensions reject atomically.", reject="invariant")
        for unit, parent_first in ((8, False), (7, True)):
            commands = [case.update(other, {"unit": unit}), case.update(tie["id"], {"unit": unit}),
                        case.update(report, {"unit": unit}), case.update(selector, {"unit": unit})]
            case.mutate("unit-repair-" + str(unit), "Repair the owner, member and both consumers in one mutation.",
                        commands if parent_first else list(reversed(commands)),
                        "Either valid order publishes only the final consistent dimension.")
        case.mutate("delete-last", "Delete the second instrument's last member.", [case.delete(tie["id"])],
                    "Raw root has absent dimension/extrema; report still declares unit 7; selection is absent.",
                    literals={selector: {"selection": None}, report: {"count": 0, "min": None, "max": None,
                        "unit": 7, "at_least_threshold": False}})
        return case.finish()
    finally:
        case.close()


def quantity(binary, directory):
    case = Scenario(binary, directory, "quantity", "quantities")
    try:
        draft = case.backend.cli("fixture", "plan", "quantities", "--namespace", case.namespace)
        ids = draft["fixture"]["ids"]
        source, left, right, join = (ids[key] for key in ("source", "left", "right", "join"))
        values = lambda l, r, j: {left: {"quantity": str(l)}, right: {"quantity": str(r)}, join: {"quantity": str(j)}}
        case.mutate("Q0", "Source 12 feeds Scale L by 1/2 and R by 1/3; Join adds them.", draft["commands"],
                    "Declared ready publications: Scale slot 9; Join slots 8 and 3. No private outputs or roots.",
                    literals=values(6, 4, 10))
        case.mutate("source-18", "Change Source to 18.", [case.update(source, {"value": "18"})],
                    "Parents become ready before the shared scheduler evaluates Join=15.", literals=values(9, 6, 15))
        case.mutate("source-13-exact", "Request Source=13 with exact ratios.", [case.update(source, {"value": "13"})],
                    "A fractional exact result rejects the entire batch, preserving 18/9/6/15.", reject="inexact")
        other = case.create("other-source", 101, {"value": "18"})
        case.mutate("other-source", "Add a separate existing source for retargeting.", [other], "Independent publication.")
        for parent_first in (False, True):
            commands = [case.update(other["id"], {"value": "12"}), case.update(left, {"parent": other["id"]})]
            case.mutate("retarget-" + str(parent_first).lower(), "Retarget L and edit its existing new parent atomically.",
                        commands if parent_first else list(reversed(commands)),
                        "Both valid orders use the final parent value: L=6, R=6, Join=12.", literals=values(6, 6, 12))
            case.mutate("reset-retarget-" + str(parent_first).lower(), "Restore the original parent and other source.",
                        [case.update(left, {"parent": source}), case.update(other["id"], {"value": "18"})],
                        "This resets the next order trial to the same starting state.", literals=values(9, 6, 15))
        case.mutate("equal-retarget", "Retarget L to an equal-valued source.", [case.update(left, {"parent": other["id"]})],
                    "Equal published quantity retains the new declared dependency.", literals=values(9, 6, 15))
        case.mutate("new-parent-change", "Edit that new parent to 12.", [case.update(other["id"], {"value": "12"})],
                    "L=6 proves that equal-value retargeting retained the new edge.", literals=values(6, 6, 12))
        case.mutate("repeated-parent", "Join reads L in both distinct declaration slots.", [case.update(join, {"right": left})],
                    "Repeated parent is legal: each declared slot contributes 6, giving 12.", literals=values(6, 6, 12))
        case.mutate("zero-cycle", "Retarget L to Join and choose factor zero.", [case.update(left, {
            "parent": join, "factor": {"numerator": "0", "denominator": "1"}})],
            "Declared feedback is cyclic even though multiplying by zero would hide a numerical change.", reject="feedback")
        return case.finish()
    finally:
        case.close()


def service(binary, directory):
    from effects_worker import run
    result = run(binary, directory, workshop_only=True)
    plans = {path.stem.removesuffix(".plan"): json.loads(path.read_text())
             for path in (directory / "backend").glob("*.plan.json")}
    stories = [
        ("literal-12-10-7", "Edit Account.balance quota 12 to 10 while creating Dispatch.units=3.",
         "The immutable execution intent commits atomically. A confirmed remote success applies 3 once: 10-3=7.",
         ["account", "literal-atomic-intent"], {"quota_before": "12", "quota_committed": "10", "quota_after": "7"}),
        ("blocked-repair-apply-once", "Keep remote success when quota=2 blocks applying 3; repair quota to 5.",
         "An immutable success fact survives domain rejection. Retrying application gives 2 without another submission.",
         ["blocked-application", "spend-before-provider-result", "authorized-repair"],
         {"blocked_quota": "2", "repaired_quota": "5", "quota_after": "2"}),
    ]
    steps = []
    by_name = {row["name"]: row for row in result["cases"]}
    expected_cases = {
        "literal-12-10-7": {"submissions": 1, "accepted": 1, "quota": 7},
        "blocked-repair-apply-once": {"submissions": 1, "accepted": 1, "repaired_quota": "5", "final_quota": "2"},
    }
    equal("service.case_inventory", sorted(expected_cases), sorted(by_name))
    equal("service.integrity", "valid", result["integrity"]["status"])
    # Check the authored transition inputs from saved ordinary plans. These
    # literals are the source oracle; worker summaries alone are observations.
    initial_account = plans["account"]["request"]["commands"][0]
    equal("service.initial_quota", {"op": "create", "contract": 101,
          "fields": {"balance": "12"}}, {key: value for key, value in initial_account.items() if key != "id"})
    literal = plans["literal-atomic-intent"]["request"]["commands"]
    equal("service.literal.commands", [
        {"op": "update", "id": literal[0]["id"], "if_version": literal[0]["if_version"],
         "set": {"balance": "10"}, "unset": []},
        {"op": "create", "id": literal[1]["id"], "contract": 205,
         "fields": {"account": literal[0]["id"], "units": "3", "execute_at": literal[1]["fields"]["execute_at"], "not_after": None}},
    ], literal)
    create_blocked = plans["blocked-application"]["request"]["commands"]
    equal("service.blocked_initial_quota", "12", create_blocked[0]["set"]["balance"])
    equal("service.blocked_dispatch_units", "3", create_blocked[1]["fields"]["units"])
    equal("service.spend_quota", "2", plans["spend-before-provider-result"]["request"]["commands"][0]["set"]["balance"])
    equal("service.repair_quota", "5", plans["authorized-repair"]["request"]["commands"][0]["set"]["balance"])
    equal("service.literal.expected_quota", 10 - 3, 7)
    equal("service.repair.expected_quota", 5 - 3, 2)
    for name, intent, dependency, labels, values in stories:
        observed = by_name[name]
        contract = expected_cases[name]
        equal("service.provider_submissions", contract["submissions"], observed["submissions"])
        equal("service.provider_acceptance", contract["accepted"], observed["accepted"])
        if name == "blocked-repair-apply-once":
            equal("service.repaired_quota", contract["repaired_quota"], observed["repaired_balance"])
            equal("service.final_quota", contract["final_quota"], observed["final_balance"])
        steps.append({"name": name, "intent": intent, "dependency": dependency,
                      "method": "records.mutate + effects.status / operator effects retry",
                      "plans": [plans[label] for label in labels], "expected": values,
                      "observed": observed, "provider_expectation": {"submissions": 1, "accepted": 1},
                      "internal": result["integrity"]})
    return {"name": "service", "model_selector": "effect-demo", "model": result["model"],
            "status": "passed", "steps": steps, "verification": result,
            "scope": "fixed fake provider with separate SQLite journal; one store, no cross-store transaction"}
