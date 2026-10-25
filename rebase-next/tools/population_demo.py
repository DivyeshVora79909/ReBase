"""Literal compositions of population proposals with the existing tools.

The examples here never own HTTP, receipt or scheduling semantics. They use
``client`` for saved intents, ``verify_oracles`` for independent source facts,
and G8's ``bounded_step`` for finite paced actions.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import os
from pathlib import Path
import time
import uuid

import client
import population
from g7_http import discard_once
from g8_pressure import bounded_step
from g8_observe import sample as resource_sample
from verify_oracles import OracleError, evaluate, stage
from verify_runtime import Scenario, equal, write_json


CONTROLLED_EQUIPMENT = "increasing-start/common-future-end"


def equipment_context(call, model, pool_id, *, start, end, requested,
                      previous_start, common_end, active=True):
    """Read fresh equipment availability for one controlled chronological step.

    This recipe is valid for a controlled store whose baseline has no unseen
    intermediate capacity losses, and whose generated reservations start in
    increasing order and share ``common_end``. The prefix alone does not prove
    arbitrary interval feasibility.
    """
    for name, value in (("start", start), ("end", end), ("requested", requested),
                        ("common_end", common_end)):
        if type(value) is not int:
            raise ValueError(f"{name} must be an exact integer")
    if previous_start is not None and (type(previous_start) is not int or start <= previous_start):
        raise ValueError("reservation starts must increase strictly")
    if end != common_end or not start < end or requested < 0:
        raise ValueError("controlled reservations require a common future end and valid range")
    response = call("roots.read", {
        "model": model, "owner": pool_id, "slot": 7,
        "read": {"kind": "before", "at": str(start)},
    })
    value = response.get("value") if isinstance(response, dict) else None
    total = value.get("sum") if isinstance(value, dict) else None
    if not isinstance(total, str) or not total.lstrip("-").isdigit() or str(int(total)) != total:
        raise ValueError("fresh equipment prefix must be a canonical decimal string")
    return {
        "construction": CONTROLLED_EQUIPMENT,
        "available_before": total,
        "starts": str(start),
        "ends": str(end),
        "requested": str(requested),
        "common_end": str(common_end),
        "active": bool(active),
    }


def equipment_reservation_strategy(_schema, _seed, _cursor, context):
    """Small explicit strategy; the ref overlay chooses a typed Pool ID."""
    return {
        "pool": "00000000-0000-4000-8000-000000000000",
        "starts": context["starts"],
        "ends": context["ends"],
        "requested": context["requested"],
        "active": True,
    }


def equipment_reservation_rule(fields, context, references):
    """Cap the authored request using the just-read prefix in the controlled recipe."""
    if context.get("construction") != CONTROLLED_EQUIPMENT:
        raise ValueError("equipment interval rule requires its declared controlled construction")
    pool_id = references.get("pool")
    if not isinstance(pool_id, str) or fields.get("pool") != pool_id:
        raise ValueError("typed Pool reference is required")
    available = int(context["available_before"])
    request = int(context["requested"])
    fields["starts"] = context["starts"]
    fields["ends"] = context["ends"]
    fields["requested"] = str(min(request, max(0, available)))
    fields["active"] = bool(context.get("active", True))
    return fields


def prepare_equipment_population(developer_catalog, pool_id, *, seed, count,
                                 pool_unit=7, provider=None):
    """Initialize one explicit Reservation quota with a supplied Pool anchor."""
    pool = {"id": pool_id, "contract": "Pool", "fields": {"unit": pool_unit}}
    return population.prepare(
        developer_catalog,
        {"Reservation": count},
        seed=seed,
        existing={"Pool": [pool]},
        strategies={"Reservation": equipment_reservation_strategy},
        rules={"Reservation": equipment_reservation_rule},
        provider=provider,
        batch_size=1,
    )


def authored_input_provider(record):
    """Make ordinary provider values from authored input only.

    IDs are allocated by ``population.propose`` and declared references are
    overlaid from typed pools. Private outputs and record versions never enter
    the value provider.
    """
    if not isinstance(record, dict) or not isinstance(record.get("input"), dict):
        raise ValueError("authored clone source must contain a public input object")
    template = deepcopy(record["input"])

    def provide(_schema, count, _seed):
        return [deepcopy(template) for _ in range(count)]

    return provide


def propose_equipment_reservation(state, call, model, pool_id, *, start, end,
                                  requested, previous_start, common_end, active=True):
    """Refresh the pool prefix before each dependent proposal."""
    context = equipment_context(
        call, model, pool_id, start=start, end=end, requested=requested,
        previous_start=previous_start, common_end=common_end, active=active,
    )
    return population.propose(state, context, max_commands=1)


def bind_saved_plan(state, proposal, url, token, destination):
    """Compose existing client prepare/save with the caller-owned pending record."""
    draft = {
        "model": state.catalog["model"],
        "commands": deepcopy(proposal.commands),
        "returning": list(proposal.returning),
    }
    plan = client.prepare(url, token, draft)
    if state.target is not None and plan.get("target") != state.target:
        raise population.PopulationError("destination differs from the population job's committed target")
    client.save_plan(destination, plan)
    state.pending.plan = plan
    return plan


def execute_and_accept(state, proposal, plan, url, token, *, status=False):
    """Submit or reconcile this exact plan; an exception leaves it pending."""
    response = client.execute(url, token, plan, status=status)
    if response.get("status") == "committed":
        population.accept(state, proposal, plan, response)
    return response


def check_equipment_proposal(facts, proposal, read_record):
    """Check the proposed final source graph independently after commitment."""
    proposed_facts = stage(facts, proposal.commands)
    expected = evaluate("equipment", proposed_facts)
    contract_codes = {command["id"]: command["contract"] for command in proposal.commands}
    records = {}
    for addition in proposal.additions:
        observed = read_record(addition["id"])
        expected_derived = expected["derived"].get(addition["id"])
        if observed.get("contract") != contract_codes[addition["id"]] or observed.get("input") != addition["fields"]:
            raise AssertionError("committed public input differs from authored population proposal")
        if observed.get("derived") != expected_derived:
            raise AssertionError("committed equipment result differs from source oracle")
        records[addition["id"]] = observed
    return proposed_facts, {"expected": expected, "records": records}


def measured_actions(requests, submit, *, duration, offered_rate, clients,
                     max_pending, observer=None, checker=None, on_offer=None,
                     generation_seconds=None, setup_seconds=None):
    """Feed authored CRUD/read actions through G8's existing bounded scheduler.

    ``observer(item, outcome)`` can call existing G8 process/physical samplers;
    ``checker`` can apply independent source expectations. This function adds
    no queue, retry or observation implementation of its own.
    """
    samples = []
    verification_seconds = 0.0
    observation_seconds = 0.0
    client_call_seconds = 0.0

    def timed_submit(item):
        started = time.monotonic()
        outcome = submit(item)
        elapsed = time.monotonic() - started
        if not isinstance(outcome, dict):
            raise ValueError("bounded submit callback must return an outcome object")
        outcome = dict(outcome)
        outcome["client_call_seconds"] = elapsed
        return outcome

    def completed(item, outcome):
        nonlocal verification_seconds, observation_seconds, client_call_seconds
        client_call_seconds += outcome.get("client_call_seconds", 0.0)
        started = time.monotonic()
        if checker is not None:
            checker(item, outcome)
        verification_seconds += time.monotonic() - started
        if observer is not None:
            started = time.monotonic()
            samples.append(observer(item, outcome))
            observation_seconds += time.monotonic() - started

    action_started = time.monotonic()
    result = bounded_step(
        requests, timed_submit, duration=duration, offered_rate=offered_rate,
        clients=clients, max_pending=max_pending,
        on_offer=on_offer, on_complete=completed,
    )
    return {
        "bounded_step": result,
        "observations": samples,
        "timing_seconds": {
            "generation": generation_seconds,
            "setup": setup_seconds,
            "client_call_wall_time_including_local_serialization": client_call_seconds,
            "verification_callbacks": verification_seconds,
            "observer_callbacks": observation_seconds,
            "action_window_including_queue_and_submit": time.monotonic() - action_started,
        },
    }


def _timed(timings, label, action):
    started = time.monotonic()
    value = action()
    timings[label] = timings.get(label, 0.0) + time.monotonic() - started
    return value


def _verify_facts(backend, model, facts, selector):
    expected = evaluate(selector, facts)
    for identity, fact in facts.items():
        observed = backend.call("records.get", {"model": model, "id": identity})
        equal("population.source.contract", fact["contract"], observed["contract"])
        equal("population.source.input", fact["fields"], observed["input"])
        equal("population.source.derived", expected["derived"].get(identity), observed["derived"])
    return expected


def _commit_proposal(case, state, proposal, facts, label, timings):
    backend, model = case.backend, case.model
    proposed = stage(facts, proposal.commands)
    expected = evaluate(case.selector, proposed)
    path = backend.directory / f"{label}.plan.json"
    plan = _timed(timings, "client_prepare_wall_seconds",
                  lambda: bind_saved_plan(state, proposal, backend.url, backend.token, path))
    response = _timed(timings, "client_execute_wall_seconds",
                      lambda: client.execute(backend.url, backend.token, plan))
    population.accept(state, proposal, plan, response)
    for addition in proposal.additions:
        record = backend.call("records.get", {"model": model, "id": addition["id"]})
        equal("population.commit.input", addition["fields"], record["input"])
        equal("population.commit.derived", expected["derived"].get(addition["id"]), record["derived"])
    case.steps.append({"name": label, "plan": plan, "response": response,
                       "expected": expected, "source_count": len(proposed)})
    return proposed, {"operation_id": response["result"]["operation_id"],
                      "generated_ids": [item["id"] for item in proposal.additions],
                      "commands": proposal.commands, "plan_path": str(path)}


def _ordinary_mutation(case, facts, commands, label, timings):
    proposed = stage(facts, commands)
    expected = evaluate(case.selector, proposed)
    draft = {"model": case.model, "commands": commands, "returning": []}
    path = case.backend.directory / f"{label}.plan.json"
    plan = _timed(timings, "client_prepare_wall_seconds", lambda: client.prepare(
        case.backend.url, case.backend.token, draft))
    client.save_plan(path, plan)
    response = _timed(timings, "client_execute_wall_seconds", lambda: client.execute(
        case.backend.url, case.backend.token, plan))
    equal("population.ordinary.status", "committed", response["status"])
    _verify_facts(case.backend, case.model, proposed, case.selector)
    case.steps.append({"name": label, "plan": plan, "response": response,
                       "expected": expected, "source_count": len(proposed)})
    return proposed, {"operation_id": response["result"]["operation_id"],
                      "commands": commands, "plan_path": str(path)}


def _pool_strategy(_schema, _seed, _cursor, _context):
    return {"unit": 7}


def _delivery_strategy(_schema, _seed, _cursor, _context):
    return {"pool": "00000000-0000-4000-8000-000000000000",
            "at": "0", "quantity": "10"}


def run_equipment(binary, directory, *, seed=20261025):
    """Run sequential fresh-prefix population and a stale same-time conflict."""
    timings = {}
    setup_started = time.monotonic()
    case = Scenario(binary, directory, "equipment", "population-equipment")
    timings["server_and_store_setup_seconds"] = time.monotonic() - setup_started
    try:
        backend = case.backend
        developer = backend.cli("model", "developer")
        facts, population_rows = {}, []
        generation_started = time.monotonic()

        pool_state = population.prepare(developer, {"Pool": 1}, seed=seed,
            strategies={"Pool": _pool_strategy}, batch_size=1)
        pool_proposal = population.propose(pool_state, {})
        pool_id = pool_proposal.commands[0]["id"]
        facts, row = _commit_proposal(case, pool_state, pool_proposal, facts, "seed-pool", timings)
        population_rows.append(row)

        delivery_state = population.prepare(developer, {"Delivery": 1}, seed=seed + 1,
            existing={"Pool": [{"id": pool_id, "contract": "Pool"}]},
            strategies={"Delivery": _delivery_strategy}, batch_size=1)
        delivery_proposal = population.propose(delivery_state, {})
        delivery_id = delivery_proposal.commands[0]["id"]
        facts, row = _commit_proposal(case, delivery_state, delivery_proposal, facts,
                                      "seed-delivery-10", timings)
        population_rows.append(row)

        reservation_state = prepare_equipment_population(
            developer, pool_id, seed=seed + 2, count=3)
        fresh_prefixes = []
        previous_start = None
        for index, (start, requested) in enumerate(((10, 8), (20, 7), (30, 1))):
            context = equipment_context(
                backend.call, case.model, pool_id, start=start, end=100,
                requested=requested, previous_start=previous_start,
                common_end=100,
            )
            fresh_prefixes.append(context["available_before"])
            proposal = population.propose(reservation_state, context, max_commands=1)
            facts, row = _commit_proposal(case, reservation_state, proposal, facts,
                                          f"reservation-{index + 1}", timings)
            population_rows.append(row)
            previous_start = start
            if index == 0:
                current = backend.call("records.get", {"model": case.model, "id": delivery_id})
                facts, row = _ordinary_mutation(case, facts, [{
                    "op": "update", "id": delivery_id, "if_version": current["version"],
                    "set": {"quantity": "12"}, "unset": [],
                }], "raise-delivery-to-12", timings)
                population_rows.append(row)
        timings["population_generation_seconds"] = time.monotonic() - generation_started
        equal("equipment.fresh_prefixes", ["10", "4", "0"], fresh_prefixes)
        final_oracle = _verify_facts(backend, case.model, facts, case.selector)

        conflict = run_equipment_stale_conflict(case, developer, seed + 20, timings)
        # Five finite actions reuse the accepted generated reservation as the
        # source for read/update/create/delete; every mutation uses client plans.
        experiment, experiment_facts = run_equipment_actions(
            case, facts, reservation_state, pool_id, timings)
        result = {
            "status": "passed", "model": case.model,
            "source_count": len(experiment_facts),
            "population": population_rows,
            "fresh_available_before": fresh_prefixes,
            "equipment_expected": final_oracle,
            "stale_context_conflict": conflict,
            "measured_experiment": experiment,
            "timings_seconds": timings,
            "scope": "single-writer disposable redb; strict-before Equipment construction has increasing starts and one common future end; no claim for arbitrary intervals or multi-writer capacity",
        }
        case.steps.append({"name": "g8-bounded-actions", "result": experiment})
        case_report = case.finish()
        case_report["steps"] = case.steps
        return {"result": result, "scenario": case_report}
    finally:
        case.close()


def run_equipment_stale_conflict(case, developer, seed, timings):
    """Interleave same-time valid inputs; the second final graph must reject."""
    backend, model = case.backend, case.model
    facts = case.steps[-1]["expected"] if case.steps else {}
    # Use a fresh independent root so the known capacity is exactly ten.
    pool_state = population.prepare(developer, {"Pool": 1}, seed=seed,
        strategies={"Pool": _pool_strategy}, batch_size=1)
    pool_proposal = population.propose(pool_state, {})
    pool_id = pool_proposal.commands[0]["id"]
    all_facts = {}
    all_facts, _ = _commit_proposal(case, pool_state, pool_proposal, all_facts,
                                    "conflict-pool", timings)
    delivery_state = population.prepare(developer, {"Delivery": 1}, seed=seed + 1,
        existing={"Pool": [{"id": pool_id, "contract": "Pool"}]},
        strategies={"Delivery": _delivery_strategy}, batch_size=1)
    delivery_proposal = population.propose(delivery_state, {})
    delivery_id = delivery_proposal.commands[0]["id"]
    all_facts, _ = _commit_proposal(case, delivery_state, delivery_proposal, all_facts,
                                    "conflict-delivery", timings)

    # A's plan commits after B has already read the same strict prefix and
    # saved its exact intent, making the stale final graph independently bad.
    stale_state = prepare_equipment_population(developer, pool_id, seed=seed + 2, count=1)
    stale_context = equipment_context(backend.call, model, pool_id, start=10, end=100,
        requested=6, previous_start=None, common_end=100)
    stale_proposal = population.propose(stale_state, stale_context, max_commands=1)
    stale_plan = bind_saved_plan(stale_state, stale_proposal, backend.url, backend.token,
                                 backend.directory / "stale-reservation.plan.json")
    fresh_state = prepare_equipment_population(developer, pool_id, seed=seed + 3, count=1)
    fresh_context = equipment_context(backend.call, model, pool_id, start=10, end=100,
        requested=6, previous_start=None, common_end=100)
    fresh_proposal = population.propose(fresh_state, fresh_context, max_commands=1)
    all_facts, _ = _commit_proposal(case, fresh_state, fresh_proposal, all_facts,
                                    "same-time-reservation-A", timings)
    try:
        evaluate("equipment", stage(all_facts, stale_proposal.commands))
    except OracleError as error:
        equal("conflict.oracle_kind", "invariant", error.kind)
    else:
        raise AssertionError("source oracle accepted the stale same-time allocation")
    try:
        client.execute(backend.url, backend.token, stale_plan)
    except client.RpcError as error:
        equal("conflict.server_kind", "invariant", error.kind)
        population.reject(stale_state, stale_proposal, stale_plan, error)
    else:
        raise AssertionError("server accepted the stale same-time allocation")
    equal("conflict.rejected_quota", 0, stale_state.accepted["Reservation"])
    equal("conflict.rejected_pool", 1, len(stale_state.pools["Pool"]))
    equal("conflict.receipt", "not_observed",
          client.execute(backend.url, backend.token, stale_plan, status=True)["status"])

    # A fresh context at a later start sees only four units and yields a valid
    # exact amount; this is an explicit new proposal and operation.
    context = equipment_context(backend.call, model, pool_id, start=20, end=100,
        requested=6, previous_start=10, common_end=100)
    proposal = population.propose(stale_state, context, max_commands=1)
    equal("conflict.refreshed_prefix", "4", context["available_before"])
    all_facts, row = _commit_proposal(case, stale_state, proposal, all_facts,
                                      "fresh-reservation-B", timings)
    return {"kind": "invariant", "rejected_operation_id": stale_plan["request"]["operation_id"],
            "fresh_operation_id": row["operation_id"], "quota_after_reject": 0,
            "refreshed_available_before": context["available_before"],
            "committed_after_refresh": stale_state.accepted["Reservation"]}


def run_equipment_actions(case, facts, reservation_state, pool_id, timings):
    """Run finite generated CRUD/read actions through G8's bounded scheduler."""
    backend, model = case.backend, case.model
    generated = [item for item in reservation_state.pools["Reservation"].values()]
    if not generated:
        raise ValueError("accepted population must provide a Reservation to exercise")
    source_id = generated[0]["id"]
    active_fact = deepcopy(facts)
    inactive_fields = {"pool": pool_id, "starts": "50", "ends": "100",
                       "requested": "1", "active": False}
    clone_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"population-demo-clone:{source_id}"))
    action_items = [
        {"kind": "read", "id": source_id},
        {"kind": "update", "id": source_id, "set": {"active": False}},
        {"kind": "read", "id": source_id},
        {"kind": "create", "id": clone_id, "contract": 410, "fields": inactive_fields},
        {"kind": "delete", "id": clone_id},
    ]
    action_cursor = {"facts": active_fact}
    rpc_methods = {}

    def measured_call(label, fn):
        started = time.monotonic()
        result = fn()
        rpc_methods[label] = rpc_methods.get(label, 0.0) + time.monotonic() - started
        return result

    def submit(item):
        if item["kind"] == "read":
            value = measured_call("records.get", lambda: backend.call(
                "records.get", {"model": model, "id": item["id"]}))
            return {"kind": "read", "id": value["id"]}
        commands = []
        if item["kind"] == "create":
            commands = [{"op": "create", "id": item["id"], "contract": item["contract"],
                         "fields": item["fields"]}]
        else:
            current = measured_call("records.get", lambda: backend.call(
                "records.get", {"model": model, "id": item["id"]}))
            if item["kind"] == "update":
                commands = [{"op": "update", "id": item["id"], "if_version": current["version"],
                             "set": item["set"], "unset": []}]
            else:
                commands = [{"op": "delete", "id": item["id"], "if_version": current["version"]}]
        proposed = stage(action_cursor["facts"], commands)
        expected = evaluate("equipment", proposed)
        path = backend.directory / f"measured-{item['kind']}-{len(action_cursor['facts'])}.plan.json"
        plan = measured_call("client.prepare", lambda: client.prepare(
            backend.url, backend.token, {"model": model, "commands": commands, "returning": []}))
        client.save_plan(path, plan)
        response = measured_call("client.execute", lambda: client.execute(
            backend.url, backend.token, plan))
        equal("measured.commit", "committed", response["status"])
        action_cursor["facts"] = proposed
        return {"kind": "committed", "id": item["id"],
                "operation_id": response["result"]["operation_id"],
                "expected": expected}

    def check(item, outcome):
        _verify_facts(backend, model, action_cursor["facts"], case.selector)
        if item["kind"] == "read":
            equal("measured.read.id", item["id"], outcome["id"])

    def observe(_item, _outcome):
        path = str(backend.store)
        return resource_sample(backend.process.pid, os.getpid(), paths=(path,),
                               phase="population-g9", logical={"source_count": len(action_cursor["facts"])})

    generation_seconds = timings.get("population_generation_seconds", 0.0)
    setup_seconds = timings.get("server_and_store_setup_seconds", 0.0)
    run = measured_actions(iter(action_items), submit, duration=1.0, offered_rate=5,
        clients=1, max_pending=1, observer=observe, checker=check,
        generation_seconds=generation_seconds, setup_seconds=setup_seconds)
    run["rpc_method_wall_seconds"] = rpc_methods
    run["actions"] = action_items
    return run, action_cursor["facts"]


def _quantity_source(_schema, _seed, _cursor, _context):
    return {"value": "12"}


def run_lost_response_population(case, developer, seed, timings):
    """Reconcile one committed population plan after its HTTP reply is dropped."""
    backend = case.backend
    state = population.prepare(developer, {"Source": 1}, seed=seed,
        strategies={"Source": _quantity_source}, batch_size=1)
    proposal = population.propose(state, {})
    destination = backend.directory / "quantity-lost-response.plan.json"
    with discard_once(backend, "after_response") as (proxy_url, observation):
        plan = bind_saved_plan(state, proposal, proxy_url, backend.token, destination)
        original = client._bytes(plan)
        try:
            client.execute(proxy_url, backend.token, plan)
        except client.ClientError as error:
            equal("population.lost_reply.kind", "outcome_unknown", error.kind)
        else:
            raise AssertionError("discarded population reply unexpectedly reached the client")
        try:
            population.propose(state, {})
        except population.PopulationError:
            pass
        else:
            raise AssertionError("uncertain population intent allowed a replacement proposal")
        status = client.execute(proxy_url, backend.token, plan, status=True)
        equal("population.lost_reply.status", "committed", status["status"])
        population.accept(state, proposal, plan, status)
        equal("population.lost_reply.plan_unchanged", original, client._bytes(plan))
        equal("population.lost_reply.same_operation", plan["request"]["operation_id"],
              status["result"]["operation_id"])
        equal("population.lost_reply.one_forwarded_request", 1, observation["discarded"])
        equal("population.lost_reply.server_response", 200, observation["upstream_status"])
    _verify_facts(backend, case.model, {
        proposal.commands[0]["id"]: {"contract": proposal.commands[0]["contract"],
                                      "fields": proposal.commands[0]["fields"]}
    }, case.selector)
    return {"boundary": "after_response", "status": status["status"],
            "operation_id": status["result"]["operation_id"], "replacement_operation_id": None,
            "original_plan_unchanged": True, "accepted_source_quota": state.accepted["Source"],
            "provider_observation": observation, "saved_plan": str(destination)}


def _quantity_scale(_schema, _seed, _cursor, _context):
    return {"parent": "00000000-0000-4000-8000-000000000000",
            "factor": {"numerator": "1", "denominator": "2"}, "rounding": "exact"}


def _quantity_join(_schema, _seed, _cursor, _context):
    return {"left": "00000000-0000-4000-8000-000000000000",
            "right": "00000000-0000-4000-8000-000000000000"}


def _quantity_selector(child, path, pools, _usage, _rng, _context):
    if child != "Join":
        raise ValueError("Quantity selector is authored only for Join")
    target = "Source" if path == "left" else "Scale" if path == "right" else None
    if target is None or not pools.get(target):
        raise ValueError(f"No typed Quantity parent for Join.{path}")
    return target, next(iter(pools[target]))


def run_quantity(binary, directory, *, seed=20261035):
    """Populate a mixed exact Source/Scale/Join graph through ordinary HTTP."""
    timings = {}
    setup_started = time.monotonic()
    case = Scenario(binary, directory, "quantity", "population-quantity")
    timings["server_and_store_setup_seconds"] = time.monotonic() - setup_started
    try:
        backend = case.backend
        developer = backend.cli("model", "developer")
        facts, rows = {}, []
        generation_started = time.monotonic()
        source_state = population.prepare(developer, {"Source": 2}, seed=seed,
            strategies={"Source": _quantity_source}, batch_size=1)
        source_proposal = population.propose(source_state, {})
        source_id = source_proposal.commands[0]["id"]
        facts, row = _commit_proposal(case, source_state, source_proposal, facts,
                                      "quantity-source-12", timings)
        rows.append(row)
        stopped_state = {"cursor": source_state.cursor,
                         "accepted": deepcopy(source_state.accepted),
                         "pool_ids": {name: list(ids) for name, ids in source_state.pool_ids.items()},
                         "pending": source_state.pending}
        equal("quantity.stop_inspect.accepted_source", 1, stopped_state["accepted"]["Source"])
        equal("quantity.stop_inspect.pending", None, stopped_state["pending"])
        continued = population.propose(source_state, {})
        continued_id = continued.commands[0]["id"]
        facts, row = _commit_proposal(case, source_state, continued, facts,
                                      "quantity-source-continued", timings)
        rows.append(row)

        scale_state = population.prepare(developer, {"Scale": 1}, seed=seed + 1,
            existing={"Source": [{"id": source_id, "contract": "Source"}]},
            strategies={"Scale": _quantity_scale}, batch_size=1)
        scale_proposal = population.propose(scale_state, {})
        scale_id = scale_proposal.commands[0]["id"]
        facts, row = _commit_proposal(case, scale_state, scale_proposal, facts,
                                      "quantity-scale-half", timings)
        rows.append(row)

        join_state = population.prepare(developer, {"Join": 1}, seed=seed + 2,
            existing={"Source": [{"id": source_id, "contract": "Source"}],
                      "Scale": [{"id": scale_id, "contract": "Scale"}]},
            strategies={"Join": _quantity_join}, select_reference=_quantity_selector,
            batch_size=1)
        join_proposal = population.propose(join_state, {})
        join_id = join_proposal.commands[0]["id"]
        facts, row = _commit_proposal(case, join_state, join_proposal, facts,
                                      "quantity-polymorphic-join", timings)
        rows.append(row)

        # Clone an actual public input. Only `input` is copied; the new row ID
        # is generated, and declared left/right references are selected anew
        # from the typed Source and Scale pools.
        authored = backend.call("records.get", {"model": case.model, "id": join_id})
        clone_state = population.prepare(developer, {"Join": 1}, seed=seed + 3,
            existing={"Source": [{"id": source_id, "contract": "Source"}],
                      "Scale": [{"id": scale_id, "contract": "Scale"}]},
            provider=authored_input_provider(authored),
            select_reference=_quantity_selector, batch_size=1)
        clone_proposal = population.propose(clone_state, {})
        clone_id = clone_proposal.commands[0]["id"]
        if clone_id == join_id:
            raise AssertionError("authored clone must have a fresh generated ID")
        facts, row = _commit_proposal(case, clone_state, clone_proposal, facts,
                                      "quantity-authored-input-clone", timings)
        rows.append(row)
        timings["population_generation_seconds"] = time.monotonic() - generation_started
        oracle = _verify_facts(backend, case.model, facts, case.selector)
        equal("quantity.source", {"quantity": "12"}, oracle["derived"][source_id])
        equal("quantity.scale", {"quantity": "6"}, oracle["derived"][scale_id])
        equal("quantity.join", {"quantity": "18"}, oracle["derived"][join_id])
        equal("quantity.cloned_join", {"quantity": "18"}, oracle["derived"][clone_id])
        lost_reply = run_lost_response_population(case, developer, seed + 20, timings)

        missing = population.prepare(developer, {"Scale": 1}, seed=seed + 10,
                                    strategies={"Scale": _quantity_scale})
        try:
            population.propose(missing, {})
        except population.PopulationError as error:
            missing_context = str(error)
        else:
            raise AssertionError("Quantity Scale without a Source anchor was proposed")
        return {"status": "passed", "model": case.model, "source_count": len(facts),
                "population": rows, "oracle": oracle,
                "stop_inspect_continue": {"inspected_after_first_commit": stopped_state,
                    "continued_source_id": continued_id,
                    "accepted_source_after_continue": source_state.accepted["Source"]},
                "lost_response_reconciliation": lost_reply,
                "negative_missing_parent": missing_context,
                "timings_seconds": timings,
                "scope": "one disposable redb store; exact integer/rational Source/Scale/Join graph; no general inference claim"}
    finally:
        case.close()


def run_live_demo(binary, output, *, seed=20261025):
    """Run both licensed SDK-free redb stores serially and retain JSON reports."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    equipment = run_equipment(binary, output / "equipment", seed=seed)
    quantity = run_quantity(binary, output / "quantity", seed=seed + 100)
    report = {"status": "passed", "binary": str(Path(binary).resolve()),
              "equipment": equipment, "quantity": quantity,
              "limits": {"backend": "SDK-free redb", "stores": "fresh and serial",
                         "no_cargo": True, "not_a_capacity_claim": True}}
    write_json(output / "population-demo.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=20261025)
    args = parser.parse_args()
    report = run_live_demo(args.binary, args.out, seed=args.seed)
    print(f"population demo {report['status']}: {args.out / 'population-demo.json'}")


if __name__ == "__main__":
    main()
