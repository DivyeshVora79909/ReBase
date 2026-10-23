"""Bounded, seeded quantity exploration with explicit replay artifacts.

The default profile is deliberately small: one disposable quantity fixture,
eight instantiated action families and at most 32 actions. This is generated
stateful exploration, not an exhaustive proof of the engine.
"""
from copy import deepcopy
import json
import random
from pathlib import Path
import subprocess
import tempfile

import client
from verify_runtime import Mismatch, Scenario, digest, write_json


DEFAULT_STEPS = 32
ACTION_FAMILIES = ("source_update", "scale_factor", "retarget", "cycle",
                   "blocked_delete", "inexact", "noop", "replay")


def minimize(trace, predicate, budget=128):
    """Greedily delete trace spans while predicate keeps the same failure.

    `predicate(candidate)` may return False/None, True, or a failure-kind
    string. A string result establishes the failure class on the original and
    every accepted reduction must return that same string. Preconditions are
    the predicate's responsibility, so an unrelated failure cannot shrink a
    trace unless it has the same explicit class. Returns a deep-copied trace.
    """
    original = deepcopy(list(trace))
    initial = predicate(deepcopy(original))
    if not initial:
        return original
    target = initial if isinstance(initial, str) else True

    def preserves(candidate):
        result = predicate(deepcopy(candidate))
        return result == target if isinstance(target, str) else bool(result)

    current = original
    remaining = max(0, int(budget))
    granularity = 2
    while current and remaining:
        width = max(1, (len(current) + granularity - 1) // granularity)
        reduced = False
        for start in range(0, len(current), width):
            if not remaining:
                break
            remaining -= 1
            candidate = current[:start] + current[start + width:]
            if preserves(candidate):
                current = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if not reduced:
            if granularity >= len(current):
                break
            granularity = min(len(current), granularity * 2)
    return deepcopy(current)


def _root(binary, destination):
    return Path(destination).resolve()


def _fixture(case, label="quantity"):
    draft = case.backend.cli("fixture", "plan", "quantities", "--namespace", str(case.namespace))
    fixture_ids = draft["fixture"]["ids"]
    commands = deepcopy(draft["commands"])
    other = case.create("other-source", 101, {"value": "18"})
    commands.insert(1, other)
    case.mutate("Q0", "Create Source, Scale L/R, Join and an independent source.", commands,
                "Source quantities feed declared ready parents; Join reads slots 8 and 3.")
    return {**fixture_ids, "other": other["id"]}, draft


def _action(case, ids, name, rng, previous_plan=None):
    """Instantiate one template as explicit wire commands and a replay recipe."""
    if name == "source_update":
        identity = ids[rng.choice(("source", "other"))]
        value = str(rng.choice((0, 6, 12, 18)))
        return {"kind": name, "ids": {"target": identity}, "value": value,
                "commands": [case.update(identity, {"value": value})]}
    if name == "scale_factor":
        identity = ids[rng.choice(("left", "right"))]
        numerator = rng.choice(("0", "1"))
        return {"kind": name, "ids": {"target": identity}, "numerator": numerator,
                "commands": [case.update(identity, {"factor": {"numerator": numerator,
                                                                    "denominator": "1"},
                                                     "rounding": "exact"})]}
    if name == "retarget":
        identity = ids["left"]
        parent = rng.choice((ids["source"], ids["other"]))
        return {"kind": name, "ids": {"target": identity, "parent": parent},
                "commands": [case.update(identity, {"parent": parent})]}
    if name == "cycle":
        identity = ids["left"]
        return {"kind": name, "ids": {"target": identity, "parent": ids["join"]},
                "commands": [case.update(identity, {"parent": ids["join"],
                    "factor": {"numerator": "0", "denominator": "1"}})],
                "expected_rejection": "feedback"}
    if name == "blocked_delete":
        identity = ids["source"]
        return {"kind": name, "ids": {"target": identity},
                "commands": [case.delete(identity)],
                "expected_rejection": "unavailable_reference"}
    if name == "inexact":
        scale = ids["left"]
        source = ids["source"]
        return {"kind": name, "ids": {"target": source, "scale": scale},
                "commands": [case.update(source, {"value": "13"}),
                    case.update(scale, {"parent": source,
                        "factor": {"numerator": "1", "denominator": "2"}, "rounding": "exact"})],
                "expected_rejection": "inexact"}
    if name == "noop":
        identity = ids["source"]
        current = case.get(identity)["input"]["value"]
        return {"kind": name, "ids": {"target": identity}, "value": current,
                "commands": [case.update(identity, {"value": current})]}
    if name == "replay":
        return {"kind": name, "operation_id": (previous_plan or {}).get("request", {}).get("operation_id"),
                "commands": []}
    raise ValueError("Unknown action family " + name)


def _expected_error(action):
    return action.get("expected_rejection")


def _source_fingerprint():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root,
                            capture_output=True, text=True)
    return {"revision": result.stdout.strip() if result.returncode == 0 else None,
            "files": {name: digest(root / "tools" / name) for name in
                      ("verify_explore.py", "verify_runtime.py", "verify_oracles.py", "client.py")}}


def _profile(seed, steps, case):
    return {"model": "quantity", "case": case or "quantity", "seed": int(seed),
            "steps": max(0, min(int(steps), 256)), "action_alphabet": list(ACTION_FAMILIES),
            "alphabet_exhaustive": False,
            "coverage_note": "Seeded instantiated sequences only; native checks are not executed by this mode."}


def explore(binary, destination, seed, case=None, steps=DEFAULT_STEPS):
    """Run deterministic stateful quantity actions and retain complete plans."""
    if case not in (None, "quantity"):
        raise ValueError("explore currently supports case='quantity'")
    requested_steps = int(steps)
    destination = _root(binary, destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    steps = max(0, min(int(steps), 256))
    rng = random.Random(int(seed))
    actions, plans, coverage = [], [], {name: 0 for name in ACTION_FAMILIES}
    scenario, ids, draft, initial_plan = None, None, None, None
    last_plan = None
    try:
        scenario = Scenario(binary, destination / "backend", "quantity", "explore-" + str(seed))
        ids, draft = _fixture(scenario)
        initial_plan = deepcopy(scenario.steps[0]["plan"])
        plans.append(initial_plan)
        for index in range(steps):
            kind = ACTION_FAMILIES[index % len(ACTION_FAMILIES)]
            # Seed controls concrete values, target selection and retarget choices.
            action = _action(scenario, ids, kind, rng, last_plan)
            action["action_index"] = index
            if kind == "replay":
                if last_plan is None:
                    action["classified"] = "invalid_precondition:no_prior_intent"
                    actions.append(action)
                    coverage[kind] += 1
                    continue
                replayed = client.execute(scenario.backend.url, scenario.backend.token, last_plan)
                if not replayed.get("replayed"):
                    raise Mismatch("replay.idempotence", True, replayed)
                action.update({"classified": "replayed_same_target", "exact_plan": deepcopy(last_plan),
                               "observed": replayed})
                actions.append(action)
                coverage[kind] += 1
                continue
            expected_error = _expected_error(action)
            actions.append(action)
            item = scenario.mutate(f"explore-{index:03d}-{kind}",
                f"Seeded {kind} action over explicit quantity sources.", action["commands"],
                "Independent Fraction/list oracle recomputes the final graph and values.",
                reject=expected_error)
            action["plan"] = deepcopy(item["plan"])
            action["request_bytes_hex"] = client._bytes(item["plan"]["request"]).hex()
            action["expected"] = deepcopy(item.get("expected_state", item.get("expected")))
            action["observed"] = deepcopy(item.get("observed_records", item.get("observed")))
            action["oracle_rejection"] = item.get("oracle_rejection")
            action["execution"] = {key: deepcopy(item[key]) for key in
                ("before_facts", "after_facts", "internal", "complete_rollback", "receipt", "work", "duration_seconds")
                if key in item}
            plans.append(deepcopy(item["plan"]))
            last_plan = item["plan"]
            coverage[kind] += 1
        report = {"format": "rebase-explore-1", "status": "passed", "profile": _profile(seed, steps, case),
                  "source": _source_fingerprint(), "binary": {"path": str(Path(binary).resolve()),
                  "sha256": digest(binary)}, "model": scenario.model, "behavior": scenario.catalog,
                  "fixture": {"namespace": str(scenario.namespace), "draft": draft,
                              "initial_plan": initial_plan,
                              "initial_commands": deepcopy(draft["commands"])},
                  "identities": ids, "coverage": coverage, "attempted": len(actions),
                  "classified_invalid": sum(1 for row in actions if row.get("classified", "").startswith("invalid")),
                  "accepted": sum(1 for row in actions if row.get("oracle_rejection") is None and row["kind"] != "replay"),
                  "rejected": sum(1 for row in actions if row.get("oracle_rejection") is not None),
                  "checked": len(actions), "truncated": requested_steps > 256,
                  "actions": actions,
                  "exact_plans": plans,
                  "replay_semantics": "Logical replay regenerates each plan/context in a fresh store from symbolic recipes. Exact plans are diagnostic and valid only for their original target/context.",
                  "native_exhaustive": {"status": "not_run_by_this_tool", "trace_count": 259,
                                        "reason": "The root check report owns native exhaustive coverage status."}}
        write_json(destination / "artifact.json", report)
        return report
    except BaseException as error:
        if (actions and actions[-1]["kind"] != "replay" and "plan" not in actions[-1]
                and scenario is not None and scenario.steps):
            failed_step = scenario.steps[-1]
            expected_step = f"explore-{actions[-1]['action_index']:03d}-{actions[-1]['kind']}"
            if failed_step.get("name") == expected_step:
                actions[-1]["plan"] = deepcopy(failed_step.get("plan"))
                if failed_step.get("plan"):
                    actions[-1]["request_bytes_hex"] = client._bytes(failed_step["plan"]["request"]).hex()
                    plans.append(deepcopy(failed_step["plan"]))
        report = {"format": "rebase-explore-1", "status": "failed", "profile": _profile(seed, steps, case),
                  "source": _source_fingerprint(), "binary": {"path": str(Path(binary).resolve()),
                  "sha256": digest(binary)}, "model": scenario.model if scenario else None,
                  "behavior": scenario.catalog if scenario else None,
                  "fixture": ({"namespace": str(scenario.namespace), "draft": draft} if scenario and draft else None),
                  "identities": ids, "actions": actions, "exact_plans": plans,
                  "mismatch": {"type": type(error).__name__, "kind": getattr(error, "kind", type(error).__name__),
                               "message": str(error)}}
        write_json(destination / "failure.original.json", report)
        trace = actions
        if scenario is not None and ids is not None and draft is not None:
            predicate = lambda candidate: _failure_class_replay(binary, destination, ids,
                                candidate, report["mismatch"]["kind"])
            reduced = minimize(trace, predicate, budget=64)
            reproduced = predicate(reduced) == report["mismatch"]["kind"]
            if not reproduced:
                reduced = trace
            report["actions"] = reduced
            report["minimization"] = {"original_actions": len(trace), "minimized_actions": len(reduced),
                                      "budget": 64, "status": "minimized" if reproduced else "not_reproduced",
                                      "same_failure_kind_reproduced": reproduced}
        else:
            report["minimization"] = {"original_actions": 0, "minimized_actions": 0,
                                      "status": "not_applicable", "same_failure_kind_reproduced": False}
        write_json(destination / "failure.minimized.json", report)
        raise
    finally:
        if scenario is not None:
            scenario.close()


def _failure_class_replay(binary, parent, original_ids, actions, target_kind):
    """Fresh-fixture predicate used only after a real mismatch."""
    temp = Path(tempfile.mkdtemp(prefix="rebase-shrink-", dir=parent))
    scenario = None
    try:
        scenario = Scenario(binary, temp / "backend", "quantity", "shrink")
        # Recreate the same source identities through a fresh logical fixture.
        ids, _ = _fixture(scenario)
        remap = {original_ids[key]: ids[key] for key in original_ids if key in ids}
        for index, action in enumerate(actions):
            kind = action.get("kind")
            if kind == "replay":
                continue
            # Keep the original symbolic choices while refreshing target versions.
            translated = _translate_action(action, remap)
            commands = _rebuild(case=scenario, ids=ids, action=translated)
            scenario.mutate("shrink-%d" % index, "Shrink replay", commands,
                            "Recompute independent quantity oracle.", reject=action.get("expected_rejection"))
        return False
    except Mismatch as error:
        return error.kind if error.kind == target_kind else False
    except Exception:
        return False
    finally:
        if scenario is not None:
            scenario.close()


def _rebuild(case, ids, action):
    """Rebind a symbolic saved action to fresh record versions."""
    kind, selected = action["kind"], action.get("ids", {})
    if kind == "source_update":
        return [case.update(selected["target"], {"value": action["value"]})]
    if kind == "scale_factor":
        return [case.update(selected["target"], {"factor": {"numerator": action["numerator"],
                "denominator": "1"}, "rounding": "exact"})]
    if kind == "retarget":
        return [case.update(selected["target"], {"parent": selected["parent"]})]
    if kind == "cycle":
        return [case.update(selected["target"], {"parent": selected["parent"],
                "factor": {"numerator": "0", "denominator": "1"}})]
    if kind == "blocked_delete":
        return [case.delete(selected["target"])]
    if kind == "inexact":
        return [case.update(selected["target"], {"value": "13"}),
                case.update(selected["scale"], {"parent": ids["source"],
                    "factor": {"numerator": "1", "denominator": "2"}, "rounding": "exact"})]
    if kind == "noop":
        return [case.update(selected["target"], {"value": action["value"]})]
    raise ValueError("Unknown action family " + str(kind))


def _translate_action(action, remap):
    result = deepcopy(action)
    result["ids"] = {key: remap.get(value, value) for key, value in action.get("ids", {}).items()}
    return result


def replay(binary, destination, artifact):
    """Logically reproduce an artifact in a fresh store with new plan contexts."""
    artifact_path = Path(artifact) if isinstance(artifact, (str, Path)) else None
    if artifact_path is not None:
        if artifact_path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("Exploration artifact exceeds 8 MiB")
        source = json.loads(artifact_path.read_text())
    else:
        source = deepcopy(artifact)
    if source.get("format") != "rebase-explore-1":
        raise ValueError("Unsupported exploration artifact")
    actions = source.get("actions", [])
    if not isinstance(actions, list) or len(actions) > 256:
        raise ValueError("Exploration artifact exceeds the 256-action replay limit")
    for action in actions:
        if not isinstance(action, dict) or action.get("kind") not in ACTION_FAMILIES:
            raise ValueError("Exploration artifact contains an unknown action family")
    destination = _root(binary, destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    scenario = None
    try:
        scenario = Scenario(binary, destination / "backend", "quantity", "logical-replay")
        _check_model_compatibility(source, scenario.model)
        ids, _ = _fixture(scenario)
        old_ids = source.get("identities", {})
        remap = {old_ids[key]: ids[key] for key in old_ids if key in ids}
        results, last_plan = [], None
        for index, action in enumerate(actions):
            if action["kind"] == "replay":
                if last_plan is not None:
                    result = client.execute(scenario.backend.url, scenario.backend.token, last_plan)
                    if not result.get("replayed"):
                        raise Mismatch("replay.idempotence", True, result)
                else:
                    result = {"classified": "invalid_precondition:no_prior_intent"}
                results.append({"kind": "replay", "observed": result})
                continue
            # Rebind with newly obtained versions and a new operation context.
            action = _translate_action(action, remap)
            commands = _rebuild(scenario, ids, action)
            expected_error = action.get("expected_rejection")
            item = scenario.mutate(f"logical-{index:03d}-{action['kind']}", "Logical replay: " + action["kind"],
                commands, "Fresh target and freshly bound intent; source oracle is reevaluated.", reject=expected_error)
            last_plan = item["plan"]
            original_plan = action.get("plan")
            results.append({"kind": action["kind"], "old_operation_id": (original_plan or {}).get("request", {}).get("operation_id"),
                "new_operation_id": last_plan["request"]["operation_id"],
                "old_context": (original_plan or {}).get("request", {}).get("context"),
                "new_context": last_plan["request"]["context"], "observed": item.get("observed")})
        result = {"format": "rebase-explore-replay-1", "status": "passed",
                  "source_artifact": str(artifact_path) if artifact_path is not None else None,
                  "model": scenario.model, "fresh_target": {key: scenario.catalog.get(key) for key in ("model", "behavior")},
                  "steps": results,
                  "exact_byte_resume": "not performed: original plans are retained for the original compatible target only"}
        write_json(destination / "replay.json", result)
        return result
    finally:
        if scenario is not None:
            scenario.close()


def _check_model_compatibility(source, model):
    if source.get("model") != model:
        raise ValueError(
            f"Exploration artifact model {source.get('model')!r} does not match fresh Quantity model {model!r}")
