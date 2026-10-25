"""Explicit, caller-owned population proposals for the public model catalog.

This module authors data only. Submission, status reconciliation and authority
remain the responsibility of :mod:`client` and the server.
"""

from __future__ import annotations

from copy import deepcopy
from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
import json
import random
import re
import uuid
from typing import Any, Callable
from types import MappingProxyType

import jsonschema
import client as operation_client


class PopulationError(ValueError):
    """Invalid catalog, generation settings, proposal or acknowledgement."""


@dataclass
class State:
    catalog: dict
    contracts: dict[str, dict]
    validators: dict[str, Any]
    quotas: dict[str, int]
    accepted: dict[str, int]
    pools: dict[str, dict[str, dict]]
    seed: int | str
    pool_ids: dict[str, list[str]] = field(default_factory=dict)
    identity_ids: set[str] = field(default_factory=set)
    provider_buffers: dict[str, list[dict]] = field(default_factory=dict)
    provider_cursors: dict[str, int] = field(default_factory=dict)
    cursor: int = 0
    provider: Callable | None = None
    strategies: dict[str, Callable] = field(default_factory=dict)
    rules: dict[str, Callable] = field(default_factory=dict)
    priorities: dict[str, int] = field(default_factory=dict)
    batch_size: int = 1
    clock: Any = None
    pending: Pending | None = None
    reference_usage: dict[tuple[str, str, str, str], int] = field(default_factory=dict)
    last_receipt: str | None = None
    target: dict | None = None
    provider_batch_size: int = 32
    select_reference: Callable | None = None


@dataclass
class Proposal:
    """Detached authored commands and the deterministic cursor transition."""
    commands: list[dict]
    digest: str
    start_cursor: int
    end_cursor: int
    additions: list[dict]
    usage: dict[tuple[str, str, str, str], int]
    returning: list[str] = field(default_factory=list)
    provider_buffers_after: dict[str, list[dict]] = field(default_factory=dict)
    provider_cursors_after: dict[str, int] = field(default_factory=dict)


class Pending:
    """The current proposal and, once prepared, its exact saved client plan."""
    def __init__(self, proposal, plan=None, expected_target=None, expected_model=None):
        self.proposal = proposal
        self.proposal_digest = _proposal_digest(proposal)
        self.expected_target = deepcopy(expected_target)
        self.expected_model = expected_model
        self.plan_digest = None
        self._plan_snapshot = None
        if plan is not None:
            self.plan = plan

    @property
    def plan(self):
        return deepcopy(self._plan_snapshot)

    @plan.setter
    def plan(self, value):
        if value is None:
            if self._plan_snapshot is not None:
                raise PopulationError("a bound pending plan cannot be cleared")
            return
        snapshot = deepcopy(value)
        if (self.proposal_digest != _proposal_digest(self.proposal)
                or self.proposal.digest != self.proposal_digest):
            raise PopulationError("proposal changed before saved plan binding")
        _validate_plan(self.proposal, snapshot, self.expected_model, self.expected_target)
        digest = _digest(snapshot)
        if self._plan_snapshot is not None:
            if digest == self.plan_digest:
                return
            raise PopulationError("a pending plan is write-once and cannot be rebound")
        self._plan_snapshot = snapshot
        self.plan_digest = digest


def _json(value):
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False,
                          sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise PopulationError("value is not finite JSON") from error


def _digest(value):
    return hashlib.sha256(_json(value)).hexdigest()


def _proposal_digest(proposal):
    return _digest({"commands": proposal.commands, "start": proposal.start_cursor,
                    "end": proposal.end_cursor, "additions": proposal.additions,
                    "usage": [[*key, value] for key, value in sorted(proposal.usage.items())],
                    "returning": proposal.returning,
                    "provider_buffers_after": proposal.provider_buffers_after,
                    "provider_cursors_after": proposal.provider_cursors_after})


def _int(value, label, *, minimum=0):
    if type(value) is not int or value < minimum:
        raise PopulationError(f"{label} must be an integer >= {minimum}")
    return value


def _validate_plan(proposal, plan, model, target=None):
    try:
        operation_client._plan(plan)
    except (operation_client.ClientError, KeyError, TypeError) as error:
        raise PopulationError("saved client plan is malformed") from error
    if model is not None and plan["request"]["model"] != model:
        raise PopulationError("saved plan request does not match prepared model")
    if target is not None and plan["target"] != target:
        raise PopulationError("saved plan target differs from the population job's committed target")
    if (plan["request"]["commands"] != proposal.commands
            or plan["request"]["returning"] != proposal.returning):
        raise PopulationError("saved request content differs from proposal commands")


def prepare(catalog, counts, *, seed, existing=None, strategies=None, rules=None,
            provider=None, priorities=None, batch_size=1, clock=None,
            provider_batch_size=32, select_reference=None, reference_usage=None):
    """Compile a public developer catalog and initialize explicit generation state.

    ``existing`` maps public contract names to rows with explicit ``id`` and
    ``contract`` (``fields`` are optional). Supplied IDs provide references but
    do not fulfill quotas. Their counts are a lower-bound preflight only because
    the supplied space may not enumerate the whole database; server limits remain
    authoritative. A strategy has signature
    ``strategy(schema, seed, cursor, context) -> fields``; a rule has signature
    ``rule(fields, context, selected_references) -> fields``. An optional clock
    value or ``clock(cursor)`` callback is exposed as ``context['clock']``.
    ``select_reference(child, path, compatible_pools, usage, rng, context)`` can
    replace default uniform-per-record typed parent selection. Provider values
    are held in the explicit state buffer in batches independent of mutation
    ``batch_size``. ``compatible_pools`` and ``usage`` are read-only views; a
    selector may inspect pools at its own cost, while the default chooses a
    target by pool size then indexes one retained ID without a full-pool scan.
    The usage view contains committed choices only. Optional ``reference_usage``
    seeds only caller-known history.
    """
    if not isinstance(catalog, dict) or not isinstance(counts, dict):
        raise PopulationError("catalog and counts must be objects")
    if not (type(seed) is int or isinstance(seed, str)):
        raise PopulationError("seed must be an integer or string")
    if not isinstance(catalog.get("contracts"), list) or not isinstance(catalog.get("capabilities"), dict):
        raise PopulationError("a developer catalog with contracts and capabilities is required")
    limits = catalog["capabilities"].get("limits")
    if not isinstance(limits, dict) or type(limits.get("public_records")) is not int:
        raise PopulationError("catalog must publish the public_records limit")
    max_commands = limits.get("commands", 64)
    _int(max_commands, "commands limit", minimum=1)
    batch_size = _int(batch_size, "batch_size", minimum=1)
    if batch_size > max_commands or batch_size > 64:
        raise PopulationError("batch_size exceeds the model command limit")
    provider_batch_size = _int(provider_batch_size, "provider_batch_size", minimum=1)
    if provider_batch_size > 128:
        raise PopulationError("provider_batch_size exceeds the value provider limit of 128")
    contracts = {}
    validators = {}
    codes = set()
    for supplied_contract in catalog["contracts"]:
        if not isinstance(supplied_contract, dict) or supplied_contract.get("visibility") != "public":
            continue
        contract = deepcopy(supplied_contract)
        name, code, schema = contract.get("name"), contract.get("code"), contract.get("schema")
        if not isinstance(name, str) or not name or type(code) is not int or code in codes:
            raise PopulationError("public contracts require unique names and integer codes")
        if name in contracts or not isinstance(schema, dict):
            raise PopulationError(f"invalid or duplicate public contract {name!r}")
        try:
            validator_type = jsonschema.validators.validator_for(schema)
            validator_type.check_schema(schema)
            validator = validator_type(schema)
        except (jsonschema.SchemaError, jsonschema.exceptions.SchemaError, ValueError, TypeError) as error:
            raise PopulationError(f"invalid schema for {name}: {error}") from error
        contracts[name] = contract
        codes.add(code)
        validators[name] = validator
    if not contracts:
        raise PopulationError("catalog has no public contracts")
    for name, quota in counts.items():
        if name not in contracts:
            raise PopulationError(f"unknown or private contract in counts: {name}")
        _int(quota, f"count for {name}")
    quotas = {name: counts.get(name, 0) for name in contracts}
    if sum(quotas.values()) > limits["public_records"]:
        raise PopulationError("requested count exceeds the model public_records limit")
    per_contract = limits.get("per_contract", {})
    if not isinstance(per_contract, dict):
        raise PopulationError("per_contract limits must be an object")
    for name, quota in quotas.items():
        cap = per_contract.get(str(contracts[name]["code"]),
                               per_contract.get(contracts[name]["code"], per_contract.get(name)))
        if cap is not None and quota > _int(cap, f"per-contract limit for {name}"):
            raise PopulationError(f"requested count for {name} exceeds the per-contract limit")
    strategies = dict(strategies or {})
    rules = dict(rules or {})
    priorities = dict(priorities or {})
    for label, mapping in (("strategies", strategies), ("rules", rules), ("priorities", priorities)):
        if not isinstance(mapping, dict) or mapping.keys() - contracts.keys():
            raise PopulationError(f"{label} must use public contract names")
    if any(not callable(fn) for fn in strategies.values()) or any(not callable(fn) for fn in rules.values()):
        raise PopulationError("strategies and rules must be callable")
    for name, value in priorities.items():
        _int(value, f"priority for {name}")
    if provider is not None and not callable(provider):
        raise PopulationError("provider must be callable")
    if select_reference is not None and not callable(select_reference):
        raise PopulationError("select_reference must be callable")
    if clock is not None and not callable(clock):
        _json(clock)
    pools = {name: {} for name in contracts}
    pool_ids = {name: [] for name in contracts}
    identity_ids = set()
    existing_counts = {name: 0 for name in contracts}
    for name, rows in (existing or {}).items():
        if name not in contracts or not isinstance(rows, list):
            raise PopulationError(f"existing pool must name a public contract: {name}")
        for row in rows:
            if not isinstance(row, dict) or row.get("contract") != name:
                raise PopulationError("existing rows require an explicit compatible contract")
            identity, fields = row.get("id"), row.get("fields")
            try:
                if not isinstance(identity, str) or str(uuid.UUID(identity)) != identity:
                    raise ValueError()
            except (ValueError, AttributeError) as error:
                raise PopulationError("existing rows require canonical UUID IDs") from error
            if identity in identity_ids:
                raise PopulationError("existing rows require unique explicit IDs")
            if fields is not None and (not isinstance(fields, dict) or list(validators[name].iter_errors(fields))):
                raise PopulationError(f"existing row {identity} does not match {name} schema")
            pools[name][identity] = {"id": identity, "contract": name, "fields": deepcopy(fields)}
            pool_ids[name].append(identity)
            identity_ids.add(identity)
            existing_counts[name] += 1
    if len(identity_ids) + sum(quotas.values()) > limits["public_records"]:
        raise PopulationError("supplied IDs plus requested count exceed public_records limit (lower-bound preflight)")
    for name, quota in quotas.items():
        cap = per_contract.get(str(contracts[name]["code"]),
                               per_contract.get(contracts[name]["code"], per_contract.get(name)))
        if cap is not None and existing_counts[name] + quota > _int(cap, f"per-contract limit for {name}"):
            raise PopulationError(f"supplied IDs plus requested count for {name} exceed the per-contract limit")
    if reference_usage is not None and not isinstance(reference_usage, Mapping):
        raise PopulationError("reference_usage must be a mapping")
    declared_usage = set()
    for child_name, child_contract in contracts.items():
        for ref in child_contract.get("references", []):
            for target_name, target_contract in contracts.items():
                if target_contract["code"] in ref.get("targets", []):
                    declared_usage.add((child_name, ref.get("field"), target_name))
    seeded_usage = {}
    for key, value in (reference_usage or {}).items():
        if (not isinstance(key, tuple) or len(key) != 4
                or (key[0], key[1], key[2]) not in declared_usage
                or not isinstance(key[3], str)
                or type(value) is not int or value < 0):
            raise PopulationError("reference_usage keys must be (child, path, parent, ID) with nonnegative counts")
        try:
            if str(uuid.UUID(key[3])) != key[3]:
                raise ValueError()
        except ValueError as error:
            raise PopulationError("reference_usage parent IDs must be canonical UUIDs") from error
        seeded_usage[key] = value
    return State(deepcopy(catalog), contracts, validators, quotas,
                 {name: 0 for name in contracts}, pools, seed, pool_ids=pool_ids,
                 identity_ids=identity_ids, provider_buffers={name: [] for name in contracts},
                 provider_cursors={name: 0 for name in contracts}, provider=provider,
                 strategies=strategies, rules=rules, priorities=priorities,
                 batch_size=batch_size, clock=clock, provider_batch_size=provider_batch_size,
                 select_reference=select_reference, reference_usage=seeded_usage)


def _path_tokens(path):
    if not isinstance(path, str) or not path:
        raise PopulationError("reference path must be a nonempty string")
    if path.startswith("/"):
        parts = path[1:].split("/")
        if any(not part for part in parts):
            raise PopulationError(f"invalid JSON-pointer reference path {path!r}")
        tokens = [int(part) if part.isdigit() else part for part in parts]
        return [token.replace("~1", "/").replace("~0", "~") if isinstance(token, str) else token
                for token in tokens]
    tokens, cursor = [], 0
    for match in re.finditer(r"(?:^|\.)([^.\[\]]+)|\[(\d*)\]", path):
        if match.start() != cursor:
            raise PopulationError(f"invalid declared reference path {path!r}")
        name, array_index = match.groups()
        if name is not None:
            tokens.append(name)
        elif array_index == "":
            tokens.append("*")
        else:
            tokens.append(int(array_index))
        cursor = match.end()
    if cursor != len(path) or not tokens:
        raise PopulationError(f"invalid declared reference path {path!r}")
    return tokens


def _set_path(value, path, replacement):
    """Set declared dotted, JSON-pointer, wildcard or concrete array paths."""
    tokens = _path_tokens(path)
    def visit(node, index):
        if index == len(tokens):
            return replacement
        token = tokens[index]
        if token in ("*", "-"):
            if not isinstance(node, list):
                raise PopulationError(f"reference path {path!r} expects an array")
            return [visit(item, index + 1) for item in node]
        if isinstance(node, dict) and isinstance(token, str):
            if token not in node:
                node[token] = [] if index + 1 < len(tokens) and type(tokens[index + 1]) is int else {}
            node[token] = visit(node[token], index + 1)
            return node
        if isinstance(node, list):
            if isinstance(token, str) and token.isdigit():
                token = int(token)
            if type(token) is not int:
                raise PopulationError(f"reference path {path!r} expects an array index")
            if token < 0 or token > len(node):
                raise PopulationError(f"reference path {path!r} would create an array gap")
            if token == len(node):
                node.append(visit(None, index + 1))
            else:
                node[token] = visit(node[token], index + 1)
            return node
        raise PopulationError(f"reference path {path!r} has an incompatible generated shape")
    return visit(value, 0)


def _path_values(value, path):
    """Read a declared reference path, expanding explicit [] array segments."""
    tokens = _path_tokens(path)
    def visit(node, index):
        if index == len(tokens):
            return [node]
        token = tokens[index]
        if token in ("*", "-"):
            if not isinstance(node, list):
                raise PopulationError(f"reference path {path!r} expects an array")
            return [item for child in node for item in visit(child, index + 1)]
        if isinstance(node, dict) and isinstance(token, str):
            return visit(node[token], index + 1) if token in node else []
        if isinstance(node, list):
            if isinstance(token, str) and token.isdigit():
                token = int(token)
            if type(token) is int and 0 <= token < len(node):
                return visit(node[token], index + 1)
        return []
    return visit(value, 0)


def _remaining(state, name):
    return state.quotas[name] - state.accepted[name]


def propose(state, fresh_context, *, max_commands=None):
    """Author one bounded proposal from a mapping or parent-aware context callback.

    A callback has signature ``fresh_context(contract_name, selected_references,
    proposal_cursor) -> mapping``. It is called per row after typed references
    are selected and before that row's rule; value strategies run earlier and
    therefore receive empty context (plus an explicitly configured clock).
    """
    if not isinstance(state, State):
        raise PopulationError("prepare must produce the caller-owned state")
    if state.pending is not None:
        raise PopulationError("a proposal is already pending; accept or reject it first")
    context_callback = fresh_context if callable(fresh_context) else None
    context = None if context_callback else deepcopy(dict(fresh_context)) if isinstance(fresh_context, Mapping) else None
    if context_callback is None and context is None:
        raise PopulationError("fresh_context must be an explicit mapping or caller callback (missing is not zero)")
    if state.clock is not None and context_callback is None and "clock" in context:
        raise PopulationError("clock must come from the explicit clock setting, not both inputs")
    batch_size = state.batch_size if max_commands is None else _int(max_commands, "max_commands", minimum=1)
    if batch_size > state.batch_size:
        raise PopulationError("max_commands cannot exceed the prepared batch_size")
    eligible = {}
    for name, contract in state.contracts.items():
        remaining = _remaining(state, name)
        weight = remaining * state.priorities.get(name, 1)
        refs_ok = True
        for ref in contract.get("references", []):
            if ref.get("optional"):
                continue
            targets = [t for t in ref.get("targets", []) if isinstance(t, int)]
            target_names = [n for n, c in state.contracts.items() if c["code"] in targets]
            if not any(state.pools[n] for n in target_names):
                refs_ok = False
                break
        if remaining > 0 and weight > 0 and refs_ok:
            eligible[name] = weight
    if not eligible:
        blocked = {name: _remaining(state, name) for name in state.contracts if _remaining(state, name)}
        raise PopulationError(f"no eligible quota; unavailable prerequisites or exhausted counts: {blocked}")
    prng = random.Random(f"{type(state.seed).__name__}:{state.seed}:{state.cursor}")
    selected = []
    remaining_slots = batch_size
    while remaining_slots and eligible:
        name = prng.choices(list(eligible), weights=list(eligible.values()), k=1)[0]
        selected.append(name)
        remaining_slots -= 1
        if _remaining(state, name) <= selected.count(name):
            del eligible[name]
    start = state.cursor
    clock_values = {}
    def clock_value(cursor):
        if state.clock is not None:
            if cursor not in clock_values:
                clock_values[cursor] = state.clock(cursor) if callable(state.clock) else deepcopy(state.clock)
            return deepcopy(clock_values[cursor])
        return None

    def context_for(cursor, contract_name=None, selected_references=None):
        if context_callback is not None and contract_name is not None:
            result = context_callback(contract_name, deepcopy(selected_references or {}), cursor)
            if not isinstance(result, Mapping):
                raise PopulationError("fresh_context callback must return a mapping")
            result = deepcopy(dict(result))
        elif context_callback is not None:
            # A context callback needs selected parent IDs, which do not exist
            # until after field generation and typed reference selection.
            result = {}
        else:
            result = deepcopy(context)
        current_clock = clock_value(cursor)
        if current_clock is not None:
            if "clock" in result:
                raise PopulationError("clock must come from the explicit clock setting, not both inputs")
            result["clock"] = current_clock
        return result
    seed_label = f"{type(state.seed).__name__}:{state.seed}"
    generated_ids = [str(uuid.uuid5(uuid.NAMESPACE_URL, f"rebase-population:{seed_label}:{start+i}"))
                     for i in range(len(selected))]
    if len(set(generated_ids)) != len(generated_ids) or set(generated_ids) & state.identity_ids:
        raise PopulationError("deterministic identity collision with an existing or proposed row")
    additions, commands, usage = [], [], {}
    generated = {}
    provider_buffers_after = deepcopy(state.provider_buffers)
    provider_cursors_after = dict(state.provider_cursors)
    # Providers receive one schema/count/seed call per contract batch.
    for name in dict.fromkeys(selected):
        count = selected.count(name)
        schema = deepcopy(state.contracts[name]["schema"])
        if name in state.strategies:
            positions = [i for i, selected_name in enumerate(selected) if selected_name == name]
            values = [state.strategies[name](deepcopy(schema), state.seed, start + i, context_for(start + i))
                      for i in positions]
        elif state.provider is not None:
            buffer = provider_buffers_after.setdefault(name, [])
            remaining_quota = _remaining(state, name) - len(buffer)
            while len(buffer) < count:
                request_count = min(state.provider_batch_size, remaining_quota)
                if request_count <= 0:
                    raise PopulationError(f"provider quota for {name} cannot cover the requested proposal")
                provider_cursor = provider_cursors_after.get(name, 0)
                seed_material = f"{type(state.seed).__name__}:{state.seed}:{name}:{provider_cursor}".encode()
                provider_seed = int.from_bytes(hashlib.sha256(seed_material).digest()[:4], "big")
                batch = state.provider(schema, request_count, provider_seed)
                if (not isinstance(batch, list) or len(batch) != request_count
                        or any(not isinstance(value, dict) for value in batch)):
                    raise PopulationError(f"provider for {name} must return exactly {request_count} object(s)")
                for value in batch:
                    _json(value)
                buffer.extend(deepcopy(batch))
                provider_cursors_after[name] = provider_cursor + request_count
                remaining_quota -= request_count
            values = [buffer.pop(0) for _ in range(count)]
        else:
            raise PopulationError(f"contract {name} needs an explicit strategy or value provider")
        if not isinstance(values, list) or len(values) != count or any(not isinstance(v, dict) for v in values):
            raise PopulationError(f"value source for {name} must return exactly {count} object(s)")
        generated[name] = iter(values)
    for offset, name in enumerate(selected):
        contract = state.contracts[name]
        fields = deepcopy(next(generated[name]))
        rowrefs = {}
        for ref_index, ref in enumerate(contract.get("references", [])):
            targets = [target for target, metadata in state.contracts.items()
                       if metadata["code"] in ref.get("targets", []) and state.pool_ids[target]]
            current_values = _path_values(fields, ref.get("field", ""))
            if ref.get("optional") and (not current_values or all(value is None for value in current_values)):
                continue
            if not targets:
                if ref.get("optional"):
                    continue
                raise PopulationError(f"missing required reference prerequisite for {name}.{ref.get('field')}")
            if state.select_reference is None:
                chosen_name = prng.choices(targets, weights=[len(state.pool_ids[target]) for target in targets], k=1)[0]
                chosen_id = state.pool_ids[chosen_name][prng.randrange(len(state.pool_ids[chosen_name]))]
            else:
                compatible_pools = MappingProxyType({
                    target: MappingProxyType(state.pools[target]) for target in targets})
                choice = state.select_reference(name, ref["field"], compatible_pools,
                    MappingProxyType(state.reference_usage), prng, context_for(start + offset))
                if not isinstance(choice, tuple) or len(choice) != 2:
                    raise PopulationError("select_reference must return (target_contract, ID)")
                chosen_name, chosen_id = choice
                if chosen_name not in compatible_pools or chosen_id not in compatible_pools[chosen_name]:
                    raise PopulationError("select_reference chose an ID outside the declared compatible pools")
            _set_path(fields, ref["field"], chosen_id)
            rowrefs[ref["field"]] = chosen_id
        if name in state.rules:
            row_context = context_for(start + offset, name, rowrefs)
        else:
            row_context = context_for(start + offset, name, rowrefs) if context_callback is not None else context_for(start + offset)
        if name in state.rules:
            fields = state.rules[name](deepcopy(fields), row_context, deepcopy(rowrefs))
        if not isinstance(fields, dict) or list(state.validators[name].iter_errors(fields)):
            raise PopulationError(f"final generated fields do not match {name} schema")
        for ref in contract.get("references", []):
            targets = {target for target, metadata in state.contracts.items()
                       if metadata["code"] in ref.get("targets", [])}
            reference_values = _path_values(fields, ref.get("field", ""))
            if not reference_values and not ref.get("optional") and "[]" not in ref.get("field", ""):
                raise PopulationError(f"required reference {name}.{ref.get('field')} is absent")
            for identity in reference_values:
                if identity is None and ref.get("optional"):
                    continue
                target_name = (next((target for target in targets if isinstance(identity, str)
                                     and identity in state.pools[target]), None))
                if target_name is None:
                    raise PopulationError(f"final reference {name}.{ref.get('field')} is unavailable or has the wrong type")
                key = (name, ref["field"], target_name, identity)
                usage[key] = usage.get(key, 0) + 1
        identity = generated_ids[offset]
        command = {"op": "create", "id": identity, "contract": contract["code"], "fields": deepcopy(fields)}
        commands.append(command)
        additions.append({"id": identity, "contract": name, "fields": deepcopy(fields), "references": rowrefs})
    try:
        serialized = _json(commands)
    except PopulationError:
        raise
    if len(commands) > 64 or len(serialized) > 65536:
        raise PopulationError("proposal exceeds command or request byte cap")
    proposal = Proposal(deepcopy(commands), "", start, start + len(commands),
                        deepcopy(additions), deepcopy(usage), [item["id"] for item in additions[:32]],
                        provider_buffers_after, provider_cursors_after)
    proposal.digest = _proposal_digest(proposal)
    state.pending = Pending(proposal, expected_target=deepcopy(state.target),
                            expected_model=state.catalog.get("model"))
    return proposal


def _bound(state, proposal, plan):
    pending = state.pending
    if not isinstance(pending, Pending) or pending.proposal is not proposal:
        raise PopulationError("proposal is not the exact current pending proposal")
    if pending.proposal_digest != _proposal_digest(proposal) or proposal.digest != _proposal_digest(proposal):
        raise PopulationError("proposal commands changed after creation or binding")
    if pending.plan is None:
        raise PopulationError("bind the exact saved plan in Pending before execution")
    if pending.plan_digest != _digest(plan):
        raise PopulationError("saved plan changed after binding")
    _validate_plan(proposal, plan, state.catalog.get("model"), state.target)
    if pending.proposal_digest != proposal.digest:
        raise PopulationError("proposal and plan request binding differs")


def _advance_attempt(state, proposal):
    state.cursor = proposal.end_cursor
    state.provider_buffers = deepcopy(proposal.provider_buffers_after)
    state.provider_cursors = dict(proposal.provider_cursors_after)


def accept(state, proposal, plan, response):
    """Advance pools and quotas only for an exact committed records receipt."""
    _bound(state, proposal, plan)
    if (not isinstance(response, dict) or response.get("status") != "committed"
            or not isinstance(response.get("result"), dict)
            or response["result"].get("operation_id") != plan["request"]["operation_id"]):
        raise PopulationError("accept requires a committed receipt for the exact operation ID")
    receipt = response["result"]
    if not isinstance(receipt.get("revision"), str) or not isinstance(receipt.get("records"), list):
        raise PopulationError("committed receipt requires revision and records fields")
    returned = receipt["records"]
    if any(not isinstance(item, dict) or not isinstance(item.get("id"), str)
           or ("record" in item and item["record"] is not None and not isinstance(item["record"], dict))
           for item in returned):
        raise PopulationError("receipt records require IDs and optional object/null projections")
    returned_ids = [item["id"] for item in returned]
    if returned_ids != proposal.returning or returned_ids != plan["request"]["returning"]:
        raise PopulationError("receipt returned IDs differ from the exact requested ID sequence")
    for item in proposal.additions:
        name = item["contract"] if item["contract"] in state.contracts else next(
            n for n, c in state.contracts.items() if c["code"] == item["contract"])
        state.pools[name][item["id"]] = {k: deepcopy(item[k]) for k in ("id", "contract", "fields")}
        state.pool_ids[name].append(item["id"])
        state.identity_ids.add(item["id"])
        state.accepted[name] += 1
    for key, count in proposal.usage.items():
        state.reference_usage[key] = state.reference_usage.get(key, 0) + count
    _advance_attempt(state, proposal)
    state.last_receipt = plan["request"]["operation_id"]
    if state.target is None:
        state.target = deepcopy(plan["target"])
    state.pending = None
    return state


_DEFINITE_REJECTIONS = {"invalid_input", "forbidden", "not_found", "unavailable_reference",
                        "already_exists", "stale_version", "transaction_conflict",
                        "transaction_aborted", "transaction_limit", "model_mismatch",
                        "invariant", "feedback", "inexact", "operation_conflict", "work_limit",
                        "state_limit", "receipt_limit", "request_limit"}


def reject(state, proposal, plan=None, outcome=None):
    """Discard only a definite no-commit result; unknown outcomes retain pending."""
    if plan is None and outcome is None:
        pending = state.pending
        if (not isinstance(pending, Pending) or pending.proposal is not proposal
                or pending.plan is not None
                or pending.proposal_digest != _proposal_digest(proposal)
                or proposal.digest != _proposal_digest(proposal)):
            raise PopulationError("only the exact unbound pending proposal can be cancelled")
        _advance_attempt(state, proposal)
        state.pending = None
        return state
    if plan is None or outcome is None:
        raise PopulationError("bound rejection requires the exact plan and definite server outcome")
    _bound(state, proposal, plan)
    kind = getattr(outcome, "kind", None)
    if kind in {"outcome_unknown", "operation_expired", "not_observed"}:
        raise PopulationError("uncertain outcome retains the exact pending proposal and plan")
    definite_rpc_error = (isinstance(outcome, operation_client.RpcError)
                          and getattr(outcome, "http_status", None) == 200
                          and kind in _DEFINITE_REJECTIONS)
    if not definite_rpc_error:
        raise PopulationError("only a definite server no-commit outcome can reject a proposal")
    _advance_attempt(state, proposal)
    state.pending = None
    return state
