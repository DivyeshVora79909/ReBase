#!/usr/bin/env python3
"""Semantic controls for the explicit population state machine."""

import copy
import unittest
import uuid

import population
import client


def contract(name, code, item_schema, references=()):
    return {"name": name, "code": code, "visibility": "public", "schema": item_schema,
            "references": list(references)}


def schema(properties, required=()):
    return {"$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object", "properties": properties, "required": list(required),
            "additionalProperties": False}


BASE = contract("Base", 101, schema({"unit": {"type": "integer", "minimum": 1}}, ["unit"]))
OTHER = contract("Other", 102, schema({"unit": {"type": "integer", "minimum": 1}}, ["unit"]))
CHILD = contract("Child", 205, schema({
    "parent": {"type": "string"},
    "metadata": {"type": "object", "properties": {"owner": {"type": "string"}},
                 "required": ["owner"], "additionalProperties": False},
    "items": {"type": "array", "items": {"type": "object", "properties": {"parent": {"type": "string"}},
                                         "required": ["parent"], "additionalProperties": False}},
    "label": {"type": "string"}, "optional": {"type": ["string", "null"]},
}, ["parent", "metadata", "items", "label", "optional"]), [
    {"field": "parent", "optional": False, "targets": [101]},
    {"field": "metadata.owner", "optional": False, "targets": [101, 102]},
    {"field": "items[].parent", "optional": False, "targets": [101]},
    {"field": "optional", "optional": True, "targets": [103]},
])


def catalog(contracts=(BASE, OTHER, CHILD), *, limit=100, commands=64):
    return {"model": "test-model", "contracts": copy.deepcopy(list(contracts)),
            "capabilities": {"limits": {"public_records": limit, "commands": commands,
                                         "per_contract": {}}}}


def base_row(identity, name="Base"):
    return {"id": identity, "contract": name, "fields": {"unit": 7}}


def strategy(name):
    def produce(_schema, seed, cursor, _context):
        if name in ("Base", "Other"):
            return {"unit": 8}
        return {"parent": "pending", "metadata": {"owner": "pending"},
                "items": [{"parent": "pending"}], "label": f"{seed}-{cursor}", "optional": None}
    return produce


def source_map():
    return {name: strategy(name) for name in ("Base", "Other", "Child")}


def bind(state, proposal, *, op=None, target=None, attach=True):
    op = op or str(uuid.uuid4())
    target = target or state.pending.expected_target or state.target or {
        "url": "http://example.test/rpc", "model": "test-model",
        "store": str(uuid.uuid4()), "tenant": str(uuid.uuid4()), "actor": str(uuid.uuid4())}
    plan = {"format": "rebase-operation-plan-1",
            "target": target,
            "request": {"model": "test-model", "context": "context-v1", "operation_id": op,
                        "commands": copy.deepcopy(proposal.commands), "returning": list(proposal.returning)}}
    if attach:
        state.pending.plan = plan
    return plan


def committed(plan):
    # client.execute returns the direct local.rs wire result.
    return {"status": "committed", "replayed": False, "result": {
        "operation_id": plan["request"]["operation_id"], "revision": str(uuid.uuid4()),
        "records": [{"id": identity, "record": None} for identity in plan["request"]["returning"]]}}


class PopulationControls(unittest.TestCase):
    def test_wrong_intent_and_model_cannot_be_bound_before_submission(self):
        state = population.prepare(catalog(), {"Base": 1}, seed=12,
                                   strategies={"Base": strategy("Base")})
        proposal = population.propose(state, {})
        original = bind(state, proposal, attach=False)
        for field in ("commands", "model"):
            changed = copy.deepcopy(original)
            if field == "commands":
                changed["request"]["commands"][0]["fields"]["unit"] += 1
            else:
                changed["request"]["model"] = changed["target"]["model"] = "other-model"
            with self.subTest(field=field), self.assertRaises(population.PopulationError):
                state.pending.plan = changed
            self.assertIsNone(state.pending.plan)
            self.assertEqual(state.accepted["Base"], 0)
        original_digest = proposal.digest
        proposal.digest = "tampered-marker"
        with self.assertRaises(population.PopulationError):
            state.pending.plan = original
        self.assertIsNone(state.pending.plan)
        proposal.digest = original_digest
        state.pending.plan = original
        self.assertEqual(state.pending.plan, original)

    def test_same_seed_and_settings_replay_exact_commands_but_states_are_independent(self):
        kwargs = dict(counts={"Base": 3}, seed=44, strategies={"Base": strategy("Base")}, batch_size=2)
        left, right = population.prepare(catalog(), **kwargs), population.prepare(catalog(), **kwargs)
        a = population.propose(left, {"root": 1})
        b = population.propose(right, {"root": 1})
        self.assertEqual(a.commands, b.commands)
        self.assertEqual(a.digest, b.digest)
        plan = bind(left, a)
        population.accept(left, a, plan, committed(plan))
        self.assertEqual(left.accepted["Base"], 2)
        self.assertEqual(right.accepted["Base"], 0)
        self.assertEqual(len(right.pools["Base"]), 0)

    def test_prepare_detaches_catalog_metadata_and_compiled_schema(self):
        source = catalog()
        state = population.prepare(source, {"Base": 1}, seed=12,
            strategies={"Base": strategy("Base")})
        source["contracts"][0]["code"] = 999
        source["contracts"][0]["schema"]["properties"]["unit"]["minimum"] = 99
        proposal = population.propose(state, {})
        self.assertEqual(proposal.commands[0]["contract"], 101)
        self.assertEqual(state.catalog["contracts"][0]["code"], 101)
        self.assertEqual(state.contracts["Base"]["schema"]["properties"]["unit"]["minimum"], 1)

    def test_explicit_clock_is_supplied_per_attempt_cursor(self):
        seen = []
        state = population.prepare(catalog(), {"Base": 2}, seed=44, batch_size=2,
            clock=lambda cursor: 1000 + cursor,
            strategies={"Base": lambda _schema, _seed, cursor, context:
                        (seen.append((cursor, context["clock"])) or {"unit": context["clock"]})})
        proposal = population.propose(state, {"fresh": True})
        self.assertEqual(seen, [(0, 1000), (1, 1001)])
        self.assertEqual([item["fields"]["unit"] for item in proposal.commands], [1000, 1001])

    def test_typed_supplied_pools_polymorphic_nested_array_and_optional_references(self):
        a, b = str(uuid.uuid4()), str(uuid.uuid4())
        state = population.prepare(catalog(), {"Child": 1}, seed=4,
            existing={"Base": [base_row(a)], "Other": [base_row(b, "Other")]},
            strategies={"Child": strategy("Child")})
        proposal = population.propose(state, {"root": "fresh"})
        fields = proposal.commands[0]["fields"]
        self.assertEqual(fields["parent"], a)
        self.assertIn(fields["metadata"]["owner"], {a, b})
        self.assertEqual(fields["items"][0]["parent"], a)
        self.assertIsNone(fields["optional"])
        self.assertEqual(sum(proposal.usage.values()), 3)
        self.assertEqual({key[1] for key in proposal.usage},
                         {"parent", "metadata.owner", "items[].parent"})

    def test_proposal_selects_from_retained_pool_ids_without_scanning_rows(self):
        class NoPoolScan(dict):
            def values(self):
                raise AssertionError("proposal rebuilt a parent-row list")
        identities = [str(uuid.uuid4()) for _ in range(3000)]
        state = population.prepare(catalog(limit=4000), {"Child": 1}, seed=7,
            existing={"Base": [base_row(identity) for identity in identities]},
            strategies={"Child": strategy("Child")})
        state.pools["Base"] = NoPoolScan(state.pools["Base"])
        proposal = population.propose(state, {})
        self.assertIn(proposal.commands[0]["fields"]["parent"], set(identities))
        self.assertEqual(state.pool_ids["Base"], identities)

    def test_required_cycle_stalls_until_supplied_anchor(self):
        a_schema = schema({"b": {"type": "string"}}, ["b"])
        b_schema = schema({"a": {"type": "string"}}, ["a"])
        a = contract("A", 1, a_schema, [{"field": "b", "optional": False, "targets": [2]}])
        b = contract("B", 2, b_schema, [{"field": "a", "optional": False, "targets": [1]}])
        strategies = {"A": lambda *_: {"b": "placeholder"}, "B": lambda *_: {"a": "placeholder"}}
        state = population.prepare(catalog((a, b)), {"A": 1, "B": 1}, seed=1, strategies=strategies)
        with self.assertRaisesRegex(population.PopulationError, "unavailable prerequisites"):
            population.propose(state, {})
        anchor = str(uuid.uuid4())
        state = population.prepare(catalog((a, b)), {"A": 1}, seed=1,
            existing={"B": [{"id": anchor, "contract": "B", "fields": {"a": anchor}}]}, strategies=strategies)
        proposal = population.propose(state, {})
        self.assertEqual(proposal.commands[0]["fields"]["b"], anchor)

    def test_pending_binding_receipt_exactness_and_mutation_digest(self):
        state = population.prepare(catalog(), {"Base": 1}, seed=1, strategies={"Base": strategy("Base")})
        proposal = population.propose(state, {})
        plan = bind(state, proposal)
        bad = committed(plan)
        bad["result"]["operation_id"] = str(uuid.uuid4())
        with self.assertRaisesRegex(population.PopulationError, "exact operation ID"):
            population.accept(state, proposal, plan, bad)
        self.assertEqual(state.accepted["Base"], 0)
        proposal.commands[0]["fields"]["unit"] = 9
        with self.assertRaisesRegex(population.PopulationError, "changed"):
            population.accept(state, proposal, plan, committed(plan))
        self.assertIsNotNone(state.pending)

    def test_accept_needs_records_receipt_and_plan_digest(self):
        state = population.prepare(catalog(), {"Base": 1}, seed=2, strategies={"Base": strategy("Base")})
        proposal = population.propose(state, {})
        plan = bind(state, proposal)
        malformed = committed(plan)
        malformed["result"]["operation_id"] = str(uuid.uuid4())
        with self.assertRaises(population.PopulationError):
            population.accept(state, proposal, plan, malformed)
        bad_plan = copy.deepcopy(plan)
        bad_plan["request"]["commands"][0]["fields"]["unit"] = 99
        with self.assertRaisesRegex(population.PopulationError, "changed after binding"):
            population.accept(state, proposal, bad_plan, committed(bad_plan))

    def test_committed_receipt_must_match_requested_returning_id_sequence(self):
        state = population.prepare(catalog(), {"Base": 1}, seed=2, strategies={"Base": strategy("Base")})
        proposal = population.propose(state, {})
        plan = bind(state, proposal)
        wrong_ids = committed(plan)
        wrong_ids["result"]["records"][0]["id"] = str(uuid.uuid4())
        with self.assertRaisesRegex(population.PopulationError, "exact requested ID sequence"):
            population.accept(state, proposal, plan, wrong_ids)
        self.assertEqual(state.accepted["Base"], 0)

    def test_supplied_typed_ids_need_no_full_rows(self):
        anchor = str(uuid.uuid4())
        state = population.prepare(catalog(), {"Child": 1}, seed=3,
            existing={"Base": [{"id": anchor, "contract": "Base"}]},
            strategies={"Child": strategy("Child")})
        proposal = population.propose(state, {})
        self.assertEqual(proposal.commands[0]["fields"]["parent"], anchor)

    def test_context_callback_runs_after_parent_selection_for_each_row(self):
        parent = str(uuid.uuid4())
        observed = []
        def fresh(contract_name, selected_references, cursor):
            observed.append((contract_name, selected_references["parent"], cursor))
            return {"parent": selected_references["parent"]}
        state = population.prepare(catalog(), {"Child": 1}, seed=9,
            existing={"Base": [{"id": parent, "contract": "Base"}]},
            strategies={"Child": strategy("Child")},
            rules={"Child": lambda fields, context, _refs: {**fields, "label": context["parent"]}})
        proposal = population.propose(state, fresh)
        self.assertEqual(observed, [("Child", parent, 0)])
        self.assertEqual(proposal.commands[0]["fields"]["label"], parent)

    def test_supplied_pool_ids_must_be_canonical_uuid_strings(self):
        for identity in ("not-an-id", "550E8400-E29B-41D4-A716-446655440000",
                         "550e8400e29b41d4a716446655440000"):
            with self.subTest(identity=identity):
                with self.assertRaisesRegex(population.PopulationError, "canonical UUID"):
                    population.prepare(catalog(), {}, seed=1,
                        existing={"Base": [{"id": identity, "contract": "Base"}]})

    def test_basis_indexed_refs_create_required_first_entry_and_omit_optional_refs(self):
        account = contract("Account", 11, schema({"label": {"type": "string"}}, ["label"]))
        basis = contract("Basis", 22, schema({
            "sources": {"type": "array", "minItems": 1, "items": {"type": "string"}},
            "account": {"type": "string"},
            "feedback": {"type": "object", "properties": {"account": {"type": "string"}},
                         "additionalProperties": False},
        }, ["sources", "account"]), [
            {"field": "sources[0]", "optional": False, "targets": [11]},
            {"field": "sources[1]", "optional": True, "targets": [11]},
            {"field": "account", "optional": False, "targets": [11]},
            {"field": "feedback.account", "optional": True, "targets": [11]},
        ])
        identity = str(uuid.uuid4())
        state = population.prepare(catalog((account, basis)), {"Basis": 1}, seed=6,
            existing={"Account": [{"id": identity, "contract": "Account"}]},
            strategies={"Basis": lambda *_: {"sources": []}})
        proposal = population.propose(state, {})
        fields = proposal.commands[0]["fields"]
        self.assertEqual(fields["sources"], [identity])
        self.assertEqual(fields["account"], identity)
        self.assertNotIn("feedback", fields)

    def test_provider_batch_buffer_advances_only_after_decision(self):
        calls = []
        def provider(_schema, count, seed):
            calls.append((count, seed))
            return [{"unit": index + 1} for index in range(count)]
        state = population.prepare(catalog(), {"Base": 40}, seed=17,
            provider=provider, provider_batch_size=32, batch_size=1)
        for index in range(10):
            proposal = population.propose(state, {})
            if index == 0:
                self.assertEqual(state.provider_buffers["Base"], [])
                self.assertEqual(state.provider_cursors["Base"], 0)
            plan = bind(state, proposal)
            population.accept(state, proposal, plan, committed(plan))
        self.assertEqual([count for count, _ in calls], [32])
        self.assertEqual(state.provider_cursors["Base"], 32)
        self.assertEqual(len(state.provider_buffers["Base"]), 22)
        self.assertEqual(state.accepted["Base"], 10)

    def test_provider_batches_replay_across_interleaved_states(self):
        calls = []
        def provider(_schema, count, seed):
            calls.append((count, seed))
            return [{"unit": seed + index + 1} for index in range(count)]
        kwargs = dict(counts={"Base": 40}, seed=31, provider=provider,
                      provider_batch_size=32, batch_size=1)
        left, right = population.prepare(catalog(), **kwargs), population.prepare(catalog(), **kwargs)
        for _ in range(3):
            left_proposal = population.propose(left, {})
            right_proposal = population.propose(right, {})
            self.assertEqual(left_proposal.commands, right_proposal.commands)
            left_plan = bind(left, left_proposal)
            right_plan = bind(right, right_proposal)
            population.accept(left, left_proposal, left_plan, committed(left_plan))
            population.accept(right, right_proposal, right_plan, committed(right_plan))
        self.assertEqual([count for count, _ in calls], [32, 32])

    def test_provider_batch_refills_twice_for_maximum_command_batch(self):
        calls = []
        def provider(_schema, count, seed):
            calls.append((count, seed))
            return [{"unit": 3} for _ in range(count)]
        state = population.prepare(catalog(commands=64), {"Base": 64}, seed=40,
            provider=provider, batch_size=64, provider_batch_size=32)
        proposal = population.propose(state, {})
        self.assertEqual(len(proposal.commands), 64)
        self.assertEqual([count for count, _ in calls], [32, 32])
        self.assertEqual(state.provider_buffers["Base"], [])
        self.assertEqual(state.provider_cursors["Base"], 0)

    def test_provider_can_leave_required_reference_for_declared_overlay(self):
        parent = str(uuid.uuid4())
        child = contract("Child", 205, schema({"parent": {"type": "string"}}, ["parent"]),
            [{"field": "parent", "optional": False, "targets": [101]}])
        state = population.prepare(catalog((BASE, child)), {"Child": 1}, seed=41,
            existing={"Base": [{"id": parent, "contract": "Base"}]},
            provider=lambda _schema, count, _seed: [{} for _ in range(count)])
        proposal = population.propose(state, {})
        self.assertEqual(proposal.commands[0]["fields"]["parent"], parent)

    def test_definite_rejection_advances_provider_buffer_without_accepting_rows(self):
        calls = []
        def provider(_schema, count, seed):
            calls.append((count, seed))
            return [{"unit": index + 1} for index in range(count)]
        state = population.prepare(catalog(), {"Base": 3}, seed=18,
            provider=provider, provider_batch_size=3)
        proposal = population.propose(state, {})
        plan = bind(state, proposal)
        self.assertEqual(state.provider_buffers["Base"], [])
        population.reject(state, proposal, plan,
            client.RpcError("invalid_input", "definite no commit", http_status=200))
        self.assertEqual(state.accepted["Base"], 0)
        self.assertEqual(state.cursor, 1)
        self.assertEqual(state.provider_cursors["Base"], 3)
        self.assertEqual(len(state.provider_buffers["Base"]), 2)
        self.assertEqual(len(calls), 1)
        next_proposal = population.propose(state, {})
        self.assertEqual(len(calls), 1)
        self.assertEqual(next_proposal.commands[0]["fields"]["unit"], 2)

    def test_unbound_reject_cancels_exact_proposal_and_advances_only_attempt_state(self):
        calls = []
        def provider(_schema, count, seed):
            calls.append((count, seed))
            return [{"unit": index + 1} for index in range(count)]
        state = population.prepare(catalog(), {"Base": 5}, seed=18,
            provider=provider, provider_batch_size=4)
        proposal = population.propose(state, {})
        self.assertIsNone(state.pending.plan)
        population.reject(state, proposal)
        self.assertEqual(state.accepted["Base"], 0)
        self.assertEqual(state.pools["Base"], {})
        self.assertEqual(state.cursor, 1)
        self.assertEqual(state.provider_cursors["Base"], 4)
        self.assertEqual(len(state.provider_buffers["Base"]), 3)
        next_proposal = population.propose(state, {})
        self.assertEqual(len(calls), 1)
        self.assertEqual(next_proposal.commands[0]["fields"]["unit"], 2)

    def test_unbound_cancel_requires_exact_unchanged_pending_proposal(self):
        state = population.prepare(catalog(), {"Base": 1}, seed=1,
            strategies={"Base": strategy("Base")})
        proposal = population.propose(state, {})
        proposal.commands[0]["fields"]["unit"] = 99
        with self.assertRaisesRegex(population.PopulationError, "exact unbound"):
            population.reject(state, proposal)
        self.assertIsNotNone(state.pending)

    def test_inexact_is_a_definite_no_commit_rejection(self):
        state = population.prepare(catalog(), {"Base": 1}, seed=1,
            strategies={"Base": strategy("Base")})
        proposal = population.propose(state, {})
        plan = bind(state, proposal)
        population.reject(state, proposal, plan,
            client.RpcError("inexact", "exact rational check failed", http_status=200))
        self.assertIsNone(state.pending)
        self.assertEqual(state.accepted["Base"], 0)

    def test_provider_failure_leaves_explicit_buffer_and_cursor_unchanged(self):
        state = population.prepare(catalog(), {"Base": 3}, seed=8,
            provider=lambda _schema, count, _seed: [{"unit": 1}] * (count - 1))
        with self.assertRaisesRegex(population.PopulationError, "exactly"):
            population.propose(state, {})
        self.assertEqual(state.provider_buffers["Base"], [])
        self.assertEqual(state.provider_cursors["Base"], 0)
        self.assertIsNone(state.pending)

    def test_select_reference_can_use_committed_per_parent_usage(self):
        parent_a, parent_b = str(uuid.uuid4()), str(uuid.uuid4())
        child = contract("Child", 205, schema({"parent": {"type": "string"}}, ["parent"]),
            [{"field": "parent", "optional": False, "targets": [101]}])
        chooser_calls = []
        def rich_get_richer(child_name, path, pools, usage, rng, _context):
            ids = list(pools["Base"])
            richness = {identity: usage.get((child_name, path, "Base", identity), 0) for identity in ids}
            richest = max(richness.values())
            selected = rng.choice([identity for identity in ids if richness[identity] == richest])
            chooser_calls.append((selected, dict(richness)))
            return "Base", selected
        state = population.prepare(catalog((BASE, child)), {"Child": 2}, seed=23,
            existing={"Base": [base_row(parent_a), base_row(parent_b)]},
            strategies={"Child": lambda *_: {"parent": "placeholder"}},
            select_reference=rich_get_richer)
        first = population.propose(state, {})
        first_id = first.commands[0]["fields"]["parent"]
        self.assertEqual(state.reference_usage, {})
        first_plan = bind(state, first)
        population.accept(state, first, first_plan, committed(first_plan))
        key = ("Child", "parent", "Base", first_id)
        self.assertEqual(state.reference_usage, {key: 1})
        second = population.propose(state, {})
        self.assertEqual(second.commands[0]["fields"]["parent"], first_id)
        self.assertEqual(chooser_calls[1][1][first_id], 1)
        second_plan = bind(state, second)
        population.accept(state, second, second_plan, committed(second_plan))
        self.assertEqual(state.reference_usage[key], 2)

    def test_supplied_ids_are_included_in_lower_bound_quota_caps(self):
        identity = str(uuid.uuid4())
        with self.assertRaisesRegex(population.PopulationError, "lower-bound preflight"):
            population.prepare(catalog(limit=2), {"Base": 2}, seed=1,
                existing={"Base": [base_row(identity)]})
        limited = catalog()
        limited["capabilities"]["limits"]["per_contract"] = {"101": 1}
        with self.assertRaisesRegex(population.PopulationError, "per-contract limit"):
            population.prepare(limited, {"Base": 1}, seed=1,
                existing={"Base": [base_row(identity)]})

    def test_pending_plan_binding_is_write_once_and_defensive(self):
        state = population.prepare(catalog(), {"Base": 1}, seed=1,
            strategies={"Base": strategy("Base")})
        proposal = population.propose(state, {})
        plan = bind(state, proposal)
        exposed = state.pending.plan
        exposed["request"]["context"] = "changed"
        self.assertEqual(state.pending.plan, plan)
        with self.assertRaisesRegex(population.PopulationError, "write-once"):
            state.pending.plan = {**plan, "request": {**plan["request"], "context": "new"}}
        with self.assertRaisesRegex(population.PopulationError, "cannot be cleared"):
            state.pending.plan = None
        self.assertEqual(state.pending.plan, plan)

    def test_definite_rejection_advances_attempt_only_and_unknown_retains(self):
        state = population.prepare(catalog(), {"Base": 2}, seed=2, strategies={"Base": strategy("Base")})
        first = population.propose(state, {})
        plan = bind(state, first)
        with self.assertRaisesRegex(population.PopulationError, "uncertain"):
            population.reject(state, first, plan, client.RpcError("operation_expired", "expired", http_status=200))
        self.assertEqual(state.pending.plan, plan)
        self.assertEqual(state.accepted["Base"], 0)
        population.reject(state, first, plan, client.RpcError("invalid_input", "rejected", http_status=200))
        self.assertEqual(state.accepted["Base"], 0)
        self.assertEqual(state.cursor, 1)
        second = population.propose(state, {})
        self.assertNotEqual(first.commands[0]["id"], second.commands[0]["id"])

    def test_schema_provider_and_strategy_failures_do_not_mutate_accepted_state(self):
        malformed = catalog()
        malformed["contracts"][0]["schema"] = {"type": "banana"}
        with self.assertRaises(population.PopulationError):
            population.prepare(malformed, {}, seed=1)
        state = population.prepare(catalog(), {"Base": 1}, seed=1,
            provider=lambda _schema, _count, _seed: [{"unit": "bad"}])
        with self.assertRaisesRegex(population.PopulationError, "final generated fields"):
            population.propose(state, {})
        self.assertEqual(state.accepted["Base"], 0)
        state = population.prepare(catalog(), {"Base": 1}, seed=1, provider=lambda *_: [])
        with self.assertRaisesRegex(population.PopulationError, "exactly 1"):
            population.propose(state, {})

    def test_identity_collision_missing_context_unknown_contract_and_quotas(self):
        seed = 11
        generated_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"rebase-population:int:{seed}:0"))
        state = population.prepare(catalog(), {"Base": 1}, seed=seed,
            existing={"Base": [base_row(generated_id)]}, strategies={"Base": strategy("Base")})
        with self.assertRaisesRegex(population.PopulationError, "identity collision"):
            population.propose(state, {})
        state = population.prepare(catalog(), {"Base": 1}, seed=seed, strategies={"Base": strategy("Base")})
        with self.assertRaisesRegex(population.PopulationError, "explicit mapping"):
            population.propose(state, None)
        with self.assertRaisesRegex(population.PopulationError, "unknown or private"):
            population.prepare(catalog(), {"Hidden": 1}, seed=1)
        with self.assertRaisesRegex(population.PopulationError, "public_records limit"):
            population.prepare(catalog(limit=1), {"Base": 2}, seed=1)

    def test_pending_blocks_second_proposal_and_plan_is_bound_by_digest(self):
        state = population.prepare(catalog(), {"Base": 1}, seed=1, strategies={"Base": strategy("Base")})
        proposal = population.propose(state, {})
        with self.assertRaisesRegex(population.PopulationError, "already pending"):
            population.propose(state, {})
        plan = bind(state, proposal)
        changed_plan = state.pending.plan
        changed_plan["request"]["context"] = "changed"
        with self.assertRaisesRegex(population.PopulationError, "plan changed"):
            population.accept(state, proposal, changed_plan, committed(changed_plan))
        with self.assertRaisesRegex(population.PopulationError, "write-once"):
            state.pending.plan = changed_plan
        with self.assertRaisesRegex(population.PopulationError, "cannot be cleared"):
            state.pending.plan = None
        self.assertEqual(state.pending.plan, plan)

    def test_batch_and_wire_byte_caps_fail_before_plan_creation(self):
        with self.assertRaisesRegex(population.PopulationError, "command limit"):
            population.prepare(catalog(commands=2), {"Base": 3}, seed=1,
                               strategies={"Base": strategy("Base")}, batch_size=3)
        large = contract("Large", 1, schema({"value": {"type": "string"}}, ["value"]))
        state = population.prepare(catalog((large,)), {"Large": 1}, seed=1,
            strategies={"Large": lambda *_: {"value": "x" * 66000}})
        with self.assertRaisesRegex(population.PopulationError, "byte cap"):
            population.propose(state, {})

    def test_committed_population_job_is_fenced_to_one_exact_target(self):
        state = population.prepare(catalog(), {"Base": 2}, seed=5,
            strategies={"Base": strategy("Base")}, batch_size=1)
        first = population.propose(state, {})
        target = {"url": "http://example.test/rpc", "model": "test-model",
                  "store": str(uuid.uuid4()), "tenant": str(uuid.uuid4()), "actor": str(uuid.uuid4())}
        first_plan = bind(state, first, target=target)
        population.accept(state, first, first_plan, committed(first_plan))
        self.assertEqual(state.target, target)
        second = population.propose(state, {})
        other_target = {**target, "actor": str(uuid.uuid4())}
        second_plan = bind(state, second, target=other_target, attach=False)
        with self.assertRaisesRegex(population.PopulationError, "target differs"):
            state.pending.plan = second_plan
        self.assertEqual(state.accepted["Base"], 1)
        self.assertIsNotNone(state.pending)


if __name__ == "__main__":
    unittest.main()
