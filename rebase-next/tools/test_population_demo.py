import unittest
from unittest.mock import patch
from types import SimpleNamespace

import population_demo as demo
from population import prepare, propose


POOL = "00000000-0000-4000-8000-000000000001"


def equipment_catalog():
    uuid = {"type": "string", "pattern": "^[0-9a-f-]{36}$"}
    return {
        "model": "equipment-demo-model",
        "capabilities": {"limits": {
            "public_records": 100, "commands": 64, "returning": 32,
            "request_bytes": 65536, "per_contract": {},
        }},
        "contracts": [
            {"code": 101, "name": "Pool", "visibility": "public",
             "schema": {"type": "object", "additionalProperties": False,
                        "properties": {"unit": {"type": "integer"}},
                        "required": ["unit"]}, "references": []},
            {"code": 205, "name": "Delivery", "visibility": "public",
             "schema": {"type": "object", "additionalProperties": False,
                        "properties": {"pool": uuid, "at": {"type": "string"},
                                       "quantity": {"type": "string"}},
                        "required": ["pool", "at", "quantity"]},
             "references": [{"field": "pool", "targets": [101], "optional": False}]},
            {"code": 410, "name": "Reservation", "visibility": "public",
             "schema": {"type": "object", "additionalProperties": False,
                        "properties": {"pool": uuid, "starts": {"type": "string"},
                                       "ends": {"type": "string"},
                                       "requested": {"type": "string"},
                                       "active": {"type": "boolean"}},
                        "required": ["pool", "starts", "ends", "requested", "active"]},
             "references": [{"field": "pool", "targets": [101], "optional": False}]},
            {"code": 900, "name": "PrivateOutput", "visibility": "engine",
             "schema": {"type": "object"}, "references": []},
        ],
    }


class PopulationDemoTests(unittest.TestCase):
    def test_fresh_equipment_context_requires_controlled_chronology_and_reads_before(self):
        calls = []

        def call(method, params):
            calls.append((method, params))
            return {"value": {"sum": "10"}}

        context = demo.equipment_context(
            call, "model", POOL, start=20, end=100, requested=7,
            previous_start=10, common_end=100,
        )
        self.assertEqual(context["construction"], demo.CONTROLLED_EQUIPMENT)
        self.assertEqual(context["available_before"], "10")
        self.assertEqual(calls, [("roots.read", {
            "model": "model", "owner": POOL, "slot": 7,
            "read": {"kind": "before", "at": "20"},
        })])
        with self.assertRaisesRegex(ValueError, "increase strictly"):
            demo.equipment_context(call, "model", POOL, start=10, end=100,
                                  requested=7, previous_start=10, common_end=100)
        with self.assertRaisesRegex(ValueError, "common future end"):
            demo.equipment_context(call, "model", POOL, start=20, end=30,
                                  requested=7, previous_start=10, common_end=100)

    def test_population_composition_uses_typed_anchor_and_fresh_capacity_rule(self):
        state = demo.prepare_equipment_population(equipment_catalog(), POOL,
                                                  seed=20261025, count=1)
        context = {"construction": demo.CONTROLLED_EQUIPMENT,
                   "available_before": "2", "starts": "20", "ends": "100",
                   "requested": "7", "common_end": "100"}
        proposal = propose(state, context)
        command = proposal.commands[0]
        self.assertEqual(command["contract"], 410)
        self.assertEqual(command["fields"], {
            "pool": POOL, "starts": "20", "ends": "100",
            "requested": "2", "active": True,
        })
        self.assertEqual(proposal.additions[0]["references"], {"pool": POOL})
        self.assertEqual(state.accepted["Reservation"], 0)

    def test_equipment_proposal_is_checked_against_independent_source_oracle(self):
        state = prepare(
            equipment_catalog(), {"Reservation": 1}, seed=41,
            existing={"Pool": [{"id": POOL, "contract": "Pool", "fields": {"unit": 7}}]},
            strategies={"Reservation": demo.equipment_reservation_strategy},
            rules={"Reservation": demo.equipment_reservation_rule},
        )
        facts = {
            POOL: {"contract": 101, "fields": {"unit": 7}},
            "00000000-0000-4000-8000-000000000002": {
                "contract": 205, "fields": {"pool": POOL, "at": "0", "quantity": "10"}},
        }
        context = {"construction": demo.CONTROLLED_EQUIPMENT,
                   "available_before": "10", "starts": "10", "ends": "100",
                   "requested": "8", "common_end": "100"}
        proposal = propose(state, context)
        proposed_facts = {**facts, proposal.commands[0]["id"]: {
            "contract": 410, "fields": proposal.commands[0]["fields"]}}
        from verify_oracles import evaluate
        expected = evaluate("equipment", proposed_facts)["derived"][proposal.commands[0]["id"]]
        observed = {"contract": 410, "input": proposal.commands[0]["fields"], "derived": expected}
        next_facts, checked = demo.check_equipment_proposal(
            facts, proposal, lambda identity: observed if identity == proposal.commands[0]["id"] else None)
        self.assertEqual(next_facts, proposed_facts)
        self.assertEqual(checked["records"][proposal.commands[0]["id"]], observed)

    def test_measured_actions_compose_existing_bounded_step_callbacks(self):
        events, observed, checked = [], [], []

        def bounded(requests, submit, **kwargs):
            item = next(iter(requests))
            outcome = submit(item)
            kwargs["on_offer"](item) if kwargs.get("on_offer") else None
            kwargs["on_complete"](item, outcome)
            return {"scheduled": 1, "completed": 1}

        with patch.object(demo, "bounded_step", bounded):
            result = demo.measured_actions(
                iter([{"action": "read", "id": POOL}]),
                lambda item: {"kind": "committed", "id": item["id"]},
                duration=1, offered_rate=1, clients=1, max_pending=1,
                generation_seconds=0.2, setup_seconds=0.1,
                observer=lambda item, outcome: observed.append((item, outcome)) or {"sample": 1},
                checker=lambda item, outcome: checked.append((item, outcome)),
                on_offer=lambda item: events.append(item),
            )
        self.assertEqual(result["bounded_step"], {"scheduled": 1, "completed": 1})
        self.assertEqual(events, [{"action": "read", "id": POOL}])
        self.assertEqual(len(observed), 1)
        self.assertEqual(len(checked), 1)
        self.assertEqual(result["observations"], [{"sample": 1}])
        self.assertEqual(checked[0][1]["id"], POOL)
        self.assertIn("client_call_seconds", checked[0][1])
        self.assertEqual(result["timing_seconds"]["generation"], 0.2)
        self.assertEqual(result["timing_seconds"]["setup"], 0.1)
        self.assertIn("verification_callbacks", result["timing_seconds"])

    def test_saved_plan_for_another_target_is_blocked_before_publication(self):
        expected_target = {"url": "http://a/rpc", "model": "m", "store": "s1",
                           "tenant": "t", "actor": "a"}
        other = {**expected_target, "url": "http://b/rpc", "store": "s2"}
        state = SimpleNamespace(catalog={"model": "m"}, target=expected_target,
                                 pending=SimpleNamespace(plan=None))
        proposal = SimpleNamespace(commands=[], returning=[])
        plan = {"target": other}
        with patch.object(demo.client, "prepare", return_value=plan), \
                patch.object(demo.client, "save_plan") as save:
            with self.assertRaisesRegex(ValueError, "destination differs"):
                demo.bind_saved_plan(state, proposal, "http://b/rpc", "token", "unused.plan")
        save.assert_not_called()

    def test_authored_clone_provider_copies_only_public_input(self):
        record = {"id": POOL, "version": 42, "contract": 101,
                  "input": {"parent": POOL}, "derived": {"secret": "ignored"}}
        provider = demo.authored_input_provider(record)
        values = provider({"type": "object"}, 2, 9)
        values[0]["parent"] = "changed"
        self.assertEqual(values[1], {"parent": POOL})
        self.assertEqual(record["input"], {"parent": POOL})
        with self.assertRaisesRegex(ValueError, "public input"):
            demo.authored_input_provider({"id": POOL, "derived": {}})


if __name__ == "__main__":
    unittest.main()
