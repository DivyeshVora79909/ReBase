# Composable population tools

**Current versus planned:** this guide documents the accepted Python population
tools. G10 proposes Node ESM developer functions and an ordered-storage
redesign; neither is implemented. Existing commands remain the runnable
baseline until replacement checkpoints pass. See the [G10 program](../research/56-node-and-index-redesign-program.md),
[Node contract](../research/57-node-developer-contract.md),
[storage contract](../research/58-ordered-storage-redesign.md) and
[capability inventory](../research/59-node-capability-inventory.md).

`tools/population.py` helps a Python script author bounded creates from a
developer model catalog. It does not submit mutations or decide whether a
whole business graph is valid. Your code supplies values, reference pools and
current context; the existing client saves and sends each intent, and the
server remains authoritative for reference access and global rules.

G9.1’s API and state flow are implemented. The real Equipment and Quantity
examples exercised the ordinary API and G8’s existing bounded action scheduler.
G9.4's isolated source-tooling handoff passes. Use the examples as source
workflows, not as a newly packaged release. The G8 0.16.0 binary predates these Python
tools; a compatible binary supplies the existing model/runtime only.

## Run the examples

The full demo is a small, Node-free Pool/Delivery/Reservation example followed
by a separate Quantity Source/Scale/Join example. It creates fresh redb stores,
saves original mutation plans, checks committed records against independent
source oracles, and retains a JSON report. Pass a binary with the same model
catalog and schemas as the tools. Install the pinned Python schema validator in
a local virtual environment; Node is not needed for this demo:

Run these commands from `rebase-next/`:

```sh
python3 -m venv target/g9-venv
target/g9-venv/bin/python -m pip install -r tools/requirements-population.txt
```

```sh
target/g9-venv/bin/python -B tools/population_demo.py \
  --binary /path/to/rebase-next \
  --out target/my-population-demo \
  --seed 20261025
```

The directory must be new. The example’s equipment rule refreshes a strict
`before` prefix before each reservation. Its increasing starts and common future
end are a controlled construction; a prefix alone does not prove arbitrary
interval feasibility. Quantity demonstrates exact integer/rational fields,
typed polymorphic references, an authored-input clone of one Quantity `Join`
with a fresh ID, and reconciliation after a lost response. The clone copies one
public `input`, then selects its declared references again; it does not copy a
stored graph.
The Quantity `Source` input field is `value`; the example supplies the exact
decimal string `"12"` and uses an exact rational `Scale` factor.
See [`population_demo.py`](../tools/population_demo.py) for the literal
compositions.

## The four operations

The public API is deliberately small:

```python
population.prepare(catalog, counts, *, seed, existing=None, strategies=None,
                   rules=None, provider=None, priorities=None, batch_size=1,
                   clock=None, provider_batch_size=32,
                   select_reference=None, reference_usage=None)
population.propose(state, fresh_context, *, max_commands=None)
population.accept(state, proposal, plan, response)
population.reject(state, proposal, plan=None, outcome=None)
```

`prepare` returns a caller-owned `State`. `counts` names public contracts;
omitted contracts have quota zero. `existing` maps contract names to rows with
an explicit `id` and `contract`; `fields` may be omitted when the ID is used
only as a reference. IDs do not fulfill the new-record quota. They are a
lower-bound preflight because the supplied reference space may not enumerate
the database. Use typed contract names, never infer a type from the UUID.

The default contract choice is weighted by remaining quota multiplied by the
contract’s optional `priorities` value (default 1). Contracts with unavailable
required reference pools are ineligible. By default a reference is selected
uniformly per record from all IDs in compatible typed pools. A custom selector
has signature
`select_reference(child, path, compatible_pools, usage, rng, context) -> (contract, id)`.
It must return an ID in a declared compatible pool. The explicit
`state.reference_usage` ledger counts committed choices only. For references
made before this job, seed `reference_usage`; the tool cannot know unprovided
history.

Field strategies and rules are ordinary functions:

```python
strategy(schema, seed, cursor, context) -> fields
rule(fields, context, selected_references) -> fields
fresh_context(contract_name, selected_references, proposal_cursor) -> mapping
```

Each quota-bearing contract needs a `strategy` or the optional `provider` to
make its base values. Strategies run before parent IDs are chosen. The optional
`fresh_context` callback runs after references are selected; a rule then sees
that context and the chosen references and can overlay dependent values. You
can also pass a mapping when no fresh read is needed. Put values required by
native model bindings in explicit strategies or rules. Use canonical decimal
strings and exact rational inputs where the model specifies them; avoid floats
for exact native arithmetic. JSON Schema checks the authored object shape. It
does not prove reference authority or global invariants; the mutation
transaction performs those checks.

For example, this script reads the developer catalog from the existing
executable, supplies the ID of an already committed Pool, and reads a fresh
prefix after `propose` has selected the typed parent. Fill in the endpoint,
token and Pool ID for your secured service:

```python
import json
import subprocess
from pathlib import Path
import sys
sys.path.insert(0, "tools")
import client
import population
from population_demo import (
    equipment_context,
    equipment_reservation_rule,
)

binary = "/path/to/rebase-next"
url = "http://127.0.0.1:8080/rpc"
token = Path("target/token.txt").read_text().strip()
pool_id = "UUID of an already committed Pool record"

catalog = json.loads(subprocess.run(
    [binary, "--model", "equipment", "model", "developer"],
    check=True, capture_output=True, text=True,
).stdout)

def call(method, params):
    return client.call(url, token, method, params)

state = population.prepare(
    catalog,
    {"Reservation": 1},
    seed=20261025,
    existing={"Pool": [{"id": pool_id, "contract": "Pool"}]},
    # Base fields do not depend on the later parent-aware context callback.
    # The reference overlay fills pool; the rule fills the final time/amount.
    strategies={"Reservation": lambda *_: {
        "starts": "0", "ends": "1", "requested": "0", "active": True,
    }},
    rules={"Reservation": equipment_reservation_rule},
    batch_size=1,
)

def fresh_context(contract, references, cursor):
    return equipment_context(
        call, catalog["model"], references["pool"], start=10, end=100,
        requested=8, previous_start=None, common_end=100,
    )

proposal = population.propose(state, fresh_context, max_commands=1)
```

The full example is preferable for submission because it also binds the plan
to the authenticated destination and saves it before execution. This snippet
assumes the supplied Pool has the same controlled history as the full example;
arbitrary interval histories need a rule checking their required interval.

## Save, submit, and reconcile

`State.pending` is an explicit `Pending` record. A proposal is detached and
deterministic for the same seed/configuration and attempt cursor. Its IDs are
UUIDv5-derived, so choose a distinct seed for an independent job. Only one
proposal can be pending. Accepted quotas, typed pools and usage counts advance
only after `accept` confirms the exact receipt. Inspect the mutable state
directly (`state.accepted`, `state.pool_ids`, `state.reference_usage`,
`state.cursor`, `state.pending`); no global RNG or hidden population cache is
involved.

Use the existing client and bind its saved plan before sending:

```python
plan_path = Path("target/reservation-20261025.plan.json")
draft = {"model": state.catalog["model"],
         "commands": proposal.commands,
         "returning": proposal.returning}
plan = client.prepare(url, token, draft)
client.save_plan(plan_path, plan)  # private, write-once path
state.pending.plan = plan          # exact destination/request binding
response = client.execute(url, token, plan)
population.accept(state, proposal, plan, response)
```

`accept` requires `response.status == "committed"` and
`response.result.operation_id` equal to `plan["request"]["operation_id"]`, plus
the records/revision receipt shape. It checks the requested returned IDs; up to
64 creates may commit while returning at most 32 records. The saved Pending plan
is detached and write-once. A changed proposal or plan, wrong target, stale
receipt or double application cannot advance the pools twice.

If plan creation or another local step fails before submission, only the exact
unbound proposal may be cancelled with
`population.reject(state, proposal, None, None)`. After binding, rejection
requires the exact plan and a definite server no-commit error. A timeout,
transport error, `outcome_unknown`, `operation_expired` or `not_observed` is
uncertain: retain the exact pending plan and reconcile with
`client.execute(url, token, plan, status=True)` or replay that same plan. A
`not_observed` status by itself does not prove that an in-flight operation
failed. Never refresh its context or silently create a replacement operation.
A rejection from a status lookup or a separate in-flight attempt does not
establish that an earlier uncertain submission failed.

Stopping and continuing means retaining the caller-owned `State`; it is
in-memory. It is not a persistent population-job restart format. Saved client
plans are the durable mutation intents and remain the source of truth for
reconciliation.

## Bounds and optional generated values

The catalog’s actual model limits govern requested and supplied records and any
per-contract caps. A proposal is additionally limited to 64 commands, 32
returned records and 65,536 serialized command bytes. The model receipt limit
remains 1,024 operations. These are existing bounds, not a million-record
capacity claim. Supplied IDs plus requested quotas are a conservative
lower-bound preflight; the server enforces actual stored counts.
The client also checks the complete RPC envelope, including context and returned
IDs; the preliminary serialized-command check does not replace that byte limit.

The default mutation `batch_size` is 1, which lets each next proposal use newly
committed parents and fresh aggregates. Increase it only when your construction
and oracle account for every command in that batch. Optional `provider_batch_size`
defaults to 32 and buffers base values explicitly; it is separate from mutation
batching.

Most examples use Python strategies and need no Node installation. The optional
JSON Schema value provider needs its single pinned Node package:

```sh
npm ci --prefix tools/schema-values --ignore-scripts
```

Pass `population_values.generate_values` as `provider`; its callback shape is
`provider(schema, count, seed) -> list[dict]`. Node is optional. The provider
accepts at most 128 values and 256 KiB of JSON input per call. A POSIX
file-size limit caps output at 2 MiB; the process also has a 15-second wall
timeout and 16/17-second CPU soft/hard limits. Node runs with a 64 MiB old-space
limit. These bounds and process cleanup limit the intended local workload; they
do not provide a full RSS or hostile-code sandbox. The provider produces base
fields only. It does not interpret `x-*` native annotations, select references
or replace explicit strategies/rules and final server validation.

## Acceptance status

G9.0–G9.4 are accepted within the [recorded bounds](../research/55-population-tooling-result.md).
Forty-five controls and the live Equipment/Quantity API/workload examples pass
both locally and from an isolated committed source export. A separate real
optional-provider case creates seven mixed records with three buffered Node
calls, then validates the documented callback example. The prior G8 package
does not include the new Python population tools. These examples are
bounded developer workflows, not a general model solver or capacity
certification.
