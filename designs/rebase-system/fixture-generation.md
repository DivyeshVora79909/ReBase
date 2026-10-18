# Incremental fixture generation

The development tool should turn a schema, an explicit starting dataset, and
requested counts into useful related data. The reusable part is choosing the
next feasible input. SurrealDB already owns calculations, validation, and
transaction rollback; duplicating those in a JavaScript reactive engine would
increase maintenance.

## Execution plan

1. Reuse the existing compiled input model, isolated seeded Faker, JSON Schema
   Faker, native value binding, and optional Z3 session. Extract shared value
   generation so offline and incremental paths enforce the same input boundary.
2. Compile public reference metadata once in `createModel`. Add a sequential
   `generate` operation with explicit read/apply effects. Infer reference pools
   from record IDs; existing rows never consume requested new-row quotas.
3. Select eligible tables by remaining quota and priority. Select parents by
   record weight, with polymorphic alternatives, arrays, role-specific usage,
   and explicit compatibility dependencies. Use a weighted sum tree for changing
   parent pools; keep table scheduling as a small linear scan.
4. Connect generation to `populate`: read selected parents and insert each row
   in the same SDK transaction. Update pools and usage only after acceptance.
   Preserve offline `plan`/`insert` for named, staged, inspectable fixtures.
5. Exercise reference cycles, quota scheduling, distribution, compatibility,
   live aggregate feedback, solver scopes, and rollback. Add a real accounting
   example and document the REPL composition and measured limits.

## Public contract

`generate({ model, seed, space, counts, rules, read, apply, ... })` is the small
generation loop. `space` is an array of existing records; its table pools are
derived from IDs. `counts` maps table names to new-record counts, with omitted
tables requesting zero. `rules` overrides only choices the schema cannot make.

`apply(row, context)` accepts one bound row and returns the complete accepted record.
Public references in that response must stay within the starting space and
previously accepted rows, including nested references supplied through `values`.
The saved references determine role usage and subsequent selection weights.
Generated/protected references and create-only JSON Schema constraints are
excluded from this check. Rejection happens before publishing the row or
advancing quotas; native population cancels the whole transaction.
`read(ids)` optionally refreshes chosen parents before value generation. These
ordinary functions keep selection separate from effects. The core does not
open connections or own transactions. For custom composition the caller owns
effect atomicity and supplies any additional callback context explicitly.

`populate(db, { model, counts, ... })` supplies native SDK reads and writes and
owns one commit/cancel boundary. `populate(db, { model, recipe, ... })` retains
the offline-plan workflow. Mixing counts and recipe is an error.

Each table rule may supply `priority`, `refs`, `values`, and `id`. Reference
policies can bias target tables and favor popular or less-used parents. A custom
weight function can exclude incompatible candidates by returning zero;
`after` names reference fields it needs, independent of property-name order.
Optional references remain optional unless requested explicitly. Static values
can pin references; `refs: { field: false }` delegates a reference to `values`.

`values(context)` receives selected parents, the per-table index, total accepted
row sequence, seeded Faker, and run-local table pools. It can return `null` when
the selected tuple is currently infeasible. Ordinary errors are fatal. A bounded
number of declined attempts per table is reset by each successful write.

## Selection and state

For an eligible table:

```text
table weight = remaining new rows × priority
parent weight = table bias × (role usage + offset)^skew × custom weight
```

The default parent weight is one. Consequently 100 records of one polymorphic
target have 100 times the total weight of one record of another target. Positive
skew favors previously used parents; negative skew favors less-used parents.
Offset keeps unused parents eligible. These are distribution controls, not
promises of exact percentages. Known starting children and explicit usage
counts can initialize each reference role independently.

Every required scalar field needs a parent; arrays need enough distinct parents
for their minimum cardinality. Polymorphic alternatives form a union. A seeded
self-reference or required cycle can proceed as records become available.
An empty required cycle cannot create its own first parent.

Parent indexes grow as accepted records enter their pools. A binary sum tree
provides logarithmic selection and weight updates without rescanning all
parents. Recomputing ancestor sums also avoids accumulating subtraction error
when a large weight is temporarily removed for sampling without replacement.
Custom tuple-dependent weights require a candidate scan; this cost remains
explicit rather than hidden behind a purported general index.

The loop stores identities, selection weights, usage, and accepted records.
It does not maintain a second copy of business aggregates. Native population
refreshes the selected parents in one bound query before each values callback.
These current parent values are the input to arithmetic or solver constraints.
Other pool entries remain snapshots; callbacks must not treat them as live
aggregates. More distant queries can use the same transaction explicitly.

## Constraints and failure boundaries

- JSON Schema and native reference metadata describe inputs, not an automatic
  inverse of arbitrary SurrealQL validators. Cross-record compatibility and
  business-specific feasibility remain ordinary functions.
- Use arithmetic for simple bounds and exact integer units for money. A single
  `withSolver` session can enclose a generation run; use `push`/`pop` for changing
  bounds so previous bounds do not accumulate or survive into later rows.
- Chronology is explicit scenario data. Increasing timestamps must still start
  after relevant existing history and respect business dates. A current balance
  alone does not establish validity of a backdated change.
- A stalled run reports remaining counts and current blockers. It is not a
  mathematical proof that no complete dataset exists. There is no automatic
  global reserve optimizer, unbounded retry, or silent partial commit.
- Database errors abort the native population transaction. Only an explicit
  callback decline triggers another selection attempt.
- Existing native input/type restrictions remain in force. Automatic selection
  covers public scalar and array reference fields; nested references need
  explicit values and still pass normal binding and space validation.

## Preparation evidence

The current checkout uses Node 26.12.0, SurrealDB 3.3.0, Faker 10.6.0,
JSON Schema Faker 0.6.3, and Z3 5.3.1. A disposable native transaction trial
confirmed that `SELECT * FROM $ids` accepts bound arrays of record IDs, observes
an event-updated parent immediately after insertion, and restores the original
parent on cancellation. No configured application database was used.

## Implemented and verified — October 18, 2026

Implemented against `ad61288`, with no dependency changes. The selection loop
is in `dev-tools/fixtures/generate.js`; the weighted index and shared input
generation are separate modules. Existing API/workbench exports expose the new
primitive through `fixtures`. The [usage guide](../../dev-tools/README.md#incremental-counts-and-current-database-values)
includes native population, explicit effects, compatibility policies, and the
accounting example.

- `npm run test:dev-tools`: 100 tests passed. This includes existing planner,
  native binding, compiler, preparation, and REPL regressions plus generation,
  weighted sampling, and scoped solver reuse.
- `node dev-tools/checks/fixtures-probe.js`: passed on disposable SurrealKV.
  Four incremental withdrawals each observed the preceding reactive update;
  the exact balance moved from 23.45 to 21.59. Both incremental database rejection
  and bounded stalling restored snapshots of every compiled table after prior
  writes. The existing overdraw, backdating, cross-tenant, clearing, and replay
  checks also passed: five rejected transactions in total, 65 cleared tables.
- `git diff --check`: passed. The broader backend and accounting acceptance
  suites were not rerun; no compiler/runtime or business-rule implementation
  changed.

A local Node 26.12.0 sampling experiment used 100,000 parents with initially
equal weights. Index construction took 8.7 ms; 100,000 selections with a weight
increment after each selection took 82.5 ms. For 1,000 selections, Faker's linear
weighted-array helper took 1,128 ms and the index took 0.83 ms. A separate
in-memory run generated and validated 10,000 children from 10,000 supplied
parents with skew 1 in 922 ms after model creation. Seed 41 was used throughout.
These are single local measurements, not timing guarantees or database
throughput/capacity claims. Custom tuple weights still scan their candidates;
native queries, constraints, and writes add their own costs.

The planned generation slice is complete. Arbitrary validator inversion,
automatic nested-reference synthesis, exact final distribution quotas, global
completion search, and production-scale data loading remain outside this API's
contract. Future changes should follow concrete scenario requirements or
measured bottlenecks.

## Saved-reference correction — October 18, 2026

Review of `91d6df1` exposed a missing acceptance boundary: usage came from the
prepared input, and references rewritten by the database were not checked
against the pool. The generator now extracts public references from the saved
record using the compiled field bindings, validates membership before updating
run state, and derives usage from those references. No public API, dependency,
or database query was added.

- `npm run test:dev-tools`: 112 tests passed. New regressions reproduced the
  original failures and cover rewritten scalar/polymorphic array references,
  optional additions/removals, nested wildcard paths, protected outputs,
  input-only constraints, and subsequent selection feedback.
- `node dev-tools/checks/fixture-references-probe.js`: passed on disposable
  SurrealDB 3.3.0/SurrealKV. Native `VALUE` normalization updated the saved parent
  and usage; a later rewrite outside the supplied pool cancelled both pending
  child writes and every parent event update. The regular fixture probe now
  includes this focused check.
- `git diff --check`: passed. The full accounting fixture integration probe
  and broader backend acceptance suites were not rerun for this correction.
