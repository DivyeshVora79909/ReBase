# Reactive Calculation Suite Plan

Status: corrected architecture and implementation plan
Last reviewed: 2026-09-04

This document replaces the earlier plan that described the accounts and
warehouse facts as append-only or immutable. That framing does not match
ReBase. ReBase is a mutable, reactive calculation graph: users edit source
inputs, SurrealDB recalculates stored derivations, materialized views maintain
aggregates, and synchronous `e_*` guards accept or reject the resulting state.

## Decision

Keep the database model mutable and highly normalized. Do not turn the domain
into an event-sourced ledger or a traditional transaction-history store.

SurrealDB transactions still provide atomicity for each write and its
synchronous events. Atomicity is an engine guarantee; it is not a requirement
that business records be immutable. A failed guard must roll back the mutable
source write, its view changes, and its invalidation pings together.

Immutability is an optional per-domain policy for a future legal or provider
workflow. It is not the default contract for accounts, CRM, warehouse, or HRM.

## Field and table roles

The existing naming direction is useful and should remain explicit:

| Role | Meaning | Mutation rule |
| --- | --- | --- |
| `a_*` | authoritative business input or relationship | mutable when table/field permissions allow |
| `d_*` | persisted deterministic derivation (`VALUE`) | machine-owned; recalculated on every write/ping |
| `e_*` | write-time invariant/guard (`VALUE` plus `ASSERT`) | machine-owned; a `THROW` rejects the mutation |
| `v_*` | incremental aggregate/materialized view | read-only projection maintained by SurrealDB |
| `c_*` | optional read-time convenience projection | never used as an integrity source |
| `system_ping` | invalidation trigger | internal only; carries no business meaning |

`d_*` and `e_*` are not alternate sources of truth. They are database-owned
projections of the current mutable `a_*` graph. The frontend may expose only a
safe subset of `a_*`, but frontend hiding is not a security boundary; table and
field permissions remain authoritative.

## Reactive write contract

The intended path for a cross-record calculation is:

```text
write mutable source record
  -> VALUE fields on that record recalculate
  -> direct-source incremental views update
  -> view event pings aggregate targets
  -> dependent records recalculate through system_ping
  -> e_* guards run on every affected record
  -> any failed guard rolls back the complete synchronous chain
```

A parent mutation follows the reverse path:

```text
parent field changes
  -> native REFERENCE reverse scan finds dependent rows
  -> synchronous invalidation event pings those rows
  -> their d_* values and views move to the new values
  -> old and new aggregate targets are revalidated
```

This is the missing piece in several current account and CRM paths. A view
that dereferences `child.parent.some_field` does not learn about a parent-field
change merely because the reference exists. The dependent child must be
explicitly pinged, preferably through a stored direct `d_*` shadow field.

## Compiler reactivity work

The compiler should build a validated dependency graph in addition to the
authorization reference graph.

1. A dependency edge identifies the source table/field, the reverse reference
   field, and the dependent table/field or view.
2. Simple record paths can be inferred from the schema. Arbitrary expressions
   in guards and view projections must either be parsed by a real expression
   parser or declare a small validated marker such as
   `@rebase-depends order.a_order_date`. A missing declaration is a compile
   warning/error, not silent stale state.
3. For each edge, generate a synchronous event with a precise `WHEN` clause.
   It updates only the affected reverse references and only when the declared
   source field changed.
4. Use `REFERENCE` reverse scans for fan-out, deduplicate targets, and preserve
   both `$before` and `$after` targets for moves and deletes.
5. Keep the existing view-to-target ping. When a group key changes, invalidate
   both the old and new group rows even if the engine reports them as separate
   view mutations.
6. Detect cycles in the derived dependency graph. A normal calculation graph
   must be acyclic; recursive trees need a declared depth/fixed-point policy.
   The authorization reader-cycle guard remains a separate invariant.
7. Keep synchronous invalidation lightweight. Large external work stays in the
   existing async effect path; an async event is never used for an invariant
   that must reject the triggering write.

Guard code containing a nested query must capture its outer record before the
subquery because SurrealQL rebinds `$this` inside a subquery:

```surql
LET $self = $this.id;
LET $row = (SELECT * FROM v_total WHERE parent = $self)[0];
```

Do not use a query and then unconditionally `RETURN true` as a data check. It
only proves that the query did not raise an error.

## Accounts

### Preserve the mutable calculation graph

Keep invoices, invoice lines, payments, allocations, taxes, adjustments, and
stock links editable under their existing authorization policy. Their guards
must read current aggregate views and reject a mutation when the resulting
calculation is invalid.

The current account guards are a good direction. For example, treasury
balance, invoice allocation, delivery quantity, tax sign, and payment
direction are naturally `e_*` invariants. They should not be replaced by an
append-only posting workflow at this stage.

### Make currency a dimension, not an inferred scalar

The old `org.a_currency`, `tax_account.a_currency`, and
`payment.a_fx_rate` combination cannot describe both sides of a cross-currency
calculation. Normalize the independent dimensions:

- `currency`: code, minor-unit precision, symbol, and active state;
- organization functional currency: an explicit `record<currency>` relation;
- optional `fx_rate`: base currency, quote currency, rate, source, and effective
  datetime;
- every monetary source row: amount, transaction currency, rate policy, and
  any explicit rounding input.

If a transfer has different source and destination amounts/currencies, use the
Accounts kernel's `money_exchange` fact with two explicit typed legs and one
immutable `fx_rate` snapshot. Ordinary `money_movement` remains same-currency;
do not compress conversion into one `a_currency` chosen with `??`. A payment
allocation currently targets an ordinary movement and therefore remains
same-currency until a dedicated exchange-settlement contract is added.

Derived base amounts, currency differences, balances, and statistics remain
`VALUE` fields and may be recalculated when a mutable rate or source amount
changes. Aggregate views always group by currency (and organization) before
any conversion; a raw sum of unlike currencies is invalid. A future `locked`
or `posted` policy can freeze selected rows without changing this base model.

### Required dependency repairs

The current source shows concrete reactive gaps:

- reducing an `invoice_line` below an existing allocation can bypass the
  invoice guard because the guard is on `invoice`, not the line;
- changing an item cost can leave dependent line COGS and aggregates stale;
- changing a payment rate or invoice currency/rate must revalidate allocation
  and treasury targets;
- adjustment targets and notes need invalidation when their referenced
  organization or invoice changes.

Generate reverse pings for these edges. A child write then updates its view,
the view pings the invoice/payment/treasury target, and the target guard can
reject the whole child mutation. A parent change pings lines and allocations
so their `d_*` fields and views are refreshed before the write commits.

Use direct source shadows for values that appear in group keys, for example
`invoice_line.d_currency`, `invoice_line.d_org`, and any item/rate value needed
by a view. This keeps the view's `FROM` fields direct and makes its incremental
dependency explicit.

## CRM

Keep the opportunity -> quote -> order -> line tree mutable. Add reactive
shadows rather than immutable snapshots:

- line organization, currency, and parent identifiers as `d_*` values;
- order event date as a direct line `d_*` datetime for temporal views;
- stage/pipeline and lifecycle derivations where a guard needs them;
- target organization/person keys for task, activity, note, and attachment
  aggregates.

Parent field changes must reverse-ping their children. This repairs the current
failure where an order-line daily/monthly view does not move when only
`order.a_order_date` changes. The raw `opportunity` view using `created_at`
must either rely on the common framework field after composition or declare an
explicit source field; standalone validation must not silently depend on a
field that is absent from the composed schema.

Keep useful guards such as “opportunity has a person or organization” and
“stage belongs to pipeline.” Add dependency pings so changing a stage,
pipeline, parent, or organization re-evaluates existing opportunities/orders
and their aggregate rows. Lifecycle transitions can remain mutable and be
validated by `e_*` rules; no global append-only rule is needed.

## Warehouse and HRM

Warehouse movements and attendance entries are mutable calculation facts. A
correction edits or adds a source row, then stock/duration/day/month/year
projections recalculate through the same synchronous dependency chain.

Negative stock, non-negative duration, overlap, approval, and ownership rules
belong on the source write and its affected aggregate targets. Ancestor-only
writes are table permissions, not frontend branches. A rebuildable aggregate
cache is acceptable; it must never be an undocumented second source of truth.

## Temporal views and cron declarations

Temporal views should group on direct, stored datetime/bucket fields and declare:

- source table and event-time field;
- UTC or an explicit business-timezone policy;
- supported unit (`year`, `month`, `day`, `hour`, `minute`, or `second`);
- group dimensions, measures, and empty/null policy;
- repair strategy.

Use half-open windows `[from, to)` and define `first` as
`ORDER BY event_time, id LIMIT 1`. A cron record may select a target descriptor,
time window, and action, but the runtime resolves those through compiler-known
metadata. It must not interpolate an arbitrary table or function name supplied
by a client.

## Table existence and `SELECT` in guards

There is no record-user-safe generic `table::exists()` function in the pinned
engine.

- A privileged system connection can check a static catalog set with
  `object::keys((INFO FOR DB).tables)`.
- `type::table($name)` is only a cast. A dynamic `SELECT` errors for a missing
  table, but returns `[]` for an empty or caller-hidden table.
- A nested `SELECT` inside an `ASSERT` remains in the current transaction; it
  does not commit or break it. A later `THROW` rolls back earlier writes.
- For a record/cardinality check, compare `array::len(...)` or `count()`
  explicitly. For a typed reference, the compiler's existence assertion and
  chosen `REFERENCE ON DELETE` action are preferable.

Use catalog checks at startup/migration and descriptor allowlists for generic
cron/resource selection. Do not make record validity depend on an ignored
`SELECT` result or on caller-visible table introspection.

## Implementation order

1. Add dependency metadata/analysis and regression probes for nested `$this`,
   synchronous view pings, old/new group invalidation, and guard rollback.
2. Extend generated invalidation events to business fields, not only
   ownership/readers; add direct `d_*` shadows for cross-table view keys.
3. Repair account currency dimensions and add allocation/rate/treasury
   dependency edges without making source rows immutable.
4. Repair CRM temporal keys, parent propagation, lifecycle guards, and
   aggregate deletion/move behavior.
5. Apply the same dependency contract to warehouse and HRM source facts.
6. Add typed temporal-view and cron descriptors plus a bounded rebuild/repair
   command for imports and upgrades (bulk import does not run ordinary events).
7. Run integration and on-disk performance tests only after each reactive path
   has a positive and rollback regression.

## Verification contract

The focused suite must prove:

- child mutations that violate a parent `e_guard` are rejected atomically;
- parent changes refresh all dependent `d_*` fields and both old/new view
  groups;
- account calculations never sum unlike currencies and rate changes propagate;
- CRM order-date and organization changes move temporal/organization views;
- corrections to warehouse/HRM facts update summaries synchronously;
- cycles are rejected or follow an explicitly bounded recursive policy;
- privileged catalog checks and descriptor allowlists reject unknown targets;
- rebuilds restore view state after bulk import or a controlled interruption;
- fan-out, conflict retries, latency, RSS, and datastore growth are measured
  with on-disk RocksDB and explicit budgets.

No source schema or compiler implementation is changed by this planning note.
