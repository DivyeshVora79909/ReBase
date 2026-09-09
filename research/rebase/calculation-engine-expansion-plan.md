# Calculation Engine Expansion Plan

Status: target architecture and implementation plan; planning only
Last reviewed: 2026-09-04

This plan expands ReBase into an all-in-one calculation suite while preserving
its central idea: mutable primitive records, database-owned derivations,
synchronous guards, and incrementally maintained views. The suite is not a
traditional normalized CRUD application, an immutable legal ledger, or a
generic workflow engine. It is a declarative calculation graph whose domains
can be composed without making each domain depend on every other domain's
implementation.

The engine fact boundary is documented in
[`../surrealdb/temporal-integrity-dimensional-fact-check.md`](../surrealdb/temporal-integrity-dimensional-fact-check.md).
The composition/build sequence is detailed in
[`./all-in-one-suite-plan.md`](./all-in-one-suite-plan.md). This document makes
the product decisions and the order of work explicit.

## 1. Product contract

### 1.1 What the suite guarantees

- Authoritative `a_*` records are mutable when permissions allow.
- `d_*` fields are deterministic database-owned derivations, never user input.
- `e_*` guards validate the resulting graph synchronously and roll back an
  invalid write and its synchronous invalidation chain.
- `v_*` tables are read-only, incrementally maintained projections.
- Cross-domain links are explicit typed references or explicit polymorphic
  unions; no implicit string joins are used for integrity.
- The backend is stateless. A request identifies records/actions, and the
  compiled schema/runtime performs the deterministic work.
- Rebuild and repair are first-class because derived state can be interrupted,
  bulk-loaded, or invalidated by a late temporal correction.

### 1.2 What it deliberately does not guarantee

- A current aggregate is not a historical ledger.
- Every possible dimension combination is not precomputed.
- A provider call is not a synchronous business invariant.
- A client cannot submit an arbitrary table, function, or SurrealQL fragment.
- Compliance filing, statutory tax interpretation, payroll, and legal
  immutability are not hidden in the generic engine.

## 2. The graph vocabulary

The compiler and schema conventions remain the smallest useful common language:

```text
a_*  authoritative primitive or relationship
d_*  persisted direct derivation/snapshot
e_*  synchronous invariant/guard
v_*  materialized aggregate or projection
c_*  optional read-time convenience projection
```

The normal write path is:

```text
a_* write
  -> d_* recalculation
  -> direct-source v_* maintenance
  -> generated reverse invalidation
  -> dependent d_*/e_* recalculation
  -> commit or complete rollback
```

The compiler must treat three kinds of record-shaped values differently:

| Kind | Purpose | Native reference? | Reactive edge? |
| --- | --- | --- | --- |
| authoritative relation | graph topology and integrity | yes, with explicit delete action | yes |
| derivation shadow | calculation key or parent snapshot | only when explicitly requested | generated dependency only |
| provenance origin | display/audit of a draft or deleted copy | usually no | no |

This separation prevents a derived record such as `d4_item` from accidentally
becoming an authorization reader or delete-cascade edge.

## 3. Independent domains and the shared kernel

Domains are independently authored packages. They share a small set of
canonical primitives and connect through typed contracts, not by importing one
another's private views or events.

### 3.1 Shared kernel

The first all-in-one profile owns these once:

- `user`, `groups`, and the authorization graph;
- `organization`/party and optional legal/finance profile;
- `currency`, precision, and FX-rate primitives;
- `item` and `service` catalogs (separate validation, one union at edges);
- tax component/rule primitives;
- event time, timezone/bucket policy, lifecycle, audit, and revision metadata.

`designs/core` is the intended home for principals and truly shared fields.
CRM, accounts, and test fixtures must not each define another principal,
organization, product, or currency identity.

### 3.2 Domain packages

| Domain | Owns | May consume |
| --- | --- | --- |
| CRM | people, organizations, campaigns, pipelines, opportunities, quotes, orders, activities | core party/catalog/currency |
| Catalog | items, services, prices, units, bundles | core currency/tax |
| Warehouse | locations, lots/packages, inventory movements, stock views | catalog, CRM contracts, accounts dimensions |
| Manufacturing | BOMs, work orders, material consumption/production movements | catalog, warehouse, accounts |
| Accounts | invoices, invoice lines, payments, allocations, treasury, adjustments | party, catalog, warehouse, tax, currency |
| HRM | employment/assignment, attendance, leave facts, time views | user, organization, calendar policy |
| Marketing | campaigns, audiences, activities, attribution facts | CRM party, catalog, communications |
| Ecommerce | carts, orders/fulfillment edges, returns, payment intents | CRM, catalog, warehouse, accounts |
| Productivity | tasks, projects, time entries, resource reports | user, organization, HRM |
| Communications | templates, message requests, delivery/effect records | CRM/account/HRM projections and delivery identities |
| Test/effects | scalar/relation fixtures and provider effects | framework/core only |

Each package exposes source tables, typed references, and dependency metadata.
It does not expose a private ad hoc query that another package must understand.

## 4. Lifecycle lanes without calculation leakage

The proposed draft/deleted copies are useful when they are treated as explicit
lanes, not as a second hidden business model.

### 4.1 Four lanes

1. **Canonical**: records that participate in guards and calculation views.
2. **Draft**: user-editable staging records; no canonical aggregate effects.
3. **Void/deleted**: terminal or excluded snapshots retained for explanation,
   recovery, and audit; no canonical aggregate effects.
4. **Archive**: cold historical copies for reporting or retention policy; no
   live dependency fan-out.

The canonical schema and each lane schema may share a generated field
descriptor, but the lane table must be explicit. A draft is not made inert by
merely setting a `state` string if every view still scans it.

### 4.2 Promotion and archival

The frontend may copy a draft into a canonical create/update request, but the
database must own the promotion boundary:

```text
draft write
  -> explicit promote action with origin ID
  -> canonical schema/reference/guard validation
  -> canonical views update
  -> draft marked promoted (or retained as provenance)
```

Promotion is idempotent on `(origin_lane, origin_id, promotion_key)`. A failed
promotion leaves the draft untouched. Archive/void actions copy the relevant
snapshot before removing it from the active calculation path.

### 4.3 Inert links are deliberately not integrity links

If a lane can outlive its canonical target, its origin is an opaque ID plus a
validated source-table key, or a record union without `REFERENCE`. It must not
dereference the origin in a view or guard. A native `REFERENCE` is reserved for
relations that should block/cascade deletion and remain in the live graph.

Blindly duplicating every table for every possible state is rejected because it
multiplies schema, views, permissions, and promotion paths. Add a lane only
when its participation boundary is materially different, and generate its
promotion/archive operation from the same descriptor.

## 5. Temporal integrity policy

Mutable calculations are sufficient for many CRM, marketing, and productivity
facts. They are not sufficient to prove every historical balance after an old
transaction is edited. The suite therefore assigns a temporal policy per
source table instead of forcing an immutable ledger everywhere.

### 5.1 Policy levels

| Level | Rule | Example |
| --- | --- | --- |
| `current` | validate only the resulting current graph | opportunity stage, contact data |
| `effective_replay` | retain prior state and replay the affected ordered partition | treasury, stock, attendance |
| `checkpointed_replay` | replay from periodic summaries with a bounded lookback | very large inventory/account partitions |
| `snapshot_only` | preserve report snapshots but do not reject historical edits | exploratory BI |

Every `effective_replay` source declares `partition_key`, `effective_at`,
tie-break, delta/quantity expression, invalid prefix rule, and synchronous
budget. The compiler generates the revision event and replay query. It also
generates a repair descriptor for bulk imports and late writes.

### 5.2 Why history is necessary

If an old mutable value is overwritten and no `$before` snapshot exists, a
current view cannot reconstruct the former path. Changefeeds are post-commit
and retention-bound; they are not a substitute for a revision source.

The practical design is a hybrid: mutable user-facing source facts plus
machine-owned revision rows where historical validity matters. This preserves
the calculation-engine model while making the necessary information available.

### 5.3 Efficient replay path

The first implementation uses indexed partitions and bounded ordered replay.
If a partition exceeds the synchronous budget, reject or mark an explicit
repair-needed result rather than silently accepting an unvalidated correction.
Later, a generated block summary can use the associative pair:

```text
{ total, minimum_prefix }
```

to reduce work. That optimization is domain-specialized and benchmark-gated;
it is not a universal SurrealDB feature.

## 6. Canonical dimensions and composable money

### 6.1 Entity, catalog, currency

The primitive transaction/fact shape is conceptually:

```text
fact {
  a_entity          -> organization/user/party
  a_catalog_ref     -> item | service
  a_currency        -> currency
  a_amount          decimal
  a_effective_at    datetime
  a_tax_components  -> tax_component[] (when applicable)
}
```

The actual tables remain domain-specific. This shape is a contract, not a
generic JSON blob. Store direct shadows for all fields used as view keys:
`d_entity`, `d_catalog_kind`, `d_currency`, `d_event_bucket`, and derived base
amounts.

### 6.2 Item and service normalization

Keep `item` and `service` separate where their constraints differ:

- items may have stock units, lots, serials, cost layers, and warehouse
  movements;
- services may have duration, capacity, skill, and delivery state;
- both can be referenced by a quote/order/invoice line through
  `record<item | service>`;
- a guarded `record::tb()` branch determines which derivations are legal.

Do not create a second shared product identity merely to make joins convenient.
If a client needs a common display list, expose a read-only union projection.

### 6.3 Currency and FX

An organization functional currency is a default/reporting dimension, not a
replacement for transaction currency. Each monetary source stores:

- transaction currency and amount;
- functional/base currency and derived amount when conversion is requested;
- rate pair, effective time, source, rounding, and precision policy;
- whether the rate is an estimate or a correction snapshot.

Cross-currency transfers use two explicit legs (or an equivalent pair), never
one scalar selected through an ambiguous `??` chain. Views group by currency
and organization before conversion. FX gain/loss is a derived component or
explicit correction fact, not an accidental mixed-currency sum.

## 7. Declarative tax composition

ReBase calculates tax components; it does not promise statutory compliance.
VAT/GST/TDS/TCS fit the same compositional model:

```text
tax_component {
  a_base_ref       -> line/transaction
  a_kind           enum(vat, gst, tds, tcs, custom)
  a_direction      enum(input, output, withholding, collection)
  a_jurisdiction   optional tax_region
  a_rate           decimal (optional for fixed amounts)
  a_amount         decimal
  a_currency       currency
  a_account        -> ledger_account
  a_effective_at   datetime
}
```

Rules/catalogs can describe rates and applicability, while the transaction
stores the selected component and amount used in the calculation. The guard
checks sign, currency, base, reference, and account compatibility. TDS/TCS
are liability/receivable components with direction; they are not extra hidden
dimensions on every invoice line. A client can declare additional categories
through the same table contract without changing the calculation engine.

## 8. Domain implementation plans

### 8.1 CRM

- Canonicalize party, opportunity, quote, order, and line references.
- Persist direct organization, currency, parent, and event-time shadows.
- Reverse-ping lines when a parent date, stage, pipeline, organization, or
  currency changes.
- Repair the monthly view's framework timestamp dependency.
- Add lifecycle lanes only for genuine draft/void workflows.

### 8.2 Warehouse and inventory

- Define mutable `inventory_movement` facts with typed source/destination
  locations, item/service eligibility, quantity, lot/package, cost, and time.
- Derive direction, stock impact, cost value, and contract shadows.
- Maintain only required stock/item/location views; keep rare combinations as
  bounded queries.
- Use `effective_replay` for negative-stock and running-balance policies.

### 8.3 Manufacturing

- Model BOM/component and work-order facts separately from inventory movements.
- Material consumption and production are ordinary movement facts, so stock and
  cost views remain reusable.
- Guards validate component quantities, unit compatibility, and cycle policy.
- Do not encode a manufacturing workflow in a provider/runtime handler.

### 8.4 Accounts and finance

- Repair invoice-line writes so allocation guards run on child changes.
- Split transaction currency, base currency, and FX snapshot/rate policy.
- Make payment legs, allocations, taxes, adjustments, treasury, and COGS
  dependency edges explicit.
- Mark treasury/stock partitions `effective_replay` where historical prefixes
  are a business invariant; leave exploratory reports `current`.
- Treat account views as sparse projections, not a full multi-dimensional cube.

### 8.5 HRM

- Reuse `user` as the employee principal; add employment/assignment facts.
- Add attendance start/end facts, direct duration derivation, and day/month/
  year views using an explicit timezone policy.
- Apply ancestor-only write policy at the table boundary when required.
- Choose `effective_replay` only for attendance policies that need historical
  overlap/prefix validation; do not make payroll implicit.

### 8.6 Ecommerce, products, and services

- Keep commerce order/return/payment intent records independent from CRM
  ownership while sharing party/catalog/currency references.
- Reuse warehouse movements for fulfillment and returns.
- Reuse account invoice/payment components for settlement without importing
  private finance views.
- Make item/service polymorphism explicit at line boundaries.

### 8.7 Marketing and productivity

- Store campaign/audience/attribution and task/project/time facts as mutable
  sources.
- Use current-state views unless a client explicitly selects a temporal policy.
- Keep reporting dimensions selective and sparse; do not add a view for every
  dashboard filter.

### 8.8 Communications: email and SMS

Communications belongs at the edge of the graph, not inside account or CRM
guards. A generic message request contains a recipient identity, template key,
rendered/value inputs, channel, schedule, and lifecycle. Templates expose
validated variables from compiled record descriptors (for example invoice
number, amount, or contact name); they do not execute arbitrary queries.

The effect runtime remains stateless and uses the existing explicit named
adapters for delivery. Email and SMS/phone authentication can reference the
same delivery identities, but provider credentials and retries stay in effect
records. A failed provider call changes effect lifecycle state; it must not
invalidate a monetary or CRM write synchronously.

Future edge functions follow the same boundary: a statically declared action
descriptor names the function, input shape, and authorization capability, and
the runtime invokes only that descriptor. A client never supplies an arbitrary
function/table name. Provider adapters and edge actions remain outside the
calculation graph's synchronous guards.

## 9. Temporal calculation crons

Calculation/report crons are separate from external delivery schedules. A
typed `calculation_cron` descriptor contains:

- compiled target key (table or view);
- compiled event-time field;
- validated half-open window and optional lookback;
- deterministic selection (`first` currently means `ORDER BY time, id LIMIT 1`);
- compiled action key and bounded payload shape;
- owner, cursor/watermark, lifecycle, and last result.

The client chooses among generated descriptors. It cannot submit arbitrary
table names, fields, functions, or SurrealQL. A unique run key makes retries
idempotent. Late writes use the declared lookback/repair policy instead of
silently rewriting a closed report.

Table existence is checked at profile install/startup through a privileged
catalog connection. Record users use generated capability descriptors and
ordinary permission-aware `SELECT` statements; there is no generic
record-user `table::exists()` test. This keeps catalog introspection and
business validation separate.

## 10. Compiler and generator work

### Phase A: source composition

1. Add a static profile manifest and provenance for every source statement.
2. Extract one principal pair into `designs/core`.
3. Canonicalize organization, item/product, currency, and inventory movement
   names; reject duplicate declarations with both source locations.
4. Separate account view/event material from seed data.

### Phase B: dependency graph

1. Parse authoritative references separately from derived record shadows.
2. Infer simple dependency paths and validate explicit markers for complex
   expressions.
3. Generate direct `d_*` shadows and reverse invalidation events for old/new
   targets.
4. Capture outer `$this` before generated subqueries.
5. Detect ordinary cycles; require an explicit depth/fixed-point policy for
   recursive trees.

### Phase C: domain contracts

1. Add canonical currency/FX, item/service, tax component, and finance-profile
   descriptors.
2. Repair CRM parent/time propagation and account child-write guards.
3. Add warehouse, manufacturing, HRM, commerce, marketing, and productivity
   source contracts in separate packages.
4. Add communications/template descriptors and connect only to named effect
   adapters.

### Phase D: temporal and lifecycle infrastructure

1. Generate revision events for `effective_replay` tables.
2. Add bounded replay and repair commands with keyset pagination.
3. Add explicit draft promotion and void/archive actions.
4. Add typed calculation-cron records and idempotent run records.
5. Add changefeed consumers for repair/audit, never for synchronous acceptance.

### Phase E: profile build and frontend metadata

1. Compile one deterministic all-in-one bundle from independent domains.
2. Validate generated references, permissions, views, dependency edges, and
   action descriptors.
3. Run disposable integration and scale tests.
4. Only then expose the generated resource/view metadata to MetaSol. The
   frontend remains a client of the compiled graph, not a second integrity
   implementation.

## 11. Verification matrix

### Compiler and pure contracts

- profile DAG, one principal pair, canonical names, and source provenance;
- duplicate/collision diagnostics and derived-reference classification;
- dependency marker resolution and cycle diagnostics;
- deterministic output and generated old/new invalidation events;
- typed cron/action descriptors and no dynamic identifiers;
- tax component codecs, currency pair/rate validation, and lane promotion keys.

### Disposable on-disk SurrealDB checks

- current-state CRUD and authorization across every domain;
- parent-only edits move old and new aggregate buckets;
- child edits invoke parent guards and roll back atomically;
- currency dimensions never mix in a sum;
- item/service polymorphic branches and invalid combinations;
- VAT/GST/TDS/TCS sign/base/account guards;
- draft promotion, void/archive exclusion, and inert provenance links;
- revision capture, historical replay, late-write policy, and repair;
- cron windows, first-row tie-break, duplicate run prevention, and lookback;
- communication template rendering and effect lifecycle without provider calls
  in synchronous guards.

### Scale and correctness gates

Use temporary on-disk RocksDB and bounded batched requests. Generate realistic
skew: hot entities/products, long-tail dimensions, dense and sparse groups,
deep parent chains, late timestamps, deletes, moves, and concurrent hot-key
writes. Measure p50/p95/p99 latency, fan-out, conflicts/retries, RSS, datastore
bytes, view/index amplification, replay cost, and repair throughput at each
feasible tier. Do not promise 10 million or 100 million rows until the host
budget is known; a raw row count says nothing about physical key growth.

Every dependency edge gets a valid and invalid mutation test. An invalid write
must leave the source, revisions, views, pings, and old/new groups unchanged.
After a bulk load, a rebuild must produce the same derived state as ordinary
writes for the same source set.

## 12. Adoption gates and open decisions

The suite is ready for the next implementation stage only when:

1. one profile compiles without duplicate principals or canonical collisions;
2. all cross-record business dependencies have a shadow or generated ping;
3. current-state guards and view maintenance converge synchronously;
4. strict temporal tables retain enough history to validate their stated rule;
5. currency and tax components are explicit and unlike-currency sums are
   impossible by schema/guard;
6. draft/void/archive lanes cannot leak into canonical views;
7. repair and rebuild are bounded, resumable, and observable;
8. calculation crons and communications resolve only compiled descriptors;
9. on-disk benchmarks identify actual bottlenecks and resource budgets;
10. MetaSol can consume one generated descriptor rather than duplicating graph
    rules.

Open decisions to settle during implementation, with probes rather than
assumptions:

- the exact canonical names for `organization`, `product/item`, and movement;
- which finance/stock partitions need `effective_replay` versus `current`;
- the synchronous replay budget and checkpoint interval;
- whether a client's local timezone is persisted per fact or per organization;
- which aggregate combinations justify materialization;
- the initial tax-rule fields and whether a jurisdiction catalog is needed;
- the template variable allowlist and communication retention policy.

These are bounded schema decisions, not reasons to add a generic configuration
graph or plugin system.

## 13. Deliberately rejected alternatives

- Convert every domain into an immutable event-sourced ledger.
- Duplicate every table for every lifecycle state by default.
- Use a current aggregate or changefeed as a substitute for lost history.
- Build a full entity x currency x item x tax cube proactively.
- Put currency selection in one company scalar or infer it through `??` paths.
- Let cron/template input become arbitrary table/function/query execution.
- Put provider/API calls inside synchronous business guards.
- Treat derived record shadows as authorization references automatically.
