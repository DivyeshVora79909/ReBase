# All-in-One Reactive Calculation Suite

Status: composition plan with an implemented Accounts slice. The
`designs/all-in-one/` profile currently contains `core` and `accounts`; CRM,
HRM, warehouse, manufacturing, ecommerce, and productivity remain future
sibling domains.

Last reviewed: 2026-09-08

For the deeper product decisions behind lifecycle lanes, temporal replay,
currency/tax composition, communications, and domain boundaries, see
[`calculation-engine-expansion-plan.md`](./calculation-engine-expansion-plan.md).
The Accounts-only movement and primitive-algebra target is specified in
[`accounts-movement-architecture-plan.md`](./accounts-movement-architecture-plan.md),
with its graph in [`accounts-movement-architecture.mmd`](./accounts-movement-architecture.mmd).
Engine measurements and limits are recorded in
[`../surrealdb/temporal-integrity-dimensional-fact-check.md`](../surrealdb/temporal-integrity-dimensional-fact-check.md).

This plan describes how the current test, CRM, accounts, warehouse, and future
HRM material become one ReBase suite. It follows the corrected product model:
ReBase is a mutable, reactive calculation graph. Authoritative records remain
editable when permissions allow; `VALUE` derivations, materialized views, and
synchronous `e_*` guards keep the graph coherent and reject invalid resulting
state.

The first implementation slice is now present in `designs/all-in-one/`:
`core/schema.surql` owns the principal pair, while the Accounts schema, views,
and synchronous events implement the movement/position kernel and exact
effective-time prefix replay. Its compiler support is covered by
`check:all-in-one` and `probe:accounts`. Checkpoint/block-summary optimization
and the future sibling domains described below remain planned work.

The suite is not an event-sourced ledger, an immutable transaction log, or a
second application database. SurrealDB transactions provide atomicity for a
write and its synchronous events, but atomicity does not require business rows
to be immutable.

## 1. Goals and boundaries

### Goals

- Compile all selected domains into one deterministic namespace/database bundle.
- Keep one principal graph and one generated authorization policy across every
  domain.
- Preserve the `a_*` authoritative, `d_*` derived, `e_*` guarded, and `v_*`
  aggregate roles.
- Make cross-domain calculations reactive when a child, parent, reference, or
  grouping dimension changes.
- Represent money, inventory, temporal facts, and HRM facts as explicit graph
  dimensions rather than hidden scalar assumptions.
- Let a typed cron declaration select a compiled target and a bounded time
  window without allowing arbitrary table or function execution.
- Make bulk loading, rebuilding, repair, and performance measurement explicit
  operations rather than undocumented side effects.

### Out of scope for this suite pass

- Replacing the authentication or authorization model.
- A generic query/function console or a client-controlled SurrealQL executor.
- Global append-only or legal-posting policy. A future domain may add one as a
  separate policy after the mutable graph is proven.
- Provider implementation changes. Effect tables continue to use the existing
  named-adapter runtime boundary.
- A complete payroll, tax filing, or statutory HR product. The first HRM slice
  is attendance and the shared employee graph; later tables can use the same
  contracts.
- Frontend implementation. The compiler may expose metadata for MetaSol later,
  but this plan does not duplicate frontend domain rules.

## 2. Current material and gaps

The repository currently contains these fragments:

| Material | Current contents | Suite role |
| --- | --- | --- |
| `framework/` | auth, access, authentication, audit | shared generated framework |
| `designs/test/` | test relations, provider configs, effect tables (currently also owns `user`/`groups`) | optional contract fixture; principal tables move to `core` |
| `designs/core/` | target home for `user`, `groups`, and shared principal extensions | permanent principal anchor |
| `designs/accounts/` | 16 finance/inventory tables plus account views | finance and stock calculation fragment |
| `designs/crm/` | 31 CRM/master-data tables plus CRM views | customer and sales graph |
| `designs/warehouse/` | not present yet | new explicit inventory domain, extracted from the account fragment |
| `designs/hrm/` | not present yet | new employee/attendance domain |

The account fragment currently defines `org`, `item`, `warehouse`, and `sl`,
while CRM defines `organization`, `product`, and `currency`. These are semantic
collisions even where the identifiers differ. The suite must resolve them
before it claims to be one graph. The account `seed.surql` file also contains
view/event definitions; classification must remain syntax/marker based, but
the material should be moved for developer clarity.

The raw accounts and CRM fragments validate syntactically, but neither has the
principal markers required to compile as a complete ReBase project by itself.
The first source refactor extracts `user` and `groups` into the small
`designs/core/` material set. The all-in-one profile then binds those tables
exactly once and can include `designs/test/` as an optional contract fixture.
This keeps a production-shaped suite independent from test-only provider and
relation tables.

## 3. Target composition boundary

Add one small, static profile (for example,
`profiles/all-in-one.json`). It is composition metadata, not a runtime plugin
system and not a business-rule registry:

```json
{
  "name": "all-in-one",
  "framework": "framework",
  "domains": [
    { "name": "core", "root": "designs/core", "role": "principal" },
    { "name": "crm", "root": "designs/crm", "dependsOn": ["core"] },
    { "name": "warehouse", "root": "designs/warehouse", "dependsOn": ["crm"] },
    { "name": "accounts", "root": "designs/accounts", "dependsOn": ["crm", "warehouse"] },
    { "name": "hrm", "root": "designs/hrm", "dependsOn": ["core", "crm"] },
    { "name": "test-contract", "root": "designs/test", "dependsOn": ["core"], "optional": true }
  ]
}
```

The exact filename is not important; the contracts are:

1. Every root is explicit and is resolved relative to the repository, never
   from an environment-controlled path.
2. Domain names and dependency edges are unique and form a DAG.
3. The profile has exactly one user and one group principal marker after all
   material is combined.
4. Framework material is loaded once. A domain cannot smuggle in a second
   framework or principal implementation.
5. The manifest controls source ordering only. Table behavior remains in
   SurrealQL and generated compiler analysis.
6. A single-fragment compile remains useful for syntax probes, but a fragment
   without principals is explicitly a partial material set, not a deployable
   ReBase bundle.

The first migration moves the principal table definitions and their principal
fixture fields out of `designs/test/` into `designs/core/`. Until that move is
made, a transitional test profile may point the principal role at `test`, but
it must not also load a second principal definition. Production and prototype
profiles are explicit files; there is no runtime feature flag that silently
adds test tables.

The compiler CLI should gain a profile option while retaining the existing
single-project option:

```text
node dev-tools/compiler/cli.js --profile profiles/all-in-one.json
node dev-tools/compiler/cli.js --project designs/test
```

The profile build writes `build/all-in-one/schema.surql`,
`runtime-contracts.json`, and the merged handler/webhook trees. Output is
deterministic for a fixed profile and source tree.

## 4. Canonical shared entities

Do not preserve two conceptually identical records merely because they came
from different prototypes. Since the project is not deployed, perform a
direct source rename/refactor and update every reference, view, guard, seed,
fixture, and handler in the same change. Do not maintain compatibility alias
tables.

| Current fragment name | Canonical suite direction | Reason |
| --- | --- | --- |
| `crm.organization` and `accounts.org` | `organization` as the CRM/party record; add a finance profile relation | avoids two organization identities while keeping accounting-specific settings separate |
| `crm.product` and `accounts.item` | `product` as the sellable/stockable item; add cost/service attributes | one product dimension can feed CRM prices, COGS, and warehouse movements |
| `crm.currency` | `currency` for every monetary source and view | one currency catalog and one precision policy |
| `accounts.sl` | `inventory_movement` (or another explicit name) | `sl` is not self-describing and is a cross-domain source fact |
| `accounts.acc` | `ledger_account` | remove an ambiguous abbreviation from the public model |
| `accounts.stock_acc` | `inventory_account` if it remains distinct | preserves the accounting meaning without conflating it with a warehouse |
| `accounts.tax_account` | retain or rename to `tax_account` | already self-describing and referenced by tax lines |

The finance profile is a one-to-one, typed relation from a financial legal
entity to its accounting settings. It is preferable to putting a single
`a_currency` scalar on an unrelated party record. If later requirements prove
that a CRM organization and a legal entity are always identical, the profile
can be folded into `organization` without changing the transaction/view
contracts.

Canonicalization is a schema migration concern, not a runtime alias concern:

1. define the canonical tables and fields;
2. transform any fixture/seed data and references;
3. compile and validate the complete bundle;
4. remove the old declarations;
5. reject old names in compiler collision/unknown-reference checks.

## 5. Declaration ownership and collision rules

Composition must fail early rather than silently producing a different graph.
The compiler should retain source provenance (`domain`, file, statement index)
for every declaration and enforce these rules:

### Tables

- One domain owns each table name.
- A second table definition is an error unless it is an explicit extension of
  the owning table and does not change its table-level policy.
- Identical repeated `OVERWRITE` declarations may be normalized once, but
  conflicting definitions always fail with both source locations.
- Generated framework fields and lifecycle fields are reserved; a domain may
  not shadow them.

### Fields

- Each `(table, field)` has one authoritative definition.
- An extension may add a new field to `user`, `groups`, or another declared
  shared table, but cannot redefine an existing type, `VALUE`, `ASSERT`,
  `REFERENCE`, or permission clause.
- A field name collision in two domains is an error even if the apparent types
  are compatible. Compatibility must be expressed as one shared declaration.

### Indexes, events, functions, accesses, and views

- Names are global within the database and must be unique.
- Exact duplicate definitions are deduplicated only when their normalized
  source is equal; differing definitions fail.
- New domain material should use a domain prefix for internal view/event/index
  names (`v_crm_*`, `e_fin_*`, `idx_hrm_*`) to make ownership visible and avoid
  accidental collisions.
- Generated names include a stable hash only when a readable name would still
  collide; hashes are not used as a substitute for validation.

### Seeds and handlers

- Seed records never rely on source-file lexicographic order. The profile DAG
  and reference graph determine phases.
- A duplicate explicit record ID is an error unless the seed is marked as an
  idempotent bootstrap update.
- Handler table names, webhook route names, and adapter names are checked
  against the merged generated contracts. A handler cannot become available
  merely because another domain imports its file.

## 6. Compilation and dependency order

The current parser already combines material by syntax. The suite compiler
should add a dependency analysis layer without turning SurrealQL into a second
programming language.

### Build phases

1. Load and classify all framework/domain material with provenance.
2. Validate the profile DAG, canonical-name policy, principal markers, and
   declaration collisions.
3. Parse all tables and fields before resolving references; forward table
   references are allowed.
4. Bind framework principal placeholders exactly once.
5. Analyze record-reference edges, ownership/readers edges, effect inputs, and
   view source/group expressions.
6. Emit raw schema and generated reference assertions, permissions, audit,
   timestamps, indexes, and lifecycle fields.
7. Emit direct derived fields before views that consume them.
8. Emit views, then synchronous invalidation events, then async effect events.
9. Emit seeds in dependency batches and copy only validated handlers.
10. Write a deterministic artifact and compare it in `--check` mode.

Schema declaration order is not used as a hidden dependency mechanism. The
compiler may topologically order generated sections, while SurrealDB remains
the authority for actual execution and type checking.

### Cross-domain dependency matrix

The following edges are the minimum suite contract. The listed source field
changes must either recalculate a direct `d_*` shadow or synchronously ping the
dependent record and its old/new aggregate groups.

| Source change | Dependents | Required result |
| --- | --- | --- |
| `user`/`groups` ownership, parent, or reader change | every business row; HRM employment/attendance | authorization indexes and visible aggregate projections converge |
| `organization` identity or finance-profile change | CRM people/opportunities/orders; invoices/payments/taxes; HRM assignments | organization dimensions and guards re-evaluate |
| `product` cost, service flag, currency, or active state | CRM lines; inventory movements; invoice lines; COGS views | cost/service shadows and product groups move |
| `currency` precision or active state; FX rate change | product, opportunity/order, invoice/payment legs, tax lines | no unlike-currency sum; old/new currency groups revalidated |
| opportunity parent/stage/pipeline/organization/currency | quotes, orders, lines, tasks, CRM aggregates | parent constraints and all affected groups refresh |
| quote/opportunity order parent, order date, organization, currency | order lines and daily/monthly views | temporal bucket and organization totals move on parent-only edits |
| warehouse/location or inventory movement quantity/product/package | stock balances, contract lines, finance COGS | negative-stock and contract guards run in the same write chain |
| invoice/line amount, tax, adjustment, currency, or rate | allocations, payment/treasury balances, tax and invoice views | allocation and sign guards cannot be bypassed by editing a child |
| employment effective interval or attendance start/end | attendance day/month/year and employee totals | duration and every old/new time bucket converge |

This table is a design review checklist, not a second runtime registry. The
compiler derives simple edges from typed references and accepts explicit
dependency markers only for expressions it cannot safely infer.

### Dependency metadata

Simple paths such as `line.parent.a_date` can be inferred from typed record
fields. A complex guard or view expression must either be understood by the
existing parser or declare a small explicit dependency marker, for example:

```text
@rebase-depends order.a_order_date
@rebase-depends product.d1_avg_cogs
```

The marker names are validated against the parsed schema. Missing metadata for
an expression that crosses a record boundary is a compile error or a clearly
actionable warning, never a silently stale view.

### Reactive invalidation contract

For every dependency edge, generate the smallest safe synchronous path:

```text
authoritative write
  -> direct d_* fields recalculate
  -> direct-source v_* groups move
  -> old and new group targets receive system_ping
  -> reverse-referenced dependents receive system_ping
  -> dependent d_*/e_* fields recalculate
  -> any failed e_* guard rolls back the complete chain
```

Required generator behavior:

- Use native reverse-reference scans, not broad table scans, for fan-out.
- Deduplicate a target when several fields point to the same record.
- Ping both `$before` and `$after` parents/group keys on updates and deletes.
- Compare the declared source fields in the event `WHEN` clause so unrelated
  updates do not fan out.
- Capture an outer `$this` identity before a nested subquery because SurrealQL
  rebinds `$this` inside that subquery.
- Detect ordinary dependency cycles at compile time. Recursive tree fields are
  allowed only with an explicit cycle guard and a documented traversal bound.
- Keep high-latency provider work asynchronous; a provider call is never used
  as a synchronous graph invariant.

## 7. Domain plans

### 7.1 Shared principal and framework layer

The `user` and `groups` tables remain the single authorization graph. Every
business table receives the generated `owned_by`, `readers_index`, timestamps,
audit policy, and `system_ping` fields. Domain code must not copy these fields
or invent a second permission graph.

Record references continue to carry explicit target unions and native delete
actions. The compiler adds existence assertions for required, optional, and
array references. A hidden or unauthorized target is intentionally treated as
not existing from the record session's perspective.

Views are read-only projections. Their permissions are generated from the
source capability and do not become an authorization shortcut for underlying
rows.

### 7.2 CRM

Keep the mutable graph:

```text
organization/person/product
  -> campaign/pipeline/stage/opportunity
  -> quote -> order -> line
  -> task/activity/note/attachment
```

Master/status tables remain ordinary records. Use `product` and `currency` as
shared dimensions rather than CRM-only copies.

Required repairs before suite acceptance:

- Add direct `d_*` shadows for organization, currency, parent IDs, and order
  event time wherever a view groups or guards on a dereferenced value.
- Replace the raw `created_at` dependency in the opportunity monthly view with
  the framework field after composition, or declare an explicit source event
  time. A standalone fragment must not depend on an absent field.
- Reverse-ping opportunity lines when an opportunity's organization, currency,
  stage, pipeline, or lifecycle changes.
- Reverse-ping order lines when an order date, organization, parent, currency,
  or status changes so daily/monthly views move buckets.
- Revalidate old and new organization/person/product aggregate rows when a
  reference is moved or deleted.
- Define deterministic cascade convergence tests for opportunity deletion and
  line views; do not assume a dereferenced view will repair itself.

CRM monetary values use the shared currency dimension. A raw aggregate may
only sum rows with the same currency and organization dimensions.

### 7.3 Warehouse and inventory

Extract the physical stock model from the account fragment into an explicit
warehouse domain. The first source fact is a mutable `inventory_movement`:

- source and destination are typed polymorphic locations (warehouse,
  inventory account, or contract line where required);
- product/item, quantity, optional package/lot, cost basis, and event datetime
  are authoritative inputs;
- direction, resolved product, effective quantity, and cost value are `d_*`
  fields;
- stock-in, stock-out, product, warehouse, and contract views are `v_*`
  projections.

Guards must reject negative effective stock, invalid external-to-external
  movement, missing product resolution, incompatible contract/package links,
  and quantity beyond a contract line. Corrections remain edits to source facts
  (or new correction facts if a later policy chooses that); the database does
  not become append-only by default.

Dependency edges include product cost/service changes, warehouse/location
changes, package changes, contract quantity changes, and adjustment changes.
Every affected stock bucket and contract guard receives a synchronous ping.

If lots, serials, or expiry dates become necessary, add them as explicit
dimensions or reference tables. Do not hide them in an untyped JSON object that
an incremental view cannot index or validate.

### 7.4 Accounts and finance

Preserve invoices, lines, payments, allocations, taxes, adjustments, and
treasury balances as mutable calculation records. Repair the current graph
before adding higher-level reporting.

#### Currency model

Use one `currency` catalog and make currency a dimension of every monetary
source row. A finance profile stores an organization's functional currency;
that setting is not a substitute for a transaction currency.

Each monetary source must state, as applicable:

- transaction currency and amount;
- functional/base currency and derived amount;
- rate source, effective datetime, and rounding policy;
- whether the rate is a mutable estimate or a future locked snapshot.

A transfer with different currencies uses two typed payment legs (or an
equivalent explicit pair), not one `a_currency` chosen with `??`. Views group
by organization, account, and currency before any conversion. Currency gain or
loss is a derived calculation from the two legs and the selected rate policy;
unlike-currency amounts are never summed directly.

#### Required reactive repairs

- A line quantity/price/adjustment change must re-run the invoice allocation
  guard, not only an explicit invoice update.
- Payment amount, direction, currency, or rate changes must revalidate all
  allocations and treasury targets.
- Invoice currency/rate changes must move/revalidate old and new currency
  aggregate groups.
- Product cost changes must refresh COGS on dependent invoice and movement
  lines.
- Tax rate/account and adjustment target changes must refresh tax, invoice,
  and note aggregates.
- Organization/finance-profile changes must ping all dependent monetary rows.

Keep direct shadows such as line organization, currency, vector, and effective
rate where they are used as view group keys. This makes dependency edges
explicit and avoids stale multi-hop dereferences.

### 7.5 HRM

Add a small HRM fragment around the existing `user` principal rather than
creating a second employee identity. The first slice should contain only the
facts needed to prove the architecture:

- an employment/assignment record linking a user to an organization or team,
  with effective dates and a mutable lifecycle;
- an attendance source record with employee, event/start/end datetimes,
  optional location/shift reference, and a derived non-negative duration;
- optional leave/absence source records only when a concrete workflow requires
  them;
- day/month/year (and later hour/week if supported by the declared policy)
  aggregate views over direct event-time shadows.

Attendance writes are owned by the employee or assigned owner according to the
normal graph policy, but update/delete may be restricted to ancestors by a
table-level permission override. This is a generated policy/marker decision,
not a frontend branch and not a special authentication state.

Guards cover end-before-start, invalid effective employment, duplicate/overlap
policy where required, and non-negative duration. Corrections ping every old
and new time bucket and employee/organization aggregate.

Do not model payroll or statutory rules as hidden computed fields in this first
pass. Add each as an explicit source/derivation/view chain after its invariant
and repair behavior has a probe.

### 7.6 Test and external-effect material

Keep `designs/test` as the broad contract fixture. It verifies scalar,
optional, JSON, enum, record, record-array, polymorphic, recursive, credential,
sync-effect, async-effect, schedule, and webhook behavior in the composed
principal context.

Effect tables remain isolated from business calculations:

- configuration rows own tenant/provider credentials;
- handlers receive only their declared references and named adapters;
- output/provider/lifecycle fields remain machine-owned;
- queue locators retain `{ namespace, database, id }`;
- a cron action may create or wake a declared effect, but may not call an
  arbitrary function name from a client payload.

## 8. Temporal views and calculation crons

### 8.1 Temporal view contract

Every temporal view declaration records:

- source table and direct event-time field;
- bucket unit supported by the pinned engine (`year`, `month`, `day`, `hour`,
  `minute`, or `second`);
- UTC or an explicit business-timezone policy;
- group dimensions and measures;
- treatment of empty, null, and missing values;
- repair/rebuild strategy.

`time::group` accepts a datetime and normalizes instants to UTC. It does not
accept `week` or `quarter` in the tested engine and has no timezone argument.
For tenant-local calendar semantics, normalize/persist a business bucket and
its zone before materialization; never silently label a UTC bucket as local.

Use half-open windows `[from, to)`. A `first` selection means:

```surql
ORDER BY event_time, id LIMIT 1
```

The ID tie-break is mandatory; an unspecified first row is not deterministic.

Supported incremental statistics are limited to functions the engine can
maintain for a materialized view (`sum`, `mean`, `min`, `max`, `variance`, and
`stddev` in the pinned probe). Median/percentile-style statistics are ordinary
queries or scheduled recomputations until a separate incremental algorithm is
proven. Existing groups make reads cheap, but writes still pay view/index
maintenance and fan-out; do not describe every aggregate operation as O(1).

### 8.2 Calculation cron table

Keep external-effect schedules and calculation/report schedules as separate
concepts. Add one typed calculation-cron table (name to be finalized, for
example `calculation_cron`) with fields equivalent to:

- `target_descriptor`: a generated enum/key for a compiled source table or
  temporal view;
- `event_time_field`: a generated field key valid for that target;
- `window`: validated `from`, `to`, unit, and optional lookback;
- `selection`: currently `first`, with a deterministic tie-break;
- `action`: a compiler-declared action key (report, consolidation, or effect
  submission);
- schedule lifecycle, owner, cursor/watermark, and last-run result.

The client may choose among generated descriptors, but cannot submit an
arbitrary table, field, function, or SurrealQL fragment. The runtime resolves a
descriptor to a static query shape and binds only values. This keeps the
system a superset of future use cases without creating a dynamic code
execution surface.

At a due time the scheduler:

1. claims one cron occurrence idempotently;
2. resolves the descriptor from the compiled profile;
3. queries the authorized/privileged target for the declared half-open window;
4. selects the deterministic first row (or records `empty`);
5. invokes the declared action with a bounded record locator/payload;
6. records success, failure, retry, or an ambiguous external outcome;
7. advances the watermark only after the action's acceptance contract is met.

A unique run key such as `(cron, window_start, window_end, action)` prevents
duplicate occurrence records. Reconciliation may retry a run; it must not
create a second logical result accidentally. Late source writes are handled by
an explicit lookback/repair policy, not by silently changing historical
buckets.

### 8.3 Table existence and `SELECT` boundaries

There is no record-user-safe generic `table::exists()` function in the pinned
engine. `type::table()` is a cast. A dynamic `SELECT` errors for a missing
table but returns an empty result for an empty or caller-hidden table.

Use these boundaries:

- startup/migration checks: privileged `INFO FOR DB` against the static
  profile's expected table set;
- record sessions: only compiler-declared target tables and views;
- cron selection: generated descriptor allowlist, never arbitrary identifiers;
- UI capability discovery: a separately authorized generated capability
  document, not catalog introspection.

A nested `SELECT` inside `VALUE` or `ASSERT` is legal and remains in the same
transaction. It does not commit or break the mutation. If a guard needs to
prove cardinality, compare it explicitly, for example:

```surql
array::len((SELECT VALUE id FROM parent WHERE id = $candidate)) > 0
```

Reading rows and then unconditionally returning `true` only proves that the
query did not error. It is not an existence or table-select check. Nested
subqueries also rebind `$this`; capture the outer ID before entering one.

## 9. Permissions and integrity ownership

The generated framework remains the only authorization layer:

- table permissions decide select/create/update/delete capability;
- ownership, dominated principals, and readers decide row visibility;
- field permissions protect machine fields and credentials;
- typed references and native delete actions protect graph topology;
- `e_*` guards enforce resulting business state.

The HRM ancestor-only write case is represented as a table policy override
(for example, update allowed only to an owner ancestor), not as a special
frontend rule. The same pattern applies to finance corrections, stock
adjustments, or admin-maintained master data.

Generated permissions must use indexed exact lookups wherever possible. A
permission subquery may be used for a business check, but it must not be a
hidden catalog scan or an attempt to infer whether a caller can select another
table.

## 10. Rebuild, repair, and bulk data

Materialized views and `d_*` fields are derived state and must be rebuildable.
The suite needs a bounded repair command with these modes:

- rebuild one view or dependency component;
- rebuild one table's derived fields;
- rebuild a time range and dimension subset;
- verify source-to-view totals without writing;
- resume after interruption from a keyset cursor.

Bulk import deliberately does not pretend that ordinary per-row events ran.
The importer therefore:

1. loads reference/master rows in dependency batches;
2. loads source facts with `RETURN NONE` and keyset pagination;
3. runs the declared derived/view rebuild;
4. runs all affected `e_*` verification queries;
5. reports mismatches and refuses to mark the profile healthy until repaired.

Seeds and fixtures use generated record IDs. The only fixed identity in the
suite bootstrap is the declared root group anchor; all other references come
from committed records or deterministic lookup keys.

## 11. Compiler and tool changes (implementation sequence)

This is the smallest practical implementation sequence. Each step must remain
usable and testable before the next one lands.

### Phase A: composition and diagnostics

1. Add profile parsing/validation and multi-domain provenance to
   `dev-tools/compiler/materials.js` and the CLI.
2. Extend `pipeline.js` to combine ordered domain roots, discover one principal
   pair, and emit a single artifact.
3. Add declaration collision diagnostics with source locations.
4. Make `populate.js` and `workbench.js` accept a profile/build name and use
   the profile's seed/data roots.
5. Add deterministic profile and collision contract tests.

### Phase B: canonical shared graph

1. Extract `user` and `groups` into `designs/core/`; leave only optional test
   relations/effects in `designs/test/`.
2. Rename/merge `org`/`organization`, `item`/`product`, and `sl` into the
   canonical model described above.
3. Introduce the finance profile, currency dimensions, and explicit monetary
   fields.
4. Split account view/event material from the misleading seed file.
5. Update all references, views, fixtures, and guards in one source change.
6. Compile and validate the complete CRM + warehouse + accounts graph before
   adding HRM.

### Phase C: dependency analysis and reactive generation

1. Extend schema analysis with business dependency edges, not only reader
   references.
2. Add validated dependency markers for expressions that cannot be inferred.
3. Generate direct `d_*` shadows and reverse invalidation events.
4. Revalidate old/new aggregate keys on moves, updates, and deletes.
5. Add cycle diagnostics and explicit recursive-tree handling.

### Phase D: HRM and temporal contracts

1. Add the minimal employment/attendance source tables and permissions.
2. Add direct event-time shadows and day/month/year views.
3. Add the typed calculation-cron table, descriptor metadata, idempotent run
   records, and scheduler action adapter.
4. Keep provider-effect scheduling on the existing effect lifecycle path.

### Phase E: data, repair, and verification

1. Add dependency-aware fixtures for every domain and field family.
2. Add rebuild/repair tooling and interruption recovery.
3. Run the cross-domain mutation matrix and on-disk scale suite.
4. Only after all backend contracts pass, expose the generated resource/view
   metadata to MetaSol.

## 12. Verification plan

### Static/compiler contracts

- profile paths, names, dependency DAG, and exactly one principal pair;
- duplicate table/field/index/event/view/function/access rejection;
- canonical-name and reserved-generated-field checks;
- dependency marker resolution and cycle diagnostics;
- deterministic output and copied handler parity;
- generated view permissions, references, and adapter contracts;
- query-result helpers always use the final statement (`.at(-1) || []`).

### Disposable on-disk SurrealDB integration

Run against temporary on-disk RocksDB stores, never an in-memory store for the
performance suite. Use two namespace/database contexts and verify:

- principal authorization and cross-context isolation;
- CRUD and strict reference behavior for every composed base table;
- CRM parent moves/deletes and temporal bucket updates;
- warehouse movement, corrections, negative-stock rollback, and product-cost
  propagation;
- invoice/payment/allocation/tax/adjustment guards and currency separation;
- HRM attendance duration, ownership, ancestor writes, and bucket updates;
- empty/hidden/missing table behavior and privileged catalog checks;
- cron window boundaries, first-row tie-break, idempotent runs, retry, and
  late-data repair;
- sync/async effect lifecycle, webhook correlation, and provider output
  immutability;
- audit/change-log visibility and rollback of a failed synchronous chain.

### Reactive negative tests

For each dependency edge, perform both a valid and invalid mutation. Assert
that a failed child write leaves the source row, all view rows, pings, and
parent guards exactly as they were. For a move, assert both the old and new
aggregate groups. For a delete, assert reference action, view convergence, and
repair behavior.

### Scale and performance gates

Generate rich, skewed real-life-like data in batches with a reproducible seed:

- low-cardinality hot groups and high-cardinality sparse groups;
- deep principal and parent chains;
- many-to-one and many-to-many fan-out;
- skewed currencies, products, dates, and attendance intervals;
- concurrent edits to the same aggregate keys;
- deletes and moves that exercise old/new invalidation.

Measure, at each feasible tier (for example 10k, 100k, 1m, 10m and larger
only when hardware permits):

- p50/p95/p99 write and read latency;
- synchronous fan-out count and transaction conflict/retry rate;
- CPU, RSS, network bytes, datastore bytes, index/view amplification;
- repair throughput and time-to-convergence;
- hot-key contention and worst-case bucket size.

The test harness must generate bounded batches and keyset pages, avoid one
request per record, suppress unused result serialization, and stop before host
memory exhaustion. A benchmark report must separate engine measurements from
product budgets; no claim that the graph is universally O(1) is accepted.

### Required commands before adoption

```bash
npm run check
surreal validate build/all-in-one/schema.surql
node dev-tools/compiler/cli.js --profile profiles/all-in-one.json --check
npm run probe:compiler
npm run probe:architecture
npm run probe:reference-permissions
npm run probe:runtime
npm run probe:adapters
npm run probe
npm run verify
git diff --check
```

Add a suite-specific compile/integration/performance command rather than
silently changing the meaning of the existing `test` profile.

## 13. Definition of done

The all-in-one suite is ready for prototype use when:

1. one profile compiles framework, `core` principals, CRM, warehouse, accounts,
   and the minimal HRM fragment (with the test contract as an explicit optional
   domain) without collisions or hardcoded deployment identity;
2. every cross-domain reference resolves through strict typed fields and
   native delete semantics;
3. every indirect view/guard dependency has a direct shadow or an explicit
   generated reverse ping;
4. valid mutable corrections converge synchronously, and invalid corrections
   roll back atomically;
5. currency aggregates never mix dimensions and temporal buckets have a stated
   timezone/window policy;
6. calculation crons can select only compiled targets and produce idempotent,
   bounded runs;
7. bulk import followed by repair reproduces the same derived state as ordinary
   writes;
8. permission, authentication, effect, webhook, and cross-context probes pass;
9. on-disk performance reports identify actual bottlenecks and remain within
   agreed resource budgets;
10. MetaSol can later consume one generated suite descriptor instead of
    maintaining a second copy of the domain graph.

## 14. Decisions deliberately rejected

- A global immutable/accounting ledger: conflicts with the mutable calculation
  graph and makes corrections needlessly expensive.
- A dynamic table/function name from cron input: unsafe and impossible to
  authorize reliably in a record session.
- `SELECT` plus unconditional `RETURN true` as table existence: it does not
  distinguish empty, hidden, and missing data and does not break a transaction.
- A second organization/product/currency dimension per domain: creates silent
  joins and inconsistent aggregates.
- A generic configuration/plugin graph in the compiler: adds indirection while
  the suite has a small, statically known set of domains.
- Treating materialized view reads as free O(1) work: writes still pay
  maintenance, fan-out, conflicts, and storage amplification.
