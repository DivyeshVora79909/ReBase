# Accounts Movement Architecture Plan

Status: Accounts kernel implemented in `designs/all-in-one/accounts/`, including
synchronous effective-time prefix replay. Checkpoint/budget optimization and
additional domain composition remain planned.
Cross-currency exchange is represented by an explicit two-leg `money_exchange`
fact; ordinary `money_movement` is intentionally same-currency.
Last reviewed: 2026-09-08

This plan replaces the current Accounts fragment as the design target. It is
intentionally limited to the calculation core: money, inventory, service
capacity, currency and FX, tax components, claims, settlement, adjustments,
and the reactive integrity machinery that connects them. CRM, HRM,
communications, ecommerce, manufacturing workflows, and MetaSol changes are
out of scope for this implementation pass.

The engine findings that constrain this plan are in
[`../surrealdb/accounts-transaction-concurrency-fact-check.md`](../surrealdb/accounts-transaction-concurrency-fact-check.md).
The wider composition rules remain in
[`all-in-one-suite-plan.md`](./all-in-one-suite-plan.md) and
[`calculation-engine-expansion-plan.md`](./calculation-engine-expansion-plan.md).

## 1. Product contract

ReBase Accounts is a mutable reactive calculation graph, not an immutable
statutory ledger and not a generic CRUD transaction table.

The database owns:

- typed graph references and delete behavior;
- deterministic derived fields and aggregate projections;
- synchronous guards that reject an invalid resulting graph;
- current resource positions used as write conflict boundaries;
- revisions and bounded replay where effective-time history matters.

The client owns the business choice of which valid facts to enter. The client
does not own the integrity algorithm, cumulative balance arithmetic, currency
compatibility checks, or tax propagation.

The central distinction is:

```text
resource position       = what is currently available or owed
movement fact            = what changed a position
claim/component          = what a document or tax rule says is due
settlement               = a monetary movement that pays a claim
context/wrapper          = a user-facing relationship and optional lock
```

### 1.1 Primitive algebra

The kernel should calculate a small number of explicit position equations.
These equations are more stable than document names and keep the system open
to client-specific wrappers:

| Primitive | Current position | Source facts that change it |
| --- | --- | --- |
| monetary resource | `opening + inbound - outbound` | `money_movement`, `money_exchange` legs, money adjustments, refunds |
| inventory resource | `opening + received - issued` | `inventory_movement`, returns, stock adjustments |
| service capacity | `granted - delivered` | `service_capacity`, `service_delivery`, capacity adjustments |
| claim / receivable | `assessed - settled - reversed` | invoice lines, tax components, applications, refunds |
| tax assessment | `taxable_base * rate + adjustments` | tax input/output rows and tax adjustments |

These are not interchangeable signs. A positive tax output is an assessment
against a customer or authority; it is not itself a cash outflow. A payment is
an execution that reduces a claim and changes a monetary position. A return or
refund reverses an earlier execution subject to its source cap; it does not
rewrite the original fact.

This gives the graph a clean dependency direction:

```text
resource movement -> position
document line      -> claim
tax component      -> tax assessment + claim shadow
settlement         -> claim reduction + monetary movement
reversal           -> bounded counter-movement
```

The position tables are therefore the small writable concurrency anchors, while
claims and tax projections remain derived/contextual views over source facts.
No single `asset_or_liability` enum is needed to make these relationships
work; endpoint kind, movement family, and signed delta are enough.

Assets and liabilities are classifications of positions and projections. They
are not a reason to force every domain into one universal movement table.
Cash, stock quantity, and service capacity have different invariants, so they
share conventions but remain separate movement families.

## 2. Decisions at a glance

| Concern | Adopted direction | Why |
| --- | --- | --- |
| Money inbound/outbound/internal | one `money_movement` fact with typed endpoints | same-currency conservation rule; direction is derived from endpoints and signed deltas |
| Cross-currency exchange | `money_exchange` with two explicit amounts and an `fx_rate` snapshot | each currency position receives an unambiguous leg; no scalar rate is smuggled into a one-currency movement |
| Inventory inbound/outbound/internal | one `inventory_movement` fact with typed endpoints | quantity conservation is shared; wrappers can describe delivery or production |
| Services | separate `service_delivery` and `service_capacity` | services consume capacity, not owned stock; no fake anonymous receipt is needed |
| Refund | separate `money_refund` referencing the original payment/movement | cap and provenance differ from an ordinary transfer |
| Return | separate `inventory_return` referencing the original delivery movement | quantity cap and source semantics differ from an ordinary transfer |
| Adjustments | common note wrapper, family-specific adjustment lines | preserves normalization without a giant conditional guard |
| Currency | first-class `currency` table and typed reference | custom units, precision, display metadata, and FX need identity |
| Tax | granular input/output components attached to taxable lines | tax is additive assessment/liability, not a divisor or automatic payment |
| Current balance | mutable `position_state` row | views are read-only; the row provides atomic OCC and assertions |
| Historical validity | generated replay policy for selected partitions | a current total cannot prove old prefixes |
| Context links | singular typed references for integrity; optional arrays for provenance | avoids hiding critical relationships in an unbounded context array |
| Deleted records | audit/revision history, not duplicate deleted tables | keeps one canonical calculation path and avoids state-lane drift |

## 3. Canonical primitives

Names below are recommendations, not a requirement to preserve the current
abbreviations (`org`, `acc`, `sl`). The implementation should use explicit,
self-describing names and remove the old declarations in the same migration.

### 3.1 Party and currency

`organization` is the external party/legal identity used by Accounts. It is
not automatically a balance-bearing account. A separate finance profile can
bind defaults such as a reporting currency without putting accounting state
on a CRM identity.

The implemented `organization_finance_profile` is a one-per-organization
metadata row with functional and optional reporting currency references. It is
deliberately advisory: no movement, position, invoice, or exchange reads it to
fill a missing currency.

`currency` is a catalog record, not an enum. Minimum fields:

```text
code / name
minor_unit_precision
display metadata
active
```

The record represents a unit of measure. Its existence does not imply an
exchange value. A client may define INR, USD, BTC, points, or a private unit.
Every balance-bearing monetary position and every monetary movement must carry
an explicit currency reference. Do not use a company default or a `??` chain
to infer the currency of a transfer.

`fx_rate` is an optional snapshot record containing:

```text
base_currency
quote_currency
rate
effective_at
source / policy / rounding
```

An FX rate is a fact used by one `money_exchange` or valuation. It is not a
mutable global scalar silently applied to historical rows.

### 3.2 Monetary endpoints

The implemented slice keeps endpoint tables semantically distinct while
using a polymorphic union at movement edges:

```text
treasury_account
misc_account
organization
```

`treasury_account` is a guarded owned position and has exactly one currency.
`misc_account` is a flexible client-defined offset/account; if it stores a
balance, it also has exactly one currency. An unbalanced classification can be
represented as a context on a movement, but it must not masquerade as a
multi-currency position.

`organization` is an external endpoint. A receivable or payable projection
can be derived from claims and settlements without pretending that the
organization owns the application's treasury balance.

The endpoint field can use:

```surql
record<treasury_account | misc_account | organization>
```

with an explicit `record::tb()` branch. The branch determines whether a
negative-result guard, currency match, or external-party rule applies.

Do not permit every syntactically valid union pair. The movement guard should
declare the allowed endpoint matrix (for example, treasury-to-organization,
organization-to-treasury, treasury-to-treasury, and treasury-to-misc). An
organization-to-organization transfer is normally rejected unless a separate
business operation explicitly defines it.

Tax input/output rows are not required to be monetary endpoints. They become
claims/projections until a client explicitly creates a tax settlement movement.

### 3.3 Inventory and service primitives

Use `operating_unit` as the generic container concept. A physical warehouse,
office, branch, or service-delivery location can be represented by a typed
operating unit profile. If physical location rules later need their own
identity, add `inventory_location` below it rather than overloading
`warehouse` with service semantics.

Keep `item` and `service` as separate catalog tables:

- `item` can have units, lots, serials, cost, and stock positions;
- `service` can have duration, skill, capacity, and delivery limits;
- document lines may use `record<item | service>` only where the two meanings
  genuinely share a line contract;
- every derived expression must branch explicitly on `record::tb()`.

`service_capacity` is a positive entitlement/limit keyed by
`operating_unit + service` (and any declared period). It is not an inbound
service from an anonymous party. Consumption is represented by
`service_delivery`, and the guard is:

```text
consumed quantity <= granted capacity
```

## 4. Movement families

### 4.1 Monetary movement

Canonical table: `money_movement`.

Required concepts:

```text
from_endpoint / to_endpoint
amount
currency
effective_at (READONLY)
recorded_at (machine-owned)
optional fx snapshot or explicit second leg
optional integrity-critical context
```

Inbound, outbound, and internal transfers are not separate source tables. A
single movement is easier to aggregate and gives the database one conservation
rule. Direction is derived from endpoint kinds and the signed effect on each
position.

Cross-currency movement must not be represented by one ambiguous amount and a
scalar rate. The kernel uses `money_exchange` with explicit source and
destination amounts, currencies, and one immutable FX snapshot. It is a
separate fact from `money_movement`, which remains a same-currency conservation
operation. This keeps each position delta unambiguous and lets views group by
currency before conversion; rounding, fees, and client policy remain visible in
the two authoritative amounts rather than hidden in a scalar multiplication.

The transaction currency is a fact on an ordinary movement and must match every
position endpoint it touches. An exchange carries one currency per leg. A view
may report a base-currency equivalent, but it must never add unlike raw
currencies into one balance.

An ordinary movement must satisfy:

- endpoints exist and are an allowed pair;
- endpoints are not the same position unless the movement is explicitly a
  no-op-free correction;
- amount is positive at the fact level;
- currency and FX fields are compatible;
- every guarded position remains valid after both deltas.

### 4.2 Inventory movement

Canonical table: `inventory_movement`.

Required concepts:

```text
from_node / to_node
item
quantity
optional unit valuation and currency snapshot
effective_at (READONLY)
optional delivery/invoice context
```

Inbound, outbound, and internal stock movement use the same conservation
shape. The endpoint union may include `operating_unit`, `organization`, and a
client-defined `misc_stock_node`. The guard applies only to nodes that own a
non-negative stock position.

Manufacturing should not create a second arithmetic engine. A future
`production_run` wrapper can reference consumption and production movements;
the movement facts remain ordinary inventory facts. A scheduled consolidation
may be added later, but ordinary stock acceptance stays synchronous.

The old `sl` name should be removed in favor of `inventory_movement` (or a
similarly explicit name) throughout views, guards, seeds, and contracts.

### 4.3 Service delivery and capacity

Canonical tables:

```text
service_capacity
service_delivery
```

There is no required `service_inbound` fact. A service offered by an
operating unit is a delivery/consumption fact. A client may record an external
expense or purchase as a monetary/misc movement, but that does not create
service stock.

The capacity row acts like a constrained position:

```text
remaining = granted - consumed
```

The mutable `position_state` for this key is guarded against a negative
remaining value. A limit change is a capacity fact and is replayed through the
same position; it is not a fake receipt from an anonymous endpoint.

## 5. Position state and reactive write path

Every guarded movement family gets a generated mutable position row. Suggested
keys are deterministic composite IDs:

```text
money_position       = endpoint + currency
inventory_position   = operating_unit + item (+ lot/package when required)
service_position     = operating_unit + service (+ period when declared)
```

The row stores machine-owned values such as:

```text
available / balance
revision
total_in / total_out
last_replayed_effective_at
rebuild_status (only when a repair lane is needed)
```

The generated write path is:

```text
create/update/delete movement
  -> recalculate direct d_* fields
  -> synchronous event computes the delta
  -> update every affected position_state row
  -> position ASSERT checks current invariant
  -> materialized views refresh
  -> view/dependency events ping affected wrappers and claims
  -> commit, or roll back the entire chain
```

The position update is semantic, not a random ping. It changes the balance and
revision in the same transaction, giving SurrealDB a real write-write conflict
boundary. Materialized views remain read-only projections and are never used
as writable locks.

For a movement with multiple endpoints, generated code must update anchors in
a canonical order (for example sorted by stable record ID) and use a
deterministic movement ID. This reduces conflict churn and makes retries safe.

The position is rebuildable state, not an excuse to discard source facts. A
reconciliation descriptor must be generated for each position family:

```text
source table, partition key, signed delta, view names, guard, repair action
```

The implemented slice supports mutable money amounts, inventory quantities,
opening balances, service quantities, refunds, returns, and adjustment deltas.
Each edit applies an inverse old value and a new value to the same position
anchor; `effective_at`, endpoints, item/service identity, and idempotency keys
remain immutable.

## 6. Current-state versus effective-time integrity

The system needs two explicit policies rather than one misleading promise.

### 6.1 Current-state policy

Use for facts where only the present graph matters. A position update and an
aggregate view are sufficient. CRM-like wrappers and exploratory client
calculations can use this policy.

### 6.2 Effective-replay policy

Use for treasury balances, guarded inventory, service capacity, and any
movement where inserting or editing an old business date must not invalidate
an earlier prefix silently.

Each replay-enabled table declares:

```text
partition key
effective_at field
deterministic tie-break
signed delta expression
invalid prefix predicate
synchronous work budget
revision/history requirement
```

On a create, delete, or amount/endpoint edit, the generated event:

1. captures the old and new partition keys;
2. writes a machine-owned revision snapshot when required;
3. selects the affected ordered suffix;
4. folds `{ total, minimum_prefix }` with `array::fold`;
5. rejects a negative/over-limit prefix;
6. updates the current position and aggregate projections.

If the suffix exceeds the synchronous budget, the write must be rejected or
enter an explicit repair-needed result. It must not claim validation succeeded.
Checkpoint rows and block summaries are a later optimization, not a hidden
engine feature.

`effective_at` is immutable. `recorded_at` and audit/revision metadata capture
when the system observed the correction. This separates client chronology from
system chronology and prevents ambiguous in-place reordering.

## 7. Claims, invoices, settlement, and reversals

### 7.1 Invoice as a claim wrapper

`invoice` and `invoice_line` are user-facing claim/context tables, not a second
balance engine. A line references exactly one `item | service`, organization,
currency, quantity/price, and tax components. Its derived gross/net values
feed claim projections.

An invoice may have a mutable `locked` flag. When locked, direct line and tax
edits are rejected; corrections use adjustment facts. The lock is a wrapper
policy, not a global immutability rule.

Child rows should carry direct derived organization/currency shadows used by
views and guards. A child guard compares its organization to the invoice's
organization. Parent changes trigger generated reverse invalidation; a hash is
not needed as an integrity proof.

### 7.2 Payment application

Keep a many-to-many settlement edge, named `payment_application` (the current
`payment_allocation` concept is sound). A payment can settle multiple claims,
and a claim can receive multiple payments. The edge stores the amount and
currency actually applied, with an explicit conversion snapshot when needed.

The guards enforce:

```text
sum(applications to payment) <= payment amount
sum(applications to invoice) <= invoice net/gross claim after adjustments
direction and organization are compatible
```

An optional invoice context directly on a payment may help UI filtering, but it
must not replace the allocation edge.

### 7.3 Refund and return

Use separate execution tables:

```text
money_refund
inventory_return
```

`money_refund` references one original payment/movement and carries an amount
and effective time. A view of prior refunds enforces:

```text
total refunds <= original payment amount
```

`inventory_return` references one original delivery movement (or delivery
line) and enforces returned quantity <= delivered quantity minus prior
returns. A return is not merely an unrestricted negative inventory movement,
because its source linkage and cap are part of its meaning.

Both references should use `ON DELETE REJECT` while the execution exists. If a
client needs to retain a historical explanation after deleting a source, copy
an opaque provenance snapshot into audit rather than dereferencing a dangling
record.

### 7.4 Adjustments

Retain a reusable `adjustment_note` wrapper with an organization and optional
lock. Use family-specific lines:

```text
money_adjustment_line
inventory_adjustment_line
tax_adjustment_line
```

Each line has one target, signed delta, and a unique `(note, target)` key. The
target reference is polymorphic within its family, not one giant union of
every Accounts table. This keeps the graph highly normalized while allowing
each guard to express the correct cap and sign rules.

Adjustments remain mutable under client permissions. A locked note prevents
edits to its child lines; an audit/revision record explains later corrections.

## 8. Tax as a composable assessment

Do not model tax as a divisor, a hardcoded company setting, or an automatic
payment account.

Canonical primitives:

```text
tax_rule       = client-selectable metadata (rate/formula/category)
tax_input      = one assessed component on one taxable line
tax_output     = one assessed component on one taxable line
```

Input and output remain separate tables because their liability direction and
reporting meaning differ. They share a generated field descriptor, not a
runtime polymorphic mega-guard.

Each component stores or derives:

```text
taxable target line
tax rule reference
rate and calculation basis
untaxed base snapshot or derivation
tax amount
currency
effective_at
```

Tax is additive:

```text
gross = untaxed base + tax components
```

The invoice line receives aggregate tax shadows; the tax row receives its own
share and can be corrected through a tax adjustment line. Tax input/output
views show claims/liabilities and information. A later tax settlement is an
ordinary money movement with explicit context; it must not mutate the tax
assessment into a payment.

The first plan supports VAT/GST-like rates and arbitrary client-defined tax
rules. TDS/TCS-like withholding can be represented as a distinct rule and
directional component once its business semantics are specified; no country
compliance interpretation is hidden in the kernel.

## 9. References, context, and deletion

Use a singular typed reference for every relationship that affects a guard or
aggregate:

```text
invoice_line.invoice
payment_application.payment
payment_application.invoice
money_refund.original_payment
inventory_return.original_movement
tax_input.target_line
tax_output.target_line
```

Choose delete behavior deliberately:

```text
REJECT = source is required for integrity
CASCADE = child has no meaning without parent
UNSET = optional context may survive without target
```

An optional heterogeneous `contexts` array is allowed only for provenance,
search, or UI explanation. It uses `ON DELETE UNSET` (or an opaque origin), is
never dereferenced by a core guard, and never replaces an allocation,
refund-source, return-source, or tax-target field.

Every authoritative reference also gets an explicit existence assertion where
input dangling IDs would otherwise be accepted. A reference type alone is not
an existence guarantee.

## 10. Aggregates and dimensional control

Maintain only projections that are either:

1. required by a synchronous guard;
2. a repeated operational read; or
3. a declared temporal reporting contract.

Initial required projections are:

```text
money position by endpoint + currency
inventory position by operating unit + item (+ lot when required)
service remaining capacity by operating unit + service
payment applications by payment and invoice
refund totals by original payment
return totals by original movement
tax totals by target line and input/output direction
claim totals by organization + currency
```

Do not build a full organization x item x service x currency x tax x time
cube. A fact may carry all relevant dimensions, while views remain sparse and
purpose-built. Add a two-dimensional view only when a guard or known query
needs it. Higher-dimensional reporting can select from lower-dimensional
positions and source facts.

Use direct `d_*` shadows for group keys (`d_currency`, `d_organization`,
`d_item`, `d_effective_bucket`). A view that reaches through a parent record
does not automatically react to a parent field edit; the compiler must emit a
reverse invalidation event or use a direct shadow.

## 11. Lifecycle, permissions, and audit

Do not create duplicate deleted/inactive tables for Accounts in this phase.
The canonical rows remain mutable; audit/revision rows retain the prior state
where history matters. A wrapper may have a simple `locked` or `voided` field
when that state changes participation, but every view must explicitly filter
it and every transition must be guarded.

Permissions remain independent from accounting semantics:

- table permissions decide who may create/update/delete a fact;
- field permissions protect machine-owned `d_*`, `e_*`, revision, and position
  fields;
- guards enforce graph and numeric integrity for every writer, including
  privileged/admin writers;
- frontend hiding is not a security boundary.

No user-supplied table name, target function, or arbitrary context reference
may become executable query text. Compiler descriptors own the allowed tables,
movement families, and repair actions.

## 12. Implementation phases

Phases 1-4 are represented by the current all-in-one Accounts schema, views,
events, and disposable probe. The current write path uses mutable position
anchors for OCC, direct outer-ID captures inside nested VALUE queries, and
explicit reverse invalidation. The historical-prefix part of Phase 5 is now
implemented: `position_entry` rows and a synchronous table event fold each
affected partition on create/update/delete and reject a negative guarded
prefix. `effective_at` is immutable. Checkpoint rows, a bounded work budget,
and a repair/rebuild command remain future work; the current fold is exact but
proportional to the affected partition.

### Phase 0: freeze the evidence boundary

- Check in the focused raw-material probe or fold its assertions into the
  architecture probe.
- Pin the SurrealDB/SDK versions used by CI.
- Add regression cases for view read-only behavior, view-event rollback,
  position conflicts, two-leg atomicity, reference cleanup, and replay.

### Phase 1: canonical primitives

- Rename `org`, `acc`, `sl`, and other ambiguous public names.
- Add `currency`, explicit endpoint currency, and FX snapshot primitives.
- Split `item` and `service`.
- Add `operating_unit`, `service_capacity`, and `position_state` descriptors.
- Move view/event declarations out of seed material.

### Phase 2: movement kernel

- Replace payment variants with `money_movement` and generated endpoint
  branches.
- Replace `sl` with `inventory_movement`.
- Add `service_delivery` and capacity guards.
- Generate position IDs, delta events, assertions, and reconciliation metadata.
- Require deterministic IDs/idempotency keys for movement writes.

### Phase 3: claims and settlement

- Rebuild invoice/invoice-line wrappers over item/service lines.
- Add `payment_application` as the canonical many-to-many settlement edge.
- Add `money_refund`, `inventory_return`, and family-specific adjustments.
- Generate parent/child organization and currency invalidation paths.

### Phase 4: tax composition

- Add `tax_rule`, `tax_input`, and `tax_output`.
- Propagate tax components to line and claim projections.
- Add tax adjustment guards and tax settlement context without conflating
  assessment with payment.

### Phase 5: temporal policy

- Mark treasury, inventory, and capacity partitions as replay-enabled.
- Add immutable `effective_at` and deterministic `position_entry` facts.
- Run synchronous ordered `array::fold` replay from a native position-table
  event; reject guarded negative prefixes atomically with the source write.
- Add recorded-time revision snapshots, an explicit rebuild-needed outcome,
  and checkpoint/block-summary experiments for hot partitions in a later pass.

### Phase 6: verification and cleanup

- Run schema/compiler/runtime checks and disposable on-disk Accounts fixtures.
- Verify concurrent deterministic creates and retry behavior.
- Verify late inserts, edits, deletes, refunds, returns, tax adjustments, FX,
  and cross-organization rejection.
- Remove the old Accounts declarations and stale view/event names.
- Do not modify MetaSol/frontend in this pass.

## 13. Verification matrix

| Capability | Required proof |
| --- | --- |
| Currency | unlike currencies cannot be summed or transferred without explicit FX |
| Money | source/destination positions update atomically; treasury cannot go negative |
| Inventory | stock position cannot go negative; internal transfer conserves quantity |
| Service | delivery cannot exceed capacity; capacity edits replay correctly |
| Claims | invoice line edits revalidate invoice/application caps |
| Settlement | split payment and multi-payment allocations remain bounded |
| Refund | aggregate refunds never exceed original payment |
| Return | aggregate returns never exceed original delivery quantity |
| Tax | input/output components propagate additive amounts and remain target-bound |
| Adjustments | family target, organization, sign, and lock guards hold |
| Temporal | effective-time negative prefix rolls back source, position, and views |
| Concurrency | conflicts are retryable; deterministic retry produces one fact |
| References | reject/unset/cascade behavior matches each relationship contract |
| Dimensions | only declared sparse views are maintained; no accidental cube |
| Repair | rebuilding position state from source facts converges exactly |

## 14. Explicit non-goals and alternatives

This plan does not make Accounts an immutable legal ledger, implement country
tax compliance, add a generic workflow engine, add provider adapters, or build
CRM/HRM/ecommerce tables.

The following alternatives were considered and rejected for the first pass:

- one universal `transaction` table for money, stock, and services: too many
  materially different invariants and conditional branches;
- enum-only currency: loses identity, precision, custom-unit metadata, and FX
  relationships;
- tax account as the only tax model: hides granular taxable-line direction and
  makes adjustments opaque;
- refund/return as unrestricted negative movements: loses source caps and
  provenance;
- a generic context array for all relationships: weakens integrity and makes
  guards dependent on unsafe polymorphic scans;
- writing materialized views for OCC: prohibited by the engine;
- treating every correction as append-only: conflicts with the mutable
  calculation-engine product contract.

The resulting architecture is highly normalized and polymorphic at the edges,
while keeping each invariant legible and database-enforceable.
