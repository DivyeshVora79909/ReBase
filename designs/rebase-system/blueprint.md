# Domain composition blueprint

Status: proposed domain design. Updated routing, 2026-09-28: accounting,
logistics, resource exchange and basic assembly use the current
[accounting blueprint](../all-in-accounting/blueprint.md) and
[bounded handoff](../all-in-accounting/implementation-handoff.md); CRM/HRM remain
future modules. The [foundation](./foundation.md) and
[operations](./operations.md) specify the wider redesign; [applications](./applications.md)
expands the domain contracts and [plan](./plan.md) owns their execution order.
The implemented baseline is the
[temporal calculation contract](../../research/rebase/temporal-trees.md).
Engine capabilities marked proposed below require a separate proof before a
domain relies on them.

All applications follow the same invariant-first design recipe and reuse the
same maintenance engine where their ordering semantics match. They do not all
share one schema, one root, one dependency graph, or one tree layout.

## 1. System invariants

| Invariant | Rule |
|---|---|
| One data context | A selected application profile runs in its configured namespace/database. Domain modules do not require separate namespaces or databases to keep their calculations apart. |
| Shared identity | A module may reference a shared organization, person, resource, currency, or operating unit. Identity sharing does not imply shared balances, workflow state, or tree membership. |
| Domain ownership | Each fact, owner, root field, projection, validation, and dependency belongs to a named domain module. |
| Explicit integration | A CRM order does not create an invoice, payment, shipment, or employment change by itself. A typed command or composition must state which records it creates and which rules apply. |
| Unit integrity | A summary only combines compatible units and dimensions. Money in different currencies, quantities of different resources, hours, and ordinal positions are not summed together. |
| Declared causality | Derived fields consume declared inputs in an acyclic dependency graph. References and tree topology alone do not cause recalculation. |
| Ordered integrity | A tree is used for a constraint only when its order and summary algebra prove that constraint across inserts, edits, moves, deletes, and ties. |
| Same-write validity | A business write and its derived repair either pass all affected guards or roll back together. A multi-statement SQL transaction does not defer each source event's guard until commit. |
| No double counting | A fact projects to each required owner. An owner's aggregate is not also inserted as a fact into an ancestor tree that already receives the original facts. |
| No clock side effects | Time passing alone creates no posting, status transition, payroll entry, reservation expiry, or recalculation. A scheduled action is an explicit idempotent write. |

The database's transaction documentation distinguishes a statement's own
transaction from a manually grouped `BEGIN`/`COMMIT` transaction. ReBase adds a
further business rule: generated source events finish and validate their
calculation closure at each source statement. Required multi-record recipes
must therefore be implemented at a source-event boundary that can repair and
validate the complete recipe atomically. See the official
[transaction guide](https://surrealdb.com/docs/learn/querying/concepts-and-guides/transactions)
and the measured local [temporal contract](../../research/rebase/temporal-trees.md).

## 2. Shared vocabulary

| Term | Meaning |
|---|---|
| Identity | A stable person, organization, resource, currency, unit, or other named thing. |
| Domain fact | An authoritative interaction such as a payment, delivery, status change, leave grant, rating, or work entry. |
| Dimension | The typed context that makes a value meaningful: economic entity × treasury × currency, location × item, employment × leave type, case × team, or project × capacity pool. A personal entity may be the existing user. |
| Owner | A record whose root summarizes facts for one declared dimension. |
| Projection | One unit-correct contribution from a source fact into one owner tree. |
| Tree family | One schema-declared root field plus its membership slots and summary contract. Each eligible owner record has its own tree instance. |
| Group | A document or operation scope such as an invoice, shipment, case, production run, employment, or work order. A group gets a tree only when it needs an ordered invariant or a justified query. |
| Dependency | A declared recalculation route from changed source fields to derived consumer fields. It is separate from references and AVL links. |
| Composition | A typed operation that creates or updates records in one or more modules with explicit effects, authorization, and rollback behavior. |

The system is a set of overlapping owner trees plus an acyclic dependency graph.
An AVL parent is a structural link, not a business parent or chronological
predecessor. A group reference does not, by itself, require a tree.

One authoritative record may emit several real/receivable/payable effects to
several roots. A document and an account can both own validation trees without
having identical business meaning. Deterministic 1:1 effects may share a
record; variable or independently managed children keep explicit lifecycle.
Uniform tags must match the expected owner/header, and every applicable table
variant must participate. Native field assertions handle local validity; final
closure guards handle repaired aggregates. File/definition order is not a
substitute for that runtime boundary.

## 3. Value kinds and order semantics

The value kind determines which operations are meaningful. It does not dictate
that every field needs an ordered tree.

| Kind | Examples | Safe default | Possible tree use |
|---|---|---|---|
| Nominal | Organization, tax type, item, department, currency identity | Equality, grouping, and typed reference; no implied order or arithmetic. | Usually only an owner dimension or a grouping key. |
| Ordinal | Pipeline stage, priority band, client rating label, proficiency level | Explicit stable ordering; comparisons are meaningful, distances are not. | Rank, select, ordered threshold, or a proven count/capacity rule. |
| Discrete | Case count, service slot, package count, whole task units | Integer count with a declared unit and bounds. | Prefix count, capacity, or order-statistic queries. |
| Continuous | Money, duration, mass, probability, decimal rating | Decimal value with unit, precision, and rounding policy. | Sums, extrema, weighted capacity, or ranking when the unit and meaning agree. |

An ordered stage is best represented as a typed stage/label record with an
explicit order value, rather than an enum whose meaning is hidden in branching
code. Keep the stage identity stable when its display name changes. Reordering
active stages is a domain operation: either version the order or refresh and
validate every affected member atomically. Do not silently reinterpret old
history after changing a shared rank.

An ordinal rating such as `low < medium < high` must not be averaged as though
its steps were equal. A calibrated continuous score can be averaged only when
the calibration and population are explicit. Keep the raw observation and the
selected policy/version so a later policy edit has a defined effect.

## 4. Application boundaries

All modules use the same identity records and database context where useful,
but own separate workflow facts and calculation roots. Cross-module references
can enforce existence/deletion rules; they do not create calculation edges
unless the derived fields explicitly consume mutable remote values. SurrealDB
supports tracked top-level record references and delete policies; ReBase's
local contract also requires a declared dependency for reactive reads. See
[record references](https://surrealdb.com/docs/reference/query-language/language-primitives/record-references)
and the [dependency contract](../../research/rebase/temporal-trees.md#dependencies-and-settlement).

| Module | Owns | Does not silently own |
|---|---|---|
| Identity and access | Shared organization/person/unit/currency/resource identities, principals, and authorization. | Domain balances, CRM stages, employment state, or operational history. |
| Accounting and ledger | An economic entity's dated asset/resource/claim effects, explicit accounting classifications, and accounting reports. | CRM forecasting or HRM workflow state. A balance is not inferred from an unrelated module's rows. |
| Billing and tax | Invoice/document lifecycle, pricing/tax inputs, assessments, and calculation policy. | Cash receipt or inventory movement unless an explicit accounting/logistics composition posts it. |
| CRM | Lead/opportunity/case history, client ratings, stage definitions, interactions, and pipeline analytics. | An accounting invoice or ledger posting merely because an opportunity/order exists. |
| HRM | Employment, leave/capacity, approved work time, and optional proficiency/rating history. | CRM ownership or accounting payroll effects unless explicit policies create those records. |
| Logistics and inventory | Stock/resource position, reservations, fulfillment, returns, and location/unit constraints. | Revenue, invoice claims, or cash settlement without explicit linked effects. |
| Manufacturing | Declared production runs, input requirements, work-cell capacity, and scheduled outputs. | Usable stock or financial value before its explicit output posting is valid. |
| Projects and work | Project/task state, effort, priority, and resource capacity. | HR employment or customer billing effects unless an explicit bridge maps the work. |
| Reporting | Read/query compositions over authorized domain facts and published summaries. | A hidden write-back path into source facts or another module's guards. |

An integration can deliberately connect modules. For example, a client may
choose a CRM order and invoke a typed operation that creates a billing document
and an accounting receivable. That operation names the source fields copied,
the effective dates, the policy version, and failure behavior. It does not make
CRM pipeline projections depend on accounting ledger updates. The same pattern
applies to a shipment that creates stock and invoice facts, or approved work
that creates a payroll source record.

`designs/all-in-one` is useful evidence that CRM and HRM can be composed beside
accounting in one profile while owning distinct roots. It is a technical
composition, not a claim that these modules share business calculations.

For example, a CRM opportunity's stage changes belong in its effective-time
history as interactions that reference typed stage records. The stage records
are ordered within a versioned pipeline; the current stage is the latest valid
transition, not an enum field that clients edit directly. A query or derived
projection can expose that result, subject to the engine's supported publication
path. Current opportunities need a separate ordinal team/pipeline tree only if
exact rank or stage-order queries justify maintaining it. A client rating's
history and a ranking by current rating likewise have different owners and
keys. This lets a client add stages or rating labels without hard-coded enum
branches, while keeping transition time separate from stage order.

## 5. Tree contract

The current tree engine maintains an intrusive augmented AVL directly on
business records. Each declared membership slot contributes one projection;
each root field is an independent tree family. A source can join several
families, and each membership costs storage and synchronous tree work.

The supported temporal baseline orders by time:

```text
[effective_at, canonical_record_id, slot]
```

The associative summary supports bounded measure sums and prefix extrema,
count, exact uniform tags, and date spans. C2a/b supports several distinct
positions per record/owner and complete-primary-key extrema alongside strict
record prefixes. Equal-time structural ordering remains deterministic; choose
complete-time versus strict-prefix business semantics explicitly. See the
[engine contract](../../research/rebase/temporal-trees.md) and current compiled
evidence in [verification](./verification.md).

The compiler now supports explicit `datetime` and `int` root/node contracts.
The compiled stage fixture verifies independent chronological and integer trees
on one source record. An ordinal owner binds one domain and scale version through
native validation. Within that partition, its key is:

```text
[order_value, canonical_record_id, slot]
```

The implemented key types are `datetime` and safely transported `int`; arbitrary
heterogeneous values and client-supplied comparators are unsupported. AVL
rotations and owner fencing remain shared. Key validation and query bounds are
typed; integer trees skip temporal prefix sweeps. Ordinal trees support
rank/selection and bounded aggregates;
do not materialize a field for every record's global rank, since one score edit
can reorder many rows. Only add rank-dependent synchronous rules after their
fan-out and rollback behavior are measured.

The [first checkpoint](./ordinal-feasibility.md) records the historical integer
experiment; [verification](./verification.md) records compiled C1 coverage.
Homogeneous decimal-score ordering needs its own precision contract.

Do not form a Cartesian product of every attribute, team, period, status,
currency, and resource. A family is partitioned by the smallest meaningful
owner dimension; absent/optional classifications stay out of the tree unless
their absence is itself part of a guard. Use ordinary indexes or views for
exploratory analytics, and ordered trees for exact maintained invariants or
measured rank/range paths.

## 6. Design recipe for a module

For each proposed module, write down these items before schema work:

1. **Authoritative facts:** what the client may create or amend, and what is a
   derived value.
2. **Identity and dimensions:** native record types, units, and owner
   partitions. State which referenced dimensions are immutable.
3. **Invariants:** express each as a bound, prefix rule, interval, dependency,
   or cross-record composition. Give a counterexample to a total-only check.
4. **Tree decision:** owner field, key, measures/tags/spans, order-boundary
   policy, and source membership slots. If no exact invariant or hot query
   requires a tree, do not add one.
5. **Dependency graph:** list consumed fields and routes, draw the DAG, and
   reject a cycle or same-tree whole-summary feedback.
6. **Mutation boundary:** prove that create/edit/move/delete, derived-output
   creation, and authorization all settle before final validation. Identify
   which input edits can fan out to many consumers.
7. **Independent oracle:** reconstruct expected state from authoritative
   records without reading the maintained tree or derived helper fields.
8. **Cost:** count total active positions and reactive records for a whole
   business operation. Include failed writes, retries, and downstream refresh.
9. **Composition boundary:** say which other modules can be referenced and
   which effects require an explicit bridge.

Keep business field names direct (`effective_at`, `counterparty`, `quantity`,
`currency`, `stage`) and name derived fields after their meaning. Reserve a
consistent prefix such as `rb_` for protected tree/dependency storage. The
compiler recognizes annotations, not a general `a_`/`z_` business vocabulary;
same-record derived fields may be declared in any order. C3 resolves their
dependencies and verifies topological lowering on both CREATE and refresh;
numbered business-field names are not required.
Do not expose internal roots or slots as editable application state.

## 7. Reporting and audit boundaries

Trees maintain exact state and queries that justify their write cost. They are
not a replacement for text search, general analytics, arbitrary filtering, or
an accounting policy. Native indexes/views and read-only report queries remain
appropriate for those jobs. Grouped views are not synchronous historical
prefix validators when sources depend on mutable parent fields; see the
[temporal integrity research](../../research/surrealdb/temporal-integrity-dimensional-fact-check.md).

Authoritative changes should be auditable; rotations, derived refreshes, and
tree repairs should not appear as new business activity. A reporting module may
read several domains under their existing permissions but must identify each
measure's unit, as-of time, dimension, and policy/version. Do not imply a
consolidated financial statement until its valuation and classification rules
are explicit.
