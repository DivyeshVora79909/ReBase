# Application designs from the same primitives

Status: module design, 2026-09-25. This expands the [tree catalog](./tree-catalog.md)
into implementation contracts. None of the proposed full applications is
implemented by this document. The [foundation](./foundation.md) and
[operations](./operations.md) gates come first.

The 2026-09-28 [accounting revision](../all-in-accounting/blueprint.md) and
[handoff](../all-in-accounting/implementation-handoff.md) supersede older
account/book and effect-layout assumptions below for accounting, logistics,
exchange and basic assembly. CRM/HRM sections remain future proposals.

## Common recipe

Each module defines native facts, immutable/versioned dimensions, explicit
projections, guards, calculation dependencies, and required compositions. A tree
exists only for an ordered invariant or a justified rank/range query. Native
indexes/views handle equality, grouping, search, and label counts.

A domain package owns its tables/functions/fixtures. Sharing organization,
person, currency, location, or resource identities does not share workflow,
balances, authorization, or a calculation graph. All may run in one selected
namespace/database. If separately deployed, cross-database identity is an
explicit integration mapping, not an ordinary native record reference.

Native polymorphic types express required shape. Reuse small schema/function
fragments when behavior is identical; split a table when required inputs,
lifecycle, endpoint types, or calculation ancestry differ. A tax name, CRM
stage label, or skill label alone does not justify another table.

## 1. Accounting and billing

Use the detailed [accounting blueprint](../all-in-accounting/blueprint.md) for
the endpoint matrix and formulas. Its economic distinctions remain useful:
real asset/resource movement, receivable change, payable change, source-based
calculation, and constrained allocation. These are domain effects/measures;
the calculation engine does not know those names.

| Contract | Decision |
|---|---|
| Book and units | Every posting has one book perspective. Currency, quantity unit, resource, and policy version are explicit. Another party's books are not posted implicitly. |
| Identities/accounts | Treasury, organization, tax, miscellaneous, resource/location. A dimension account combines the needed identities, with native unique constraints. Labels such as GST/TDS are policy data. |
| Core movements | Six strictly typed movement shapes cover the twelve allowed money/resource endpoint directions. A real money movement includes a treasury; a real resource movement includes a resource account. |
| Claims | Separate receivable/payable measures; signed corrections stay in their original measure. Compute net as R − P at read time. |
| Documents | Invoice/credit-note/group identity is independent from physical delivery. Add a group root only for a stated capacity, time, or calculation guard. |
| Settlement | Allocation consumes the target claim and the payment source pool. Enforce both across time, with currency/counterparty/book agreement. |
| Calculation | Real → real/claim is allowed; claim → real/another claim amount is excluded by the requested initial policy. Pure basis records cannot hide a forbidden ancestry. |
| Valuation | Quantity, carrying value, invoice amount, and cash are different measures. Depreciation can change value without moving physical quantity. |
| Recognition | `effective_at`, invoice issue, and payment due time are distinct. Due forecasts get another ordering only when required. |
| FX | Native decimal rates and immutable precision; explicit rounding/residuals. Quote edits either use a retained version or deliberately refresh every consumer. No cross-currency scalar balance. |

A concrete sale for net 100 plus tax 18:

1. A delivery changes quantity in the resource account.
2. The billing basis creates customer receivable +118 and tax payable +18
   through its required typed recipe, at their declared recognition times.
3. A receipt creates treasury +118. Its allocation reduces customer receivable
   by 118 and consumes 118 of that receipt's available settlement capacity.
4. A tax remittance changes treasury and reduces the appropriate payable;
   input-credit offsets, withholding, and refunds use explicit balanced recipes.

No step invents a second receivable merely because a payable was settled.
Purchase, partial/multiple settlement, credit note, cash-only refund, stock-only
return, tax credit, advance, and withholding variants have separate source
contracts where their required effects differ. Mandatory siblings can use the
generic source-owned lifecycle proved in C2c; each accounting composition still
needs its own dimension, authorization, and source-oracle checks. An optional
reference is not completeness proof.

Acceptance: independent reconstruction of every money/resource/claim prefix,
all twelve endpoint directions, partial/duplicate/over allocations, equal-time
settlement, retroactive edits, FX residuals, and atomic required output failure.
Full financial statements require valuation, classification, and opening-period
policies explicitly; a calculation kernel alone does not implement them.

## 2. Inventory, logistics, services, and manufacturing

| Module | Authoritative records | Ordered owners and guards | Dependency boundary |
|---|---|---|---|
| Inventory | Receipt, issue, transfer, return, quantity/value correction. | Resource × location × book position; nonnegative permitted availability, compatible units. | One canonical stock position; no duplicate accounting rollup of the same facts. |
| Reservations | Resource allocation with start/end/weight; capacity grants/reductions. | Resource pool, two dated positions per allocation, half-open overlap/load limits. | Edit/delete/move both endpoints atomically. Reservation is distinct from fulfilled movement. |
| Logistics | Shipment/receipt group, fulfillment allocations, returns. | Only necessary source/fulfillment capacity scopes and the canonical inventory owner. | Fulfillment consumes a declared source allocation; billing is an explicit bridge. |
| Services/work orders | Service commitment, planned interval, performed work and optional valuation. | Service/resource capacity and source completion limits. | A service is a resource with a capacity contract, not automatically storable physical stock. |
| Manufacturing | Production run, versioned requirements, input allocations, duration, completion basis, coproduct outputs. | Homogeneous input scopes, shared batch completion, work-cell capacity, inventory positions. | Input trees → readiness basis → future output movements; outputs never calculate their own input sufficiency. |

A production recipe constrains each required resource separately. It never
adds ore kilograms to labor hours or currency. Coproducts share batch usage so
two output rows cannot each spend the full same input. An output is required
only once the declared readiness contract is satisfied; missing requirements
are not an empty successful recipe.

A future output's amount/time may depend on valid input quantities/dates and
processing duration. Editing an old input must move/recalculate that output
and reject any resulting unsupported shipment or capacity use in the same
operation. A future projection is a plan/fact under the chosen scenario, not
confirmation of physical completion or a server cron action.

Acceptance: backdated shortages with positive final totals, touching intervals,
capacity changes at a boundary, cancellation, partial inputs, multi-output
batch sharing, wrong-resource input, changed duration after downstream use,
and failure halfway through output creation/removal.

## 3. CRM

Build CRM around parties, conversations/interactions, opportunities/cases,
versioned workflow definitions, transition facts, and observations/ratings.
Search, contact lookup, notes, tags, and grouped pipeline totals use native
queries/indexes/views. They do not each get an AVL tree.

| Component | Native facts and policy | Tree decision |
|---|---|---|
| Party/contact directory | Organizations/people, typed contact identities and relationships. | Lookup/search only unless an ordered maintained query is justified. |
| Opportunity/case lifecycle | Dated transitions with explicit before/after stage and a versioned allowed-transition rule. Interactions and effort are separate facts. | One lifecycle history per opportunity/case; optional organization activity history. |
| Stage policy | Stable stage identities, display label, explicit ordinal code, versioned transition rules. | Labels are ordinary rows. A board rank uses the declared stage code, never name sort order. |
| Pipeline/rating ranking | A projection of one current/snapshot opportunity or one selected observation per subject. | Optional team/board × scale-version ordinal owner; count/rank/select and compatible amount measures. |
| Tasks/communications | Due actions, assignment, contact interaction, optional operation request. | Native due index by default; work/capacity roots only when enforced. |
| Quotation/order analytics | CRM-owned quoted/expected values and selected probabilities with currency/version. | Native grouped summaries or justified ranking; no ledger effect. |

Arbitrary client stages cannot be validated by treating every transition as the
same +1/−1 binary status. A static transition-summary extension can hold the
first required state, last resulting state, count, and `valid` flag. Combining
adjacent nonempty blocks also checks `left.last == right.first`; individual
transitions validate their referenced allowed rule. This is constant width even
with many stage labels. Prove its identity/associativity and backdated edits in
A3 before claiming generalized lifecycle integrity. State IDs are exact values;
an unordered distinct-stage histogram belongs in a nominal view.

Default state queries are explicitly `as_of(t)`. A ranking over a materialized
state names its snapshot/as-of time. The passage of time cannot silently update
a current-stage projection when a future transition becomes effective. An
operational current board must either admit only effective transitions or use
explicit one-shot refresh operations for future boundaries; the first profile
uses actual effective transitions and stores future intent as scheduled work.
Historical/planned queries remain separate.

Stage-order changes create a new version, or use a deliberate complete refresh
and validation. A score change affects the relevant ranking, not an accounting
balance. Store measured scores separately from ordinal ratings; an ordinal code
is not an averageable quantity.

Acceptance: allowed/disallowed/reopened transitions, stale expected stage,
backdated chain break, simultaneous ties, renamed labels versus new scale
versions, rank movement without time-history movement, hidden contact fields,
and duplicate CRM-to-billing conversion. The bridge copies a declared snapshot;
accounting edits do not rewrite the CRM pipeline.

## 4. HRM

Use person, employment relationship, contract/policy version, capacity/leave
account, grants, reservations/approved usage, work entries, and skill
observations. Authorization belongs to HR scopes, not the shared person's
entire set of other application references.

| Component | Native facts and policy | Tree decision |
|---|---|---|
| Employment | Employer/person relationship, dated contract and assignment changes. | Employment history for interval/state guards; ordinary directory indexes otherwise. |
| Leave/allowance | Employment × leave-category account, explicit dated grant/use/reversal. | Nonnegative entitlement history; no implicit daily accrual from time passing. |
| Availability/workload | Capacity grants/reductions and weighted planned intervals. | Pool or employment capacity with start/release memberships. |
| Approved work/time | Dated duration, assignment, approval facts, correction/source scope. | Ordered limit/period scopes only where a rule requires them. |
| Skills/proficiency | Observations reference a versioned ordinal scale or calibrated numeric score. | Optional team × skill × scale ranking, distinct from employment chronology. |
| Payroll inputs | Approved work and explicit compensation policy snapshots. | HR owns inputs; a typed bridge produces accounting obligations in a selected book. |

Calendar leave rules compute billable units under an explicit versioned calendar;
interval occupancy and entitlement consumption are different measures.
A recurring allowance is multiple explicit grant records or one-shot scheduled
creation, not a hidden cron engine. Editing/deleting an old grant may invalidate
later leave and must roll back if the entitlement would become negative.

Acceptance: overlapping employment/work intervals, allowance used before grant,
retroactive contract/capacity reduction, cancel/reassign interval, calendar/timezone
boundaries, confidentiality, changed skill rank, and payroll bridge idempotency.
No payroll, CRM, or accounting posting appears because an employment record
merely references the same organization.

## 5. Projects/work and reporting

Projects own work-item transitions, estimates, approved effort, assignments, and
resource reservations. Reuse the verified CRM transition summary for a work
lifecycle and interval capacity for constraints. Maintain a priority/rank family
only for a required queue/ranking query; avoid a cached global rank on every row.
Time budgets use units/periods explicitly, rather than assuming all work has a
comparable arbitrary complexity score. Complexity weights require one declared
scale per constrained owner.

Reporting reads the authorized published contracts: dimension, measure/unit,
key/order, as-of time, scenario, and policy version. Accounting, CRM, and HRM
reports may join shared identities without joining their calculation graphs.
Views for nominal analytics are appropriate; a view over mutable dereferenced
parents is not automatically a synchronous historical validator.

## 6. Explicit bridges

| Bridge | Source and resulting records | Required guarantee |
|---|---|---|
| CRM → billing | Chosen opportunity/quotation snapshot → billing document and declared lines. | Stable source revision/conversion key; exact copied-field map; no duplicate conversion. |
| Billing → accounting | Issued/recognized document basis → receivable/payable/tax outputs. | Complete required set, dimension agreement, same-operation rollback. |
| Logistics → billing | Accepted fulfillment snapshot → chosen billing basis. | Partial delivery/return accounting is explicit; no unrequested invoice. |
| Work/HR → accounting | Approved work/payroll basis → obligation in selected book. | HR privacy, currency/valuation policy, idempotency, no reverse workflow coupling. |
| Manufacturing → inventory | Ready batch basis → all required resource output movements. | Shared batch usage, timing, complete outputs, downstream stock validation. |

A frontend may invoke a bridge, but backend integrity cannot depend on several
unprotected client CRUD calls being completed correctly. One typed source-owned
composition provides the boundary where mandatory effects exist. Separate
deployments require durable integration intents and cannot promise a single
cross-database atomic transaction.

Use the [catalog](./tree-catalog.md) as a starting family budget, not a promise
of a fixed total. Count families, owner instances, active positions, and reactive
consumer visits separately. Each implemented profile needs its own oracle and
cost evidence before being called complete.
