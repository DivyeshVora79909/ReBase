# ReBase tree catalog

Status: source inventory rechecked and proposed logical catalog, 2026-09-25.
The application baseline uses datetime AVL trees. C1 adds explicit compiled
`datetime`/`int` keys and finite owner contracts, verified with a versioned-stage
fixture that participates independently in both orderings. See the [plan](./plan.md).
See [applications](./applications.md) for module behavior beyond family counts.

## How to read the count

A **tree family** is one declared root field and its membership contract. Each
owner record that has that field owns one independent runtime tree instance.
For example, one `money_account` root family may have thousands of account
instances, each with its own balance history. A source record may participate
in several owner trees through separate membership slots.

Therefore there is no fixed total number of runtime trees for the whole
system. It varies with the chosen profile and with the number of owner records.
For a compiled profile, count root fields for logical families, owner records
for runtime instances, and populated membership slots for write/storage cost.

The current composed `designs/all-in-one` profile declares **22 root fields**.
This count is derived from its `@rebase-tree-root` declarations. It is not a
benchmark, the number of populated instances, or a recommended target.

## Current profile inventory

| Domain area | Current owner root fields | Logical purpose |
|---|---|---|
| Account dimensions | `money_account.z_book`, `stock_account.z_book`, `currency_exchange.z_usage`, `operating_unit.z_activity`, `adjustment_note.z_book` | Money/resource balances and guards, quote use, activity, and correction grouping. |
| Money interactions | `payment.z_history`, `settlement.z_history`, `tax_remittance.z_history`, `tax_recovery.z_history`, `money_charge.z_history`, `money_parent_charge.z_history`, `asset_allocation.z_history`, `asset_parent_allocation.z_history` | Per-source capacity, allocation, charge, and correction histories. |
| Logistics | `delivery.z_history`, `delivery_charge.z_history`, `delivery_parent_charge.z_history` | Delivery correction/charge scopes. Stock and unit activity are separately owned by account/unit roots above. |
| Billing and tax | `invoice.z_book`, `tax_assessment.z_history` | Invoice group constraints and assessment source history. |
| CRM | `organization.z_cases`, `crm_case.z_history` | Organization CRM activity and chronological case lifecycle/effort. |
| HRM | `employment.z_history`, `leave_account.z_book` | Employment bounds/activity and employment × leave-type allowance. |
| **Total** | **22 root fields** | Source-level family count only. |

The storage names above reflect the current schema, not the preferred business
naming style. A future naming cleanup should keep public business fields
semantic and mark internal roots/slots explicitly without changing their
calculation contracts.

## Proposed domain catalog

These are candidate families, not a mandate to create every row. The order and
summary must match a specific invariant. Domain-specific roots stay distinct
even when multiple modules refer to the same organization or person.

| Module / family | Owner partition | Order | Typical summary or guard | Status |
|---|---|---|---|---|
| Accounting: monetary position | Book × treasury/account × currency | Effective time | Dated inflow/outflow, available/floor balance; one currency per owner. | Temporal base pattern exists in the composed profile. |
| Accounting: resource position | Book × location/unit × item or service | Effective time | Dated quantity and nonnegative stock/capacity. | Base pattern exists; C2a/b interval engine prerequisites pass, while reservation recipes remain planned. |
| Accounting: claims | Book × counterparty × currency × claim measure | Effective time | Separate receivable/payable prefixes; settlement reduces its target measure. | Proposed in the accounting blueprint. |
| Accounting: document/source scope | Invoice, receipt, claim source, correction group, or allocation pool | Effective time | Amount/quantity capacity and source-before-consumer rules. | Select only for required guards or live calculations. |
| Billing/tax: document lifecycle | One invoice/document group | Effective time | Issue/recognition/due dates and bounded line totals. | Proposed; connects to accounting only through typed postings. |
| CRM: case lifecycle | One case | Effective time | Open/closed state prefix, effort, chronological bounds. | Current `crm_case.z_history` example. |
| CRM: organization activity | Shared organization, CRM root only | Effective time | Open-case count and interaction effort. | Current `organization.z_cases` example. |
| CRM: stage/rating order | Team/board × rating or stage-order version | Ordinal value, then stable identity | Rank/select, bounded counts, or selected ordinal aggregate. | Proposed; requires typed ordinal keys. |
| HRM: employment history | One employment relationship | Effective time | Employment interval and dated activity bounds. | Current `employment.z_history` example. |
| HRM: allowance/capacity | Employment × leave/work category | Effective time | Grants minus use; optional dated service/workload capacity. | Current leave allowance example; broader capacity proposed. |
| HRM: proficiency order | Team/unit × skill × policy version | Ordinal level or calibrated score | Rank and distribution by one declared scale. | Optional proposal; ordinal/continuous semantics must stay distinct. |
| Logistics: inventory position | Book × location/unit × resource | Effective time | Available quantity after receipts, issues, returns, and adjustments. | Shares a deliberate stock-posting contract with accounting. |
| Logistics: reservation capacity | Resource pool × location × policy window | Start and release positions | Maximum concurrent quantity/slots; half-open interval policy. | Engine prerequisites C2a/b pass; module-specific recipes and policy checks remain planned. |
| Projects/work: effort and state | Work item/project × assigned scope | Effective time | State transitions, effort, budget/capacity consumption. | Proposed; use only required owner levels. |
| Projects/work: priority queue | Project/team × priority scale/version | Ordinal order, then stable identity | Rank/select; no per-task cached global rank by default. | Proposed; requires typed ordinal keys. |
| Manufacturing: batch inputs/outputs | Production run × declared recipe/output scope | Effective time | Input completeness, yield, costs/quantities, planned versus actual output. | Proposed; generic required outputs and multi-root causality passed C2c/d, while manufacturing recipe and policy checks remain open. |
| Manufacturing: work-cell capacity | Work cell/resource pool × schedule policy | Start and release positions | Concurrent machine/labor load and interval ceilings. | Proposed; interval primitives and generic required outputs passed C2a-c, while manufacturing-specific recipe proofs remain open. |

### First-profile family budget

This is a sizing guide for logical families, not a table count or a feature
commitment. `+N` means add one family for each genuinely distinct owner/order
contract, not for each client label or row.

| Module | Starting family budget | Notes |
|---|---:|---|
| Accounting/ledger | 3 core families + 0..N document/source scopes | Monetary position, resource position, and claims. A document or settlement pool gets another family only for its own capacity or live calculation. |
| Billing/tax | 1..2 | Invoice/document history; add assessment/source history only when required by a calculation or guard. Claims still belong to a typed accounting dimension when posted there. |
| CRM | 2 temporal + 0..N ordinal | The current example already has case lifecycle and organization activity. Add an ordinal family only for a defined team/board ranking query or guard. |
| HRM | 2 temporal + 0..N capacity/ordinal | Current example has employment history and leave allowance. Add capacity per distinct pool and ordinal ordering per versioned skill/scale only when used. |
| Logistics/inventory | 1 shared position + 0..N reservations/scopes | Reuse the canonical resource-position family if dimensions and policy match accounting. Do not maintain a second stock balance for the same facts. |
| Manufacturing | 0..1 run scope + 0..N capacity pools | Input/output inventory uses the logistics/accounting posting contract. A run root is needed only for batch completeness, output limits, or calculations. |
| Projects/work | 1..2 temporal + 0..N ordinal | Work-item state/effort and a separate capacity owner when required; a priority queue is an optional ordinal family. |

If two modules truly maintain the same authoritative position and invariant,
choose one owner and let the other module use an explicit posting/read
composition. If their policies differ, they are separate invariants and need
separate projections with their additional cost shown. The overall profile is
the union after resolving such shared families, not the sum of every row in
this estimate.

## Tree selection rules

1. **Do not make a tree just because a record is ordered or grouped.** A normal
   index, view, or list may be enough.
2. **One root per independently guarded owner dimension.** Currency,
   inventory item/location, employment/leave type, case, and team are different
   owners when their units or validation differ.
3. **Keep order modes separate.** Effective time validates historical state;
   ordinal value supports rank/order questions. A stage's business sequence
   does not turn a dated case transition into an ordinal tree event.
4. **Bound summary shape.** A tree summary is a schema-bounded vector of
   compatible measures plus exact tags/spans. Do not create an unbounded key
   for every client label or use hashes as equality proofs.
5. **Measure whole operations.** `k` memberships imply approximately
   `O(sum(log n_i))` tree-path work before dependent refresh, but each input
   edit can visit many consumers. Count source, derived, allocation, and
   capacity memberships together.
6. **Avoid hidden cross-domain ownership.** An `organization` can own one CRM
   root and be referenced by an accounting record, but the CRM and accounting
   trees have different root fields, measures, guards, and dependency routes.
7. **Version mutable ordering policy.** Changing an ordinal scale or stage
   order must not silently reshuffle old observations. Use a new version or a
   complete refresh/revalidation operation.

## Engine capability ledger

| Capability | Current status | Required research or implementation |
|---|---|---|
| Intrusive AVL, multiple owner fields, bounded associative summaries | Implemented and probed for datetime and safe integer keys. | Preserve existing regression coverage. |
| Multiple memberships from one fact into different owners/families | Implemented within declared slots. | Continue to count all slots and owner projections. |
| Multiple effective timestamps from one fact into one owner tree | C2a implemented and verified with distinct slots, deletion topologies, mutations, and rollback. | Continue module-specific interval cases in the [accounting plan](../all-in-accounting/plan.md). |
| Complete-timestamp balance/capacity policy | C2b implemented and verified beside strict record-prefix summaries. | Continue policy-specific historical/window cases in the [accounting plan](../all-in-accounting/plan.md); load metrics remain in D1. |
| Integer ordered keys | C1 passed compiled independent time/rank trees, versioned scales, strict type/pair checks, ACL and rollback. | [Current evidence](./verification.md). Full-width integer/decimal transport and integer prefix-dependent formulas remain separate work. |
| Exact mutable rank-dependent outputs | Not established. | Defer until fan-out, acyclic causality, atomicity, and rollback are demonstrated. |
| Required child/output lifecycle | Generic private source-owned recipes passed C2c with atomic rollback, stable role IDs, child cleanup and record-user CRUD denial. | Multi-root basis/output refresh, diamond causality, downstream rekey, feedback rejection and audit rollback passed C2d; retain each accounting/manufacturing recipe's own policy and oracle cases. |

The generic SurrealDB transaction/reference/index facilities do not replace
these engine proofs. Native indexes suit record lookup and ordered query paths;
the ReBase AVL is maintained application state with stronger synchronous
prefix semantics. See SurrealDB's [index guidance](https://surrealdb.com/docs/learn/schema-management/indexes/index-types-and-strategies)
and the local [temporal integrity findings](../../research/surrealdb/temporal-integrity-dimensional-fact-check.md).
