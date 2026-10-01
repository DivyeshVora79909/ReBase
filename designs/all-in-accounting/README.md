# Accounting and resource module

Updated 2026-09-29. Current design covers accounting, billing/tax, logistics,
resource exchange and basic assembly, with a bounded timed-production extension.
CRM and HRM remain independent future modules. A1a-A1d and A2a-A2d have recorded
compiled probe checkpoints under the older compulsory book schema; they do
not prove the revised identity/effect design. This is one module within the
[ReBase system blueprint](../rebase-system/README.md).

Build the suite from **typed accounts, real movements, receivable/payable
postings, explicit calculation dependencies, and groups that own necessary
constraints**. Reuse ReBase's intrusive temporal trees. Separate a transaction's
economic effect from its calculation source and its validation memberships.

One source may carry several real/receivable/payable effects. Its calculation
dependencies, document grouping, and validation memberships are separate
contracts. Co-locate deterministic 1:1 effects when lifecycle/permissions agree;
independently managed or variable children remain explicit. Account labels
alone do not define different execution recipes.

| Document | Purpose |
|---|---|
| [Blueprint](./blueprint.md) | Current identity/effect model, validation stages, exchange/tax contracts, temporal limits and extension rules. |
| [Implementation handoff](./implementation-handoff.md) | Ordered H0–H8 tasks, source evidence, proof gates and continuation instruction for smaller models. |
| [Context map](./context-map.md) | Focused reading route and evidence-preserving compression procedure. |
| [Plan and checkpoint history](./plan.md) | Earlier A1/A2 implementation evidence and retained detailed acceptance matrix. |

The principal decisions are:

- Keep three effect families: **real, receivable, payable**. A posting's family
  is independent of whether it is explicit, derived, past-dated, or future-dated.
- Keep each posting in an explicit economic entity's perspective: existing
  user or organization. Authorization ownership is a separate role; a personal
  account needs no artificial organization/book.
- Retain the six simple movement tables where useful. They do not limit the
  number of accounts/effects per source. Add native variants for meaningful
  required-shape/lifecycle differences and share declared tree contracts.
- Reduce a settled receivable or payable in its own measure. Compute net claims
  as `receivable - payable`; keep no independent net input. A historical net
  bound needs its own derived measure in the existing root.
- Give a group a tree only when it needs ordered validation, a calculation
  basis, or a justified maintained query. A reference alone does not require a tree.
- Express interval capacity and fixed-duration rolling limits as dated additions
  and releases. Shared engine extensions C2a/b now support these primitives;
  accounting-specific history/window policies still need their acceptance cases.
- Compare the total work for a business operation. Splitting a large record into
  several smaller records can lower each record's memberships while increasing
  the number of reactive records.

Current packet status, evidence IDs, fixture limits, and open policies live in
the [implementation handoff](./implementation-handoff.md). In particular,
H2 posts assessed purchase tax immediately as a receivable; H4b3 records
eligible/usable recognition separately without posting a second receivable.
H4b5c residual policy and populated legacy-profile migration remain open.
H8 has no writable `end_at`: managed roles compute planned start plus immutable
duration because SurrealDB 3.2.0 rejects READONLY projection refresh and permits
writable VALUE override. The bounded H8 profile is not a production migration;
workforce and costing remain out of scope. CRM/HRM remain sibling modules and
do not enter this calculation graph by default. Valuation and financial
reports have an explicit scope boundary.

The source study used the current [temporal contract](../../research/rebase/temporal-trees.md),
the [all-in-one suite](../all-in-one/README.md), relevant temporal generator/runtime
sections, and the existing [write measurements](../../research/rebase/write-amplification-results.md).
The shared engine's multiple-position contract, timestamp-boundary algebra,
and generic required-output lifecycle have compiled correctness probes (C2a/b/c
in the system plan). The broader accounting-specific historical/window matrix
and write-cost/throughput claims remain open; executable A1a-A1d and A2a-A2d
history does not establish completion of the revised module.
