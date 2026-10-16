# Accounting continuation boundary — October 16

The [declarative-engine plan](../rebase-system/declarative-engine-plan.md) owns
current work and acceptance gates. Read the [developer guide](developer-guide.md),
[declared-query contract](../rebase-system/function-reactivity.md), current Git
diff and [verification record](verification.md). Earlier capture-engine acceptance
belongs to its recorded revisions.

Full current acceptance passed 103 source checkpoints, 105 structural checks,
90 exact value queries and 54 rollback snapshots, including populated
reapplication and cleanup. The
[engine verification record](../rebase-system/declarative-engine-verification.md)
and [manifest](../rebase-system/evidence/2026-10-16-declarative-engine.json)
record supporting gates and the separately verified numeric-demo checker change.
The accounting implementation and generated schema remain identical to the
[full-run evidence](../rebase-system/evidence/2026-10-16-declarative-accounting.json).

The accounting model retains subsidiary roots, sparse native dimensions,
event-time reporting, directional claims, exact product-difference adjustments,
strict tax rules, optional fees, tax cash, transfers and production. Ordered
calculations now use named query fields. Posting helpers consume their results;
source metadata and query bounds determine inverse propagation. Production uses
final-validation descriptors. Invoices validate their own roots directly.

Business uniqueness is expressed through explicit tenant-rooted custom indexes.
Native references/backlinks, authorization and runtime effects retain their
separate roles. No compatibility subscription engine or data migration is kept.

The source oracle derives financial values, memberships and every active query
role independently from source facts. It checks descriptor contents, exact
results, reverse slots, root inventory and full AVL/link/summary state. Cleanup
removes children one record at a time and verifies empty financial/dependency
roots. Remaining identity records correctly retain their identity memberships.

Run `npm run verify:accounting` for the full disposable accounting gate,
`npm run probe:dependencies` for generic propagation, and
`npm run probe:dependency-cost` for bounded structural evidence. Builds emit
`dependency-plan.json`; `--explain issue_adjustment.amount_delta` reads current
source without writing files. Generated directories are not authoring inputs.

MetaSol adaptation, deployment, populated migration and representative production
capacity are separate tasks. Current-rate stock valuation requires its own
calculation; historical reporting does not change just because time advances.
