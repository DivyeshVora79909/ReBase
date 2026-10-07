# Accounting redesign handoff — 2026-10-07

The subsequent [reader/index change](../rebase-system/reader-index-verification.md)
updates the shared framework and reruns accounting regression. The original
accounting redesign evidence below remains tied to commit `88c5ae7` and its
recorded hashes; it does not imply the shared framework stayed unchanged later.


The active contract is the [blueprint](blueprint.md), with the
[source map](context-map.md), [tax contract](delivery-taxes.md), and
[execution record](redesign-2026-10-07.md). These supersede the October 5 direct
normalization and earlier H1–H8 recipes. The user confirmed that refunds are
on/before the invoice date and cash adjustments/reversals are after it.

Baseline HEAD was `78671715764437af606ebfe6408824d81ca5d284`. Existing dirty work
was preserved before editing in `/tmp/rebase-accounting-20261007-35pij68t`.
The redesigned sources are in the normal accounting profile. The old recipe
directory and recipe-only probes/commands were deleted at the user's request.
Do not recreate a compatibility profile or automatic business-child generator.

There are ten native domain files and 34 public create schemas, compiling with
the shared framework to 51 tables. No shared compiler, authentication, gateway
or runtime implementation was changed. The account wrappers were removed;
organization and treasury are now account records with required currency.
Issues require invoices, pricing/conversion is scalar, and taxes use dated base
or net aggregates with no explicit tax predecessor.

## Evidence route

Use [verification](verification.md) for the final commands, counts and source
fingerprints. The independent oracle replays authored inputs using rational
arithmetic and reconstructs every root, slot, chronology link and AVL summary.
Rejection snapshots include every domain row and the audit ledger. Public schema
exports, typed SDK values and the example fixture have separate tests.

Local acceptance passed: 63 mutation checkpoints and 35 complete rollback
snapshots in 397.33 seconds, including populated schema reapplication and cleanup.
All 27 developer-tool tests passed against the final sources; the 15 client-schema
tests are included in that total. Compiler and architecture checks also passed.
All 67 saved shared-engine files match their baseline hashes. Use the current
evidence rather than the older 52-mutation normalization result or H1–H8 timings.

## Boundaries and continuation

- Ledger summaries include future records. Read a prefix for an as-of balance.
- Complete timestamp guards differ from strictly earlier compounding readers.
  Never use record-ID order as a tax or capacity business rule.
- Each source closure validates before the next statement. Reverse cash before
  reducing a fully paid invoice. Choose cleanup order that also preserves valid
  intermediate closures, then delete linked records one at a time.
- Correction-tax rows are explicit. There is no mandatory child reconciliation.
  Production supports arbitrary authored input/output rows and resource guards;
  it does not infer bills of materials, yield, costing or statutory tax policy.
- Native VALUE formulas replace attempted computed values on create; protected
  derived/tree data cannot be used as trusted client input.
- Accounts and resource units are independent. Do not post account subtotals into
  the same monetary root or treat independently priced stock as synchronized.
- The separate MetaSol frontend still targets previous contracts. Its migration
  is not part of this backend request; update its work plan before changing it.
- Live providers, production deployment, a populated schema conversion and
  representative storage/latency capacity are outside this local acceptance.

Continue with a focused reproduction for a new concern, then its corresponding
source and public schema. Avoid reopening the shared engine without evidence.
