# Accounting continuation boundary — October 13

Read the [execution contract](redesign-2026-10-13.md), [developer guide](developer-guide.md)
and [verification record](verification.md), then inspect Git status/diff. Treat
this handoff and earlier agent summaries as navigation, not independent proof.

Fresh consolidated acceptance is complete: 101 source-oracle checkpoints and
51 rollback snapshots, populated reapplication and cleanup. All 27 developer-tool
tests and the focused compiler, architecture and function-impact checks passed.
The verification record identifies exact sources, timings and coverage.

The active model has subsidiaries, sparse native organization positions,
event-time reporting, nonnegative directional R/P, unified quantity/price and
payment adjustments, five strict tax-adjustment tables, shared directed dated
rates and authored impact ranges. It carries cash/tax/fee/claim/transfer/production
capabilities forward with independent capacity measures.

Authoring sources are `core/`, `postings/` and 48 public `schemas/`. Build output
is generated. The accounting source oracle replays arithmetic from authored
fields and independently checks all declared financial/index/reader trees.
`verify:accounting` runs core and extension cases in one disposable database,
then checks populated reapplication and child-first cleanup.

The separate MetaSol API, populated migration, logistics/assets/POS, rootless
trees, a new storage engine and production-scale benchmarking are outside this
snapshot. Any of those needs a separate concrete task. A future current-rate
valuation report must be designed explicitly; event-time postings do not provide
automatic mark-to-market of remaining balances.
