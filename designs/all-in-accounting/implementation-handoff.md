# Accounting continuation boundary — October 14

The active task is now the [integrity repair handoff](../rebase-system/integrity-repair-handoff-2026-10-14.md).
Later stress evidence challenges dependency-index integrity, and the lead review
demonstrated gaps in the private oracle. The acceptance results below describe
the earlier bounded run; the repair and strengthened acceptance remain pending.

Read the [developer guide](developer-guide.md), [automatic-read contract](../rebase-system/function-reactivity.md)
and [verification record](verification.md), then inspect Git status/diff. Earlier
agent summaries are navigation; source, mathematics and executed evidence decide
what is implemented.

The automatic-read redesign is accepted: 103 accounting checkpoints, 51 complete
rollback snapshots, exact populated reapplication and child-first cleanup. The
focused read proof passed 50 checkpoints and 7 rollbacks. All 30 developer-tool
tests and the recorded compiler/runtime/tree checks passed.

Calculations use `fn::tree::read_value` and `fn::record::read_value`. The compiler
captures transitive helper calls for derivation, membership providers, required
outputs and final validators. Applications no longer define FX reader slots,
reader roots, impact functions or temporal-reader flags. `@rebase-impact` is
retired. Reverse positions use private typed AVL indexes; native record-ID date
ranges failed the same-timestamp nanosecond case and must not be reinstated.

The subsidiary accounting dimensions, native/reporting units, positive directional
R/P, unified adjustments and tax mathematics remain the domain contract. Fees,
claims, cash, transfer and production cases remain accepted. Source-oracle
snapshots include private subscriptions/fences and verify both reverse indexes.

Authoring sources are `core/`, `postings/`, 48 public `schemas/` and the shared
framework/compiler. Build output is generated. Evidence identifies exact sources,
the schema fingerprint, timings and coverage. `verify:accounting` runs the whole
profile in a disposable database; `probe:observed-reads` exercises the generic
read engine separately.

MetaSol, populated old-schema migration, logistics/assets/POS, rootless trees,
new storage engines and production-scale benchmarking remain separate tasks.
A current-rate stock valuation report needs its own calculation; changing the
clock does not revalue historical postings automatically.
