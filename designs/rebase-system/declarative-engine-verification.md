# Declarative-engine verification — October 16, 2026

The engine replacement and full accounting acceptance passed locally on
SurrealDB **3.3.0**, Node **22.23.2**, using disposable SurrealKV databases.
All required regression gates are complete. Changes are reviewable and
uncommitted against `cc7b98dea8db57f51150dcc40aecd56eb7dc10e3`.
The [execution plan](declarative-engine-plan.md) owns the design and completed
gates; the [developer blueprint](developer-blueprint.md) and
[query contract](function-reactivity.md) describe authoring.

## Accepted implementation

- Named `range`, `latest`, `next` and `exact` queries use fixed private slots
  on business records and reverse roots on source owners. Interval and business
  indexes share the AVL implementation. Dynamic capture tables, generated helper
  copies and the compatibility capture engine have been removed.
- Pure formulas resolve local inputs in dependency order. Source revisions fence
  concurrent evaluations even when an output is unchanged. Validation queries,
  required outputs, permissions and transaction rollback retain explicit boundaries.
- Accounting declares **138 queries**: 32 direct rates, 9 prefixes, 95 reporting
  queries and 2 production validation queries. The three all-in-one ordered
  formulas also use declarations. Six accounting business uniqueness constraints
  use private tenant-rooted trees; native references and runtime indexes remain.
- Builds emit `dependency-plan.json`. CLI, public API and native workbench
  `explain` show source locations, input order, queries and reference routes
  without writing files or opening a database. Accounting exports 48 public
  create schemas and prepares 17 SDK fixture rows.

The accounting schema contains **65 tables**, occupies **11,183,330 bytes**, and
has SHA-256
`f97c34d49df04f68930eb9fa67882a2a283a2cb25e98ff27fe44f847c010b275`.
Freshness checks and the completed financial probe's final recompilation agree
on these bytes. Generated SQL grew; this work does not establish a reduction in
schema size or compilation/application cost.

## Executed checks

| Check | Result |
| --- | --- |
| Full accounting and extensions | 103 source checkpoints, 105 structural checks, 90 exact value queries, 54 complete rollback snapshots; populated identical-schema reapplication and child-first cleanup |
| FX and purchase-tax history | 76 checkpoints, 44 source writes, 46 exact value queries, 2 rollbacks, 31 checked cleanup deletions |
| Declared dependencies | 111 checkpoints, 3 rollbacks, 6 conflicts, 10 declarations; seeded history, reapplication and cleanup |
| Interval queries | 18 checkpoints, 1 rollback; unbounded endpoints, coincident slots, whole-container/endpoint propagation and cleanup |
| Temporal trees | 240 randomized mutations, permissions, concurrent fencing and populated reapplication |
| Typed trees | 252 mutation checkpoints, 1,570 reads, 107 rejection snapshots; cleanup and reapplication |
| Ordered trees | 22 mutations, 683 reads/pages, 10 rollbacks; exact decimals and independent sessions |
| Complete-time algebra | 4,665 sequences / 57,909 folds, plus 777 missing-measure sequences / 3,477 folds |
| Integer ordinal tree | 111 mutations, 412 reads, 11 rollbacks; cleanup |
| Derived order and required/causal outputs | Passed local/helper ordering, protected output lifecycle, diamond propagation, rekeying and rollback checks |
| Dependency cost | 32 readers: 121 structural reads, 1 evaluation; 128 readers: 155 reads, 1 evaluation; unconsumed channel: 0 evaluations; 133 source checkpoints |
| Builds and inspection | Four profiles built and passed freshness; all 12 generated schema/migration files passed native validation; CLI/API explanation agreed and stale plans were rejected |
| Verifier adapter regression | 10 focused tests passed, including strict default numbers, exact rational results and rejection of an 18-place discrepancy |
| Final broad continuation | All-in-one accounts, CRM/HRM suite, general security/data probe and all 54 developer tests passed |
| Native regression after the adapter | 7 source/structural checkpoints, exact dependency integrity and complete cleanup |

The [final manifest](evidence/2026-10-16-declarative-engine.json) and
[retained command output](evidence/2026-10-16-declarative-engine-output.txt)
record command outcomes, source revision boundaries and final fingerprints.
The [full accounting evidence](evidence/2026-10-16-declarative-accounting.json)
and [FX evidence](evidence/2026-10-16-declarative-fx.json) retain the runtime,
schema hashes, cases, source fingerprints and timings. The full accounting run
completed in 26m29s, including DDL, independent scans, reapplication and cleanup.
These are acceptance-suite timings, not ordinary write latency.

## Broad runner and verifier revision boundary

The original `npm run verify` invocation exited **1** in the all-in-one
JavaScript numeric oracle: a query result of `152.11` was compared strictly
with the independently calculated binary floating-point value
`152.10999999999999`. All preceding gates, through causal outputs, passed.

The checker now accepts an optional `equalResult` callback. Only the
all-in-one demo supplies its existing numeric tolerance. Descriptor metadata and
bounds still compare exactly; the main accounting oracle retains rational
equality by default. Focused tests reject both a material demo discrepancy and
an 18-place error in a rational result.

This adapter was added after the full accounting and FX runs finished.
Their stored fingerprints are preserved: only
`dev-tools/temporal-tree/dependency-oracle.js` differs from those recorded
source sets. Engine, accounting formulas and generated schema are unchanged.
The continuation
`npm run probe:accounts && npm run probe:suite && npm run probe && npm run test:dev-tools`
exited **0**. The native adjustment regression passed against the updated
checker. All broad-gate components therefore passed across the recorded runs;
there was no second complete `npm run verify` invocation.

The retained ordinal output ends with an obsolete sentence saying integer
prefix dependencies are unsupported. Only that diagnostic sentence was corrected
after its run; integer query behavior is covered by the typed/dependency probes.

## Reproduced defects

Acceptance work corrected derived parent-date moves before prefix evaluation,
coincident interval-slot coalescing, and filtering of whole-container or interval
endpoint changes. A controlled removal of the interval identity fix fails its
regression. A native endpoint reproduction retained `10` after its source
changed to `12`; the corrected channel filter passes. Descriptor validation
also distinguishes the SQL `FLEXIBLE` clause from the same word in a string.
Accounting uniqueness roots and nodes deny record-user inspection.

## Reproduce

Run from the repository root with the pinned database binary and installed
dependencies. The full commands below include expensive native acceptance.

```bash
npm run build
npm run build:all-in-one
npm run build:all-in-accounting
npm run build:index-analytics
npm run verify
npm run verify:accounting
npm run probe:ordinal-tree
npm run probe:dependency-cost
npm run probe:accounting-adjustment-rekey
npm run probe:accounting-integrity-fx
surreal validate build/all-in-accounting/migrate-one-shot-backfill.surql
surreal validate build/all-in-accounting/migrate-one-shot-finalize.surql
surreal validate build/index-analytics/migrate-one-shot-backfill.surql
surreal validate build/index-analytics/migrate-one-shot-finalize.surql
```

To emit a fresh financial evidence file, invoke
`node dev-tools/accounting/probe.js --all --evidence <new-path.json>`.
Do not overwrite a dated acceptance record with another source revision.

## Limits

The checks cover bounded native histories and explicit contracts. They do not
prove every possible history, production throughput, populated migration from
the retired engine, or external-provider behavior. MetaSol integration was not
part of this replacement.

Arbitrary SQL reads do not acquire reverse dependencies automatically. Query
slots are finite, but the affected population and formula work can still be
large. Diamonds can revisit a record. Feedback is rejected; there is no
fixed-point solver or general guarantee for topology chosen by query results.
The measured structural reads describe the supplied fixtures, not a general
storage-capacity or latency claim.
