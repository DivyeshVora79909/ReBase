# Accounting verification — October 14

## Fresh integrity repair acceptance

The repaired compiler and accounting model passed a fresh full acceptance on
SurrealDB **3.3.0 / Node 24.19.0** with SurrealKV: **103 source-oracle
checkpoints, 105 structural checks, 90 exact value queries and 51 complete
rollback snapshots**. The 69-table schema passed populated identical-schema
reapplication and child-first cleanup. The run took **14m36s**.

The accepted schema is 5,124,663 bytes with SHA-256
`8515e1c503e886640ce0383b2fc3045999b3fc70ea1094b47f6e99a63c44d464`. The
[machine-readable acceptance](../rebase-system/evidence/2026-10-14-integrity-accounting.json)
contains all compiled-table snapshots, source hashes, exact commands, runtime
versions and phase timings. The
[integrity report](../rebase-system/evidence/2026-10-14-integrity-repair.md)
lists targeted gate results and their bounded scope.

The standalone [FX and purchase-tax regression](../rebase-system/evidence/2026-10-14-integrity-fx.json)
passed 44 source writes, 31 per-delete cleanup checks, 76 checkpoints, 46 exact
value queries and 2 complete rollback snapshots. It covers the reported later
sale index failure, dated multi-currency changes, and a converted purchase
issue with base tax, tax-on-tax, an issue adjustment, and both explicit tax
children.

## Earlier automatic-reactivity acceptance (historical)

Fresh consolidated acceptance passed on SurrealDB 3.3.0 / Node 22.23.2 with
SurrealKV: **103 source-oracle checkpoints and 51 complete rollback snapshots**.
Core and extension cases ran in one disposable database, followed by exact
populated-schema reapplication and sequential child-first cleanup. All logical
reads, evaluation frames and reverse groups were released during cleanup.

The [evidence](../rebase-system/evidence/2026-10-14-automatic-accounting.json)
records cases, timings and frozen source fingerprints. Its schema SHA-256 is
`a95860f839a4177e92efbb558f43b0fc98df178dc4f9b7d612fb8e4332fede03`, matching
the CLI's **5,120,586-byte, 69-table** schema. See the
[completed output](../rebase-system/evidence/2026-10-14-automatic-accounting-output.txt).
October 13 evidence verifies the historical `ae10ba8` implementation.

## Earlier run coverage

- Sparse native positions, mirrored contributions, covered advances and
  independent chronological invoice capacities.
- Combined quantity/price adjustments, chronological cascades, all five strict
  tax adjustments, capped marginal rules and source/reference moves.
- Automatic dated-rate insertion, editing, movement, reparenting, deletion,
  fallback and reader date/reference changes, including same-date nanoseconds.
- Independent rational source arithmetic, business AVL structure and every
  consumed subscription value, generation, point index and interval index.
- Rejections restore accounting, audit, subscriptions, source fences and trees.
- Fees, fee taxes, withholding, tax cash/offsets, claims, competing settlements,
  cross-subsidiary transfers and independent exchange observations.
- Production reservations, strictly prior gross funding, output capacity,
  resource windows and adjacent intervals.
- Tenant and record-user permissions, protected metadata/derived fields,
  native SDK decimals, the executable fixture and its graph/tree queries.
- A late rate edit with the populated financial/production graph recalculates
  reporting projections while preserving every native stock summary.
- Exact populated reapplication and cleanup of all calculation subscriptions.

The focused [automatic-read proof](../rebase-system/evidence/2026-10-14-automatic-reads.json)
passed **50 checkpoints and 7 rollbacks**, including duplicate/nested reads,
branch changes, empty results, selected record/key objects, prefix chains,
publications, forced concurrent registration, tenant isolation and cleanup.
Its interval case visited **24 nodes for 68 registered ranges**.

All **30 developer-tool tests** passed; see the
[test output](../rebase-system/evidence/2026-10-14-automatic-dev-tests.txt).
Compiler, architecture, temporal-tree, typed-tree, ordered-tree, derived-order,
required-output, causal-output, runtime and adapter checks passed. The typed-tree
proof covered 113 mutations, 1,101 ordered reads and 105 rejection snapshots;
the temporal proof included 240 randomized mutations. The ordered proof covered
composite, decimal, record, UUID and Boolean keys and concurrent sessions.

## Earlier acceptance cost

| Phase | Elapsed |
| --- | ---: |
| Fresh schema application | 142.727 s |
| Fixture setup | 7.147 s |
| Core and extension scenarios | 1,248.498 s |
| Populated schema reapplication | 232.166 s |
| Sequential cleanup | 258.383 s |

The run took approximately 31.5 minutes on this host. These correctness-suite
measurements include independent source scans, metadata/tree verification and
DDL. They do not measure ordinary transaction latency or production capacity.

## Reproduce

```bash
npm run build:all-in-accounting
npm run verify:accounting
npm run probe:accounting-integrity-fx
npm run probe:typed-tree-seeded
npm run probe:observed-reads
npm run test:dev-tools
```

The [developer guide](developer-guide.md) and shared
[automatic-read contract](../rebase-system/function-reactivity.md) define the API.
A populated old-schema migration, MetaSol adaptation and current-rate valuation
of remaining stock require separate work. Event-time reporting units and the
accounting calculation equations retain their existing meaning.
