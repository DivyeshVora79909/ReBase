# Accounting verification — October 14

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

## What passed

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

## Observed acceptance cost

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
npm run probe:observed-reads
npm run test:dev-tools
```

The [developer guide](developer-guide.md) and shared
[automatic-read contract](../rebase-system/function-reactivity.md) define the API.
A populated old-schema migration, MetaSol adaptation and current-rate valuation
of remaining stock require separate work. Event-time reporting units and the
accounting calculation equations retain their existing meaning.
