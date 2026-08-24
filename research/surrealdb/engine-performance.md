# SurrealDB Performance and Scaling Findings

Status: measured performance reference

This file combines the former query-performance dossier, instance-scaling
measurements, and performance-relevant data-generation results. It owns engine
costs and routing evidence; ReBase policy derived from it belongs in
[`../rebase/authorization.md`](../rebase/authorization.md) and
[`../rebase/compiler-development.md`](../rebase/compiler-development.md).

Tested versions: SurrealDB `3.2.x`, x86_64 Linux, primarily isolated in-memory
databases. Benchmark numbers are local observations, not universal capacity
promises.

## Executive findings

- No universal query strategy exists: permission-only, filtered/sorted, and
  wide-ACL queries need different shapes.
- Dynamic ACL array intersections often force a table scan; scalar OR fan-out
  can use an index for narrow ACLs.
- Wide ACL fan-out becomes slower than a bounded table scan.
- Materialized string indexes are reliable in the tested planner; direct
  indexes over `array<record>` produced incorrect empty matches.
- Namespace/database/table catalog size had little effect on simple CRUD in the
  tested scale; topology extraction benefits from composite batching.
- Schemafull definition is much more expensive than schemaless definition, but
  CRUD latency remained roughly constant across thousands of table definitions.
- Relation arrays, reverse references, events, computed fields, indexes, and
  result serialization dominate fixture-write cost.

## Query-plan benchmarks

### ACL width crossover

| Rows | ACL width `m` | Native scan | Scalar OR fan-out | Filter/sort composite index |
| ---: | ---: | ---: | ---: | ---: |
| 10k | 1 | 415 ms | **15 ms** | 50 ms |
| 10k | 10 | **62 ms** | 141 ms | 67 ms |
| 10k | 100 | **21 ms** | 2,345 ms | 74 ms |
| 100k | 1 | 350 ms | **74 ms** | 390 ms |
| 100k | 10 | **69 ms** | 881 ms | 57 ms |
| 100k | 100 | **24 ms** | 21,126 ms | 83 ms |

The exact crossover depends on data distribution, indexes, limits, storage, and
hardware. Narrow permission-only reads can benefit from scalar fan-out; a
selective business filter/sort should lead with its composite index; wide ACLs
should use a bounded scan with early limit.

### Isolated query shapes

| Shape | Plan | Median DB time | Observation |
| --- | --- | ---: | --- |
| Dynamic `$auth.z_access_index` | TableScan | 13.19 ms | Dynamic intersections were not index-friendly |
| Bound ACL array | reader IndexScan | 3.54 ms | Better allocation, still limited |
| Scalar reader OR branches | reader IndexScan | 3.34 ms | Useful for narrow permission-only reads |
| Business filter + sort | composite IndexScan | 0.60 ms | RLS remained a residual filter |

Permission checks are not O(1); they scale with ACL width and candidate rows.

## Materialized authorization indexes

Indexing `readers_index: array<string>` worked reliably. Direct indexing on
`array<record<...>>` returned zero matches in the tested planner. Scalar OR
branches over discrete access keys forced a union index scan. Mixed
`record<user | groups>` ownership had no measured penalty when represented by
the materialized string index.

The access strategy is workload-dependent:

| Query | Preferred shape |
| --- | --- |
| Narrow permission-only list | Scalar OR fan-out |
| Selective filter/order | Composite business index, RLS residual |
| Wide ACL and no selective filter | Native bounded table scan |
| Direct owner lookup | Native owner comparison |

Do not hard-code a global “always fan out” or “always table scan” promise.

## Catalog and topology scaling

Measured in-memory catalog observations:

| Object count | Catalog listing p95 / average | Memory trend |
| ---: | ---: | --- |
| 5,000 namespaces | ~16 ms average | ~21 MB above baseline |
| 5,000 databases in one namespace | ~17 ms average | ~22 MB above baseline |
| 5,000 tables in one database | ~28 ms average | process RSS ~143 MB |

Simple single-row CRUD remained about 1–2 ms across table counts in the probe.
Schemafull creation of 500 tables with typed fields/indexes took ~371 ms versus
~41 ms schemaless. `INFO FOR DB` on 1,000 tables took ~11 ms and `INFO FOR TABLE`
about ~1.5 ms.

For a hierarchy of namespaces × databases × tables, composite multi-statement
extraction beat sequential and a concurrency pool:

| Topology | Sequential | Concurrent 25 | Composite |
| --- | ---: | ---: | ---: |
| 10 NS × 5 DB × 10 tables | 81.56 ms | 24.37 ms | **17.79 ms** |
| 50 NS × 5 DB × 10 tables | 323.37 ms | 106.06 ms | **67.03 ms** |
| 10 NS × 50 DB × 10 tables | 590.43 ms | 180.00 ms | **86.20 ms** |
| 20 NS × 20 DB × 20 tables | 426.25 ms | 171.26 ms | **131.40 ms** |

`USE NS ... DB ...` cannot execute dynamically inside a `FOR`; generate bounded
top-level composite statements instead.

## Data-generation costs and rules

Approximate time for 10,000 records in the original probe:

| Operation | Time |
| --- | ---: |
| Mapped bulk `INSERT` | 10.6 s |
| Direct `FOR` + ordinal IDs | 0.28 s |
| Direct `FOR` + random database IDs | 0.33 s |
| `FOR` + object merge | 0.47 s |
| Two cross-table loops with references | 0.69 s |
| Self-reference with ordinal IDs | 0.55 s |
| Precomputed random ID array | ~15 s |
| Two-parent arrays with reverse references | ~9.2 s |

The practical findings are:

- let `CREATE table CONTENT` generate IDs directly;
- avoid giant precomputed random-ID arrays and one request per record;
- batch cross-table writes and suppress result serialization with `RETURN NONE`;
- use keyset pagination and bounded reservoirs rather than `COUNT + OFFSET` or
  `ORDER BY rand()`;
- select reference pools only from committed prior batches;
- use explicit anchors such as `groups:root` and reject required dependency
  cycles before writing;
- JSON Schema/AJV/JSON-Schema-Faker validate/generate scalar payloads in Node,
  while SurrealDB validates native types, assertions, references, permissions,
  events, and computed fields;
- JS seeds reproduce payloads and uniqueness retries, but SurrealDB `rand::*`
  IDs and relation choices are intentionally not controlled by that seed;
- a separate deterministic ordinal materialization mode is needed to reproduce
  exact graph edges.

Node ID generation was not the bottleneck (~1.9 million IDs/s in the local
probe); full relation-aware JSF was about 500–650 rows/s, payload-only JSF about
2,600–5,300 rows/s. Relation reverse maintenance, events, computed fields,
indexes, and output account for the database-side cost.

## Engine pitfalls

### Computed fields and create permissions

`FOR create NONE` on a computed/value field caused the `VALUE` expression to be
skipped during create in one probe, leaving a computed ACL field empty. A `VALUE`
expression may already overwrite client input; do not add create-deny permissions
without probing the actual field and access context. See
[`update-permissions.md`](./update-permissions.md).

### Reactive cascade recursion

Creating a record contributing to two reactive views targeting the same parent
triggered a nested cascade error (`deletion for a view but no record exists`).
The compiler’s generated cascade guard prevents recursive re-entry.

### Import is not schema deployment

`surreal import` is intended for raw data dumps and disabled schema processing in
the tested workflow. Use `surreal sql` for schema deployment so events,
computed fields, and RLS are installed and executed.

### Polymorphic ownership casts

Casting `$value` to string inside a create permission and checking it against
`$auth.z_access_index` silently dropped creates in the probe. Use native record
comparisons for owner authorization; reserve string casts for indexed materialized
reader/access lookup paths.

### Stale build artifacts

Reused output folders retained removed optimizer/manifest files. The compiler
must clean known legacy artifacts or compare the complete expected artifact tree.

### Change detection

Direct structural `!=` was roughly twice as fast as hashing on nested 10–500 item
values and was comparable to `value::diff()`. `value::diff()` returns JSON Patch
operations, not a prior-value snapshot. `array::difference()` is symmetric;
`array::complement()` is one-sided and only suitable for set-like semantics.

## Measurement rules

1. Choose query shape from ACL width and filter selectivity.
2. Benchmark the same schema, indexes, limits, result projection, storage mode,
   and batch size when comparing alternatives.
3. Measure reverse-reference fanout before changing propagation.
4. Treat local timings as evidence for a workload, not a capacity guarantee.
5. Re-run probes after SurrealDB, storage engine, index, event, or compiler
   changes.
