# Authorization Select Performance

## Verdict

The current authorization model is correct and fast for record lookups and explicitly selective queries, but the unqualified default select shape does not scale as a count/list operation. SurrealDB uses a `TableScan` for the generated visibility/readers/owner OR predicate. The existing `owned_by` and `readers_index.*` indexes are used when the query supplies an explicit owner or reader condition, but they do not turn the complete authorization predicate into one indexed access path.

This is acceptable for bounded pages, direct record access, and queries with a business filter. It is not acceptable to expose unrestricted `COUNT`, export, or deep offset pagination over large tables to ordinary record users without a separate query/index design.

## Scope And Environment

- Project: current `designs/test` authorization behavior.
- SurrealDB `3.2.0` for Linux x86_64.
- Node `22.23.2`.
- Host: Linux x64; measurements are local WebSocket client wall-clock timings.
- Datastore: disposable temporary RocksDB, deleted after each run.
- Dataset: 10,000, 50,000, and 100,000 rows in each synthetic table. Rows were inserted in 250-row transactions with a 50 ms pause after each batch.
- Each latency value used three warmups and twelve measured calls; p50 and p95 are reported.
- Query payloads were separated: `SELECT VALUE id` measures authorization/query work with minimal serialization; `SELECT *` shows full-row payload cost.
- The benchmark process runs at reduced OS priority. Query concurrency is capped at eight in-flight connections; connection creation is staggered. These controls prevent burst-induced desktop starvation without reducing total rows or the measured workload.

Reproduce with:

```sh
node dev-tools/authorization-performance.js
```

Useful safety controls are `REBASE_PERF_ROWS`, `REBASE_PERF_BATCH_ROWS`, `REBASE_PERF_BATCH_PAUSE_MS`, and `REBASE_PERF_QUERY_CONCURRENCY`. The harness defaults to temporary RocksDB; set `REBASE_PERF_MEMORY=1` only for a small disposable smoke test.

For long runs, set `REBASE_PERF_OUTPUT=/path/to/result.json`. The harness checkpoints the JSON after every completed scale so an isolated late scenario failure does not discard earlier measurements.

## Policies Tested

The benchmark reproduces the current generated predicate:

```surql
'table_select' IN $auth.permissions AND
(!!visibility OR readers_index CONTAINS <string>$auth.id
 OR <string>owned_by IN $auth.z_access_index)
```

The comparison tables are:

- `bench_default`: visibility + readers + dominated-owner predicate; indexes on `owned_by`, `readers_index.*`, and `(bucket, seq)`.
- `bench_owner_current`: visibility + dominated-owner predicate, but still retains reader field/indexes as current owner mode generation does.
- `bench_owner_lean`: same owner predicate with reader storage/index removed; comparison for a policy-aware generator.
- `bench_open`: permission check only; baseline without row visibility logic.

The narrow actor had `z_access_index` width 2. The wide actor had width 102 (the actor plus 100 dominated groups). Rows were distributed across visible, reader, direct-owner, dominated-owner, and denied cases.

## Query Plans

Representative `EXPLAIN FULL` results at 1,000 rows:

| Query shape | Plan | Meaning |
|---|---|---|
| Default page, no business filter | `TableScan` | The complete dynamic OR authorization predicate is not index-driven. |
| Explicit `owned_by = ...` | `IndexScan` on `bench_default_owned_by` | Owner filtering is indexed when supplied by the query. |
| Explicit `readers_index CONTAINS ...` | `IndexScan` on `bench_default_readers` | Reader filtering is indexed when supplied by the query. |
| `visibility = true` | `TableScan` with pre-decode filter | No visibility index exists. |
| `(bucket, seq)` business filter/order | `IndexScan` | A selective business predicate remains usable. |
| Owner-mode page without explicit filter | `TableScan` | Removing the reader branch alone does not change the unqualified plan. |

The permission expression is therefore a residual security predicate for common list queries, not a general replacement for tenant/business indexes.

### Additional index/type permutations

An extended 10k-row matrix tested the missing isolated variants:

| Permission/query variant | Stored type/index | Unqualified plan | Concrete matching filter plan |
|---|---|---|---|
| Full current OR + indexed visibility | record owner; indexes on visibility, owner, readers | `TableScan` | `visibility = true` uses visibility `IndexScan` |
| Full current OR + string owner | string owner; owner index | `TableScan` | `owned_by_key = 'user:bench_narrow'` uses `IndexScan` |
| Owner only, string | string owner; owner index | `TableScan` | concrete owner equality uses `IndexScan` |
| Owner only, record | record owner; owner index | `TableScan` | concrete record equality uses `IndexScan` |
| Reader only | `array<string>`; element index | `TableScan` | concrete reader `CONTAINS` uses `IndexScan` |
| Visibility only | bool; visibility index | `TableScan` | explicit `visibility = true` uses `IndexScan` |
| Full OR using `visibility = true` instead of `!!visibility` | all three indexes | `TableScan` | no change to unqualified OR plan |

SurrealDB can index record-valued owner equality. The limitation is not that record IDs are inherently unindexable: both record equality and string equality selected their indexes. The dynamic `field IN $auth.z_access_index` expression inside table permissions was not chosen as an index scan for either type. Likewise, a table permission containing only reader membership or only indexed visibility remained a table scan unless the user query repeated a concrete matching predicate.

## Latency Results

Values are p50 milliseconds; p95 is in parentheses. `ids` is `SELECT VALUE id ... LIMIT 100`; count is an authorized `COUNT` over the full table.

### Narrow access set (`z_access_index` width 2)

| Rows/table | Default page ids | Default full rows | Default count | Explicit owner | Explicit reader | Visible filter | Selective business filter | Direct allowed/denied id |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10k | 8.6 (9.0) | 9.9 (11.2) | 312.0 (363.4) | 17.0 (18.9) | 12.8 (15.2) | 4.0 (4.8) | 3.2 (3.5) | 1.6 (2.1) / 1.6 (2.0) |
| 50k | 7.6 (8.1) | 8.6 (11.6) | 1,471.6 (1,674.1) | 17.1 (17.6) | 13.6 (14.7) | 3.6 (4.6) | 9.1 (9.4) | 1.5 (2.0) / 1.5 (1.7) |
| 100k | 6.9 (8.4) | 8.9 (10.0) | 2,991.4 (3,461.9) | 15.1 (18.6) | 13.6 (15.8) | 3.4 (4.2) | 14.2 (16.1) | 1.6 (1.8) / 1.4 (1.8) |

The bounded default page remains roughly constant because the first 100 qualifying rows are found early in this distribution. The authorized count scales approximately linearly: about 0.31 s at 10k, 1.47 s at 50k, and 2.99 s at 100k.

### Extended isolated matrix at 10k rows

Values are p50 milliseconds from the reduced five-repetition extension run. These compare authorization shapes, not production capacity.

| Variant | Narrow page | Narrow count | Wide page | Wide count |
|---|---:|---:|---:|---:|
| Full current OR, record owner | 8.3 | 255.8 | — | — |
| Full OR, string owner | 6.3 | 267.4 | 14.4 | 512.2 |
| Owner only, string | 5.6 | 235.4 | 13.0 | 434.3 |
| Owner only, record | 6.3 | 287.8 | 18.0 | 511.2 |
| Reader only | 5.8 | 276.9 | 11.2 | 424.1 |
| Visibility only, indexed | 9.2 | 136.6 | same for both actors | same for both actors |
| Full OR + visibility index | 11.3 | 269.7 | — | — |
| Full OR with `visibility = true` | 9.0 | 354.2 | — | — |

At 10k rows the string-owner isolated policy was somewhat faster than the record-owner equivalent, especially for the wide actor, but both still scanned and both remained sensitive to access-array width. This does not justify replacing `owned_by` records with strings: it would give up typed references and database integrity for a variable constant-factor gain, without solving the main scan problem.

Adding a visibility index made the full unqualified OR page slower in this run (11.3 ms versus 8.3 ms) and did not improve its count. An explicit visibility query selected the index but took about 12.8 ms for a 100-row page versus about 3.9 ms for the unindexed table scan because one third of rows were visible and sequential scanning found matches cheaply. Boolean indexes are useful only when the selected value is sufficiently rare or a composite query needs them.

Concrete owner/reader filters selected indexes, but their authorized counts still evaluated table permissions and remained about 0.23–0.29 s at 10k. Repeating a concrete authorization filter narrows candidate lookup for pages; it is not a permission bypass or a guaranteed count optimization.

### Wide access set (`z_access_index` width 102)

| Rows/table | Default page ids | Default count | Owner-current page | Owner-current count |
|---:|---:|---:|---:|---:|
| 10k | 17.6 (18.5) | 582.8 (696.0) | 15.2 (16.3) | 468.6 (567.6) |
| 50k | 20.4 (26.9) | 2,837.0 (3,091.2) | 11.4 (12.3) | 1,961.4 (2,044.3) |
| 100k | 17.1 (19.6) | 5,764.9 (5,914.2) | 13.0 (15.5) | 4,515.6 (4,857.7) |

Widening the actor access set from 2 to 102 strings roughly doubled the default page and count latency. This cost comes from evaluating membership against a larger `$auth.z_access_index` on rows that reach the owner branch. Owner mode removes the reader branch and is materially cheaper for wide actors, but it remains scan-based for unqualified pages/counts.

### Owner-current versus owner-lean writes

At 100k rows/table, cumulative insertion time was approximately:

| Table | Insert time |
|---|---:|
| `bench_owner_current` (reader field/index retained) | 142.6 s |
| `bench_owner_lean` (reader field/index removed) | 139.7 s |

This synthetic difference is about 2%. It is not evidence that reader indexes are free: the benchmark uses short arrays and is dominated by transactional/index maintenance across several columns. It does show that owner mode currently carries unnecessary reader storage/index maintenance with a measurable, though modest, write cost in this shape.

## Concurrency

The bounded concurrency smoke test ran against the 100k-row dataset with `SELECT VALUE id FROM bench_default LIMIT 100`:

| Clients | Operations | Throughput | p50 | p95 |
|---:|---:|---:|---:|---:|
| 1 | 10 | 34.7 qps | 8.4 ms | 10.0 ms |
| 8 | 80 | 253.1 qps | 10.6 ms | 13.3 ms |
| 32 (8 in flight) | 160 | 189.9 qps | 10.5 ms | 13.1 ms |

The 32-client result is intentionally capped at eight in-flight queries. It demonstrates bounded behavior, not an unconstrained saturation limit.

## Findings

1. **High: unqualified authorized counts and full scans scale linearly.** The default policy causes table scans. At 100k rows, a narrow actor count is about 3.0 s p50 and a wide actor count about 5.8 s. This will become an operational problem for dashboards, exports, and pagination that repeatedly counts the whole relation.
2. **Medium: wide dominance sets increase authorization CPU cost.** A 102-entry `z_access_index` nearly doubles default page/count latency versus a 2-entry set. The design is functionally valid, but hierarchy width is a direct performance dimension.
3. **Medium: global owner mode is only a predicate optimization today.** It removes the reader OR branch, but generated reader fields, reader indexes, and related maintenance remain. Make index/field generation policy-aware if owner mode is used broadly.
4. **Low: visibility is not indexed.** A query explicitly filtering `visibility = true` is a table scan. This is usually acceptable because visible rows are common and pages terminate early; it is not suitable for large visibility-only counts.
5. **Positive: direct record authorization is stable.** Allowed and denied direct-ID reads stayed around 1.5–1.6 ms through 100k rows.
6. **Positive: explicit owner/reader and business predicates use indexes.** Callers should provide a selective business predicate or explicit authorization-compatible filter for list endpoints.

## Recommendations

- Keep the current security predicate as the authoritative fallback; do not replace it with client-supplied authorization filters.
- Make generated list APIs require a bounded `LIMIT` and reject or specially authorize unbounded `COUNT`/export requests.
- Prefer keyset pagination over offsets, but add a composite index matching the real business order. The synthetic `(bucket, seq)` index was used, though its residual authorization work still grows with table size.
- Consider a policy-aware compiler branch that omits `readers_index` fields, indexes, and reader cascade work for `@rebase-select owner`. This is a write/storage optimization, not a fix for scan-based counts.
- Keep `z_access_index` compact where possible. Deep, wide DAGs should be treated as a capacity metric and observed.
- Do not add a visibility index without measuring the actual visible/hidden distribution; it may help highly selective visibility queries but adds write cost.
- Keep `owned_by` as a typed record. SurrealDB demonstrably uses its index for concrete record equality. A parallel string owner does not make the dynamic access-array permission index-driven and would duplicate ownership state.
- If a list endpoint knows it is intentionally owner-only or reader-only, include the corresponding concrete filter so SurrealDB can select that index; the table permission must still remain authoritative.
- Repeat this benchmark with production-like row widths, reader-array widths, persistent RocksDB settings, and realistic business indexes before selecting capacity limits.

## Limitations

These are local single-process measurements, not a production cluster benchmark. Network latency, concurrent writes, cache state, disk class, dataset skew, and actual client projections will change absolute numbers. The benchmark intentionally uses synthetic tables to isolate authorization behavior; it does not claim that every generated table has the same write amplification or reference/view cost.
