# Authorization stress results

This experiment compares ordinary permission-filtered reads with explicit custom
tree candidate selection, followed by normal authenticated record hydration.
It uses the current compiled framework, real persisted source records and full
intrusive AVL nodes. It does not substitute compressed or weighted placeholder
nodes for the requested population.

Runner and methodology: [authorization-stress](../../dev-tools/experiments/authorization-stress/README.md).

## Environment and scope

- Baseline: `aef9eb37a82fca30541a448436878a3c23bf946e`, after pulling origin main.
- Node 26.12.0, SurrealDB 3.3.0, Linux, AMD EPYC 9V74, four CPU quota equivalents.
- Disposable, on-disk SurrealKV on loopback; no application database or credentials.
- 32 owner partitions. The wide actor can read 16; the sparse actor can read one.
- Main scaling workload: one membership slot and one additive aggregate per record.
- Separate 1,000-row configurations: zero slots/zero aggregates, one/zero,
  four/one and four/eight. Every configuration uses real authenticated mutations.
- Sequential read cases use three timed warm-cache samples after an excluded
  warm-up. Expensive bounded post-filters use one measured pass. These samples
  describe this run; they do not establish a production p95 or capacity target.

## Measured results

The [complete machine-readable report](authorization-stress-results.json) finished
with status `passed` in 1,403.7 seconds on 2026-10-19 UTC. All five requested
scales completed; none were skipped. Twenty-four native sorted SELECT comparison
paths timed out and are explicitly recorded as limits, not successful queries.

Median time in milliseconds for the first page of up to 50 records:

| Stored records | Wide custom merge | Wide native scan | Sparse custom merge | Sparse native scan |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 580.4 | 9.2 | 17.1 | 10.0 |
| 1,000 | 869.4 | 66.1 | 74.1 | 79.6 |
| 10,000 | 942.8 | 662.4 | 123.8 | 779.9 |
| 100,000 | 962.1 | 3 s timeout | 126.0 | 3 s timeout |
| 1,000,000 | 1,096.3 | 3 s timeout | 122.8 | 3 s timeout |

Sparse pages contain only four records at scale 100 and 32 at scale 1,000. From
10,000 onward they contain 50. The million-record fixture has 32 trees with
31,250 nodes each; it is not one tree containing a million nodes.

The indexed path stayed relatively stable as the table grew, but it did not win
every comparison. Ordinary scans were much faster for the wide actor at small
scales. At 1,000 rows, native backlink candidate sorting took 23.8 ms for the
sparse actor, compared with 74.1 ms for custom paging. At 100,000 rows, sorting
that actor's 3,125 backlink candidates took 2,103.9 ms, versus 126.0 ms for the
custom page. Candidate materialization above 20,000 was deliberately skipped.

At one million records, the bounded merge fetched 80 candidates for the wide
50-row page; full prefetch fetched 800 and took 5,568.2 ms. Four-way bounded
fetching took 1,046.3 ms and five RPCs, versus 1,096.3 ms and two RPCs for the
single candidate request plus hydration. This small sample does not establish a
meaningful parallel-fetch benefit. One/two/four independent reader sessions
delivered 0.94/1.86/3.64 completed pages per second in the short concurrent test.

Native mutation medians, milliseconds, for one slot and one aggregate:

| Stored records | CREATE | Payload UPDATE | Aggregate UPDATE | Rekey | Owner move | DELETE |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 36.8 | 10.7 | 35.3 | 48.0 | 49.7 | 25.9 |
| 1,000 | 45.9 | 11.0 | 39.0 | 57.8 | 67.9 | 34.1 |
| 10,000 | 55.8 | 12.1 | 50.5 | 76.8 | 91.4 | 43.7 |
| 100,000 | 62.0 | 11.9 | 61.5 | 103.2 | 117.6 | 57.4 |
| 1,000,000 | 73.5 | 11.6 | 70.7 | 123.3 | 130.3 | 62.2 |

Four simultaneous writers to one owner root all committed at every scale. Each
scale surfaced six conflicts, with no exhausted four-attempt retry budget.
At one million records the group completed at 11.8 successful creates/second,
including retries, then sequential cleanup restored the exact root aggregates.
This is a short hotspot check, not a sustained write saturation measurement.

Native mutation costs at 1,000 rows also depend strongly on slots and measures:

| Slots | Measures per slot | CREATE ms | Aggregate UPDATE ms | Rekey ms | Owner move ms | DELETE ms |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 0 | 9.2 | 7.8 | 7.7 | 9.6 | 5.9 |
| 1 | 0 | 48.5 | 10.8 | 57.8 | 66.4 | 30.4 |
| 4 | 1 | 174.3 | 177.6 | 312.7 | 310.8 | 146.7 |
| 4 | 8 | 285.9 | 314.7 | 492.4 | 540.7 | 254.2 |

These are three native samples per operation. The main one-slot/one-measure
configuration is in the preceding table. Wider maintenance is an observed write
cost; more indexes and aggregates are not free.

The wide actor's million-row unindexed `hot` filter found ten matches after
visiting 853 rows in 12.56 seconds. An absent predicate visited the 1,000-row cap
in 13.78 seconds and correctly reported `truncated: true`. The sparse actor took
2.31 seconds for its capped absent search. Ordered paging does not make
unindexed filtering cheap or prove absence after a bounded search.

Million-row construction took 582.0 seconds and complete initial verification
128.8 seconds. After the read/write matrix, sampled server RSS was 5,809.7 MiB,
client RSS 148.3 MiB and the private directory 2,116.0 MiB. Combined RSS was about
5,958 MiB against the 6,000 MiB sampled limit: there was little headroom. These
are post-stage observations, not peaks or per-record storage estimates. This run
does not isolate which phase caused memory growth or establish a safe production
memory ceiling.

At 100,000 rows the outsider's native denial scan timed out; at one million all
three native denial scans timed out. Their custom root reads were rejected.
Successful smaller-scale negative tests and functional checks remain evidence,
but a timed-out denial scan does not establish that it completed without leakage.

All 118 development-tool unit tests passed after the scale run, including the six
new pagination tests covering skewed/interleaved streams, ties, forward/reverse
walks, bounded/full buffering, fanout, overlap rejection and truncated continuation.

The archived scale report's construction limitation contains the older phrase
“source events only.” For its recorded `seed-mode: image`, construction also
suspends other field/schema processing as explained below; all definitions were
restored before measurement. The source hash records the exact measured suite.

## What the checks establish

The functional authorization matrix checks 2,415 assertions across 11 cases:
source-DAG dominance and access, inherited reader selection and reordering, owner
changes, grants and revocations with existing and fresh sessions, table-role
revocation, direct-parent group access without principal SELECT permission,
different UPDATE and DELETE authority, diamond alternate paths, cycle rejection,
tenant separation, closure forgery, rollback and concurrent opposing parent edits.
Graph shapes include a chain, balanced tree, star and diamond. Expected access
comes from a separate JavaScript traversal of source parents, not the database's
cached authorization closure.

Every completed scale checks all initially seeded records, every complete tree
node and every root header in bounded batches against source-derived expected
state. Native ownership backlinks are checked separately. Small stages also run
the independent structural oracle, reconstructing AVL ordering, balance, links,
chronology and aggregates. They walk every visible record forward and backward,
checking cursor progress, rank ties, completeness and duplicates.

Larger stages test first/middle/last pages, sizes 1/50/200, reverse paging,
independent record lookups, bounded and full-prefetch merges, four-way candidate
fetching, native scans and reference candidates, summary/range aggregates and
nonindexed post-filters. Results must match independent expected source IDs.
Post-filters have a 1,000-row visit budget and explicitly report incomplete
searches. A truncated empty result does not mean no later match exists.

Native authenticated CREATE, payload UPDATE, aggregate UPDATE, rekey, owner move
and DELETE verify actual row changes and exact aggregate restoration. Four
writers contend on the same owner root, with up to four attempts per writer;
the suite records conflicts and exhausted retries, checks committed IDs and
aggregates, and cleans up through sequential native deletes. Concurrent reads
use one, two and four independent record sessions.

## Interpretation and limits

The planner evidence distinguishes `TableScan`, `ReferenceScan` and `RecordIdScan`.
The custom tree is an explicit query API: declaring it does not make an ordinary
SELECT automatically choose it. There is no added native compound-index control
in this experiment; scan comparisons use the current unindexed sorted query
shape. These results do not compare custom trees against every native indexing
design. A native reference union also needs to
materialize and sort its candidates; narrowing candidates is not the same as
obtaining an ordered page directly.

For `K` disjoint authorized owner roots and page size `P`, an ideal indexed merge
does roughly `K` tree seeks plus a heap merge costing `P log K`, with additional
buffer refill work. Tree seeks depend on each partition's height, not the page
offset. Full prefetch can return up to `K * P` candidates. Bounded buffering
reduces this excess, but root discovery, interpreted database functions,
permission checks, seeks, hydration and round trips still have real costs.
The suite measures discovery separately once per actor/stage; page medians
exclude discovery and assume the resulting authorized root list is reusable
during that unchanged authorization state.

The owner-root union is complete for this deliberately declared workload because
`read_by = owned_by`. Arbitrary inherited-reader business records need a complete
reader candidate index or another complete candidate source. Applying only an
owner index to those records could omit records a user is allowed to read.
Native hydration protects returned records; it cannot recover missing candidates.

Fixture preparation is not native insert throughput. Construction timings also
include replacing the preceding scale, schema changes and restoration; they are
not isolated raw INSERT timings. Default image mode obtains
native prototypes, suspends workload events and other field/schema processing,
retains native ownership REFERENCE handling, inserts full validated images and
restores exact metadata before timing. Root-header imports contain no native
reference fields. `OPTION IMPORT` on source records would skip reference
bookkeeping; restoring events afterward would not reconstruct missing trees.

After native writes, full structural reconstruction is capped at 1,000 rows.
At larger scales, the checks cover intended row effects, root aggregates and
revisions, but not every post-write node invariant. Initial image verification
at every scale is complete. Functional graph changes use small isolated graphs;
the experiment does not measure a reparent/revocation that repairs a million
dependent business records. Such work can grow with the affected population.

The suite also does not establish crash recovery, cold-cache latency, a production
write saturation point, behavior during concurrent page mutation, arbitrary
overlapping-root deduplication, or application accounting/business-rule cost.
Pagination exposes revisions but does not promise a multi-request snapshot.
Memory and disk observations are sampled, not guaranteed process peaks. Native
query timeouts are performance limits, not completed-query correctness evidence.

## Reproduction

```sh
node dev-tools/experiments/authorization-stress \
  --scales 100,1000,10000,100000,1000000 \
  --seed-mode image --owner-count 32 --batch-rows 500 --samples 3 \
  --budget-seconds 1800 --max-stage-seconds 900 \
  --max-rss-mb 6000 --max-disk-mb 10000 \
  --scan-timeout-ms 3000 --variant-rows 1000 \
  --output /tmp/rebase-authorization-stress.json

npm run test:dev-tools
```

Admission projections can skip requested scales, and the suite has a hard overall
deadline. Inspect status, completed stages, skipped scales and timed-out paths;
requesting one million rows does not itself demonstrate a completed million-row
test. The JSON records actual counts, durations, samples, plans, resource
observations, environment and source/schema hashes.
