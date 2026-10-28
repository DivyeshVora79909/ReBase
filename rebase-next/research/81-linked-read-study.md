# Linked read-path study

**Status: complete for the bounded local study.** This measures the unchanged native source at `1560ba1` on `linked-avl-baseline`. It adds research harnesses and evidence only; it does not implement the ordered-index redesign or change production code, behavior, codecs, or public limits. The [artifact index](evidence/2026-10-28-linked-read-artifacts.json) contains exact source and build hashes, raw samples, topology metadata, and earlier incomplete trials.

## What each path measures

The paths below are separate because they return different things and exercise different layers.

| Label | Measured path | Meaning |
| --- | --- | --- |
| A | Current `tree::range_keys` / prefix summary | Returns a native aggregate summary. It does not return the requested records. |
| B | Research-composed next-chain traversal over persisted native AVL nodes and `Attempt::record` | Measures linked ID traversal and optional sequential Entry hydration. The research caller selected a 1,000,000-unit Attempt budget; q=10,000 is outside public query/page bounds. |
| C | Actual `Store::page` public reader path | Reads the ordered UUID index and hydrates public records over repeated calls with a 32-row limit and 128-row visit budget. The harness calls Store directly and excludes HTTP, TLS, JWT, and authority setup. Its 4,096-record fixture bypasses mutation/reference-graph validation during bulk setup; the page path itself does not hydrate Accounts. |
| D | Experimental raw ordered range with Entry payload embedded in the index value | A research-only covering-index comparison. It duplicates Entry payload and does not describe the current default index. |

## How the runs were checked

The main fixture has n=10,000 and n=100,000 records; the n=100,000 native fixture contains 200,001 rows and 103,052,217 encoded value bytes. Each Entry encodes to 330 bytes. The experimental covering index adds that Entry payload to its ordered value and uses 28-byte ordered keys, trading additional stored bytes for fewer linked record loads. At n=100,000, that is 33.0 MB of duplicated Entry payload plus 2.8 MB of ordered-key bytes by the recorded per-entry sizes, before adapter/database overhead. The bulk fixtures bypass public population admission for this experiment only; no production capacity or query cap changed.

The redb, SurrealKV, and final FoundationDB profiles each completed 53 main cases with three timed samples per case. The separate actual `Store::page` harness completed four q sizes per backend with three timed samples each. Every output and checksum was checked against independently constructed source expectations outside the timed span. Result row counts and hashes agree across all three backends for each matched case; page output hashes also agree across backends.

This is 171 timed cases total (159 main cases plus 12 public-page cases), with three samples per case: 513 timed samples across the three backends. Each timing is the median of three fresh read transactions after a process warmup. Backend, OS, and storage caches were warm or uncontrolled. These are descriptive medians, not p95/p99 or tail-capacity evidence. Large linked traces can overflow their event/provenance bounds; their counters continue, while trace completeness and dependent key lineage remain explicitly incomplete. Correctness checks do not rely on those incomplete traces.

The native harness was compiled with the optimized local Rust toolchain against existing dependencies, using the exact source map and `-O` flags retained in evidence. No Cargo build or native rerun was performed for report processing. The 80-file compiled native source map matched current file hashes, the optimized library hash is `f60b60e1f562a4f546b7de34a82f6b233f2b933396d13ec8285510ab4bf162e7`, and both harness source and binary hashes matched their recorded values. The accepted 91-file application source map also rechecked with no file mismatches and its original digest `be20039f3f563320bf4095a3a85d6b4da57aa2875ba858c64e6a6acc4c077281`.

## Linked traversal and covering range at n=100,000

Times below are milliseconds. Each cell is `redb / SurrealKV / local FoundationDB`, in that order. For B and D, q is the requested result count. `start=0` begins at the earliest key in ascending key order, then returns q consecutive results. The q=10,000 row is a research consumer; it exceeds production query/page bounds.

**B — linked ID traversal, with no Entry hydration**

| q | redb / SurrealKV / FDB (ms) |
| ---: | ---: |
| 50 | 0.301 / 0.302 / 9.840 |
| 100 | 0.569 / 0.550 / 16.610 |
| 1,000 | 6.191 / 7.825 / 178.452 |
| 10,000 | 70.720 / 67.051 / 1,827.391 |

**B — linked traversal plus sequential Entry hydration**

| q | redb / SurrealKV / FDB (ms) |
| ---: | ---: |
| 50 | 0.539 / 0.490 / 17.137 |
| 100 | 1.082 / 0.975 / 30.800 |
| 1,000 | 11.894 / 10.993 / 332.093 |
| 10,000 | 140.705 / 127.049 / 3,561.220 |

**D — raw payload-covering ordered range**

| q | redb / SurrealKV / FDB (ms) |
| ---: | ---: |
| 50 | 0.175 / 0.182 / 1.304 |
| 100 | 0.353 / 0.370 / 1.807 |
| 1,000 | 3.610 / 3.798 / 14.809 |
| 10,000 | 36.452 / 42.379 / 140.132 |

For these direct research consumers, the linked ID path loads roughly one AVL node per result, and hydration adds one Entry load per result. The raw covering range scans ordered rows and avoids those Attempt loads. At q=10,000 the FDB sample reports 40,003 binding GETs for linked traversal plus Entry hydration (20,003 GETs for linked ID traversal alone) versus 158 GETs and 626 range calls for the covering scan. These are binding method invocations, not network packets or round trips. The scan also reads the duplicated Entry payload and has additional storage cost.

## Current aggregate summaries (A)

This is a separate full-range query with q=100,000. It returns zero record rows because the result is an aggregate summary.

| Operation | Attempt loads | redb (ms) | SurrealKV (ms) | local FDB (ms) |
| --- | ---: | ---: | ---: | ---: |
| `summary_range` | 1 | 0.0059 | 0.0064 | 0.614 |
| `summary_prefix` | 33 | 0.187 | 0.181 | 5.015 |

The summary path does not establish that arbitrary record pages are served in constant time; it answers a different query contract.

## Actual public `Store::page` path (C)

The fixture contains n=4,096 records. Each result uses repeated calls with limit 32 and visit budget 128, so q=4,096 requires 128 Store calls. Binding counters are unavailable in this harness. This is a direct, unsecured Store call and does not include HTTP or authentication.

| q | Store calls | redb (ms) | SurrealKV (ms) | local FDB (ms) |
| ---: | ---: | ---: | ---: | ---: |
| 50 | 2 | 0.314 | 0.388 | 10.388 |
| 100 | 4 | 0.600 | 0.788 | 21.699 |
| 1,000 | 32 | 6.069 | 7.689 | 202.457 |
| 4,096 | 128 | 24.456 | 31.726 | 912.626 |

The current public/business population bound is 4,096, so this is the relevant largest page fixture. There is no public `Store::page` q=10,000 result.

## Latency sensitivity, not WAN measurement

The retained calculation adds a hypothetical delay to each observed serial operation. It is not an injected-latency run or a measured network RTT. At q=10,000 on local FDB, adding 1 ms per Attempt cache miss projects linked IDs to 11,828 ms and linked hydration to 23,562 ms. That assumes each miss causes exactly one additional unhidden remote trip; SDK caching, batching, overlap, and retries can invalidate the assumption. For D, the equivalent model adds delay per reported binding GET or range invocation: 784 calls yield 924 ms at 1 ms each and 4,060 ms at 5 ms each. Binding calls can be served from SDK caches or map to different wire activity, so these are only arithmetic sensitivities.

The model uses 4,500 ms as a conservative analysis warning, not as an observed threshold from these runs. FoundationDB's ordinary transaction age limit is about five seconds from first read; the local evidence does not prove that a WAN or multi-host transaction would behave the same. The complete assumptions and all q cases are in [the sensitivity output](evidence/2026-10-28-linked-read-latency-sensitivity-final.json).

## FoundationDB topology and incomplete trials

The final FoundationDB profile used three local server processes with separate simulated zones on one host, one data center and one usable region, triple SSD redundancy, 1,024 MiB per process, and 64 MiB cache/storage settings. The same optimized binaries and 4,500 ms client timeout were used. All 53 main cases and four page cases passed; both harness exit codes were zero, the database was healthy before and after both runs, and the lead/root confirmed the owned processes and stores were cleaned up. This is one-host process-topology evidence, not three regions, multi-host latency, or failover evidence.

Earlier FoundationDB attempts remain separate from the final profile:

- The initial unhealthy startup attempt is retained as a failed setup trial.
- The 256 MiB three-process and 512 MiB single-process attempts ran out of memory during fixture seeding and did not complete a matrix.
- An earlier three-process run passed n=10,000 cases, then hit the existing client timeout while uploading the n=100,000 fixture. It did not measure completed n=100,000 reads.
- A three-process 1,024 MiB run passed 38 cases before the study's 1,500,000,000-byte allocation guard stopped it during FoundationDB preallocation. Peak allocation was 1,623,781,376 bytes (about 1.512 GiB), with 1,309,122,560 bytes (about 1.219 GiB) before the jump. This was a study guard stop, not a read timeout, database read error, disk-full event, or server OOM.
- The final same-profile rerun raised only the owned allocation guard to 3,000,000,000 bytes (3.0 decimal GB; about 2.794 GiB). Peak owned allocation was 1,599,311,872 bytes, the final statuses remained healthy, and all owned data/log directories were removed. It completed and cleaned up; the full profile metadata and exact failure history are preserved separately in the artifact package.

## Limits and conclusion

Local FDB measurements do not establish geographic latency. Reads need not visit every replica, and read and commit paths can have different replication work. Instrumented binding calls are not wire packets or RTTs. Three observations per case do not support tail estimates. The large linked traces have incomplete provenance at q=1,000 and q=10,000 even though their counters and independent output checks remain available. The 3,000,000,000-byte study guard (3.0 decimal GB; about 2.794 GiB), private research fixtures, and q=10,000 caller budget are experimental controls; they do not raise public engine limits.

The direct runs show the current linked path's per-record load cost, the current page API's bounded repeated-call cost, and the read/storage tradeoff of a duplicated payload index under these local conditions. They do not select a production layout, establish production capacity, or claim multi-host performance. The ordered-index redesign remains unimplemented, and S0.2 stays on hold.


## Earlier local FDB numeric-offset trial (separate experiment)

A prior scratch trial compared native ordered-key selectors with numeric ordinal offsets. It used 10,000- and 100,000-key `p/` datasets with nonuniform numeric gaps, plus one `q/outside` key, on one local FoundationDB 7.3.77 server. This is distinct from the linked-read workload above: it tests finding a key by ordinal in a native ordered range, not traversing linked IDs or serving the application page API. The native selector returned one key in one measured binding call, while median time increased with offset: 0.215 ms at offset 0, 0.378 ms at 100, 13.588 ms at 10,000, and 144.286 ms at 99,999. The API/source research establishes the documented O(offset) behavior; these warm local timings alone do not prove asymptotic complexity. An offset equal to the prefix length returned `q/outside`, confirming that numeric selector offsets are not prefix scoped. The trial did not measure multi-host latency, writes, contention, or an application rank index. Its separately contextualized report, raw samples, and sources are archived in [the numeric-offset artifact set](evidence/2026-10-28-numeric-offset-artifacts.json).

In that separate trial, a range seek to the already-known last key took 0.310 ms median. A numeric offset is not a skip-list implementation; the linked consumer does not use one. FoundationDB documents the [linear cost of large key-selector offsets](https://github.com/apple/foundationdb/blob/7.3.77/documentation/sphinx/source/known-limitations.rst#L58-L69).
