# Native seek versus ordinal offset: bounded scratch trial

Actual native API trials passed on redb 4.4.0, SurrealKV 1.0.0 and one owned local FoundationDB 7.3.77 server. This is design research; no application changes, S0.2 acceptance, rank cache or application AVL was involved.

Source data: 10,000 and 100,000 distinct `p/` + big-endian-u64 keys with deterministic nonuniform gaps of 1–31, value = source ordinal, plus one `q/outside` entry. The first numeric suffix is 1023; rank 100 has suffix 2705. Thus adding a numeric key offset cannot substitute for selecting an ordinal. Prefix inventories and final results were checked against source-generated expectations. FDB offset equal to prefix length was independently asserted to return `q/outside`, demonstrating that a selector is not prefix scoped.

Every timed case has three warmups, then seven samples. Each operation opens a fresh read transaction; full prefix validation warmed state before cases. SurrealKV was closed/flushed/reopened before those reads. Fixed order, no CPU affinity or cold-cache controls. Values below are medians. Raw samples are in JSONL.

| n | Backend / operation | K | Median |
| --- | --- | ---: | ---: |
| 10,000 | redb-4.4.0 key_seek | 9,999 | 0.000691 ms |
| 10,000 | redb-4.4.0 ordinal_iterate | 9,999 | 0.383478 ms |
| 10,000 | surrealkv-1.0.0 key_seek | 9,999 | 0.002444 ms |
| 10,000 | surrealkv-1.0.0 ordinal_iterate | 9,999 | 0.687997 ms |
| 100,000 | redb-4.4.0 key_seek | 0 | 0.000801 ms |
| 100,000 | redb-4.4.0 ordinal_iterate | 0 | 0.000771 ms |
| 100,000 | surrealkv-1.0.0 key_seek | 0 | 0.002794 ms |
| 100,000 | surrealkv-1.0.0 ordinal_iterate | 0 | 0.002804 ms |
| 100,000 | redb-4.4.0 key_seek | 100 | 0.000751 ms |
| 100,000 | redb-4.4.0 ordinal_iterate | 100 | 0.004316 ms |
| 100,000 | surrealkv-1.0.0 key_seek | 100 | 0.002915 ms |
| 100,000 | surrealkv-1.0.0 ordinal_iterate | 100 | 0.009454 ms |
| 100,000 | redb-4.4.0 key_seek | 10,000 | 0.000741 ms |
| 100,000 | redb-4.4.0 ordinal_iterate | 10,000 | 0.386883 ms |
| 100,000 | surrealkv-1.0.0 key_seek | 10,000 | 0.003125 ms |
| 100,000 | surrealkv-1.0.0 ordinal_iterate | 10,000 | 0.674727 ms |
| 100,000 | redb-4.4.0 key_seek | 99,999 | 0.000751 ms |
| 100,000 | redb-4.4.0 ordinal_iterate | 99,999 | 3.866698 ms |
| 100,000 | surrealkv-1.0.0 key_seek | 99,999 | 0.002874 ms |
| 100,000 | surrealkv-1.0.0 ordinal_iterate | 99,999 | 6.832046 ms |
| 10,000 | foundationdb-7.3.77 known_key_range_limit_1 | 9,999 | 0.223567 ms |
| 10,000 | foundationdb-7.3.77 native_get_key_offset | 9,999 | 13.562239 ms |
| 10,000 | foundationdb-7.3.77 native_range_offset_limit_1 | 9,999 | 14.050956 ms |
| 10,000 | foundationdb-7.3.77 client_prefix_scan_to_rank | 9,999 | 13.386835 ms |
| 100,000 | foundationdb-7.3.77 known_key_range_limit_1 | 0 | 0.236075 ms |
| 100,000 | foundationdb-7.3.77 native_get_key_offset | 0 | 0.214864 ms |
| 100,000 | foundationdb-7.3.77 native_range_offset_limit_1 | 0 | 0.219421 ms |
| 100,000 | foundationdb-7.3.77 client_prefix_scan_to_rank | 0 | 0.196306 ms |
| 100,000 | foundationdb-7.3.77 known_key_range_limit_1 | 100 | 0.197247 ms |
| 100,000 | foundationdb-7.3.77 native_get_key_offset | 100 | 0.377599 ms |
| 100,000 | foundationdb-7.3.77 native_range_offset_limit_1 | 100 | 0.414054 ms |
| 100,000 | foundationdb-7.3.77 client_prefix_scan_to_rank | 100 | 0.352581 ms |
| 100,000 | foundationdb-7.3.77 known_key_range_limit_1 | 10,000 | 0.216387 ms |
| 100,000 | foundationdb-7.3.77 native_get_key_offset | 10,000 | 13.587928 ms |
| 100,000 | foundationdb-7.3.77 native_range_offset_limit_1 | 10,000 | 14.186550 ms |
| 100,000 | foundationdb-7.3.77 client_prefix_scan_to_rank | 10,000 | 13.762671 ms |
| 100,000 | foundationdb-7.3.77 known_key_range_limit_1 | 99,999 | 0.310258 ms |
| 100,000 | foundationdb-7.3.77 native_get_key_offset | 99,999 | 144.285868 ms |
| 100,000 | foundationdb-7.3.77 native_range_offset_limit_1 | 99,999 | 146.025620 ms |
| 100,000 | foundationdb-7.3.77 client_prefix_scan_to_rank | 99,999 | 141.642265 ms |

At n=100,000, redb whole-table `len` took median 431 ns and correctly returned 100,001, including the outside-prefix entry. Explicit prefix counting consumed 100,000 public cursor entries and took 3.167 ms on redb, 7.918 ms on SurrealKV, and 141.912 ms on this local FDB setup.

Counter scope matters: embedded ordinal traversal explicitly visits K+1 public cursor entries; these are not disk reads. Each native FDB selector returned one entry through one measured binding read call, while server scan counts are uninstrumented. The client scan at K=99,999 returned 100,000 entries through 53 `get_range` binding calls. Those counts omit read-version/internal client calls and do not count network requests. FDB selector median time grew with the offset despite the one-call public surface. The source/API research independently establishes the documented O(offset) bound; these small timings alone do not prove asymptotic complexity.

This measures warm local paths only. It does not measure writes, concurrent modifications, shard boundaries, production scale, multi-host latency or application summary/rank-index designs. Finding a key from an unknown ordinal is separate from seeking an already known key.

All owned stores were removed, and the owned FDB process (PID 25043) stopped. Retained artifacts: `embedded.rs`, `embedded.jsonl`, `fdb.rs`, `fdb.jsonl`, `run-fdb.mjs`, `fdb-runner.log`, `manifest.json`, and `build.sh`. Build script reuses existing exact rlibs and is deliberately specific to this workspace. No Cargo invocation was needed.

Exploratory setup failures were corrected before retained samples: an unrelated Tokio rlib produced a no-reactor panic; switching to SurrealKV’s dependency-matched Tokio resolved it. An invalid hyphen in the initial FDB cluster description was corrected. A separate post-trial ctypes client-version query was called before API selection and segfaulted; selecting API 730 first returned the verified 7.3.77 client version. These were not included as passing trial samples.
