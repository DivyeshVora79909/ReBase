# SurrealDB Cross-Namespace Reconciliation Scanning

## Scope

This document records empirical benchmark findings and architectural conclusions regarding multi-namespace/database context switching within a single SurrealQL transaction in SurrealDB 3.2.0.

The evaluated use case is periodic **offline/secondary reconciliation** in ReBase, where a background worker scans deterministic, known job tables across known tenant namespaces and databases to find unhandled pending jobs (`status = 'pending'`). This is not the real-time event-delivery queue path.

---

## Environment

* **SurrealDB Version:** `3.2.0 for linux on x86_64`
* **Operating System:** Linux x86_64 (Kernel 6.x)
* **Processor:** 12-Core Intel(R) Core(TM) i5-12450H
* **Memory:** 16 GB Physical RAM (System Available: ~6 GB)
* **Storage Engine:** Local in-memory (`memory`) / NVMe storage
* **Methodology:** Live empirical benchmarking using a real local instance via HTTP endpoint with connection pooling and timing instrumentation.

---

## Verified Transaction Behavior

* **[VERIFIED] Top-Level Multi-Statement Transaction Switching:**  
  A single top-level SurrealQL transaction script sent to SurrealDB can repeatedly switch namespace and database context using `USE NS ... DB ...;` and query tables across those contexts:
  ```surrealql
  BEGIN TRANSACTION;
  USE NS ns_001 DB db_001;
  SELECT id, status, created_at FROM jobs_001 WHERE status = 'pending';
  USE NS ns_001 DB db_002;
  SELECT id, status, created_at FROM jobs_001 WHERE status = 'pending';
  USE NS ns_002 DB db_001;
  SELECT id, status, created_at FROM jobs_001 WHERE status = 'pending';
  COMMIT TRANSACTION;
  ```
* **[VERIFIED] Prohibited Inside Code Blocks:**  
  `USE NS/DB` remains strictly prohibited by the SurrealQL parser inside code blocks (such as `DEFINE EVENT ... THEN { USE ... }`) and inside `eval::surql()`. Top-level script transaction support must **not** be generalized to event triggers or functions.

---

## Reconciliation Architecture Context

```
[Normal Path: Primary Event Pipeline]
Tenant Mutation ──► Event Trigger ──► Worker Execution (Real-time)

[Secondary Path: Periodic Reconciliation Scanner]
Reconciliation Worker (e.g. every 5 min)
  │
  ▼
1 Multi-Statement Script:
  BEGIN TRANSACTION;
    USE NS tenant_A DB app; SELECT ... WHERE status = 'pending';
    USE NS tenant_B DB app; SELECT ... WHERE status = 'pending';
    ... (N known tenant DBs)
  COMMIT TRANSACTION;
  │
  ▼
Batch returned to worker ──► Re-enqueues unhandled/stalled jobs
```

* **Purpose:** Catch-up and integrity verification for failed, dropped, or unhandled events.
* **Tolerances:** Latency is secondary (seconds/minutes acceptable); scans can be retried on failure without impacting real-time tenant operations.

---

## Benchmark Dataset

Each job record across all datasets had a realistic schema and payload:
```json
{
  "status": "pending | failed | success | cancelled | running",
  "priority": 1,
  "created_at": "2026-08-21T15:30:00.000Z",
  "attempts": 0,
  "worker_id": "worker_1 | NONE",
  "payload": { "task": "process_order", "items": [0], "meta": "payload_data" },
  "tenant_id": "tenant_name",
  "job_type": "export | sync | billing | email | report"
}
```
* **Status distribution:** ~5% `pending`, 10% `failed`, 80% `success`, 5% other.

---

## Benchmark Results

### Centralized vs Distributed Architecture (50,000 Total Records, ~5% Pending)

| Architecture | Setup Details | Scan Strategy | Index on `status` | Measured Time (ms) | Throughput (recs/sec) | Pending Found |
| :--- | :--- | :--- | :---: | ---:| ---:| ---:|
| **Centralized** | 1 NS, 1 DB, 1 Table (50k rows) | Single Query | Yes | **67.22 ms** | ~743,826 | 2,500 |
| **Centralized** | 1 NS, 1 DB, 1 Table (50k rows) | Single Query | No | **75.73 ms** | ~660,240 | 2,500 |
| **Distributed** | 10 NS, 5 DB/NS, 2 Tbl/DB (100 tables) | Single Transaction | Yes | **114.34 ms** | ~437,292 | 2,513 |
| **Distributed** | 10 NS, 5 DB/NS, 2 Tbl/DB (100 tables) | Single Transaction | No | **117.32 ms** | ~426,184 | 2,513 |
| **Distributed** | 10 NS, 5 DB/NS, 2 Tbl/DB (100 tables) | 8 Parallel Workers | Yes | **981.50 ms** | ~50,942 | 2,513 |
| **Distributed** | 10 NS, 5 DB/NS, 2 Tbl/DB (100 tables) | Sequential Per-DB HTTP | Yes | **3,113.51 ms** | ~16,059 | 2,513 |
| **Large-Table** | 1 DB, 5 Large (8k) + 20 Small (500) | Single Transaction | Yes | **115.47 ms** | ~433,012 | 2,509 |

---

### HTTP vs Single Transaction Ratios

* **[MEASURED]** Single multi-statement transaction vs sequential per-DB HTTP requests:  
  $$\frac{3{,}113.51\text{ ms}}{114.34\text{ ms}} \approx 27.2\times\text{ faster}$$
* **[MEASURED]** Single multi-statement transaction vs 8-worker parallel HTTP requests:  
  $$\frac{981.50\text{ ms}}{114.34\text{ ms}} \approx 8.58\times\text{ faster}$$
* **[MEASURED]** Centralized single table vs 100-table distributed single transaction:  
  $$\frac{114.34\text{ ms}}{67.22\text{ ms}} \approx 1.70\times\text{ faster (centralized)}$$

*(Note: Ratios reflect the tested hardware, payload, and network loopback environment; they are not universal engine constants.)*

---

### Table Count Scaling (Constant 20,000 Total Records)

Tested across different fragmentation levels with total records kept constant at 20,000:

| Configuration | Total Tables | Recs / Table | Context Switches | Single Transaction Time (ms) | Parallel 8-Worker Time (ms) |
| :--- | ---:| ---:| ---:| ---:| ---:|
| **1 Table × 20,000** | 1 | 20,000 | 0 | **54.17 ms** | 61.01 ms |
| **10 Tables × 2,000** | 10 | 2,000 | 10 | **103.86 ms** | 243.89 ms |
| **50 Tables × 400** | 50 | 400 | 50 | **84.64 ms** | 459.90 ms |
| **100 Tables × 200** | 100 | 200 | 100 | **78.05 ms** | 767.34 ms |
| **200 Tables × 100** | 200 | 100 | 200 | **104.31 ms** | 1,644.92 ms |

* **[INTERPRETATION]** Single-transaction execution times fluctuated in the ~78–104 ms range across 10 to 200 tables. In contrast, separate HTTP request overhead scaled aggressively ($61\text{ ms} \rightarrow 1{,}644\text{ ms}$) as table and request counts increased.

---

### Centralized Record Count Scaling (Indexed)

| Total Records in Table | Pending Records (~5%) | Single Query Time (ms) | Server RSS (MB) |
| ---:| ---:| ---:| ---:|
| **1,000** | 50 | **51.74 ms** | 613.07 MB |
| **10,000** | 500 | **57.86 ms** | 613.07 MB |
| **50,000** | 2,500 | **75.83 ms** | 613.07 MB |
| **100,000** | 5,000 | **63.66 ms** | 613.08 MB |
| **250,000** | 12,500 | **51.00 ms** | 613.09 MB |

* **[INTERPRETATION]** Across the tested range (1,000 to 250,000 records), indexed lookup time remained within the same tens-of-milliseconds baseline (~50–76 ms).

---

### Query Variants (50,000 Records, Indexed)

| Query Filter Variant | Distributed (100 Tables in 1 TX) | Centralized (1 Table) |
| :--- | ---:| ---:|
| `WHERE status = 'pending'` (Full scan of pending) | **114.34 ms** | **67.22 ms** |
| `WHERE status = 'pending' LIMIT 10` | **94.88 ms** | **55.27 ms** |
| `WHERE status = 'pending' ORDER BY created_at LIMIT 10` | **79.63 ms** | **49.20 ms** |

* **[MEASURED]** Bounding result sizes with `LIMIT 10` reduced scan time by ~17% in distributed transactions and ~18% in centralized queries due to reduced serialization and memory transfer overhead.

---

### Index Impact

* **50k Distributed (100 tables):** Unindexed = **117.32 ms** vs Indexed = **114.34 ms** (~2.5% delta).
* **50k Centralized (1 table):** Unindexed = **75.73 ms** vs Indexed = **67.22 ms** (~11.2% delta).
* **[INTERPRETATION]** Indexes provide selective scanning benefits; however, when data is heavily partitioned across many small tables (e.g. 200–500 records/table), statement dispatch and parsing overhead represent a large portion of the total execution time, masking index acceleration.

---

## Failure Semantics

### Tested Scenario: Error Inside Single Transaction
```surrealql
BEGIN TRANSACTION;
USE NS tenant_01 DB app;
SELECT * FROM jobs WHERE status = 'pending';

USE NS missing_tenant DB app; -- Non-existent table/database
SELECT * FROM jobs WHERE status = 'pending';

USE NS tenant_02 DB app;
SELECT * FROM jobs WHERE status = 'pending';
COMMIT TRANSACTION;
```

### Observed Engine Behavior:
1. **Statement 2:** Returns `NotFound: "The table 'jobs' does not exist" (status: ERR)`.
2. **Statement 3:** Returns `Cancelled: "The query was not executed due to a cancelled transaction" (status: ERR)`.
3. **COMMIT:** Returns `NotExecuted: "Cannot COMMIT: the transaction was aborted due to a prior error" (status: ERR)`.

### Operational Impact on Reconciliation:
* **All-or-Nothing Execution:** SurrealDB transactions are fail-fast. A single invalid namespace, missing table, or syntax error cancels all remaining statements in the transaction batch.
* **Precondition:** A single transaction scanner is safe **only** if the inventory of namespaces, databases, and tables is deterministic, valid, and synchronized with the catalog before generating the query batch.

---

## Engineering Interpretation

1. **Reconciliation vs Real-time Queue:**  
   Because this is a background reconciliation scan (running periodically at intervals of minutes), the multi-tenant distributed schema does not need to be forced into a single centralized table purely for scanning speed.
2. **Batching Efficiency:**  
   Generating a single multi-statement SurrealQL script with repeated `USE NS ... DB ...; SELECT ...;` eliminates HTTP round-trip serialization overhead and performs ~27× faster than sequential HTTP queries on the tested workload.
3. **Chunking Boundary:**  
   For large tenant deployments (e.g. 500+ namespaces), queries should be chunked into moderate batches (e.g. 50–100 namespaces per transaction script) to limit transaction payload size, avoid parser memory spikes, and isolate tenant catalog drift.

---

## Recommended Reconciliation Pattern

For periodic multi-tenant reconciliation in ReBase:

1. **Catalog Resolution:** The reconciliation worker queries the system catalog to obtain a deterministic list of active `(namespace, database, table)` targets.
2. **Script Generation:** The worker constructs a single SurrealQL script chunking up to 50–100 targets per transaction:
   ```surrealql
   BEGIN TRANSACTION;
   USE NS tenant_001 DB app; SELECT id, status, created_at FROM jobs WHERE status = 'pending' LIMIT 50;
   USE NS tenant_002 DB app; SELECT id, status, created_at FROM jobs WHERE status = 'pending' LIMIT 50;
   ...
   COMMIT TRANSACTION;
   ```
3. **Execution & Parse:** The worker sends the batch in 1 HTTP/WebSocket request, extracts returned pending records, and pushes missed jobs to the processing queue.
4. **Retry on Abort:** If a batch aborts due to a catalog mismatch (e.g. deleted tenant), the worker refreshes its catalog inventory and retries.

---

## Limitations & Boundaries

* **[NOT ESTABLISHED]** Multi-node distributed clustering (TiKV backend) context-switch latency was not measured; tests were performed on a single-node engine.
* **[NOT ESTABLISHED]** Fixed microsecond overhead guarantee: Context switching overhead (~675 µs/switch in this benchmark) is an empirical estimate derived from this specific test environment and hardware, not an engine contract.
* **[NOT ESTABLISHED]** Behavior under massive statement counts (e.g. 10,000+ statements in a single script) was not tested and may encounter AST parser recursion or payload limits.

---

## Raw Experimental Facts Summary

* **Engine:** SurrealDB 3.2.0 (linux/x86_64).
* **Multi-NS Transaction Support:** Supported in top-level scripts; prohibited in event/eval blocks.
* **100-Switch Context Benchmark:** 67.51 ms (inside transaction) vs 67.59 ms (outside transaction).
* **50k Record Scan Times:**
  * Centralized (1 table, indexed): **67.22 ms**
  * Distributed (100 tables, 1 TX): **114.34 ms**
  * Distributed (100 tables, 8 HTTP workers): **981.50 ms**
  * Distributed (100 tables, sequential HTTP): **3,113.51 ms**
* **Error Behavior:** Missing table causes instant transaction cancellation for all following statements.
