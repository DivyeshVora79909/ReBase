# SurrealDB ASYNC Events Engineering Reference

This document records the measured execution model, failure semantics, timing, recursion, and transaction boundaries of `ASYNC` events in SurrealDB `3.2.0` (tested on x86_64 Linux in-memory datastore).

---

## 1. Core Execution Model

- **Decoupled Transactions**: `ASYNC` events execute in completely separate, background transactions on Tokio tasks after the originating transaction successfully commits.
- **Client Non-Blocking**: The triggering mutation (`CREATE`, `UPDATE`, `DELETE`) commits and returns immediately to the client. Async events never delay client responses.
- **Trigger Isolation**: If the originating transaction rolls back (`CANCEL TRANSACTION` or runtime error), no async event is queued or executed.
- **Failure Non-Propagation**: An unhandled exception or `THROW` inside an `ASYNC` event rolls back only the event's own transaction. The originating committed record is unaffected.

```text
[Client Mutation] -> [Commit Txn] -> [Return Client 200 OK]
                           |
                     (async spawn)
                           v
                   [Event Txn Begin]
                   [Event Body Exec]
                   [Event Txn Commit / Rollback]
```

---

## 2. Retry Semantics & Timing

- **Grammar**: `DEFINE EVENT <name> ON <table> [WHEN <cond>] ASYNC [RETRY <int>] [MAXDEPTH <int>] THEN { ... };`
- **Attempt Formula**: `RETRY N` allows exactly $1 + N$ execution attempts (1 initial attempt + $N$ retries).
- **Early Termination**: If an attempt completes without error, subsequent retries are immediately aborted.
- **Zero Scheduler Delay**: SurrealDB has **no built-in backoff or delay** between retries. Failed attempts retry immediately in a tight loop (~1–4ms overhead).
- **Linear Delays via `SLEEP`**: `SLEEP <duration>` inside the event body is re-executed on every retry attempt. A 1s `SLEEP` creates an exact 1.004s interval between retries.
- **No Attempt Context**: `$retry`, `$attempt`, `$retries`, and `$retry_count` are not bound in SurrealQL (all evaluate to `NONE`). Dynamic formulas like `SLEEP($attempt * 1s)` are impossible natively.
- **No State Persistence Across Retries**: Because a failed attempt rolls back its transaction, table writes (e.g. self-incrementing counters) are reverted. Internal database state cannot survive across failed attempts.
- **External Side Effects**: Non-transactional calls (e.g. `http::post()`) execute on **every retry attempt** (at-least-once delivery).

---

## 3. Recursion & MAXDEPTH

- **Causal Tracking**: `MAXDEPTH N` enforces a strict ceiling on recursive self-updates ($A \to A$) and circular table chains ($A \to B \to C \to A$).
- **Limit Reached**: When recursion reaches depth $N$, further mutations throw: `The event <name> reached the max async event nesting depth: N`.
- **Safe State Machines**: Recursive events bounded by `WHEN $after.status != 'DONE'` and `MAXDEPTH <int>` execute sequentially and deterministically.

---

## 4. Concurrency & Ordering

- **Worker Concurrency**: Events execute concurrently across Tokio worker tasks without head-of-line blocking (`SLEEP` in one event does not stall other events).
- **Non-Deterministic Ordering**: Asynchronous completion order is **not guaranteed**, even for sequential mutations targeting the same record ID.

---

## 5. Capability Matrix

| Capability | Supported | Mechanism / Semantics | Production Viability |
| :--- | :---: | :--- | :--- |
| **Async Decoupling** | Yes | Separate background transaction | Production Ready |
| **Automatic Retry** | Yes | `ASYNC RETRY <int>` ($1+N$ attempts) | Production Ready |
| **Fixed Retry Delay** | Yes | `SLEEP <duration>` in event block | Production Ready |
| **Exponential Backoff** | No | No attempt counter or persistent state | Requires External Worker |
| **Linear Backoff** | No | No attempt counter | Requires External Worker |
| **Jitter** | Partial | `SLEEP rand::duration(...)` | Fixed range per attempt |
| **Max Nesting Depth** | Yes | `ASYNC MAXDEPTH <int>` | Production Ready |
| **Circular Chaining** | Yes | Cycle terminated at `MAXDEPTH` | Production Ready |
| **FIFO Ordering** | No | Interleaved Tokio tasks | Not Guaranteed |
| **Persistent Retry Count** | No | Atomic rollback on attempt error | Impossible in DB |
| **Dead-Letter Queue** | No | Logs error to stderr/log stream | Requires External Worker |

---

## 6. Engineering implications

- A fixed-delay event is possible:
  ```surrealql
  DEFINE EVENT process_order ON orders WHEN $event = "CREATE" ASYNC RETRY 3 THEN {
      SLEEP 2s;
      -- idempotent task
  };
  ```
- Exponential backoff, persistent attempt counts, and dead-letter handling need
  an external worker/managed queue because failed event transactions roll back
  their own state.
- Any self-triggering event needs both a terminating `WHEN` condition and a
  `MAXDEPTH` bound.
