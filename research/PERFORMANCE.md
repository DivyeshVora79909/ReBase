# ReBase Performance & Architecture Dossier (SurrealDB 3.2.x)

## 1. Executive Summary

This document serves as the single source of truth for ReBase query performance, execution plans, and architectural decisions on SurrealDB 3.2.x. Key findings:

- **No Universal Query Strategy:** Permission-only queries and filtered/sorted queries require fundamentally different execution plans.
- **Dynamic ACL Variables Fail Indexing:** `CONTAINSANY $auth.z_access_index` forces a `TableScan`. Scalar-bound `OR` branches are required to trigger `IndexScan`.
- **Polymorphic Ownership is Performant:** Mixed `record<user | groups>` ownership with a materialized `array<string>` index (`readers_index`) scales identically to group-only ownership when using scalar fan-out.
- **Cost-Based Routing is Mandatory:** Wide ACLs (`m=100`) make scalar fan-out slower than a native `TableScan` with early exit. Query shape must be selected based on ACL width and filter selectivity.

---

## 2. Benchmark Matrices & Latency Data

### Matrix A: Scale & ACL Width (10k vs 100k Rows)

Tests the crossover point where generating `m` OR branches becomes more expensive than a raw TableScan with `LIMIT`.

| Rows     | `m` (ACL Width) | Native Scan (TableScan + LIMIT) | Indexed Fan-Out (Scalar OR) | Filter/Sort (Composite Index) |
| :------- | :-------------- | :------------------------------ | :-------------------------- | :---------------------------- |
| **10k**  | 1               | 415 ms                          | **15 ms**                   | 50 ms                         |
| **10k**  | 10              | **62 ms**                       | 141 ms                      | 67 ms                         |
| **10k**  | 100             | **21 ms**                       | 2,345 ms                    | 74 ms                         |
| **100k** | 1               | 350 ms                          | **74 ms**                   | 390 ms                        |
| **100k** | 10              | **69 ms**                       | 881 ms                      | 57 ms                         |
| **100k** | 100             | **24 ms**                       | 21,126 ms                   | 83 ms                         |

> **Critical Takeaway:** For narrow ACLs (`m=1`), Indexed Fan-out is **27x faster**. For wide ACLs (`m=100`), generating 100 `OR` branches causes massive overhead, making a Native Scan with early-exit **880x faster**.

### Matrix B: Isolated Runtime Query Shapes (5,000 Synthetic Records)

Median DB execution times for distinct query shapes against an isolated in-memory SurrealDB instance.

| Query Shape                    | Execution Plan        | Median DB Time | Notes                                                                 |
| :----------------------------- | :-------------------- | :------------- | :-------------------------------------------------------------------- |
| Dynamic `$auth.z_access_index` | `TableScan`           | 13.19 ms       | O(N) complexity; safe but slow at scale                               |
| Bound ACL Array (`LET`)        | `Reader IndexScan`    | 3.54 ms        | Slightly faster allocation; still struggles with pure index selection |
| Scalar Reader `OR` Branches    | `Reader IndexScan`    | 3.34 ms        | **~4x faster** than dynamic; mandatory for permission-only queries    |
| Business Filter + Sorting      | `Composite IndexScan` | 0.60 ms        | **~22x faster**; RLS applied as residual filter                       |

---

## 3. Core Execution Plan Findings

### What Works

- **Materialized String Arrays:** Indexing `readers_index: array<string>` works reliably. Direct indexing on `array<record<...>>` causes the planner to return zero matching rows.
- **Scalar OR Fan-Out:** Unrolling `$auth.z_access_index` into discrete scalar variables (`$r0`, `$r1`, ...) forces SurrealDB to use a `UnionIndexScan` on `readers_index.*`.
- **Business Index Priority:** When a selective filter (`category = 'x'`) and sort (`ORDER BY score`) are present, SurrealDB correctly prefers the composite business index and applies RLS as a residual filter.
- **Polymorphic Access Keys:** Checking `[user_id, parent_group, dominated_group]` in a single index scan executes identically to checking groups alone. There is no performance penalty for mixed user/group ownership when using the materialized string index.

### What Fails

- **Dynamic RHS Variables:** `readers_index CONTAINSANY $auth.z_access_index` always results in a `TableScan`. The planner cannot optimize dynamic array intersections.
- **Direct Record Array Indexes:** Creating an index on `array<record>` leads to incorrect empty result sets. Always derive a string representation first.
- **Wide ACL Fan-Out:** Generating >50 OR branches creates significant query compilation and execution overhead. At `m=100`, fan-out is catastrophically slow compared to a bounded table scan.

### Complexity Reality Check

- **Permission-Only (Indexed):** `O(m log n + candidates)` where `m` = ACL width, `n` = index size.
- **Filtered/Sorted (Indexed):** `O(log n + k)` where `k` = matching rows examined before LIMIT. RLS is evaluated only on candidate rows.
- **Unindexed Sort:** Adds `O(K log K)` sorting cost after filtering.
- **⚠️ NOT O(1):** Permission checks are never constant time. They scale with ACL width and candidate set size.

---

## 4. Cost-Based Query Routing Policy

The frontend/query-builder **must** implement cost-based routing. No single strategy fits all workloads.

| Query Type               | Recommended Strategy     | When to Use                                                                            |
| :----------------------- | :----------------------- | :------------------------------------------------------------------------------------- |
| **Permission-Dominated** | Scalar OR Fan-Out        | "Get all my resources" with no business filters. Narrow ACLs (`m < 20`).               |
| **Filtered / Sorted**    | Composite Business Index | Any query with `WHERE` clause or `ORDER BY`. Let RLS be residual.                      |
| **Wide ACL Fallback**    | Native TableScan + LIMIT | User belongs to 100+ groups AND no selective business filter exists.                   |
| **Owner-Only Mode**      | Direct Owner Comparison  | When `authorization.selectMode = "owner"` in config. Skips inherited readers entirely. |

> **Rule of Thumb:** If your query has a selective business filter, **always** lead with the business index. Only use permission-first fan-out for pure "list everything I can see" queries with narrow ACLs.

---

## 5. Critical Engine Pitfalls & Edge Cases

These SurrealDB 3.2.x behaviors caused silent failures during testing. All have been addressed in the compiler.

### A. `FOR create NONE` Skips VALUE Calculation

- **Bug:** Adding `FOR create NONE` to a computed field like `readers_index` causes SurrealDB to skip the `VALUE` expression entirely during CREATE operations.
- **Impact:** Records were created with empty `readers_index`, making them invisible to their creator immediately after creation.
- **Fix:** Removed `FOR create NONE` from all computed ACL fields. The `VALUE` clause inherently overwrites client input, so integrity is preserved without the permission restriction.

### B. Reactive View Cascade Recursion Crash

- **Bug:** Creating a record contributing to two reactive views targeting the same parent triggered nested downward cascades, causing internal error: `"deletion for a view but no record exists"`.
- **Fix:** Compiler now injects a cascade guard flag into generated events to prevent recursive re-entry during nested materialized view updates.

### C. `surreal import` Disables Schema Processing

- **Bug:** `surreal import` is designed for raw data dumps and silently disables events, computed fields, and RLS processing.
- **Fix:** Deployment uses `surreal sql` exclusively. Never use `import` for schema deployment.

### D. Polymorphic Ownership String Casting in Permissions

- **Bug:** Using `<string>$value IN $auth.z_access_index` inside `FOR create` permissions validated syntactically but caused SurrealDB to silently drop CREATE operations.
- **Fix:** Owner authorization uses native record comparisons (`$auth`, `$auth.parents`, `$auth.dominates`). String casting is reserved strictly for the indexed `readers_index` lookup path.

### E. Stale Artifacts in Reused Build Directories

- **Bug:** Reusing output folders could retain old `optimizer.json` or `manifest.json` files even though the compiler no longer generates them.
- **Fix:** Compiler now explicitly cleans known legacy artifacts from output directories before writing new schema.

---

## 6. Final Architecture Decisions

### Polymorphic Ownership (Implemented)

```surrealql
DEFINE FIELD owned_by ON <table>
  TYPE record<user | groups>
  REFERENCE ON DELETE REJECT;

DEFINE FIELD readers ON <table>
  TYPE array<record<user | groups>>;

DEFINE FIELD readers_index ON <table>
  TYPE array<string>
  VALUE readers.map(|$r| <string>$r);
```

- Users can own private resources directly.
- Groups own shared resources.
- Ancestors access resources owned by dominated users/groups via `z_access_index`.
- Siblings cannot read each other's private resources.
- `REFERENCE ON DELETE REJECT` prevents orphaned records.

### Settings as Normal Business Schema

- **Removed** framework-level `setting` table.
- Settings are now defined in regular `schema.surql` like any other business table.
- Automatically receives ownership, RLS, indexes, auditing, references, and reactive cascades.
- Pattern documented as optional schema recipe, not compiler infrastructure.

### Authorization Select Modes

```js
// rebase.config.js
module.exports = {
  authorization: {
    selectMode: "readers", // or "owner"
  },
};
```

- **`readers` (default):** Direct ownership + inherited readers via `readers_index CONTAINSANY $auth.z_access_index`.
- **`owner`:** Only records where `owned_by IN $auth.z_access_index`. Skips inherited reader propagation for selected tables.

### Zero-Glue Deployment

- Removed `deploy.js`, `bootstrap-admin.js`, custom HTTP wrappers.
- Deployment uses official `surreal sql` CLI.
- Bootstrap uses interactive SurrealQL session or manual admin creation.
- All connection values sourced exclusively from `.env` via Node's native `--env-file`.

---

## 7. Verification Status

✅ **Static Validation Complete**

- All three example designs (test, CRM, accounts) compile successfully
- Generated schemas pass `surreal validate`
- Deterministic compiler `--check` passes
- JavaScript syntax checks pass
- No stale references to removed features

✅ **Live Runtime Tests Passed** (Isolated SurrealDB 3.2.0)

- Private user-owned resource creation and visibility
- Group-owned resource sharing
- Sibling isolation (Bob cannot see Alice's private resources)
- Ancestor/manager access to subordinate resources
- Mixed user/group reader inheritance
- Ownership assignment rejection for unrelated entities
- Immediate `readers_index` materialization on CREATE
- Manager update/delete behavior
- Reactive view cascade propagation
- Delete reference protection (`ON DELETE REJECT`)

⚠️ **Environment Limitation Note**
One consolidated live test runner was blocked by environment approval service (HTTP 503), not by project defects. All individual runtime assertions passed before this limitation was encountered. No production database was modified during testing.

---

_Last Updated: Based on final greenfield DX and polymorphic ownership implementation. Supersedes all prior benchmark notes, optimizer.json artifacts, and conversation-derived performance claims._
