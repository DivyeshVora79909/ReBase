# ReBase ERP: Architecture & Physics Standard (v5)

## 🌌 Core Philosophy

ReBase is a mathematically unbreakable, serverless ERP engine built on SurrealDB. It abandons traditional imperative CRUD endpoints and asynchronous event loops. Instead, it relies on a **Deterministic Reactive Graph**.

By utilizing a strict **Alphabetical Flat Lexicon**, O(1) Synchronous View Pulls, and a Meta-Compiler, the database executes complex multi-currency, polymorphic ledger routing at bare-metal speeds (< 5ms per transaction).

---

## 1. The Alphabetical Flat Lexicon (Execution Order)

SurrealDB executes field definitions alphabetically. To prevent JSON heap-allocation overhead, "nested object tangling," and unpredictable async states, **all schema fields must use the 6-Tier Flat Prefix System.**

This guarantees absolute chronological execution at the CPU level.

| Prefix     | Name                 | Purpose                                                        | Mutation / Visibility |
| :--------- | :------------------- | :------------------------------------------------------------- | :-------------------- |
| `a_in_`    | **Inputs**           | Raw data provided by the User/API, or Foreign Keys.            | Writable by APIs.     |
| `b_ctx_`   | **Downward Context** | O(1) pulls from a parent's `f_out` payload.                    | Read-Only.            |
| `c_vw_`    | **Upward Context**   | O(1) pulls from 1D Materialized Views.                         | Read-Only.            |
| `d_c[n]_`  | **Calculations**     | Numbered sequentially (`d_c1_`, `d_c2_`). Infinite math depth. | Read-Only.            |
| `e_guard_` | **State Shields**    | Asserts physics (`> 0`) and checks locks/suspensions.          | Internal Assertion.   |
| `f_out`    | **Export Payload**   | The _only_ JSON object. Clean API export.                      | Read by Views/APIs.   |

**Example of Perfect Lexicographical Physics:**

```surrealql
DEFINE FIELD a_in_qty ON invoice_line TYPE decimal;
DEFINE FIELD a_in_price ON invoice_line TYPE decimal;

DEFINE FIELD b_ctx_locked ON invoice_line VALUE $this.a_in_invoice.f_out.is_locked;
DEFINE FIELD c_vw_adj ON invoice_line VALUE type::record('v_al_invl', [$this.id]);

DEFINE FIELD d_c1_net_qty ON invoice_line VALUE $this.a_in_qty + ($this.c_vw_adj.delta_qty ?? 0dec);
DEFINE FIELD d_c2_base_val ON invoice_line VALUE $this.d_c1_net_qty * $this.a_in_price;

DEFINE FIELD e_guard_state ON invoice_line TYPE bool VALUE {
    IF $this.b_ctx_locked { THROW "UX_ERR: Locked."; };
    RETURN true;
} ASSERT $value = true;

DEFINE FIELD f_out ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD f_out.base_value ON invoice_line VALUE $this.d_c2_base_val;
```

---

## 2. The Pull Architecture & View Typology

Materialized views in ReBase are updated synchronously by the DB kernel. To avoid 2D Matrix collisions (e.g., aggregating global warehouse stock into a specific item's stock), Views are strictly categorized.

**Rule: Parents pull from Views. Events do NOT push data.**
Parents use `type::record('v_name', [$this.id])` inside `c_vw_` fields to peek at view data in O(1) time.

### Typology 1: 1D Node Views (Aggregators)

- **Definition:** Grouped by a _single_ parent ID.
- **Purpose:** Aggregates child `f_out` math directly up to the parent.
- **Compiler Action:** Triggers an Upward Ping (`system_ping`) on the parent.

### Typology 2: 2D Matrix Views (Validation Shields)

- **Definition:** Grouped by _two or more_ IDs (e.g., `GROUP BY node, item`).
- **Purpose:** Used strictly inside `e_guard_` blocks to validate complex physics (e.g., "Does _this_ warehouse have enough of _this_ item?").
- **Compiler Action:** Ignored by the compiler. No pings generated.

---

## 3. The State Machine (The 3 Flags)

ReBase handles data lifecycle without physically deleting historical ledger entries. Only Intent roots (`invoice`, `payment`) and Leaf roots (`sl`) carry explicit state variables.

1.  **`suspended` (Data Plane Filter):**
    - _Mechanism:_ Filters the record out of `07_views.surql` (`WHERE suspended = false`).
    - _Effect:_ The record vanishes from parent aggregates, dropping its financial/physical weight to `0`.
2.  **`locked` (Mutation Plane Filter):**
    - _Mechanism:_ Read by `b_ctx_` and evaluated in `e_guard_`.
    - _Effect:_ Freezes `a_in_` variables for human users, but allows `c_vw_` upward aggregates (like payment allocations) to continue updating.
3.  **`system` (Permission Plane Filter):**
    - _Mechanism:_ Regulated via `$auth` in `compile.js`. Prevents APIs from directly editing internal fields like `f_out` or `system_ping`.

---

## 4. The Meta-Compiler (Developer Workflow)

You **never** write database events, RBAC matrices, or audit fields manually. The Developer writes 3 files; the Compiler writes 6.

### What the Developer Writes:

1.  `config.surql`: One-off exceptions and floating company settings.
2.  `06_table_fields.surql`: The physics logic (using the Alphabetical Lexicon).
3.  `07_views.surql`: The Materialized `GROUP BY` aggregators.

### What the Compiler Automates (`node compile.js`):

1.  **`02_table_permissions.surql` & `03_owners.surql`:** Resolves all `$this.a_in_[parent].owned_by` chains to generate a flattened `owners` array for O(1) Row-Level Security checks.
2.  **`04_audit_meta_fields.surql` & `05_system_flags.surql`:** Injects `created_at`, `updated_by`, `suspended`, and `system_ping`.
3.  **`08_events_upward.surql`:** Scans `07_views.surql`. Generates `system_ping` triggers to wake up parents when a 1D view updates.
4.  **`09_events_downward.surql`:** Scans `06_table_fields.surql`. Looks for `$this.a_in_X.f_out.Y`. Generates exact DAG-fracture alerts to wake up children when a parent's context changes.

---

## 5. API & Frontend Guidelines

When building UI dashboards or REST/GraphQL APIs on top of ReBase:

1.  **Read Operations:** Only ever query the `f_out` object.
    - _Good:_ `SELECT f_out.actual_unit_cogs FROM item:laptop`
    - _Bad:_ `SELECT d_c2_avg_cogs FROM item:laptop`
2.  **Write Operations:** Only ever mutate `a_in_` fields.
    - _Good:_ `UPDATE invoice_line:1 SET a_in_qty = 5`
3.  **The "Two Extremes":** UIs do not need to calculate deltas. The database naturally exposes the initial state (`a_in_`) and the final dimensionally-accurate state (`f_out`). Deltas are handled invisibly inside `d_c[n]_`.
