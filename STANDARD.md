# 🏛️ The Reactive Graph Engine: Master Engineering Constitution

This document is the absolute, deterministic source of truth for our backend architecture. It abandons procedural, domain-driven "commerce" logic in favor of **Algebraic Physics** and **Data-Driven Systems Engineering**.

Any AI model or human developer building upon this stack must strictly adhere to these laws. There is no ambiguity; the database kernel enforces the reality.

---

## I. The Lexicographical Pipeline (Schema Structure)

SurrealDB evaluates `VALUE` clauses in strict ASCII alphabetical order. We exploit this to create a deterministic, 7-tier compilation pipeline. Every dependent table must strictly follow this object/field naming convention to guarantee that data is fetched before it is calculated, and calculated before it is asserted.

1. **`A_guard` (The Intent & State Shield):** Evaluates **1st**. Validates human intent, state transitions (`suspended`, `locked`), and DAG topology. Throws explicit `UX_ERR` strings.
2. **Raw Fields (The Base Facts):** Evaluates **2nd**. Human inputs, structural foreign keys, and state flags (`qty`, `cogs`, `suspended`, `locked`, `system_ping`).
3. **`za_parent` (Downward Context):** Evaluates **3rd**. Pulls structural or mathematical context from parents via Graph Traversal or Direct Pings.
4. **`zb_child` (Upward Context):** Evaluates **4th**. Receives aggregated dimensional vectors from Materialized Views.
5. **`zz` (Primary Physics):** Evaluates **5th**. Combines raw inputs, `za_parent`, and `zb_child` to calculate the current state of reality.
6. **`zzz` (Secondary Shields):** Evaluates **6th**. Applies `ASSERT` constraints to the `zz` math (e.g., `ASSERT $value >= 0dec`).
7. **`zzzzz_out` (The API Payload):** Evaluates **7th**. The strict, dimensional export object that Views are legally allowed to read.

---

## II. The Three Planes of Validation

To eliminate ambiguity, every constraint in the system must be mapped to exactly one of these three planes. We do not mix Intent with Physics.

### Plane 1: Intent & Topology (Lives in `A_guard`)

- **Purpose:** Prevent illogical human actions _before_ math is calculated.
- **Examples:**
  - "Cannot suspend an invoice if physical deliveries exist."
  - "Cannot allocate a payment to an invoice from a different Org." (DAG Check)
  - "Cannot record an Outbound Stock Movement against a Purchase Invoice."
- **Mechanism:** `IF condition THEN THROW "UX_ERR: ..."`

### Plane 2: Conservation of Physics (Lives in `zz` / `zzz` inline `ASSERT`)

- **Purpose:** Enforce the absolute laws of nature (mass/money cannot be negative).
- **Examples:**
  - Treasury Balance: `ASSERT (in - out) >= 0`
  - Stock Remaining: `ASSERT (ordered - delivered) >= 0`
  - Allocation Shield: `ASSERT (received - allocated) >= 0`
- **Mechanism:** `DEFINE FIELD zzz.shield ... ASSERT $value >= 0dec`

### Plane 3: The Matrix Exception (Lives in `zzz` via O(1) View Peek)

- **Purpose:** Handle 2D intersections that cannot be normalized into a single parent record.
- **The Rule:** A `warehouse` cannot hold a physical limit for _every possible item_ in its schema. Therefore, the physics shield for `Warehouse x Item` must live on the **Leaf Node (`sl`)**.
- **Mechanism:** The `sl` table uses `type::record('v_sl_node_item', [$this.from, $this.item])` to peek at the View's aggregated math in O(1) time _during the transaction_. If the stock drops below zero, the transaction physically collapses before the View is ever updated.

---

## III. Dimensional Math & Maximum Entropy

We ban generic names like `amount`, `qty`, or `type` in the `zzzzz_out` payload. We use **Dimensional Naming**. This eliminates the need for parents to write `IF type == 'sales'` logic. The name _is_ the dimension.

- **The Law of Maximum Entropy:** A child must export _every_ dimensional vector it generates.
- **Example:** `invoice_line` exports both `zzzzz_out.sales_financial_value` and `zzzzz_out.purchase_financial_value`. `sl` exports `zzzzz_out.inbound_physical_qty` and `zzzzz_out.outbound_physical_qty`.
- **Result:** Views only ever use `math::sum()`. They never use `WHERE` filters for logic. The math is purely commutative. Parents receive omniscient context, allowing them to enforce complex cross-dimensional rules without table scans.

---

## IV. State Mechanics & Performance

We do not use categorical string statuses (e.g., 'draft', 'posted', 'void'). We use boolean flags and system timestamps that dictate exact database mechanics.

1.  **`suspended` (Snatch Participation):** The record is quarantined. Views explicitly filter these out (`WHERE suspended = false`). It drops from upward propagation instantly.
2.  **`locked` (Choke Propagation):** The record's financial math is cryptographically sealed. Upward View Events check `$parent.locked`. If true, the event throws, halting any child modifications that would alter aggregates.
3.  **`system_ping` (The Performance Clutch):** A `datetime` field with `PERMISSIONS FOR update NONE`. Heavy declarative subqueries or complex `zz` math check: `IF $before.system_ping != $this.system_ping`.
    - **Result:** Human metadata edits (like changing `notes`) bypass the math engine entirely. Only System Events (Direct Pings) can engage the clutch and force recalculation.

---

## V. The Three Pings (Data Motion)

No procedural business logic is allowed in `EVENTS`. Events exist **strictly to pass data** between nodes.

### 1. Upward View Ping (The Aggregator)

- **Trigger:** Fires automatically when a View recalculates.
- **Action:** Checks the `locked` choke point. Pushes the aggregate sum to the parent's `zb_child` object and sparks the parent's evaluation cycle by updating `updated_at`.

### 2. Downward Topology Ping (DAG Integrity)

- **Trigger:** Fires when a parent's root identity changes (e.g., shifting an Invoice to a different Org).
- **Action:** `UPDATE <~child SET updated_at = time::now()`. Forces children to re-verify the DAG "Pentagon Check" via their `za_parent` and `A_guard`.

### 3. Downward Data Ping (The Zig-Zag / Orthogonal)

- **Trigger:** Fires when a parent's core mathematical inputs change (e.g., `invoice_line` base value changes), requiring a child (like `tax_line`) to recalculate fractions.
- **Safety Rule:** Must _only_ trigger on explicit human/math field changes, never on `zb_child` view updates, to prevent infinite loops. Updates the child's `system_ping` to engage the math clutch.

---

## VI. File Structure Standard

The architecture is strictly divided into specialized files to prevent execution loop errors and maintain context. LLMs and developers must append code to the correct file.

- `01_auth_rbac.surql`: Users, groups, link relations, and database access definitions.
- `02_table_permissions.surql`: Root table access control (`FOR select, create, update, delete`).
- `03_owned_by_fields.surql`: Inheritance pointers mapping records to RBAC groups.
- `04_audit_meta_fields.surql`: `created_at`, `updated_at`, `created_by`, `updated_by`.
- `05_system_flags.surql`: `suspended`, `locked`, and `system_ping` definitions.
- `06_table_fields.surql`: The 7-Tier Lexicographical Pipeline (`A_guard` through `zzzzz_out`).
- `07_views.surql`: Stateless aggregations (`GROUP BY`). Always apply `WHERE suspended = false`.
- `08_events_upward.surql`: View -> Parent pings (`updated_at` triggers and `locked` chokes).
- `09_events_downward.surql`: Topology & Data pings (The Zig-Zag variable hand-off).

---

### Summary Mandate for AI & Developers

When adding a new feature, table, or relational concept to the engine:

1. **Define the Dimensions:** What are the vectors? (Inbound/Outbound, Sales/Purchase).
2. **Map the DAG:** Identify the Anchors, Intents, Branches, Leaves, and Deltas.
3. **Draft the `zzzzz_out` Payloads:** Ensure maximum entropy is exported.
4. **Assign Validations:** Put state/logic blocks in `A_guard`. Put conservation laws (`>= 0`) in `zzz` ASSERTs. Put 2D Matrix limits in `zzz` O(1) View Peeks.
5. **Wire the Pings:** Write the Upward View Pings, and the strictly filtered Downward Pings.

**Philosophy:** _Errors belong in the Frontend. The Backend belongs to Physics._
