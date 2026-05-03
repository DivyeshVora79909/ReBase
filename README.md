# SurrealDB 3.0 – The Implicit Control Protocol

#### A Masterclass for LLM‑Assisted Schema Architecture

> **Release:** SurrealDB 3.0 (February 2026).  
> **Audience:** Future LLMs, system engineers, and developers who want to harness SurrealDB’s native primitives for fully **implicit, self‑enforcing data integrity**.  
> **Core Principle:** Define **what** must be true, not **how** to make it true. Let the database engine carry the burden of ordering, recomputation, and referential safety.

This document is the product of exhaustive research, deterministic verification, and system‑level brainstorming. It merges every critical fact, corrected pattern, and optimal composition into a single reference.

---

## 1. Deterministic Engine Behaviour – The Facts

Understanding these low‑level truths is mandatory before writing any schema.

### 1.1 Field Processing Order (Alphabetical, Two‑Pass)

When a record is written (INSERT/UPDATE), SurrealDB processes **all defined fields** in **strict alphabetical order** (the field **name**), not the order they appear in the query.

- **Pass 1 – `VALUE` evaluation**  
  For every field (A→Z), the engine:
  1. Applies `$input` (raw user‑provided value).
  2. Runs the `VALUE` clause; the result becomes the final field value.
  3. If the field was not supplied and a `DEFAULT` exists, the default value is used instead.

- **Pass 2 – `ASSERT` evaluation**  
  For every field (A→Z), the `ASSERT` clause is checked against the final, post‑value value.

**Strategic consequence**  
A field named with a `z_` prefix is guaranteed to run **after** all normal fields. This allows it to safely reference any other field’s _already‑computed_ value.

### 1.2 The Pointer Lexicon (Exact Semantics)

| Pointer          | Context                     | Refers to                                                                          |
| ---------------- | --------------------------- | ---------------------------------------------------------------------------------- |
| `$value`         | Field `VALUE`, `ASSERT`     | The incoming data **for this field** (post‑`DEFAULT` if absent).                   |
| `$input`         | Field `VALUE`, `ASSERT`     | The **raw user‑provided** value before any transformation.                         |
| `$before`        | Field `VALUE`, `ASSERT`     | The **previous stored value of this specific field** (NONE on create).             |
| `$after`         | Field `VALUE`               | Alias of `$value` (itself) – rarely used.                                          |
| `$before`        | **Event**                   | The **entire record** before the mutation (NONE on CREATE).                        |
| `$after`         | **Event**                   | The **entire record** after the mutation (NONE on DELETE).                         |
| `$event`         | Event                       | String: `"CREATE"`, `"UPDATE"`, `"DELETE"`.                                        |
| `$auth`          | Permissions, Events, Access | The authenticated user’s record ID.                                                |
| bare `fieldname` | `VALUE` clause              | The **new value** of that field (already computed, because of alphabetical order). |
| `$this`          | `VALUE`, subqueries         | The current record. `$this.field` ≡ bare `field`.                                  |

**Critical rule**  
You cannot access `$before.other_field` inside a field’s `VALUE` clause; `$before` there is only that field’s old value. To compare old vs new across **different fields**, you **must** use an **EVENT**.

### 1.3 Reference Integrity Details

- `REFERENCE ON DELETE …` only inspects **top‑level** record IDs (single, array, or set).
- Options: `CASCADE`, `REJECT`, `SET NULL`, `NO ACTION`.
- Nested references inside objects/arrays are **not** automatically followed – use shadow fields (§3.3).

### 1.4 Row‑Level Security & Permissions

- RLS conditions (`PERMISSIONS FOR …`) **filter** rows; they never return a 403 error. If the condition is false, the row is invisible.
- `FOR create` can only use `$auth` because the record does not exist yet.
- Field‑level permissions (`PERMISSIONS NONE`) completely hide data.
- Access methods (signup/signin/authenticate) **bypass RLS**. They execute as system operations.
- Custom functions are always **security invoker**. To protect sensitive logic, put it inside events or access methods.

### 1.5 Typing Essentials

- `option<T>` – allows `NONE`.
- `record<table>` – validated Record ID pointing to a specific table.
- `array<T>` – ordered list, duplicates allowed.
- `set<T>` – unordered, unique elements.
- `object` – unstructured; use `.*` subfields to constrain shape.
- `FLEXIBLE TYPE` – allows extra keys in an object within a `SCHEMAFULL` table.
- `literal<"a", "b">` – string enum.

### 1.6 Access Methods (Record Users)

Each `DEFINE ACCESS ... ON DATABASE TYPE RECORD` requires three clauses, each a **single expression** (no `LET` statements). They return a record ID or `NONE`.

- `SIGNUP` – invoked on sign‑up.
- `SIGNIN` – invoked on sign‑in.
- `AUTHENTICATE` – invoked on every authenticated request; must return the user ID or `NONE` to terminate the session.

`$auth` in later RLS is the ID returned by `AUTHENTICATE`, and all its fields are immediately available.

---

## 2. The Three Scopes of Integrity

Every data rule in your application falls into one of these scopes. SurrealDB provides native tools for each.

| Scope                   | Definition                                            | Native Tools                                                                                          |
| ----------------------- | ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| **Record**              | A single row                                          | `VALUE`, `ASSERT`, `DEFAULT`, `z_` cross‑field computed fields, `READONLY`                            |
| **Collection**          | All rows of a table                                   | `UNIQUE` index, events that query the whole table, computed set coercion                              |
| **Relational (Global)** | Cross‑table references, aggregates, graph constraints | `REFERENCE ON DELETE`, shadow references, events that update parent records, polymorphic graph events |

---

## 3. Record‑Level Integrity – Implicit Within a Row

### 3.1 Sanitise & Validate Incoming Data

`VALUE` transforms; `ASSERT` rejects if the final value is invalid.

```sql
DEFINE FIELD email ON user TYPE string
    VALUE string::lowercase(string::trim($value))
    ASSERT string::is_email($value);
```

### 3.2 Cross‑Field Constraints Using `z_` Prefix

Because fields run alphabetically, a field named `z_check` can read any other field’s newly computed value.

```sql
DEFINE FIELD start_date ON booking TYPE datetime;
DEFINE FIELD end_date ON booking TYPE datetime;

DEFINE FIELD z_dates_valid ON booking TYPE bool
    VALUE $this.end_date > $this.start_date
    ASSERT $value = true;
```

### 3.3 Automatic Audit of Raw Input

Use `$input` to preserve exactly what the user sent, before `VALUE` transforms it.

```sql
DEFINE FIELD email_raw ON user TYPE string
    VALUE $input   -- untrimmed, un‑lowercased
    PERMISSIONS NONE;
```

### 3.4 Auto‑timestamps

```sql
DEFINE FIELD created_at ON my_table TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD updated_at ON my_table TYPE datetime VALUE time::now();
```

`$before` on `created_at` is its own previous value; on create it is `NONE`, so `time::now()` is taken.

### 3.5 Implicit Computed Fields (Stored) vs Dynamic (Computed)

- **Stored computed** – `VALUE` clause: recalculated on each write, stored on disk. Cheap reads.
- **Dynamic computed** – `COMPUTED` keyword (SurrealDB 3.0): evaluated at read time. Always current, no write overhead.

```sql
DEFINE FIELD age ON person TYPE int VALUE time::now().year - birthday.year; -- stored, correct as of last write
DEFINE FIELD can_vote ON person COMPUTED $this.age >= 18; -- always up‑to‑date
```

### The 3.6 Core Primitives for In‑Record Aggregation

### 3.6.1. **Path & Filter Expressions**

_Navigate the JSON tree and filter arrays inline – no functions needed._

- **Syntax**: `$this.field`, `array[WHERE condition]`, `.*`
- **What it does**: Reaches into nested objects/arrays, extracts values, or filters array elements using a condition. This is evaluated directly on the AST and is extremely fast.
- **Example**: `regions[WHERE status = "active"].managers`
- **Use for**: Getting a specific field, pre‑filtering arrays before handing them to other methods.

### 2. **Array/Set Functions (Functional)**

_Transform, combine, and reduce arrays with closure‑based operations._

- **Syntax**: `.map(|$item| …)`, `.filter(|$item| …)`, `array::flatten()`, `array::group()`, `math::sum()`, `object::values()`, etc.
- **What it does**: Pure functions that iterate over arrays (or objects) and return new arrays or scalars. No virtual tables are created.
- **Example**:
  ```surql
  LET $teams = array::flatten(array::flatten(regions.managers).teams);
  RETURN math::sum($teams.map(|$t| $t.stats.costs));
  ```
- **Use for**: Simple sums, counts, flattening nested arrays, grouping into an object (via `array::group`), and filtering.
- **⚠️ Limitation**: `array::sort` only works on primitive arrays (numbers/strings), not arrays of objects. There is no built‑in function to sort objects by a property – you need Way 3 for that.

### 3. **In‑Record Subqueries (Virtual Table)**

_Treat an array as a temporary table and run full SurrealQL on it._

- **Syntax**: `(SELECT … FROM $array …)`, optionally with `ONLY`, `VALUE`, `SPLIT`, `GROUP BY`, `ORDER BY`, `LIMIT`, etc.
- **What it does**: Converts a local array into a virtual table in memory. This gives you access to all SQL clauses – grouping, sorting, limiting, and relational unrolling (`SPLIT`).
- **Example**:
  ```surql
  (SELECT role, math::sum(stats.costs) AS total FROM $teams GROUP BY role ORDER BY total DESC LIMIT 5)
  ```
- **Use for**: When you **must** have SQL features – especially sorting object arrays by a computed key, pagination, or unrolling 3D/4D arrays with `SPLIT`. This is the only practical way to sort objects by a field.

### Composition Tool: **Block Expressions** (`{ LET …; RETURN …; }`)

Not a data‑processing “way”, but the glue that lets you combine the three primitives cleanly. Use `LET` to store intermediate arrays from Path/Filter or Array Functions, then feed them into a subquery or a final function.

---

## 4. Collection‑Level Integrity – Constraints Across Rows

### 4.1 Classic Unique Index

```sql
DEFINE INDEX unique_email ON TABLE user COLUMNS email UNIQUE;
```

### 4.2 Uniqueness on Nested Arrays (Set Coercion)

You cannot directly index an array for uniqueness. Instead, flatten duplicates into a `z_::set<T>` and index that.

```sql
DEFINE FIELD tags ON article TYPE array<string>;
DEFINE FIELD zz_unique_tags ON article TYPE set<string>
    VALUE $this.tags;   -- set() automatically removes duplicates

DEFINE INDEX idx_tags ON article COLUMNS zz_unique_tags UNIQUE;
```

Two records sharing any value after deduplication will be rejected.

### 4.3 Event‑Driven Whole‑Collection Constraints

When a rule depends on multiple rows (e.g., “sum of quantities per category ≤ 100”), use an event on the table that queries the collection and throws.

```sql
DEFINE EVENT cap_total ON TABLE item WHEN $event != "DELETE" THEN {
    LET $sum = (SELECT VALUE math::sum(quantity) FROM item WHERE category = $after.category)[0] ?? 0;
    IF $sum > 100 { THROW "Category cap exceeded"; };
};
```

---

## 5. Relational (Global) Integrity – Cross‑Table & Graph

### 5.1 Standard Foreign Key with `REFERENCE`

On any top‑level `record<T>` field:

```sql
DEFINE FIELD project ON task TYPE record<project> REFERENCE ON DELETE CASCADE;
```

Works identically for arrays/sets:

```sql
DEFINE FIELD members ON project TYPE array<record<user>> REFERENCE ON DELETE REJECT;
```

### 5.2 Shadow References – Integrity for Deeply Nested Record IDs

SurrealDB’s `REFERENCE` does **not** inspect nested objects. To enforce referential integrity on IDs buried inside an array‑of‑objects, you **flatten** them into a top‑level `set<record<T>>` (a **shadow field**) and attach the `REFERENCE` there.

**Example – document with nested file references:**

```sql
-- Original nested fields
DEFINE FIELD blocks ON page TYPE array<object>;
DEFINE FIELD blocks.*.image_id ON page TYPE record<file>;

-- Shadow field (zz_ runs last)
DEFINE FIELD zz_all_files ON page TYPE set<record<file>>
    VALUE <set> (blocks.image_id ?? []).flatten().filter(|$v| $v != NONE)
    REFERENCE ON DELETE REJECT;

-- Must also declare the sub‑field for SCHEMAFULL storage
DEFINE FIELD zz_all_files.* ON page TYPE record<file>;
```

Now deleting a `file` that is referenced anywhere inside `blocks` will fail with a `REJECT` error.

**Polymorphic shadow references** work the same way – the set can be `set<record<table_a | table_b>>`.

### 5.3 Implicit Cross‑Table Aggregation & Validation (The “Empty Update” Pattern)

Instead of materialised views or manual aggregation, **store the aggregate on the parent** as a computed field, and use an event on the child table to trigger re‑evaluation of the parent by performing an **update without any SET data**.

**Invoice pattern (definitive version):**

```sql
DEFINE TABLE invoice SCHEMAFULL;
DEFINE TABLE invoice_line SCHEMAFULL;

DEFINE FIELD invoice_id ON invoice_line TYPE record<invoice>;
DEFINE FIELD quantity ON invoice_line TYPE int;
DEFINE FIELD amount ON invoice_line TYPE decimal;

-- Parent: computed total quantity with ASSERT
DEFINE FIELD total_qty ON invoice TYPE int
    VALUE (SELECT VALUE math::sum(quantity) FROM invoice_line WHERE invoice_id = $this.id)[0] ?? 0
    ASSERT $value >= 0;

-- Child event: after any write, re‑trigger parent's VALUE/ASSERT
DEFINE EVENT maintain_invoice ON TABLE invoice_line
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $inv = $after.invoice_id OR $before.invoice_id;
    UPDATE $inv;   -- simply touching the parent recomputes all VALUE fields
};
```

**Why this is optimal**:

- No extra view/table.
- The integrity rule lives in the parent’s `ASSERT`; the event is only a signal to recompute.
- Any violation (e.g., negative total) aborts the whole transaction.

### 5.4 Polymorphic Graph Integrity (TYPE RELATION)

For many‑to‑many relationships that can involve different table types, use `TYPE RELATION`.

```sql
DEFINE TABLE link SCHEMAFULL TYPE RELATION IN user|groups OUT user|groups;
```

**Polymorphism advantage** – a single edge type can connect any combination of users and groups, which is impossible with standard record links.

**Additional graph integrity enforced by events**:

- **Cycle prevention**

```sql
DEFINE EVENT no_cycles ON TABLE link WHEN $event = "CREATE" THEN {
    IF $after.out.{..+shortest=$after.in}->link->(?).len() > 0 {
        THROW "Cycle detected";
    };
};
```

- **Orphan prevention** (last edge removal)

```sql
DEFINE EVENT prevent_last_edge_removal ON TABLE link WHEN $event = "DELETE" THEN {
    IF record::exists($before.in) AND record::exists($before.out) {
        LET $other = (SELECT id FROM link WHERE out = $before.out AND id != $before.id LIMIT 1);
        IF $other.len() = 0 { THROW "Last edge – would orphan node"; };
    };
};
```

- **Leaf‑only deletion** (remove edges before deleting a node)

```sql
DEFINE EVENT prevent_non_leaf_delete ON TABLE user WHEN $event = "DELETE" THEN {
    IF $before.id->link.len() > 0 { THROW "Node still has edges – delete them first"; };
    DELETE link WHERE in = $before.id OR out = $before.id;
};
```

### 5.5 RBAC with Pre‑computed Permission Sets (Zero‑Cost RLS)

Instead of traversing the graph on every RLS check, use an event to **pre‑compute** all needed permissions and store them directly on the user record.

**Recipe**:

1. User table has fields:
   - `permissions` – `array<string>` (union of all group roles).
   - `parents` – `array<record<groups>>` (direct groups).
   - `dominates` – `array<record<user|groups>>` (recursive closure of managed entities).
2. A special field `last_refreshed_at` on the user acts as a **refresh trigger**.
3. An event on the user table detects when `last_refreshed_at` is changed (by access methods or admin) and then recomputes the arrays:

```sql
DEFINE EVENT refresh_rbac ON TABLE user WHEN $event = "UPDATE" THEN {
    IF $before.last_refreshed_at != $after.last_refreshed_at {
        UPDATE $after.id SET
            dominates   = ($after.id.{..+collect}->link->(?) ??[]).filter(|$v| $v != NONE).sort(),
            parents     = ($after.id<-link<-groups ??[]).filter(|$v| $v != NONE).distinct(),
            permissions = ($after.id<-link<-groups.role ??[]).flatten().filter(|$v| $v != NONE).distinct();
    };
};
```

4. RLS on any table then uses `$auth.permissions` and `$auth.dominates`:

```sql
PERMISSIONS FOR select WHERE id = $auth OR ('node_select' IN $auth.permissions AND id IN $auth.dominates);
```

**Result** – graph traversal happens only on writes (inside a system‑privileged event); all reads are simple O(1) array checks.

---

## 6. Event‑Driven Patterns Verified & Expanded

### 6.1 State‑Transition Logging (Corrected)

**Mistake to avoid**: trying to access `$before.other_field` in a field’s `VALUE`.  
**Solution**: use an event.

```sql
DEFINE FIELD status ON task TYPE string;
DEFINE FIELD z_status_log ON task TYPE array<object> DEFAULT [];

DEFINE EVENT log_status_change ON TABLE task WHEN $event = "UPDATE" THEN {
    IF $before.status != $after.status {
        UPDATE $after.id SET z_status_log = ($before.z_status_log ?? []) + [{
            from: $before.status,
            to: $after.status,
            ts: time::now()
        }];
    };
};
```

The log is never lost because the event runs in the same transaction.

### 6.2 Auto‑linking on Creation

When a user creates a subordinate record, automatically generate an edge.

```sql
DEFINE EVENT auto_edge ON TABLE user WHEN $event = "CREATE" AND $after.created_by != NONE THEN {
    RELATE ($after.created_by) -> link -> ($after.id);
};
```

### 6.3 Privilege Escalation Prevention

When a group’s roles are updated, verify that the editor (`$auth`) holds all roles being granted.

```sql
DEFINE EVENT prevent_escalation ON TABLE groups WHEN $event IN ["CREATE", "UPDATE"] THEN {
    IF $auth != NONE {
        LET $unauthorized = array::complement($after.role, $auth.permissions);
        IF $unauthorized.len() > 0 { THROW "You cannot grant permissions you don't have: " + <string>$unauthorized; };
    };
};
```

### 6.4 Zero‑Lock Pattern (Array Immutability Under Conditions)

Use an `IF` ladder in `VALUE` to make an array immutable once populated.

```sql
DEFINE FIELD role ON groups TYPE array<string> VALUE (
    IF $before == NONE THEN ($value ?? []).distinct()
    ELSE IF array::len($before) == 0 THEN []
    ELSE IF ($value ?? []).len() == 0 THEN $before
    ELSE $value.distinct() END
);
```

- On create: accept roles, deduplicate.
- Once roles exist: any attempt to set to empty or `NONE` is ignored (falls back to `$before`).
- Only non‑empty updates allowed.

---

## 7. Utilities & Advanced Idioms

### 7.1 Descriptive Errors with `THROW` in `ASSERT`

```sql
DEFINE FIELD age ON person TYPE int
    ASSERT IF $value >= 0 THEN true ELSE THROW "Age must be non‑negative" END;
```

### 7.2 `!!$value` – Reject Falsy Values (including 0, empty)

```sql
DEFINE FIELD quantity ON line_item TYPE int
    ASSERT !!$value;
```

### 7.3 Parameters for Schema‑Wide Constants

```sql
DEFINE PARAM $MIN_PASSWORD_LENGTH TYPE int VALUE 8;
DEFINE FIELD password ON user TYPE string ASSERT string::len($value) >= $MIN_PASSWORD_LENGTH;
```

### 7.4 `FLEXIBLE TYPE` for Extensible Objects

```sql
DEFINE FIELD metadata ON user TYPE FLEXIBLE object;
DEFINE FIELD metadata.created_by ON user TYPE string;  -- mandatory key
-- user can now set metadata.custom_key freely
```

### 7.5 `ASYNC` Events (3.0) for Non‑Critical Side Effects

```sql
DEFINE EVENT send_notification ON TABLE order WHEN $event = "CREATE" THEN ASYNC {
    http::post("https://webhook.example.com/new-order", $after);
};
```

The event runs outside the transaction and failure does **not** roll back the order.

### 7.6 Shortest Path Checks with `..+shortest`

```sql
LET $path = $start.{..+shortest=$end}->link->(?);
IF $path.len() > 0 { /* already connected */ }
```

---

## 8. Authentication & Access Methods – The Minimal Correct Setup

```sql
DEFINE ACCESS account ON DATABASE TYPE RECORD
    SIGNUP (
        UPDATE user SET
            password = crypto::argon2::generate($password),
            invite_token = NONE,
            last_refreshed_at = time::now()
        WHERE email = string::lowercase($email)
          AND invite_token = type::uuid($invite)
          AND string::len($password) > 6
    )
    SIGNIN (
        UPDATE user SET last_refreshed_at = time::now()
        WHERE email = string::lowercase($email)
          AND invite_token = NONE
          AND crypto::argon2::compare(password ?? "", $password)
    )
    AUTHENTICATE {
        IF $auth.password = NONE { RETURN NONE; };
        RETURN $auth;
    }
    DURATION FOR SESSION 8h, FOR TOKEN 1h;
```

- `SIGNUP` uses an invite token to claim an account.
- `SIGNIN` updates the refresh timestamp (which in turn triggers the RBAC recomputation event).
- `AUTHENTICATE` returns `NONE` if the user has no password (deactivated), denying access.

---

## 9. Schema‑Design Decision Matrix

| Requirement                                                 | Recommended Implementation                                                    |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Field must be trimmed email                                 | `VALUE` + `ASSERT` with `string::is_email`                                    |
| Two fields must be in a certain order                       | `z_` computed field reading both, `ASSERT` on it                              |
| Record must have unique email across table                  | `UNIQUE` index                                                                |
| Nested array items must be unique across all records        | Flatten into `z_::set<T>` + `UNIQUE` index                                    |
| Child aggregate must always remain positive                 | Parent computed field with `ASSERT`; child event triggers `UPDATE parent`     |
| Nested references must be protected from dangling deletions | Shadow `zz_` set with `REFERENCE ON DELETE`                                   |
| Graph must have no cycles                                   | Event on edge table using `..+shortest`                                       |
| Permissions must be checked instantly                       | Pre‑compute permissions array on user via event; RLS uses `$auth.permissions` |
| Only non‑empty array updates allowed after creation         | `VALUE` with fallback logic to `$before`                                      |
| Password must be stored securely                            | `crypto::argon2::generate` in access method                                   |
| Must log every status change                                | Event that appends to `z_log` when old and new differ                         |

---

## Appendix A – Official Documentation Links (SurrealDB 3.0)

### Statements & Clauses

- [DEFINE FIELD – all attributes](https://surrealdb.com/docs/surrealql/statements/define/field)  
  ([alternative reference link](https://surrealdb.com/docs/reference/query-language/statements/define/field))
- [DEFINE EVENT – when/then, async](https://surrealdb.com/docs/surrealql/statements/define/event)  
  ([alternative reference link](https://surrealdb.com/docs/reference/query-language/statements/define/event))
- [DEFINE TABLE](https://surrealdb.com/docs/reference/query-language/statements/define/table)
- [DEFINE FUNCTION](https://surrealdb.com/docs/reference/query-language/statements/define/function)
- [DEFINE ACCESS (Record)](https://surrealdb.com/docs/surrealql/statements/define/access/record)  
  ([alternative reference link](https://surrealdb.com/docs/reference/query-language/statements/define/access/record))
- [RELATE – create graph edges](https://surrealdb.com/docs/reference/query-language/statements/relate)
- [FOR loop](https://surrealdb.com/docs/reference/query-language/statements/for)
- [IF ELSE](https://surrealdb.com/docs/reference/query-language/statements/if-else)
- [LET – assign variable](https://surrealdb.com/docs/reference/query-language/statements/let)

### Language Primitives & Data Types

- [Statements and values overview](https://surrealdb.com/docs/learn/querying/surrealql/statements-and-values)
- [Data types](https://surrealdb.com/docs/reference/query-language/language-primitives/data-types)
- [Arrays](https://surrealdb.com/docs/reference/query-language/language-primitives/data-types/arrays)
- [Objects](https://surrealdb.com/docs/reference/query-language/language-primitives/data-types/objects)
- [Sets](https://surrealdb.com/docs/reference/query-language/language-primitives/data-types/sets)
- [Record references](https://surrealdb.com/docs/reference/query-language/language-primitives/record-references)
- [Record links](https://surrealdb.com/docs/reference/query-language/language-primitives/record-links)
- [Parameters & Pointers ($before, $after, $value, $input)](https://surrealdb.com/docs/surrealql/parameters)

### Schema Management

- [Fields and validation](https://surrealdb.com/docs/learn/schema-management/tables-and-fields/fields-and-validation)
- [Record IDs and addressing](https://surrealdb.com/docs/learn/schema-management/tables-and-fields/record-ids-and-addressing)
- [Defining events](https://surrealdb.com/docs/learn/schema-management/events-and-triggers/defining-events)
- [Reactive patterns with events](https://surrealdb.com/docs/learn/schema-management/events-and-triggers/reactive-patterns)
- [Custom functions](https://surrealdb.com/docs/learn/querying/concepts-and-guides/custom-functions)

### Graph & Relations

- [Reference Integrity](https://surrealdb.com/docs/surrealql/datamodel/references)
- [Record Links vs Graph Relations](https://surrealdb.com/docs/learn/data-models/graph/record-links-vs-graph-relations)  
  ([alternative link](https://surrealdb.com/docs/reference/query-language/language-primitives/record-links))
- [Creating relations](https://surrealdb.com/docs/learn/data-models/graph/creating-relations)
- [Graph traversal](https://surrealdb.com/docs/learn/data-models/graph/graph-traversal)

### Security & Permissions

- [Permissions & Row Level Security (RLS)](https://surrealdb.com/docs/learn/security/authorization/permissions-and-row-level-security)

### Migrations & Futures

- [Futures → COMPUTED field migration](https://surrealdb.com/docs/surrealql/datamodel/futures)

### Blog / Best Practices

- [Ten tips for your schema](https://surrealdb.com/blog/ten-tips-and-tricks-for-your-database-schema)
- [Ten more schema tips](https://surrealdb.com/blog/ten-more-schema-tips)

---

_All patterns and facts validated against SurrealDB 3.0 stable (February 2026). This document serves as the definitive coding standard for implicit‑control architectures on SurrealDB._
