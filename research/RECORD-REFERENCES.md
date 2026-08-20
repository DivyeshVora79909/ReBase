# SurrealDB Record References Engineering Reference

This document records the measured behavior, constraints, cascading deletion, array interactions, query semantics, and transaction boundaries of `REFERENCE` fields in SurrealDB `3.2.0` (tested on x86_64 Linux in-memory datastore).

---

## 1. Core Reference & Type Semantics

- **Record Types vs Constraints**:
  - `TYPE record<parent>` enforces **syntax & table prefix** only (e.g. `parent:...`). It does **not** verify that the target record exists.
  - Creating a record referencing `parent:does_not_exist` succeeds immediately without errors across `TYPE record`, `TYPE record<parent>`, and `TYPE array<record<parent>>`.
  - Referential integrity constraints are activated **only** when `REFERENCE ON DELETE <ACTION>` is declared on a root-level field.
- **Grammar**:
  ```surrealql
  DEFINE FIELD <name> ON <table> TYPE <type> REFERENCE [ON DELETE <IGNORE | CASCADE | REJECT | UNSET | THEN { ... }>];
  ```
  _(Note: `REFERENCE` cannot be placed on nested wildcard fields like `parents._`; define it at the root array field `parents`).\*

---

## 2. ON DELETE Actions (Single References)

| Action           | Behavior on Target Deletion                                                        | Target State | Referencing Child State                               | Error / Rollback                                     |
| :--------------- | :--------------------------------------------------------------------------------- | :----------- | :---------------------------------------------------- | :--------------------------------------------------- |
| **IGNORE**       | Deletion proceeds; reference field is untouched.                                   | Deleted      | Survives; retains dangling pointer (e.g. `parent:1`). | None                                                 |
| **CASCADE**      | Deletion proceeds; referencing record is automatically deleted.                    | Deleted      | Deleted (synchronous cascade).                        | None                                                 |
| **REJECT**       | Deletion is blocked; transaction aborts and rolls back.                            | Preserved    | Preserved intact.                                     | `Cannot delete ... referenced with ON DELETE REJECT` |
| **UNSET**        | Target is deleted; field is set to `NONE`. Requires `TYPE option<record<parent>>`. | Deleted      | Survives; field becomes `NONE`.                       | Fails if field is not `option<...>`                  |
| **THEN { ... }** | Custom SurrealQL block executes upon target deletion.                              | Deleted      | Survives or custom modified.                          | Aborts transaction on block failure                  |

---

## 3. ON DELETE Actions (Array of References)

Given `child.parents = [parent:1, parent:2, parent:3]`:

- **IGNORE**: Deleting `parent:1` succeeds. The array remains `[parent:1, parent:2, parent:3]`. The deleted element is **not** pruned.
- **CASCADE**: Deleting **any single referenced member** (e.g. `parent:1`) **deletes the entire referencing child record**.
- **REJECT**: Deleting any referenced member currently in the array is blocked with a `REJECT` error.
- **UNSET**: Deleting `parent:1` automatically removes only that element from the array, leaving `[parent:2, parent:3]`.

---

## 4. Multi-Field & Mixed Combinations

Given a record with `owner` (single ref) and `orgs` (array ref) both pointing to `org:1`:

| Single Ref (`owner`) | Array Ref (`orgs`) | Deleting Target `org:1` | Final Child State                             |
| :------------------- | :----------------- | :---------------------- | :-------------------------------------------- |
| `IGNORE`             | `IGNORE`           | Succeeds                | Survives (both retain dangling pointers)      |
| `IGNORE`             | `CASCADE`          | Succeeds                | **Deleted** (array cascade triggered)         |
| `IGNORE`             | `REJECT`           | **Rejected**            | Survives (array reject blocked deletion)      |
| `CASCADE`            | `IGNORE`           | Succeeds                | **Deleted** (single cascade triggered)        |
| `CASCADE`            | `CASCADE`          | Succeeds                | **Deleted** (deleted exactly once)            |
| `CASCADE`            | `REJECT`           | **Rejected**            | Survives (`REJECT` takes absolute precedence) |
| `REJECT`             | `IGNORE`           | **Rejected**            | Survives (`REJECT` blocks deletion)           |
| `REJECT`             | `CASCADE`          | **Rejected**            | Survives (`REJECT` blocks deletion)           |
| `REJECT`             | `REJECT`           | **Rejected**            | Survives (`REJECT` blocks deletion)           |

**Rule**: `REJECT` evaluated on _any_ path takes absolute priority and prevents deletion across all related tables.

---

## 5. Cascading Chains, Trees & Atomicity

- **Chain Cascade ($A \to B \to C \to D \to E$)**:
  Deleting $A$ synchronously cascades down the entire hierarchy in a single transaction ($E, D, C, B, A$ all deleted).
- **CASCADE $\to$ REJECT Dependency ($A \xrightarrow{\text{CASCADE}} B \xrightarrow{\text{REJECT}} C$)**:
  Deleting $A$ requires cascading to $B$. But $C$ rejects deletion of $B$. SurrealDB catches the conflict, aborts the operation, and rolls back the transaction. $A$, $B$, and $C$ all remain untouched.
- **Branching Trees ($A \to B \text{ [REJECT]}$, $A \to D \text{ [CASCADE]}$)**:
  If any branch encounters a `REJECT`, the entire multi-branch operation aborts atomically. No partial cascade occurs on $D$.
- **Circular Cascades ($A \to B \to C \to A$)**:
  Deleting $A$ cascades to $B$, which cascades to $C$, which points back to $A$. Since $A$ is already marked for deletion, the cycle terminates cleanly without infinite recursion.

---

## 6. Dead / Dangling Record Query Semantics

When `IGNORE` leaves dangling pointers (e.g. `child.parent = parent:deleted`):

- **Field Dereferencing (`child.parent.name`)**: Returns `NONE` / `null`. Does not throw.
- **Record Dereferencing (`SELECT * FROM child.parent`)**: Returns empty result `[]`.
- **Equality Filtering (`WHERE parent = parent:deleted`)**: Evaluates to `true` (matches literal record ID string).
- **FETCH (`FETCH parent`)**: Populates `parent: null` for single refs; populates `[null, { alive_record }]` for arrays.
- **Functions (`record::exists(parent)`)**: Returns `false` for dead pointers and `true` for existing records.

---

## 7. Direct Answers to Core Research Questions

1. **Is a record reference a real referential integrity constraint?**  
   _Yes, but only on delete_. Creation/update allows dangling IDs; `REFERENCE ON DELETE` enforces constraints upon target deletion.
2. **Can it point to a nonexistent record?**  
   _Yes_. `CREATE` and `UPDATE` do not validate target existence.
3. **What does IGNORE do to a single reference?**  
   Leaves the referencing record intact with a dangling record ID.
4. **What does IGNORE do to an array reference?**  
   Leaves the array unchanged; the dead ID remains inside the array.
5. **Does IGNORE remove dead array elements?**  
   _No_. Use `ON DELETE UNSET` to remove deleted elements from arrays.
6. **What does CASCADE do to a single reference?**  
   Deletes the referencing record.
7. **What does CASCADE do to an array reference?**  
   Deletes the entire referencing record if **any** array member is deleted.
8. **What does REJECT do?**  
   Aborts target deletion with an error and rolls back the transaction.
9. **What happens in CASCADE $\to$ REJECT chains?**  
   The entire operation is rejected atomically; no records are deleted.
10. **Is cascade atomic?**  
    _Yes_. All cascades occur inside the caller's transaction boundary.
11. **Can partial cascade deletion occur?**  
    _No_. Any failure in the cascade DAG rolls back all modifications.
12. **How are circular cascades handled?**  
    Terminated cleanly once all cycle members are marked for deletion.
13. **Do synchronous and async events fire on cascaded deletion?**  
    _Yes_. Both `SYNC` and `ASYNC` events defined on cascaded tables execute upon deletion.
14. **Can dead record IDs be queried?**  
    _Yes_. They evaluate as valid IDs, match equality filters, and return `null` on field dereference or `FETCH`.

---

## 8. Production Architecture Recommendations

1. **True Foreign Key Integrity**:
   Because `CREATE` does not verify existence, ReBase generates creation/update
   assertions for every top-level record field:
   ```surrealql
   DEFINE FIELD parent ON child TYPE record<parent>
       ASSERT record::exists($value)
       REFERENCE ON DELETE CASCADE;
   ```
   On SurrealDB `3.2.0`, an authenticated field `ASSERT` sees a row-hidden
   existing target as nonexistent. This gives the framework both input
   integrity and ordinary reference-use authorization. The exact permission
   interaction is version-sensitive and is therefore probe-gated; see
   [REFERENCE-AUTHORIZATION-FINDINGS.md](./REFERENCE-AUTHORIZATION-FINDINGS.md).
2. **Array References**:
   - Use `ON DELETE UNSET` when child records should survive individual member deletion.
   - Use `ON DELETE CASCADE` only when child records lose meaning if _any_ parent is removed.
3. **Nullable Foreign Keys**:
   When using `ON DELETE UNSET` on single references, always declare `TYPE option<record<parent>>` to avoid schema coercion errors.
