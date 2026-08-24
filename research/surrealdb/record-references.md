# Record Reference Semantics

Status: measured engine reference

Tested: SurrealDB `3.2.0`, x86_64 Linux, isolated in-memory database.

## Type versus integrity

`TYPE record<parent>` validates the record-ID type/table prefix but does not
verify target existence. Create/update accepted dangling IDs for scalar,
typed-scalar, and array record fields. `REFERENCE ON DELETE ...` adds reverse
link/delete behavior at a root field; it does not validate the target on input.

```surql
DEFINE FIELD parent ON child TYPE record<parent>
    REFERENCE ON DELETE REJECT;
```

Declare `REFERENCE` on the root array field, not a nested wildcard path.

## Delete actions

| Action | Single reference | Array reference |
| --- | --- | --- |
| `IGNORE` | Target deletes; child keeps a dangling ID | Array remains unchanged with dead element |
| `CASCADE` | Referencing child deletes | Deleting any member deletes the whole child |
| `REJECT` | Target deletion fails/rolls back | Any matching member blocks deletion |
| `UNSET` | Field becomes `NONE`; requires `option<record<...>>` | Only the deleted member is removed |
| `THEN { ... }` | Custom block runs; failure aborts transaction | Same custom transactional semantics |

When multiple reference paths point to the same target, any `REJECT` wins and
blocks the entire deletion. Otherwise any `CASCADE` deletes the child once;
`IGNORE` paths do not prevent it.

## Cascade atomicity and cycles

- A cascade chain deletes all reachable dependents in one transaction.
- If a later `REJECT` blocks a cascade, every earlier deletion rolls back.
- A rejecting branch prevents partial deletion in other branches.
- Circular cascades terminate cleanly when a record already marked for deletion
  is revisited.
- Sync and async delete events fire on records deleted through cascade.

## Dangling-link query behavior

After `IGNORE` leaves a dead ID:

| Operation | Result |
| --- | --- |
| `child.parent.name` | `NONE`/null, no exception |
| `SELECT * FROM child.parent` | empty result |
| `WHERE parent = parent:deleted` | literal ID still matches |
| `FETCH parent` | `null`; arrays contain `null` for dead members |
| `record::exists(parent)` | `false` |

A dead record ID remains a valid typed value; dereferencing and existence are
what reveal the missing row.

## Input-integrity consequence

True reference integrity needs both input and delete rules:

```surql
DEFINE FIELD parent ON child TYPE record<parent>
    ASSERT record::exists($value)
    REFERENCE ON DELETE REJECT;
```

On SurrealDB 3.2.0, a field assertion evaluated from an authenticated record
session also treated row-hidden targets as nonexistent. That permission behavior
is version-sensitive and documented in
[`reference-authorization.md`](./reference-authorization.md).

Choose delete behavior from domain semantics:

- `UNSET` when the child survives target deletion;
- `CASCADE` only when losing any referenced target invalidates the child;
- `REJECT` for ownership/configuration/integrity edges that must be resolved
  explicitly;
- `IGNORE` only when dangling IDs are intentionally useful.

For single-field `UNSET`, use an optional record type or schema coercion fails.
