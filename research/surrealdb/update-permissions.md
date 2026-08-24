# SurrealDB Update and Field Permission Findings

Status: measured compatibility reference

Tested: SurrealDB `3.2.0`, x86_64 Linux, isolated in-memory databases.

## Reproduction

The original update-permission runner recorded 28 cases, including table-level
`SET`, `MERGE`, JSON `PATCH`, `CONTENT`, `UPSERT`, bulk updates, field filters,
and event rollback. Keep the project’s architecture/security probes as the
upgrade gate and reproduce any narrower claim in a disposable instance.

## Table-level update permissions

`FOR update WHERE owner = $auth` is enforced against both the existing row and
the candidate/resulting row, analogous to a `USING` plus `WITH CHECK` boundary:

- Alice cannot transfer her row to Bob: the existing row passes but the result
  fails.
- Bob cannot take over Alice’s row: the result would pass but the existing row
  fails.
- Both statements return no row and leave the original unchanged.
- The same behavior was observed for `SET`, `MERGE`, JSON `PATCH`, `CONTENT`,
  and `UPSERT` of an existing record.
- Bulk updates filter unauthorized rows rather than necessarily throwing.

Table predicates using `$before.owner` or `$after.owner` were not reliable
authorization snapshots in the tested version. Do not build primary table
authorization around those event-style variables.

## Field permissions are filters

Field permissions are non-throwing filters:

- `PERMISSIONS FOR update NONE` retains the previous value;
- a false `$value` condition retains the previous field value;
- one field can be filtered while other fields in the same statement update;
- a field `$before` predicate can inspect that field’s previous value.

Use field permissions for server-managed, immutable, or deliberately ignored
writes. They are not substitutes for assertions when the caller must receive an
explicit validation failure or when multiple fields must be governed atomically.

## `VALUE` and permission context

`VALUE` is the field’s transformation/defaulting expression, but its effective
execution depends on whether the mutation is allowed to materialize that field.
Do not state that `VALUE` universally runs on every row mutation.

The following isolated 3.2.0 observations are the compatibility boundary:

| Field definition | Privileged/root create/update | Record-user create/update |
| --- | --- | --- |
| `VALUE rand::uuid::v7() PERMISSIONS NONE` | Value generated/rewritten | Field may be omitted by permission filtering; a client update did not reliably rotate it. |
| `VALUE rand::uuid::v7()` with `select NONE`, `create WHERE true`, `update NONE` | Value generated/rewritten | Record-user create initialized it; explicit update input was filtered and did not provide a general rotation guarantee. |

The generated async cancellation field uses a narrower measured pattern:

```surql
TYPE bool
VALUE IF $before = NONE THEN false ELSE $value END
PERMISSIONS
  FOR select WHERE true
  FOR create WHERE $value = false
  FOR update WHERE $value = true AND ($before = NONE OR $before = false)
```

On 3.2.0, a record user supplying `true` on create received a stored `false`;
the first later `false -> true` update succeeded; and an attempted `true -> false`
update retained `true`. This gives a materialized boolean plus monotonic client
cancellation without trusting the create payload. `npm run probe:runtime` keeps
this behavior in the upgrade gate.

An explicit client-supplied token is overwritten when the field is actually
materialized by an allowed privileged mutation. A record user can see neither a
`PERMISSIONS NONE` field nor a field denied for select; a privileged runtime may
read it for an access/signup predicate.

### Consequence for machine-controlled invite tokens

The safe invariant is:

```surql
DEFINE FIELD invite_token ON user TYPE uuid
    VALUE rand::uuid::v7()
    PERMISSIONS NONE;
```

This prevents client reads/writes, but it does not by itself prove that every
record-user row mutation rotates the token. If rotation on every mutation is a
security requirement, use one of these explicit designs:

1. a synchronous/async machine event that performs a guarded internal update;
2. a server-only mutation path that always writes/materializes the token;
3. a version-pinned probe confirming the exact permission context for the
   deployment’s real table permissions and update shapes.

Signup must compare the hidden token inside the database access query and should
not treat a client-visible field projection as the source of truth.

## Event rollback

Synchronous event blocks with `THROW` roll back the triggering statement. This
held for single-row and bulk updates when one row triggered the event. The event
itself is privileged; see
[`reference-authorization.md`](./reference-authorization.md).

## ReBase ownership matrix

The selected project policy protects `owned_by` with:

```surql
FOR update WHERE
    $value = $before
    OR $before = $auth
    OR $before IN $auth.dominates
```

Combined with the table boundary, the measured matrix is:

| Case | Result |
| --- | --- |
| Parent-group member edits ordinary fields | Allowed |
| Owner delegates to an accessible parent group | Allowed |
| Parent-group member attempts ownership transfer | Ownership retained; ordinary fields may update |
| Owner transfers to a dominated principal | Allowed |
| Dominator transfers a dominated row to self | Allowed |
| Owner/dominator transfers to an unrelated principal | Resulting-row table permission denies update |
| Client writes a server-managed field with an ordinary field | Server field retained; ordinary field updates |

## Project policy

Table permissions govern existing/resulting rows. Field permissions protect
server-managed values and may silently retain old values. Assertions validate
input and must be used when invalid data must fail. Do not reintroduce mutation
events for ordinary ownership governance when the table-plus-field rule is
sufficient.

## Upgrade policy

Pin the supported SurrealDB version and run the architecture/security probes
before every upgrade. Any change to field materialization, `$before` context,
permission filtering, or event rollback requires updating this finding and the
dependent ReBase decision document before changing generated schema.
