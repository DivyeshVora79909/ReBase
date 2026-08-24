# ReBase Authorization and Data Model

Status: adopted authorization, graph, audit, and compiler policy

This document owns ReBase’s database-native security model. Engine observations
that make the model possible live in [`../surrealdb/update-permissions.md`](../surrealdb/update-permissions.md),
[`../surrealdb/reference-authorization.md`](../surrealdb/reference-authorization.md),
and [`parents-field.md`](./parents-field.md).

## Design method

Treat unfamiliar SurrealDB behavior as a hypothesis until a disposable probe
reproduces it. Prefer one fixed security model, set operations, schema-derived
generation, explicit bounded exceptions, native database behavior, and live
upgrade probes. Breaking changes are acceptable before production; security
regressions and parallel sources of truth are not.

## Vocabulary

- **Principal:** a `user` or `groups` record.
- **Business record:** any application record outside framework-owned principal,
  audit, effect, schedule, and operational tables.
- **Ownership:** every business record has `owned_by TYPE record<user | groups>`.
  Ownership anchors create, update, select, delete, reader inheritance, and
  delegation.
- **Table permission:** `<table>_select`, `<table>_create`,
  `<table>_update`, and `<table>_delete`; permission strings do not by
  themselves grant access to every row.
- **Access index:** `z_access_index` is a materialized string array containing a
  principal’s own ID, direct parent groups, and dominated principals. It makes
  row checks bounded membership tests instead of graph traversals.
- **Reader index:** `readers_index` is a materialized string array of principals
  inherited from referenced business records; it never contains business record
  IDs.

## Principal DAG

Users and groups form a directed acyclic graph through `parents`; it is not a
tree. The framework maintains:

1. every assigned parent exists;
2. a node cannot parent itself or one of its descendants;
3. `dominates` updates after edge changes;
4. permissions/capabilities propagate from parent groups;
5. a user cannot edit its own `parents` field;
6. role/capability updates cannot grant values absent from the actor’s own
   permissions.

`parent_groups` means direct parent groups only. `dominates` means descendants
reachable below the principal. `groups:root` bootstraps generated permissions.
The parent-edge delta rule is documented separately in
[`parents-field.md`](./parents-field.md).

## Uniform business-table permissions

There is no owner-only/readers-only/visibility-mode compiler switch. Every
business table uses the same set-based row boundary.

### Select

```surql
'<table>_select' IN $auth.permissions
AND (
    !!visibility
    OR readers_index CONTAINS <string>$auth.id
    OR <string>owned_by IN $auth.z_access_index
)
```

`visibility` is an ordinary boolean. `true` exposes a row to actors holding the
table select permission; false, `NONE`, or absence grants nothing. A context
table may define visibility, while an ordinary table may omit it.

### Create and update

```surql
'<table>_create' IN $auth.permissions
AND (owned_by = $auth OR owned_by IN $auth.parent_groups OR owned_by IN $auth.dominates)
```

Update uses the same owner boundary with `<table>_update`. SurrealDB 3.2 applies
the table predicate to both existing and resulting rows; do not replace it with
unreliable table-level `$before`/`$after` predicates.

### Delete

```surql
'<table>_delete' IN $auth.permissions
AND (owned_by = $auth OR owned_by IN $auth.dominates)
```

Direct parent-group access intentionally does not grant delete.

### Ownership writes

```surql
$value = $before
OR $before = $auth
OR $before IN $auth.dominates
```

Together with table permissions this allows an owner to delegate to an
accessible parent group, lets parent-group members edit ordinary fields without
taking ownership, and lets dominators redirect/reclaim dominated records. A
field permission is a non-throwing filter: a denied ownership write may leave
the old owner while other fields update, so callers must inspect the result when
they need confirmation.

## Reader inheritance

Reader inheritance lets a derived record inherit access from referenced business
resources. Only `readers_index` is materialized. A computed
`rebase_reader_sources` projection exists solely for cycle detection.

For a contributing business reference, inherit:

```surql
[<string>$reference.owned_by, $reference.readers_index]
```

Flatten, deduplicate, remove `NONE`, and index the result.

References to `user` or `groups` contribute nothing. A polymorphic field that
accepts principals and business tables is excluded as a whole. Scalar business
references participate automatically because fanout is one. Arrays participate
only with `@rebase-readers`, must use native `REFERENCE`, must have business-only
targets, and accept the recomputation cost explicitly.

There is no `shared_with` field. Use groups for direct sharing or reference a
business resource whose readers should flow into the derived record.

When a referenced owner/readers value changes, reverse references and
`system_ping` force dependent value fields to recompute. Revocation correctness
is more important than making writes appear cheap.

### Cycle rejection and revocation convergence

Reader inheritance is a strict DAG. The compiler emits `rebase_reader_sources`
cycle projections and rejects writes that close a cycle via a generated
`REBASE_READER_CYCLE` event. This guard exists for revocation convergence, not
infinite-loop prevention.

Without the guard, cycles do not cause runaway cascades (propagation stabilizes
because cascade events only continue when `owned_by` or `readers_index`
changes). However, cycles create a concrete authorization bug during ownership
transfer:

1. A is owned by Alice.
2. B is owned by Bob and references A.
3. A is updated to reference B, creating A → B → A.
4. A is transferred from Alice to Carol.

After the transfer, Alice remains in both records' `readers_index` even though
she is no longer an owner or valid reader source. The cycle retained her through
previously materialized reader arrays. The revoked principal becomes permanently
stale.

This is not fixable by existence checks:

- `record::exists()` does not help. A, B, and `user:alice` all still exist.
- Filtering `NONE` only removes missing references or null values; it does not
  remove a principal whose ownership was revoked.
- Strict `REFERENCE` fields already provide existence and delete behavior through
  their `ON DELETE` policies. Adding `record::exists()` to every reader
  calculation adds per-record lookup cost without solving the stale-principal
  problem.

The guard enforces the invariant: `readers_index` is derived from an acyclic
dependency graph, so ownership transfer and reader revocation converge correctly.

### Guard blast radius

The cycle guard implementation is small:

- `reactivity.js` contains the cycle event generator (~26 source lines).
- `security.js` emits the computed dependency field and source expressions.
- `compiler.js` adds one generated section.
- A typical build generates 3 `rebase_reader_sources` fields, 3 cycle events,
  ~24 generated lines, and ~2 KB of SurrealQL.
- No gateway, handler, queue, or API behavior depends on the guard.
- Runtime cost is paid only when participating references are created or changed.
- It prevents the write before the more expensive downward cascade begins.

### Regression verification

Disposable probes must cover:

1. A positive probe asserting that production schemas reject a cycle write.
2. A regression probe documenting the actual failure mode: allow a cycle in a
   guard-disabled disposable schema, transfer ownership, and assert the revoked
   principal remains in `readers_index`.

### Future cycle support

If cycles must eventually be supported, a different algorithm is required:
recompute readers from current ownership roots using visited-set graph traversal.
That is a larger and potentially more expensive redesign, not a simple filter.
Until such a case is demonstrated, do not add `record::exists()` checks to
reader derivation.

## Views

Generated views are capability-scoped company context, not row-scoped business
projections. A view uses its source table capability:

```surql
'<source_table>_select' IN $auth.permissions
```

The compiler must not inject source-row `owned_by`, `readers_index`, or
`visibility` predicates. A view author intentionally controls aggregate/grouping
dimensions, including identifiers that may identify principals or records.

## Audit and change history

Marked tables produce asynchronous `audit_mutation` records for create, update,
and delete. Audit is outside the business transaction’s latency/failure path.
Field markers define redaction/omission and changed-field tracking. Framework
managed fields such as readers, permissions, dominance, indexes, and timestamps
are omitted by default.

`change_logs` is a smaller client-facing history for fields explicitly marked
for change logging. It is independently authorized by the target’s existence,
table capability, and access index. Cascaded recomputation may create additional
audit entries; that noise is accepted because it does not complicate or block
the permission model. SurrealDB 3.2 exposes no transaction ID inside async
events, so records retain event time, actor, target, before/after, and changed
fields without synthetic transaction grouping.

## Compiler security contract

The compiler’s deterministic order is:

1. business schema;
2. framework tables/access definitions;
3. uniform table permissions and system fields;
4. reader derivation, cycle guards, and propagation;
5. audit and change-log events;
6. views and reactive fields;
7. required indexes;
8. root permission bootstrap and project seed.

Generation branches on schema facts—scalar versus array references, principal
targets, audit markers, and view group keys—not on project security modes.

The compiler must not create a second authorization catalog, `operations.json`,
JSON-schema gateway contract, visibility mode, global array-reader switch,
generic `shared_with`, handler-version registry, or hard-coded scenario graph.

## Data and verification policy

The Surreal schema is the source of truth for tables, references, cardinality,
computed/read-only fields, ownership, and framework-managed values. JSON Schema
files only generate valid scalar fakes. The populator uses keyset pagination,
bounded reservoirs, dependency-aware batches, and printed replay seeds; it does
not use `COUNT + OFFSET`, `ORDER BY rand()`, or a hard-coded relationship map.

Disposable probes must cover the permission matrix, delegation, DAG cycles,
reader inheritance/revocation/cycles, views, audit, effects, webhooks, and
schema-driven data generation. The upgrade gate is `npm run verify` plus the
targeted architecture probe.

## Explicit non-goals

Do not introduce alternate select modes, direct principal reader arrays, global
array reader inheritance, operation/schema discovery APIs, dotted capability
hierarchies, privileged database connections for ordinary handlers, row-level
ACL injection into aggregate views, removal of compliance audit, random full
table fixture sorts, or security changes based only on assumptions about
SurrealDB behavior.
