# Permission-Aware Record Existence

Status: measured compatibility reference

Tested: SurrealDB `3.2.0`, x86_64 Linux, isolated in-memory database.
Reproduction: `npm run probe:architecture`.

## Documented baseline

Official documentation establishes that:

- `record<table>` constrains record-ID syntax/table prefix;
- a record link alone does not prove target existence;
- `record::exists(record)` reports existence;
- field `ASSERT` rejects a value when false;
- field permissions narrow record-user visibility/writes;
- queries inside events execute without table/field permission checks.

The documentation does not clearly promise that `record::exists()` is
permission-aware in every schema evaluation context. The client-session results
below are therefore version-sensitive, not universal SurrealDB guarantees.

References:

- <https://surrealdb.com/docs/reference/query-language/functions/database-functions/record#recordexists>
- <https://surrealdb.com/docs/reference/query-language/statements/define/field>
- <https://surrealdb.com/docs/reference/query-language/statements/define/event#events-and-permissions>
- [`record-references.md`](./record-references.md)

## Measured record-user behavior

The probe created an accessible `config:alice`, a row-hidden existing
`config:bob`, a missing ID, and a field-hidden `api_key`. From Alice’s record
session:

```text
record::exists(config:alice)   -> true
record::exists(config:bob)     -> false
record::exists(config:missing) -> false

config:alice.owned_by -> principal:alice
config:bob.owned_by   -> NONE
config:alice.api_key  -> NONE
SELECT * FROM config:bob -> []
```

Row permission controls whether the target row exists to the client query;
field permission controls which values are visible after the row is accessible.
This supports selectable configuration metadata with hidden credentials.

## Assertions

For an ordinary client-usable required reference:

```surql
DEFINE FIELD config ON send_brevo_email
    TYPE record<email_brevo_config>
    ASSERT record::exists($value);
```

The tested field assertion accepted the accessible row and rejected both the
hidden existing row and missing ID. For cardinality:

```surql
-- optional scalar
ASSERT $value = NONE OR record::exists($value)

-- array, including optional containers normalized to []
ASSERT array::all($value ?? [], |$reference| record::exists($reference))
```

Cardinality, uniqueness, maximum length, and domain constraints remain separate
assertions. The compiler combines a developer assertion with the existence
invariant rather than replacing it, and only alters top-level record fields.

### Required hidden scalar fields

On SurrealDB 3.2.0, `TYPE string` alone does not reject an omitted field during
`CREATE`. A required credential therefore uses a `VALUE` guard that throws when
`$value = NONE` or empty, then returns the value unchanged. The guard still
permits ordinary updates that omit the field because SurrealDB supplies the
stored value to the field expression. This keeps missing provider credentials a
database validation error instead of a queue-time failure.

## Permissions are not validators

This is not equivalent:

```surql
DEFINE FIELD config ON job TYPE record<config>
    PERMISSIONS FOR create WHERE record::exists($value);
```

In the probe, a field create permission accepted a hidden physical target and
silently omitted a missing target. Field permissions are filters, not required
reference validation.

Likewise, a table predicate `FOR create WHERE record::exists(config)` accepted a
hidden physical target. A table predicate `config.owned_by = $auth` rejected
hidden/missing targets because it expressed the actual ownership policy.
Existence alone is never an authorization decision.

## Events are privileged

An event can read hidden rows and hidden fields regardless of the triggering
record user. Therefore:

```text
client triggered event
  != client authorized every event-visible reference
```

If a reference is not client-visible but must still be usable, use an explicit
synchronous event guard comparing `owned_by`, allowed principals, or another
policy with `$auth`, or use a visible alias/capability row. Do not weaken the
default assertion for every reference.

Recommended configuration boundary:

1. expose harmless provider metadata under normal row access;
2. hide API keys/tokens with field `PERMISSIONS NONE`;
3. store the provider credential as a required opaque field on the authorized
   configuration row, when the product deliberately keeps credentials in its
   own database;
4. let privileged handlers load declared credential fields. Queue locators and
   sync snapshots carry configuration record IDs, never credential values.

## ReBase compiler policy

The generated defaults are:

1. strict record target types where known;
2. cardinality-appropriate `record::exists()` assertions;
3. native `REFERENCE ON DELETE` policy;
4. immutable effect inputs after submission where appropriate;
5. selectable configuration metadata and hidden credential fields;
6. runtime loaders restricted to declared root references.

Principal `parents` is the deliberate exception because it validates only changed
edges, including hidden unchanged parents; see
[`../rebase/parents-field.md`](../rebase/parents-field.md).

## Upgrade/fallback policy

Pin the supported SurrealDB version and run architecture/security probes before
every upgrade. If permission-aware field assertions change:

1. use the canonical ownership/readers predicate against a universal field such
   as `owned_by`;
2. use a synchronous explicit-use guard for invisible targets;
3. never fall back to type-only record references, which permit dangling and
   unauthorized IDs.
