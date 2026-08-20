# UUIDv7 Record ID Findings

Status: measured architecture input

Tested version: SurrealDB `3.2.0` on x86_64 Linux with the in-memory datastore

Reproduction: `npm run probe:architecture`

## Decision

Every effect table should declare an explicit UUIDv7 record-ID policy:

```surql
DEFINE FIELD id ON send_brevo_email
    TYPE uuid
    DEFAULT rand::uuid::v7();
```

This provides one predictable record-ID type across client-created effects,
scheduled occurrences, runtime-created records, queue envelopes, provider
idempotency keys, and webhook correlation.

Use the full locator at infrastructure boundaries:

```js
{
  namespace: "tenant_namespace",
  database: "tenant_database",
  id: "send_brevo_email:u'01a0...'"
}
```

The record ID already contains the table name. Namespace and database are still
required because a SurrealDB record ID is scoped to a database.

## Officially documented behavior

SurrealDB documents that:

- record IDs can contain UUIDv7 values;
- `CREATE table:uuid()` generates a UUIDv7 record ID;
- `rand::uuid()` generates UUIDv7;
- `rand::uuid::v7()` is an alias of `rand::uuid()`;
- UUIDv7 has millisecond timestamp precision;
- `DEFINE FIELD id ON table TYPE uuid` constrains the record-ID value type;
- since SurrealDB 3.2, `DEFAULT` and `ASSERT` are supported on `id`;
- `VALUE`, `REFERENCE`, `COMPUTED`, `READONLY`, `FLEXIBLE`, and non-key field
  clauses are forbidden on `id`.

References:

- <https://surrealdb.com/docs/reference/query-language/language-primitives/data-types/record-ids>
- <https://surrealdb.com/docs/reference/query-language/language-primitives/data-types/uuids>
- <https://surrealdb.com/docs/reference/query-language/functions/database-functions/rand#randuuid>
- <https://surrealdb.com/docs/reference/query-language/statements/define/field#defining-a-type-for-the-id-field>

## Measured behavior

With:

```surql
DEFINE TABLE typed_id SCHEMAFULL;
DEFINE FIELD id ON typed_id TYPE uuid;
DEFINE FIELD value ON typed_id TYPE int;
```

all of these succeed:

```surql
CREATE typed_id SET value = 1;
CREATE typed_id:u'0198c6c4-bd70-7d6d-8a7a-87bb773590db' SET value = 2;
CREATE type::record('typed_id', rand::uuid::v7()) SET value = 3;
```

The unspecified first ID was automatically generated as UUIDv7 on the tested
version. `record::id(id)` returned a UUID value and `type::is_uuid(...)` was
true for every row.

This correctly fails:

```surql
CREATE typed_id:bad SET value = 4;
```

An equivalent table without an `id TYPE uuid` declaration received SurrealDB's
ordinary 20-character random text ID.

Although implicit UUID generation from `TYPE uuid` is measured, the generated
framework schema should include `DEFAULT rand::uuid::v7()` explicitly. That is
clearer, is directly supported by the 3.2 field documentation, and avoids
depending on implicit type-directed generation.

## Creation forms

### Ordinary client creation

```surql
CREATE send_brevo_email SET ...;
```

The `id` default supplies the UUIDv7.

### Generated sync wrapper

```surql
LET $id = type::record('file_access_grant', rand::uuid::v7());
CREATE ONLY $id SET ...;
RETURN (SELECT * FROM $id)[0];
```

The explicit variable gives the query a stable ID it can re-select after the
synchronous event applies its patch.

### Runtime and scheduler creation

The runtime may either omit the ID and use the schema default or construct it
explicitly:

```surql
CREATE type::record($table, rand::uuid::v7()) CONTENT $content;
```

Do not accept a free-form table string from an external request. The table is
selected from the compiled effect registry.

## Uniqueness and entropy

UUIDv7 has enough randomness for practical uniqueness at billions or trillions
of generated values when generated correctly. It is temporally sortable and
well suited to distributed creation.

This does not make a SurrealDB record ID formally global:

```text
table:id is unique inside one database
namespace + database + table:id identifies the data location
```

Nor does UUID entropy provide logical idempotency. If a retry creates a new
UUID, it creates a different effect:

```text
attempt 1 -> send_brevo_email:uuid-A
attempt 2 -> send_brevo_email:uuid-B
```

For immutable async effects, use the stable effect record ID as the provider
idempotency key. The client/compiler must reuse the same record ID when retrying
the same logical submission.

For mutable sync effects, use:

```text
record ID + generation
```

Scheduled execution does not require a template identity in the effect table.
The scheduler copies the scheduled input and `owned_by` into a fresh ordinary
effect record and generates a new UUIDv7. A repeated alarm is therefore a
repeated submission. If the provider operation must be idempotent, the handler
uses the effect/provider idempotency policy; the framework does not add a
cross-table template reference or compound occurrence index.

## Ordering limits

UUIDv7 embeds a millisecond timestamp. It is useful for broad temporal locality,
but it is not a total business ordering guarantee:

- many IDs can share the same millisecond;
- different machines can have clock skew;
- provider events can arrive out of order;
- queue delivery order is independent of record-ID order.

Use explicit `created_at`, `scheduled_for`, provider timestamps, and generation
values for business ordering.

## Compiler rules

The compiler should:

1. generate `id TYPE uuid DEFAULT rand::uuid::v7()` for every effect table;
2. reject an effect table with an incompatible custom ID type;
3. permit a documented opt-out only for a table that requires a complex/range
   ID and cannot use the standard effect runtime;
4. generate the sync create/re-select wrapper;
5. validate locators with SurrealDB's record types rather than string splitting
   alone;
6. extract the handler table with `record::tb(id)`/a strict runtime parser;
7. keep namespace and database in every queue/runtime locator;
8. never treat “new UUID” as a retry strategy.

## Upgrade and fallback policy

Run the architecture probe before a SurrealDB upgrade. If implicit generation
changes, the explicit `DEFAULT rand::uuid::v7()` remains the primary defense.

If a provider requires its own idempotency identifier, store that provider key
separately while retaining the UUIDv7 record ID. Scheduled jobs remain ordinary
effect records; no deterministic occurrence ID or template reference is part of
the global compiler contract.
