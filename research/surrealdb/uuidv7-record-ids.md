# UUIDv7 Record ID Findings

Status: measured compatibility reference

Tested: SurrealDB `3.2.0`, x86_64 Linux, isolated in-memory database.
Reproduction: `npm run probe:architecture`.

## Documented behavior

SurrealDB supports UUIDv7 record IDs; `CREATE table:uuid()`, `rand::uuid()`, and
`rand::uuid::v7()` generate UUIDv7. UUIDv7 has millisecond timestamp precision.
`DEFINE FIELD id ON table TYPE uuid` constrains the key type; since 3.2, `DEFAULT`
and `ASSERT` are supported on `id`, while `VALUE`, `REFERENCE`, `COMPUTED`,
`READONLY`, `FLEXIBLE`, and ordinary non-key field clauses are forbidden.

References:

- <https://surrealdb.com/docs/reference/query-language/language-primitives/data-types/record-ids>
- <https://surrealdb.com/docs/reference/query-language/language-primitives/data-types/uuids>
- <https://surrealdb.com/docs/reference/query-language/functions/database-functions/rand#randuuid>
- <https://surrealdb.com/docs/reference/query-language/statements/define/field#defining-a-type-for-the-id-field>

## Measured type/default behavior

With:

```surql
DEFINE TABLE typed_id SCHEMAFULL;
DEFINE FIELD id ON typed_id TYPE uuid;
DEFINE FIELD value ON typed_id TYPE int;
```

all succeeded:

```surql
CREATE typed_id SET value = 1;
CREATE typed_id:u'0198c6c4-bd70-7d6d-8a7a-87bb773590db' SET value = 2;
CREATE type::record('typed_id', rand::uuid::v7()) SET value = 3;
```

The unspecified ID was generated as UUIDv7; `record::id(id)` was a UUID and
`type::is_uuid(...)` was true. `CREATE typed_id:bad` failed. A table without the
typed `id` field received SurrealDB’s ordinary random text ID.

Use an explicit default even though implicit type-directed generation worked:

```surql
DEFINE FIELD id ON effect TYPE uuid DEFAULT rand::uuid::v7();
```

This is clearer and less dependent on implicit behavior.

## Creation forms

```surql
-- ordinary create: schema default supplies UUIDv7
CREATE send_brevo_email SET ...;

-- sync helper: use the ID returned by SurrealDB to re-select the event patch
LET $created = CREATE ONLY test_attachment SET ...;
RETURN (SELECT * FROM $created.id)[0];

-- trusted scheduler: use the created record returned by SurrealDB
LET $occurrence = CREATE ONLY send_brevo_email CONTENT $content;
```

When a UUID-typed record ID is printed, SurrealDB includes the UUID type tag:
`table:u'01...'` (JSON serializers may display the quote as `u"01..."`).
This is canonical formatting, not an extra character in the UUID and not a
duplicate conversion. Casting the UUID to `<string>` or concatenating it first
changes the key to a string record ID (`table:\`01...\``); do not do that for
typed UUID tables. `type::record(table, rand::uuid::v7())` is the correct
dynamic-table construction.

Never accept a free-form external table string; select the table from the
compiled registry.

## Scope, uniqueness, and idempotency

UUIDv7 has ample practical entropy for distributed billions/trillions of IDs and
provides broad temporal locality. It is not a globally scoped locator:

```text
table:id is unique inside one database
namespace + database + table:id identifies the data location
```

It is also not logical idempotency. Retrying a submission with a new UUID creates
a new effect. Reuse the effect ID for the same immutable async submission; use
`effect ID + generation` for mutable sync effects. Store a separate provider
key if the provider has its own idempotency namespace.

A scheduled occurrence is a fresh ordinary effect with a SurrealDB-generated
record ID. It does not require a template reference or deterministic compound
ID. Repeated alarms are repeated submissions handled by the effect/provider
idempotency policy.

## Ordering limits

UUIDv7 is not a total business order:

- many IDs share one millisecond;
- machines may have clock skew;
- queues and provider webhooks arrive out of order.

Use `created_at`, `scheduled_for`, provider timestamps, and generation/revision
fields for business ordering.

## ReBase compatibility rules

The compiler does not add an application-managed `id` field to effect tables.
SurrealDB generates ordinary record keys, and the returned key is carried as the
locator. UUIDv7 remains a supported SurrealDB capability for schemas that
explicitly choose it, but it is not a ReBase requirement or retry strategy.

Run the architecture probe before SurrealDB upgrades. The probe documents typed
UUID behavior independently of the project's ordinary-key default.
