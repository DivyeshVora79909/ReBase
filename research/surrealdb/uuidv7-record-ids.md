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

-- sync helper: stable ID enables re-select after event patch
LET $id = type::record('file_access_grant', rand::uuid::v7());
CREATE ONLY $id SET ...;
RETURN (SELECT * FROM $id)[0];

-- trusted runtime/scheduler
CREATE type::record($compiled_table, rand::uuid::v7()) CONTENT $content;
```

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

A scheduled occurrence is a fresh ordinary effect with a new UUIDv7. It does not
require a template reference or deterministic compound ID. Repeated alarms are
repeated submissions handled by the effect/provider idempotency policy.

## Ordering limits

UUIDv7 is not a total business order:

- many IDs share one millisecond;
- machines may have clock skew;
- queues and provider webhooks arrive out of order.

Use `created_at`, `scheduled_for`, provider timestamps, and generation/revision
fields for business ordering.

## ReBase compatibility rules

The compiler generates the explicit UUIDv7 `id` field for effect tables, rejects
incompatible custom key types unless explicitly opted out, validates locators as
record values, extracts the handler table with a strict parser, retains
namespace/database in infrastructure envelopes, and never treats a new UUID as
a retry strategy.

Run the architecture probe before SurrealDB upgrades. The explicit default is
the primary fallback if implicit typed-ID generation changes.
