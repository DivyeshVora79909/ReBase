# SurrealDB Synchronous Event Snapshot Findings

Status: measured architecture input

Tested version: SurrealDB `3.2.0` on x86_64 Linux with the in-memory datastore

Reproduction: `npm run probe:architecture`

## Decision

Synchronous effect tables are viable when the SurrealDB event sends a bounded
provisional snapshot to the runtime. Sending only `{ namespace, database, id }`
is not sufficient because another database session cannot read the uncommitted
record.

The supported flow is:

```text
client query
  -> create/update provisional effect record
  -> synchronous SurrealDB event
  -> HTTP POST of a minimal $after snapshot
  -> table handler returns a bounded patch
  -> event applies the patch
  -> transaction commits
  -> client query re-selects the record
  -> client receives the event-populated result
```

Use this for bounded, reversible, read-like, or provider-idempotent operations:

- presigned upload or download URLs;
- temporary access grants;
- short-lived provider tokens;
- quotes, previews, and provider reads;
- credential verification;
- other operations where the useful contract is “a fulfilled committed record
  contains a valid result”.

Prefer the asynchronous effect path for irreversible or ambiguity-sensitive
operations such as sending email, capturing a payment, or starting a slow
provider workflow.

## Officially documented behavior

The SurrealDB `DEFINE EVENT` documentation states that ordinary events:

- execute inside the transaction that triggered them;
- receive `$before`, `$after`, `$value`, and `$event`;
- can throw and therefore fail the triggering transaction;
- run their internal queries without table or field permission checks.

The same documentation states that `ASYNC` events run in a separate transaction
after the original mutation is committed.

The HTTP function documentation states that:

- an object body is JSON encoded;
- a JSON response is parsed into a SurrealQL value;
- a non-2xx HTTP response fails the function;
- network access is denied unless SurrealDB is started with an appropriate
  `--allow-net` capability.

References:

- <https://surrealdb.com/docs/reference/query-language/statements/define/event>
- <https://surrealdb.com/docs/reference/query-language/functions/database-functions/http>
- <https://surrealdb.com/docs/reference/query-language/language-primitives/parameters#before-after>

## Measured behavior

### The generated ID is available inside the event

For a record created without an explicit ID, `$after.id` contains the generated
record ID. The event can use that ID in local queries and can transmit it to an
HTTP endpoint.

Inside the synchronous event, both of these see the provisional record:

```surql
record::exists($after.id)
(SELECT * FROM $after.id)[0]
```

This is a transaction-local view. It does not imply visibility from another
connection.

### A separate session cannot load the provisional record

The probe sends the generated ID to an HTTP receiver. The receiver queries the
same database through a separate root session before returning its response.
The query returns zero records.

Therefore this is invalid for a synchronous event:

```text
event -> POST { ns, db, id } -> Hono opens another DB session -> SELECT id
```

The runtime must receive the handler input in the event request itself.

### The event can apply the HTTP response before commit

The event can parse a JSON response and update `$after.id`. The update is
committed with the outer mutation.

Conceptual event:

```surql
DEFINE EVENT issue_grant ON file_access_grant
WHEN $event IN ['CREATE', 'UPDATE']
THEN {
    LET $patch = http::post(
        $runtime_url,
        {
            event: $event,
            record: {
                id: $after.id,
                generation: $after.generation,
                object: $after.object,
                expires_in: $after.expires_in
            }
        },
        $runtime_headers
    );

    UPDATE $after.id SET
        issued_generation = $patch.issued_generation,
        expires_at = $patch.expires_at,
        access_url = $patch.access_url;
};
```

The response must be copied through an explicit generated allowlist. Avoid a
blind `MERGE $patch` in production because a handler bug could overwrite input,
ownership, audit, or lifecycle fields.

### `CREATE RETURN AFTER` does not include the nested event patch

SurrealDB `3.2.0` commits the event update, but the immediate image returned by
the triggering `CREATE ... RETURN AFTER` is the create statement's own image.
It did not contain fields written by the nested event update.

This is insufficient for a sync API:

```surql
CREATE file_access_grant SET ... RETURN AFTER;
```

The client query must re-select the record after the create statement:

```surql
LET $id = type::record('file_access_grant', rand::uuid::v7());
CREATE ONLY $id SET
    owned_by = $auth,
    object = $object,
    expires_in = $expires_in;
RETURN (SELECT * FROM $id)[0];
```

The probe observes:

- the `CREATE ONLY` result does not contain the event-populated patch;
- the subsequent `SELECT` in the same database request does contain it.

The compiler/client SDK must generate this wrapper for synchronous effect
creation and refresh. Applications must not hand-roll a plain create and assume
that `RETURN AFTER` contains the handler result.

### An external effect is not rolled back

The probe performs a successful HTTP request and then throws from the event.
The outer record is absent, but the HTTP receiver observed the request.

No SurrealDB transaction can make a Brevo, Razorpay, S3, or another external API
transactional. The exact sync guarantee is:

```text
fulfilled committed record
  => the runtime returned success and the database patch committed
```

It is not:

```text
missing record
  => the provider definitely did nothing
```

Timeouts, connection loss after provider acceptance, runtime crashes, and an
event failure after HTTP success remain ambiguous.

Mitigations, in descending order of usefulness:

1. use the async path for irreversible effects;
2. pass a stable provider idempotency key;
3. make the handler a state reconciler that can query the provider;
4. accept bounded orphaned objects for short-lived URLs or grants;
5. use provider webhooks/reconciliation to recover evidence where supported.

### Missing sync handlers fail safely

When the event calls a route that returns non-2xx, `http::post()` fails and the
outer mutation rolls back. This is useful runtime protection for a deployment
whose database schema and handler registry are inconsistent.

Build-time validation is still required; runtime rollback is the final guard,
not the primary deployment check.

## Snapshot contract

The event request should contain only the values needed by the table handler:

```js
{
  namespace: "tenant_namespace",
  database: "tenant_database",
  event: "CREATE",
  record: {
    id: "file_access_grant:u'...'",
    owned_by: "user:alice",
    generation: 1,
    object: "invoice_attachment:...",
    expires_in: "15m"
  }
}
```

Rules:

- `record.id` is mandatory and already includes the table name;
- namespace and database identify data context, not handler behavior;
- the table name extracted from `record.id` selects the handler;
- include referenced IDs, not expanded secret records;
- include client-visible inputs and concurrency values only;
- never serialize every `$after` field by default;
- never send credential fields merely because event queries can read them;
- the handler may use a privileged session to load committed-independent config
  records, but it cannot reload the provisional effect record itself;
- the returned patch must include the input generation and be applied only when
  it still matches.

## Mutable synchronous records

Mutable token/grant records need generation semantics to prevent stale results
from overwriting a newer client request:

```text
requested_generation = 4
issued_generation = 3
```

On an allowed refresh mutation:

1. SurrealDB increments `requested_generation`;
2. the event sends that generation in the snapshot;
3. the handler returns the same generation with the new grant;
4. the event applies the patch only when the current requested generation still
   equals the response generation.

The stable provider idempotency identity is:

```text
record ID + requested generation
```

The mutable business inputs and output fields should use strict field
permissions. Updating a generic `updated_at` field is not the framework API;
updating an explicit requested expiry, scope, or generation is.

## Operational constraints

- SurrealDB must have `--allow-net` restricted to the runtime target.
- Keep the DB-to-runtime endpoint on a private network when possible.
- Authenticate the wake endpoint independently of tenant authentication. The
  architecture probe verifies a bearer header sent through `http::post`; a
  production deployment can load that credential from a framework-owned record
  with client permissions disabled, or terminate stronger workload identity at
  a private proxy.
- Do not bake a long-lived public webhook secret into generated application
  schema. Prefer network-level identity/mTLS or a deployment-managed credential
  boundary.
- Bound the runtime timeout below the database/client timeout.
- Bound request and response sizes.
- Do not retry an irreversible sync call automatically unless the provider uses
  the same idempotency key.
- Record ambiguous provider outcomes outside the tenant-facing success record if
  operational investigation is required.

## Fallbacks

If a future SurrealDB version changes provisional event behavior:

1. pin the last verified version and keep `npm run probe:architecture` in the
   upgrade gate;
2. replace the table with an async effect;
3. create a committed request record and let the client await/poll it;
4. issue the short-lived object through an authenticated Hono endpoint using a
   database-minted capability token.

The first default remains the native synchronous snapshot flow while its probe
passes.
