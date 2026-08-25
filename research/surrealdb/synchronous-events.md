# Synchronous Event and Provisional Snapshot Findings

Status: measured compatibility reference

Tested: SurrealDB `3.2.0`, x86_64 Linux, isolated in-memory database.
Reproduction: `npm run probe:architecture`.

## Documented baseline

Ordinary `DEFINE EVENT` handlers execute in the triggering transaction, receive
`$before`, `$after`, `$value`, and `$event`, can fail the transaction, and run
internal queries without table/field permission checks. `ASYNC` events execute
after commit in another transaction. `http::*` encodes object bodies as JSON,
parses JSON responses, fails on non-2xx, and requires an allowed network target.

References:

- <https://surrealdb.com/docs/reference/query-language/statements/define/event>
- <https://surrealdb.com/docs/reference/query-language/functions/database-functions/http>
- <https://surrealdb.com/docs/reference/query-language/language-primitives/parameters#before-after>

## Provisional record visibility

For a create without an explicit ID, `$after.id` contains the generated record
ID. Inside the synchronous event, both of these see the provisional record:

```surql
record::exists($after.id)
(SELECT * FROM $after.id)[0]
```

An HTTP receiver using a separate root session queried the same ID before
returning and received no row. Thus this cannot work:

```text
event -> POST { namespace, database, id }
      -> runtime opens another DB session
      -> SELECT provisional id
```

The event must send the handler’s required provisional inputs in the HTTP body.
Use referenced IDs and bounded scalar/concurrency fields, not expanded secrets
or every `$after` field.

## Applying a response before commit

The event can parse a JSON response and apply an explicit patch to `$after.id`;
the nested update commits with the outer mutation:

```surql
LET $response = http::post($runtime_url, {
    namespace: session::ns(),
    database: session::db(),
    event: $event,
    record: {
        id: $after.id,
        generation: $after.generation,
        object: $after.object,
        expires_in: $after.expires_in
    }
}, $runtime_headers);

UPDATE $after.id SET
    issued_generation = $response.patch.issued_generation,
    expires_at = $response.patch.expires_at,
    access_url = $response.patch.access_url;
```

Copy through a generated allowlist. A blind `MERGE $response.patch` can overwrite
ownership, inputs, audit fields, or lifecycle state.

## Returned create image

`CREATE ... RETURN AFTER` returned the create statement’s own image and did not
include fields written by the nested event update. A later `SELECT` in the same
database request did include the committed patch:

```surql
LET $created = CREATE ONLY file_access_grant SET
    owned_by = $auth,
    object = $object,
    expires_in = $expires_in;
RETURN (SELECT * FROM $created.id)[0];
```

Generated synchronous create/refresh helpers capture SurrealDB's returned ID and
re-select. Applications must not assume plain `RETURN AFTER` contains the event
result.

## External effects are not rolled back

The probe completed an HTTP request and then threw from the event. The outer
record rolled back, but the HTTP receiver observed the request. No SurrealDB
transaction can make Brevo, Razorpay, S3, or another external API atomic.

Exact guarantee:

```text
fulfilled committed record
  => runtime returned success and database patch committed
```

Invalid guarantee:

```text
missing record
  => provider definitely did nothing
```

Timeout after provider acceptance, connection loss, runtime crash, and event
failure after HTTP success remain ambiguous. Prefer async for irreversible work,
use stable provider idempotency, reconcile provider state, and accept bounded
orphans only for short-lived/reversible objects.

## Failure behavior

A non-2xx runtime response makes `http::post()` fail and rolls back the outer
mutation. This is a useful final guard for a missing sync handler, but build-time
schema/handler validation remains the normal deployment protection.

## Mutable synchronous effects

Use generation fields when a client refreshes scope/expiry:

```text
requested_generation = 4
issued_generation = 3
```

The event sends the requested generation, the handler returns it, and the patch
applies only while it remains current. Provider idempotency uses
`record ID + generation`, preventing a stale result from overwriting a newer
request.

## Operational constraints

- restrict SurrealDB `--allow-net` to the runtime target;
- authenticate database-to-runtime calls independently of tenant auth;
- prefer private networking or workload identity/mTLS;
- bound request/response sizes and runtime timeout below database/client timeout;
- do not retry irreversible sync effects unless the provider reuses the same
  idempotency key;
- store operational evidence for ambiguous outcomes outside a claimed atomic
  success contract.

## Fallbacks

If an upgrade changes provisional behavior:

1. pin the last verified version and retain the architecture probe;
2. move the table to the async effect path;
3. create a committed request and let the client await/poll it;
4. issue the object through authenticated Hono using a database-minted bounded
   capability token.
