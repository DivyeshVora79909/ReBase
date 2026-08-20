# ReBase Blank-Sheet Edge Architecture Contract

Status: proposed canonical target for the redesign

This document is the orchestration target after the SurrealDB findings. It is
not a migration plan for the current `gateway/` implementation. The existing
capability, generic-job, outbox, and operation-catalog code may be deleted and
replaced.

## 1. The model is one pipeline with independent axes

“Sync”, “async”, “queue”, and “stateful response” are not four mutually
exclusive modes. They describe different properties:

| Property | Values | Meaning |
| --- | --- | --- |
| Completion coupling | inline / durable | Does the caller wait for the effect result, or receive a durable pending record? |
| Trigger | client write / schedule / provider callback / repair | What caused the effect record to be created or revisited? |
| External ownership | client / platform worker | Who communicates with the external provider? |
| Result shape | database result / external capability | Is the committed result data, or a bounded token/URL/grant that the client uses elsewhere? |

The implementation should not create a Cartesian-product mode registry. The
compiler derives one table adapter from the table declaration, and every caller
feeds the same stateless table handler.

## 2. Two table families

### Storage tables

Storage tables hold configuration, templates, credentials, metadata, schedules,
and ordinary business data. They have no provider side effect event.

Examples:

- `email_brevo_config`;
- `razorpay_config`;
- `invoice`;
- `send_brevo_email_template`;
- a schedule/template record.

### Effect tables

Effect tables represent one externally meaningful operation and its current
user-facing state. They are both the request record and the current effect
projection, but not a transport queue and not an immutable attempt log.

Examples:

- `send_brevo_email`;
- `razorpay_payment`;
- `file_access_grant`;
- `invoice_s3_attachment`;
- `scheduled_send_brevo_email` if the product needs a separate public shape.

An effect table declares:

```text
table name
process: sync | async
trigger: create | update | delete (one or more)
input fields and patch fields
reference fields and use policy
state machine
schedule support (optional)
```

The process and trigger metadata are compiler input. Runtime behavior is keyed
by the table name; the caller (direct event, queue worker, schedule wake, or
webhook) selects an adapter and invokes that same table handler.

## 3. Table-keyed handler map

The runtime keeps a small in-memory map whose key is the effect table name:

```text
handlers["send_brevo_email"]
handlers["razorpay_payment"]
handlers["file_access_grant"]
```

The compiler/dev tool may build this map from modules, generated metadata, or a
manual composition function. That choice is a development concern. The runtime
does not use namespace or database as behavior identity, and it does not create
different handler identities for sync, async, scheduled, or webhook callers.

Example:

```js
module.exports = {
  send_brevo_email: require("./send_brevo_email"),
  file_access_grant: require("./file_access_grant"),
};
```

`process` chooses the generated invocation adapter; it is not part of handler
lookup. A handler does not branch on who called it.

The compiler rejects:

- an effect table that declares a process but has no table-keyed handler;
- a handler map entry for an unknown table;
- duplicate table keys;
- a storage table accidentally assigned an effect handler;
- a missing handler module or invalid handler contract;
- a reference declaration whose table/type does not match the schema;
- a trigger that is incompatible with the declared state machine.

## 4. Common handler contract

```js
module.exports = {
  async execute({
    context,     // namespace, database, record ID, trigger
    record,      // provisional snapshot for sync; committed row for async
    load,        // generated declared-reference loader
    providers,
    signal,
  }) {
    // Transform validated database context into provider SDK input.
    // Return a bounded, generated-patch-compatible result.
    return {
      state: "succeeded",
      patch: {},
    };
  },
};
```

The handler may transform data for the provider SDK. The compiler can generate
reference aliases and a typed context helper, but it must not require that the
Surreal schema exactly resemble an SDK object.

Invariants:

- schema/RLS/field permissions validate the client mutation before dispatch;
- handlers do not trust arbitrary expanded objects supplied by clients;
- only declared references are loaded;
- secret fields are available only to privileged runtime code;
- returned patches are allowlisted and state-checked;
- provider idempotency keys are stable across duplicate delivery;
- terminal records are no-ops unless an explicit repair operation exists;
- retryable, terminal, and ambiguous provider outcomes are distinct.

## 5. Common effect record fields

The compiler generates only user-facing effect state, not SQS mechanics:

```text
id                    uuidv7 record ID
owned_by              record<user | groups>
effect_state          pending | processing | waiting | succeeded | failed |
                      cancelled | scheduled
created_at            datetime, immutable
updated_at            datetime
requested_generation  int, only for mutable sync effects
issued_generation     int, only for mutable sync effects
provider_reference    option<string>
provider_state        option<string>
result                option<object>, trimmed and field-permissioned
error_code            option<string>, non-secret
error_message         option<string>, redacted/non-sensitive
scheduled_for         option<datetime>
```

Do not put queue visibility timeout, lease owner, retry delay, SQS receipt
handles, or dead-letter state in tenant effect records. SQS and the platform
runtime own those concerns.

The exact state vocabulary is generated per effect table. A simple sync grant
may only need `pending | succeeded | failed`; a payment may need
`pending | processing | waiting | succeeded | failed | cancelled`.

## 6. Sync effects

Use a sync effect when the client needs a committed result in the same request
and the provider operation is bounded, reversible, read-like, or idempotent.

```text
client mutation
  -> Surreal schema/RLS/field validation
  -> synchronous event in the same transaction
  -> event posts a minimal provisional snapshot to Hono
  -> Hono dispatches handlers[table] and awaits the handler
  -> Hono returns an allowlisted patch
  -> event applies the patch
  -> transaction commits
  -> generated query re-selects the record
  -> client receives the committed result
```

Good fits:

- S3 presigned upload/download URL;
- short-lived provider access token;
- capability grant with an expiry;
- a provider quote or read;
- credential verification.

Do not use the sync path to pretend that an irreversible provider side effect is
transactional. If the provider accepts the call and SurrealDB later rolls back,
the provider call remains. Use provider idempotency or move the operation to the
async path.

### Generated sync query rule

The compiler must generate the explicit ID and re-select wrapper:

```surql
LET $id = type::record('file_access_grant', rand::uuid::v7());
CREATE ONLY $id SET
    owned_by = $auth,
    attachment = $attachment,
    requested_generation = 1,
    expires_in = $expires_in;
RETURN (SELECT * FROM $id)[0];
```

The plain `CREATE ... RETURN AFTER` response is not sufficient on the tested
SurrealDB version because it does not include the nested event patch.

### Mutable sync grants

When a client changes an expiry or scope:

1. increment `requested_generation`;
2. event sends that generation;
3. handler returns the same generation with a fresh grant;
4. event applies the patch only if the record still requests that generation;
5. older results become no-ops.

This makes a client-visible grant record safe to update without inventing a
second command table.

## 7. Async effects

Use async effects for slow, irreversible, webhook-driven, retry-heavy, or
provider-ambiguous work.

```text
client creates validated effect record
  -> outer transaction commits
  -> ASYNC SurrealDB notifier posts { namespace, database, id }
  -> Hono publishes that locator to SQS
  -> worker receives locator
  -> worker reloads the committed row and declared references
  -> handlers[table] executes the state-driven handler
  -> handler writes the current effect state/result
  -> provider webhook or reconciliation completes waiting work
```

The async event is a low-latency notifier, not the durable source of truth. If
the notifier or Hono is down, periodic reconciliation finds pending rows and
republishes locators.

The client sees the effect record immediately with `effect_state = pending` and
can subscribe, poll, or issue a normal read. It never needs to know SQS details.

The queue envelope is:

```json
{
  "namespace": "tenant_namespace",
  "database": "tenant_database",
  "id": "razorpay_payment:u'01a0...'"
}
```

The handler reloads all trusted state. It does not accept a queue payload as the
business object.

## 8. Reconciliation

Reconciliation is intentionally simple:

```text
for each compiled async effect table:
  retrieve pending/waiting/scheduled-due rows
  publish each direct locator
```

The compiler can emit one SurrealQL script containing all declared tables. Each
table should have an index on its pending/due fields. Direct record locators are
the important access path; the existence of many strongly typed effect tables
does not require a central table.

Do not ask SQS whether an exact locator is already queued. That is not a reliable
correctness query. Duplicate delivery and duplicate reconciliation are expected
and are handled by:

- terminal-state checks;
- stable UUIDv7 effect IDs;
- generation checks for mutable sync grants;
- provider idempotency keys;
- conditional state updates.

## 9. Webhooks

Webhooks are an external input adapter, not a new handler identity.

Required sequence:

1. read and preserve the raw request body;
2. verify the provider-specific HMAC/signature and timestamp/replay rules;
3. derive a provider event ID and dedupe key;
4. locate a local effect/config record through an indexed provider object ID or
   an opaque signed correlation token;
5. verify the provider account matches the referenced configuration;
6. apply an idempotent state patch;
7. return success only after the local update is durably accepted.

Never trust `namespace`, `database`, or a tenant record ID merely because it was
included in an unauthenticated provider payload. The user-facing record ID may
be embedded in a signed provider metadata field, but signature verification and
account matching come first.

For internal DB-to-Hono wake calls, use a separate deployment-managed secret or
mTLS, a timestamp/nonce replay window, exact-body signing, strict limits, and a
private network. Do not reuse a tenant bearer token.

## 10. Schedules

A schedule is ordinary async work with a time-based trigger. At the scheduled
time, the scheduler copies the input fields and `owned_by` into a fresh record
in the same effect table, clears schedule-only fields, marks the new record
`pending`, and generates a new UUIDv7. It stores no template reference unless a
product explicitly chooses to add one.

The new record follows the normal async event, queue, and handler path. Duplicate
alarms are ordinary duplicate submissions; provider idempotency or an
effect-specific policy decides whether they are harmless, rejected, or
intentionally repeated.

The admin server may use an in-memory alarm structure for a small deployment,
rebuilt from authoritative schedule records at startup. A managed external
scheduler may replace it later. It should wake the platform, not write directly
to tenant tables without an authenticated platform boundary.

The scheduled record's `owned_by` is copied into the new record, which is then
authorized and visible under the same tenant ownership rules.

## 11. References and hidden configuration

For ordinary client-usable references, generate:

```surql
DEFINE FIELD config ON send_brevo_email
    TYPE record<email_brevo_config>
    ASSERT record::exists($value);
```

This was visibility-aware in SurrealDB 3.2.0: existing unauthorized and missing
records were rejected. It is probe-gated because the exact permission behavior
is not clearly promised by the function reference.

Do not use field create permissions as required-reference validators. They can
silently omit fields or accept a physically existing hidden target.

Events bypass permissions. A generated event must not interpret its privileged
ability to read a hidden config as proof that the client may use it. For a
completely hidden configuration, use an explicit ownership/use assertion or a
visible alias/capability row.

Credential fields should be field-hidden in the tenant-facing schema. Encryption
at rest is a later deployment concern; authorization and non-leakage are the
core contract now.

## 12. Compiler responsibilities

The blank-sheet compiler should:

1. parse storage/effect process and trigger declarations;
2. verify every effect table and table-keyed handler contract;
3. generate UUIDv7 ID fields;
4. generate lifecycle/state fields and indexes;
5. generate client-visible ownership/RLS and field permissions;
6. generate reference `ASSERT` rules;
7. generate sync snapshot events and async locator events;
8. generate the sync create/re-select query helper;
9. generate the multi-table async reconciliation query;
10. emit/load the static table-keyed handler map;
11. copy handler modules and provider adapters to the build artifact;
12. run the architecture probes as an upgrade gate.

The compiler must not generate:

- a universal capability/operation catalog;
- one generic job table for every effect;
- queue lease/retry mechanics in tenant records;
- handler keys based on namespace/database;
- a separate handler per invocation source;
- a client-facing API that bypasses SurrealDB authorization for ordinary writes.

## 13. Runtime responsibilities

Hono/admin runtime owns:

- internal wake authentication;
- table-name registry lookup;
- privileged reference loading;
- provider SDK calls;
- SQS publish/consume;
- provider-specific webhook verification;
- retry/visibility/dead-letter transport through SQS;
- operational logs, metrics, and alerts;
- reconciliation scheduling.

SurrealDB owns:

- authentication and session issuance;
- table, row, and field authorization;
- schema validation and reference assertions;
- synchronous transaction boundary;
- async event enqueue trigger;
- current user-facing effect state;
- ownership of scheduled and ordinary effect records.

Providers own:

- external object state;
- provider idempotency behavior;
- provider webhooks and signatures;
- provider-side expiry/revocation where applicable.

## 14. Minimal implementation sequence

After the research gate, implement in this order:

1. replace the current operation/capability handler discovery with table-keyed
   handler validation;
2. add generated UUIDv7/lifecycle fields to one sample effect table;
3. generate and test a sync snapshot event plus re-select query;
4. generate and test one async locator event with the local memory queue;
5. add the SQS adapter using the same locator envelope;
6. add state-driven duplicate delivery and generation tests;
7. add provider HMAC webhook correlation;
8. add generated reconciliation across declared async tables;
9. add scheduled-copy behavior for ordinary effect records;
10. delete obsolete generic jobs, operation catalogs, and duplicated authorization
    paths once the replacement probes pass.

Each step keeps the handler contract identical. Only the adapters are added.
