# ReBase

ReBase compiles SurrealDB authorization, validation, audit, reactive calculations, and table-keyed external effects. Clients use SurrealDB directly; the native Node HTTP runtime performs work requiring privileged provider access.

**Developer tools:** start with the [JavaScript workbench guide](./dev-tools/README.md).
The [developer-tools handoff](./designs/rebase-system/developer-experience-handoff.md)
records review evidence and execution instructions; the
[plan](./designs/rebase-system/developer-experience-plan.md) preserves the design
decisions. The separately redesigned frontend has its own
[documentation](./designs/frontend/README.md) and
[verification record](./designs/frontend/verification.md).

**Current development contract:** read the [tenant and tree redesign](./designs/rebase-system/tenant-tree-redesign.md),
[ordered-tree contract](./designs/rebase-system/ordered-tree-contract.md), and
[single-design runtime](./designs/rebase-system/single-design-runtime.md).
**Backend T0–T6 is ready for lead review (2026-10-05):** the
[execution handoff](./designs/rebase-system/tenant-tree-handoff.md) and
[verification evidence](./designs/rebase-system/evidence/2026-10-05-tenant-tree-verification.json)
record passing builds, full backend/accounting suites, positions and mocked refunds.
Use SurrealDB **3.3.0** as pinned by `.surreal-version`. One configured
namespace/database identifies a design; explicitly provisioned `rebase_tenant`
records isolate users and data inside it.

Tables define record types. Their records can participate in several independent
augmented ordered trees, with explicit roots, key types, slots, contributions
and validation. New roots use unique logical keys unless they declare duplicate
keys. Native table indexes remain available. This is an entity/component model
with materialized ordered indexes; it does not require an object framework.

The [core handoff](./designs/rebase-system/core-handoff.md) and
[accounting handoff](./designs/all-in-accounting/implementation-handoff.md)
track validation and domain boundaries. The [configuration reference](./designs/rebase-system/core-configuration.md)
owns process settings. Historical evidence remains tied to its original sources.
Frontend implementation is deferred: [the tenant migration](./designs/frontend/continuation-prompts.md)
must be completed before claiming MetaSol compatible with this backend.
Local checks use disposable databases and mock providers; production delivery
and representative capacity need their own evidence.

## Layout

```text
framework/                    Shared auth, access, and audit SurrealQL
dev-tools/compiler/           Schema analysis, generators, ordered AVL, build API and thin CLI
dev-tools/index.js            Public JavaScript development functions
dev-tools/workbench.js        Native Node REPL
gateway/                      Native Node runtime, named service adapters, and queue drivers
designs/<name>/schema.surql   Business and effect tables
designs/<name>/views.surql    Aggregate views
designs/<name>/data/          Development data JSON Schemas
designs/<name>/schemas/       Explicitly public JSON validation schemas
designs/<name>/table-handlers Table-keyed effect handlers
designs/all-in-one/          Composed calculation suite (core, accounts, CRM, HRM)
designs/rebase-system/        Cross-domain system blueprint and tree catalog
```

## Commands

```bash
npm run build
npm run build:all-in-one
npm run check
npm run check:all-in-one
npm run build:all-in-accounting
npm run check:all-in-accounting
npm run verify
npm run probe:temporal-tree
npm run probe:accounts
npm run probe:suite
npm run server
npm run workbench
npm run populate -- --tenant rebase_tenant:demo --table all --count 100
```

Node loads an optional environment profile before starting each tool. For example:

```bash
node --env-file=.env.local gateway/server.js
node --env-file=.env.cloud dev-tools/compiler/cli.js
node --env-file=.env.local dev-tools/populate.js --count 100
node --env-file=.env.local dev-tools/workbench.js
```

Each tool resolves its process environment once into a validated, immutable
configuration profile. The inherited process environment takes precedence over
values in a Node `--env-file` profile. Partial namespace/database or runtime
URL/secret pairs, malformed numbers and booleans, unsupported URLs, and invalid
queue settings fail at startup. Connection, listener, queue, and runtime event
settings cannot be overridden with command-line flags; select them in the
profile. A connected workbench serves the one design selected by that profile.
Provider API credentials remain typed fields in SurrealDB configuration records.

The compiler emits `build/<project>/schema.surql`, a private `runtime-contracts.json`, and validated `table-handlers/` modules. It does not emit tenant operation catalogs, generic job schemas, or compatibility artifacts.

Runtime event generation uses the same profile's default namespace/database and
runtime binding. Keep build and deploy on the same profile:

```bash
node --env-file=.env.cloud dev-tools/compiler/cli.js \
  --project designs/test \
  --check
```

## Database Security

Each business table receives table permissions plus set-based row authorization:

Ordinary record access requires the current actor's tenant, operation permission,
and ownership or declared reader relationship. Principals are `rebase_tenant`,
`rebase_user`, and `rebase_group`; users/groups require same-tenant parents.
The protected `rebase_access` relation stores their transitive closure.
`visibility` and descendant permission arrays are removed.

A record derives immutable `tenant` from `owned_by`. Its declared tree roots'
immediate owners contribute to a bounded private `readers_index`.
Explicit `@rebase-readers` references can add immediate owners for non-tree
relationships. Readers grant selection, not mutation, and do not recursively
copy other records' reader arrays. Native field permissions, reference guards
and transaction validation remain authoritative.

## Authentication

Email, phone and passkey identity records use `owned_by: rebase_user` and a
derived tenant. Email/phone addresses are normalized and unique within their
tenant. Password/code/OAuth/passkey signin selects a tenant explicitly.
Users must remain enabled and use a verified credential. Role changes and
revocation use live database state rather than token-cached permissions.

`POST /anonymous/authentication/challenges` accepts `{tenant, identifier}`
and an optional channel. It gives the same accepted response for missing or
disallowed identities, rate-limits requests, and queues encrypted delivery
using that tenant's explicit delivery policy. Callers cannot choose arbitrary
provider configurations or recipients. There is no public generic signup.

WebAuthn registration/authentication endpoints verify challenge, origin, RP ID,
user verification, signature, counters and replay through SimpleWebAuthn.
Set `REBASE_PASSKEY_RP_ID` and `REBASE_PASSKEY_ORIGINS` together to enable them.
An authenticated registration uses the current tenant session; authentication
returns a short-lived one-use exchange token for `account_passkey` signin.

OAuth is a stateless allowlisted verifier for an existing tenant email identity.
No provider is enabled by default. Its native signin variables are
`{tenant, provider, oauth_token}`. Provider credentials stay in protected database
rows; production challenge delivery requires a stable payload encryption key.

## Table Effects

An effect table declares its adapter on the table and its sync snapshot/output boundaries on fields:

```surql
DEFINE TABLE test_attachment SCHEMAFULL COMMENT '
  @rebase-effect sync
  @rebase-adapter createS3UploadGrant
  @rebase-adapter createS3AccessGrant
  @rebase-adapter deleteS3Object';
DEFINE FIELD file_name ON test_attachment TYPE string READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD access_url ON test_attachment TYPE option<string>
  PERMISSIONS FOR select WHERE true FOR create, update NONE
  COMMENT '@rebase-effect-output';
```

Its handler is keyed only by table name:

```js
module.exports = {
  table: "test_attachment",
  on: {
    async CREATE({ record, load, adapters, signal }) {
      const config = await load(record.storage_config);
      const grant = await adapters.createS3UploadGrant({
        accessKeyId: config.access_key_id,
        secretAccessKey: config.secret_access_key,
        endpoint: config.endpoint,
        region: config.region,
        objectKey: "...",
        contentType: record.media_type,
        contentLength: record.byte_length_limit,
        expiresIn: record.access_duration,
        signal,
      });
      return { outcome: "success", patch: { access_url: grant.uploadUrl } };
    },
  },
};
```

The test design provides the reference examples:

- `rebase_email_delivery_config`: configuration storage with a required API-key field hidden from normal reads.
- `send_brevo_email`: committed async record, one-shot execution time, BullMQ delivery, and retry reconciliation.
- `file_storage_config` plus `test_attachment`: a deterministic, typed file entity that issues S3-compatible upload/download grants and removes the object on deletion.
- `razorpay_config` plus `razorpay_order`: synchronous Razorpay Test Mode order creation with required database-owned credentials and a signed `order.paid` webhook that updates the same order row.

`npm run probe:runtime` verifies generated sync events and managed live task wakeups against a disposable SurrealDB, including duplicate claims, retry recovery, reconciliation, wake authentication, and webhooks.

The runtime uses one BullMQ queue for versioned operation hints. Tasks carry
`execute_at` and priority fields; delayed hints are admitted only within the
bounded horizon, and reconciliation republishes missing hints from SurrealDB.
The version-2 queue payload contains only a record-ID locator and private execution/revision
identity, while current due time and priority are loaded from the database.

There is no provider mode. `createAdapters()` statically composes the five named
functions available in this build, and runtime contracts inject only the
functions named by each table's repeatable `@rebase-adapter` markers. Missing
functions fail closed. Tests and embedding code can replace exact names through
`startServer({ adapters })` or `createAdapters({ overrides })`; arbitrary names
are rejected.

Tenant credentials are never read from environment variables. They are required,
typed fields on strict configuration rows and hidden from normal client reads.
`sendBrevoEmail` consumes `rebase_email_delivery_config.api_key` directly,
maps `file_storage_config.access_key_id`, `secret_access_key`, `endpoint`, and
`region` to the S3-compatible SDK. `REBASE_STORAGE_BUCKET` is one shared
profile value for the design; object keys include its context hash and a fresh
record identity, while native permissions enforce tenant access. `createRazorpayOrder` maps
`razorpay_config.key_id` and `key_secret` to the Razorpay Orders API. Razorpay
webhook secrets are loaded from the referenced configuration row after the
encrypted route capsule identifies and validates its tenant/configuration. Webhook adapters remain a separate
static map because raw-body signatures cannot be dispatched from request data.

## Development Tools

`npm run populate` generates sample records from `data/*.schema.json` using the compiled reference graph. Pass a normal JavaScript `transform` callback through the public API when a fixture needs edited values. `npm run workbench` starts Node's built-in JavaScript REPL; see the [developer tools guide](./dev-tools/README.md) for the public functions and direct SDK examples.
