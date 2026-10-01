# ReBase

ReBase compiles SurrealDB authorization, validation, audit, reactive calculations, and table-keyed external effects. Clients use SurrealDB directly; the native Node HTTP runtime performs work requiring privileged provider access.

**Current work and evidence:** see the [core handoff](./designs/rebase-system/core-handoff.md)
for K1–K5 implementation and restart requirements, the [core audit](./designs/rebase-system/core-audit.md)
and [lead recheck](./designs/rebase-system/evidence/2026-09-29-lead-checkpoint-audit.json)
for dated checks and fingerprints, and the [accounting handoff](./designs/all-in-accounting/implementation-handoff.md)
for domain status and open H4b5c policy/H8 cost measurement. [Configuration](./designs/rebase-system/core-configuration.md)
is the settings reference. CRM/HRM remain future scope.

[`research/rebase/architecture.md`](./research/rebase/architecture.md) defines
the current runtime contract. [`research/README.md`](./research/README.md)
indexes project decisions separately from measured SurrealDB behavior.
The [temporal calculation contract](./research/rebase/temporal-trees.md) describes
the implemented v2 system: business records participate directly in augmented
AVL trees; shared functions maintain ordered aggregates and field-sensitive
dependencies. Roots and nodes now require explicit `datetime`/`int` key types
and finite owner targets. The [compiled stage fixture](./dev-tools/temporal-tree/typed-fixture.surql)
verifies one record's independent time and integer orderings.
The [all-in-one profile](./designs/all-in-one/README.md) composes
currency accounts, assets and claims, stock/service capacity, invoices, derived
transactions, CRM case histories, and HRM allowances using this core.
The proposed [ReBase system blueprint](./designs/rebase-system/README.md) treats
those domains as separate calculation modules over shared identities. Its
[reviewed redesign plan](./designs/rebase-system/plan.md) covers general ordered
trees, compiler passes, field-level audit, direct-parent readers, native Node
operations, typed provider credentials, and one-shot task recovery. Fresh
foundation and runtime checks support the recorded core gates, including
credential ownership and final integration. Production migration, live
providers, and representative load remain open in the handoff.
[Verification](./designs/rebase-system/verification.md) separates implemented
checks from pending work.
The proposed [all-in-accounting suite](./designs/all-in-accounting/README.md)
documents the accounting module's blueprint and implementation plan for typed
movements, claims, temporal resource limits, and manufacturing compositions.

## Layout

```text
framework/                    Shared auth, access, and audit SurrealQL
src/                          Schema analysis, generators, shared ordered AVL
dev-tools/compiler/           Stateless compiler stages and CLI
gateway/                      Native Node runtime, named service adapters, and queue drivers
designs/<name>/schema.surql   Business and effect tables
designs/<name>/views.surql    Aggregate views
designs/<name>/data/          Development data JSON Schemas
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
npm run verify
npm run probe:temporal-tree
npm run probe:accounts
npm run probe:suite
npm run server
npm run workbench
npm run populate -- --table all --count 100
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
profile. The workbench can switch only among contexts listed by that profile.
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

```surql
FOR select WHERE '<table>_select' IN $auth.permissions
  AND (!!visibility
    OR readers_index CONTAINSANY $auth.z_access_index
    OR <string>owned_by IN $auth.z_access_index)
```

The framework principals are `rebase_user` and `rebase_group`. Reader access is
computed from explicitly marked direct reference fields; ancestors and tree
membership do not grant access. `readers_index` is private. Create and update
require the matching table permission and an allowed resulting owner. Delete
requires self ownership or domination. Direct parent groups can receive
delegation, but parent membership alone cannot reclaim a delegated record.

Strict schema fields, assertions, references, field permissions, and record visibility remain in SurrealDB. The runtime receives either a compiler-selected provisional snapshot or a committed record locator; it is not another client authorization layer.

## Authentication

Authentication is separate from authorization and from the optional password
credential. A principal can have typed identity rows across
`authentication_email` and `authentication_phone`; authentication does not add
a separate identity-presence or count guard. An identity is usable for signin
only after it has been verified by a short-lived, single-use
`authentication_challenge`. Address changes invalidate that identity and all
outstanding challenges through a database revision fence; they do not alter the
authorization graph. Passwords may be absent until the recipient completes a
delivered challenge; OAuth is the other supported password-independent path.

`account_password` accepts a normalized email, phone number, or username and a
password, but requires a currently verified identity. `account_code` consumes a
six-digit challenge atomically, verifies its identity, and may keep, set, or
clear the password. There is no `SIGNUP` flow; administrators create
principals and delivery identities, while the recipient proves possession
through the challenge flow.

`POST /anonymous/authentication/challenges` accepts a namespace, database, and
email, phone, or username identifier. It always returns the same `202` response
for present, missing, and disallowed identities, applies per-address and
context/identifier rate limits, and queues delivery through the fixed
`rebase_authentication_delivery_policy:default` row. Email and SMS credentials
and sender values live in private typed database configuration rows; callers
cannot select a provider or configuration. Challenge hashing and delivery-task
creation commit atomically. The task stores an encrypted message payload, while
the challenge hash remains private to SurrealDB. Production requires a stable
`REBASE_AUTHENTICATION_PAYLOAD_SECRET` of at least 32 bytes, separate from the
runtime event-authentication secret.

When a runtime URL and runtime secret are supplied at compilation, the compiler
also emits the `oauth` record access method. It calls the authenticated,
stateless `/internal/oauth` verifier and selects an existing principal by the
returned verified email. OAuth has `SIGNIN` only: it never creates a user,
provisions a namespace/database, or stores provider identity.
OAuth verifier functions are explicitly allowlisted and injected into the server;
no OAuth provider is enabled by default. OAuth is signin-only and stateless: a
provider token is verified at request time, its email is matched to an existing
local email identity (the provider proof supplies verification), and no provider
subject or OAuth row is stored.
SurrealDB reserves `$token`, so the SDK signin boundary uses
`variables: { provider, oauth_token }`; the internal HTTP verifier receives the
normalized `{ provider, token }` body.

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

- `email_brevo_config`: configuration storage with a required API-key field hidden from normal reads.
- `send_brevo_email`: committed async record, one-shot execution time, BullMQ delivery, and retry reconciliation.
- `file_storage_config` plus `test_attachment`: a deterministic, typed file entity that issues S3-compatible upload/download grants and removes the object on deletion.
- `razorpay_config` plus `razorpay_order`: synchronous Razorpay Test Mode order creation with required database-owned credentials and a signed `order.paid` webhook that updates the same order row.

`npm run probe:runtime` verifies generated sync and async events against a disposable SurrealDB, including duplicate claims, retry recovery, reconciliation, wake authentication, and webhooks.

The runtime uses one BullMQ queue for versioned operation hints. Tasks carry
`execute_at` and priority fields; delayed hints are admitted only within the
bounded horizon, and reconciliation republishes missing hints from SurrealDB.
The queue payload contains the context locator and private execution/revision
identity, while current due time and priority are loaded from the database.

There is no provider mode. `createAdapters()` statically composes the five named
functions available in this build, and runtime contracts inject only the
functions named by each table's repeatable `@rebase-adapter` markers. Missing
functions fail closed. Tests and embedding code can replace exact names through
`startServer({ adapters })` or `createAdapters({ overrides })`; arbitrary names
are rejected.

Tenant credentials are never read from environment variables. They are required,
typed fields on strict configuration rows and hidden from normal client reads.
`sendBrevoEmail` consumes `email_brevo_config.api_key` directly,
maps `file_storage_config.access_key_id`, `secret_access_key`, `endpoint`, and
`region` to the S3-compatible SDK. `REBASE_STORAGE_BUCKET` is one shared
profile value for every namespace/database; the object key contains a
namespace/database hash so records remain isolated. `createRazorpayOrder` maps
`razorpay_config.key_id` and `key_secret` to the Razorpay Orders API. Razorpay
webhook secrets are loaded from the referenced configuration row after the
signed route capsule resolves its context. Webhook adapters remain a separate
static map because raw-body signatures cannot be dispatched from request data.

## Development Tools

`npm run populate` derives topology from the compiled schema and scalar generation rules from `data/*.schema.json`. `npm run workbench` provides build, deploy, populate, authentication, query, sample, and probe commands without a fixed namespace/database.
