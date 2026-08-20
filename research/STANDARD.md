# ReBase Architecture Standard

Status: Authorization/graph reference; runtime sections are historical

Audience: maintainers, contributors, and coding agents

The current implementation contract is [../ARCHITECTURE.md](../ARCHITECTURE.md).
This document remains the detailed reference for authorization, graph, audit,
and compiler decisions. Its capability, generic-job, and outbox sections are
preserved as rejected/historical alternatives.

## Blank-Sheet Redesign Addendum

The edge-function and durable-job sections below describe the pre-redesign
capability runtime. For the unreleased blank-sheet architecture, the following
research documents are the current decision record and supersede those sections
where they conflict:

- [BLANK-SHEET-ARCHITECTURE-CONTRACT.md](./BLANK-SHEET-ARCHITECTURE-CONTRACT.md)
- [HANDLER-REGISTRY-DISPATCH-FINDINGS.md](./HANDLER-REGISTRY-DISPATCH-FINDINGS.md)
- [SYNC-EVENT-SNAPSHOT-FINDINGS.md](./SYNC-EVENT-SNAPSHOT-FINDINGS.md)
- [REFERENCE-AUTHORIZATION-FINDINGS.md](./REFERENCE-AUTHORIZATION-FINDINGS.md)
- [UUIDV7-RECORD-ID-FINDINGS.md](./UUIDV7-RECORD-ID-FINDINGS.md)

The blank-sheet runtime redesign is now implemented. The addendum keeps this
file useful for the existing authorization and graph invariants.

The goal is a small, algorithmic system that a solo developer can understand and
maintain. ReBase uses SurrealDB as the source of truth for data shape, graph
relationships, ownership, authorization, and dynamic external-service context.
JavaScript should orchestrate these primitives rather than duplicate them in
parallel catalogs, schemas, and compatibility layers.

## Decision Method

Design suggestions, comments, and existing code are hypotheses until verified.
When behavior depends on SurrealDB semantics, test it against a disposable
SurrealDB instance before changing the architecture. Do not accept or reject a
design merely because it sounds conventional.

Breaking changes are acceptable during the current development phase. Security
regressions, unexplained behavior, unnecessary architecture modes, and hidden
maintenance systems are not acceptable.

Prefer:

- one fixed security model;
- set operations over procedural permission trees;
- schema-derived behavior over duplicated declarations;
- explicit bounded exceptions over global feature switches;
- native SurrealDB behavior over custom reimplementations;
- small self-describing edge handlers over operation catalogs;
- live disposable probes over large static test fixtures;
- correctness and understandable performance over speculative abstraction.

"No if/else" is not a literal coding rule. It means there must not be several
fragile architectural modes whose combinations are difficult to reason about.
Branches that follow directly from schema types or execution modes are normal.

## Core Vocabulary

### Principal

A principal is a `user` or `groups` record.

### Business record

A business record is any application record outside framework-owned tables such
as `user`, `groups`, audit tables, edge job tables, outbox tables, webhook
receipts, and logs.

### Ownership

Every business record has one `owned_by` value of type:

```surql
record<user | groups>
```

Ownership is the anchor for create, update, select, delete, reader inheritance,
and graph delegation.

### Table permission

Table permissions are strings such as:

```text
invoice_select
invoice_create
invoice_update
invoice_delete
```

They authorize database operations on a table. They do not by themselves grant
access to every row.

### Edge capability

An edge capability is the exact name of an externally callable edge function,
for example:

```text
campaignMail
campaignMailV2
```

Capabilities authorize external orchestration. They are separate from table
permissions.

### Access indexes

`z_access_index` is a materialized array of principal IDs represented as strings.
For a user it contains:

- the user's own ID;
- the user's direct parent groups;
- principals dominated by the user.

The index exists so row authorization is a bounded membership check rather than
a graph traversal on every query.

`readers_index` is a materialized array of principal IDs represented as strings.
It contains principals inherited through referenced business resources. It does
not contain business resource IDs.

## User And Group DAG

Users and groups form a directed acyclic graph through their `parents` fields.
The graph is not a tree. A node may have multiple parents.

The graph provides:

- direct parent-group membership;
- downward domination;
- inherited table permissions;
- inherited edge capabilities;
- ownership delegation boundaries.

The framework must preserve these invariants:

1. Assigned parent records must exist.
2. A node cannot parent itself.
3. A node cannot be assigned below one of its descendants.
4. `dominates` must update when graph edges change.
5. User permissions and capabilities must update when parent-group roles or
   capabilities change.
6. A user cannot edit their own `parents` field.
7. Role and capability updates cannot grant values the authenticated actor does
   not already possess.

`parent_groups` means direct parent groups, not every ancestor group.

`dominates` means descendants reachable below the principal.

The root group is the bootstrap owner of all generated table permissions and all
discovered edge capabilities.

## Uniform Business-Table Permissions

Every business table uses one permission model. There is no owner-only mode,
reader mode, visibility mode, or per-project authorization mode.

### Select

A row can be selected only when the actor has the table's select permission and
at least one row-access condition is true:

```surql
'<table>_select' IN $auth.permissions
AND (
    !!visibility
    OR readers_index CONTAINS <string>$auth.id
    OR <string>owned_by IN $auth.z_access_index
)
```

This means a user can select a row when:

- its `visibility` value is truthy;
- the user's own principal ID is in `readers_index`;
- its owner is the user, one of the user's direct parent groups, or a principal
  dominated by the user.

The condition uses set membership. It must not be replaced with broad
`CONTAINSANY` comparisons between unrelated access sets.

### Visibility

`visibility` is a boolean business value. The select predicate checks
`!!visibility` on every business table.

- If the table defines the field and the value is true, the row is visible to
  actors with the table's select permission.
- If the field is false, `NONE`, or absent, visibility grants nothing.
- The compiler does not need a visibility marker or a special table mode.
- Visibility is an ordinary mutable field unless the business schema gives it
  stricter field permissions.

Context tables used by external services commonly define visibility. Ordinary
tables may omit it.

### Create

Create requires the table's create permission and an accessible resulting owner:

```surql
'<table>_create' IN $auth.permissions
AND (
    owned_by = $auth
    OR owned_by IN $auth.parent_groups
    OR owned_by IN $auth.dominates
)
```

### Update

Update uses the same owner-access boundary as create:

```surql
'<table>_update' IN $auth.permissions
AND (
    owned_by = $auth
    OR owned_by IN $auth.parent_groups
    OR owned_by IN $auth.dominates
)
```

SurrealDB 3.2 applies the ordinary table update permission to both the existing
row and the resulting row. This is a required part of the model. Do not replace
it with speculative `$before` or `$after` table predicates.

### Delete

Delete requires total domination. Direct parent-group access is intentionally
excluded:

```surql
'<table>_delete' IN $auth.permissions
AND (
    owned_by = $auth
    OR owned_by IN $auth.dominates
)
```

### Ownership-field update

The `owned_by` field uses this exact update rule:

```surql
$value = $before
OR $before = $auth
OR $before IN $auth.dominates
```

Combined with the table update predicate, this creates deliberate one-way
delegation:

- an owner can delegate a self-owned resource to an accessible parent group;
- a parent-group member can edit ordinary fields but cannot take ownership;
- the original owner cannot reclaim the resource after group delegation;
- a dominator can redirect or reclaim a dominated resource;
- an owner or dominator cannot transfer a resource to an unrelated principal,
  because the resulting row fails the table update permission.

SurrealDB field permissions are filters. A denied `owned_by` write can leave
`owned_by` unchanged while other fields in the same update succeed. Callers that
must confirm an ownership change need to inspect the returned row.

Do not replace this table-plus-field rule pair with mutation events or a custom
ownership service.

## Reader Derivation

Reader inheritance exists so the owners and inherited readers of a referenced
business resource can read records derived from that resource.

Example:

```text
campaign profile -> email configuration
```

The configuration's owner can read the profile because the profile derives part
of its context from that configuration.

### Canonical representation

Only `readers_index` is materialized. The separate `readers` record array is not
part of the target architecture. The compiler may emit
`rebase_reader_sources` as a non-materialized computed dependency field solely
for cycle detection; it is not an access list and is not selected by record
sessions.

For a referenced business record, reader contribution is conceptually:

```surql
[
    <string>$reference.owned_by,
    $reference.readers_index
]
```

The final value is recursively flattened, deduplicated, stripped of `NONE`, and
indexed.

### References that never contribute

A reference field contributes nothing when:

- the value is `NONE`;
- its declared record target is empty or cannot be resolved;
- any of its declared record targets is `user`;
- any of its declared record targets is `groups`.

This is a field-level rule and applies to scalar and array references. If a
polymorphic declaration contains both a business table and `user` or `groups`,
drop the entire field from reader derivation. Do not inspect each runtime value
and keep only the business-record values. User and group records do not have
`owned_by`, and mixed principal/business fields are not an implicit sharing
contract.

Fields such as these do not grant read access:

```surql
reviewer: user:alice
technical_owner: user:bob
owning_group: groups:finance
```

Ownership and group membership already provide the principal-sharing mechanism.

### Scalar record fields

A scalar reference to a business table participates automatically. No marker is
required because its fanout is bounded to one value per field. It must declare
native `REFERENCE`; this is the strict referential-integrity and reverse-link
contract used by propagation.

For polymorphic scalar references containing only business tables, evaluate the
runtime record normally and inherit from that business record. If the declaration
also accepts `user` or `groups`, exclude the entire field as described above.

### Array record fields

Arrays are excluded by default because their fanout may be large and reader
recomputation can propagate through reverse references.

An array participates only when its field comment contains:

```text
@rebase-readers
```

For a marked array:

- skip `NONE` values;
- require native `REFERENCE`;
- require every declared target to be a business table;
- exclude the entire field if its declaration accepts `user` or `groups`;
- inherit ownership and `readers_index` from its business-record values;
- flatten and deduplicate the result.

The marker is an explicit acceptance of the field's recomputation cost. There is
no global `inheritArrayReaders` switch.

### No `shared_with`

There is no generic `shared_with` principal array. It duplicates group-based
sharing and creates a second access model.

To share a resource:

- assign it to an appropriate group; or
- reference a business resource whose ownership/readers should flow into the
  derived record.

Do not reintroduce direct user/group reader lists under another name.

### Propagation and revocation

When a referenced record's owner or readers change, dependent records must
recompute their `readers_index`. Revocation correctness is more important than
making writes appear cheap.

The current cascade mechanism and `system_ping` field are implementation details
verified by disposable probes. Native reverse references identify dependent
records and `system_ping` forces stored value-field recomputation. Do not remove
them based solely on code appearance.

### Reader graph cycles

Reader inheritance is a directed authorization graph and must be acyclic. A
cycle can preserve a removed principal in a materialized readers set, which is a
security defect. For every table with contributing fields, the compiler emits a
computed `rebase_reader_sources` dependency projection and an event that rejects
a write that would close a cycle with `REBASE_READER_CYCLE`. The projection is
not a second reader index and does not create a sharing mechanism.

## Views

Generated views are intentionally capability-scoped company context, not
row-scoped projections.

A view over a source table uses the source table's select capability:

```surql
'<source_table>_select' IN $auth.permissions
```

The compiler must not inject source-row `owned_by`, `readers_index`, or
`visibility` predicates into views. A user with the capability may see aggregate
context across source rows they cannot select individually. This is required
functionality, not a vulnerability.

View authors remain responsible for the dimensions they expose. A grouping key
that identifies a user, group, or business record is visible by design if it is
included in the view. The compiler must preserve the declared view rather than
guessing whether a grouping dimension is sensitive.

## Audit Model

Mutation auditing is retained for future compliance and operational review even
when no application code currently reads it.

Marked tables produce asynchronous audit events. The audit write is deliberately
outside the business mutation's transaction path so it does not increase normal
transaction latency or cause the business mutation to fail.

The audit system keeps:

- `audit_mutation` for record create, update, and delete history;
- `audit_action` for explicit operational actions when needed;
- table marker `@rebase-audit`;
- field marker `@rebase-audit-redact`;
- field marker `@rebase-audit-omit`.

Audit records are temporary operational data. They may be exported or archived
manually on a monthly schedule.

If SurrealDB provides a native transaction identifier that is available inside
asynchronous events, record it. Do not create a synthetic transaction-ID or
transaction-coordination subsystem solely for audit grouping. If no native value
exists, keep the current timestamp, actor, target, event, before, after, and
changed-field information.

Cascaded recomputations may generate additional audit entries. This is accepted.
Audit precision is useful, but it must not complicate or block the primary
permission model.

## Compiler Model

The compiler has one deterministic pipeline. The broad ordering is:

1. emit the business schema;
2. emit framework tables and access definitions;
3. overwrite business tables with uniform permissions and system fields;
4. generate reader derivation, cycle guards, and propagation;
5. generate audit events for marked tables;
6. generate declared views and reactive fields;
7. generate required indexes;
8. seed root table permissions and discovered edge capabilities;
9. emit the project seed.

The compiler may branch on facts discovered from the schema, such as scalar
versus array references, system versus business targets, audit markers, and view
group keys. These are algorithmic branches, not architecture modes.

The target compiler does not have:

- `authorization.selectMode`;
- a global `inheritArrayReaders` option;
- per-project security modes;
- source `operations.json` files;
- operation JSON Schemas;
- operation-schema immutability/version registries;
- legacy artifact compatibility branches;
- separate visibility configuration.

Project configuration should exist only for values that genuinely vary between
projects. Identical configuration files containing fixed defaults are noise and
should be removed.

The build output should contain the compiled `schema.surql` and copied `edge/`
handlers. A generated operation catalog is not a source of truth.

## Edge Functions

An edge function orchestrates authenticated external work using already modeled
database context.

Examples include:

- sending a campaign email;
- sending a transactional message;
- producing an invoice through an external provider;
- receiving and verifying a provider webhook;
- starting a durable asynchronous job.

### Naming and capability identity

Edge functions are graph nodes, not members of a required dotted hierarchy.

Use JavaScript-style camelCase function names:

```text
campaignMail
transactionalMail
campaignMailV2
```

The canonical file, capability, and endpoint are:

```text
edge/campaignMail.js
campaignMail
POST /v1/edge/campaignMail
```

Directories may organize source files, but they must not silently change the
capability identity. Capability names must be unique.

### Manual versioning

There is no handler-version registry or compatibility framework.

For a breaking change:

1. add a new function such as `campaignMailV2`;
2. grant its capability to the required groups;
3. migrate the frontend or external caller manually;
4. allow old jobs to finish;
5. retain or delete the old handler and job records when operationally suitable.

Do not add glue code that tries to migrate every historical handler payload.

### Handler declaration

Each handler declares its own execution mode and record-context contract:

```js
module.exports = {
  mode: "job",

  records: {
    config: "email_brevo_config",
    profile: "email_campaign_profile",
    template: ["invoice_template", "campaign_template"],
    files: {
      tables: ["file"],
      many: true,
      required: false,
      max: 20,
    },
  },

  timeoutMs: 60_000,
  maxAttempts: 5,

  async execute({ auth, records, args, providers, signal, execution }) {
    // Orchestrate authorized records and raw scalar arguments.
  },
};
```

The handler declaration is the only operation contract. It replaces
`operations.json` and operation JSON Schemas.

### Record arguments

The `records` declaration defines:

- accepted argument names;
- accepted source table or tables;
- whether the argument is required;
- whether it accepts one ID or many IDs;
- bounded cardinality for many-valued inputs.

A polymorphic slot declares the accepted tables directly:

```js
template: ["invoice_template", "campaign_template"]
```

The gateway rejects a record from any other table before execution. A primitive
record cannot be substituted for an email configuration merely because both are
syntactically valid record IDs.

### Scalar arguments

Scalar or structured non-record arguments are passed as raw JSON in `args`.
There is no centralized JSON Schema registry.

The handler validates only the domain facts it needs:

```js
const subject = String(args.subject || "").trim();
if (!subject) throw new GatewayError("SUBJECT_REQUIRED", "Subject is required", 400);
```

This validation belongs beside the behavior that consumes the value. It must not
be duplicated in an operation catalog and a separate schema tree.

Transport-level validation remains in the gateway:

- valid JSON when JSON is expected;
- body-size limits;
- record-slot shape and cardinality;
- valid record-ID syntax;
- declared record tables;
- bounded record counts.

Provider credentials and API keys should come from authorized context records or
server-side secret providers, not ordinary client scalar arguments.

### Request shape

The standard authenticated request is:

```http
POST /v1/edge/campaignMail
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
  "records": {
    "config": "email_brevo_config:production",
    "profile": "email_campaign_profile:weekly"
  },
  "args": {
    "subject": "Hello"
  },
  "requestId": "optional-client-correlation-id"
}
```

Record context and scalar arguments are separate so authorization cannot be
confused with handler-local domain validation.

## Gateway Authorization Flow

For an authenticated request, the gateway performs this sequence:

1. authenticate the bearer token;
2. load the current actor and graph-derived capabilities;
3. discover the handler by its exact function name;
4. verify that the actor has the handler capability;
5. validate the supplied record slots against the handler declaration;
6. validate each record ID's syntax and declared table;
7. deduplicate the IDs;
8. resolve all IDs in one bounded database operation;
9. apply the same table-select and row-select model used by direct database
   access;
10. require every requested record to resolve;
11. pass `{ auth, records, args, providers, signal, execution }` to the handler.

An unavailable, nonexistent, wrong-table, or unauthorized record must not be
distinguished in a way that leaks its existence. Return a generic unavailable or
not-found result.

The gateway may use privileged database access for the bounded resolution query,
but the authorization predicate must come from the same shared policy source as
the compiler. Do not maintain a handwritten second interpretation of row access.

Handlers receive resolved authorized records. They do not receive an unrestricted
privileged database connection by default.

The gateway is stateless with respect to business configuration. Context tables
hold provider choices, templates, credentials references, campaign profiles, and
other dynamic service configuration.

## Execution Modes

ReBase retains three execution modes.

### Request

The gateway authorizes the call, invokes the handler immediately, applies a
timeout, records the outcome, and returns the handler result.

### Job

For a durable job:

1. authorize the capability and record IDs before enqueueing;
2. persist raw `args`, named record IDs, actor, function name, attempts, and
   idempotency information;
3. write the outbox entry transactionally with the job;
4. publish through the outbox relay;
5. claim work with a lease;
6. reload the actor and re-authorize every record when the worker executes;
7. invoke the current handler;
8. finish, retry with delay, cancel, or fail according to durable job state.

Authorization at enqueue time is not sufficient. Access may be revoked before a
worker runs.

Keep:

- idempotency keys;
- outbox delivery;
- leases and lease expiry;
- retry limits and retry delay;
- cancellation;
- terminal job records;
- bounded execution logs.

These mechanisms provide real reliability and are not operation-schema overhead.

### Webhook

Webhooks do not use client record authorization or operation JSON Schemas.

The webhook handler owns:

- raw-body signature verification;
- provider identification;
- provider event-ID extraction;
- payload parsing;
- required field checks;
- provider-specific orchestration.

The gateway owns:

- body-size limits;
- route-to-handler lookup;
- deduplication keys;
- webhook receipt leases;
- duplicate/in-progress behavior;
- outcome persistence and logging.

Do not parse or normalize the body before signature verification when the provider
signature covers raw bytes.

## No Operation Or Schema Discovery API

The target gateway does not expose `/v1/operations`, `/v1/schemas`, or equivalent
catalog endpoints.

Clients call known edge functions. When clients need dynamic application data,
model it as ordinary context tables with normal select permissions and
`visibility` where public read access is intended. If data must be read-only,
give it select permission and deny create, update, and delete.

Do not build metadata APIs for information already representable through normal
tables and permissions.

## Development Data And Workbench

The development environment must be dynamic and useful for manual exploration.
It must not depend on a large static scenario graph.

### Data schemas

`data/<table>.schema.json` files remain only for generating valid scalar fake
values. They are not gateway request contracts.

The Surreal schema is the source of truth for:

- tables;
- record references;
- reference target tables;
- scalar versus array cardinality;
- computed fields;
- read-only fields;
- ownership fields;
- framework-managed fields.

The populator must not duplicate relationship topology in a hard-coded scenario
map.

### Reference population

References are selected from records already committed in the database.

The scalable default is:

1. page through candidate record IDs with keyset pagination;
2. keep a bounded reservoir per target table;
3. choose randomly from the reservoir in JavaScript;
4. generate a random seed by default;
5. print the seed so a failure can be replayed;
6. insert in dependency-aware batches;
7. refresh candidate reservoirs only after a batch commits.

Do not repeatedly use `COUNT + OFFSET` or `ORDER BY rand()` on large tables.
Those approaches tend to rescan data as the database grows.

The populator may create unusual ownership combinations. That is useful for
testing a set-based permission system. Invalid schema values and nonexistent
record references are not useful and must be avoided.

### Workbench commands

The target REPL/workbench provides compact dynamic commands such as:

```text
.build
.deploy
.populate all 100
.populate invoice 25
.as alice@example.com password
.edge campaignMail {...}
.probe security
.probe gateway
.probe data
```

Static cookbook scripts, a separate legacy REPL, and a monolithic smoke program
are not part of the target architecture.

## Verification Strategy

The final development model does not maintain a large `test/**` unit and
integration suite. Before deleting existing tests, replace their critical value
with disposable live probes that:

- start or connect to an isolated SurrealDB instance;
- create their own namespace and database;
- generate their own principals and records;
- assert the permission matrix;
- assert one-way ownership delegation;
- assert DAG cycle rejection and propagation;
- assert scalar and marked-array reader inheritance;
- assert reader revocation and transitive cascades;
- assert request, job, retry, cancellation, worker reauthorization, and webhook
  deduplication behavior;
- assert schema-driven population, strict references, batching, bounded
  reservoirs, and replay-seed determinism;
- remove their namespace or terminate the in-memory instance.

Compiler verification includes:

- compiling the primary `designs/test` project;
- running `surreal validate` on the generated schema;
- checking deterministic output;
- deploying the generated schema to a disposable SurrealDB instance.

`designs/accounts` and `designs/crm` are incidental examples, not active product
scope. Do not spend time redesigning or patching them unless a shared compiler bug
is demonstrated.

## Performance Rules

1. Authorization reads use materialized indexes and set membership.
2. `readers_index` is indexed.
3. Direct user/group references never enlarge `readers_index`.
4. Scalar business references inherit readers automatically because their fanout
   is bounded.
5. Array business references require an explicit marker because their fanout is
   unbounded by default.
6. All edge context IDs are resolved in one bounded database operation.
7. Duplicate IDs are resolved once and mapped back to named slots.
8. Job and webhook reliability state remains in SurrealDB.
9. Data-generation sampling uses keyset pagination and bounded memory.
10. Async audit events must not block business transactions.
11. Do not optimize away propagation until revocation correctness is proven.
12. Measure broad reverse-reference fanout against a disposable realistic data
    set before changing cascade behavior.

## Explicit Non-Goals And Forbidden Regressions

Do not introduce:

- alternate select modes;
- per-table visibility compiler modes;
- direct user/group reader inheritance;
- a generic `shared_with` field;
- global array-reader inheritance;
- source or generated `operations.json` as an operation contract;
- operation argument, result, or webhook JSON Schema registries;
- operation/schema discovery endpoints;
- dotted capability hierarchies imposed by directories;
- a handler-version registry;
- compatibility glue for unused development APIs;
- a privileged database connection exposed to ordinary handlers;
- row-level ACL injection into company-context aggregate views;
- deletion of compliance auditing merely because no current reader exists;
- a hard-coded scenario relationship map;
- random selection strategies that require full-table random sorts;
- security changes justified only by assumptions about SurrealDB behavior.

Do not interpret this list as a ban on all new code. Add a mechanism when it
protects a real invariant, supplies required reliability, or removes meaningful
duplication. Avoid mechanisms whose main purpose is to support hypothetical
future variants.

## Current Verification

`npm run verify` checks deterministic compilation, validates the generated
SurrealQL, and runs disposable live probes. The probes cover uniform row access,
one-way ownership delegation, principal-reference exclusion, scalar and marked
array readers, revocation, reader-cycle rejection, DAG cycle rejection,
capability-scoped views, asynchronous audit delivery, request handling, durable
jobs, cancellation, retry, worker-time reauthorization, webhook verification,
and deduplication.

SurrealDB does not expose a native transaction identifier to asynchronous event
code in the supported version. Audit records therefore keep native event data
without synthetic transaction grouping.

`designs/accounts` and `designs/crm` remain incidental examples. Modify them
only when a demonstrated shared compiler bug requires it.

When README text, research notes, generated artifacts, comments, or current code
conflict with this document, verify whether the conflict is an intentional
transitional state. For target architecture decisions, this document takes
precedence unless the maintainer explicitly changes the decision.

## Change Checklist

Before accepting a core change, verify:

1. Which invariant or duplicated mechanism does the change address?
2. Is the behavior already supplied by SurrealDB or the business schema?
3. Does it create a second source of truth?
4. Does it add an architecture mode?
5. Does it change select, ownership, reader, view, audit, job, or webhook
   semantics?
6. Has the relevant SurrealDB behavior been reproduced in a disposable instance?
7. Does revocation remain correct after cascades settle?
8. Are edge handlers still self-describing?
9. Are raw scalar arguments still handler-owned?
10. Are all context records table-checked and authorized?
11. Is the generated schema valid and deterministic?
12. Does the change reduce or justify its maintenance cost?

When uncertainty remains, document the uncertainty and probe it. Do not silently
choose a familiar pattern that changes ReBase into a conventional schema-driven
API framework. ReBase is a database-centered, set-authorized context and edge
orchestration system.
