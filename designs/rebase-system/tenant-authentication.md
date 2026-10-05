# Tenant and authentication contract

Updated 2026-10-05. This is the current tenant, principal, identity, and provider
credential contract for the [tenant/tree redesign](./tenant-tree-redesign.md).
It supersedes root-group and database-per-tenant assumptions in older handoffs.
The database schema and probes below are the executable authority.

## Tenant and principal graph

Each deployed design selects one SurrealDB namespace/database. Developers
explicitly provision `rebase_tenant` records inside that design. A tenant is a
parentless root whose `tenant` field equals its own ID; there is no automatically
created tenant or special `rebase_group:root` record.

`rebase_user` and `rebase_group` require at least one parent. Parents may be a
tenant, user, or group, and every parent must belong to the same tenant. The
principal derives its tenant on creation. Reparenting within the tenant is
allowed; changing tenants is rejected. Missing parents, self-parenting, and DAG
cycles are rejected in the same transaction as the attempted write.

The tenant's role is the full permission list generated for the design. A user
inherits the union of its **direct** tenant/group parents' roles. A user parent
contributes graph ancestry, not its own permission list. Groups keep explicit
roles. A record actor cannot assign a role or create/reparent a user into roles
it does not possess. Seeing tenant metadata does not let an ordinary member
attach a new administrator directly to that tenant.

`parent_groups` contains direct group and tenant parents. The helper
`fn::rebase::can_access(actor, target)` accepts self, one of those direct parents,
or a descendant. `fn::rebase::dominates(actor, target)` accepts only a strict
descendant. Separate table operation permissions still apply. A direct tenant
child receives the design's full permission vocabulary; this does not turn it
into a SurrealDB system user or bypass native private tables.

The generated `tenant` field uses `fn::rebase::owner_tenant(owned_by)`. If a
record actor is authorized to use a hidden owner, valid graph membership already
proves that owner's tenant; the helper returns the actor's current tenant.
Otherwise it reads the owner's tenant under native permissions. This permits
group ownership without requiring the actor to have `node_select`.

Implicit tenant, user, group, email, phone, and passkey identity IDs default to
native UUIDv7 values. Explicit string and composite IDs remain valid. HTTP
authentication resolves a supplied tenant to the database's canonical record
string before comparisons and rate-limit keys. SDK `u"..."` and native `u'...'`
spellings of the same UUID identify the same tenant and limit bucket.

## Authorization closure

`rebase_access` is a protected relation whose `in` is an ancestor and `out` is a
descendant. Its deterministic ID is `rebase_access:[ancestor, descendant]`.
There are no materialized `dominates` or `z_access_index` arrays on principals.

Record users may read only closure pairs with themselves as `in`; they cannot
create, update, or delete pairs or call the maintenance function. Native table
`PERMISSIONS NONE` also hides rows from permission helpers, so caller-scoped
selection is deliberate. It exposes the caller's own graph membership, not a
generic permission bypass.

Membership uses `record::exists` on the exact pair ID. SurrealDB 3.3 `EXPLAIN`
reports `RecordIdScan` for that lookup. Graph maintenance uses native incoming
and outgoing relation adjacency. This does not establish that arbitrary joins
or table permission predicates become index scans.

A changed parent set refreshes the changed principal and its descendants in
the order of their previous private `authorization_depth`. It recomputes each
ancestor set from current direct parents and updates only the changed closure
pairs. Alternate paths in a diamond survive removal of one edge. Every DAG
mutation and role change writes the tenant's `authorization_revision` fence,
so concurrent changes cannot commit incompatible graph snapshots. A conflict
is returned to the caller; the engine does not silently replay user mutations.

This trades control-plane writes and storage for small authorization reads.
Closure storage can be quadratic in the principal count; a reparent can touch
the affected subtree's ancestor pairs. The tenant fence also serializes these
rare authorization changes. These are not logarithmic domain-tree writes.
Current permission data remains authoritative; permission arrays are not copied
into JWT `CONTEXT`. Existing HTTP tokens and WebSocket sessions were tested
against role and ancestry revocation.

## Materialized aggregate views

Grouped `v_*` definitions in `views.surql` must select and group by `tenant`
and declare exactly one publication policy in a comment before the definition.
The compiler rejects missing or conflicting policies. Aggregate rows cannot
recover the ownership of source rows after that information has been grouped
away, so each policy defines the scope of the stored result explicitly.

`@rebase-view-record-scoped` also requires direct `owned_by` and `readers_index`
projections and both fields in `GROUP BY`, alongside the business grouping keys:

```surql
-- @rebase-view-record-scoped
DEFINE TABLE OVERWRITE v_entry_totals AS
    SELECT tenant, owned_by, readers_index, account, count() AS entries,
        math::sum(amount) AS total
    FROM entry GROUP BY tenant, owned_by, readers_index, account;
```

The generated SELECT permission uses the source table's current operation
permission, tenant, and owner/reader policy. A build using `selectPolicy: owner`
keeps that restriction on the view. One business key can therefore have several
aggregate rows with different authorization scopes; consumers must not assume
one row per account. Native selection returns only the scopes the actor may
read. Owner and membership changes refresh the stored reader scopes.

`@rebase-view-tenant-published` deliberately publishes its selected aggregates
to authenticated members of the same tenant who hold the source table's
`<table>_select` permission, including contributions they cannot read as source
rows. It is appropriate only when that publication is part of the design:

```surql
-- @rebase-view-tenant-published
DEFINE TABLE OVERWRITE v_tenant_entry_totals AS
    SELECT tenant, count() AS entries FROM entry GROUP BY tenant;
```

Views over system tables require the tenant-published policy because those
tables do not have the ordinary ownership/reader fields. Generated
`c_<view>_<group-key>` fields select the view through its native permissions;
they do not grant another route to hidden groups. View writes are private.
The author must still choose appropriate aggregate measures: these annotations
do not infer confidentiality from arbitrary expressions or publish source
records. The tenant-record probe covers sibling owners, declared readers,
owner-only builds, another tenant, anonymous access, and computed-field reads.

## Identities and delivered codes

Email and phone identities use immutable `owned_by: record<rebase_user>` and
derive an immutable tenant. Email is normalized to lowercase and phone uses
E.164 form. Native unique indexes enforce `(tenant, address)`, `(tenant, number)`,
and `(tenant, username)` within their respective tables. The same address or
username may exist in different tenants.

`account_password`, `account_code`, and generated `oauth` sign-in requests must
include a tenant record ID. Password sign-in by email or phone requires a current
verified identity. Username/password sign-in requires at least one verified
email, phone, or enrolled passkey. OAuth verifies an allowlisted provider token
and marks the matching tenant email revision verified. Identity presence alone
does not prove authentication, and users may temporarily have no identities.

An email/phone content change invalidates that identity's verification and its
outstanding challenge. Credential changes increment the user's private
`authentication_revision`; challenges carry both user and identity revisions.
Delivered-code sign-in allows at most five attempts, atomically consumes a
correct code once, and may keep/set/clear the password. Provider delivery is
queued atomically with its challenge and encrypted payload.

`POST /anonymous/authentication/challenges` accepts `{tenant, identifier,
channel?}`. Namespace/database, recipients, identity IDs, provider configurations,
and a caller-supplied client address are not routing inputs. The response remains
generic for unavailable identities/policies. The configured design supplies the
database, the tenant's policy selects the delivery configurations, and each
configuration must belong to the same tenant as the user and challenge.

## Provider credentials

`rebase_email_delivery_config` and `rebase_sms_delivery_config` accept a tenant,
user, or group owner and derive their tenant. Tenant-owned platform credentials
are provisioned and managed through the system connection. Record users cannot
read or mutate these records. User/group-owned BYOC records follow current
`can_access` checks, and secret fields remain write-only to record users.

`rebase_authentication_delivery_policy` is private and has one unique `tenant`
field. Developers bind that tenant's email/phone configurations explicitly.
There is no database-global `:default` delivery policy or implicit `:platform`
credential selection.

Generic email/SMS tasks require an explicit configuration. Ordinary clients
must be allowed to reference that credential. System-created tasks may use an
explicit same-tenant platform credential. Before loading secrets, the worker
checks credential/task tenant equality and, for record-created tasks, the
creator's current operation permission and graph access. A queued task does
not preserve a revoked grant. Authentication delivery also rechecks its user,
identity, challenge, revisions, tenant, nonce, consumption, and expiry.

## Passkeys

Passkey support uses `@simplewebauthn/server` 13.3.3. Configure
`REBASE_PASSKEY_RP_ID`, optional `REBASE_PASSKEY_RP_NAME`, and comma-separated
`REBASE_PASSKEY_ORIGINS`. Origins must be explicit HTTPS origins within the RP
ID; HTTP localhost is accepted for local work. If no RP is configured, the
passkey routes return unavailable. Browser enrollment is a deferred frontend
task.

| Route | Request | Result |
| --- | --- | --- |
| `POST /authentication/passkeys/registration/options` | `{tenant}` and native record bearer token | `{challengeId, options}` |
| `POST /authentication/passkeys/registration/verify` | `{tenant, challengeId, response}` and bearer token | `{verified: true, id}` |
| `POST /anonymous/authentication/passkeys/options` | `{tenant}` | `{challengeId, options}` |
| `POST /anonymous/authentication/passkeys/verify` | `{tenant, challengeId, response}` | `{verified: true, exchangeToken, expiresAt}` |

Registration validates the bearer token through a separate native SurrealDB
request, checks its tenant, requires issuance within ten minutes, and reloads
the enabled user. A body `token` cannot replace the `Authorization` header.
Registration requests resident credentials and user verification. Verification
checks challenge, RP ID, origin, credential public key, and user verification.
The database stores the verified key, user handle, counter, device state, and
immutable owner; record clients can rename/revoke but cannot manufacture keys.

Authentication looks up the credential within the supplied tenant and RP,
verifies the signature and user handle, and applies the authenticator counter
check. Counter updates and exchange creation are transactional. A 32-byte
random exchange secret is returned; only its hash is used as a protected row
ID. Finish native SurrealDB sign-in using `account_passkey` and
`{tenant, exchange_token: exchangeToken}`. The exchange expires after one minute
and has exactly one consumer, including simultaneous correct requests.

WebAuthn challenges expire after five minutes and are claimed before verification;
a failed or interrupted attempt needs fresh options. Credential/user revision
changes fence registration/exchange state, and revoking a passkey removes its
outstanding exchanges. New challenges and successful authentications prune at
most 100 expired rows for their tenant from the corresponding technical table.
This is opportunistic cleanup, not a hard storage bound when traffic stops.

Native tokens retain the existing one-hour token and eight-hour session limits.
`authentication_revision` fences pending authentication work, not every already
issued session. Authorization predicates read current stored grants instead of
using JWT permission snapshots.

## Executed verification

On local SurrealDB 3.3.0:

- `node dev-tools/checks/tenant-auth-probe.js`: tenant inheritance, native creates
  without `node_select`, immutable/mixed tenant rejection, scoped uniques,
  privilege escalation rejection, diamonds, concurrent cycles, deletion,
  independent closure reconstruction, UUIDv7 defaults, exact-record plan.
- `node dev-tools/checks/authentication-probe.js`: request routing, generic
  responses, encrypted queue payloads, error behavior, OAuth provider allowlist.
- `node dev-tools/checks/passkey-probe.js`: real software-authenticator P-256
  signatures through the library, UUID tenant canonicalization/rate limits,
  native bearer routing, origin/RP/challenge/UV/signature failures, counters,
  concurrent exchange consumption, and credential revocation.
- `node dev-tools/checks/credential-probe.js`: secret redaction, explicit
  same-tenant platform/BYOC binding, unauthorized references, and revocation
  before secret loading.
- `node dev-tools/checks/probe.js all`: current WebSocket grants, closure and
  tenant isolation, immediate reader permissions, domain self-parent invariant,
  audit behavior, and seeded data generation with native IDs.

These checks use disposable databases and mock provider delivery. They do not
certify physical authenticators/browser enrollment, live providers, production
deployment, or large authorization-graph capacity.
