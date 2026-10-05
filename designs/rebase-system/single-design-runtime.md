# One design, many tenants

The namespace/database in the process profile selects one installed design.
`rebase_tenant` records partition its data and authorization. A request cannot
select another database. Another design uses a separate process/profile.

The [development contract](tenant-tree-redesign.md) owns the overall model.
`config/environment.js` is authoritative for settings. Use SurrealDB **3.3.0**
(`.surreal-version`) and rebuild every selected design before applying it.
This change targets new installations; the older one-shot task migration does
not migrate deployed namespace-per-tenant data into this model.

## Requests and durable work

Synchronous effects and grants send their declared provisional input snapshot,
including tenant, owner and creator. The runtime supplies the configured design
to the handler. A synchronous effect still cannot load its uncommitted source
from another connection; source snapshots remain necessary.

Queued/inline locators contain only `{ id }`. Queue envelopes are version 2:
`{version, kind, locator, executionId, revision}`, with no execution ID on receipt
hints. The runtime reloads due time, priority and state before admission or work.
The Redis prefix includes a stable hash of the configured design, so two
designs using the same base prefix cannot execute each other's record IDs.
Old version-1 envelopes are rejected; reconciliation recovers their durable
source records through new hints.

Managed live queries watch only task identity, outcome and lease fields.
They request work after committed changes and coalesce a bounded set of IDs.
Deleted, leased and terminal tasks do not trigger needless work. Reconnect and
overflow request reconciliation; a periodic durable cursor scan also recovers
missed messages and work outside the scheduling horizon. A live notification
contains no authority to execute a provider operation.

Failure to attach the initial watcher requests reconciliation and schedules
another attachment. The existing lifecycle uses exponential delay from one
second up to thirty seconds, with one attachment attempt or active watcher at
a time. Partial subscriptions are cleaned up on failure; shutdown cancels the
retry timer and stops the watcher. The SDK has no attachment abort signal, so
shutdown waits up to one second for an in-flight attachment and cleans up its
subscription if it resolves later. Periodic reconciliation remains active
throughout live recovery.

The Node connection uses the `ws` transport. A native regression cuts the TCP
connection, commits a task while offline, and verifies restored subscriptions
and reconciliation. The built-in Node WebSocket could stall the SDK when a
reconnect handshake failed without a close event.

Keep the existing five-minute admission horizon, one-minute default scan
cadence, atomic Redis admission, database leases, provider-start markers and
receipts. UUIDv7 improves record generation; it does not replace execution
identity, revision fencing or provider idempotency.

## References, credentials and callbacks

Handlers can load only declared references, including references reached
through their compiled contracts. Tenant-bearing references must remain in the
source tenant. Generic email/SMS tasks require an explicit configuration.
Credential authorization is checked before loading secrets; client-created
tasks also recheck their creator's current permission and owner access.
Tenant-owned service credentials remain private and are bound explicitly for
authentication/system delivery. There is no implicit global fallback.

Webhook capsule version 2 contains `provider`, `tenant`, `config`, and `id`.
Authenticated internal route creation accepts provider/config; the runtime
derives the tenant from the stored configuration. Incoming callbacks verify
the configuration/target tenant before provider verification, then commit a
durable receipt before queue publication. Receipt identity includes the tenant,
provider configuration and provider event ID. Reusing it with another payload
is a conflict. Receipt execution checks the tenant again.

SurrealDB and its SDK may use different valid quoting for the same UUID record
key. Runtime identity comparisons use bound native record equality when the
strings differ. Queue locators use the stored record's canonical SDK identity.
Do not implement record identity with arbitrary text substitutions.

## Client contract

Login supplies a tenant identifier plus its credential. Namespace/database are
fixed connection configuration, not tenant selectors. The frontend migration
is deferred and specified in [its continuation](../frontend/continuation-prompts.md).
The old frontend has not been certified against this backend.

For a declared sort path, use the tree's bounded seek/page operation. A balanced
seek costs O(log n), then chronological links cost O(k) for k entries. Native
table indexes and bounded table scans remain appropriate for other queries.
Every client query still goes through native record/field permissions.

## Local verification

`probe:runtime` covers disposable SurrealDB/Redis, mock providers, durable
recovery and real worker processes. `probe:live` covers failed initial attachment,
retry and cancellation, partial-subscription cleanup, actual socket loss,
managed resubscription, overflow and callback shutdown. `probe:webhook-inbox`
covers receipt commit ordering, lost responses and tenant rejection.
These checks establish local behavior, not live-provider delivery or
representative throughput/capacity.
