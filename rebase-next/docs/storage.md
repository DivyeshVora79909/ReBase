# Storage lifecycle and recovery

The default backend is one process owning one embedded redb file. The same
persistence boundary also serves explicitly selected FoundationDB and standalone
SurrealKV targets; see [backend usage and scope](storage-backends.md). Runtime
writes, derived repairs, indexes, authority, query epochs and receipts commit atomically.
Network startup checks complete current-state integrity before listening.
The redb operator functions take the file lock; stop the HTTP process first.
The [external-work model](external-effects.md) also persists executions, due
rows, immutable provider facts, signed inbox events and reserved recovery capacity.
Effect-bearing restores rotate activation and remain quarantined; explicit
reconciliation-only activation can resolve and apply confirmed outcomes. Delivery
and new Dispatch creation stay disabled until a clean reset. Receipt archives
preserve effect evidence; reset rejects unresolved work and pending inbox rows.
Choose the compiled model explicitly in the native configuration. Wrong-model
opens and restores reject.

The [N5 lifecycle example](../tools/node/examples/n5-lifecycle.mjs) composes scoped operator functions over an already-owned native handle.

Backup reads all application tables from one consistent snapshot. A SHA-256
checksum detects accidental damage. These are trusted operator backups, not
signed artifacts from untrusted users. They contain private state and cursor
signing material; files are created with mode 0600 on Unix. Protect/encrypt them
with existing storage infrastructure. Issuer private keys are not stored here.

Restore writes a temporary database, validates complete table inventory, model
and format, verifies current calculations and structures, closes/reopens it, and
only then atomically publishes a **new** destination. Existing files/symlinks
are never overwritten. Failed validation leaves no published destination or
owned temporary file. Backup and restore are bounded to 64 MiB for each
compiled model.
Use one restored instance as the replacement, not simultaneous writable clones.

Each compiled model supplies its own independent semantic check; the shared
checker validates storage, indexes and tree structure. For calculation, `check`
derives expected records/roles/memberships/routes/queries from complete
source observations, checks scalar equations and final causal edges including
zero contributions, and verifies actual AVL order, links, balance, neighbours,
exact subtree/root summaries and historical floors. It also checks authority
scopes, complete public/reader indexes, separate population/reservation counts,
bounded query epochs and the exact receipt/slot bijection.
It calls no tree writer/rotation/settlement/query traversal. It reuses the
independently tested summary algebra and reader-fold primitive. This is a
current-state verifier; it cannot reconstruct the historical truth of every old
receipt without past source history. The separate Python acceptance oracles
still verify calculation fixture histories and rollback independently. Equipment
checking independently derives interval allocation/event arithmetic from its public
sources and compares publications, outputs and memberships; focused tests cover
its lifecycle, rollback and public HTTP workflow.
Invoicing checking reconstructs pricing, tax reassessments, linked credits,
payment/refund capacity and complete-time balance/claim histories from public
sources before comparing private outputs and maintained trees.

## Receipt retention without unsafe retries

Before constructing a mutation, call `session.describe {}` and retain its
`operation_context` as the mutation's required `context` field. Retain that
context, the operation UUID and the exact normalized request for reconciliation.
`operations.status` also requires the original context. The HMAC binds actor,
tenant, store, model and receipt generation; it grants no authorization.

The active window holds exactly 1,024 possible receipt allocations. Each operation
hashes its actor/operation key to a starting slot and probes at most 1,024 slots
for a free one. The slot pointer, bound receipt and all application changes commit
together. Replay is checked before allocation, so retained operations still replay
at capacity. There is no global receipt count written on every operation and no
per-bucket quota that strands capacity. Collisions and near-full probing can cause
contention; a full window rejects a new operation atomically with `receipt_limit`.
Before it fills, stop the service and archive it:

```sh
rebase-next receipts archive app.redb backups/receipt-window-0001.json
```

This first creates and fsyncs a complete backup, then reads and protects the entire
application-table image inside the cleanup transaction. Its SHA-256 digest must
match the published backup. Cleanup atomically clears both receipts and allocation
slots and advances the numeric operation-context expiry epoch. Domain records,
root tokens, query epochs, authority and effect evidence remain intact. A racing
domain, authority or effect write either changes the digest or conflicts with the
protected cleanup; the backup remains available after rejection. Ordinary
mutations read the expiry header and do not rewrite it, so archive/reset still
fence in-flight operations. Old request contexts now
return `operation_expired`, so loss of a receipt never silently permits its old
request to run again. Fetch a fresh context **only for a new intended operation**.
Never update the context of an uncertain old request to bypass that error.

Reconcile an expired operation by restoring its archive to an isolated offline
file and inspecting the receipt there with its original context. Do not expose
that archived copy as a second writable service. Keep archives for the required
reconciliation/audit period. There is no automatic unsafe receipt eviction.

## Reset disposable state

The Node operator resets a store only through an already-owned native handle.
Open that handle for the existing store with the `store.reset` grant, scope the
operator to the handle, and pass its expected store UUID:

```js
import { openOperator } from './tools/node/index.mjs';

// `native` is an already-open, caller-owned handle configured for this store.
const operator = openOperator(native, {
  scope: native.scope,
  methods: ['store.reset'],
});
const reset = await operator.reset({ expectStore: native.scope.store });
```

One transaction clears domain records/trees/indexes/reservations/query epochs/receipts/slots,
preserves configured principals/grants, advances every credential epoch, and
installs a new store UUID/cursor key. Old tokens, cursors and operation contexts
are fenced. Issue fresh credentials before reusing the service. This avoids any
reference-deletion ordering or recompilation/redeployment. Reset is a trusted
operator function and has no network RPC counterpart.

## Data identity and upgrades

The last verified deployment bundle, 0.6.0, uses store format
`rebase-store-4` and native codec `native-slice-kv-4`. The current 0.16.0 source
uses `rebase-store-10`, `native-slice-kv-7`, `rebase-effects-4` and
`rebase-local-api-4`. One store holds one selected
compiled model.
Model identity hashes the resolved declarations/schemas and the explicit native
behavior contract revision. Transport formatting and dependency patch bytes do
not define a data model. Maintainers must bump the affected `Binding::BEHAVIOR`
when changing binding, calculation, causality or invariants. Calculation uses
`native_slice::BEHAVIOR_CONTRACT`; Equipment owns its revision in its module.
Shared semantic changes require bumping every affected binding. Structural/schema changes also
change the resolved model identity. Evidence independently fingerprints the
executed sources. Do not confuse a build fingerprint with data compatibility.

Source 0.16.0 separates immutable model/store identity, exact population/reservation
counts and the numeric authority administration revision. Population is written
only when its counts change. Domain writes have no global mutation sequence.

| Field | Meaning in API 4 |
| --- | --- |
| Record `version` / command `if_version` | Canonical nonnil UUID for equality-only compare-and-set. Changed records get a fresh mutation token; unchanged records retain theirs. |
| Root `revision` | Canonical nonnil UUID identifying that root's current stored state. |
| Mutation/cancellation result `revision` | Fresh UUID for the committed operation, retained unchanged by its receipt. A genuine no-op has a new result token while unchanged records/roots keep theirs. |
| Page/exists `revision` | Lowercase SHA-256 digest of selected reader/contract epochs and, for secured stores, the authority administration revision. |
| Access `revision` / `if_revision` | Canonical decimal string counter for graph administration only. Domain mutations do not advance it. |
| Execution `revision` / cancellation `if_revision` | Ordered per-execution decimal-string fence; distinct from the cancellation result UUID. |

Never sort UUID tokens or interpret them as counters. Delete/recreate obtains a
fresh token, so an earlier record token cannot pass CAS after reuse. `check`,
`inspect` and backup metadata expose no global domain revision. Cursor digest
semantics are described in the [operation reference](local-prototype.md#query-and-publication-semantics).

The current behavior identities are `rebase-calculation-contract-7`,
`equipment-reservations-6`, `invoice-assessments-6`,
`dimensioned-measurements-4`, `effect-demo-ingress-4` and `quantity-flow-2`.
All require new compatible stores. These identities describe the changed shared
coordination contract, not new business formulas.

Historically, in 0.14.0 source, calculation behavior was `rebase-calculation-contract-6`,
equipment behavior was `equipment-reservations-5`, and invoicing behavior was
`invoice-assessments-5`. Measurement used `dimensioned-measurements-3` for native
ObservationReport and LatestObservation queries with authored-unit dependencies.
Effect-demo used `effect-demo-ingress-3`; its action and typed outcome schema
also participated in its model identity. Calculation, equipment, invoicing and
effect-demo identities matched 0.13.0. Family-owned query results preserved
Standard and report bytes; measurement's changed model identity rejected earlier measurement
stores even though the shared store/codec versions remained unchanged.
Store format 9 added checked inbox rows and explicit worker modes. API 3 replaced
the effect status boolean with `worker_mode`; the capability catalog declared
the disabled default. Format 8 added checked facts, leases, application state and bounded due
sweeps. Format 7 introduced effect tables and tagged operation receipts.
The 0.8 native index codes, generic keys and independent subtree spans required
format 6. The 0.9 publication inputs reused existing Direct route bytes and
attempt-local values: only invoicing's model identity changed. Other 0.8 models
retained their identities. The typed read ranges and augmented reverse-route node
layout introduced in 0.7.0 remain in use. Those source versions rejected older formats,
including 0.7.0 format 5 and 0.6.0 format 4, without migrating them. Keep each
matching binary and its backups together. The 0.6.0 bundle remains the last
verified deployment; source checkpoint acceptance does not certify a new bundle.

The calculation/equipment declared limits remain 4,096 public sources, 8,192
active private outputs and 16,384 retained role reservations per model.
Invoicing remains 64 public sources, 256 active outputs and 512 retained roles.
Measurement allows 64 public sources and no private outputs or reservations.
Backup remains capped at 64 MiB, and the active receipt window remains 1,024
operations.

Format 2 through 9 stores and their backups intentionally reject in 0.16.0. The
runtime header is checked before native metadata decoding, so an old store
reports a model/format mismatch rather than being reinterpreted. There is no
silent migration, automatic reset or cross-model restore. Restore a backup only
with its matching binary, compiled model and behavior identity.

A read-only identity check rejects a clean incompatible store without changing
even redb's maintenance bytes. The writable handle rechecks identity as well.
If a process crashed, redb can require allocator recovery before a read-only open
is possible; normal recovery is retained and identity is checked afterwards.
That recovery can change storage-maintenance bytes. Recover old stores with the
matching binary, then check and back them up before attempting an upgrade.

Before upgrading, stop the old process, run its `check` and `backup`, and retain
that compatible binary with its verified backups and receipt archives. Restore
older-format backups with their matching old binary. Use a new store whenever
model/format identity changes unless an explicit reviewed migration is provided;
do not use restore as a migration tool.
For rollback, use the old binary and its pre-upgrade snapshot. Never run the old
and replacement writable copies together. No distributed failover is promised.
