# Storage lifecycle and recovery

The supported backend is one process owning one embedded redb file. Runtime
writes, derived repairs, indexes, authority and receipts commit atomically.
Network startup checks complete current-state integrity before listening.
Operator commands below take the file lock; stop the HTTP process first.
These examples use the default `calculation` model. For equipment or invoicing,
prepend `--model equipment` or `--model invoicing` before every command, including `version`, `restore`,
`receipts archive`, and `reset`. Wrong-model opens and restores reject.

```sh
rebase-next version
rebase-next check app.redb
rebase-next backup app.redb backups/before-change.json
rebase-next restore backups/before-change.json restored.redb
```

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
scopes, complete public/reader indexes, reservations and receipt structure.
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

The active window holds at most 1024 receipts. Before it fills, stop the service
and archive it:

```sh
rebase-next receipts archive app.redb backups/receipt-window-0001.json
```

This first creates and fsyncs a complete backup, then atomically clears receipts
and advances the operation fence if the backed-up state is still current.
Domain data, authority and revision remain intact. A racing write makes archive
fail safely; its consistent backup remains available. Old request contexts now
return `operation_expired`, so loss of a receipt never silently permits its old
request to run again. Fetch a fresh context **only for a new intended operation**.
Never update the context of an uncertain old request to bypass that error.

Reconcile an expired operation by restoring its archive to an isolated offline
file and inspecting the receipt there with its original context. Do not expose
that archived copy as a second writable service. Keep archives for the required
reconciliation/audit period. There is no automatic unsafe receipt eviction.

## Reset disposable state

Read the store UUID from `check` or `inspect`, then supply it explicitly:

```sh
rebase-next reset disposable.redb --expect-store <store-uuid>
```

One transaction clears domain records/trees/indexes/reservations/receipts,
preserves configured principals/grants, advances every credential epoch, and
installs a new store UUID/cursor key. Old tokens, cursors and operation contexts
are fenced. Issue fresh credentials before reusing the service. This avoids any
reference-deletion ordering or recompilation/redeployment. The command is a
trusted operator tool and has no network RPC counterpart.

## Data identity and upgrades

The last verified deployment bundle, 0.6.0, uses store format
`rebase-store-4` and native codec `native-slice-kv-4`. The current 0.8.0 source
uses `rebase-store-6` and `native-slice-kv-6`. One store holds one selected
compiled model.
Model identity hashes the resolved declarations/schemas and the explicit native
behavior contract revision. Transport formatting and dependency patch bytes do
not define a data model. Maintainers must bump the affected `Binding::BEHAVIOR`
when changing binding, calculation, causality or invariants. Calculation uses
`native_slice::BEHAVIOR_CONTRACT`; Equipment owns its revision in its module.
Shared semantic changes require bumping every affected binding. Structural/schema changes also
change the resolved model identity. Evidence independently fingerprints the
executed sources. Do not confuse a build fingerprint with data compatibility.

In 0.8.0 source, calculation behavior is `rebase-calculation-contract-6`,
equipment behavior is `equipment-reservations-5`, and invoicing behavior is
`invoice-assessments-4`. The model-local index codes, generic native keys and independent subtree spans
change format 5. The typed read ranges and augmented reverse-route node
layout introduced in 0.7.0 remains in use. The source rejects older stores,
including 0.7.0 format 5 and 0.6.0 format 4, without migrating them. Keep each
matching binary and its backups together. The 0.6.0 bundle remains the last
verified deployment; source checkpoint acceptance does not certify a new bundle.

The calculation/equipment declared limits remain 4,096 public sources, 8,192
active private outputs and 16,384 retained role reservations per model.
Invoicing remains 64 public sources, 256 active outputs and 512 retained roles.
Measurement allows 64 public sources and no private outputs or reservations.
Backup remains capped at 64 MiB, and the active receipt window remains 1,024
operations.

Format 2, 3, 4 and 5 stores and their backups intentionally reject in 0.8.0. The
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
