# Storage lifecycle and recovery

The supported backend is one process owning one embedded redb file. Runtime
writes, derived repairs, indexes, authority and receipts commit atomically.
Network startup checks complete current-state integrity before listening.
Operator commands below take the file lock; stop the HTTP process first.

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
owned temporary file. Backup and restore are bounded to 64 MiB for this model.
Use one restored instance as the replacement, not simultaneous writable clones.

`check` derives expected records/roles/memberships/routes/queries from complete
source observations, checks scalar equations and final causal edges including
zero contributions, and verifies actual AVL order, links, balance, neighbours,
exact subtree/root summaries and historical floors. It also checks authority
scopes, complete public/reader indexes, reservations and receipt structure.
It calls no tree writer/rotation/settlement/query traversal. It reuses the
independently tested summary algebra and reader-fold primitive. This is a
current-state verifier; it cannot reconstruct the historical truth of every old
receipt without past source history. The separate Python acceptance oracles
still verify fixture histories and rollback independently.

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

Store format `rebase-store-2` and the native codec have explicit versions.
Model identity hashes the resolved declarations/schemas and the explicit native
behavior contract revision. Transport formatting and dependency patch bytes do
not define a data model. Maintainers must bump `BEHAVIOR_CONTRACT` when changing
binding, calculation, causality or invariants; structural/schema changes also
change the resolved model identity. Evidence independently fingerprints the
executed sources. Do not confuse a build fingerprint with data compatibility.

This is the first such data contract; old prototype stores intentionally reject.
A changed data/model contract requires an explicit reviewed migration or a new
disposable store. No automatic semantic migration or distributed failover is
promised. Preserve a verified backup before changing the deployed binary/model.
