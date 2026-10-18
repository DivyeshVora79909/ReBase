# Continue MetaSol

Start from [verification](verification.md), [architecture](architecture.md),
[screen contracts](screen-contracts.md) and the
[current backend guide](../all-in-accounting/developer-guide.md). Inspect both
Git repositories independently. Rebuild the backend when its generated artifacts
are stale; refresh the frontend contract before using changed schemas.

```text
Continue the current MetaSol checkout, using its actual Git diff and compiled
contracts. Keep Solid/TanStack, native SurrealDB values and ordinary JSX/modules.
Do not revive the October 8 forms, scalar conversion fields, retired records,
table scans or offset pagination.

Use published input schemas for validation/types and declared references/roots
for reads. Preserve every cursor component and membership slot. Composite pages
require typed leading prefixes; sparse result pages retain continuation. Snapshot
query inputs in their keys instead of reading a newer reactive selection later.

Keep one original version and create identity per form. Creating a prerequisite
preserves the parent draft and requires explicit parent submission. Principal
refresh is not a session change. Authentication/route boundaries, late responses,
permissions and exact values must retain their established behavior.

Use npm run demo or npm run test:acceptance in MetaSol for an owned disposable
database. Never apply demo setup to an existing connection profile. Run tests for
changed behavior and update current documentation with actual evidence. Chromium
must be installed for the maintained browser checks.

The two user-owned files dev-tools/fixtures/examples/accounting-complete.js and
dev-tools/fixtures/examples/populate-full-enterprise.js were excluded from this
frontend work. Do not include them in a frontend commit. Review both repository
statuses and stage explicitly. Commits were authorized; publishing is separate.
```

A new workflow should compose an existing field, reader, source callback or
contextual action when those contracts fit. Introduce another abstraction only
when actual consumers need it. Historical screenshots and verification JSON
remain historical.
