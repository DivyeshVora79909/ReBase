# ReBase Research Index

This directory is the project’s compact research corpus. It is split by
information kind so an agent can load only the material needed for a task.

## Taxonomy

| Area                         | Responsibility                                                                                                                                                                                                  |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`surrealdb/`](./surrealdb/) | Measured SurrealDB behavior, documented engine semantics, probes, limits, and performance evidence. These files describe what the database does; they do not define the whole ReBase product architecture.      |
| [`rebase/`](./rebase/)       | Adopted ReBase policy and target architecture: authorization, compiler behavior, effect runtime, scheduling, and development contracts. These files describe what ReBase chooses to do using the engine behavior. |

## ReBase documents

- [`rebase/architecture.md`](./rebase/architecture.md) — canonical end-to-end
  effect architecture and ownership boundaries.
- [`rebase/runtime-dispatch.md`](./rebase/runtime-dispatch.md) — table-keyed
  handler registry, common handler contract, invocation adapters, and runtime
  security boundary.
- [`rebase/scheduler.md`](./rebase/scheduler.md) — schedules, reconciliation,
  wake delivery, and rejected scheduler alternatives.
- [`rebase/session-lifecycle.md`](./rebase/session-lifecycle.md) — system-user
  token renewal, WebSocket reconnect authentication, and record-token expiry.
- [`rebase/authorization.md`](./rebase/authorization.md) — principal DAG,
  ownership, readers, views, and audit policy.
- [`rebase/parents-field.md`](./rebase/parents-field.md) — principal-parent
  delta validation and its permission matrix.
- [`rebase/compiler-development.md`](./rebase/compiler-development.md) —
  compiler pipeline, schema-derived generation, workbench/population, and
  verification rules.
## SurrealDB documents

- [`surrealdb/access-definitions.md`](./surrealdb/access-definitions.md) —
  access methods execution and token generation via SIGNIN/SIGNUP AUTHENTICATE
- [`surrealdb/async-events.md`](./surrealdb/async-events.md) — asynchronous
  event transaction, retry, recursion, and ordering semantics.
- [`surrealdb/synchronous-events.md`](./surrealdb/synchronous-events.md) —
  provisional snapshots, HTTP calls, commit behavior, and sync fallbacks.
- [`surrealdb/update-permissions.md`](./surrealdb/update-permissions.md) —
  table/field permission behavior and machine-controlled `VALUE` fields.
- [`surrealdb/reference-authorization.md`](./surrealdb/reference-authorization.md)
  — permission-aware `record::exists()` and assertion boundaries.
- [`surrealdb/record-references.md`](./surrealdb/record-references.md) —
  reference types, delete actions, dangling links, and cascade atomicity.
- [`surrealdb/uuidv7-record-ids.md`](./surrealdb/uuidv7-record-ids.md) — UUIDv7
  record IDs, scope, ordering, and idempotency limits.
- [`surrealdb/engine-performance.md`](./surrealdb/engine-performance.md) —
  query plans, ACL routing, catalog scaling, schema-definition cost, and
  data-generation performance.
- [`surrealdb/data-generation.md`](./surrealdb/data-generation.md) —
  schema-driven fixture generation and dependency-batch findings.

## Evidence conventions

- `Measured` means a disposable probe observed the behavior on the stated
  SurrealDB version and environment.
- `Documented` means the behavior is supported by an official reference.
- `Adopted` means ReBase uses the behavior as a current design rule.
- `Alternative` or `Rejected` preserves a useful competing design without
  making it part of the default architecture.

Every engine-sensitive decision should retain its reproduction command and
remain covered by `npm run probe:architecture`, `npm run probe`, or a narrower
disposable probe. Upgrade-sensitive facts are not silently promoted to universal
SurrealDB guarantees.

## Naming convention

Research filenames use lowercase kebab-case and one primary topic per file.
Directories classify the document; filenames identify the topic. Cross-topic
design consequences belong in the ReBase document that owns the decision, with
a short link back to the engine finding rather than a copied explanation.
