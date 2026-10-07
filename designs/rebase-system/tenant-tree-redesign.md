# Tenant and tree development contract

Updated 2026-10-05. **Backend T0–T6 passed and is ready for lead review.** This
contract describes the redesign from ReBase checkpoint `eb001a2`; the
[verification evidence](evidence/2026-10-05-tenant-tree-verification.json) records
the completed integration. Frontend implementation remains deferred; its
replacement contract is part of this work.

For continuation, use the [execution handoff](tenant-tree-handoff.md).
It interprets the dependency-order clarification, inventories existing work,
and records final checks and retained limits. Distinguish its original
source-review checkpoint from the later executed verification.

## Model and scope

A table defines a record type. A record can be an entity, an entity's component,
and a member of several independent ordered trees. These roles need not become
an inheritance hierarchy or a new object framework. A tree is a materialized
ordered index with a declared root, typed key, slots, aggregate contributions,
and validation. Roots can belong to different record types. A source can
contribute several positions to one root and participate in several roots.

Keep the proven intrusive AVL implementation, chronological next/previous
links, complete-timestamp summaries, managed dependent records, and final
transaction validation. Organize these primitives through explicit schema
declarations and ordinary SurrealQL. Do not introduce another framework.

The deployment's namespace and database identify one design. Tenants sharing
that design live in this database. Separate designs may use separate deployments
or contexts. SurrealDB still requires namespace/database selection; removing
application routing does not remove this database boundary.

## Decisions and corrections

1. A balanced search tree seeks in O(log n); next/previous links page in O(k)
   after that seek. Following a linked list alone is O(n). Public ordered reads
   use a bounded server-side seek/page call, not one network request per record.
2. Nominal values can be ordered by an explicit stable representation. Equality
   lookup and uniqueness do not require appending a datetime. Native indexes
   remain useful for fields confined to one table. Cross-table trees share the
   same root and typed key contract. Neither mechanism replaces permissions.
3. New ordered roots default to unique logical keys. Roots allowing ties must
   declare that explicitly. Existing accounting/temporal roots allow ties;
   imposing unique effective dates would reject valid transactions. Every
   physical membership remains uniquely identified by source and slot. Logical
   keys and pagination tie breakers are different concepts.
4. Root identity already partitions a tree. A tenant-local root does not need
   the tenant copied into every logical key as well. Shared roots can use a
   declared composite key, but cross-tenant authorization roots are not created
   implicitly. A global uniqueness lookup does not grant global record reads.
5. Writes cost the memberships and dependent records actually changed, plus
   authorization maintenance where applicable. O(r m log n) describes bounded
   tree work, not all event execution. DAG closure can contain O(v squared)
   pairs; shared root revisions can contend. No universal low amplification or
   throughput claim follows from logarithmic tree depth.
6. Live queries are low-latency hints. Durable tasks, deterministic execution
   identities, receipts, reconciliation and atomic Redis admission remain
   necessary after disconnects, restart, duplicates, and missed notifications.
7. UUIDv7 is an explicit ID-generation choice. Existing deterministic managed
   IDs remain deterministic. Globally unique IDs do not authenticate a caller,
   provide idempotency by themselves, or remove tenant checks.

## Tenant and authorization boundary

- Add `rebase_tenant` as a parentless principal/root. There is no hardcoded
  `rebase_group:root` and no implicit tenant provisioning. Tenant roles contain
  the generated design permissions. A directly attached user inherits those
  roles under the existing direct-parent rule.
- Users and groups have at least one parent. Parents are tenant, user or group
  records; every parent belongs to the same tenant. Tenant identity is immutable.
  The authorization graph alone has DAG semantics and cycle checks.
- Every ordinary owned record derives immutable `tenant` from `owned_by`.
  Changes of owner within the tenant remain possible under current authorization.
  References to tenant-bearing domain records and tree owners must agree with
  the source tenant. Validate the reference boundary, even for privileged writes.
- Native table permissions require an authenticated actor in the same tenant,
  the current stored operation permission, and the relevant ownership/reader
  relationship. Remove `visibility` as an authorization bypass and authored
  field. Frontend filters can narrow scans, but cannot supply isolation.
- Replace large descendant arrays with a protected authorization closure if a
  small native probe proves exact-key membership, event maintenance, deletion,
  diamond paths and revocation. Closure reads expose only the current actor's
  outgoing authorization pairs; clients cannot write the closure. A tenant
  revision fences concurrent DAG changes. Keep direct-parent role semantics.
- Token context may carry small identity metadata. Stored permissions and
  enabled-login state remain authoritative so revocation affects existing
  tokens. Do not copy an unbounded permission/ancestor graph into tokens.
- Derive one `read_by` from immediate declared reference/root owners; a later
  descendant replaces its ancestor, incomparable candidates retain the first,
  and absent candidates fall back to `owned_by`. Use explicit groups for shared
  access. Do not inherit another record's reader recursively. Graph and source
  owner edits refresh the choice through dependency backlinks.
- Index membership may explicitly opt out of reader inheritance with
  `@rebase-tree-no-reader`. Tenant/owner analytics is design-authored. The
  [developer blueprint](developer-blueprint.md) is the current authoring route.
- The framework uses the custom tenant tree for username/email/phone/passkey
  identity keys. Generic native lookup indexes are no longer generated;
  authored indexes and concrete private runtime/view lookup indexes remain.

## Ordered data and aggregate boundary

Declare the exact key atom types and duplicate policy at the root. Nodes declare
the finite root/slot targets; schema compilation rejects inconsistent key
domains and unbounded/invalid participation. Extend the existing key algebra
to needed scalar/composite ordered values without coercing integers or decimals
through JavaScript numbers. Seek, range, rank and cursor comparisons share the
same ordering. Preserve stable slot identities and rekey/delete rollback.

Logical uniqueness is enforced inside the tree mutation transaction using the
root's serialized revision, including updates, owner moves, and concurrent
inserts. An event doing an unfenced SELECT-before-CREATE is insufficient.

Uniformity summaries already combine a value and uniform flag. Comparing the
root summary with a required tenant/org/currency is O(1) at validation after
O(log n) membership maintenance. Direct single-parent equality is O(1) and does
not need a new tree. Adding a uniformity rule to populated data requires a
validated rebuild. Sum/count give averages; ordered summaries/rank give order
statistics. Stored aggregate data must remain private unless deliberately
published by a domain field.

## Calculation dependency order

The user's final clarification requires dependent fields to follow their actual
dependencies, regardless of public field names or declaration order. Keep the
existing `@rebase-derived` topological resolver and its private numbered CREATE
helpers; they already implement that contract for directly expressed local
dependencies. Native unannotated VALUE expressions and dependencies hidden in
helper bodies do not automatically gain that guarantee. A native CREATE formula
uses the guarded `fn::tree::read` API for a prefix; private traversal helpers
remain available to privileged maintenance and validation.

Cross-record dependency propagation and managed-output lifecycle order are
separate concerns. Direct typed `REFERENCE` fields between managed-output tables
define the supported prerequisite graph. The compiler creates prerequisites
first and removes dependents first, independently of table/file names or schema
order. It rejects cycles, including self-reference, rather than guessing an
order from actual rows. Other ordinary references do not become calculation
edges. Managed outputs may own trees, but cannot own another required-output
recipe. Their cleanup checks current node counts; publication and final guards
remain at the outer source transaction boundary.

## Accounting organization

Keep economic identity separate from authorization ownership and tenant. Keep
real, receivable and payable as independent contributions chosen by the developer;
one tree may maintain several measures, or separate roots may provide distinct
ordering/validation. A table is not required to participate in all three.

Audit the implemented sales/purchase delivery, invoice, tax, withholding,
currency and settlement chains. Delivery-level tax calculation must have
explicit source provenance and may contribute to invoice validation and tax
accounts simultaneously. Preserve same-timestamp settlements, compound tax
dependencies, decimal currency checks, required children and rollback. Do not
relabel an invoice-based formula as delivery-based without changing and probing
the corresponding dependent lifecycle. This is a calculation engine; statutory
filing/compliance behavior is not being invented.

## Authentication and runtime

Email/phone identities have `owned_by: rebase_user`, a derived tenant, normalized
address/number, and per-tenant uniqueness. Login identifies a tenant explicitly
or through a trusted tenant-specific entry point. The same email can belong to
two different tenants. Username compatibility must follow the same scope.
Authenticate only enabled users through a verified credential. Audit actual
passkey support before claiming it exists; a WebAuthn implementation must verify
challenge, RP ID, origin, signature, credential ownership and replay, using an
established verifier rather than accepting a credential ID as proof.

Runtime process configuration selects one design connection. Request/job paths
carry record identity and tenant where the external boundary needs it. Never
take arbitrary database routing from the client. Credentials, challenges,
provider objects, receipts and idempotency keys retain tenant ownership where
their external identifiers can collide. Tenant-level delivery configs can be
shared within that tenant; cross-tenant service use requires an explicit trusted
binding. No live provider deployment is needed for local acceptance.

## Execution and acceptance

1. **Recover and plan:** inspect both Git repositories and the current handoff;
   prepend a compact replacement continuation to the pasted context while
   preserving its history. Record unresolved boundaries here before code edits.
2. **Feasibility:** acquire SurrealDB 3.3.0 locally; probe exact-key closure reads
   under real record permissions, composite ordering/uniqueness, and tenant
   derivation. Record failures and use the user's correctness-first fallback
   for optional query optimizations.
3. **Core slices in parallel:** tenant/auth principal maintenance; typed tree
   extensions; single-design runtime. Integrate compiler tenant/reference rules,
   root-derived readers and removal of visibility. Review shared interfaces
   before broad source changes.
4. **Domain and tooling:** migrate authored schema/fixtures to explicit duplicate
   policy and tenants; scope table-local unique indexes; repair accounting tax
   provenance where required; update development seeds and public contracts.
5. **Validation:** deterministic builds for all profiles; native schema validation
   on 3.3; meaningful record-token cross-tenant and revocation tests; tree source
   oracle/rekey/delete/concurrency regressions; accounting lifecycle/rollback;
   runtime scheduling/receipt/admission checks. Run the required full backend
   verification after focused checks pass. Preserve failure evidence until fixed.
6. **Completion:** update handoffs, developer examples, frontend continuation and
   dated evidence with exact commands/results. Commit one coherent validated
   backend change when complete. No remote push or live deployment is requested.

Frontend follow-up removes tenant selection through NS/DB, adds explicit tenant
login/session identity and tenant-aware query cache keys, uses bounded tree pages
for declared sort paths, and retains direct Solid/SDK modules. Until updated,
the old frontend is not claimed compatible with the new backend contract.

## Working status

- Baseline: ReBase `eb001a2`, initially clean; MetaSol remains a separate,
  unchanged Git repository. This is a backend change with a deferred browser
  compatibility packet.
- Local SurrealDB upgraded to 3.3.0 and pinned by `.surreal-version`; the old
  binary is preserved locally. No deployed database or provider was changed.
- The 2026-10-04 source review recorded 141 tracked modifications and 17 untracked
  files. The 2026-10-05 execution resumed 145 tracked modifications and 19
  untracked files, preserving that implementation and its baseline diff.
- Aggregate-view privacy, managed-output dependency order, authenticated tree
  reads, nested references, delivery taxes and initial live recovery now pass
  integrated regressions. All three builds, full backend/accounting suites,
  positions and mocked refunds passed, including 26 developer-tool tests and
  syntax checks for 84 changed/new JS files. Exact command/source relationships
  are recorded in the dated evidence; only an isolated H7 probe changed after
  the retained build/backend passes.
- Keep the documented 3.3.0 unindexed ID-order source-scan workaround. MetaSol
  remains clean at `ada483e` and requires a subsequent compatibility packet.
  Live providers, production deployment/migration and capacity are excluded.
  Next action: lead review of the local backend commit and recorded evidence.

## Daily developer route

1. Declare a normal table and fields, ownership and references. Tenant and common
   audit/security fields are generated; provision the tenant explicitly.
2. Add only the independent ordered memberships needed for sorting, aggregation
   or validation. Declare root key types and duplicate policy; use stable slots.
3. Author ordinary membership/validation functions and any required managed
   output recipe. Keep pure calculations separate from durable provider work.
4. Publish only the fields/tree paths a client needs. Use native table indexes
   for local lookups; use a shared tree when several source tables truly share
   one ordered/unique domain. Permission predicates do not imply an indexed
   candidate scan, so retain useful explicit filters.
5. Prove a small success, rejected-write rollback and tenant/reader case. Build
   all affected profiles, run the focused probe, then the integrated verification.
   Batch linked-member deletions as sequential single-record statements inside
   a transaction; broad DELETE of linked rows currently rolls back safely.

The [ordered-tree contract](ordered-tree-contract.md) is the declaration and
query reference. The [runtime contract](single-design-runtime.md) is the task,
credential and callback reference. Frontend continuation lives in
[its migration packet](../frontend/continuation-prompts.md#tenant-backend-migration--next-required-packet).
