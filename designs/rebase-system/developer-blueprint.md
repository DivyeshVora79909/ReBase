# Developer blueprint: records, permissions and calculation trees

This is the authoring contract, updated October 13. It accompanies the executable
[analytics design](../index-analytics/README.md),
[accounting developer guide](../all-in-accounting/developer-guide.md),
[tree API](ordered-tree-contract.md) and
[tenant/authentication contract](tenant-authentication.md).
Use [current verification](reader-index-verification.md) to distinguish exercised
behavior from an application feature you still need to build.

## Where code belongs

| Location | Responsibility |
| --- | --- |
| `framework/` | Fixed tenant/user/group DAG, authorization closure, authentication, audit and durable runtime records |
| `dev-tools/compiler/` | Parse ordinary SurrealQL and annotations; emit permissions, references, dependencies and tree maintenance |
| `designs/<design>/` | Business tables, calculations, root/node declarations, membership functions, validators and optional analytics |
| `gateway/` | Authentication/provider boundaries, durable operations, queueing and reconciliation |
| `build/<design>/` | Generated schema, contracts and client exports; rebuild instead of editing |
| `dev-tools/checks/` and `dev-tools/temporal-tree/` | Disposable functional, security, structural and rollback checks |

A deployed design has one configured namespace/database and explicitly
provisioned tenant records. A tenant is an authorization boundary. An accounting
subsidiary is a business division; an organization is its counterparty, with
explicit native currency/resource positions. These records have different
responsibilities. UUIDv7 IDs are a default identity format, never authorization.

Use native tables, scalar fields, typed references and ordinary functions. The
annotations below are the implemented contract; there is no runtime class
registry, arbitrary query planner, automatically inferred ledger or implicit
business-child generator.

## Start with an ordinary record

The smallest useful table can be just:

```surql
DEFINE TABLE OVERWRITE memo SCHEMAFULL;
DEFINE FIELD OVERWRITE title ON memo TYPE string ASSERT string::len($value) > 0;
DEFINE FIELD OVERWRITE effective_at ON memo TYPE option<datetime>;
```

Compile a directory with:

```bash
node dev-tools/compiler/cli.js --project designs/my-design --output build/my-design
surreal validate build/my-design/schema.surql
```

Normal design tables receive `owned_by`, immutable derived `tenant`, derived
`read_by`, `created_at`, `updated_at`, author metadata, permission checks and
reference guards. Supply `owned_by` when creating a row. `effective_at` is an
authored business timestamp; the framework does not invent it. `created_at` is
the actual immutable creation timestamp. Backdating changes the former.

Framework principals have their own graph permissions. Private framework
challenge, execution and credential tables retain their specific native
policies. The compiler does not turn them into ordinary public business tables.

## One reader, separate write authority

The default SELECT policy requires authentication, the same tenant, the table's
`<table>_select` permission and `fn::rebase::can_access($auth, read_by)`. CREATE,
UPDATE and DELETE continue to check `owned_by` and the respective operation
permission. `can_access` means self, an authorized direct tenant/group parent,
or a descendant in the protected DAG. The optional `@rebase-select owner`
profile uses ownership for SELECT instead; it still derives the same `read_by`.

`read_by` is one native principal RecordId, visible on a readable row and
protected from client assignment. Its VALUE expression computes candidates:

1. Immediate owners of fields explicitly marked `@rebase-readers`, in source
   declaration order. Reference arrays retain their authored element order.
2. Immediate owners of maintained tree roots, in node declaration order, except
   slots marked `@rebase-tree-no-reader`. A principal root contributes itself.
3. Starting with the first candidate, replace it only when it dominates the next
   candidate. Equal or incomparable candidates keep the current choice. If there
   are no candidates, use `owned_by`.

This does not preserve the union of incomparable reader branches. A writer on
an incomparable branch may lose SELECT while retaining its ownership-based
write authority. Use an explicitly shared group when several branches must read
the same record. Reordering reader declarations can change access; treat it as a
permission change. No step inherits another record's `read_by` or walks AVL
parents to discover readers.

```surql
DEFINE FIELD OVERWRITE subject ON memo TYPE option<record<customer>>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers';
```

The referenced `customer` must be an ordinary authored table. This marker does
not enroll references to framework/system tables; a principal contributes itself
when it is a maintained tree root. Unmarked references do not grant visibility.
Owner changes refresh direct reader dependents through private
reference backlinks. DAG edits recalculate choices for records linked to the
affected principals and their owned roots. These repairs commit with the source
transaction. `rebase_reader_sources` is internal dependency routing, not a
reader-principal array or a second public permission model.

## Define an index as a root and node slots

The [analytics sources](../index-analytics/records.surql) are a complete running
example. Each root declaration states its key types, uniqueness and visibility.
Each participating table declares a membership function and allowed node slots:

```surql
DEFINE FIELD OVERWRITE z_created ON rebase_tenant TYPE object PERMISSIONS NONE
    COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE TABLE OVERWRITE activity SCHEMAFULL COMMENT '@rebase-members fn::activity::members';
DEFINE FIELD OVERWRITE points ON activity TYPE decimal DEFAULT 1dec;
DEFINE FIELD OVERWRITE z_created ON activity TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner rebase_tenant.z_created @rebase-tree-no-reader';

DEFINE FUNCTION OVERWRITE fn::activity::members($row: object) {
    RETURN [fn::tree::ordered_member($row.id, 'z_created', $row.tenant,
        'z_created', [$row.created_at], { points: $row.points }, {})];
} PERMISSIONS NONE;
```

This standalone illustration uses different function/slot names from the full
example; do not load both into the same profile. A root on a framework principal
is a supported design extension. Do not redefine the principal's table policy.
Tree storage receives its default, links, fields and mutation permissions from
the compiler; do not author a DEFAULT, VALUE or manual tree PATCH.

`@rebase-tree-no-reader` suppresses only reader inheritance from that membership.
It does not publish the source, skip integrity checks or disable aggregation.
Use it for tenant/owner analytics so joining a shared index does not make every
source readable by everyone who can see tenant metadata.

The member helper arguments are source ID, source slot, root record, root slot,
business-key array, numeric measures and equality tags. Give every measure one
explicit unit. Counts are automatic. Key components are typed ordering values;
they are not summed. Tags track uniformity; use a validator if mixed tags should
reject. Never add both source postings and their own subtotals to the same sum.

Roots are unique by the complete business key unless they declare duplicates.
Uniqueness spans all tables and node slots targeting that root, inside its
transaction and tenant boundary. Missing optional keys must return NONE or omit
the member. Duplicate datetime roots admit equal-time facts. The stored suffix
`[canonical source ID, slot]` orders ties; it is not a business uniqueness rule.

Keys support datetime, int, decimal, string, record, bool and uuid components.
The compiler and runtime accept 1–16 business-key components. Seventeen are
rejected. Key width is separate from the number of node memberships on a record;
adding a tree does not add a component to another tree's key.
An index ordered by `[owned_by, created_at]` efficiently supports its leading
owner partition. It does not efficiently answer every arbitrary status or
reader predicate. Declare another index only when the query needs it.

## Query the declared index explicitly

Ordinary `SELECT ... WHERE ... ORDER BY ...` is not rewritten to use these trees.
Call the public tree API and load the returned record IDs with native SELECT:

```surql
RETURN fn::tree::read($owner, 'z_owned_created', 'summary', []);
RETURN fn::tree::read($owner, 'z_owned_created', 'page', [50]);
RETURN fn::tree::read($owner, 'z_owned_created', 'page', [50, $next]);
RETURN fn::tree::read($tenant, 'z_owner_created', 'range', [[$owner, $from], [$owner, $until]]);
RETURN fn::tree::read($owner, 'z_owned_effective', 'before', [$as_of]);
RETURN fn::tree::read($owner, 'z_owned_created', 'select', [1]);
```

The tenant-root call above requires a privileged session in the supplied design.
`before` excludes its key boundary; `range` is lower-inclusive, upper-exclusive;
`select` ranks start at one. A datetime boundary includes its complete timestamp
when read through `timestamp + 1ns`. Preserve SDK RecordId/Decimal/datetime types
and bind values. Keep returned cursor keys intact. Pages are bounded to 200;
their revision detects writes between requests, not a multi-query snapshot.

Root visibility authorizes its stored summary. Path reads and pages additionally
require permission for traversed/returned members. A public root summary can
publish facts about private children: select its policy deliberately. The sample
keeps tenant aggregates private and owner aggregates at the principal's boundary.
Internal `fn::tree::find`, `page`, `get` and mutations are private; applications
use `fn::tree::read`. No function accepts a client permission-bypass flag.

Generic native tenant/owner/reader/reference lookup indexes are no longer
generated. Authored native indexes remain possible. Materialized-view lookup
indexes and private runtime challenge, scheduling, receipt and webhook indexes
remain where those concrete consumers use them. Native REFERENCE backlinks and
the authorization relation still use SurrealDB's storage; custom trees do not
eliminate that underlying KV work.

## Authentication uses the same tree primitive

The framework's private `rebase_tenant.z_auth_identifiers` root has a unique
`[kind, normalized value]` key. Username, email, phone and passkey rows contribute
their own nodes across tables. The kind namespaces are `username`, `email`,
`phone` and `passkey`; there is no duplicate side table storing identity claims.

Native VALUE clauses normalize email/username to lowercase and trim phone
numbers. Passkey credential IDs retain case. A missing username has no node.
Rekeying, deleting and failed collisions repair or roll back the same tree.
Concurrent conflicting insertions have at most one successful commit.

Trusted password/code/OAuth/gateway/passkey paths use the private
`fn::rebase::identity(tenant, kind, value)` exact lookup. Owner identity lists use
native reference backlinks. Identity roots, nodes and lookup functions are not
public directories. Password/verification state, recent-session checks and
WebAuthn validation remain separate requirements after locating a row.

To add an identity source, declare its normalized value, immutable principal
owner/tenant, node slot and membership function targeting this root. Choose a
kind namespace deliberately. Reusing an existing kind enforces collisions across
both tables. Extending uniqueness does not automatically add a new login method;
implement and verify its trusted authentication boundary explicitly.

## Reactive calculations and validation

Use pure VALUE expressions for local calculations and `@rebase-derived` for
stored calculations over declared mutable reference dependencies. The existing
compiler resolves local dependency order; alphabetical field names are not an
execution contract. An ordinary reference or index membership alone is not a
causal calculation edge. Materialize cross-record dependencies one hop at a time.

For local field ordering, a whole `$this` row may be passed directly to a
schema-declared helper, which may access static fields or forward that row to
another declared helper. Whole-row aliases, wrappers, dynamic field access and
escaping row values are rejected because their dependencies are not proved.
Pass explicit field values for those calculations; scalar aliases and expressions
remain supported. The compiler preserves literal argument positions when
following helper parameters. See the [compiler repair record](integrity-2026-10-15/compiler.md).

For mutable reads hidden in ordinary helper functions, use
`fn::tree::read_value` or `fn::record::read_value`. The compiler captures the
executed query and maintains its reverse subscription automatically. Applications
do not define an impact function or reader tree. The [automatic reactivity
contract](function-reactivity.md) explains predecessor, prefix and range reads,
branch cleanup, transactional validation and the executable proof.

Reactive expressions and their helpers must be read-only. This applies to
derived fields, memberships, required-output recipes and validators. The compiler
rejects mutation statements, transaction/schema operations, HTTP/API calls,
scripting, dynamic helper calls and undeclared custom helpers in those paths.
Ordinary application write functions remain available outside reactive formulas;
the coordinator performs the resulting updates and managed-output writes.

For split/aggregate/use-again calculations, read a published upstream root or a
strictly prior temporal prefix. The accounting tax implementation is the worked
example: base 100 plus two 9 taxes yields 118; a later 10% net tax reads that
earlier amount. A backdated contribution refreshes the affected later readers.
Within the same tree, use a tracked strictly prior prefix; posting memberships
do not need a reader flag. Do not read a final aggregate that
contains the record's own result. Equal-time compounding and complete-timestamp
validation are distinct rules.

Put source-local constraints and aggregate constraints in explicit
`@rebase-validate fn::...` functions on their respective tables. The coordinator
repairs memberships, drains temporal dependents, publishes roots and validates
inside the source transaction. Each source statement settles before the next;
an explicit multi-statement transaction does not defer all intermediate guards.
Author changes in a valid order. Delete dependent rows before their referenced
sources and nonempty roots. Managed required outputs are a separate opt-in
contract; the accounting redesign uses explicitly authored business children.

A source with m memberships costs the sum of affected balanced paths plus
dependent recalculation. A backdated change can invalidate a large suffix.
Authorization graph closure/reader repair and shared-root contention have their
own costs. Functional tests do not establish universal throughput or capacity.

## A compact accounting extension pattern

The [accounting developer guide](../all-in-accounting/developer-guide.md)
is a worked example of choosing sparse dimensions and source participation.
Subsidiaries collect explicitly converted reporting contributions; organizations
also retain separate native currency/resource accounts. Independent claims,
adjustment documents and directed exchange contexts are explicit facts.
A deterministic payment charge is fields and memberships on its payment, using
one shared rule and no automatic child. An adjustment document only validates;
it does not repeat its children's financial effects.

Keep aggregate units explicit. A native resource account sums its own quantities;
a native currency account sums that currency. Organization and subsidiary reports
convert each event using the rate at its date. Descriptor records have no automatic
financial roots. Declare any additional composite query index explicitly. Keep
sales, purchases, gross cash, charges and taxes separate. Store additive numerator
and denominator components, then divide the selected summary. A zero denominator
means no average. Authoritative dated rates and observed trades use separate roots.

Read immutable dimensions directly when safe; materialize mutable referenced
values one hop at a time. A source's several slots at the same temporal root and
timestamp are combined by the coordinator; do not combine them again in a second
business row. Guard optional inputs before constructing a membership requiring
a concrete record. Final root validation still runs after the affected closure.
Invoice and note roots validate linear capacities and dimensions. Empty documents
are valid; the accounting profile has no draft/finalization requirement.

## Before adding a new domain

Write down its units, ownership, chosen-reader behavior, key ordering,
uniqueness, root visibility, missing-value behavior and calculation dependencies.
Copy a small source pattern from the analytics or accounting example, then prove
create/edit/backdate/reparent/delete and a complete rejected-write rollback.
Exercise record users, a second tenant, competing sessions and populated
reapplication. Keep public input schemas, examples and checks with the change.

Build artifacts must include the framework and generated tree coordinator;
loading only raw `framework/*.surql` does not install identity maintenance.
Identical-schema reapplication is tested. Applying this redesign to an older
populated schema needs a deliberate data/index rebuild and migration rehearsal;
removing native indexes alone does not backfill custom nodes. No such production
migration or deployment is included in this local source change.
