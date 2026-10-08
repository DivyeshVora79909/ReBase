# Ordered tree development contract

ReBase uses **intrusive, augmented ordered trees** as maintained indexes over
business records. A table describes a kind of entity or contribution. A record
may contain several node slots, each contributing to a declared root. Ownership,
business references, tree membership, and causal dependencies remain separate
relationships. Native SurrealDB indexes remain useful for table-local lookup;
the custom tree adds cross-table ordering, exact summaries and synchronous guards.

## Schema and identity

A root is `(root record ID, root field)`, such as `account:cash/z_position`.
A node is `(source record ID, node field)`. Its `owner` link points directly to
the root, independently of its AVL parent and the source's `owned_by` principal.
Rotations change structural links, never business ownership or dependency links.

```surql
DEFINE FIELD identifiers ON directory TYPE object
    COMMENT '@rebase-tree-root @rebase-tree-key string';
DEFINE FIELD directory_node ON email_identity TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key string @rebase-tree-owner directory.identifiers';
```

The source table declares its ordinary `@rebase-members fn::...` provider. That
pure function returns entries made with `fn::tree::ordered_member`:

```surql
fn::tree::ordered_member($row.id, 'directory_node', $row.directory,
    'identifiers', [$row.normalized_email], {}, {})
```

The developer defines normalization, required fields, and the allowed root types
in ordinary schema. Roots and nodes must declare the same ordered key types.
Allowed atomic types are `datetime`, `int`, `decimal`, `string`, `record`, `bool`,
and `uuid`; a composite declaration has an explicit list of comma-separated components,
for example `@rebase-tree-key record,string,datetime`. Each position keeps its
native type. Integers use the exact JavaScript transport range; decimal inputs
must be native decimals. Float and mixed-number domains are deliberately absent.
Business keys have 1–16 components, enforced by compiler and runtime. The two
internal tie-break components do not count toward this limit. Node membership
count is independent of key width. Sixteen components pass; seventeen reject.

Principal records may hold design-declared roots; the compiler generates their
maintenance events without replacing principal permissions. On a node,
`@rebase-tree-no-reader` excludes that membership from `read_by` candidates while
preserving all tree integrity and aggregate behavior. See the
[developer blueprint](developer-blueprint.md) for explicit analytics and the
private cross-table authentication index.

The stored key is `[business components..., canonical source ID, slot name]`.
The last two strings come from the database; callers retain returned keys as
cursors rather than rebuilding them from a client library's ID formatting.
Nominal values can be unique keys themselves or partitions before another
component. They do not require an artificial timestamp.

## Uniqueness and multiple positions

Roots are **unique by the complete business key by default**, across every
declared source table. `@rebase-tree-duplicates` on the root explicitly permits
equal business keys. Nodes inherit the selected root's policy. Existing temporal
and ordinal roots declare duplicates, because simultaneous transactions and
equal ranks are valid; the source/slot suffix gives them a stable full order.

Unique insertion checks the business key along the same AVL search path. Every
write also touches the shared root revision, so concurrent conflicting inserts
cannot both commit. A caller may need to retry a definite transaction conflict;
an unconfirmed network response is not permission to replay a write blindly.

On duplicate roots, coincident slots from the same source and the same complete
business key coalesce into one net contribution. The first schema-declared slot
represents it. Distinct keys remain distinct positions, including two effective
dates from one source. Unique roots reject duplicate business keys even when two
slots belong to the same source. Deleting a source repairs all its cached slots.

## Queries

Queries run on the server in one call, using balanced search followed by stored
`next` or `prev` links. A bare linked list alone would not give logarithmic seek.

Use `fn::tree::read` in authored VALUE/COMPUTED expressions that run under record
permissions, including the native CREATE phase of `@rebase-derived` fields.
The private `before`, `range` and storage helpers are for privileged maintenance
and validation. The public reader also accepts authenticated system sessions:
when no record `$auth` exists, native permission on the private root getter
distinguishes a system connection from a guest. Anonymous calls remain rejected
even on a server that allows guest queries; there is no caller-supplied bypass.

```surql
-- Cross-table exact business-key lookup; returns a node link or NONE.
RETURN fn::tree::read(directory:main, 'identifiers', 'find', ['a@example.test']);

-- First 50 items. Each item contains { link: { rid, slot }, key }.
RETURN fn::tree::read(account:cash, 'z_position', 'page', [50]);

-- Continue with the previous result's next key, preserving native key types.
RETURN fn::tree::read(account:cash, 'z_position', 'page', [50, $next]);

-- Reverse order, or seek the first node at/after a typed key boundary.
RETURN fn::tree::read(account:cash, 'z_position', 'page', [50, NONE, true]);
RETURN fn::tree::read(account:cash, 'z_position', 'seek', [[d'2026-10-04'], false, true]);
```

`page` accepts `[limit, after?, reverse?]`, with a limit of 1–200. `after` is an
exclusive key boundary. `next` is the last returned full key when another page
exists; otherwise it is absent. `revision` detects intervening tree writes but
does not promise a snapshot across requests. `seek` accepts
`[key, reverse?, inclusive?]`; partial keys are lexicographic lower boundaries.
`find` accepts exactly the business components and returns the first tie on a
duplicate root. Existing `summary`, `before`, `range`, `rank`, `select`, and
`percentile` operations retain their contracts. Range bounds are `[lower, upper)`.

The root table and root-slot select policy authorize aggregate operations.
`summary` reads the cached root aggregate directly and can include private
member contributions, so a root owner or declared reader may request it without
being able to read every source record. `before`, `rank`, and `range` also return
aggregates and may use cached subtree summaries. They require node traversal and
can fail when a native table or field permission blocks a node that the query
must read. A query never skips an unreadable node and silently changes its
result. Root access is the publication boundary for aggregate results.

Operations that return a source link (`seek`, `find`, `select`, `percentile`,
and `page`) also check the member's exact root owner, tenant, source-table select
permission, and node-slot select policy before returning it. They fail the
whole operation when a selected member is unreadable; they do not skip private
members and silently change rank or page order. The public reader keeps raw
traversal inside `fn::tree::read`; low-level `fn::tree::*` slot and traversal
helpers remain private. Fetch selected business fields from returned links
through ordinary record permissions.

Grouped materialized views have their own explicit
[record-scoped or tenant-published policy](tenant-authentication.md#materialized-aggregate-views).
Tree root access does not grant access to an unrelated view or its source rows.

### SurrealDB 3.3.0 source-scan limitation

The multi-reader required-output fixture returned three rows (`spare`, `main`,
`spare`) from an indexed `SELECT ... FROM a_recipe_compound ORDER BY id`, although
the stored source contained two records. The same query with
`WITH NOINDEX ORDER BY id` returned the two correct rows, as did an unordered
scan. The retained reproduction is
`/tmp/rebase-tenant-tree-20261005-vmr9wyb4/managed-root-auth-scan.log`.
The smaller isolated reproduction was inconsistent, so this evidence does not
identify the engine's internal cause or establish that every indexed sort fails.

Required-output and delivery-tax source oracles explicitly use
`WITH NOINDEX ORDER BY id` to preserve complete, deterministic snapshots.
Do not deduplicate query results to hide this discrepancy. For affected native
ID-ordered source queries, retain the primary scan until a verified engine fix
or equivalent query proves correct; it can cost a table scan. Declared tree
pages use their own typed traversal and permission checks. No database upgrade,
blanket index removal, or performance claim follows from this workaround.

## Validation and readers

Every maintained membership checks that source and root have the same tenant.
The common record contract makes tenant immutable and derives it from ownership.
Changing ownership inside one tenant is independent of changing root membership.

An exact tag summary records `{ value, uniform }`. A developer can require all
deliveries to have one organization/currency by making every contribution supply
that tag and checking both `uniform` and the expected value on the published
root. A missing tag is omitted rather than treated as a mismatch: required-tag
presence is part of the developer's schema/provider contract. Counts, sums,
extrema, and ordered prefix summaries are maintained along repaired paths.
Average is a chosen measure's sum divided by the corresponding count; an ordinal
code is not automatically a meaningful numerical measure.

Complete-timestamp balance/capacity guards and prefix-dependent calculations
remain specific to a pure `datetime` key. A composite partitioned tree is an
ordered index; its first component must not be mistaken for global chronology.
The existing published-basis and required-output boundaries still prevent
aggregate feedback and preserve atomic dependent lifecycle.

`fn::rebase::tree_roots(row)` extracts actual root IDs from the row's maintained
slots. Reader sources combine these roots with explicit immediate reader links;
readers inherit each root's `owned_by`, never its entire readers array. This
works for different source/root owners without recursive inheritance or a walk
through AVL parents. Pure slot metadata and root extraction are callable during
native record-user field evaluation; mutations and membership providers remain
private.

## Cost and mutation boundaries

With `m` memberships, a source change repairs roughly
`O(sum(log(n_i)))` tree paths before required outputs and dependent refresh.
Root equality checks are constant work after the summaries are repaired. A page
visits `O(log n + k)` records and returns at most 200 items. SurrealQL's bounded
array construction and per-record storage operations still have real overhead;
these bounds are not a latency benchmark. Historical dependent suffixes can be
large, so neither `m <= 12` nor a small dependency fan-out is guaranteed by the
engine: those are developer-controlled design budgets.

Use single-record mutation statements for linked sources. A direct multirow
`DELETE table WHERE ...` can tombstone several linked records before their
individual events run; the runtime has only the current record's detached image
and rejects that operation. The probe verifies complete rollback. For atomic
batch deletion, choose the IDs first, then issue one delete per record inside a
transaction:

```surql
BEGIN TRANSACTION;
FOR $rid IN $selected_ids { DELETE ONLY $rid; };
COMMIT TRANSACTION;
```

The ordered-tree probe reconstructs topology, chronology and summaries from
authoritative source fields. It covers exact decimals, composite and nominal
keys, multiple source tables/slots, key/owner changes, same-key coalescing,
bounded pages, unique conflicts, currency/tenant rollback, concurrent writers,
schema reapplication, and the batch-deletion boundary. Temporal/typed/positions
probes separately retain causal, instant-summary and record-user ACL coverage.
