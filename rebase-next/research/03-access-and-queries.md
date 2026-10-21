# Current authority and bounded indexed queries

**Status:** semantic proposal, 2026-10-21. Preserve the latest reader correction
and current graph semantics. Transport and cryptographic authentication are future
infrastructure; the proof exercises only scoped merge behavior and reader choice.

## 1. Identity and access

Authentication proves identity; authorization determines permitted operations.
Tenant/user/group records may serve both, but a graph edge is not an identity
proof. Use a mature verifier or identity provider. Verify token signature, issuer,
audience, expiry and intended service context before trusting its subject.

Tokens should identify an actor/session and may narrow allowed operations. Load
current tenant, active session policy, roles, direct parents and graph reachability
inside each transaction attempt. Do not copy mutable authority into long-lived
token claims and call it fresh. Request-local caching can remove an extra
cross-request permission cache/revision scheme when each attempt reads current
authority and protects those reads. Immediate session revocation remains an
explicit stored-state or lifetime policy.

Freshness has a defined time boundary: a read uses current authority from its
data snapshot; a write protects authority through commit. An overlapping read
may finish after a revocation with a snapshot that precedes it. See the
[authority wireframe](07-contract-wireframes.md#6-authority-has-a-time-boundary);
per-attempt caching alone does not implement response-time revocation.

Server-owned operations choose permitted scope and behavior. A client may receive
query descriptions or ergonomic wrappers, but cannot enforce restrictions on
itself. Signed executable code/policy inside a token would create another versioned
interpreter; verified identifiers and optional capability restrictions suffice.

## 2. The principal DAG

Preserve tenant-scoped acyclicity, same-tenant parent checks and alternate paths.
The current `can_access(a,p)` means `a == p`, an authorized **direct** group/tenant
parent `p`, or `p` is a strict descendant of `a`. Direct group membership does not
grant sibling-member access. Operation/field permissions still apply.

Current users inherit direct tenant/group roles; user-parent edges contribute
ancestry rather than copying that user's role. Groups keep explicit roles.
Creating/reparenting principals cannot assign authority the actor lacks. Graph
control-plane updates and role changes use an explicit conflict boundary.

Materialized reachability favors reads and retains sparse average storage, but
can be quadratic. A diamond needs alternate-path-safe deletion. Exact closure
pairs can serve point access; enumeration of descendants needs an adjacency/index
path. Reuse the established DAG model initially, rather than adding an independent
Cedar/OpenFGA service and a second authority store. A different policy engine is
useful only when its semantics replace concrete complexity without breaking
transactional freshness or requiring duplicated scope indexes.

## 3. Readers and owners

The final user follow-up restores the need for a reader index. Keep:

`read permission → read_by` and `write permission → owned_by`.

`read_by` is a derived selected immediate principal, not a recursive list of every
ancestor or a universal DAG minimum. Its current deterministic fold is:

1. Collect immediate owners of marked references in declaration/array order.
2. Collect immediate owners of eligible active roots in slot declaration order;
   a principal root contributes itself. Visibility-neutral analytics/dependency
   slots do not contribute a reader.
3. Starting with the first candidate, replace it only when it strictly dominates
   the next. Equal/incomparable candidates keep the selected value. With no
   candidate, use the record owner.

Preserve that explicit order; sorting candidate names changes policy. Incomparable
branches do not receive union visibility. Explicit sharing groups solve deliberate
shared access; a multi-reader extension needs its own declared semantics/indexes.

Changes to candidate references, their owners, active roots or relevant DAG edges
must repair reader choices and their candidate indexes atomically. Access-root
membership itself must not feed back into reader selection. Adding analytics
must not change record visibility.

`read_by` supplies visibility. It does not explain which calculation changed an
aggregate. Inspection of dependency/contribution provenance supplies that
explanation without requiring permanent past-event history.

## 4. Query inventory follows real access patterns

Stable primary record IDs do not require owner/time suffixes. A point lookup
loads the record, resolves its contract and enforces tenant/operation/field rules.
All remaining access paths are declared indexes or references.

| Access path | Reason | Initial scope |
| --- | --- | --- |
| UUID → record | Point get/write/existence and reference validation | Required |
| Principal adjacency and exact reachability | Current graph authority | Required for DAG |
| Reader + contract + order | Complete authorized lists under scalar-reader policy | Required for each supported reader list |
| Direct reverse reference | Recalculation, delete/link integrity and reader repair | Required where those features use it |
| Ordered reverse query | Locate range/selection dependents by root and channel | Required for declared queries |
| Business root/member projection | Domain ordering, uniqueness, summary and guards | Declared by design |
| Owner + contract + order | Owner lists/bulk mutation candidates | Only when exposed |
| Tenant + contract + order | Wide tenant query with low merge fanout | Workload tradeoff |
| Tenant + creation order | Cross-contract activity/analytics | Optional explicit index |
| Session/identity/effect due-time | Lookup/revocation and durable dispatch | When those capabilities are added |

A root may encode partition identity `(tenant, reader, contract, index)` while
nodes compare only `(time, UUID, slot)`. This is not a recommendation to maintain
every possible combination. A composite key is one membership; 20 distinct
maintained projections are 20 memberships. Broad tenant indexing trades more
write work/root contention for fewer partition seeks. It is not redundant merely
because a merge can construct the same result.

Root/member node representations can omit repeated partition metadata only when
the root association is explicit and integrity checked. Tenant isolation is a
logical check, regardless of prefixes. A key layout by itself grants no access.

## 5. Streaming merge and budget semantics

Use one traversal for one root. For several accessible reader partitions with
the same full comparator, deduplicate the principal set, open one stream per
partition and retain each next item in a min-heap. Pop the minimum and advance
that stream. Refill small buffers on demand; do not prefetch a full page per
partition by default.

For `K` partitions and `V` visited candidates, cost includes scope discovery,
`Σ log(n_i)` seeks, `O(V log K)` heap work and hydration/predicate work. Memory
includes the scope plus `O(K * buffer_size)`; it is not constant independent of
authorized principals. K-way merge produces ordered union, not arbitrary bitmap
intersection. Bitmaps require a separate dense identity/rank map and introduce
their own update/lifetime costs; omit them until a workload warrants them.

Partition setup needs a budget as well. Discover the complete scope and obtain
each stream head/emptiness before promising a globally ordered page. A candidate
visit budget does not bound that work. The initial wireframe rejects setup that
exceeds its fanout/work limit before returning a partial ordered result; the
current slice-based merge proof does not exercise this boundary.

Scalar reader indexes partition rows disjointly. General multi-membership roots
may overlap: decide whether output counts occurrences or distinct records. Do not
silently deduplicate a business aggregate or assume the stress fixture's disjoint
owner roots prove arbitrary overlap semantics.

Residual predicates stream over **authorized** candidates and readable fields.
They are scans, even through an index. The API may reject unsupported predicates
by default and expose bounded residual filters explicitly. Track visited count,
not only returned count. A sparse page can return no rows and a continuation.

For `exists`, outcomes are:

- Found a readable matching candidate: **yes**.
- Fully exhausted the permitted search space: **no**.
- Exhausted visit/time budget: **unknown**, with continuation.

For point-ID existence, missing and inaccessible can deliberately share one public
answer to avoid exposing private identities. Internal integrity checks distinguish
absence and denied references under engine authority. Define which operation is
being called; do not let a cheap integrity existence check bypass public access.

## 6. Pagination and field boundaries

One page reads scope, indexes and hydrated rows from one consistent attempt.
Keep full typed cursor order including ties; advance at the last **visited**
candidate so residual filters do not repeat work. A global last-visited key is
reusable only across streams using the same total order and query semantics.

The cursor binds model/order/query identity and position. Reauthorize every page;
cursor contents cannot grant access. Proposed initial policy reports/rejects
changed index/scope revisions and lets the client restart explicitly. It does not
promise one frozen snapshot across many requests. Broad stable snapshot exports
are another operation with storage-specific limits. A revision vector across
many roots costs space; a coarse revision trades invalidations for a smaller cursor.
Choose that policy before implementing general multi-page reads.

The proposed revision footprint must include relevant content/permission
changes, not just index rekeys. Editing a residual-filter field can change
membership in the result while leaving tree order unchanged. Include empty
partition insertion and reader/scope changes too. See the
[query wireframe](07-contract-wireframes.md#5-queries-order-scope-and-budget).

Field permissions apply to projection, filtering and ordering; a hidden field in
a predicate can disclose facts even when excluded from the response. Root
publication is explicit: a summary can include private contributions by design,
and is not automatically the aggregate of only visible leaves. The new runtime
may traverse private structural nodes internally after checking the root boundary,
but leaf-returning operations enforce their declared record/field policies.
This is a proposed simplification of native SurrealDB traversal limitations, not
a claim that existing public reads already do so.

Preserve occurrence/ordinal meaning on general root reads: reject a selected
unreadable member rather than silently skipping it. `records.page` over complete
authorized reader partitions is a separate record-list contract. Root aggregates
and record-list counts cannot be substituted for one another.

## 7. Mutations and references

Check the source operation/contract, client-writable fields, current owner and
permitted new owner. New references require target existence, allowed contract,
tenant compatibility and declared link permission (normally readable target).
Referencing an organization does not require permission to create organizations.

Protected internal recalculations, balance changes, tree rotations and required
outputs run with engine authority under the declared plan. They must not require
the actor to write every derived field. Allowlisting these actions is distinct
from granting an unrestricted write bypass. Return only permitted settled data.
Effect intents also have a declared authority and immutable allowlisted inputs.

## 8. Small standard-facing API

Use structured calls parsed by Serde; JSON Schema validates shape, while the model
validates names, access paths, bounds and permissions. No new textual parser is
needed. Start with `records.get`, `records.page`, `records.exists`, `records.mutate`
and explicit root `range`/selection reads. Ordinary internal functions implement
the same operations without a network round trip.

JSON-RPC 2.0 standardizes message envelopes; `jsonrpsee` implements server/client
plumbing. JSON-RPC IDs correlate messages, not idempotency receipts. Notifications
do not confirm mutations. Batches are not atomic database units; one explicit
mutation request contains the complete unit.

OpenRPC describes methods but currently specifies Draft-07 schema objects. The
model may use Draft 2020-12; exporting arbitrary schemas into OpenRPC is not a
lossless rename. Initially publish the original schemas plus a small capability
catalog; add a validated supported-subset OpenRPC export when useful. OpenAPI is
for HTTP API descriptions; GraphQL is a query language with its own execution
semantics. JSON:API provides resource conventions. These are optional adapters,
not replacements for access-path, transactional or mathematical semantics.
