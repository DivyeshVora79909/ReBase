# Frontend architecture

[MetaSol](../../MetaSol/README.md) is a JavaScript/JSX application using Solid,
TanStack Solid Router/Query and the native SurrealDB SDK. Accounting demonstrates
ordinary routes, explicit data functions and a small set of shared UI components.
The [screen contracts](screen-contracts.md) map all 43 public accounting record
types. The [execution plan](execution-plan.md), [verification](verification.md)
and [deferred work](deferred-work.md) describe delivery scope and its limits.

## Composition and ownership

| Owner | State and responsibility | Lifetime |
| --- | --- | --- |
| `Application` | Validated public configuration, router, QueryClient, token-storage adapter | Browser application |
| `WorkspaceProvider` | One SDK client, connection status, reconnect/disposal | Resolved connection and tenant identity |
| `SessionProvider` | Record authentication, verified principal, storage mode, epoch | Authenticated account in that workspace |
| `NotificationsProvider` | Recent activity, unread state, announcement and toast | Current authenticated session, in memory |
| `PreferencesProvider` | Appearance, accent, density, time zone, compact navigation, default token mode | Device, with memory fallback |
| Route component | URL filters, page/view, explicit reads, open editor selection | Mounted route |
| Form component | Input values, original record/version, stable create ID, dirty/error state | One opened editor |

[`Application.jsx`](../../MetaSol/src/app/Application.jsx) and the providers own
shared lifetimes; `src/routes/` composes pages; `src/data/` contains queries and input
encoders; `src/ui/` contains repeated interactions. Business modules use these
pieces directly. Runtime configuration supplies connection profiles, not schemas,
menus, form descriptions or plugins. A new domain normally adds routes and a data
module. It does not require a provider, resource registry or query language.

## Connection and session identity

URLs are `/w/:profile/:tenant/…`. Each public profile fixes endpoint, namespace,
database and record access method. [`runtime.js`](../../MetaSol/src/app/runtime.js)
includes profile ID, engine, normalized endpoint, design context, access and tenant
in the workspace identity. A profile label is not sufficient token/cache scope.
The workspace route keys the provider tree by that identity and disposes the old
client and its cached queries/mutations when it changes.

Password sign-in supplies the tenant. Restoration and sign-in validate token
scope and load the principal through a native tenant-equality check. Only that
check establishes the canonical tenant RecordId; routes and token keys then use
it. Transient verification failures retain credentials for deliberate retry;
rejected or expired sessions clear them. `session.can()` controls visible actions;
record permissions and reference checks on the database authorize every request.

A query key starts with `['workspace', identity, epoch]`. Authentication changes
rotate the epoch and clear its previous queries, mutations and notices.
[`queries.js`](../../MetaSol/src/app/queries.js) captures SDK/session identity
before work and checks it on completion. Successful mutations invalidate that
session's queries. Reconnect invalidates workspace reads. Cancellation suppresses
obsolete UI results; it does not undo a committed database write.

Tokens can use memory, tab or device storage through the scoped adapter. Storage
changes remove the old copy and report fallback. Preferences have separate
storage. Financial drafts and query results are not persisted.

## Explicit reads and references

Data modules project the fields their pages need, bind user values and apply
`tenant = $auth.tenant`. Interpolated table/order fragments come from finite local
choices. Sorted source scans use `WITH NOINDEX` for the documented native ID-order
scan issue; they do not hide duplicates with client deduplication. Regular lists
fetch 26 rows and display 25, with a sentinel for Next and no guessed total.

[`references.js`](../../MetaSol/src/data/references.js) is a finite lookup
allowlist, not domain metadata. Searches fetch 13 choices and display 12;
hydration accepts at most 50 selected native references. Labels are separate
from raw IDs. A copied record reference is parsed natively before an exact ID
match, because SDK/server quoting differs; ordinary name searches need no extra
request. Only malformed-conversion errors fall back to text search. A page-specific
picker search binds its invoice/note/source filter
and supplies a matching reactive `scope` prop. The picker includes that scope
in its query key, so changing the parent selection changes the cached search.

Query callbacks receive the actual SDK, the same input used in their key and an
abort signal. Guard Solid Query's suspending `data` getter while pending when
controls must retain focus. A failed refresh can display the current session's
cached rows with an error; results never cross a session boundary.

## Authored forms and write confirmation

[`SourceForm`](../../MetaSol/src/ui/SourceForm.jsx) shares the write lifecycle.
The caller supplies `table`, optional `record`/`initial`, `encode`, callbacks and
explicit JSX fields. Its shallow signal preserves native SDK values. The encoder
whitelists authored inputs; owner selection is composed once by SourceForm.
Derived balances, amounts and tree state remain server-owned. Callers disable
immutable dimensions and pass `immutable` fields to omit them from updates.

Open an editor with a stable table and original record snapshot. Key its owner
by that selection, not the latest refetched row. This keeps dirty drafts intact
and preserves the original `updated_at` for optimistic concurrency. A create ID
is generated once per mounted form and survives failed submissions.

[`writes.js`](../../MetaSol/src/data/writes.js) uses native transactions, exact
one-row assertions and `updated_at` checks; deletes return the removed row with
`RETURN BEFORE`. Every SDK statement response is inspected before accepting the
single returned native ID. Empty transaction slots are not success evidence.
After 20 seconds without confirmation the result is unknown. `FormError` retains
the draft reference and offers a reviewed current-record inspection. A found row
must be compared with the draft; absence can mean lost access or pending work.
Writes are never automatically retried, and balances are never optimistic.

SourceForm protects dirty/pending navigation and busy dialog closure. Session
fencing prevents old-account callbacks. Its mounted flag additionally prevents a
completed save from navigating or changing local state after its editor unmounts.
A confirmed write can still invalidate data and publish a notice in its unchanged
session. A late failure in that same session publishes its exact record reference
and a manual inspection action; an old session cannot publish into a new one.
Leaving an editor never promises to cancel the server transaction.

## Native units, time and tree reads

Controls keep exact decimal text; encoders use native Decimal, RecordId, Date and
Duration. Use `undefined` for optional NONE values; preserve explicit zero/false.
Never JSON-round-trip native values or convert financial amounts to Number.
Date controls use device-local time with milliseconds, while display may use the
selected time zone. Saved dates are absolute instants.

Recorded account positions include the complete timeline, including future facts.
Historical balances use `fn::tree::read(id, 'z_history', 'before', [instant])` and
exclude the boundary instant. History pages carry full typed keys and a separate
revision; the route restarts paging when an observed revision changes. Analytics
uses typed half-open ranges and sums compatible units only. Published analytics
summaries follow root visibility policy; they are not a per-reader sum of visible
source rows. See [screen contracts](screen-contracts.md) for exact semantics.

## Small extension seams

Notifications currently contain up to 30 recent updates from this sign-in, with
announcements, dismissal and local unread state. Forms keep actionable errors;
connection status stays in WorkspaceProvider. A durable inbox needs a public
recipient/read-state backend contract, explicit data functions and reconnect
catch-up. Live subscriptions would be owned by their route/query with disposal
and targeted invalidation. Neither durable nor live notifications is implemented.

Gateway recovery, OTP or passkeys can add ordinary auth routes and functions in
`src/data/auth.js`, then feed native tokens through the same tenant verification.
Those frontend flows are deferred. Navigation docking belongs to the shell,
preferences and CSS; another application should share proven modules and author
its own routes. See the [developer guide](developer-guide.md) before extending.
