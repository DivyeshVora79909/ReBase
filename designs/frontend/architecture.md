# MetaSol architecture

MetaSol composes Solid, TanStack Router/Query, Kobalte and the native SurrealDB SDK.
The accounting profile demonstrates connected calculation facts, sparse native
positions and explicit workflows. The baseline for this redesign is ReBase
`ebe999d`; October 8 frontend assumptions are replaced.

## Ownership and lifetime

| Owner | Responsibility | Lifetime |
| --- | --- | --- |
| Application | Public configuration, router, QueryClient, component overrides | Browser application |
| WorkspaceProvider | One SDK connection and reconnect/disposal | Endpoint, fixed namespace/database, access and tenant identity |
| SessionProvider | Verified principal, tokens, epoch and completion fences | Authenticated session |
| NotificationsProvider | Confirmed activity and unconfirmed-write inspection | Current session, in memory |
| PreferencesProvider | Runtime appearance plus device-local overrides | Application/device |
| ScopeProvider | Selected subsidiary | Mounted authenticated workspace |
| ComposerProvider | Flat stack of mounted forms | Current route and session |
| SourceForm | Native draft, original version, stable create ID, dirty/error state | One editor |
| RecordCollection / RecordPicker | Query input, native cursor history and display state | One mounted control |

A feature normally adds an ordinary read callback, route or contextual action.
It does not register a resource, invent a query language or add a provider per
table. The shared modules handle repeated boundaries; business workflow decisions
remain explicit.

## One public input contract

`MetaSol/client-contract.js` consumes `build/all-in-accounting/schema.surql` and
`client/schemas`. It reuses the parent model loader instead of maintaining a
second schema parser. The ignored generated client bundle contains the exact
published JSON Schemas plus native input bindings, readonly flags, readable
field names, native references and public root/member metadata. Server functions,
credentials and private roots are not published.

`createInputModel()` compiles validators once. `prepare(table, input, {original})`
rejects unknown fields, validates the complete input, preserves native SDK values
and omits readonly dimensions from an update. Blank optional values are omitted
on create and cleared with native NONE on update. Generated constraints improve
feedback; database assertions, authorization and reactive calculations remain
authoritative. Presentation labels, section order and contextual suggestions are
ordinary frontend code.

## Read capabilities

Direct identity reads use bound native record IDs. Business lookups follow
declared inverse references. Catalog candidates follow ownership references from
the authenticated principal, its groups and its explicit authorization closure.
Generated tenant fields are not native REFERENCE fields; tenant backlinks are
not assumed. Principals are read through the authorization closure directly.

Declared public roots use `fn::tree::read`. Pages retain every native key
component and membership slot, hydrate identities, and restore traversal order.
Filters examine bounded visited candidates; empty filtered pages preserve their
next cursor. Changed root revisions require an explicit restart. Exact IDs in an
indexed picker use the public member-value reader to verify membership rather
than walking preceding pages or guessing a business key.

Read callbacks receive the same snapshotted identity and arguments that keyed
their request. A revision is checked when a page is fetched; cached pages are
not a live feed. Page traversal and identity hydration are separate reads, so
this surface does not promise a frozen database snapshot.

Composite browsing requires a typed leading prefix. A forward walk starts from
the partial key and stops when keys leave that partition. Reverse browsing is
available without a prefix; reverse prefix walks are rejected because the public
API has no generic upper-bound sentinel. Current accounting public roots have
single business components; private identity/composite roots remain private.

Inverse-reference lists are bounded lookup surfaces with no pagination claim.
They have no arbitrary sort or offset fallback. Bounding returned candidates
does not make traversal of an unbounded backlink constant-time. Add another
declared tree only for a demonstrated access pattern.

## Connected forms

Kobalte owns combobox keyboard and listbox behavior. The picker supplies async
rows, selection hydration, exact-ID parsing, scope identity and explicit
loading/error/empty states. It retains selected options while their query
refreshes. Pending Solid Query data is never read in a way that suspends and
detaches the form. Scope changes and selection dependencies fence old results.

Creating a prerequisite pushes a new editor onto a flat stack. Parent drafts
remain mounted. A successful child save returns its native identity; the user
still submits the parent explicitly. Known parent fields initialize the child.
Background principal refreshes retain drafts; route/session boundary changes
clear them. Native dialogs restore focus after a child closes.
Dialogs use a stable portal under their application's theme root; reactive
route rendering cannot move an open dialog out of the browser's modal layer.
Conversion assistance follows actual backend directions: invoice payments use
treasury currency → invoice currency; transfers use outgoing → incoming native
unit. Rates are dated, and inverse pairs are independent.

SourceForm keeps one create ID and the originally read `updated_at`. Transactions
inspect every SDK response and require exactly one confirmed native ID. A
20-second confirmation timeout is an unknown outcome, with inspection of that
same ID before retry. No automatic write retry or optimistic financial balance
is used. Native rejection and stale-version errors leave the draft intact.

## Isolation, appearance and limits

Query identity includes normalized endpoint, fixed namespace/database, access
method, canonical tenant and session epoch. Authentication changes clear prior
queries, mutations and notices. Read and write completion checks suppress old
session callbacks. Leaving a form does not promise cancellation of server work.

Theme tokens come from public runtime configuration plus user overrides. Color
mode, accent, density, navigation, radius, typeface and display time zone are
configurable. Portals mount inside their owning native dialog or theme root.
Ordinary JSX props replace Input/Textarea/Select/Reference primitives or a named
field renderer while retaining the schema and write boundary.

This is a connected frontend harness, not an offline sync engine, a persistent
notification service or an arbitrary-database abstraction. See
[deferred work](deferred-work.md) and [verification](verification.md).
