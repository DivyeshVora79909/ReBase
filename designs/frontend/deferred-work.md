# Frontend extension boundaries

The current implementation and maintained scenarios are described in
[verification](verification.md). These are future capabilities, not unfinished
prerequisites for the current accounting harness.

## Collaborative updates and scale

Writes and reconnects invalidate the current session's queries. Other users'
changes require refresh. A collaborative screen can own a native subscription,
invalidate its query, requery after reconnect and dispose the subscription with
its session. Narrow invalidation only after measuring real query volume.

Cursor revisions detect changes when another page is read. Paging plus record
hydration is not a database snapshot: hydration can see newer record values.
Cached pages are not a live feed. Full snapshot/export behavior needs an explicit
backend consistency contract.

Backlink lookups bound returned rows, not total relationship work. Add a declared
tree for a measured high-cardinality browse requirement. No table scan or offset
fallback should conceal an absent index. Current public accounting roots have
single business key components. The composable reader supports forward composite
prefixes; reverse prefix paging needs a native upper-bound contract.

## Further acceptance

Maintained native/browser checks now exist. Expand them alongside changed
behavior: role revocation during cached reads, transport loss during a real
committing write, fee combinations, cross-currency corrections and pathological
large histories. All published forms being reachable does not establish every
business-field combination or large-scale throughput.

The browser suite currently targets Chromium desktop and touch emulation.
Real-device assistive-technology audits and additional browser engines remain
separate acceptance work.

## Durable activity and authentication

Activity and drafts stay in session/page memory. A durable inbox first needs
recipient/tenant authorization, stable event identity, acknowledgement, retention
and reconnect catch-up. Worker wake-ups and private audit records are not a user
inbox API.

Code challenges and passkeys need a configured gateway/RP and explicit routes.
They should finish through the same native principal/tenant verification and
session rotation as password sign-in. Do not expose inactive recovery controls
or build an authentication plugin framework in anticipation.

## Import, presentation and other applications

Page CSV export preserves exact displayed values. Bulk export needs bounded
traversal with explicit consistency and progress. Bulk import needs generated
schema validation, review and per-record outcomes. Neither should silently hide
partial failures.

Current date entry uses device-local time and display supports local/UTC.
Localization, more layout arrangements or specialized fields can be ordinary
presentation functions, JSX overrides and CSS. Runtime appearance tokens are
already configurable.

Another compiled profile can use the contract loader and shared boundaries, but
business routes, display projections and workflow semantics remain application
code. No arbitrary-database adapter or tenant plugin system is implied.

Inventory costing, compliance, reconciliation, inferred FX gains, schedules and
approval policies require separate product decisions. This frontend authors
calculation facts; it does not infer those policies.
