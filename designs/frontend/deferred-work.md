# Future frontend work

These are extension boundaries for the current accounting demo. They do not
justify introducing a registry, universal form engine or additional application
framework. The [execution plan](execution-plan.md) records the current scope.

## Automated workflow coverage

The user deferred new tests for this pass. Retained checks cover native values and
token storage; current integration is recorded as a manual walkthrough. When adding
coverage, begin with a small disposable current-schema fixture and test externally
visible behavior: tenant/account switches with late results, uncertain saves,
exact update conflicts, historical balances, invoice-date boundaries, nonlinear
tax corrections, note finalization and gross/net fees. Do not revive removed
recipe fixtures or claim historical test counts for the current schema.

## Persistent notifications

Current notices are bounded in-memory activity for one authenticated session.
The backend has no public user inbox, acknowledgement table or browser-push API.
Its runtime live notifications wake workers; its audit table is private.

First define recipient/tenant authorization, stable event identity, unread state,
retention and reconnect catch-up. Then add a normal data module and inbox route,
reusing notice presentation. Attach any live subscription to that owning route or
provider and dispose it on session changes. Durable jobs, delivery queues and
worker audit data stay on the backend. Do not persist financial form drafts as a
substitute for a notification store.

## Standard authentication flows

The backend already supports code challenges and passkey exchanges. Add explicit
routes/data functions when a gateway/RP is configured. Code request uses
`POST /anonymous/authentication/challenges`; native sign-in uses `account_code`.
Passkey browser credentials enter the configured gateway and finish through native
`account_passkey` exchange. Both must finish the same native tenant/principal check
and session rotation as password sign-in. Provider setup, identity verification,
recovery UX and expired/replayed challenges need a focused acceptance packet.

Do not expose inactive recovery/signup controls. No universal authentication-plugin
layer or browser access to private identifier trees is needed.

## Live views and large histories

The current demo explicitly refreshes authoritative reads, and invalidates current
session queries after writes/reconnect. For a real collaborative screen, own a
native subscription with the corresponding query, invalidate that query, requery
after reconnect and kill the subscription on disposal. Keep typed tree cursors
native and reset traversal when its revision changes. Native filtered lists have
bounded pages; they are not snapshots or complete export populations.

Measure query volume before narrowing the current session-wide post-write
invalidation. Preserve correctness across affected accounts and analytics roots.
Do not generalize subscription management before more than one real consumer needs
it. Historical cache permission behavior should be exercised with role revocation.

## Import, export and presentation

Page CSV exports use the explicit displayed projection and exact strings. Bulk
export needs an independently bounded query/stream with unchanged filters and
visible limits; bulk import needs current public-schema validation, preview and
per-record outcomes. Record permission failures and partial import cannot become
silent successes. No spreadsheet/query DSL is part of the current foundation.

Navigation is responsive and can collapse to icons. Future orientation, docking or
drag layout belongs to shell/preferences/CSS. Date displays support device time or
UTC; input uses device time. More localization belongs to presentation functions,
not monetary storage. Additional page layouts can reuse render callbacks without
changing database/query ownership.

## Other applications and accounting policy

CRM/HRM or another compiled design can compose its own routes with the same small
session/UI modules. Runtime config continues to describe connections, not tenant
plugins, table menus or business workflows.

The backend supports explicit calculation facts. Inventory costing, statutory
filing, inferred FX gains/losses, bank reconciliation, legal offset eligibility,
interest/accrual schedules and document approval workflows need separate product
rules. Existing source fields or scheduled operations do not establish those rules.
No backend migration or provider deployment is part of this frontend change.
