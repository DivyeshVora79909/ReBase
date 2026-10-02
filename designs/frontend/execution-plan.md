# Frontend execution plan

2026-10-02. Execute directly; lower-model prompts are maintenance aids, not a
substitute for this implementation. No compatibility shim for the removed generic
console is required. Keep this work visible in the new `designs/frontend/` package
and the separately versioned `MetaSol/` application.

## Delivery record

| Stage | Delivered result |
| --- | --- |
| F0 | Both Git roots inspected; existing dirty starter snapshot retained; current schemas and installed SDK checked. |
| F1 | Workspace/session/query fencing, responsive shell, entry/sign-in styling, preferences, bounded single/multi record selection and shared record presentation. |
| F2 | Treasury list/detail/create and exclusive cutoff; exact cash entry/edit/delete, rollback/conflict handling and uncertain-save inspection. |
| F3 | Claims, untaxed invoices/allocations, inventory, directory, entered FX/reversal, immutable recipes, assembly and timed production. |
| F4 | Architecture, screen contracts, developer examples, restart prompts and explicit deferred packets. |
| F5 | Native, browser, build, screenshot and repository checks recorded in [verification](verification.md). |

The [screen contracts](screen-contracts.md) define the delivered feature scope.
The [deferred-work map](deferred-work.md) distinguishes browser workflows still
to add from missing backend policies. No compatibility layer or delegation to a
smaller model was used for this implementation.

## Product and engineering decisions

1. **One compiled application, ordinary composition.** This application is the
   accounting suite. A future CRM-only or client-specific application composes
   explicit routes and the same small session/UI primitives in source. Runtime
   configuration supplies connections, not tables, routes, business policies or
   tenant plugins. No route/form/query registry or new query language.
2. **Distinct contexts.** Application owns public connection settings and the
   query client; workspace owns the SDK connection and namespace/database;
   session owns the authenticated principal and an epoch; preferences own local
   appearance. Economic entity is a filter, never an authorization identity.
   Switching account or workspace invalidates old work and clears private cache.
3. **Use the installed libraries directly.** Keep Solid and TanStack's Solid
   adapters. A library's implementation language is not a reason to replace it.
   Thin query/mutation helpers may centralize repeated session fences, while
   exposing the actual SDK and page query callback.
4. **Native values at the boundary.** Preserve record table and typed key; bind
   user input. Use decimal strings and SDK Decimal, never Number for money. Show
   separate currencies/units and explicit time semantics. Whole-history tree
   totals include future-dated facts and are not an available-today balance.
5. **Explicit forms.** Source fields are authored by the page. Computed net,
   balance, invoice outputs, tree fields and managed production roles are never
   writable controls. Validate locally for usability and on the database for
   truth. Stable source IDs and exact affected-row checks bound uncertain retries.
6. **Extract only useful UI.** A lazy single/multi record picker, table, card
   grid, grouped board, pagination, error/loading state, amount/date display and
   modal/drawer serve real pages. Columns and render functions are ordinary JSX.
   Grouping describes its loaded population, caps distinct columns at ten plus
   Other, and never implies a whole-database aggregate or automatic drag mutation.
7. **Keep state honest.** Search/sort/page/view belong in the URL; unsaved inputs
   stay in the form; cosmetic preferences stay on the device; authoritative
   records stay in the query cache. No financial offline write queue or secret
   persistence outside the explicit session-storage choice.

## Execution order

### F0 — Recover and plan

Read the current frontend, backend schema and active handoffs. Preserve a before
snapshot of the dirty frontend; inspect both repositories. Record the actual
SDK versions and available tests. State which contracts are implementation,
historical evidence, or future work. **Exit:** this plan and a scoped baseline.

### F1 — Contexts and shared interaction

Build a responsive accounting shell and workspace entry, retain reliable
connection/session ownership, expose principal permissions for affordances, and
extend small preferences for density and time display. Implement only the shared
query/mutation fence and UI used by the accounting routes. Add lazy polymorphic
record selection with bounded search, selected-value hydration, keyboard support,
duplicate-free multi-select and stale-context suppression.

**Exit:** a real record session gates reads; account/context changes cannot show
old results; keyboard/mobile navigation works; no root credentials reach the app.

### F2 — Treasury and source cash workflows

Build account search/detail, account creation, money in/out/transfers and explicit
source editing/deletion where native rules permit it. Use current schema names
and derive displays from readable, explicit projections. Include current owner,
economic entity, currency and date semantics in forms. Add atomic exact-row
mutation helpers and preserve a stable source ID after ambiguous transport errors.

**Exit:** native compiled-profile tests prove a visible committed balance change,
rollback on invalid cash use, unauthorized denial, precise decimals, stale-session
suppression and a bounded activity page. Do not claim a complete ledger from a
subset of movement tables.

### F3 — Accounting, inventory and operational pages

Implement ordinary pages for claim accounts and standalone claims, invoices,
inventory and stock movement, exchange, and recipe-based assembly/production.
Use existing source records for actions; privately managed outputs remain server
owned. Add explicit entity/master-data setup where these workflows require it.
Prefer a reviewed bounded action over a generic editor for a complex recipe.

**Exit:** each visible action has its own field/permission/transaction contract
and focused native verification. Read-only portions say what their numbers mean.
Unresolved residual, tax-filing, costing and workforce policies receive concrete
deferred packets rather than invented forms.

### F4 — Developer blueprint and deferred work

Write the context map, file ownership, page/query/form examples, component APIs,
contract matrix and short restart prompts. Inventory deferred frontend and backend
work with prerequisites, invariant, smallest proof, allowed files and completion
criteria. Distinguish implemented accounting tables from unpublished browser
projections and independent CRM/HRM designs.

**Exit:** a junior can add an ordinary page from one example without knowing
compiler internals or copying a query framework. New docs link to current source.

### F5 — Integrate and inspect

Run focused native value and mutation tests, production build, browser workflow
tests on disposable SurrealDB, and relevant existing session regressions. Inspect
desktop and mobile screenshots, keyboard states, empty/error states and final
diffs. Verify local links and source fingerprints. Record actual results and
limits in this package and in MetaSol's usage guide.

**Exit:** tests pass for delivered features; the implementation and evidence agree;
no hidden production deployment or live-provider activity is claimed.

## Parallel backend work and policy boundaries

The core K1–K5 and accounting H1–H8 source/evidence already exist. This frontend
work consumes them; it does not restart the developer-tools redesign. H4b5c tax
residual policy, representative physical-cost measurements, populated legacy
migration, live providers, workforce, costing, valuation, statutory filing, CRM
and HRM each need their own contract. Full planning for those items belongs in
this package's deferred-work record, with canonical backend references.

Routine frontend implementation choices and breaking changes are authorized by
the current request. Pause only for an actual missing business rule that cannot
be inferred safely; continue independent implementation while that rule is open.
