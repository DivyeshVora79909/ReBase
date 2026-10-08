# Frontend meaning and execution plan — October 8, 2026

## Meaning of the request

Build a small engineering boilerplate and demonstrate it with a usable accounting
application. JavaScript/JSX, Solid, TanStack's Solid Router/Query and the native
SurrealDB SDK already provide the composition model. Pages author forms and
queries; shared components remove actual repetition. New business capabilities
should normally require a route and a data module, without changing startup,
session handling or other domains.

The supplied history explicitly corrected the earlier generic framework and
asked for a simple boilerplate. Preserve that correction. Prototype breaking
changes are authorized; remove superseded domain code instead of retaining an
adapter. Accounting is a calculation system, with explicit facts and optional
groupings, rather than a compulsory posting or compliance workflow. Calculations
and final validation belong to the backend.

The current request asks for study and a written plan before implementation,
consideration of notifications and future maintenance cost, and no new automated
tests in this pass. Build and manually exercise a disposable accounting demo;
report those checks separately from historical test evidence.

## Inspected baseline and authority

- Parent ReBase: clean `cada5e2`, following `a8ecfca` (scalar readers, identity
  trees, analytics) and `88c5ae7` (direct accounting).
- Separate MetaSol: `ada483e`, with unfinished dirty tenant migration. The
  starting diff/untracked routes were saved outside the repositories before
  replacement. Review both repositories independently.
- Read the supplied histories for intent, current frontend modules/diff, all 43
  public accounting input schemas, framework authorization and current contracts.
  Prior frontend acceptance does not cover this API.
- Authority: [accounting blueprint](../all-in-accounting/blueprint.md),
  [October 8 extensions](../all-in-accounting/extension-contract.md),
  [source map](../all-in-accounting/context-map.md),
  [framework blueprint](../rebase-system/developer-blueprint.md),
  [authentication](../rebase-system/tenant-authentication.md),
  [public tree reader](../rebase-system/ordered-tree-contract.md).

## Engineering decisions

1. Distinct lifetimes: application configuration/query client; workspace SDK;
   authenticated session/epoch; device appearance; route filters; local forms.
   Private results and notices belong to tenant plus authenticated session.
2. Namespace/database stay in configured connections. URLs use
   `/w/:profile/:tenant/…`. Verify tenant natively after sign-in and use canonical
   IDs. Native permissions authorize actions; `session.can()` controls affordances.
3. Keep native RecordId, Decimal, Date and Duration. Bind user values and allowlist
   interpolated table/order names. Omitted inputs use NONE; zero/false stay
   explicit. Save only authored input fields.
4. Retain exact affected-row checks, stable create IDs, optimistic `updated_at`
   checks and session fences. Never automatically retry uncertain writes; keep
   the draft and provide record inspection.
5. Reuse bounded record selection, table/cards, pagination, fields, source-form
   lifecycle, dialogs, amount/date and feedback. Forms compose explicit JSX and
   their own content builders. No resource/form/query registry or schema-driven UI.
6. Notifications have one small session-scoped owner, accessible announcements
   and recent activity. Confirmed writes publish notices; actionable errors stay
   in forms. Connection state stays in its provider. A durable inbox needs a
   public backend contract; worker wake-ups are not user notifications.
7. Keep semantic CSS, appearance/density settings, responsive navigation and a
   compact navigation preference. Future docking belongs to the shell alone.
8. Show units and time meaning. Whole-history positions include future facts;
   as-of reads use typed boundaries. Never total unlike currencies/resources.
   Invoices validate descendants; gross settlement, charges and net cash are
   separate measures. Analytics enrollment is an explicit opt-in.

## Accounting demo surface

| Page | Explicit records and behavior |
| --- | --- |
| Overview | Orientation, quick actions and readable unit-specific positions |
| Accounts | Seven account families, policies/dimensions, historical balances, bounded source history and monetary/resource entries |
| Directory | Currency, measure unit, item, service, operating unit, directed exchange pair |
| Invoices | Sales/purchase headers, issues, base/net taxes, payments, withholding, returns/corrections and server totals |
| Adjustments | Notes, signed correction rows, separate commercial/cash totals, draft/finalize/reopen |
| Claims and taxes | Independent claims/source settlement; tax settlement/deposit/refund/credit offset |
| Transfers | Resource/currency exchange, scalar conversion, optional pair/output links |
| Production | Parent dates and independent inputs, outputs, costs, service/operating capacity |
| Analytics | Readable root, typed date range and unit-specific trade/payment/pair summaries |
| Shell | Tenant sign-in, notifications, connection recovery, preferences and user directory |

All 43 public accounting record types fit these pages. Fee inputs share one
small field group. Advanced inputs use labeled disclosures. Empty/loading/denied/
disconnected/failed-save states must remain usable. Public input schemas guide
authored forms without generating the UI.

## Execution sequence

| Step | Deliverable | State |
| --- | --- | --- |
| P0 | History/Git/source review and this meaning/plan | Complete |
| P1 | Shared fields/writes, current lookups, session recovery, notifications/shell | Complete |
| P2 | Accounts/directory, invoices/adjustments and operations | Complete |
| P3 | Typed analytics and disposable local demo | Complete |
| P4 | Build, one-off native/browser walkthrough, desktop/mobile and source review | Complete |
| P5 | Current documentation, exact verification limits, coherent local commits | Complete |

Parallel file ownership: foundation/shell, commerce, operations. Lead owns shared
field/data contracts, accounts/directory, analytics, demo and documentation. Source
changes follow this plan; agents do not edit each other's files or invent layers.

The frontend implementation is committed in MetaSol as `89799ec`. Fresh results,
source fingerprints and prototype limits are in [verification](verification.md).
The disposable demo was stopped and removed its owned temporary state. This
parent documentation packet records the implementation; nothing was pushed or
deployed.

## Future additions without rebuilding the foundation

- Recovery/OTP/passkeys: ordinary auth routes and gateway functions; tokens enter
  the existing native tenant check. Expose flows only when configured.
- Durable notifications: public recipient/read/unread contract, a data module and
  inbox route; add reconnect catch-up before live ingestion.
- Live data: a native subscription owned by its route/query, targeted invalidation,
  reconnect requery and disposal. Add where a real workflow needs it.
- Bulk import: preview current public inputs and show individual outcomes. Page
  exports use explicit projections and exact strings. No generic import engine.
- CRM/HRM or another compiled app: compose routes with the same session/UI modules;
  no runtime tenant plugin system.
- Advanced navigation docking: shell/preferences/CSS only, independent of domain.
- Automated regression work follows the settled demo: tenant fencing, uncertain
  writes, temporal balances, invoice dates, correction/fee units. Historical
  evidence remains historical.
