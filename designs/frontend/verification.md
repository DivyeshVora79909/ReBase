# Frontend verification — October 8, 2026

This is historical frontend evidence for the `cada5e2` backend API. It does not
certify compatibility with the October 13 [subsidiary redesign](../all-in-accounting/developer-guide.md).

The current frontend targets ReBase `cada5e2`, including direct accounting,
explicit tenants, scalar readers, adjustment notes, inline charges and typed
analytics. MetaSol started at `ada483e` with an unfinished tenant migration.
The [execution plan](execution-plan.md) records the review and implementation
scope. MetaSol implementation is committed as `89799ec`. Backend source was
unchanged during this frontend packet.

New automated workflow tests were deferred at the user's request. These checks
distinguish retained tests from one-off native/browser walkthroughs. Temporary
scripts and synthetic records exercise the disposable demo; they are not a
maintained regression suite or production acceptance.

## Current checks

| Check | Result |
| --- | --- |
| Production Vite build | Final build passed: 197 modules, 4.02 seconds in Vite |
| Retained `npm test` | 10 passed, 0 failed, skipped or cancelled |
| Public input audit | All 43 accounting create schemas mapped to authored form/content paths |
| Disposable demo | Compiled current schema, provisioned a record user and created 41 seed records through record authentication |
| Native data readers | 108 calls passed with no errors, including all four analytics modes |
| Browser routes | Login/restoration and 14 accounting/settings/user routes opened without page errors |
| Browser writes | Directory/account entries, invoice/tax/charged payment, adjustment-note lifecycle, claim settlement and tax operations passed |
| Session recovery | Invalid credentials, tenant mismatch, restoration, signout, interrupted principal check and blocked connection passed |
| Presentation | Desktop/mobile, dark mode, compact navigation and preference persistence passed |
| Final syntax and demo shutdown | 66 files parsed; SIGINT closed both owned servers/ports and removed the temporary schema |
| Documentation and source evidence | 153 local links resolved; all 71 source fingerprints matched |

## Native reads and seeded calculations

The demo owns a loopback memory SurrealDB process and temporary compilation
directory. Administrator credentials remain in its Node process. Browsers and
data readers authenticate as the provisioned record user. Neither configured
databases nor `public/runtime.json` are changed by `npm run demo`.

The 108 read calls cover all seven account families, details, summary/before/history
tree readers, directory types, overview, reference search/hydration, commerce,
claims, tax operations, production and analytics. Native Decimal and RecordId
results were retained. Before the browser's additional records:

- Sales invoice: INR 6,372 commercial value, INR 4,000 paid, INR 2,372 outstanding.
- Charged payment: INR 4,000 gross, INR 40 charge, INR 7.20 charge tax,
  INR 3,952.80 net cash.
- Independent claim: INR 1,200 remaining.
- Trade: INR 5,400 sales and INR 1,600 purchases; weighted mug price INR 450.
- Whole-history bank balance: INR 115,752.80, including future production facts.
- All four production line queries returned populated inputs, outputs, cost and
  capacity. Unit, pair and operating-unit analytics ranges passed.

The first reader walkthrough found no notes, tax cash/offset operations or most
correction types. Its success establishes empty-query compatibility for those
paths; populated browser checks are recorded separately below.

## Browser walkthrough

Browser time zone was Asia/Kolkata. A saved demo record-user session opened
Accounts and its detail, Invoices and its detail, Claims, Taxes, Transfers,
Production and its detail, Directory, Adjustments, Analytics, Settings and Users.
No browser page errors were observed.

Completed mutations:

- Created a currency through Directory.
- Rejected an account entry that breached the historical account floor. The same
  draft was corrected to INR 25, saved, changed to INR 30 and deleted. The account
  returned to its original balance; activity showed the three confirmed writes.
- Created a sales invoice, a one-unit INR 100 stock issue and 18% base tax. The
  invoice displayed INR 118 commercial value.
- Created an INR 100 payment with a 1% charge, 18% charge tax and explicit tax
  credit. The page displayed INR 1 charge, INR 0.18 charge tax, INR 98.82 net
  cash and INR 18 invoice outstanding.
- Rejected finalization of an empty adjustment note. Added a price correction,
  its recalculated tax and a negative payment adjustment. The note showed INR
  −11.80 commercial change, INR −10 settlement change and three contributions.
  Finalization and reopening passed. The related invoice showed INR 106.20
  commercial value, INR 90 paid and INR 16.20 outstanding.
- Applied an INR 120 partial claim settlement, leaving INR 1,080. Deposited
  INR 50 tax credit, received an INR 10 tax refund and applied INR 5 credit
  against a tax liability. All appeared through their populated page queries.
- Selected roots in all four browser analytics modes. Enrolled issue/correction
  values appeared in trade and operating-unit reports; payment and directed-pair
  measures rendered with their respective units.

Session and form-state checks:

- Wrong-password sign-in returns native `NotFoundError` on this server. Only that
  sign-in result becomes a clear credential rejection; unrelated missing-record
  queries do not invalidate a session.
- Correct login and reload restore the saved token. A token copied into a
  different tenant's storage key is rejected and removed. Signout removes it.
- An isolated simulated principal-query failure preserves the authenticated
  shell, principal and exact token; Retry access check performs a native read
  successfully. Blocking only that context's database WebSocket during reload
  preserves credentials and hides authenticated pages. Retry connection restores
  the requested route after the block is removed.
- Browser Back and Refresh preserve an opened invoice/note's captured
  sales/purchase kind and draft values. Invoice organization remains captured.
  Dirty Cancel prompts remain active.
- Four browser-only injected failures exercised a mounted unknown outcome, a
  late unknown save after navigation, a late rejected delete and an old-session
  failure after logout/relogin. Mounted errors retained the form; same-session
  late errors showed activity with the exact record and explicit native inspection.
  Old-session feedback was suppressed. These injections performed no writes.

At 390 × 844, Overview and Settings fit the viewport. Mobile navigation traps
keyboard focus and Escape restores its trigger. Clean form-dialog and activity
panel Escape restore their triggers. Dark/compact/density/UTC preferences survive
reload. At 1280px the compact sidebar measures 78px and expands to 242px; icon
links retain accessible names. Screenshots were visually inspected.

## Findings corrected during integration

The checks and source review corrected optional fee-tax conversion defaults,
typed analytics range bounds, record-picker cache scope, refresh-driven editor
remounting, stale callbacks after form unmount, history cursor revision handling,
invalid-password classification, mutable creation-form context and late-failure
activity/inspection. A copied SDK record ID used angle brackets while the server's
string projection used backticks, causing text search to miss it. Reference
searches now parse copied IDs natively and bind an exact match inside their
existing tenant/source filters. Nine focused reads passed SDK/server ID spellings,
plain names, partial/malformed IDs, and invoice inclusion/exclusion. These were
frontend corrections; business validation and calculations remain on the server.

## Build and source evidence

[Current evidence](evidence/2026-10-08-frontend.json) records the source commit,
fingerprints and check scope. Four pages also passed against the final production
bundle: Overview, invoice detail, adjustment-note detail and payment analytics.
Their runtime override existed only in the checking browser. No alerts or page
errors occurred. SIGINT closed the owned demo/database processes and ports and
removed the temporary schema directory in 0.2 seconds.

Visually inspected examples:
[desktop invoice](evidence/2026-10-08-invoice-desktop.png),
[finalized adjustment note](evidence/2026-10-08-adjustment-note.png) and
[mobile overview](evidence/2026-10-08-overview-mobile.png).

The final build and retained checks ran with a PATH-only process environment:
[build log](evidence/2026-10-08-frontend-build.log) and
[retained-test log](evidence/2026-10-08-frontend-retained-tests.log). All 66 current
JavaScript/JSX source, test, demo and Vite configuration files parsed successfully.
No `.env` file or prefixed environment variable configures the client; public
connection configuration is loaded from `/runtime.json`.

Environment: Node 22.23.2, SurrealDB 3.3.0, SDK 2.0.8, Solid 1.9.14,
TanStack Solid Router 1.170.36 / Query 5.101.4, Vite 8.1.5 and Playwright 1.62.1.

## Limits and historical evidence

Maintained tests now cover native values and token storage only. Superseded
accounting, runtime and browser fixtures referred to removed APIs/routes and were
removed. No new automated workflow tests were added. This packet does not prove
every field combination or rejection path for all 43 forms, cross-tenant late
responses under every transport failure, or large-dataset performance.

Persistent notifications, live inbox delivery, gateway recovery/passkeys, bulk
import/export and deployment remain [deferred](deferred-work.md). Activity and
drafts are session/page memory only. Native sorted scans retain `WITH NOINDEX`;
public tree reads may reject an unreadable member rather than silently excluding
it. No push or deployment is part of this packet.

October 2/3 evidence remains historical:
[frontend evidence](evidence/2026-10-02-frontend.json) and
[combined redesign evidence](../rebase-system/evidence/2026-10-03-redesign-verification.json).
Its 26 native/unit and 28 browser test results concern the removed accounting
contract and must not be cited as acceptance of the current frontend.
